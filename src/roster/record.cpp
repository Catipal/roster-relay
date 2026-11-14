// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/record.h>

#include <hash.h>

#include <cstring>

namespace roster {

//! TORV2 is absent deliberately rather than by oversight: v2 onion services no
//! longer resolve, so a record naming one can never be dialled. Accepting it
//! would produce a valid record with no usable endpoint, indistinguishable on
//! the wire from a rendezvous-only record but without the service bit that
//! declares the intent. Rejecting keeps that ambiguity out of the roster.
size_t EndpointAddrSize(uint8_t network)
{
    switch (network) {
    case EP_IPV4: return ADDR_SIZE_IPV4;
    case EP_IPV6: return ADDR_SIZE_IPV6;
    case EP_TORV3: return ADDR_SIZE_TORV3;
    case EP_I2P: return ADDR_SIZE_I2P;
    case EP_CJDNS: return ADDR_SIZE_CJDNS;
    default: return 0;
    }
}

namespace {

uint32_t ReadLE32(const unsigned char* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void WriteLE32(std::vector<unsigned char>& out, uint32_t v)
{
    out.push_back((unsigned char)(v & 0xff));
    out.push_back((unsigned char)((v >> 8) & 0xff));
    out.push_back((unsigned char)((v >> 16) & 0xff));
    out.push_back((unsigned char)((v >> 24) & 0xff));
}

//! Ports are network byte order, matching BIP155 and every other address
//! encoding on the wire.
uint16_t ReadBE16(const unsigned char* p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

void WriteBE16(std::vector<unsigned char>& out, uint16_t v)
{
    out.push_back((unsigned char)((v >> 8) & 0xff));
    out.push_back((unsigned char)(v & 0xff));
}

void AppendKey(std::vector<unsigned char>& out, const KeyBytes& key)
{
    out.insert(out.end(), key.begin(), key.end());
}

const char* TypeTagWord(RecordType type)
{
    switch (type) {
    case RecordType::ANNOUNCE: return "announce";
    case RecordType::REVOKE: return "revoke";
    case RecordType::DELEGATE: return "delegate";
    case RecordType::ROTATE: return "rotate";
    case RecordType::VETO: return "veto";
    }
    return "unknown";
}

//! Fixed body sizes, excluding the 4-byte header and the 64-byte signature.
static constexpr size_t BODY_REVOKE = RECORD_KEY_SIZE;                          // 32
static constexpr size_t BODY_DELEGATE = RECORD_KEY_SIZE * 2 + 4;                // 68
static constexpr size_t BODY_DELEGATE_WITH_COMMIT = BODY_DELEGATE + RECORD_HASH_SIZE; // 100
static constexpr size_t BODY_ROTATE = RECORD_KEY_SIZE * 2;                      // 64
static constexpr size_t BODY_VETO = RECORD_KEY_SIZE * 2;                        // 64

} // namespace

bool ExpiryInRange(uint32_t expiry_height, int confirm_height)
{
    if (confirm_height < 0) return false;
    const uint64_t confirm = static_cast<uint64_t>(confirm_height);
    // 64-bit throughout: confirm + MAX_TTL would overflow uint32 for a
    // near-maximal expiry, and the comparison would then wrap into accepting it.
    return expiry_height >= confirm + MIN_TTL && expiry_height <= confirm + MAX_TTL;
}

bool IsValidNote(Span<const unsigned char> text)
{
    if (text.size() == 0 || text.size() > MAX_NOTE_SIZE) return false;
    if (text[0] == ' ' || text[text.size() - 1] == ' ') return false;
    size_t i = 0;
    while (i < text.size()) {
        const unsigned char lead = text[i];
        uint32_t cp;
        size_t len;
        if (lead < 0x80) {
            cp = lead;
            len = 1;
        } else if (lead >= 0xc2 && lead <= 0xdf) {
            cp = lead & 0x1f;
            len = 2;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            cp = lead & 0x0f;
            len = 3;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            cp = lead & 0x07;
            len = 4;
        } else {
            return false; // a continuation byte first, an overlong 0xc0/0xc1, or past U+10FFFF
        }
        if (i + len > text.size()) return false;
        for (size_t k = 1; k < len; ++k) {
            const unsigned char c = text[i + k];
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3f);
        }
        // Shortest form only, and nothing a decoder may map differently.
        if (len == 3 && cp < 0x800) return false;
        if (len == 4 && (cp < 0x10000 || cp > 0x10ffff)) return false;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
        // Control characters, C0 and C1, and DEL: line breaks and tabs too,
        // since a note is one line.
        if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return false;
        // Marks that are invisible yet change how the text around them reads:
        // direction overrides and isolates, which can make a note show a key
        // or an amount it does not contain, and the byte-order mark.
        if (cp == 0x200e || cp == 0x200f || (cp >= 0x202a && cp <= 0x202e) ||
            (cp >= 0x2066 && cp <= 0x2069) || cp == 0xfeff) {
            return false;
        }
        i += len;
    }
    return true;
}

bool operator==(const Endpoint& a, const Endpoint& b)
{
    return a.network == b.network && a.addr == b.addr && a.port == b.port;
}

std::string ParseErrorString(ParseError err)
{
    switch (err) {
    case ParseError::OK: return "ok";
    case ParseError::TOO_SHORT: return "too short";
    case ParseError::TOO_LONG: return "too long";
    case ParseError::BAD_MAGIC: return "bad magic";
    case ParseError::BAD_VERSION: return "unsupported version";
    case ParseError::BAD_TYPE: return "unknown record type";
    case ParseError::BAD_LENGTH: return "length does not match record type";
    case ParseError::BAD_ENDPOINT_COUNT: return "too many endpoints";
    case ParseError::BAD_ENDPOINT_NETWORK: return "unknown or unsupported endpoint network";
    case ParseError::BAD_MEETING_POINT: return "meeting point on a record with endpoints";
    case ParseError::BAD_NOTE: return "note on a record with endpoints, or not acceptable text";
    case ParseError::TRAILING_BYTES: return "trailing bytes after record";
    }
    return "unknown error";
}

ParseError ParseRecord(Span<const unsigned char> raw, Record& out)
{
    if (raw.size() > MAX_RECORD_SIZE) return ParseError::TOO_LONG;
    if (raw.size() < RECORD_HEADER_SIZE + RECORD_SIG_SIZE) return ParseError::TOO_SHORT;

    const unsigned char* p = raw.data();
    if (std::memcmp(p, RECORD_MAGIC, sizeof(RECORD_MAGIC)) != 0) return ParseError::BAD_MAGIC;

    const uint8_t ver = p[3] >> 4;
    const uint8_t type_nibble = p[3] & 0x0f;
    if (ver != RECORD_VERSION) return ParseError::BAD_VERSION;
    if (type_nibble < 0x01 || type_nibble > 0x05) return ParseError::BAD_TYPE;

    out = Record{};
    out.type = static_cast<RecordType>(type_nibble);

    // Everything between the header and the trailing signature.
    const size_t body_size = raw.size() - RECORD_HEADER_SIZE - RECORD_SIG_SIZE;
    const unsigned char* body = p + RECORD_HEADER_SIZE;
    size_t off = 0;

    switch (out.type) {
    case RecordType::ANNOUNCE: {
        // op_key(32) + expiry(4) + services(4) + prev_height(4) + ep_count(1)
        static constexpr size_t FIXED = RECORD_KEY_SIZE + 4 + 4 + 4 + 1;
        if (body_size < FIXED) return ParseError::BAD_LENGTH;

        std::memcpy(out.op_key.data(), body, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        out.expiry_height = ReadLE32(body + off);
        off += 4;
        out.services = ReadLE32(body + off);
        off += 4;
        out.prev_height = ReadLE32(body + off);
        off += 4;

        const uint8_t ep_count = body[off];
        off += 1;
        if (ep_count > MAX_ENDPOINTS) return ParseError::BAD_ENDPOINT_COUNT;

        out.endpoints.reserve(ep_count);
        for (uint8_t i = 0; i < ep_count; ++i) {
            if (off + 1 > body_size) return ParseError::BAD_LENGTH;
            Endpoint ep;
            ep.network = body[off];
            off += 1;
            const size_t addr_size = EndpointAddrSize(ep.network);
            if (addr_size == 0) return ParseError::BAD_ENDPOINT_NETWORK;
            if (off + addr_size + 2 > body_size) return ParseError::BAD_LENGTH;
            ep.addr.assign(body + off, body + off + addr_size);
            off += addr_size;
            ep.port = ReadBE16(body + off);
            off += 2;
            out.endpoints.push_back(std::move(ep));
        }

        // A key reached at an address needs no meeting point, and allowing
        // both would let the largest record outgrow MAX_RECORD_SIZE.
        if (out.services & SERVICE_MEET_PRESENT) {
            if (ep_count != 0) return ParseError::BAD_MEETING_POINT;
            if (off + RECORD_KEY_SIZE > body_size) return ParseError::BAD_LENGTH;
            KeyBytes point;
            std::memcpy(point.data(), body + off, RECORD_KEY_SIZE);
            out.meet_point = point;
            off += RECORD_KEY_SIZE;
        }

        // A note stands where an address would: never beside one.
        if (out.services & SERVICE_NOTE_PRESENT) {
            if (ep_count != 0) return ParseError::BAD_NOTE;
            if (off + 1 > body_size) return ParseError::BAD_LENGTH;
            const size_t note_size = body[off];
            off += 1;
            if (off + note_size > body_size) return ParseError::BAD_LENGTH;
            if (!IsValidNote(Span<const unsigned char>(body + off, note_size))) return ParseError::BAD_NOTE;
            out.note.assign(reinterpret_cast<const char*>(body + off), note_size);
            off += note_size;
        }

        if (out.services & SERVICE_META_PRESENT) {
            if (off + RECORD_HASH_SIZE > body_size) return ParseError::BAD_LENGTH;
            uint256 h;
            std::memcpy(h.begin(), body + off, RECORD_HASH_SIZE);
            out.meta_hash = h;
            off += RECORD_HASH_SIZE;
        }
        break;
    }
    case RecordType::REVOKE: {
        if (body_size != BODY_REVOKE) return ParseError::BAD_LENGTH;
        std::memcpy(out.op_key.data(), body, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        break;
    }
    case RecordType::DELEGATE: {
        if (body_size != BODY_DELEGATE && body_size != BODY_DELEGATE_WITH_COMMIT) {
            return ParseError::BAD_LENGTH;
        }
        std::memcpy(out.id_key.data(), body, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        std::memcpy(out.op_key.data(), body + off, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        out.expiry_height = ReadLE32(body + off);
        off += 4;
        if (body_size == BODY_DELEGATE_WITH_COMMIT) {
            uint256 h;
            std::memcpy(h.begin(), body + off, RECORD_HASH_SIZE);
            out.recovery_commit = h;
            off += RECORD_HASH_SIZE;
        }
        break;
    }
    case RecordType::ROTATE: {
        if (body_size != BODY_ROTATE) return ParseError::BAD_LENGTH;
        std::memcpy(out.id_key.data(), body, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        std::memcpy(out.new_id_key.data(), body + off, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        break;
    }
    case RecordType::VETO: {
        if (body_size != BODY_VETO) return ParseError::BAD_LENGTH;
        std::memcpy(out.id_key.data(), body, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        std::memcpy(out.recovery_key.data(), body + off, RECORD_KEY_SIZE);
        off += RECORD_KEY_SIZE;
        break;
    }
    }

    // A record whose declared contents stop short of its own length is
    // malleable: the same logical record could be published at several
    // encodings, each with a distinct txid. Reject rather than tolerate.
    if (off != body_size) return ParseError::TRAILING_BYTES;

    std::memcpy(out.sig.data(), p + RECORD_HEADER_SIZE + body_size, RECORD_SIG_SIZE);
    return ParseError::OK;
}

std::vector<unsigned char> SerializeRecord(const Record& rec)
{
    std::vector<unsigned char> out;
    out.reserve(MAX_RECORD_SIZE);

    out.insert(out.end(), std::begin(RECORD_MAGIC), std::end(RECORD_MAGIC));
    out.push_back((unsigned char)((RECORD_VERSION << 4) | (uint8_t)rec.type));

    switch (rec.type) {
    case RecordType::ANNOUNCE: {
        AppendKey(out, rec.op_key);
        WriteLE32(out, rec.expiry_height);
        // Keep the declared bit and the actual field in step, so a caller
        // cannot produce a record that will not parse back.
        uint32_t services = rec.services;
        if (rec.meta_hash.has_value()) {
            services |= SERVICE_META_PRESENT;
        } else {
            services &= ~SERVICE_META_PRESENT;
        }
        if (rec.meet_point.has_value()) {
            services |= SERVICE_MEET_PRESENT;
        } else {
            services &= ~SERVICE_MEET_PRESENT;
        }
        if (!rec.note.empty()) {
            services |= SERVICE_NOTE_PRESENT;
        } else {
            services &= ~SERVICE_NOTE_PRESENT;
        }
        WriteLE32(out, services);
        WriteLE32(out, rec.prev_height);
        out.push_back((unsigned char)rec.endpoints.size());
        for (const Endpoint& ep : rec.endpoints) {
            out.push_back(ep.network);
            out.insert(out.end(), ep.addr.begin(), ep.addr.end());
            WriteBE16(out, ep.port);
        }
        if (rec.meet_point.has_value()) AppendKey(out, *rec.meet_point);
        if (!rec.note.empty()) {
            // Callers check with IsValidNote first; the length byte is only
            // ever written for a note that fits it.
            out.push_back((unsigned char)std::min<size_t>(rec.note.size(), 0xff));
            out.insert(out.end(), rec.note.begin(), rec.note.end());
        }
        if (rec.meta_hash.has_value()) {
            out.insert(out.end(), rec.meta_hash->begin(), rec.meta_hash->end());
        }
        break;
    }
    case RecordType::REVOKE:
        AppendKey(out, rec.op_key);
        break;
    case RecordType::DELEGATE:
        AppendKey(out, rec.id_key);
        AppendKey(out, rec.op_key);
        WriteLE32(out, rec.expiry_height);
        if (rec.recovery_commit.has_value()) {
            out.insert(out.end(), rec.recovery_commit->begin(), rec.recovery_commit->end());
        }
        break;
    case RecordType::ROTATE:
        AppendKey(out, rec.id_key);
        AppendKey(out, rec.new_id_key);
        break;
    case RecordType::VETO:
        AppendKey(out, rec.id_key);
        AppendKey(out, rec.recovery_key);
        break;
    }

    out.insert(out.end(), rec.sig.begin(), rec.sig.end());
    return out;
}

std::vector<KeyBytes> RecordKeys(const Record& rec)
{
    switch (rec.type) {
    case RecordType::ANNOUNCE:
    case RecordType::REVOKE:
        return {rec.op_key};
    case RecordType::DELEGATE:
        return {rec.id_key, rec.op_key};
    case RecordType::ROTATE:
        // Both ends, so a watcher of either identity sees the move. Missing the
        // new key would hide exactly the event worth watching for.
        return {rec.id_key, rec.new_id_key};
    case RecordType::VETO:
        return {rec.id_key, rec.recovery_key};
    }
    return {};
}

const KeyBytes& SigningKeyBytes(const Record& rec)
{
    switch (rec.type) {
    case RecordType::ANNOUNCE:
    case RecordType::REVOKE:
        return rec.op_key;
    case RecordType::DELEGATE:
    case RecordType::ROTATE:
        // DELEGATE is authorised by the identity it delegates from; ROTATE is
        // signed by the identity being moved away from, which is what makes
        // the veto window in §7 meaningful.
        return rec.id_key;
    case RecordType::VETO:
        return rec.recovery_key;
    }
    return rec.op_key;
}

XOnlyPubKey SigningKey(const Record& rec)
{
    const KeyBytes& key = SigningKeyBytes(rec);
    return XOnlyPubKey(Span<const unsigned char>(key.data(), key.size()));
}

std::string RecordTag(RecordType type, const std::string& chain_id)
{
    return std::string("BPS/") + TypeTagWord(type) + "/v" + std::to_string(RECORD_VERSION) + "/" + chain_id;
}

Span<const unsigned char> SignedPortion(Span<const unsigned char> raw)
{
    if (raw.size() < RECORD_SIG_SIZE) return Span<const unsigned char>();
    return raw.first(raw.size() - RECORD_SIG_SIZE);
}

uint256 RecordSigHash(Span<const unsigned char> raw, RecordType type, const std::string& chain_id)
{
    const Span<const unsigned char> signed_bytes = SignedPortion(raw);
    CHashWriter writer = TaggedHash(RecordTag(type, chain_id));
    writer.write((const char*)signed_bytes.data(), signed_bytes.size());
    return writer.GetSHA256();
}

bool VerifyRecord(const Record& rec, Span<const unsigned char> raw, const std::string& chain_id)
{
    if (raw.size() < RECORD_HEADER_SIZE + RECORD_SIG_SIZE) return false;
    // No separate key-validity check: XOnlyPubKey has no IsFullyValid() in this
    // tree, and VerifySchnorr already fails closed on a key that does not lift
    // to a curve point. One rejection path is better than two.
    const uint256 sighash = RecordSigHash(raw, rec.type, chain_id);
    return SigningKey(rec).VerifySchnorr(sighash, rec.sig);
}

bool ParseAndVerify(Span<const unsigned char> raw, const std::string& chain_id, Record& out)
{
    if (ParseRecord(raw, out) != ParseError::OK) return false;
    return VerifyRecord(out, raw, chain_id);
}

} // namespace roster
