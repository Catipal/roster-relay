// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/record.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <names/name.h>
#include <pubkey.h>

#include <cstring>

namespace names {

namespace {

constexpr size_t HEADER = roster::RECORD_HEADER_SIZE;
constexpr size_t KEY = roster::RECORD_KEY_SIZE;
constexpr size_t SIG = 64;

const char* TagWord(NameRecordType type)
{
    switch (type) {
    case NameRecordType::COMMIT: return "name-commit";
    case NameRecordType::CLAIM: return "name-claim";
    case NameRecordType::TRANSFER: return "name-transfer";
    case NameRecordType::SUBNAME: return "name-subname";
    case NameRecordType::SELL: return "name-sell";
    case NameRecordType::BUY: return "name-buy";
    }
    return "unknown";
}

bool KnownType(uint8_t raw, NameRecordType& out)
{
    switch (raw) {
    case static_cast<uint8_t>(NameRecordType::COMMIT):
    case static_cast<uint8_t>(NameRecordType::CLAIM):
    case static_cast<uint8_t>(NameRecordType::TRANSFER):
    case static_cast<uint8_t>(NameRecordType::SUBNAME):
    case static_cast<uint8_t>(NameRecordType::SELL):
    case static_cast<uint8_t>(NameRecordType::BUY):
        out = static_cast<NameRecordType>(raw);
        return true;
    default:
        return false;
    }
}

/** Reads a length-prefixed label. The label must already be in its one valid spelling. */
bool ReadLabel(const unsigned char*& p, const unsigned char* end, std::string& out)
{
    if (p >= end) return false;
    const size_t n = *p++;
    if (n == 0 || n > MAX_LABEL_LENGTH || (size_t)(end - p) < n) return false;
    out.assign(reinterpret_cast<const char*>(p), n);
    p += n;
    return IsValidLabel(out);
}

void PutLabel(std::vector<unsigned char>& out, const std::string& label)
{
    out.push_back(static_cast<unsigned char>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
}

/** Reads a length-prefixed byte string of 1 to `max` bytes. */
bool ReadBytes(const unsigned char*& p, const unsigned char* end, size_t max, std::vector<unsigned char>& out)
{
    if (p >= end) return false;
    const size_t n = *p++;
    if (n == 0 || n > max || (size_t)(end - p) < n) return false;
    out.assign(p, p + n);
    p += n;
    return true;
}

void PutBytes(std::vector<unsigned char>& out, const std::vector<unsigned char>& bytes)
{
    out.push_back(static_cast<unsigned char>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

} // namespace

bool ParseNameRecord(Span<const unsigned char> raw, NameRecord& out)
{
    if (raw.size() < HEADER || raw.size() > roster::MAX_RECORD_SIZE) return false;
    if (std::memcmp(raw.data(), roster::RECORD_MAGIC, 3) != 0) return false;
    if ((raw[3] >> 4) != roster::RECORD_VERSION) return false;
    NameRecord rec;
    if (!KnownType(raw[3] & 0x0f, rec.type)) return false;

    const unsigned char* p = raw.data() + HEADER;
    const unsigned char* end = raw.data() + raw.size();
    switch (rec.type) {
    case NameRecordType::COMMIT:
        if (end - p != 32) return false;
        std::memcpy(rec.commitment.begin(), p, 32);
        out = rec;
        return true;
    case NameRecordType::CLAIM:
        if (end - p < (ptrdiff_t)KEY) return false;
        std::memcpy(rec.key.data(), p, KEY);
        p += KEY;
        if (!ReadLabel(p, end, rec.name) || rec.name.size() < MIN_ROOT_LENGTH) return false;
        if (end - p != (ptrdiff_t)(16 + 4 + SIG)) return false;
        std::memcpy(rec.salt.data(), p, 16);
        p += 16;
        rec.expiry_height = ReadLE32(p);
        p += 4;
        break;
    case NameRecordType::TRANSFER:
        if (!ReadLabel(p, end, rec.name) || rec.name.size() < MIN_ROOT_LENGTH) return false;
        if (end - p != (ptrdiff_t)(KEY + SIG)) return false;
        std::memcpy(rec.key.data(), p, KEY);
        p += KEY;
        break;
    case NameRecordType::SUBNAME:
        if (!ReadLabel(p, end, rec.name) || rec.name.size() < MIN_ROOT_LENGTH) return false;
        if (!ReadLabel(p, end, rec.label)) return false;
        if (end - p != (ptrdiff_t)(KEY + 4 + SIG)) return false;
        std::memcpy(rec.key.data(), p, KEY);
        p += KEY;
        rec.expiry_height = ReadLE32(p);
        p += 4;
        break;
    case NameRecordType::SELL: {
        if (!ReadLabel(p, end, rec.name) || rec.name.size() < MIN_ROOT_LENGTH) return false;
        if (end - p < (ptrdiff_t)(32 + 4 + 8)) return false;
        uint256 hash;
        std::memcpy(hash.begin(), p, 32);
        p += 32;
        rec.coin = COutPoint(hash, ReadLE32(p));
        p += 4;
        rec.payout_value = (CAmount)ReadLE64(p);
        p += 8;
        if (!MoneyRange(rec.payout_value) || rec.payout_value <= 0) return false;
        std::vector<unsigned char> payout;
        if (!ReadBytes(p, end, MAX_PAYOUT_SCRIPT, payout)) return false;
        rec.payout = CScript(payout.begin(), payout.end());
        if (!ReadBytes(p, end, MAX_COIN_SIG, rec.coin_sig)) return false;
        if (end - p != (ptrdiff_t)SIG) return false;
        break;
    }
    case NameRecordType::BUY:
        if (end - p < (ptrdiff_t)KEY) return false;
        std::memcpy(rec.key.data(), p, KEY);
        p += KEY;
        if (!ReadLabel(p, end, rec.name) || rec.name.size() < MIN_ROOT_LENGTH) return false;
        if (end - p != (ptrdiff_t)(4 + SIG)) return false;
        rec.expiry_height = ReadLE32(p);
        p += 4;
        break;
    }
    std::memcpy(rec.sig.data(), p, SIG);
    out = rec;
    return true;
}

std::vector<unsigned char> SerializeNameRecord(const NameRecord& rec)
{
    std::vector<unsigned char> out(roster::RECORD_MAGIC, roster::RECORD_MAGIC + 3);
    out.push_back(static_cast<unsigned char>((roster::RECORD_VERSION << 4) | static_cast<uint8_t>(rec.type)));
    unsigned char b[4];
    switch (rec.type) {
    case NameRecordType::COMMIT:
        out.insert(out.end(), rec.commitment.begin(), rec.commitment.end());
        return out;
    case NameRecordType::CLAIM:
        out.insert(out.end(), rec.key.begin(), rec.key.end());
        PutLabel(out, rec.name);
        out.insert(out.end(), rec.salt.begin(), rec.salt.end());
        WriteLE32(b, rec.expiry_height);
        out.insert(out.end(), b, b + 4);
        break;
    case NameRecordType::TRANSFER:
        PutLabel(out, rec.name);
        out.insert(out.end(), rec.key.begin(), rec.key.end());
        break;
    case NameRecordType::SUBNAME:
        PutLabel(out, rec.name);
        PutLabel(out, rec.label);
        out.insert(out.end(), rec.key.begin(), rec.key.end());
        WriteLE32(b, rec.expiry_height);
        out.insert(out.end(), b, b + 4);
        break;
    case NameRecordType::SELL: {
        PutLabel(out, rec.name);
        out.insert(out.end(), rec.coin.hash.begin(), rec.coin.hash.end());
        WriteLE32(b, rec.coin.n);
        out.insert(out.end(), b, b + 4);
        unsigned char v[8];
        WriteLE64(v, (uint64_t)rec.payout_value);
        out.insert(out.end(), v, v + 8);
        PutBytes(out, std::vector<unsigned char>(rec.payout.begin(), rec.payout.end()));
        PutBytes(out, rec.coin_sig);
        break;
    }
    case NameRecordType::BUY:
        out.insert(out.end(), rec.key.begin(), rec.key.end());
        PutLabel(out, rec.name);
        WriteLE32(b, rec.expiry_height);
        out.insert(out.end(), b, b + 4);
        break;
    }
    out.insert(out.end(), rec.sig.begin(), rec.sig.end());
    return out;
}

uint256 Commitment(const std::string& name, const Salt& salt, const roster::KeyBytes& owner)
{
    static const std::string TAG = "BPS name commitment";
    uint256 out;
    const unsigned char len = static_cast<unsigned char>(name.size());
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(TAG.data()), TAG.size())
        .Write(&len, 1)
        .Write(reinterpret_cast<const unsigned char*>(name.data()), name.size())
        .Write(salt.data(), salt.size())
        .Write(owner.data(), owner.size())
        .Finalize(out.begin());
    return out;
}

uint256 NameSigHash(Span<const unsigned char> raw, NameRecordType type, const std::string& chain_id)
{
    CHashWriter writer = TaggedHash(std::string("BPS/") + TagWord(type) + "/v" +
                                    std::to_string(roster::RECORD_VERSION) + "/" + chain_id);
    const size_t signed_len = raw.size() >= SIG ? raw.size() - SIG : 0;
    writer.write(reinterpret_cast<const char*>(raw.data()), signed_len);
    return writer.GetSHA256();
}

bool SignNameRecord(const CKey& key, NameRecord& rec, const std::string& chain_id,
                    std::vector<unsigned char>& raw_out)
{
    if (rec.type == NameRecordType::COMMIT) {
        raw_out = SerializeNameRecord(rec);
        return true;
    }
    rec.sig.fill(0);
    std::vector<unsigned char> raw = SerializeNameRecord(rec);
    if (!key.SignSchnorr(NameSigHash(raw, rec.type, chain_id), Span<unsigned char>(rec.sig.data(), rec.sig.size()))) {
        return false;
    }
    raw_out = SerializeNameRecord(rec);
    return true;
}

bool VerifyNameRecord(const NameRecord& rec, Span<const unsigned char> raw,
                      const roster::KeyBytes& signer, const std::string& chain_id)
{
    if (rec.type == NameRecordType::COMMIT) return true;
    const XOnlyPubKey key(Span<const unsigned char>(signer.data(), signer.size()));
    return key.VerifySchnorr(NameSigHash(raw, rec.type, chain_id),
                             Span<const unsigned char>(rec.sig.data(), rec.sig.size()));
}

} // namespace names
