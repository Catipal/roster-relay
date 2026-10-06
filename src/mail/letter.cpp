// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/letter.h>

#include <crypto/common.h>
#include <crypto/hkdf_sha256_32.h>
#include <crypto/mlkem768.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <overlay/frame.h>
#include <random.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/time.h>

#include <cstring>

namespace mail {

namespace {

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char b[8];
    WriteLE64(b, v);
    out.insert(out.end(), b, b + 8);
}

void PutU32(std::vector<unsigned char>& out, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    out.insert(out.end(), b, b + 4);
}

std::vector<unsigned char> Sha256(const unsigned char* data, size_t len)
{
    std::vector<unsigned char> out(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(data, len).Finalize(out.data());
    return out;
}

/** Everything in a mail key but its signature, which is what the signature covers. */
std::vector<unsigned char> PreKeyBody(const PreKey& key)
{
    std::vector<unsigned char> out;
    out.reserve(PREKEY_SIZE);
    out.push_back(MAIL_VERSION);
    out.insert(out.end(), key.owner.begin(), key.owner.end());
    PutU64(out, key.key_id);
    PutU64(out, (uint64_t)key.created);
    PutU64(out, (uint64_t)key.expires);
    out.insert(out.end(), key.ec_key.begin(), key.ec_key.end());
    out.insert(out.end(), key.kem_key.begin(), key.kem_key.end());
    return out;
}

uint256 PreKeySigHash(const PreKey& key, const std::string& chain_id)
{
    const std::vector<unsigned char> body = PreKeyBody(key);
    CHashWriter writer = TaggedHash("BPS/mail-key/v" + std::to_string(MAIL_VERSION) + "/" + chain_id);
    writer.write((const char*)body.data(), body.size());
    return writer.GetSHA256();
}

/**
 * The letter's key, from both exchanges and everything that names this
 * encryption: the header (recipient, key id, ephemeral key, ML-KEM ciphertext)
 * and the recipient's two public keys. Binding the public keys as well as the
 * ciphertext is what hybrid constructions such as X-Wing do, so a ciphertext
 * cannot be replayed against a different key that happens to decapsulate it.
 */
overlay::FrameKey LetterKey(const uint256& ecdh, const mlkem768::SharedSecret& kem,
                            const std::vector<unsigned char>& header, const CPubKey& ec_key,
                            const std::vector<unsigned char>& kem_key, const std::string& chain_id)
{
    unsigned char ikm[64];
    std::memcpy(ikm, ecdh.begin(), 32);
    std::memcpy(ikm + 32, kem.data(), 32);
    CHKDF_HMAC_SHA256_L32 hkdf(ikm, sizeof(ikm), "BPS mail v" + std::to_string(MAIL_VERSION) + " " + chain_id);
    memory_cleanse(ikm, sizeof(ikm));

    std::vector<unsigned char> keys(ec_key.begin(), ec_key.end());
    keys.insert(keys.end(), kem_key.begin(), kem_key.end());
    const std::vector<unsigned char> h1 = Sha256(header.data(), header.size());
    const std::vector<unsigned char> h2 = Sha256(keys.data(), keys.size());
    std::string info(h1.begin(), h1.end());
    info.append(h2.begin(), h2.end());

    overlay::FrameKey key;
    hkdf.Expand32(info, key.data());
    return key;
}

uint256 LetterSigHash(const std::vector<unsigned char>& header, const roster::KeyBytes& from,
                      int64_t sent, const std::string& subject, const std::string& body,
                      const std::string& chain_id)
{
    const std::vector<unsigned char> h = Sha256(header.data(), header.size());
    std::vector<unsigned char> msg(h.begin(), h.end());
    msg.insert(msg.end(), from.begin(), from.end());
    PutU64(msg, (uint64_t)sent);
    msg.push_back((unsigned char)subject.size());
    msg.insert(msg.end(), subject.begin(), subject.end());
    PutU32(msg, (uint32_t)body.size());
    msg.insert(msg.end(), body.begin(), body.end());
    CHashWriter writer = TaggedHash("BPS/mail/v" + std::to_string(MAIL_VERSION) + "/" + chain_id);
    writer.write((const char*)msg.data(), msg.size());
    return writer.GetSHA256();
}

void RandomBytes(unsigned char* out, size_t len)
{
    // GetStrongRandBytes gives at most 32 bytes a call.
    while (len > 0) {
        const size_t n = std::min<size_t>(len, 32);
        GetStrongRandBytes(out, (int)n);
        out += n;
        len -= n;
    }
}

} // namespace

roster::KeyBytes XOnly(const CPubKey& key)
{
    roster::KeyBytes out{};
    if (key.IsValid() && key.size() == CPubKey::COMPRESSED_SIZE) {
        std::copy(key.begin() + 1, key.end(), out.begin());
    }
    return out;
}

std::vector<unsigned char> SerializePreKey(const PreKey& key)
{
    std::vector<unsigned char> out = PreKeyBody(key);
    out.insert(out.end(), key.sig.begin(), key.sig.end());
    return out;
}

bool ParsePreKey(const std::vector<unsigned char>& raw, PreKey& out)
{
    if (raw.size() != PREKEY_SIZE || raw[0] != MAIL_VERSION) return false;
    const unsigned char* p = raw.data() + 1;
    std::copy(p, p + 32, out.owner.begin());
    p += 32;
    out.key_id = ReadLE64(p);
    p += 8;
    out.created = (int64_t)ReadLE64(p);
    p += 8;
    out.expires = (int64_t)ReadLE64(p);
    p += 8;
    out.ec_key.Set(p, p + CPubKey::COMPRESSED_SIZE);
    p += CPubKey::COMPRESSED_SIZE;
    out.kem_key.assign(p, p + mlkem768::PUBLIC_KEY_SIZE);
    p += mlkem768::PUBLIC_KEY_SIZE;
    std::copy(p, p + 64, out.sig.begin());
    return out.ec_key.IsFullyValid() && out.expires > out.created;
}

bool PublicPreKey(const CKey& owner, const std::string& chain_id, const PreKeySecret& secret,
                  PreKey& out)
{
    if (!owner.IsValid() || !secret.ec_secret.IsValid()) return false;
    if (secret.kem_public.size() != mlkem768::PUBLIC_KEY_SIZE) return false;
    out = PreKey();
    out.owner = XOnly(owner.GetPubKey());
    out.key_id = secret.key_id;
    out.created = secret.created;
    out.expires = secret.expires;
    out.ec_key = secret.ec_secret.GetPubKey();
    out.kem_key = secret.kem_public;
    return owner.SignSchnorr(PreKeySigHash(out, chain_id), Span<unsigned char>(out.sig.data(), out.sig.size()));
}

bool MakePreKey(const CKey& owner, const std::string& chain_id, uint64_t key_id, int64_t now,
                PreKey& public_out, PreKeySecret& secret_out)
{
    PreKeySecret secret;
    secret.key_id = key_id;
    secret.created = now;
    secret.expires = now + PREKEY_LIFETIME + PREKEY_GRACE;
    secret.ec_secret.MakeNewKey(true);

    unsigned char seed[mlkem768::SEED_SIZE];
    RandomBytes(seed, sizeof(seed));
    const bool made = mlkem768::KeyPairFromSeed(seed, secret.kem_public, secret.kem_secret);
    memory_cleanse(seed, sizeof(seed));
    if (!made) return false;

    if (!PublicPreKey(owner, chain_id, secret, public_out)) return false;
    secret_out = secret;
    memory_cleanse(secret.kem_secret.data(), secret.kem_secret.size());
    return true;
}

bool VerifyPreKey(const PreKey& key, const std::string& chain_id)
{
    if (!key.ec_key.IsFullyValid() || key.kem_key.size() != mlkem768::PUBLIC_KEY_SIZE) return false;
    if (key.expires <= key.created) return false;
    const XOnlyPubKey owner(Span<const unsigned char>(key.owner.data(), key.owner.size()));
    return owner.VerifySchnorr(PreKeySigHash(key, chain_id), Span<const unsigned char>(key.sig.data(), key.sig.size()));
}

bool ReadEnvelope(const std::vector<unsigned char>& envelope, roster::KeyBytes& recipient_out,
                  uint64_t& key_id_out)
{
    if (envelope.size() < ENVELOPE_HEADER_SIZE + PAD_TO + overlay::FRAME_TAG_SIZE) return false;
    if (envelope.size() > MAX_ENVELOPE_SIZE) return false;
    if (envelope[0] != MAIL_VERSION) return false;
    // Padded to whole blocks, so anything else was not made by Seal.
    if ((envelope.size() - ENVELOPE_HEADER_SIZE - overlay::FRAME_TAG_SIZE) % PAD_TO != 0) return false;
    std::copy(envelope.begin() + 1, envelope.begin() + 33, recipient_out.begin());
    key_id_out = ReadLE64(envelope.data() + 33);
    return true;
}

uint256 EnvelopeId(const std::vector<unsigned char>& envelope)
{
    uint256 id;
    CSHA256().Write(envelope.data(), envelope.size()).Finalize(id.begin());
    return id;
}

bool Seal(const CKey& sender, const PreKey& to, Letter& letter, const std::string& chain_id,
          std::vector<unsigned char>& envelope_out, std::string& error)
{
    envelope_out.clear();
    if (letter.to != to.owner) {
        error = "That mail key belongs to someone else.";
        return false;
    }
    if (letter.subject.size() > MAX_SUBJECT) {
        error = strprintf("The subject is longer than %u bytes.", (unsigned)MAX_SUBJECT);
        return false;
    }
    if (letter.body.size() > MAX_BODY) {
        error = strprintf("The letter is longer than %u bytes.", (unsigned)MAX_BODY);
        return false;
    }
    if (!to.ec_key.IsFullyValid() || to.kem_key.size() != mlkem768::PUBLIC_KEY_SIZE) {
        error = "The recipient's mail key is not usable.";
        return false;
    }
    letter.from = XOnly(sender.GetPubKey());
    if (letter.sent == 0) letter.sent = GetTime();

    // Classical half: a fresh key for this letter alone, so nothing about it
    // links to any other letter.
    CKey ephemeral;
    ephemeral.MakeNewKey(true);
    const CPubKey ephemeral_pub = ephemeral.GetPubKey();
    uint256 ecdh;
    if (!to.ec_key.ECDH(ephemeral.begin(), ecdh)) {
        error = "The recipient's mail key is not usable.";
        return false;
    }

    // Post-quantum half.
    unsigned char coins[mlkem768::COINS_SIZE];
    RandomBytes(coins, sizeof(coins));
    std::vector<unsigned char> kem_ct;
    mlkem768::SharedSecret kem;
    const bool encapsulated = mlkem768::Encapsulate(to.kem_key, coins, kem_ct, kem);
    memory_cleanse(coins, sizeof(coins));
    if (!encapsulated) {
        error = "The recipient's mail key is not a valid ML-KEM key.";
        return false;
    }

    std::vector<unsigned char> header;
    header.reserve(ENVELOPE_HEADER_SIZE);
    header.push_back(MAIL_VERSION);
    header.insert(header.end(), to.owner.begin(), to.owner.end());
    PutU64(header, to.key_id);
    header.insert(header.end(), ephemeral_pub.begin(), ephemeral_pub.end());
    header.insert(header.end(), kem_ct.begin(), kem_ct.end());

    overlay::FrameKey key = LetterKey(ecdh, kem, header, to.ec_key, to.kem_key, chain_id);
    memory_cleanse(ecdh.begin(), 32);
    memory_cleanse(kem.data(), kem.size());

    std::array<unsigned char, 64> sig;
    if (!sender.SignSchnorr(LetterSigHash(header, letter.from, letter.sent, letter.subject, letter.body, chain_id),
                            Span<unsigned char>(sig.data(), sig.size()))) {
        error = "Could not sign the letter.";
        return false;
    }

    std::vector<unsigned char> plain;
    plain.push_back(MAIL_VERSION);
    plain.insert(plain.end(), letter.from.begin(), letter.from.end());
    PutU64(plain, (uint64_t)letter.sent);
    plain.push_back((unsigned char)letter.subject.size());
    plain.insert(plain.end(), letter.subject.begin(), letter.subject.end());
    PutU32(plain, (uint32_t)letter.body.size());
    plain.insert(plain.end(), letter.body.begin(), letter.body.end());
    plain.insert(plain.end(), sig.begin(), sig.end());
    plain.resize(((plain.size() + PAD_TO - 1) / PAD_TO) * PAD_TO, 0);

    // One key, used once: the nonce can be zero.
    std::vector<unsigned char> sealed;
    overlay::AeadSeal(key, 0, header.data(), header.size(), plain, sealed);
    memory_cleanse(key.data(), key.size());
    memory_cleanse(plain.data(), plain.size());

    envelope_out = header;
    envelope_out.insert(envelope_out.end(), sealed.begin(), sealed.end());
    return true;
}

std::string OpenResultString(OpenResult r)
{
    switch (r) {
    case OpenResult::OK: return "ok";
    case OpenResult::MALFORMED: return "not a sealed letter";
    case OpenResult::NOT_FOR_US: return "addressed to someone else";
    case OpenResult::KEY_GONE: return "sealed to a mail key this node has deleted";
    case OpenResult::DAMAGED: return "damaged, or not sealed to this node's key";
    case OpenResult::FORGED: return "the sender's signature does not hold";
    }
    return "unknown";
}

OpenResult Open(const std::vector<unsigned char>& envelope, const roster::KeyBytes& self,
                const SecretLookup& secrets, const std::string& chain_id, Letter& out)
{
    roster::KeyBytes recipient;
    uint64_t key_id = 0;
    if (!ReadEnvelope(envelope, recipient, key_id)) return OpenResult::MALFORMED;
    if (recipient != self) return OpenResult::NOT_FOR_US;
    const PreKeySecret* secret = secrets ? secrets(key_id) : nullptr;
    if (secret == nullptr) return OpenResult::KEY_GONE;

    const std::vector<unsigned char> header(envelope.begin(), envelope.begin() + ENVELOPE_HEADER_SIZE);
    CPubKey ephemeral;
    ephemeral.Set(header.begin() + 41, header.begin() + 41 + CPubKey::COMPRESSED_SIZE);
    if (!ephemeral.IsFullyValid()) return OpenResult::MALFORMED;
    const std::vector<unsigned char> kem_ct(header.begin() + 41 + CPubKey::COMPRESSED_SIZE, header.end());

    uint256 ecdh;
    if (!ephemeral.ECDH(secret->ec_secret.begin(), ecdh)) return OpenResult::DAMAGED;
    mlkem768::SharedSecret kem;
    if (!mlkem768::Decapsulate(secret->kem_secret, kem_ct, kem)) return OpenResult::DAMAGED;

    overlay::FrameKey key = LetterKey(ecdh, kem, header, secret->ec_secret.GetPubKey(),
                                      secret->kem_public, chain_id);
    memory_cleanse(ecdh.begin(), 32);
    memory_cleanse(kem.data(), kem.size());

    std::vector<unsigned char> plain;
    const bool opened = overlay::AeadOpen(key, 0, header.data(), header.size(),
                                          envelope.data() + ENVELOPE_HEADER_SIZE,
                                          envelope.size() - ENVELOPE_HEADER_SIZE, plain);
    memory_cleanse(key.data(), key.size());
    if (!opened) return OpenResult::DAMAGED;

    // version(1) from(32) sent(8) subject_len(1) subject body_len(4) body sig(64) zeros
    Letter letter;
    size_t at = 0;
    if (plain.size() < 1 + 32 + 8 + 1 || plain[0] != MAIL_VERSION) return OpenResult::MALFORMED;
    at = 1;
    std::copy(plain.begin() + at, plain.begin() + at + 32, letter.from.begin());
    at += 32;
    letter.sent = (int64_t)ReadLE64(plain.data() + at);
    at += 8;
    const size_t subject_len = plain[at++];
    if (subject_len > MAX_SUBJECT || plain.size() < at + subject_len + 4) return OpenResult::MALFORMED;
    letter.subject.assign(plain.begin() + at, plain.begin() + at + subject_len);
    at += subject_len;
    const size_t body_len = ReadLE32(plain.data() + at);
    at += 4;
    if (body_len > MAX_BODY || plain.size() < at + body_len + 64) return OpenResult::MALFORMED;
    letter.body.assign(plain.begin() + at, plain.begin() + at + body_len);
    at += body_len;
    std::array<unsigned char, 64> sig;
    std::copy(plain.begin() + at, plain.begin() + at + 64, sig.begin());
    at += 64;
    // Padding is zeros and no more than one block of it; anything else is a
    // second way to write the same letter.
    if (plain.size() - at >= PAD_TO) return OpenResult::MALFORMED;
    for (size_t i = at; i < plain.size(); ++i) {
        if (plain[i] != 0) return OpenResult::MALFORMED;
    }
    memory_cleanse(plain.data(), plain.size());

    const XOnlyPubKey sender(Span<const unsigned char>(letter.from.data(), letter.from.size()));
    if (!sender.VerifySchnorr(LetterSigHash(header, letter.from, letter.sent, letter.subject, letter.body, chain_id),
                              Span<const unsigned char>(sig.data(), sig.size()))) {
        return OpenResult::FORGED;
    }
    letter.to = recipient;
    out = letter;
    return OpenResult::OK;
}

} // namespace mail
