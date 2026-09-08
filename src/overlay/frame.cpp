// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/frame.h>

#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <crypto/poly1305.h>
#include <support/cleanse.h>

#include <cstring>

namespace overlay {

namespace {

/** Zero padding to the next multiple of 16, as the AEAD construction requires. */
void PadTo16(std::vector<unsigned char>& v)
{
    const size_t rem = v.size() % 16;
    if (rem != 0) v.insert(v.end(), 16 - rem, 0);
}

/**
 * ChaCha20-Poly1305 over one datagram.
 *
 * The construction is RFC 8439's, adapted to this tree's ChaCha20, which takes
 * a 64-bit nonce and a 64-bit block counter rather than the RFC's 96/32 split.
 * That is safe here because the key is fresh per session and per direction and
 * the nonce is a counter that only increases, so a (key, nonce) pair is never
 * used twice - which is the single property the whole construction rests on.
 *
 * Block 0 of the keystream provides the one-time Poly1305 key; the ciphertext
 * starts at block 1, so the two never overlap.
 */
void ComputeTag(const FrameKey& key, uint64_t nonce,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* ct, size_t ct_len,
                unsigned char out[POLY1305_TAGLEN])
{
    ChaCha20 chacha;
    chacha.SetKey(key.data(), key.size());
    chacha.SetIV(nonce);
    chacha.Seek(0);

    unsigned char block0[64];
    chacha.Keystream(block0, sizeof(block0));

    std::vector<unsigned char> mac_input;
    mac_input.insert(mac_input.end(), aad, aad + aad_len);
    PadTo16(mac_input);
    mac_input.insert(mac_input.end(), ct, ct + ct_len);
    PadTo16(mac_input);

    unsigned char lengths[16];
    WriteLE64(lengths, static_cast<uint64_t>(aad_len));
    WriteLE64(lengths + 8, static_cast<uint64_t>(ct_len));
    mac_input.insert(mac_input.end(), lengths, lengths + sizeof(lengths));

    poly1305_auth(out, mac_input.data(), mac_input.size(), block0);

    memory_cleanse(block0, sizeof(block0));
}

void Keystream(const FrameKey& key, uint64_t nonce, const unsigned char* in,
               unsigned char* out, size_t len)
{
    ChaCha20 chacha;
    chacha.SetKey(key.data(), key.size());
    chacha.SetIV(nonce);
    chacha.Seek(1); // block 0 is reserved for the Poly1305 key
    chacha.Crypt(in, out, len);
}

void WriteHeader(unsigned char* out, FrameType type, uint64_t session, uint64_t counter)
{
    std::memcpy(out, FRAME_MAGIC, sizeof(FRAME_MAGIC));
    out[4] = FRAME_VERSION;
    out[5] = static_cast<unsigned char>(type);
    WriteLE64(out + 6, session);
    WriteLE64(out + 14, counter);
}

bool KnownType(uint8_t raw, FrameType& out)
{
    switch (raw) {
    case static_cast<uint8_t>(FrameType::HANDSHAKE_INIT):
    case static_cast<uint8_t>(FrameType::HANDSHAKE_RESP):
    case static_cast<uint8_t>(FrameType::DATA):
        out = static_cast<FrameType>(raw);
        return true;
    default:
        return false;
    }
}

} // namespace

bool SealFrame(const FrameKey& key, FrameType type, uint64_t session,
               uint64_t counter, const std::vector<unsigned char>& payload,
               std::vector<unsigned char>& out)
{
    if (payload.size() > MAX_FRAME_PAYLOAD) return false;

    out.assign(FRAME_HEADER_SIZE + payload.size() + FRAME_TAG_SIZE, 0);
    WriteHeader(out.data(), type, session, counter);

    if (!payload.empty()) {
        Keystream(key, counter, payload.data(), out.data() + FRAME_HEADER_SIZE,
                  payload.size());
    }

    // The header is authenticated but not encrypted: a receiver has to read the
    // session before it can pick a key, so it cannot be hidden - but it can be
    // made impossible to alter, which is what covering it as AAD does.
    ComputeTag(key, counter, out.data(), FRAME_HEADER_SIZE,
               out.data() + FRAME_HEADER_SIZE, payload.size(),
               out.data() + FRAME_HEADER_SIZE + payload.size());
    return true;
}

bool OpenFrame(const FrameKey& key, const unsigned char* data, size_t len,
               FrameType& type_out, uint64_t& session_out,
               uint64_t& counter_out, std::vector<unsigned char>& payload_out)
{
    if (len < FRAME_OVERHEAD || len > SAFE_DATAGRAM) return false;
    if (std::memcmp(data, FRAME_MAGIC, sizeof(FRAME_MAGIC)) != 0) return false;
    if (data[4] != FRAME_VERSION) return false;

    FrameType type;
    if (!KnownType(data[5], type)) return false;

    const uint64_t session = ReadLE64(data + 6);
    const uint64_t counter = ReadLE64(data + 14);
    const size_t ct_len = len - FRAME_OVERHEAD;
    const unsigned char* ct = data + FRAME_HEADER_SIZE;

    // Authenticate before decrypting, so a forged datagram never produces
    // plaintext that a caller might act on.
    unsigned char expected[POLY1305_TAGLEN];
    ComputeTag(key, counter, data, FRAME_HEADER_SIZE, ct, ct_len, expected);

    const unsigned char* given = ct + ct_len;
    // Constant time: a byte-at-a-time compare leaks how much of a forged tag
    // was correct, which is enough to forge one byte at a time.
    unsigned char diff = 0;
    for (size_t i = 0; i < POLY1305_TAGLEN; ++i) diff |= expected[i] ^ given[i];
    memory_cleanse(expected, sizeof(expected));
    if (diff != 0) return false;

    payload_out.assign(ct_len, 0);
    if (ct_len != 0) Keystream(key, counter, ct, payload_out.data(), ct_len);

    type_out = type;
    session_out = session;
    counter_out = counter;
    return true;
}

bool PeekFrame(const unsigned char* data, size_t len, FrameType& type_out,
               uint64_t& session_out, uint64_t& counter_out)
{
    if (len < FRAME_HEADER_SIZE || len > SAFE_DATAGRAM) return false;
    if (std::memcmp(data, FRAME_MAGIC, sizeof(FRAME_MAGIC)) != 0) return false;
    if (data[4] != FRAME_VERSION) return false;
    if (!KnownType(data[5], type_out)) return false;
    session_out = ReadLE64(data + 6);
    counter_out = ReadLE64(data + 14);
    return true;
}

void WriteFrameHeader(FrameType type, uint64_t session, uint64_t counter,
                      std::vector<unsigned char>& out)
{
    const size_t at = out.size();
    out.resize(at + FRAME_HEADER_SIZE);
    WriteHeader(out.data() + at, type, session, counter);
}

void AeadSeal(const FrameKey& key, uint64_t nonce, const unsigned char* aad,
              size_t aad_len, const std::vector<unsigned char>& plaintext,
              std::vector<unsigned char>& out)
{
    out.assign(plaintext.size() + FRAME_TAG_SIZE, 0);
    if (!plaintext.empty()) {
        Keystream(key, nonce, plaintext.data(), out.data(), plaintext.size());
    }
    ComputeTag(key, nonce, aad, aad_len, out.data(), plaintext.size(),
               out.data() + plaintext.size());
}

bool AeadOpen(const FrameKey& key, uint64_t nonce, const unsigned char* aad,
              size_t aad_len, const unsigned char* data, size_t len,
              std::vector<unsigned char>& out)
{
    if (len < FRAME_TAG_SIZE) return false;
    const size_t ct_len = len - FRAME_TAG_SIZE;

    unsigned char expected[POLY1305_TAGLEN];
    ComputeTag(key, nonce, aad, aad_len, data, ct_len, expected);

    unsigned char diff = 0;
    for (size_t i = 0; i < POLY1305_TAGLEN; ++i) diff |= expected[i] ^ data[ct_len + i];
    memory_cleanse(expected, sizeof(expected));
    if (diff != 0) return false;

    out.assign(ct_len, 0);
    if (ct_len != 0) Keystream(key, nonce, data, out.data(), ct_len);
    return true;
}

bool ReplayWindow::Accept(uint64_t counter)
{
    if (!m_any) {
        m_any = true;
        m_highest = counter;
        m_seen = 1;
        return true;
    }

    if (counter > m_highest) {
        const uint64_t advance = counter - m_highest;
        // Shifting by 64 or more is undefined, and anything that far ahead
        // clears the window outright anyway.
        m_seen = (advance >= WINDOW) ? 0 : (m_seen << advance);
        m_seen |= 1;
        m_highest = counter;
        return true;
    }

    const uint64_t behind = m_highest - counter;
    if (behind >= WINDOW) return false; // too old to prove it is not a replay
    const uint64_t bit = uint64_t{1} << behind;
    if (m_seen & bit) return false;     // seen already
    m_seen |= bit;
    return true;
}

} // namespace overlay
