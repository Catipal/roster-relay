// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/handshake.h>

#include <crypto/hkdf_sha256_32.h>
#include <crypto/sha256.h>
#include <random.h>
#include <support/cleanse.h>

#include <cstring>

namespace overlay {

namespace {

const std::string PROTOCOL_NAME = "BPS/overlay/handshake/v1";
const std::string INFO_CHAIN = "BPS/overlay/v1/chain";
const std::string INFO_KEY = "BPS/overlay/v1/key";
const std::string INFO_I2R = "BPS/overlay/v1/i2r";
const std::string INFO_R2I = "BPS/overlay/v1/r2i";
const std::string INFO_SESSION = "BPS/overlay/v1/session";

/** h = SHA256(h || data), binding every public value into the transcript. */
void MixHash(uint256& h, const unsigned char* data, size_t len)
{
    CSHA256().Write(h.begin(), 32).Write(data, len).Finalize(h.begin());
}

/**
 * Fold a shared secret into the chaining key and derive a message key.
 *
 * Two outputs from one extraction, which is HKDF used the way Noise uses it:
 * the chaining key carries every secret mixed so far, so the final session keys
 * depend on all four Diffie-Hellman results and not just the last.
 */
void MixKey(uint256& ck, const uint256& ikm, FrameKey& key_out)
{
    const std::string salt(reinterpret_cast<const char*>(ck.begin()), 32);
    CHKDF_HMAC_SHA256_L32 hkdf(ikm.begin(), 32, salt);

    unsigned char next_ck[32];
    hkdf.Expand32(INFO_CHAIN, next_ck);
    hkdf.Expand32(INFO_KEY, key_out.data());
    std::memcpy(ck.begin(), next_ck, 32);
    memory_cleanse(next_ck, sizeof(next_ck));
}

/** Serialise a public key, compressed. False if it is not usable. */
bool Serialize(const CPubKey& pub, unsigned char out[HANDSHAKE_PUBKEY_SIZE])
{
    if (!pub.IsValid() || pub.size() != HANDSHAKE_PUBKEY_SIZE) return false;
    std::memcpy(out, pub.begin(), HANDSHAKE_PUBKEY_SIZE);
    return true;
}

CKey NewEphemeral()
{
    CKey k;
    k.MakeNewKey(true);
    return k;
}

void SplitSession(const uint256& ck, const uint256& h, bool initiator, SessionKeys& out)
{
    const std::string salt(reinterpret_cast<const char*>(ck.begin()), 32);
    CHKDF_HMAC_SHA256_L32 hkdf(h.begin(), 32, salt);

    FrameKey i2r, r2i;
    hkdf.Expand32(INFO_I2R, i2r.data());
    hkdf.Expand32(INFO_R2I, r2i.data());

    // Each direction gets its own key, so a frame cannot be reflected back at
    // its sender and accepted as though the peer had sent it.
    out.send = initiator ? i2r : r2i;
    out.recv = initiator ? r2i : i2r;

    unsigned char sid[32];
    hkdf.Expand32(INFO_SESSION, sid);
    out.session_id = ReadLE64(sid);

    memory_cleanse(i2r.data(), i2r.size());
    memory_cleanse(r2i.data(), r2i.size());
    memory_cleanse(sid, sizeof(sid));
}

} // namespace

void SessionKeys::Clear()
{
    memory_cleanse(send.data(), send.size());
    memory_cleanse(recv.data(), recv.size());
    session_id = 0;
}

HandshakeInitiator::~HandshakeInitiator()
{
    memory_cleanse(m_ck.begin(), 32);
    memory_cleanse(m_h.begin(), 32);
}

bool HandshakeInitiator::Start(const CKey& static_key, const CPubKey& responder_static,
                               std::vector<unsigned char>& msg1_out)
{
    if (m_started) return false;
    if (!static_key.IsValid() || !responder_static.IsValid()) return false;

    unsigned char rs[HANDSHAKE_PUBKEY_SIZE];
    if (!Serialize(responder_static, rs)) return false;

    CSHA256().Write(reinterpret_cast<const unsigned char*>(PROTOCOL_NAME.data()),
                    PROTOCOL_NAME.size())
        .Finalize(m_ck.begin());
    m_h = m_ck;
    // Binding the responder's identity means a message built for one peer can
    // never be replayed at another.
    MixHash(m_h, rs, sizeof(rs));

    m_static = static_key;
    m_ephemeral = NewEphemeral();
    if (!m_ephemeral.IsValid()) return false;

    unsigned char e_pub[HANDSHAKE_PUBKEY_SIZE];
    if (!Serialize(m_ephemeral.GetPubKey(), e_pub)) return false;
    MixHash(m_h, e_pub, sizeof(e_pub));

    uint256 es;
    if (!responder_static.ECDH(m_ephemeral.begin(), es)) return false;
    FrameKey k1;
    MixKey(m_ck, es, k1);
    memory_cleanse(es.begin(), 32);

    unsigned char s_pub[HANDSHAKE_PUBKEY_SIZE];
    if (!Serialize(m_static.GetPubKey(), s_pub)) return false;
    std::vector<unsigned char> enc_static;
    AeadSeal(k1, 0, m_h.begin(), 32,
             std::vector<unsigned char>(s_pub, s_pub + sizeof(s_pub)), enc_static);
    memory_cleanse(k1.data(), k1.size());
    MixHash(m_h, enc_static.data(), enc_static.size());

    uint256 ss;
    if (!responder_static.ECDH(m_static.begin(), ss)) return false;
    FrameKey k2;
    MixKey(m_ck, ss, k2);
    memory_cleanse(ss.begin(), 32);

    // An empty payload sealed under k2: it carries nothing, but only a party
    // holding the initiator's static key could have produced it, which is what
    // proves identity to the responder.
    std::vector<unsigned char> confirm;
    AeadSeal(k2, 0, m_h.begin(), 32, std::vector<unsigned char>(), confirm);
    memory_cleanse(k2.data(), k2.size());
    MixHash(m_h, confirm.data(), confirm.size());

    msg1_out.clear();
    msg1_out.insert(msg1_out.end(), e_pub, e_pub + sizeof(e_pub));
    msg1_out.insert(msg1_out.end(), enc_static.begin(), enc_static.end());
    msg1_out.insert(msg1_out.end(), confirm.begin(), confirm.end());

    m_started = true;
    return msg1_out.size() == HANDSHAKE_INIT_SIZE;
}

bool HandshakeInitiator::Finish(const unsigned char* msg2, size_t len, SessionKeys& out)
{
    if (!m_started || m_consumed) return false;
    // Everything below advances the transcript, so this attempt is spent
    // whether or not it succeeds.
    m_consumed = true;
    if (len != HANDSHAKE_RESP_SIZE) return false;

    CPubKey re(msg2, msg2 + HANDSHAKE_PUBKEY_SIZE);
    if (!re.IsValid()) return false;
    MixHash(m_h, msg2, HANDSHAKE_PUBKEY_SIZE);

    uint256 ee;
    if (!re.ECDH(m_ephemeral.begin(), ee)) return false;
    FrameKey k3;
    MixKey(m_ck, ee, k3);
    memory_cleanse(ee.begin(), 32);
    memory_cleanse(k3.data(), k3.size());

    uint256 se;
    if (!re.ECDH(m_static.begin(), se)) return false;
    FrameKey k4;
    MixKey(m_ck, se, k4);
    memory_cleanse(se.begin(), 32);

    std::vector<unsigned char> plain;
    const bool ok = AeadOpen(k4, 0, m_h.begin(), 32, msg2 + HANDSHAKE_PUBKEY_SIZE,
                             FRAME_TAG_SIZE, plain);
    memory_cleanse(k4.data(), k4.size());
    // A failed tag here means the far side did not hold the static key we
    // encrypted to, so it is not the peer the roster named.
    if (!ok || !plain.empty()) return false;

    MixHash(m_h, msg2 + HANDSHAKE_PUBKEY_SIZE, FRAME_TAG_SIZE);
    SplitSession(m_ck, m_h, /*initiator=*/true, out);
    return true;
}

bool HandshakeResponder::Accept(const CKey& static_key, const unsigned char* msg1,
                                size_t len, CPubKey& initiator_out,
                                std::vector<unsigned char>& msg2_out,
                                SessionKeys& keys_out)
{
    if (!static_key.IsValid()) return false;
    if (len != HANDSHAKE_INIT_SIZE) return false;

    unsigned char rs[HANDSHAKE_PUBKEY_SIZE];
    if (!Serialize(static_key.GetPubKey(), rs)) return false;

    uint256 ck, h;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(PROTOCOL_NAME.data()),
                    PROTOCOL_NAME.size())
        .Finalize(ck.begin());
    h = ck;
    MixHash(h, rs, sizeof(rs));

    const unsigned char* p = msg1;
    CPubKey e(p, p + HANDSHAKE_PUBKEY_SIZE);
    if (!e.IsValid()) return false;
    MixHash(h, p, HANDSHAKE_PUBKEY_SIZE);
    p += HANDSHAKE_PUBKEY_SIZE;

    uint256 es;
    if (!e.ECDH(static_key.begin(), es)) return false;
    FrameKey k1;
    MixKey(ck, es, k1);
    memory_cleanse(es.begin(), 32);

    const size_t enc_static_len = HANDSHAKE_PUBKEY_SIZE + FRAME_TAG_SIZE;
    std::vector<unsigned char> s_pub_bytes;
    const bool got_static = AeadOpen(k1, 0, h.begin(), 32, p, enc_static_len, s_pub_bytes);
    memory_cleanse(k1.data(), k1.size());
    if (!got_static || s_pub_bytes.size() != HANDSHAKE_PUBKEY_SIZE) return false;

    CPubKey s(s_pub_bytes.begin(), s_pub_bytes.end());
    if (!s.IsValid()) return false;
    MixHash(h, p, enc_static_len);
    p += enc_static_len;

    uint256 ss;
    if (!s.ECDH(static_key.begin(), ss)) return false;
    FrameKey k2;
    MixKey(ck, ss, k2);
    memory_cleanse(ss.begin(), 32);

    std::vector<unsigned char> empty_out;
    const bool confirmed = AeadOpen(k2, 0, h.begin(), 32, p, FRAME_TAG_SIZE, empty_out);
    memory_cleanse(k2.data(), k2.size());
    // Until this tag verifies, the static key just decrypted is only a claim.
    if (!confirmed || !empty_out.empty()) return false;
    MixHash(h, p, FRAME_TAG_SIZE);

    CKey re = NewEphemeral();
    if (!re.IsValid()) return false;
    unsigned char re_pub[HANDSHAKE_PUBKEY_SIZE];
    if (!Serialize(re.GetPubKey(), re_pub)) return false;
    MixHash(h, re_pub, sizeof(re_pub));

    uint256 ee;
    if (!e.ECDH(re.begin(), ee)) return false;
    FrameKey k3;
    MixKey(ck, ee, k3);
    memory_cleanse(ee.begin(), 32);
    memory_cleanse(k3.data(), k3.size());

    uint256 se;
    if (!s.ECDH(re.begin(), se)) return false;
    FrameKey k4;
    MixKey(ck, se, k4);
    memory_cleanse(se.begin(), 32);

    std::vector<unsigned char> confirm;
    AeadSeal(k4, 0, h.begin(), 32, std::vector<unsigned char>(), confirm);
    memory_cleanse(k4.data(), k4.size());
    MixHash(h, confirm.data(), confirm.size());

    msg2_out.clear();
    msg2_out.insert(msg2_out.end(), re_pub, re_pub + sizeof(re_pub));
    msg2_out.insert(msg2_out.end(), confirm.begin(), confirm.end());
    if (msg2_out.size() != HANDSHAKE_RESP_SIZE) return false;

    SplitSession(ck, h, /*initiator=*/false, keys_out);
    initiator_out = s;

    memory_cleanse(ck.begin(), 32);
    memory_cleanse(h.begin(), 32);
    return true;
}

} // namespace overlay
