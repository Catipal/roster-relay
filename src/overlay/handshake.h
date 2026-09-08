// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_HANDSHAKE_H
#define BITCOIN_OVERLAY_HANDSHAKE_H

#include <key.h>
#include <overlay/frame.h>
#include <pubkey.h>
#include <uint256.h>

#include <vector>

/**
 * The overlay's key agreement.
 *
 * A two-message exchange in the shape of Noise_IK: the responder's static
 * public key is known in advance - it is what the roster publishes - so the
 * initiator can encrypt to it immediately and the exchange completes in one
 * round trip.
 *
 * Four Diffie-Hellman operations are mixed in, and each buys something
 * specific:
 *
 *   es  initiator ephemeral x responder static   - only the intended responder
 *                                                  can proceed, so this
 *                                                  authenticates R to I
 *   ss  initiator static    x responder static   - authenticates I to R
 *   ee  both ephemerals                          - forward secrecy: recovering
 *                                                  either static key later does
 *                                                  not open recorded sessions
 *   se  initiator static    x responder ephemeral - binds I's identity to this
 *                                                  session rather than to any
 *                                                  session with R
 *
 * The initiator's static public key travels encrypted under a key derived from
 * es, so an observer sees only ephemeral keys and cannot tell who is
 * connecting. On an anonymity overlay that is the point, not a refinement.
 *
 * WARNING: this is a hand-written handshake. The frame layer beneath it fails
 * loudly when it is wrong; this does not - a mistake here yields a working
 * session that silently lacks a property it claims. It wants review by someone
 * who did not write it before anything real depends on it.
 */
namespace overlay {

/** What both sides end up with. */
struct SessionKeys {
    FrameKey send;      //!< keys this side seals with
    FrameKey recv;      //!< keys this side opens with
    uint64_t session_id{0};

    void Clear();
};

/** Wire sizes, so callers can size buffers without guessing. */
static constexpr size_t HANDSHAKE_PUBKEY_SIZE = 33; //!< compressed secp256k1
static constexpr size_t HANDSHAKE_INIT_SIZE =
    HANDSHAKE_PUBKEY_SIZE                       // initiator ephemeral
    + HANDSHAKE_PUBKEY_SIZE + FRAME_TAG_SIZE    // encrypted static key
    + FRAME_TAG_SIZE;                           // confirmation tag
static constexpr size_t HANDSHAKE_RESP_SIZE =
    HANDSHAKE_PUBKEY_SIZE + FRAME_TAG_SIZE;

class HandshakeInitiator
{
public:
    /**
     * Produce the first message.
     *
     * `responder_static` is the peer's identity as published in the roster, so
     * a session can only be completed by the peer the chain actually lists.
     */
    bool Start(const CKey& static_key, const CPubKey& responder_static,
               std::vector<unsigned char>& msg1_out);

    /** Consume the reply and derive the session. */
    bool Finish(const unsigned char* msg2, size_t len, SessionKeys& out);

    ~HandshakeInitiator();

private:
    uint256 m_ck;
    uint256 m_h;
    CKey m_ephemeral;
    CKey m_static;
    bool m_started{false};
};

class HandshakeResponder
{
public:
    /**
     * Consume the first message, produce the reply, and derive the session.
     *
     * `initiator_out` is who the far side proved itself to be. A caller that
     * cares which peers may connect checks it against the roster - this layer
     * establishes identity, it does not decide who is welcome.
     */
    bool Accept(const CKey& static_key, const unsigned char* msg1, size_t len,
                CPubKey& initiator_out, std::vector<unsigned char>& msg2_out,
                SessionKeys& keys_out);
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_HANDSHAKE_H
