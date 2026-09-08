// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_FRAME_H
#define BITCOIN_OVERLAY_FRAME_H

#include <array>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

/**
 * The overlay's datagram format.
 *
 * This is the bottom of the routing layer: one encrypted, authenticated UDP
 * datagram between two adjacent hops. Everything above - path building, onion
 * layering, rendezvous - is this frame repeated, so the decisions here are hard
 * to revisit later and are made deliberately rather than by default.
 *
 * UDP rather than TCP, because a stream carried inside a stream makes the two
 * retransmission timers fight: throughput collapses under loss, one lost
 * segment stalls every hop behind it, and NAT traversal never arrives. Those
 * are properties of the transport, not of the implementation, so they cannot be
 * fixed above this layer.
 *
 * The header travels in clear because a receiver must find the session before
 * it can decrypt anything, but it is covered by the tag, so it cannot be
 * altered. Fragment bookkeeping lives *inside* the encrypted body instead, so
 * an observer cannot see how a message was split.
 */
namespace overlay {

/** So a stray datagram on this port is obviously not ours. */
static const unsigned char FRAME_MAGIC[4] = {'B', 'P', 'S', 'O'};

static constexpr uint8_t FRAME_VERSION = 1;

enum class FrameType : uint8_t {
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESP = 0x02,
    DATA = 0x03,
};

/**
 * The largest datagram that crosses the public internet intact.
 *
 * Not an MTU guess to be tuned later: anything above roughly this size gets IP
 * fragmented, and fragmented UDP is dropped by enough middleboxes that it fails
 * unpredictably rather than slowly. Every onion layer added above eats into
 * this budget, which is why the fragment header exists from the first commit
 * rather than being retrofitted once paths get long.
 */
static constexpr size_t SAFE_DATAGRAM = 1200;

/** magic(4) + version(1) + type(1) + session(8) + counter(8) */
static constexpr size_t FRAME_HEADER_SIZE = 22;
static constexpr size_t FRAME_TAG_SIZE = 16;
static constexpr size_t FRAME_OVERHEAD = FRAME_HEADER_SIZE + FRAME_TAG_SIZE;
static constexpr size_t MAX_FRAME_PAYLOAD = SAFE_DATAGRAM - FRAME_OVERHEAD;

/** msg_id(4) + index(2) + count(2), carried encrypted inside a DATA frame. */
static constexpr size_t FRAGMENT_HEADER_SIZE = 8;
static constexpr size_t MAX_FRAGMENT_PAYLOAD = MAX_FRAME_PAYLOAD - FRAGMENT_HEADER_SIZE;

using FrameKey = std::array<unsigned char, 32>;

/**
 * Encrypt and authenticate one frame.
 *
 * The nonce is the counter, so the caller must never reuse one under the same
 * key. Session keys are fresh per session and counters only ever increase,
 * which is what keeps that promise; there is no internal check, because a
 * silent repeat here destroys confidentiality and a caller that gets this wrong
 * needs to fail loudly in review rather than quietly at runtime.
 */
bool SealFrame(const FrameKey& key, FrameType type, uint64_t session,
               uint64_t counter, const std::vector<unsigned char>& payload,
               std::vector<unsigned char>& out);

/**
 * Authenticate and decrypt one frame.
 *
 * False for anything that is not a well-formed frame sealed under this key -
 * wrong magic, wrong version, truncated, or a failed tag. The tag is checked
 * before any plaintext is produced, so a forged datagram never yields bytes a
 * caller might act on.
 */
bool OpenFrame(const FrameKey& key, const unsigned char* data, size_t len,
               FrameType& type_out, uint64_t& session_out,
               uint64_t& counter_out, std::vector<unsigned char>& payload_out);

/**
 * ChaCha20-Poly1305 over an arbitrary buffer with explicit associated data.
 *
 * The handshake needs the same AEAD but has its own message layout rather than
 * the frame header, so it cannot go through SealFrame. Same nonce discipline
 * applies: never reuse one under a given key.
 */
void AeadSeal(const FrameKey& key, uint64_t nonce, const unsigned char* aad,
              size_t aad_len, const std::vector<unsigned char>& plaintext,
              std::vector<unsigned char>& out);

/** Counterpart to AeadSeal. False on a failed tag, before any plaintext exists. */
bool AeadOpen(const FrameKey& key, uint64_t nonce, const unsigned char* aad,
              size_t aad_len, const unsigned char* data, size_t len,
              std::vector<unsigned char>& out);

/**
 * Rejects replayed and long-delayed frames.
 *
 * UDP reorders, so a strictly increasing counter would drop legitimate traffic.
 * This keeps a sliding window of 64 counters behind the highest seen, which
 * tolerates reordering while making a replay - the same counter twice - fail.
 */
class ReplayWindow
{
public:
    /** True the first time a counter is seen, false if replayed or too old. */
    bool Accept(uint64_t counter);

    uint64_t Highest() const { return m_highest; }

private:
    static constexpr unsigned WINDOW = 64;
    uint64_t m_highest{0};
    uint64_t m_seen{0}; //!< bit i set means (m_highest - i) has been accepted
    bool m_any{false};
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_FRAME_H
