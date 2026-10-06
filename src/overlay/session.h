// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SESSION_H
#define BITCOIN_OVERLAY_SESSION_H

#include <overlay/frame.h>
#include <overlay/handshake.h>

#include <stdint.h>
#include <vector>

namespace overlay {

/**
 * Padding, so a relay cannot read message sizes off the wire.
 *
 * Content is encrypted, but its length is not: a relay forwarding 41 bytes and
 * then 900 learns a great deal about what is being carried, and lengths alone
 * identify message types and fingerprint traffic. Padding to a handful of
 * buckets collapses that into almost no information.
 *
 * Buckets rather than always padding to the maximum, because a network where
 * every acknowledgement costs 1200 bytes is a network nobody runs. This is the
 * usual compromise and it is a compromise: an observer still learns which
 * bucket, which is a few bits.
 *
 * What this does NOT address, and no amount of padding will: timing and volume.
 * An adversary watching both ends of a path can correlate when things move and
 * how much, and that remains the open problem in this field rather than
 * something left undone here.
 */
static constexpr size_t SESSION_LENGTH_PREFIX = 2;
static constexpr size_t MAX_SESSION_PAYLOAD = MAX_FRAME_PAYLOAD - SESSION_LENGTH_PREFIX;

/** Every sealed payload is padded up to one of these. */
size_t PaddedSize(size_t payload_len);

/**
 * An established link to one peer.
 *
 * Holds what the handshake produced and everything that must not be got wrong
 * afterwards: a counter that never repeats, a replay window for the traffic
 * coming back, and the session id both sides agreed on.
 *
 * The counter is the AEAD nonce, so a repeat is not a bug that degrades
 * performance - it destroys confidentiality for both frames involved. That is
 * why Seal owns the counter rather than accepting one, and why exhaustion is a
 * refusal rather than a wrap.
 */
class Session
{
public:
    explicit Session(const SessionKeys& keys);
    ~Session();

    /**
     * Wrap a payload as a datagram ready to send.
     *
     * The payload is padded to a size bucket before sealing, so what goes on
     * the wire says almost nothing about how long the message was.
     *
     * `pad` false skips that, and exists for one caller: a path layer wrapping
     * traffic that was already padded where it began. Padding every layer
     * again would round each one up to the next bucket, and with three relays
     * that leaves room for barely sixty bytes of anything. The receiver does
     * not need to know which was used - the real length is always inside.
     *
     * False when the payload is too large for one frame, or when this session
     * has sent all the frames it safely can. Callers fragment above this.
     */
    bool Seal(const std::vector<unsigned char>& payload,
              std::vector<unsigned char>& datagram_out, bool pad = true);

    /**
     * Unwrap a received datagram.
     *
     * False for anything not sealed by this peer for this session, and for
     * replays. A frame that fails here is discarded, not answered: on a
     * connectionless transport, replying to junk is how a node becomes a
     * reflector for somebody else's traffic.
     */
    bool Open(const unsigned char* data, size_t len,
              std::vector<unsigned char>& payload_out);

    uint64_t Id() const { return m_id; }
    uint64_t FramesSent() const { return m_next_counter - 1; }

    /**
     * Frames this session may still send.
     *
     * Rekeying does not exist yet, so a session is finite by construction. The
     * ceiling is far beyond any plausible use - at a thousand frames a second
     * it is millions of years - but it is a real edge and it is checked rather
     * than assumed, because the failure mode if it were ever reached silently
     * is the worst one this design has.
     */
    uint64_t Remaining() const;

private:
    FrameKey m_send;
    FrameKey m_recv;
    uint64_t m_id;
    uint64_t m_next_counter{1}; //!< 0 is never used, so a zeroed struct is obvious
    ReplayWindow m_replay;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_SESSION_H
