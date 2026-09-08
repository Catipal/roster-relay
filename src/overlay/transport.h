// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_TRANSPORT_H
#define BITCOIN_OVERLAY_TRANSPORT_H

#include <key.h>
#include <netaddress.h>
#include <overlay/handshake.h>
#include <overlay/session.h>
#include <pubkey.h>

#include <map>
#include <memory>
#include <vector>

namespace overlay {

/**
 * The overlay's state machine, deliberately without a socket.
 *
 * Everything that decides who is connected, which key opens what, and what to
 * send back lives here and is driven by handing it datagrams. The socket is a
 * thin wrapper around it. That split exists so the part where mistakes are
 * expensive can be tested exhaustively in a unit test - two of these passing
 * buffers to each other - rather than only against a live network where
 * failures are intermittent and hard to reproduce.
 *
 * One instance per node, holding every session that node has.
 *
 * Templated on how a peer is named. Hop sessions are keyed by address; sessions
 * that run end to end through a relay are keyed by the path they travel, since
 * the far end of a path has no address this node knows - that is the point of
 * it. The logic is identical either way, so it is written once.
 */
template <typename PeerKey>
class TransportT
{
public:
    /** What Receive() concluded about a datagram. */
    enum class Result {
        IGNORED,      //!< not ours, malformed, replayed, or unauthenticated
        HANDSHAKE,    //!< progressed a handshake; reply_out may be set
        ESTABLISHED,  //!< a session now exists with this peer
        PAYLOAD,      //!< payload_out holds application data
    };

    explicit TransportT(const CKey& static_key);

    /**
     * Begin a session with a peer whose identity comes from the roster.
     *
     * Produces the datagram to send. Starting again with the same peer
     * replaces any handshake already in flight, because a peer that never
     * answers must not pin a slot forever.
     */
    bool Connect(const PeerKey& peer, const CPubKey& peer_static,
                 std::vector<unsigned char>& datagram_out);

    /**
     * Feed one received datagram.
     *
     * `from` says where it came from - an address for a hop session, a path id
     * for one that runs end to end. Either way it is a hint for lookup and
     * never an identity: a UDP source address is forgeable and a path id is
     * known to the relay carrying it. What authenticates a peer is the
     * handshake, and afterwards the session key.
     */
    Result Receive(const PeerKey& from, const unsigned char* data, size_t len,
                   std::vector<unsigned char>& reply_out,
                   std::vector<unsigned char>& payload_out);

    /** Wrap application data for an established peer. */
    bool Send(const PeerKey& peer, const std::vector<unsigned char>& payload,
              std::vector<unsigned char>& datagram_out);

    bool HasSession(const PeerKey& peer) const;
    bool HasPendingHandshake(const PeerKey& peer) const;

    /** Who this peer proved itself to be. Invalid if there is no session. */
    CPubKey PeerIdentity(const PeerKey& peer) const;

    /** Drop everything for one peer. */
    void Forget(const PeerKey& peer);

    size_t SessionCount() const { return m_sessions.size(); }
    size_t PendingCount() const { return m_pending.size(); }

private:
    struct Pending {
        HandshakeInitiator initiator;
        CPubKey expected;
    };
    struct Established {
        std::unique_ptr<Session> session;
        CPubKey identity;
    };

    CKey m_static;
    std::map<PeerKey, Pending> m_pending;
    std::map<PeerKey, Established> m_sessions;
};

/** Sessions with an adjacent peer, named by where it is. */
using Transport = TransportT<CService>;

/** Sessions with the far end of a path, named by the path itself. */
using PathTransport = TransportT<uint64_t>;

} // namespace overlay

#endif // BITCOIN_OVERLAY_TRANSPORT_H
