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
 */
class Transport
{
public:
    /** What Receive() concluded about a datagram. */
    enum class Result {
        IGNORED,      //!< not ours, malformed, replayed, or unauthenticated
        HANDSHAKE,    //!< progressed a handshake; reply_out may be set
        ESTABLISHED,  //!< a session now exists with this peer
        PAYLOAD,      //!< payload_out holds application data
    };

    explicit Transport(const CKey& static_key);

    /**
     * Begin a session with a peer whose identity comes from the roster.
     *
     * Produces the datagram to send. Starting again with the same peer
     * replaces any handshake already in flight, because a peer that never
     * answers must not pin a slot forever.
     */
    bool Connect(const CService& peer, const CPubKey& peer_static,
                 std::vector<unsigned char>& datagram_out);

    /**
     * Feed one received datagram.
     *
     * `from` is the address it arrived from, which is a hint rather than an
     * identity - anyone can forge a source address on UDP. What authenticates
     * a peer is the handshake and afterwards the session key, never this.
     */
    Result Receive(const CService& from, const unsigned char* data, size_t len,
                   std::vector<unsigned char>& reply_out,
                   std::vector<unsigned char>& payload_out);

    /** Wrap application data for an established peer. */
    bool Send(const CService& peer, const std::vector<unsigned char>& payload,
              std::vector<unsigned char>& datagram_out);

    bool HasSession(const CService& peer) const;
    bool HasPendingHandshake(const CService& peer) const;

    /** Who this peer proved itself to be. Invalid if there is no session. */
    CPubKey PeerIdentity(const CService& peer) const;

    /** Drop everything for one peer. */
    void Forget(const CService& peer);

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
    std::map<CService, Pending> m_pending;
    std::map<CService, Established> m_sessions;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_TRANSPORT_H
