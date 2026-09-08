// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SOCKET_H
#define BITCOIN_OVERLAY_SOCKET_H

#include <compat.h>
#include <key.h>
#include <netaddress.h>
#include <overlay/transport.h>
#include <pubkey.h>
#include <sync.h>
#include <threadinterrupt.h>

#include <atomic>
#include <map>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace overlay {

/** Default port for the overlay, one above this chain's p2p port. */
static constexpr uint16_t DEFAULT_OVERLAY_PORT = 9346;

/** Whether the overlay listens at all. Off until it has been reviewed. */
static const bool DEFAULT_OVERLAY = false;

/**
 * A UDP socket driving a Transport.
 *
 * Deliberately thin. Every decision about who is connected and what may be
 * decrypted lives in Transport, which is tested without any of this; the job
 * here is to move bytes and to own the thread, so that a bug in socket
 * handling cannot quietly become a bug in the protocol.
 *
 * Existing p2p is untouched: this is its own socket on its own port, not a
 * change to CConnman, which is TCP by construction and would have to be made
 * generic to carry datagrams.
 */
class Socket
{
public:
    /** Called on the receive thread for each authenticated payload. */
    using PayloadHandler = std::function<void(const CService&, std::vector<unsigned char>&&)>;

    explicit Socket(const CKey& static_key);
    ~Socket();

    /** Open and bind. False with `error` set; nothing is started yet. */
    bool Bind(const CService& listen_addr, std::string& error);

    /** Begin the receive thread. Bind must have succeeded. */
    bool Start(PayloadHandler handler);

    /** Stop the thread and close the socket. Safe to call twice. */
    void Stop();

    /** Begin a session with a peer whose identity came from the roster. */
    bool Connect(const CService& peer, const CPubKey& peer_static);

    /** Send application data to an established peer. */
    bool Send(const CService& peer, const std::vector<unsigned char>& payload);

    bool HasSession(const CService& peer);
    size_t SessionCount();

    /** Handshakes dropped by the flood limit, for tests and diagnostics. */
    size_t HandshakesRefused();

    /** The address actually bound, which resolves a port of 0. */
    CService BoundAddress() const { return m_bound; }

private:
    void ThreadReceive();
    /** False when this datagram should be dropped before any key agreement. */
    bool AllowHandshake(const CService& from, int64_t now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool SendDatagram(const CService& to, const std::vector<unsigned char>& datagram);

    SOCKET m_socket{INVALID_SOCKET};
    CService m_bound;

    // Transport is not thread safe and is reached from both the receive thread
    // and whichever thread calls Connect or Send, so it is guarded rather than
    // made lock-free: this is not a hot path, and the alternative is the kind
    // of subtlety that hides protocol bugs.
    Mutex m_mutex;
    Transport m_transport GUARDED_BY(m_mutex);

    // Handshake flood control. A responder performs two Diffie-Hellman
    // operations before it learns anything at all about who is asking, so an
    // unmetered HANDSHAKE_INIT is free CPU for an attacker. Two limits, because
    // one is not enough: per source stops a single host, and the global cap is
    // what actually holds when sources are forged - which on UDP they can be,
    // freely.
    static constexpr int64_t RATE_WINDOW = 10;      //!< seconds
    static constexpr size_t PER_SOURCE_LIMIT = 10;  //!< handshakes per window
    static constexpr size_t GLOBAL_LIMIT = 200;     //!< handshakes per window
    static constexpr size_t MAX_TRACKED_SOURCES = 4096;
    std::map<CService, size_t> m_attempts GUARDED_BY(m_mutex);
    size_t m_global_attempts GUARDED_BY(m_mutex){0};
    int64_t m_window_start GUARDED_BY(m_mutex){0};
    size_t m_refused GUARDED_BY(m_mutex){0};

    PayloadHandler m_handler;
    std::thread m_thread;
    CThreadInterrupt m_interrupt;
    std::atomic<bool> m_running{false};
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_SOCKET_H
