// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_RELAY_H
#define BITCOIN_OVERLAY_RELAY_H

#include <overlay/path.h>
#include <overlay/socket.h>
#include <sync.h>

#include <functional>

namespace overlay {

/**
 * A node that can carry other people's traffic.
 *
 * Sits above Socket rather than inside it: the socket's job is to move bytes
 * and own the thread, and routing is a separate decision that should not be
 * able to break the transport by being wrong.
 *
 * The anonymity this provides at one hop is limited and worth stating plainly.
 * A relay forwarding a payload can read it, because the two ends share no key
 * it lacks. What it does buy is that the far end learns the relay's address
 * rather than the origin's. Layered encryption over longer paths is what makes
 * the relay blind, and that is the next stage, not this one.
 */
class Relay
{
public:
    using AppHandler = std::function<void(const CService&, std::vector<unsigned char>&&)>;
    /** Called when a path we asked for was accepted or refused. */
    using PathHandler = std::function<void(uint64_t path_id, bool ok)>;

    explicit Relay(const CKey& static_key);

    bool Bind(const CService& listen_addr, std::string& error);
    bool Start(AppHandler app, PathHandler path = nullptr);
    void Stop();

    bool Connect(const CService& peer, const CPubKey& peer_static);
    CService BoundAddress() const { return m_socket.BoundAddress(); }
    bool HasSession(const CService& peer) { return m_socket.HasSession(peer); }

    /** Send application data straight to a peer we have a session with. */
    bool SendApp(const CService& peer, const std::vector<unsigned char>& payload);

    /**
     * Ask `via` to carry traffic between us and `dest`.
     *
     * Both legs must already be sessions of the relay's, so the relay is asked
     * only to join two peers it already knows, never to dial somewhere new on
     * a stranger's say-so.
     */
    bool BuildPath(uint64_t path_id, const CService& via, const CService& dest);

    /** Send bytes along an established path. */
    bool SendVia(const CService& via, uint64_t path_id,
                 const std::vector<unsigned char>& inner);

    size_t PathCount();

private:
    void OnPayload(const CService& from, std::vector<unsigned char>&& msg);

    Socket m_socket;
    Mutex m_mutex;
    PathTable m_paths GUARDED_BY(m_mutex);
    AppHandler m_app;
    PathHandler m_path;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_RELAY_H
