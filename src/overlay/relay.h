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
 * Traffic can travel two ways. SendVia hands the relay bytes it can read, which
 * is enough when the point is only that the far end sees the relay rather than
 * the origin. SendSecret runs a second handshake with the far end THROUGH the
 * path, so the relay carries ciphertext it holds no key for - it still learns
 * that two of its peers are talking and how much, but not what.
 *
 * One relay is still one relay. It knows both ends by address even when it
 * cannot read them, so this resists a curious relay rather than a hostile one.
 * Not being in a position to know both ends needs more than one hop, which is
 * what remains after this.
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

    /** Send bytes along an established path. The relay can read these. */
    bool SendVia(const CService& via, uint64_t path_id,
                 const std::vector<unsigned char>& inner);

    /**
     * Begin an end-to-end session with the far end of a path.
     *
     * The handshake travels as ordinary path traffic, so the relay forwards it
     * without being able to complete it: only the holder of `far_static` can,
     * and that key comes from the roster rather than from the relay.
     */
    bool ConnectSecret(const CService& via, uint64_t path_id,
                       const CPubKey& far_static);

    /** True once the far end of this path has completed the exchange. */
    bool HasSecretSession(uint64_t path_id);

    /** Send data the relay carrying it cannot read. */
    bool SendSecret(const CService& via, uint64_t path_id,
                    const std::vector<unsigned char>& payload);

    size_t PathCount();

private:
    void OnPayload(const CService& from, std::vector<unsigned char>&& msg);

    Socket m_socket;
    Mutex m_mutex;
    PathTable m_paths GUARDED_BY(m_mutex);
    // Sessions with the far ends of paths, keyed by path rather than address,
    // because the far end of a path has no address this node knows.
    PathTransport m_secret GUARDED_BY(m_mutex);
    AppHandler m_app;
    PathHandler m_path;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_RELAY_H
