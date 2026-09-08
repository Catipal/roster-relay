// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_RELAY_H
#define BITCOIN_OVERLAY_RELAY_H

#include <overlay/path.h>
#include <overlay/socket.h>
#include <sync.h>

#include <functional>
#include <map>
#include <memory>

namespace overlay {

/**
 * A node that can carry other people's traffic, and build paths through others.
 *
 * Sits above Socket rather than inside it: the socket's job is to move bytes
 * and own the thread, and routing is a separate decision that should not be
 * able to break the transport by being wrong.
 *
 * Paths are extended one hop at a time, each extension travelling through the
 * part already built. So the first relay is asked over a direct session, the
 * second is asked through the first, and so on - which is why a peer is a Hop
 * rather than an address: past the first relay, the node doing the asking has
 * no address the asked node could learn.
 *
 * The layering that follows is what makes more than one hop worth having:
 *
 *   A -> R1  sees ciphertext for R2, and does not know C
 *   R1 -> R2 sees ciphertext for C, and does not know A
 *
 * Neither relay is in a position to know both ends, which is the property one
 * hop cannot provide however well it is encrypted.
 */
class Relay
{
public:
    /** Called with authenticated application data, and where it came from. */
    using AppHandler = std::function<void(const Hop&, std::vector<unsigned char>&&)>;
    /** Called when a path we asked for was accepted or refused. */
    using PathHandler = std::function<void(uint64_t path_id, bool ok)>;

    explicit Relay(const CKey& static_key);

    bool Bind(const CService& listen_addr, std::string& error);
    bool Start(AppHandler app, PathHandler path = nullptr);
    void Stop();

    bool Connect(const CService& peer, const CPubKey& peer_static);
    CService BoundAddress() const { return m_socket.BoundAddress(); }
    bool HasSession(const CService& peer) { return m_socket.HasSession(peer); }

    /** Send application data straight to an adjacent peer. */
    bool SendApp(const CService& peer, const std::vector<unsigned char>& payload);

    /**
     * Ask `via` to carry traffic between us and `dest`.
     *
     * `via` is an adjacent peer for the first hop, or a path for any hop after
     * it - extending a path means asking its far end to build the next leg.
     * The asked relay will only join peers it already has sessions with.
     */
    bool BuildPath(uint64_t path_id, const Hop& via, const CService& dest);

    /** Send bytes along a path. Every relay on it can read these. */
    bool SendOnPath(uint64_t path_id, const std::vector<unsigned char>& inner);

    /**
     * Begin an end-to-end session with the far end of a path.
     *
     * The handshake travels as ordinary path traffic, so the relays forward it
     * without being able to complete it: only the holder of `far_static` can,
     * and that key comes from the roster rather than from any relay.
     */
    bool ConnectSecret(uint64_t path_id, const CPubKey& far_static);

    /** True once the far end of this path has completed the exchange. */
    bool HasSecretSession(uint64_t path_id);

    /** Send data no relay on the path can read. */
    bool SendSecret(uint64_t path_id, const std::vector<unsigned char>& payload);

    /**
     * Register as reachable at the far end of a path.
     *
     * A service does this at each of its derived rendezvous points. The relay
     * learns only a key and a path - not where the service is, and not who
     * will come looking for it.
     */
    bool Introduce(uint64_t path_id, const roster::KeyBytes& service);

    /**
     * Ask the far end of a path to splice us to a service.
     *
     * On success both sides end up as ends of `meet_id`, which the relay joins
     * without either learning the other's address. Neither side had to look
     * anything up: the relay was chosen by arithmetic from the roster.
     */
    bool Meet(uint64_t path_id, const roster::KeyBytes& service, uint64_t meet_id);

    size_t PathCount();
    size_t IntroductionCount();

private:
    /** Dispatch one decrypted overlay message. */
    void OnMessage(const Hop& from, std::vector<unsigned char>&& msg);
    /** Seal an already-formed message for the far end of a path. */
    bool SendSecretRaw(uint64_t path_id, const std::vector<unsigned char>& msg);
    /** Route a message to a hop, wrapping it for a path if that is what it is. */
    bool SendToHop(const Hop& to, const std::vector<unsigned char>& msg);

    Socket m_socket;
    Mutex m_mutex;
    PathTable m_paths GUARDED_BY(m_mutex);
    // Sessions with the far ends of paths, keyed by path rather than address,
    // because the far end of a path has no address this node knows.
    PathTransport m_secret GUARDED_BY(m_mutex);
    // Services that have registered here, and the path each is reachable on.
    // Bounded like the path table: registering is something strangers do.
    std::map<roster::KeyBytes, uint64_t> m_intros GUARDED_BY(m_mutex);
    AppHandler m_app;
    PathHandler m_path;
};

/**
 * The running overlay, or null when -overlay is off.
 *
 * Declared here and defined in relay.cpp, the way the indexes are, so that
 * anything needing it does not have to reach into init.
 */
extern std::unique_ptr<Relay> g_overlay;

} // namespace overlay

#endif // BITCOIN_OVERLAY_RELAY_H
