// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_RELAY_H
#define BITCOIN_OVERLAY_RELAY_H

#include <overlay/path.h>
#include <overlay/socket.h>
#include <sync.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace overlay {

/**
 * The most application data one datagram carries end to end over a path.
 *
 * Every relay on a path adds a layer, and each layer costs its frame (38
 * bytes), the path header (9) and a length (2). Only the innermost layer is
 * padded; the ones wrapped around it are not, so the size a relay sees says
 * which padding bucket the payload fell in and nothing more. At this size the
 * innermost layer fills the 640-byte bucket and up to ten relays fit inside one
 * 1,200-byte datagram. Anything larger is split by the application.
 */
static constexpr size_t MAX_PATH_APP_PAYLOAD = 637;

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
    /**
     * Whether this node may open a session with `dest` because a path asked it
     * to. Set from the roster: yes only for a relay listed at that address
     * with that key. Without a policy nothing is dialled on anyone's behalf.
     */
    using DialPolicy = std::function<bool(const CService& dest, const CPubKey& key)>;
    /**
     * Whether this node, as a meeting point, registers `service`. Set from the
     * roster: only keys it lists, since a listing is what keeps one person from
     * filling meeting points with a thousand services. Without a policy any
     * service that proves its key is registered.
     */
    using IntroducePolicy = std::function<bool(const roster::KeyBytes& service)>;
    /**
     * Where to actually reach the next relay on a path. Given the key and the
     * address the roster lists, returns the address to dial - usually the same,
     * but a radio neighbour of a node with no internet to it is reached at a
     * local port instead, with `slow` set. Set from overlay/radio.h; without it
     * the roster address is used unchanged.
     */
    using NextHopResolver = std::function<CService(const CPubKey& key, const CService& listed, bool& slow)>;

    /** One stop on a circuit: where it listens and the key that must answer there. */
    struct CircuitHop {
        CService addr;
        CPubKey key;
    };

    explicit Relay(const CKey& static_key);

    bool Bind(const CService& listen_addr, std::string& error);
    bool Start(AppHandler app, PathHandler path = nullptr);
    void Stop();
    /**
     * Make anything waiting on the network give up now: paths being built,
     * answers being waited for. For shutdown, before the threads doing that
     * waiting are joined.
     */
    void Interrupt();

    void SetDialPolicy(DialPolicy policy);
    void SetIntroducePolicy(IntroducePolicy policy);
    void SetNextHopResolver(NextHopResolver resolver);

    bool Connect(const CService& peer, const CPubKey& peer_static);
    CService BoundAddress() const { return m_socket.BoundAddress(); }
    bool HasSession(const CService& peer) { return m_socket.HasSession(peer); }
    /** Who an adjacent peer proved itself to be - its roster key. */
    CPubKey PeerIdentity(const CService& peer) { return m_socket.PeerIdentity(peer); }
    bool HasPendingHandshake(const CService& peer) { return m_socket.HasPendingHandshake(peer); }

    /** Send application data straight to an adjacent peer. */
    bool SendApp(const CService& peer, const std::vector<unsigned char>& payload);

    /**
     * Ask `via` to carry traffic between us and `dest`.
     *
     * `via` is an adjacent peer for the first hop, or a path for any hop after
     * it - extending a path means asking its far end to build the next leg.
     * Without `dest_key` the asked relay only joins peers it already has
     * sessions with; with it, it may dial `dest` first if the roster lists that
     * key there.
     */
    bool BuildPath(uint64_t path_id, const Hop& via, const CService& dest,
                   const CPubKey& dest_key = CPubKey());

    /**
     * Wait for the answer to BuildPath: 1 accepted, 0 refused, -1 no answer.
     * Each answer is consumed by the wait that returns it.
     */
    int AwaitPath(uint64_t path_id, std::chrono::milliseconds timeout);

    /** Send bytes along a path. Every relay on it can read these. */
    bool SendOnPath(uint64_t path_id, const std::vector<unsigned char>& inner);

    /**
     * Begin an end-to-end session with the far end of a path.
     *
     * The handshake travels as ordinary path traffic, so the relays forward it
     * without being able to complete it: only the holder of `far_static` can,
     * and that key comes from the roster rather than from any relay.
     *
     * Anonymous by default: this side proves a key made for this handshake
     * alone, so the far end learns nothing about who built the path. A node
     * that has to be recognised - a service registering at its meeting point -
     * passes false and proves its roster key instead.
     */
    bool ConnectSecret(uint64_t path_id, const CPubKey& far_static, bool anonymous = true);

    /** True once the far end of this path has completed the exchange. */
    bool HasSecretSession(uint64_t path_id);

    /** Who the far end of a path proved itself to be, or invalid. */
    CPubKey SecretPeerIdentity(uint64_t path_id);

    /** Send data no relay on the path can read. */
    bool SendSecret(uint64_t path_id, const std::vector<unsigned char>& payload);

    /**
     * Build a path through `hops`, the last of which is the destination, with
     * an end-to-end session to each stop in turn.
     *
     * The first hop is reached directly and must already be, or become, an
     * adjacent session. Every later stop is asked through the part already
     * built and dials its successor if it has to. Blocks for up to
     * `step_timeout` per stop, retrying each step a few times, because these
     * are datagrams and any of them can be lost.
     *
     * On success `path_out` is the path to the destination: SendSecret on it
     * reaches the destination through every relay before it, and nothing on
     * the way can read it or learn who sent it.
     *
     * `prove_last` shows the destination this node's roster key instead of a
     * throwaway one, as a service must to register at a meeting point; every
     * relay before it still sees only throwaway keys.
     */
    bool BuildCircuit(const std::vector<CircuitHop>& hops, uint64_t& path_out, std::string& error,
                      std::chrono::milliseconds step_timeout = std::chrono::milliseconds{4000},
                      bool prove_last = false);

    /**
     * Forget a path this node built, and every leg under it that `legs` names.
     *
     * Local only: the relays forget theirs when it falls idle (PATH_TTL).
     */
    void ClosePath(const std::vector<uint64_t>& legs);

    /** The legs of the most recent circuit built, innermost last, for ClosePath. */
    std::vector<uint64_t> CircuitLegs(uint64_t path_id);

    /**
     * Register as reachable at the far end of a path.
     *
     * A service does this at each of its derived rendezvous points. The relay
     * learns only a key and a path - not where the service is, and not who
     * will come looking for it. The path's end-to-end session must have been
     * opened with ConnectSecret(..., false), proving that same key: otherwise
     * anyone could register as anyone, and the meeting point would splice
     * clients to an impostor. The meeting point answers, and AwaitPath on
     * `path_id` returns it; a registration lasts as long as its path, so
     * repeating it every few minutes keeps both alive.
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
    /** A request to extend a path to a relay this node is still dialling. */
    struct PendingBuild {
        uint64_t path_id;
        Hop from;
        CService dest;
        CPubKey key;
        int64_t deadline;
    };
    /** How long a dial on someone else's behalf may take, in seconds. */
    static constexpr int64_t PENDING_BUILD_TTL = 10;
    /** The same when the next relay is reached over radio, where a handshake is slower. */
    static constexpr int64_t RADIO_DIAL_TTL = 90;
    /** Bounded, because asking a relay to dial is something strangers do. */
    static constexpr size_t MAX_PENDING_BUILDS = 64;

    /** Dispatch one decrypted overlay message. */
    void OnMessage(const Hop& from, std::vector<unsigned char>&& msg);
    /** A session with an adjacent peer has just completed. */
    void OnEstablished(const CService& peer);
    /** Join `from` to `dest` as `path_id`, tell both, and answer `from`. */
    void FinishBuild(uint64_t path_id, const Hop& from, const CService& dest);
    /** Answer the builds that have waited too long for their dial. */
    void ExpirePendingBuilds();
    /** Seal an already-formed message for the far end of a path. */
    bool SendSecretRaw(uint64_t path_id, const std::vector<unsigned char>& msg);
    /**
     * Route a message to a hop, wrapping it for a path if that is what it is.
     *
     * `wrapping` is set when the message is itself another layer's ciphertext
     * on its way out: it was padded where it began, so it is not padded again.
     */
    bool SendToHop(const Hop& to, const std::vector<unsigned char>& msg, bool wrapping = false);
    /** Record the answer to a path request for AwaitPath. */
    void NoteResult(uint64_t path_id, bool ok);
    /** Forget registrations whose path is gone. */
    void PruneIntros() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    Socket m_socket;
    Mutex m_mutex;
    PathTable m_paths GUARDED_BY(m_mutex);
    // Sessions with the far ends of paths, keyed by path rather than address,
    // because the far end of a path has no address this node knows.
    PathTransport m_secret GUARDED_BY(m_mutex);
    // Services that have registered here, and the path each is reachable on.
    // Bounded like the path table: registering is something strangers do.
    std::map<roster::KeyBytes, uint64_t> m_intros GUARDED_BY(m_mutex);
    std::vector<PendingBuild> m_pending_builds GUARDED_BY(m_mutex);
    // Circuits this node built: the innermost path and the legs under it.
    std::map<uint64_t, std::vector<uint64_t>> m_circuits GUARDED_BY(m_mutex);
    DialPolicy m_dial GUARDED_BY(m_mutex);
    IntroducePolicy m_introduce GUARDED_BY(m_mutex);
    NextHopResolver m_next_hop GUARDED_BY(m_mutex);

    Mutex m_results_mutex;
    std::condition_variable m_results_cv;
    std::map<uint64_t, bool> m_results GUARDED_BY(m_results_mutex);

    AppHandler m_app;
    PathHandler m_path;
    std::atomic<bool> m_interrupted{false};
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
