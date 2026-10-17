// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_GATEWAYCLIENT_H
#define BITCOIN_OVERLAY_GATEWAYCLIENT_H

#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>
#include <overlay/limits.h>
#include <overlay/meeting.h>
#include <overlay/path.h>
#include <roster/record.h>
#include <sync.h>
#include <threadinterrupt.h>

#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

struct netif;
struct pbuf;

/**
 * Using the network's internet: the visitor's side of a gateway (design
 * note §8·7).
 *
 * The node keeps a few gateways met - each through its own relays to one of
 * the gateway's meeting points, so no gateway learns who is using it - and
 * sends each new connection to the next of them in turn, so no gateway sees
 * everything one person does. The connections themselves are the node's own
 * TCP/IP stack's (overlay/netstack.h): it holds them on an interface whose
 * other side is the overlay, and its packets go to the gateway chosen for
 * their connection. Programs reach it through the local proxy
 * (overlay/localproxy.h), or - all of a computer's traffic - through the
 * system-wide interface (overlay/sysif.h), whose packets are the computer's
 * own and go to the gateways as they are.
 *
 * Giving to get: a node uses the network's internet only
 * while its own gateway is on, or when it has no internet line of its own and
 * relays over radio instead. Gateways cannot check this without learning who
 * is asking, so the node checks itself.
 */
namespace overlay {

/** Gateways kept met at once. */
static constexpr int DEFAULT_GATEWAY_POOL = 3;
/** -gatewayhops: relays between this node and a gateway's meeting point. */
static constexpr int DEFAULT_GATEWAY_HOPS = 1;

class GatewayClient
{
public:
    /** Whether this node may use gateways now, and if not, why. */
    using Allowed = std::function<bool(std::string& why)>;
    /** The gateways the roster lists, this node's own key left out. */
    using Candidates = std::function<std::vector<roster::KeyBytes>()>;
    using Meeter = std::function<bool(const roster::KeyBytes& key, int hops, Meeting& out, std::string& error)>;
    using Closer = std::function<void(const Meeting& m)>;
    using Sender = std::function<bool(uint64_t path, const std::vector<uint8_t>& payload)>;
    using Resolved = std::function<void(ResolveStatus status, const std::vector<IpAddr>& addrs, uint32_t ttl)>;
    using GatewayGone = std::function<void(uint64_t path)>;
    /** A gateway's packet for the system-wide interface, and the meeting it came across. */
    using InterfaceSink = std::function<void(uint64_t path, std::vector<uint8_t>&& pkt)>;

    static constexpr int64_t HELLO_EVERY_MS = 60 * 1000;
    /** A gateway not heard from this long is let go; its meeting path has idled out. */
    static constexpr int64_t SILENT_LIMIT_MS = 3 * 60 * 1000;
    /**
     * With connections open through it, a gateway answers every few
     * moments; silent this long, it is gone, and the next connection goes
     * elsewhere instead of waiting out the idle limit.
     */
    static constexpr int64_t BUSY_SILENCE_MS = 30 * 1000;
    /**
     * A gateway that has missed its answer to the last HELLO gets no new
     * connections: its meeting path is probably gone - a relay on it restarted,
     * or it did - and the next connection should not be the one to find out.
     */
    static constexpr int64_t STALE_MS = HELLO_EVERY_MS + 20 * 1000;
    static constexpr int64_t RETRY_AFTER_MS = 60 * 1000;
    static constexpr int64_t OFF_RETRY_AFTER_MS = 10 * 60 * 1000;
    static constexpr int64_t RESOLVE_TIMEOUT_MS = 10 * 1000;
    static constexpr int64_t ALLOWED_CHECK_MS = 10 * 1000;

    GatewayClient(int pool, int hops, bool allow_local, Allowed allowed, Candidates candidates,
                  Meeter meet, Closer close, Sender send);
    ~GatewayClient();

    /** Needs the stack running (GetNetStack().Start). */
    bool Start(std::string& error);
    void Stop();

    /** Whether `path` is one of this node's meetings with a gateway. */
    bool Owns(uint64_t path) const;
    /** A gateway's message across one of those meetings. From the receive thread; never blocks. */
    void HandleApp(const Hop& from, std::vector<uint8_t>&& payload);

    /** Whether destinations on this computer's own network may be asked for (regtest). */
    bool LocalAllowed() const { return m_allow_local; }
    /** The address connections held by the node's own stack come from, for `version`. */
    static IpAddr StackAddress(uint8_t version);

    // Stack thread only.

    /** The meeting of the gateway a new connection to `port` should use: the next open one that carries it. */
    bool Choose(uint8_t protocol, uint16_t port, uint64_t& path);
    /** Whether any gateway is open at all. */
    bool AnyOpen() const;
    /** Send a connection's packets to the gateway on `path`. */
    void AddFlow(uint8_t protocol, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                 uint64_t path);
    void RemoveFlow(uint8_t protocol, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port);
    /** One IP packet to the gateway on `path`, in as many messages as it takes. */
    void SendPacket(uint64_t path, const std::vector<uint8_t>& pkt);
    /**
     * Bytes a connection through `path` may send now, and spending them.
     * Paced at PACE_SHARE of the default per-path relay cap
     * (overlay/limits.h), so an upload stays under the relays' caps rather
     * than being dropped at them, which stalls TCP.
     */
    uint64_t PaceAvailable(uint64_t path);
    void PaceUse(uint64_t path, size_t bytes);
    /** Look a name up at a gateway; `done` runs on the stack thread. */
    void Resolve(const std::string& name, uint8_t family, Resolved done);
    /** Called on the stack thread when a gateway leaves, so connections through it can end at once. */
    int AddGatewayGone(GatewayGone gone);
    void RemoveGatewayGone(int id);
    /**
     * Packets from gateways addressed to `v4` or `v6` go to `sink` instead of
     * the node's own stack: the system-wide interface's. Null to stop.
     */
    void SetInterface(const IpAddr& v4, const IpAddr& v6, InterfaceSink sink);

    /** From the stack's C callbacks. */
    void OnStackOutput(struct pbuf* p);

    struct GatewayView {
        roster::KeyBytes key{};
        bool known{false}; //!< whether it has said how it is yet
        GatewayState state{GatewayState::OFF};
        int64_t since{0};
        uint64_t flows{0};
    };
    struct Stats {
        bool allowed{false};
        std::string why;
        int hops{0};
        std::vector<GatewayView> gateways;
        uint64_t flows{0};
        uint64_t lookups{0};
        uint64_t meetings_failed{0};
        std::string last_error;
    };
    Stats GetStats() const;

private:
    struct Entry {
        roster::KeyBytes key{};
        Meeting meeting;
        bool known{false};
        GatewayState state{GatewayState::OFF};
        std::set<uint16_t> tcp, udp;
        int64_t since{0};
        int64_t last_heard{0};
        int64_t last_hello{0};
        int64_t off_since{0};
    };
    struct Pending {
        Resolved done;
        int64_t deadline{0};
    };
    using FlowKey = std::tuple<uint8_t, IpAddr, uint16_t, IpAddr, uint16_t>;

    void ThreadWorker();
    void Round();
    int64_t m_next_allowed_check{0}; //!< worker thread only
    /** Let a gateway go: close its meeting, and tell the stack. */
    void Drop(uint64_t path, int64_t retry_after) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void DrainInbox();
    void Tick();

    const int m_pool;
    const int m_hops;
    const bool m_allow_local;
    const Allowed m_allowed_check;
    const Candidates m_candidates;
    const Meeter m_meet;
    const Closer m_close;
    const Sender m_send;
    std::map<int, GatewayGone> m_gone; //!< stack thread
    int m_next_gone{0};
    IpAddr m_if_v4, m_if_v6;           //!< stack thread
    InterfaceSink m_if_sink;

    std::thread m_thread;
    CThreadInterrupt m_interrupt;
    std::atomic<bool> m_running{false};

    mutable Mutex m_mutex;
    std::map<uint64_t, Entry> m_entries GUARDED_BY(m_mutex); //!< by meeting path
    std::map<roster::KeyBytes, int64_t> m_cooldown GUARDED_BY(m_mutex);
    std::map<uint64_t, uint64_t> m_flow_counts GUARDED_BY(m_mutex);
    bool m_allowed GUARDED_BY(m_mutex){false};
    std::string m_why GUARDED_BY(m_mutex);
    std::string m_last_error GUARDED_BY(m_mutex);
    uint64_t m_rr GUARDED_BY(m_mutex){0};

    Mutex m_inbox_mutex;
    std::deque<std::pair<uint64_t, std::vector<uint8_t>>> m_inbox GUARDED_BY(m_inbox_mutex);
    bool m_drain_posted GUARDED_BY(m_inbox_mutex){false};

    // Stack thread only.
    struct netif* m_netif{nullptr};
    int m_tick{0};
    uint16_t m_frag_id{0};
    uint32_t m_next_request{0};
    Reassembler m_reassembler;
    std::map<FlowKey, uint64_t> m_flows;
    std::map<uint32_t, Pending> m_pending;

    TrafficLimits m_pacer;

    std::atomic<uint64_t> m_lookups{0}, m_meetings_failed{0}, m_flow_total{0};
};

/** The running client, or null when nothing on this node uses gateways. */
extern std::unique_ptr<GatewayClient> g_gateway_client;

} // namespace overlay

#endif // BITCOIN_OVERLAY_GATEWAYCLIENT_H
