// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_GATEWAY_H
#define BITCOIN_OVERLAY_GATEWAY_H

#include <compat.h>
#include <overlay/exitpolicy.h>
#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>
#include <overlay/limits.h>
#include <overlay/path.h>
#include <sync.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

class CNetAddr;
struct tcp_pcb;
struct pbuf;
struct netif;

/**
 * A gateway: the overlay's way out to the internet (design note §8·7).
 *
 * By design: free, run by every node that has the internet
 * unless its owner switches it off, listed by its key with no address and
 * reached only at its meeting points, so it never learns who is using it and
 * nobody learns where it is. It is the one role in BPS that is an exit: the
 * websites a visitor reaches see the gateway's address.
 *
 * What arrives, across a meeting, is the visitor's own IP packets
 * (overlay/gatewayproto.h). They are checked (overlay/ippacket.h), and a new
 * connection is held to the exit policy (overlay/exitpolicy.h), the daily
 * budget and the per-visitor limits before anything is opened. Then:
 *
 *  - TCP is given to the gateway's own TCP/IP stack (overlay/netstack.h).
 *    Each new connection gets an address of its own inside the stack and is
 *    pointed at one listener there - a connection table, as a NAT's REDIRECT
 *    rule keeps - so the stack accepts it without knowing where it was going.
 *    The gateway then opens an ordinary connection from its own address to
 *    where it was going, and passes the bytes between the two. TCP therefore
 *    runs from the visitor to the gateway, and from the gateway to the site.
 *  - UDP goes out on an ordinary socket per flow, connected to the one
 *    address it is for, and what comes back is wrapped as a packet again.
 *
 * Names are looked up with the gateway computer's own resolver, and only
 * public addresses are given back, so a visitor learns nothing of the
 * owner's own network.
 *
 * A node serves as a gateway only while the roster lists its key as one: the
 * gateway bit, and no endpoint. Never under a key with an address, which
 * would publish where an exit is.
 */
namespace overlay {

/** -gateway: on unless the owner switches it off (design note §8·7). */
static const bool DEFAULT_GATEWAY = true;
/** -gatewaybandwidth: MiB a gateway carries in a day, both ways. */
static constexpr uint64_t DEFAULT_GATEWAY_BANDWIDTH_MIB = 1024;
/** -gatewayrate: KiB/s one visitor's meeting may move. */
static constexpr uint64_t DEFAULT_GATEWAY_RATE_KIB = 64;
/** -gatewaymaxflows: connections open at once, for everyone. */
static constexpr size_t DEFAULT_GATEWAY_MAX_FLOWS = 512;
/** Connections one meeting may hold open at once. */
static constexpr size_t GATEWAY_FLOWS_PER_MEETING = 128;

struct GatewayConfig {
    ExitPolicy policy;
    uint64_t daily_budget{DEFAULT_GATEWAY_BANDWIDTH_MIB << 20};
    uint64_t meeting_rate{DEFAULT_GATEWAY_RATE_KIB << 10};
    size_t max_flows{DEFAULT_GATEWAY_MAX_FLOWS};
    size_t flows_per_meeting{GATEWAY_FLOWS_PER_MEETING};
};

class Gateway
{
public:
    /** Send a message to the visitor at the end of `path`, sealed (Relay::SendSecret). */
    using Sender = std::function<bool(uint64_t path, const std::vector<uint8_t>& payload)>;
    /** Whether the roster lists this node as a gateway now. */
    using ListedCheck = std::function<bool()>;
    /** This machine's own addresses, which a stranger never connects to. */
    using SelfAddresses = std::function<std::vector<IpAddr>()>;
    /** Look a name up. The default asks the system's resolver. */
    using Resolver = std::function<ResolveStatus(const std::string& name, uint8_t family, std::vector<IpAddr>& out)>;
    /** Called when the gateway starts or stops being listed, to register at meeting points or not. */
    using ListedChanged = std::function<void(bool listed)>;

    static constexpr int64_t CONNECT_TIMEOUT_MS = 20 * 1000;
    static constexpr int64_t UDP_IDLE_MS = 2 * 60 * 1000;
    static constexpr int64_t TCP_IDLE_MS = 30 * 60 * 1000;
    /** A meeting silent this long is gone (PathTable::PATH_TTL), and its connections with it. */
    static constexpr int64_t VISITOR_IDLE_MS = 10 * 60 * 1000;
    /** A closed connection's place in the table is kept this long, for the stack's last segments. */
    static constexpr int64_t CLOSE_LINGER_MS = 2 * 60 * 1000;
    static constexpr int64_t REFRESH_MS = 60 * 1000;
    static constexpr size_t MAX_INBOX = 4096;
    static constexpr size_t MAX_LOOKUPS = 256;
    static constexpr uint32_t RESOLVE_TTL = 300;

    Gateway(const GatewayConfig& config, Sender send, ListedCheck listed, SelfAddresses self,
            Resolver resolve = nullptr, ListedChanged changed = nullptr);
    ~Gateway();

    /** Needs the stack running (GetNetStack().Start). */
    bool Start(std::string& error);
    void Stop();

    /** Overlay application data starting GATEWAY_TAG. From the receive thread; never blocks. */
    void HandleApp(const Hop& from, std::vector<uint8_t>&& payload);

    GatewayState State() const;

    struct Stats {
        GatewayState state{GatewayState::OFF};
        bool listed{false};
        uint64_t today_bytes{0};
        uint64_t daily_budget{0};
        uint64_t meeting_rate{0};
        uint64_t tcp_flows{0};
        uint64_t udp_flows{0};
        uint64_t visitors{0};
        uint64_t opened{0};          //!< connections opened since start
        uint64_t refused_policy{0};  //!< refused by the exit policy or for the address
        uint64_t refused_limits{0};  //!< refused for the budget or the connection limits
        uint64_t refused_state{0};   //!< refused because the gateway is off
        uint64_t malformed{0};       //!< messages or packets that did not parse
        uint64_t lookups{0};
        std::string policy;
        bool allow_local{false};
    };
    Stats GetStats() const;

    // For the stack's C callbacks (gateway.cpp). Stack thread only.
    void OnStackOutput(struct pbuf* p);
    int8_t OnAccept(struct tcp_pcb* pcb);
    int8_t OnTcpRecv(uint64_t id, struct tcp_pcb* pcb, struct pbuf* p);
    int8_t OnTcpSent(uint64_t id);
    void OnTcpError(uint64_t id);

private:
    struct Flow {
        uint64_t id{0};
        uint64_t path{0};
        uint8_t protocol{0};
        IpAddr visitor;
        uint16_t visitor_port{0};
        IpAddr dst;
        uint16_t dst_port{0};
        IpAddr internal; //!< TCP: its own address inside the stack
        uint16_t internal_port{0};
        struct tcp_pcb* pcb{nullptr};
        SOCKET sock{INVALID_SOCKET};
        bool connecting{false};
        bool connected{false};
        bool visitor_eof{false};
        bool remote_eof{false};
        bool remote_shut{false};
        bool closed{false};
        std::vector<uint8_t> to_remote; //!< from the visitor, not yet on the socket
        int64_t created{0};
        int64_t last_active{0};
        int64_t closed_at{0};
    };
    using FlowKey = std::tuple<uint64_t, uint8_t, IpAddr, uint16_t, IpAddr, uint16_t>;

    struct Visitor {
        int64_t last_seen{0};
        size_t flows{0};
    };

    struct Lookup {
        uint64_t path;
        uint32_t request;
        uint8_t family;
        std::string name;
    };

    // Stack thread.
    void DrainInbox();
    void OnMessage(uint64_t path, const std::vector<uint8_t>& payload);
    void OnPacket(uint64_t path, std::vector<uint8_t>& pkt);
    void OnTcpPacket(uint64_t path, std::vector<uint8_t>& pkt, const PacketInfo& info);
    void OnUdpPacket(uint64_t path, const std::vector<uint8_t>& pkt, const PacketInfo& info);
    /** Whether a new connection may open; if not, why, and whether it was the policy. */
    bool Admit(uint64_t path, uint8_t protocol, const IpAddr& dst, uint16_t port, std::string& why);
    Flow* NewFlow(uint64_t path, const PacketInfo& info);
    void SendToVisitor(uint64_t path, const std::vector<uint8_t>& pkt);
    void SendStatus(uint64_t path, GatewayState state);
    bool StartRemote(Flow& f);
    void OnSocket(uint64_t id, bool readable, bool writable, bool failed);
    /** False if the flow was aborted. */
    bool FlushToRemote(Flow& f);
    bool PumpFromRemote(Flow& f);
    void UpdateInterest(const Flow& f);
    void MaybeFinish(Flow& f);
    /** Reset both sides and let the flow go. `in_callback` when lwIP called us with this pcb. */
    void Abort(Flow& f, const std::string& why, bool in_callback = false);
    void Close(Flow& f);
    void Tick();
    Flow* FindFlow(uint64_t id);
    void InternalFor(uint8_t version, IpAddr& addr, uint16_t& port);

    // Resolver thread.
    void ThreadWorker();
    void Refresh();

    const GatewayConfig m_config;
    const Sender m_send;
    const ListedCheck m_listed_check;
    const SelfAddresses m_self_addresses;
    Resolver m_resolve;
    const ListedChanged m_listed_changed;

    TrafficLimits m_limits;
    std::atomic<bool> m_listed{false};
    std::atomic<bool> m_running{false};

    // Between the receive thread and the stack thread.
    Mutex m_inbox_mutex;
    std::deque<std::pair<uint64_t, std::vector<uint8_t>>> m_inbox GUARDED_BY(m_inbox_mutex);
    bool m_drain_posted GUARDED_BY(m_inbox_mutex){false};

    // Between the stack thread and the resolver thread.
    mutable Mutex m_worker_mutex;
    std::condition_variable m_worker_cv;
    std::deque<Lookup> m_lookups GUARDED_BY(m_worker_mutex);
    std::vector<IpAddr> m_self GUARDED_BY(m_worker_mutex);
    bool m_worker_stop GUARDED_BY(m_worker_mutex){false};
    std::thread m_worker;

    // Stack thread only.
    struct netif* m_netif{nullptr};
    struct tcp_pcb* m_listen4{nullptr};
    struct tcp_pcb* m_listen6{nullptr};
    int m_tick{0};
    int64_t m_last_sweep{0};
    uint64_t m_next_id{0};
    uint64_t m_next_internal{0};
    uint16_t m_frag_id{0};
    Reassembler m_reassembler;
    std::map<uint64_t, Flow> m_flows;
    std::map<FlowKey, uint64_t> m_by_key;
    std::map<std::pair<IpAddr, uint16_t>, uint64_t> m_by_internal;
    std::map<uint64_t, Visitor> m_visitors;

    // Read by GetStats from any thread.
    std::atomic<uint64_t> m_tcp_flows{0}, m_udp_flows{0}, m_visitor_count{0};
    std::atomic<uint64_t> m_opened{0}, m_refused_policy{0}, m_refused_limits{0}, m_refused_state{0};
    std::atomic<uint64_t> m_malformed{0}, m_lookup_count{0};
};

/** The running gateway, or null when -gateway is off or the overlay is. */
extern std::unique_ptr<Gateway> g_gateway;

class MeetingService;
/**
 * The gateway's registration at its meeting points, running only while the
 * roster lists this node as a gateway. Null when -meetable keeps the node
 * registered anyway (overlay::g_meeting).
 */
extern std::unique_ptr<MeetingService> g_gateway_meeting;

/** This machine's interface addresses, for SelfAddresses. */
std::vector<IpAddr> LocalInterfaceAddresses();

/** An IPv4 or IPv6 CNetAddr as an IpAddr. False for other networks. */
bool NetAddrToIp(const CNetAddr& n, IpAddr& out);

} // namespace overlay

#endif // BITCOIN_OVERLAY_GATEWAY_H
