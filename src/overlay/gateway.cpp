// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/gateway.h>

#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <overlay/meeting.h>
#include <overlay/netstack.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/time.h>

#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>

#include <algorithm>
#include <cstring>

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#ifdef WIN32
#define BPS_SHUT_WR SD_SEND
#else
#define BPS_SHUT_WR SHUT_WR
#endif

namespace overlay {

std::unique_ptr<Gateway> g_gateway;
Mutex g_gateway_meeting_mutex;
std::unique_ptr<MeetingService> g_gateway_meeting;

namespace {
Mutex g_identity_mutex;
GatewayIdentity g_identity GUARDED_BY(g_identity_mutex);
} // namespace

GatewayIdentity GetGatewayIdentity()
{
    LOCK(g_identity_mutex);
    return g_identity;
}

void SetGatewayIdentity(const GatewayIdentity& id)
{
    LOCK(g_identity_mutex);
    g_identity = id;
}

namespace {

/*
 * Inside the stack, every connection a visitor opens gets an address of its
 * own and is pointed at one listener. The ranges are not routable outside the
 * stack and never leave it: IPv4's shared address space, and a unique-local
 * IPv6 prefix whose /64 lwIP takes as on-link for its interface.
 */
const IpAddr LISTEN_V4 = IpAddr::V4(100, 64, 0, 1);
constexpr uint32_t INTERNAL_V4_BASE = (100u << 24) | (64u << 16); // 100.64.0.0/10
constexpr uint32_t INTERNAL_V4_HOSTS = (1u << 22) - 3;            // all but network, listener, broadcast
const std::array<uint8_t, 8> INTERNAL_V6_PREFIX{{0xfd, 0x62, 0x70, 0x73, 0x67, 0x77, 0x00, 0x00}};
constexpr uint16_t LISTEN_PORT = 1;
constexpr uint16_t FIRST_INTERNAL_PORT = 1024;
constexpr uint32_t INTERNAL_PORTS = 64000;

IpAddr ListenV6()
{
    std::array<uint8_t, 16> b{};
    std::copy(INTERNAL_V6_PREFIX.begin(), INTERNAL_V6_PREFIX.end(), b.begin());
    b[15] = 1;
    return IpAddr::V6(b);
}

/** The gateway the stack's callbacks reach. One stack per process, so one gateway. */
Gateway* g_active = nullptr;

int64_t NowMs()
{
    return GetTimeMillis();
}

void ToLwip(const IpAddr& a, ip_addr_t& out)
{
    if (a.version == 6) {
        IP_ADDR6(&out, 0, 0, 0, 0);
        std::memcpy(ip_2_ip6(&out)->addr, a.bytes.data(), 16);
    } else {
        IP_ADDR4(&out, a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]);
    }
}

IpAddr FromLwip(const ip_addr_t& a)
{
    if (IP_IS_V6_VAL(a)) {
        std::array<uint8_t, 16> b;
        std::memcpy(b.data(), ip_2_ip6(&a)->addr, 16);
        return IpAddr::V6(b);
    }
    const uint32_t v = ip_2_ip4(&a)->addr; // network order, as stored
    const uint8_t* p = (const uint8_t*)&v;
    return IpAddr::V4(p[0], p[1], p[2], p[3]);
}

bool ToSockaddr(const IpAddr& a, uint16_t port, struct sockaddr_storage& ss, socklen_t& len)
{
    std::memset(&ss, 0, sizeof(ss));
    if (a.version == 4) {
        struct sockaddr_in* in = (struct sockaddr_in*)&ss;
        in->sin_family = AF_INET;
        std::memcpy(&in->sin_addr, a.bytes.data(), 4);
        in->sin_port = htons(port);
        len = sizeof(*in);
        return true;
    }
    if (a.version == 6) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)&ss;
        in6->sin6_family = AF_INET6;
        std::memcpy(&in6->sin6_addr, a.bytes.data(), 16);
        in6->sin6_port = htons(port);
        len = sizeof(*in6);
        return true;
    }
    return false;
}

bool FromNetAddrImpl(const CNetAddr& n, IpAddr& out)
{
    if (n.IsIPv4()) {
        struct in_addr a;
        if (!n.GetInAddr(&a)) return false;
        const uint8_t* p = (const uint8_t*)&a;
        out = IpAddr::V4(p[0], p[1], p[2], p[3]);
        return true;
    }
    if (n.IsIPv6()) {
        struct in6_addr a;
        if (!n.GetIn6Addr(&a)) return false;
        std::array<uint8_t, 16> b;
        std::memcpy(b.data(), &a, 16);
        out = IpAddr::V6(b);
        return true;
    }
    return false;
}

/** A non-blocking socket of the given kind, ready for the stack's loop, or INVALID_SOCKET. */
SOCKET OpenSocket(uint8_t version, bool tcp)
{
    SOCKET s = socket(version == 6 ? AF_INET6 : AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    // A visitor's connection leaves on this computer's own line, never into
    // its own system-wide interface - which would hand it to another gateway.
    if (!IsSelectableSocket(s) || !MarkBypass(s)) {
        CloseSocket(s);
        return INVALID_SOCKET;
    }
#ifdef SO_NOSIGPIPE
    int set = 1;
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (sockopt_arg_type)&set, sizeof(int));
#endif
    if (tcp) SetSocketNoDelay(s);
    if (!SetSocketNonBlocking(s, true)) {
        CloseSocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

bool WouldBlock(int err)
{
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINTR
#ifdef WIN32
           || err == WSAEINVAL || err == WSAEALREADY
#endif
        ;
}

ResolveStatus SystemResolve(const std::string& name, uint8_t family, std::vector<IpAddr>& out)
{
    std::vector<CNetAddr> found;
    if (!LookupHost(name, found, 2 * MAX_RESOLVED, true)) return ResolveStatus::NO_SUCH_NAME;
    for (const CNetAddr& n : found) {
        IpAddr a;
        if (!FromNetAddrImpl(n, a)) continue;
        if (family != RESOLVE_ANY && a.version != family) continue;
        out.push_back(a);
    }
    return ResolveStatus::OK;
}

err_t GwOutput4(struct netif*, struct pbuf* p, const ip4_addr_t*)
{
    if (g_active) g_active->OnStackOutput(p);
    return ERR_OK;
}

err_t GwOutput6(struct netif*, struct pbuf* p, const ip6_addr_t*)
{
    if (g_active) g_active->OnStackOutput(p);
    return ERR_OK;
}

err_t GwNetifInit(struct netif* n)
{
    n->output = GwOutput4;
    n->output_ip6 = GwOutput6;
    n->mtu = (u16_t)MAX_GATEWAY_PACKET;
    n->name[0] = 'g';
    n->name[1] = 'w';
    return ERR_OK;
}

err_t GwAccept(void*, struct tcp_pcb* pcb, err_t err)
{
    if (err != ERR_OK || pcb == nullptr || !g_active) return ERR_VAL;
    return g_active->OnAccept(pcb);
}

err_t GwRecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t)
{
    if (!g_active) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    return g_active->OnTcpRecv((uint64_t)(uintptr_t)arg, pcb, p);
}

err_t GwSent(void* arg, struct tcp_pcb*, u16_t)
{
    return g_active ? (err_t)g_active->OnTcpSent((uint64_t)(uintptr_t)arg) : (err_t)ERR_OK;
}

void GwError(void* arg, err_t)
{
    if (g_active) g_active->OnTcpError((uint64_t)(uintptr_t)arg);
}

void Detach(struct tcp_pcb* pcb)
{
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
}

} // namespace

bool NetAddrToIp(const CNetAddr& n, IpAddr& out)
{
    return FromNetAddrImpl(n, out);
}

std::vector<IpAddr> LocalInterfaceAddresses()
{
    std::vector<IpAddr> out;
#ifdef WIN32
    char name[256] = "";
    if (gethostname(name, sizeof(name)) != SOCKET_ERROR) {
        std::vector<CNetAddr> found;
        if (LookupHost(name, found, 0, true)) {
            for (const CNetAddr& n : found) {
                IpAddr a;
                if (FromNetAddrImpl(n, a)) out.push_back(a);
            }
        }
    }
#else
    struct ifaddrs* list = nullptr;
    if (getifaddrs(&list) == 0) {
        for (struct ifaddrs* i = list; i != nullptr; i = i->ifa_next) {
            if (i->ifa_addr == nullptr) continue;
            if (i->ifa_addr->sa_family == AF_INET) {
                const uint8_t* p = (const uint8_t*)&((struct sockaddr_in*)i->ifa_addr)->sin_addr;
                out.push_back(IpAddr::V4(p[0], p[1], p[2], p[3]));
            } else if (i->ifa_addr->sa_family == AF_INET6) {
                std::array<uint8_t, 16> b;
                std::memcpy(b.data(), &((struct sockaddr_in6*)i->ifa_addr)->sin6_addr, 16);
                out.push_back(IpAddr::V6(b));
            }
        }
        freeifaddrs(list);
    }
#endif
    return out;
}

Gateway::Gateway(const GatewayConfig& config, Sender send, ServingCheck serving, SelfAddresses self,
                 Resolver resolve, ServingChanged changed)
    : m_config(config), m_send(std::move(send)), m_serving_check(std::move(serving)),
      m_self_addresses(std::move(self)), m_resolve(std::move(resolve)), m_serving_changed(std::move(changed))
{
    if (!m_resolve) m_resolve = SystemResolve;
    m_limits.Configure(m_config.daily_budget, m_config.meeting_rate);
    m_pacer.Configure(0, m_config.meeting_rate * PACE_SHARE_NUM / PACE_SHARE_DEN);
}

Gateway::~Gateway()
{
    Stop();
}

bool Gateway::Start(std::string& error)
{
    NetStack& stack = GetNetStack();
    if (!stack.Running()) {
        error = "the node's TCP/IP stack is not running";
        return false;
    }
    if (g_active) {
        error = "a gateway is already running in this process";
        return false;
    }

    bool ok = false;
    stack.RunSync([&] {
        m_netif = new struct netif;
        std::memset(m_netif, 0, sizeof(*m_netif));
        ip4_addr_t addr, mask, gw;
        IP4_ADDR(&addr, LISTEN_V4.bytes[0], LISTEN_V4.bytes[1], LISTEN_V4.bytes[2], LISTEN_V4.bytes[3]);
        IP4_ADDR(&mask, 255, 192, 0, 0); // the whole /10 is on this interface
        IP4_ADDR(&gw, 0, 0, 0, 0);
        if (netif_add(m_netif, &addr, &mask, &gw, nullptr, GwNetifInit, ip_input) == nullptr) {
            error = "cannot add the gateway's interface to the stack";
            delete m_netif;
            m_netif = nullptr;
            return;
        }
        ip_addr_t v6;
        ToLwip(ListenV6(), v6);
        s8_t idx = -1;
        if (netif_add_ip6_address(m_netif, ip_2_ip6(&v6), &idx) != ERR_OK) {
            error = "cannot give the gateway's interface its IPv6 address";
            netif_remove(m_netif);
            delete m_netif;
            m_netif = nullptr;
            return;
        }
        netif_ip6_addr_set_state(m_netif, idx, IP6_ADDR_PREFERRED);
        netif_set_up(m_netif);
        netif_set_link_up(m_netif);

        for (int v = 4; v <= 6; v += 2) {
            struct tcp_pcb* pcb = tcp_new_ip_type(v == 6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
            ip_addr_t at;
            ToLwip(v == 6 ? ListenV6() : LISTEN_V4, at);
            if (pcb == nullptr || tcp_bind(pcb, &at, LISTEN_PORT) != ERR_OK) {
                error = "cannot open the gateway's listener";
                if (pcb) tcp_abort(pcb);
                return;
            }
            pcb = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG);
            tcp_accept(pcb, GwAccept);
            (v == 6 ? m_listen6 : m_listen4) = pcb;
        }
        g_active = this;
        m_tick = GetNetStack().AddTick([this] { Tick(); });
        ok = true;
    });
    if (!ok) {
        Stop();
        return false;
    }

    m_running = true;
    {
        LOCK(m_worker_mutex);
        m_worker_stop = false;
    }
    m_worker = std::thread(&TraceThread<std::function<void()>>, "gateway",
                           std::function<void()>(std::bind(&Gateway::ThreadWorker, this)));
    return true;
}

void Gateway::Stop()
{
    {
        LOCK(m_worker_mutex);
        m_worker_stop = true;
    }
    m_worker_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
    m_running = false;

    NetStack& stack = GetNetStack();
    auto teardown = [this, &stack] {
        for (std::pair<const uint64_t, Flow>& f : m_flows) {
            if (!f.second.closed) Abort(f.second, "the gateway is stopping");
        }
        m_flows.clear();
        m_by_key.clear();
        m_by_internal.clear();
        m_visitors.clear();
        for (struct tcp_pcb** l : {&m_listen4, &m_listen6}) {
            if (*l) {
                tcp_close(*l);
                *l = nullptr;
            }
        }
        if (m_netif) {
            netif_remove(m_netif);
            delete m_netif;
            m_netif = nullptr;
        }
        if (m_tick) stack.RemoveTick(m_tick);
        m_tick = 0;
        if (g_active == this) g_active = nullptr;
    };
    if (stack.Running()) {
        stack.RunSync(teardown);
    } else {
        teardown();
    }
    if (m_serving && m_serving_changed) m_serving_changed(false);
    m_serving = false;
}

GatewayState Gateway::State() const
{
    if (!m_serving) return GatewayState::OFF;
    if (!m_limits.GetStats(NowMs()).accepting) return GatewayState::CLOSED_TODAY;
    return GatewayState::OPEN;
}

Gateway::Stats Gateway::GetStats() const
{
    Stats s;
    s.state = State();
    s.serving = m_serving;
    const TrafficLimits::Stats l = m_limits.GetStats(NowMs());
    s.today_bytes = l.today;
    s.daily_budget = l.daily_budget;
    s.meeting_rate = l.path_rate;
    s.tcp_flows = m_tcp_flows;
    s.udp_flows = m_udp_flows;
    s.visitors = m_visitor_count;
    s.opened = m_opened;
    s.refused_policy = m_refused_policy;
    s.refused_limits = m_refused_limits;
    s.refused_state = m_refused_state;
    s.malformed = m_malformed;
    s.lookups = m_lookup_count;
    s.policy = m_config.policy.ToString();
    s.allow_local = m_config.policy.LocalAllowed();
    return s;
}

void Gateway::HandleApp(const Hop& from, std::vector<uint8_t>&& payload)
{
    // A gateway is the end of a meeting, never someone's adjacent peer: a
    // visitor that reached it directly would have told it where they are.
    if (!from.via_path || !m_running) return;
    bool post = false;
    {
        LOCK(m_inbox_mutex);
        if (m_inbox.size() >= MAX_INBOX) {
            ++m_malformed;
            return;
        }
        m_inbox.emplace_back(from.path, std::move(payload));
        if (!m_drain_posted) {
            m_drain_posted = true;
            post = true;
        }
    }
    if (post) GetNetStack().Post([this] { DrainInbox(); });
}

void Gateway::DrainInbox()
{
    std::deque<std::pair<uint64_t, std::vector<uint8_t>>> work;
    {
        LOCK(m_inbox_mutex);
        work.swap(m_inbox);
        m_drain_posted = false;
    }
    if (!m_netif) return;
    for (const std::pair<uint64_t, std::vector<uint8_t>>& m : work) OnMessage(m.first, m.second);
}

void Gateway::SendStatus(uint64_t path, GatewayState state)
{
    const std::vector<uint16_t> tcp(m_config.policy.TcpPorts().begin(), m_config.policy.TcpPorts().end());
    const std::vector<uint16_t> udp(m_config.policy.UdpPorts().begin(), m_config.policy.UdpPorts().end());
    m_send(path, EncodeStatus(state, tcp, udp));
}

void Gateway::OnMessage(uint64_t path, const std::vector<uint8_t>& payload)
{
    GatewayMessage msg;
    if (!DecodeGatewayMessage(payload, msg)) {
        ++m_malformed;
        return;
    }
    const int64_t now = NowMs();
    Visitor& v = m_visitors[path];
    if (v.last_seen == 0) ++m_visitor_count;
    v.last_seen = now;

    switch (msg.kind) {
    case GatewayKind::HELLO:
        SendStatus(path, State());
        return;
    case GatewayKind::PACKET:
        OnPacket(path, msg.bytes);
        return;
    case GatewayKind::FRAG: {
        std::vector<uint8_t> whole;
        if (m_reassembler.Add(path, msg, now, whole)) OnPacket(path, whole);
        return;
    }
    case GatewayKind::RESOLVE: {
        if (State() != GatewayState::OPEN) {
            m_send(path, EncodeResolved(msg.request, ResolveStatus::REFUSED, 0, {}));
            return;
        }
        bool queued = false;
        {
            LOCK(m_worker_mutex);
            if (m_lookups.size() < MAX_LOOKUPS) {
                m_lookups.push_back(Lookup{path, msg.request, msg.family, msg.name});
                queued = true;
            }
        }
        if (queued) {
            m_worker_cv.notify_one();
        } else {
            m_send(path, EncodeResolved(msg.request, ResolveStatus::FAILED, 0, {}));
        }
        return;
    }
    case GatewayKind::RESOLVED:
    case GatewayKind::STATUS:
        // What a gateway says, not what it is told.
        return;
    }
}

void Gateway::OnPacket(uint64_t path, std::vector<uint8_t>& pkt)
{
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why)) {
        ++m_malformed;
        LogPrint(BCLog::NET, "gateway: dropped a packet: %s\n", why);
        return;
    }
    // Within the visitor's rate and the day's budget, or dropped as a full
    // link would drop it; TCP slows down in answer.
    if (!m_limits.Forward(path, pkt.size(), NowMs())) return;
    if (info.IsTcp()) {
        OnTcpPacket(path, pkt, info);
    } else {
        OnUdpPacket(path, pkt, info);
    }
}

bool Gateway::Admit(uint64_t path, uint8_t protocol, const IpAddr& dst, uint16_t port, std::string& why)
{
    const GatewayState state = State();
    if (state != GatewayState::OPEN) {
        why = state == GatewayState::OFF ? "the gateway is off" : "the gateway's budget for today is spent";
        ++(state == GatewayState::OFF ? m_refused_state : m_refused_limits);
        SendStatus(path, state);
        return false;
    }
    if (!m_config.policy.Allows(protocol, dst, port, why)) {
        ++m_refused_policy;
        return false;
    }
    {
        LOCK(m_worker_mutex);
        if (std::find(m_self.begin(), m_self.end(), dst) != m_self.end() && !m_config.policy.LocalAllowed()) {
            why = "that is this gateway's own address";
            ++m_refused_policy;
            return false;
        }
    }
    if (m_tcp_flows + m_udp_flows >= m_config.max_flows || m_visitors[path].flows >= m_config.flows_per_meeting) {
        why = "too many connections open";
        ++m_refused_limits;
        return false;
    }
    if (!m_limits.AdmitPath(NowMs())) {
        why = "the gateway's budget for today is spent";
        ++m_refused_limits;
        SendStatus(path, GatewayState::CLOSED_TODAY);
        return false;
    }
    return true;
}

void Gateway::InternalFor(uint8_t version, IpAddr& addr, uint16_t& port)
{
    const uint64_t n = m_next_internal++;
    if (version == 6) {
        std::array<uint8_t, 16> b{};
        std::copy(INTERNAL_V6_PREFIX.begin(), INTERNAL_V6_PREFIX.end(), b.begin());
        // An interface identifier of its own for every connection, past the listener's ::1.
        const uint64_t id = n + 2;
        for (int i = 0; i < 8; ++i) b[8 + i] = (uint8_t)(id >> (56 - 8 * i));
        addr = IpAddr::V6(b);
        port = FIRST_INTERNAL_PORT;
        return;
    }
    // Addresses and ports both, so 4 million addresses times 64,000 ports
    // go by before a pair comes round again - never, in practice, and so never
    // onto a pair the stack still remembers.
    const uint32_t host = 2 + (uint32_t)((n / INTERNAL_PORTS) % INTERNAL_V4_HOSTS);
    const uint32_t a = INTERNAL_V4_BASE + host;
    addr = IpAddr::V4((uint8_t)(a >> 24), (uint8_t)(a >> 16), (uint8_t)(a >> 8), (uint8_t)a);
    port = (uint16_t)(FIRST_INTERNAL_PORT + n % INTERNAL_PORTS);
}

Gateway::Flow* Gateway::NewFlow(uint64_t path, const PacketInfo& info)
{
    Flow f;
    f.id = ++m_next_id;
    f.path = path;
    f.protocol = info.protocol;
    f.visitor = info.src;
    f.visitor_port = info.src_port;
    f.dst = info.dst;
    f.dst_port = info.dst_port;
    f.created = f.last_active = NowMs();
    if (info.IsTcp()) InternalFor(info.version, f.internal, f.internal_port);

    const FlowKey key(path, info.protocol, info.src, info.src_port, info.dst, info.dst_port);
    m_by_key[key] = f.id;
    if (info.IsTcp()) m_by_internal[std::make_pair(f.internal, f.internal_port)] = f.id;
    ++m_visitors[path].flows;
    ++(info.IsTcp() ? m_tcp_flows : m_udp_flows);
    ++m_opened;
    return &m_flows.emplace(f.id, f).first->second;
}

Gateway::Flow* Gateway::FindFlow(uint64_t id)
{
    std::map<uint64_t, Flow>::iterator it = m_flows.find(id);
    return it == m_flows.end() ? nullptr : &it->second;
}

void Gateway::OnTcpPacket(uint64_t path, std::vector<uint8_t>& pkt, const PacketInfo& info)
{
    const FlowKey key(path, info.protocol, info.src, info.src_port, info.dst, info.dst_port);
    std::map<FlowKey, uint64_t>::iterator it = m_by_key.find(key);
    Flow* f = it == m_by_key.end() ? nullptr : FindFlow(it->second);
    if (f && f->closed) {
        // A connection the table still remembers, reused for a new one.
        if (!info.IsTcpOpen()) return;
        m_by_key.erase(it);
        f = nullptr;
    }
    if (!f) {
        // Only a SYN opens a connection. Anything else for one the gateway
        // does not know is left unanswered.
        if (!info.IsTcpOpen()) return;
        std::string why;
        if (!Admit(path, IPPROTO_TCP_NUM, info.dst, info.dst_port, why)) {
            LogPrint(BCLog::NET, "gateway: refused a connection to %s port %u: %s\n", info.dst.ToString(), info.dst_port, why);
            SendToVisitor(path, BuildTcpReset(info));
            return;
        }
        f = NewFlow(path, info);
    }
    f->last_active = NowMs();

    // Into the stack: from the connection's own address, to the one listener.
    const IpAddr& listen = info.version == 6 ? ListenV6() : LISTEN_V4;
    RewritePacket(pkt, info, f->internal, f->internal_port, listen, LISTEN_PORT);
    struct pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)pkt.size(), PBUF_RAM);
    if (p == nullptr) return;
    pbuf_take(p, pkt.data(), (u16_t)pkt.size());
    if (m_netif->input(p, m_netif) != ERR_OK) pbuf_free(p);
}

void Gateway::OnStackOutput(struct pbuf* p)
{
    std::vector<uint8_t> pkt(p->tot_len);
    pbuf_copy_partial(p, pkt.data(), p->tot_len, 0);
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why) || !info.IsTcp()) return;
    // Back out: the stack answers a connection's own address, which says
    // which connection it is, and so who it goes to and where it came from.
    std::map<std::pair<IpAddr, uint16_t>, uint64_t>::iterator it =
        m_by_internal.find(std::make_pair(info.dst, info.dst_port));
    if (it == m_by_internal.end()) return;
    Flow* f = FindFlow(it->second);
    if (!f) return;
    RewritePacket(pkt, info, f->dst, f->dst_port, f->visitor, f->visitor_port);
    SendToVisitor(f->path, pkt);
}

void Gateway::SendToVisitor(uint64_t path, const std::vector<uint8_t>& pkt)
{
    // Paced where it is read from the site, so counted here only against the day.
    if (!m_limits.Spend(pkt.size(), NowMs())) return;
    for (const std::vector<uint8_t>& m : EncodePacket(pkt, ++m_frag_id)) m_send(path, m);
}

int8_t Gateway::OnAccept(struct tcp_pcb* pcb)
{
    const IpAddr from = FromLwip(pcb->remote_ip);
    std::map<std::pair<IpAddr, uint16_t>, uint64_t>::iterator it =
        m_by_internal.find(std::make_pair(from, pcb->remote_port));
    Flow* f = it == m_by_internal.end() ? nullptr : FindFlow(it->second);
    if (!f || f->closed || f->pcb) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    f->pcb = pcb;
    tcp_arg(pcb, (void*)(uintptr_t)f->id);
    tcp_recv(pcb, GwRecv);
    tcp_sent(pcb, GwSent);
    tcp_err(pcb, GwError);
    // Someone else's bytes go on as they come, not held for an ACK.
    tcp_nagle_disable(pcb);
    if (!StartRemote(*f)) {
        Detach(pcb);
        f->pcb = nullptr;
        tcp_abort(pcb);
        Close(*f);
        return ERR_ABRT;
    }
    return ERR_OK;
}

bool Gateway::StartRemote(Flow& f)
{
    struct sockaddr_storage ss;
    socklen_t len = 0;
    if (!ToSockaddr(f.dst, f.dst_port, ss, len)) return false;
    f.sock = OpenSocket(f.dst.version, true);
    if (f.sock == INVALID_SOCKET) return false;
    if (connect(f.sock, (struct sockaddr*)&ss, len) == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (!WouldBlock(err)) {
            LogPrint(BCLog::NET, "gateway: connect to %s failed: %s\n", f.dst.ToString(), NetworkErrorString(err));
            CloseSocket(f.sock);
            return false;
        }
        f.connecting = true;
    } else {
        f.connected = true;
    }
    const uint64_t id = f.id;
    GetNetStack().Watch(f.sock, f.connected, f.connecting, [this, id](bool r, bool w, bool e) { OnSocket(id, r, w, e); });
    return true;
}

int8_t Gateway::OnTcpRecv(uint64_t id, struct tcp_pcb* pcb, struct pbuf* p)
{
    Flow* f = FindFlow(id);
    if (!f || f->closed || f->pcb != pcb) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (p == nullptr) {
        f->visitor_eof = true;
    } else {
        const size_t at = f->to_remote.size();
        f->to_remote.resize(at + p->tot_len);
        pbuf_copy_partial(p, f->to_remote.data() + at, p->tot_len, 0);
        pbuf_free(p);
        f->last_active = NowMs();
    }
    // Acted on once lwIP has returned: closing or resetting a connection from
    // inside its own callback is something lwIP allows only in narrow ways.
    GetNetStack().Post([this, id] {
        Flow* g = FindFlow(id);
        if (g && !g->closed && FlushToRemote(*g)) MaybeFinish(*g);
    });
    return ERR_OK;
}

int8_t Gateway::OnTcpSent(uint64_t id)
{
    GetNetStack().Post([this, id] {
        Flow* f = FindFlow(id);
        if (f && !f->closed) PumpFromRemote(*f);
    });
    return ERR_OK;
}

void Gateway::OnTcpError(uint64_t id)
{
    // lwIP has freed the pcb already: a reset from the visitor, or its retries ran out.
    Flow* f = FindFlow(id);
    if (!f || f->closed) return;
    f->pcb = nullptr;
    Close(*f);
}

void Gateway::OnSocket(uint64_t id, bool readable, bool writable, bool failed)
{
    Flow* f = FindFlow(id);
    if (!f || f->closed) return;

    if (f->protocol == IPPROTO_UDP_NUM) {
        if (failed) {
            Close(*f);
            return;
        }
        uint8_t buf[MAX_GATEWAY_PACKET];
        for (int i = 0; i < 16; ++i) {
            const int n = recv(f->sock, (char*)buf, sizeof(buf), 0);
            if (n <= 0) break;
            f->last_active = NowMs();
            // What comes back must fit the interface's packet size, headers and all.
            const size_t room = MAX_GATEWAY_PACKET - (f->dst.version == 6 ? 40 : 20) - 8;
            if ((size_t)n > room) continue;
            SendToVisitor(f->path, BuildUdp(f->dst, f->dst_port, f->visitor, f->visitor_port,
                                            std::vector<uint8_t>(buf, buf + n)));
        }
        return;
    }

    if (f->connecting) {
        if (!writable && !failed) return;
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(f->sock, SOL_SOCKET, SO_ERROR, (sockopt_arg_type)&err, &len) == SOCKET_ERROR) err = WSAGetLastError();
        if (err != 0 || failed) {
            Abort(*f, strprintf("could not connect to %s port %u: %s", f->dst.ToString(), f->dst_port,
                                NetworkErrorString(err)));
            return;
        }
        f->connecting = false;
        f->connected = true;
    } else if (failed) {
        Abort(*f, "the connection failed");
        return;
    }
    if (!FlushToRemote(*f)) return;
    if (!PumpFromRemote(*f)) return;
    MaybeFinish(*f);
}

bool Gateway::FlushToRemote(Flow& f)
{
    if (!f.connected) return true;
    size_t done = 0;
    while (done < f.to_remote.size()) {
        const size_t chunk = std::min<size_t>(f.to_remote.size() - done, 1 << 16);
        const int n = send(f.sock, (const char*)f.to_remote.data() + done, (int)chunk, MSG_NOSIGNAL);
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        const int err = WSAGetLastError();
        if (WouldBlock(err)) break;
        Abort(f, "sending to the site failed: " + NetworkErrorString(err));
        return false;
    }
    if (done) {
        f.to_remote.erase(f.to_remote.begin(), f.to_remote.begin() + done);
        // The window opens only as far as the bytes have gone on, so a slow
        // site slows the visitor down instead of filling the gateway's memory.
        for (size_t left = done; left && f.pcb;) {
            const u16_t c = (u16_t)std::min<size_t>(left, 0xffff);
            tcp_recved(f.pcb, c);
            left -= c;
        }
    }
    if (f.to_remote.empty() && f.visitor_eof && !f.remote_shut) {
        shutdown(f.sock, BPS_SHUT_WR);
        f.remote_shut = true;
    }
    UpdateInterest(f);
    return true;
}

bool Gateway::PumpFromRemote(Flow& f)
{
    if (!f.pcb || !f.connected || f.remote_eof) {
        UpdateInterest(f);
        return true;
    }
    uint8_t buf[8 * TCP_MSS];
    bool wrote = false;
    m_paced.erase(f.id);
    for (;;) {
        const size_t space = tcp_sndbuf(f.pcb);
        if (space < TCP_MSS || tcp_sndqueuelen(f.pcb) + 16 >= TCP_SND_QUEUELEN) break;
        const uint64_t allowance = m_pacer.Available(f.path, NowMs());
        if (allowance < TCP_MSS) {
            // Back when the meeting's allowance has come round again (Tick).
            m_paced.insert(f.id);
            break;
        }
        const size_t want = (size_t)std::min<uint64_t>(std::min(space, sizeof(buf)), allowance);
        const int n = recv(f.sock, (char*)buf, (int)want, 0);
        if (n > 0) {
            m_pacer.Forward(f.path, (size_t)n, NowMs());
            if (tcp_write(f.pcb, buf, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) {
                Abort(f, "the stack refused data");
                return false;
            }
            wrote = true;
            f.last_active = NowMs();
            continue;
        }
        if (n == 0) {
            f.remote_eof = true;
            tcp_shutdown(f.pcb, 0, 1);
            break;
        }
        const int err = WSAGetLastError();
        if (WouldBlock(err)) break;
        Abort(f, "reading from the site failed: " + NetworkErrorString(err));
        return false;
    }
    if (wrote && f.pcb) tcp_output(f.pcb);
    UpdateInterest(f);
    return true;
}

void Gateway::UpdateInterest(const Flow& f)
{
    if (f.sock == INVALID_SOCKET) return;
    const bool room = f.pcb && tcp_sndbuf(f.pcb) >= TCP_MSS && tcp_sndqueuelen(f.pcb) + 16 < TCP_SND_QUEUELEN &&
                      !m_paced.count(f.id);
    const bool read = f.connected && !f.remote_eof && room;
    const bool write = f.connecting || (f.connected && !f.to_remote.empty());
    GetNetStack().SetInterest(f.sock, read, write);
}

void Gateway::MaybeFinish(Flow& f)
{
    if (f.closed) return;
    if (f.visitor_eof && f.remote_eof && f.to_remote.empty()) Close(f);
}

void Gateway::Abort(Flow& f, const std::string& why, bool in_callback)
{
    if (f.closed) return;
    LogPrint(BCLog::NET, "gateway: closing a connection to %s: %s\n", f.dst.ToString(), why);
    if (f.pcb && !in_callback) {
        Detach(f.pcb);
        tcp_abort(f.pcb);
    }
    f.pcb = nullptr;
    Close(f);
}

void Gateway::Close(Flow& f)
{
    if (f.closed) return;
    if (f.pcb) {
        Detach(f.pcb);
        if (tcp_close(f.pcb) != ERR_OK) tcp_abort(f.pcb);
        f.pcb = nullptr;
    }
    if (f.sock != INVALID_SOCKET) {
        GetNetStack().Unwatch(f.sock);
        CloseSocket(f.sock);
    }
    f.closed = true;
    f.closed_at = NowMs();
    m_paced.erase(f.id);
    f.to_remote.clear();
    f.to_remote.shrink_to_fit();
    std::map<uint64_t, Visitor>::iterator v = m_visitors.find(f.path);
    if (v != m_visitors.end() && v->second.flows) --v->second.flows;
    --(f.protocol == IPPROTO_TCP_NUM ? m_tcp_flows : m_udp_flows);
}

void Gateway::OnUdpPacket(uint64_t path, const std::vector<uint8_t>& pkt, const PacketInfo& info)
{
    const FlowKey key(path, info.protocol, info.src, info.src_port, info.dst, info.dst_port);
    std::map<FlowKey, uint64_t>::iterator it = m_by_key.find(key);
    Flow* f = it == m_by_key.end() ? nullptr : FindFlow(it->second);
    if (f && f->closed) {
        m_by_key.erase(it);
        f = nullptr;
    }
    if (!f) {
        std::string why;
        if (!Admit(path, IPPROTO_UDP_NUM, info.dst, info.dst_port, why)) {
            LogPrint(BCLog::NET, "gateway: refused UDP to %s port %u: %s\n", info.dst.ToString(), info.dst_port, why);
            return;
        }
        f = NewFlow(path, info);
        struct sockaddr_storage ss;
        socklen_t len = 0;
        f->sock = OpenSocket(info.version, false);
        // Connected, so what comes back is only from where the visitor sent:
        // the gateway is never a way for strangers to reach the visitor.
        if (f->sock == INVALID_SOCKET || !ToSockaddr(info.dst, info.dst_port, ss, len) ||
            connect(f->sock, (struct sockaddr*)&ss, len) == SOCKET_ERROR) {
            Close(*f);
            return;
        }
        f->connected = true;
        const uint64_t id = f->id;
        GetNetStack().Watch(f->sock, true, false, [this, id](bool r, bool w, bool e) { OnSocket(id, r, w, e); });
    }
    f->last_active = NowMs();
    const uint8_t* payload = pkt.data() + info.ip_header + info.l4_header;
    send(f->sock, (const char*)payload, (int)info.payload, MSG_NOSIGNAL);
}

void Gateway::Tick()
{
    const int64_t now = NowMs();
    // Flows that were waiting for their meeting's allowance try again.
    if (!m_paced.empty()) {
        const std::set<uint64_t> waiting = m_paced;
        for (uint64_t id : waiting) {
            Flow* f = FindFlow(id);
            if (!f || f->closed) {
                m_paced.erase(id);
            } else {
                PumpFromRemote(*f);
            }
        }
    }
    if (now - m_last_sweep < 1000) return;
    m_last_sweep = now;

    std::vector<uint64_t> gone;
    for (std::pair<const uint64_t, Flow>& e : m_flows) {
        Flow& f = e.second;
        if (f.closed) {
            if (now - f.closed_at > CLOSE_LINGER_MS) gone.push_back(f.id);
            continue;
        }
        std::map<uint64_t, Visitor>::const_iterator v = m_visitors.find(f.path);
        const bool visitor_gone = v == m_visitors.end() || now - v->second.last_seen > VISITOR_IDLE_MS;
        if (f.protocol == IPPROTO_TCP_NUM && f.connecting && now - f.created > CONNECT_TIMEOUT_MS) {
            Abort(f, "the site did not answer");
        } else if (f.protocol == IPPROTO_TCP_NUM && now - f.last_active > TCP_IDLE_MS) {
            Abort(f, "idle");
        } else if (f.protocol == IPPROTO_UDP_NUM && now - f.last_active > UDP_IDLE_MS) {
            Close(f);
        } else if (visitor_gone) {
            Abort(f, "the visitor's meeting is gone");
        }
    }
    for (uint64_t id : gone) {
        const Flow& f = m_flows[id];
        const FlowKey key(f.path, f.protocol, f.visitor, f.visitor_port, f.dst, f.dst_port);
        std::map<FlowKey, uint64_t>::iterator k = m_by_key.find(key);
        if (k != m_by_key.end() && k->second == id) m_by_key.erase(k);
        if (f.protocol == IPPROTO_TCP_NUM) m_by_internal.erase(std::make_pair(f.internal, f.internal_port));
        m_flows.erase(id);
    }
    for (std::map<uint64_t, Visitor>::iterator v = m_visitors.begin(); v != m_visitors.end();) {
        if (v->second.flows == 0 && now - v->second.last_seen > VISITOR_IDLE_MS) {
            m_reassembler.Forget(v->first);
            v = m_visitors.erase(v);
            --m_visitor_count;
        } else {
            ++v;
        }
    }
}

void Gateway::Refresh()
{
    const bool serving = m_serving_check ? m_serving_check() : false;
    if (serving != m_serving.exchange(serving)) {
        LogPrintf("gateway: %s\n", serving ? "serving; taking connections"
                                           : "not serving (see getgatewayinfo); taking none");
        if (m_serving_changed) m_serving_changed(serving);
    }
    std::vector<IpAddr> self = m_self_addresses ? m_self_addresses() : std::vector<IpAddr>();
    LOCK(m_worker_mutex);
    m_self.swap(self);
}

void Gateway::ThreadWorker()
{
    int64_t next_refresh = 0;
    while (true) {
        Lookup job;
        bool have = false;
        {
            WAIT_LOCK(m_worker_mutex, lock);
            const int64_t wait = std::max<int64_t>(0, next_refresh - NowMs());
            m_worker_cv.wait_for(lock, std::chrono::milliseconds(wait), [this]() EXCLUSIVE_LOCKS_REQUIRED(m_worker_mutex) {
                return m_worker_stop || !m_lookups.empty();
            });
            if (m_worker_stop) return;
            if (!m_lookups.empty()) {
                job = m_lookups.front();
                m_lookups.pop_front();
                have = true;
            }
        }
        if (NowMs() >= next_refresh) {
            Refresh();
            next_refresh = NowMs() + REFRESH_MS;
        }
        if (!have) continue;

        ++m_lookup_count;
        std::string lower = job.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) { return (char)tolower((unsigned char)c); });
        std::vector<IpAddr> found;
        ResolveStatus status = ResolveStatus::NO_SUCH_NAME;
        if (!IsLocalOnlyName(lower)) status = m_resolve(lower, job.family, found);
        // Only public addresses go back: what the owner's own network calls
        // its machines is not the visitor's to learn.
        std::vector<IpAddr> answer;
        for (const IpAddr& a : found) {
            if (answer.size() >= MAX_RESOLVED) break;
            if (m_config.policy.LocalAllowed() || IsPublicAddress(a)) answer.push_back(a);
        }
        if (status == ResolveStatus::OK && answer.empty()) status = ResolveStatus::NO_SUCH_NAME;
        m_send(job.path, EncodeResolved(job.request, status, status == ResolveStatus::OK ? RESOLVE_TTL : 0, answer));
    }
}

} // namespace overlay
