// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/sysif.h>

#include <logging.h>
#include <overlay/gatewayclient.h>
#include <overlay/gatewayproto.h>
#include <overlay/netstack.h>
#include <tinyformat.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace overlay {

std::unique_ptr<SystemInterface> g_system_interface;

namespace {

int64_t NowMs()
{
    return GetTimeMillis();
}

// The computer's side of the interface. Private addresses that nothing on
// the internet uses, apart from the node's own stack's (gatewayclient.cpp),
// so that what comes back from a gateway can be told apart.
constexpr uint8_t IF_V4[4] = {10, 77, 1, 2};
constexpr uint8_t RESOLVER_V4[4] = {10, 77, 1, 53};
constexpr uint8_t IF_V6[16] = {0xfd, 0x62, 0x70, 0x73, 0x69, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
constexpr uint8_t RESOLVER_V6[16] = {0xfd, 0x62, 0x70, 0x73, 0x69, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53};

IpAddr FromBytes(uint8_t version, const uint8_t* b)
{
    if (version == 4) return IpAddr::V4(b[0], b[1], b[2], b[3]);
    std::array<uint8_t, 16> a{};
    std::memcpy(a.data(), b, a.size());
    return IpAddr::V6(a);
}

/** Largest TCP segment a packet of INTERFACE_MTU carries, for `version`. */
uint16_t InterfaceMss(uint8_t version)
{
    return (uint16_t)(INTERFACE_MTU - (version == 6 ? 40 : 20) - 20);
}

#ifdef __linux__
class LinuxTun : public PacketDevice
{
public:
    explicit LinuxTun(const std::string& name) : m_name(name) {}
    ~LinuxTun() override { Stop(); }

    bool Start(Receive receive, std::string& error) override
    {
        if (m_name.empty() || m_name.size() >= IFNAMSIZ) {
            error = strprintf("\"%s\" is not an interface name", m_name);
            return false;
        }
        m_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (m_fd < 0) {
            error = strprintf("cannot open /dev/net/tun: %s", strerror(errno));
            return false;
        }
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);
        if (ioctl(m_fd, TUNSETIFF, &ifr) < 0) {
            const int err = errno;
            close(m_fd);
            m_fd = -1;
            error = err == EPERM || err == EBUSY
                ? strprintf("cannot open the interface %s (%s). Make it once as an administrator, for the user "
                            "BPS Relay runs as: ip tuntap add dev %s mode tun user <that user>",
                            m_name, strerror(err), m_name)
                : strprintf("cannot open the interface %s: %s", m_name, strerror(err));
            return false;
        }
        m_receive = std::move(receive);
        GetNetStack().Watch((SOCKET)m_fd, true, false, [this](bool readable, bool, bool) {
            if (readable) Drain();
        });
        return true;
    }

    void Stop() override
    {
        if (m_fd < 0) return;
        if (GetNetStack().Running()) GetNetStack().Unwatch((SOCKET)m_fd);
        close(m_fd);
        m_fd = -1;
    }

    bool Write(const std::vector<uint8_t>& pkt) override
    {
        return m_fd >= 0 && write(m_fd, pkt.data(), pkt.size()) == (ssize_t)pkt.size();
    }

    std::string Name() const override { return m_name; }

private:
    void Drain()
    {
        // A bounded batch, so one busy interface does not starve the rest of the loop.
        for (int i = 0; i < 256 && m_fd >= 0; ++i) {
            uint8_t buf[2048];
            const ssize_t n = read(m_fd, buf, sizeof(buf));
            if (n <= 0) break;
            m_receive(std::vector<uint8_t>(buf, buf + n));
        }
    }

    const std::string m_name;
    int m_fd{-1};
    Receive m_receive;
};
#endif

} // namespace

std::unique_ptr<PacketDevice> MakeTunDevice(const std::string& name)
{
#ifdef __linux__
    return std::unique_ptr<PacketDevice>(new LinuxTun(name));
#else
    (void)name;
    return nullptr;
#endif
}

IpAddr InterfaceAddress(uint8_t version)
{
    return version == 6 ? FromBytes(6, IF_V6) : FromBytes(4, IF_V4);
}

IpAddr InterfaceResolver(uint8_t version)
{
    return version == 6 ? FromBytes(6, RESOLVER_V6) : FromBytes(4, RESOLVER_V4);
}

SystemInterface::SystemInterface(GatewayClient& client, std::unique_ptr<PacketDevice> device)
    : m_client(client), m_device(std::move(device))
{
}

SystemInterface::~SystemInterface()
{
    Stop();
}

bool SystemInterface::Start(std::string& error)
{
    if (!m_device) {
        error = "this system has no interface BPS Relay can carry its traffic on yet";
        return false;
    }
    NetStack& stack = GetNetStack();
    if (!stack.Running()) {
        error = "the node's TCP/IP stack is not running";
        return false;
    }
    bool ok = false;
    stack.RunSync([&] {
        if (!m_device->Start([this](std::vector<uint8_t>&& pkt) { FromComputer(std::move(pkt)); }, error)) return;
        m_alive = std::make_shared<bool>(true);
        m_client.SetInterface(InterfaceAddress(4), InterfaceAddress(6),
                              [this](uint64_t path, std::vector<uint8_t>&& pkt) { FromGateway(path, std::move(pkt)); });
        m_gone = m_client.AddGatewayGone([this](uint64_t path) { OnGatewayGone(path); });
        m_tick = stack.AddTick([this] { Tick(); });
        ok = true;
    });
    if (!ok) return false;
    m_running = true;
    LogPrintf("system interface: %s carries this computer's traffic to the network's gateways; its resolver is %s\n",
              m_device->Name(), InterfaceResolver(4).ToString());
    return true;
}

void SystemInterface::Stop()
{
    if (!m_running.exchange(false)) return;
    NetStack& stack = GetNetStack();
    auto teardown = [this, &stack] {
        m_client.SetInterface(IpAddr(), IpAddr(), nullptr);
        if (m_gone) m_client.RemoveGatewayGone(m_gone);
        m_gone = 0;
        if (m_tick) stack.RemoveTick(m_tick);
        m_tick = 0;
        for (const std::pair<const FlowKey, Flow>& f : m_flows) {
            m_client.RemoveFlow(std::get<0>(f.first), std::get<1>(f.first), std::get<2>(f.first), std::get<3>(f.first),
                                std::get<4>(f.first));
        }
        m_flows.clear();
        m_queues.clear();
        m_alive.reset();
        m_device->Stop();
        m_flow_count = 0;
    };
    if (stack.Running()) {
        stack.RunSync(teardown);
    } else {
        teardown();
    }
}

SystemInterface::Stats SystemInterface::GetStats() const
{
    Stats s;
    s.device = m_device ? m_device->Name() : "";
    s.running = m_running;
    s.flows = m_flow_count;
    s.packets_out = m_packets_out;
    s.packets_in = m_packets_in;
    s.bytes_out = m_bytes_out;
    s.bytes_in = m_bytes_in;
    s.refused = m_refused;
    s.dropped = m_dropped;
    s.lookups = m_lookups;
    s.kept_local = m_kept_local;
    return s;
}

void SystemInterface::ToComputer(const std::vector<uint8_t>& pkt)
{
    if (m_device->Write(pkt)) {
        ++m_packets_in;
        m_bytes_in += pkt.size();
    }
}

void SystemInterface::Refuse(const PacketInfo& info)
{
    ++m_refused;
    // A program waiting on a connection hears at once that it will not open,
    // rather than retrying into silence. UDP has nothing to say it with.
    if (info.IsTcp() && !(info.tcp_flags & TCP_RST)) ToComputer(BuildTcpResetFor(info));
}

void SystemInterface::FromComputer(std::vector<uint8_t>&& pkt)
{
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why)) {
        ++m_dropped;
        return;
    }
    // Only what the computer sends as itself on this interface.
    if (!(info.src == InterfaceAddress(info.version))) {
        ++m_dropped;
        return;
    }
    if (info.dst == InterfaceResolver(info.version)) {
        if (info.IsUdp() && info.dst_port == DNS_PORT) {
            Lookup(info, pkt);
        } else {
            Refuse(info);
        }
        return;
    }
    // Routes keep the computer's own network off the interface; this keeps
    // it off even when they do not.
    if (!m_client.LocalAllowed() && !IsPublicAddress(info.dst)) {
        Refuse(info);
        return;
    }

    const FlowKey key(info.protocol, info.src, info.src_port, info.dst, info.dst_port);
    std::map<FlowKey, Flow>::iterator it = m_flows.find(key);
    const int64_t now = NowMs();
    if (it == m_flows.end()) {
        // A new connection: TCP only by its opening segment. Anything else is
        // left over from one that ended - a gateway went - and is told so.
        if (info.IsTcp() && !info.IsTcpOpen()) {
            Refuse(info);
            return;
        }
        uint64_t path = 0;
        if (m_flows.size() >= MAX_FLOWS || !m_client.Choose(info.protocol, info.dst_port, path)) {
            Refuse(info);
            return;
        }
        m_client.AddFlow(info.protocol, info.src, info.src_port, info.dst, info.dst_port, path);
        Flow f;
        f.path = path;
        it = m_flows.emplace(key, f).first;
        m_flow_count = m_flows.size();
    }
    Flow& f = it->second;
    f.last = now;
    if (info.IsTcp()) {
        f.last_out = info;
        if (info.tcp_flags & TCP_FIN) f.fin_out = true;
        if ((info.tcp_flags & TCP_SYN) && ClampTcpMss(pkt, info, InterfaceMss(info.version))) {
            ParsePacket(pkt, info, why);
        }
    }
    const uint64_t path = f.path;
    const bool reset = info.IsTcp() && (info.tcp_flags & TCP_RST);
    if (f.fin_out && f.fin_in && !f.closed_at) f.closed_at = now;
    Send(path, std::move(pkt));
    if (reset) RemoveFlow(it);
}

void SystemInterface::Send(uint64_t path, std::vector<uint8_t>&& pkt)
{
    Queue& q = m_queues[path];
    // Straight out while nothing waits and the relays' share allows it.
    if (q.packets.empty() && m_client.PaceAvailable(path) >= pkt.size()) {
        m_client.PaceUse(path, pkt.size());
        ++m_packets_out;
        m_bytes_out += pkt.size();
        m_client.SendPacket(path, pkt);
        return;
    }
    if (q.bytes + pkt.size() > MAX_QUEUE_BYTES) {
        ++m_dropped;
        return;
    }
    q.bytes += pkt.size();
    q.packets.push_back(std::move(pkt));
}

void SystemInterface::FromGateway(uint64_t path, std::vector<uint8_t>&& pkt)
{
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why)) {
        ++m_dropped;
        return;
    }
    // Only for a connection the computer opened, and only from the gateway
    // it went through.
    std::map<FlowKey, Flow>::iterator it =
        m_flows.find(FlowKey(info.protocol, info.dst, info.dst_port, info.src, info.src_port));
    if (it == m_flows.end() || it->second.path != path) {
        ++m_dropped;
        return;
    }
    Flow& f = it->second;
    f.last = NowMs();
    bool reset = false;
    if (info.IsTcp()) {
        if (info.tcp_flags & TCP_FIN) f.fin_in = true;
        reset = (info.tcp_flags & TCP_RST) != 0;
        if ((info.tcp_flags & TCP_SYN) && ClampTcpMss(pkt, info, InterfaceMss(info.version))) {
            ParsePacket(pkt, info, why);
        }
        if (f.fin_out && f.fin_in && !f.closed_at) f.closed_at = f.last;
    }
    ToComputer(pkt);
    if (reset) RemoveFlow(it);
}

void SystemInterface::RemoveFlow(std::map<FlowKey, Flow>::iterator it)
{
    m_client.RemoveFlow(std::get<0>(it->first), std::get<1>(it->first), std::get<2>(it->first), std::get<3>(it->first),
                        std::get<4>(it->first));
    m_flows.erase(it);
    m_flow_count = m_flows.size();
}

void SystemInterface::OnGatewayGone(uint64_t path)
{
    m_queues.erase(path);
    for (std::map<FlowKey, Flow>::iterator it = m_flows.begin(); it != m_flows.end();) {
        if (it->second.path != path) {
            ++it;
            continue;
        }
        // The connection's state was at that gateway: the program hears at
        // once that it ended, and opens a new one through another.
        if (std::get<0>(it->first) == IPPROTO_TCP_NUM && it->second.last_out.version != 0) {
            ToComputer(BuildTcpResetFor(it->second.last_out));
        }
        it = m_flows.erase(it);
    }
    m_flow_count = m_flows.size();
}

void SystemInterface::Tick()
{
    // Waiting packets, as the relays' share comes back.
    for (std::map<uint64_t, Queue>::iterator q = m_queues.begin(); q != m_queues.end();) {
        Queue& queue = q->second;
        while (!queue.packets.empty()) {
            const size_t size = queue.packets.front().size();
            if (m_client.PaceAvailable(q->first) < size) break;
            m_client.PaceUse(q->first, size);
            ++m_packets_out;
            m_bytes_out += size;
            m_client.SendPacket(q->first, queue.packets.front());
            queue.bytes -= size;
            queue.packets.pop_front();
        }
        q = queue.packets.empty() ? m_queues.erase(q) : std::next(q);
    }

    const int64_t now = NowMs();
    for (std::map<FlowKey, Flow>::iterator it = m_flows.begin(); it != m_flows.end();) {
        const Flow& f = it->second;
        const bool tcp = std::get<0>(it->first) == IPPROTO_TCP_NUM;
        const bool done = tcp ? (f.closed_at && now - f.closed_at > TCP_CLOSED_MS) || now - f.last > TCP_IDLE_MS
                              : now - f.last > UDP_IDLE_MS;
        if (done) {
            m_client.RemoveFlow(std::get<0>(it->first), std::get<1>(it->first), std::get<2>(it->first),
                                std::get<3>(it->first), std::get<4>(it->first));
            it = m_flows.erase(it);
        } else {
            ++it;
        }
    }
    m_flow_count = m_flows.size();

    for (std::map<std::pair<std::string, uint16_t>, Cached>::iterator c = m_cache.begin(); c != m_cache.end();) {
        c = c->second.until <= now ? m_cache.erase(c) : std::next(c);
    }
}

void SystemInterface::Lookup(const PacketInfo& info, const std::vector<uint8_t>& pkt)
{
    const std::vector<uint8_t> msg(pkt.begin() + info.ip_header + info.l4_header, pkt.end());
    DnsQuery q;
    DnsRcode rcode;
    bool answerable;
    if (!ParseDnsQuery(msg, q, rcode, answerable)) {
        if (answerable) AnswerLookup(info, q, rcode, {}, 0);
        return;
    }
    ++m_lookups;
    // Never sent anywhere: hidden sites, home names, single labels.
    if (IsLocalOnlyName(q.name)) {
        ++m_kept_local;
        AnswerLookup(info, q, DnsRcode::NO_SUCH_NAME, {}, MIN_DNS_TTL);
        return;
    }
    // Only addresses are looked up. Every other type - HTTPS, SVCB, MX, TXT
    // - has no records here, which every client takes as a reason to go on
    // without them.
    if (q.qtype != DNS_TYPE_A && q.qtype != DNS_TYPE_AAAA) {
        AnswerLookup(info, q, DnsRcode::OK, {}, MIN_DNS_TTL);
        return;
    }
    const int64_t now = NowMs();
    std::map<std::pair<std::string, uint16_t>, Cached>::const_iterator c = m_cache.find(std::make_pair(q.name, q.qtype));
    if (c != m_cache.end() && c->second.until > now) {
        const uint32_t left = (uint32_t)std::max<int64_t>(1, (c->second.until - now) / 1000);
        AnswerLookup(info, q, c->second.rcode, c->second.addrs, left);
        return;
    }
    if (m_lookups_waiting >= MAX_LOOKUPS) {
        AnswerLookup(info, q, DnsRcode::SERVER_FAILURE, {}, 0);
        return;
    }
    ++m_lookups_waiting;
    const std::weak_ptr<bool> alive = m_alive;
    m_client.Resolve(q.name, q.qtype == DNS_TYPE_A ? RESOLVE_V4 : RESOLVE_V6,
                     [this, alive, info, q](ResolveStatus status, const std::vector<IpAddr>& addrs, uint32_t ttl) {
                         if (alive.expired()) return;
                         if (m_lookups_waiting) --m_lookups_waiting;
                         const DnsRcode rcode = status == ResolveStatus::OK ? DnsRcode::OK
                                              : status == ResolveStatus::NO_SUCH_NAME ? DnsRcode::NO_SUCH_NAME
                                              : status == ResolveStatus::REFUSED ? DnsRcode::REFUSED
                                              : DnsRcode::SERVER_FAILURE;
                         const uint32_t keep = std::max(MIN_DNS_TTL, std::min(MAX_DNS_TTL, ttl));
                         if (rcode == DnsRcode::OK || rcode == DnsRcode::NO_SUCH_NAME) {
                             if (m_cache.size() >= MAX_CACHED_NAMES) m_cache.erase(m_cache.begin());
                             Cached& entry = m_cache[std::make_pair(q.name, q.qtype)];
                             entry.rcode = rcode;
                             entry.addrs = addrs;
                             entry.ttl = keep;
                             entry.until = NowMs() + (int64_t)keep * 1000;
                         }
                         AnswerLookup(info, q, rcode, addrs, keep);
                     });
}

void SystemInterface::AnswerLookup(const PacketInfo& info, const DnsQuery& q, DnsRcode rcode,
                                   const std::vector<IpAddr>& addrs, uint32_t ttl)
{
    ToComputer(BuildUdp(info.dst, info.dst_port, info.src, info.src_port, BuildDnsAnswer(q, rcode, addrs, ttl)));
}

} // namespace overlay
