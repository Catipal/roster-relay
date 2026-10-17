// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/gatewayclient.h>

#include <logging.h>
#include <overlay/netstack.h>
#include <random.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>

#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include <algorithm>
#include <cstring>

namespace overlay {

std::unique_ptr<GatewayClient> g_gateway_client;

namespace {

/*
 * The visitor's own addresses inside the stack. They never leave this
 * computer: a gateway gives every connection an address of its own on its
 * side, so what a visitor calls itself does not matter, only that it is not
 * an address a visitor might want to reach.
 */
constexpr uint8_t VISITOR_V4[4] = {10, 77, 0, 2};
const uint32_t VISITOR_V6[4] = {PP_HTONL(0xfd627073UL), PP_HTONL(0x76690000UL), 0, PP_HTONL(2)};

GatewayClient* g_client_active = nullptr;

int64_t NowMs()
{
    return GetTimeMillis();
}

err_t ClientOutput4(struct netif*, struct pbuf* p, const ip4_addr_t*)
{
    if (g_client_active) g_client_active->OnStackOutput(p);
    return ERR_OK;
}

err_t ClientOutput6(struct netif*, struct pbuf* p, const ip6_addr_t*)
{
    if (g_client_active) g_client_active->OnStackOutput(p);
    return ERR_OK;
}

err_t ClientNetifInit(struct netif* n)
{
    n->output = ClientOutput4;
    n->output_ip6 = ClientOutput6;
    n->mtu = (u16_t)MAX_GATEWAY_PACKET;
    n->name[0] = 'o';
    n->name[1] = 'v';
    return ERR_OK;
}

} // namespace

GatewayClient::GatewayClient(int pool, int hops, bool allow_local, Allowed allowed, Candidates candidates,
                             Meeter meet, Closer close, Sender send)
    : m_pool(std::max(1, pool)), m_hops(std::max(1, std::min(MAX_MEET_HOPS, hops))), m_allow_local(allow_local),
      m_allowed_check(std::move(allowed)), m_candidates(std::move(candidates)), m_meet(std::move(meet)),
      m_close(std::move(close)), m_send(std::move(send))
{
    m_pacer.Configure(0, (DEFAULT_RELAY_PATH_RATE_KIB << 10) * PACE_SHARE_NUM / PACE_SHARE_DEN);
}

uint64_t GatewayClient::PaceAvailable(uint64_t path)
{
    return m_pacer.Available(path, NowMs());
}

void GatewayClient::PaceUse(uint64_t path, size_t bytes)
{
    m_pacer.Forward(path, bytes, NowMs());
}

GatewayClient::~GatewayClient()
{
    Stop();
}

bool GatewayClient::Start(std::string& error)
{
    NetStack& stack = GetNetStack();
    if (!stack.Running()) {
        error = "the node's TCP/IP stack is not running";
        return false;
    }
    if (g_client_active) {
        error = "a gateway client is already running in this process";
        return false;
    }
    bool ok = false;
    stack.RunSync([&] {
        m_netif = new struct netif;
        std::memset(m_netif, 0, sizeof(*m_netif));
        ip4_addr_t addr, mask, gw;
        IP4_ADDR(&addr, VISITOR_V4[0], VISITOR_V4[1], VISITOR_V4[2], VISITOR_V4[3]);
        IP4_ADDR(&mask, 255, 255, 255, 255);
        IP4_ADDR(&gw, 0, 0, 0, 0);
        if (netif_add(m_netif, &addr, &mask, &gw, nullptr, ClientNetifInit, ip_input) == nullptr) {
            error = "cannot add the overlay's interface to the stack";
            delete m_netif;
            m_netif = nullptr;
            return;
        }
        ip6_addr_t v6;
        IP6_ADDR(&v6, VISITOR_V6[0], VISITOR_V6[1], VISITOR_V6[2], VISITOR_V6[3]);
        s8_t idx = -1;
        if (netif_add_ip6_address(m_netif, &v6, &idx) == ERR_OK) netif_ip6_addr_set_state(m_netif, idx, IP6_ADDR_PREFERRED);
        netif_set_up(m_netif);
        netif_set_link_up(m_netif);
        // Everything that is not the stack's own goes out to the overlay.
        netif_set_default(m_netif);
        g_client_active = this;
        m_tick = GetNetStack().AddTick([this] { Tick(); });
        ok = true;
    });
    if (!ok) return false;
    m_running = true;
    m_next_allowed_check = 0;
    m_interrupt.reset();
    m_thread = std::thread(&TraceThread<std::function<void()>>, "gwclient",
                           std::function<void()>(std::bind(&GatewayClient::ThreadWorker, this)));
    return true;
}

void GatewayClient::Stop()
{
    m_interrupt();
    if (m_thread.joinable()) m_thread.join();
    m_running = false;

    std::vector<Meeting> closing;
    {
        LOCK(m_mutex);
        for (const std::pair<const uint64_t, Entry>& e : m_entries) closing.push_back(e.second.meeting);
        m_entries.clear();
        m_flow_counts.clear();
    }
    for (const Meeting& m : closing) {
        if (m_close) m_close(m);
    }

    NetStack& stack = GetNetStack();
    auto teardown = [this, &stack] {
        std::map<uint32_t, Pending> pending;
        pending.swap(m_pending);
        for (std::pair<const uint32_t, Pending>& p : pending) p.second.done(ResolveStatus::FAILED, {});
        m_flows.clear();
        if (m_netif) {
            netif_remove(m_netif);
            delete m_netif;
            m_netif = nullptr;
        }
        if (m_tick) stack.RemoveTick(m_tick);
        m_tick = 0;
        if (g_client_active == this) g_client_active = nullptr;
    };
    if (stack.Running()) {
        stack.RunSync(teardown);
    } else {
        teardown();
    }
}

bool GatewayClient::Owns(uint64_t path) const
{
    LOCK(m_mutex);
    return m_entries.count(path) > 0;
}

void GatewayClient::HandleApp(const Hop& from, std::vector<uint8_t>&& payload)
{
    if (!from.via_path || !m_running) return;
    GatewayMessage m;
    if (!DecodeGatewayMessage(payload, m)) return;
    {
        LOCK(m_mutex);
        std::map<uint64_t, Entry>::iterator it = m_entries.find(from.path);
        if (it == m_entries.end()) return;
        Entry& e = it->second;
        e.last_heard = NowMs();
        if (m.kind == GatewayKind::STATUS) {
            if (m.state != GatewayState::OPEN && (!e.known || e.state == GatewayState::OPEN)) e.off_since = e.last_heard;
            if (!e.known || e.state != m.state) {
                LogPrint(BCLog::NET, "gateway client: %s is %s\n", HexStr(e.key).substr(0, 16),
                         m.state == GatewayState::OPEN ? "open" : m.state == GatewayState::OFF ? "off" : "closed for today");
            }
            e.known = true;
            e.state = m.state;
            e.tcp = std::set<uint16_t>(m.tcp_ports.begin(), m.tcp_ports.end());
            e.udp = std::set<uint16_t>(m.udp_ports.begin(), m.udp_ports.end());
            return;
        }
    }
    if (m.kind != GatewayKind::PACKET && m.kind != GatewayKind::FRAG && m.kind != GatewayKind::RESOLVED) return;
    bool post = false;
    {
        LOCK(m_inbox_mutex);
        if (m_inbox.size() >= 4096) return;
        m_inbox.emplace_back(from.path, std::move(payload));
        if (!m_drain_posted) {
            m_drain_posted = true;
            post = true;
        }
    }
    if (post) GetNetStack().Post([this] { DrainInbox(); });
}

void GatewayClient::DrainInbox()
{
    std::deque<std::pair<uint64_t, std::vector<uint8_t>>> work;
    {
        LOCK(m_inbox_mutex);
        work.swap(m_inbox);
        m_drain_posted = false;
    }
    if (!m_netif) return;
    for (const std::pair<uint64_t, std::vector<uint8_t>>& item : work) {
        GatewayMessage m;
        if (!DecodeGatewayMessage(item.second, m)) continue;
        std::vector<uint8_t> pkt;
        if (m.kind == GatewayKind::RESOLVED) {
            std::map<uint32_t, Pending>::iterator it = m_pending.find(m.request);
            if (it == m_pending.end()) continue;
            Resolved done = std::move(it->second.done);
            m_pending.erase(it);
            done(m.status, m.addrs);
            continue;
        }
        if (m.kind == GatewayKind::PACKET) {
            pkt = std::move(m.bytes);
        } else if (!m_reassembler.Add(item.first, m, NowMs(), pkt)) {
            continue;
        }
        // A gateway is a stranger too: what it sends is checked like anything else.
        PacketInfo info;
        std::string why;
        if (!ParsePacket(pkt, info, why) || !info.IsTcp()) continue;
        struct pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)pkt.size(), PBUF_RAM);
        if (p == nullptr) continue;
        pbuf_take(p, pkt.data(), (u16_t)pkt.size());
        if (m_netif->input(p, m_netif) != ERR_OK) pbuf_free(p);
    }
}

void GatewayClient::OnStackOutput(struct pbuf* p)
{
    std::vector<uint8_t> pkt(p->tot_len);
    pbuf_copy_partial(p, pkt.data(), p->tot_len, 0);
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why)) return;
    std::map<FlowKey, uint64_t>::const_iterator it =
        m_flows.find(FlowKey(info.protocol, info.src_port, info.dst, info.dst_port));
    if (it == m_flows.end()) return;
    const uint64_t path = it->second;
    if (!Owns(path)) return;
    for (const std::vector<uint8_t>& m : EncodePacket(pkt, ++m_frag_id)) m_send(path, m);
}

bool GatewayClient::Choose(uint8_t protocol, uint16_t port, uint64_t& path)
{
    LOCK(m_mutex);
    std::vector<uint64_t> open;
    for (const std::pair<const uint64_t, Entry>& e : m_entries) {
        const Entry& g = e.second;
        if (!g.known || g.state != GatewayState::OPEN) continue;
        const std::set<uint16_t>& ports = protocol == IPPROTO_UDP_NUM ? g.udp : g.tcp;
        if (ports.count(port)) open.push_back(e.first);
    }
    if (open.empty()) return false;
    // A different gateway for each connection, so none sees all of them.
    path = open[m_rr++ % open.size()];
    return true;
}

bool GatewayClient::AnyOpen() const
{
    LOCK(m_mutex);
    for (const std::pair<const uint64_t, Entry>& e : m_entries) {
        if (e.second.known && e.second.state == GatewayState::OPEN) return true;
    }
    return false;
}

void GatewayClient::AddFlow(uint8_t protocol, uint16_t local_port, const IpAddr& dst, uint16_t dst_port, uint64_t path)
{
    m_flows[FlowKey(protocol, local_port, dst, dst_port)] = path;
    ++m_flow_total;
    LOCK(m_mutex);
    ++m_flow_counts[path];
}

void GatewayClient::RemoveFlow(uint8_t protocol, uint16_t local_port, const IpAddr& dst, uint16_t dst_port)
{
    std::map<FlowKey, uint64_t>::iterator it = m_flows.find(FlowKey(protocol, local_port, dst, dst_port));
    if (it == m_flows.end()) return;
    const uint64_t path = it->second;
    m_flows.erase(it);
    --m_flow_total;
    LOCK(m_mutex);
    std::map<uint64_t, uint64_t>::iterator c = m_flow_counts.find(path);
    if (c != m_flow_counts.end() && c->second && --c->second == 0) m_flow_counts.erase(c);
}

void GatewayClient::Resolve(const std::string& name, uint8_t family, Resolved done)
{
    uint64_t path = 0;
    {
        LOCK(m_mutex);
        std::vector<uint64_t> open;
        for (const std::pair<const uint64_t, Entry>& e : m_entries) {
            if (e.second.known && e.second.state == GatewayState::OPEN) open.push_back(e.first);
        }
        if (!open.empty()) path = open[m_rr++ % open.size()];
    }
    if (path == 0) {
        done(ResolveStatus::FAILED, {});
        return;
    }
    const uint32_t id = ++m_next_request;
    Pending p;
    p.done = std::move(done);
    p.deadline = NowMs() + RESOLVE_TIMEOUT_MS;
    m_pending[id] = std::move(p);
    ++m_lookups;
    m_send(path, EncodeResolve(id, family, name));
}

void GatewayClient::Tick()
{
    const int64_t now = NowMs();
    std::vector<Resolved> late;
    for (std::map<uint32_t, Pending>::iterator it = m_pending.begin(); it != m_pending.end();) {
        if (now > it->second.deadline) {
            late.push_back(std::move(it->second.done));
            it = m_pending.erase(it);
        } else {
            ++it;
        }
    }
    for (Resolved& done : late) done(ResolveStatus::FAILED, {});
}

void GatewayClient::Drop(uint64_t path, int64_t retry_after)
{
    std::map<uint64_t, Entry>::iterator it = m_entries.find(path);
    if (it == m_entries.end()) return;
    m_cooldown[it->second.key] = NowMs() + retry_after;
    m_entries.erase(it);
    m_flow_counts.erase(path);
}

void GatewayClient::ThreadWorker()
{
    while (m_interrupt.sleep_for(std::chrono::seconds{1})) {
        Round();
    }
}

void GatewayClient::Round()
{
    const int64_t now = NowMs();

    std::vector<Meeting> closing;
    std::vector<uint64_t> gone;
    std::vector<uint64_t> hello;
    bool allowed;
    {
        LOCK(m_mutex);
        allowed = m_allowed;
    }
    if (now >= m_next_allowed_check) {
        std::string why;
        allowed = m_allowed_check ? m_allowed_check(why) : true;
        m_next_allowed_check = now + ALLOWED_CHECK_MS;
        LOCK(m_mutex);
        if (allowed != m_allowed) {
            LogPrintf("gateway client: %s\n", allowed ? "using the network's gateways" : "not using gateways: " + why);
        }
        m_allowed = allowed;
        m_why = why;
    }

    {
        LOCK(m_mutex);
        for (const std::pair<const uint64_t, Entry>& e : m_entries) {
            const Entry& g = e.second;
            const std::map<uint64_t, uint64_t>::const_iterator busy = m_flow_counts.find(e.first);
            int64_t retry = -1;
            if (!allowed) {
                retry = 0;
            } else if (now - g.last_heard > SILENT_LIMIT_MS ||
                       (busy != m_flow_counts.end() && busy->second > 0 && now - g.last_heard > BUSY_SILENCE_MS)) {
                retry = RETRY_AFTER_MS;
            } else if (g.known && g.state == GatewayState::OFF && now - g.off_since > 2 * 60 * 1000) {
                retry = OFF_RETRY_AFTER_MS;
            }
            if (retry >= 0) {
                gone.push_back(e.first);
                closing.push_back(g.meeting);
            } else if (now - g.last_hello >= HELLO_EVERY_MS) {
                hello.push_back(e.first);
            }
        }
        for (uint64_t path : gone) {
            const std::map<uint64_t, Entry>::const_iterator it = m_entries.find(path);
            const bool silent = it != m_entries.end() && now - it->second.last_heard > BUSY_SILENCE_MS;
            Drop(path, !allowed ? 0 : silent ? RETRY_AFTER_MS : OFF_RETRY_AFTER_MS);
        }
        for (uint64_t path : hello) m_entries[path].last_hello = now;
    }
    for (const Meeting& m : closing) {
        if (m_close) m_close(m);
    }
    for (uint64_t path : gone) {
        GetNetStack().Post([this, path] {
            for (std::map<FlowKey, uint64_t>::iterator it = m_flows.begin(); it != m_flows.end();) {
                if (it->second == path) {
                    it = m_flows.erase(it);
                    --m_flow_total;
                } else {
                    ++it;
                }
            }
            m_reassembler.Forget(path);
            if (m_gone) m_gone(path);
        });
    }
    // Asking how a gateway is keeps its meeting path from idling out too.
    for (uint64_t path : hello) m_send(path, EncodeHello());
    if (!allowed) return;

    // Fill the pool: one new meeting a round, since each takes seconds.
    std::set<roster::KeyBytes> have;
    size_t usable = 0;
    {
        LOCK(m_mutex);
        for (const std::pair<const uint64_t, Entry>& e : m_entries) {
            have.insert(e.second.key);
            if (!e.second.known || e.second.state == GatewayState::OPEN) ++usable;
        }
        if (usable >= (size_t)m_pool || m_entries.size() >= 2 * (size_t)m_pool) return;
        for (std::map<roster::KeyBytes, int64_t>::iterator c = m_cooldown.begin(); c != m_cooldown.end();) {
            if (c->second <= now) {
                c = m_cooldown.erase(c);
            } else {
                have.insert(c->first);
                ++c;
            }
        }
    }
    std::vector<roster::KeyBytes> candidates = m_candidates ? m_candidates() : std::vector<roster::KeyBytes>();
    candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                                    [&have](const roster::KeyBytes& k) { return have.count(k) > 0; }),
                     candidates.end());
    if (candidates.empty()) return;
    FastRandomContext rng;
    const roster::KeyBytes key = candidates[rng.randrange(candidates.size())];

    Meeting meeting;
    std::string error;
    if (!m_meet(key, m_hops, meeting, error)) {
        ++m_meetings_failed;
        LogPrint(BCLog::NET, "gateway client: could not meet %s: %s\n", HexStr(key).substr(0, 16), error);
        LOCK(m_mutex);
        m_cooldown[key] = NowMs() + RETRY_AFTER_MS;
        m_last_error = error;
        return;
    }
    {
        LOCK(m_mutex);
        Entry e;
        e.key = key;
        e.meeting = meeting;
        e.since = e.last_heard = e.last_hello = NowMs();
        m_entries[meeting.path] = e;
    }
    LogPrint(BCLog::NET, "gateway client: met %s through %d relay(s)\n", HexStr(key).substr(0, 16), meeting.hops);
    m_send(meeting.path, EncodeHello());
}

GatewayClient::Stats GatewayClient::GetStats() const
{
    Stats s;
    s.hops = m_hops;
    s.flows = m_flow_total;
    s.lookups = m_lookups;
    s.meetings_failed = m_meetings_failed;
    LOCK(m_mutex);
    s.allowed = m_allowed;
    s.why = m_why;
    s.last_error = m_last_error;
    for (const std::pair<const uint64_t, Entry>& e : m_entries) {
        GatewayView v;
        v.key = e.second.key;
        v.known = e.second.known;
        v.state = e.second.state;
        v.since = e.second.since;
        std::map<uint64_t, uint64_t>::const_iterator c = m_flow_counts.find(e.first);
        v.flows = c == m_flow_counts.end() ? 0 : c->second;
        s.gateways.push_back(v);
    }
    return s;
}

} // namespace overlay
