// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/localproxy.h>

#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <overlay/gateway.h>
#include <overlay/gatewayclient.h>
#include <overlay/gatewayproto.h>
#include <overlay/limits.h>
#include <overlay/netstack.h>
#include <tinyformat.h>
#include <util/time.h>

#include <lwip/ip.h>
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

std::unique_ptr<LocalProxy> g_local_proxy;

namespace {

// SOCKS5 replies (RFC 1928).
constexpr uint8_t REP_OK = 0;
constexpr uint8_t REP_FAILURE = 1;
constexpr uint8_t REP_NOT_ALLOWED = 2;
constexpr uint8_t REP_NET_UNREACHABLE = 3;
constexpr uint8_t REP_HOST_UNREACHABLE = 4;
constexpr uint8_t REP_REFUSED = 5;
constexpr uint8_t REP_TTL_EXPIRED = 6;
constexpr uint8_t REP_COMMAND = 7;
constexpr uint8_t REP_ADDRESS_TYPE = 8;

LocalProxy* g_proxy_active = nullptr;

int64_t NowMs()
{
    return GetTimeMillis();
}

bool WouldBlock(int err)
{
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEINTR;
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

err_t ProxyConnected(void* arg, struct tcp_pcb*, err_t err)
{
    return g_proxy_active ? (err_t)g_proxy_active->OnConnected((uint64_t)(uintptr_t)arg, err) : (err_t)ERR_OK;
}

err_t ProxyRecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t)
{
    if (!g_proxy_active) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    return g_proxy_active->OnRecv((uint64_t)(uintptr_t)arg, pcb, p);
}

err_t ProxySent(void* arg, struct tcp_pcb*, u16_t)
{
    return g_proxy_active ? (err_t)g_proxy_active->OnSent((uint64_t)(uintptr_t)arg) : (err_t)ERR_OK;
}

void ProxyError(void* arg, err_t err)
{
    if (g_proxy_active) g_proxy_active->OnError((uint64_t)(uintptr_t)arg, err);
}

void Detach(struct tcp_pcb* pcb)
{
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
}

} // namespace

LocalProxy::LocalProxy(GatewayClient& client, uint16_t port) : m_client(client), m_port(port) {}

LocalProxy::~LocalProxy()
{
    Stop();
}

bool LocalProxy::Start(std::string& error)
{
    NetStack& stack = GetNetStack();
    if (!stack.Running()) {
        error = "the node's TCP/IP stack is not running";
        return false;
    }
    m_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listen == INVALID_SOCKET) {
        error = "cannot open a socket: " + NetworkErrorString(WSAGetLastError());
        return false;
    }
#ifndef WIN32
    int one = 1;
    setsockopt(m_listen, SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&one, sizeof(one));
#endif
    struct sockaddr_in at;
    std::memset(&at, 0, sizeof(at));
    at.sin_family = AF_INET;
    // Loopback only: the proxy is for programs on this computer, never for
    // anyone who can reach it over a network.
    at.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    at.sin_port = htons(m_port);
    if (bind(m_listen, (struct sockaddr*)&at, sizeof(at)) == SOCKET_ERROR ||
        listen(m_listen, SOMAXCONN) == SOCKET_ERROR || !SetSocketNonBlocking(m_listen, true)) {
        error = strprintf("cannot listen on 127.0.0.1:%u: %s. Another program is probably using that port; "
                          "choose another with -gatewayproxyport.", m_port, NetworkErrorString(WSAGetLastError()));
        CloseSocket(m_listen);
        return false;
    }
    stack.RunSync([this, &stack] {
        g_proxy_active = this;
        stack.Watch(m_listen, true, false, [this](bool, bool, bool) { OnListen(); });
        m_tick = stack.AddTick([this] { Tick(); });
        m_client.SetGatewayGone([this](uint64_t path) { OnGatewayGone(path); });
    });
    LogPrintf("local proxy: SOCKS5 on 127.0.0.1:%u, out through the network's gateways\n", m_port);
    return true;
}

void LocalProxy::Stop()
{
    if (m_listen == INVALID_SOCKET) return;
    NetStack& stack = GetNetStack();
    auto teardown = [this, &stack] {
        std::vector<uint64_t> ids;
        for (const std::pair<const uint64_t, Session>& s : m_sessions) ids.push_back(s.first);
        for (uint64_t id : ids) {
            std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
            if (it != m_sessions.end()) Close(it->second);
        }
        stack.Unwatch(m_listen);
        if (m_tick) stack.RemoveTick(m_tick);
        m_tick = 0;
        m_client.SetGatewayGone(nullptr);
        if (g_proxy_active == this) g_proxy_active = nullptr;
    };
    if (stack.Running()) {
        stack.RunSync(teardown);
    } else {
        teardown();
    }
    CloseSocket(m_listen);
}

void LocalProxy::OnListen()
{
    for (;;) {
        SOCKET c = accept(m_listen, nullptr, nullptr);
        if (c == INVALID_SOCKET) break;
        if (!IsSelectableSocket(c) || m_sessions.size() >= MAX_SESSIONS || !SetSocketNonBlocking(c, true)) {
            CloseSocket(c);
            continue;
        }
        SetSocketNoDelay(c);
        Session s;
        s.id = ++m_next_id;
        s.sock = c;
        s.deadline = NowMs() + HANDSHAKE_TIMEOUT_MS;
        const uint64_t id = s.id;
        m_sessions.emplace(id, std::move(s));
        ++m_session_count;
        GetNetStack().Watch(c, true, false, [this, id](bool r, bool w, bool e) { OnSocket(id, r, w, e); });
    }
}

void LocalProxy::OnSocket(uint64_t id, bool readable, bool, bool failed)
{
    std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
    if (it == m_sessions.end()) return;
    Session& s = it->second;
    if (failed) {
        Close(s);
        return;
    }
    if (readable && !s.local_eof) {
        uint8_t buf[16384];
        while (s.in.size() < MAX_BUFFER) {
            const int n = recv(s.sock, (char*)buf, sizeof(buf), 0);
            if (n > 0) {
                s.in.insert(s.in.end(), buf, buf + n);
                continue;
            }
            if (n == 0) {
                s.local_eof = true;
                break;
            }
            if (WouldBlock(WSAGetLastError())) break;
            Close(s);
            return;
        }
    }
    if ((s.stage == Stage::GREETING || s.stage == Stage::REQUEST) && !s.closing) {
        if (!Handshake(s)) return;
    }
    Pump(id);
}

void LocalProxy::Reply(Session& s, uint8_t code)
{
    // The bound address is not this proxy's to tell: zeros, as Tor sends.
    const uint8_t reply[10] = {5, code, 0, 1, 0, 0, 0, 0, 0, 0};
    s.out.insert(s.out.end(), reply, reply + sizeof(reply));
    s.ours += sizeof(reply);
    if (code == REP_OK) {
        s.stage = Stage::RELAY;
    } else {
        s.closing = true;
    }
}

bool LocalProxy::Handshake(Session& s)
{
    if (s.stage == Stage::GREETING) {
        if (s.in.size() < 2) return true;
        if (s.in[0] != 5) {
            Close(s);
            return false;
        }
        const size_t n = s.in[1];
        if (s.in.size() < 2 + n) return true;
        const bool open = std::find(s.in.begin() + 2, s.in.begin() + 2 + n, 0) != s.in.begin() + 2 + n;
        s.in.erase(s.in.begin(), s.in.begin() + 2 + n);
        const uint8_t answer[2] = {5, (uint8_t)(open ? 0 : 0xff)};
        s.out.insert(s.out.end(), answer, answer + 2);
        s.ours += 2;
        if (!open) {
            s.closing = true;
            return true;
        }
        s.stage = Stage::REQUEST;
    }
    if (s.in.size() < 5) return true;
    if (s.in[0] != 5) {
        Close(s);
        return false;
    }
    const uint8_t cmd = s.in[1], atyp = s.in[3];
    size_t need;
    if (atyp == 1) {
        need = 4 + 4 + 2;
    } else if (atyp == 4) {
        need = 4 + 16 + 2;
    } else if (atyp == 3) {
        need = 5 + (size_t)s.in[4] + 2;
    } else {
        Reply(s, REP_ADDRESS_TYPE);
        return true;
    }
    if (s.in.size() < need) return true;
    s.dst_port = (uint16_t)((s.in[need - 2] << 8) | s.in[need - 1]);
    std::string name;
    if (atyp == 1) {
        s.dst = IpAddr::V4(s.in[4], s.in[5], s.in[6], s.in[7]);
    } else if (atyp == 4) {
        std::array<uint8_t, 16> b;
        std::copy(s.in.begin() + 4, s.in.begin() + 20, b.begin());
        s.dst = IpAddr::V6(b);
    } else {
        name.assign((const char*)s.in.data() + 5, s.in[4]);
    }
    // What follows the request, if the program did not wait, is for the site.
    s.in.erase(s.in.begin(), s.in.begin() + need);
    if (cmd != 1) {
        Reply(s, REP_COMMAND);
        return true;
    }
    if (atyp != 3) {
        Connect(s);
        return true;
    }

    std::transform(name.begin(), name.end(), name.begin(), [](char c) { return (char)tolower((unsigned char)c); });
    // An address written as a name is used as it is.
    CNetAddr literal;
    if (LookupHost(name, literal, false)) {
        IpAddr a;
        if (NetAddrToIp(literal, a)) {
            s.dst = a;
            Connect(s);
            return true;
        }
    }
    // Never sent out: a .bps name would tell a gateway which hidden site
    // someone wanted, and a home-network name means nothing out there.
    if (!IsResolvableName(name) || IsLocalOnlyName(name)) {
        LogPrint(BCLog::NET, "local proxy: not sending the name %s to a gateway\n", name);
        Reply(s, REP_HOST_UNREACHABLE);
        return true;
    }
    s.stage = Stage::RESOLVING;
    s.deadline = NowMs() + CONNECT_TIMEOUT_MS;
    const uint64_t id = s.id;
    m_client.Resolve(name, RESOLVE_ANY, [this, id](ResolveStatus status, const std::vector<IpAddr>& addrs) {
        std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
        if (it == m_sessions.end() || it->second.stage != Stage::RESOLVING) return;
        Session& t = it->second;
        if (status != ResolveStatus::OK || addrs.empty()) {
            Reply(t, status == ResolveStatus::FAILED || status == ResolveStatus::REFUSED ? REP_NET_UNREACHABLE : REP_HOST_UNREACHABLE);
        } else {
            // IPv4 first where there is a choice: it is what every gateway can reach.
            const std::vector<IpAddr>::const_iterator v4 =
                std::find_if(addrs.begin(), addrs.end(), [](const IpAddr& a) { return a.version == 4; });
            t.dst = v4 != addrs.end() ? *v4 : addrs.front();
            Connect(t);
        }
        GetNetStack().Post([this, id] { Pump(id); });
    });
    return true;
}

void LocalProxy::Connect(Session& s)
{
    if (!m_client.LocalAllowed() && !IsPublicAddress(s.dst)) {
        Reply(s, REP_NOT_ALLOWED);
        return;
    }
    uint64_t path = 0;
    if (!m_client.Choose(IPPROTO_TCP_NUM, s.dst_port, path)) {
        // No gateway at all, or none that carries this port.
        Reply(s, m_client.AnyOpen() ? REP_NOT_ALLOWED : REP_NET_UNREACHABLE);
        return;
    }
    struct tcp_pcb* pcb = tcp_new_ip_type(s.dst.version == 6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
    if (pcb == nullptr || tcp_bind(pcb, s.dst.version == 6 ? IP6_ADDR_ANY : IP4_ADDR_ANY, 0) != ERR_OK) {
        if (pcb) tcp_abort(pcb);
        Reply(s, REP_FAILURE);
        return;
    }
    s.local_port = pcb->local_port;
    s.path = path;
    // The flow first, so the very first segment knows which gateway it goes to.
    m_client.AddFlow(IPPROTO_TCP_NUM, s.local_port, s.dst, s.dst_port, path);
    s.flow = true;
    tcp_arg(pcb, (void*)(uintptr_t)s.id);
    tcp_recv(pcb, ProxyRecv);
    tcp_sent(pcb, ProxySent);
    tcp_err(pcb, ProxyError);
    tcp_nagle_disable(pcb);
    ip_addr_t dst;
    ToLwip(s.dst, dst);
    s.pcb = pcb;
    s.stage = Stage::CONNECTING;
    s.deadline = NowMs() + CONNECT_TIMEOUT_MS;
    if (tcp_connect(pcb, &dst, s.dst_port, ProxyConnected) != ERR_OK) {
        Detach(pcb);
        tcp_abort(pcb);
        s.pcb = nullptr;
        Reply(s, REP_FAILURE);
    }
}

int8_t LocalProxy::OnConnected(uint64_t id, int8_t err)
{
    std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
    if (it == m_sessions.end() || it->second.stage != Stage::CONNECTING) return ERR_OK;
    Reply(it->second, err == ERR_OK ? REP_OK : REP_FAILURE);
    ++m_served;
    GetNetStack().Post([this, id] { Pump(id); });
    return ERR_OK;
}

int8_t LocalProxy::OnRecv(uint64_t id, struct tcp_pcb* pcb, struct pbuf* p)
{
    std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
    if (it == m_sessions.end() || it->second.pcb != pcb) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    Session& s = it->second;
    if (p == nullptr) {
        s.remote_eof = true;
    } else {
        const size_t at = s.out.size();
        s.out.resize(at + p->tot_len);
        pbuf_copy_partial(p, s.out.data() + at, p->tot_len, 0);
        pbuf_free(p);
    }
    GetNetStack().Post([this, id] { Pump(id); });
    return ERR_OK;
}

int8_t LocalProxy::OnSent(uint64_t id)
{
    GetNetStack().Post([this, id] { Pump(id); });
    return ERR_OK;
}

void LocalProxy::OnError(uint64_t id, int8_t err)
{
    // lwIP has freed the connection: a reset from the gateway or the site, or its retries ran out.
    std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
    if (it == m_sessions.end()) return;
    Session& s = it->second;
    s.pcb = nullptr;
    if (s.stage == Stage::CONNECTING) {
        Reply(s, err == ERR_RST ? REP_REFUSED : REP_HOST_UNREACHABLE);
    } else {
        s.remote_eof = true;
        s.closing = true;
    }
    GetNetStack().Post([this, id] { Pump(id); });
}

void LocalProxy::Pump(uint64_t id)
{
    std::map<uint64_t, Session>::iterator it = m_sessions.find(id);
    if (it == m_sessions.end()) return;
    Session& s = it->second;

    // To the program. The window to the site opens only as fast as the
    // program reads, so a slow reader slows the site, not the node's memory.
    size_t sent = 0;
    while (sent < s.out.size()) {
        const int n = send(s.sock, (const char*)s.out.data() + sent, (int)std::min<size_t>(s.out.size() - sent, 1 << 16), MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (WouldBlock(WSAGetLastError())) break;
        Close(s);
        return;
    }
    if (sent) {
        s.out.erase(s.out.begin(), s.out.begin() + sent);
        // Only the site's bytes reopen its window, not the proxy's own replies.
        const size_t own = std::min(sent, s.ours);
        s.ours -= own;
        for (size_t left = sent - own; left && s.pcb && s.stage == Stage::RELAY;) {
            const u16_t c = (u16_t)std::min<size_t>(left, 0xffff);
            tcp_recved(s.pcb, c);
            left -= c;
        }
    }
    if (s.stage == Stage::RELAY && s.remote_eof && s.out.empty() && !s.local_shut) {
        shutdown(s.sock, BPS_SHUT_WR);
        s.local_shut = true;
    }

    // To the site.
    if (s.stage == Stage::RELAY && s.pcb) {
        bool wrote = false;
        while (!s.in.empty()) {
            const size_t room = tcp_sndbuf(s.pcb);
            if (room == 0 || tcp_sndqueuelen(s.pcb) + 16 >= TCP_SND_QUEUELEN) break;
            // Paced to stay under the relays' caps; Tick comes back for the rest.
            const uint64_t allowance = m_client.PaceAvailable(s.path);
            if (allowance == 0) break;
            const size_t n = (size_t)std::min<uint64_t>(std::min<size_t>(std::min(room, s.in.size()), 0xffff), allowance);
            if (tcp_write(s.pcb, s.in.data(), (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) break;
            m_client.PaceUse(s.path, n);
            s.in.erase(s.in.begin(), s.in.begin() + n);
            wrote = true;
        }
        if (s.local_eof && s.in.empty() && !s.remote_shut) {
            tcp_shutdown(s.pcb, 0, 1);
            s.remote_shut = true;
            wrote = true;
        }
        if (wrote && s.pcb) tcp_output(s.pcb);
    }

    const bool finished = (s.closing && s.out.empty()) ||
                          (s.stage == Stage::RELAY && s.local_eof && s.remote_eof && s.out.empty() && s.in.empty()) ||
                          (s.local_eof && s.stage != Stage::RELAY && s.out.empty());
    if (finished) {
        Close(s);
        return;
    }
    UpdateInterest(s);
}

void LocalProxy::UpdateInterest(const Session& s)
{
    const bool read = !s.local_eof && !s.closing && s.in.size() < MAX_BUFFER;
    GetNetStack().SetInterest(s.sock, read, !s.out.empty());
}

void LocalProxy::Close(Session& s)
{
    if (s.pcb) {
        Detach(s.pcb);
        if (s.closing || tcp_close(s.pcb) != ERR_OK) tcp_abort(s.pcb);
        s.pcb = nullptr;
    }
    if (s.flow) m_client.RemoveFlow(IPPROTO_TCP_NUM, s.local_port, s.dst, s.dst_port);
    GetNetStack().Unwatch(s.sock);
    CloseSocket(s.sock);
    m_sessions.erase(s.id);
    --m_session_count;
}

void LocalProxy::OnGatewayGone(uint64_t path)
{
    std::vector<uint64_t> ids;
    for (std::pair<const uint64_t, Session>& e : m_sessions) {
        Session& s = e.second;
        if (s.path != path || !s.flow) continue;
        if (s.pcb) {
            Detach(s.pcb);
            tcp_abort(s.pcb);
            s.pcb = nullptr;
        }
        if (s.stage == Stage::CONNECTING) {
            Reply(s, REP_NET_UNREACHABLE);
        } else {
            s.closing = true;
        }
        ids.push_back(s.id);
    }
    for (uint64_t id : ids) Pump(id);
}

void LocalProxy::Tick()
{
    const int64_t now = NowMs();
    std::vector<uint64_t> late;
    for (std::pair<const uint64_t, Session>& e : m_sessions) {
        Session& s = e.second;
        // Uploads waiting for their allowance.
        if (s.stage == Stage::RELAY && !s.in.empty() && s.pcb && !s.closing) {
            late.push_back(s.id);
            continue;
        }
        if (s.stage == Stage::RELAY || s.closing || now <= s.deadline) continue;
        if (s.stage == Stage::RESOLVING || s.stage == Stage::CONNECTING) {
            if (s.pcb) {
                Detach(s.pcb);
                tcp_abort(s.pcb);
                s.pcb = nullptr;
            }
            Reply(s, REP_TTL_EXPIRED);
        } else {
            s.closing = true;
        }
        late.push_back(s.id);
    }
    for (uint64_t id : late) Pump(id);
}

} // namespace overlay
