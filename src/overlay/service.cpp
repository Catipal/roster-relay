// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/service.h>

#include <crypto/common.h>
#include <fs.h>
#include <index/rosterindex.h>
#include <logging.h>
#include <netbase.h>
#include <overlay/hosting.h>
#include <overlay/meeting.h>
#include <random.h>
#include <roster/peers.h>
#include <roster/view.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <util/memory.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>

namespace overlay {

std::unique_ptr<ServiceHub> g_services;

namespace {

#ifdef MSG_NOSIGNAL
const int SEND_FLAGS = MSG_NOSIGNAL;
#else
const int SEND_FLAGS = 0;
#endif

#ifndef SHUT_WR
#define SHUT_WR 1 // SD_SEND on Windows
#endif

void PutU32(std::vector<unsigned char>& out, uint32_t v) { unsigned char b[4]; WriteLE32(b, v); out.insert(out.end(), b, b + 4); }

std::vector<unsigned char> Message(uint8_t tag, uint32_t id, const std::string& text = std::string(), bool with_text = false)
{
    std::vector<unsigned char> out{tag};
    PutU32(out, id);
    if (with_text) {
        const std::string t = text.substr(0, 255);
        out.push_back((unsigned char)t.size());
        out.insert(out.end(), t.begin(), t.end());
    }
    return out;
}

bool SendTo(const Hop& to, const std::vector<unsigned char>& msg)
{
    if (!g_overlay) return false;
    return to.via_path ? g_overlay->SendSecret(to.path, msg) : g_overlay->SendApp(to.addr, msg);
}

bool WouldBlock()
{
    const int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS;
}

fs::path ServicesFile() { return GetDataDir() / "services"; }

} // namespace

bool ValidServiceName(const std::string& name)
{
    if (name.empty() || name.size() > MAX_SERVICE_NAME) return false;
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return true;
}

/** One stream and the local socket at its end. */
struct ServiceHub::Stream {
    explicit Stream(uint32_t id) : stream(id) {}

    Hop hop;
    ReliableStream stream;
    SOCKET sock{INVALID_SOCKET};
    bool visitor{false};
    bool open{false};             //!< the host said it is open (always, on the host's side)
    int64_t open_sent_ms{0};
    int64_t asked_ms{0};          //!< when the visitor first asked
    std::string service;
    roster::KeyBytes site{};
    std::shared_ptr<void> hold;   //!< keeps the visitor's path open
    std::vector<unsigned char> to_sock;
    std::vector<unsigned char> held;
    Filter filter;
    bool flushed{false};
    bool sock_eof{false};         //!< the local program has sent all it will
    bool sock_shut{false};        //!< told the local program nothing more is coming
    int64_t active_ms{0};
};

ServiceHub::ServiceHub(const roster::KeyBytes& self) : m_self(self) {}

ServiceHub::~ServiceHub() { Stop(); }

bool ServiceHub::Start(std::string& error)
{
    {
        LOCK(m_mutex);
        Load();
    }
    m_running = true;
    m_worker = std::thread([this] { util::ThreadRename("services"); ThreadWork(); });
    m_opener = std::thread([this] { util::ThreadRename("services-open"); ThreadOpen(); });
    UpdateMeeting();
    return true;
}

void ServiceHub::Stop()
{
    if (!m_running.exchange(false)) return;
    m_open_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
    if (m_opener.joinable()) m_opener.join();
    LOCK(m_mutex);
    for (auto& s : m_streams) {
        if (s.second->sock != INVALID_SOCKET) CloseSocket(s.second->sock);
    }
    m_streams.clear();
    for (auto& l : m_listeners) CloseSocket(l.second.sock);
    m_listeners.clear();
    for (Pending& p : m_pending) CloseSocket(p.sock);
    m_pending.clear();
}

// --- hosting --------------------------------------------------------------------------

void ServiceHub::Save() const
{
    fsbridge::ofstream f(ServicesFile(), std::ios::trunc);
    for (const auto& s : m_services) f << s.first << " " << s.second << "\n";
}

void ServiceHub::Load()
{
    fsbridge::ifstream f(ServicesFile());
    std::string name;
    unsigned port;
    while (f >> name >> port) {
        if (ValidServiceName(name) && port > 0 && port <= 65535 && m_services.size() < MAX_SERVICES) {
            m_services[name] = (uint16_t)port;
        }
    }
}

bool ServiceHub::Publish(const std::string& name, uint16_t port, std::string& error)
{
    if (!ValidServiceName(name)) {
        error = "a service's name is 1 to 32 of a-z, 0-9 and -";
        return false;
    }
    if (port == 0) {
        error = "the port must be the one the program listens on, on 127.0.0.1";
        return false;
    }
    {
        LOCK(m_mutex);
        if (!m_services.count(name) && m_services.size() >= MAX_SERVICES) {
            error = strprintf("at most %u services", MAX_SERVICES);
            return false;
        }
        m_services[name] = port;
        Save();
    }
    UpdateMeeting();
    LogPrintf("services: publishing %s at 127.0.0.1:%u\n", name, port);
    return true;
}

bool ServiceHub::Unpublish(const std::string& name)
{
    bool was;
    {
        LOCK(m_mutex);
        was = m_services.erase(name) > 0;
        Save();
    }
    UpdateMeeting();
    return was;
}

std::map<std::string, uint16_t> ServiceHub::Services() const
{
    LOCK(m_mutex);
    return m_services;
}

bool ServiceHub::Hidden() const
{
    if (!g_rosterindex) return false;
    roster::Record own;
    return !roster::SeenRevoked(m_self) &&
           roster::LiveAnnouncement(*g_rosterindex, m_self, g_rosterindex->GetSummary().best_block_height, own) &&
           roster::IsListedThroughOverlay(own.services, own.endpoints.size());
}

void ServiceHub::UpdateMeeting()
{
    bool any;
    {
        LOCK(m_mutex);
        any = !m_services.empty();
    }
    SetMeetNeed(MEET_FOR_SERVICE, any && Hidden());
}

// --- visiting -------------------------------------------------------------------------

bool ServiceHub::Forward(const roster::KeyBytes& site, const std::string& service, uint16_t local, uint16_t& bound,
                         std::string& error)
{
    if (!ValidServiceName(service)) {
        error = "a service's name is 1 to 32 of a-z, 0-9 and -";
        return false;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        error = strprintf("could not make a socket (%s)", NetworkErrorString(WSAGetLastError()));
        return false;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // this computer only
    sa.sin_port = htons(local);
    if (::bind(s, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR || listen(s, SOMAXCONN) == SOCKET_ERROR) {
        error = strprintf("cannot listen on 127.0.0.1:%u (%s)", local, NetworkErrorString(WSAGetLastError()));
        CloseSocket(s);
        return false;
    }
    socklen_t len = sizeof(sa);
    getsockname(s, (struct sockaddr*)&sa, &len);
    bound = ntohs(sa.sin_port);
    SetSocketNonBlocking(s, true);
    LOCK(m_mutex);
    Listener l;
    l.sock = s;
    l.site = site;
    l.service = service;
    m_listeners[bound] = l;
    return true;
}

bool ServiceHub::StopForward(uint16_t local)
{
    LOCK(m_mutex);
    auto it = m_listeners.find(local);
    if (it == m_listeners.end()) return false;
    CloseSocket(it->second.sock);
    m_listeners.erase(it);
    return true;
}

std::vector<ServiceHub::ForwardInfo> ServiceHub::Forwards() const
{
    LOCK(m_mutex);
    std::vector<ForwardInfo> out;
    for (const auto& l : m_listeners) {
        ForwardInfo f;
        f.site = l.second.site;
        f.service = l.second.service;
        f.local = l.first;
        for (const auto& s : m_streams) {
            if (s.second->visitor && s.second->site == f.site && s.second->service == f.service) ++f.open;
        }
        out.push_back(f);
    }
    return out;
}

void ServiceHub::Attach(SOCKET sock, const roster::KeyBytes& site, const std::string& service,
                        std::vector<unsigned char> prefix, Filter filter)
{
    LOCK(m_mutex);
    if (!m_running || m_pending.size() >= MAX_STREAMS) {
        CloseSocket(sock);
        return;
    }
    Pending p;
    p.sock = sock;
    p.site = site;
    p.service = service;
    p.prefix = std::move(prefix);
    p.filter = std::move(filter);
    m_pending.push_back(std::move(p));
    m_open_cv.notify_all();
}

void ServiceHub::ThreadOpen()
{
    // Building a path takes seconds, so it is done here, one connection at a
    // time, and the worker carries on moving everyone else's bytes.
    while (m_running) {
        Pending p;
        {
            WAIT_LOCK(m_mutex, lock);
            if (m_pending.empty()) {
                m_open_cv.wait_for(lock, std::chrono::milliseconds{200});
                continue;
            }
            p = std::move(m_pending.front());
            m_pending.pop_front();
        }
        Hop to;
        std::shared_ptr<void> hold;
        std::string error;
        if (!OpenSitePath(p.site, to, hold, nullptr, error)) {
            LogPrint(BCLog::NET, "services: cannot reach %s for %s: %s\n", HexStr(p.site), p.service, error);
            CloseSocket(p.sock);
            continue;
        }
        const int64_t now = GetTimeMillis();
        LOCK(m_mutex);
        if (m_streams.size() >= MAX_STREAMS) {
            CloseSocket(p.sock);
            continue;
        }
        uint32_t id;
        do id = (uint32_t)GetRand(std::numeric_limits<uint32_t>::max() - 1) + 1; while (m_streams.count({to, id}));
        std::unique_ptr<Stream> s = MakeUnique<Stream>(id);
        s->hop = to;
        s->visitor = true;
        s->sock = p.sock;
        SetSocketNonBlocking(s->sock, true);
        s->service = p.service;
        s->site = p.site;
        s->hold = hold;
        s->filter = std::move(p.filter);
        // What the program already sent waits in the stream until the
        // service is open.
        if (!p.prefix.empty()) s->stream.Write(p.prefix.data(), p.prefix.size());
        s->asked_ms = s->open_sent_ms = s->active_ms = now;
        SendTo(to, Message(SVC_OPEN, id, p.service, true));
        m_streams.emplace(std::make_pair(to, id), std::move(s));
    }
}

// --- the overlay ------------------------------------------------------------------------

void ServiceHub::HandleApp(const Hop& from, const std::vector<unsigned char>& payload)
{
    LOCK(m_mutex);
    // Bounded: a flood waits its turn rather than growing without end.
    if (m_inbox.size() >= 8192) return;
    m_inbox.emplace_back(from, payload);
}

void HandleServiceApp(const Hop& from, const std::vector<unsigned char>& payload)
{
    if (g_services) g_services->HandleApp(from, payload);
}

void ServiceHub::OnOpen(const Hop& from, uint32_t id, const std::string& name, int64_t now_ms)
{
    auto existing = m_streams.find({from, id});
    if (existing != m_streams.end()) {
        // Asked again: the answer was lost.
        if (!existing->second->visitor) SendTo(from, Message(SVC_OPENED, id));
        return;
    }
    auto refuse = [&](const std::string& why) {
        ++m_stats.refused;
        SendTo(from, Message(SVC_REFUSED, id, why, true));
    };
    auto svc = m_services.find(name);
    if (svc == m_services.end()) return refuse("no service of that name here");
    size_t mine = 0;
    for (const auto& s : m_streams) if (s.first.first == from) ++mine;
    if (m_streams.size() >= MAX_STREAMS || mine >= MAX_STREAMS_PER_HOP) return refuse("too busy");

    // The loopback port its owner published, and nowhere else.
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return refuse("out of sockets");
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(svc->second);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        CloseSocket(s);
        return refuse("the program is not running");
    }
    SetSocketNonBlocking(s, true);
    std::unique_ptr<Stream> st = MakeUnique<Stream>(id);
    st->hop = from;
    st->sock = s;
    st->open = true;
    st->service = name;
    st->active_ms = now_ms;
    m_streams.emplace(std::make_pair(from, id), std::move(st));
    SendTo(from, Message(SVC_OPENED, id));
}

void ServiceHub::Process(const Hop& from, const std::vector<unsigned char>& msg, int64_t now_ms)
{
    uint32_t id;
    if (!ServiceStreamId(msg, id)) return;
    if (msg[0] == SVC_OPEN) {
        if (msg.size() < 6 || msg.size() != 6 + (size_t)msg[5]) return;
        OnOpen(from, id, std::string(msg.begin() + 6, msg.end()), now_ms);
        return;
    }
    auto it = m_streams.find({from, id});
    if (it == m_streams.end()) {
        // A stream this node does not have - it restarted, or closed it:
        // say so, so the far end stops rather than retrying for minutes.
        if (msg[0] == SVC_DATA || msg[0] == SVC_FIN) SendTo(from, ReliableStream::ResetMessage(id));
        return;
    }
    Stream& s = *it->second;
    if (msg[0] == SVC_OPENED) {
        if (s.visitor) s.open = true;
        return;
    }
    if (msg[0] == SVC_REFUSED) {
        if (s.visitor && !s.open) {
            const std::string why = msg.size() > 6 ? std::string(msg.begin() + 6, msg.end()) : std::string();
            LogPrint(BCLog::NET, "services: %s refused: %s\n", s.service, why);
            Close(s, false);
        }
        return;
    }
    s.stream.Receive(msg, now_ms);
    s.active_ms = now_ms;
}

void ServiceHub::Close(Stream& s, bool reset)
{
    if (reset && !s.stream.Dead()) SendTo(s.hop, ReliableStream::ResetMessage(s.stream.Id()));
    if (s.sock != INVALID_SOCKET) CloseSocket(s.sock);
    s.sock = INVALID_SOCKET;
}

void ServiceHub::Pump(Stream& s, int64_t now_ms)
{
    if (s.sock == INVALID_SOCKET) return;
    if (s.visitor && !s.open) {
        // Waiting for the host to answer; asked again now and then.
        if (now_ms - s.asked_ms > STREAM_OPEN_SECONDS * 1000) {
            LogPrint(BCLog::NET, "services: %s did not answer\n", s.service);
            DropSitePath(s.site, s.hop);
            Close(s, false);
        } else if (now_ms - s.open_sent_ms >= 2000) {
            SendTo(s.hop, Message(SVC_OPEN, s.stream.Id(), s.service, true));
            s.open_sent_ms = now_ms;
        }
        return;
    }

    unsigned char buf[16384];
    // The program's bytes into the stream, as far as it has room.
    while (!s.sock_eof && s.stream.SendSpace() > 0) {
        const int n = recv(s.sock, (char*)buf, (int)std::min(sizeof(buf), s.stream.SendSpace()), 0);
        if (n > 0) {
            s.stream.Write(buf, (size_t)n);
            m_stats.bytes_out += (uint64_t)n;
            s.active_ms = now_ms;
        } else if (n == 0) {
            s.sock_eof = true;
            s.stream.Shutdown();
        } else {
            if (!WouldBlock()) {
                Close(s, true);
                return;
            }
            break;
        }
    }
    // The stream's bytes to the program, as fast as it takes them.
    while (true) {
        if (s.to_sock.empty()) {
            std::vector<unsigned char> chunk = s.stream.Read(65536);
            if (chunk.empty() && !(s.filter && s.stream.ReadClosed() && !s.flushed)) break;
            m_stats.bytes_in += chunk.size();
            if (s.filter) {
                s.held.insert(s.held.end(), chunk.begin(), chunk.end());
                const bool end = s.stream.ReadClosed();
                s.to_sock = s.filter(s.held, end);
                if (end) s.flushed = true;
                if (s.to_sock.empty()) break;
            } else {
                s.to_sock = std::move(chunk);
            }
        }
        const int n = send(s.sock, (const char*)s.to_sock.data(), (int)s.to_sock.size(), SEND_FLAGS);
        if (n > 0) {
            s.to_sock.erase(s.to_sock.begin(), s.to_sock.begin() + n);
            s.active_ms = now_ms;
        } else {
            if (!WouldBlock()) {
                Close(s, true);
                return;
            }
            break;
        }
    }
    if (s.stream.ReadClosed() && s.to_sock.empty() && !s.sock_shut) {
        shutdown(s.sock, SHUT_WR);
        s.sock_shut = true;
    }

    for (const std::vector<unsigned char>& m : s.stream.Poll(now_ms)) SendTo(s.hop, m);

    if (s.stream.Finished() || s.stream.Dead()) {
        if (s.stream.Dead() && s.visitor) DropSitePath(s.site, s.hop);
        Close(s, false);
    } else if (now_ms - s.active_ms > STREAM_IDLE_SECONDS * 1000) {
        Close(s, true);
    }
}

void ServiceHub::ThreadWork()
{
    int64_t next_meeting_check = GetTime() + 60;
    while (m_running) {
        // Wait for a socket, or the next thing a stream has to send.
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        SOCKET maxfd = 0;
        int64_t wait_ms = 200;
        {
            LOCK(m_mutex);
            const int64_t now = GetTimeMillis();
            auto add = [&](SOCKET s, fd_set& set) {
                FD_SET(s, &set);
                maxfd = std::max(maxfd, s);
            };
            for (const auto& l : m_listeners) add(l.second.sock, rfds);
            for (const auto& e : m_streams) {
                const Stream& s = *e.second;
                if (s.sock == INVALID_SOCKET) continue;
                if (!s.sock_eof && s.stream.SendSpace() > 0) add(s.sock, rfds);
                if (!s.to_sock.empty()) add(s.sock, wfds);
                wait_ms = std::min<int64_t>(wait_ms, s.stream.NextWake(now) - now);
            }
            // Messages from the overlay arrive without waking select, so it
            // is never long while streams are open.
            if (!m_streams.empty()) wait_ms = std::min<int64_t>(wait_ms, 10);
            if (!m_inbox.empty()) wait_ms = 0;
        }
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = (long)std::max<int64_t>(0, wait_ms) * 1000;
        select(maxfd + 1, &rfds, &wfds, nullptr, &tv);

        if (GetTime() >= next_meeting_check) {
            next_meeting_check = GetTime() + 60;
            // Outside the lock: it can start or stop the meeting service.
            UpdateMeeting();
        }

        LOCK(m_mutex);
        const int64_t now = GetTimeMillis();
        while (!m_inbox.empty()) {
            const auto item = std::move(m_inbox.front());
            m_inbox.pop_front();
            Process(item.first, item.second, now);
        }
        for (auto& l : m_listeners) {
            while (true) {
                struct sockaddr_in from;
                socklen_t len = sizeof(from);
                SOCKET c = accept(l.second.sock, (struct sockaddr*)&from, &len);
                if (c == INVALID_SOCKET) break;
                if (from.sin_family != AF_INET || (ntohl(from.sin_addr.s_addr) >> 24) != 127 ||
                    m_pending.size() >= MAX_STREAMS) {
                    CloseSocket(c);
                    continue;
                }
                Pending p;
                p.sock = c;
                p.site = l.second.site;
                p.service = l.second.service;
                m_pending.push_back(std::move(p));
                m_open_cv.notify_all();
            }
        }
        for (auto it = m_streams.begin(); it != m_streams.end();) {
            Pump(*it->second, now);
            it = it->second->sock == INVALID_SOCKET ? m_streams.erase(it) : std::next(it);
        }
        m_stats.streams = m_streams.size();
    }
}

ServiceHub::Stats ServiceHub::GetStats() const
{
    LOCK(m_mutex);
    Stats s = m_stats;
    s.streams = m_streams.size();
    return s;
}

} // namespace overlay
