// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/netstack.h>

#include <logging.h>
#include <netbase.h>
#include <random.h>
#include <util/system.h>

#include <lwip/init.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/timeouts.h>

#ifdef USE_POLL
#include <poll.h>
#endif

// As net.cpp does: where MSG_NOSIGNAL does not exist, SO_NOSIGPIPE or the
// platform keeps a closed peer from raising SIGPIPE instead.
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#include <chrono>
#include <future>
#include <limits>
#include <mutex>
#include <tuple>
#include <vector>

/*
 * What lwIP asks of the platform, with C linkage because lwIP is C: a
 * millisecond clock for its timers, and randomness for initial sequence
 * numbers and ports (overlay/lwip/arch/cc.h).
 */
extern "C" u32_t sys_now(void)
{
    // Monotonic: lwIP's timers measure intervals, and a wall clock that steps
    // would fire them early or hold them back. It wraps every 49 days, which
    // lwIP's arithmetic expects.
    return (u32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

extern "C" uint32_t bps_lwip_rand(void)
{
    return (uint32_t)GetRand(std::numeric_limits<uint32_t>::max());
}

extern "C" struct netif* bps_lwip_route4(const struct ip4_addr*, const struct ip4_addr* dest)
{
    if (dest && ip4_addr_isloopback(dest) && netif_default && netif_is_up(netif_default) &&
        netif_is_link_up(netif_default)) {
        return netif_default;
    }
    return nullptr; // everything else as lwIP routes it
}

namespace overlay {

void InitNetStack()
{
    static std::once_flag once;
    std::call_once(once, [] { lwip_init(); });
}

NetStack& GetNetStack()
{
    static NetStack stack;
    return stack;
}

NetStack::~NetStack()
{
    Stop();
}

bool NetStack::Start(std::string& error)
{
    if (m_running) return true;
    InitNetStack();

    // The loop waits on sockets, so work posted from another thread wakes it
    // through one: a datagram to itself on the loopback interface, which
    // works the same everywhere, Windows included.
    m_wake = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_wake == INVALID_SOCKET) {
        error = "cannot open the stack's wake socket: " + NetworkErrorString(WSAGetLastError());
        return false;
    }
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = 0;
    m_wake_len = sizeof(m_wake_addr);
    if (bind(m_wake, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR ||
        getsockname(m_wake, (struct sockaddr*)&m_wake_addr, &m_wake_len) == SOCKET_ERROR ||
        !SetSocketNonBlocking(m_wake, true)) {
        error = "cannot bind the stack's wake socket: " + NetworkErrorString(WSAGetLastError());
        CloseSocket(m_wake);
        return false;
    }

    m_stop = false;
    m_running = true;
    m_thread = std::thread(&TraceThread<std::function<void()>>, "netstack",
                           std::function<void()>(std::bind(&NetStack::Loop, this)));
    return true;
}

void NetStack::Stop()
{
    if (!m_running) return;
    m_stop = true;
    Wake();
    if (m_thread.joinable()) m_thread.join();
    CloseSocket(m_wake);
    m_watch.clear();
    m_ticks.clear();
    m_running = false;
}

void NetStack::Wake()
{
    if (m_wake == INVALID_SOCKET) return;
    const char byte = 0;
    sendto(m_wake, &byte, 1, MSG_NOSIGNAL, (const struct sockaddr*)&m_wake_addr, m_wake_len);
}

void NetStack::Post(Task task)
{
    {
        LOCK(m_tasks_mutex);
        m_tasks.push_back(std::move(task));
    }
    Wake();
}

void NetStack::RunSync(const Task& task)
{
    if (!m_running) {
        // No thread to hand it to, and so nobody else touching the stack.
        task();
        return;
    }
    assert(!OnStackThread());
    std::promise<void> done;
    std::future<void> finished = done.get_future();
    Post([&task, &done] {
        task();
        done.set_value();
    });
    finished.wait();
}

bool NetStack::OnStackThread() const
{
    return std::this_thread::get_id() == m_thread.get_id();
}

int NetStack::AddTick(Task tick)
{
    const int id = ++m_next_tick;
    m_ticks[id] = std::move(tick);
    return id;
}

void NetStack::RemoveTick(int id)
{
    m_ticks.erase(id);
}

void NetStack::Watch(SOCKET s, bool want_read, bool want_write, SocketHandler handler)
{
    Watched& w = m_watch[s];
    w.read = want_read;
    w.write = want_write;
    w.handler = std::move(handler);
}

void NetStack::SetInterest(SOCKET s, bool want_read, bool want_write)
{
    std::map<SOCKET, Watched>::iterator it = m_watch.find(s);
    if (it == m_watch.end()) return;
    it->second.read = want_read;
    it->second.write = want_write;
}

void NetStack::Unwatch(SOCKET s)
{
    m_watch.erase(s);
}

void NetStack::RunPosted()
{
    std::deque<Task> tasks;
    {
        LOCK(m_tasks_mutex);
        tasks.swap(m_tasks);
    }
    for (Task& t : tasks) t();
}

void NetStack::Loop()
{
    // What a wait found: a socket, and whether it can be read, written, or failed.
    std::vector<std::tuple<SOCKET, bool, bool, bool>> ready;

    while (!m_stop) {
        int wait = MAX_WAIT_MS;
        const u32_t lwip_wait = sys_timeouts_sleeptime();
        if (lwip_wait != SYS_TIMEOUTS_SLEEPTIME_INFINITE && lwip_wait < (u32_t)wait) wait = (int)lwip_wait;
        bool woken = false;
        ready.clear();

#ifdef USE_POLL
        std::vector<struct pollfd> fds;
        fds.reserve(m_watch.size() + 1);
        fds.push_back({(int)m_wake, POLLIN, 0});
        for (const std::pair<const SOCKET, Watched>& w : m_watch) {
            short events = 0;
            if (w.second.read) events |= POLLIN;
            if (w.second.write) events |= POLLOUT;
            fds.push_back({(int)w.first, events, 0});
        }
        if (poll(fds.data(), fds.size(), wait) > 0) {
            woken = fds[0].revents & POLLIN;
            for (size_t i = 1; i < fds.size(); ++i) {
                const short r = fds[i].revents;
                if (!r) continue;
                ready.emplace_back((SOCKET)fds[i].fd, (r & (POLLIN | POLLHUP)) != 0, (r & POLLOUT) != 0,
                                   (r & (POLLERR | POLLNVAL)) != 0);
            }
        }
#else
        fd_set rfds, wfds, efds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(m_wake, &rfds);
        SOCKET highest = m_wake;
        for (const std::pair<const SOCKET, Watched>& w : m_watch) {
            if (w.second.read) FD_SET(w.first, &rfds);
            if (w.second.write) FD_SET(w.first, &wfds);
            // A connect that fails shows up here on Windows, not as writable.
            FD_SET(w.first, &efds);
            highest = std::max(highest, w.first);
        }
        struct timeval tv;
        tv.tv_sec = wait / 1000;
        tv.tv_usec = (wait % 1000) * 1000;
        if (select(highest + 1, &rfds, &wfds, &efds, &tv) > 0) {
            woken = FD_ISSET(m_wake, &rfds);
            for (const std::pair<const SOCKET, Watched>& w : m_watch) {
                const bool r = FD_ISSET(w.first, &rfds), wr = FD_ISSET(w.first, &wfds), e = FD_ISSET(w.first, &efds);
                if (r || wr || e) ready.emplace_back(w.first, r, wr, e);
            }
        }
#endif

        if (woken) {
            char drain[64];
            while (recv(m_wake, drain, sizeof(drain), 0) > 0) {}
        }
        for (const std::tuple<SOCKET, bool, bool, bool>& r : ready) {
            // A handler may unwatch other sockets, or its own, so look each up again.
            std::map<SOCKET, Watched>::iterator it = m_watch.find(std::get<0>(r));
            if (it == m_watch.end()) continue;
            const SocketHandler handler = it->second.handler;
            handler(std::get<1>(r), std::get<2>(r), std::get<3>(r));
        }
        RunPosted();
        sys_check_timeouts();
        const std::map<int, Task> ticks = m_ticks;
        for (const std::pair<const int, Task>& t : ticks) {
            if (m_ticks.count(t.first)) t.second();
        }
    }
    // Owners clean up through posted work before asking the loop to stop.
    RunPosted();
}

} // namespace overlay
