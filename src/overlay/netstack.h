// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_NETSTACK_H
#define BITCOIN_OVERLAY_NETSTACK_H

#include <compat.h>
#include <sync.h>

#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <thread>

/**
 * The node's own TCP/IP stack, and the thread that runs it (design note §8·7).
 *
 * A gateway carries a visitor's IP packets, and holding TCP connections for
 * them without administrator rights takes a stack in user space: lwIP,
 * vendored in src/lwip and configured in overlay/lwip/lwipopts.h. lwIP keeps
 * its state in globals and is not thread-safe, so there is one stack per
 * process and one thread that touches it. That thread is an event loop:
 * work posted from other threads, the sockets a gateway opens to the
 * internet, and lwIP's timers, all taken in turn. Nothing on it blocks.
 */
namespace overlay {

/** Initialise lwIP, once per process. Safe to call again. */
void InitNetStack();

class NetStack
{
public:
    using Task = std::function<void()>;
    /** Called on the stack thread with what a watched socket is ready for. */
    using SocketHandler = std::function<void(bool readable, bool writable, bool failed)>;

    /** How long the loop waits at most, so lwIP's timers and Tick run on time. */
    static constexpr int MAX_WAIT_MS = 100;

    ~NetStack();

    bool Start(std::string& error);
    /** Run what is posted, then stop. Owners clean up on the thread before this. */
    void Stop();
    bool Running() const { return m_running; }

    /** Run `task` on the stack thread. From any thread. */
    void Post(Task task);
    /** Run `task` on the stack thread and wait for it. Not from the stack thread. */
    void RunSync(const Task& task);
    bool OnStackThread() const;

    // Stack thread only.

    /** Run `tick` once a loop, about every MAX_WAIT_MS, until removed. */
    int AddTick(Task tick);
    void RemoveTick(int id);

    void Watch(SOCKET s, bool want_read, bool want_write, SocketHandler handler);
    void SetInterest(SOCKET s, bool want_read, bool want_write);
    void Unwatch(SOCKET s);
    size_t WatchCount() const { return m_watch.size(); }

private:
    struct Watched {
        bool read{false};
        bool write{false};
        SocketHandler handler;
    };

    void Loop();
    void Wake();
    void RunPosted();

    std::thread m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stop{false};
    SOCKET m_wake{INVALID_SOCKET};
    struct sockaddr_storage m_wake_addr{};
    socklen_t m_wake_len{0};

    Mutex m_tasks_mutex;
    std::deque<Task> m_tasks GUARDED_BY(m_tasks_mutex);

    // Owned by the stack thread.
    std::map<SOCKET, Watched> m_watch;
    std::map<int, Task> m_ticks;
    int m_next_tick{0};
};

/** The one stack this process has. */
NetStack& GetNetStack();

} // namespace overlay

#endif // BITCOIN_OVERLAY_NETSTACK_H
