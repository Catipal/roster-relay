// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SERVICE_H
#define BITCOIN_OVERLAY_SERVICE_H

#include <compat.h>
#include <overlay/path.h>
#include <overlay/stream.h>
#include <overlay/webrequest.h>
#include <roster/record.h>
#include <sync.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * Services over the overlay (design note §11·6, stage 4).
 *
 * A service is a program on the host's own computer - a web application, a
 * chat server, a game - listening on 127.0.0.1, published under a name and
 * the host's roster key. A visitor's node listens on a port of its own
 * computer and carries every connection made to it to the service, as a
 * reliable stream (overlay/stream.h) along the same path a site's pages take:
 * through relays to a host listed at an address, at its meeting points to
 * one listed with none. Nobody learns the other's address.
 *
 * No exits: the host's node connects to nothing but the loopback ports its
 * owner published, whatever a visitor asks for.
 *
 * A service named "web" is HTTP, and its requests pass a gate first
 * (overlay/webrequest.h): one request per stream, told apart by visitor.
 */
namespace overlay {

static constexpr size_t MAX_SERVICES = 16;
static constexpr size_t MAX_SERVICE_NAME = 32;
//! Streams open at once, in all and from one visitor.
static constexpr size_t MAX_STREAMS = 256;
static constexpr size_t MAX_STREAMS_PER_HOP = 16;
//! A stream with nothing moving for this long is closed.
static constexpr int64_t STREAM_IDLE_SECONDS = 600;
//! How long a visitor waits for a service to answer an open.
static constexpr int64_t STREAM_OPEN_SECONDS = 20;

/** Whether `name` can name a service: 1 to 32 of a-z, 0-9 and '-'. */
bool ValidServiceName(const std::string& name);

class ServiceHub
{
public:
    /** `self` is this node's roster key, which its services are published under. */
    explicit ServiceHub(const roster::KeyBytes& self);
    ~ServiceHub();

    bool Start(std::string& error);
    void Stop();

    // --- hosting ----------------------------------------------------------

    /** Let visitors reach 127.0.0.1:`port` as `name`; kept for the next start. */
    bool Publish(const std::string& name, uint16_t port, std::string& error);
    bool Unpublish(const std::string& name);
    std::map<std::string, uint16_t> Services() const;
    /** Whether the services are met at meeting points: this node is listed with no address. */
    bool Hidden() const;

    // --- visiting ---------------------------------------------------------

    /**
     * Listen on 127.0.0.1:`local` (0 for any free port) and carry every
     * connection made there to `service` at the site `site`. `bound` is the
     * port listened on.
     */
    bool Forward(const roster::KeyBytes& site, const std::string& service, uint16_t local, uint16_t& bound,
                 std::string& error);
    bool StopForward(uint16_t local);
    struct ForwardInfo {
        roster::KeyBytes site{};
        std::string service;
        uint16_t local{0};
        size_t open{0};
    };
    std::vector<ForwardInfo> Forwards() const;

    /**
     * What a visitor's side does with the bytes coming back before they reach
     * its socket: given everything so far, the bytes to pass on now (the rest
     * is held). The browser proxy uses it to add its own headers to a web
     * service's answer.
     */
    using Filter = std::function<std::vector<unsigned char>(std::vector<unsigned char>& held, bool end)>;
    /**
     * Carry `sock`, an accepted connection on this computer, to `service` at
     * `site`: `prefix` first (bytes already read from it), then whatever
     * else it sends. The hub owns the socket from here and closes it.
     */
    void Attach(SOCKET sock, const roster::KeyBytes& site, const std::string& service,
                std::vector<unsigned char> prefix, Filter filter);

    // --- the overlay ------------------------------------------------------

    /** A service message from the far end of a path. Queued; never blocks. */
    void HandleApp(const Hop& from, const std::vector<unsigned char>& payload);

    struct Stats {
        size_t streams{0};
        uint64_t bytes_in{0};   //!< from the overlay to local programs
        uint64_t bytes_out{0};  //!< from local programs to the overlay
        uint64_t refused{0};    //!< opens turned down
    };
    Stats GetStats() const;

private:
    struct Stream;
    struct Listener {
        SOCKET sock{INVALID_SOCKET};
        roster::KeyBytes site{};
        std::string service;
    };
    /** A connection waiting for its path to be built. */
    struct Pending {
        SOCKET sock{INVALID_SOCKET};
        roster::KeyBytes site{};
        std::string service;
        std::vector<unsigned char> prefix;
        Filter filter;
    };

    void ThreadWork();
    void ThreadOpen();
    void Process(const Hop& from, const std::vector<unsigned char>& msg, int64_t now_ms)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void OnOpen(const Hop& from, uint32_t id, const std::string& name, int64_t now_ms)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Pump(Stream& s, int64_t now_ms) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Close(Stream& s, bool reset) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Save() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Load() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void UpdateMeeting();

    const roster::KeyBytes m_self;
    //! Made at each start: what visitors' labels are worked out under.
    const uint256 m_visitor_secret;
    std::atomic<bool> m_running{false};
    std::thread m_worker;
    std::thread m_opener;

    mutable Mutex m_mutex;
    std::condition_variable m_open_cv;
    std::map<std::string, uint16_t> m_services GUARDED_BY(m_mutex);
    std::map<uint16_t, Listener> m_listeners GUARDED_BY(m_mutex);
    std::map<std::pair<Hop, uint32_t>, std::unique_ptr<Stream>> m_streams GUARDED_BY(m_mutex);
    std::deque<std::pair<Hop, std::vector<unsigned char>>> m_inbox GUARDED_BY(m_mutex);
    std::deque<Pending> m_pending GUARDED_BY(m_mutex);
    Stats m_stats GUARDED_BY(m_mutex);
};

/** The running hub, or null when the overlay is off. */
extern std::unique_ptr<ServiceHub> g_services;

/** Route a service message to the hub. */
void HandleServiceApp(const Hop& from, const std::vector<unsigned char>& payload);

} // namespace overlay

#endif // BITCOIN_OVERLAY_SERVICE_H
