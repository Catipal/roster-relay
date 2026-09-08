// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/socket.h>

#include <logging.h>
#include <netbase.h>
#include <util/system.h>
#include <util/time.h>


#include <cstring>

namespace overlay {

namespace {

/** How long the receive loop blocks before checking whether it should stop. */
static constexpr int64_t POLL_TIMEOUT_MS = 200;

CService FromSockAddr(const struct sockaddr_storage& ss, socklen_t len)
{
    CService out;
    out.SetSockAddr(reinterpret_cast<const struct sockaddr*>(&ss));
    (void)len;
    return out;
}

} // namespace

Socket::Socket(const CKey& static_key) : m_transport(static_key) {}

Socket::~Socket()
{
    Stop();
}

bool Socket::Bind(const CService& listen_addr, std::string& error)
{
    if (m_socket != INVALID_SOCKET) {
        error = "overlay socket is already bound";
        return false;
    }

    struct sockaddr_storage storage;
    socklen_t len = sizeof(storage);
    std::memset(&storage, 0, sizeof(storage));
    if (!listen_addr.GetSockAddr(reinterpret_cast<struct sockaddr*>(&storage), &len)) {
        error = strprintf("cannot use %s as an overlay listen address", listen_addr.ToString());
        return false;
    }

    const SOCKET sock = socket(storage.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        error = strprintf("cannot create a UDP socket: %s", NetworkErrorString(WSAGetLastError()));
        return false;
    }

    if (storage.ss_family == AF_INET6) {
        // Keep v6 and v4 sockets separate, so a v6 bind does not silently also
        // claim the v4 port and make the failure mode depend on the platform.
        int one = 1;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (sockopt_arg_type)&one, sizeof(one));
    }

    if (!SetSocketNonBlocking(sock, true)) {
        error = "cannot set the overlay socket non-blocking";
        CloseSocket(const_cast<SOCKET&>(sock));
        return false;
    }

    if (::bind(sock, reinterpret_cast<struct sockaddr*>(&storage), len) == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        error = strprintf("cannot bind %s: %s", listen_addr.ToString(), NetworkErrorString(err));
        SOCKET s = sock;
        CloseSocket(s);
        return false;
    }

    // Read back what was actually bound, so a configured port of zero reports
    // the port the system chose rather than zero.
    struct sockaddr_storage bound;
    socklen_t bound_len = sizeof(bound);
    std::memset(&bound, 0, sizeof(bound));
    if (getsockname(sock, reinterpret_cast<struct sockaddr*>(&bound), &bound_len) == 0) {
        m_bound = FromSockAddr(bound, bound_len);
    } else {
        m_bound = listen_addr;
    }

    m_socket = sock;
    LogPrintf("overlay: listening on %s\n", m_bound.ToString());
    return true;
}

bool Socket::Start(PayloadHandler handler)
{
    if (m_socket == INVALID_SOCKET) return false;
    if (m_running.exchange(true)) return false;

    m_handler = std::move(handler);
    m_thread = std::thread(&TraceThread<std::function<void()> >, "overlay",
                           std::function<void()>([this] { ThreadReceive(); }));
    return true;
}

void Socket::Stop()
{
    if (m_running.exchange(false)) {
        m_interrupt();
        if (m_thread.joinable()) m_thread.join();
    }
    if (m_socket != INVALID_SOCKET) {
        CloseSocket(m_socket);
    }
}

bool Socket::SendDatagram(const CService& to, const std::vector<unsigned char>& datagram)
{
    if (m_socket == INVALID_SOCKET) return false;
    if (datagram.size() > SAFE_DATAGRAM) return false;

    struct sockaddr_storage storage;
    socklen_t len = sizeof(storage);
    std::memset(&storage, 0, sizeof(storage));
    if (!to.GetSockAddr(reinterpret_cast<struct sockaddr*>(&storage), &len)) return false;

    const ssize_t sent = ::sendto(m_socket,
                                  reinterpret_cast<const char*>(datagram.data()),
                                  datagram.size(), 0,
                                  reinterpret_cast<struct sockaddr*>(&storage), len);
    // A datagram either goes whole or not at all; a short write means the
    // network refused it, and there is nothing useful to retry here. Loss is
    // the transport's normal condition, so this is logged, not escalated.
    if (sent != static_cast<ssize_t>(datagram.size())) {
        LogPrint(BCLog::NET, "overlay: send to %s failed\n", to.ToString());
        return false;
    }
    return true;
}

bool Socket::Connect(const CService& peer, const CPubKey& peer_static)
{
    std::vector<unsigned char> datagram;
    {
        LOCK(m_mutex);
        if (!m_transport.Connect(peer, peer_static, datagram)) return false;
    }
    return SendDatagram(peer, datagram);
}

bool Socket::Send(const CService& peer, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> datagram;
    {
        LOCK(m_mutex);
        if (!m_transport.Send(peer, payload, datagram)) return false;
    }
    return SendDatagram(peer, datagram);
}

bool Socket::HasSession(const CService& peer)
{
    LOCK(m_mutex);
    return m_transport.HasSession(peer);
}

size_t Socket::HandshakesRefused()
{
    LOCK(m_mutex);
    return m_refused;
}

size_t Socket::SessionCount()
{
    LOCK(m_mutex);
    return m_transport.SessionCount();
}

bool Socket::AllowHandshake(const CService& from, int64_t now)
{
    if (now - m_window_start >= RATE_WINDOW) {
        m_window_start = now;
        m_global_attempts = 0;
        m_attempts.clear();
    }

    if (m_global_attempts >= GLOBAL_LIMIT) {
        ++m_refused;
        return false;
    }

    // A forged source address would otherwise get its own quota, so the source
    // table is bounded too: past the cap, unknown sources are refused rather
    // than tracked, and the global limit above is doing the real work.
    std::map<CService, size_t>::iterator it = m_attempts.find(from);
    if (it == m_attempts.end()) {
        if (m_attempts.size() >= MAX_TRACKED_SOURCES) {
            ++m_refused;
            return false;
        }
        it = m_attempts.insert(std::make_pair(from, size_t{0})).first;
    }
    if (it->second >= PER_SOURCE_LIMIT) {
        ++m_refused;
        return false;
    }

    ++it->second;
    ++m_global_attempts;
    return true;
}

void Socket::ThreadReceive()
{
    // One datagram at most; anything larger is not ours by construction, and
    // recvfrom truncates it, which the frame layer then rejects.
    std::vector<unsigned char> buffer(SAFE_DATAGRAM);

    while (m_running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_socket, &readfds);
        struct timeval tv;
        tv.tv_sec = POLL_TIMEOUT_MS / 1000;
        tv.tv_usec = (POLL_TIMEOUT_MS % 1000) * 1000;

        const int ready = select(m_socket + 1, &readfds, nullptr, nullptr, &tv);
        if (ready < 0) {
            if (m_running) LogPrint(BCLog::NET, "overlay: select failed\n");
            continue;
        }
        if (ready == 0) continue;

        struct sockaddr_storage from;
        socklen_t from_len = sizeof(from);
        std::memset(&from, 0, sizeof(from));
        const ssize_t got = ::recvfrom(m_socket,
                                       reinterpret_cast<char*>(buffer.data()),
                                       buffer.size(), 0,
                                       reinterpret_cast<struct sockaddr*>(&from), &from_len);
        if (got <= 0) continue;

        const CService peer = FromSockAddr(from, from_len);
        std::vector<unsigned char> reply, payload;
        Transport::Result result;
        {
            LOCK(m_mutex);
            // Metered before any key agreement happens, which is the only
            // place it helps: past this point the work is already done.
            FrameType type;
            uint64_t sid = 0, ctr = 0;
            if (PeekFrame(buffer.data(), static_cast<size_t>(got), type, sid, ctr) &&
                type == FrameType::HANDSHAKE_INIT &&
                !AllowHandshake(peer, GetTime())) {
                continue;
            }
            result = m_transport.Receive(peer, buffer.data(), static_cast<size_t>(got),
                                         reply, payload);
        }

        if (!reply.empty()) SendDatagram(peer, reply);

        switch (result) {
        case Transport::Result::PAYLOAD:
            // Handled outside the lock: a handler that calls back into Send
            // would otherwise deadlock, and holding the transport across
            // arbitrary caller code is how a lock becomes a bottleneck.
            if (m_handler) m_handler(peer, std::move(payload));
            break;
        case Transport::Result::ESTABLISHED:
            LogPrint(BCLog::NET, "overlay: session established with %s\n", peer.ToString());
            break;
        case Transport::Result::HANDSHAKE:
        case Transport::Result::IGNORED:
            // Silence is deliberate for IGNORED. Answering unrecognised
            // datagrams is what turns a node into a reflector, and logging
            // every one of them is its own flood.
            break;
        }
    }
}

constexpr int64_t Socket::RATE_WINDOW;
constexpr size_t Socket::PER_SOURCE_LIMIT;
constexpr size_t Socket::GLOBAL_LIMIT;
constexpr size_t Socket::MAX_TRACKED_SOURCES;

} // namespace overlay
