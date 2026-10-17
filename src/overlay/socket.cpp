// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/socket.h>

#include <logging.h>
#include <netbase.h>
#include <util/system.h>
#include <util/time.h>

#ifdef WIN32
#include <mswsock.h>
#include <ws2ipdef.h>
#endif

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

/** A unicast address a reply may come from: not broadcast or multicast, not unspecified. */
bool UsableSource(const Socket::LocalAddress& a)
{
    if (a.family == AF_INET) {
        const uint32_t v = ((uint32_t)a.addr[0] << 24) | ((uint32_t)a.addr[1] << 16) | ((uint32_t)a.addr[2] << 8) | a.addr[3];
        return v != 0 && v != 0xffffffffU && (a.addr[0] & 0xf0) != 0xe0;
    }
    if (a.family == AF_INET6) {
        static const unsigned char zero[16] = {};
        return a.addr[0] != 0xff && std::memcmp(a.addr, zero, 16) != 0;
    }
    return false;
}

#ifdef WIN32
using CmsgHeader = WSACMSGHDR;
#define BPS_CMSG_FIRSTHDR WSA_CMSG_FIRSTHDR
#define BPS_CMSG_NXTHDR WSA_CMSG_NXTHDR
#define BPS_CMSG_DATA WSA_CMSG_DATA
#define BPS_CMSG_SPACE WSA_CMSG_SPACE
#define BPS_CMSG_LEN WSA_CMSG_LEN
using Pktinfo4 = IN_PKTINFO;
using Pktinfo6 = IN6_PKTINFO;
#define BPS_HAVE_PKTINFO4 1
#define BPS_HAVE_PKTINFO6 1
#else
using CmsgHeader = struct cmsghdr;
#define BPS_CMSG_FIRSTHDR CMSG_FIRSTHDR
#define BPS_CMSG_NXTHDR CMSG_NXTHDR
#define BPS_CMSG_DATA CMSG_DATA
#define BPS_CMSG_SPACE CMSG_SPACE
#define BPS_CMSG_LEN CMSG_LEN
#ifdef IP_PKTINFO
using Pktinfo4 = struct in_pktinfo;
#define BPS_HAVE_PKTINFO4 1
#endif
#if defined(IPV6_RECVPKTINFO) && defined(IPV6_PKTINFO)
using Pktinfo6 = struct in6_pktinfo;
#define BPS_HAVE_PKTINFO6 1
#endif
#endif

/** Room for the larger of the two kinds of packet information. */
constexpr size_t CONTROL_SPACE = 128;

/** Ask the system to tell, for each datagram, the address it was sent to. */
bool EnablePacketInfo(SOCKET sock, int family)
{
    int one = 1;
    if (family == AF_INET) {
#ifdef BPS_HAVE_PKTINFO4
        return setsockopt(sock, IPPROTO_IP, IP_PKTINFO, (sockopt_arg_type)&one, sizeof(one)) == 0;
#endif
    } else if (family == AF_INET6) {
#if defined(WIN32)
        return setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, (sockopt_arg_type)&one, sizeof(one)) == 0;
#elif defined(BPS_HAVE_PKTINFO6)
        return setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, (sockopt_arg_type)&one, sizeof(one)) == 0;
#endif
    }
    (void)sock;
    (void)one;
    return false;
}

/** The address a received datagram was sent to, from its packet information. */
template <typename Message>
void ReadPacketInfo(Message& msg, Socket::LocalAddress& local)
{
    for (CmsgHeader* c = BPS_CMSG_FIRSTHDR(&msg); c != nullptr; c = BPS_CMSG_NXTHDR(&msg, c)) {
#ifdef BPS_HAVE_PKTINFO4
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            Pktinfo4 info;
            std::memcpy(&info, BPS_CMSG_DATA(c), sizeof(info));
            local.family = AF_INET;
            std::memcpy(local.addr, &info.ipi_addr, 4);
            local.ifindex = 0;
        }
#endif
#ifdef BPS_HAVE_PKTINFO6
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
            Pktinfo6 info;
            std::memcpy(&info, BPS_CMSG_DATA(c), sizeof(info));
            local.family = AF_INET6;
            std::memcpy(local.addr, &info.ipi6_addr, 16);
            // The interface matters only where the address alone does not
            // say which link: link-local.
            const bool link_local = local.addr[0] == 0xfe && (local.addr[1] & 0xc0) == 0x80;
            local.ifindex = link_local ? (unsigned int)info.ipi6_ifindex : 0;
        }
#endif
    }
}

/** sendto, from the local address `local`. -1 when it cannot be said, or sending failed. */
int SendFrom(SOCKET sock, const unsigned char* data, size_t len, const struct sockaddr* to, socklen_t to_len,
             const Socket::LocalAddress& local)
{
    alignas(8) char control[CONTROL_SPACE];
    std::memset(control, 0, sizeof(control));
    size_t control_len = 0;
#ifdef WIN32
    WSABUF wbuf;
    wbuf.buf = reinterpret_cast<char*>(const_cast<unsigned char*>(data));
    wbuf.len = (ULONG)len;
    WSAMSG msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.name = const_cast<struct sockaddr*>(to);
    msg.namelen = to_len;
    msg.lpBuffers = &wbuf;
    msg.dwBufferCount = 1;
    msg.Control.buf = control;
    msg.Control.len = sizeof(control);
#else
    struct iovec iov;
    iov.iov_base = const_cast<unsigned char*>(data);
    iov.iov_len = len;
    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_name = const_cast<struct sockaddr*>(to);
    msg.msg_namelen = to_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
#endif
    CmsgHeader* c = BPS_CMSG_FIRSTHDR(&msg);
    if (c == nullptr) return -1;
    if (local.family == AF_INET) {
#ifdef BPS_HAVE_PKTINFO4
        Pktinfo4 info;
        std::memset(&info, 0, sizeof(info));
        std::memcpy(&info.ipi_addr, local.addr, 4);
#ifndef WIN32
        // Linux reads the source from ipi_spec_dst; the interface is left to the route.
        std::memcpy(&info.ipi_spec_dst, local.addr, 4);
#endif
        c->cmsg_level = IPPROTO_IP;
        c->cmsg_type = IP_PKTINFO;
        c->cmsg_len = BPS_CMSG_LEN(sizeof(info));
        std::memcpy(BPS_CMSG_DATA(c), &info, sizeof(info));
        control_len = BPS_CMSG_SPACE(sizeof(info));
#endif
    } else if (local.family == AF_INET6) {
#ifdef BPS_HAVE_PKTINFO6
        Pktinfo6 info;
        std::memset(&info, 0, sizeof(info));
        std::memcpy(&info.ipi6_addr, local.addr, 16);
        info.ipi6_ifindex = local.ifindex;
        c->cmsg_level = IPPROTO_IPV6;
        c->cmsg_type = IPV6_PKTINFO;
        c->cmsg_len = BPS_CMSG_LEN(sizeof(info));
        std::memcpy(BPS_CMSG_DATA(c), &info, sizeof(info));
        control_len = BPS_CMSG_SPACE(sizeof(info));
#endif
    }
    if (control_len == 0) return -1;
#ifdef WIN32
    msg.Control.len = (ULONG)control_len;
    DWORD sent = 0;
    if (WSASendMsg(sock, &msg, 0, &sent, nullptr, nullptr) != 0) return -1;
    return (int)sent;
#else
    msg.msg_controllen = control_len;
    return (int)sendmsg(sock, &msg, 0);
#endif
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
    // The overlay's own datagrams never go into the interface it carries.
    if (!MarkBypass(sock)) {
        error = "cannot mark the overlay socket to pass the system-wide interface by";
        CloseSocket(const_cast<SOCKET&>(sock));
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
    // Bound to every address of the computer, answers must name the one each
    // peer wrote to (LocalAddress). Bound to one, the system does that already.
    if (m_bound.IsBindAny()) {
        m_pktinfo = EnablePacketInfo(sock, storage.ss_family);
#ifdef WIN32
        if (m_pktinfo) {
            GUID guid = WSAID_WSARECVMSG;
            LPFN_WSARECVMSG fn = nullptr;
            DWORD bytes = 0;
            if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn, sizeof(fn), &bytes,
                         nullptr, nullptr) == 0 && fn) {
                m_recvmsg = reinterpret_cast<void*>(fn);
            } else {
                m_pktinfo = false;
            }
        }
#endif
        if (!m_pktinfo) {
            LogPrintf("overlay: this system does not say which address a datagram came to; on a computer with "
                      "several, answers may leave from another\n");
        }
    }
    LogPrintf("overlay: listening on %s\n", m_bound.ToString());
    return true;
}

Socket::LocalAddress Socket::LocalAddressFor(const CService& peer)
{
    LOCK(m_local_mutex);
    std::map<CService, LocalAddress>::const_iterator it = m_local.find(peer);
    return it == m_local.end() ? LocalAddress() : it->second;
}

int Socket::ReceiveDatagram(unsigned char* buf, size_t len, struct sockaddr_storage& from, LocalAddress& local)
{
    local = LocalAddress();
    std::memset(&from, 0, sizeof(from));
    if (!m_pktinfo) {
        socklen_t from_len = sizeof(from);
        return (int)::recvfrom(m_socket, reinterpret_cast<char*>(buf), len, 0,
                               reinterpret_cast<struct sockaddr*>(&from), &from_len);
    }
    alignas(8) char control[CONTROL_SPACE];
#ifdef WIN32
    WSABUF wbuf;
    wbuf.buf = reinterpret_cast<char*>(buf);
    wbuf.len = (ULONG)len;
    WSAMSG msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.name = reinterpret_cast<struct sockaddr*>(&from);
    msg.namelen = sizeof(from);
    msg.lpBuffers = &wbuf;
    msg.dwBufferCount = 1;
    msg.Control.buf = control;
    msg.Control.len = sizeof(control);
    DWORD got = 0;
    if (reinterpret_cast<LPFN_WSARECVMSG>(m_recvmsg)(m_socket, &msg, &got, nullptr, nullptr) != 0) return -1;
    ReadPacketInfo(msg, local);
    return (int)got;
#else
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    const ssize_t got = recvmsg(m_socket, &msg, 0);
    if (got >= 0) ReadPacketInfo(msg, local);
    return (int)got;
#endif
}

bool Socket::Start(PayloadHandler handler, EstablishedHandler established)
{
    if (m_socket == INVALID_SOCKET) return false;
    if (m_running.exchange(true)) return false;

    m_handler = std::move(handler);
    m_established = std::move(established);
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

    // To a peer that wrote to us, from the address it wrote to; to one that has
    // not, from whichever the route names, and it answers to that one.
    ssize_t sent = -1;
    const LocalAddress local = m_pktinfo ? LocalAddressFor(to) : LocalAddress();
    if (local.family != 0) {
        sent = SendFrom(m_socket, datagram.data(), datagram.size(), reinterpret_cast<struct sockaddr*>(&storage), len, local);
    }
    if (sent < 0) {
        sent = ::sendto(m_socket, reinterpret_cast<const char*>(datagram.data()), datagram.size(), 0,
                        reinterpret_cast<struct sockaddr*>(&storage), len);
    }
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

CPubKey Socket::PeerIdentity(const CService& peer)
{
    LOCK(m_mutex);
    return m_transport.PeerIdentity(peer);
}

bool Socket::HasPendingHandshake(const CService& peer)
{
    LOCK(m_mutex);
    return m_transport.HasPendingHandshake(peer);
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
        LocalAddress local;
        const int got = ReceiveDatagram(buffer.data(), buffer.size(), from, local);
        if (got <= 0) continue;

        const CService peer = FromSockAddr(from, sizeof(from));
        if (UsableSource(local)) {
            // Kept for every source, forged ones too: all it decides is which of
            // this computer's own addresses an answer leaves from. Bounded,
            // since sources are free to make up.
            LOCK(m_local_mutex);
            std::map<CService, LocalAddress>::iterator it = m_local.find(peer);
            if (it == m_local.end()) {
                if (m_local.size() >= MAX_LOCAL_ADDRESSES) m_local.erase(m_local.begin());
                m_local.emplace(peer, local);
            } else {
                it->second = local;
            }
        }
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
            if (m_established) m_established(peer);
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
constexpr size_t Socket::MAX_LOCAL_ADDRESSES;

} // namespace overlay
