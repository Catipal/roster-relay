// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/dnsclient.h>

#include <compat.h>
#include <netbase.h>
#include <overlay/dnsanswer.h>
#include <overlay/sysif.h>
#include <random.h>
#include <util/time.h>

#ifdef WIN32
#include <iphlpapi.h>
#include <overlay/netservice.h>
#endif

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace overlay {

namespace {

/** Per server and record type. */
constexpr int64_t ASK_TIMEOUT_MS = 2500;
/** Servers tried, at most. */
constexpr size_t MAX_SERVERS = 3;

bool IsOwnResolver(const CNetAddr& a)
{
    for (uint8_t v : {4, 6}) {
        const IpAddr r = InterfaceResolver(v);
        CNetAddr n;
        if (v == 4) {
            struct in_addr in;
            std::memcpy(&in, r.bytes.data(), 4);
            n = CNetAddr(in);
        } else {
            struct in6_addr in6;
            std::memcpy(&in6, r.bytes.data(), 16);
            n = CNetAddr(in6);
        }
        if (n == a) return true;
    }
    return false;
}

std::string ReadFile(const char* path)
{
    std::ifstream f(path);
    if (!f) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

enum class Asked { ANSWERED, NO_SUCH_NAME, FAILED };

/** One question to one server. */
Asked AskOne(const CService& server, const std::string& name, uint16_t qtype, std::vector<IpAddr>& out)
{
    struct sockaddr_storage to;
    socklen_t to_len = sizeof(to);
    if (!server.GetSockAddr((struct sockaddr*)&to, &to_len)) return Asked::FAILED;
    SOCKET s = socket(((struct sockaddr*)&to)->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return Asked::FAILED;
    if (!IsSelectableSocket(s) || !MarkBypass(s) || !SetSocketNonBlocking(s, true)) {
        CloseSocket(s);
        return Asked::FAILED;
    }
    const uint16_t id = (uint16_t)GetRand(65536);
    const std::vector<uint8_t> query = BuildDnsQuery(id, name, qtype);
    if (query.empty() || sendto(s, (const char*)query.data(), query.size(), 0, (struct sockaddr*)&to, to_len) < 0) {
        CloseSocket(s);
        return Asked::FAILED;
    }
    const int64_t deadline = GetTimeMillis() + ASK_TIMEOUT_MS;
    Asked result = Asked::FAILED;
    while (true) {
        const int64_t left = deadline - GetTimeMillis();
        if (left <= 0) break;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        struct timeval tv;
        tv.tv_sec = (long)(left / 1000);
        tv.tv_usec = (long)((left % 1000) * 1000);
        if (select((int)s + 1, &rfds, nullptr, nullptr, &tv) <= 0) break;
        std::vector<uint8_t> buf(1500);
        struct sockaddr_storage from;
        socklen_t from_len = sizeof(from);
        const int n = recvfrom(s, (char*)buf.data(), buf.size(), 0, (struct sockaddr*)&from, &from_len);
        if (n <= 0) continue;
        // Only the server asked answers; anything else on the port is noise.
        CService sender;
        if (!sender.SetSockAddr((const struct sockaddr*)&from) || !(sender == server)) continue;
        buf.resize(n);
        DnsRcode rcode;
        std::vector<IpAddr> addrs;
        uint32_t ttl;
        if (!ParseDnsResponse(buf, id, qtype, rcode, addrs, ttl)) continue;
        if (rcode == DnsRcode::OK) {
            out.insert(out.end(), addrs.begin(), addrs.end());
            result = Asked::ANSWERED;
        } else if (rcode == DnsRcode::NO_SUCH_NAME) {
            result = Asked::NO_SUCH_NAME;
        }
        break;
    }
    CloseSocket(s);
    return result;
}

} // namespace

std::vector<CService> ParseResolvConf(const std::string& text)
{
    std::vector<CService> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream words(line);
        std::string key, value;
        if (!(words >> key >> value) || key != "nameserver") continue;
        // A scope (fe80::1%eth0) cannot be carried; such a server is local anyway.
        if (value.find('%') != std::string::npos) continue;
        CService addr;
        if (!Lookup(value, addr, 53, false)) continue;
        if (addr.IsLocal() || IsOwnResolver(addr)) continue;
        if (std::find(out.begin(), out.end(), addr) == out.end()) out.push_back(addr);
    }
    return out;
}

std::vector<CService> UpstreamResolvers()
{
#ifdef WIN32
    // Every connected adapter's resolvers but BPS Relay's own.
    std::vector<CService> out;
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buf(size);
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
                                    (PIP_ADAPTER_ADDRESSES)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
                                  (PIP_ADAPTER_ADDRESSES)buf.data(), &size);
    }
    if (rc != NO_ERROR) return out;
    for (PIP_ADAPTER_ADDRESSES a = (PIP_ADAPTER_ADDRESSES)buf.data(); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || (a->FriendlyName && wcscmp(a->FriendlyName, NET_SERVICE_ADAPTER) == 0)) continue;
        for (PIP_ADAPTER_DNS_SERVER_ADDRESS d = a->FirstDnsServerAddress; d; d = d->Next) {
            CService found;
            if (!found.SetSockAddr(d->Address.lpSockaddr)) continue;
            const CService server(found, 53);
            if (server.IsLocal() || IsOwnResolver(server)) continue;
            // Windows lists placeholder site-local resolvers (fec0:0:0:ffff::1) where none is set.
            if (server.IsIPv6() && server.ToStringIP().rfind("fec0:", 0) == 0) continue;
            if (std::find(out.begin(), out.end(), server) == out.end()) out.push_back(server);
        }
    }
    return out;
#else
    // systemd-resolved writes the servers it forwards to here; /etc/resolv.conf
    // then names only its stub on 127.0.0.53.
    std::vector<CService> out = ParseResolvConf(ReadFile("/run/systemd/resolve/resolv.conf"));
    if (out.empty()) out = ParseResolvConf(ReadFile("/etc/resolv.conf"));
    return out;
#endif
}

ResolveStatus ResolveDirect(const std::vector<CService>& servers, const std::string& name, uint8_t family,
                            std::vector<IpAddr>& out)
{
    out.clear();
    std::vector<uint16_t> types;
    if (family != RESOLVE_V6) types.push_back(DNS_TYPE_A);
    if (family != RESOLVE_V4) types.push_back(DNS_TYPE_AAAA);
    bool answered = false, no_such = false;
    for (uint16_t qtype : types) {
        for (size_t i = 0; i < servers.size() && i < MAX_SERVERS; ++i) {
            const Asked r = AskOne(servers[i], name, qtype, out);
            if (r == Asked::FAILED) continue;
            if (r == Asked::ANSWERED) answered = true;
            if (r == Asked::NO_SUCH_NAME) no_such = true;
            break;
        }
    }
    if (!out.empty()) return ResolveStatus::OK;
    return answered || no_such ? ResolveStatus::NO_SUCH_NAME : ResolveStatus::FAILED;
}

} // namespace overlay
