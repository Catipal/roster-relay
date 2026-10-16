// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/exitpolicy.h>

#include <tinyformat.h>
#include <util/strencodings.h>

namespace overlay {

ExitPolicy::ExitPolicy()
{
    std::string error;
    Parse(DEFAULT_GATEWAY_PORTS, error);
}

bool ExitPolicy::Parse(const std::string& spec, std::string& error)
{
    std::set<uint16_t> tcp, udp;
    size_t start = 0;
    while (start <= spec.size()) {
        size_t end = spec.find(',', start);
        if (end == std::string::npos) end = spec.size();
        std::string item = spec.substr(start, end - start);
        start = end + 1;
        if (item.empty()) continue;

        bool is_udp = false;
        if (item.compare(0, 4, "udp:") == 0) {
            is_udp = true;
            item = item.substr(4);
        } else if (item.compare(0, 4, "tcp:") == 0) {
            item = item.substr(4);
        }
        int32_t port = 0;
        if (!ParseInt32(item, &port) || port < 1 || port > 65535) {
            error = strprintf("\"%s\" is not a port: list ports as 443 for TCP and udp:443 for UDP", item);
            return false;
        }
        if (port == NEVER_PORT) {
            error = "port 25 is never carried by a gateway: it is how servers pass mail to each other, "
                    "and a gateway that carried it could be used to send spam";
            return false;
        }
        (is_udp ? udp : tcp).insert((uint16_t)port);
    }
    if (tcp.empty() && udp.empty()) {
        error = "no ports: a gateway with nothing to carry is a gateway switched off (-gateway=0)";
        return false;
    }
    m_tcp = tcp;
    m_udp = udp;
    return true;
}

bool ExitPolicy::AllowsPort(uint8_t protocol, uint16_t port) const
{
    if (port == NEVER_PORT) return false;
    if (protocol == IPPROTO_TCP_NUM) return m_tcp.count(port) > 0;
    if (protocol == IPPROTO_UDP_NUM) return m_udp.count(port) > 0;
    return false;
}

bool ExitPolicy::Allows(uint8_t protocol, const IpAddr& dst, uint16_t port, std::string& why) const
{
    if (!AllowsPort(protocol, port)) {
        why = strprintf("%s port %u is not in this gateway's exit policy",
                        protocol == IPPROTO_UDP_NUM ? "UDP" : "TCP", port);
        return false;
    }
    if (!m_allow_local && !IsPublicAddress(dst)) {
        why = strprintf("%s is not a public address", dst.ToString());
        return false;
    }
    return true;
}

std::string ExitPolicy::ToString() const
{
    std::string s;
    for (uint16_t p : m_tcp) s += strprintf("%s%u", s.empty() ? "" : ",", p);
    for (uint16_t p : m_udp) s += strprintf("%sudp:%u", s.empty() ? "" : ",", p);
    return s;
}

} // namespace overlay
