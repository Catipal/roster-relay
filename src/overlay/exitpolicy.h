// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_EXITPOLICY_H
#define BITCOIN_OVERLAY_EXITPOLICY_H

#include <overlay/ippacket.h>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

/**
 * What a gateway carries out to the internet (design note §8·7).
 *
 * By design: encrypted web, and the ports mail and
 * messaging apps use that are encrypted from their first byte - so nothing
 * leaves a gateway readable, and the gateway's provider sees which address
 * and how much, not what. Ports that begin in plain text and upgrade later
 * (587, 5222) are left out. Port 25 is never carried, whatever an owner
 * lists, so a gateway cannot be used to send spam.
 *
 * The address must be a public one (IsPublicAddress): a stranger is never
 * let into the owner's own network, or onto the machine itself.
 */
namespace overlay {

/** -gatewayports: TCP ports by number, UDP ones as udp:N. */
static const char* const DEFAULT_GATEWAY_PORTS = "443,465,853,993,995,5223,5228,udp:443";

/** Never carried, whatever the owner lists: SMTP between servers, the spam port. */
static constexpr uint16_t NEVER_PORT = 25;

class ExitPolicy
{
public:
    /** The decided default. */
    ExitPolicy();

    /**
     * Read a list like "443,993,udp:443". False with `error` for anything
     * malformed, an empty list, or port 25.
     */
    bool Parse(const std::string& spec, std::string& error);

    /**
     * Let a gateway connect to loopback and private addresses. Regtest only,
     * for tests whose "internet" is a server on 127.0.0.1.
     */
    void AllowLocal(bool allow) { m_allow_local = allow; }
    bool LocalAllowed() const { return m_allow_local; }

    bool AllowsPort(uint8_t protocol, uint16_t port) const;

    /** Port and address together. False with `why`, for the log and the visitor. */
    bool Allows(uint8_t protocol, const IpAddr& dst, uint16_t port, std::string& why) const;

    const std::set<uint16_t>& TcpPorts() const { return m_tcp; }
    const std::set<uint16_t>& UdpPorts() const { return m_udp; }
    /** The policy in the form -gatewayports takes. */
    std::string ToString() const;

private:
    std::set<uint16_t> m_tcp;
    std::set<uint16_t> m_udp;
    bool m_allow_local{false};
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_EXITPOLICY_H
