// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SYSROUTE_H
#define BITCOIN_OVERLAY_SYSROUTE_H

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

/**
 * Routing the whole computer through the system-wide interface (design note
 * §8·7). Linux, by design: an administrator grants the
 * program the right to manage the network once (setcap cap_net_admin), and
 * the node then sets the routes up itself and takes them down when it stops.
 *
 * The way WireGuard's wg-quick does it, by policy routing:
 *
 *  - a routing table of the node's own sends everything to the interface;
 *  - one rule sends there whatever does not carry the node's mark - the node
 *    marks its own sockets (peer-to-peer, the overlay, a gateway's exits and
 *    lookups; netbase.h MarkBypass), so they keep the computer's own line;
 *  - a rule before it keeps the computer's own networks (every route but the
 *    default) off the interface, so a printer or a router stays reachable;
 *  - systemd-resolved, where it runs, is told to ask the interface's
 *    resolver for every name.
 *
 * If the node dies without taking them down, the interface goes with it and
 * its table empties, so the rules no longer send anything anywhere and the
 * computer is back on its own line; the next start clears what is left.
 */
namespace overlay {

/** The mark on the node's own sockets, its routing table, and its rules' priority. */
static constexpr uint32_t ROUTE_MARK = 0x6270;
static constexpr uint32_t ROUTE_TABLE = 25200;
static constexpr uint32_t ROUTE_PRIORITY = 25200;

/** One command, and whether the routes cannot work without it. */
struct RouteStep {
    std::vector<std::string> argv;
    bool required{true};
};

/** What routing the computer through `dev` takes (ip and resolvectl), and undoing it. */
std::vector<RouteStep> PlanRoutesUp(const std::string& dev, bool resolver);
std::vector<RouteStep> PlanRoutesDown(const std::string& dev, bool resolver);

/**
 * Whether this process may route the computer; if not, `how` says how to let
 * it. On Linux, the right to manage the network; on Windows, BPS Relay's
 * network service installed and running (bps-relay-net.cpp).
 */
bool HaveNetAdmin(std::string& how);

/** Windows: the computer's own interfaces, IPv4 and IPv6, for the node's own sockets (netbase.h). */
bool DefaultInterfaces(uint32_t& v4_index, uint32_t& v6_index);

class SystemRoutes
{
public:
    ~SystemRoutes();
    /** Clear anything left from before, then route the computer through `dev`. */
    bool Apply(const std::string& dev, std::string& error);
    /** Take the routes down. */
    void Undo();
    bool Active() const { return m_active; }
    /** Whether the computer's resolver was pointed at the interface too. */
    bool Resolver() const { return m_resolver; }

private:
    std::string m_dev;
    bool m_active{false};
    bool m_resolver{false};
};

extern std::unique_ptr<SystemRoutes> g_system_routes;

} // namespace overlay

#endif // BITCOIN_OVERLAY_SYSROUTE_H
