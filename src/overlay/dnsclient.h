// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_DNSCLIENT_H
#define BITCOIN_OVERLAY_DNSCLIENT_H

#include <netaddress.h>
#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>

#include <string>
#include <vector>

/**
 * A gateway's lookups while its own computer's traffic goes through the
 * system-wide interface (overlay/sysroute.h).
 *
 * Then the computer's resolver is the interface's, which asks a gateway. A
 * gateway asking it for a visitor would hand the lookup to another gateway,
 * and that one, if its computer is routed the same way, to a third. So a
 * gateway in that state asks the resolvers its computer used before the
 * routes were set - its provider's, or whatever its owner chose - directly,
 * on sockets that pass the interface by.
 */
namespace overlay {

/** The `nameserver` lines of a resolv.conf, less loopback stubs and the interface's own resolver. */
std::vector<CService> ParseResolvConf(const std::string& text);

/**
 * The resolvers this computer asks, as its configuration names them:
 * systemd-resolved's upstream list where it runs, else /etc/resolv.conf.
 * Empty where they cannot be read.
 */
std::vector<CService> UpstreamResolvers();

/**
 * Look `name` up by asking `servers` directly (family RESOLVE_V4, RESOLVE_V6
 * or RESOLVE_ANY). Blocking, a few seconds at most per server; for the
 * gateway's lookup thread.
 */
ResolveStatus ResolveDirect(const std::vector<CService>& servers, const std::string& name, uint8_t family,
                            std::vector<IpAddr>& out);

} // namespace overlay

#endif // BITCOIN_OVERLAY_DNSCLIENT_H
