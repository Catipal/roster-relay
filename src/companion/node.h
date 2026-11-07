// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_NODE_H
#define BITCOIN_COMPANION_NODE_H

#include <companion/protocol.h>
#include <companion/service.h>

#include <string>
#include <vector>

/** What the companion service reads from the running node: the roster, the chain, the overlay. */
namespace companion {

/**
 * Relays a phone can build its paths through: listed, reachable over IPv4 or
 * IPv6 - a phone has no Tor - and not this node, at most `max` of them in
 * random order so no two phones lean on the same few. None when this node is
 * not listed itself: no path could end here.
 */
std::vector<RelayEntry> PhoneRelays(size_t max);

/**
 * Where this node's overlay listens as the roster lists it. False when this
 * node is not a listed relay: a phone can then reach it only directly, with
 * no relays in between, at one of HomeAddresses().
 */
bool ListedOverlayAddress(std::string& out);

/** At most this many addresses go into a pairing ticket. */
static constexpr size_t MAX_HOME_ADDRESSES = 6;

/**
 * Every address a phone might reach this node's overlay at, best first, as a
 * pairing ticket carries them (comma separated): the listed one, any given
 * with -companionaddress, the public address peers see, then this computer's
 * own addresses on its local networks - for a phone on the same Wi-Fi, which
 * the router may not let back in through the public one. False if none.
 * `listed` says whether the first is the roster's.
 */
bool HomeAddresses(std::string& out, bool& listed);

/** The node functions the service is given. */
NodeHooks MakeNodeHooks();

} // namespace companion

#endif // BITCOIN_COMPANION_NODE_H
