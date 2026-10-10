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
 * random order so no two phones lean on the same few.
 */
std::vector<RelayEntry> PhoneRelays(size_t max);

/**
 * Where this node's overlay listens as the roster lists it. False when this
 * node is not a listed relay, which in this version means no phone can reach it.
 */
bool ListedOverlayAddress(std::string& out);

/** The node functions the service is given. */
NodeHooks MakeNodeHooks();

} // namespace companion

#endif // BITCOIN_COMPANION_NODE_H
