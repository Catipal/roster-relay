// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_PEERS_H
#define BITCOIN_ROSTER_PEERS_H

#include <roster/record.h>

#include <chrono>
#include <stddef.h>
#include <vector>

// netaddress.h rather than a forward declaration, because RelayInfo holds a
// CService by value.
#include <netaddress.h>

class CAddress;
class RosterIndex;

/**
 * Turning roster records into peers worth dialling.
 *
 * This is the layer that makes the roster a discovery mechanism rather than a
 * database: without it a node publishes and answers queries, but never uses
 * what the chain tells it. Everything here is client policy in the sense of
 * §0 - the chain says which peers exist, and this decides which of them this
 * particular node is willing to try.
 */
namespace roster {

/** Whether roster entries are offered to the address manager at all. */
static const bool DEFAULT_ROSTERCONNECT = true;

/**
 * How often the live roster is re-read and offered to the address manager.
 *
 * The roster moves at block pace and expiries are measured in months, so there
 * is nothing to gain from checking often. The address manager keeps what it is
 * given, so this is a top-up rather than a refresh.
 */
static constexpr std::chrono::minutes ROSTER_PEERS_INTERVAL{30};

/**
 * Convert one endpoint to a CService.
 *
 * The roster encodes an endpoint as network(1) || addr || port(2, big endian),
 * which is BIP155's layout save for the CompactSize length BIP155 puts before
 * the address, and the network ids are the same numbers. So rather than
 * reimplement address parsing - CNetAddr keeps its BIP155 helpers private, and
 * a second parser is a second thing to get wrong - this re-frames the endpoint
 * as addrv2 and hands it to the deserialiser the p2p layer already uses.
 *
 * False when the endpoint names something this build cannot represent, which
 * is not an error: a record may legitimately carry a network this node has
 * never heard of.
 */
bool EndpointToService(const Endpoint& ep, CService& out);

/** One roster member, as the overlay needs it: who it is, and where. */
struct RelayInfo {
    KeyBytes key;
    CService addr;
};

/**
 * The live roster as relay candidates, in ascending key order.
 *
 * Ordered canonically because rendezvous derivation is arithmetic over this
 * list: two nodes with the same members in a different order compute different
 * meeting points and never meet.
 *
 * One entry per key, taking the first dialable endpoint. A relay advertising
 * three addresses is still one relay, and counting it three times would let it
 * occupy three path positions.
 */
bool CollectRelays(const RosterIndex& index, int tip_height,
                   std::vector<RelayInfo>& out);

/** Why entries were passed over, for logging that says something useful. */
struct CollectStats {
    size_t live{0};            //!< keys in the live roster
    size_t no_endpoint{0};     //!< listed, but offering nowhere to dial
    size_t unrepresentable{0}; //!< a network this build cannot express
    size_t unreachable{0};     //!< a network this node has no transport for
    size_t unroutable{0};      //!< private or documentation space, which addrman drops anyway
    size_t collected{0};       //!< addresses actually returned
};

/**
 * Gather dialable addresses from the live roster.
 *
 * Filtered by what this node can actually reach, so a node without Tor does
 * not fill its address manager with onion addresses it will never connect to.
 * Returns false only when the index could not be read; an empty roster is a
 * successful, empty answer.
 */
bool CollectPeers(const RosterIndex& index, int tip_height,
                  std::vector<CAddress>& out, CollectStats& stats);

} // namespace roster

#endif // BITCOIN_ROSTER_PEERS_H
