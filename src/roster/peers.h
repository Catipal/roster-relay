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

/** One roster member, as the overlay needs it: who it is, where, and its standing. */
struct RelayInfo {
    KeyBytes key;
    CService addr;
    //! Blocks of continuous history (§5), 0 while it has none AGE_DEPTH deep.
    int age{0};
    //! The identity running it (§7), or all zeros.
    KeyBytes identity{};
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
 *
 * `allow_local` keeps loopback and private endpoints, for regtest only: every
 * node of a functional test listens on 127.0.0.1, and a test of paths needs
 * them to count as relays.
 */
bool CollectRelays(const RosterIndex& index, int tip_height,
                   std::vector<RelayInfo>& out, bool allow_local = false);

/**
 * The relay set every node agrees on at `height`: keys the roster lists as live
 * there with an endpoint any node could dial, in ascending key order.
 *
 * Unlike CollectRelays, nothing about this node enters into it - not which
 * networks it can reach, not revocations it has seen ahead of the chain -
 * because meeting points are computed from it on both sides of a meeting and
 * have to come out the same. `allow_local` as for CollectRelays.
 */
bool AgreedRelays(const RosterIndex& index, int height, std::vector<KeyBytes>& out, bool allow_local = false);

/**
 * The gateways the roster lists as live at `height`: keys whose record carries
 * SERVICE_GATEWAY and no endpoint, in ascending key order, without those this
 * node has seen revoked.
 *
 * A visitor picks among them at random, so unlike AgreedRelays nothing here
 * has to come out the same on two nodes.
 */
bool CollectGateways(const RosterIndex& index, int height, std::vector<KeyBytes>& out);

/**
 * The announcement that lists `key` at `height`: its latest one confirmed by
 * then and not yet expired. False when the key is not listed there.
 */
bool LiveAnnouncement(const RosterIndex& index, const KeyBytes& key, int height, Record& out);

/**
 * Re-read the relay set into the overlay's path selector, unless it was read
 * at the index's current height less than `max_age` seconds ago, and return it.
 *
 * Read at the roster index's own height, on regtest with local endpoints
 * kept. Rate limited, because it reads the index and its callers include
 * relays deciding whether to dial for a stranger. Empty when the overlay or
 * the index is off.
 */
std::vector<RelayInfo> FreshRelays(int64_t max_age = 10);

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
