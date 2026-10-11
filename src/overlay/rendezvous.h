// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_RENDEZVOUS_H
#define BITCOIN_OVERLAY_RENDEZVOUS_H

#include <roster/record.h>

#include <stdint.h>
#include <vector>

/**
 * Meeting without knowing where.
 *
 * A service that will not publish its address still has to be findable. The
 * usual answer is a distributed hash table: the service stores a pointer to
 * itself, and a client looks it up. That lookup is the weakness - whoever
 * answers it can answer selectively, showing one client the truth and another
 * an attacker's introduction point, and the client cannot tell.
 *
 * Here there is no lookup. Both sides compute the same meeting points by
 * arithmetic over the roster, which is agreed because it comes off the chain.
 * A wrong answer is not something an adversary can give, because nobody is
 * asked. That is the concrete reason this design is worth a chain rather than
 * joining an existing network, and it is the one property here that is not
 * simply a reimplementation of what already exists.
 *
 * Agreement needs two things. The relay set is read at an agreed height - the
 * epoch's anchor, a few blocks before it starts - rather than "now", and with
 * no filter that differs between nodes. And the points are the relays scoring
 * highest for the service, not indexes into a list: two nodes whose sets
 * differ by a relay still share all but at most one point, where a modulo
 * would move every one of them.
 */
namespace overlay {

/** Blocks per rendezvous epoch: one day at 180-second spacing. */
static constexpr uint32_t RENDEZVOUS_EPOCH_BLOCKS = 480;

/** How many meeting points a service keeps, so one relay going down is survivable. */
static constexpr size_t RENDEZVOUS_POINTS = 3;

/** An epoch's relay set is the roster this many blocks before it starts, which every node has by then. */
static constexpr int RENDEZVOUS_ANCHOR_DEPTH = 6;

/**
 * For this many blocks into a new epoch a service stays registered at the old
 * one's points too, for visitors whose chain is a little behind.
 */
static constexpr int RENDEZVOUS_OVERLAP = 30;

/**
 * The epoch a height falls in.
 *
 * Rendezvous points rotate so that an adversary cannot permanently install
 * itself as a given service's meeting point and wait. Rotation is by height
 * rather than clock, so every node agrees without needing synchronised time.
 */
uint64_t RendezvousEpoch(int height);

/** The height whose roster decides an epoch's meeting points. */
int RendezvousAnchor(uint64_t epoch);

/**
 * The epochs a service registers for at `height`: the current one, the next
 * once its anchor is reached, and the previous one for RENDEZVOUS_OVERLAP
 * blocks after it ended. A visitor a few blocks ahead or behind still finds it.
 */
std::vector<uint64_t> EpochsToRegister(int height);

/** The epochs a visitor tries at `height`, in order: the current one, then the one before. */
std::vector<uint64_t> EpochsToTry(int height);

/**
 * Which relays a service meets its clients at in `epoch`.
 *
 * `relays` is the relay set at the epoch's anchor, in any order. Each relay
 * scores TaggedHash("BPS/meet/v2")(service, epoch, relay) and the highest
 * `count` are the points; the service itself is never one of them. Fewer only
 * when the roster is smaller, and empty for an empty roster, which is a real
 * state during bootstrap and not an error.
 */
std::vector<roster::KeyBytes> RendezvousPoints(const roster::KeyBytes& service_key,
                                               uint64_t epoch,
                                               const std::vector<roster::KeyBytes>& relays,
                                               size_t count = RENDEZVOUS_POINTS);

} // namespace overlay

#endif // BITCOIN_OVERLAY_RENDEZVOUS_H
