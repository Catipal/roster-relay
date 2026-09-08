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
 * The relay set has to be identical on both sides or they compute different
 * points, which is why the roster is ordered canonically by key and read at an
 * agreed height rather than "now".
 */
namespace overlay {

/** Blocks per rendezvous epoch: one day at 180-second spacing. */
static constexpr uint32_t RENDEZVOUS_EPOCH_BLOCKS = 480;

/** How many meeting points a service keeps, so one relay going down is survivable. */
static constexpr size_t RENDEZVOUS_POINTS = 3;

/**
 * The epoch a height falls in.
 *
 * Rendezvous points rotate so that an adversary cannot permanently install
 * itself as a given service's meeting point and wait. Rotation is by height
 * rather than clock, so every node agrees without needing synchronised time.
 */
uint64_t RendezvousEpoch(int height);

/**
 * Which relays a service meets its clients at.
 *
 * `relays` must be every eligible relay, in ascending key order - the same list
 * on both sides, or they arrive at different answers and never meet. Returns at
 * most `count` distinct relays, fewer only when the roster itself is smaller.
 *
 * Empty for an empty roster, which is a real state during bootstrap and not an
 * error: a network with no relays has nowhere to meet.
 */
std::vector<roster::KeyBytes> RendezvousPoints(const roster::KeyBytes& service_key,
                                               uint64_t epoch,
                                               const std::vector<roster::KeyBytes>& relays,
                                               size_t count = RENDEZVOUS_POINTS);

} // namespace overlay

#endif // BITCOIN_OVERLAY_RENDEZVOUS_H
