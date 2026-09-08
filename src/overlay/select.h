// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SELECT_H
#define BITCOIN_OVERLAY_SELECT_H

#include <netaddress.h>
#include <random.h>
#include <roster/record.h>

#include <memory>
#include <sync.h>
#include <vector>

/**
 * Choosing which relays to build a path through.
 *
 * Client policy in the sense of section 0: the chain says which relays exist,
 * and this decides which of them this node is willing to route through. Nothing
 * here is consensus, and two clients may reasonably choose differently.
 *
 * Two rules do most of the work, and the first is counterintuitive enough that
 * it is worth stating rather than assuming.
 *
 * ENTRY RELAYS ARE KEPT, NOT ROTATED. The instinct is to pick a fresh first hop
 * for every path, on the grounds that variety is safer. It is the opposite. An
 * adversary running a fraction f of relays is the entry for any given path with
 * probability f, so over many paths the chance they are *ever* the entry rises
 * toward certainty. Keeping a small fixed set means the bet is taken once: with
 * probability f the client is exposed from the start, and otherwise it is never
 * exposed at all. Trading a small permanent risk for the elimination of a
 * cumulative one is what a guard is, and every serious onion router does this.
 *
 * NO TWO HOPS BEHIND THE SAME OPERATOR. Two relays in one address block are
 * plausibly one party, and a path through both is a path with one hop. The
 * grouping used is the address manager's own, so it inherits whatever the node
 * already believes about network topology instead of inventing a second answer.
 */
namespace overlay {

struct RelayCandidate {
    roster::KeyBytes key;
    CService addr;

    bool operator==(const RelayCandidate& o) const { return key == o.key; }
};

class PathSelector
{
public:
    /** How many entry relays are kept. More than one so a single one going down is survivable, few enough that the bet stays taken once. */
    static constexpr size_t GUARD_COUNT = 2;

    explicit PathSelector(size_t guard_count = GUARD_COUNT);

    /**
     * Replace the candidate set, as read from the roster.
     *
     * Guards already chosen are kept if they are still listed, because a guard
     * that rotated whenever the roster changed would not be a guard.
     */
    void SetRelays(const std::vector<RelayCandidate>& relays);

    /**
     * Choose `hops` relays for one path: an entry relay first, fresh ones after.
     *
     * False when the roster cannot supply that many relays under the diversity
     * rule - which is a real state on a small network, and better refused than
     * quietly satisfied with two hops that are the same operator.
     */
    bool Select(size_t hops, std::vector<RelayCandidate>& out);

    /** The entry relays currently held. */
    std::vector<RelayCandidate> Guards() const { return m_guards; }

    /** Forget one entry relay, when it has stopped answering. */
    void DropGuard(const roster::KeyBytes& key);

    size_t CandidateCount() const { return m_relays.size(); }

    /**
     * Every candidate, in the order they were supplied.
     *
     * That order is the roster's own, ascending by key, which rendezvous
     * derivation depends on: a differently ordered list gives different
     * meeting points, and two nodes that disagree never meet.
     */
    const std::vector<RelayCandidate>& Candidates() const { return m_relays; }

private:
    bool DistinctOperator(const RelayCandidate& c,
                          const std::vector<RelayCandidate>& chosen) const;

    size_t m_guard_count;
    std::vector<RelayCandidate> m_relays;
    std::vector<RelayCandidate> m_guards;
    mutable FastRandomContext m_rng;
};

/**
 * Which relays this node will route through, refreshed from the roster.
 *
 * Guarded because the refresh runs on the scheduler and readers are RPC
 * threads. Null until the overlay starts.
 */
extern Mutex g_selector_mutex;
extern std::unique_ptr<PathSelector> g_selector GUARDED_BY(g_selector_mutex);

} // namespace overlay

#endif // BITCOIN_OVERLAY_SELECT_H
