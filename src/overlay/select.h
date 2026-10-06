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

/**
 * Relays on every path this node builds, before its destination.
 *
 * Two is the fewest that keep any one relay from knowing both ends: the first
 * sees who is asking, the last sees what is reached, and an adversary holding
 * a fraction f of the relays sees a whole path with probability f squared.
 *
 * The third protects the entry relay. With two, the far relay sees which relay
 * the traffic came through - the client's entry relay, which it keeps for
 * months (see below) - and an adversary there can then watch or attack that
 * one relay. A middle hop hides the entry from the far end. Tor and Session's
 * onion requests use three for the same reason, and so does this. The cost is
 * one more relay's latency on every packet and a roster that can supply three
 * relays run by different operators; until it can, paths are refused rather
 * than shortened.
 */
static constexpr size_t DEFAULT_PATH_HOPS = 3;

struct RelayCandidate {
    roster::KeyBytes key;
    CService addr;
    //! Blocks of continuous history, or 0 when unknown or too young to count.
    int age{0};
    //! The identity running it, or all zeros: relays one identity runs are one operator.
    roster::KeyBytes identity{};

    bool operator==(const RelayCandidate& o) const { return key == o.key; }
};

class PathSelector
{
public:
    /** How many entry relays are kept. More than one so a single one going down is survivable, few enough that the bet stays taken once. */
    static constexpr size_t GUARD_COUNT = 2;

    /**
     * `local_relays` treats each loopback or private address with its port as
     * an operator of its own. Only for regtest, where every node of a test is
     * on 127.0.0.1 and would otherwise count as one operator.
     */
    explicit PathSelector(size_t guard_count = GUARD_COUNT, bool local_relays = false);

    /** This node's own key, which no path it builds goes through. */
    void SetSelf(const roster::KeyBytes& self);

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

    /**
     * The same, for a path that ends at `destination`.
     *
     * The destination is never one of the relays, and none of them is its
     * operator: a last relay run by whoever runs the destination makes the
     * path one hop shorter than it claims to be.
     */
    bool Select(size_t hops, std::vector<RelayCandidate>& out, const RelayCandidate& destination);

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
    std::vector<unsigned char> GroupOf(const CService& a) const;
    bool IsSelf(const RelayCandidate& c) const { return m_has_self && c.key == m_self; }

    size_t m_guard_count;
    bool m_local_relays;
    bool m_has_self{false};
    roster::KeyBytes m_self{};
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
