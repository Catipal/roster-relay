// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/select.h>

#include <algorithm>

namespace overlay {

constexpr size_t PathSelector::GUARD_COUNT;

Mutex g_selector_mutex;
std::unique_ptr<PathSelector> g_selector;

PathSelector::PathSelector(size_t guard_count, bool local_relays)
    : m_guard_count(guard_count), m_local_relays(local_relays) {}

void PathSelector::SetSelf(const roster::KeyBytes& self)
{
    m_self = self;
    m_has_self = true;
    DropGuard(self);
}

std::vector<unsigned char> PathSelector::GroupOf(const CService& a) const
{
    // On regtest every node is on one loopback address, which the address
    // manager rightly calls one group; there each address and port counts as
    // its own operator instead, or no test could build a path at all.
    if (m_local_relays && !a.IsRoutable()) {
        std::vector<unsigned char> key = a.GetKey();
        key.insert(key.begin(), 0xFF);
        return key;
    }
    // The address manager's own grouping, so this does not invent a second one.
    return a.GetGroup(std::vector<bool>());
}

void PathSelector::SetRelays(const std::vector<RelayCandidate>& relays)
{
    m_relays = relays;

    // Keep the guards that are still listed. A guard that changed whenever the
    // roster shifted would give back exactly the cumulative exposure it exists
    // to prevent.
    std::vector<RelayCandidate> kept;
    for (size_t i = 0; i < m_guards.size(); ++i) {
        for (size_t j = 0; j < m_relays.size(); ++j) {
            if (m_guards[i].key == m_relays[j].key) {
                kept.push_back(m_relays[j]);
                break;
            }
        }
    }
    m_guards = kept;
}

void PathSelector::DropGuard(const roster::KeyBytes& key)
{
    for (size_t i = 0; i < m_guards.size(); ++i) {
        if (m_guards[i].key == key) {
            m_guards.erase(m_guards.begin() + i);
            return;
        }
    }
}

bool PathSelector::DistinctOperator(const RelayCandidate& c,
                                    const std::vector<RelayCandidate>& chosen) const
{
    const std::vector<unsigned char> group = GroupOf(c.addr);
    for (size_t i = 0; i < chosen.size(); ++i) {
        if (chosen[i].key == c.key) return false;
        if (GroupOf(chosen[i].addr) == group) return false;
    }
    return true;
}

bool PathSelector::Select(size_t hops, std::vector<RelayCandidate>& out)
{
    return Select(hops, out, RelayCandidate());
}

bool PathSelector::Select(size_t hops, std::vector<RelayCandidate>& out,
                          const RelayCandidate& destination)
{
    out.clear();
    if (hops == 0 || m_relays.empty()) return false;

    // Top the guard set up first, so the entry relay is drawn once and then
    // reused rather than being part of every path's draw.
    while (m_guards.size() < m_guard_count) {
        std::vector<RelayCandidate> eligible;
        for (size_t i = 0; i < m_relays.size(); ++i) {
            if (IsSelf(m_relays[i])) continue;
            if (DistinctOperator(m_relays[i], m_guards)) eligible.push_back(m_relays[i]);
        }
        if (eligible.empty()) break; // a small roster may not support two
        m_guards.push_back(eligible[m_rng.randrange(eligible.size())]);
    }

    // The destination and its operator are ruled out everywhere, guards
    // included. A guard that happens to be the destination is passed over for
    // this path only; it stays a guard.
    std::vector<RelayCandidate> avoid;
    if (destination.addr.IsValid()) avoid.push_back(destination);
    std::vector<RelayCandidate> usable_guards;
    for (size_t i = 0; i < m_guards.size(); ++i) {
        if (DistinctOperator(m_guards[i], avoid)) usable_guards.push_back(m_guards[i]);
    }
    if (usable_guards.empty()) return false;

    out.push_back(usable_guards[m_rng.randrange(usable_guards.size())]);

    // The rest are fresh for every path: rotating these costs nothing, and an
    // adversary who is not the entry learns far less by being a later hop.
    while (out.size() < hops) {
        std::vector<RelayCandidate> taken = out;
        taken.insert(taken.end(), avoid.begin(), avoid.end());
        std::vector<RelayCandidate> eligible;
        for (size_t i = 0; i < m_relays.size(); ++i) {
            if (IsSelf(m_relays[i])) continue;
            if (DistinctOperator(m_relays[i], taken)) eligible.push_back(m_relays[i]);
        }
        if (eligible.empty()) {
            // Refused rather than quietly returning a shorter path, or one
            // whose hops are the same operator: a caller that asked for two
            // independent hops and silently got one would believe something
            // untrue about its own anonymity.
            out.clear();
            return false;
        }
        out.push_back(eligible[m_rng.randrange(eligible.size())]);
    }

    return out.size() == hops;
}

} // namespace overlay
