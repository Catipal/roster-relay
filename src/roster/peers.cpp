// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/peers.h>

#include <roster/view.h>

#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <index/rosterindex.h>
#include <logging.h>
#include <net.h>
#include <netaddress.h>
#include <overlay/select.h>
#include <protocol.h>
#include <streams.h>
#include <sync.h>
#include <util/time.h>
#include <validation.h>
#include <version.h>

#include <map>

namespace roster {

namespace {
Mutex g_fresh_mutex;
int64_t g_fresh_at GUARDED_BY(g_fresh_mutex){0};
int g_fresh_height GUARDED_BY(g_fresh_mutex){-1};
std::vector<RelayInfo> g_fresh GUARDED_BY(g_fresh_mutex);
} // namespace

std::vector<RelayInfo> FreshRelays(int64_t max_age)
{
    LOCK(g_fresh_mutex);
    RosterIndex* index = g_rosterindex.get();
    if (index == nullptr) return g_fresh;
    // The roster only changes when the index reaches a new block, so a copy
    // read at the index's current height is current whatever its age. The age
    // limit only bounds how long the same height can be trusted.
    const int height = index->GetSummary().best_block_height;
    const int64_t now = GetTime();
    if (g_fresh_at != 0 && height == g_fresh_height && now - g_fresh_at < max_age) return g_fresh;

    std::vector<RelayInfo> relays;
    const bool local = Params().NetworkIDString() == CBaseChainParams::REGTEST;
    if (!CollectRelays(*index, height, relays, local)) return g_fresh;

    // A stale roster may be missing revocations, so the age it shows is not
    // a thing to prefer relays by (§5); it still says where they are.
    const bool stale = GetRosterStatus().stale;
    std::vector<overlay::RelayCandidate> candidates;
    candidates.reserve(relays.size());
    for (const RelayInfo& r : relays) {
        overlay::RelayCandidate c;
        c.key = r.key;
        c.addr = r.addr;
        c.age = stale ? 0 : r.age;
        c.identity = r.identity;
        candidates.push_back(c);
    }
    {
        LOCK(overlay::g_selector_mutex);
        if (overlay::g_selector) overlay::g_selector->SetRelays(candidates);
    }
    if (relays.size() != g_fresh.size()) {
        LogPrint(BCLog::NET, "overlay: %u relay candidates from the roster\n", relays.size());
    }
    g_fresh = relays;
    g_fresh_at = now;
    g_fresh_height = height;
    return g_fresh;
}

bool EndpointToService(const Endpoint& ep, CService& out)
{
    if (ep.addr.empty()) return false;
    // Guard the CompactSize cast below and reject anything absurd before it
    // reaches the deserialiser.
    if (ep.addr.size() > 512) return false;

    CDataStream s(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    s << ep.network;
    WriteCompactSize(s, ep.addr.size());
    s.write(reinterpret_cast<const char*>(ep.addr.data()), ep.addr.size());
    // CService appends the port big-endian after the address, which is the
    // same order and width the record uses.
    const unsigned char port_be[2] = {
        static_cast<unsigned char>((ep.port >> 8) & 0xff),
        static_cast<unsigned char>(ep.port & 0xff),
    };
    s.write(reinterpret_cast<const char*>(port_be), sizeof(port_be));

    CService parsed;
    try {
        s >> parsed;
    } catch (const std::exception&) {
        return false;
    }
    // An unknown BIP155 network deserialises without throwing and lands as an
    // address that is simply not valid, which is the answer we want anyway.
    if (!parsed.IsValid()) return false;

    out = parsed;
    return true;
}

bool CollectRelays(const RosterIndex& index, int tip_height,
                   std::vector<RelayInfo>& out, bool allow_local)
{
    out.clear();

    std::map<KeyBytes, RosterEntry> live;
    if (!index.BuildRoster(tip_height, live)) return false;

    // std::map iterates in key order, which is the canonical order rendezvous
    // derivation depends on - both sides must build the identical list.
    for (std::map<KeyBytes, RosterEntry>::const_iterator it = live.begin();
         it != live.end(); ++it) {
        // A revocation counts the moment this node sees it, confirmed or not.
        if (SeenRevoked(it->first)) continue;
        Record rec;
        if (!it->second.Parse(rec)) continue;

        for (size_t i = 0; i < rec.endpoints.size(); ++i) {
            CService service;
            if (!EndpointToService(rec.endpoints[i], service)) continue;
            if (!allow_local && (!service.IsRoutable() || !IsReachable(service))) continue;
            RelayInfo info;
            info.key = it->first;
            info.addr = service;
            Standing standing;
            if (GetStanding(index, it->first, tip_height, standing)) {
                info.age = standing.age;
                if (standing.has_identity) info.identity = standing.identity;
            }
            out.push_back(info);
            // One entry per key: a relay advertising three addresses is one
            // relay, and counting it three times would let it hold three
            // positions on a path that is supposed to have three parties.
            break;
        }
    }
    return true;
}

bool AgreedRelays(const RosterIndex& index, int height, std::vector<KeyBytes>& out, bool allow_local)
{
    out.clear();
    std::map<KeyBytes, RosterEntry> live;
    if (!index.BuildRoster(height, live)) return false;
    for (std::map<KeyBytes, RosterEntry>::const_iterator it = live.begin(); it != live.end(); ++it) {
        Record rec;
        if (!it->second.Parse(rec)) continue;
        for (const Endpoint& ep : rec.endpoints) {
            CService service;
            if (!EndpointToService(ep, service)) continue;
            // Routable is a property of the address, the same everywhere;
            // reachable is a property of this node, and stays out.
            if (!allow_local && !service.IsRoutable()) continue;
            out.push_back(it->first);
            break;
        }
    }
    return true;
}

bool CollectPeers(const RosterIndex& index, int tip_height,
                  std::vector<CAddress>& out, CollectStats& stats)
{
    stats = CollectStats();

    std::map<KeyBytes, RosterEntry> live;
    // Read the index before taking cs_main: BuildRoster hits leveldb, and the
    // conversion below is the only part that needs the chain.
    if (!index.BuildRoster(tip_height, live)) return false;
    stats.live = live.size();

    // Announcements not on the chain - waiting in the mempool, or taken out by
    // a reorg - are extra dial hints for keys the chain lists (§9), beside the
    // confirmed address rather than instead of it: a stale address costs one
    // failed handshake, because the transport checks the key.
    std::vector<std::pair<KeyBytes, RosterEntry>> entries(live.begin(), live.end());
    for (const auto& hint : g_hints.All()) {
        if (!live.count(hint.first)) continue;
        RosterEntry entry;
        entry.raw = hint.second.raw;
        entry.height = tip_height;
        entries.emplace_back(hint.first, entry);
    }

    LOCK(cs_main);
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (SeenRevoked(it->first)) continue;
        Record rec;
        if (!it->second.Parse(rec)) continue;

        if (rec.endpoints.empty()) {
            ++stats.no_endpoint;
            continue;
        }

        for (size_t i = 0; i < rec.endpoints.size(); ++i) {
            CService service;
            if (!EndpointToService(rec.endpoints[i], service)) {
                ++stats.unrepresentable;
                continue;
            }
            // Drop what the address manager would drop anyway (addrman.cpp:264
            // rejects anything not routable), so the counts below describe what
            // was actually accepted rather than what was handed over.
            if (!service.IsRoutable()) {
                ++stats.unroutable;
                continue;
            }
            // A node with no Tor transport should not fill its address manager
            // with onion addresses it can never dial.
            if (!IsReachable(service)) {
                ++stats.unreachable;
                continue;
            }
            // Services are left at NODE_NONE deliberately. The record's service
            // bits describe the roster's own roles, not the p2p service flags,
            // and claiming NODE_NETWORK on a peer's behalf would be asserting
            // something the chain never said. The connection attempt learns the
            // real flags from the peer's own version message.
            CAddress addr(service, NODE_NONE);
            // Date the address from the block that carried the record, so the
            // address manager ages roster peers by when they were announced.
            // Claiming "now" would present a year-old record as fresh, and
            // leaving it unset would bury a record published this morning. The
            // announcement height is the one honest timestamp available, and
            // being unforgeable is the whole reason the roster is on a chain.
            const CBlockIndex* pindex = ::ChainActive()[it->second.height];
            if (pindex != nullptr) addr.nTime = pindex->GetBlockTime();
            out.push_back(addr);
            ++stats.collected;
        }
    }

    return true;
}

} // namespace roster
