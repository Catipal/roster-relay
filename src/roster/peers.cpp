// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/peers.h>

#include <chain.h>
#include <index/rosterindex.h>
#include <net.h>
#include <netaddress.h>
#include <protocol.h>
#include <streams.h>
#include <sync.h>
#include <validation.h>
#include <version.h>

#include <map>

namespace roster {

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

bool CollectPeers(const RosterIndex& index, int tip_height,
                  std::vector<CAddress>& out, CollectStats& stats)
{
    stats = CollectStats();

    std::map<KeyBytes, RosterEntry> live;
    // Read the index before taking cs_main: BuildRoster hits leveldb, and the
    // conversion below is the only part that needs the chain.
    if (!index.BuildRoster(tip_height, live)) return false;
    stats.live = live.size();

    LOCK(cs_main);
    for (std::map<KeyBytes, RosterEntry>::const_iterator it = live.begin();
         it != live.end(); ++it) {
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
