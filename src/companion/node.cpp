// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/node.h>

#include <chainparams.h>
#include <key.h>
#include <overlay/relay.h>
#include <random.h>
#include <roster/keystore.h>
#include <roster/listing.h>
#include <roster/peers.h>
#include <validation.h>

#include <algorithm>

namespace companion {

namespace {

bool OwnKey(roster::KeyBytes& out)
{
    CKey key;
    std::string error;
    if (!roster::GetOperationalKey(key, error)) return false;
    const CPubKey pub = key.GetPubKey();
    std::copy(pub.begin() + 1, pub.begin() + 33, out.begin());
    return true;
}

} // namespace

std::vector<RelayEntry> PhoneRelays(size_t max)
{
    roster::KeyBytes self{};
    const bool have_self = OwnKey(self);
    const bool regtest = Params().NetworkIDString() == CBaseChainParams::REGTEST;

    std::vector<RelayEntry> out;
    for (const roster::RelayInfo& r : roster::FreshRelays()) {
        if (have_self && r.key == self) continue;
        const CService addr = roster::OverlayAddressFor(r.addr);
        if (!addr.IsIPv4() && !addr.IsIPv6()) continue;
        if (!regtest && !addr.IsRoutable()) continue;
        RelayEntry e;
        if (!roster::StakerPubKeyFromRoster(r.key, e.key)) continue;
        e.addr = addr.ToString();
        out.push_back(e);
    }
    Shuffle(out.begin(), out.end(), FastRandomContext());
    if (out.size() > max) out.resize(max);
    return out;
}

bool ListedOverlayAddress(std::string& out)
{
    roster::KeyBytes self{};
    if (!OwnKey(self)) return false;
    for (const roster::RelayInfo& r : roster::FreshRelays()) {
        if (r.key == self) {
            out = roster::OverlayAddressFor(r.addr).ToString();
            return true;
        }
    }
    return false;
}

NodeHooks MakeNodeHooks()
{
    NodeHooks hooks;
    hooks.height = [] {
        LOCK(cs_main);
        return ::ChainActive().Height();
    };
    hooks.relays = [] { return PhoneRelays(MAX_RELAYS); };
    hooks.identify = [](const overlay::Hop& hop) {
        if (!hop.via_path || !overlay::g_overlay) return CPubKey();
        return overlay::g_overlay->SecretPeerIdentity(hop.path);
    };
    hooks.sender = overlay::RelaySender([] { return overlay::g_overlay.get(); });
    return hooks;
}

} // namespace companion
