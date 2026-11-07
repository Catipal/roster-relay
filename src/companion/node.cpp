// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/node.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparams.h>
#include <compat.h>
#include <key.h>
#include <net.h>
#include <netbase.h>
#include <overlay/relay.h>
#include <random.h>
#include <roster/keystore.h>
#include <roster/listing.h>
#include <roster/peers.h>
#include <validation.h>

#include <util/system.h>

#include <algorithm>

#if !defined(WIN32) && HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS
#include <ifaddrs.h>
#include <net/if.h>
#endif

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

/** This computer's IPv4 addresses on private networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x). */
std::vector<CNetAddr> LanAddresses()
{
    std::vector<CNetAddr> out;
#ifdef WIN32
    char host[256] = "";
    if (gethostname(host, sizeof(host)) != SOCKET_ERROR) {
        std::vector<CNetAddr> all;
        if (LookupHost(host, all, 0, /* fAllowLookup */ true)) {
            for (const CNetAddr& a : all) {
                if (a.IsIPv4() && a.IsRFC1918()) out.push_back(a);
            }
        }
    }
#elif HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS
    struct ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) == 0) {
        for (struct ifaddrs* ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || (ifa->ifa_flags & IFF_UP) == 0) continue;
            if (ifa->ifa_addr->sa_family != AF_INET) continue;
            const CNetAddr a(reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr);
            if (a.IsRFC1918()) out.push_back(a);
        }
        freeifaddrs(addrs);
    }
#endif
    return out;
}

} // namespace

bool HomeAddresses(std::string& out, bool& listed)
{
    out.clear();
    listed = false;
    const uint16_t port = overlay::g_overlay ? overlay::g_overlay->BoundAddress().GetPort() : 0;
    std::vector<std::string> found;
    size_t length = 0;
    const auto add = [&](const std::string& a) {
        const size_t more = a.size() + (found.empty() ? 0 : 1);
        if (!a.empty() && found.size() < MAX_HOME_ADDRESSES && length + more <= MAX_NODE_ADDR &&
            std::find(found.begin(), found.end(), a) == found.end()) {
            found.push_back(a);
            length += more;
        }
    };

    std::string listed_addr;
    if (ListedOverlayAddress(listed_addr)) {
        listed = true;
        add(listed_addr);
    }
    // Given by hand, for a router that forwards a different outside port, or
    // an address peers do not report. Numbers only: a phone resolves no names.
    for (const std::string& given : gArgs.GetArgs("-companionaddress")) {
        CService s;
        if (Lookup(given, s, port, /* fAllowLookup */ false) && s.IsValid() && s.GetPort() != 0) add(s.ToString());
    }
    if (port != 0) {
        CService pub;
        if (GetLocal(pub) && pub.IsRoutable() && (pub.IsIPv4() || pub.IsIPv6())) {
            add(CService(pub, port).ToString());
        }
        for (const CNetAddr& lan : LanAddresses()) add(CService(lan, port).ToString());
    }
    for (size_t i = 0; i < found.size(); ++i) out += (i ? "," : "") + found[i];
    return !found.empty();
}

std::vector<RelayEntry> PhoneRelays(size_t max)
{
    // A path ends here, dialled by the relay before this node from the
    // internet, and only a listed node can be counted on to answer that. An
    // unlisted one gives its phones no relays, so they come straight here at
    // once rather than first trying paths that cannot arrive - and its
    // pairing code stays short enough to scan easily.
    std::string listed;
    if (!ListedOverlayAddress(listed)) return {};
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
        if (!overlay::g_overlay) return CPubKey();
        // Over a path, the key the far end proved end to end; directly, the
        // key the adjacent peer proved in its handshake. Either way a key the
        // sender holds, and a request is served only for a paired one.
        return hop.via_path ? overlay::g_overlay->SecretPeerIdentity(hop.path)
                            : overlay::g_overlay->PeerIdentity(hop.addr);
    };
    hooks.sender = overlay::RelaySender([] { return overlay::g_overlay.get(); });
    return hooks;
}

} // namespace companion
