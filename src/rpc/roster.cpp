// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <compat.h>
#include <index/rosterindex.h>
#include <key_io.h>
#include <netaddress.h>
#include <netbase.h>
#include <core_io.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <random.h>
#include <roster/keystore.h>
#include <roster/listing.h>
#include <roster/payout.h>
#include <roster/peers.h>
#include <roster/record.h>
#include <roster/view.h>
#include <overlay/chainsync.h>
#include <overlay/gateway.h>
#include <overlay/gatewayclient.h>
#include <overlay/localproxy.h>
#include <overlay/meeting.h>
#include <overlay/radio.h>
#include <overlay/relay.h>
#include <overlay/rendezvous.h>
#include <overlay/select.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/standard.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

/**
 * Slack between the tip and the default expiry, in blocks.
 *
 * The validity rule is expressed against the *confirming* height, and a record
 * can only ever confirm after the tip it was built against. Defaulting to
 * exactly tip + MIN_TTL therefore produces a record that is invalid by one
 * block the moment it is mined — the failure is silent, because an invalid
 * record is simply not indexed.
 *
 * 144 blocks is ~7 hours at 180 s spacing, and 1% of MIN_TTL, so it buys ample
 * room to confirm at negligible cost. A record that sits unconfirmed longer
 * than this becomes invalid rather than dangerous: absolute expiry means it
 * fails closed.
 */
constexpr int DEFAULT_CONFIRM_MARGIN = 144;

RosterIndex& RequireIndex()
{
    if (!g_rosterindex) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND,
                           "Roster index is not enabled. Restart with -rosterindex.");
    }
    return *g_rosterindex;
}

const char* NetworkName(uint8_t network)
{
    switch (network) {
    case roster::EP_IPV4: return "ipv4";
    case roster::EP_IPV6: return "ipv6";
    case roster::EP_TORV3: return "onion";
    case roster::EP_I2P: return "i2p";
    case roster::EP_CJDNS: return "cjdns";
    }
    return "unknown";
}

const char* TypeName(roster::RecordType type)
{
    switch (type) {
    case roster::RecordType::ANNOUNCE: return "announce";
    case roster::RecordType::REVOKE: return "revoke";
    case roster::RecordType::DELEGATE: return "delegate";
    case roster::RecordType::ROTATE: return "rotate";
    case roster::RecordType::VETO: return "veto";
    }
    return "unknown";
}

UniValue EndpointToJSON(const roster::Endpoint& ep)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("network", NetworkName(ep.network));

    // IPv4 and IPv6 render as addresses because that is what an operator reads.
    // The others are emitted as the raw bytes they are: an onion v3 endpoint is
    // a 32-byte service pubkey, and turning it back into a .onion string means
    // recomputing a checksum this file has no business owning.
    if (ep.network == roster::EP_IPV4 && ep.addr.size() == roster::ADDR_SIZE_IPV4) {
        struct in_addr raw;
        std::memcpy(&raw, ep.addr.data(), sizeof(raw));
        out.pushKV("address", CNetAddr(raw).ToStringIP());
    } else if (ep.network == roster::EP_IPV6 && ep.addr.size() == roster::ADDR_SIZE_IPV6) {
        struct in6_addr raw;
        std::memcpy(&raw, ep.addr.data(), sizeof(raw));
        out.pushKV("address", CNetAddr(raw).ToStringIP());
    } else {
        out.pushKV("address_hex", HexStr(ep.addr));
    }

    out.pushKV("port", (int)ep.port);
    return out;
}

UniValue EntryToJSON(const RosterEntry& entry, const roster::Record& rec)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("type", TypeName(rec.type));
    out.pushKV("height", entry.height);
    out.pushKV("txid", entry.txid.GetHex());
    out.pushKV("vout", (uint64_t)entry.vout);

    switch (rec.type) {
    case roster::RecordType::ANNOUNCE:
        out.pushKV("key", HexStr(rec.op_key));
        out.pushKV("expiry_height", (uint64_t)rec.expiry_height);
        out.pushKV("services", (uint64_t)rec.services);
        // Being listed and being reachable are different questions: an
        // announcement may carry no endpoint at all, which is legal and says
        // "this identity exists" without offering anywhere to dial.
        out.pushKV("dialable", !rec.endpoints.empty());
        out.pushKV("gateway", roster::IsGatewayRecord(rec.services, rec.endpoints.size()));
        out.pushKV("prev_height", (uint64_t)rec.prev_height);
        {
            UniValue eps(UniValue::VARR);
            for (const roster::Endpoint& ep : rec.endpoints) eps.push_back(EndpointToJSON(ep));
            out.pushKV("endpoints", eps);
        }
        if (rec.meta_hash) out.pushKV("meta_hash", rec.meta_hash->GetHex());
        break;
    case roster::RecordType::REVOKE:
        out.pushKV("key", HexStr(rec.op_key));
        break;
    case roster::RecordType::DELEGATE:
        out.pushKV("identity_key", HexStr(rec.id_key));
        out.pushKV("operational_key", HexStr(rec.op_key));
        out.pushKV("expiry_height", (uint64_t)rec.expiry_height);
        if (rec.recovery_commit) out.pushKV("recovery_commit", rec.recovery_commit->GetHex());
        break;
    case roster::RecordType::ROTATE:
        out.pushKV("from_identity", HexStr(rec.id_key));
        out.pushKV("to_identity", HexStr(rec.new_id_key));
        break;
    case roster::RecordType::VETO:
        out.pushKV("identity_key", HexStr(rec.id_key));
        out.pushKV("recovery_key", HexStr(rec.recovery_key));
        break;
    }
    return out;
}

roster::KeyBytes ParseKeyArg(const UniValue& value)
{
    if (!IsHex(value.get_str()) || value.get_str().size() != roster::RECORD_KEY_SIZE * 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes of hex");
    }
    const std::vector<unsigned char> raw = ParseHex(value.get_str());
    roster::KeyBytes key;
    std::memcpy(key.data(), raw.data(), key.size());
    return key;
}

//! Dotted quad for IPv4 because that is what anyone typing an endpoint will
//! reach for; hex for everything else, which the help text states plainly
//! rather than leaving the caller to discover.
std::vector<unsigned char> ParseEndpointAddress(uint8_t network, const std::string& text)
{
    if (network == roster::EP_IPV4 && text.find('.') != std::string::npos) {
        std::vector<unsigned char> out;
        size_t pos = 0;
        for (int i = 0; i < 4; ++i) {
            size_t dot = text.find('.', pos);
            const std::string octet = text.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
            int32_t value = 0;
            if (octet.empty() || !ParseInt32(octet, &value) || value < 0 || value > 255) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Malformed IPv4 address: " + text);
            }
            out.push_back((unsigned char)value);
            if (dot == std::string::npos) {
                if (i != 3) throw JSONRPCError(RPC_INVALID_PARAMETER, "Malformed IPv4 address: " + text);
                break;
            }
            pos = dot + 1;
        }
        return out;
    }

    if (!IsHex(text)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "address must be hex for this network (IPv4 also accepts dotted form)");
    }
    return ParseHex(text);
}

} // namespace

static RPCHelpMan getradioinfo()
{
    return RPCHelpMan{"getradioinfo",
                "\nRadio links: the overlay carried over Reticulum (-radio).\n"
                "\nThe Reticulum bridge (contrib/reticulum/bps-rns-bridge.py) runs beside the node and reports the\n"
                "BPS nodes it hears on the radio. A neighbour that is a listed relay becomes the entry relay of\n"
                "this node's paths when -radioentry is on, so mail and listing requests reach the overlay\n"
                "without the internet.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "Whether -radio is on"},
                        {RPCResult::Type::BOOL, "bridge", /* optional */ true, "Whether the bridge has reported in the last minute"},
                        {RPCResult::Type::STR, "directory", /* optional */ true, "Where the node and the bridge exchange files"},
                        {RPCResult::Type::STR_HEX, "destination", /* optional */ true, "This node's Reticulum destination"},
                        {RPCResult::Type::ARR, "interfaces", /* optional */ true, "Reticulum's interfaces", {{RPCResult::Type::STR, "", ""}}},
                        {RPCResult::Type::BOOL, "entry", /* optional */ true, "Whether paths enter through radio neighbours (-radioentry)"},
                        {RPCResult::Type::ARR, "neighbours", /* optional */ true, "BPS nodes heard on the radio", {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "key", "Its roster key"},
                                {RPCResult::Type::STR_HEX, "destination", "Its Reticulum destination"},
                                {RPCResult::Type::STR, "local", "The bridge's port standing for it, which the overlay sends to"},
                                {RPCResult::Type::NUM, "hops", "Radio hops away, or -1 if unknown"},
                                {RPCResult::Type::NUM_TIME, "heard", "When it last announced or sent anything"},
                                {RPCResult::Type::BOOL, "link", "Whether a Reticulum link to it is open"},
                                {RPCResult::Type::NUM, "bitrate", "Bits a second of the radio the way to it starts on, as Reticulum reports it, or 0 if not known"},
                                {RPCResult::Type::BOOL, "relay", "Whether the roster lists it as a relay, so paths can enter through it"},
                                {RPCResult::Type::BOOL, "session", "Whether the overlay has a session with it"},
                            }},
                        }},
                    }},
                RPCExamples{HelpExampleCli("getradioinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    if (!overlay::g_radio) {
        out.pushKV("enabled", false);
        return out;
    }
    const int64_t now = GetTime();
    const overlay::RadioState state = overlay::g_radio->State();
    out.pushKV("enabled", true);
    out.pushKV("bridge", overlay::g_radio->BridgeAlive(now));
    out.pushKV("directory", overlay::g_radio->Dir().string());
    if (!state.destination.empty()) out.pushKV("destination", state.destination);
    UniValue interfaces(UniValue::VARR);
    for (const std::string& i : state.interfaces) interfaces.push_back(i);
    out.pushKV("interfaces", interfaces);
    out.pushKV("entry", overlay::g_radio_entry);
    std::vector<roster::KeyBytes> relays;
    {
        LOCK(overlay::g_selector_mutex);
        if (overlay::g_selector) {
            for (const overlay::RelayCandidate& c : overlay::g_selector->Candidates()) relays.push_back(c.key);
        }
    }
    UniValue neighbours(UniValue::VARR);
    for (const overlay::RadioPeer& p : overlay::g_radio->Neighbours(now)) {
        UniValue n(UniValue::VOBJ);
        n.pushKV("key", HexStr(p.key));
        n.pushKV("destination", p.destination);
        n.pushKV("local", p.local.ToString());
        n.pushKV("hops", p.hops);
        n.pushKV("heard", p.heard);
        n.pushKV("link", p.link_up);
        n.pushKV("bitrate", p.bitrate);
        n.pushKV("relay", std::find(relays.begin(), relays.end(), p.key) != relays.end());
        n.pushKV("session", overlay::g_overlay && overlay::g_overlay->HasSession(p.local));
        neighbours.push_back(n);
    }
    out.pushKV("neighbours", neighbours);
    return out;
},
    };
}

static RPCHelpMan getchainfeedinfo()
{
    return RPCHelpMan{"getchainfeedinfo",
                "\nBlocks carried over the overlay between radio neighbours (-overlayblocks).\n"
                "\nShows each radio neighbour and the chain height it last reported, so a node with only\n"
                "radio can be seen following a neighbour that is ahead.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "Whether the chain feed is running"},
                        {RPCResult::Type::BOOL, "pulls", /* optional */ true, "Whether this node pulls blocks it is missing"},
                        {RPCResult::Type::ARR, "neighbours", /* optional */ true, "Radio neighbours and their last reported height",
                            {{RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "key", "The neighbour's roster key"},
                                {RPCResult::Type::STR, "local", "The bridge's port standing for it"},
                                {RPCResult::Type::NUM, "height", "Its best height as it last told us, or -1"},
                                {RPCResult::Type::NUM_TIME, "heard", "When it last told us, or 0"},
                            }}}},
                    }},
                RPCExamples{HelpExampleCli("getchainfeedinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("enabled", overlay::g_chainsync != nullptr);
    if (overlay::g_chainsync) {
        out.pushKV("pulls", overlay::g_chainsync->Pulls());
        UniValue arr(UniValue::VARR);
        for (const overlay::ChainSync::PeerView& p : overlay::g_chainsync->Neighbours()) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("key", HexStr(p.key));
            o.pushKV("local", p.addr.ToString());
            o.pushKV("height", p.height);
            o.pushKV("heard", p.heard);
            arr.push_back(o);
        }
        out.pushKV("neighbours", arr);
    }
    return out;
},
    };
}

static RPCHelpMan getmeetinginfo()
{
    return RPCHelpMan{"getmeetinginfo",
                "\nWhere this node can be met without an address (-meetable).\n"
                "\nA node listed with no endpoint keeps itself registered at its meeting points: relays anyone\n"
                "computes from the roster, reached through -meethops relays of its own, so a meeting point\n"
                "learns its key and not where it is. Also counts the services this node holds as a meeting point.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "meetable", "Whether -meetable is on"},
                        {RPCResult::Type::NUM, "hops", /* optional */ true, "Relays between this node and each meeting point"},
                        {RPCResult::Type::ARR, "registrations", /* optional */ true, "Meeting points this node is registered at",
                            {{RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::STR_HEX, "point", "The meeting point's roster key"},
                                {RPCResult::Type::ARR, "epochs", "Epochs it is a point for", {{RPCResult::Type::NUM, "", ""}}},
                                {RPCResult::Type::ARR, "through", "The relays in front of this node on the way there", {{RPCResult::Type::STR_HEX, "", ""}}},
                                {RPCResult::Type::NUM_TIME, "since", "When it first answered"},
                                {RPCResult::Type::NUM_TIME, "refreshed", "When it last answered"},
                            }}}},
                        {RPCResult::Type::STR, "error", /* optional */ true, "Why a point is missing, if one is"},
                        {RPCResult::Type::NUM, "held", /* optional */ true, "Services registered at this node as a meeting point"},
                    }},
                RPCExamples{HelpExampleCli("getmeetinginfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("meetable", overlay::g_meeting != nullptr);
    if (overlay::g_meeting) {
        out.pushKV("hops", overlay::g_meeting->Hops());
        UniValue regs(UniValue::VARR);
        for (const overlay::Registration& r : overlay::g_meeting->Registrations()) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("point", HexStr(r.point));
            UniValue epochs(UniValue::VARR);
            for (uint64_t e : r.epochs) epochs.push_back(e);
            o.pushKV("epochs", epochs);
            UniValue through(UniValue::VARR);
            for (const roster::KeyBytes& k : r.reached.through) through.push_back(HexStr(k));
            o.pushKV("through", through);
            o.pushKV("since", r.since);
            o.pushKV("refreshed", r.refreshed);
            regs.push_back(o);
        }
        out.pushKV("registrations", regs);
        const std::string error = overlay::g_meeting->LastError();
        if (!error.empty()) out.pushKV("error", error);
    }
    if (overlay::g_overlay) out.pushKV("held", (uint64_t)overlay::g_overlay->IntroductionCount());
    return out;
},
    };
}

static RPCHelpMan meet()
{
    return RPCHelpMan{"meet",
                "\nReach a node by its roster key through one of its meeting points, ask whether it is there,\n"
                "and leave. Nothing is looked up: the meeting points are computed from the roster.\n",
                {
                    {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Its roster key"},
                    {"hops", RPCArg::Type::NUM, /* default */ strprintf("%d", overlay::DEFAULT_MEET_HOPS), "Relays between this node and the meeting point, 1 to 3"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "point", "The meeting point used"},
                        {RPCResult::Type::NUM, "epoch", "The epoch its points were taken from"},
                        {RPCResult::Type::NUM, "hops", "Relays on this side"},
                        {RPCResult::Type::NUM, "rtt_ms", "Round trip across the meeting, in milliseconds"},
                    }},
                RPCExamples{HelpExampleCli("meet", "\"a1b2...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::vector<unsigned char> raw = ParseHexV(request.params[0], "key");
    roster::KeyBytes key{};
    if (raw.size() != key.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes of hex, as the roster lists it");
    std::copy(raw.begin(), raw.end(), key.begin());
    const int hops = request.params[1].isNull() ? overlay::DEFAULT_MEET_HOPS : request.params[1].get_int();
    if (hops < 1 || hops > overlay::MAX_MEET_HOPS) throw JSONRPCError(RPC_INVALID_PARAMETER, "hops must be 1 to 3");

    overlay::Meeting m;
    std::string error;
    if (!overlay::MeetService(key, hops, m, error)) throw JSONRPCError(RPC_MISC_ERROR, "Could not meet it: " + error);
    std::chrono::milliseconds rtt{0};
    const bool there = overlay::EchoAcross(m, std::chrono::milliseconds{15000}, rtt);
    overlay::CloseMeeting(m);
    if (!there) throw JSONRPCError(RPC_MISC_ERROR, "It was met but did not answer.");
    UniValue out(UniValue::VOBJ);
    out.pushKV("point", HexStr(m.point));
    out.pushKV("epoch", m.epoch);
    out.pushKV("hops", m.hops);
    out.pushKV("rtt_ms", (int64_t)rtt.count());
    return out;
},
    };
}

static RPCHelpMan getoverlayinfo()
{
    return RPCHelpMan{"getoverlayinfo",
                "\nState of the encrypted overlay, and where this node can be met.\n"
                "\nThe rendezvous points below are computed, not looked up: any node with\n"
                "the same roster arrives at the same list by the same arithmetic, so nobody\n"
                "is in a position to answer the question differently for different callers.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "Whether -overlay is running"},
                        {RPCResult::Type::STR, "listening", /* optional */ true, "Address the overlay socket is bound to"},
                        {RPCResult::Type::NUM, "sessions", /* optional */ true, "Established links to adjacent peers"},
                        {RPCResult::Type::NUM, "paths", /* optional */ true, "Paths this node is an end of or carries"},
                        {RPCResult::Type::NUM, "introductions", /* optional */ true, "Services registered here as a rendezvous point"},
                        {RPCResult::Type::NUM, "handshakes_refused", /* optional */ true, "Inbound handshakes dropped by the flood limit"},
                        {RPCResult::Type::OBJ, "carried", /* optional */ true, "Other people's traffic this node forwarded today (UTC), and its limits",
                            {
                                {RPCResult::Type::NUM, "today_bytes", "Bytes forwarded so far today"},
                                {RPCResult::Type::NUM, "daily_budget_bytes", "-relaybandwidth in bytes, 0 for no limit"},
                                {RPCResult::Type::NUM, "path_rate_bytes", "-relaypathrate in bytes a second, 0 for no limit"},
                                {RPCResult::Type::BOOL, "accepting", "Whether a new path would be accepted now"},
                                {RPCResult::Type::NUM, "refused_paths", "New paths refused today because the budget was spent"},
                                {RPCResult::Type::NUM, "dropped_rate", "Datagrams dropped today for going over a path's rate"},
                                {RPCResult::Type::NUM, "dropped_budget", "Datagrams dropped today past the budget's overrun"},
                            }},
                        {RPCResult::Type::NUM, "relay_candidates", /* optional */ true, "Relays from the roster this node would route through"},
                        {RPCResult::Type::ARR, "guards", /* optional */ true, "Entry relays, which are kept rather than rotated",
                            {{RPCResult::Type::STR_HEX, "", "Operational key"}}},
                        {RPCResult::Type::NUM, "epoch", /* optional */ true, "Rendezvous epoch at the current height"},
                        {RPCResult::Type::ARR, "rendezvous", /* optional */ true, "Where this node can be met this epoch, derived from the roster",
                            {{RPCResult::Type::STR_HEX, "", "Operational key of a rendezvous relay"}}},
                    }},
                RPCExamples{HelpExampleCli("getoverlayinfo", "") + HelpExampleRpc("getoverlayinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    if (!overlay::g_overlay) {
        out.pushKV("enabled", false);
        return out;
    }

    out.pushKV("enabled", true);
    out.pushKV("listening", overlay::g_overlay->BoundAddress().ToString());
    out.pushKV("paths", (uint64_t)overlay::g_overlay->PathCount());
    out.pushKV("introductions", (uint64_t)overlay::g_overlay->IntroductionCount());
    {
        const overlay::TrafficLimits::Stats carried = overlay::g_overlay->LimitStats();
        UniValue c(UniValue::VOBJ);
        c.pushKV("today_bytes", carried.today);
        c.pushKV("daily_budget_bytes", carried.daily_budget);
        c.pushKV("path_rate_bytes", carried.path_rate);
        c.pushKV("accepting", carried.accepting);
        c.pushKV("refused_paths", carried.refused_paths);
        c.pushKV("dropped_rate", carried.dropped_rate);
        c.pushKV("dropped_budget", carried.dropped_budget);
        out.pushKV("carried", c);
    }

    int tip;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Height();
    }
    const uint64_t epoch = overlay::RendezvousEpoch(tip);
    out.pushKV("epoch", (uint64_t)epoch);

    LOCK(overlay::g_selector_mutex);
    if (!overlay::g_selector) return out;
    out.pushKV("relay_candidates", (uint64_t)overlay::g_selector->CandidateCount());

    UniValue guards(UniValue::VARR);
    const std::vector<overlay::RelayCandidate> held = overlay::g_selector->Guards();
    for (size_t i = 0; i < held.size(); ++i) {
        guards.push_back(HexStr(held[i].key));
    }
    out.pushKV("guards", guards);

    // Derived from this node's own operational key, so this answers "where
    // would somebody looking for me be told to go" without anyone being asked.
    CKey op_key;
    std::string error;
    if (roster::GetOperationalKey(op_key, error)) {
        const CPubKey pub = op_key.GetPubKey();
        roster::KeyBytes self;
        std::copy(pub.begin() + 1, pub.begin() + 33, self.begin());

        // From the roster at the epoch's anchor, as anyone looking for this
        // node computes them.
        UniValue rv(UniValue::VARR);
        std::vector<roster::KeyBytes> points;
        std::string rv_error;
        if (overlay::MeetingPointsFor(self, epoch, points, rv_error)) {
            for (size_t i = 0; i < points.size(); ++i) rv.push_back(HexStr(points[i]));
        }
        out.pushKV("rendezvous", rv);
    }
    return out;
},
    };
}

static RPCHelpMan getgatewayinfo()
{
    return RPCHelpMan{"getgatewayinfo",
                "\nThis node as a gateway to the internet (design note section 8.7).\n"
                "\nA gateway serves only while the roster lists its key as one: the gateway bit and no\n"
                "address, met at its meeting points. Websites see this computer's address for what it carries.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "enabled", "Whether -gateway is on, with the overlay and the roster index"},
                        {RPCResult::Type::STR, "state", /* optional */ true, "open, closed for today (budget spent), or off (not listed as a gateway)"},
                        {RPCResult::Type::BOOL, "listed", /* optional */ true, "Whether the roster lists this node as a gateway"},
                        {RPCResult::Type::STR_HEX, "key", /* optional */ true, "The key it serves under, when listed"},
                        {RPCResult::Type::BOOL, "second_key", /* optional */ true, "Whether that is its gateway key, apart from its operational key (a relay's gateway)"},
                        {RPCResult::Type::STR, "own_listing", /* optional */ true, "This node's own listing: none, with an address (a relay's, whose gateway takes the gateway key), or without one"},
                        {RPCResult::Type::NUM, "registrations", /* optional */ true, "Meeting points it is registered at"},
                        {RPCResult::Type::STR, "policy", /* optional */ true, "Ports it carries, as -gatewayports takes them"},
                        {RPCResult::Type::NUM, "today_bytes", /* optional */ true, "Bytes carried today (UTC), both ways"},
                        {RPCResult::Type::NUM, "daily_budget_bytes", /* optional */ true, "-gatewaybandwidth in bytes, 0 for no limit"},
                        {RPCResult::Type::NUM, "visitor_rate_bytes", /* optional */ true, "-gatewayrate in bytes a second, 0 for no limit"},
                        {RPCResult::Type::NUM, "tcp_connections", /* optional */ true, "TCP connections open now"},
                        {RPCResult::Type::NUM, "udp_flows", /* optional */ true, "UDP flows open now"},
                        {RPCResult::Type::NUM, "visitors", /* optional */ true, "Meetings it has heard from recently"},
                        {RPCResult::Type::NUM, "opened", /* optional */ true, "Connections and flows opened since start"},
                        {RPCResult::Type::NUM, "refused_policy", /* optional */ true, "Refused: a port or address it does not carry"},
                        {RPCResult::Type::NUM, "refused_limits", /* optional */ true, "Refused: the day's budget, or too many connections"},
                        {RPCResult::Type::NUM, "refused_off", /* optional */ true, "Refused: not listed as a gateway"},
                        {RPCResult::Type::NUM, "malformed", /* optional */ true, "Messages or packets that did not parse"},
                        {RPCResult::Type::NUM, "lookups", /* optional */ true, "Names looked up for visitors"},
                        {RPCResult::Type::BOOL, "allow_local", /* optional */ true, "Present when -gatewayallowlocal lets it reach local addresses (regtest)"},
                        {RPCResult::Type::OBJ, "visitor", /* optional */ true, "This node using the network's gateways (-gatewayproxy)",
                            {
                                {RPCResult::Type::BOOL, "allowed", "Whether it may: its own gateway is listed, or it relays over radio with no line of its own"},
                                {RPCResult::Type::STR, "why", /* optional */ true, "Why not, when it may not"},
                                {RPCResult::Type::NUM, "hops", "Relays between it and a gateway's meeting point"},
                                {RPCResult::Type::STR, "proxy", /* optional */ true, "Where the local SOCKS5 proxy listens"},
                                {RPCResult::Type::NUM, "proxy_sessions", /* optional */ true, "Programs connected to the proxy now"},
                                {RPCResult::Type::NUM, "served", /* optional */ true, "Connections the proxy has opened since start"},
                                {RPCResult::Type::NUM, "connections", "Connections out through gateways now"},
                                {RPCResult::Type::NUM, "lookups", "Names looked up at gateways"},
                                {RPCResult::Type::NUM, "meetings_failed", "Gateways it tried and could not meet"},
                                {RPCResult::Type::STR, "last_error", /* optional */ true, "Why the last meeting failed"},
                                {RPCResult::Type::ARR, "gateways", "The gateways it has met",
                                    {
                                        {RPCResult::Type::OBJ, "", "",
                                            {
                                                {RPCResult::Type::STR_HEX, "key", "The gateway's key"},
                                                {RPCResult::Type::STR, "state", "open, closed for today, off, or unknown until it answers"},
                                                {RPCResult::Type::NUM, "since", "When it was met (milliseconds)"},
                                                {RPCResult::Type::NUM, "connections", "Connections through it now"},
                                            }},
                                    }},
                            }},
                    }},
                RPCExamples{HelpExampleCli("getgatewayinfo", "") + HelpExampleRpc("getgatewayinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    if (overlay::g_gateway_client) {
        const overlay::GatewayClient::Stats c = overlay::g_gateway_client->GetStats();
        UniValue v(UniValue::VOBJ);
        v.pushKV("allowed", c.allowed);
        if (!c.allowed && !c.why.empty()) v.pushKV("why", c.why);
        v.pushKV("hops", c.hops);
        if (overlay::g_local_proxy) {
            v.pushKV("proxy", strprintf("127.0.0.1:%u", overlay::g_local_proxy->Port()));
            v.pushKV("proxy_sessions", (uint64_t)overlay::g_local_proxy->Sessions());
            v.pushKV("served", overlay::g_local_proxy->Served());
        }
        v.pushKV("connections", c.flows);
        v.pushKV("lookups", c.lookups);
        v.pushKV("meetings_failed", c.meetings_failed);
        if (!c.last_error.empty()) v.pushKV("last_error", c.last_error);
        UniValue gws(UniValue::VARR);
        for (const overlay::GatewayClient::GatewayView& g : c.gateways) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("key", HexStr(g.key));
            o.pushKV("state", !g.known ? "unknown" : g.state == overlay::GatewayState::OPEN ? "open"
                              : g.state == overlay::GatewayState::CLOSED_TODAY ? "closed for today" : "off");
            o.pushKV("since", g.since);
            o.pushKV("connections", g.flows);
            gws.push_back(o);
        }
        v.pushKV("gateways", gws);
        out.pushKV("visitor", v);
    }
    if (!overlay::g_gateway) {
        out.pushKV("enabled", false);
        return out;
    }
    const overlay::Gateway::Stats s = overlay::g_gateway->GetStats();
    out.pushKV("enabled", true);
    out.pushKV("state", s.state == overlay::GatewayState::OPEN ? "open"
                        : s.state == overlay::GatewayState::CLOSED_TODAY ? "closed for today" : "off");
    out.pushKV("listed", s.listed);
    const overlay::GatewayIdentity id = overlay::GetGatewayIdentity();
    if (id.listed) {
        out.pushKV("key", HexStr(id.key));
        out.pushKV("second_key", id.second_key);
    }
    out.pushKV("own_listing", !id.own_listed ? "none" : id.own_address ? "with an address" : "without an address");
    size_t registrations = 0;
    {
        LOCK(overlay::g_gateway_meeting_mutex);
        if (overlay::g_gateway_meeting) {
            registrations = overlay::g_gateway_meeting->Registrations().size();
        } else if (id.listed && !id.second_key && overlay::g_meeting) {
            registrations = overlay::g_meeting->Registrations().size();
        }
    }
    out.pushKV("registrations", (uint64_t)registrations);
    out.pushKV("policy", s.policy);
    out.pushKV("today_bytes", s.today_bytes);
    out.pushKV("daily_budget_bytes", s.daily_budget);
    out.pushKV("visitor_rate_bytes", s.meeting_rate);
    out.pushKV("tcp_connections", s.tcp_flows);
    out.pushKV("udp_flows", s.udp_flows);
    out.pushKV("visitors", s.visitors);
    out.pushKV("opened", s.opened);
    out.pushKV("refused_policy", s.refused_policy);
    out.pushKV("refused_limits", s.refused_limits);
    out.pushKV("refused_off", s.refused_state);
    out.pushKV("malformed", s.malformed);
    out.pushKV("lookups", s.lookups);
    if (s.allow_local) out.pushKV("allow_local", true);
    return out;
},
    };
}

static RPCHelpMan getrosterinfo()
{
    return RPCHelpMan{"getrosterinfo",
        "\nStatus of the peer roster index and this node's announcing identity.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "enabled", "Whether -rosterindex is running"},
                {RPCResult::Type::BOOL, "synced", "Whether the index has caught up with the chain"},
                {RPCResult::Type::NUM, "best_block_height", "Height the index is synced to"},
                {RPCResult::Type::NUM, "live_peers", "Peers in the roster at the current tip"},
                {RPCResult::Type::STR_HEX, "operational_key", "This node's announcing key, created on first use"},
                {RPCResult::Type::NUM, "min_ttl", "Shortest life a record may claim, in blocks"},
                {RPCResult::Type::NUM, "max_ttl", "Longest life a record may claim, in blocks"},
                {RPCResult::Type::NUM, "roster_age_seconds", /* optional */ true, "How old the block the roster stands at is"},
                {RPCResult::Type::BOOL, "stale", /* optional */ true, "Older than about 30 days: still dialled, not trusted, since revocations may be missing"},
                {RPCResult::Type::STR_HEX, "identity_key", /* optional */ true, "This node's identity, if it has one here"},
                {RPCResult::Type::NUM, "revocations_seen", "Revocations kept, from blocks, the mempool and peers"},
                {RPCResult::Type::NUM, "unconfirmed_hints", "Announcements not on the chain, kept as dial hints"},
            }},
        RPCExamples{HelpExampleCli("getrosterinfo", "") + HelpExampleRpc("getrosterinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("enabled", (bool)g_rosterindex);

    if (g_rosterindex) {
        const IndexSummary summary = g_rosterindex->GetSummary();
        out.pushKV("synced", summary.synced);
        out.pushKV("best_block_height", summary.best_block_height);

        int tip;
        {
            LOCK(cs_main);
            tip = ::ChainActive().Height();
        }
        std::map<roster::KeyBytes, RosterEntry> live;
        if (g_rosterindex->BuildRoster(tip, live)) {
            out.pushKV("live_peers", (uint64_t)live.size());
        }
    }

    CKey key;
    std::string error;
    if (roster::GetOperationalKey(key, error)) {
        const CPubKey pubkey = key.GetPubKey();
        out.pushKV("operational_key", HexStr(Span<const unsigned char>(pubkey.data() + 1, 32)));
    } else {
        out.pushKV("operational_key_error", error);
    }

    out.pushKV("min_ttl", (uint64_t)roster::MIN_TTL);
    out.pushKV("max_ttl", (uint64_t)roster::MAX_TTL);
    const roster::RosterStatus status = roster::GetRosterStatus();
    if (status.enabled && status.block_time > 0) {
        out.pushKV("roster_age_seconds", status.age_seconds);
        out.pushKV("stale", status.stale);
    }
    CKey identity;
    std::string identity_error;
    if (roster::GetIdentityKey(identity, identity_error)) out.pushKV("identity_key", HexStr(roster::KeyBytesOf(identity)));
    out.pushKV("revocations_seen", (uint64_t)(roster::g_revocations ? roster::g_revocations->Size() : 0));
    out.pushKV("unconfirmed_hints", (uint64_t)roster::g_hints.All().size());
    return out;
},
    };
}

static RPCHelpMan getroster()
{
    return RPCHelpMan{"getroster",
        "\nThe live peer roster at the current tip.\n"
        "\nBuilt from the rolling window only, so the cost does not grow with the chain. A key revoked by\n"
        "a revocation this node has seen is left out at once, confirmed or not (design note 001, §9).\n",
        {
            {"count", RPCArg::Type::NUM, /* default */ "100", "Maximum entries to return, 0 for all."},
            {"skip", RPCArg::Type::NUM, /* default */ "0", "Entries to skip, for paging."},
            {"hints", RPCArg::Type::BOOL, /* default */ "false", "Also list announcements not on the chain - waiting in the mempool or taken out by a reorg - marked unconfirmed"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "type", "Always \"announce\" for a live roster entry"},
                    {RPCResult::Type::STR_HEX, "key", "The peer's operational key"},
                    {RPCResult::Type::NUM, "height", "Height the record confirmed at"},
                    {RPCResult::Type::NUM, "expiry_height", "Height the record stops counting"},
                    {RPCResult::Type::NUM, "prev_height", "Height of this key's previous record, 0 if first"},
                    {RPCResult::Type::BOOL, "dialable", "Whether the record carries any endpoint at all"},
                    {RPCResult::Type::BOOL, "gateway", "Whether the key is a gateway to the internet, met at its meeting points: the gateway bit, on a record with no endpoint"},
                    {RPCResult::Type::NUM, "age_blocks", "Blocks of continuous history, 0 until it is deep enough to count"},
                    {RPCResult::Type::NUM, "since_height", "Where that history starts"},
                    {RPCResult::Type::STR_HEX, "identity", /* optional */ true, "The identity running it"},
                    {RPCResult::Type::BOOL, "unconfirmed", /* optional */ true, "Present on hints: not on the chain"},
                    {RPCResult::Type::ARR, "endpoints", "Dialable addresses, empty when reachable only by rendezvous",
                        {
                            {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::STR, "network", "ipv4, ipv6, onion, i2p or cjdns"},
                                    {RPCResult::Type::STR, "address", "Textual address, for ipv4 and ipv6"},
                                    {RPCResult::Type::STR_HEX, "address_hex", "Raw address bytes, for every other network"},
                                    {RPCResult::Type::NUM, "port", "TCP port"},
                                }},
                        }},
                }},
            }},
        RPCExamples{HelpExampleCli("getroster", "") + HelpExampleCli("getroster", "10 20")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RosterIndex& index = RequireIndex();

    const int count = request.params[0].isNull() ? 100 : request.params[0].get_int();
    const int skip = request.params[1].isNull() ? 0 : request.params[1].get_int();
    if (count < 0 || skip < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "count and skip must not be negative");

    int tip;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Height();
    }

    std::map<roster::KeyBytes, RosterEntry> live;
    if (!index.BuildRoster(tip, live)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read the roster index");
    }

    const bool hints = !request.params[2].isNull() && request.params[2].get_bool();
    UniValue out(UniValue::VARR);
    int seen = 0, emitted = 0;
    for (const std::pair<const roster::KeyBytes, RosterEntry>& item : live) {
        if (roster::SeenRevoked(item.first)) continue;
        if (seen++ < skip) continue;
        if (count != 0 && emitted >= count) break;
        roster::Record rec;
        if (!item.second.Parse(rec)) continue;
        UniValue entry = EntryToJSON(item.second, rec);
        roster::Standing standing;
        if (roster::GetStanding(index, item.first, tip, standing)) {
            entry.pushKV("age_blocks", standing.age);
            entry.pushKV("since_height", standing.anchor);
            if (standing.has_identity) entry.pushKV("identity", HexStr(standing.identity));
        }
        out.push_back(entry);
        ++emitted;
    }
    if (hints) {
        for (const auto& hint : roster::g_hints.All()) {
            roster::Record rec;
            if (roster::ParseRecord(hint.second.raw, rec) != roster::ParseError::OK) continue;
            if (roster::SeenRevoked(hint.first)) continue;
            RosterEntry entry;
            entry.raw = hint.second.raw;
            entry.height = -1;
            UniValue o = EntryToJSON(entry, rec);
            o.pushKV("unconfirmed", true);
            o.pushKV("source", hint.second.source);
            out.push_back(o);
        }
    }
    return out;
},
    };
}

static RPCHelpMan getrosterhistory()
{
    return RPCHelpMan{"getrosterhistory",
        "\nEvery record the index holds for one key, oldest first.\n"
        "\nThis is the age chain of design note 001 §5. It reaches only as far back as the\n"
        "index retains; an index run with -rosterindexwindow will have dropped older links,\n"
        "which are still provable from the chain by merkle inclusion against block headers.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte key, hex."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "type", "announce, revoke, delegate, rotate or veto"},
                    {RPCResult::Type::NUM, "height", "Height the record confirmed at"},
                    {RPCResult::Type::STR_HEX, "txid", "Transaction carrying the record"},
                    {RPCResult::Type::NUM, "vout", "Output index within that transaction"},
                }},
            }},
        RPCExamples{HelpExampleCli("getrosterhistory", "\"<64 hex chars>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RosterIndex& index = RequireIndex();
    const roster::KeyBytes key = ParseKeyArg(request.params[0]);

    std::vector<RosterEntry> entries;
    if (!index.ReadRecordsForKey(key, entries)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read the roster index");
    }

    UniValue out(UniValue::VARR);
    for (const RosterEntry& entry : entries) {
        roster::Record rec;
        if (entry.Parse(rec)) out.push_back(EntryToJSON(entry, rec));
    }
    return out;
},
    };
}

/**
 * Build and sign an announcement with this node's operational key.
 *
 * Shared by createannouncement and requestlisting, so a record handed to a
 * relay is exactly the one this node would publish itself. Throws
 * JSONRPCError, naming the rule, rather than producing a record the index
 * would silently drop.
 */
static std::vector<unsigned char> BuildAnnouncement(const UniValue& options, roster::Record& rec,
                                                    UniValue& warnings)
{
    // Refused rather than ignored, and refused rather than honoured. The relay
    // layer is an open design question, not an abandoned one, but nothing
    // implements it -- so setting the bit would advertise a capability no peer
    // can use, and silently dropping the option would let an operator believe
    // they had enabled something.
    for (const std::string& unimplemented : {"relay_capable", "rendezvous_only"}) {
        if (options.exists(unimplemented)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                "%s is defined in the record format but not implemented: no peer relays, so the "
                "bit would advertise something undeliverable. The obstacle is sybil resistance for "
                "relay selection rather than anything about the wire format. For an address you can "
                "publish without revealing your location, and which works behind NAT today, use an "
                "onion endpoint. Omitting endpoints entirely is also legal and lists the identity "
                "without offering anywhere to dial.", unimplemented));
        }
    }

    // Signed with the operational key, or with the gateway key a relay lists
    // its gateway under, apart from its own address (design note section 8.7).
    const std::string which = options.exists("key") ? options["key"].get_str() : "operational";
    if (which != "operational" && which != "gateway") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "key is \"operational\" or \"gateway\"");
    }
    const bool gateway_key = which == "gateway";
    CKey key;
    std::string error;
    if (!(gateway_key ? roster::GetGatewayKey(key, error) : roster::GetOperationalKey(key, error))) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    }

    int tip;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Height();
    }

    rec.type = roster::RecordType::ANNOUNCE;
    const CPubKey pubkey = key.GetPubKey();
    std::memcpy(rec.op_key.data(), pubkey.data() + 1, rec.op_key.size());

    // Default to the shortest legal life rather than the longest. A shorter
    // record costs more renewals but leaves the roster faster when a peer stops
    // announcing, and §5's passive expiry is the only departure path that an
    // adversary cannot suppress. Longer is an explicit choice to trade
    // freshness for bytes.
    rec.expiry_height = options.exists("expiry_height")
        ? (uint32_t)options["expiry_height"].get_int64()
        : (uint32_t)(tip + (int)roster::MIN_TTL + DEFAULT_CONFIRM_MARGIN);

    if (options.exists("endpoints")) {
        const UniValue& eps = options["endpoints"].get_array();
        if (eps.size() > roster::MAX_ENDPOINTS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("At most %u endpoints", roster::MAX_ENDPOINTS));
        }
        for (size_t i = 0; i < eps.size(); ++i) {
            const UniValue& item = eps[i].get_obj();
            const std::string net = item["network"].get_str();

            roster::Endpoint ep;
            if (net == "ipv4") ep.network = roster::EP_IPV4;
            else if (net == "ipv6") ep.network = roster::EP_IPV6;
            else if (net == "onion") ep.network = roster::EP_TORV3;
            else if (net == "i2p") ep.network = roster::EP_I2P;
            else if (net == "cjdns") ep.network = roster::EP_CJDNS;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown network: " + net);

            ep.addr = ParseEndpointAddress(ep.network, item["address"].get_str());
            if (ep.addr.size() != roster::EndpointAddrSize(ep.network)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("%s address must be %u bytes, got %u", net,
                              (unsigned)roster::EndpointAddrSize(ep.network), (unsigned)ep.addr.size()));
            }

            const int64_t port = item["port"].get_int64();
            if (port < 0 || port > 65535) throw JSONRPCError(RPC_INVALID_PARAMETER, "port out of range");
            ep.port = (uint16_t)port;

            rec.endpoints.push_back(ep);
        }
    }

    // A gateway is listed by its key alone and met at its meeting points. With
    // an endpoint the record would publish where an exit is - the public exit
    // list design note §8·7 exists to avoid - so the two never go together.
    // The gateway key exists for nothing else: it is always listed as a
    // gateway, and always with no address.
    if (gateway_key || (options.exists("gateway") && options["gateway"].get_bool())) {
        if (!rec.endpoints.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "A gateway is listed with no endpoint: it is met at its meeting points, so nobody "
                "learns where it is. A record with an address and the gateway bit would publish "
                "where an exit is. Drop the endpoints, or the gateway option.");
        }
        rec.services |= roster::SERVICE_GATEWAY;
    }

    // Link the age chain without making the caller track it. §5's prev_height
    // is what makes age unforgeable, and an operator who has to remember it by
    // hand will eventually publish a zero and silently restart their history.
    //
    // The link goes to this key's last announcement - or, when this node's
    // identity has delegated to the key since, to that delegation: linking to
    // it is how the key accepts the identity (§7). Only this node's own
    // identity: anyone can publish a delegation naming any key.
    if (options.exists("prev_height")) {
        rec.prev_height = (uint32_t)options["prev_height"].get_int64();
    } else if (g_rosterindex) {
        std::vector<RosterEntry> previous;
        CKey identity;
        std::string identity_error;
        const bool have_identity = roster::GetIdentityKey(identity, identity_error);
        const roster::KeyBytes id = have_identity ? roster::KeyBytesOf(identity) : roster::KeyBytes{};
        if (g_rosterindex->ReadRecordsForKey(rec.op_key, previous)) {
            int announced = 0, delegated = 0;
            for (const RosterEntry& e : previous) {
                roster::Record r;
                if (!e.Parse(r)) continue;
                if (r.type == roster::RecordType::ANNOUNCE && r.op_key == rec.op_key) announced = e.height;
                if (have_identity && r.type == roster::RecordType::DELEGATE && r.op_key == rec.op_key && r.id_key == id) {
                    delegated = e.height;
                }
            }
            rec.prev_height = (uint32_t)std::max(announced, delegated);
        }
    }

    // Check before signing so the error names the rule rather than arriving as
    // a silent rejection at index time.
    // Validate against the earliest height this record could possibly confirm
    // at, not against the tip. Checking at the tip would accept records that
    // become invalid the instant they are mined, and the rejection would be
    // silent -- an invalid record is simply not indexed, with nothing to say why.
    if (!roster::ExpiryInRange(rec.expiry_height, tip + 1)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "expiry_height %u is out of range: a record confirming at height %d needs an expiry "
            "between %d and %d, and it can only confirm later than the current tip of %d. Leave "
            "expiry_height unset to get the floor plus %d blocks of room to confirm.",
            rec.expiry_height, tip + 1, tip + 1 + (int)roster::MIN_TTL,
            tip + 1 + (int)roster::MAX_TTL, tip, DEFAULT_CONFIRM_MARGIN));
    }

    const std::string chain_id = Params().NetworkIDString();
    std::vector<unsigned char> raw = roster::SerializeRecord(rec);
    const uint256 sighash = roster::RecordSigHash(raw, rec.type, chain_id);
    if (!key.SignSchnorr(sighash, Span<unsigned char>(rec.sig.data(), rec.sig.size()))) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign the record");
    }
    raw = roster::SerializeRecord(rec);

    // Never hand out a record this node would itself reject.
    roster::Record check;
    if (!roster::ParseAndVerify(raw, chain_id, check)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Produced a record that does not verify; this is a bug");
    }

    // Say so when a record names something this node could not dial itself.
    // A warning rather than a refusal: unlike the retired relay bits, these
    // networks are real and other implementations do speak them, so publishing
    // one is a legitimate choice — it just should not be a silent one.
    warnings = UniValue(UniValue::VARR);
    for (const roster::Endpoint& ep : rec.endpoints) {
        if (ep.network == roster::EP_I2P) {
            warnings.push_back("This build has no I2P transport, so it cannot dial the I2P endpoint "
                               "it just signed. Peers running a node with I2P support can.");
        } else if (ep.network == roster::EP_CJDNS) {
            warnings.push_back("CJDNS endpoints route only for hosts already on a CJDNS network; "
                               "peers not on one will not reach this address.");
        }
    }
    if (rec.endpoints.empty() && !(rec.services & roster::SERVICE_GATEWAY)) {
        warnings.push_back("No endpoints: this record lists the identity but offers nowhere to dial. "
                           "Intentional for a name holder or for accruing age; add an endpoint to be reachable.");
    }

    return raw;
}

static RPCHelpMan createannouncement()
{
    return RPCHelpMan{"createannouncement",
        "\nBuild and sign an announcement record with this node's operational key.\n"
        "\nReturns wire bytes only; nothing is broadcast and no coins are spent. Carry the\n"
        "hex in an OP_RETURN output to publish it — createrawtransaction accepts it as a\n"
        "\"data\" output. The signature covers the record alone, so anyone may pay the fee\n"
        "and the payer is not recorded (design note 001 §2).\n",
        {
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "",
                {
                    {"expiry_height", RPCArg::Type::NUM, /* default */ "tip + min_ttl + 144",
                     "Absolute height the record stops counting, measured against the block that confirms it rather than the current tip. Must be at least min_ttl and at most max_ttl ahead of that block, so leave room to confirm; the default adds 144 blocks for exactly that."},
                    {"prev_height", RPCArg::Type::NUM, /* default */ "looked up from the index",
                     "Height of this key's previous record, linking the age chain. 0 for a first announcement."},
                    {"endpoints", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "Up to three addresses.",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"network", RPCArg::Type::STR, RPCArg::Optional::NO, "ipv4, ipv6, onion, i2p or cjdns."},
                                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
                                     "Dotted form for ipv4; hex bytes for every other network, including the 32-byte onion service pubkey."},
                                    {"port", RPCArg::Type::NUM, RPCArg::Optional::NO, "TCP port."},
                                }},
                        }},
                    {"gateway", RPCArg::Type::BOOL, /* default */ "false",
                     "List this key as a gateway to the internet, met at its meeting points (design note §8·7). Only on a record with no endpoints."},
                    {"key", RPCArg::Type::STR, /* default */ "operational",
                     "Which key signs: \"operational\", or \"gateway\" - the second key a relay lists its gateway under, since its operational key carries its address. A gateway key is always listed as a gateway, with no endpoints, and is created in <datadir>/gateway.key on first use."},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "hex", "The signed record, ready for an OP_RETURN output"},
                {RPCResult::Type::STR_HEX, "key", "The operational key that signed it"},
                {RPCResult::Type::NUM, "expiry_height", "Absolute height the record stops counting"},
                {RPCResult::Type::NUM, "size", "Record length in bytes"},
                {RPCResult::Type::ARR, "warnings", /* optional */ true, "Present only when something about the record deserves saying out loud",
                    {
                        {RPCResult::Type::STR, "", "A condition that does not make the record invalid, but does affect who can reach it"},
                    }},
            }},
        RPCExamples{
            HelpExampleCli("createannouncement", "'{\"endpoints\":[{\"network\":\"ipv4\",\"address\":\"203.0.113.7\",\"port\":9345}]}'")
          + HelpExampleCli("createannouncement", "'{}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0].get_obj();

    roster::Record rec;
    UniValue warnings(UniValue::VARR);
    const std::vector<unsigned char> raw = BuildAnnouncement(options, rec, warnings);

    UniValue out(UniValue::VOBJ);
    out.pushKV("hex", HexStr(raw));
    out.pushKV("key", HexStr(rec.op_key));
    out.pushKV("expiry_height", (uint64_t)rec.expiry_height);
    out.pushKV("size", (uint64_t)raw.size());
    if (!warnings.empty()) out.pushKV("warnings", warnings);
    return out;
},
    };
}

/**
 * requestlisting for a relay's gateway key: through a path proving that key,
 * from a relay that is not one of this node's entry relays, which see its
 * address. The path's relays and the relay that pays then each know at most
 * one of the two, as at a meeting.
 */
static UniValue RequestGatewayListing(const UniValue& options, const UniValue& relay_param)
{
    CKey gateway_key;
    std::string error;
    if (!roster::GetGatewayKey(gateway_key, error)) throw JSONRPCError(RPC_MISC_ERROR, error);
    const roster::KeyBytes own = roster::KeyBytesOf(gateway_key);
    roster::KeyBytes node{};
    {
        CKey op;
        if (roster::ReadOperationalKey(op)) node = roster::KeyBytesOf(op);
    }

    std::set<roster::KeyBytes> guards;
    {
        LOCK(overlay::g_selector_mutex);
        if (overlay::g_selector) {
            // Entry relays are drawn when a path first needs one. Draw them
            // now, or the relay asked could become one with this very path.
            std::vector<overlay::RelayCandidate> unused;
            overlay::g_selector->Select(1, unused);
            for (const overlay::RelayCandidate& g : overlay::g_selector->Guards()) guards.insert(g.key);
        }
    }
    roster::KeyBytes relay_key{};
    if (!relay_param.isNull()) {
        const std::vector<unsigned char> key = ParseHexV(find_value(relay_param.get_obj(), "key"), "key");
        if (key.size() != relay_key.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes of hex, as the roster lists it");
        }
        std::copy(key.begin(), key.end(), relay_key.begin());
        if (guards.count(relay_key)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "That relay is one of this node's entry relays, which know where it is. Ask another.");
        }
    } else {
        std::vector<roster::KeyBytes> others;
        for (const roster::RelayInfo& r : roster::FreshRelays()) {
            if (r.key != own && r.key != node && !guards.count(r.key)) others.push_back(r.key);
        }
        std::sort(others.begin(), others.end());
        others.erase(std::unique(others.begin(), others.end()), others.end());
        if (others.empty()) {
            throw JSONRPCError(RPC_MISC_ERROR,
                "The roster lists no relay to ask other than this node's entry relays.");
        }
        relay_key = others[GetRand(others.size())];
    }
    if (relay_key == own || relay_key == node) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A node cannot ask itself to pay for its gateway's listing.");
    }

    roster::Record rec;
    UniValue warnings(UniValue::VARR);
    std::vector<unsigned char> raw = BuildAnnouncement(options, rec, warnings);
    const int hops = std::max(1, std::min(overlay::MAX_MEET_HOPS,
                                          (int)gArgs.GetArg("-meethops", overlay::DEFAULT_MEET_HOPS)));
    const std::chrono::seconds answer_wait{60};
    bool answered = false;
    roster::ListingOutcome outcome = roster::RequestListingOverPath(relay_key, gateway_key, raw, hops, answer_wait, answered);
    // As below: a relay that stakes rarely names the window it needs, once.
    if (!outcome.ok && answered && outcome.needed_window > 0) {
        int tip;
        {
            LOCK(cs_main);
            tip = ::ChainActive().Height();
        }
        UniValue longer = options;
        longer.pushKV("expiry_height", tip + (int)roster::MIN_TTL + (int)outcome.needed_window + 6);
        raw = BuildAnnouncement(longer, rec, warnings);
        outcome = roster::RequestListingOverPath(relay_key, gateway_key, raw, hops, answer_wait, answered);
    }
    int tip_now;
    {
        LOCK(cs_main);
        tip_now = ::ChainActive().Height();
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("status", outcome.ok ? "published" : answered ? "refused" : "unanswered");
    out.pushKV("relay", HexStr(relay_key));
    out.pushKV("key", HexStr(rec.op_key));
    out.pushKV("expiry_height", (uint64_t)rec.expiry_height);
    out.pushKV("confirm_window", (int64_t)rec.expiry_height - (int64_t)roster::MIN_TTL - tip_now);
    if (outcome.ok) {
        out.pushKV("txid", outcome.txid.GetHex());
    } else {
        out.pushKV("reason", outcome.reason);
    }
    return out;
}

static RPCHelpMan requestlisting()
{
    return RPCHelpMan{"requestlisting",
        "\nAsk a relay to pay for publishing this node's listing.\n"
        "\nFor a node with no coins. The record is built and signed here exactly as\n"
        "createannouncement builds it, then sent over the overlay to a relay, which pays\n"
        "the fee if it has chosen to (-acceptlistings on its side) and adds this node to\n"
        "the peers it shares rewards with. A relay can refuse, and one that later stops\n"
        "paying lets the listing lapse within the month; renewing from a funded wallet\n"
        "with publishrecord is always possible (design note 001 section 8).\n"
        "\nNeeds -overlay. With no relay named, this node's own entry relay is asked.\n"
        "\nWith options {\"key\":\"gateway\"}, the listing is a relay's gateway key\n"
        "(design note 001 section 8.7): the gateway bit and no address. It is asked for\n"
        "through a path of -meethops relays that proves the gateway key and nothing\n"
        "else, from a relay that is not one of this node's entry relays (a random listed\n"
        "one unless named), so the relay that pays learns the key and never this node's\n"
        "address. Paying from this node's own wallet instead would tie the gateway to\n"
        "this relay's own listing on the chain, and so to its address.\n"
        "\nThe relay puts the listing into a block it stakes itself, which is how it\n"
        "confirms while most nodes still refuse to relay records. A relay that stakes\n"
        "rarely asks for a record that can wait longer to confirm; this call signs\n"
        "again with the window it asks for, once.\n",
        {
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "As for createannouncement.", {}, "options"},
            {"relay", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED_NAMED_ARG, "The relay to ask, instead of this node's entry relay.",
                {
                    {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The relay's operational key, as the roster lists it."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Where its overlay listens, host:port. Not used for a gateway key, which reaches the relay through a path."},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "status", "published, refused or unanswered"},
                {RPCResult::Type::STR_HEX, "relay", "Key of the relay that was asked"},
                {RPCResult::Type::STR, "relay_address", /* optional */ true, "Where it was asked; absent when asked through a path"},
                {RPCResult::Type::STR_HEX, "key", "The key listed: this node's operational key, or its gateway key"},
                {RPCResult::Type::NUM, "expiry_height", "Height the listing stops counting"},
                {RPCResult::Type::NUM, "confirm_window", "Blocks the listing could wait to confirm and still count"},
                {RPCResult::Type::STR_HEX, "txid", /* optional */ true, "The relay's transaction, when published"},
                {RPCResult::Type::STR, "reason", /* optional */ true, "Why not, when refused or unanswered"},
            }},
        RPCExamples{
            HelpExampleCli("requestlisting", "")
          + HelpExampleCli("requestlisting", "'{}' '{\"key\":\"<hex>\",\"address\":\"203.0.113.7:48931\"}'")
          + HelpExampleCli("requestlisting", "'{\"key\":\"gateway\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0].get_obj();
    const std::string which = options.exists("key") ? options["key"].get_str() : "operational";
    if (which != "operational" && which != "gateway") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be \"operational\" or \"gateway\"");
    }
    if (!overlay::g_overlay) {
        throw JSONRPCError(RPC_MISC_ERROR, "The overlay is off (-overlay), so there is no way to reach a relay.");
    }
    if (which == "gateway") return RequestGatewayListing(options, request.params[1]);

    roster::KeyBytes relay_key{};
    CService relay_addr;
    bool slow = false;
    if (!request.params[1].isNull()) {
        const UniValue& relay = request.params[1].get_obj();
        const std::vector<unsigned char> key = ParseHexV(find_value(relay, "key"), "key");
        if (key.size() != relay_key.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes of hex, as the roster lists it");
        }
        std::copy(key.begin(), key.end(), relay_key.begin());
        const UniValue& address_value = find_value(relay, "address");
        if (!address_value.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Name the relay's address too: it is asked directly.");
        }
        const std::string address = address_value.get_str();
        if (!Lookup(address, relay_addr, overlay::OverlayPortFor(Params().GetDefaultPort()), false)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot read the relay address: " + address);
        }
    } else {
        std::vector<overlay::RelayCandidate> chosen;
        {
            LOCK(overlay::g_selector_mutex);
            if (!overlay::g_selector || !overlay::g_selector->Select(1, chosen)) {
                throw JSONRPCError(RPC_MISC_ERROR,
                    "No relay is listed in the roster yet, so there is nobody to ask. Name one, or "
                    "publish from a funded wallet with publishrecord.");
            }
        }
        // The entry relay, which this node keeps rather than rotating. It is the
        // relay that already sees this node's address, so asking it reveals
        // nothing new. It may be a radio neighbour.
        relay_key = chosen[0].key;
        relay_addr = overlay::FirstHopAddress(relay_key, roster::OverlayAddressFor(chosen[0].addr), slow);
    }

    CPubKey relay_pubkey;
    if (!roster::StakerPubKeyFromRoster(relay_key, relay_pubkey)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The relay key is not a point on the curve.");
    }

    roster::Record rec;
    UniValue warnings(UniValue::VARR);
    std::vector<unsigned char> raw = BuildAnnouncement(options, rec, warnings);

    bool answered = false;
    // A radio link moves a few hundred bytes a second: longer waits, and
    // longer still the slower the radio is.
    const auto greeting = overlay::RadioAirtime(relay_addr, overlay::RADIO_GREETING_BYTES);
    const auto exchange = overlay::RadioAirtime(relay_addr, 2 * overlay::SAFE_DATAGRAM);
    const std::chrono::seconds connect_wait{slow ? 90 + 4 * std::chrono::duration_cast<std::chrono::seconds>(greeting).count() : 15};
    const std::chrono::seconds answer_wait{slow ? 240 + 2 * std::chrono::duration_cast<std::chrono::seconds>(exchange).count() : 30};
    roster::ListingOutcome outcome = roster::RequestListing(
        relay_addr, relay_pubkey, raw, connect_wait, answer_wait, answered);

    // The relay stakes too rarely for the window this record left. It knows
    // its own staking rate and this node does not, so take its figure, sign
    // again, and ask once more. A few blocks of slack cover the two nodes'
    // tips differing.
    if (!outcome.ok && answered && outcome.needed_window > 0) {
        int tip;
        {
            LOCK(cs_main);
            tip = ::ChainActive().Height();
        }
        UniValue longer = options;
        longer.pushKV("expiry_height", tip + (int)roster::MIN_TTL + (int)outcome.needed_window + 6);
        raw = BuildAnnouncement(longer, rec, warnings);
        outcome = roster::RequestListing(relay_addr, relay_pubkey, raw, connect_wait, answer_wait, answered);
    }
    int tip_now;
    {
        LOCK(cs_main);
        tip_now = ::ChainActive().Height();
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("status", outcome.ok ? "published" : answered ? "refused" : "unanswered");
    out.pushKV("relay", HexStr(relay_key));
    out.pushKV("relay_address", relay_addr.ToString());
    out.pushKV("key", HexStr(rec.op_key));
    out.pushKV("expiry_height", (uint64_t)rec.expiry_height);
    out.pushKV("confirm_window", (int64_t)rec.expiry_height - (int64_t)roster::MIN_TTL - tip_now);
    if (outcome.ok) {
        out.pushKV("txid", outcome.txid.GetHex());
    } else {
        out.pushKV("reason", outcome.reason);
    }
    return out;
},
    };
}

static RPCHelpMan getrosterstaker()
{
    return RPCHelpMan{"getrosterstaker",
        "\nThe staking address behind a roster key.\n"
        "\nThis is what lets a relay pay a peer it has only ever seen on the chain. A relay\n"
        "delegates stake with the peer's key as the staker and its own as the owner, so the\n"
        "peer earns the staker fee on every block that delegation wins, and consensus stops\n"
        "the peer from spending the principal (OP_CHECKCOLDSTAKEVERIFY). Nothing has to be\n"
        "asked of the peer and no payout address is ever published: the address is a\n"
        "function of the listing.\n"
        "\nA record carries only the x coordinate of the key, so the parity byte is fixed by\n"
        "convention at even, which is the form a node keeps in roster.key.\n",
        {
            {"key", RPCArg::Type::STR_HEX, /* default */ "this node's own key",
             "The 32-byte roster key, hex, as getroster reports it."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "key", "The roster key asked about"},
                {RPCResult::Type::STR_HEX, "staker_pubkey", "The full public key it names"},
                {RPCResult::Type::STR, "staker_address", "Pass this to delegatestake as staker_address"},
            }},
        RPCExamples{
            HelpExampleCli("getrosterstaker", "")
          + HelpExampleCli("getrosterstaker", "\"e6caa9dc821087cadae32b2dc4a5a4c8201acc78cf6033297c8b66318d082b5e\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    roster::KeyBytes key{};

    if (request.params[0].isNull()) {
        CKey own;
        std::string error;
        if (!roster::GetOperationalKey(own, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);
        const CPubKey pubkey = own.GetPubKey();
        std::copy(pubkey.begin() + 1, pubkey.begin() + 33, key.begin());
    } else {
        const std::string hex = request.params[0].get_str();
        if (!IsHex(hex) || hex.size() != roster::RECORD_KEY_SIZE * 2) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes of hex");
        }
        const std::vector<unsigned char> raw = ParseHex(hex);
        std::copy(raw.begin(), raw.end(), key.begin());
    }

    CPubKey staker;
    if (!roster::StakerPubKeyFromRoster(key, staker)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Those 32 bytes are not a point on the curve, so they name no key. "
                           "A record carrying them could never have verified.");
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("key", HexStr(key));
    out.pushKV("staker_pubkey", HexStr(staker));
    out.pushKV("staker_address", EncodeDestination(PKHash(staker)));
    return out;
},
    };
}

static RPCHelpMan dumprosterkey()
{
    return RPCHelpMan{"dumprosterkey",
        "\nThe private key behind this node's roster listing, in wallet import format.\n"
        "\nOnly needed to be paid. A relay delegating stake to this node names its roster key\n"
        "as the staker, and producing those coinstakes needs the key in a wallet - so import\n"
        "this into a staking wallet with importprivkey.\n"
        "\nIt is already unencrypted in the datadir, by design: section 7 makes this the\n"
        "operational key, hot, signing routine announcements, and cheap to replace in one\n"
        "block. It is not the identity key. Even so, anything that can reach this RPC can\n"
        "take over this node's listing until it is revoked, so treat the answer as a secret\n"
        "and do not run it on a node whose RPC is exposed.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "wif", "The key, for importprivkey"},
                {RPCResult::Type::STR_HEX, "key", "The roster key it corresponds to"},
                {RPCResult::Type::STR, "staker_address", "The address a relay would delegate to"},
                {RPCResult::Type::STR, "path", "Where the key is stored"},
            }},
        RPCExamples{HelpExampleCli("dumprosterkey", "") + HelpExampleRpc("dumprosterkey", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CKey key;
    std::string error;
    if (!roster::GetOperationalKey(key, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);

    const CPubKey pubkey = key.GetPubKey();
    roster::KeyBytes op_key{};
    std::copy(pubkey.begin() + 1, pubkey.begin() + 33, op_key.begin());

    UniValue out(UniValue::VOBJ);
    out.pushKV("wif", EncodeSecret(key));
    out.pushKV("key", HexStr(op_key));
    out.pushKV("staker_address", EncodeDestination(PKHash(pubkey)));
    out.pushKV("path", roster::OperationalKeyPath());
    return out;
},
    };
}

namespace {

//! Read one 32-byte roster key from an RPC argument.
roster::KeyBytes ParseRosterKey(const UniValue& value)
{
    const std::string hex = value.get_str();
    if (!IsHex(hex) || hex.size() != roster::RECORD_KEY_SIZE * 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes of hex");
    }
    const std::vector<unsigned char> raw = ParseHex(hex);
    roster::KeyBytes key{};
    std::copy(raw.begin(), raw.end(), key.begin());
    return key;
}

} // namespace

static RPCHelpMan addrosteruser()
{
    return RPCHelpMan{"addrosteruser",
        "\nTake on a peer: list it, and share this node's block rewards with it.\n"
        "\nThe list is local and is never published. Section 8 has the peer hand its signed\n"
        "record to a relay, which pays the fee - so a relay knows its own roll because the\n"
        "peers came to it, and putting that on the chain would hand an adversary the map of\n"
        "who a relay carries.\n"
        "\nSharing only happens while -relayshare is above zero and this node is staking its\n"
        "own coins. A delegated stake never shares: consensus allows a cold stake exactly one\n"
        "output besides the delegation.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The peer's 32-byte roster key."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "added", "False if it was already listed"},
                {RPCResult::Type::NUM, "users", "How many peers are listed now"},
                {RPCResult::Type::STR, "pays_to", "Where its share would go"},
            }},
        RPCExamples{HelpExampleCli("addrosteruser", "\"e6caa9dc...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const roster::KeyBytes key = ParseRosterKey(request.params[0]);

    CPubKey pubkey;
    if (!roster::StakerPubKeyFromRoster(key, pubkey)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Those 32 bytes are not a point on the curve, so there is nowhere to "
                           "pay. A record carrying them could never have verified.");
    }

    std::vector<roster::KeyBytes> users;
    std::string error;
    if (!roster::LoadUsers(users, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);

    const bool added = std::find(users.begin(), users.end(), key) == users.end();
    if (added) {
        users.push_back(key);
        if (!roster::SaveUsers(users, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("added", added);
    out.pushKV("users", (uint64_t)users.size());
    out.pushKV("pays_to", EncodeDestination(PKHash(pubkey)));
    return out;
},
    };
}

static RPCHelpMan removerosteruser()
{
    return RPCHelpMan{"removerosteruser",
        "\nStop sharing with a peer.\n"
        "\nThis is the whole enforcement mechanism, and it needs no evidence anybody else can\n"
        "check: a relay watches its own connections, so it knows whether a listed peer\n"
        "actually carries traffic, and never has to prove it. The party who knows is the\n"
        "party who acts.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The peer's 32-byte roster key."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "removed", "False if it was not listed"},
                {RPCResult::Type::NUM, "users", "How many peers are listed now"},
            }},
        RPCExamples{HelpExampleCli("removerosteruser", "\"e6caa9dc...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const roster::KeyBytes key = ParseRosterKey(request.params[0]);

    std::vector<roster::KeyBytes> users;
    std::string error;
    if (!roster::LoadUsers(users, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);

    const size_t before = users.size();
    users.erase(std::remove(users.begin(), users.end(), key), users.end());
    const bool removed = users.size() != before;
    if (removed && !roster::SaveUsers(users, error)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("removed", removed);
    out.pushKV("users", (uint64_t)users.size());
    return out;
},
    };
}

static RPCHelpMan getrelaypayout()
{
    return RPCHelpMan{"getrelaypayout",
        "\nWho this node shares its block rewards with, and what each would receive.\n"
        "\nThe amounts are what the next block this node wins would pay, not a schedule and\n"
        "not a promise. Nothing enforces the share: a relay that pays nothing produces a\n"
        "perfectly valid block. What makes it happen is that a relay with no users protects\n"
        "nobody, itself included.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "share_percent", "Percent of each reward shared, from -relayshare"},
                {RPCResult::Type::NUM, "users", "Peers listed and still live, the ones a block would pay"},
                {RPCResult::Type::NUM, "lapsed", "Peers on the list whose listing has run out; not paid"},
                {RPCResult::Type::STR_AMOUNT, "block_reward", "The reward at the current height"},
                {RPCResult::Type::STR_AMOUNT, "total", "What the next block would share in all"},
                {RPCResult::Type::STR_AMOUNT, "each", "What one peer would receive"},
                {RPCResult::Type::STR, "note", /* optional */ true, "Why nothing would be paid, when nothing would"},
                {RPCResult::Type::ARR, "payouts", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "key", "The peer's roster key"},
                                {RPCResult::Type::STR, "address", "Where its share goes"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "What it would receive"},
                            }},
                    }},
            }},
        RPCExamples{HelpExampleCli("getrelaypayout", "") + HelpExampleRpc("getrelaypayout", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int share = (int)gArgs.GetArg("-relayshare", roster::DEFAULT_RELAY_SHARE);

    std::vector<roster::KeyBytes> users;
    std::string error;
    if (!roster::LoadUsers(users, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    // Exactly the peers the next staked block would pay: those still listed.
    const size_t listed = users.size();
    users = roster::LiveUsers(users);

    int height;
    {
        LOCK(cs_main);
        height = ::ChainActive().Height();
    }
    const CAmount reward = GetBlockSubsidy(height + 1, Params().GetConsensus());

    // The same floor CreateCoinStake applies, so this reports what would
    // actually happen rather than an idealised version of it.
    const CTxOut sample(0, CScript() << OP_DUP << OP_HASH160
                                     << std::vector<unsigned char>(20, 0)
                                     << OP_EQUALVERIFY << OP_CHECKSIG);
    const CAmount floor = GetDustThreshold(sample, ::dustRelayFee);

    std::vector<roster::Payout> payouts;
    const CAmount total = roster::PlanPayouts(reward, share, users, floor, payouts);

    UniValue out(UniValue::VOBJ);
    out.pushKV("share_percent", share);
    out.pushKV("users", (uint64_t)users.size());
    out.pushKV("lapsed", (uint64_t)(listed - users.size()));
    out.pushKV("block_reward", ValueFromAmount(reward));
    out.pushKV("total", ValueFromAmount(total));
    out.pushKV("each", ValueFromAmount(payouts.empty() ? 0 : payouts[0].amount));

    if (total == 0) {
        if (share <= 0) {
            out.pushKV("note", "-relayshare is zero, so nothing is shared");
        } else if (users.empty()) {
            out.pushKV("note", "no peers are listed; see addrosteruser");
        } else {
            out.pushKV("note", strprintf(
                "each share would be under the %d satoshi dust floor, so nobody is paid - "
                "raise -relayshare or list fewer peers", floor));
        }
    }

    UniValue list(UniValue::VARR);
    for (size_t i = 0; i < payouts.size(); ++i) {
        CPubKey pubkey;
        roster::StakerPubKeyFromRoster(payouts[i].key, pubkey);
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("key", HexStr(payouts[i].key));
        entry.pushKV("address", EncodeDestination(PKHash(pubkey)));
        entry.pushKV("amount", ValueFromAmount(payouts[i].amount));
        list.push_back(entry);
    }
    out.pushKV("payouts", list);
    return out;
},
    };
}

void RegisterRosterRPCCommands(CRPCTable& t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category            name                    actor (function)        argNames
  //  ------------------  ----------------------  ----------------------  ----------
    { "overlay",          "getoverlayinfo",       &getoverlayinfo,        {} },
    { "overlay",          "getradioinfo",         &getradioinfo,          {} },
    { "overlay",          "getmeetinginfo",       &getmeetinginfo,        {} },
    { "overlay",          "getgatewayinfo",       &getgatewayinfo,        {} },
    { "overlay",          "getchainfeedinfo",     &getchainfeedinfo,      {} },
    { "overlay",          "meet",                 &meet,                  {"key","hops"} },
    { "roster",           "getrosterinfo",        &getrosterinfo,         {} },
    { "roster",           "getroster",            &getroster,             {"count","skip","hints"} },
    { "roster",           "getrosterhistory",     &getrosterhistory,      {"key"} },
    { "roster",           "createannouncement",   &createannouncement,    {"options"} },
    { "roster",           "requestlisting",       &requestlisting,        {"options","relay"} },
    { "roster",           "getrosterstaker",      &getrosterstaker,       {"key"} },
    { "roster",           "dumprosterkey",        &dumprosterkey,         {} },
    { "roster",           "addrosteruser",        &addrosteruser,         {"key"} },
    { "roster",           "removerosteruser",     &removerosteruser,      {"key"} },
    { "roster",           "getrelaypayout",       &getrelaypayout,        {} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
