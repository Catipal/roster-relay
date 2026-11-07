// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <companion/node.h>
#include <companion/service.h>
#include <companion/wallethook.h>
#include <core_io.h>
#include <overlay/relay.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace companion;

namespace {

Service& EnsureCompanion()
{
    if (!g_companion) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           overlay::g_overlay ? "The phone companion is off (-companion=0)."
                                              : "The phone companion works over the overlay, which is off (-overlay).");
    }
    return *g_companion;
}

uint256 ParseToken(const UniValue& v)
{
    const std::string hex = v.get_str();
    if (hex.size() != 64 || !IsHex(hex)) throw JSONRPCError(RPC_INVALID_PARAMETER, "A pairing token is 64 hex digits.");
    return uint256S(hex);
}

std::string StateName(PairState s)
{
    switch (s) {
    case PairState::WAITING: return "waiting";
    case PairState::ACCEPTED: return "accepted";
    case PairState::REJECTED: return "rejected";
    case PairState::EXPIRED: return "expired";
    case PairState::UNKNOWN: break;
    }
    return "unknown";
}

Limits ParseLimits(const UniValue& per_tx, const UniValue& per_day)
{
    Limits limits(AmountFromValue(per_tx), AmountFromValue(per_day));
    std::string error;
    if (!ValidLimits(limits, error)) throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    return limits;
}

UniValue DeviceToJSON(const Device& d, int64_t now)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("key", HexStr(d.key));
    o.pushKV("name", d.name);
    o.pushKV("created", d.created);
    o.pushKV("last_seen", d.last_seen);
    o.pushKV("per_tx", ValueFromAmount(d.limits.per_tx));
    o.pushKV("per_day", ValueFromAmount(d.limits.per_day));
    o.pushKV("spent_today", ValueFromAmount(SpentInWindow(d.spends, now)));
    o.pushKV("locked", d.Locked());
    return o;
}

RPCHelpMan getcompanioninfo()
{
    return RPCHelpMan{"getcompanioninfo",
        "\nThe phone companion on this node: the allowance wallet it pays from, whether a phone can reach it, and the\n"
        "phones paired with it.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether -companion is on"},
            {RPCResult::Type::STR, "wallet", /* optional */ true, "The allowance wallet (-companionwallet)"},
            {RPCResult::Type::BOOL, "wallet_ok", /* optional */ true, "Whether that wallet can pay for the phone"},
            {RPCResult::Type::STR, "wallet_error", /* optional */ true, "Why not"},
            {RPCResult::Type::STR_AMOUNT, "balance", /* optional */ true, "Confirmed, in the allowance wallet"},
            {RPCResult::Type::STR_AMOUNT, "pending", /* optional */ true, "Not yet confirmed"},
            {RPCResult::Type::BOOL, "listed", /* optional */ true, "Whether this node is a listed relay, which a phone needs to reach it"},
            {RPCResult::Type::STR, "address", /* optional */ true, "Where the roster lists this node's overlay"},
            {RPCResult::Type::STR, "addresses", /* optional */ true, "Every address a pairing ticket gives a phone, comma separated, best first"},
            {RPCResult::Type::NUM, "path_relays", /* optional */ true, "Listed relays a phone could build its paths through; with fewer than 3 it connects directly"},
            {RPCResult::Type::STR_HEX, "node_key", /* optional */ true, "The key a phone builds its paths to"},
            {RPCResult::Type::NUM, "devices", /* optional */ true, "Paired phones"},
            {RPCResult::Type::NUM, "locked", /* optional */ true, "Paired phones locked after too many wrong PINs"},
            {RPCResult::Type::NUM, "waiting", /* optional */ true, "Phones that answered a ticket and wait to be accepted"},
        }},
        RPCExamples{HelpExampleCli("getcompanioninfo", "") + HelpExampleRpc("getcompanioninfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    if (!g_companion) {
        out.pushKV("enabled", false);
        return out;
    }
    Service& s = *g_companion;
    out.pushKV("enabled", true);
    out.pushKV("wallet", s.WalletName());
    const WalletHooks hooks = GetWalletHooks();
    CAmount balance = 0, pending = 0;
    std::string error = "This node was built without a wallet.";
    const bool ok = hooks.status && hooks.status(s.WalletName(), balance, pending, error);
    out.pushKV("wallet_ok", ok);
    if (ok) {
        out.pushKV("balance", ValueFromAmount(balance));
        out.pushKV("pending", ValueFromAmount(pending));
    } else {
        out.pushKV("wallet_error", error);
    }
    std::string address;
    const bool listed = ListedOverlayAddress(address);
    out.pushKV("listed", listed);
    if (listed) out.pushKV("address", address);
    std::string addresses;
    bool first_listed = false;
    if (HomeAddresses(addresses, first_listed)) out.pushKV("addresses", addresses);
    out.pushKV("path_relays", (uint64_t)PhoneRelays(MAX_RELAYS).size());
    out.pushKV("node_key", HexStr(s.NodeKey()));
    const std::vector<Device> devices = s.Devices();
    out.pushKV("devices", (uint64_t)devices.size());
    out.pushKV("locked", (uint64_t)std::count_if(devices.begin(), devices.end(), [](const Device& d) { return d.Locked(); }));
    size_t waiting = 0;
    for (const Pairing& p : s.Pairings(GetTime())) {
        if (p.answered && p.state == PairState::WAITING) ++waiting;
    }
    out.pushKV("waiting", (uint64_t)waiting);
    return out;
},
    };
}

RPCHelpMan companionpair()
{
    return RPCHelpMan{"companionpair",
        "\nShow a phone the way to this node: a pairing ticket, good for " + strprintf("%d", TICKET_TTL / 60) + " minutes and for one phone.\n"
        "\nThe phone answers it with a name and a PIN; it is paired once you accept it here (companionaccept), after\n"
        "checking the six digits it shows match the ones companionpending shows.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "ticket", "To show as a QR code or paste into the phone"},
            {RPCResult::Type::STR_HEX, "token", "Names this pairing in companionaccept"},
            {RPCResult::Type::NUM_TIME, "expires", ""},
        }},
        RPCExamples{HelpExampleCli("companionpair", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    std::string addresses;
    bool listed = false;
    if (!HomeAddresses(addresses, listed)) {
        throw JSONRPCError(RPC_MISC_ERROR, "This node knows no address a phone could reach it at. List it as a relay "
                                           "(the Relay card), or give one with -companionaddress.");
    }
    // With fewer than three, the phone connects straight to this node: it
    // still proves its key, but no relays stand between them.
    const std::vector<RelayEntry> relays = PhoneRelays(TICKET_RELAYS);
    const PairingTicket t = s.NewTicket(Params().NetworkIDString(), addresses, relays, GetTime());
    UniValue out(UniValue::VOBJ);
    out.pushKV("ticket", EncodeTicket(t));
    out.pushKV("token", t.token.GetHex());
    out.pushKV("expires", t.expires);
    return out;
},
    };
}

RPCHelpMan companionpending()
{
    return RPCHelpMan{"companionpending",
        "\nPairings in progress: tickets shown, and the phones that answered them.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "token", ""},
                {RPCResult::Type::STR, "state", "waiting, accepted, rejected or expired"},
                {RPCResult::Type::BOOL, "answered", "Whether a phone has answered the ticket"},
                {RPCResult::Type::STR, "name", /* optional */ true, "The phone's name for itself"},
                {RPCResult::Type::STR, "code", /* optional */ true, "Must match the six digits on the phone"},
                {RPCResult::Type::NUM_TIME, "expires", ""},
            }},
        }},
        RPCExamples{HelpExampleCli("companionpending", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    UniValue out(UniValue::VARR);
    for (const Pairing& p : s.Pairings(GetTime())) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("token", p.token.GetHex());
        o.pushKV("state", StateName(p.state));
        o.pushKV("answered", p.answered);
        if (p.answered) {
            o.pushKV("name", p.name);
            o.pushKV("code", p.code);
        }
        o.pushKV("expires", p.expires);
        out.push_back(o);
    }
    return out;
},
    };
}

RPCHelpMan companionaccept()
{
    return RPCHelpMan{"companionaccept",
        "\nPair the phone that answered a ticket, with the most it may spend. Check first that the six digits it shows\n"
        "are the code companionpending shows: if not, someone else answered the ticket - reject it.\n",
        {
            {"token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "From companionpair or companionpending"},
            {"per_tx", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Most one payment may send, fee included"},
            {"per_day", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Most all payments may send in any 24 hours, fees included"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "key", "The phone's device key"},
            {RPCResult::Type::STR, "name", ""},
        }},
        RPCExamples{HelpExampleCli("companionaccept", "\"<token>\" 5 20")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    const uint256 token = ParseToken(request.params[0]);
    const Limits limits = ParseLimits(request.params[1], request.params[2]);
    std::string error;
    if (!s.Accept(token, limits, GetTime(), error)) throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    for (const Pairing& p : s.Pairings(GetTime())) {
        if (p.token != token) continue;
        UniValue out(UniValue::VOBJ);
        out.pushKV("key", HexStr(p.device));
        out.pushKV("name", p.name);
        return out;
    }
    return NullUniValue;
},
    };
}

RPCHelpMan companionreject()
{
    return RPCHelpMan{"companionreject",
        "\nRefuse the phone that answered a ticket. The ticket cannot be used again; show a new one.\n",
        {
            {"token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{HelpExampleCli("companionreject", "\"<token>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    std::string error;
    if (!s.Reject(ParseToken(request.params[0]), error)) throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    return NullUniValue;
},
    };
}

RPCHelpMan listcompaniondevices()
{
    return RPCHelpMan{"listcompaniondevices",
        "\nThe phones paired with this node.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "key", "Its device key"},
                {RPCResult::Type::STR, "name", ""},
                {RPCResult::Type::NUM_TIME, "created", ""},
                {RPCResult::Type::NUM_TIME, "last_seen", ""},
                {RPCResult::Type::STR_AMOUNT, "per_tx", ""},
                {RPCResult::Type::STR_AMOUNT, "per_day", ""},
                {RPCResult::Type::STR_AMOUNT, "spent_today", "In the last 24 hours, fees included"},
                {RPCResult::Type::BOOL, "locked", "Locked by wrong PINs until unlockcompaniondevice"},
            }},
        }},
        RPCExamples{HelpExampleCli("listcompaniondevices", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    const int64_t now = GetTime();
    UniValue out(UniValue::VARR);
    for (const Device& d : s.Devices()) out.push_back(DeviceToJSON(d, now));
    return out;
},
    };
}

CPubKey ParseDevice(const UniValue& v)
{
    return HexToPubKey(v.get_str());
}

RPCHelpMan setcompanionlimits()
{
    return RPCHelpMan{"setcompanionlimits",
        "\nChange what a paired phone may spend. Only here: a phone cannot change its own limits.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The phone's device key"},
            {"per_tx", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, ""},
            {"per_day", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, ""},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{HelpExampleCli("setcompanionlimits", "\"<key>\" 2 10")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    std::string error;
    if (!s.SetLimits(ParseDevice(request.params[0]), ParseLimits(request.params[1], request.params[2]), error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    return NullUniValue;
},
    };
}

RPCHelpMan revokecompaniondevice()
{
    return RPCHelpMan{"revokecompaniondevice",
        "\nUnpair a phone - lost, stolen or replaced. It can do nothing more until it is paired again.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The phone's device key"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{HelpExampleCli("revokecompaniondevice", "\"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    if (!s.Revoke(ParseDevice(request.params[0]))) throw JSONRPCError(RPC_INVALID_PARAMETER, "No such device.");
    return NullUniValue;
},
    };
}

RPCHelpMan unlockcompaniondevice()
{
    return RPCHelpMan{"unlockcompaniondevice",
        "\nLet a phone locked by wrong PINs try again.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The phone's device key"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{HelpExampleCli("unlockcompaniondevice", "\"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    Service& s = EnsureCompanion();
    std::string error;
    if (!s.Unlock(ParseDevice(request.params[0]), error)) throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    return NullUniValue;
},
    };
}

} // namespace

void RegisterCompanionRPCCommands(CRPCTable& t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category     name                      actor (function)          argNames
  //  -----------  ------------------------  ------------------------  ----------
    { "companion", "getcompanioninfo",       &getcompanioninfo,        {} },
    { "companion", "companionpair",          &companionpair,           {} },
    { "companion", "companionpending",       &companionpending,        {} },
    { "companion", "companionaccept",        &companionaccept,         {"token","per_tx","per_day"} },
    { "companion", "companionreject",        &companionreject,         {"token"} },
    { "companion", "listcompaniondevices",   &listcompaniondevices,    {} },
    { "companion", "setcompanionlimits",     &setcompanionlimits,      {"key","per_tx","per_day"} },
    { "companion", "revokecompaniondevice",  &revokecompaniondevice,   {"key"} },
    { "companion", "unlockcompaniondevice",  &unlockcompaniondevice,   {"key"} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
