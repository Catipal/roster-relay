// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <core_io.h>
#include <index/nameindex.h>
#include <key_io.h>
#include <names/name.h>
#include <names/petnames.h>
#include <names/registrar.h>
#include <names/resolve.h>
#include <names/sale.h>
#include <names/state.h>
#include <roster/keystore.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/standard.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>

#include <limits>
#include <string>
#include <vector>

namespace {

std::shared_ptr<const names::NameState> EnsureNames(int& height)
{
    if (!g_nameindex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Names need the name index (-nameindex).");
    }
    std::shared_ptr<const names::NameState> state;
    if (!g_nameindex->GetState(state, height)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "The name index could not be read.");
    }
    return state;
}

std::string Normal(const UniValue& v)
{
    std::string normal;
    if (!names::Normalize(v.get_str(), normal)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Names are plain letters a-z, digits and hyphens.");
    }
    return normal;
}

roster::KeyBytes OwnKey()
{
    CKey key;
    std::string error;
    if (!roster::GetOperationalKey(key, error)) throw JSONRPCError(RPC_MISC_ERROR, error);
    const CPubKey pub = key.GetPubKey();
    roster::KeyBytes out;
    std::copy(pub.begin() + 1, pub.begin() + 33, out.begin());
    return out;
}

/** Where a sale stands, as far as the chain and the mempool can tell. */
struct SaleView {
    std::string state; //!< open, pending (a purchase or cancellation is waiting to confirm) or unusable
    CAmount price{0};  //!< what a buyer pays the holder
};

SaleView ViewSale(const names::Offer& offer, const JSONRPCRequest& request)
{
    SaleView view;
    const CTxMemPool& mempool = EnsureMemPool(request.context);
    LOCK2(cs_main, mempool.cs);
    CCoinsViewMemPool coins(&::ChainstateActive().CoinsTip(), mempool);
    Coin coin;
    if (!coins.GetCoin(offer.coin, coin) || coin.IsSpent()) {
        view.state = "unusable";
        view.price = offer.payout_value - names::SALE_COIN_VALUE;
        return view;
    }
    view.price = offer.payout_value - coin.out.nValue;
    if (mempool.isSpent(offer.coin)) {
        view.state = "pending";
    } else {
        view.state = names::CheckSale(offer.coin, coin.out, offer.payout_value, offer.payout, offer.coin_sig)
            ? "open" : "unusable";
    }
    return view;
}

UniValue SaleToJSON(const names::Offer& offer, const JSONRPCRequest& request)
{
    const SaleView view = ViewSale(offer, request);
    UniValue o(UniValue::VOBJ);
    o.pushKV("price", ValueFromAmount(view.price));
    o.pushKV("state", view.state);
    CTxDestination dest;
    if (ExtractDestination(offer.payout, dest)) o.pushKV("pay_to", EncodeDestination(dest));
    o.pushKV("coin", offer.coin.ToString());
    o.pushKV("listed_height", offer.height);
    return o;
}

UniValue EntryToJSON(const std::string& name, const names::NameEntry& e, const names::NameState& state, int height,
                     const JSONRPCRequest& request)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("name", name);
    o.pushKV("status", names::StatusString(state.StatusOf(name, height)));
    o.pushKV("owner", HexStr(e.owner));
    o.pushKV("expiry_height", (int64_t)e.expiry);
    o.pushKV("blocks_left", (int64_t)e.expiry - height);
    o.pushKV("registered_height", e.registered);
    UniValue subs(UniValue::VARR);
    for (const auto& s : e.subnames) {
        if ((int64_t)s.second.expiry <= height) continue;
        UniValue sub(UniValue::VOBJ);
        sub.pushKV("name", s.first + "." + name);
        sub.pushKV("key", HexStr(s.second.key));
        sub.pushKV("expiry_height", (int64_t)std::min(s.second.expiry, e.expiry));
        subs.push_back(sub);
    }
    o.pushKV("subnames", subs);
    if (const names::Offer* offer = state.ActiveOffer(name, height)) o.pushKV("for_sale", SaleToJSON(*offer, request));
    return o;
}

} // namespace

static RPCHelpMan getnameinfo()
{
    return RPCHelpMan{"getnameinfo",
        "\nState of names on this node: the index and the rules.\n"
        "\nA name resolves to a roster key, never to an address. Registering and renewing a name cost\n"
        "only the network fee; a name its holder sells costs what they ask. Subnames under a root are\n"
        "free, and petnames are this user's own labels (design note 001, section 11).\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether -nameindex is on"},
            {RPCResult::Type::NUM, "best_block_height", /* optional */ true, "Last block the index has read"},
            {RPCResult::Type::BOOL, "active", /* optional */ true, "Whether names have started on this network"},
            {RPCResult::Type::NUM, "start_height", /* optional */ true, "Height names start at, if they have one"},
            {RPCResult::Type::NUM, "live_names", /* optional */ true, "Names registered and not expired"},
            {RPCResult::Type::OBJ, "rules", "", {
                {RPCResult::Type::NUM, "min_length", "Shortest root name that can be registered"},
                {RPCResult::Type::NUM, "min_term", "Shortest registration, in blocks"},
                {RPCResult::Type::NUM, "max_term", "Furthest a name can be renewed ahead, in blocks"},
                {RPCResult::Type::NUM, "grace", "Blocks after expiry only the holder may renew in"},
                {RPCResult::Type::NUM, "commit_min_age", "Blocks between committing and claiming"},
                {RPCResult::Type::NUM, "settle_depth", "Blocks before a resolution counts as settled"},
            }},
            {RPCResult::Type::NUM, "pending_registrations", /* optional */ true, "Registrations this node is seeing through"},
            {RPCResult::Type::BOOL, "payable", /* optional */ true, "Whether this node's roster key takes payments by name (setnamepayments)"},
        }},
        RPCExamples{HelpExampleCli("getnameinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("enabled", g_nameindex != nullptr);
    const int start = names::StartHeight(Params().NetworkIDString());
    if (g_nameindex) {
        int height = 0;
        std::shared_ptr<const names::NameState> state = EnsureNames(height);
        out.pushKV("best_block_height", height);
        out.pushKV("active", height >= start);
        if (start != std::numeric_limits<int>::max()) out.pushKV("start_height", start);
        out.pushKV("live_names", (uint64_t)state->CountLive(height));
        CKey own;
        if (roster::ReadOperationalKey(own)) {
            const CPubKey pub = own.GetPubKey();
            roster::KeyBytes key;
            std::copy(pub.begin() + 1, pub.begin() + 33, key.begin());
            out.pushKV("payable", state->PaymentKey(key) != nullptr);
        }
    }
    UniValue rules(UniValue::VOBJ);
    rules.pushKV("min_length", (int)names::MIN_ROOT_LENGTH);
    rules.pushKV("min_term", (int)names::MIN_TERM);
    rules.pushKV("max_term", (int)names::MAX_TERM);
    rules.pushKV("grace", (int)names::GRACE);
    rules.pushKV("commit_min_age", (int)names::COMMIT_MIN_AGE);
    rules.pushKV("settle_depth", (int)names::SETTLE_DEPTH);
    out.pushKV("rules", rules);
    if (names::g_registrar) out.pushKV("pending_registrations", (uint64_t)names::g_registrar->All().size());
    return out;
},
    };
}

static RPCHelpMan resolvename()
{
    return RPCHelpMan{"resolvename",
        "\nWhat a name, a subname (label.name) or a petname resolves to.\n"
        "\nA petname from this node's address book wins over a registered name spelled the same,\n"
        "because it is this user's own word for someone. A key written out in full resolves to itself.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "A name, label.name, petname or key"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "name", "What was resolved, normalised"},
            {RPCResult::Type::STR, "source", "key, petname or name"},
            {RPCResult::Type::STR_HEX, "key", "The roster key it resolves to"},
            {RPCResult::Type::STR_HEX, "owner", /* optional */ true, "Who holds the root name"},
            {RPCResult::Type::NUM, "expiry_height", /* optional */ true, "When it stops resolving unless renewed"},
            {RPCResult::Type::NUM, "registered_height", /* optional */ true, "When its holder registered it"},
            {RPCResult::Type::NUM, "depth", /* optional */ true, "Blocks since it last changed hands or terms"},
            {RPCResult::Type::BOOL, "settled", /* optional */ true, "Deep enough to rely on for anything irreversible"},
            {RPCResult::Type::BOOL, "subname", /* optional */ true, "Whether it is a subname"},
            {RPCResult::Type::BOOL, "payable", /* optional */ true, "Whether its key takes payments by name (sendtoname)"},
            {RPCResult::Type::NUM, "payable_height", /* optional */ true, "When that key published the spending key it is paid on"},
        }},
        RPCExamples{HelpExampleCli("resolvename", "\"pilot\"") + HelpExampleCli("resolvename", "\"alice.pilot\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    names::Target target;
    std::string error;
    if (!names::ResolveTarget(request.params[0].get_str(), target, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("name", target.source == names::Source::KEY ? HexStr(target.key) : target.label);
    out.pushKV("source", names::SourceString(target.source));
    out.pushKV("key", HexStr(target.key));
    if (target.source == names::Source::NAME) {
        out.pushKV("owner", HexStr(target.name.owner));
        out.pushKV("expiry_height", (int64_t)target.name.expiry);
        out.pushKV("registered_height", target.name.registered);
        out.pushKV("depth", target.depth);
        out.pushKV("settled", target.depth >= (int)names::SETTLE_DEPTH);
        out.pushKV("subname", target.name.subname);
    }
    if (g_nameindex) {
        int height = 0;
        std::shared_ptr<const names::NameState> state;
        if (g_nameindex->GetState(state, height)) {
            const names::PayKey* pay = state->PaymentKey(target.key);
            out.pushKV("payable", pay != nullptr);
            if (pay) out.pushKV("payable_height", pay->height);
        }
    }
    return out;
},
    };
}

static RPCHelpMan listnames()
{
    return RPCHelpMan{"listnames",
        "\nNames a key holds, with their subnames, or every live name.\n",
        {
            {"owner", RPCArg::Type::STR, /* default */ "this node's roster key", "A roster key, \"all\" for every live name, or \"forsale\" for every name up for sale"},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "name", ""},
                {RPCResult::Type::STR, "status", "live, grace (expired, renewable by its holder) or free"},
                {RPCResult::Type::STR_HEX, "owner", ""},
                {RPCResult::Type::NUM, "expiry_height", ""},
                {RPCResult::Type::NUM, "blocks_left", ""},
                {RPCResult::Type::NUM, "registered_height", ""},
                {RPCResult::Type::ARR, "subnames", "", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "name", ""},
                        {RPCResult::Type::STR_HEX, "key", ""},
                        {RPCResult::Type::NUM, "expiry_height", ""},
                    }},
                }},
                {RPCResult::Type::OBJ, "for_sale", /* optional */ true, "Present while the name is up for sale", {
                    {RPCResult::Type::STR_AMOUNT, "price", "What a buyer pays the holder"},
                    {RPCResult::Type::STR, "state", "open, pending (a purchase or cancellation is waiting to confirm) or unusable"},
                    {RPCResult::Type::STR, "pay_to", /* optional */ true, "Where the price is paid"},
                    {RPCResult::Type::STR, "coin", "The sale coin"},
                    {RPCResult::Type::NUM, "listed_height", ""},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("listnames", "") + HelpExampleCli("listnames", "all") +
                    HelpExampleCli("listnames", "forsale")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int height = 0;
    std::shared_ptr<const names::NameState> state = EnsureNames(height);
    UniValue out(UniValue::VARR);
    const std::string who = request.params[0].isNull() ? std::string() : request.params[0].get_str();
    roster::KeyBytes owner{};
    const bool for_sale = who == "forsale";
    const bool every = who == "all" || for_sale;
    if (!every) {
        if (who.empty()) {
            owner = OwnKey();
        } else {
            const std::vector<unsigned char> raw = ParseHexV(request.params[0], "owner");
            if (raw.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "owner must be a roster key");
            std::copy(raw.begin(), raw.end(), owner.begin());
        }
    }
    for (const auto& entry : every ? state->Everything() : state->OwnedBy(owner)) {
        const names::Status status = state->StatusOf(entry.first, height);
        if (for_sale && !state->ActiveOffer(entry.first, height)) continue;
        if (every && !for_sale && status != names::Status::LIVE) continue;
        if (status == names::Status::FREE) continue;
        out.push_back(EntryToJSON(entry.first, entry.second, *state, height, request));
    }
    return out;
},
    };
}

static RPCHelpMan getnameprice()
{
    return RPCHelpMan{"getnameprice",
        "\nWhat a name costs this node now, and whether it can have it.\n"
        "\nA free name costs nothing but the network fee. A name up for sale costs the price its holder\n"
        "asks, paid to the holder in the same transaction that moves the name; the fee is on top.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name"},
            {"years", RPCArg::Type::NUM, /* default */ "1", "Years it would run for, 1 or 2"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "name", "Normalised"},
            {RPCResult::Type::NUM, "length", ""},
            {RPCResult::Type::STR, "status", "free, for sale, held, yours or unavailable"},
            {RPCResult::Type::STR_AMOUNT, "asking", /* optional */ true, "For a name for sale, what its holder asks"},
            {RPCResult::Type::STR_AMOUNT, "price", "What it costs beyond the network fee: the asking price, or 0"},
            {RPCResult::Type::BOOL, "available", "Whether this node could have it now"},
            {RPCResult::Type::STR, "action", /* optional */ true, "register or buy, when available"},
            {RPCResult::Type::STR, "reason", /* optional */ true, "Why not, if not"},
        }},
        RPCExamples{HelpExampleCli("getnameprice", "\"pilot\" 2")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string name = Normal(request.params[0]);
    const int years = request.params[1].isNull() ? 1 : request.params[1].get_int();
    if (years < 1 || years > 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "years must be 1 or 2");
    UniValue out(UniValue::VOBJ);
    out.pushKV("name", name);
    out.pushKV("length", (int)name.size());
    CAmount asking = -1;
    std::string status = "free";
    std::string action = "register";
    std::string why;
    if (g_nameindex) {
        int height = 0;
        std::shared_ptr<const names::NameState> state = EnsureNames(height);
        const int next = height + 1;
        const roster::KeyBytes self = OwnKey();
        const names::NameEntry* entry = state->Find(name);
        const names::Offer* offer = state->ActiveOffer(name, next);
        if (offer && entry->owner != self) {
            // Bought, not registered.
            status = "for sale";
            action = "buy";
            const uint32_t expiry = state->BuyExpiry(name, years, next);
            const SaleView sale = ViewSale(*offer, request);
            asking = sale.price;
            why = state->CheckBuy(name, self, expiry, next);
            if (why.empty() && sale.state == "pending") why = "Someone is buying it now, or its holder is taking it off sale.";
            if (why.empty() && sale.state != "open") why = "Its sale cannot be used: the coin it sells is gone or the signature does not fit.";
        } else {
            why = state->CheckAvailable(name, self, next);
            if (!why.empty()) {
                const names::Status s = state->StatusOf(name, next);
                status = s == names::Status::FREE ? "unavailable" : entry && entry->owner == self ? "yours" : "held";
            }
        }
    } else {
        why = "Names need the name index (-nameindex).";
        status = "unavailable";
    }
    out.pushKV("status", status);
    if (asking >= 0) out.pushKV("asking", ValueFromAmount(asking));
    out.pushKV("price", ValueFromAmount(std::max<CAmount>(asking, 0)));
    out.pushKV("available", why.empty());
    if (why.empty()) out.pushKV("action", action);
    if (!why.empty()) out.pushKV("reason", why);
    return out;
},
    };
}

static RPCHelpMan setpetname()
{
    return RPCHelpMan{"setpetname",
        "\nGive someone a name in this node's own address book. Free, local, and it cannot clash.\n"
        "\nGiven a registered name, it pins the key that name resolves to now, so the petname keeps\n"
        "meaning that person even if the name later changes hands.\n",
        {
            {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "What you call them, up to 64 characters"},
            {"who", RPCArg::Type::STR, RPCArg::Optional::NO, "Their roster key, or a name to pin"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "label", ""},
            {RPCResult::Type::STR_HEX, "key", ""},
        }},
        RPCExamples{HelpExampleCli("setpetname", "\"Mum\" \"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!names::g_petnames) throw JSONRPCError(RPC_MISC_ERROR, "The address book is not loaded.");
    names::Target target;
    std::string error;
    if (!names::ResolveTarget(request.params[1].get_str(), target, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    if (!names::g_petnames->Set(request.params[0].get_str(), target.key, error)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("label", TrimString(request.params[0].get_str()));
    out.pushKV("key", HexStr(target.key));
    return out;
},
    };
}

static RPCHelpMan deletepetname()
{
    return RPCHelpMan{"deletepetname",
        "\nRemove a petname from this node's address book.\n",
        {
            {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The petname"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether there was one"},
        RPCExamples{HelpExampleCli("deletepetname", "\"Mum\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!names::g_petnames) throw JSONRPCError(RPC_MISC_ERROR, "The address book is not loaded.");
    return names::g_petnames->Remove(request.params[0].get_str());
},
    };
}

static RPCHelpMan listpetnames()
{
    return RPCHelpMan{"listpetnames",
        "\nThis node's address book.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "label", ""},
                {RPCResult::Type::STR_HEX, "key", ""},
            }},
        }},
        RPCExamples{HelpExampleCli("listpetnames", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VARR);
    if (!names::g_petnames) return out;
    for (const names::Petname& p : names::g_petnames->All()) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("label", p.label);
        o.pushKV("key", HexStr(p.key));
        out.push_back(o);
    }
    return out;
},
    };
}

static RPCHelpMan listnameregistrations()
{
    return RPCHelpMan{"listnameregistrations",
        "\nRegistrations this node is seeing through, and how recent ones ended.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "name", ""},
                {RPCResult::Type::STR, "status", "committed, claimed, done or lost"},
                {RPCResult::Type::STR, "note", ""},
                {RPCResult::Type::ELISION, "", ""},
            }},
        }},
        RPCExamples{HelpExampleCli("listnameregistrations", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VARR);
    if (!names::g_registrar) return out;
    for (const names::PendingRegistration& p : names::g_registrar->All()) out.push_back(names::PendingToJSON(p));
    return out;
},
    };
}

void RegisterNameRPCCommands(CRPCTable& t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category    name              actor (function)   argNames
  //  ----------  ----------------  -----------------  ----------
    { "names",    "getnameinfo",    &getnameinfo,      {} },
    { "names",    "resolvename",    &resolvename,      {"name"} },
    { "names",    "listnames",      &listnames,        {"owner"} },
    { "names",    "getnameprice",   &getnameprice,     {"name","years"} },
    { "names",    "setpetname",     &setpetname,       {"label","who"} },
    { "names",    "deletepetname",  &deletepetname,    {"label"} },
    { "names",    "listpetnames",   &listpetnames,     {} },
    { "names",    "listnameregistrations", &listnameregistrations, {} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
