// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <compat.h>
#include <index/rosterindex.h>
#include <netaddress.h>
#include <roster/keystore.h>
#include <roster/record.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cstring>
#include <map>
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
        out.pushKV("relay_capable", (rec.services & roster::SERVICE_RELAY_CAPABLE) != 0);
        out.pushKV("rendezvous_only", (rec.services & roster::SERVICE_RENDEZVOUS_ONLY) != 0);
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
    return out;
},
    };
}

static RPCHelpMan getroster()
{
    return RPCHelpMan{"getroster",
        "\nThe live peer roster at the current tip.\n"
        "\nBuilt from the rolling window only, so the cost does not grow with the chain.\n",
        {
            {"count", RPCArg::Type::NUM, /* default */ "100", "Maximum entries to return, 0 for all."},
            {"skip", RPCArg::Type::NUM, /* default */ "0", "Entries to skip, for paging."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "type", "Always \"announce\" for a live roster entry"},
                    {RPCResult::Type::STR_HEX, "key", "The peer's operational key"},
                    {RPCResult::Type::NUM, "height", "Height the record confirmed at"},
                    {RPCResult::Type::NUM, "expiry_height", "Height the record stops counting"},
                    {RPCResult::Type::NUM, "prev_height", "Height of this key's previous record, 0 if first"},
                    {RPCResult::Type::BOOL, "relay_capable", "Whether the peer offers to act as a rendezvous point"},
                    {RPCResult::Type::BOOL, "rendezvous_only", "Whether the peer publishes no address"},
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

    UniValue out(UniValue::VARR);
    int seen = 0, emitted = 0;
    for (const std::pair<const roster::KeyBytes, RosterEntry>& item : live) {
        if (seen++ < skip) continue;
        if (count != 0 && emitted >= count) break;
        roster::Record rec;
        if (!item.second.Parse(rec)) continue;
        out.push_back(EntryToJSON(item.second, rec));
        ++emitted;
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
                    {"relay_capable", RPCArg::Type::BOOL, /* default */ "false", "Advertise willingness to act as a rendezvous point."},
                    {"rendezvous_only", RPCArg::Type::BOOL, /* default */ "false", "Publish no address; be reached by derived rendezvous."},
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
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "hex", "The signed record, ready for an OP_RETURN output"},
                {RPCResult::Type::STR_HEX, "key", "The operational key that signed it"},
                {RPCResult::Type::NUM, "expiry_height", "Absolute height the record stops counting"},
                {RPCResult::Type::NUM, "size", "Record length in bytes"},
            }},
        RPCExamples{
            HelpExampleCli("createannouncement", "'{\"endpoints\":[{\"network\":\"ipv4\",\"address\":\"203.0.113.7\",\"port\":9345}]}'")
          + HelpExampleCli("createannouncement", "'{\"rendezvous_only\":true}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue options = request.params[0].isNull() ? UniValue(UniValue::VOBJ) : request.params[0].get_obj();

    CKey key;
    std::string error;
    if (!roster::GetOperationalKey(key, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);

    int tip;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Height();
    }

    roster::Record rec;
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

    if (options.exists("relay_capable") && options["relay_capable"].get_bool()) {
        rec.services |= roster::SERVICE_RELAY_CAPABLE;
    }
    if (options.exists("rendezvous_only") && options["rendezvous_only"].get_bool()) {
        rec.services |= roster::SERVICE_RENDEZVOUS_ONLY;
    }

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

    // Link the age chain without making the caller track it. §5's prev_height
    // is what makes age unforgeable, and an operator who has to remember it by
    // hand will eventually publish a zero and silently restart their history.
    if (options.exists("prev_height")) {
        rec.prev_height = (uint32_t)options["prev_height"].get_int64();
    } else if (g_rosterindex) {
        std::vector<RosterEntry> previous;
        if (g_rosterindex->ReadRecordsForKey(rec.op_key, previous) && !previous.empty()) {
            rec.prev_height = (uint32_t)previous.back().height;
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

    UniValue out(UniValue::VOBJ);
    out.pushKV("hex", HexStr(raw));
    out.pushKV("key", HexStr(rec.op_key));
    out.pushKV("expiry_height", (uint64_t)rec.expiry_height);
    out.pushKV("size", (uint64_t)raw.size());
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
    { "roster",           "getrosterinfo",        &getrosterinfo,         {} },
    { "roster",           "getroster",            &getroster,             {"count","skip"} },
    { "roster",           "getrosterhistory",     &getrosterhistory,      {"key"} },
    { "roster",           "createannouncement",   &createannouncement,    {"options"} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
