// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The roster's fingerprint, for clients that hold only headers (design note
// 001, §6). A full node hands out the roster a block committed to, with the
// coinbase and its merkle branch; the client checks the branch against its
// header, reads the root out of the coinbase, and recomputes it from the
// members. The server can withhold, but it cannot lie.

#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/rosterindex.h>
#include <merkleblock.h>
#include <roster/commitment.h>
#include <roster/identity.h>
#include <roster/ledger.h>
#include <roster/record.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <streams.h>
#include <util/strencodings.h>
#include <validation.h>
#include <version.h>

#include <algorithm>
#include <set>

namespace {

const std::string& ChainId()
{
    static const std::string id = Params().NetworkIDString();
    return id;
}

/** The committed members at `height`, from the ledger if it can say, else the roster index. */
std::vector<roster::WindowAnnouncement> CommittedMembers(int height)
{
    std::vector<roster::WindowAnnouncement> members;
    if (roster::g_ledger && roster::g_ledger->Members(height, members)) return members;
    if (!g_rosterindex) {
        throw JSONRPCError(RPC_MISC_ERROR, "This node keeps neither the roster ledger nor a roster index (-rosterindex).");
    }
    if (g_rosterindex->GetSummary().best_block_height < height - roster::AGE_DEPTH) {
        throw JSONRPCError(RPC_MISC_ERROR, "The roster index has not reached that height yet.");
    }
    std::map<roster::KeyBytes, RosterEntry> committed;
    if (!g_rosterindex->BuildCommittedRoster(height, committed)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read the roster index");
    }
    for (const auto& item : committed) {
        roster::WindowAnnouncement a;
        a.key = item.first;
        a.height = item.second.height;
        a.raw = item.second.raw;
        members.push_back(std::move(a));
    }
    return members;
}

std::vector<roster::CommitmentEntry> Entries(const std::vector<roster::WindowAnnouncement>& members)
{
    std::vector<roster::CommitmentEntry> entries;
    for (const roster::WindowAnnouncement& a : members) {
        roster::CommitmentEntry e;
        e.key = a.key;
        e.height = (uint32_t)a.height;
        e.raw = a.raw;
        entries.push_back(std::move(e));
    }
    return entries;
}

int HeightArg(const UniValue& v)
{
    LOCK(cs_main);
    const int tip = ::ChainActive().Height();
    if (v.isNull()) return tip;
    const int height = v.get_int();
    if (height < 0 || height > tip) throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    return height;
}

/** The block's coinbase, its merkle branch, and the root it commits to. */
void CoinbaseProof(int height, UniValue& out)
{
    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = ::ChainActive()[height];
    }
    CBlock block;
    if (!pindex || !ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
        throw JSONRPCError(RPC_MISC_ERROR, "That block is not on this node's disk");
    }
    CDataStream proof(SER_NETWORK, PROTOCOL_VERSION);
    proof << CMerkleBlock(block, std::set<uint256>{block.vtx[0]->GetHash()});
    out.pushKV("height", height);
    out.pushKV("blockhash", pindex->GetBlockHash().GetHex());
    uint256 committed;
    if (roster::GetBlockCommitment(block, committed)) out.pushKV("committed_root", committed.GetHex());
    out.pushKV("coinbase", EncodeHexTx(*block.vtx[0]));
    out.pushKV("proof", HexStr(proof));
}

/**
 * Check a coinbase proof against this node's headers and read the committed
 * root out of it. Empty on success, else why not.
 */
std::string CheckCoinbaseProof(const UniValue& snapshot, int& height_out, uint256& root_out)
{
    CMerkleBlock mb;
    try {
        CDataStream ss(ParseHexV(find_value(snapshot, "proof"), "proof"), SER_NETWORK, PROTOCOL_VERSION);
        ss >> mb;
    } catch (const std::exception&) {
        return "unreadable merkle proof";
    }
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(mb.header.GetHash());
        if (!pindex || !::ChainActive().Contains(pindex)) return "the block is not on this node's chain";
        height_out = pindex->nHeight;
    }
    std::vector<uint256> matches;
    std::vector<unsigned int> positions;
    if (mb.txn.ExtractMatches(matches, positions) != mb.header.hashMerkleRoot) return "the branch does not lead to the block";
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, find_value(snapshot, "coinbase").get_str())) return "unreadable coinbase";
    const CTransactionRef coinbase = MakeTransactionRef(std::move(mtx));
    bool at_zero = false;
    for (size_t i = 0; i < matches.size(); ++i) {
        if (matches[i] == coinbase->GetHash() && positions[i] == 0) at_zero = true;
    }
    if (!at_zero || !coinbase->IsCoinBase()) return "the transaction proved is not the block's coinbase";
    CBlock shell;
    shell.vtx.push_back(coinbase);
    if (!roster::GetBlockCommitment(shell, root_out)) return "the block carries no roster commitment";
    return std::string();
}

/** A member as served, checked as a full node would have when it was committed. */
std::string CheckMember(const UniValue& m, int height, roster::CommitmentEntry& out)
{
    const std::vector<unsigned char> raw = ParseHexV(find_value(m, "hex"), "hex");
    roster::Record rec;
    if (!roster::ParseAndVerify(raw, ChainId(), rec) || rec.type != roster::RecordType::ANNOUNCE) {
        return "a member is not an announcement signed by its key";
    }
    const int at = find_value(m, "height").get_int();
    if (at > height - roster::AGE_DEPTH || at < height - roster::AGE_DEPTH - (int)roster::MAX_TTL) {
        return "a member's height is outside the window the block commits to";
    }
    if (!roster::ExpiryInRange(rec.expiry_height, at) || rec.expiry_height <= (uint32_t)height) {
        return "a member is out of range or has expired";
    }
    out.key = rec.op_key;
    out.height = (uint32_t)at;
    out.raw = raw;
    return std::string();
}

UniValue MemberToJSON(const roster::WindowAnnouncement& a)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("key", HexStr(a.key));
    o.pushKV("height", a.height);
    o.pushKV("hex", HexStr(a.raw));
    return o;
}

} // namespace

static RPCHelpMan getrostersnapshot()
{
    return RPCHelpMan{"getrostersnapshot",
        "\nThe roster a block commits to, with what proves it, for a client holding only headers.\n"
        "\nThe members are the roster " + strprintf("%d", roster::AGE_DEPTH) + " blocks before the block, as every node enforcing\n"
        "DEPLOYMENT_ROSTER computed it; the coinbase and its merkle branch carry the root. Check it\n"
        "with verifyrostersnapshot. Served from the roster ledger, or from -rosterindex.\n",
        {
            {"height", RPCArg::Type::NUM, /* default */ "the tip", "The block"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "height", ""},
            {RPCResult::Type::STR_HEX, "blockhash", ""},
            {RPCResult::Type::STR_HEX, "root", "The root of the members below"},
            {RPCResult::Type::STR_HEX, "committed_root", /* optional */ true, "The root the block carries, if it carries one"},
            {RPCResult::Type::ARR, "members", "", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "key", ""},
                    {RPCResult::Type::NUM, "height", "Where its announcement confirmed"},
                    {RPCResult::Type::STR_HEX, "hex", "The announcement"},
                }},
            }},
            {RPCResult::Type::STR_HEX, "coinbase", ""},
            {RPCResult::Type::STR_HEX, "proof", "The coinbase's merkle branch, as gettxoutproof gives it"},
        }},
        RPCExamples{HelpExampleCli("getrostersnapshot", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int height = HeightArg(request.params[0]);
    const std::vector<roster::WindowAnnouncement> members = CommittedMembers(height);
    UniValue out(UniValue::VOBJ);
    CoinbaseProof(height, out);
    out.pushKV("root", roster::MerkleRoot(Entries(members)).GetHex());
    UniValue list(UniValue::VARR);
    for (const roster::WindowAnnouncement& a : members) list.push_back(MemberToJSON(a));
    out.pushKV("members", list);
    return out;
},
    };
}

static RPCHelpMan verifyrostersnapshot()
{
    return RPCHelpMan{"verifyrostersnapshot",
        "\nCheck a roster snapshot against this node's headers only - no roster, no index, no ledger:\n"
        "what a light client does. Valid means the members are exactly the roster the block commits to.\n",
        {
            {"snapshot", RPCArg::Type::OBJ, RPCArg::Optional::NO, "What getrostersnapshot returned", {}, "snapshot"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", ""},
            {RPCResult::Type::STR, "reason", /* optional */ true, "Why not, if not"},
            {RPCResult::Type::NUM, "height", /* optional */ true, ""},
            {RPCResult::Type::NUM, "members", /* optional */ true, "How many"},
            {RPCResult::Type::STR_HEX, "root", /* optional */ true, ""},
        }},
        RPCExamples{HelpExampleCli("verifyrostersnapshot", "'{...}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& snapshot = request.params[0].get_obj();
    UniValue out(UniValue::VOBJ);
    const auto fail = [&](const std::string& why) {
        out.setObject();
        out.pushKV("valid", false);
        out.pushKV("reason", why);
        return out;
    };
    int height = 0;
    uint256 committed;
    const std::string why = CheckCoinbaseProof(snapshot, height, committed);
    if (!why.empty()) return fail(why);
    const UniValue& members = find_value(snapshot, "members");
    if (!members.isArray()) return fail("no members");
    std::vector<roster::CommitmentEntry> entries;
    std::set<roster::KeyBytes> keys;
    for (size_t i = 0; i < members.size(); ++i) {
        roster::CommitmentEntry e;
        const std::string bad = CheckMember(members[i], height, e);
        if (!bad.empty()) return fail(bad);
        if (!keys.insert(e.key).second) return fail("a key appears twice");
        entries.push_back(std::move(e));
    }
    const uint256 root = roster::MerkleRoot(entries);
    if (root != committed) return fail("the members do not make the root the block commits to");
    out.pushKV("valid", true);
    out.pushKV("height", height);
    out.pushKV("members", (int)entries.size());
    out.pushKV("root", root.GetHex());
    return out;
},
    };
}

static RPCHelpMan getrostermembership()
{
    return RPCHelpMan{"getrostermembership",
        "\nProve one key is in the roster a block commits to, with a merkle branch instead of the whole\n"
        "roster. Check it with verifyrostermembership.\n",
        {
            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The operational key"},
            {"height", RPCArg::Type::NUM, /* default */ "the tip", "The block"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::OBJ, "member", "", {{RPCResult::Type::ELISION, "", "key, height, hex"}}},
            {RPCResult::Type::NUM, "index", "Its place among the leaves"},
            {RPCResult::Type::ARR, "branch", "", {{RPCResult::Type::STR_HEX, "", ""}}},
            {RPCResult::Type::ELISION, "", "height, blockhash, coinbase and proof, as getrostersnapshot"},
        }},
        RPCExamples{HelpExampleCli("getrostermembership", "\"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::vector<unsigned char> raw_key = ParseHexV(request.params[0], "key");
    if (raw_key.size() != roster::RECORD_KEY_SIZE) throw JSONRPCError(RPC_INVALID_PARAMETER, "key must be 32 bytes");
    roster::KeyBytes key;
    std::copy(raw_key.begin(), raw_key.end(), key.begin());
    const int height = HeightArg(request.params[1]);
    std::vector<roster::WindowAnnouncement> members = CommittedMembers(height);
    std::sort(members.begin(), members.end(),
              [](const roster::WindowAnnouncement& a, const roster::WindowAnnouncement& b) { return a.key < b.key; });
    uint32_t index = 0;
    while (index < members.size() && members[index].key != key) ++index;
    if (index == members.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "That key is not in the roster this block commits to");
    const std::vector<uint256> leaves = roster::CommitmentLeaves(Entries(members));
    UniValue out(UniValue::VOBJ);
    CoinbaseProof(height, out);
    out.pushKV("member", MemberToJSON(members[index]));
    out.pushKV("index", (int)index);
    UniValue branch(UniValue::VARR);
    for (const uint256& h : roster::MerkleBranch(leaves, index)) branch.push_back(h.GetHex());
    out.pushKV("branch", branch);
    return out;
},
    };
}

static RPCHelpMan verifyrostermembership()
{
    return RPCHelpMan{"verifyrostermembership",
        "\nCheck a membership proof against this node's headers only.\n",
        {
            {"proof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "What getrostermembership returned", {}, "proof"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", ""},
            {RPCResult::Type::STR, "reason", /* optional */ true, "Why not, if not"},
            {RPCResult::Type::STR_HEX, "key", /* optional */ true, ""},
            {RPCResult::Type::NUM, "height", /* optional */ true, ""},
        }},
        RPCExamples{HelpExampleCli("verifyrostermembership", "'{...}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& proof = request.params[0].get_obj();
    UniValue out(UniValue::VOBJ);
    const auto fail = [&](const std::string& why) {
        out.setObject();
        out.pushKV("valid", false);
        out.pushKV("reason", why);
        return out;
    };
    int height = 0;
    uint256 committed;
    const std::string why = CheckCoinbaseProof(proof, height, committed);
    if (!why.empty()) return fail(why);
    roster::CommitmentEntry entry;
    const std::string bad = CheckMember(find_value(proof, "member"), height, entry);
    if (!bad.empty()) return fail(bad);
    const UniValue& branch_json = find_value(proof, "branch");
    if (!branch_json.isArray()) return fail("no branch");
    std::vector<uint256> branch;
    for (size_t i = 0; i < branch_json.size(); ++i) branch.push_back(ParseHashV(branch_json[i], "branch"));
    const uint32_t index = (uint32_t)find_value(proof, "index").get_int();
    if (roster::RootFromBranch(roster::CommitmentLeaf(entry), branch, index) != committed) {
        return fail("the branch does not lead to the root the block commits to");
    }
    out.pushKV("valid", true);
    out.pushKV("key", HexStr(entry.key));
    out.pushKV("height", height);
    return out;
},
    };
}

void RegisterRosterCommitmentRPCCommands(CRPCTable& t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category    name                      actor (function)          argNames
  //  ----------  ------------------------  ------------------------  ----------
    { "roster",   "getrostersnapshot",      &getrostersnapshot,       {"height"} },
    { "roster",   "verifyrostersnapshot",   &verifyrostersnapshot,    {"snapshot"} },
    { "roster",   "getrostermembership",    &getrostermembership,     {"key","height"} },
    { "roster",   "verifyrostermembership", &verifyrostermembership,  {"proof"} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
