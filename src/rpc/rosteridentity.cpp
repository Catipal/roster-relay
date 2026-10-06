// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Identities, revocations and age (design note 001, sections 5, 7 and 9).
//
// The create* calls sign a record and return it; nothing is spent. Publish
// one with the wallet's publishrecord, as with announcements - except a
// revocation, which sendrevocation also passes from node to node for free.

#include <chain.h>
#include <chainparams.h>
#include <core_io.h>
#include <index/rosterindex.h>
#include <key_io.h>
#include <merkleblock.h>
#include <net_processing.h>
#include <node/context.h>
#include <roster/extract.h>
#include <roster/identity.h>
#include <roster/keystore.h>
#include <roster/record.h>
#include <roster/view.h>
#include <rpc/blockchain.h>
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

RosterIndex& Index()
{
    if (!g_rosterindex) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Roster index is not enabled. Restart with -rosterindex.");
    }
    return *g_rosterindex;
}

int ChainTip()
{
    LOCK(cs_main);
    return ::ChainActive().Height();
}

roster::KeyBytes KeyArg(const UniValue& v, const char* name)
{
    const std::string hex = v.get_str();
    if (!IsHex(hex) || hex.size() != roster::RECORD_KEY_SIZE * 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a 32-byte key in hex", name));
    }
    const std::vector<unsigned char> raw = ParseHex(hex);
    roster::KeyBytes key{};
    std::copy(raw.begin(), raw.end(), key.begin());
    return key;
}

CKey SecretArg(const UniValue& v, const char* name)
{
    const CKey key = DecodeSecret(v.get_str());
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s is not a private key", name));
    return key;
}

CKey OperationalKey()
{
    CKey key;
    std::string error;
    if (!roster::GetOperationalKey(key, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    return key;
}

/** The identity key to sign with: the one given, or this node's. */
CKey IdentityKey(const UniValue& given)
{
    if (!given.isNull()) return SecretArg(given, "identity_key");
    CKey key;
    std::string error;
    if (!roster::GetIdentityKey(key, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, error.empty()
            ? "This node has no identity. Make one with createidentity, or pass the identity key."
            : error);
    }
    return key;
}

/** Sign `rec` with `key` and return its bytes, checked as any reader would. */
std::vector<unsigned char> Sign(const CKey& key, roster::Record& rec)
{
    rec.sig.fill(0);
    std::vector<unsigned char> raw = roster::SerializeRecord(rec);
    const uint256 hash = roster::RecordSigHash(raw, rec.type, ChainId());
    if (!key.SignSchnorr(hash, Span<unsigned char>(rec.sig.data(), rec.sig.size()))) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not sign the record");
    }
    raw = roster::SerializeRecord(rec);
    roster::Record check;
    if (!roster::ParseAndVerify(raw, ChainId(), check)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Produced a record that does not verify; this is a bug");
    }
    return raw;
}

/** A delegation lasting as long as a record may: it is renewed like a listing. */
std::vector<unsigned char> MakeDelegation(const CKey& id, const roster::KeyBytes& op, const Optional<uint256>& commit)
{
    roster::Record rec;
    rec.type = roster::RecordType::DELEGATE;
    rec.id_key = roster::KeyBytesOf(id);
    rec.op_key = op;
    // Confirming later only brings the upper bound closer, never past it.
    rec.expiry_height = (uint32_t)(ChainTip() + (int)roster::MAX_TTL);
    rec.recovery_commit = commit;
    return Sign(id, rec);
}

UniValue IdentityToJSON(const roster::IdentityState& s, const roster::IdentityBook& book, const RosterIndex& index,
                        int tip)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("key", HexStr(s.key));
    o.pushKV("first_height", s.first_height);
    o.pushKV("age_blocks", s.first_height >= 0 && tip - s.first_height >= roster::AGE_DEPTH ? tip - s.first_height : 0);
    o.pushKV("recovery_key_committed", (bool)s.recovery_commit);
    o.pushKV("retired", s.retired);
    if (s.retired) o.pushKV("rotated_to", HexStr(s.successor));
    o.pushKV("current_key", HexStr(book.Current(s.key)));
    UniValue before(UniValue::VARR);
    for (const roster::KeyBytes& k : s.predecessors) before.push_back(HexStr(k));
    o.pushKV("rotated_from", before);
    if (s.rotating) {
        UniValue r(UniValue::VOBJ);
        r.pushKV("to", HexStr(s.rotating_to));
        r.pushKV("height", s.rotate_height);
        r.pushKV("takes_effect_at", s.rotate_height + roster::ROTATE_VETO);
        r.pushKV("blocks_left_to_veto", std::max(0, s.rotate_height + roster::ROTATE_VETO - tip));
        o.pushKV("rotation", r);
    }
    UniValue vetoed(UniValue::VARR);
    for (int h : s.vetoed) vetoed.push_back(h);
    o.pushKV("vetoed_rotations", vetoed);
    UniValue ops(UniValue::VARR);
    for (const auto& d : s.delegations) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("key", HexStr(d.first));
        e.pushKV("height", d.second.first);
        e.pushKV("expiry_height", (int64_t)d.second.second);
        // Whether the key itself accepted: its announcements link to a
        // delegation from this identity.
        std::vector<roster::HeldRecord> history;
        bool accepted = false;
        if (index.ReadHistory(d.first, history)) {
            const roster::AgeChain chain = roster::WalkAgeChain(d.first, history, tip);
            accepted = chain.delegation && chain.delegation->rec.id_key == s.key;
        }
        e.pushKV("accepted", accepted);
        e.pushKV("counts", accepted && book.Delegates(s.key, d.first, tip));
        ops.push_back(e);
    }
    o.pushKV("operational_keys", ops);
    return o;
}

/** Where a record sits on the chain, with what proves it: the transaction and its merkle branch. */
UniValue LinkToJSON(const roster::HeldRecord& h, const char* role)
{
    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = ::ChainActive()[h.height];
    }
    if (!pindex) throw JSONRPCError(RPC_MISC_ERROR, strprintf("No block at height %d on this chain", h.height));
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Block %d is not on this node's disk (pruned?)", h.height));
    }
    CTransactionRef found;
    for (const CTransactionRef& tx : block.vtx) {
        if (tx->GetHash() == h.txid) found = tx;
    }
    if (!found) throw JSONRPCError(RPC_MISC_ERROR, "The record's transaction is not in its block; reindex the roster");
    CDataStream proof(SER_NETWORK, PROTOCOL_VERSION);
    proof << CMerkleBlock(block, std::set<uint256>{h.txid});

    UniValue o(UniValue::VOBJ);
    o.pushKV("role", role);
    o.pushKV("height", h.height);
    o.pushKV("blockhash", pindex->GetBlockHash().GetHex());
    o.pushKV("txid", h.txid.GetHex());
    o.pushKV("vout", (int)h.vout);
    o.pushKV("tx", EncodeHexTx(*found));
    o.pushKV("proof", HexStr(proof));
    return o;
}

} // namespace

static RPCHelpMan getidentity()
{
    return RPCHelpMan{"getidentity",
        "\nWho runs a roster key and since when, or the state of an identity (design note 001, §5 and §7).\n"
        "\nAn operational key runs under an identity when its own announcements link to a delegation\n"
        "from it (prev_height), so nobody can claim someone else's node. Age is continuous history,\n"
        "counted once it is " + strprintf("%d", roster::AGE_DEPTH) + " blocks deep.\n",
        {
            {"key", RPCArg::Type::STR_HEX, /* default */ "this node's operational key", "An operational or identity key"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "key", ""},
            {RPCResult::Type::NUM, "age_blocks", "Blocks of history, 0 until it is deep enough to count"},
            {RPCResult::Type::NUM, "since_height", "Where that history starts, -1 if none"},
            {RPCResult::Type::BOOL, "revoked", "Revoked on the chain or by a revocation this node has seen"},
            {RPCResult::Type::STR_HEX, "identity", /* optional */ true, "The identity running it"},
            {RPCResult::Type::OBJ, "as_identity", /* optional */ true, "When the key is itself an identity",
                {{RPCResult::Type::ELISION, "", "first_height, age, recovery, rotation, operational keys"}}},
        }},
        RPCExamples{HelpExampleCli("getidentity", "") + HelpExampleCli("getidentity", "\"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RosterIndex& index = Index();
    const roster::KeyBytes key = request.params[0].isNull() ? roster::KeyBytesOf(OperationalKey())
                                                             : KeyArg(request.params[0], "key");
    const int tip = index.GetSummary().best_block_height;
    roster::Standing standing;
    if (!roster::GetStanding(index, key, tip, standing)) throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read the roster index");
    UniValue out(UniValue::VOBJ);
    out.pushKV("key", HexStr(key));
    out.pushKV("age_blocks", standing.age);
    out.pushKV("since_height", standing.anchor);
    out.pushKV("revoked", standing.revoked);
    if (standing.has_identity) out.pushKV("identity", HexStr(standing.identity));

    std::vector<roster::HeldRecord> cluster;
    if (!index.ReadIdentityCluster(key, cluster)) throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read the roster index");
    roster::IdentityBook book;
    book.Build(cluster, tip);
    if (const roster::IdentityState* s = book.Find(key)) out.pushKV("as_identity", IdentityToJSON(*s, book, index, tip));
    return out;
},
    };
}

static RPCHelpMan createidentity()
{
    return RPCHelpMan{"createidentity",
        "\nMake an identity for this node (design note 001, §7), and sign its first delegation.\n"
        "\nTwo new keys. The identity key anchors this node's history, so the age it builds survives a\n"
        "new operational key. The recovery key is shown once and kept nowhere: write it down. With it\n"
        "you can cancel (createveto) a rotation of the identity you did not make, within\n"
        + strprintf("%d", roster::ROTATE_VETO) + " blocks. The first delegation commits to it, and only the first can.\n"
        "\nPublish the delegation with publishrecord. This node's next announcement then links to it,\n"
        "which is how its key accepts the identity.\n"
        "\nBy default the identity key is kept in roster_identity.key beside roster.key. It is meant to\n"
        "live offline: pass store=false to be given it instead, and pass it to the calls that sign with it.\n",
        {
            {"store", RPCArg::Type::BOOL, /* default */ "true", "Keep the identity key on this node"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "identity_key", ""},
            {RPCResult::Type::STR, "identity_key_wif", /* optional */ true, "Only when store=false"},
            {RPCResult::Type::STR_HEX, "recovery_key", ""},
            {RPCResult::Type::STR, "recovery_key_wif", "Write it down; it is not kept"},
            {RPCResult::Type::STR_HEX, "delegation", "The first DELEGATE, to publish"},
        }},
        RPCExamples{HelpExampleCli("createidentity", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const bool store = request.params[0].isNull() ? true : request.params[0].get_bool();
    CKey existing;
    std::string error;
    if (store && roster::GetIdentityKey(existing, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf(
            "This node has an identity already (%s). Move it to a new key with createrotation.",
            HexStr(roster::KeyBytesOf(existing))));
    }
    CKey id, recovery;
    id.MakeNewKey(true);
    recovery.MakeNewKey(true);
    const roster::KeyBytes recovery_x = roster::KeyBytesOf(recovery);
    const std::vector<unsigned char> raw = MakeDelegation(id, roster::KeyBytesOf(OperationalKey()),
                                                          roster::RecoveryCommitment(recovery_x));
    if (store && !roster::SetIdentityKey(id, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    UniValue out(UniValue::VOBJ);
    out.pushKV("identity_key", HexStr(roster::KeyBytesOf(id)));
    if (!store) out.pushKV("identity_key_wif", EncodeSecret(id));
    out.pushKV("recovery_key", HexStr(recovery_x));
    out.pushKV("recovery_key_wif", EncodeSecret(recovery));
    out.pushKV("delegation", HexStr(raw));
    return out;
},
    };
}

static RPCHelpMan createdelegation()
{
    return RPCHelpMan{"createdelegation",
        "\nSign a delegation from an identity to an operational key: \"this key is mine\".\n"
        "\nA delegation lasts as long as a record may, about a year, and is renewed the same way. It\n"
        "counts once the key's own next announcement links to it. Publish it with publishrecord.\n",
        {
            {"key", RPCArg::Type::STR_HEX, /* default */ "this node's operational key", "The operational key"},
            {"identity_key", RPCArg::Type::STR, /* default */ "this node's", "The identity's private key, if not kept here"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "delegation", "The DELEGATE, to publish"},
            {RPCResult::Type::NUM, "expiry_height", ""},
        }},
        RPCExamples{HelpExampleCli("createdelegation", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const roster::KeyBytes op = request.params[0].isNull() ? roster::KeyBytesOf(OperationalKey())
                                                            : KeyArg(request.params[0], "key");
    const CKey id = IdentityKey(request.params[1]);
    const std::vector<unsigned char> raw = MakeDelegation(id, op, nullopt);
    roster::Record rec;
    roster::ParseRecord(raw, rec);
    UniValue out(UniValue::VOBJ);
    out.pushKV("delegation", HexStr(raw));
    out.pushKV("expiry_height", (int64_t)rec.expiry_height);
    return out;
},
    };
}

static RPCHelpMan createrotation()
{
    return RPCHelpMan{"createrotation",
        "\nMove this node's identity to a new key, carrying its age (design note 001, §7).\n"
        "\nSigns a ROTATE from the identity key to a new one, and a delegation from the new one to this\n"
        "node's operational key. Publish both with publishrecord. The rotation takes effect "
        + strprintf("%d", roster::ROTATE_VETO) + "\nblocks after it confirms; until then the recovery key can cancel it. The new identity key\n"
        "replaces the old in roster_identity.key, and the old is kept beside it.\n",
        {
            {"identity_key", RPCArg::Type::STR, /* default */ "this node's", "The current identity's private key, if not kept here"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "from", ""},
            {RPCResult::Type::STR_HEX, "to", ""},
            {RPCResult::Type::STR_HEX, "rotation", "The ROTATE, to publish"},
            {RPCResult::Type::STR_HEX, "delegation", "The new identity's DELEGATE, to publish"},
            {RPCResult::Type::STR, "to_wif", /* optional */ true, "The new identity key, when the old one was passed in"},
        }},
        RPCExamples{HelpExampleCli("createrotation", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const bool given = !request.params[0].isNull();
    const CKey old_id = IdentityKey(request.params[0]);
    CKey new_id;
    new_id.MakeNewKey(true);
    roster::Record rec;
    rec.type = roster::RecordType::ROTATE;
    rec.id_key = roster::KeyBytesOf(old_id);
    rec.new_id_key = roster::KeyBytesOf(new_id);
    const std::vector<unsigned char> rotation = Sign(old_id, rec);
    const std::vector<unsigned char> delegation = MakeDelegation(new_id, roster::KeyBytesOf(OperationalKey()), nullopt);
    std::string error;
    if (!given && !roster::SetIdentityKey(new_id, error)) throw JSONRPCError(RPC_INTERNAL_ERROR, error);
    UniValue out(UniValue::VOBJ);
    out.pushKV("from", HexStr(rec.id_key));
    out.pushKV("to", HexStr(rec.new_id_key));
    out.pushKV("rotation", HexStr(rotation));
    out.pushKV("delegation", HexStr(delegation));
    if (given) out.pushKV("to_wif", EncodeSecret(new_id));
    return out;
},
    };
}

static RPCHelpMan createveto()
{
    return RPCHelpMan{"createveto",
        "\nCancel a rotation of an identity, with its recovery key (design note 001, §7).\n"
        "\nFor when the identity key has been taken and someone rotated it away. Valid until the\n"
        "rotation takes effect, " + strprintf("%d", roster::ROTATE_VETO) + " blocks after it confirmed. Publish it with publishrecord.\n"
        "It reveals the recovery key's public half, which is safe; keep the private half.\n",
        {
            {"recovery_key", RPCArg::Type::STR, RPCArg::Optional::NO, "The recovery key, as createidentity gave it"},
            {"identity", RPCArg::Type::STR_HEX, /* default */ "this node's identity", "The identity being rotated"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "veto", "The VETO, to publish"},
        }},
        RPCExamples{HelpExampleCli("createveto", "\"<recovery key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const CKey recovery = SecretArg(request.params[0], "recovery_key");
    roster::Record rec;
    rec.type = roster::RecordType::VETO;
    if (request.params[1].isNull()) {
        rec.id_key = roster::KeyBytesOf(IdentityKey(NullUniValue));
    } else {
        rec.id_key = KeyArg(request.params[1], "identity");
    }
    rec.recovery_key = roster::KeyBytesOf(recovery);
    UniValue out(UniValue::VOBJ);
    out.pushKV("veto", HexStr(Sign(recovery, rec)));
    return out;
},
    };
}

static RPCHelpMan createrevocation()
{
    return RPCHelpMan{"createrevocation",
        "\nSign a revocation of an operational key: the end of that key, for good (design note 001, §5, §9).\n"
        "\nFor a key that is compromised or retired. Every node drops a revoked key the moment it sees\n"
        "the revocation, and nothing the key signs counts again. This cannot be undone. A node whose\n"
        "own key is revoked needs a new one: stop it, move roster.key aside, start it again.\n"
        "\nPass it on with sendrevocation, which costs nothing, and publish it with publishrecord so\n"
        "it is on the chain too.\n",
        {
            {"key", RPCArg::Type::STR, /* default */ "this node's operational key", "The private key to revoke, if not this node's"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "key", ""},
            {RPCResult::Type::STR_HEX, "revocation", "The REVOKE"},
        }},
        RPCExamples{HelpExampleCli("createrevocation", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const CKey key = request.params[0].isNull() ? OperationalKey() : SecretArg(request.params[0], "key");
    roster::Record rec;
    rec.type = roster::RecordType::REVOKE;
    rec.op_key = roster::KeyBytesOf(key);
    UniValue out(UniValue::VOBJ);
    out.pushKV("key", HexStr(rec.op_key));
    out.pushKV("revocation", HexStr(Sign(key, rec)));
    return out;
},
    };
}

static RPCHelpMan sendrevocation()
{
    return RPCHelpMan{"sendrevocation",
        "\nKeep a revocation and pass it to every peer, without a transaction (design note 001, §9).\n"
        "\nA revocation needs no confirmation to be believed - it is signed by the key it revokes and only\n"
        "ever removes - so nodes drop the key as soon as it reaches them and pass it on once.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The REVOKE, as createrevocation made it"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "key", "The key revoked"},
            {RPCResult::Type::BOOL, "new", "Whether this node had not seen it before"},
            {RPCResult::Type::NUM, "peers", "Peers it was passed to"},
        }},
        RPCExamples{HelpExampleCli("sendrevocation", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::vector<unsigned char> raw = ParseHexV(request.params[0], "hex");
    roster::Record rec;
    if (!roster::ParseAndVerify(raw, ChainId(), rec) || rec.type != roster::RecordType::REVOKE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not a revocation signed by the key it revokes");
    }
    if (!roster::g_revocations) throw JSONRPCError(RPC_MISC_ERROR, "Revocations are not kept on this node");
    const bool fresh = roster::g_revocations->Add(raw);
    NodeContext& node = EnsureNodeContext(request.context);
    int peers = 0;
    if (node.connman && node.peerman) {
        node.peerman->RelayRosterRevocation(raw);
        peers = (int)node.connman->GetNodeCount(CConnman::CONNECTIONS_ALL);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("key", HexStr(rec.op_key));
    out.pushKV("new", fresh);
    out.pushKV("peers", peers);
    return out;
},
    };
}

static RPCHelpMan listrevocations()
{
    return RPCHelpMan{"listrevocations",
        "\nEvery revocation this node has seen, from blocks, the mempool or peers. Kept for good.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "key", ""},
                {RPCResult::Type::BOOL, "confirmed", "Whether the chain carries one too"},
                {RPCResult::Type::STR_HEX, "hex", ""},
            }},
        }},
        RPCExamples{HelpExampleCli("listrevocations", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue out(UniValue::VARR);
    if (!roster::g_revocations) return out;
    const int tip = g_rosterindex ? g_rosterindex->GetSummary().best_block_height : -1;
    for (const std::vector<unsigned char>& raw : roster::g_revocations->All()) {
        roster::Record rec;
        if (roster::ParseRecord(raw, rec) != roster::ParseError::OK) continue;
        UniValue o(UniValue::VOBJ);
        o.pushKV("key", HexStr(rec.op_key));
        o.pushKV("confirmed", g_rosterindex && g_rosterindex->RevokedAt(rec.op_key, tip) >= 0);
        o.pushKV("hex", HexStr(raw));
        out.push_back(o);
    }
    return out;
},
    };
}

static RPCHelpMan getageproof()
{
    return RPCHelpMan{"getageproof",
        "\nProve how long a key has been listed, to anyone holding only block headers (design note 001, §5).\n"
        "\nThe proof is the key's chain of announcements, each pointing at the one before, back to where it\n"
        "starts - and, when the key runs under an identity, the delegation it accepted and the identity's\n"
        "earliest record. Every link comes with its transaction and a merkle branch to its block. Check it\n"
        "with verifyageproof, which needs no roster index. A rotation's age is not carried here: that\n"
        "it was not vetoed cannot be shown by inclusion alone.\n",
        {
            {"key", RPCArg::Type::STR_HEX, /* default */ "this node's operational key", "The operational key"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "key", ""},
            {RPCResult::Type::NUM, "since_height", "Where the history proved starts"},
            {RPCResult::Type::ARR, "links", "", {{RPCResult::Type::ELISION, "", "height, blockhash, tx, proof"}}},
        }},
        RPCExamples{HelpExampleCli("getageproof", "\"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    RosterIndex& index = Index();
    const roster::KeyBytes key = request.params[0].isNull() ? roster::KeyBytesOf(OperationalKey())
                                                             : KeyArg(request.params[0], "key");
    const int tip = index.GetSummary().best_block_height;
    std::vector<roster::HeldRecord> history;
    if (!index.ReadHistory(key, history)) throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read the roster index");
    const roster::AgeChain chain = roster::WalkAgeChain(key, history, tip);
    if (chain.links.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "This key has never announced");

    UniValue links(UniValue::VARR);
    int since = chain.anchor;
    for (const roster::HeldRecord& h : chain.links) {
        links.push_back(LinkToJSON(h, h.rec.type == roster::RecordType::DELEGATE ? "delegation" : "announcement"));
    }
    if (chain.delegation) {
        // The identity's earliest record it signed itself.
        const roster::KeyBytes id = chain.delegation->rec.id_key;
        std::vector<roster::HeldRecord> own;
        if (index.ReadHistory(id, own)) {
            for (const roster::HeldRecord& h : own) {
                const bool signed_by_id = (h.rec.type == roster::RecordType::DELEGATE ||
                                           h.rec.type == roster::RecordType::ROTATE) && h.rec.id_key == id;
                if (!signed_by_id || h.height > tip) continue;
                if (h.height < chain.delegation->height) {
                    links.push_back(LinkToJSON(h, "identity"));
                    since = std::min(since, h.height);
                }
                break; // oldest first: the first one is the earliest
            }
        }
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("key", HexStr(key));
    out.pushKV("since_height", since);
    out.pushKV("links", links);
    return out;
},
    };
}

static RPCHelpMan verifyageproof()
{
    return RPCHelpMan{"verifyageproof",
        "\nCheck an age proof against this node's block headers. Needs no roster index: this is what a\n"
        "client without the chain's history does (design note 001, §5).\n",
        {
            {"proof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "What getageproof returned", {}, "proof"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", ""},
            {RPCResult::Type::STR, "reason", /* optional */ true, "Why not, if not"},
            {RPCResult::Type::STR_HEX, "key", /* optional */ true, ""},
            {RPCResult::Type::NUM, "since_height", /* optional */ true, "Where the proved history starts"},
            {RPCResult::Type::NUM, "age_blocks", /* optional */ true, "0 until it is deep enough to count"},
            {RPCResult::Type::STR_HEX, "identity", /* optional */ true, "The identity the key accepted"},
        }},
        RPCExamples{HelpExampleCli("verifyageproof", "'{...}'")},
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
    const roster::KeyBytes key = KeyArg(find_value(proof, "key"), "key");
    const UniValue& links = find_value(proof, "links");
    if (!links.isArray() || links.empty()) return fail("no links");

    int tip;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Height();
    }
    std::vector<roster::HeldRecord> held;
    for (size_t i = 0; i < links.size(); ++i) {
        const UniValue& link = links[i];
        CMerkleBlock mb;
        try {
            CDataStream ss(ParseHexV(find_value(link, "proof"), "proof"), SER_NETWORK, PROTOCOL_VERSION);
            ss >> mb;
        } catch (const std::exception&) {
            return fail(strprintf("link %u: unreadable merkle proof", i));
        }
        int height;
        {
            LOCK(cs_main);
            const CBlockIndex* pindex = LookupBlockIndex(mb.header.GetHash());
            if (!pindex || !::ChainActive().Contains(pindex)) return fail(strprintf("link %u: block not on this chain", i));
            height = pindex->nHeight;
        }
        std::vector<uint256> matches;
        std::vector<unsigned int> positions;
        if (mb.txn.ExtractMatches(matches, positions) != mb.header.hashMerkleRoot) {
            return fail(strprintf("link %u: merkle branch does not lead to its block", i));
        }
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, find_value(link, "tx").get_str())) return fail(strprintf("link %u: unreadable transaction", i));
        const CTransaction tx(mtx);
        if (std::find(matches.begin(), matches.end(), tx.GetHash()) == matches.end()) {
            return fail(strprintf("link %u: transaction is not the one proved", i));
        }
        const int vout = find_value(link, "vout").get_int();
        std::vector<unsigned char> payload;
        if (vout < 0 || vout >= (int)tx.vout.size() || !roster::ExtractOpReturnPayload(tx.vout[vout].scriptPubKey, payload)) {
            return fail(strprintf("link %u: no record at that output", i));
        }
        roster::HeldRecord h;
        if (!roster::ParseAndVerify(payload, ChainId(), h.rec)) return fail(strprintf("link %u: record does not verify", i));
        if ((h.rec.type == roster::RecordType::ANNOUNCE || h.rec.type == roster::RecordType::DELEGATE) &&
            !roster::ExpiryInRange(h.rec.expiry_height, height)) {
            return fail(strprintf("link %u: record out of range for its block", i));
        }
        h.height = height;
        held.push_back(h);
    }

    // The links must be one history: announcements by the key, each pointing
    // at the next; then perhaps the delegation the last one pointed at; then
    // perhaps a record the delegating identity signed earlier.
    if (held[0].rec.type != roster::RecordType::ANNOUNCE || held[0].rec.op_key != key) {
        return fail("the first link is not an announcement by the key");
    }
    int since = held[0].height;
    Optional<roster::KeyBytes> identity;
    size_t i = 1;
    for (; i < held.size(); ++i) {
        const roster::HeldRecord& prev = held[i - 1];
        const roster::HeldRecord& h = held[i];
        if (prev.rec.type != roster::RecordType::ANNOUNCE) break;
        if ((int64_t)prev.rec.prev_height != h.height) return fail(strprintf("link %u is not where link %u points", i, i - 1));
        if (h.rec.type == roster::RecordType::ANNOUNCE && h.rec.op_key == key) {
            since = h.height;
        } else if (h.rec.type == roster::RecordType::DELEGATE && h.rec.op_key == key) {
            since = h.height;
            identity = h.rec.id_key;
            ++i;
            break;
        } else {
            return fail(strprintf("link %u is neither the key's announcement nor a delegation to it", i));
        }
    }
    if (i < held.size()) {
        const roster::HeldRecord& h = held[i];
        const bool signed_by_id = identity && (h.rec.type == roster::RecordType::DELEGATE ||
                                               h.rec.type == roster::RecordType::ROTATE) && h.rec.id_key == *identity;
        if (!signed_by_id || i + 1 != held.size()) return fail("the last link is not a record of the identity");
        since = std::min(since, h.height);
    }
    out.pushKV("valid", true);
    out.pushKV("key", HexStr(key));
    out.pushKV("since_height", since);
    out.pushKV("age_blocks", tip - since >= roster::AGE_DEPTH ? tip - since : 0);
    if (identity) out.pushKV("identity", HexStr(*identity));
    return out;
},
    };
}

void RegisterRosterIdentityRPCCommands(CRPCTable& t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category    name                actor (function)    argNames
  //  ----------  ------------------  ------------------  ----------
    { "roster",   "getidentity",      &getidentity,       {"key"} },
    { "roster",   "createidentity",   &createidentity,    {"store"} },
    { "roster",   "createdelegation", &createdelegation,  {"key","identity_key"} },
    { "roster",   "createrotation",   &createrotation,    {"identity_key"} },
    { "roster",   "createveto",       &createveto,        {"recovery_key","identity"} },
    { "roster",   "createrevocation", &createrevocation,  {"key"} },
    { "roster",   "sendrevocation",   &sendrevocation,    {"hex"} },
    { "roster",   "listrevocations",  &listrevocations,   {} },
    { "roster",   "getageproof",      &getageproof,       {"key"} },
    { "roster",   "verifyageproof",   &verifyageproof,    {"proof"} },
};
// clang-format on
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
