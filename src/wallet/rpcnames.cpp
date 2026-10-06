// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpcnames.h>

#include <chainparams.h>
#include <core_io.h>
#include <index/nameindex.h>
#include <names/name.h>
#include <names/record.h>
#include <names/registrar.h>
#include <names/resolve.h>
#include <names/state.h>
#include <psbt.h>
#include <random.h>
#include <roster/keystore.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/standard.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>

#include <algorithm>

// Defined in rpcwallet.cpp.
void FundTransaction(CWallet* const pwallet, CMutableTransaction& tx, CAmount& fee_out, int& change_position,
                     const UniValue& options, CCoinControl& coinControl, bool override_min_fee);

namespace {

const std::string& ChainId()
{
    static const std::string id = Params().NetworkIDString();
    return id;
}

std::string Normal(const std::string& text)
{
    std::string normal;
    if (!names::Normalize(text, normal)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Names are plain letters a-z, digits and hyphens.");
    }
    return normal;
}

/** This node's roster key, which holds the names it registers. */
CKey OwnKey(roster::KeyBytes& x_out)
{
    CKey key;
    std::string error;
    if (!roster::GetOperationalKey(key, error)) throw JSONRPCError(RPC_MISC_ERROR, error);
    const CPubKey pub = key.GetPubKey();
    std::copy(pub.begin() + 1, pub.begin() + 33, x_out.begin());
    return key;
}

/** The name state, caught up with the chain this wallet sees. */
std::shared_ptr<const names::NameState> CurrentNames(int& next_out, bool wait = true)
{
    if (!g_nameindex) throw JSONRPCError(RPC_MISC_ERROR, "Names need the name index (-nameindex).");
    if (wait) g_nameindex->BlockUntilSyncedToCurrentChain();
    std::shared_ptr<const names::NameState> state;
    int height = 0;
    if (!g_nameindex->GetState(state, height)) throw JSONRPCError(RPC_DATABASE_ERROR, "The name index could not be read.");
    // A record sent now confirms in the next block at the earliest, so that is
    // the height every check is made against.
    next_out = height + 1;
    if (next_out < state->StartHeight()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Names have not started on this network yet.");
    }
    return state;
}

/**
 * Pay to publish a name record, burning `burn` in the same OP_RETURN output.
 *
 * Every caller has checked the record against the name state first: the chain
 * accepts a record that does not count, and burns its coins all the same.
 */
CTransactionRef SendNameRecord(CWallet* const pwallet, const std::vector<unsigned char>& raw, CAmount burn,
                               CAmount& fee)
{
    const unsigned needed = (unsigned)(raw.size() + roster::OP_RETURN_OVERHEAD);
    if (needed > nMaxDatacarrierBytes) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "This record needs a datacarrier limit of %u bytes and this node allows %u. Raise -datacarriersize. "
            "Nothing was spent.", needed, nMaxDatacarrierBytes));
    }
    EnsureWalletIsUnlocked(pwallet);

    const CScript carrier = CScript() << OP_RETURN << raw;
    {
        LOCK(pwallet->cs_wallet);
        for (const auto& entry : pwallet->mapWallet) {
            const CWalletTx& wtx = entry.second;
            if (wtx.GetDepthInMainChain() != 0 || wtx.isAbandoned()) continue;
            for (const CTxOut& out : wtx.tx->vout) {
                if (out.scriptPubKey == carrier) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                        "This wallet already sent this record in %s, which has not confirmed yet. Nothing was spent.",
                        wtx.GetHash().GetHex()));
                }
            }
        }
    }

    CMutableTransaction raw_tx;
    raw_tx.vout.emplace_back(burn, carrier);
    CCoinControl coin_control;
    coin_control.m_add_inputs = true;
    fee = 0;
    int change_position = -1;
    FundTransaction(pwallet, raw_tx, fee, change_position, NullUniValue, coin_control, /* override_min_fee */ true);

    PartiallySignedTransaction psbtx(raw_tx);
    bool complete = true;
    const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, true, false);
    if (err != TransactionError::OK) throw JSONRPCTransactionError(err);
    CMutableTransaction mtx;
    if (!FinalizeAndExtractPSBT(psbtx, mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not sign the funding inputs. Nothing was broadcast.");
    }
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    pwallet->CommitTransaction(tx, {}, {});
    return tx;
}

std::vector<unsigned char> Signed(const CKey& key, names::NameRecord& rec)
{
    std::vector<unsigned char> raw;
    if (!names::SignNameRecord(key, rec, ChainId(), raw)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Could not sign the name record.");
    }
    return raw;
}

int Years(const UniValue& v)
{
    const int years = v.isNull() ? 1 : v.get_int();
    if (years < 1 || years > 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "years must be 1 or 2");
    return years;
}

} // namespace

bool PublishNameClaim(const names::PendingRegistration& p, uint256& txid_out, std::string& error_out)
{
    const std::shared_ptr<CWallet> wallet = GetWallet(p.wallet);
    if (!wallet) {
        error_out = strprintf("Waiting for wallet %s, which committed this name, to be opened.",
                              p.wallet.empty() ? "(default)" : p.wallet);
        return false;
    }
    try {
        if (wallet->IsLocked() || wallet->m_wallet_unlock_staking_only) {
            error_out = strprintf("Unlock wallet %s to finish registering %s.",
                                  p.wallet.empty() ? "(default)" : p.wallet, p.name);
            return false;
        }
        roster::KeyBytes owner;
        const CKey key = OwnKey(owner);
        if (owner != p.owner) {
            error_out = "This node's roster key has changed since the name was committed.";
            return false;
        }
        // No waiting on the index here: this runs on the scheduler thread,
        // which the index itself is fed from.
        int next = 0;
        std::shared_ptr<const names::NameState> state = CurrentNames(next, /* wait */ false);
        const uint32_t term = std::min<uint32_t>(p.years * names::BLOCKS_PER_YEAR, names::MAX_TERM);
        names::NameRecord rec;
        rec.type = names::NameRecordType::CLAIM;
        rec.key = owner;
        rec.name = p.name;
        rec.salt = p.salt;
        rec.expiry_height = (uint32_t)next + term;
        const CAmount burn = names::Price(p.name.size(), term);
        const std::string why = state->CheckClaim(p.name, owner, p.salt, rec.expiry_height, burn, next);
        if (!why.empty()) {
            error_out = why;
            return false;
        }
        CAmount fee = 0;
        txid_out = SendNameRecord(wallet.get(), Signed(key, rec), burn, fee)->GetHash();
        return true;
    } catch (const UniValue& e) {
        const UniValue& message = find_value(e, "message");
        error_out = message.isStr() ? message.get_str() : e.write();
    } catch (const std::exception& e) {
        error_out = e.what();
    }
    return false;
}

RPCHelpMan registername()
{
    return RPCHelpMan{"registername",
        "\nRegister a root name for this node's roster key.\n"
        "\nTwo steps, the second automatic. This sends a commitment that hides the name; once it is\n"
        + strprintf("%u", names::COMMIT_MIN_AGE) + " blocks deep the node sends the claim, which reveals the name and burns its\n"
        "price, from this same wallet. Nobody can copy a claim seen waiting to be mined, because a\n"
        "claim only counts against a commitment made blocks earlier. Calling this again for a name in\n"
        "progress reports how it is going, and finishes it if it can.\n"
        "\nThe price is burned - sent where nobody can spend it - rather than paid to anyone, so the\n"
        "staker of a block cannot register names for free. Check it first with getnameprice.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "3 to 32 letters, digits or inner hyphens"},
            {"years", RPCArg::Type::NUM, /* default */ "1", "1 or 2"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "name", ""},
            {RPCResult::Type::STR, "status", "committed, claimed, done or lost"},
            {RPCResult::Type::STR, "note", "What is happening now"},
            {RPCResult::Type::ELISION, "", "and the details of the registration"},
        }},
        RPCExamples{HelpExampleCli("registername", "\"pilot\"") + HelpExampleCli("registername", "\"pilot\" 2")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    if (!names::g_registrar) throw JSONRPCError(RPC_MISC_ERROR, "Names need the name index (-nameindex).");

    const std::string name = Normal(request.params[0].get_str());
    const int years = Years(request.params[1]);
    roster::KeyBytes owner;
    const CKey key = OwnKey(owner);

    // A registration already under way: report it, and move it along.
    names::PendingRegistration pending;
    if (names::g_registrar->Find(name, pending)) {
        names::g_registrar->Process();
        for (const names::PendingRegistration& p : names::g_registrar->All()) {
            if (p.name == name && p.commit_txid == pending.commit_txid) return names::PendingToJSON(p);
        }
        return names::PendingToJSON(pending);
    }

    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const std::string why = state->CheckAvailable(name, owner, next);
    if (!why.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, why + " Nothing was spent.");

    const CAmount price = names::Price(name.size(), (uint32_t)years * names::BLOCKS_PER_YEAR);
    {
        LOCK(pwallet->cs_wallet);
        const CAmount spendable = pwallet->GetBalance().m_mine_trusted;
        if (spendable < price) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf(
                "%s costs %s BPS for %d year%s, and this wallet has %s BPS it can spend. Nothing was spent.",
                name, FormatMoney(price), years, years == 1 ? "" : "s", FormatMoney(spendable)));
        }
    }
    EnsureWalletIsUnlocked(pwallet);

    names::PendingRegistration p;
    p.name = name;
    GetStrongRandBytes(p.salt.data(), (int)p.salt.size());
    p.owner = owner;
    p.years = (uint32_t)years;
    p.wallet = pwallet->GetName();
    p.started = next;
    p.status = "committed";
    p.note = strprintf("Committed; the name is claimed in %u blocks.", names::COMMIT_MIN_AGE);

    names::NameRecord commit;
    commit.type = names::NameRecordType::COMMIT;
    commit.commitment = names::Commitment(name, p.salt, owner);
    CAmount fee = 0;
    p.commit_txid = SendNameRecord(pwallet, names::SerializeNameRecord(commit), 0, fee)->GetHash();
    names::g_registrar->Add(p);

    UniValue out = names::PendingToJSON(p);
    out.pushKV("claim_after_height", next + (int)names::COMMIT_MIN_AGE);
    out.pushKV("fee", ValueFromAmount(fee));
    return out;
},
    };
}

RPCHelpMan renewname()
{
    return RPCHelpMan{"renewname",
        "\nExtend a name this node holds, by burning its price again.\n"
        "\nA name can be renewed while it is live and for a month after it expires; after that anyone may\n"
        "register it. Renewal is always by hand. A name can be paid at most two years ahead.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name"},
            {"years", RPCArg::Type::NUM, /* default */ "1", "1 or 2"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::STR, "name", ""},
            {RPCResult::Type::NUM, "expiry_height", "When it now ends"},
            {RPCResult::Type::STR_AMOUNT, "burned", ""},
            {RPCResult::Type::STR_AMOUNT, "fee", ""},
        }},
        RPCExamples{HelpExampleCli("renewname", "\"pilot\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const std::string name = Normal(request.params[0].get_str());
    const int years = Years(request.params[1]);
    roster::KeyBytes owner;
    const CKey key = OwnKey(owner);
    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const names::NameEntry* entry = state->Find(name);
    if (!entry || state->StatusOf(name, next) == names::Status::FREE || entry->owner != owner) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("This node does not hold %s.", name));
    }
    const uint32_t from = std::max<uint32_t>(entry->expiry, (uint32_t)next);
    names::NameRecord rec;
    rec.type = names::NameRecordType::CLAIM;
    rec.key = owner;
    rec.name = name;
    rec.expiry_height = from + (uint32_t)years * names::BLOCKS_PER_YEAR;
    if ((int64_t)rec.expiry_height - next > names::MAX_TERM) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "%s is paid until block %u already, and a name can be paid at most two years ahead.%s",
            name, entry->expiry, years > 1 ? " Renew for one year." : ""));
    }
    const CAmount burn = names::Price(name.size(), rec.expiry_height - from);
    const std::string why = state->CheckClaim(name, owner, rec.salt, rec.expiry_height, burn, next);
    if (!why.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, why + " Nothing was spent.");
    CAmount fee = 0;
    const CTransactionRef tx = SendNameRecord(wallet.get(), Signed(key, rec), burn, fee);
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("name", name);
    out.pushKV("expiry_height", (int64_t)rec.expiry_height);
    out.pushKV("burned", ValueFromAmount(burn));
    out.pushKV("fee", ValueFromAmount(fee));
    return out;
},
    };
}

RPCHelpMan transfername()
{
    return RPCHelpMan{"transfername",
        "\nGive a name this node holds to another roster key. Cannot be undone from here.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name"},
            {"to", RPCArg::Type::STR, RPCArg::Optional::NO, "The new holder: a roster key, a petname or a name"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::STR, "name", ""},
            {RPCResult::Type::STR_HEX, "new_owner", ""},
        }},
        RPCExamples{HelpExampleCli("transfername", "\"pilot\" \"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const std::string name = Normal(request.params[0].get_str());
    roster::KeyBytes owner;
    const CKey key = OwnKey(owner);
    names::Target to;
    std::string error;
    if (!names::ResolveTarget(request.params[1].get_str(), to, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const names::NameEntry* entry = state->Find(name);
    if (!entry || state->StatusOf(name, next) != names::Status::LIVE || entry->owner != owner) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("This node does not hold a live %s.", name));
    }
    if (to.key == owner) throw JSONRPCError(RPC_INVALID_PARAMETER, "That is this node's own key.");
    names::NameRecord rec;
    rec.type = names::NameRecordType::TRANSFER;
    rec.name = name;
    rec.key = to.key;
    CAmount fee = 0;
    const CTransactionRef tx = SendNameRecord(wallet.get(), Signed(key, rec), 0, fee);
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("name", name);
    out.pushKV("new_owner", HexStr(to.key));
    return out;
},
    };
}

RPCHelpMan setsubname()
{
    return RPCHelpMan{"setsubname",
        "\nPoint label.name at a roster key, under a name this node holds. Free beyond the fee.\n"
        "\nA subname lasts as long as the name above it. Use \"remove\" as the key to take one away.\n",
        {
            {"subname", RPCArg::Type::STR, RPCArg::Optional::NO, "label.name"},
            {"to", RPCArg::Type::STR, RPCArg::Optional::NO, "A roster key, petname or name, or \"remove\""},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::STR, "subname", ""},
            {RPCResult::Type::STR_HEX, "key", "All zeros when removed"},
        }},
        RPCExamples{HelpExampleCli("setsubname", "\"alice.pilot\" \"<key>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    std::string root, label;
    const std::string full = Normal(request.params[0].get_str());
    if (!names::SplitName(full, root, label) || label.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A subname is written label.name.");
    }
    roster::KeyBytes owner;
    const CKey key = OwnKey(owner);
    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const names::NameEntry* entry = state->Find(root);
    if (!entry || state->StatusOf(root, next) != names::Status::LIVE || entry->owner != owner) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("This node does not hold a live %s.", root));
    }
    names::NameRecord rec;
    rec.type = names::NameRecordType::SUBNAME;
    rec.name = root;
    rec.label = label;
    const std::string to_text = request.params[1].get_str();
    if (to_text == "remove") {
        rec.expiry_height = 0;
    } else {
        names::Target to;
        std::string error;
        if (!names::ResolveTarget(to_text, to, error)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
        rec.key = to.key;
        rec.expiry_height = entry->expiry;
    }
    CAmount fee = 0;
    const CTransactionRef tx = SendNameRecord(wallet.get(), Signed(key, rec), 0, fee);
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("subname", full);
    out.pushKV("key", HexStr(rec.key));
    return out;
},
    };
}
