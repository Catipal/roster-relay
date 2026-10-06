// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/rpcnames.h>

#include <chainparams.h>
#include <coins.h>
#include <core_io.h>
#include <index/nameindex.h>
#include <key_io.h>
#include <names/name.h>
#include <names/record.h>
#include <names/registrar.h>
#include <names/resolve.h>
#include <names/sale.h>
#include <names/state.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <psbt.h>
#include <random.h>
#include <roster/extract.h>
#include <roster/keystore.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/standard.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
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
 * Sign a transaction this wallet has funded, check the mempool takes it, and
 * only then keep it. A transaction the wallet keeps but the network refuses
 * would sit unconfirmed, tying up its coins. Inputs listed in `presigned`
 * already carry their input script and are left as they are.
 */
CTransactionRef SignAndSend(CWallet* const pwallet, CMutableTransaction raw_tx, const std::set<size_t>& presigned = {})
{
    PartiallySignedTransaction psbtx(raw_tx);
    for (size_t i : presigned) {
        psbtx.inputs[i].final_script_sig = raw_tx.vin[i].scriptSig;
        psbtx.tx->vin[i].scriptSig.clear();
    }
    bool complete = true;
    const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, true, false);
    if (err != TransactionError::OK) throw JSONRPCTransactionError(err);
    CMutableTransaction mtx;
    if (!FinalizeAndExtractPSBT(psbtx, mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not sign the funding inputs. Nothing was broadcast.");
    }
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    std::string error;
    if (!pwallet->chain().broadcastTransaction(tx, pwallet->m_default_max_tx_fee, /* relay */ false, error)) {
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, error + ". Nothing was spent.");
    }
    pwallet->CommitTransaction(tx, {}, {});
    return tx;
}

/**
 * Fund `raw_tx` from this wallet with the change after every output it has,
 * so the outputs keep their places. Returns where the change went, or -1.
 */
int FundChangeLast(CWallet* const pwallet, CMutableTransaction& raw_tx, CAmount& fee, CCoinControl& coin_control)
{
    coin_control.m_add_inputs = true;
    fee = 0;
    UniValue options(UniValue::VOBJ);
    options.pushKV("changePosition", (int)raw_tx.vout.size());
    int change_position = -1;
    FundTransaction(pwallet, raw_tx, fee, change_position, options, coin_control, /* override_min_fee */ true);
    return change_position;
}

/** Fund `raw_tx` from this wallet, its change last, then sign and send it. */
CTransactionRef SendFunded(CWallet* const pwallet, CMutableTransaction raw_tx, CAmount& fee)
{
    CCoinControl coin_control;
    FundChangeLast(pwallet, raw_tx, fee, coin_control);
    return SignAndSend(pwallet, raw_tx);
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
    return SendFunded(pwallet, raw_tx, fee);
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

/** The sale coin as it stands now, in the chain or the mempool. */
bool FindSaleCoin(CWallet* const pwallet, const COutPoint& outpoint, Coin& coin_out)
{
    std::map<COutPoint, Coin> coins;
    coins[outpoint];
    pwallet->chain().findCoins(coins);
    coin_out = coins[outpoint];
    return !coin_out.IsSpent();
}

/** Bytes a sale coin's input adds: outpoint, script length, a signature push, sequence. */
constexpr unsigned SALE_INPUT_SIZE = 32 + 4 + 1 + 74 + 4;

/** Refuse when this wallet has a sale of `name` waiting to confirm. */
void CheckNoSaleWaiting(CWallet* const pwallet, const std::string& name)
{
    LOCK(pwallet->cs_wallet);
    for (const auto& entry : pwallet->mapWallet) {
        const CWalletTx& wtx = entry.second;
        if (wtx.GetDepthInMainChain() != 0 || wtx.isAbandoned()) continue;
        for (const CTxOut& out : wtx.tx->vout) {
            std::vector<unsigned char> payload;
            names::NameRecord rec;
            if (!roster::ExtractOpReturnPayload(out.scriptPubKey, payload)) continue;
            if (!names::ParseNameRecord(payload, rec)) continue;
            if (rec.type == names::NameRecordType::SELL && rec.name == name) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                    "A sale of %s from this wallet is waiting to confirm in %s. Nothing was spent.",
                    name, wtx.GetHash().GetHex()));
            }
        }
    }
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
    if (state->ActiveOffer(name, next)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "%s is up for sale. Take it off sale first (cancelnamesale); a transfer would not count meanwhile. "
            "Nothing was spent.", name));
    }
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

RPCHelpMan sellname()
{
    return RPCHelpMan{"sellname",
        "\nPut a name this node holds up for sale. Anyone can then buy it at once, without this node being\n"
        "online: they pay the price to this wallet and renew the name, both in one transaction.\n"
        "\nTwo transactions are sent. The first sets aside a small coin; the second publishes the sale,\n"
        "with this node's signature letting whoever pays the price spend that coin. Paying and taking\n"
        "the name are then one transaction, so a buyer cannot pay without getting the name, and two\n"
        "buyers cannot both pay. While the name is for sale it cannot be transferred or put up again;\n"
        "cancelnamesale takes it off sale.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name"},
            {"price", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "What the buyer pays this wallet, in " + CURRENCY_UNIT + ". The buyer burns the renewal on top."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "name", ""},
            {RPCResult::Type::STR_AMOUNT, "price", "What a buyer pays this wallet"},
            {RPCResult::Type::STR, "pay_to", "The address it is paid to"},
            {RPCResult::Type::STR_HEX, "coin_txid", "Transaction setting aside the sale coin"},
            {RPCResult::Type::STR_HEX, "txid", "Transaction publishing the sale"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Both fees together"},
        }},
        RPCExamples{HelpExampleCli("sellname", "\"pilot\" 250")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    const std::string name = Normal(request.params[0].get_str());
    const CAmount price = AmountFromValue(request.params[1]);
    if (price <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "The price must be more than zero.");
    if (!MoneyRange(price + names::SALE_COIN_VALUE)) throw JSONRPCError(RPC_INVALID_PARAMETER, "That price is out of range.");
    roster::KeyBytes owner;
    const CKey key = OwnKey(owner);
    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const std::string why = state->CheckSell(name, owner, next);
    if (!why.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, why + " Nothing was spent.");
    CheckNoSaleWaiting(pwallet, name);
    EnsureWalletIsUnlocked(pwallet);

    CTxDestination pay_to, anchor_to;
    std::string error;
    {
        LOCK(pwallet->cs_wallet);
        if (!pwallet->GetNewDestination(OutputType::LEGACY, "sale of " + name, pay_to, error) ||
            !pwallet->GetNewChangeDestination(OutputType::LEGACY, anchor_to, error)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
        }
    }
    const CScript payout = GetScriptForDestination(pay_to);
    if (payout.size() > names::MAX_PAYOUT_SCRIPT) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet's address is too long for a sale record.");
    }
    CKey sale_key;
    if (!names::SaleKey(key, name, payout, sale_key)) throw JSONRPCError(RPC_MISC_ERROR, "Could not make the sale key.");
    const CScript coin_script = names::SaleCoinScript(sale_key.GetPubKey());
    const CAmount payout_value = price + names::SALE_COIN_VALUE;

    // The sale coin, and beside it a coin the sale record will spend, so the
    // record cannot confirm before the coin it sells exists.
    CMutableTransaction coin_tx;
    coin_tx.vout.emplace_back(names::SALE_COIN_VALUE, coin_script);
    coin_tx.vout.emplace_back(names::SALE_COIN_VALUE, GetScriptForDestination(anchor_to));
    CAmount coin_fee = 0;
    const CTransactionRef coin = SendFunded(pwallet, coin_tx, coin_fee);
    const COutPoint coin_out(coin->GetHash(), 0);
    const COutPoint anchor(coin->GetHash(), 1);

    names::NameRecord rec;
    rec.type = names::NameRecordType::SELL;
    rec.name = name;
    rec.coin = coin_out;
    rec.payout_value = payout_value;
    rec.payout = payout;
    if (coin->vout[0].scriptPubKey != coin_script || coin->vout[1].scriptPubKey != GetScriptForDestination(anchor_to) ||
        !names::SignSale(sale_key, coin_out, coin_script, payout_value, payout, rec.coin_sig) ||
        !names::CheckSale(coin_out, coin->vout[0], payout_value, payout, rec.coin_sig)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf(
            "Could not sign the sale. The coin set aside in %s is still this node's.", coin->GetHash().GetHex()));
    }
    const std::vector<unsigned char> raw = Signed(key, rec);

    CMutableTransaction sell_tx;
    sell_tx.vin.emplace_back(anchor);
    sell_tx.vout.emplace_back(0, CScript() << OP_RETURN << raw);
    CAmount fee = 0;
    const CTransactionRef tx = SendFunded(pwallet, sell_tx, fee);

    UniValue out(UniValue::VOBJ);
    out.pushKV("name", name);
    out.pushKV("price", ValueFromAmount(price));
    out.pushKV("pay_to", EncodeDestination(pay_to));
    out.pushKV("coin_txid", coin->GetHash().GetHex());
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("fee", ValueFromAmount(coin_fee + fee));
    return out;
},
    };
}

RPCHelpMan cancelnamesale()
{
    return RPCHelpMan{"cancelnamesale",
        "\nTake a name this node holds off sale, by spending the coin set aside for the sale back to this\n"
        "wallet. Nobody can buy it from then on, and once that confirms it can be transferred or put\n"
        "up again.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::STR, "name", ""},
        }},
        RPCExamples{HelpExampleCli("cancelnamesale", "\"pilot\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    const std::string name = Normal(request.params[0].get_str());
    roster::KeyBytes owner;
    const CKey key = OwnKey(owner);
    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const names::Offer* offer = state->ActiveOffer(name, next);
    if (!offer || state->Find(name)->owner != owner) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("This node has no sale of %s open.", name));
    }
    CKey sale_key;
    if (!names::SaleKey(key, name, offer->payout, sale_key)) throw JSONRPCError(RPC_MISC_ERROR, "Could not make the sale key.");
    const CScript coin_script = names::SaleCoinScript(sale_key.GetPubKey());
    Coin coin;
    if (!FindSaleCoin(pwallet, offer->coin, coin)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "The coin selling %s has been spent already, so the sale is over; it is off sale once that "
            "transaction confirms.", name));
    }
    if (coin.out.scriptPubKey != coin_script) {
        throw JSONRPCError(RPC_MISC_ERROR, "That sale was not made by this node's key.");
    }

    CTxDestination back_to;
    std::string error;
    {
        LOCK(pwallet->cs_wallet);
        if (!pwallet->GetNewChangeDestination(OutputType::LEGACY, back_to, error)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
        }
    }
    // The coin pays its own fee: one input, one output.
    CCoinControl coin_control;
    const CAmount fee = GetMinimumFeeRate(*pwallet, coin_control, nullptr).GetFee(10 + SALE_INPUT_SIZE + 34);
    if (coin.out.nValue - fee <= GetDustThreshold(CTxOut(0, GetScriptForDestination(back_to)), pwallet->chain().relayDustFee())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "The sale coin is too small to pay the fee for spending it.");
    }
    CMutableTransaction mtx;
    mtx.vin.emplace_back(offer->coin, CScript(), (uint32_t)CTxIn::SEQUENCE_FINAL);
    mtx.vout.emplace_back(coin.out.nValue - fee, GetScriptForDestination(back_to));
    const uint256 hash = SignatureHash(coin_script, mtx, 0, SIGHASH_ALL, coin.out.nValue, SigVersion::BASE);
    std::vector<unsigned char> sig;
    if (!sale_key.Sign(hash, sig)) throw JSONRPCError(RPC_MISC_ERROR, "Could not sign.");
    sig.push_back((unsigned char)SIGHASH_ALL);
    mtx.vin[0].scriptSig = CScript() << sig;
    const CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    if (!pwallet->chain().broadcastTransaction(tx, pwallet->m_default_max_tx_fee, /* relay */ true, error)) {
        throw JSONRPCError(RPC_TRANSACTION_REJECTED, error);
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("name", name);
    return out;
},
    };
}

RPCHelpMan buyname()
{
    return RPCHelpMan{"buyname",
        "\nBuy a name its holder has put up for sale, for this node's roster key.\n"
        "\nOne transaction pays the holder's price, burns the renewal - as registering would - and moves\n"
        "the name, so it either all happens or none of it does. Check the price first with getnameprice.\n",
        {
            {"name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name"},
            {"years", RPCArg::Type::NUM, /* default */ "1", "Years of renewal that come with it, 1 or 2, counted from when it ends now and at most two years ahead"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", ""},
            {RPCResult::Type::STR, "name", ""},
            {RPCResult::Type::STR_AMOUNT, "paid", "To the holder"},
            {RPCResult::Type::STR_AMOUNT, "burned", "The renewal"},
            {RPCResult::Type::STR_AMOUNT, "fee", ""},
            {RPCResult::Type::NUM, "expiry_height", "When the name ends for this node"},
        }},
        RPCExamples{HelpExampleCli("buyname", "\"pilot\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    const std::string name = Normal(request.params[0].get_str());
    const int years = Years(request.params[1]);
    roster::KeyBytes buyer;
    const CKey key = OwnKey(buyer);
    int next = 0;
    std::shared_ptr<const names::NameState> state = CurrentNames(next);
    const names::Offer* offer = state->ActiveOffer(name, next);
    if (!offer) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not for sale.", name));
    const names::NameEntry& entry = *state->Find(name);
    const uint32_t expiry = state->BuyExpiry(name, years, next);
    const uint32_t from = std::max<uint32_t>(entry.expiry, (uint32_t)next);
    const CAmount burn = names::Price(name.size(), expiry - from);
    const std::string why = state->CheckBuy(name, buyer, expiry, burn, next);
    if (!why.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, why + " Nothing was spent.");
    // A sale near the end of its grace month may be over before this confirms.
    if ((int64_t)entry.expiry + names::GRACE <= (int64_t)next + 6) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "%s lapses within a few blocks, and the purchase could arrive too late. Nothing was spent.", name));
    }

    Coin coin;
    if (!FindSaleCoin(pwallet, offer->coin, coin)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "The coin selling %s has been spent: someone has just bought it, or its holder took it off sale. "
            "Nothing was spent.", name));
    }
    if (!names::CheckSale(offer->coin, coin.out, offer->payout_value, offer->payout, offer->coin_sig)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "The sale of %s is not signed properly, so it cannot be bought. Nothing was spent.", name));
    }
    const CAmount paid = offer->payout_value - coin.out.nValue;
    EnsureWalletIsUnlocked(pwallet);

    names::NameRecord rec;
    rec.type = names::NameRecordType::BUY;
    rec.key = buyer;
    rec.name = name;
    rec.expiry_height = expiry;
    const std::vector<unsigned char> raw = Signed(key, rec);

    // The payment first, at the index the seller signed for; then the BUY.
    CMutableTransaction mtx;
    mtx.vout.emplace_back(offer->payout_value, offer->payout);
    mtx.vout.emplace_back(burn, CScript() << OP_RETURN << raw);
    CCoinControl coin_control;
    CAmount fee = 0;
    const int change_position = FundChangeLast(pwallet, mtx, fee, coin_control);

    // The sale coin goes in front; it carries the seller's signature already.
    // Its value comes back to this wallet less the fee its bytes add.
    mtx.vin.insert(mtx.vin.begin(), CTxIn(offer->coin, names::SaleScriptSig(offer->coin_sig), CTxIn::SEQUENCE_FINAL));
    const CAmount extra_fee = GetMinimumFeeRate(*pwallet, coin_control, nullptr).GetFee(SALE_INPUT_SIZE);
    const CAmount back = coin.out.nValue - extra_fee;
    if (change_position >= 0 && change_position < (int)mtx.vout.size()) {
        mtx.vout[change_position].nValue += back;
    } else {
        CTxDestination change_to;
        std::string error;
        {
            LOCK(pwallet->cs_wallet);
            if (!pwallet->GetNewChangeDestination(OutputType::LEGACY, change_to, error)) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
            }
        }
        const CTxOut change(back, GetScriptForDestination(change_to));
        if (!IsDust(change, pwallet->chain().relayDustFee())) mtx.vout.push_back(change);
    }
    const CTransactionRef tx = SignAndSend(pwallet, mtx, {0});

    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("name", name);
    out.pushKV("paid", ValueFromAmount(paid));
    out.pushKV("burned", ValueFromAmount(burn));
    out.pushKV("fee", ValueFromAmount(fee + extra_fee));
    out.pushKV("expiry_height", (int64_t)expiry);
    return out;
},
    };
}
