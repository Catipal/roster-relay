// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/companion.h>

#include <addressbook.h>
#include <amount.h>
#include <key_io.h>
#include <names/resolve.h>
#include <rpc/protocol.h>
#include <univalue.h>
#include <util/system.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcnames.h>
#include <wallet/wallet.h>

#include <algorithm>

// Defined in rpcwallet.cpp.
void FundTransaction(CWallet* const pwallet, CMutableTransaction& tx, CAmount& fee_out, int& change_position,
                     const UniValue& options, CCoinControl& coinControl, bool override_min_fee);

namespace {

/** The text of a JSONRPCError, which is how the wallet's spending code reports. */
std::string ErrorText(const UniValue& e)
{
    const UniValue& message = find_value(e, "message");
    return message.isStr() ? message.get_str() : e.write();
}

/**
 * The allowance wallet, if it is open and fit to be one: its own keys, no
 * passphrase - the home node signs with nobody there to type one, so the
 * safeguard is a small balance instead - not paying for this node's listing,
 * and not handing its coins to a staker. It is kept from staking too: a staked
 * coin is locked for 500 blocks, and an allowance is for spending.
 */
std::shared_ptr<CWallet> Allowance(const std::string& name, std::string& error)
{
    if (name.empty()) {
        error = "No allowance wallet is set for the phone (-companionwallet).";
        return nullptr;
    }
    std::shared_ptr<CWallet> w = GetWallet(name);
    if (!w) {
        error = strprintf("The allowance wallet \"%s\" is not open.", name);
        return nullptr;
    }
    if (name == gArgs.GetArg("-listingwallet", "")) {
        error = "The allowance wallet cannot be the wallet that pays for this node's listing (-listingwallet).";
        return nullptr;
    }
    if (w->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = strprintf("The allowance wallet \"%s\" holds no private keys, so it cannot pay.", name);
        return nullptr;
    }
    if (w->IsCrypted()) {
        error = strprintf("The allowance wallet \"%s\" has a passphrase. The home node pays for the phone with nobody "
                          "there to type it, so an allowance wallet has none: keep its balance small instead.", name);
        return nullptr;
    }
    {
        LOCK(w->cs_wallet);
        if (w->IsAutoDelegating()) {
            error = strprintf("The allowance wallet \"%s\" delegates its coins to a staker (setstakingaddress). "
                              "An allowance has to stay spendable: clear its staking address.", name);
            return nullptr;
        }
    }
    if (w->m_enabled_staking) w->StopStake();
    if (!w->m_staking_enabled_setting || *w->m_staking_enabled_setting) w->SetStakingEnabledSetting(false);
    return w;
}

bool Status(const std::string& name, CAmount& balance, CAmount& pending, std::string& error)
{
    const std::shared_ptr<CWallet> w = Allowance(name, error);
    if (!w) return false;
    const CWallet::Balance bal = w->GetBalance();
    balance = bal.m_mine_trusted;
    pending = bal.m_mine_untrusted_pending;
    return true;
}

bool NewAddress(const std::string& name, std::string& address, std::string& error)
{
    const std::shared_ptr<CWallet> w = Allowance(name, error);
    if (!w) return false;
    CTxDestination dest;
    if (!w->GetNewDestination(w->m_default_address_type, "Phone", dest, error)) return false;
    address = EncodeDestination(dest);
    return true;
}

/** What a phone shows as the other side of a payment: the name it went to, or the address. */
std::string Counterparty(const CWallet& w, const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(w.cs_wallet)
{
    for (const CTxOut& out : wtx.tx->vout) {
        if (w.IsMine(out) != ISMINE_NO) continue;
        CTxDestination dest;
        if (!ExtractDestination(out.scriptPubKey, dest)) continue;
        const AddressBook::CAddressBookData* entry = w.FindAddressBookEntry(dest);
        const std::string prefix = "Paid to ";
        if (entry && entry->GetLabel().rfind(prefix, 0) == 0) return entry->GetLabel().substr(prefix.size());
        return EncodeDestination(dest);
    }
    return std::string();
}

bool History(const std::string& name, size_t skip, size_t count, std::vector<companion::HistoryItem>& out,
             std::string& error)
{
    const std::shared_ptr<CWallet> w = Allowance(name, error);
    if (!w) return false;
    out.clear();
    LOCK(w->cs_wallet);
    std::vector<const CWalletTx*> txs;
    for (const auto& entry : w->mapWallet) {
        const CWalletTx& wtx = entry.second;
        if (wtx.IsCoinStake() || wtx.isAbandoned()) continue;
        txs.push_back(&wtx);
    }
    std::sort(txs.begin(), txs.end(), [](const CWalletTx* a, const CWalletTx* b) { return a->GetTxTime() > b->GetTxTime(); });
    for (size_t i = skip; i < txs.size() && out.size() < count; ++i) {
        const CWalletTx& wtx = *txs[i];
        companion::HistoryItem item;
        item.txid = wtx.GetHash();
        const CAmount debit = wtx.GetDebit(ISMINE_SPENDABLE);
        const CAmount credit = wtx.GetCredit(ISMINE_SPENDABLE);
        item.amount = credit - debit;
        if (debit > 0) item.fee = std::max<CAmount>(0, debit - wtx.tx->GetValueOut());
        item.time = wtx.GetTxTime();
        item.confirmations = wtx.GetDepthInMainChain();
        if (debit > 0) item.counterparty = Counterparty(*w, wtx);
        out.push_back(item);
    }
    return true;
}

void Cancel(const std::string& name, const companion::PreparedPayment& payment);

bool Prepare(const std::string& name, const std::string& to, CAmount amount, bool subtract_fee,
             companion::PreparedPayment& out, std::string& error)
{
    const std::shared_ptr<CWallet> w = Allowance(name, error);
    if (!w) return false;
    if (amount <= 0 || !MoneyRange(amount)) {
        error = "That is not an amount that can be sent.";
        return false;
    }
    out = companion::PreparedPayment();
    try {
        CMutableTransaction mtx;
        const CTxDestination dest = DecodeDestination(to);
        if (IsValidDestination(dest)) {
            out.payee_script = GetScriptForDestination(dest);
            out.payee = EncodeDestination(dest);
            mtx.vout.emplace_back(amount, out.payee_script);
        } else {
            // Not an address, so a name, petname or roster key - paid the way
            // sendtoname pays, and refused just as it refuses one that changed
            // hands too recently to be trusted with money that cannot come back.
            names::Target target;
            std::string why;
            if (!names::ResolveTarget(to, target, why)) {
                error = "That is neither an address nor a name: " + why;
                return false;
            }
            const NamePaymentPlan plan = PlanNamePayment(target, /* allow_unsettled */ false);
            out.payee_script = GetScriptForDestination(plan.address);
            out.payee = EncodeDestination(CTxDestination(plan.address));
            out.label = "Paid to " + plan.who;
            mtx.vout.emplace_back(amount, out.payee_script);
            mtx.vout.emplace_back(0, plan.marker);
        }

        // Its coins are locked until it is sent or cancelled, so two payments
        // prepared at once cannot both count on the same coin.
        UniValue options(UniValue::VOBJ);
        options.pushKV("lockUnspents", true);
        if (subtract_fee) {
            UniValue outputs(UniValue::VARR);
            outputs.push_back(0);
            options.pushKV("subtractFeeFromOutputs", outputs);
        }
        CCoinControl coin_control;
        coin_control.m_add_inputs = true;
        CAmount fee = 0;
        int change_position = -1;
        FundTransaction(w.get(), mtx, fee, change_position, options, coin_control, /* override_min_fee */ true);
        out.tx = mtx;
        out.fee = fee;
        // The change lands anywhere, as for any payment, so the payee's output
        // is found by its script rather than by where it started.
        out.amount = -1;
        for (const CTxOut& o : mtx.vout) {
            if (o.scriptPubKey == out.payee_script) {
                out.amount = o.nValue;
                break;
            }
        }
        if (out.amount < 0) {
            Cancel(name, out);
            error = "The payment came out without its payee. Nothing was sent.";
            return false;
        }
        return true;
    } catch (const UniValue& e) {
        error = ErrorText(e);
    } catch (const std::exception& e) {
        error = e.what();
    }
    return false;
}

void Cancel(const std::string& name, const companion::PreparedPayment& payment)
{
    const std::shared_ptr<CWallet> w = GetWallet(name);
    if (!w) return;
    LOCK(w->cs_wallet);
    for (const CTxIn& in : payment.tx.vin) w->UnlockCoin(in.prevout);
}

bool Send(const std::string& name, const companion::PreparedPayment& payment, uint256& txid, bool& rejected,
          std::string& error)
{
    rejected = false;
    const std::shared_ptr<CWallet> w = Allowance(name, error);
    if (!w) {
        rejected = true;
        return false;
    }
    try {
        const CTransactionRef tx = SignAndSend(w.get(), payment.tx);
        txid = tx->GetHash();
        if (!payment.label.empty()) {
            CTxDestination dest;
            if (ExtractDestination(payment.payee_script, dest)) {
                w->SetAddressBook(dest, payment.label, AddressBook::AddressBookPurpose::SEND);
            }
        }
        // Spent now; the locks only held them while the phone was deciding.
        Cancel(name, payment);
        return true;
    } catch (const UniValue& e) {
        // SignAndSend throws only before anything is broadcast: it could not
        // sign, or the network refused the transaction.
        error = ErrorText(e);
        rejected = true;
    } catch (const std::exception& e) {
        error = e.what();
    }
    return false;
}

} // namespace

companion::WalletHooks MakeCompanionWalletHooks()
{
    companion::WalletHooks hooks;
    hooks.status = Status;
    hooks.new_address = NewAddress;
    hooks.history = History;
    hooks.prepare = Prepare;
    hooks.send = Send;
    hooks.cancel = Cancel;
    return hooks;
}
