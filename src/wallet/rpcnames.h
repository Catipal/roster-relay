// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCNAMES_H
#define BITCOIN_WALLET_RPCNAMES_H

#include <names/registrar.h>
#include <names/resolve.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <uint256.h>

#include <set>
#include <string>

class CWallet;
class RPCHelpMan;

/** The wallet half of names: everything that spends. Lookups are node RPCs (rpc/names.cpp). */
RPCHelpMan registername();
RPCHelpMan renewname();
RPCHelpMan transfername();
RPCHelpMan setsubname();
RPCHelpMan sellname();
RPCHelpMan cancelnamesale();
RPCHelpMan buyname();
RPCHelpMan setnamepayments();
RPCHelpMan sendtoname();
RPCHelpMan listnamepayments();

/** Sends a matured registration's claim. Installed with names::SetClaimPublisher. */
bool PublishNameClaim(const names::PendingRegistration& pending, uint256& txid_out, std::string& error_out);

/** Where a payment by name goes, worked out but not yet funded. */
struct NamePaymentPlan {
    std::string who;    //!< as the payee was named: the label, or the roster key in hex
    PKHash address;     //!< the payee's, for this payment only
    CScript marker;     //!< the OP_RETURN output that lets the payee find it
};

/**
 * Work out where a payment to `target` goes, for sendtoname and for anything
 * else that pays a name. Throws the JSONRPCError sendtoname would when the
 * target cannot be paid, or should not be yet: a name or spending key that
 * changed in the last SETTLE_DEPTH blocks, unless `allow_unsettled`.
 */
NamePaymentPlan PlanNamePayment(const names::Target& target, bool allow_unsettled, bool wait_for_index = true);

/**
 * Sign a transaction this wallet has funded, check the mempool takes it, and
 * only then keep it. Throws a JSONRPCError, having spent nothing, when it
 * cannot be signed or the network refuses it. Inputs listed in `presigned`
 * already carry their input script and are left as they are.
 */
CTransactionRef SignAndSend(CWallet* const pwallet, CMutableTransaction raw_tx, const std::set<size_t>& presigned = {});

#endif // BITCOIN_WALLET_RPCNAMES_H
