// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_SALE_H
#define BITCOIN_NAMES_SALE_H

#include <amount.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <string>
#include <vector>

/**
 * Selling a name while the seller is offline.
 *
 * A name is not a coin, so on its own nothing would stop two buyers both
 * paying for it, or a seller taking the money and keeping the name. A coin
 * fixes both. The seller sets one aside - the sale coin - and signs a spend of
 * it with SIGHASH_SINGLE | ANYONECANPAY: valid in any transaction whose
 * first output pays the asking price to the seller, whatever else the
 * transaction holds. That signature is published in the SELL record, so the
 * chain itself is the shop window. A buyer adds the sale coin as the first
 * input, the payment as the first output, a BUY record and their own coins;
 * the name moves only if that same transaction spent the sale coin (names/
 * state.h). The coin can be spent once, so one buyer wins and every other
 * buyer's transaction is simply invalid and costs them nothing; and while the
 * coin is unspent the seller cannot transfer or re-list the name, so the
 * seller cannot take the payment and keep the name either.
 *
 * The sale coin pays to a key derived from the node's roster key and the
 * sale, never to a wallet key. A wallet that held it would spend it in an
 * ordinary payment or stake it, and either would quietly take the name off
 * sale.
 */
namespace names {

/** What the seller sets aside. It goes to the buyer, so the payout adds it back. */
static constexpr CAmount SALE_COIN_VALUE = 10000;

/** How the seller signs the sale coin: this input, and the output at its index, only. */
static constexpr int SALE_SIGHASH = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY;

/** The sale coin's script: pay-to-pubkey, so spending it needs only the signature. */
CScript SaleCoinScript(const CPubKey& pubkey);

/** The key a sale coin pays to, derived from the holder's key, the name and the payout script. */
bool SaleKey(const CKey& owner_key, const std::string& name, const CScript& payout, CKey& key_out);

/**
 * The transaction shape the seller signs: the sale coin as input 0, the
 * payout as output 0, version 2, no lock time. A buyer's transaction must
 * keep those four things; everything else is theirs.
 */
CMutableTransaction SaleTemplate(const COutPoint& coin, CAmount payout_value, const CScript& payout);

/** Sign the sale coin's spend for a sale paying `payout_value` to `payout`. */
bool SignSale(const CKey& sale_key, const COutPoint& coin, const CScript& coin_script, CAmount payout_value,
              const CScript& payout, std::vector<unsigned char>& sig_out);

/** The input script that spends the sale coin with that signature. */
CScript SaleScriptSig(const std::vector<unsigned char>& sig);

/**
 * Whether a published sale can actually be bought: the signature spends this
 * coin, as it stands in the UTXO set, in a transaction paying the payout.
 */
bool CheckSale(const COutPoint& coin, const CTxOut& coin_out, CAmount payout_value, const CScript& payout,
               const std::vector<unsigned char>& sig);

} // namespace names

#endif // BITCOIN_NAMES_SALE_H
