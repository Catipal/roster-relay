// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_NAMEPAY_H
#define BITCOIN_WALLET_NAMEPAY_H

#include <primitives/transaction.h>

#include <string>

class CWallet;

/**
 * The receiving half of paying by name (names/payment.h).
 *
 * A wallet that takes payments by name keeps the spend keys it published,
 * marked in its address book. Every transaction the wallet is shown is looked
 * at for a payment marker before the wallet decides whether it is its own;
 * when there is one, the wallet works out where a payment to each of its spend
 * keys would have gone, and if an output pays there, adds that address - with
 * its private key when the wallet is unlocked, watch-only until it is. So the
 * payment is the wallet's own by the time the wallet looks.
 */
namespace namepay {

/** Address book data on a spend key this wallet published. */
extern const std::string SPEND_KEY_TAG;
/** Address book data on each address paid by name: the tweak, then the spend key, in hex. */
extern const std::string PAYMENT_TAG;
/** The label a payment's address gets. */
extern const std::string PAYMENT_LABEL;

/** Pick up a payment by name in `tx`, if it has one for this wallet. Needs cs_wallet. */
void ScanTransaction(CWallet& wallet, const CTransaction& tx);

/** Take the private keys of payments that arrived while the wallet was locked. */
void ImportPending(CWallet& wallet);

} // namespace namepay

#endif // BITCOIN_WALLET_NAMEPAY_H
