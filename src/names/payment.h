// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_PAYMENT_H
#define BITCOIN_NAMES_PAYMENT_H

#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <roster/record.h>
#include <uint256.h>

#include <vector>

/**
 * Paying by name, without a name ever pointing at an address.
 *
 * Design note 001 section 11: a name resolves to a roster key, and a payment
 * must not land on one address that every payer can see - that would link
 * every payment to the name, and to each other. So each payment goes to an
 * address of its own, derived the way stealth addresses are, with two keys:
 *
 *   - the scan key is the roster key K the name resolves to. The payee's node
 *     holds it and uses it to recognise payments. It is hot, on the node.
 *   - the spend key B is a wallet key, published once in a PAYKEY record that
 *     K signs. Only the wallet holding it can spend what arrives.
 *
 * The payer picks a one-time key e and pays to D = B + t·G, where
 * t = H(ECDH(e, K) || B), and puts e·G in a PAYMENT marker in the same
 * transaction. The payee computes the same t from its own k and e·G, finds
 * the output, and spends it with b + t. Nobody else can tell who was paid, or
 * that two payments went to the same person; and someone who steals the
 * roster key can see the payments but not spend them.
 */
namespace names {

/** The marker a payment carries in its OP_RETURN output. */
std::vector<unsigned char> PaymentMarker(const CPubKey& one_time);

/** The one-time key in a transaction's payment marker, if it has one. */
bool ReadPaymentMarker(const CTransaction& tx, CPubKey& one_time_out);

/** The even-Y public key a 32-byte roster key names: what ECDH is done with. */
bool ScanPubKey(const roster::KeyBytes& key, CPubKey& out);

/** Payer: the address a payment to (K, B) is made to, with one-time key `e`. */
bool PaymentDestination(const roster::KeyBytes& scan_key, const CPubKey& spend_key, const CKey& one_time,
                        CPubKey& dest_out);

/** Payee: the tweak t for a payment carrying `one_time`, from its scan key k. */
bool PaymentTweak(const CKey& scan_key, const CPubKey& one_time, const CPubKey& spend_key, uint256& tweak_out);

} // namespace names

#endif // BITCOIN_NAMES_PAYMENT_H
