// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_KEYSTORE_H
#define BITCOIN_ROSTER_KEYSTORE_H

#include <key.h>
#include <pubkey.h>
#include <roster/record.h>

#include <string>

namespace roster {

/**
 * The node's operational key, loaded from <datadir>/roster.key or created there
 * on first use.
 *
 * Deliberately not a wallet key. §2's central claim is that being discoverable
 * requires no coins, and a wallet-derived key would quietly break it: a node
 * run with -disablewallet could not announce at all. It would also publish the
 * x-only pubkey of an address the operator might receive to, linking roster
 * identity to wallet history for no benefit.
 *
 * The file is unencrypted, which is a considered position rather than an
 * omission. §7 makes this the *operational* key: hot by definition, signing
 * routine announcements, and cheap to replace — compromise is recovered in one
 * block by publishing a DELEGATE for a new key and a REVOKE for this one. The
 * identity key that anchors age and history is a different key, belongs
 * offline, and this file is not it.
 */
bool GetOperationalKey(CKey& key_out, std::string& error);

/** Where the key lives, for logging and for error messages. */
std::string OperationalKeyPath();

/**
 * The ordinary pubkey behind a published roster key.
 *
 * A record carries only the x coordinate, so an address cannot be read off it
 * without a convention for the missing parity byte. The convention is even-Y,
 * which is what GetOperationalKey stores, so this and the peer's own wallet
 * arrive at the same key. That is what lets a relay delegate stake to a peer it
 * has only ever seen on the chain: the peer's staking address is a function of
 * its listing, and nothing extra has to be published or asked for.
 *
 * False when the 32 bytes are not an x coordinate on the curve at all, which a
 * record signature check would already have rejected.
 */
bool StakerPubKeyFromRoster(const KeyBytes& op_key, CPubKey& pubkey_out);

/** The 32 bytes a record publishes for a key. */
KeyBytes KeyBytesOf(const CKey& key);

/**
 * This node's identity key (§7), from <datadir>/roster_identity.key.
 *
 * Unlike the operational key it is never created by itself: a node has an
 * identity only once its operator makes one (createidentity). False with an
 * empty error when there is none.
 *
 * It belongs offline, and an operator who wants it so keeps it elsewhere and
 * passes it to the RPCs that sign with it instead. Kept here, it is a
 * convenience that trades some of what the two tiers buy for not having to.
 */
bool GetIdentityKey(CKey& key_out, std::string& error);

/** Store `key` as this node's identity key. A key it replaces is kept beside it, renamed. */
bool SetIdentityKey(const CKey& key, std::string& error);

std::string IdentityKeyPath();

} // namespace roster

#endif // BITCOIN_ROSTER_KEYSTORE_H
