// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_KEYSTORE_H
#define BITCOIN_ROSTER_KEYSTORE_H

#include <key.h>

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

} // namespace roster

#endif // BITCOIN_ROSTER_KEYSTORE_H
