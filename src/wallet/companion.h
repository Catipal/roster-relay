// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_COMPANION_H
#define BITCOIN_WALLET_COMPANION_H

#include <companion/wallethook.h>

/**
 * The wallet half of the phone companion: an allowance wallet that the home
 * node spends from for a paired phone. Installed with companion::SetWalletHooks.
 */
companion::WalletHooks MakeCompanionWalletHooks();

#endif // BITCOIN_WALLET_COMPANION_H
