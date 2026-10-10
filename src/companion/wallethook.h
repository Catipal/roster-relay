// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_WALLETHOOK_H
#define BITCOIN_COMPANION_WALLETHOOK_H

#include <amount.h>
#include <companion/protocol.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <functional>
#include <string>
#include <vector>

/**
 * How the companion service reaches the allowance wallet.
 *
 * The node does not link the wallet, so the wallet installs these when it
 * starts, the way it installs the listing and name publishers. None is called
 * with a companion lock held: each takes the wallet's own locks, and the order
 * is cs_wallet before cs_main.
 *
 * Every function names the wallet it acts on and fails, with `error` set for a
 * person to read, when that wallet is not open or not fit to be an allowance.
 */
namespace companion {

/** A payment built and its coins set aside, not signed and not sent. */
struct PreparedPayment {
    CMutableTransaction tx;
    CAmount amount{0}; //!< what the payee receives
    CAmount fee{0};
    CScript payee_script;
    std::string payee; //!< the address paid
    std::string label; //!< for the wallet's address book: who it was for
};

struct WalletHooks {
    /** Whether `wallet` can serve as an allowance, and its balance if so. */
    std::function<bool(const std::string& wallet, CAmount& balance, CAmount& pending, std::string& error)> status;
    /** A fresh address in `wallet` to be paid at. */
    std::function<bool(const std::string& wallet, std::string& address, std::string& error)> new_address;
    /** The latest transactions, newest first. */
    std::function<bool(const std::string& wallet, size_t skip, size_t count, std::vector<HistoryItem>& out,
                       std::string& error)>
        history;
    /** Build and fund a payment to an address or a name. Its coins stay locked until send or cancel. */
    std::function<bool(const std::string& wallet, const std::string& to, CAmount amount, bool subtract_fee,
                       PreparedPayment& out, std::string& error)>
        prepare;
    /**
     * Sign, check the mempool takes it, keep it. `rejected` is set when the
     * network refused it outright - the one case where nothing can have been
     * spent; any other failure might have.
     */
    std::function<bool(const std::string& wallet, const PreparedPayment& payment, uint256& txid, bool& rejected,
                       std::string& error)>
        send;
    /** Release a prepared payment's coins. */
    std::function<void(const std::string& wallet, const PreparedPayment& payment)> cancel;
};

/** Installed by the wallet at startup. Without it every request says there is no wallet. */
void SetWalletHooks(WalletHooks hooks);
WalletHooks GetWalletHooks();

} // namespace companion

#endif // BITCOIN_COMPANION_WALLETHOOK_H
