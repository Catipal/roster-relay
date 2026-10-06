// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPCNAMES_H
#define BITCOIN_WALLET_RPCNAMES_H

#include <names/registrar.h>
#include <uint256.h>

#include <string>

class RPCHelpMan;

/** The wallet half of names: everything that spends. Lookups are node RPCs (rpc/names.cpp). */
RPCHelpMan registername();
RPCHelpMan renewname();
RPCHelpMan transfername();
RPCHelpMan setsubname();
RPCHelpMan sellname();
RPCHelpMan cancelnamesale();
RPCHelpMan buyname();

/** Sends a matured registration's claim. Installed with names::SetClaimPublisher. */
bool PublishNameClaim(const names::PendingRegistration& pending, uint256& txid_out, std::string& error_out);

#endif // BITCOIN_WALLET_RPCNAMES_H
