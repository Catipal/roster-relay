// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_RECORD_H
#define BITCOIN_NAMES_RECORD_H

#include <amount.h>
#include <key.h>
#include <primitives/transaction.h>
#include <roster/record.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <string>
#include <vector>

/**
 * Name records: the on-chain half of names.
 *
 * Same envelope as roster records - "BPS", then version and type in one byte,
 * carried alone in an OP_RETURN - with type numbers the roster does not use,
 * so a roster reader skips them and a name reader skips announcements. A
 * record that pays carries its price as the value of that same OP_RETURN
 * output, which nobody can spend: the coins are burned.
 *
 *   COMMIT    hdr || commitment(32)                                            36 B
 *   CLAIM     hdr || owner(32) || len || name || salt(16) || expiry(4) || sig 121-153 B
 *   TRANSFER  hdr || len || name || new_owner(32) || sig(64)                  104-133 B
 *   SUBNAME   hdr || len || root || len || label || key(32) || expiry || sig  110-170 B
 *   SELL      hdr || len || name || coin(36) || payout_value(8) ||
 *             len || payout || len || coin_sig || sig(64)                     up to 245 B
 *   BUY       hdr || buyer(32) || len || name || expiry(4) || sig(64)         108-137 B
 *
 * A CLAIM both registers (after a COMMIT) and renews. A SUBNAME whose key is
 * all zeros removes that subname. Every record but COMMIT is signed with
 * BIP340 under a tag naming the type and the chain; who must have signed it
 * depends on the name's state, so that is checked where the state is known
 * (names/state.h), not here.
 *
 * SELL and BUY let a holder put a name up for sale and anyone buy it at once,
 * with the seller offline. The seller sets aside a small coin (names/sale.h)
 * and signs, in the SELL record, a spend of it that is only valid in a
 * transaction paying `payout_value` to `payout` (SIGHASH_SINGLE |
 * ANYONECANPAY). A buyer spends that coin and publishes a BUY in the same
 * transaction, so paying and taking the name are one transaction: either both
 * happen or neither does, and since the coin can be spent once, two buyers
 * cannot both pay.
 */
namespace names {

enum class NameRecordType : uint8_t {
    COMMIT = 0x06,
    CLAIM = 0x07,
    TRANSFER = 0x08,
    SUBNAME = 0x09,
    SELL = 0x0a,
    BUY = 0x0b,
};

/** Longest payout script a SELL carries: a P2PKH, which is what this wallet hands out. */
static constexpr size_t MAX_PAYOUT_SCRIPT = 25;
/** Longest DER signature plus its sighash byte. */
static constexpr size_t MAX_COIN_SIG = 73;

using Salt = std::array<unsigned char, 16>;

struct NameRecord {
    NameRecordType type{NameRecordType::COMMIT};
    //! COMMIT: hides a name, salt and owner until the CLAIM reveals them.
    uint256 commitment;
    //! CLAIM: the owner. TRANSFER: the new owner. SUBNAME: the key it resolves to. BUY: the buyer.
    roster::KeyBytes key{};
    //! CLAIM, TRANSFER, SELL and BUY: the name. SUBNAME: the root it is under.
    std::string name;
    //! SUBNAME: the part before the dot.
    std::string label;
    //! CLAIM: what made the commitment unguessable.
    Salt salt{};
    //! CLAIM, SUBNAME and BUY: an absolute height, as roster expiries are.
    uint32_t expiry_height{0};
    //! SELL: the coin set aside for the sale, which a buyer spends.
    COutPoint coin;
    //! SELL: what the buyer's transaction pays the seller, coin value included.
    CAmount payout_value{0};
    //! SELL: where it is paid.
    CScript payout;
    //! SELL: the seller's signature spending `coin`, SIGHASH_SINGLE | ANYONECANPAY.
    std::vector<unsigned char> coin_sig;
    std::array<unsigned char, 64> sig{};
};

/** Structural parse; names must already be in their one valid spelling. */
bool ParseNameRecord(Span<const unsigned char> raw, NameRecord& out);

/** Round-trips exactly with ParseNameRecord. */
std::vector<unsigned char> SerializeNameRecord(const NameRecord& rec);

/** What a COMMIT publishes: SHA256 of a tag, the name, the salt and the owner. */
uint256 Commitment(const std::string& name, const Salt& salt, const roster::KeyBytes& owner);

/** The hash a record's signature covers: everything before the signature, tagged by type and chain. */
uint256 NameSigHash(Span<const unsigned char> raw, NameRecordType type, const std::string& chain_id);

/** Sign `rec` with `key` and return its bytes, ready to publish. */
bool SignNameRecord(const CKey& key, NameRecord& rec, const std::string& chain_id,
                    std::vector<unsigned char>& raw_out);

/** Whether `signer` signed this record, as published in `raw`. */
bool VerifyNameRecord(const NameRecord& rec, Span<const unsigned char> raw,
                      const roster::KeyBytes& signer, const std::string& chain_id);

} // namespace names

#endif // BITCOIN_NAMES_RECORD_H
