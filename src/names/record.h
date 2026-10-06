// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_RECORD_H
#define BITCOIN_NAMES_RECORD_H

#include <key.h>
#include <roster/record.h>
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
 *
 * A CLAIM both registers (after a COMMIT) and renews. A SUBNAME whose key is
 * all zeros removes that subname. Every record but COMMIT is signed with
 * BIP340 under a tag naming the type and the chain; who must have signed it
 * depends on the name's state, so that is checked where the state is known
 * (names/state.h), not here.
 */
namespace names {

enum class NameRecordType : uint8_t {
    COMMIT = 0x06,
    CLAIM = 0x07,
    TRANSFER = 0x08,
    SUBNAME = 0x09,
};

using Salt = std::array<unsigned char, 16>;

struct NameRecord {
    NameRecordType type{NameRecordType::COMMIT};
    //! COMMIT: hides a name, salt and owner until the CLAIM reveals them.
    uint256 commitment;
    //! CLAIM: the owner. TRANSFER: the new owner. SUBNAME: the key it resolves to.
    roster::KeyBytes key{};
    //! CLAIM and TRANSFER: the name. SUBNAME: the root it is under.
    std::string name;
    //! SUBNAME: the part before the dot.
    std::string label;
    //! CLAIM: what made the commitment unguessable.
    Salt salt{};
    //! CLAIM and SUBNAME: an absolute height, as roster expiries are.
    uint32_t expiry_height{0};
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
