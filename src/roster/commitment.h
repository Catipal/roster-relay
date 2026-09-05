// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_COMMITMENT_H
#define BITCOIN_ROSTER_COMMITMENT_H

#include <roster/record.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlock;

/**
 * The roster commitment: a merkle root over the live roster, published in the
 * coinbase in the same shape as the witness commitment.
 *
 * What it buys is narrower than it first appears, and the distinction matters.
 * The roster window is only a few tens of megabytes, so a light client can
 * already download it outright; NODE_ROSTER means it can get it from a pruned
 * peer rather than an archival one. This commitment does not make roster
 * bootstrap *possible* — it makes it *verifiable*, so the server handing over
 * a roster can be hostile and still cannot lie, only withhold.
 *
 * The cost is a different kind of thing from everything else in this design.
 * Once active, every validating node must maintain roster state, MAX_TTL
 * becomes a consensus parameter rather than a policy one, and a disagreement
 * between two implementations about whether a record parses stops being an
 * index quirk and becomes a chain split. Activation is therefore a decision to
 * be taken separately and deliberately, not a consequence of this code
 * existing.
 */
namespace roster {

/**
 * Coinbase commitment prefix, "BPSR". Deliberately distinct from the witness
 * commitment's 0xaa21a9ed so the two outputs can never be confused for one
 * another by an implementation scanning the coinbase.
 */
static constexpr unsigned char COMMITMENT_HEADER[4] = {0x42, 0x50, 0x53, 0x52};

/** OP_RETURN + push(36) + 4-byte header + 32-byte root. */
static constexpr size_t COMMITMENT_SCRIPT_SIZE = 38;

/** Returned by GetCommitmentIndex when the coinbase carries no commitment. */
static constexpr int NO_ROSTER_COMMITMENT = -1;

/** One live roster member, as committed to. */
struct CommitmentEntry {
    KeyBytes key{};
    uint32_t height{0};
    std::vector<unsigned char> raw;
};

/**
 * Merkle root over the live roster.
 *
 * Entries are sorted by key before hashing, so the root is a function of the
 * roster's contents and not of the order a particular implementation happened
 * to walk its database in. This is the whole reason the function takes its
 * argument by value and sorts internally rather than trusting the caller.
 *
 * An empty roster commits to all-zero, which is a value distinct from every
 * possible merkle root and so cannot be confused with a populated one.
 *
 * Duplicate keys are a caller error and are rejected rather than tolerated:
 * the merkle construction here duplicates a lone trailing leaf, which is only
 * safe against CVE-2012-2459-style ambiguity while the leaf set is unique.
 */
uint256 MerkleRoot(std::vector<CommitmentEntry> entries, bool* duplicate_key = nullptr);

/** The leaf hash for one entry. Tagged, so it cannot collide with any other
 *  hash this design computes over the same bytes. */
uint256 CommitmentLeaf(const CommitmentEntry& entry);

/** Build the coinbase output script carrying a root. */
CScript MakeCommitmentScript(const uint256& root);

/** Index of the last roster commitment output in the coinbase, or
 *  NO_ROSTER_COMMITMENT. Last, not first, matching the witness commitment
 *  rule: a miner may only append, so the final one is the authoritative one. */
int GetCommitmentIndex(const CBlock& block);

/** Read the committed root out of a block's coinbase. */
bool GetCommitmentRoot(const CBlock& block, uint256& root_out);

} // namespace roster

#endif // BITCOIN_ROSTER_COMMITMENT_H
