// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_COMMITMENT_H
#define BITCOIN_ROSTER_COMMITMENT_H

#include <roster/record.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <vector>

class CBlock;

/**
 * The roster commitment - the roster's fingerprint: a merkle root over the
 * roster, carried in every block once DEPLOYMENT_ROSTER is active.
 *
 * Where it goes. Not an output of its own: a proof-of-stake coinbase may have
 * one output, or two with a witness commitment (CheckFirstCoinstakeOutput),
 * and relaxing that would be a hard fork. The root is instead one more push
 * in the witness commitment output's script, after the 38 bytes that carry
 * the witness root - the way signet carries its block signature (BIP325). A
 * node that does not know the rule finds the witness commitment where it
 * always did, checks the 32 bytes at offset 6 as it always did, and ignores
 * the rest: so this is a soft fork, and old nodes keep following the chain.
 *
 * What it commits to (BuildCommittedRoster, the ledger): the roster a block
 * at height H sees AGE_DEPTH blocks back - the latest announcement of each
 * key confirmed in [H - AGE_DEPTH - MAX_TTL, H - AGE_DEPTH], unexpired at H,
 * less every key revoked at or below H - AGE_DEPTH, ever. The lag keeps a
 * shallow reorg from changing what is committed, as §9 asks.
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

/** The tag that starts the roster push, "BPSR". Distinct from the witness and signet tags. */
static constexpr unsigned char COMMITMENT_HEADER[4] = {0x42, 0x50, 0x53, 0x52};

/** The push the roster root adds to a witness commitment script: 36 data bytes, header and root. */
static constexpr size_t COMMITMENT_PUSH_DATA = 4 + 32;

/** One announcement in a window, as the selection rule sees it. */
struct WindowAnnouncement {
    KeyBytes key{};
    int height{0};
    uint32_t ordinal{0};
    uint32_t expiry{0};
    std::vector<unsigned char> raw;
    uint256 txid;
    uint32_t vout{0};
};

/**
 * Who is in the roster at `at_height`, given a window's announcements in
 * chain order: for each key, its latest announcement, if that has not expired
 * by `at_height` and the key is not `revoked`. The latest decides even when
 * it ends sooner than an earlier one. An identical copy of an earlier
 * announcement is not later - anyone can pay to publish an old record again,
 * and that must not wind a peer back to an address it has left.
 *
 * Shared by the node's own roster, the snapshot it serves light clients and
 * the commitment in blocks, so the three cannot disagree about the rule.
 * Returned in key order.
 */
std::vector<WindowAnnouncement> SelectLive(const std::vector<WindowAnnouncement>& in_chain_order, int at_height,
                                           const std::function<bool(const KeyBytes&)>& revoked);

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

/** The leaves MerkleRoot hashes, in the order it hashes them: by key. */
std::vector<uint256> CommitmentLeaves(std::vector<CommitmentEntry> entries);

/** The merkle branch for leaf `index`, in the tree ComputeMerkleRoot builds. */
std::vector<uint256> MerkleBranch(std::vector<uint256> leaves, uint32_t index);

/** The root a leaf and its branch lead to. */
uint256 RootFromBranch(uint256 leaf, const std::vector<uint256>& branch, uint32_t index);

/** Append a roster root to a witness commitment script. */
void AppendCommitment(CScript& witness_commitment, const uint256& root);

/**
 * The roster root in a witness commitment script. False when there is none,
 * or more than one: a block must not be able to commit to two rosters.
 */
bool ReadCommitment(const CScript& witness_commitment, uint256& root_out);

/** The roster root a block commits to, from its witness commitment output. */
bool GetBlockCommitment(const CBlock& block, uint256& root_out);

} // namespace roster

#endif // BITCOIN_ROSTER_COMMITMENT_H
