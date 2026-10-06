// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/commitment.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/block.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace roster {

std::vector<WindowAnnouncement> SelectLive(const std::vector<WindowAnnouncement>& in_chain_order, int at_height,
                                           const std::function<bool(const KeyBytes&)>& revoked)
{
    std::map<KeyBytes, const WindowAnnouncement*> latest;
    std::map<KeyBytes, std::set<std::vector<unsigned char>>> seen;
    for (const WindowAnnouncement& a : in_chain_order) {
        if (!seen[a.key].insert(a.raw).second) continue;
        latest[a.key] = &a;
    }
    std::vector<WindowAnnouncement> out;
    for (const auto& item : latest) {
        if (item.second->expiry <= static_cast<uint32_t>(std::max(at_height, 0))) continue;
        if (revoked && revoked(item.first)) continue;
        out.push_back(*item.second);
    }
    return out;
}

uint256 CommitmentLeaf(const CommitmentEntry& entry)
{
    // The confirming height is committed alongside the record because it is
    // not in the record: §1 leaves out any self-asserted time precisely so the
    // block supplies it. A commitment that omitted it would let a record be
    // proved present without proving when.
    CHashWriter writer = TaggedHash("BPS/roster/leaf/v1");
    ser_writedata32be(writer, entry.height);
    writer.write((const char*)entry.raw.data(), entry.raw.size());
    return writer.GetSHA256();
}

uint256 MerkleRoot(std::vector<CommitmentEntry> entries, bool* duplicate_key)
{
    if (duplicate_key) *duplicate_key = false;
    if (entries.empty()) return uint256();

    std::sort(entries.begin(), entries.end(),
              [](const CommitmentEntry& a, const CommitmentEntry& b) { return a.key < b.key; });

    for (size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].key == entries[i - 1].key) {
            if (duplicate_key) *duplicate_key = true;
            return uint256();
        }
    }

    std::vector<uint256> leaves;
    leaves.reserve(entries.size());
    for (const CommitmentEntry& entry : entries) {
        leaves.push_back(CommitmentLeaf(entry));
    }

    // Keys are unique and each record embeds its own key, so no two leaves can
    // be equal. That is what makes the trailing-leaf duplication in this
    // merkle construction unambiguous here, so the mutation flag has nothing
    // to report and is not consulted.
    return ComputeMerkleRoot(std::move(leaves));
}

std::vector<uint256> CommitmentLeaves(std::vector<CommitmentEntry> entries)
{
    std::sort(entries.begin(), entries.end(),
              [](const CommitmentEntry& a, const CommitmentEntry& b) { return a.key < b.key; });
    std::vector<uint256> leaves;
    leaves.reserve(entries.size());
    for (const CommitmentEntry& entry : entries) leaves.push_back(CommitmentLeaf(entry));
    return leaves;
}

std::vector<uint256> MerkleBranch(std::vector<uint256> leaves, uint32_t index)
{
    std::vector<uint256> branch;
    if (index >= leaves.size()) return branch;
    while (leaves.size() > 1) {
        // The same shape as ComputeMerkleRoot: a lone last node pairs with itself.
        if (leaves.size() & 1) leaves.push_back(leaves.back());
        branch.push_back(leaves[index ^ 1]);
        std::vector<uint256> next;
        next.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) next.push_back(Hash(leaves[i], leaves[i + 1]));
        leaves.swap(next);
        index >>= 1;
    }
    return branch;
}

uint256 RootFromBranch(uint256 leaf, const std::vector<uint256>& branch, uint32_t index)
{
    for (const uint256& sibling : branch) {
        leaf = (index & 1) ? Hash(sibling, leaf) : Hash(leaf, sibling);
        index >>= 1;
    }
    return leaf;
}

void AppendCommitment(CScript& witness_commitment, const uint256& root)
{
    std::vector<unsigned char> push(COMMITMENT_HEADER, COMMITMENT_HEADER + sizeof(COMMITMENT_HEADER));
    push.insert(push.end(), root.begin(), root.end());
    witness_commitment << push;
}

bool ReadCommitment(const CScript& witness_commitment, uint256& root_out)
{
    if (witness_commitment.size() < MINIMUM_WITNESS_COMMITMENT) return false;
    // Past the witness commitment's own push, each further push is a tagged
    // section (BIP325 puts signet's signature here the same way).
    CScript::const_iterator pc = witness_commitment.begin() + MINIMUM_WITNESS_COMMITMENT;
    bool found = false;
    opcodetype opcode;
    std::vector<unsigned char> data;
    while (pc < witness_commitment.end()) {
        if (!witness_commitment.GetOp(pc, opcode, data)) return false;
        if (data.size() != COMMITMENT_PUSH_DATA) continue;
        if (std::memcmp(data.data(), COMMITMENT_HEADER, sizeof(COMMITMENT_HEADER)) != 0) continue;
        if (found) return false;
        std::memcpy(root_out.begin(), data.data() + sizeof(COMMITMENT_HEADER), 32);
        found = true;
    }
    return found;
}

bool GetBlockCommitment(const CBlock& block, uint256& root_out)
{
    const int position = GetWitnessCommitmentIndex(block);
    if (position == NO_WITNESS_COMMITMENT) return false;
    return ReadCommitment(block.vtx[0]->vout[position].scriptPubKey, root_out);
}

} // namespace roster
