// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/commitment.h>

#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/block.h>

#include <algorithm>
#include <cstring>

namespace roster {

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

CScript MakeCommitmentScript(const uint256& root)
{
    CScript script;
    script.resize(COMMITMENT_SCRIPT_SIZE);
    script[0] = OP_RETURN;
    script[1] = 0x24; // push 36 bytes: 4 header + 32 root
    std::memcpy(&script[2], COMMITMENT_HEADER, sizeof(COMMITMENT_HEADER));
    std::memcpy(&script[6], root.begin(), 32);
    return script;
}

int GetCommitmentIndex(const CBlock& block)
{
    int position = NO_ROSTER_COMMITMENT;
    if (block.vtx.empty()) return position;

    const CTransactionRef& coinbase = block.vtx[0];
    for (size_t o = 0; o < coinbase->vout.size(); ++o) {
        const CScript& script = coinbase->vout[o].scriptPubKey;
        if (script.size() < COMMITMENT_SCRIPT_SIZE) continue;
        if (script[0] != OP_RETURN || script[1] != 0x24) continue;
        if (std::memcmp(&script[2], COMMITMENT_HEADER, sizeof(COMMITMENT_HEADER)) != 0) continue;
        position = static_cast<int>(o);
    }
    return position;
}

bool GetCommitmentRoot(const CBlock& block, uint256& root_out)
{
    const int position = GetCommitmentIndex(block);
    if (position == NO_ROSTER_COMMITMENT) return false;

    const CScript& script = block.vtx[0]->vout[position].scriptPubKey;
    std::memcpy(root_out.begin(), &script[6], 32);
    return true;
}

} // namespace roster
