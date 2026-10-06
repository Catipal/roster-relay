// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_LEDGER_H
#define BITCOIN_ROSTER_LEDGER_H

#include <roster/commitment.h>
#include <roster/record.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <memory>
#include <set>
#include <vector>

class CBlock;
class CBlockIndex;
class CChainParams;
class CScript;
namespace Consensus {
struct Params;
}

/**
 * The roster as consensus sees it, kept beside the chain state.
 *
 * Validating the roster commitment (commitment.h) needs the roster at every
 * block, synchronously, on every node that enforces the rule - the roster
 * index cannot serve that: it is optional, it trails the chain on its own
 * thread, and it may be told to start late or forget history. So this keeps,
 * for the active chain, the announcements of the last MAX_TTL + AGE_DEPTH
 * blocks (and a margin for reorgs) and every revocation ever, updated as
 * blocks connect and disconnect, and saved with the chain state.
 *
 * It exists only while the commitment can matter: a deployment that has
 * failed, as DEPLOYMENT_ROSTER has on every network until an activation is
 * scheduled, costs nothing.
 */
namespace roster {

/** Records before this height cannot exist on this network, and are not read. */
int LedgerStart(const std::string& chain_id);

/** Whether blocks after `pprev` must carry the roster commitment. Needs cs_main. */
bool CommitmentActive(const CBlockIndex* pprev, const Consensus::Params& params);

class Ledger
{
public:
    explicit Ledger(const std::string& chain_id);

    /** Apply a block that has just become the tip. */
    void Connect(const CBlock& block, const CBlockIndex* pindex);
    /** Take back the tip block. */
    void Disconnect(const CBlockIndex* pindex);

    /**
     * The root a block at `height` must commit to. False when this ledger
     * cannot say - not loaded, missing blocks, or a reorg deeper than it
     * keeps - in which case the rule is not checked here, as on a node that
     * does not know it.
     */
    bool Root(int height, uint256& root_out) const;

    /** The committed members themselves, for whoever wants to show them. */
    bool Members(int height, std::vector<WindowAnnouncement>& out) const;

    /** Load what Save wrote, if it matches the chain tip; else read the blocks again. */
    void Load(const CChainParams& params);
    /** Write to <datadir>/roster_ledger.dat. Called when the chain state is flushed. */
    void Save() const;

    int Height() const;
    bool Complete() const;

private:
    void Prune();
    bool Window(int height, std::vector<WindowAnnouncement>& out) const;

    const std::string m_chain_id;
    const int m_start;
    mutable Mutex m_mutex;
    uint256 m_tip GUARDED_BY(m_mutex);
    int m_height GUARDED_BY(m_mutex){-1};
    //! Lowest height whose announcements are all still here.
    int m_low GUARDED_BY(m_mutex){0};
    bool m_complete GUARDED_BY(m_mutex){false};
    std::map<int, std::vector<WindowAnnouncement>> m_announcements GUARDED_BY(m_mutex);
    //! Revoked key -> every height it was revoked at. Never pruned.
    std::map<KeyBytes, std::set<int>> m_revoked GUARDED_BY(m_mutex);
};

extern std::unique_ptr<Ledger> g_ledger;

/** Make the ledger at startup, if the deployment can still matter. Needs the chain loaded. */
void InitLedger(const CChainParams& params);

/**
 * The roster root to append to a block built on `pprev`, when the rule is
 * active and the ledger can say. -testrostercorrupt (regtest) spoils it, so
 * a test can show such a block rejected.
 */
bool CommitmentForNewBlock(const CBlockIndex* pprev, const Consensus::Params& params, uint256& root_out);

/** -testrostercorrupt (regtest): a miner that breaks the rule does not check it either. */
bool IgnoringCommitments();

} // namespace roster

#endif // BITCOIN_ROSTER_LEDGER_H
