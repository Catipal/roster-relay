// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_NAMEINDEX_H
#define BITCOIN_INDEX_NAMEINDEX_H

#include <index/base.h>
#include <names/state.h>
#include <sync.h>

#include <atomic>
#include <memory>
#include <set>

/**
 * NameIndex keeps every name record on the chain, with what it burned, and
 * answers who holds which name by replaying them in order (names/state.h).
 *
 * Records are stored as found, not as conclusions: whether a record counted
 * depends on every record before it, and a stored conclusion would have to be
 * unwound on every reorg. Replaying is cheap at the rate names change, and the
 * result is cached until the index moves.
 */
class NameIndex : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;
    const std::string m_chain_id;
    const int m_start_height;
    //! Bumped whenever stored records change, so a cached replay knows it is stale.
    std::atomic<uint64_t> m_generation{0};

    mutable Mutex m_cache_mutex;
    mutable std::shared_ptr<const names::NameState> m_cache GUARDED_BY(m_cache_mutex);
    mutable uint64_t m_cache_generation GUARDED_BY(m_cache_mutex){0};
    mutable int m_cache_height GUARDED_BY(m_cache_mutex){-1};

    //! Coins SELL records have named. A transaction spending one is filed as
    //! a spend, which is how a sale ends and how a purchase is recognised.
    //! Touched only by Init and the index thread.
    std::set<COutPoint> m_sale_coins;

    bool EraseHeight(int height, CDBBatch& batch) const;
    //! Throw away an index written in an older format, so it is rebuilt.
    bool Upgrade();

protected:
    /** A new index starts at the network's start height for names, not at genesis. */
    bool Init() override;
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;
    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;
    BaseIndex::DB& GetDB() const override;
    const char* GetName() const override { return "nameindex"; }

public:
    explicit NameIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);
    virtual ~NameIndex() override;

    /**
     * Who holds which name, as of the last block indexed, and that block's
     * height. False if the database cannot be read.
     */
    bool GetState(std::shared_ptr<const names::NameState>& state_out, int& height_out) const;
};

/** Off in the node, as the roster index is; BPS Relay turns it on. */
static const bool DEFAULT_NAMEINDEX = false;

/** The global name index, or null when -nameindex is off. */
extern std::unique_ptr<NameIndex> g_nameindex;

#endif // BITCOIN_INDEX_NAMEINDEX_H
