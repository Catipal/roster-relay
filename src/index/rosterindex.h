// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_ROSTERINDEX_H
#define BITCOIN_INDEX_ROSTERINDEX_H

#include <index/base.h>
#include <roster/record.h>
#include <serialize.h>
#include <uint256.h>

#include <map>
#include <memory>
#include <vector>

/**
 * One indexed record, together with where on the chain it was found.
 *
 * The record is kept as the raw OP_RETURN payload rather than as a parsed
 * struct, and re-parsed on read. That costs a little CPU and buys the thing
 * worth having: <em>one</em> definition of the wire format. A second
 * serialiser for the parsed form would be a place for the two to drift apart,
 * and a database that disagrees with the chain about what a record says is a
 * worse problem than any parse cost.
 */
struct RosterEntry {
    std::vector<unsigned char> raw;
    int32_t height{0};
    uint256 txid;
    uint32_t vout{0};

    SERIALIZE_METHODS(RosterEntry, obj) { READWRITE(obj.raw, obj.height, obj.txid, obj.vout); }

    /** Re-parse the stored bytes. Always succeeds for entries the index wrote. */
    bool Parse(roster::Record& out) const;
};

/**
 * RosterIndex scans every block for peer roster records and stores those that
 * are structurally valid, in range, and correctly signed.
 *
 * Two orderings are maintained, because the two questions asked of a roster
 * have nothing in common:
 *
 *   - by height, so the live set over the rolling window of §5 can be built by
 *     a bounded scan that never grows with the chain;
 *   - by key, so one identity's announcement history — its age chain — can be
 *     walked without touching the blocks in between.
 *
 * Signature verification happens here rather than in the consumer. An index
 * holding unverified records is a trap: every reader would have to remember to
 * check, and one that forgets has a silent authentication bypass. Records that
 * fail are simply not stored, so anything the index returns has already been
 * authenticated against the key it names.
 */
class RosterIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    //! Chain id folded into the BIP340 tag, so a record signed for another
    //! network cannot be replayed onto this one. Captured once at construction.
    const std::string m_chain_id;

    //! First height worth scanning. See the constructor.
    const int m_start_height;

    //! Blocks of history to retain, or 0 to keep everything. See the constructor.
    const int m_window;

    //! Remove both key families for one height. Makes WriteBlock idempotent,
    //! which is what keeps the index correct across a reorg.
    void EraseHeight(int height, CDBBatch& batch) const;

    //! Drop every entry below `threshold`.
    void PruneBelow(int threshold, CDBBatch& batch) const;

protected:
    /**
     * Seed the index's stored locator so a first run begins at m_start_height
     * rather than at genesis.
     *
     * BaseIndex starts from whatever block its database says it last indexed,
     * and from genesis when that is unset. That default suits txindex, which
     * genuinely wants all history. It suits a roster index badly: records
     * cannot exist before the feature ships, so on an established chain the
     * default spends a long scan proving that the first million-odd blocks
     * contain nothing.
     */
    bool Init() override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "rosterindex"; }

public:
    /**
     * @param start_height  First height to scan. 0 means genesis, which is
     *   complete but wasteful on a chain older than the feature. Setting it
     *   above the height at which records first became possible would silently
     *   miss them, so it is an explicit operator choice rather than a guess
     *   the index makes for itself.
     *
     * @param window  Blocks of history to retain, or 0 to keep everything.
     *   The live roster needs only the last MAX_TTL blocks (§5), so a windowed
     *   index is bounded rather than ever-growing. What it gives up is serving
     *   another party's age proofs, which is safe to give up because those are
     *   merkle inclusion proofs against headers that any untrusted party can
     *   supply — the chain is the authority for age, not this index.
     *
     *   Archival by default: an index that quietly discards history would make
     *   age queries wrong rather than slow.
     */
    explicit RosterIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false,
                         int start_height = 0, int window = 0);

    // Declared because this class holds a unique_ptr to an incomplete type.
    virtual ~RosterIndex() override;

    /** Every record confirmed at one height, in the order they appear in the block. */
    bool ReadRecordsAtHeight(int height, std::vector<RosterEntry>& out) const;

    /** Every record ever stored for one key, oldest first. This is the age chain. */
    bool ReadRecordsForKey(const roster::KeyBytes& key, std::vector<RosterEntry>& out) const;

    /**
     * The live roster as of `tip_height`, keyed by operational key.
     *
     * Scans the window [tip_height - MAX_TTL, tip_height] only — never the
     * whole chain — which is what keeps a cold roster build O(MAX_TTL) rather
     * than O(chain), the property §5 is built around.
     */
    bool BuildRoster(int tip_height, std::map<roster::KeyBytes, RosterEntry>& out) const;
};

/**
 * Off by default. The roster is optional to every existing use of the node,
 * and an index nobody asked for is disk and sync time spent on nothing.
 */
static const bool DEFAULT_ROSTERINDEX = false;

/** The global roster index, or null when -rosterindex is not enabled. */
extern std::unique_ptr<RosterIndex> g_rosterindex;

#endif // BITCOIN_INDEX_ROSTERINDEX_H
