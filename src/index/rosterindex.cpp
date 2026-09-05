// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/rosterindex.h>

#include <chain.h>
#include <chainparams.h>
#include <dbwrapper.h>
#include <primitives/block.h>
#include <roster/extract.h>
#include <script/script.h>
#include <util/system.h>
#include <validation.h>

#include <algorithm>
#include <set>

std::unique_ptr<RosterIndex> g_rosterindex;

namespace {

constexpr uint8_t DB_ROSTER_BY_HEIGHT = 'r';
constexpr uint8_t DB_ROSTER_BY_KEY = 'k';

/**
 * Heights and ordinals are written big-endian so that LevelDB's lexicographic
 * key order is also chronological order. The usual little-endian serialisation
 * would interleave heights and make a window scan impossible.
 */
struct DBHeightKey {
    int height{0};
    uint32_t ordinal{0};

    DBHeightKey() = default;
    explicit DBHeightKey(int height_in, uint32_t ordinal_in = 0)
        : height(height_in), ordinal(ordinal_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ROSTER_BY_HEIGHT);
        ser_writedata32be(s, height);
        ser_writedata32be(s, ordinal);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix = ser_readdata8(s);
        if (prefix != DB_ROSTER_BY_HEIGHT) {
            throw std::ios_base::failure("Invalid prefix for roster index height key");
        }
        height = ser_readdata32be(s);
        ordinal = ser_readdata32be(s);
    }
};

/** Key ‖ height ‖ ordinal, so one identity's history reads back in order. */
struct DBKeyKey {
    roster::KeyBytes key{};
    int height{0};
    uint32_t ordinal{0};

    DBKeyKey() = default;
    DBKeyKey(const roster::KeyBytes& key_in, int height_in, uint32_t ordinal_in)
        : key(key_in), height(height_in), ordinal(ordinal_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_ROSTER_BY_KEY);
        s.write((const char*)key.data(), key.size());
        ser_writedata32be(s, height);
        ser_writedata32be(s, ordinal);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint8_t prefix = ser_readdata8(s);
        if (prefix != DB_ROSTER_BY_KEY) {
            throw std::ios_base::failure("Invalid prefix for roster index key key");
        }
        s.read((char*)key.data(), key.size());
        height = ser_readdata32be(s);
        ordinal = ser_readdata32be(s);
    }
};

//! The key a record is filed under. Identity plumbing is filed under the
//! identity it concerns, so that walking a key's history returns the
//! delegations and rotations that shaped it, not only its announcements.
const roster::KeyBytes& IndexKeyFor(const roster::Record& rec)
{
    switch (rec.type) {
    case roster::RecordType::ANNOUNCE:
    case roster::RecordType::REVOKE:
        return rec.op_key;
    case roster::RecordType::DELEGATE:
    case roster::RecordType::ROTATE:
    case roster::RecordType::VETO:
        return rec.id_key;
    }
    return rec.op_key;
}

} // namespace

bool RosterEntry::Parse(roster::Record& out) const
{
    return roster::ParseRecord(raw, out) == roster::ParseError::OK;
}

/** Access to the roster index database (indexes/rosterindex/) */
class RosterIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory, bool f_wipe)
        : BaseIndex::DB(GetDataDir() / "indexes" / "rosterindex", n_cache_size, f_memory, f_wipe)
    {
    }
};

RosterIndex::RosterIndex(size_t n_cache_size, bool f_memory, bool f_wipe, int start_height, int window)
    : m_db(MakeUnique<RosterIndex::DB>(n_cache_size, f_memory, f_wipe)),
      m_chain_id(Params().NetworkIDString()),
      m_start_height(start_height),
      m_window(window)
{
}

void RosterIndex::EraseHeight(int height, CDBBatch& batch) const
{
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(DBHeightKey(height, 0));

    while (it->Valid()) {
        DBHeightKey key;
        if (!it->GetKey(key) || key.height != height) break;

        // The by-key entry is filed under the record's own key, so it has to
        // be read back to be found. Leaving it behind would strand an entry
        // that ReadRecordsForKey would then try to resolve against a height
        // entry that no longer exists.
        RosterEntry entry;
        roster::Record rec;
        if (it->GetValue(entry) && entry.Parse(rec)) {
            batch.Erase(DBKeyKey(IndexKeyFor(rec), key.height, key.ordinal));
        }
        batch.Erase(key);
        it->Next();
    }
}

void RosterIndex::PruneBelow(int threshold, CDBBatch& batch) const
{
    if (threshold <= 0) return;

    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(DBHeightKey(0, 0));

    while (it->Valid()) {
        DBHeightKey key;
        // Heights are big-endian, so the first key at or above the threshold
        // ends the scan: everything after it is newer. In steady state this
        // costs one seek and nothing else.
        if (!it->GetKey(key) || key.height >= threshold) break;

        RosterEntry entry;
        roster::Record rec;
        if (it->GetValue(entry) && entry.Parse(rec)) {
            batch.Erase(DBKeyKey(IndexKeyFor(rec), key.height, key.ordinal));
        }
        batch.Erase(key);
        it->Next();
    }
}

bool RosterIndex::Init()
{
    if (m_start_height > 0) {
        CBlockLocator existing;
        if (!m_db->ReadBestBlock(existing)) {
            LOCK(cs_main);
            const CBlockIndex* start = ::ChainActive()[m_start_height - 1];
            if (start) {
                // Declaring the block before m_start_height as already indexed
                // is true in the only sense that matters -- there is nothing
                // there to index -- and it is how BaseIndex is told where to
                // resume without reaching into its private state.
                CDBBatch batch(*m_db);
                m_db->WriteBestBlock(batch, ::ChainActive().GetLocator(start));
                m_db->WriteBatch(batch);
                LogPrintf("rosterindex: starting at height %d, skipping %d earlier blocks\n",
                          m_start_height, m_start_height);
            } else {
                LogPrintf("rosterindex: -rosterindexstart=%d is beyond the current tip, "
                          "starting from genesis instead\n", m_start_height);
            }
        }
    }
    return BaseIndex::Init();
}

RosterIndex::~RosterIndex() = default;

BaseIndex::DB& RosterIndex::GetDB() const { return *m_db; }

bool RosterIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDBBatch batch(*m_db);
    uint32_t ordinal = 0;

    // Clear anything already filed at this height before writing. During a
    // normal sync there is nothing to clear; after a reorg the height is being
    // rewritten, and a replacement block with fewer records would otherwise
    // leave the surplus entries of its predecessor behind. Making the write
    // idempotent is cheaper than reasoning about which reorgs can do that.
    EraseHeight(pindex->nHeight, batch);

    for (const CTransactionRef& tx : block.vtx) {
        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            std::vector<unsigned char> payload;
            if (!roster::ExtractOpReturnPayload(tx->vout[n].scriptPubKey, payload)) continue;

            roster::Record rec;
            if (roster::ParseRecord(payload, rec) != roster::ParseError::OK) continue;

            // An expiry outside the window would escape the bounded scan that
            // BuildRoster relies on, so it is rejected here rather than left
            // for every reader to notice.
            if (rec.type == roster::RecordType::ANNOUNCE ||
                rec.type == roster::RecordType::DELEGATE) {
                if (!roster::ExpiryInRange(rec.expiry_height, pindex->nHeight)) continue;
            }

            if (!roster::VerifyRecord(rec, payload, m_chain_id)) continue;

            RosterEntry entry;
            entry.raw = std::move(payload);
            entry.height = pindex->nHeight;
            entry.txid = tx->GetHash();
            entry.vout = n;

            batch.Write(DBHeightKey(pindex->nHeight, ordinal), entry);
            batch.Write(DBKeyKey(IndexKeyFor(rec), pindex->nHeight, ordinal), uint8_t{1});
            ++ordinal;
        }
    }

    // Drop history that has fallen out of the retention window. Doing it here
    // rather than in a sweep keeps the work proportional to one block: heights
    // advance one at a time, so in steady state this finds a single height's
    // worth of entries, or none.
    bool pruned = false;
    if (m_window > 0 && pindex->nHeight > m_window) {
        const int threshold = pindex->nHeight - m_window;
        PruneBelow(threshold, batch);
        pruned = true;
    }

    // Blocks carrying no records are the overwhelming majority; do not pay a
    // write for them unless the batch has erasures to flush.
    if (ordinal == 0 && !pruned && batch.SizeEstimate() == 0) return true;
    return m_db->WriteBatch(batch);
}

bool RosterIndex::ReadRecordsAtHeight(int height, std::vector<RosterEntry>& out) const
{
    out.clear();
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(DBHeightKey(height, 0));

    while (it->Valid()) {
        DBHeightKey key;
        if (!it->GetKey(key) || key.height != height) break;

        RosterEntry entry;
        if (!it->GetValue(entry)) return false;
        out.push_back(std::move(entry));
        it->Next();
    }
    return true;
}

bool RosterIndex::ReadRecordsForKey(const roster::KeyBytes& key, std::vector<RosterEntry>& out) const
{
    out.clear();
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(DBKeyKey(key, 0, 0));

    while (it->Valid()) {
        DBKeyKey found;
        if (!it->GetKey(found) || found.key != key) break;

        RosterEntry entry;
        if (m_db->Read(DBHeightKey(found.height, found.ordinal), entry)) {
            out.push_back(std::move(entry));
        }
        it->Next();
    }
    return true;
}

bool RosterIndex::BuildRoster(int tip_height, std::map<roster::KeyBytes, RosterEntry>& out) const
{
    out.clear();
    if (tip_height < 0) return true;

    const int start = std::max(0, tip_height - static_cast<int>(roster::MAX_TTL));

    // Revocation is terminal, so it is collected first and applied to the whole
    // window regardless of ordering. Scanning only the window is sufficient
    // rather than merely convenient: an announcement cannot outlive MAX_TTL, so
    // a revocation older than the window has nothing left to revoke.
    std::set<roster::KeyBytes> revoked;
    std::vector<std::pair<roster::KeyBytes, RosterEntry>> live;

    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(DBHeightKey(start, 0));

    while (it->Valid()) {
        DBHeightKey key;
        if (!it->GetKey(key)) break;
        if (key.height > tip_height) break;

        RosterEntry entry;
        if (!it->GetValue(entry)) return false;

        roster::Record rec;
        if (entry.Parse(rec)) {
            if (rec.type == roster::RecordType::REVOKE) {
                revoked.insert(rec.op_key);
            } else if (rec.type == roster::RecordType::ANNOUNCE) {
                // Records are visited in height order, so a later announcement
                // simply overwrites an earlier one for the same key.
                if (rec.expiry_height > static_cast<uint32_t>(tip_height)) {
                    live.emplace_back(rec.op_key, std::move(entry));
                }
            }
        }
        it->Next();
    }

    for (auto& pair : live) {
        if (revoked.count(pair.first)) continue;
        out[pair.first] = std::move(pair.second);
    }
    return true;
}
