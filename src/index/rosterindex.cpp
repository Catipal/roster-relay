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
//! Revoked key -> height of its first REVOKE. Never pruned.
constexpr uint8_t DB_REVOKED = 'x';
constexpr uint8_t DB_VERSION = 'V';
//! 2: records filed under every key they name; permanent revocations.
constexpr int32_t INDEX_VERSION = 2;
//! BaseIndex's key for the last block indexed (index/base.cpp).
constexpr char DB_BEST_BLOCK = 'B';

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

struct DBRevokedKey {
    roster::KeyBytes key{};

    DBRevokedKey() = default;
    explicit DBRevokedKey(const roster::KeyBytes& key_in) : key(key_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_REVOKED);
        s.write((const char*)key.data(), key.size());
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        if (ser_readdata8(s) != DB_REVOKED) throw std::ios_base::failure("Invalid prefix for revoked key");
        s.read((char*)key.data(), key.size());
    }
};

//! The keys a record is filed under: every key it names, so that walking a
//! key's history returns the delegations, rotations and vetoes that shaped
//! it, not only its announcements.
std::vector<roster::KeyBytes> IndexKeysFor(const roster::Record& rec)
{
    std::vector<roster::KeyBytes> keys = roster::RecordKeys(rec);
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    return keys;
}

} // namespace

bool RosterEntry::Parse(roster::Record& out) const
{
    return roster::ParseRecord(raw, out) == roster::ParseError::OK;
}

bool RosterEntry::Held(roster::HeldRecord& out) const
{
    if (!Parse(out.rec)) return false;
    out.height = height;
    out.ordinal = ordinal;
    out.txid = txid;
    out.vout = vout;
    return true;
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

void RosterIndex::Notify(const roster::Record& rec, const std::vector<unsigned char>& raw, int height, bool reorged_out)
{
    std::function<void(const roster::Record&, const std::vector<unsigned char>&, int, bool)> observer;
    {
        LOCK(m_observer_mutex);
        observer = m_observer;
    }
    if (observer) observer(rec, raw, height, reorged_out);
}

void RosterIndex::SetObserver(std::function<void(const roster::Record&, const std::vector<unsigned char>&, int, bool)> f)
{
    LOCK(m_observer_mutex);
    m_observer = std::move(f);
}

void RosterIndex::EraseHeight(int height, CDBBatch& batch)
{
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(DBHeightKey(height, 0));

    std::vector<std::pair<roster::Record, std::vector<unsigned char>>> removed;
    while (it->Valid()) {
        DBHeightKey key;
        if (!it->GetKey(key) || key.height != height) break;

        // The by-key entries are filed under the record's own keys, so it has
        // to be read back to find them. Leaving one behind would strand an
        // entry that ReadRecordsForKey would then try to resolve against a
        // height entry that no longer exists.
        RosterEntry entry;
        roster::Record rec;
        if (it->GetValue(entry) && entry.Parse(rec)) {
            for (const roster::KeyBytes& k : IndexKeysFor(rec)) batch.Erase(DBKeyKey(k, key.height, key.ordinal));
            removed.emplace_back(rec, entry.raw);
        }
        batch.Erase(key);
        it->Next();
    }
    it.reset();

    for (const auto& item : removed) {
        const roster::Record& rec = item.first;
        if (rec.type == roster::RecordType::REVOKE) {
            // The first revocation is the one kept; if it is the one going,
            // fall back to the next one the key has, if any.
            int32_t first = -1;
            if (m_db->Read(DBRevokedKey(rec.op_key), first) && first == height) {
                std::vector<RosterEntry> history;
                int next = -1;
                if (ReadRecordsForKey(rec.op_key, history)) {
                    for (const RosterEntry& e : history) {
                        roster::Record r;
                        if (e.height != height && e.Parse(r) && r.type == roster::RecordType::REVOKE &&
                            (next < 0 || e.height < next)) {
                            next = e.height;
                        }
                    }
                }
                if (next < 0) {
                    batch.Erase(DBRevokedKey(rec.op_key));
                } else {
                    batch.Write(DBRevokedKey(rec.op_key), (int32_t)next);
                }
            }
        }
        Notify(rec, item.second, height, /* reorged_out */ true);
    }
}

bool RosterIndex::Upgrade()
{
    int32_t version = 0;
    if (m_db->Read(DB_VERSION, version) && version == INDEX_VERSION) return true;
    CDBBatch batch(*m_db);
    bool had_entries = false;
    // Each family is read with its own key type: GetKey fails at the first
    // key of another family, which ends the loop.
    {
        std::unique_ptr<CDBIterator> it(m_db->NewIterator());
        for (it->Seek(DBHeightKey(0, 0)); it->Valid(); it->Next()) {
            DBHeightKey key;
            if (!it->GetKey(key)) break;
            batch.Erase(key);
            had_entries = true;
        }
    }
    {
        std::unique_ptr<CDBIterator> it(m_db->NewIterator());
        for (it->Seek(DBKeyKey(roster::KeyBytes{}, 0, 0)); it->Valid(); it->Next()) {
            DBKeyKey key;
            if (!it->GetKey(key)) break;
            batch.Erase(key);
            had_entries = true;
        }
    }
    CBlockLocator existing;
    if (had_entries || m_db->ReadBestBlock(existing)) {
        LogPrintf("rosterindex: written in an older format; rebuilding it\n");
        batch.Erase(DB_BEST_BLOCK);
    }
    batch.Write(DB_VERSION, INDEX_VERSION);
    return m_db->WriteBatch(batch, true);
}

void RosterIndex::PruneBelow(int threshold, CDBBatch& batch) const
{
    // Revocations are kept: a key revoked a year ago is revoked still.
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
            for (const roster::KeyBytes& k : IndexKeysFor(rec)) batch.Erase(DBKeyKey(k, key.height, key.ordinal));
        }
        batch.Erase(key);
        it->Next();
    }
}

bool RosterIndex::Init()
{
    if (!Upgrade()) return false;
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
    // Skip history below the configured start, checked here rather than only
    // in Init(). Init() seeds the stored locator by resolving the height
    // against the active chain, which works when the index is switched on
    // afterwards but not during -reindex or an initial sync: the chain is
    // empty at that point, the height does not resolve, and the start silently
    // degrades to genesis -- precisely when skipping matters most. This check
    // needs no chain state and so holds in every case.
    if (m_start_height > 0 && pindex->nHeight < m_start_height) return true;

    CDBBatch batch(*m_db);
    uint32_t ordinal = 0;
    std::vector<std::pair<roster::Record, std::vector<unsigned char>>> written;

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
            for (const roster::KeyBytes& k : IndexKeysFor(rec)) {
                batch.Write(DBKeyKey(k, pindex->nHeight, ordinal), uint8_t{1});
            }
            if (rec.type == roster::RecordType::REVOKE) {
                int32_t first = -1;
                if (!m_db->Read(DBRevokedKey(rec.op_key), first) || first > pindex->nHeight) {
                    batch.Write(DBRevokedKey(rec.op_key), (int32_t)pindex->nHeight);
                }
            }
            written.emplace_back(rec, entry.raw);
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
    if (!m_db->WriteBatch(batch)) return false;
    for (const auto& item : written) Notify(item.first, item.second, pindex->nHeight, /* reorged_out */ false);
    return true;
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
            entry.ordinal = found.ordinal;
            out.push_back(std::move(entry));
        }
        it->Next();
    }
    return true;
}

bool RosterIndex::ReadHistory(const roster::KeyBytes& key, std::vector<roster::HeldRecord>& out) const
{
    out.clear();
    std::vector<RosterEntry> entries;
    if (!ReadRecordsForKey(key, entries)) return false;
    for (const RosterEntry& e : entries) {
        roster::HeldRecord h;
        if (e.Held(h)) out.push_back(std::move(h));
    }
    return true;
}

bool RosterIndex::ReadIdentityCluster(const roster::KeyBytes& key, std::vector<roster::HeldRecord>& out) const
{
    out.clear();
    std::set<roster::KeyBytes> seen{key};
    std::vector<roster::KeyBytes> queue{key};
    std::set<std::pair<int, uint32_t>> have;
    // Bounded: an identity rotated a hundred times is not a thing to follow.
    while (!queue.empty() && seen.size() <= 100) {
        const roster::KeyBytes cur = queue.back();
        queue.pop_back();
        std::vector<roster::HeldRecord> history;
        if (!ReadHistory(cur, history)) return false;
        for (roster::HeldRecord& h : history) {
            if (h.rec.type == roster::RecordType::ROTATE) {
                for (const roster::KeyBytes& k : {h.rec.id_key, h.rec.new_id_key}) {
                    if (seen.insert(k).second) queue.push_back(k);
                }
            }
            // Only what an identity signed or what names it as one shapes it;
            // announcements filed under an identity key do not.
            if (h.rec.type == roster::RecordType::ANNOUNCE || h.rec.type == roster::RecordType::REVOKE) continue;
            if (have.insert({h.height, h.ordinal}).second) out.push_back(std::move(h));
        }
    }
    std::sort(out.begin(), out.end());
    return true;
}

int RosterIndex::RevokedAt(const roster::KeyBytes& key, int tip) const
{
    int32_t first = -1;
    if (!m_db->Read(DBRevokedKey(key), first)) return -1;
    return first <= tip ? first : -1;
}

bool RosterIndex::ReadWindow(int first, int last, std::vector<roster::WindowAnnouncement>& out) const
{
    out.clear();
    if (last < first) return true;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(DBHeightKey(std::max(0, first), 0)); it->Valid(); it->Next()) {
        DBHeightKey key;
        if (!it->GetKey(key) || key.height > last) break;
        RosterEntry entry;
        if (!it->GetValue(entry)) return false;
        roster::Record rec;
        if (!entry.Parse(rec) || rec.type != roster::RecordType::ANNOUNCE) continue;
        roster::WindowAnnouncement a;
        a.key = rec.op_key;
        a.height = key.height;
        a.ordinal = key.ordinal;
        a.expiry = rec.expiry_height;
        a.raw = std::move(entry.raw);
        a.txid = entry.txid;
        a.vout = entry.vout;
        out.push_back(std::move(a));
    }
    return true;
}

namespace {
RosterEntry ToEntry(const roster::WindowAnnouncement& a)
{
    RosterEntry e;
    e.raw = a.raw;
    e.height = a.height;
    e.txid = a.txid;
    e.vout = a.vout;
    e.ordinal = a.ordinal;
    return e;
}
} // namespace

bool RosterIndex::BuildRoster(int tip_height, std::map<roster::KeyBytes, RosterEntry>& out) const
{
    out.clear();
    if (tip_height < 0) return true;

    // The rule is roster::SelectLive's, shared with the commitment blocks
    // carry. Revocation is terminal: a key revoked at any height up to the tip
    // is out, whatever it announced after, and revocations are kept by key so
    // that costs one lookup rather than a scan of history.
    std::vector<roster::WindowAnnouncement> window;
    if (!ReadWindow(tip_height - static_cast<int>(roster::MAX_TTL), tip_height, window)) return false;
    const auto revoked = [&](const roster::KeyBytes& key) { return RevokedAt(key, tip_height) >= 0; };
    for (const roster::WindowAnnouncement& a : roster::SelectLive(window, tip_height, revoked)) {
        out.emplace(a.key, ToEntry(a));
    }
    return true;
}

bool RosterIndex::BuildCommittedRoster(int height, std::map<roster::KeyBytes, RosterEntry>& out) const
{
    out.clear();
    const int last = height - roster::AGE_DEPTH;
    if (last < 0) return true;
    std::vector<roster::WindowAnnouncement> window;
    if (!ReadWindow(last - static_cast<int>(roster::MAX_TTL), last, window)) return false;
    const auto revoked = [&](const roster::KeyBytes& key) { return RevokedAt(key, last) >= 0; };
    for (const roster::WindowAnnouncement& a : roster::SelectLive(window, height, revoked)) {
        out.emplace(a.key, ToEntry(a));
    }
    return true;
}
