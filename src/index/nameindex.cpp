// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/nameindex.h>

#include <chain.h>
#include <chainparams.h>
#include <dbwrapper.h>
#include <names/name.h>
#include <names/record.h>
#include <primitives/block.h>
#include <roster/extract.h>
#include <util/system.h>
#include <validation.h>

std::unique_ptr<NameIndex> g_nameindex;

namespace {

constexpr uint8_t DB_NAME_BY_HEIGHT = 'n';
constexpr uint8_t DB_VERSION = 'V';
//! 2: entries carry spends of sale coins.
constexpr int32_t INDEX_VERSION = 2;
//! BaseIndex's key for the last block indexed (index/base.cpp).
constexpr char DB_BEST_BLOCK = 'B';

constexpr uint8_t KIND_RECORD = 0;
constexpr uint8_t KIND_SPEND = 1;
constexpr uint8_t FLAG_COIN_FUNDED = 1;

/** Big-endian height and ordinal, so key order is chain order. */
struct DBHeightKey {
    int height{0};
    uint32_t ordinal{0};

    DBHeightKey() = default;
    explicit DBHeightKey(int height_in, uint32_t ordinal_in = 0) : height(height_in), ordinal(ordinal_in) {}

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_NAME_BY_HEIGHT);
        ser_writedata32be(s, height);
        ser_writedata32be(s, ordinal);
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        if (ser_readdata8(s) != DB_NAME_BY_HEIGHT) {
            throw std::ios_base::failure("Invalid prefix for name index key");
        }
        height = ser_readdata32be(s);
        ordinal = ser_readdata32be(s);
    }
};

struct DBEntry {
    std::vector<unsigned char> raw;
    int64_t burned{0};
    int32_t height{0};
    uint256 txid;
    uint32_t vout{0};
    uint8_t kind{KIND_RECORD};
    COutPoint spent;
    uint8_t flags{0};

    SERIALIZE_METHODS(DBEntry, obj)
    {
        READWRITE(obj.raw, obj.burned, obj.height, obj.txid, obj.vout, obj.kind, obj.spent, obj.flags);
    }
};

} // namespace

/** Access to the name index database (indexes/nameindex/) */
class NameIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory, bool f_wipe)
        : BaseIndex::DB(GetDataDir() / "indexes" / "nameindex", n_cache_size, f_memory, f_wipe)
    {
    }
};

NameIndex::NameIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(MakeUnique<NameIndex::DB>(n_cache_size, f_memory, f_wipe)),
      m_chain_id(Params().NetworkIDString()),
      m_start_height(names::StartHeight(Params().NetworkIDString()))
{
}

NameIndex::~NameIndex() = default;

BaseIndex::DB& NameIndex::GetDB() const { return *m_db; }

bool NameIndex::Upgrade()
{
    int32_t version = 0;
    if (m_db->Read(DB_VERSION, version) && version == INDEX_VERSION) return true;
    CDBBatch batch(*m_db);
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    bool had_entries = false;
    for (it->Seek(DBHeightKey(0, 0)); it->Valid(); it->Next()) {
        DBHeightKey key;
        if (!it->GetKey(key)) break;
        batch.Erase(key);
        had_entries = true;
    }
    it.reset();
    CBlockLocator existing;
    if (had_entries || m_db->ReadBestBlock(existing)) {
        LogPrintf("nameindex: written in an older format; rebuilding it\n");
        batch.Erase(DB_BEST_BLOCK);
    }
    batch.Write(DB_VERSION, INDEX_VERSION);
    return m_db->WriteBatch(batch, true);
}

bool NameIndex::Init()
{
    if (!Upgrade()) return false;
    {
        std::unique_ptr<CDBIterator> it(m_db->NewIterator());
        for (it->Seek(DBHeightKey(0, 0)); it->Valid(); it->Next()) {
            DBHeightKey key;
            DBEntry entry;
            if (!it->GetKey(key) || !it->GetValue(entry)) break;
            names::NameRecord rec;
            if (entry.kind == KIND_RECORD && names::ParseNameRecord(entry.raw, rec) &&
                rec.type == names::NameRecordType::SELL) {
                m_sale_coins.insert(rec.coin);
            }
        }
    }
    // Nothing before the start height can count, so a new index does not read
    // those blocks: where names have not started (mainnet, for now) it begins
    // at the tip, and otherwise just below the start.
    CBlockLocator existing;
    if (m_start_height > 0 && !m_db->ReadBestBlock(existing)) {
        LOCK(cs_main);
        const int tip = ::ChainActive().Height();
        const int from = std::min(m_start_height - 1, tip);
        const CBlockIndex* start = from >= 0 ? ::ChainActive()[from] : nullptr;
        if (start) {
            CDBBatch batch(*m_db);
            m_db->WriteBestBlock(batch, ::ChainActive().GetLocator(start));
            m_db->WriteBatch(batch);
        }
    }
    return BaseIndex::Init();
}

bool NameIndex::EraseHeight(int height, CDBBatch& batch) const
{
    bool erased = false;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(DBHeightKey(height, 0)); it->Valid(); it->Next()) {
        DBHeightKey key;
        if (!it->GetKey(key) || key.height != height) break;
        batch.Erase(key);
        erased = true;
    }
    return erased;
}

bool NameIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    // Before names start on this network there is nothing that could count,
    // so the blocks are not even looked at.
    if (pindex->nHeight < m_start_height) return true;

    CDBBatch batch(*m_db);
    // Rewriting a height after a reorg replaces whatever was filed there.
    bool changed = EraseHeight(pindex->nHeight, batch);
    uint32_t ordinal = 0;
    for (const CTransactionRef& tx : block.vtx) {
        // Inputs first, as a transaction spends before it creates: a purchase
        // is a spend of the sale coin followed by a BUY in the same transaction.
        if (!m_sale_coins.empty() && !tx->IsCoinBase()) {
            for (uint32_t i = 0; i < tx->vin.size(); ++i) {
                if (!m_sale_coins.count(tx->vin[i].prevout)) continue;
                DBEntry entry;
                entry.kind = KIND_SPEND;
                entry.spent = tx->vin[i].prevout;
                entry.height = pindex->nHeight;
                entry.txid = tx->GetHash();
                entry.vout = i;
                batch.Write(DBHeightKey(pindex->nHeight, ordinal++), entry);
                changed = true;
            }
        }
        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            std::vector<unsigned char> payload;
            if (!roster::ExtractOpReturnPayload(tx->vout[n].scriptPubKey, payload)) continue;
            names::NameRecord rec;
            if (!names::ParseNameRecord(payload, rec)) continue;
            DBEntry entry;
            if (rec.type == names::NameRecordType::SELL) {
                m_sale_coins.insert(rec.coin);
                for (const CTxIn& in : tx->vin) {
                    if (in.prevout.hash == rec.coin.hash) entry.flags |= FLAG_COIN_FUNDED;
                }
            }
            entry.raw = std::move(payload);
            entry.burned = tx->vout[n].nValue;
            entry.height = pindex->nHeight;
            entry.txid = tx->GetHash();
            entry.vout = n;
            batch.Write(DBHeightKey(pindex->nHeight, ordinal++), entry);
            changed = true;
        }
    }
    if (!changed) return true;
    if (!m_db->WriteBatch(batch)) return false;
    ++m_generation;
    return true;
}

bool NameIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
{
    // Records above the new tip belong to blocks no longer on the chain.
    CDBBatch batch(*m_db);
    bool erased = false;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(DBHeightKey(new_tip->nHeight + 1, 0)); it->Valid(); it->Next()) {
        DBHeightKey key;
        if (!it->GetKey(key)) break;
        batch.Erase(key);
        erased = true;
    }
    it.reset();
    if (erased && !m_db->WriteBatch(batch)) return false;
    ++m_generation;
    return BaseIndex::Rewind(current_tip, new_tip);
}

bool NameIndex::GetState(std::shared_ptr<const names::NameState>& state_out, int& height_out) const
{
    const int best = GetSummary().best_block_height;
    const uint64_t generation = m_generation.load();
    LOCK(m_cache_mutex);
    if (m_cache && m_cache_generation == generation && m_cache_height == best) {
        state_out = m_cache;
        height_out = best;
        return true;
    }

    auto state = std::make_shared<names::NameState>(m_chain_id);
    std::vector<names::IndexedRecord> block;
    int block_height = -1;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(DBHeightKey(0, 0)); it->Valid(); it->Next()) {
        DBHeightKey key;
        if (!it->GetKey(key) || key.height > best) break;
        DBEntry entry;
        if (!it->GetValue(entry)) return false;
        if (key.height != block_height) {
            if (!block.empty()) state->ApplyBlock(block_height, block);
            block.clear();
            block_height = key.height;
        }
        names::IndexedRecord rec;
        rec.raw = std::move(entry.raw);
        rec.burned = entry.burned;
        rec.height = entry.height;
        rec.txid = entry.txid;
        rec.vout = entry.vout;
        rec.spend = entry.kind == KIND_SPEND;
        rec.spent = entry.spent;
        rec.coin_funded = (entry.flags & FLAG_COIN_FUNDED) != 0;
        block.push_back(std::move(rec));
    }
    if (!block.empty()) state->ApplyBlock(block_height, block);

    m_cache = state;
    m_cache_generation = generation;
    m_cache_height = best;
    state_out = m_cache;
    height_out = best;
    return true;
}
