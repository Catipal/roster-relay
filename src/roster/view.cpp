// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/view.h>

#include <chain.h>
#include <chainparams.h>
#include <index/rosterindex.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <roster/extract.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <fstream>

namespace roster {

std::unique_ptr<RevocationStore> g_revocations;
HintStore g_hints;
std::shared_ptr<MempoolWatcher> g_mempool_watcher;

RevocationStore::RevocationStore(const fs::path& file, const std::string& chain_id)
    : m_file(file), m_chain_id(chain_id)
{
}

bool RevocationStore::Load(std::string& error)
{
    LOCK(m_mutex);
    m_records.clear();
    if (!fs::exists(m_file)) return true;
    fsbridge::ifstream in(m_file);
    if (!in.is_open()) {
        error = "Cannot open " + m_file.string();
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || !IsHex(line)) continue;
        const std::vector<unsigned char> raw = ParseHex(line);
        Record rec;
        // Checked again on the way in: a file is not a reason to believe anything.
        if (!ParseAndVerify(raw, m_chain_id, rec) || rec.type != RecordType::REVOKE) continue;
        m_records.emplace(rec.op_key, raw);
    }
    return true;
}

bool RevocationStore::Save() const
{
    const fs::path tmp = m_file.string() + ".new";
    {
        fsbridge::ofstream out(tmp, std::ios::trunc);
        if (!out.is_open()) return false;
        for (const auto& item : m_records) out << HexStr(item.second) << "\n";
        if (!out.good()) return false;
    }
    try {
        fs::rename(tmp, m_file);
    } catch (const fs::filesystem_error& e) {
        LogPrintf("roster: could not save revocations: %s\n", e.what());
        return false;
    }
    return true;
}

bool RevocationStore::Add(const std::vector<unsigned char>& raw, std::string* error)
{
    Record rec;
    if (!ParseAndVerify(raw, m_chain_id, rec) || rec.type != RecordType::REVOKE) {
        if (error) *error = "not a revocation signed by the key it revokes";
        return false;
    }
    LOCK(m_mutex);
    if (m_records.count(rec.op_key)) return false;
    m_records.emplace(rec.op_key, raw);
    if (!Save()) LogPrintf("roster: could not write %s\n", m_file.string());
    LogPrint(BCLog::NET, "roster: %s is revoked\n", HexStr(rec.op_key));
    return true;
}

bool RevocationStore::Contains(const KeyBytes& key) const
{
    LOCK(m_mutex);
    return m_records.count(key) != 0;
}

std::vector<std::vector<unsigned char>> RevocationStore::All() const
{
    LOCK(m_mutex);
    std::vector<std::vector<unsigned char>> out;
    for (const auto& item : m_records) out.push_back(item.second);
    return out;
}

size_t RevocationStore::Size() const
{
    LOCK(m_mutex);
    return m_records.size();
}

bool SeenRevoked(const KeyBytes& key)
{
    return g_revocations && g_revocations->Contains(key);
}

void HintStore::Offer(const Record& rec, const std::vector<unsigned char>& raw, const std::string& source)
{
    if (rec.type != RecordType::ANNOUNCE) return;
    // Only keys the chain already lists or listed: anyone can make up keys.
    std::vector<RosterEntry> history;
    if (!g_rosterindex || !g_rosterindex->ReadRecordsForKey(rec.op_key, history) || history.empty()) return;
    for (const RosterEntry& e : history) {
        if (e.raw == raw) return; // already on the chain
    }
    LOCK(m_mutex);
    if (m_hints.size() >= MAX_HINTS && !m_hints.count(rec.op_key)) {
        // Drop the oldest to make room.
        auto oldest = std::min_element(m_hints.begin(), m_hints.end(),
            [](const std::pair<const KeyBytes, Hint>& a, const std::pair<const KeyBytes, Hint>& b) {
                return a.second.time < b.second.time;
            });
        m_hints.erase(oldest);
    }
    Hint& h = m_hints[rec.op_key];
    h.raw = raw;
    h.source = source;
    h.time = GetTime();
}

void HintStore::Confirmed(const KeyBytes& key, const std::vector<unsigned char>& raw)
{
    LOCK(m_mutex);
    const auto it = m_hints.find(key);
    if (it != m_hints.end() && it->second.raw == raw) m_hints.erase(it);
}

std::map<KeyBytes, Hint> HintStore::All() const
{
    LOCK(m_mutex);
    return m_hints;
}

void OnIndexedRecord(const Record& rec, const std::vector<unsigned char>& raw, int height, bool reorged_out)
{
    if (rec.type == RecordType::REVOKE) {
        // Kept whether the block stays or goes: the key's holder signed it,
        // and a reorg does not change what they meant.
        if (g_revocations) g_revocations->Add(raw);
    } else if (rec.type == RecordType::ANNOUNCE) {
        if (reorged_out) {
            g_hints.Offer(rec, raw, "reorg");
        } else {
            g_hints.Confirmed(rec.op_key, raw);
        }
    }
}

void MempoolWatcher::TransactionAddedToMempool(const CTransactionRef& tx, uint64_t mempool_sequence)
{
    const std::string chain_id = Params().NetworkIDString();
    for (const CTxOut& out : tx->vout) {
        std::vector<unsigned char> payload;
        if (!ExtractOpReturnPayload(out.scriptPubKey, payload)) continue;
        Record rec;
        if (ParseRecord(payload, rec) != ParseError::OK) continue;
        if (rec.type != RecordType::REVOKE && rec.type != RecordType::ANNOUNCE) continue;
        if (!VerifyRecord(rec, payload, chain_id)) continue;
        if (rec.type == RecordType::REVOKE) {
            if (g_revocations) g_revocations->Add(payload);
        } else {
            g_hints.Offer(rec, payload, "mempool");
        }
    }
}

bool GetStanding(const RosterIndex& index, const KeyBytes& key, int tip, Standing& out)
{
    out = Standing();
    std::vector<HeldRecord> history;
    if (!index.ReadHistory(key, history)) return false;
    const AgeChain chain = WalkAgeChain(key, history, tip);
    out.anchor = chain.anchor;
    if (chain.delegation) {
        const KeyBytes id = chain.delegation->rec.id_key;
        std::vector<HeldRecord> cluster;
        if (index.ReadIdentityCluster(id, cluster)) {
            IdentityBook book;
            book.Build(cluster, tip);
            if (book.Delegates(id, key, tip)) {
                out.has_identity = true;
                out.identity = id;
                const IdentityState* s = book.Find(id);
                if (s && s->first_height >= 0 && (out.anchor < 0 || s->first_height < out.anchor)) {
                    out.anchor = s->first_height;
                }
            }
        }
    }
    out.age = (out.anchor >= 0 && tip - out.anchor >= AGE_DEPTH) ? tip - out.anchor : 0;
    out.revoked = index.RevokedAt(key, tip) >= 0 || SeenRevoked(key);
    return true;
}

RosterStatus GetRosterStatus()
{
    RosterStatus s;
    if (!g_rosterindex) return s;
    s.enabled = true;
    s.height = g_rosterindex->GetSummary().best_block_height;
    {
        LOCK(cs_main);
        const CBlockIndex* block = s.height >= 0 ? ::ChainActive()[s.height] : nullptr;
        if (block) s.block_time = block->GetBlockTime();
    }
    if (s.block_time > 0) {
        s.age_seconds = std::max<int64_t>(0, GetAdjustedTime() - s.block_time);
        s.stale = s.age_seconds > (int64_t)ROSTER_STALE * Params().GetConsensus().nPowTargetSpacing;
    }
    return s;
}

} // namespace roster
