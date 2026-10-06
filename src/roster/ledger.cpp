// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/ledger.h>

#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <fs.h>
#include <logging.h>
#include <primitives/block.h>
#include <roster/extract.h>
#include <roster/identity.h>
#include <streams.h>
#include <timedata.h>
#include <util/system.h>
#include <validation.h>
#include <versionbits.h>

namespace roster {

std::unique_ptr<Ledger> g_ledger;

namespace {

//! Blocks kept below the window, so a reorg this deep can still be answered.
constexpr int MARGIN = 2000;
constexpr int32_t FILE_VERSION = 1;

fs::path LedgerPath() { return GetDataDir() / "roster_ledger.dat"; }

} // namespace

int LedgerStart(const std::string& chain_id)
{
    // No roster record is older than the format, and the format did not
    // exist on mainnet before this height.
    return chain_id == CBaseChainParams::MAIN ? 1220000 : 0;
}

bool CommitmentActive(const CBlockIndex* pprev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return VersionBitsState(pprev, params, Consensus::DEPLOYMENT_ROSTER, versionbitscache) == ThresholdState::ACTIVE;
}

Ledger::Ledger(const std::string& chain_id) : m_chain_id(chain_id), m_start(LedgerStart(chain_id))
{
    m_low = m_start;
}

int Ledger::Height() const
{
    LOCK(m_mutex);
    return m_height;
}

bool Ledger::Complete() const
{
    LOCK(m_mutex);
    return m_complete;
}

void Ledger::Prune()
{
    AssertLockHeld(m_mutex);
    const int threshold = m_height - AGE_DEPTH - static_cast<int>(MAX_TTL) - MARGIN;
    if (threshold <= m_low) return;
    m_announcements.erase(m_announcements.begin(), m_announcements.lower_bound(threshold));
    m_low = threshold;
}

void Ledger::Connect(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(m_mutex);
    const uint256 prev = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    if (m_height >= 0 && m_tip != prev) {
        // Out of step with the chain: stop vouching rather than guess.
        if (m_complete) LogPrintf("roster: ledger out of step at block %d; not checking roster commitments\n", pindex->nHeight);
        m_complete = false;
    }
    m_tip = pindex->GetBlockHash();
    m_height = pindex->nHeight;
    if (pindex->nHeight < m_start) return;

    // The same rules as the roster index: a record that does not parse, is
    // out of range for its block, or is not signed by its key does not exist.
    uint32_t ordinal = 0;
    for (const CTransactionRef& tx : block.vtx) {
        for (uint32_t n = 0; n < tx->vout.size(); ++n) {
            std::vector<unsigned char> payload;
            if (!ExtractOpReturnPayload(tx->vout[n].scriptPubKey, payload)) continue;
            Record rec;
            if (ParseRecord(payload, rec) != ParseError::OK) continue;
            if (rec.type == RecordType::ANNOUNCE) {
                if (!ExpiryInRange(rec.expiry_height, pindex->nHeight)) continue;
                if (!VerifyRecord(rec, payload, m_chain_id)) continue;
                WindowAnnouncement a;
                a.key = rec.op_key;
                a.height = pindex->nHeight;
                a.ordinal = ordinal++;
                a.expiry = rec.expiry_height;
                a.raw = std::move(payload);
                a.txid = tx->GetHash();
                a.vout = n;
                m_announcements[pindex->nHeight].push_back(std::move(a));
            } else if (rec.type == RecordType::REVOKE) {
                if (!VerifyRecord(rec, payload, m_chain_id)) continue;
                m_revoked[rec.op_key].insert(pindex->nHeight);
            }
        }
    }
    Prune();
}

void Ledger::Disconnect(const CBlockIndex* pindex)
{
    LOCK(m_mutex);
    if (m_tip != pindex->GetBlockHash()) {
        if (m_complete) LogPrintf("roster: ledger out of step at block %d; not checking roster commitments\n", pindex->nHeight);
        m_complete = false;
    }
    m_announcements.erase(pindex->nHeight);
    for (auto it = m_revoked.begin(); it != m_revoked.end();) {
        it->second.erase(pindex->nHeight);
        it = it->second.empty() ? m_revoked.erase(it) : std::next(it);
    }
    m_tip = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    m_height = pindex->nHeight - 1;
}

bool Ledger::Window(int height, std::vector<WindowAnnouncement>& out) const
{
    AssertLockHeld(m_mutex);
    out.clear();
    if (!m_complete) return false;
    const int last = height - AGE_DEPTH;
    if (last > m_height) return false;
    const int first = std::max(m_start, last - static_cast<int>(MAX_TTL));
    if (first < m_low) return false; // a reorg deeper than this ledger keeps
    for (auto it = m_announcements.lower_bound(first); it != m_announcements.end() && it->first <= last; ++it) {
        out.insert(out.end(), it->second.begin(), it->second.end());
    }
    return true;
}

bool Ledger::Members(int height, std::vector<WindowAnnouncement>& out) const
{
    LOCK(m_mutex);
    std::vector<WindowAnnouncement> window;
    if (!Window(height, window)) return false;
    const int last = height - AGE_DEPTH;
    const auto revoked = [&](const KeyBytes& key) {
        const auto it = m_revoked.find(key);
        return it != m_revoked.end() && *it->second.begin() <= last;
    };
    out = SelectLive(window, height, revoked);
    return true;
}

bool Ledger::Root(int height, uint256& root_out) const
{
    std::vector<WindowAnnouncement> members;
    if (!Members(height, members)) return false;
    std::vector<CommitmentEntry> entries;
    entries.reserve(members.size());
    for (const WindowAnnouncement& a : members) {
        CommitmentEntry e;
        e.key = a.key;
        e.height = (uint32_t)a.height;
        e.raw = a.raw;
        entries.push_back(std::move(e));
    }
    bool duplicate = false;
    root_out = MerkleRoot(std::move(entries), &duplicate);
    return !duplicate;
}

void Ledger::Save() const
{
    LOCK(m_mutex);
    const fs::path tmp = LedgerPath().string() + ".new";
    FILE* file = fsbridge::fopen(tmp, "wb");
    CAutoFile out(file, SER_DISK, CLIENT_VERSION);
    if (out.IsNull()) {
        LogPrintf("roster: cannot write %s\n", tmp.string());
        return;
    }
    try {
        out << FILE_VERSION << m_tip << m_height << m_low << m_complete;
        out << (uint64_t)m_announcements.size();
        for (const auto& item : m_announcements) {
            out << item.first << (uint64_t)item.second.size();
            for (const WindowAnnouncement& a : item.second) {
                out.write((const char*)a.key.data(), a.key.size());
                out << a.ordinal << a.expiry << a.raw << a.txid << a.vout;
            }
        }
        out << (uint64_t)m_revoked.size();
        for (const auto& item : m_revoked) {
            out.write((const char*)item.first.data(), item.first.size());
            out << std::vector<int>(item.second.begin(), item.second.end());
        }
        out.fclose();
        fs::rename(tmp, LedgerPath());
    } catch (const std::exception& e) {
        LogPrintf("roster: cannot write the ledger: %s\n", e.what());
    }
}

void Ledger::Load(const CChainParams& params)
{
    AssertLockHeld(cs_main);
    const CBlockIndex* tip = ::ChainActive().Tip();
    if (!tip) {
        // A new datadir, or a reindex: nothing is connected yet, not even
        // genesis, and the ledger fills in as the chain does.
        LOCK(m_mutex);
        m_announcements.clear();
        m_revoked.clear();
        m_tip = uint256();
        m_height = -1;
        m_low = m_start;
        m_complete = true;
        return;
    }
    {
        FILE* file = fsbridge::fopen(LedgerPath(), "rb");
        CAutoFile in(file, SER_DISK, CLIENT_VERSION);
        if (!in.IsNull()) {
            try {
                LOCK(m_mutex);
                int32_t version = 0;
                in >> version;
                if (version == FILE_VERSION) {
                    in >> m_tip >> m_height >> m_low >> m_complete;
                    uint64_t heights = 0;
                    in >> heights;
                    m_announcements.clear();
                    for (uint64_t i = 0; i < heights; ++i) {
                        int height = 0;
                        uint64_t count = 0;
                        in >> height >> count;
                        std::vector<WindowAnnouncement>& list = m_announcements[height];
                        for (uint64_t j = 0; j < count; ++j) {
                            WindowAnnouncement a;
                            in.read((char*)a.key.data(), a.key.size());
                            in >> a.ordinal >> a.expiry >> a.raw >> a.txid >> a.vout;
                            a.height = height;
                            list.push_back(std::move(a));
                        }
                    }
                    uint64_t keys = 0;
                    in >> keys;
                    m_revoked.clear();
                    for (uint64_t i = 0; i < keys; ++i) {
                        KeyBytes key;
                        std::vector<int> at;
                        in.read((char*)key.data(), key.size());
                        in >> at;
                        m_revoked[key] = std::set<int>(at.begin(), at.end());
                    }
                    if (m_tip == tip->GetBlockHash() && m_height == tip->nHeight) {
                        LogPrintf("roster: ledger loaded at height %d\n", m_height);
                        return;
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("roster: the saved ledger is unreadable (%s)\n", e.what());
            }
        }
    }

    // Read it again from the blocks. Only the ones since records became
    // possible, which on mainnet is a few thousand.
    LogPrintf("roster: building the ledger from block %d to %d\n", m_start, tip->nHeight);
    {
        LOCK(m_mutex);
        m_announcements.clear();
        m_revoked.clear();
        m_complete = true;
        m_low = m_start;
        const CBlockIndex* before = m_start > 0 ? ::ChainActive()[m_start - 1] : nullptr;
        m_tip = before ? before->GetBlockHash() : uint256();
        m_height = before ? before->nHeight : -1;
    }
    for (int h = std::max(0, m_start); h <= tip->nHeight; ++h) {
        const CBlockIndex* pindex = ::ChainActive()[h];
        CBlock block;
        if (!(pindex->nStatus & BLOCK_HAVE_DATA) || !ReadBlockFromDisk(block, pindex, params.GetConsensus())) {
            LogPrintf("roster: block %d is not on disk; roster commitments will not be checked\n", h);
            LOCK(m_mutex);
            m_complete = false;
            m_tip = pindex->GetBlockHash();
            m_height = h;
            continue;
        }
        Connect(block, pindex);
    }
    Save();
}

void InitLedger(const CChainParams& params)
{
    LOCK(cs_main);
    const Consensus::Params& consensus = params.GetConsensus();
    const Consensus::BIP9Deployment& d = consensus.vDeployments[Consensus::DEPLOYMENT_ROSTER];
    const ThresholdState state = VersionBitsState(::ChainActive().Tip(), consensus, Consensus::DEPLOYMENT_ROSTER, versionbitscache);
    const bool wanted = d.nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE ||
                        state == ThresholdState::STARTED || state == ThresholdState::LOCKED_IN ||
                        state == ThresholdState::ACTIVE ||
                        (state == ThresholdState::DEFINED && d.nTimeout > GetAdjustedTime());
    if (!wanted) {
        g_ledger.reset();
        return;
    }
    g_ledger = MakeUnique<Ledger>(params.NetworkIDString());
    g_ledger->Load(params);
}

bool IgnoringCommitments()
{
    static const bool ignoring = Params().NetworkIDString() == CBaseChainParams::REGTEST &&
                                 gArgs.GetBoolArg("-testrostercorrupt", false);
    return ignoring;
}

bool CommitmentForNewBlock(const CBlockIndex* pprev, const Consensus::Params& params, uint256& root_out)
{
    if (!pprev || !CommitmentActive(pprev, params)) return false;
    if (!g_ledger || !g_ledger->Root(pprev->nHeight + 1, root_out)) {
        LogPrintf("roster: cannot work out the roster commitment for block %d; the block will lack it\n",
                  pprev->nHeight + 1);
        return false;
    }
    if (IgnoringCommitments()) *root_out.begin() ^= 0x01;
    return true;
}

} // namespace roster
