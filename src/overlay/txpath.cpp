// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/txpath.h>

#include <crypto/common.h>
#include <logging.h>
#include <overlay/meeting.h>
#include <overlay/relay.h>
#include <overlay/select.h>
#include <random.h>
#include <roster/peers.h>
#include <serialize.h>
#include <streams.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <version.h>

#include <algorithm>
#include <limits>
#include <set>

namespace overlay {

std::unique_ptr<TxPath> g_txpath;

namespace {

void PutU64(std::vector<unsigned char>& out, uint64_t v) { unsigned char b[8]; WriteLE64(b, v); out.insert(out.end(), b, b + 8); }

std::vector<unsigned char> AckMessage(uint64_t reqid, bool ok, const std::string& reason)
{
    std::vector<unsigned char> out{TX_ACK};
    PutU64(out, reqid);
    out.push_back(ok ? 1 : 0);
    const std::string r = reason.substr(0, 200);
    out.insert(out.end(), r.begin(), r.end());
    return out;
}

//! How long a relay has to answer.
constexpr std::chrono::seconds ANSWER_WAIT{20};
//! A transaction in pieces that has not come whole within this is dropped.
constexpr int64_t ASSEMBLY_TTL = 60;
constexpr size_t MAX_ASSEMBLING = 64;

} // namespace

bool IsTxPathPayload(const std::vector<unsigned char>& payload)
{
    return !payload.empty() && (payload[0] == TX_SEND || payload[0] == TX_ACK);
}

TxPath::TxPath(const roster::KeyBytes& self, Accept accept, Fallback fallback)
    : m_self(self), m_accept(std::move(accept)), m_fallback(std::move(fallback)) {}

TxPath::~TxPath() { Stop(); }

void TxPath::Start()
{
    m_running = true;
    m_sender = std::thread([this] { util::ThreadRename("txpath"); ThreadSend(); });
    m_acceptor = std::thread([this] { util::ThreadRename("txpath-accept"); ThreadAccept(); });
}

void TxPath::Stop()
{
    if (!m_running.exchange(false)) return;
    {
        LOCK(m_mutex);
        m_cv.notify_all();
    }
    if (m_sender.joinable()) m_sender.join();
    if (m_acceptor.joinable()) m_acceptor.join();
}

void TxPath::Send(const CTransactionRef& tx)
{
    LOCK(m_mutex);
    m_outbox.push_back(tx);
    m_cv.notify_all();
}

TxPath::Stats TxPath::GetStats() const
{
    LOCK(m_mutex);
    Stats s = m_stats;
    s.queued = m_outbox.size();
    return s;
}

// --- this node's own ----------------------------------------------------------------

bool TxPath::SendOne(const CTransactionRef& tx, std::string& last_error, bool& definitive)
{
    definitive = false;
    if (!g_overlay) {
        last_error = "the overlay is off";
        return false;
    }
    // A relay that is not one of this node's entry relays, which see where it
    // is, nor this node. Entry relays are drawn now if no path has yet.
    std::set<roster::KeyBytes> guards;
    {
        LOCK(g_selector_mutex);
        if (g_selector) {
            std::vector<RelayCandidate> entry;
            g_selector->Select(1, entry);
            for (const RelayCandidate& g : g_selector->Guards()) guards.insert(g.key);
        }
    }
    std::vector<roster::KeyBytes> candidates;
    for (const roster::RelayInfo& r : roster::FreshRelays()) {
        if (r.key != m_self && !guards.count(r.key)) candidates.push_back(r.key);
    }
    if (candidates.empty()) {
        last_error = "the roster lists no relay but this node's entry relays";
        return false;
    }
    const roster::KeyBytes relay = candidates[GetRand(candidates.size())];

    Reached reached;
    if (!ReachRelay(relay, TXPATH_HOPS, /*prove_last=*/false, reached, last_error)) return false;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    const std::vector<unsigned char> raw(ss.begin(), ss.end());
    const uint64_t reqid = GetRand(std::numeric_limits<uint64_t>::max() - 1) + 1;
    {
        LOCK(m_mutex);
        m_waiting[reqid] = Waiting();
    }
    for (const std::vector<unsigned char>& chunk : MakeChunks(TX_SEND, reqid, raw, SITE_CHUNK_PATH)) {
        g_overlay->SendSecret(reached.path, chunk);
    }
    Waiting w;
    {
        WAIT_LOCK(m_mutex, lock);
        const auto until = std::chrono::steady_clock::now() + ANSWER_WAIT;
        while (m_running && !m_waiting[reqid].done && std::chrono::steady_clock::now() < until) {
            m_cv.wait_for(lock, std::chrono::milliseconds{500});
        }
        w = m_waiting[reqid];
        m_waiting.erase(reqid);
    }
    g_overlay->ClosePath(reached.legs);
    if (!w.done) {
        last_error = "the relay did not answer";
        return false;
    }
    if (!w.ok) {
        // The relay found it invalid: so would every other.
        last_error = w.reason;
        definitive = true;
        return false;
    }
    return true;
}

void TxPath::ThreadSend()
{
    while (m_running) {
        CTransactionRef tx;
        {
            WAIT_LOCK(m_mutex, lock);
            if (m_outbox.empty()) {
                m_cv.wait_for(lock, std::chrono::milliseconds{500});
                continue;
            }
            tx = m_outbox.front();
            m_outbox.pop_front();
        }
        std::string error;
        bool sent = false, definitive = false;
        for (int attempt = 0; attempt < TXPATH_TRIES && m_running && !sent && !definitive; ++attempt) {
            sent = SendOne(tx, error, definitive);
        }
        if (sent) {
            LogPrint(BCLog::NET, "txpath: %s left through a path\n", tx->GetHash().ToString());
            LOCK(m_mutex);
            ++m_stats.through_path;
        } else if (definitive) {
            LogPrintf("txpath: a relay refused %s: %s\n", tx->GetHash().ToString(), error);
            LOCK(m_mutex);
            ++m_stats.refused_own;
        } else if (m_running) {
            LogPrintf("txpath: no relay took %s through a path (%s); the peer-to-peer network carries it\n",
                      tx->GetHash().ToString(), error);
            m_fallback(tx);
            LOCK(m_mutex);
            ++m_stats.over_p2p;
        }
    }
}

// --- others', at a relay ------------------------------------------------------------

void TxPath::HandleApp(const Hop& from, const std::vector<unsigned char>& payload)
{
    if (payload.size() < 1 + 8) return;
    const uint64_t reqid = ReadLE64(payload.data() + 1);

    if (payload[0] == TX_ACK) {
        LOCK(m_mutex);
        auto it = m_waiting.find(reqid);
        if (it == m_waiting.end() || it->second.done || payload.size() < 10) return;
        it->second.done = true;
        it->second.ok = payload[9] == 1;
        it->second.reason.assign(payload.begin() + 10, payload.end());
        m_cv.notify_all();
        return;
    }

    // Only over a path: a transaction straight from a neighbour would come
    // from its address, which is what this is for avoiding.
    if (payload[0] != TX_SEND || !from.via_path || payload.size() < SITE_CHUNK_HEADER) return;
    const uint32_t total = ReadLE32(payload.data() + 9);
    const uint32_t offset = ReadLE32(payload.data() + 13);
    if (total == 0 || total > MAX_TXPATH_TX) return;
    const int64_t now = GetTime();
    LOCK(m_mutex);
    for (auto it = m_incoming.begin(); it != m_incoming.end();) {
        it = now - it->second.started > ASSEMBLY_TTL ? m_incoming.erase(it) : std::next(it);
    }
    const auto key = std::make_pair(from, reqid);
    auto it = m_incoming.find(key);
    if (it == m_incoming.end()) {
        if (m_incoming.size() >= MAX_ASSEMBLING) return;
        it = m_incoming.emplace(key, Incoming()).first;
        it->second.started = now;
    }
    if (!it->second.parts.Add(total, offset, payload.data() + SITE_CHUNK_HEADER, payload.size() - SITE_CHUNK_HEADER)) {
        m_incoming.erase(it);
        return;
    }
    if (!it->second.parts.Complete()) return;
    const std::vector<unsigned char> raw = it->second.parts.Bytes();
    m_incoming.erase(it);

    CTransactionRef tx;
    try {
        CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
        ss >> tx;
        if (!ss.empty()) throw std::ios_base::failure("bytes past the transaction");
    } catch (const std::exception&) {
        ++m_stats.turned_away;
        if (g_overlay) g_overlay->SendSecret(from.path, AckMessage(reqid, false, "not a transaction"));
        return;
    }
    // Taken in turn on a thread of its own: a mempool check holds the chain's lock.
    if (m_to_accept.size() >= 256) return;
    m_to_accept.emplace_back(key, tx);
    m_cv.notify_all();
}

void TxPath::ThreadAccept()
{
    while (m_running) {
        std::pair<Hop, uint64_t> key;
        CTransactionRef tx;
        bool allowed = true;
        {
            WAIT_LOCK(m_mutex, lock);
            if (m_to_accept.empty()) {
                m_cv.wait_for(lock, std::chrono::milliseconds{500});
                continue;
            }
            key = m_to_accept.front().first;
            tx = m_to_accept.front().second;
            m_to_accept.pop_front();
            // So many a minute from one path, and from all: announcing for
            // strangers must not become a way to flood the network through
            // this node.
            const int64_t now = GetTime();
            auto prune = [now](std::deque<int64_t>& d) { while (!d.empty() && now - d.front() >= 60) d.pop_front(); };
            std::deque<int64_t>& mine = m_recent[key.first];
            prune(mine);
            prune(m_recent_all);
            for (auto it = m_recent.begin(); it != m_recent.end();) {
                prune(it->second);
                it = it->second.empty() && !(it->first == key.first) ? m_recent.erase(it) : std::next(it);
            }
            if (mine.size() >= TXPATH_PER_PATH_MINUTE || m_recent_all.size() >= TXPATH_ALL_MINUTE) {
                allowed = false;
                ++m_stats.turned_away;
            } else {
                mine.push_back(now);
                m_recent_all.push_back(now);
            }
        }
        const std::string why = allowed ? m_accept(tx) : std::string("too many from this path; try another relay");
        {
            LOCK(m_mutex);
            if (allowed && why.empty()) ++m_stats.for_others;
            if (allowed && !why.empty()) ++m_stats.turned_away;
        }
        if (g_overlay) g_overlay->SendSecret(key.first.path, AckMessage(key.second, why.empty(), why));
    }
}

bool SendOwnTransaction(const CTransactionRef& tx)
{
    if (!g_txpath) return false;
    g_txpath->Send(tx);
    return true;
}

void HandleTxPathApp(const Hop& from, const std::vector<unsigned char>& payload)
{
    if (g_txpath) g_txpath->HandleApp(from, payload);
}

} // namespace overlay
