// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/chainsync.h>

#include <chainparams.h>
#include <crypto/common.h>
#include <logging.h>
#include <overlay/frame.h>
#include <overlay/radio.h>
#include <overlay/relay.h>
#include <primitives/block.h>
#include <random.h>
#include <roster/keystore.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <limits>

namespace overlay {

std::unique_ptr<ChainSync> g_chainsync;

namespace {

//! Data bytes per BLOCK chunk, well under the padded datagram so a chunk is one.
constexpr size_t CHUNK_DATA = 900;
//! A block cannot exceed the weight limit; refuse a transfer claiming more.
constexpr uint32_t MAX_BLOCK_BYTES = 4 * 1000 * 1000;
//! A half-received block is dropped after this, so a peer cannot pin memory.
constexpr int64_t TRANSFER_TTL = 120;
//! A GETBLOCK with no answer is retried after this.
constexpr int64_t ASK_TIMEOUT = 30;
//! How often a neighbour is polled for its tip when nothing is being fetched;
//! kept low so the feed costs little airtime on a duty-cycle-limited radio.
constexpr int64_t TIP_POLL = 30;

void PutU32(std::vector<unsigned char>& out, uint32_t v)
{
    unsigned char b[4];
    WriteLE32(b, v);
    out.insert(out.end(), b, b + 4);
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char b[8];
    WriteLE64(b, v);
    out.insert(out.end(), b, b + 8);
}

} // namespace

bool IsChainPayload(const std::vector<unsigned char>& payload)
{
    if (payload.empty()) return false;
    switch (payload[0]) {
    case CHAIN_GETTIP:
    case CHAIN_TIP:
    case CHAIN_GETBLOCK:
    case CHAIN_BLOCK:
    case CHAIN_NOBLOCK:
        return true;
    }
    return false;
}

ChainSync::ChainSync(const CChainParams& params, const roster::KeyBytes& self, bool pull)
    : m_params(params), m_self(self), m_pull(pull) {}

ChainSync::~ChainSync() { Stop(); }

void ChainSync::Start()
{
    if (m_thread.joinable()) return;
    m_interrupt.reset();
    m_thread = std::thread(&TraceThread<std::function<void()>>, "chainsync",
                           std::function<void()>([this] { ThreadSync(); }));
}

void ChainSync::Stop()
{
    m_interrupt();
    if (m_thread.joinable()) m_thread.join();
}

void ChainSync::SetIsolatedCheck(std::function<bool()> isolated)
{
    LOCK(m_mutex);
    m_isolated = std::move(isolated);
}

int ChainSync::LocalHeight() const
{
    LOCK(cs_main);
    return ::ChainActive().Height();
}

void ChainSync::Send(const CService& to, const std::vector<unsigned char>& msg)
{
    if (g_overlay) g_overlay->SendApp(to, msg);
}

bool ChainSync::Reach(const PeerView& peer)
{
    if (!g_overlay) return false;
    if (g_overlay->HasSession(peer.addr)) return true;
    // Only one side of a pair opens the session - the overlay is request and
    // answer over a single session, and two sessions opened at once (one each
    // way) cannot read each other. The lower key dials; the other waits for
    // that session and then answers and asks on it.
    if (!(m_self < peer.key)) return false;
    CPubKey pub;
    // The full key is the even-Y lift of the x-only key the neighbour's bridge
    // announced - pure arithmetic, so a node with no roster can still dial it.
    if (!roster::StakerPubKeyFromRoster(peer.key, pub)) return false;
    g_overlay->Connect(peer.addr, pub);
    return g_overlay->HasSession(peer.addr);
}

void ChainSync::SendTip(const CService& to)
{
    int height;
    uint256 hash;
    {
        LOCK(cs_main);
        height = ::ChainActive().Height();
        const CBlockIndex* tip = ::ChainActive().Tip();
        if (tip) hash = tip->GetBlockHash();
    }
    std::vector<unsigned char> msg{CHAIN_TIP};
    PutU32(msg, (uint32_t)std::max(0, height));
    msg.insert(msg.end(), hash.begin(), hash.end());
    Send(to, msg);
}

void ChainSync::ServeBlock(const CService& to, int height)
{
    CBlock block;
    bool have = false;
    {
        LOCK(cs_main);
        const CChain& chain = ::ChainActive();
        if (height >= 0 && height <= chain.Height()) {
            const CBlockIndex* pindex = chain[height];
            if (pindex && ReadBlockFromDisk(block, pindex, m_params.GetConsensus())) have = true;
        }
    }
    if (!have) {
        std::vector<unsigned char> msg{CHAIN_NOBLOCK};
        PutU32(msg, (uint32_t)std::max(0, height));
        Send(to, msg);
        return;
    }
    // The payload is the height and then the block, so the receiver knows
    // where it belongs before parsing it.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << block;
    std::vector<unsigned char> payload;
    PutU32(payload, (uint32_t)height);
    payload.insert(payload.end(), ss.begin(), ss.end());
    SendBlockChunks(to, payload);
}

void ChainSync::SendBlockChunks(const CService& to, const std::vector<unsigned char>& payload)
{
    const uint64_t transfer = GetRand(std::numeric_limits<uint64_t>::max());
    const uint32_t total = (uint32_t)payload.size();
    for (uint32_t offset = 0; offset < total; offset += CHUNK_DATA) {
        const uint32_t n = std::min<uint32_t>(CHUNK_DATA, total - offset);
        std::vector<unsigned char> msg{CHAIN_BLOCK};
        PutU64(msg, transfer);
        PutU32(msg, total);
        PutU32(msg, offset);
        msg.insert(msg.end(), payload.begin() + offset, payload.begin() + offset + n);
        Send(to, msg);
        // Paced so a block does not arrive as one burst a relay cannot buffer.
        if (total > CHUNK_DATA) UninterruptibleSleep(std::chrono::milliseconds{1});
    }
}

void ChainSync::OnBlock(const CService& from, std::vector<unsigned char>&& payload)
{
    if (payload.size() < 4) return;
    const uint32_t height = ReadLE32(payload.data());
    CBlock block;
    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write(reinterpret_cast<const char*>(payload.data() + 4), payload.size() - 4);
        ss >> block;
    } catch (const std::exception&) {
        return;
    }

    // Only the next block, and only if it builds on our tip: this is a forward
    // follow, not a sync that could be steered sideways. Validation is the real
    // check; this just avoids handing validation blocks it cannot use.
    {
        LOCK(cs_main);
        const CBlockIndex* tip = ::ChainActive().Tip();
        if (!tip || (int)height != tip->nHeight + 1 || block.hashPrevBlock != tip->GetBlockHash()) {
            return;
        }
    }

    std::shared_ptr<const CBlock> shared = std::make_shared<const CBlock>(std::move(block));
    bool accepted = false;
    g_chainman.ProcessNewBlock(m_params, shared, /* force */ false, &accepted);
    if (accepted) {
        LogPrint(BCLog::NET, "chainsync: took block %d over the overlay from %s\n", (int)height, from.ToString());
    }
    // Clear the outstanding ask so Tick's next pass fetches the block after.
    LOCK(m_mutex);
    std::map<std::string, State>::iterator it = m_peers.find(from.ToString());
    if (it != m_peers.end()) {
        it->second.asked_at = 0;
        it->second.asked_height = -1;
    }
}

void ChainSync::HandleApp(const CService& from, const std::vector<unsigned char>& payload)
{
    if (payload.empty()) return;
    const int64_t now = GetTime();
    switch (payload[0]) {
    case CHAIN_GETTIP:
        SendTip(from);
        return;
    case CHAIN_TIP: {
        if (payload.size() != 1 + 4 + 32) return;
        const int height = (int)ReadLE32(payload.data() + 1);
        LOCK(m_mutex);
        State& st = m_peers[from.ToString()];
        st.height = height;
        st.heard = now;
        return;
    }
    case CHAIN_GETBLOCK: {
        if (payload.size() != 1 + 4) return;
        ServeBlock(from, (int)ReadLE32(payload.data() + 1));
        return;
    }
    case CHAIN_NOBLOCK: {
        LOCK(m_mutex);
        std::map<std::string, State>::iterator it = m_peers.find(from.ToString());
        if (it != m_peers.end()) {
            it->second.asked_at = 0;
            it->second.asked_height = -1;
        }
        return;
    }
    case CHAIN_BLOCK: {
        if (payload.size() < 1 + 8 + 4 + 4) return;
        const uint64_t transfer = ReadLE64(payload.data() + 1);
        const uint32_t total = ReadLE32(payload.data() + 9);
        const uint32_t offset = ReadLE32(payload.data() + 13);
        const size_t n = payload.size() - 17;
        if (total == 0 || total > MAX_BLOCK_BYTES || (uint64_t)offset + n > total) return;
        std::vector<unsigned char> complete;
        {
            LOCK(m_mutex);
            State& st = m_peers[from.ToString()];
            if (st.transfer != transfer || st.total != total || st.buf.size() != total) {
                // A new transfer, or the first chunk of one: start it.
                st.transfer = transfer;
                st.total = total;
                st.buf.assign(total, 0);
                st.buf_at = now;
            }
            std::copy(payload.begin() + 17, payload.end(), st.buf.begin() + offset);
            // Chunks are sent in order from a single server, so the chunk that
            // reaches the end completes the block.
            if (offset + n == total) {
                complete = st.buf;
                st.transfer = 0;
                st.total = 0;
                st.buf.clear();
            }
        }
        if (!complete.empty()) OnBlock(from, std::move(complete));
        return;
    }
    }
}

std::vector<ChainSync::PeerView> ChainSync::Neighbours() const
{
    std::vector<PeerView> out;
    if (!g_radio) return out;
    const int64_t now = GetTime();
    for (const RadioPeer& p : g_radio->Neighbours(now)) {
        PeerView v;
        v.key = p.key;
        v.addr = p.local;
        {
            LOCK(m_mutex);
            std::map<std::string, State>::const_iterator it = m_peers.find(p.local.ToString());
            if (it != m_peers.end()) {
                v.height = it->second.height;
                v.heard = it->second.heard;
            }
        }
        out.push_back(v);
    }
    return out;
}

void ChainSync::Tick()
{
    if (!g_overlay || !g_radio) return;
    const int64_t now = GetTime();
    const int height = LocalHeight();

    // Serve neighbours always (that is in HandleApp), but poll and pull only
    // when the internet is not already keeping this node current - otherwise
    // the radio's scarce airtime is spent on blocks the node does not need.
    bool isolated = true;
    {
        LOCK(m_mutex);
        if (m_isolated) isolated = m_isolated();
    }
    if (!(m_pull && isolated)) return;

    const std::vector<RadioPeer> neighbours = g_radio->Neighbours(now);
    // Ask each neighbour for its tip. The overlay is request-and-answer, like
    // the rest of it: this node opens the session and the neighbour answers on
    // it (SendTip to the address the request came in on). An unsolicited push
    // the other way would ride a session the neighbour opened and cannot be
    // read on the session this node opened - the two are not the same.
    for (const RadioPeer& p : neighbours) {
        PeerView v;
        v.key = p.key;
        v.addr = p.local;
        if (!Reach(v)) continue;
        bool poll = false;
        {
            LOCK(m_mutex);
            State& st = m_peers[p.local.ToString()];
            // Poll often while behind a neighbour (to notice the next block
            // promptly), rarely otherwise, so an idle feed is nearly silent.
            const int64_t every = (st.height > height) ? 5 : TIP_POLL;
            if (now - st.polled_at >= every) {
                st.polled_at = now;
                poll = true;
            }
        }
        if (poll) Send(p.local, std::vector<unsigned char>{CHAIN_GETTIP});
    }

    // Pull the next block from a neighbour that is ahead: one block, one
    // neighbour at a time. A block must build on the tip to be taken, so there
    // is nothing to gain from asking several at once.
    for (const RadioPeer& p : neighbours) {
        PeerView v;
        v.key = p.key;
        v.addr = p.local;
        int want = -1;
        {
            LOCK(m_mutex);
            State& st = m_peers[p.local.ToString()];
            st.key = p.key;
            if (st.total != 0 && now - st.buf_at > TRANSFER_TTL) {
                st.total = 0;
                st.transfer = 0;
                st.buf.clear();
            }
            const bool outstanding = st.asked_at != 0 && now - st.asked_at < ASK_TIMEOUT;
            // Only follow a neighbour at most CHAIN_MAX_BEHIND ahead; further
            // back needs a fresh copy, not a block-by-block crawl over radio.
            if (!outstanding && st.height > height && st.height - height <= CHAIN_MAX_BEHIND) {
                want = height + 1;
                st.asked_at = now;
                st.asked_height = want;
            }
        }
        if (want >= 0 && Reach(v)) {
            std::vector<unsigned char> msg{CHAIN_GETBLOCK};
            PutU32(msg, (uint32_t)want);
            Send(p.local, msg);
            break; // one at a time
        }
    }
}

void ChainSync::ThreadSync()
{
    int64_t next = GetTime() + 3;
    while (m_interrupt.sleep_for(std::chrono::seconds{1})) {
        if (GetTime() < next) continue;
        Tick();
        next = GetTime() + 5;
    }
}

} // namespace overlay
