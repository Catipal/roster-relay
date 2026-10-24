// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/stream.h>

#include <crypto/common.h>

#include <algorithm>
#include <cmath>

namespace overlay {

namespace {

void PutU16(std::vector<unsigned char>& out, uint16_t v) { unsigned char b[2]; WriteLE16(b, v); out.insert(out.end(), b, b + 2); }
void PutU32(std::vector<unsigned char>& out, uint32_t v) { unsigned char b[4]; WriteLE32(b, v); out.insert(out.end(), b, b + 4); }
void PutU64(std::vector<unsigned char>& out, uint64_t v) { unsigned char b[8]; WriteLE64(b, v); out.insert(out.end(), b, b + 8); }

std::vector<unsigned char> Header(uint8_t tag, uint32_t id)
{
    std::vector<unsigned char> out{tag};
    PutU32(out, id);
    return out;
}

//! A burst of this many cells may leave at once before pacing holds the rest.
constexpr double BURST_BYTES = 8.0 * MAX_PATH_APP_PAYLOAD;
//! Bytes a second the pace gains for each cell acknowledged: about 5 KiB/s
//! more each second at full speed.
constexpr double RATE_STEP = 64.0;
//! An acknowledgement goes out unasked once reading has opened this many cells.
constexpr uint16_t WINDOW_UPDATE_CELLS = 8;

} // namespace

bool IsServicePayload(const std::vector<unsigned char>& payload)
{
    return !payload.empty() && payload[0] >= SVC_OPEN && payload[0] <= SVC_RESET;
}

bool ServiceStreamId(const std::vector<unsigned char>& payload, uint32_t& id)
{
    if (!IsServicePayload(payload) || payload.size() < 5) return false;
    id = ReadLE32(payload.data() + 1);
    return true;
}

ReliableStream::ReliableStream(uint32_t id) : m_id(id) {}

// --- the program's side -----------------------------------------------------------

size_t ReliableStream::SendSpace() const
{
    size_t held = m_sendbuf.size();
    for (const auto& c : m_unacked) held += c.second.data.size();
    return held >= STREAM_BUFFER ? 0 : STREAM_BUFFER - held;
}

size_t ReliableStream::Write(const unsigned char* data, size_t n)
{
    if (m_shutdown || m_dead) return 0;
    const size_t take = std::min(n, SendSpace());
    m_sendbuf.insert(m_sendbuf.end(), data, data + take);
    return take;
}

void ReliableStream::Shutdown() { m_shutdown = true; }

std::vector<unsigned char> ReliableStream::Read(size_t max)
{
    const size_t n = std::min(max, m_readbuf.size());
    std::vector<unsigned char> out(m_readbuf.begin(), m_readbuf.begin() + n);
    m_readbuf.erase(m_readbuf.begin(), m_readbuf.begin() + n);
    // Room opened: say so, or a sender that saw no room would wait for a
    // retransmission timeout to find out.
    if (n > 0 && WindowToOffer() >= m_offered + WINDOW_UPDATE_CELLS) {
        m_ack_due = true;
        m_ack_at = 0;
    }
    return out;
}

bool ReliableStream::ReadClosed() const
{
    return m_peer_fin && m_rcv_next == m_peer_end && m_readbuf.empty();
}

bool ReliableStream::Finished() const
{
    return m_shutdown && m_sendbuf.empty() && m_unacked.empty() && m_fin_acked && ReadClosed();
}

std::vector<unsigned char> ReliableStream::ResetMessage(uint32_t id) { return Header(SVC_RESET, id); }

// --- the network's side -----------------------------------------------------------

uint16_t ReliableStream::WindowToOffer() const
{
    const size_t held = m_readbuf.size() + m_ooo_bytes;
    const size_t room = held >= STREAM_BUFFER ? 0 : STREAM_BUFFER - held;
    return (uint16_t)std::min<size_t>(room / STREAM_CELL, 0xffff);
}

std::vector<unsigned char> ReliableStream::DataMessage(uint32_t seq, const Cell& cell) const
{
    std::vector<unsigned char> out = Header(SVC_DATA, m_id);
    PutU32(out, seq);
    out.insert(out.end(), cell.data.begin(), cell.data.end());
    return out;
}

std::vector<unsigned char> ReliableStream::AckMessage() const
{
    std::vector<unsigned char> out = Header(SVC_ACK, m_id);
    PutU32(out, m_rcv_next);
    uint64_t sack = 0;
    for (int i = 0; i < 64; ++i) {
        if (m_ooo.count(m_rcv_next + 1 + (uint32_t)i)) sack |= (uint64_t)1 << i;
    }
    PutU64(out, sack);
    PutU16(out, WindowToOffer());
    out.push_back(m_peer_fin && m_rcv_next == m_peer_end ? 1 : 0);
    return out;
}

void ReliableStream::Receive(const std::vector<unsigned char>& msg, int64_t now_ms)
{
    uint32_t id;
    if (m_dead || !ServiceStreamId(msg, id) || id != m_id) return;
    switch (msg[0]) {
    case SVC_DATA:
        if (msg.size() >= 9 && msg.size() <= 9 + STREAM_CELL) {
            OnData(ReadLE32(msg.data() + 5), msg.data() + 9, msg.size() - 9, now_ms);
        }
        return;
    case SVC_ACK:
        if (msg.size() == 20) {
            OnAck(ReadLE32(msg.data() + 5), ReadLE64(msg.data() + 9), ReadLE16(msg.data() + 17), msg[19] & 1, now_ms);
        }
        return;
    case SVC_FIN:
        if (msg.size() == 9) {
            const uint32_t end = ReadLE32(msg.data() + 5);
            // An end before what has already come would be a contradiction.
            if (end >= m_rcv_next && (!m_peer_fin || end == m_peer_end)) {
                m_peer_fin = true;
                m_peer_end = end;
            }
            m_ack_due = true;
            m_ack_at = now_ms;
        }
        return;
    case SVC_RESET:
        m_dead = true;
        return;
    }
}

void ReliableStream::OnData(uint32_t seq, const unsigned char* data, size_t n, int64_t now_ms)
{
    const bool repeat = seq < m_rcv_next || m_ooo.count(seq) || (m_peer_fin && seq >= m_peer_end);
    const bool too_far = seq >= m_rcv_next + 4096;
    const bool no_room = m_readbuf.size() + m_ooo_bytes + n > STREAM_BUFFER;
    if (repeat || too_far || no_room || n == 0) {
        // Answered at once: a repeat means an acknowledgement was lost, and
        // no room is something the sender has to hear.
        m_ack_due = true;
        m_ack_at = now_ms;
        return;
    }
    if (seq == m_rcv_next) {
        m_readbuf.insert(m_readbuf.end(), data, data + n);
        ++m_rcv_next;
        for (auto it = m_ooo.find(m_rcv_next); it != m_ooo.end(); it = m_ooo.find(m_rcv_next)) {
            m_readbuf.insert(m_readbuf.end(), it->second.begin(), it->second.end());
            m_ooo_bytes -= it->second.size();
            m_ooo.erase(it);
            ++m_rcv_next;
        }
        ++m_cells_since_ack;
        // Every second cell, or a moment after a lone one; at once after a gap closed.
        const int64_t when = (m_cells_since_ack >= 2 || !m_ooo.empty()) ? now_ms : now_ms + ACK_DELAY_MS;
        m_ack_at = m_ack_due ? std::min(m_ack_at, when) : when;
        m_ack_due = true;
    } else {
        m_ooo.emplace(seq, std::vector<unsigned char>(data, data + n));
        m_ooo_bytes += n;
        // A gap: said at once, so the sender can send the missing cell again.
        m_ack_due = true;
        m_ack_at = now_ms;
    }
}

void ReliableStream::Sample(int64_t rtt_ms)
{
    rtt_ms = std::max<int64_t>(rtt_ms, 1);
    if (m_srtt < 0) {
        m_srtt = rtt_ms;
        m_rttvar = rtt_ms / 2;
    } else {
        m_rttvar = (3 * m_rttvar + std::abs(m_srtt - rtt_ms)) / 4;
        m_srtt = (7 * m_srtt + rtt_ms) / 8;
    }
    m_rto = std::max(MIN_RTO_MS, std::min(MAX_RTO_MS, m_srtt + std::max<int64_t>(4 * m_rttvar, 100)));
}

void ReliableStream::Lost(int64_t now_ms, bool timeout)
{
    // Whatever was lost was most likely dropped for going too fast.
    if (timeout || !m_in_recovery) m_rate = std::max(m_rate / 2, (double)STREAM_MIN_RATE);
    if (timeout) {
        m_ssthresh = std::max(m_cwnd / 2, 2.0);
        m_cwnd = 2;
        m_rto = std::min(MAX_RTO_MS, m_rto * 2);
        m_in_recovery = false;
    } else if (!m_in_recovery) {
        // Once per window: the cells already out were sent at the old rate.
        m_ssthresh = std::max(m_cwnd / 2, 2.0);
        m_cwnd = m_ssthresh;
        m_in_recovery = true;
        m_recover = m_next_seq;
    }
}

void ReliableStream::OnAck(uint32_t next, uint64_t sack, uint16_t window, bool fin_seen, int64_t now_ms)
{
    if (next > m_next_seq) return; // acknowledges what was never sent
    m_peer_window = window;
    size_t newly = 0;
    int64_t newest_once = -1;
    for (auto it = m_unacked.begin(); it != m_unacked.end() && it->first < next;) {
        if (it->second.tries == 1) newest_once = std::max(newest_once, it->second.sent_at);
        it = m_unacked.erase(it);
        ++newly;
    }
    int above = 0;
    for (int i = 0; i < 64; ++i) {
        if (!((sack >> i) & 1)) continue;
        ++above;
        auto it = m_unacked.find(next + 1 + (uint32_t)i);
        if (it == m_unacked.end()) continue;
        if (it->second.tries == 1) newest_once = std::max(newest_once, it->second.sent_at);
        m_unacked.erase(it);
        ++newly;
    }
    // Only cells sent once tell the round trip: an answer to a cell sent
    // twice could be to either sending.
    if (newest_once >= 0) Sample(now_ms - newest_once);
    if (m_in_recovery && next >= m_recover) m_in_recovery = false;
    if (newly > 0) {
        m_cwnd += m_cwnd < m_ssthresh ? (double)newly : (double)newly / m_cwnd;
        m_cwnd = std::min(m_cwnd, MAX_WINDOW);
        m_rate = std::min(m_rate + RATE_STEP * (double)newly, (double)SERVICE_SEND_RATE);
    }
    // Three cells past a gap have arrived: the cell at the gap was lost, not
    // late. Sent again now, not after a timeout.
    auto missing = m_unacked.find(next);
    if (above >= 3 && missing != m_unacked.end() && !missing->second.fast) {
        missing->second.fast = true;
        missing->second.sent_at = -MAX_RTO_MS; // due at the next poll
        Lost(now_ms, false);
    }
    if (fin_seen && next == m_next_seq && m_fin_sent_at >= 0 && m_sendbuf.empty()) m_fin_acked = true;
}

bool ReliableStream::Spend(size_t bytes, int64_t now_ms)
{
    if (m_tokens_at < 0) {
        m_tokens = BURST_BYTES;
    } else if (now_ms > m_tokens_at) {
        m_tokens = std::min(BURST_BYTES, m_tokens + (double)(now_ms - m_tokens_at) * m_rate / 1000.0);
    }
    m_tokens_at = now_ms;
    if (m_tokens < (double)bytes) return false;
    m_tokens -= (double)bytes;
    return true;
}

std::vector<std::vector<unsigned char>> ReliableStream::Poll(int64_t now_ms)
{
    std::vector<std::vector<unsigned char>> out;
    if (m_dead) return out;

    // Cells not answered in time, oldest first.
    bool timed_out = false;
    for (auto& entry : m_unacked) {
        Cell& cell = entry.second;
        if (cell.sent_at + m_rto > now_ms) continue;
        const bool probe = m_peer_window == 0;
        if (cell.tries >= MAX_TRIES && !probe) {
            m_dead = true;
            out.clear();
            out.push_back(ResetMessage(m_id));
            return out;
        }
        if (!Spend(cell.data.size() + 9, now_ms)) break;
        // A probe of a full receiver is not a loss, and does not count.
        if (!probe) ++cell.tries;
        if (!cell.fast || cell.sent_at >= 0) timed_out = timed_out || !probe;
        cell.sent_at = now_ms;
        out.push_back(DataMessage(entry.first, cell));
    }
    if (timed_out) Lost(now_ms, true);

    // New cells, as many as the window, the far end's room and the pace allow.
    while (!m_sendbuf.empty()) {
        double limit = std::min(m_cwnd, (double)m_peer_window);
        // With nothing out, one cell may always go, so a full receiver that
        // has made room is found out even if its word of it was lost.
        if (m_unacked.empty()) limit = std::max(limit, 1.0);
        if ((double)m_unacked.size() >= limit) break;
        const size_t n = std::min(STREAM_CELL, m_sendbuf.size());
        if (!Spend(n + 9, now_ms)) break;
        Cell cell;
        cell.data.assign(m_sendbuf.begin(), m_sendbuf.begin() + n);
        m_sendbuf.erase(m_sendbuf.begin(), m_sendbuf.begin() + n);
        cell.sent_at = now_ms;
        cell.tries = 1;
        out.push_back(DataMessage(m_next_seq, cell));
        m_unacked.emplace(m_next_seq++, std::move(cell));
    }

    // The end, once every byte written has been cut into cells.
    if (m_shutdown && m_sendbuf.empty() && !m_fin_acked && (m_fin_sent_at < 0 || m_fin_sent_at + m_rto <= now_ms)) {
        if (m_fin_tries >= MAX_TRIES) {
            m_dead = true;
            out.clear();
            out.push_back(ResetMessage(m_id));
            return out;
        }
        std::vector<unsigned char> fin = Header(SVC_FIN, m_id);
        PutU32(fin, m_next_seq);
        out.push_back(std::move(fin));
        m_fin_sent_at = now_ms;
        ++m_fin_tries;
    }

    if (m_ack_due && m_ack_at <= now_ms) {
        out.push_back(AckMessage());
        m_offered = WindowToOffer();
        m_ack_due = false;
        m_cells_since_ack = 0;
    }
    return out;
}

int64_t ReliableStream::NextWake(int64_t now_ms) const
{
    if (m_dead) return now_ms + 1000;
    int64_t wake = now_ms + 1000;
    if (m_ack_due) wake = std::min(wake, m_ack_at);
    for (const auto& c : m_unacked) wake = std::min(wake, c.second.sent_at + m_rto);
    if (m_shutdown && m_sendbuf.empty() && !m_fin_acked) {
        wake = std::min(wake, m_fin_sent_at < 0 ? now_ms : m_fin_sent_at + m_rto);
    }
    if (!m_sendbuf.empty()) {
        double limit = std::min(m_cwnd, (double)m_peer_window);
        if (m_unacked.empty()) limit = std::max(limit, 1.0);
        if ((double)m_unacked.size() < limit) {
            // Due when the pace allows the next cell.
            const double need = (double)(std::min(STREAM_CELL, m_sendbuf.size()) + 9);
            const double have = m_tokens_at < 0 ? BURST_BYTES : m_tokens;
            const int64_t wait = have >= need ? 0 : (int64_t)std::ceil((need - have) * 1000.0 / m_rate);
            wake = std::min(wake, std::max(now_ms, m_tokens_at) + wait);
        }
    }
    return std::max(wake, now_ms);
}

} // namespace overlay
