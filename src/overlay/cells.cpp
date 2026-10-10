// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/cells.h>

#include <crypto/common.h>
#include <random.h>
#include <util/time.h>

#include <algorithm>
#include <limits>

namespace overlay {

namespace {

void PutU16(std::vector<unsigned char>& out, uint16_t v)
{
    unsigned char b[2];
    WriteLE16(b, v);
    out.insert(out.end(), b, b + 2);
}

void PutU64(std::vector<unsigned char>& out, uint64_t v)
{
    unsigned char b[8];
    WriteLE64(b, v);
    out.insert(out.end(), b, b + 8);
}

} // namespace

std::vector<std::vector<unsigned char>> SplitCells(uint8_t tag, uint64_t transfer,
                                                   const std::vector<unsigned char>& message)
{
    std::vector<std::vector<unsigned char>> cells;
    if (message.empty() || message.size() > MAX_CELL_MESSAGE_SIZE) return cells;
    const size_t count = (message.size() + CELL_DATA - 1) / CELL_DATA;
    for (size_t i = 0; i < count; ++i) {
        std::vector<unsigned char> cell;
        cell.reserve(CELL_HEADER_SIZE + CELL_DATA);
        cell.push_back(tag);
        PutU64(cell, transfer);
        PutU16(cell, (uint16_t)i);
        PutU16(cell, (uint16_t)count);
        const size_t from = i * CELL_DATA;
        const size_t to = std::min(message.size(), from + CELL_DATA);
        cell.insert(cell.end(), message.begin() + from, message.begin() + to);
        cells.push_back(std::move(cell));
    }
    return cells;
}

constexpr int64_t CellReassembler::TTL;
constexpr size_t CellReassembler::MAX_TRANSFERS;
constexpr size_t CellReassembler::MAX_BUFFERED;

void CellReassembler::Drop(std::map<std::pair<Hop, uint64_t>, Partial>::iterator it)
{
    m_bytes -= std::min(m_bytes, it->second.bytes);
    m_partial.erase(it);
}

void CellReassembler::Expire(int64_t now)
{
    for (auto it = m_partial.begin(); it != m_partial.end();) {
        if (now - it->second.started >= TTL) {
            auto gone = it++;
            Drop(gone);
        } else {
            ++it;
        }
    }
}

bool CellReassembler::Add(const Hop& from, const std::vector<unsigned char>& cell, int64_t now,
                          std::vector<unsigned char>& message_out, uint64_t& transfer_out)
{
    if (cell.size() <= CELL_HEADER_SIZE || cell.size() > CELL_HEADER_SIZE + CELL_DATA) return false;
    if (cell[0] != m_tag) return false;
    const uint64_t transfer = ReadLE64(cell.data() + 1);
    const size_t index = ReadLE16(cell.data() + 9);
    const size_t count = ReadLE16(cell.data() + 11);
    if (count == 0 || count > MAX_CELLS || index >= count) return false;
    // Every cell but the last is full, so a message has exactly one shape.
    if (index + 1 < count && cell.size() != CELL_HEADER_SIZE + CELL_DATA) return false;

    const std::vector<unsigned char> data(cell.begin() + CELL_HEADER_SIZE, cell.end());
    if (count == 1) {
        message_out = data;
        transfer_out = transfer;
        return true;
    }

    Expire(now);
    const std::pair<Hop, uint64_t> key(from, transfer);
    auto it = m_partial.find(key);
    if (it == m_partial.end()) {
        if (m_partial.size() >= MAX_TRANSFERS || m_bytes + count * CELL_DATA > MAX_BUFFERED) return false;
        Partial p;
        p.cells.resize(count);
        p.started = now;
        it = m_partial.emplace(key, std::move(p)).first;
    }
    Partial& p = it->second;
    // A transfer is one message; cells disagreeing about its length are not
    // part of it.
    if (p.cells.size() != count) return false;
    if (!p.cells[index].empty()) return false; // a repeat, already held
    p.cells[index] = data;
    ++p.have;
    p.bytes += data.size();
    m_bytes += data.size();
    if (p.have < count) return false;

    message_out.clear();
    for (const std::vector<unsigned char>& c : p.cells) message_out.insert(message_out.end(), c.begin(), c.end());
    transfer_out = transfer;
    Drop(it);
    return true;
}

constexpr int64_t CellChannel::GIVEN_TTL;
constexpr size_t CellChannel::MAX_GIVEN;
constexpr size_t CellChannel::MAX_GIVEN_BYTES;
constexpr size_t CellChannel::MAX_IN_FLIGHT;

CellChannel::CellChannel(uint8_t tag, Sender sender, OpCheck known_op, Server server)
    : m_tag(tag), m_sender(std::move(sender)), m_known_op(std::move(known_op)), m_reassembler(tag)
{
    LOCK(m_server_mutex);
    m_server = std::move(server);
}

void CellChannel::SetServer(Server server)
{
    LOCK(m_server_mutex);
    m_server = std::move(server);
}

size_t CellChannel::InFlight() const
{
    LOCK(m_given_mutex);
    return m_in_flight.size();
}

bool CellChannel::SendCells(const Hop& to, uint64_t transfer, const std::vector<unsigned char>& message)
{
    if (!m_sender) return false;
    const std::vector<std::vector<unsigned char>> cells = SplitCells(m_tag, transfer, message);
    if (cells.empty()) return false;
    for (size_t i = 0; i < cells.size(); ++i) {
        if (!m_sender(to, cells[i])) return false;
        // Paced, so a long message does not arrive as one burst larger than
        // the receive buffer of a relay on the way.
        if (cells.size() > 1) UninterruptibleSleep(std::chrono::milliseconds{1});
    }
    return true;
}

void CellChannel::ExpireGiven(int64_t now)
{
    for (auto it = m_given.begin(); it != m_given.end();) {
        if (now - it->second.at >= GIVEN_TTL) {
            m_given_bytes -= std::min(m_given_bytes, it->second.message.size());
            it = m_given.erase(it);
        } else {
            ++it;
        }
    }
    // A server that never answered has given up; let the request be asked again.
    for (auto it = m_in_flight.begin(); it != m_in_flight.end();) {
        if (now - it->second >= GIVEN_TTL) {
            it = m_in_flight.erase(it);
        } else {
            ++it;
        }
    }
}

void CellChannel::Handle(const Hop& from, std::vector<unsigned char>&& payload)
{
    if (!IsOurs(payload)) return;
    const int64_t now = GetTime();

    // A cell of an answer being waited for: note that it is still coming.
    if (payload.size() >= CELL_HEADER_SIZE) {
        const uint64_t cell_transfer = ReadLE64(payload.data() + 1);
        if (cell_transfer & ANSWER_BIT) {
            LOCK(m_wait_mutex);
            std::map<uint64_t, uint64_t>::const_iterator t = m_transfers.find(cell_transfer & ~ANSWER_BIT);
            if (t != m_transfers.end()) {
                std::map<uint64_t, Waiting>::iterator w = m_waiting.find(t->second);
                if (w != m_waiting.end()) w->second.progress = std::chrono::steady_clock::now();
            }
        }
    }

    std::vector<unsigned char> raw;
    uint64_t transfer = 0;
    {
        LOCK(m_cells_mutex);
        if (!m_reassembler.Add(from, payload, now, raw, transfer)) return;
    }
    if (raw.size() < CELL_MESSAGE_HEADER || !m_known_op || !m_known_op(raw[0])) return;
    const uint64_t req = ReadLE64(raw.data() + 1);

    if (raw[0] & 0x80) {
        // An answer to something asked here.
        {
            LOCK(m_wait_mutex);
            std::map<uint64_t, Waiting>::iterator it = m_waiting.find(req);
            if (it == m_waiting.end() || it->second.done) return;
            it->second.done = true;
            it->second.answer = std::move(raw);
        }
        m_wait_cv.notify_all();
        return;
    }

    // A request. Repeated ones get the answer already given, or nothing while
    // the first is still being served - the asker's next try will find it.
    const std::pair<Hop, uint64_t> asked(from, transfer);
    std::vector<unsigned char> answer;
    {
        LOCK(m_given_mutex);
        ExpireGiven(now);
        std::map<std::pair<Hop, uint64_t>, Given>::const_iterator it = m_given.find(asked);
        if (it != m_given.end()) {
            answer = it->second.message;
        } else {
            if (m_in_flight.count(asked) || m_in_flight.size() >= MAX_IN_FLIGHT) return;
            m_in_flight[asked] = now;
        }
    }
    if (!answer.empty()) {
        SendCells(from, transfer | ANSWER_BIT, answer);
        return;
    }

    Server server;
    {
        LOCK(m_server_mutex);
        server = m_server;
    }
    if (!server) {
        LOCK(m_given_mutex);
        m_in_flight.erase(asked);
        return;
    }
    Request request;
    request.from = from;
    request.transfer = transfer;
    request.message = std::move(raw);
    request.received = now;
    server(std::move(request));
}

void CellChannel::Answer(const Hop& to, uint64_t transfer, const std::vector<unsigned char>& answer)
{
    const std::pair<Hop, uint64_t> asked(to, transfer);
    {
        LOCK(m_given_mutex);
        m_in_flight.erase(asked);
        if (!m_given.count(asked) && m_given.size() < MAX_GIVEN &&
            m_given_bytes + answer.size() <= MAX_GIVEN_BYTES) {
            Given given;
            given.at = GetTime();
            given.message = answer;
            m_given[asked] = std::move(given);
            m_given_bytes += answer.size();
        }
    }
    SendCells(to, transfer | ANSWER_BIT, answer);
}

void CellChannel::Interrupt()
{
    {
        LOCK(m_wait_mutex);
        m_interrupted = true;
    }
    m_wait_cv.notify_all();
}

bool CellChannel::Ask(const Hop& to, std::vector<unsigned char> request, std::vector<unsigned char>& answer,
                      std::chrono::milliseconds timeout, std::string& error, std::chrono::milliseconds per_cell)
{
    if (request.size() > MAX_CELL_MESSAGE_SIZE) {
        error = "The message is too large to send.";
        return false;
    }
    if (request.size() < CELL_MESSAGE_HEADER) {
        error = "Malformed request.";
        return false;
    }
    const uint64_t req = GetRand(std::numeric_limits<uint64_t>::max());
    WriteLE64(request.data() + 1, req);
    const uint64_t transfer = GetRand(std::numeric_limits<uint64_t>::max()) & ~ANSWER_BIT;
    {
        LOCK(m_wait_mutex);
        m_waiting[req] = Waiting();
        m_transfers[transfer] = req;
    }

    bool done = false;
    const int64_t cells = (int64_t)((request.size() + CELL_DATA - 1) / CELL_DATA);
    // On a radio hop a try lasts until the request's cells are out and the
    // first of the answer's is back; after that, while the answer is arriving,
    // until it pauses for longer than a cell takes, both ways.
    const auto attempt = timeout / 3 + per_cell * (cells + 1);
    const auto pause = timeout / 3 + per_cell * 2;
    for (int i = 0; i < 3 && !done; ++i) {
        {
            LOCK(m_wait_mutex);
            if (m_interrupted) {
                error = "Shutting down.";
                break;
            }
        }
        if (!SendCells(to, transfer, request)) {
            error = "Could not send on the path.";
            break;
        }
        WAIT_LOCK(m_wait_mutex, lock);
        auto until = std::chrono::steady_clock::now() + attempt;
        std::chrono::steady_clock::time_point seen = m_waiting[req].progress;
        while (true) {
            m_wait_cv.wait_until(lock, until, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_wait_mutex) {
                return m_waiting[req].done || m_interrupted;
            });
            const Waiting& w = m_waiting[req];
            if (w.done || m_interrupted || w.progress == seen) break;
            // Part of the answer came in since: give the rest time.
            seen = w.progress;
            until = std::max(until, seen + pause);
        }
        done = m_waiting[req].done;
    }

    LOCK(m_wait_mutex);
    if (done) answer = std::move(m_waiting[req].answer);
    m_waiting.erase(req);
    m_transfers.erase(transfer);
    if (!done && error.empty()) error = "No answer came back.";
    return done;
}

CellChannel::Sender RelaySender(std::function<Relay*()> relay)
{
    return [relay](const Hop& to, const std::vector<unsigned char>& cell) {
        Relay* r = relay ? relay() : nullptr;
        if (!r) return false;
        return to.via_path ? r->SendSecret(to.path, cell) : r->SendApp(to.addr, cell);
    };
}

} // namespace overlay
