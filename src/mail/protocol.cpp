// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/protocol.h>

#include <crypto/common.h>
#include <logging.h>
#include <random.h>
#include <sync.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <condition_variable>
#include <cstring>
#include <limits>

namespace mail {

namespace {

/** Answers waited for by Ask, by request id. */
struct Waiting {
    bool done{false};
    Message answer;
};
Mutex g_wait_mutex;
std::condition_variable g_wait_cv;
std::map<uint64_t, Waiting> g_waiting GUARDED_BY(g_wait_mutex);
bool g_interrupted GUARDED_BY(g_wait_mutex){false};

Mutex g_cells_mutex;
Reassembler g_reassembler GUARDED_BY(g_cells_mutex);

/**
 * Answers already given, by who asked and under which transfer, so a request
 * repeated because its answer was lost gets the same answer back instead of
 * being served twice - which for a signed request would mean refusing it as a
 * replay. Bounded by count and by bytes.
 */
struct Given {
    int64_t at{0};
    std::vector<unsigned char> message;
};
Mutex g_given_mutex;
std::map<std::pair<overlay::Hop, uint64_t>, Given> g_given GUARDED_BY(g_given_mutex);
size_t g_given_bytes GUARDED_BY(g_given_mutex){0};
constexpr int64_t GIVEN_TTL = 120;
constexpr size_t MAX_GIVEN = 256;
constexpr size_t MAX_GIVEN_BYTES = 4 * 1024 * 1024;

void PutU16(std::vector<unsigned char>& out, uint16_t v)
{
    unsigned char b[2];
    WriteLE16(b, v);
    out.insert(out.end(), b, b + 2);
}

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

bool KnownOp(uint8_t raw)
{
    switch (static_cast<Op>(raw)) {
    case Op::PUT_KEY:
    case Op::GET_KEY:
    case Op::DEPOSIT:
    case Op::LIST:
    case Op::FETCH:
    case Op::REMOVE:
    case Op::RESULT:
    case Op::KEY:
    case Op::ITEMS:
    case Op::ITEM:
        return true;
    }
    return false;
}

/** Send one message to a hop, cell by cell. */
bool SendCells(const overlay::Hop& to, uint64_t transfer, const std::vector<unsigned char>& message)
{
    if (!overlay::g_overlay) return false;
    const std::vector<std::vector<unsigned char>> cells = SplitCells(transfer, message);
    if (cells.empty()) return false;
    for (size_t i = 0; i < cells.size(); ++i) {
        const bool sent = to.via_path ? overlay::g_overlay->SendSecret(to.path, cells[i])
                                      : overlay::g_overlay->SendApp(to.addr, cells[i]);
        if (!sent) return false;
        // Paced, so a long letter does not arrive as one burst larger than
        // the receive buffer of a relay on the way.
        if (cells.size() > 1) UninterruptibleSleep(std::chrono::milliseconds{1});
    }
    return true;
}

bool NeedsAuth(Op op)
{
    return op == Op::LIST || op == Op::FETCH || op == Op::REMOVE;
}

} // namespace

std::vector<unsigned char> EncodeMessage(const Message& msg)
{
    std::vector<unsigned char> out;
    out.reserve(9 + msg.body.size());
    out.push_back(static_cast<uint8_t>(msg.op));
    PutU64(out, msg.req);
    out.insert(out.end(), msg.body.begin(), msg.body.end());
    return out;
}

bool DecodeMessage(const std::vector<unsigned char>& raw, Message& out)
{
    if (raw.size() < 9 || !KnownOp(raw[0])) return false;
    out.op = static_cast<Op>(raw[0]);
    out.req = ReadLE64(raw.data() + 1);
    out.body.assign(raw.begin() + 9, raw.end());
    return true;
}

Message Result(uint64_t req, bool ok, const std::string& text)
{
    Message m;
    m.op = Op::RESULT;
    m.req = req;
    m.body.push_back(ok ? 1 : 0);
    const std::string clipped = text.substr(0, 200);
    m.body.insert(m.body.end(), clipped.begin(), clipped.end());
    return m;
}

bool ReadResult(const Message& msg, bool& ok_out, std::string& text_out)
{
    if (msg.op != Op::RESULT || msg.body.empty() || msg.body.size() > 201) return false;
    ok_out = msg.body[0] == 1;
    // Shown to a person, and the mailbox is a stranger.
    text_out = SanitizeString(std::string(msg.body.begin() + 1, msg.body.end()));
    return true;
}

bool IsMailPayload(const std::vector<unsigned char>& payload)
{
    return !payload.empty() && payload[0] == MAIL_CELL;
}

std::vector<std::vector<unsigned char>> SplitCells(uint64_t transfer,
                                                   const std::vector<unsigned char>& message)
{
    std::vector<std::vector<unsigned char>> cells;
    if (message.empty() || message.size() > MAX_MESSAGE_SIZE) return cells;
    const size_t count = (message.size() + CELL_DATA - 1) / CELL_DATA;
    for (size_t i = 0; i < count; ++i) {
        std::vector<unsigned char> cell;
        cell.reserve(CELL_HEADER_SIZE + CELL_DATA);
        cell.push_back(MAIL_CELL);
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

constexpr int64_t Reassembler::TTL;
constexpr size_t Reassembler::MAX_TRANSFERS;
constexpr size_t Reassembler::MAX_BUFFERED;

void Reassembler::Drop(std::map<std::pair<overlay::Hop, uint64_t>, Partial>::iterator it)
{
    m_bytes -= std::min(m_bytes, it->second.bytes);
    m_partial.erase(it);
}

void Reassembler::Expire(int64_t now)
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

bool Reassembler::Add(const overlay::Hop& from, const std::vector<unsigned char>& cell, int64_t now,
                      std::vector<unsigned char>& message_out, uint64_t& transfer_out)
{
    if (cell.size() <= CELL_HEADER_SIZE || cell.size() > CELL_HEADER_SIZE + CELL_DATA) return false;
    if (cell[0] != MAIL_CELL) return false;
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
    const std::pair<overlay::Hop, uint64_t> key(from, transfer);
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

Message Serve(Mailbox& box, const Message& request, int64_t now)
{
    const std::vector<unsigned char>& b = request.body;
    std::string reason;

    Auth auth;
    if (NeedsAuth(request.op)) {
        if (b.size() < AUTH_SIZE || !ParseAuth(b.data(), AUTH_SIZE, auth)) {
            return Result(request.req, false, "That request is not signed.");
        }
        if (!box.CheckAuth(auth, now, reason)) return Result(request.req, false, reason);
    }

    switch (request.op) {
    case Op::PUT_KEY: {
        PreKey key;
        if (!ParsePreKey(b, key)) return Result(request.req, false, "That is not a mail key.");
        const bool ok = box.PutPreKey(key, now, reason);
        return Result(request.req, ok, reason);
    }
    case Op::GET_KEY: {
        if (b.size() != 32) return Result(request.req, false, "That is not a roster key.");
        roster::KeyBytes owner;
        std::copy(b.begin(), b.end(), owner.begin());
        PreKey key;
        if (!box.GetPreKey(owner, now, key)) {
            return Result(request.req, false, "No current mail key is held here for that person.");
        }
        Message m;
        m.op = Op::KEY;
        m.req = request.req;
        m.body = SerializePreKey(key);
        return m;
    }
    case Op::DEPOSIT: {
        uint256 id;
        const bool ok = box.Deposit(b, now, id, reason);
        return Result(request.req, ok, ok ? id.GetHex() : reason);
    }
    case Op::LIST: {
        if (b.size() != AUTH_SIZE) return Result(request.req, false, "Malformed request.");
        std::vector<ItemInfo> items = box.List(auth.owner);
        if (items.size() > MAX_ITEMS_PER_OWNER) items.resize(MAX_ITEMS_PER_OWNER);
        Message m;
        m.op = Op::ITEMS;
        m.req = request.req;
        PutU16(m.body, (uint16_t)items.size());
        for (const ItemInfo& item : items) {
            m.body.insert(m.body.end(), item.id.begin(), item.id.end());
            PutU32(m.body, item.size);
            PutU64(m.body, (uint64_t)item.received);
        }
        return m;
    }
    case Op::FETCH: {
        if (b.size() != AUTH_SIZE + 32) return Result(request.req, false, "Malformed request.");
        uint256 id;
        std::copy(b.begin() + AUTH_SIZE, b.end(), id.begin());
        std::vector<unsigned char> envelope;
        if (!box.Fetch(auth.owner, id, envelope)) return Result(request.req, false, "No such letter is held here.");
        Message m;
        m.op = Op::ITEM;
        m.req = request.req;
        m.body.assign(id.begin(), id.end());
        m.body.insert(m.body.end(), envelope.begin(), envelope.end());
        return m;
    }
    case Op::REMOVE: {
        if (b.size() < AUTH_SIZE + 1) return Result(request.req, false, "Malformed request.");
        const size_t n = b[AUTH_SIZE];
        if (b.size() != AUTH_SIZE + 1 + 32 * n) return Result(request.req, false, "Malformed request.");
        std::vector<uint256> ids(n);
        for (size_t i = 0; i < n; ++i) {
            std::copy(b.begin() + AUTH_SIZE + 1 + 32 * i, b.begin() + AUTH_SIZE + 1 + 32 * (i + 1), ids[i].begin());
        }
        const size_t removed = box.Remove(auth.owner, ids);
        return Result(request.req, true, std::to_string(removed));
    }
    default:
        return Result(request.req, false, "Not a request.");
    }
}

void HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload)
{
    if (!IsMailPayload(payload)) return;
    const int64_t now = GetTime();

    std::vector<unsigned char> raw;
    uint64_t transfer = 0;
    {
        LOCK(g_cells_mutex);
        if (!g_reassembler.Add(from, payload, now, raw, transfer)) return;
    }
    Message msg;
    if (!DecodeMessage(raw, msg)) return;

    if (static_cast<uint8_t>(msg.op) & 0x80) {
        // An answer to something this node asked.
        {
            LOCK(g_wait_mutex);
            std::map<uint64_t, Waiting>::iterator it = g_waiting.find(msg.req);
            if (it == g_waiting.end() || it->second.done) return;
            it->second.done = true;
            it->second.answer = std::move(msg);
        }
        g_wait_cv.notify_all();
        return;
    }

    // A request. Repeated ones get the answer already given.
    const std::pair<overlay::Hop, uint64_t> asked(from, transfer);
    std::vector<unsigned char> answer;
    {
        LOCK(g_given_mutex);
        for (auto it = g_given.begin(); it != g_given.end();) {
            if (now - it->second.at >= GIVEN_TTL) {
                g_given_bytes -= std::min(g_given_bytes, it->second.message.size());
                it = g_given.erase(it);
            } else {
                ++it;
            }
        }
        std::map<std::pair<overlay::Hop, uint64_t>, Given>::const_iterator it = g_given.find(asked);
        if (it != g_given.end()) answer = it->second.message;
    }
    if (answer.empty()) {
        Message reply = g_mailbox ? Serve(*g_mailbox, msg, now)
                                  : Result(msg.req, false, "This node does not hold mail for anyone.");
        answer = EncodeMessage(reply);
        LOCK(g_given_mutex);
        if (g_given.size() < MAX_GIVEN && g_given_bytes + answer.size() <= MAX_GIVEN_BYTES) {
            Given given;
            given.at = now;
            given.message = answer;
            g_given[asked] = given;
            g_given_bytes += answer.size();
        }
    }
    SendCells(from, transfer | ANSWER_BIT, answer);
}

void InterruptAsks()
{
    {
        LOCK(g_wait_mutex);
        g_interrupted = true;
    }
    g_wait_cv.notify_all();
}

bool Ask(const overlay::Hop& to, Message request, Message& answer, std::chrono::milliseconds timeout,
         std::string& error)
{
    request.req = GetRand(std::numeric_limits<uint64_t>::max());
    const uint64_t transfer = GetRand(std::numeric_limits<uint64_t>::max()) & ~ANSWER_BIT;
    const std::vector<unsigned char> raw = EncodeMessage(request);
    if (raw.size() > MAX_MESSAGE_SIZE) {
        error = "The message is too large to send.";
        return false;
    }
    {
        LOCK(g_wait_mutex);
        g_waiting[request.req] = Waiting();
    }

    bool done = false;
    const auto attempt = timeout / 3;
    for (int i = 0; i < 3 && !done; ++i) {
        {
            LOCK(g_wait_mutex);
            if (g_interrupted) {
                error = "Shutting down.";
                break;
            }
        }
        if (!SendCells(to, transfer, raw)) {
            error = "Could not send on the path.";
            break;
        }
        WAIT_LOCK(g_wait_mutex, lock);
        g_wait_cv.wait_for(lock, attempt, [&]() EXCLUSIVE_LOCKS_REQUIRED(g_wait_mutex) {
            return g_waiting[request.req].done || g_interrupted;
        });
        done = g_waiting[request.req].done;
    }

    LOCK(g_wait_mutex);
    if (done) answer = g_waiting[request.req].answer;
    g_waiting.erase(request.req);
    if (!done && error.empty()) error = "No answer came back.";
    return done;
}

} // namespace mail
