// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/protocol.h>

#include <crypto/common.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <cstring>

namespace mail {

namespace {

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

bool NeedsAuth(Op op)
{
    return op == Op::LIST || op == Op::FETCH || op == Op::REMOVE;
}

void ServeRequest(overlay::CellChannel::Request&& request);

/** Mail's cells, served by this node's mailbox if it is one. */
overlay::CellChannel& Channel()
{
    static overlay::CellChannel channel(
        MAIL_CELL, overlay::RelaySender([] { return overlay::g_overlay.get(); }), KnownOp, ServeRequest);
    return channel;
}

void ServeRequest(overlay::CellChannel::Request&& request)
{
    Message msg;
    if (!DecodeMessage(request.message, msg)) return;
    const Message reply = g_mailbox ? Serve(*g_mailbox, msg, request.received)
                                    : Result(msg.req, false, "This node does not hold mail for anyone.");
    Channel().Answer(request.from, request.transfer, EncodeMessage(reply));
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
    return overlay::SplitCells(MAIL_CELL, transfer, message);
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
    Channel().Handle(from, std::move(payload));
}

void InterruptAsks()
{
    Channel().Interrupt();
}

bool Ask(const overlay::Hop& to, Message request, Message& answer, std::chrono::milliseconds timeout,
         std::string& error, std::chrono::milliseconds per_cell)
{
    std::vector<unsigned char> raw;
    if (!Channel().Ask(to, EncodeMessage(request), raw, timeout, error, per_cell)) return false;
    // The channel only hands back answers with an op mail knows.
    if (!DecodeMessage(raw, answer)) {
        error = "No answer came back.";
        return false;
    }
    return true;
}

} // namespace mail
