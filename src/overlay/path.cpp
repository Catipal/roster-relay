// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/path.h>

#include <overlay/frame.h>
#include <crypto/common.h>
#include <streams.h>
#include <version.h>

#include <cstring>

namespace overlay {

namespace {

/** kind(1) || path_id(8) is the largest fixed prefix any message carries. */
constexpr size_t KIND_SIZE = 1;
constexpr size_t PATH_ID_SIZE = 8;

void PutKind(MessageKind kind, std::vector<unsigned char>& out)
{
    out.clear();
    out.push_back(static_cast<unsigned char>(kind));
}

void PutU64(uint64_t v, std::vector<unsigned char>& out)
{
    unsigned char buf[8];
    WriteLE64(buf, v);
    out.insert(out.end(), buf, buf + sizeof(buf));
}

bool KnownKind(unsigned char raw, MessageKind& out)
{
    switch (raw) {
    case static_cast<unsigned char>(MessageKind::APP_DATA):
    case static_cast<unsigned char>(MessageKind::PATH_BUILD):
    case static_cast<unsigned char>(MessageKind::PATH_OK):
    case static_cast<unsigned char>(MessageKind::PATH_FAIL):
    case static_cast<unsigned char>(MessageKind::PATH_DATA):
    case static_cast<unsigned char>(MessageKind::PATH_BIND):
    case static_cast<unsigned char>(MessageKind::INTRODUCE):
    case static_cast<unsigned char>(MessageKind::MEET):
        out = static_cast<MessageKind>(raw);
        return true;
    default:
        return false;
    }
}

/** Addresses ride as addrv2, the same encoding the roster and p2p already use. */
bool PutService(const CService& s, std::vector<unsigned char>& out)
{
    if (!s.IsValid()) return false;
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    ds << s;
    if (ds.size() > 64) return false;
    out.push_back(static_cast<unsigned char>(ds.size()));
    out.insert(out.end(), ds.begin(), ds.end());
    return true;
}

bool GetService(const unsigned char* p, size_t len, CService& out, size_t& consumed)
{
    if (len < 1) return false;
    const size_t n = p[0];
    if (n == 0 || n > 64 || len < 1 + n) return false;
    CDataStream ds(reinterpret_cast<const char*>(p + 1),
                   reinterpret_cast<const char*>(p + 1 + n),
                   SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    try {
        ds >> out;
    } catch (const std::exception&) {
        return false;
    }
    if (!out.IsValid()) return false;
    consumed = 1 + n;
    return true;
}

} // namespace

bool EncodeAppData(const std::vector<unsigned char>& payload,
                   std::vector<unsigned char>& out)
{
    if (payload.size() + KIND_SIZE > MAX_FRAME_PAYLOAD) return false;
    PutKind(MessageKind::APP_DATA, out);
    out.insert(out.end(), payload.begin(), payload.end());
    return true;
}

bool EncodePathBuild(uint64_t path_id, const CService& next_hop,
                     std::vector<unsigned char>& out)
{
    PutKind(MessageKind::PATH_BUILD, out);
    PutU64(path_id, out);
    if (!PutService(next_hop, out)) {
        out.clear();
        return false;
    }
    return out.size() <= MAX_FRAME_PAYLOAD;
}

bool EncodePathResult(bool ok, uint64_t path_id, std::vector<unsigned char>& out)
{
    PutKind(ok ? MessageKind::PATH_OK : MessageKind::PATH_FAIL, out);
    PutU64(path_id, out);
    return true;
}

bool EncodePathData(uint64_t path_id, const std::vector<unsigned char>& inner,
                    std::vector<unsigned char>& out)
{
    if (inner.empty()) return false;
    if (KIND_SIZE + PATH_ID_SIZE + inner.size() > MAX_FRAME_PAYLOAD) return false;
    PutKind(MessageKind::PATH_DATA, out);
    PutU64(path_id, out);
    out.insert(out.end(), inner.begin(), inner.end());
    return true;
}

bool EncodePathBind(uint64_t path_id, std::vector<unsigned char>& out)
{
    PutKind(MessageKind::PATH_BIND, out);
    PutU64(path_id, out);
    return true;
}

bool DecodePathBind(const std::vector<unsigned char>& msg, uint64_t& path_id_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind) || kind != MessageKind::PATH_BIND) return false;
    if (msg.size() != KIND_SIZE + PATH_ID_SIZE) return false;
    path_id_out = ReadLE64(msg.data() + KIND_SIZE);
    return true;
}

bool EncodeIntroduce(const roster::KeyBytes& service, std::vector<unsigned char>& out)
{
    PutKind(MessageKind::INTRODUCE, out);
    out.insert(out.end(), service.begin(), service.end());
    return true;
}

bool DecodeIntroduce(const std::vector<unsigned char>& msg, roster::KeyBytes& service_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind) || kind != MessageKind::INTRODUCE) return false;
    if (msg.size() != KIND_SIZE + service_out.size()) return false;
    std::copy(msg.begin() + KIND_SIZE, msg.end(), service_out.begin());
    return true;
}

bool EncodeMeet(const roster::KeyBytes& service, uint64_t meet_id,
                std::vector<unsigned char>& out)
{
    PutKind(MessageKind::MEET, out);
    PutU64(meet_id, out);
    out.insert(out.end(), service.begin(), service.end());
    return true;
}

bool DecodeMeet(const std::vector<unsigned char>& msg, roster::KeyBytes& service_out,
                uint64_t& meet_id_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind) || kind != MessageKind::MEET) return false;
    if (msg.size() != KIND_SIZE + PATH_ID_SIZE + service_out.size()) return false;
    meet_id_out = ReadLE64(msg.data() + KIND_SIZE);
    std::copy(msg.begin() + KIND_SIZE + PATH_ID_SIZE, msg.end(), service_out.begin());
    return true;
}

bool DecodeKind(const std::vector<unsigned char>& msg, MessageKind& kind_out)
{
    if (msg.empty()) return false;
    return KnownKind(msg[0], kind_out);
}

bool DecodeAppData(const std::vector<unsigned char>& msg,
                   std::vector<unsigned char>& payload_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind) || kind != MessageKind::APP_DATA) return false;
    payload_out.assign(msg.begin() + KIND_SIZE, msg.end());
    return true;
}

bool DecodePathBuild(const std::vector<unsigned char>& msg, uint64_t& path_id_out,
                     CService& next_hop_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind) || kind != MessageKind::PATH_BUILD) return false;
    if (msg.size() < KIND_SIZE + PATH_ID_SIZE + 1) return false;
    path_id_out = ReadLE64(msg.data() + KIND_SIZE);

    size_t consumed = 0;
    const size_t at = KIND_SIZE + PATH_ID_SIZE;
    if (!GetService(msg.data() + at, msg.size() - at, next_hop_out, consumed)) return false;
    // Trailing bytes would mean two encodings of the same message, so refuse
    // rather than ignore them.
    return at + consumed == msg.size();
}

bool DecodePathResult(const std::vector<unsigned char>& msg, bool& ok_out,
                      uint64_t& path_id_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind)) return false;
    if (kind != MessageKind::PATH_OK && kind != MessageKind::PATH_FAIL) return false;
    if (msg.size() != KIND_SIZE + PATH_ID_SIZE) return false;
    ok_out = (kind == MessageKind::PATH_OK);
    path_id_out = ReadLE64(msg.data() + KIND_SIZE);
    return true;
}

bool DecodePathData(const std::vector<unsigned char>& msg, uint64_t& path_id_out,
                    std::vector<unsigned char>& inner_out)
{
    MessageKind kind;
    if (!DecodeKind(msg, kind) || kind != MessageKind::PATH_DATA) return false;
    if (msg.size() <= KIND_SIZE + PATH_ID_SIZE) return false;
    path_id_out = ReadLE64(msg.data() + KIND_SIZE);
    inner_out.assign(msg.begin() + KIND_SIZE + PATH_ID_SIZE, msg.end());
    return true;
}

// Out-of-line definitions. This tree is C++11, where a static constexpr member
// still needs one once it is odr-used - passing it to anything taking a
// reference, which BOOST_CHECK_EQUAL does, is enough.
constexpr size_t PathTable::MAX_PATHS;
constexpr int64_t PathTable::PATH_TTL;

bool PathTable::Create(uint64_t path_id, const Hop& upstream, const Hop& downstream,
                       int64_t now)
{
    if (!upstream.IsValid() || !downstream.IsValid()) return false;
    // A path from a peer back to itself is a reflection loop, not a route.
    if (upstream == downstream) return false;
    if (m_paths.size() >= MAX_PATHS) return false;
    // Refusing rather than replacing: replacing would let anyone who guessed or
    // observed an id take over somebody else's path.
    if (m_paths.count(path_id) != 0) return false;

    Entry e;
    e.upstream = upstream;
    e.downstream = downstream;
    e.last_used = now;
    m_paths[path_id] = e;
    return true;
}

bool PathTable::CreateEndpoint(uint64_t path_id, const Hop& upstream, int64_t now)
{
    if (!upstream.IsValid()) return false;
    if (m_paths.size() >= MAX_PATHS) return false;
    if (m_paths.count(path_id) != 0) return false;

    Entry e;
    e.upstream = upstream;
    e.downstream = Hop(); // invalid: this node is the far end
    e.last_used = now;
    m_paths[path_id] = e;
    return true;
}

Route PathTable::Next(uint64_t path_id, const Hop& from, Hop& to_out, int64_t now)
{
    std::map<uint64_t, Entry>::iterator it = m_paths.find(path_id);
    if (it == m_paths.end()) return Route::UNKNOWN;

    Route route;
    if (from == it->second.upstream) {
        if (it->second.downstream.IsValid()) {
            to_out = it->second.downstream;
            route = Route::FORWARD;
        } else {
            route = Route::DELIVER;
        }
    } else if (it->second.downstream.IsValid() && from == it->second.downstream) {
        to_out = it->second.upstream;
        route = Route::FORWARD;
    } else {
        // Knowing a path id is not membership of it. Without this check, an id
        // that leaked would let a stranger inject traffic into someone's path.
        return Route::UNKNOWN;
    }

    it->second.last_used = now;
    return route;
}

size_t PathTable::Expire(int64_t now)
{
    size_t removed = 0;
    std::map<uint64_t, Entry>::iterator it = m_paths.begin();
    while (it != m_paths.end()) {
        if (now - it->second.last_used >= PATH_TTL) {
            m_paths.erase(it++);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

bool PathTable::Carrier(uint64_t path_id, Hop& out) const
{
    std::map<uint64_t, Entry>::const_iterator it = m_paths.find(path_id);
    if (it == m_paths.end()) return false;
    // An endpoint entry has no downstream, and its upstream is the hop the
    // path runs through. A full forwarding entry belongs to a relay in the
    // middle, which has two and is not asking on its own behalf.
    if (it->second.downstream.IsValid()) return false;
    out = it->second.upstream;
    return out.IsValid();
}

bool PathTable::Has(uint64_t path_id) const
{
    return m_paths.count(path_id) != 0;
}

} // namespace overlay
