// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/gatewayproto.h>

#include <overlay/relay.h>

#include <algorithm>
#include <cstring>

namespace overlay {

namespace {

/** Tag and kind. */
constexpr size_t HEAD = 2;
/** FRAG's id, index and count. */
constexpr size_t FRAG_HEAD = 4;

void Put16(std::vector<uint8_t>& v, uint16_t x) { v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x); }
void Put32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int s = 24; s >= 0; s -= 8) v.push_back((uint8_t)(x >> s));
}
uint16_t Get16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t Get32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

std::vector<uint8_t> Start(GatewayKind kind)
{
    std::vector<uint8_t> v;
    v.push_back(GATEWAY_TAG);
    v.push_back((uint8_t)kind);
    return v;
}

void PutPorts(std::vector<uint8_t>& v, const std::vector<uint16_t>& ports)
{
    const size_t n = std::min<size_t>(ports.size(), 64);
    v.push_back((uint8_t)n);
    for (size_t i = 0; i < n; ++i) Put16(v, ports[i]);
}

bool GetPorts(const uint8_t*& p, const uint8_t* end, std::vector<uint16_t>& out)
{
    if (p >= end) return false;
    const size_t n = *p++;
    if ((size_t)(end - p) < 2 * n) return false;
    out.clear();
    for (size_t i = 0; i < n; ++i, p += 2) out.push_back(Get16(p));
    return true;
}

} // namespace

bool IsGatewayPayload(const std::vector<uint8_t>& payload)
{
    return !payload.empty() && payload[0] == GATEWAY_TAG;
}

bool IsResolvableName(const std::string& name)
{
    if (name.empty() || name.size() > MAX_RESOLVE_NAME) return false;
    if (name.front() == '.' || name.front() == '-') return false;
    for (char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '-' || c == '.' || c == '_';
        if (!ok) return false;
    }
    return name.find("..") == std::string::npos;
}

bool DecodeGatewayMessage(const std::vector<uint8_t>& payload, GatewayMessage& out)
{
    out = GatewayMessage();
    if (payload.size() < HEAD || payload[0] != GATEWAY_TAG) return false;
    const uint8_t* p = payload.data() + HEAD;
    const uint8_t* end = payload.data() + payload.size();
    const size_t len = payload.size() - HEAD;

    switch ((GatewayKind)payload[1]) {
    case GatewayKind::PACKET:
        if (len == 0) return false;
        out.kind = GatewayKind::PACKET;
        out.bytes.assign(p, end);
        return true;

    case GatewayKind::FRAG:
        if (len <= FRAG_HEAD) return false;
        out.kind = GatewayKind::FRAG;
        out.frag_id = Get16(p);
        out.frag_index = p[2];
        out.frag_count = p[3];
        if (out.frag_count < 2 || out.frag_count > MAX_FRAGS || out.frag_index >= out.frag_count) return false;
        out.bytes.assign(p + FRAG_HEAD, end);
        return true;

    case GatewayKind::RESOLVE: {
        if (len < 6) return false;
        out.kind = GatewayKind::RESOLVE;
        out.request = Get32(p);
        out.family = p[4];
        if (out.family != RESOLVE_ANY && out.family != RESOLVE_V4 && out.family != RESOLVE_V6) return false;
        const size_t n = p[5];
        if (len != 6 + n) return false;
        out.name.assign((const char*)p + 6, n);
        return IsResolvableName(out.name);
    }

    case GatewayKind::RESOLVED: {
        if (len < 10) return false;
        out.kind = GatewayKind::RESOLVED;
        out.request = Get32(p);
        if (p[4] > (uint8_t)ResolveStatus::REFUSED) return false;
        out.status = (ResolveStatus)p[4];
        out.ttl = Get32(p + 5);
        const size_t n = p[9];
        if (n > MAX_RESOLVED) return false;
        p += 10;
        for (size_t i = 0; i < n; ++i) {
            if (p >= end) return false;
            const uint8_t family = *p++;
            IpAddr a;
            if (family == 4) {
                if (end - p < 4) return false;
                a = IpAddr::V4(p[0], p[1], p[2], p[3]);
                p += 4;
            } else if (family == 6) {
                if (end - p < 16) return false;
                std::array<uint8_t, 16> b;
                std::memcpy(b.data(), p, 16);
                a = IpAddr::V6(b);
                p += 16;
            } else {
                return false;
            }
            out.addrs.push_back(a);
        }
        return p == end;
    }

    case GatewayKind::STATUS: {
        if (len < 3) return false;
        out.kind = GatewayKind::STATUS;
        if (p[0] > (uint8_t)GatewayState::OFF) return false;
        out.state = (GatewayState)p[0];
        ++p;
        if (!GetPorts(p, end, out.tcp_ports) || !GetPorts(p, end, out.udp_ports)) return false;
        return p == end;
    }

    case GatewayKind::HELLO:
        out.kind = GatewayKind::HELLO;
        return len == 0;
    }
    return false;
}

std::vector<std::vector<uint8_t>> EncodePacket(const std::vector<uint8_t>& packet, uint16_t frag_id)
{
    std::vector<std::vector<uint8_t>> out;
    if (packet.empty() || packet.size() > MAX_GATEWAY_PACKET) return out;
    if (HEAD + packet.size() <= MAX_PATH_APP_PAYLOAD) {
        std::vector<uint8_t> m = Start(GatewayKind::PACKET);
        m.insert(m.end(), packet.begin(), packet.end());
        out.push_back(std::move(m));
        return out;
    }
    const size_t piece = MAX_PATH_APP_PAYLOAD - HEAD - FRAG_HEAD;
    const size_t count = (packet.size() + piece - 1) / piece;
    if (count > MAX_FRAGS) return out;
    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> m = Start(GatewayKind::FRAG);
        Put16(m, frag_id);
        m.push_back((uint8_t)i);
        m.push_back((uint8_t)count);
        const size_t at = i * piece;
        const size_t n = std::min(piece, packet.size() - at);
        m.insert(m.end(), packet.begin() + at, packet.begin() + at + n);
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<uint8_t> EncodeResolve(uint32_t request, uint8_t family, const std::string& name)
{
    std::vector<uint8_t> m = Start(GatewayKind::RESOLVE);
    Put32(m, request);
    m.push_back(family);
    m.push_back((uint8_t)std::min<size_t>(name.size(), 255));
    m.insert(m.end(), name.begin(), name.begin() + std::min<size_t>(name.size(), 255));
    return m;
}

std::vector<uint8_t> EncodeResolved(uint32_t request, ResolveStatus status, uint32_t ttl,
                                    const std::vector<IpAddr>& addrs)
{
    std::vector<uint8_t> m = Start(GatewayKind::RESOLVED);
    Put32(m, request);
    m.push_back((uint8_t)status);
    Put32(m, ttl);
    const size_t n = std::min(addrs.size(), MAX_RESOLVED);
    m.push_back((uint8_t)n);
    for (size_t i = 0; i < n; ++i) {
        m.push_back(addrs[i].version);
        m.insert(m.end(), addrs[i].bytes.begin(), addrs[i].bytes.begin() + addrs[i].Size());
    }
    return m;
}

std::vector<uint8_t> EncodeStatus(GatewayState state, const std::vector<uint16_t>& tcp_ports,
                                  const std::vector<uint16_t>& udp_ports)
{
    std::vector<uint8_t> m = Start(GatewayKind::STATUS);
    m.push_back((uint8_t)state);
    PutPorts(m, tcp_ports);
    PutPorts(m, udp_ports);
    return m;
}

std::vector<uint8_t> EncodeHello()
{
    return Start(GatewayKind::HELLO);
}

constexpr int64_t Reassembler::REASSEMBLY_MS;
constexpr size_t Reassembler::MAX_PARTIAL;

void Reassembler::Expire(int64_t now_ms)
{
    for (auto it = m_partial.begin(); it != m_partial.end();) {
        if (now_ms - it->second.started > REASSEMBLY_MS) {
            it = m_partial.erase(it);
        } else {
            ++it;
        }
    }
}

bool Reassembler::Add(uint64_t source, const GatewayMessage& frag, int64_t now_ms, std::vector<uint8_t>& packet)
{
    Expire(now_ms);
    const std::pair<uint64_t, uint16_t> key(source, frag.frag_id);
    auto it = m_partial.find(key);
    if (it == m_partial.end()) {
        size_t mine = 0;
        for (const auto& e : m_partial) {
            if (e.first.first == source) ++mine;
        }
        if (mine >= MAX_PARTIAL) return false;
        Partial fresh;
        fresh.count = frag.frag_count;
        fresh.pieces.resize(frag.frag_count);
        fresh.started = now_ms;
        it = m_partial.emplace(key, std::move(fresh)).first;
    }
    Partial& part = it->second;
    // Pieces that disagree about how many there are, or say the same piece
    // twice, end the packet: a sender that is confused is not trusted to
    // finish it.
    if (part.count != frag.frag_count || !part.pieces[frag.frag_index].empty() || frag.bytes.empty()) {
        m_partial.erase(it);
        return false;
    }
    part.pieces[frag.frag_index] = frag.bytes;
    if (++part.have < part.count) return false;

    packet.clear();
    for (const std::vector<uint8_t>& piece : part.pieces) packet.insert(packet.end(), piece.begin(), piece.end());
    m_partial.erase(it);
    return packet.size() <= MAX_GATEWAY_PACKET;
}

void Reassembler::Forget(uint64_t source)
{
    for (auto it = m_partial.begin(); it != m_partial.end();) {
        if (it->first.first == source) {
            it = m_partial.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace overlay
