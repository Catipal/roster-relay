// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/ippacket.h>

#include <tinyformat.h>

#include <algorithm>
#include <cstring>

namespace overlay {

namespace {

uint16_t Get16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t Get32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
void Put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
void Put32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

/** One's-complement sum of `len` bytes, big-endian words, added to `sum`. */
uint32_t SumBytes(const uint8_t* p, size_t len, uint32_t sum)
{
    for (size_t i = 0; i + 1 < len; i += 2) sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (len & 1) sum += (uint32_t)(p[len - 1] << 8);
    return sum;
}

uint16_t Fold(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/** The TCP or UDP checksum over the pseudo-header and the segment. */
uint16_t TransportChecksum(const IpAddr& src, const IpAddr& dst, uint8_t protocol, const uint8_t* l4, size_t len)
{
    uint32_t sum = 0;
    sum = SumBytes(src.bytes.data(), src.Size(), sum);
    sum = SumBytes(dst.bytes.data(), dst.Size(), sum);
    sum += protocol;
    if (src.version == 6) {
        sum += (uint32_t)(len >> 16);
        sum += (uint32_t)(len & 0xffff);
    } else {
        sum += (uint32_t)len;
    }
    sum = SumBytes(l4, len, sum);
    return Fold(sum);
}

/** Fill in the IPv4 header checksum, if this is IPv4, and the TCP or UDP one. */
void FixChecksums(std::vector<uint8_t>& pkt, uint8_t version, size_t ip_header, uint8_t protocol,
                  const IpAddr& src, const IpAddr& dst)
{
    if (version == 4) {
        pkt[10] = pkt[11] = 0;
        Put16(&pkt[10], Fold(SumBytes(pkt.data(), ip_header, 0)));
    }
    uint8_t* l4 = pkt.data() + ip_header;
    const size_t len = pkt.size() - ip_header;
    const size_t at = protocol == IPPROTO_TCP_NUM ? 16 : 6;
    l4[at] = l4[at + 1] = 0;
    uint16_t sum = TransportChecksum(src, dst, protocol, l4, len);
    // In UDP a checksum of zero means "none", so a real zero is sent as all ones.
    if (protocol == IPPROTO_UDP_NUM && sum == 0) sum = 0xffff;
    Put16(l4 + at, sum);
}

/** An IP header from `src` to `dst` for a payload of `l4_len` bytes, at the start of `pkt`. */
size_t WriteIpHeader(std::vector<uint8_t>& pkt, const IpAddr& src, const IpAddr& dst, uint8_t protocol, size_t l4_len)
{
    if (src.version == 6) {
        pkt.assign(40 + l4_len, 0);
        pkt[0] = 0x60;
        Put16(&pkt[4], (uint16_t)l4_len);
        pkt[6] = protocol;
        pkt[7] = 64;
        std::memcpy(&pkt[8], src.bytes.data(), 16);
        std::memcpy(&pkt[24], dst.bytes.data(), 16);
        return 40;
    }
    pkt.assign(20 + l4_len, 0);
    pkt[0] = 0x45;
    Put16(&pkt[2], (uint16_t)(20 + l4_len));
    Put16(&pkt[6], 0x4000); // don't fragment
    pkt[8] = 64;
    pkt[9] = protocol;
    std::memcpy(&pkt[12], src.bytes.data(), 4);
    std::memcpy(&pkt[16], dst.bytes.data(), 4);
    return 20;
}

bool InV4(const IpAddr& a, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, int bits)
{
    const uint32_t v = Get32(a.bytes.data());
    const uint32_t net = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
    const uint32_t mask = bits == 0 ? 0 : ~0U << (32 - bits);
    return (v & mask) == (net & mask);
}

bool InV6(const IpAddr& a, const std::array<uint8_t, 16>& net, int bits)
{
    for (int i = 0; i < 16 && bits > 0; ++i, bits -= 8) {
        const uint8_t mask = bits >= 8 ? 0xff : (uint8_t)(0xff << (8 - bits));
        if ((a.bytes[i] & mask) != (net[i] & mask)) return false;
    }
    return true;
}

std::array<uint8_t, 16> V6Prefix(uint16_t w0, uint16_t w1 = 0, uint16_t w2 = 0)
{
    std::array<uint8_t, 16> b{};
    Put16(&b[0], w0);
    Put16(&b[2], w1);
    Put16(&b[4], w2);
    return b;
}

} // namespace

IpAddr IpAddr::V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    IpAddr r;
    r.version = 4;
    r.bytes[0] = a;
    r.bytes[1] = b;
    r.bytes[2] = c;
    r.bytes[3] = d;
    return r;
}

IpAddr IpAddr::V6(const std::array<uint8_t, 16>& b)
{
    IpAddr r;
    r.version = 6;
    r.bytes = b;
    return r;
}

std::string IpAddr::ToString() const
{
    if (version == 4) return strprintf("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    std::string s;
    for (int i = 0; i < 16; i += 2) {
        if (i) s += ':';
        s += strprintf("%x", Get16(&bytes[i]));
    }
    return s;
}

bool IpAddr::operator==(const IpAddr& o) const
{
    return version == o.version && std::equal(bytes.begin(), bytes.begin() + Size(), o.bytes.begin());
}

bool IpAddr::operator<(const IpAddr& o) const
{
    if (version != o.version) return version < o.version;
    return std::lexicographical_compare(bytes.begin(), bytes.begin() + Size(), o.bytes.begin(), o.bytes.begin() + o.Size());
}

bool PacketInfo::IsTcpOpen() const
{
    return IsTcp() && (tcp_flags & TCP_SYN) && !(tcp_flags & (TCP_ACK | TCP_RST | TCP_FIN));
}

bool ParsePacket(const std::vector<uint8_t>& pkt, PacketInfo& info, std::string& why)
{
    info = PacketInfo();
    if (pkt.empty()) { why = "empty"; return false; }
    if (pkt.size() > MAX_GATEWAY_PACKET) { why = strprintf("%u bytes, over the %u a gateway takes", pkt.size(), MAX_GATEWAY_PACKET); return false; }
    const uint8_t* p = pkt.data();
    const uint8_t version = p[0] >> 4;

    if (version == 4) {
        if (pkt.size() < 20) { why = "short IPv4 header"; return false; }
        const size_t ihl = (size_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > pkt.size()) { why = "bad IPv4 header length"; return false; }
        if (Get16(p + 2) != pkt.size()) { why = "IPv4 length disagrees with the packet"; return false; }
        // A fragment - more to come, or not the first - is never carried:
        // the interface's MTU means a visitor never needs to send one.
        if (Get16(p + 6) & 0x3fff) { why = "IPv4 fragment"; return false; }
        info.version = 4;
        info.protocol = p[9];
        info.src = IpAddr::V4(p[12], p[13], p[14], p[15]);
        info.dst = IpAddr::V4(p[16], p[17], p[18], p[19]);
        info.ip_header = ihl;
    } else if (version == 6) {
        if (pkt.size() < 40) { why = "short IPv6 header"; return false; }
        if (40 + (size_t)Get16(p + 4) != pkt.size()) { why = "IPv6 length disagrees with the packet"; return false; }
        // TCP or UDP straight after the header. Extension headers - fragments,
        // routing, options - are refused rather than walked.
        info.version = 6;
        info.protocol = p[6];
        std::array<uint8_t, 16> a;
        std::memcpy(a.data(), p + 8, 16);
        info.src = IpAddr::V6(a);
        std::memcpy(a.data(), p + 24, 16);
        info.dst = IpAddr::V6(a);
        info.ip_header = 40;
    } else {
        why = strprintf("IP version %u", version);
        return false;
    }

    const uint8_t* l4 = p + info.ip_header;
    const size_t l4_len = pkt.size() - info.ip_header;
    if (info.protocol == IPPROTO_TCP_NUM) {
        if (l4_len < 20) { why = "short TCP header"; return false; }
        const size_t off = (size_t)(l4[12] >> 4) * 4;
        if (off < 20 || off > l4_len) { why = "bad TCP header length"; return false; }
        info.l4_header = off;
        info.tcp_flags = l4[13];
        info.tcp_seq = Get32(l4 + 4);
        info.tcp_ack = Get32(l4 + 8);
    } else if (info.protocol == IPPROTO_UDP_NUM) {
        if (l4_len < 8) { why = "short UDP header"; return false; }
        if (Get16(l4 + 4) != l4_len) { why = "UDP length disagrees with the packet"; return false; }
        info.l4_header = 8;
    } else {
        why = strprintf("protocol %u", info.protocol);
        return false;
    }
    info.src_port = Get16(l4);
    info.dst_port = Get16(l4 + 2);
    info.payload = l4_len - info.l4_header;
    return true;
}

void RewritePacket(std::vector<uint8_t>& pkt, const PacketInfo& info,
                   const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port)
{
    uint8_t* p = pkt.data();
    if (info.version == 4) {
        std::memcpy(p + 12, src.bytes.data(), 4);
        std::memcpy(p + 16, dst.bytes.data(), 4);
    } else {
        std::memcpy(p + 8, src.bytes.data(), 16);
        std::memcpy(p + 24, dst.bytes.data(), 16);
    }
    Put16(p + info.ip_header, src_port);
    Put16(p + info.ip_header + 2, dst_port);
    FixChecksums(pkt, info.version, info.ip_header, info.protocol, src, dst);
}

std::vector<uint8_t> BuildTcpReset(const PacketInfo& opening)
{
    std::vector<uint8_t> pkt;
    const size_t at = WriteIpHeader(pkt, opening.dst, opening.src, IPPROTO_TCP_NUM, 20);
    uint8_t* tcp = pkt.data() + at;
    Put16(tcp, opening.dst_port);
    Put16(tcp + 2, opening.src_port);
    // RFC 9293: answering a segment without ACK, the reset has sequence zero
    // and acknowledges everything the segment occupied - its SYN, its FIN and
    // its data.
    const uint32_t occupied = (uint32_t)opening.payload + ((opening.tcp_flags & TCP_SYN) ? 1 : 0) +
                              ((opening.tcp_flags & TCP_FIN) ? 1 : 0);
    Put32(tcp + 4, 0);
    Put32(tcp + 8, opening.tcp_seq + occupied);
    tcp[12] = 5 << 4;
    tcp[13] = TCP_RST | TCP_ACK;
    FixChecksums(pkt, opening.version, at, IPPROTO_TCP_NUM, opening.dst, opening.src);
    return pkt;
}

std::vector<uint8_t> BuildUdp(const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                              const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> pkt;
    const size_t at = WriteIpHeader(pkt, src, dst, IPPROTO_UDP_NUM, 8 + payload.size());
    uint8_t* udp = pkt.data() + at;
    Put16(udp, src_port);
    Put16(udp + 2, dst_port);
    Put16(udp + 4, (uint16_t)(8 + payload.size()));
    if (!payload.empty()) std::memcpy(udp + 8, payload.data(), payload.size());
    FixChecksums(pkt, src.version, at, IPPROTO_UDP_NUM, src, dst);
    return pkt;
}

bool IsPublicAddress(const IpAddr& a)
{
    if (a.version == 4) {
        return !(InV4(a, 0, 0, 0, 0, 8)         // this network
              || InV4(a, 10, 0, 0, 0, 8)        // private
              || InV4(a, 100, 64, 0, 0, 10)     // shared address space (CGNAT)
              || InV4(a, 127, 0, 0, 0, 8)       // loopback
              || InV4(a, 169, 254, 0, 0, 16)    // link-local
              || InV4(a, 172, 16, 0, 0, 12)     // private
              || InV4(a, 192, 0, 0, 0, 24)      // IETF protocol assignments
              || InV4(a, 192, 0, 2, 0, 24)      // documentation
              || InV4(a, 192, 88, 99, 0, 24)    // 6to4 relay anycast
              || InV4(a, 192, 168, 0, 0, 16)    // private
              || InV4(a, 198, 18, 0, 0, 15)     // benchmarking
              || InV4(a, 198, 51, 100, 0, 24)   // documentation
              || InV4(a, 203, 0, 113, 0, 24)    // documentation
              || InV4(a, 224, 0, 0, 0, 4)       // multicast
              || InV4(a, 240, 0, 0, 0, 4));     // reserved, and broadcast
    }
    if (a.version != 6) return false;
    // Global unicast only. That alone leaves out the unspecified address,
    // loopback, IPv4-mapped and -translated forms, unique-local, link-local
    // and multicast; within it, the ranges below are not ordinary hosts.
    if (!InV6(a, V6Prefix(0x2000), 3)) return false;
    return !(InV6(a, V6Prefix(0x2001, 0x0000), 23)   // IETF protocol assignments, Teredo among them
          || InV6(a, V6Prefix(0x2001, 0x0db8), 32)   // documentation
          || InV6(a, V6Prefix(0x2002), 16)           // 6to4: an IPv4 address inside
          || InV6(a, V6Prefix(0x3fff), 20));         // documentation
}

} // namespace overlay
