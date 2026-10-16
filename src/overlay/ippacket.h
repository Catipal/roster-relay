// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_IPPACKET_H
#define BITCOIN_OVERLAY_IPPACKET_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * IP packets as the gateway handles them (design note §8·7).
 *
 * Everything a gateway receives from a visitor is a packet some stranger
 * wrote, so it is read here first, strictly, before anything else - lwIP
 * included - sees it. Only what a gateway carries passes: IPv4 or IPv6,
 * carrying TCP or UDP directly, whole (never a fragment), with lengths that
 * agree with each other and with the bytes that arrived. Anything else is
 * refused, with a reason for the log.
 *
 * The rest is the arithmetic of carrying them: rewriting the addresses and
 * ports a packet carries, with its checksums made right again, and building
 * the two kinds of packet a gateway writes itself - a TCP reset refusing a
 * connection, and a UDP datagram carrying an answer back.
 */
namespace overlay {

static constexpr uint8_t IPPROTO_TCP_NUM = 6;
static constexpr uint8_t IPPROTO_UDP_NUM = 17;

/** The largest packet a gateway takes or makes: the interface's MTU. */
static constexpr size_t MAX_GATEWAY_PACKET = 1280;

/** TCP flags, as they sit in byte 13 of the TCP header. */
static constexpr uint8_t TCP_FIN = 0x01;
static constexpr uint8_t TCP_SYN = 0x02;
static constexpr uint8_t TCP_RST = 0x04;
static constexpr uint8_t TCP_ACK = 0x10;

/** An address of either family: 4 bytes used for IPv4, 16 for IPv6. */
struct IpAddr {
    uint8_t version{0}; //!< 4 or 6
    std::array<uint8_t, 16> bytes{};

    static IpAddr V4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
    static IpAddr V6(const std::array<uint8_t, 16>& b);
    size_t Size() const { return version == 6 ? 16 : 4; }
    std::string ToString() const;
    bool operator==(const IpAddr& o) const;
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    bool operator<(const IpAddr& o) const;
};

/** What a packet is, once it has been checked. */
struct PacketInfo {
    uint8_t version{0};
    uint8_t protocol{0};      //!< IPPROTO_TCP_NUM or IPPROTO_UDP_NUM
    IpAddr src, dst;
    uint16_t src_port{0}, dst_port{0};
    size_t ip_header{0};      //!< bytes of IP header
    size_t l4_header{0};      //!< bytes of TCP or UDP header
    size_t payload{0};        //!< bytes after the TCP or UDP header
    uint8_t tcp_flags{0};
    uint32_t tcp_seq{0};
    uint32_t tcp_ack{0};

    bool IsTcp() const { return protocol == IPPROTO_TCP_NUM; }
    bool IsUdp() const { return protocol == IPPROTO_UDP_NUM; }
    /** A TCP SYN that opens a connection: SYN without ACK, RST or FIN. */
    bool IsTcpOpen() const;
};

/**
 * Check `pkt` and describe it. False with `why` for anything a gateway does
 * not carry. Checksums are not checked here: the TCP stack checks TCP's, and
 * a rewrite recomputes them anyway.
 */
bool ParsePacket(const std::vector<uint8_t>& pkt, PacketInfo& info, std::string& why);

/**
 * Give a checked packet new addresses and ports, and make its IPv4 header
 * and TCP or UDP checksums right. The addresses must be of the packet's own
 * IP version.
 */
void RewritePacket(std::vector<uint8_t>& pkt, const PacketInfo& info,
                   const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port);

/** A TCP reset answering `opening`: from its destination, back to its source. */
std::vector<uint8_t> BuildTcpReset(const PacketInfo& opening);

/** A UDP datagram from `src`:`src_port` to `dst`:`dst_port`, both of one IP version. */
std::vector<uint8_t> BuildUdp(const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                              const std::vector<uint8_t>& payload);

/**
 * Whether a gateway may connect to `addr` for a stranger: a public unicast
 * address. Refuses loopback, private and shared (CGNAT) ranges, link-local,
 * multicast, broadcast, documentation and benchmarking ranges, the unspecified
 * address, IPv4 reserved space, unique-local IPv6, and IPv6 forms that embed
 * an IPv4 address (mapped, translated, 6to4, Teredo), which would otherwise
 * be a way round all of the above. Anything a stranger could use to reach the
 * gateway owner's own network, or the machine itself, is not an exit.
 */
bool IsPublicAddress(const IpAddr& addr);

} // namespace overlay

#endif // BITCOIN_OVERLAY_IPPACKET_H
