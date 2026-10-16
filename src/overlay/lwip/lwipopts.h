// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * lwIP's configuration for BPS.
 *
 * lwIP 2.2.1 is vendored unmodified in src/lwip (core and headers, with its
 * licence): lwip-2.2.1.zip from download.savannah.nongnu.org, sha256
 * 7b622662dba2383d71f874f2e494b54ae948531559c17acbe75797966d646878, signed
 * by the maintainer's key 746B EB8E 5637 2EB6 95EA 02E7 1D6B 61C1 B842 99F5.
 * Everything BPS chooses about it is here and in arch/cc.h.
 *
 * What it is for (design note §8·7): a gateway receives a visitor's IP
 * packets over the overlay and has to hold TCP connections for them without
 * administrator rights, which means a TCP/IP stack of its own in user space.
 * lwIP is that stack and nothing more: TCP over IPv4 and IPv6 on interfaces
 * that are the overlay itself. UDP, names, link layers and sockets are all
 * handled elsewhere or not at all, so they are off here, and every byte that
 * reaches lwIP has already been checked (overlay/ippacket.h).
 */
#ifndef BPS_LWIP_LWIPOPTS_H
#define BPS_LWIP_LWIPOPTS_H

/* One thread owns the stack and drives its timers; no OS layer inside it. */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_TIMERS                     1

/* Memory comes from the heap; BPS bounds connections and buffers itself. */
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   8

/* Protocols: TCP over IPv4 and IPv6, and nothing it does not need. */
#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_TCP                        1
#define LWIP_UDP                        0
#define LWIP_RAW                        0
#define LWIP_ICMP                       0
#define LWIP_DNS                        0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_ACD                        0
#define LWIP_IGMP                       0
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define IP_FORWARD                      0
#define IP_REASSEMBLY                   0
#define IP_FRAG                         0
#define LWIP_IPV6_FRAG                  0
#define LWIP_IPV6_REASS                 0
#define LWIP_IPV6_MLD                   0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_IPV6_DHCP6                 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT   0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS   0
#define LWIP_ND6_ALLOW_RA_UPDATES       0
#define LWIP_ND6_TCP_REACHABILITY_HINTS 0
/* No link-local addresses are used, so no zones to keep apart. */
#define LWIP_IPV6_SCOPES                0
#define LWIP_SINGLE_NETIF               0
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_STATS                      0

/*
 * TCP sized for the overlay.
 *
 * A path carries 637 bytes of a datagram, two of which say what it is, so
 * an IP packet that is to travel in one datagram has 635. A segment of 520
 * bytes leaves room for an IPv6 header (40), the TCP header (20) and the
 * largest options either side sends (40), so every TCP segment in either
 * direction fits one datagram: lwIP announces this MSS, and the visitor's
 * own stack keeps to it.
 *
 * The window is what one path may move a second (-relaypathrate, 64 KiB/s)
 * over a round trip of about a second through four nodes. Out-of-order
 * segments are kept and acknowledged selectively, since a path loses
 * datagrams the way any network does.
 */
/* Some systems' netinet/tcp.h name a socket option TCP_MSS; here it is lwIP's. */
#ifdef TCP_MSS
#undef TCP_MSS
#endif
#define TCP_MSS                         520
#define TCP_CALCULATE_EFF_SEND_MSS      1
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   1
#define TCP_WND                         (128 * TCP_MSS)
#define TCP_SND_BUF                     (128 * TCP_MSS)
#define TCP_SND_QUEUELEN                (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_QUEUE_OOSEQ                 1
#define TCP_OOSEQ_MAX_BYTES             (128 * TCP_MSS)
#define TCP_OOSEQ_MAX_PBUFS             256
#define LWIP_TCP_SACK_OUT               1
#define LWIP_TCP_MAX_SACK_NUM           4
#define LWIP_TCP_TIMESTAMPS             0
#define LWIP_TCP_KEEPALIVE              1
#define TCP_LISTEN_BACKLOG              1
#define TCP_DEFAULT_LISTEN_BACKLOG      0xff
#define TCP_TTL                         64
/* Pools come from the heap (MEMP_MEM_MALLOC), so lwIP's pool-size checks do not apply. */
#define LWIP_DISABLE_TCP_SANITY_CHECKS  1

/* Checksums are checked on the way in: the packets come from strangers. */
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_TCP              1

/*
 * Loopback has no interface of its own in this stack. A connection to
 * 127.0.0.1 opened on a visitor's side goes out the default interface like
 * any other - which is the overlay, to a gateway, whose exit policy refuses
 * it unless -gatewayallowlocal (regtest only) says otherwise. lwIP would
 * otherwise refuse to route it at all (overlay/netstack.cpp).
 */
struct netif;
struct ip4_addr;
#ifdef __cplusplus
extern "C" {
#endif
struct netif* bps_lwip_route4(const struct ip4_addr* src, const struct ip4_addr* dest);
#ifdef __cplusplus
}
#endif
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest) bps_lwip_route4((src), (dest))

/*
 * lwIP would otherwise define htons and friends as macros, which collide
 * with the system's in any file that sees both. Its own code calls
 * lwip_htons and the rest, which it still provides.
 */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#endif /* BPS_LWIP_LWIPOPTS_H */
