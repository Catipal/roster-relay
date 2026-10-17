// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_DNSANSWER_H
#define BITCOIN_OVERLAY_DNSANSWER_H

#include <overlay/ippacket.h>

#include <stdint.h>
#include <string>
#include <vector>

/**
 * The few bytes of DNS the system-wide interface speaks (design note §8·7).
 *
 * The interface has a resolver address of its own, and the computer is told
 * to ask it. It answers A and AAAA by looking the name up at a gateway, so
 * no lookup leaves the computer as itself. Everything else - HTTPS and SVCB
 * records included, so the system's own lookups go without the hints that
 * carry encrypted-hello keys; browsers using their own secure DNS are not
 * affected - is answered as having no records of that type, which every
 * client takes as a reason to fall back. Plain DNS over UDP, one question,
 * as stub resolvers send; nothing that needs TCP.
 */
namespace overlay {

static constexpr uint16_t DNS_TYPE_A = 1;
static constexpr uint16_t DNS_TYPE_AAAA = 28;
static constexpr uint16_t DNS_CLASS_IN = 1;
static constexpr uint16_t DNS_PORT = 53;

enum class DnsRcode : uint8_t {
    OK = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NO_SUCH_NAME = 3,
    NOT_IMPLEMENTED = 4,
    REFUSED = 5,
};

/** A query as far as the interface needs it. */
struct DnsQuery {
    uint16_t id{0};
    bool recursion_desired{false};
    std::string name;      //!< lower case, no trailing dot
    uint16_t qtype{0};
    uint16_t qclass{0};
    std::vector<uint8_t> question; //!< the question section as sent, echoed back
};

/**
 * Read a query. False for anything that is not a plain one-question query;
 * `rcode` then says how to answer it; `answerable` is false when it is not
 * even a query and gets no answer at all.
 */
bool ParseDnsQuery(const std::vector<uint8_t>& msg, DnsQuery& q, DnsRcode& rcode, bool& answerable);

/**
 * The answer to `q`: `rcode`, and for OK the addresses of the type asked
 * for (others are left out), at most MAX_RESOLVED of them, each for `ttl`
 * seconds.
 */
std::vector<uint8_t> BuildDnsAnswer(const DnsQuery& q, DnsRcode rcode, const std::vector<IpAddr>& addrs, uint32_t ttl);

/** A query for `name` (lower case, no trailing dot) of `qtype`, recursion desired. Empty for a name DNS cannot carry. */
std::vector<uint8_t> BuildDnsQuery(uint16_t id, const std::string& name, uint16_t qtype);

/**
 * Read the answer to a query of `id` and `qtype`: its result code, the
 * addresses of that type it carries for any owner (a CNAME chain arrives in
 * the same answer), and the shortest of their TTLs. False when it is not an
 * answer to that query, or is cut short (truncated answers are not taken).
 */
bool ParseDnsResponse(const std::vector<uint8_t>& msg, uint16_t id, uint16_t qtype, DnsRcode& rcode,
                      std::vector<IpAddr>& addrs, uint32_t& ttl);

/** Longest a lookup's answer is kept by those who ask: five minutes. */
static constexpr uint32_t MAX_DNS_TTL = 300;
/** And at least, so a burst of queries is not a burst of lookups. */
static constexpr uint32_t MIN_DNS_TTL = 30;

} // namespace overlay

#endif // BITCOIN_OVERLAY_DNSANSWER_H
