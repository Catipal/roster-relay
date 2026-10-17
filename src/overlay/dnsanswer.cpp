// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/dnsanswer.h>

#include <overlay/gatewayproto.h>

#include <algorithm>

namespace overlay {

namespace {

constexpr size_t HEADER = 12;
constexpr uint8_t QR = 0x80;
constexpr uint8_t RD = 0x01;
constexpr uint8_t RA = 0x80;

uint16_t Get16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

void Put16(std::vector<uint8_t>& out, uint16_t v)
{
    out.push_back((uint8_t)(v >> 8));
    out.push_back((uint8_t)v);
}

void Put32(std::vector<uint8_t>& out, uint32_t v)
{
    Put16(out, (uint16_t)(v >> 16));
    Put16(out, (uint16_t)v);
}

bool NameChar(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

} // namespace

bool ParseDnsQuery(const std::vector<uint8_t>& msg, DnsQuery& q, DnsRcode& rcode, bool& answerable)
{
    q = DnsQuery();
    rcode = DnsRcode::FORMAT_ERROR;
    answerable = false;
    if (msg.size() < HEADER) return false;
    q.id = Get16(msg.data());
    const uint8_t flags = msg[2];
    // An answer, not a question: never answered, or two of these would talk
    // to each other forever.
    if (flags & QR) return false;
    answerable = true;
    q.recursion_desired = (flags & RD) != 0;
    if (((flags >> 3) & 0x0f) != 0) {
        rcode = DnsRcode::NOT_IMPLEMENTED;
        return false;
    }
    if (Get16(msg.data() + 4) != 1 || Get16(msg.data() + 6) != 0 || Get16(msg.data() + 8) != 0) return false;

    // The question: labels, never a pointer (a query has nothing to point at).
    size_t at = HEADER;
    std::string name;
    while (true) {
        if (at >= msg.size()) return false;
        const uint8_t len = msg[at++];
        if (len == 0) break;
        if (len > 63 || at + len > msg.size()) return false;
        if (!name.empty()) name.push_back('.');
        for (size_t i = 0; i < len; ++i) {
            uint8_t c = msg[at + i];
            if (c >= 'A' && c <= 'Z') c = (uint8_t)(c - 'A' + 'a');
            if (!NameChar(c)) {
                // A name nothing could be registered under; not worth a lookup.
                rcode = DnsRcode::REFUSED;
                return false;
            }
            name.push_back((char)c);
        }
        at += len;
        if (name.size() > MAX_RESOLVE_NAME) return false;
    }
    if (at + 4 > msg.size()) return false;
    q.qtype = Get16(msg.data() + at);
    q.qclass = Get16(msg.data() + at + 2);
    at += 4;
    q.question.assign(msg.begin() + HEADER, msg.begin() + at);
    q.name = name;
    if (q.name.empty() || q.qclass != DNS_CLASS_IN) {
        rcode = DnsRcode::REFUSED;
        return false;
    }
    rcode = DnsRcode::OK;
    return true;
}

std::vector<uint8_t> BuildDnsQuery(uint16_t id, const std::string& name, uint16_t qtype)
{
    std::vector<uint8_t> out;
    if (name.empty() || name.size() > MAX_RESOLVE_NAME) return out;
    Put16(out, id);
    out.push_back(RD);
    out.push_back(0);
    Put16(out, 1);
    Put16(out, 0);
    Put16(out, 0);
    Put16(out, 0);
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        const size_t len = dot - start;
        if (len == 0 || len > 63) return std::vector<uint8_t>();
        out.push_back((uint8_t)len);
        out.insert(out.end(), name.begin() + start, name.begin() + dot);
        start = dot + 1;
    }
    out.push_back(0);
    Put16(out, qtype);
    Put16(out, DNS_CLASS_IN);
    return out;
}

namespace {

/** Step over a name at `at`, compressed or not. False when it runs off the message. */
bool SkipName(const std::vector<uint8_t>& msg, size_t& at)
{
    for (int labels = 0; labels < 128; ++labels) {
        if (at >= msg.size()) return false;
        const uint8_t len = msg[at];
        if (len == 0) {
            ++at;
            return true;
        }
        if ((len & 0xc0) == 0xc0) {
            if (at + 1 >= msg.size()) return false;
            at += 2;
            return true;
        }
        if (len & 0xc0) return false;
        at += 1 + len;
    }
    return false;
}

} // namespace

bool ParseDnsResponse(const std::vector<uint8_t>& msg, uint16_t id, uint16_t qtype, DnsRcode& rcode,
                      std::vector<IpAddr>& addrs, uint32_t& ttl)
{
    addrs.clear();
    ttl = 0;
    if (msg.size() < HEADER || Get16(msg.data()) != id || !(msg[2] & QR)) return false;
    if (msg[2] & 0x02) return false; // truncated
    rcode = (DnsRcode)(msg[3] & 0x0f);
    const uint16_t questions = Get16(msg.data() + 4);
    const uint16_t answers = Get16(msg.data() + 6);
    size_t at = HEADER;
    for (uint16_t i = 0; i < questions; ++i) {
        if (!SkipName(msg, at) || at + 4 > msg.size()) return false;
        at += 4;
    }
    bool first = true;
    for (uint16_t i = 0; i < answers; ++i) {
        if (!SkipName(msg, at) || at + 10 > msg.size()) return false;
        const uint16_t type = Get16(msg.data() + at);
        const uint16_t cls = Get16(msg.data() + at + 2);
        const uint32_t rttl = ((uint32_t)Get16(msg.data() + at + 4) << 16) | Get16(msg.data() + at + 6);
        const uint16_t len = Get16(msg.data() + at + 8);
        at += 10;
        if (at + len > msg.size()) return false;
        if (cls == DNS_CLASS_IN && type == qtype && ((type == DNS_TYPE_A && len == 4) || (type == DNS_TYPE_AAAA && len == 16))) {
            IpAddr a;
            if (type == DNS_TYPE_A) {
                a = IpAddr::V4(msg[at], msg[at + 1], msg[at + 2], msg[at + 3]);
            } else {
                std::array<uint8_t, 16> b{};
                std::copy(msg.begin() + at, msg.begin() + at + 16, b.begin());
                a = IpAddr::V6(b);
            }
            if (addrs.size() < MAX_RESOLVED && std::find(addrs.begin(), addrs.end(), a) == addrs.end()) addrs.push_back(a);
            ttl = first ? rttl : std::min(ttl, rttl);
            first = false;
        }
        at += len;
    }
    return true;
}

std::vector<uint8_t> BuildDnsAnswer(const DnsQuery& q, DnsRcode rcode, const std::vector<IpAddr>& addrs, uint32_t ttl)
{
    std::vector<IpAddr> answers;
    if (rcode == DnsRcode::OK) {
        const uint8_t want = q.qtype == DNS_TYPE_A ? 4 : q.qtype == DNS_TYPE_AAAA ? 6 : 0;
        for (const IpAddr& a : addrs) {
            if (a.version == want && answers.size() < MAX_RESOLVED &&
                std::find(answers.begin(), answers.end(), a) == answers.end()) {
                answers.push_back(a);
            }
        }
    }
    std::vector<uint8_t> out;
    Put16(out, q.id);
    out.push_back((uint8_t)(QR | (q.recursion_desired ? RD : 0)));
    out.push_back((uint8_t)(RA | (uint8_t)rcode));
    Put16(out, q.question.empty() ? 0 : 1);
    Put16(out, (uint16_t)answers.size());
    Put16(out, 0);
    Put16(out, 0);
    out.insert(out.end(), q.question.begin(), q.question.end());
    for (const IpAddr& a : answers) {
        Put16(out, 0xc000 | HEADER); // the name, as in the question
        Put16(out, a.version == 4 ? DNS_TYPE_A : DNS_TYPE_AAAA);
        Put16(out, DNS_CLASS_IN);
        Put32(out, ttl);
        const size_t len = a.version == 4 ? 4 : 16;
        Put16(out, (uint16_t)len);
        out.insert(out.end(), a.bytes.begin(), a.bytes.begin() + len);
    }
    return out;
}

} // namespace overlay
