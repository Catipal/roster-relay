// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/dnsanswer.h>
#include <overlay/dnsclient.h>
#include <overlay/gatewayclient.h>
#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>
#include <overlay/netstack.h>
#include <overlay/sysif.h>
#include <overlay/sysroute.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>

using namespace overlay;

namespace {

/** Whether a packet's TCP or UDP checksum, and an IPv4 header's, come out right. */
bool ChecksumsHold(const std::vector<uint8_t>& pkt)
{
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why)) return false;
    auto sum = [](const uint8_t* p, size_t len, uint32_t s) {
        for (size_t i = 0; i + 1 < len; i += 2) s += (uint32_t)((p[i] << 8) | p[i + 1]);
        if (len & 1) s += (uint32_t)(p[len - 1] << 8);
        return s;
    };
    auto fold = [](uint32_t s) { while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)s; };
    if (info.version == 4 && fold(sum(pkt.data(), info.ip_header, 0)) != 0xffff) return false;
    const size_t len = pkt.size() - info.ip_header;
    uint32_t s = 0;
    s = sum(info.src.bytes.data(), info.src.Size(), s);
    s = sum(info.dst.bytes.data(), info.dst.Size(), s);
    s += info.protocol;
    s += (uint32_t)len;
    s = sum(pkt.data() + info.ip_header, len, s);
    return fold(s) == 0xffff;
}

/** A TCP segment from `src`:`sp` to `dst`:`dp`, IPv4, with an MSS option when `mss` is not 0. */
std::vector<uint8_t> Tcp(const IpAddr& src, uint16_t sp, const IpAddr& dst, uint16_t dp, uint8_t flags,
                         uint32_t seq, uint32_t ack, uint16_t mss = 0)
{
    // Built as a UDP packet of the right size, then turned into TCP: the
    // header layout up to the ports is the same.
    std::vector<uint8_t> pkt = BuildUdp(src, sp, dst, dp, std::vector<uint8_t>(mss ? 16 : 12, 0));
    pkt[9] = IPPROTO_TCP_NUM;
    uint8_t* tcp = pkt.data() + 20;
    std::memset(tcp + 4, 0, mss ? 20 : 16);
    tcp[4] = (uint8_t)(seq >> 24); tcp[5] = (uint8_t)(seq >> 16); tcp[6] = (uint8_t)(seq >> 8); tcp[7] = (uint8_t)seq;
    tcp[8] = (uint8_t)(ack >> 24); tcp[9] = (uint8_t)(ack >> 16); tcp[10] = (uint8_t)(ack >> 8); tcp[11] = (uint8_t)ack;
    tcp[12] = (uint8_t)((mss ? 6 : 5) << 4);
    tcp[13] = flags;
    if (mss) {
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22] = (uint8_t)(mss >> 8);
        tcp[23] = (uint8_t)mss;
    }
    PacketInfo info;
    std::string why;
    BOOST_REQUIRE(ParsePacket(pkt, info, why));
    RewritePacket(pkt, info, src, sp, dst, dp); // fixes the checksums
    return pkt;
}

/** A DNS query for `name`, as a stub resolver sends it, with an EDNS record when `edns`. */
std::vector<uint8_t> Query(const std::string& name, uint16_t qtype, uint16_t id = 0x1234, bool edns = false,
                           uint8_t flags = 0x01)
{
    std::vector<uint8_t> q = {(uint8_t)(id >> 8), (uint8_t)id, flags, 0, 0, 1, 0, 0, 0, 0, 0, (uint8_t)(edns ? 1 : 0)};
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        q.push_back((uint8_t)(dot - start));
        q.insert(q.end(), name.begin() + start, name.begin() + dot);
        start = dot + 1;
    }
    q.push_back(0);
    q.push_back((uint8_t)(qtype >> 8));
    q.push_back((uint8_t)qtype);
    q.push_back(0);
    q.push_back(1);
    if (edns) {
        const uint8_t opt[] = {0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0};
        q.insert(q.end(), opt, opt + sizeof(opt));
    }
    return q;
}

uint16_t Get16(const std::vector<uint8_t>& b, size_t at) { return (uint16_t)((b[at] << 8) | b[at + 1]); }

/** Stands in for the computer: what the interface gives it is kept. */
class FakeDevice : public PacketDevice
{
public:
    explicit FakeDevice(std::vector<std::vector<uint8_t>>& written) : m_written(written) {}
    bool Start(Receive, std::string&) override { return true; }
    void Stop() override {}
    bool Write(const std::vector<uint8_t>& pkt) override
    {
        m_written.push_back(pkt);
        return true;
    }
    std::string Name() const override { return "fake0"; }

private:
    std::vector<std::vector<uint8_t>>& m_written;
};

/** The UDP payload of `pkt`. */
std::vector<uint8_t> UdpPayload(const std::vector<uint8_t>& pkt)
{
    PacketInfo info;
    std::string why;
    BOOST_REQUIRE(ParsePacket(pkt, info, why));
    BOOST_REQUIRE(info.IsUdp());
    return std::vector<uint8_t>(pkt.begin() + info.ip_header + info.l4_header, pkt.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(sysif_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dns_queries_are_read_strictly)
{
    DnsQuery q;
    DnsRcode rcode;
    bool answerable;
    BOOST_CHECK(ParseDnsQuery(Query("Example.COM", DNS_TYPE_A, 0xbeef, true), q, rcode, answerable));
    BOOST_CHECK_EQUAL(q.id, 0xbeef);
    BOOST_CHECK_EQUAL(q.name, "example.com");
    BOOST_CHECK_EQUAL(q.qtype, DNS_TYPE_A);
    BOOST_CHECK(q.recursion_desired);

    // An answer is never answered.
    BOOST_CHECK(!ParseDnsQuery(Query("example.com", DNS_TYPE_A, 1, false, 0x81), q, rcode, answerable));
    BOOST_CHECK(!answerable);
    // Another opcode is not done here.
    BOOST_CHECK(!ParseDnsQuery(Query("example.com", DNS_TYPE_A, 1, false, 0x01 | (2 << 3)), q, rcode, answerable));
    BOOST_CHECK(answerable);
    BOOST_CHECK(rcode == DnsRcode::NOT_IMPLEMENTED);
    // Names nothing is registered under are not looked up.
    BOOST_CHECK(!ParseDnsQuery(Query("exa mple.com", DNS_TYPE_A), q, rcode, answerable));
    BOOST_CHECK(rcode == DnsRcode::REFUSED);
    // Cut short, or two questions.
    std::vector<uint8_t> cut = Query("example.com", DNS_TYPE_A);
    cut.resize(cut.size() - 3);
    BOOST_CHECK(!ParseDnsQuery(cut, q, rcode, answerable));
    BOOST_CHECK(rcode == DnsRcode::FORMAT_ERROR);
    std::vector<uint8_t> two = Query("example.com", DNS_TYPE_A);
    two[5] = 2;
    BOOST_CHECK(!ParseDnsQuery(two, q, rcode, answerable));
    BOOST_CHECK(!ParseDnsQuery(std::vector<uint8_t>(5, 0), q, rcode, answerable));
    // A pointer has nothing to point at in a query.
    std::vector<uint8_t> ptr = Query("example.com", DNS_TYPE_A);
    ptr[12] = 0xc0;
    BOOST_CHECK(!ParseDnsQuery(ptr, q, rcode, answerable));
}

BOOST_AUTO_TEST_CASE(dns_answers_carry_only_the_type_asked)
{
    DnsQuery q;
    DnsRcode rcode;
    bool answerable;
    BOOST_REQUIRE(ParseDnsQuery(Query("example.com", DNS_TYPE_A, 7), q, rcode, answerable));
    std::array<uint8_t, 16> six{};
    six[15] = 1;
    const std::vector<IpAddr> addrs = {IpAddr::V4(93, 184, 216, 34), IpAddr::V6(six), IpAddr::V4(93, 184, 216, 35),
                                       IpAddr::V4(93, 184, 216, 34)};
    const std::vector<uint8_t> a = BuildDnsAnswer(q, DnsRcode::OK, addrs, 120);
    BOOST_CHECK_EQUAL(Get16(a, 0), 7);
    BOOST_CHECK_EQUAL(a[2], 0x81); // an answer, recursion as asked
    BOOST_CHECK_EQUAL(a[3], 0x80); // recursion available, no error
    BOOST_CHECK_EQUAL(Get16(a, 4), 1);
    BOOST_CHECK_EQUAL(Get16(a, 6), 2); // two IPv4 addresses, the repeat left out
    size_t at = 12 + q.question.size();
    BOOST_CHECK(std::equal(q.question.begin(), q.question.end(), a.begin() + 12));
    for (int i = 0; i < 2; ++i) {
        BOOST_CHECK_EQUAL(Get16(a, at), 0xc00c);
        BOOST_CHECK_EQUAL(Get16(a, at + 2), DNS_TYPE_A);
        BOOST_CHECK_EQUAL(Get16(a, at + 4), DNS_CLASS_IN);
        BOOST_CHECK_EQUAL(Get16(a, at + 8), 120);
        BOOST_CHECK_EQUAL(Get16(a, at + 10), 4);
        BOOST_CHECK_EQUAL(a[at + 12], 93);
        at += 16;
    }
    BOOST_CHECK_EQUAL(at, a.size());

    const std::vector<uint8_t> nx = BuildDnsAnswer(q, DnsRcode::NO_SUCH_NAME, addrs, 30);
    BOOST_CHECK_EQUAL(nx[3] & 0x0f, 3);
    BOOST_CHECK_EQUAL(Get16(nx, 6), 0);
}

BOOST_AUTO_TEST_CASE(segments_are_kept_small_and_resets_accepted)
{
    const IpAddr me = InterfaceAddress(4);
    const IpAddr site = IpAddr::V4(93, 184, 216, 34);
    std::vector<uint8_t> syn = Tcp(me, 40000, site, 443, TCP_SYN, 1000, 0, 1460);
    PacketInfo info;
    std::string why;
    BOOST_REQUIRE(ParsePacket(syn, info, why));
    BOOST_CHECK(ClampTcpMss(syn, info, 1240));
    BOOST_CHECK_EQUAL(Get16(syn, 20 + 22), 1240);
    BOOST_CHECK(ChecksumsHold(syn));
    BOOST_REQUIRE(ParsePacket(syn, info, why));
    BOOST_CHECK(!ClampTcpMss(syn, info, 1240)); // already small enough

    // A reset the program accepts: from the site, at the sequence number it
    // last acknowledged.
    const std::vector<uint8_t> data = Tcp(me, 40000, site, 443, TCP_ACK, 2000, 777777);
    BOOST_REQUIRE(ParsePacket(data, info, why));
    const std::vector<uint8_t> rst = BuildTcpResetFor(info);
    PacketInfo r;
    BOOST_REQUIRE(ParsePacket(rst, r, why));
    BOOST_CHECK(r.src == site);
    BOOST_CHECK(r.dst == me);
    BOOST_CHECK_EQUAL(r.src_port, 443);
    BOOST_CHECK_EQUAL(r.dst_port, 40000);
    BOOST_CHECK_EQUAL(r.tcp_seq, 777777U);
    BOOST_CHECK_EQUAL(r.tcp_flags, TCP_RST);
    BOOST_CHECK(ChecksumsHold(rst));
}

BOOST_AUTO_TEST_CASE(the_interface_lets_in_only_what_the_computer_asked_for)
{
    std::string error;
    BOOST_REQUIRE(GetNetStack().Start(error));
    {
        // A client with no gateway at all: it may not use any.
        GatewayClient client(
            3, 1, false, [](std::string& why) { why = "not in this test"; return false; },
            [] { return std::vector<roster::KeyBytes>(); },
            [](const roster::KeyBytes&, int, Meeting&, std::string& e) { e = "no"; return false; },
            [](const Meeting&) {}, [](uint64_t, const std::vector<uint8_t>&) { return false; });
        BOOST_REQUIRE(client.Start(error));
        std::vector<std::vector<uint8_t>> written;
        SystemInterface sysif(client, std::unique_ptr<PacketDevice>(new FakeDevice(written)));
        BOOST_REQUIRE(sysif.Start(error));
        const IpAddr me = InterfaceAddress(4);
        const IpAddr resolver = InterfaceResolver(4);
        const IpAddr site = IpAddr::V4(93, 184, 216, 34);

        // No gateway takes the connection: the program hears so at once.
        GetNetStack().RunSync([&] { sysif.FromComputer(Tcp(me, 40000, site, 443, TCP_SYN, 1000, 0, 1460)); });
        BOOST_REQUIRE_EQUAL(written.size(), 1U);
        PacketInfo info;
        std::string why;
        BOOST_REQUIRE(ParsePacket(written[0], info, why));
        BOOST_CHECK(info.tcp_flags & TCP_RST);
        BOOST_CHECK(info.src == site);
        BOOST_CHECK_EQUAL(info.tcp_ack, 1001U);
        BOOST_CHECK_EQUAL(sysif.GetStats().refused, 1U);

        // The computer's own network never goes out, and nothing but the
        // interface's own address is carried.
        GetNetStack().RunSync([&] { sysif.FromComputer(Tcp(me, 40001, IpAddr::V4(192, 168, 1, 1), 443, TCP_SYN, 1, 0)); });
        BOOST_CHECK_EQUAL(written.size(), 2U);
        GetNetStack().RunSync([&] { sysif.FromComputer(Tcp(IpAddr::V4(10, 77, 1, 9), 40002, site, 443, TCP_SYN, 1, 0)); });
        BOOST_CHECK_EQUAL(written.size(), 2U);

        // A packet a gateway sends for no connection of the computer's is dropped.
        const uint64_t dropped = sysif.GetStats().dropped;
        GetNetStack().RunSync([&] { sysif.FromGateway(42, Tcp(site, 443, me, 40000, TCP_SYN | TCP_ACK, 5, 1001)); });
        BOOST_CHECK_EQUAL(written.size(), 2U);
        BOOST_CHECK_EQUAL(sysif.GetStats().dropped, dropped + 1);

        // Lookups: a hidden site's name is never sent anywhere.
        auto ask = [&](const std::string& name, uint16_t qtype) {
            const size_t before = written.size();
            GetNetStack().RunSync([&] { sysif.FromComputer(BuildUdp(me, 5353, resolver, DNS_PORT, Query(name, qtype))); });
            BOOST_REQUIRE_EQUAL(written.size(), before + 1);
            PacketInfo a;
            std::string w;
            BOOST_REQUIRE(ParsePacket(written.back(), a, w));
            BOOST_CHECK(a.src == resolver);
            BOOST_CHECK_EQUAL(a.src_port, DNS_PORT);
            BOOST_CHECK(a.dst == me);
            BOOST_CHECK_EQUAL(a.dst_port, 5353);
            BOOST_CHECK(ChecksumsHold(written.back()));
            return UdpPayload(written.back());
        };
        std::vector<uint8_t> answer = ask("pilot.bps", DNS_TYPE_A);
        BOOST_CHECK_EQUAL(answer[3] & 0x0f, (int)DnsRcode::NO_SUCH_NAME);
        BOOST_CHECK_EQUAL(sysif.GetStats().kept_local, 1U);
        answer = ask("printer", DNS_TYPE_A);
        BOOST_CHECK_EQUAL(answer[3] & 0x0f, (int)DnsRcode::NO_SUCH_NAME);
        // Types other than addresses have no records here.
        answer = ask("example.com", 65);
        BOOST_CHECK_EQUAL(answer[3] & 0x0f, (int)DnsRcode::OK);
        BOOST_CHECK_EQUAL(Get16(answer, 6), 0);
        // An address with no gateway to ask fails, and says so.
        answer = ask("example.com", DNS_TYPE_A);
        BOOST_CHECK_EQUAL(answer[3] & 0x0f, (int)DnsRcode::SERVER_FAILURE);
        BOOST_CHECK_EQUAL(sysif.GetStats().lookups, 4U);

        // A lookup sent to another resolver is answered here all the same,
        // from that resolver's address, so the program takes it.
        const IpAddr quad9 = IpAddr::V4(9, 9, 9, 9);
        const size_t before = written.size();
        GetNetStack().RunSync([&] { sysif.FromComputer(BuildUdp(me, 5354, quad9, DNS_PORT, Query("site.bps", DNS_TYPE_A))); });
        BOOST_REQUIRE_EQUAL(written.size(), before + 1);
        PacketInfo from;
        BOOST_REQUIRE(ParsePacket(written.back(), from, why));
        BOOST_CHECK(from.src == quad9);
        BOOST_CHECK_EQUAL(UdpPayload(written.back())[3] & 0x0f, (int)DnsRcode::NO_SUCH_NAME);
        BOOST_CHECK_EQUAL(sysif.GetStats().kept_local, 3U);

        sysif.Stop();
        client.Stop();
    }
    GetNetStack().Stop();
}

BOOST_AUTO_TEST_CASE(direct_lookups_read_answers_carefully)
{
    const std::vector<uint8_t> q = BuildDnsQuery(0x4242, "www.example.com", DNS_TYPE_A);
    BOOST_REQUIRE(!q.empty());
    BOOST_CHECK(BuildDnsQuery(1, "a..b", DNS_TYPE_A).empty());
    BOOST_CHECK(BuildDnsQuery(1, std::string(64, 'a') + ".com", DNS_TYPE_A).empty());

    // An answer as a resolver sends it: the question, a CNAME, then two
    // addresses, names compressed.
    std::vector<uint8_t> a(q);
    a[2] = 0x81;
    a[3] = 0x80;
    a[7] = 3;
    const uint8_t cname[] = {0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 1, 0, 0, 2, 0xc0, 0x10};
    a.insert(a.end(), cname, cname + sizeof(cname));
    const uint8_t a1[] = {0xc0, 0x10, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34};
    const uint8_t a2[] = {0xc0, 0x10, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 93, 184, 216, 35};
    a.insert(a.end(), a1, a1 + sizeof(a1));
    a.insert(a.end(), a2, a2 + sizeof(a2));
    DnsRcode rcode;
    std::vector<IpAddr> addrs;
    uint32_t ttl;
    BOOST_REQUIRE(ParseDnsResponse(a, 0x4242, DNS_TYPE_A, rcode, addrs, ttl));
    BOOST_CHECK(rcode == DnsRcode::OK);
    BOOST_REQUIRE_EQUAL(addrs.size(), 2U);
    BOOST_CHECK(addrs[0] == IpAddr::V4(93, 184, 216, 34));
    BOOST_CHECK_EQUAL(ttl, 30U);
    // Not for this query, cut short, or truncated: not taken.
    BOOST_CHECK(!ParseDnsResponse(a, 0x4243, DNS_TYPE_A, rcode, addrs, ttl));
    std::vector<uint8_t> cut(a.begin(), a.end() - 3);
    BOOST_CHECK(!ParseDnsResponse(cut, 0x4242, DNS_TYPE_A, rcode, addrs, ttl));
    std::vector<uint8_t> tc(a);
    tc[2] |= 0x02;
    BOOST_CHECK(!ParseDnsResponse(tc, 0x4242, DNS_TYPE_A, rcode, addrs, ttl));
    // The type asked for only.
    BOOST_REQUIRE(ParseDnsResponse(a, 0x4242, DNS_TYPE_AAAA, rcode, addrs, ttl));
    BOOST_CHECK(addrs.empty());
    // A name that does not exist.
    std::vector<uint8_t> nx(q);
    nx[2] = 0x81;
    nx[3] = 0x83;
    BOOST_REQUIRE(ParseDnsResponse(nx, 0x4242, DNS_TYPE_A, rcode, addrs, ttl));
    BOOST_CHECK(rcode == DnsRcode::NO_SUCH_NAME);
}

BOOST_AUTO_TEST_CASE(the_resolvers_the_computer_used_are_read)
{
    const std::vector<CService> got = ParseResolvConf(
        "# Generated\nnameserver 127.0.0.53\nnameserver 9.9.9.9\nnameserver ::1\nnameserver 10.77.1.53\n"
        "nameserver fe80::1%eth0\nsearch lan\nnameserver 2620:fe::fe\nnameserver 9.9.9.9\n");
    BOOST_REQUIRE_EQUAL(got.size(), 2U);
    BOOST_CHECK_EQUAL(got[0].ToString(), "9.9.9.9:53");
    BOOST_CHECK_EQUAL(got[1].ToString(), "[2620:fe::fe]:53");
}

BOOST_AUTO_TEST_CASE(routing_the_computer_is_planned_and_undone)
{
    const std::vector<RouteStep> up = PlanRoutesUp("bps0", true);
    auto has = [](const std::vector<RouteStep>& steps, const std::string& joined) {
        for (const RouteStep& s : steps) {
            std::string j;
            for (const std::string& a : s.argv) j += (j.empty() ? "" : " ") + a;
            if (j == joined) return true;
        }
        return false;
    };
    BOOST_CHECK(has(up, "ip link set dev bps0 mtu 1280 up"));
    BOOST_CHECK(has(up, "ip -4 addr replace 10.77.1.2/32 dev bps0"));
    BOOST_CHECK(has(up, "ip -4 route replace default dev bps0 table 25200"));
    // The computer's own networks before everything else, and the node's own
    // sockets, carrying the mark, past the interface.
    BOOST_CHECK(has(up, "ip -4 rule add table main suppress_prefixlength 0 priority 25200"));
    BOOST_CHECK(has(up, "ip -4 rule add not fwmark 0x6270 table 25200 priority 25201"));
    BOOST_CHECK(has(up, "resolvectl domain bps0 ~."));
    BOOST_CHECK(!has(PlanRoutesUp("bps0", false), "resolvectl domain bps0 ~."));
    // Only IPv4 is needed; IPv6 may be switched off.
    for (const RouteStep& s : up) {
        if (std::find(s.argv.begin(), s.argv.end(), "-6") != s.argv.end() || s.argv[0] == "resolvectl") {
            BOOST_CHECK(!s.required);
        }
    }
    const std::vector<RouteStep> down = PlanRoutesDown("bps0", true);
    BOOST_CHECK(has(down, "ip -4 rule del priority 25201"));
    BOOST_CHECK(has(down, "ip -4 rule del priority 25200"));
    BOOST_CHECK(has(down, "ip -6 route flush table 25200"));
    BOOST_CHECK(has(down, "resolvectl revert bps0"));
}

BOOST_AUTO_TEST_SUITE_END()
