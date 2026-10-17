// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/dnsanswer.h>
#include <overlay/gatewayclient.h>
#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>
#include <overlay/netstack.h>
#include <overlay/sysif.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

        sysif.Stop();
        client.Stop();
    }
    GetNetStack().Stop();
}

BOOST_AUTO_TEST_SUITE_END()
