// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat.h>
#include <netbase.h>
#include <overlay/exitpolicy.h>
#include <overlay/gateway.h>
#include <overlay/gatewayproto.h>
#include <overlay/ippacket.h>
#include <overlay/netstack.h>
#include <overlay/path.h>
#include <overlay/transport.h>
#include <test/util/setup_common.h>
#include <util/memory.h>
#include <util/time.h>

#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <thread>

using namespace overlay;

namespace {

IpAddr V6(const char* hex32)
{
    std::array<uint8_t, 16> b{};
    for (int i = 0; i < 16; ++i) {
        unsigned v = 0;
        sscanf(hex32 + 2 * i, "%2x", &v);
        b[i] = (uint8_t)v;
    }
    return IpAddr::V6(b);
}

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

/** A TCP SYN from `src`:`sp` to `dst`:`dp`. */
std::vector<uint8_t> Syn(const IpAddr& src, uint16_t sp, const IpAddr& dst, uint16_t dp)
{
    // Built as a UDP packet of the right size, then turned into TCP: the
    // header layout up to the ports is the same.
    std::vector<uint8_t> pkt = BuildUdp(src, sp, dst, dp, std::vector<uint8_t>(12, 0));
    const size_t ip = src.version == 6 ? 40 : 20;
    if (src.version == 6) {
        pkt[6] = IPPROTO_TCP_NUM;
    } else {
        pkt[9] = IPPROTO_TCP_NUM;
    }
    uint8_t* tcp = pkt.data() + ip;
    std::memset(tcp + 4, 0, 16);
    tcp[4] = 0x12; tcp[5] = 0x34; tcp[6] = 0x56; tcp[7] = 0x78; // sequence
    tcp[12] = 5 << 4;
    tcp[13] = TCP_SYN;
    PacketInfo info;
    std::string why;
    BOOST_REQUIRE(ParsePacket(pkt, info, why));
    RewritePacket(pkt, info, src, sp, dst, dp); // fixes the checksums
    return pkt;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(gateway_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(packets_are_checked_strictly)
{
    const IpAddr a = IpAddr::V4(10, 77, 0, 2), b = IpAddr::V4(93, 184, 216, 34);
    std::vector<uint8_t> syn = Syn(a, 50000, b, 443);
    PacketInfo info;
    std::string why;
    BOOST_REQUIRE(ParsePacket(syn, info, why));
    BOOST_CHECK(info.IsTcpOpen());
    BOOST_CHECK(info.src == a && info.dst == b);
    BOOST_CHECK_EQUAL(info.src_port, 50000);
    BOOST_CHECK_EQUAL(info.dst_port, 443);
    BOOST_CHECK_EQUAL(info.tcp_seq, 0x12345678U);
    BOOST_CHECK(ChecksumsHold(syn));

    // Each of these is refused.
    std::vector<uint8_t> bad = syn;
    bad.pop_back();
    BOOST_CHECK(!ParsePacket(bad, info, why)); // length disagrees
    bad = syn;
    bad[6] = 0x20; // more fragments
    BOOST_CHECK(!ParsePacket(bad, info, why));
    BOOST_CHECK_EQUAL(why, "IPv4 fragment");
    bad = syn;
    bad[7] = 1; // a later fragment
    BOOST_CHECK(!ParsePacket(bad, info, why));
    bad = syn;
    bad[9] = 1; // ICMP
    BOOST_CHECK(!ParsePacket(bad, info, why));
    bad = syn;
    bad[0] = 0x44; // header shorter than 20
    BOOST_CHECK(!ParsePacket(bad, info, why));
    bad = syn;
    bad[20 + 12] = 0x40; // TCP header length 16
    BOOST_CHECK(!ParsePacket(bad, info, why));
    BOOST_CHECK(!ParsePacket(std::vector<uint8_t>(), info, why));
    BOOST_CHECK(!ParsePacket(std::vector<uint8_t>(MAX_GATEWAY_PACKET + 1, 0x45), info, why));

    // IPv6, and an extension header in front of TCP refused.
    const IpAddr c = V6("20010db8000000000000000000000001"), d = V6("2a000000000000000000000000000002");
    std::vector<uint8_t> syn6 = Syn(c, 40000, d, 443);
    BOOST_REQUIRE(ParsePacket(syn6, info, why));
    BOOST_CHECK(info.version == 6 && info.IsTcpOpen());
    BOOST_CHECK(ChecksumsHold(syn6));
    bad = syn6;
    bad[6] = 0; // hop-by-hop options
    BOOST_CHECK(!ParsePacket(bad, info, why));
}

BOOST_AUTO_TEST_CASE(rewriting_keeps_checksums_right)
{
    const IpAddr a = IpAddr::V4(10, 77, 0, 2), b = IpAddr::V4(93, 184, 216, 34);
    std::vector<uint8_t> pkt = BuildUdp(a, 5353, b, 443, std::vector<uint8_t>{1, 2, 3, 4, 5});
    BOOST_CHECK(ChecksumsHold(pkt));
    PacketInfo info;
    std::string why;
    BOOST_REQUIRE(ParsePacket(pkt, info, why));
    const IpAddr x = IpAddr::V4(100, 64, 0, 9), y = IpAddr::V4(100, 64, 0, 1);
    RewritePacket(pkt, info, x, 1024, y, 1);
    BOOST_CHECK(ChecksumsHold(pkt));
    BOOST_REQUIRE(ParsePacket(pkt, info, why));
    BOOST_CHECK(info.src == x && info.dst == y && info.src_port == 1024 && info.dst_port == 1);

    std::vector<uint8_t> syn = Syn(a, 50000, b, 443);
    BOOST_REQUIRE(ParsePacket(syn, info, why));
    const std::vector<uint8_t> rst = BuildTcpReset(info);
    BOOST_CHECK(ChecksumsHold(rst));
    PacketInfo r;
    BOOST_REQUIRE(ParsePacket(rst, r, why));
    BOOST_CHECK(r.src == b && r.dst == a && r.src_port == 443 && r.dst_port == 50000);
    BOOST_CHECK_EQUAL(r.tcp_flags, TCP_RST | TCP_ACK);
    BOOST_CHECK_EQUAL(r.tcp_ack, 0x12345679U); // the SYN occupies one
}

BOOST_AUTO_TEST_CASE(only_public_addresses_are_exits)
{
    for (const IpAddr& a : {IpAddr::V4(0, 1, 2, 3), IpAddr::V4(10, 0, 0, 1), IpAddr::V4(100, 64, 0, 1),
                            IpAddr::V4(100, 127, 255, 254), IpAddr::V4(127, 0, 0, 1), IpAddr::V4(169, 254, 1, 1),
                            IpAddr::V4(172, 16, 0, 1), IpAddr::V4(172, 31, 255, 255), IpAddr::V4(192, 0, 2, 1),
                            IpAddr::V4(192, 168, 1, 1), IpAddr::V4(198, 18, 0, 1), IpAddr::V4(198, 51, 100, 7),
                            IpAddr::V4(203, 0, 113, 9), IpAddr::V4(224, 0, 0, 1), IpAddr::V4(239, 1, 1, 1),
                            IpAddr::V4(240, 0, 0, 1), IpAddr::V4(255, 255, 255, 255)}) {
        BOOST_CHECK_MESSAGE(!IsPublicAddress(a), a.ToString());
    }
    for (const IpAddr& a : {IpAddr::V4(1, 1, 1, 1), IpAddr::V4(8, 8, 8, 8), IpAddr::V4(93, 184, 216, 34),
                            IpAddr::V4(100, 63, 255, 255), IpAddr::V4(100, 128, 0, 0), IpAddr::V4(172, 32, 0, 1),
                            IpAddr::V4(198, 20, 0, 1), IpAddr::V4(223, 255, 255, 254)}) {
        BOOST_CHECK_MESSAGE(IsPublicAddress(a), a.ToString());
    }
    for (const char* a : {"00000000000000000000000000000000", "00000000000000000000000000000001",
                          "00000000000000000000ffff7f000001", "0064ff9b00000000000000000a000001",
                          "fd000000000000000000000000000001", "fe800000000000000000000000000001",
                          "ff020000000000000000000000000001", "20010000000000000000000000000001",
                          "20010db8000000000000000000000001", "20020a00000100000000000000000001",
                          "3fff0000000000000000000000000001"}) {
        BOOST_CHECK_MESSAGE(!IsPublicAddress(V6(a)), a);
    }
    for (const char* a : {"2a001450400100000000000000000001", "26064700000000000000000000001111",
                          "20010200000000000000000000000001", "24000000000000000000000000000001"}) {
        BOOST_CHECK_MESSAGE(IsPublicAddress(V6(a)), a);
    }
}

BOOST_AUTO_TEST_CASE(exit_policy)
{
    ExitPolicy p;
    BOOST_CHECK_EQUAL(p.ToString(), "443,465,853,993,995,5223,5228,udp:443");
    for (uint16_t port : {443, 465, 853, 993, 995, 5223, 5228}) BOOST_CHECK(p.AllowsPort(IPPROTO_TCP_NUM, port));
    for (uint16_t port : {25, 80, 587, 5222, 22, 53}) BOOST_CHECK(!p.AllowsPort(IPPROTO_TCP_NUM, port));
    BOOST_CHECK(p.AllowsPort(IPPROTO_UDP_NUM, 443));
    BOOST_CHECK(!p.AllowsPort(IPPROTO_UDP_NUM, 53));

    std::string why;
    BOOST_CHECK(p.Allows(IPPROTO_TCP_NUM, IpAddr::V4(93, 184, 216, 34), 443, why));
    BOOST_CHECK(!p.Allows(IPPROTO_TCP_NUM, IpAddr::V4(192, 168, 1, 1), 443, why));
    BOOST_CHECK(!p.Allows(IPPROTO_TCP_NUM, IpAddr::V4(93, 184, 216, 34), 80, why));
    p.AllowLocal(true);
    BOOST_CHECK(p.Allows(IPPROTO_TCP_NUM, IpAddr::V4(127, 0, 0, 1), 443, why));

    std::string error;
    BOOST_CHECK(p.Parse("993,udp:443,tcp:8443", error));
    BOOST_CHECK_EQUAL(p.ToString(), "993,8443,udp:443");
    BOOST_CHECK(!p.Parse("443,25", error));
    BOOST_CHECK(error.find("port 25") != std::string::npos);
    BOOST_CHECK(!p.Parse("udp:25", error));
    BOOST_CHECK(!p.Parse("443,http", error));
    BOOST_CHECK(!p.Parse("70000", error));
    BOOST_CHECK(!p.Parse("", error));
    // A refused list leaves the policy as it was.
    BOOST_CHECK_EQUAL(p.ToString(), "993,8443,udp:443");
}

BOOST_AUTO_TEST_CASE(messages_round_trip)
{
    GatewayMessage m;
    const std::vector<uint8_t> small(600, 0x45);
    std::vector<std::vector<uint8_t>> msgs = EncodePacket(small, 7);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1U);
    BOOST_CHECK(msgs[0].size() <= 637U);
    BOOST_REQUIRE(DecodeGatewayMessage(msgs[0], m));
    BOOST_CHECK(m.kind == GatewayKind::PACKET && m.bytes == small);

    // A full-size packet goes in three pieces and comes back whole.
    std::vector<uint8_t> big(MAX_GATEWAY_PACKET);
    for (size_t i = 0; i < big.size(); ++i) big[i] = (uint8_t)i;
    msgs = EncodePacket(big, 9);
    BOOST_REQUIRE_EQUAL(msgs.size(), 3U);
    Reassembler r;
    std::vector<uint8_t> whole;
    for (size_t i : {2, 0, 1}) { // out of order
        BOOST_REQUIRE(msgs[i].size() <= 637U);
        BOOST_REQUIRE(DecodeGatewayMessage(msgs[i], m));
        BOOST_CHECK(m.kind == GatewayKind::FRAG && m.frag_id == 9 && m.frag_count == 3);
        const bool done = r.Add(1, m, 0, whole);
        BOOST_CHECK_EQUAL(done, i == 1);
    }
    BOOST_CHECK(whole == big);
    BOOST_CHECK_EQUAL(r.PartialCount(), 0U);
    BOOST_CHECK(EncodePacket(std::vector<uint8_t>(MAX_GATEWAY_PACKET + 1), 1).empty());

    BOOST_REQUIRE(DecodeGatewayMessage(EncodeResolve(77, RESOLVE_V6, "example.com"), m));
    BOOST_CHECK(m.kind == GatewayKind::RESOLVE && m.request == 77 && m.family == RESOLVE_V6 && m.name == "example.com");
    BOOST_CHECK(!DecodeGatewayMessage(EncodeResolve(1, RESOLVE_ANY, "bad name"), m));
    BOOST_CHECK(!DecodeGatewayMessage(EncodeResolve(1, 5, "example.com"), m));

    const std::vector<IpAddr> addrs{IpAddr::V4(93, 184, 216, 34), V6("2a001450400100000000000000000001")};
    BOOST_REQUIRE(DecodeGatewayMessage(EncodeResolved(77, ResolveStatus::OK, 300, addrs), m));
    BOOST_CHECK(m.kind == GatewayKind::RESOLVED && m.request == 77 && m.ttl == 300 && m.addrs == addrs);

    BOOST_REQUIRE(DecodeGatewayMessage(EncodeStatus(GatewayState::CLOSED_TODAY, {443, 993}, {443}), m));
    BOOST_CHECK(m.kind == GatewayKind::STATUS && m.state == GatewayState::CLOSED_TODAY);
    BOOST_CHECK(m.tcp_ports == std::vector<uint16_t>({443, 993}) && m.udp_ports == std::vector<uint16_t>({443}));
    BOOST_REQUIRE(DecodeGatewayMessage(EncodeHello(), m));
    BOOST_CHECK(m.kind == GatewayKind::HELLO);

    // Malformed: trailing bytes, impossible counts, another tag.
    std::vector<uint8_t> v = EncodeHello();
    v.push_back(0);
    BOOST_CHECK(!DecodeGatewayMessage(v, m));
    v = EncodeStatus(GatewayState::OPEN, {443}, {});
    v.push_back(1);
    BOOST_CHECK(!DecodeGatewayMessage(v, m));
    v = msgs[0];
    v[5] = 9; // count past MAX_FRAGS
    BOOST_CHECK(!DecodeGatewayMessage(v, m));
    v = msgs[0];
    v[4] = 3; // index past count
    BOOST_CHECK(!DecodeGatewayMessage(v, m));
    v = EncodeHello();
    v[0] = 0x12;
    BOOST_CHECK(!DecodeGatewayMessage(v, m));
}

BOOST_AUTO_TEST_CASE(reassembly_is_bounded)
{
    std::vector<uint8_t> big(MAX_GATEWAY_PACKET, 0x60);
    const std::vector<std::vector<uint8_t>> msgs = EncodePacket(big, 1);
    GatewayMessage m;
    std::vector<uint8_t> whole;

    // Pieces that never complete are let go.
    Reassembler r;
    BOOST_REQUIRE(DecodeGatewayMessage(msgs[0], m));
    BOOST_CHECK(!r.Add(5, m, 0, whole));
    BOOST_CHECK_EQUAL(r.PartialCount(), 1U);
    BOOST_REQUIRE(DecodeGatewayMessage(msgs[1], m));
    BOOST_CHECK(!r.Add(5, m, Reassembler::REASSEMBLY_MS + 1, whole));
    BOOST_CHECK_EQUAL(r.PartialCount(), 1U); // the old one gone, this one new

    // The same piece twice ends the packet.
    Reassembler dup;
    BOOST_REQUIRE(DecodeGatewayMessage(msgs[0], m));
    BOOST_CHECK(!dup.Add(5, m, 0, whole));
    BOOST_CHECK(!dup.Add(5, m, 0, whole));
    BOOST_CHECK_EQUAL(dup.PartialCount(), 0U);

    // One source cannot hold more than its share of partial packets.
    Reassembler many;
    for (uint16_t id = 0; id < Reassembler::MAX_PARTIAL + 10; ++id) {
        std::vector<std::vector<uint8_t>> p = EncodePacket(big, id);
        BOOST_REQUIRE(DecodeGatewayMessage(p[0], m));
        many.Add(9, m, 0, whole);
    }
    BOOST_CHECK_EQUAL(many.PartialCount(), Reassembler::MAX_PARTIAL);
    // Another source still can.
    BOOST_REQUIRE(DecodeGatewayMessage(msgs[0], m));
    many.Add(10, m, 0, whole);
    BOOST_CHECK_EQUAL(many.PartialCount(), Reassembler::MAX_PARTIAL + 1);
    many.Forget(9);
    BOOST_CHECK_EQUAL(many.PartialCount(), 1U);
}

namespace {

/*
 * A visitor inside the same stack: an interface whose packets go to the
 * gateway as messages from meeting path 42, and which receives what the
 * gateway sends back. Delivery is always posted, never done inside a stack
 * callback, as it would be across the overlay.
 */
constexpr uint64_t MEETING = 42;
struct netif g_visitor_if;
std::atomic<int> g_visitor_resets{0};
std::deque<GatewayMessage> g_status;
std::deque<GatewayMessage> g_resolved;
std::deque<std::vector<uint8_t>> g_udp_back;
Reassembler g_visitor_reassembly;

void ToVisitor(const std::vector<uint8_t>& pkt)
{
    PacketInfo info;
    std::string why;
    if (!ParsePacket(pkt, info, why)) return;
    if (info.IsUdp()) {
        g_udp_back.push_back(std::vector<uint8_t>(pkt.begin() + info.ip_header + 8, pkt.end()));
        return;
    }
    struct pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)pkt.size(), PBUF_RAM);
    pbuf_take(p, pkt.data(), (u16_t)pkt.size());
    if (g_visitor_if.input(p, &g_visitor_if) != ERR_OK) pbuf_free(p);
}

// Called on the stack thread, and on the gateway's resolver thread for
// answers to lookups: nothing here asserts, it only hands over.
bool FromGateway(uint64_t path, const std::vector<uint8_t>& payload)
{
    if (path != MEETING) return false;
    GatewayMessage m;
    if (!DecodeGatewayMessage(payload, m)) return false;
    GetNetStack().Post([m] {
        std::vector<uint8_t> whole;
        if (m.kind == GatewayKind::PACKET) {
            ToVisitor(m.bytes);
        } else if (m.kind == GatewayKind::FRAG) {
            if (g_visitor_reassembly.Add(MEETING, m, GetTimeMillis(), whole)) ToVisitor(whole);
        } else if (m.kind == GatewayKind::STATUS) {
            g_status.push_back(m);
        } else if (m.kind == GatewayKind::RESOLVED) {
            g_resolved.push_back(m);
        }
    });
    return true;
}

err_t VisitorOut4(struct netif*, struct pbuf* p, const ip4_addr_t*)
{
    std::vector<uint8_t> pkt(p->tot_len);
    pbuf_copy_partial(p, pkt.data(), p->tot_len, 0);
    for (std::vector<uint8_t>& m : EncodePacket(pkt, 0)) {
        if (g_gateway) g_gateway->HandleApp(Hop::Path(MEETING), std::move(m));
    }
    return ERR_OK;
}

err_t VisitorInit(struct netif* n)
{
    n->output = VisitorOut4;
    n->mtu = 1280;
    n->name[0] = 'v';
    n->name[1] = 'i';
    return ERR_OK;
}

struct Client {
    struct tcp_pcb* pcb{nullptr};
    bool connected{false};
    bool reset{false};
    std::string got;
};
Client g_client;

err_t ClientConnected(void*, struct tcp_pcb*, err_t err)
{
    g_client.connected = err == ERR_OK;
    return ERR_OK;
}

err_t ClientRecv(void*, struct tcp_pcb* pcb, struct pbuf* p, err_t)
{
    if (!p) return ERR_OK;
    std::string s(p->tot_len, '\0');
    pbuf_copy_partial(p, &s[0], p->tot_len, 0);
    g_client.got += s;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

void ClientError(void*, err_t err)
{
    g_client.pcb = nullptr;
    g_client.reset = true;
    if (err == ERR_RST) ++g_visitor_resets;
}

/** Wait, checking on the stack thread, for up to ten seconds. */
template <typename F>
bool Eventually(F check)
{
    for (int i = 0; i < 200; ++i) {
        bool ok = false;
        GetNetStack().RunSync([&] { ok = check(); });
        if (ok) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

/** A TCP echo server on 127.0.0.1, answering each read with the same bytes. */
struct EchoServer {
    SOCKET listen{INVALID_SOCKET};
    uint16_t port{0};
    std::thread thread;
    std::atomic<bool> stop{false};

    EchoServer()
    {
        listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof(a);
        BOOST_REQUIRE(bind(listen, (struct sockaddr*)&a, sizeof(a)) == 0);
        BOOST_REQUIRE(::listen(listen, 4) == 0);
        getsockname(listen, (struct sockaddr*)&a, &len);
        port = ntohs(a.sin_port);
        thread = std::thread([this] {
            SOCKET c = accept(listen, nullptr, nullptr);
            if (c == INVALID_SOCKET) return;
            char buf[4096];
            for (;;) {
                const int n = recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                send(c, buf, n, 0);
            }
            CloseSocket(c);
        });
    }
    ~EchoServer()
    {
        shutdown(listen, 2); // wakes an accept still waiting
        CloseSocket(listen);
        if (thread.joinable()) thread.join();
    }
};

/** A UDP server on 127.0.0.1 that answers each datagram with it reversed. */
struct UdpReverser {
    SOCKET s{INVALID_SOCKET};
    uint16_t port{0};
    std::thread thread;

    UdpReverser()
    {
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof(a);
        BOOST_REQUIRE(bind(s, (struct sockaddr*)&a, sizeof(a)) == 0);
        getsockname(s, (struct sockaddr*)&a, &len);
        port = ntohs(a.sin_port);
        thread = std::thread([this] {
            char buf[2048];
            struct sockaddr_storage from;
            socklen_t flen = sizeof(from);
            const int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
            if (n <= 0) return;
            std::reverse(buf, buf + n);
            sendto(s, buf, n, 0, (struct sockaddr*)&from, flen);
        });
    }
    ~UdpReverser()
    {
        shutdown(s, 2); // wakes a recvfrom still waiting
        CloseSocket(s);
        if (thread.joinable()) thread.join();
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(a_visitor_reaches_the_internet_through_the_gateway)
{
    std::string error;
    BOOST_REQUIRE(GetNetStack().Start(error));

    EchoServer echo;
    UdpReverser reverser;

    GatewayConfig cfg;
    BOOST_REQUIRE(cfg.policy.Parse(strprintf("%u,udp:%u", echo.port, reverser.port), error));
    cfg.policy.AllowLocal(true); // the "internet" here is 127.0.0.1
    bool serving = true;
    g_gateway = MakeUnique<Gateway>(cfg, FromGateway, [&serving] { return serving; },
        [] { return std::vector<IpAddr>(); },
        [](const std::string& name, uint8_t, std::vector<IpAddr>& out) {
            if (name != "example.com") return ResolveStatus::NO_SUCH_NAME;
            out = {IpAddr::V4(192, 168, 1, 1), IpAddr::V4(93, 184, 216, 34), IpAddr::V4(10, 0, 0, 1)};
            return ResolveStatus::OK;
        });
    BOOST_REQUIRE(g_gateway->Start(error));
    BOOST_REQUIRE(Eventually([] { return g_gateway->State() == GatewayState::OPEN; }));

    bool added = false, dialled = false;
    GetNetStack().RunSync([&] {
        ip4_addr_t addr, mask, gw;
        IP4_ADDR(&addr, 10, 77, 0, 2);
        IP4_ADDR(&mask, 255, 255, 255, 255);
        IP4_ADDR(&gw, 0, 0, 0, 0);
        added = netif_add(&g_visitor_if, &addr, &mask, &gw, nullptr, VisitorInit, ip_input) != nullptr;
        if (!added) return;
        netif_set_up(&g_visitor_if);
        netif_set_link_up(&g_visitor_if);
        netif_set_default(&g_visitor_if);

        g_client = Client();
        g_client.pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        tcp_recv(g_client.pcb, ClientRecv);
        tcp_err(g_client.pcb, ClientError);
        tcp_nagle_disable(g_client.pcb);
        ip_addr_t dst;
        IP_ADDR4(&dst, 127, 0, 0, 1);
        dialled = tcp_connect(g_client.pcb, &dst, echo.port, ClientConnected) == ERR_OK;
    });
    BOOST_REQUIRE(added && dialled);

    BOOST_REQUIRE(Eventually([] { return g_client.connected; }));
    // Several segments each way, so the window and the stack's buffering are exercised.
    std::string sent;
    for (int i = 0; i < 4000; ++i) sent += (char)('a' + i % 26);
    bool written = false;
    GetNetStack().RunSync([&] {
        written = tcp_write(g_client.pcb, sent.data(), (u16_t)sent.size(), TCP_WRITE_FLAG_COPY) == ERR_OK;
        tcp_output(g_client.pcb);
    });
    BOOST_REQUIRE(written);
    BOOST_CHECK(Eventually([&] { return g_client.got.size() >= sent.size(); }));
    BOOST_CHECK(g_client.got == sent);
    BOOST_CHECK_EQUAL(g_gateway->GetStats().tcp_flows, 1U);
    BOOST_CHECK(g_gateway->GetStats().today_bytes > 2 * sent.size());

    // A port outside the policy is answered with a reset, and nothing is opened.
    GetNetStack().RunSync([&] {
        tcp_arg(g_client.pcb, nullptr);
        tcp_abort(g_client.pcb);
        g_client = Client();
        g_client.pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        tcp_err(g_client.pcb, ClientError);
        ip_addr_t dst;
        IP_ADDR4(&dst, 127, 0, 0, 1);
        tcp_connect(g_client.pcb, &dst, (u16_t)(echo.port == 65535 ? 1 : echo.port + 1), ClientConnected);
    });
    BOOST_CHECK(Eventually([] { return g_client.reset; }));
    BOOST_CHECK(!g_client.connected);
    BOOST_CHECK_EQUAL(g_gateway->GetStats().refused_policy, 1U);

    // UDP out and back.
    GetNetStack().RunSync([&] {
        const std::vector<uint8_t> ask{'q', 'u', 'i', 'c'};
        const std::vector<uint8_t> pkt = BuildUdp(IpAddr::V4(10, 77, 0, 2), 50001, IpAddr::V4(127, 0, 0, 1), reverser.port, ask);
        for (std::vector<uint8_t>& m : EncodePacket(pkt, 0)) g_gateway->HandleApp(Hop::Path(MEETING), std::move(m));
    });
    BOOST_CHECK(Eventually([] { return !g_udp_back.empty(); }));
    std::vector<uint8_t> back;
    GetNetStack().RunSync([&] {
        if (!g_udp_back.empty()) back = g_udp_back.front();
    });
    BOOST_CHECK(back == std::vector<uint8_t>({'c', 'i', 'u', 'q'}));

    // Names: only public addresses come back, and local names are not looked up.
    g_gateway->HandleApp(Hop::Path(MEETING), EncodeResolve(5, RESOLVE_ANY, "example.com"));
    g_gateway->HandleApp(Hop::Path(MEETING), EncodeResolve(6, RESOLVE_ANY, "printer.lan"));
    BOOST_CHECK(Eventually([] { return g_resolved.size() >= 2; }));
    std::deque<GatewayMessage> answers;
    GetNetStack().RunSync([&] { answers.swap(g_resolved); });
    for (const GatewayMessage& m : answers) {
        if (m.request == 5) {
            // allow_local keeps them all here; the filter is checked below without it.
            BOOST_CHECK(m.status == ResolveStatus::OK);
            BOOST_CHECK_EQUAL(m.addrs.size(), 3U);
        } else {
            BOOST_CHECK(m.status == ResolveStatus::NO_SUCH_NAME);
        }
    }

    // Asked how it is, it says open, with its ports.
    g_gateway->HandleApp(Hop::Path(MEETING), EncodeHello());
    BOOST_CHECK(Eventually([] { return !g_status.empty(); }));
    std::deque<GatewayMessage> said;
    GetNetStack().RunSync([&] { said.swap(g_status); });
    BOOST_REQUIRE(!said.empty());
    BOOST_CHECK(said.back().state == GatewayState::OPEN);
    BOOST_CHECK(said.back().udp_ports == std::vector<uint16_t>({reverser.port}));

    g_gateway->Stop();
    g_gateway.reset();

    // Without allow_local, and not serving: nothing opens, and it says why.
    GatewayConfig plain;
    serving = false;
    g_gateway = MakeUnique<Gateway>(plain, FromGateway, [&serving] { return serving; },
        [] { return std::vector<IpAddr>(); },
        [](const std::string&, uint8_t, std::vector<IpAddr>& out) {
            out = {IpAddr::V4(192, 168, 1, 1), IpAddr::V4(93, 184, 216, 34)};
            return ResolveStatus::OK;
        });
    BOOST_REQUIRE(g_gateway->Start(error));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    BOOST_CHECK(g_gateway->State() == GatewayState::OFF);
    GetNetStack().RunSync([&] {
        const std::vector<uint8_t> syn = Syn(IpAddr::V4(10, 77, 0, 2), 50002, IpAddr::V4(93, 184, 216, 34), 443);
        g_gateway->HandleApp(Hop::Path(MEETING), std::vector<uint8_t>(EncodePacket(syn, 0)[0]));
    });
    BOOST_CHECK(Eventually([] { return !g_status.empty(); }));
    said.clear();
    GetNetStack().RunSync([&] { said.swap(g_status); });
    BOOST_REQUIRE(!said.empty());
    BOOST_CHECK(said.back().state == GatewayState::OFF);
    BOOST_CHECK_EQUAL(g_gateway->GetStats().refused_state, 1U);
    BOOST_CHECK_EQUAL(g_gateway->GetStats().opened, 0U);

    g_gateway->Stop();
    g_gateway.reset();
    GetNetStack().RunSync([] { netif_remove(&g_visitor_if); });
    GetNetStack().Stop();
}

BOOST_AUTO_TEST_CASE(lookups_give_back_only_public_addresses)
{
    std::string error;
    BOOST_REQUIRE(GetNetStack().Start(error));
    GatewayConfig plain;
    g_gateway = MakeUnique<Gateway>(plain, FromGateway, [] { return true; },
        [] { return std::vector<IpAddr>(); },
        [](const std::string&, uint8_t, std::vector<IpAddr>& out) {
            out = {IpAddr::V4(192, 168, 1, 1), IpAddr::V4(93, 184, 216, 34), IpAddr::V4(127, 0, 0, 1)};
            return ResolveStatus::OK;
        });
    BOOST_REQUIRE(g_gateway->Start(error));
    BOOST_REQUIRE(Eventually([] { return g_gateway->State() == GatewayState::OPEN; }));
    g_gateway->HandleApp(Hop::Path(MEETING), EncodeResolve(9, RESOLVE_ANY, "example.com"));
    BOOST_CHECK(Eventually([] { return !g_resolved.empty(); }));
    std::deque<GatewayMessage> answers;
    GetNetStack().RunSync([&] { answers.swap(g_resolved); });
    BOOST_REQUIRE(!answers.empty());
    BOOST_CHECK(answers.front().status == ResolveStatus::OK);
    BOOST_CHECK(answers.front().addrs == std::vector<IpAddr>({IpAddr::V4(93, 184, 216, 34)}));
    g_gateway->Stop();
    g_gateway.reset();
    GetNetStack().Stop();
}

BOOST_AUTO_TEST_SUITE_END()
