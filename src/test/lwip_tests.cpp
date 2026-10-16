// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/netstack.h>
#include <test/util/setup_common.h>

#include <lwip/ip.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip6_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>

#include <boost/test/unit_test.hpp>

#include <deque>
#include <string>
#include <vector>

/*
 * The vendored lwIP, built with BPS's settings, holding a real TCP connection
 * in each IP version: both ends on one interface whose output is fed back to
 * its input, which is all a gateway's interface is, with the overlay in
 * between. Proves the library links, the settings agree with each other, and
 * the stack announces the segment size the overlay needs.
 */
namespace {

std::deque<std::vector<unsigned char>> g_wire;
std::vector<std::vector<unsigned char>> g_sent;

void Capture(struct pbuf* p)
{
    std::vector<unsigned char> bytes(p->tot_len);
    pbuf_copy_partial(p, bytes.data(), p->tot_len, 0);
    g_wire.push_back(bytes);
    g_sent.push_back(bytes);
}

err_t Output4(struct netif*, struct pbuf* p, const ip4_addr_t*)
{
    Capture(p);
    return ERR_OK;
}

err_t Output6(struct netif*, struct pbuf* p, const ip6_addr_t*)
{
    Capture(p);
    return ERR_OK;
}

err_t InitLoop(struct netif* n)
{
    n->output = Output4;
    n->output_ip6 = Output6;
    n->mtu = 1280;
    n->name[0] = 't';
    n->name[1] = 'l';
    return ERR_OK;
}

/** Deliver everything in flight, until the wire is quiet. */
void Pump(struct netif* n)
{
    for (int rounds = 0; rounds < 1000 && !g_wire.empty(); ++rounds) {
        const std::vector<unsigned char> bytes = g_wire.front();
        g_wire.pop_front();
        struct pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)bytes.size(), PBUF_RAM);
        BOOST_REQUIRE(p != nullptr);
        pbuf_take(p, bytes.data(), (u16_t)bytes.size());
        if (n->input(p, n) != ERR_OK) pbuf_free(p);
    }
    sys_check_timeouts();
}

struct Ends {
    struct tcp_pcb* accepted{nullptr};
    bool connected{false};
    std::string server_got;
    std::string client_got;
};
Ends g_ends;

err_t ServerRecv(void*, struct tcp_pcb* pcb, struct pbuf* p, err_t)
{
    if (p == nullptr) return ERR_OK;
    std::string s(p->tot_len, '\0');
    pbuf_copy_partial(p, &s[0], p->tot_len, 0);
    g_ends.server_got += s;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

err_t ClientRecv(void*, struct tcp_pcb* pcb, struct pbuf* p, err_t)
{
    if (p == nullptr) return ERR_OK;
    std::string s(p->tot_len, '\0');
    pbuf_copy_partial(p, &s[0], p->tot_len, 0);
    g_ends.client_got += s;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

err_t Accepted(void*, struct tcp_pcb* pcb, err_t err)
{
    if (err != ERR_OK || pcb == nullptr) return ERR_VAL;
    g_ends.accepted = pcb;
    // As the gateway runs its connections: a relay of someone else's bytes
    // sends them as they come rather than holding a short tail for an ACK.
    tcp_nagle_disable(pcb);
    tcp_recv(pcb, ServerRecv);
    return ERR_OK;
}

err_t Connected(void*, struct tcp_pcb*, err_t err)
{
    g_ends.connected = (err == ERR_OK);
    return ERR_OK;
}

/** The MSS option of the first SYN on the wire, or 0. */
unsigned FirstSynMss(bool v6)
{
    for (const std::vector<unsigned char>& pkt : g_sent) {
        const size_t ip_len = v6 ? 40 : (size_t)(pkt[0] & 0x0f) * 4;
        if (pkt.size() < ip_len + 20) continue;
        const unsigned char* tcp = pkt.data() + ip_len;
        if (!(tcp[13] & 0x02)) continue; // SYN
        const size_t tcp_len = (size_t)(tcp[12] >> 4) * 4;
        for (size_t i = 20; i + 4 <= tcp_len;) {
            if (tcp[i] == 0) break;
            if (tcp[i] == 1) { ++i; continue; }
            if (tcp[i] == 2 && tcp[i + 1] == 4) return (unsigned)tcp[i + 2] << 8 | tcp[i + 3];
            i += tcp[i + 1] ? tcp[i + 1] : 1;
        }
    }
    return 0;
}

void RoundTrip(struct netif* n, const ip_addr_t& listen_at, const ip_addr_t& dial)
{
    g_ends = Ends();
    g_wire.clear();
    g_sent.clear();
    const bool v6 = IP_IS_V6(&dial);

    struct tcp_pcb* listener = tcp_new_ip_type(v6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
    BOOST_REQUIRE(listener != nullptr);
    BOOST_REQUIRE_EQUAL(tcp_bind(listener, &listen_at, 443), ERR_OK);
    listener = tcp_listen(listener);
    BOOST_REQUIRE(listener != nullptr);
    tcp_accept(listener, Accepted);

    struct tcp_pcb* client = tcp_new_ip_type(v6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
    BOOST_REQUIRE(client != nullptr);
    tcp_recv(client, ClientRecv);
    tcp_nagle_disable(client);
    BOOST_REQUIRE_EQUAL(tcp_connect(client, &dial, 443, Connected), ERR_OK);
    Pump(n);
    BOOST_REQUIRE(g_ends.connected);
    BOOST_REQUIRE(g_ends.accepted != nullptr);
    // The segment size the overlay needs: one TCP segment, one datagram.
    BOOST_CHECK_EQUAL(FirstSynMss(v6), (unsigned)TCP_MSS);

    // More than one segment's worth each way, so segmentation is exercised.
    const std::string ask(3000, 'q');
    const std::string answer(5000, 'a');
    BOOST_REQUIRE_EQUAL(tcp_write(client, ask.data(), (u16_t)ask.size(), TCP_WRITE_FLAG_COPY), ERR_OK);
    tcp_output(client);
    Pump(n);
    BOOST_CHECK_EQUAL(g_ends.server_got.size(), ask.size());
    BOOST_CHECK(g_ends.server_got == ask);
    BOOST_REQUIRE_EQUAL(tcp_write(g_ends.accepted, answer.data(), (u16_t)answer.size(), TCP_WRITE_FLAG_COPY), ERR_OK);
    tcp_output(g_ends.accepted);
    Pump(n);
    BOOST_CHECK(g_ends.client_got == answer);

    // No packet larger than one overlay datagram carries.
    for (const std::vector<unsigned char>& pkt : g_sent) BOOST_CHECK(pkt.size() <= 635U);

    tcp_abort(client);
    tcp_abort(g_ends.accepted);
    tcp_close(listener);
    Pump(n);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(lwip_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tcp_over_a_loop_interface)
{
    overlay::InitNetStack();

    struct netif loop;
    ip4_addr_t addr, mask, gw;
    IP4_ADDR(&addr, 10, 9, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 0, 0, 0, 0);
    BOOST_REQUIRE(netif_add(&loop, &addr, &mask, &gw, nullptr, InitLoop, ip_input) != nullptr);
    ip6_addr_t addr6;
    IP6_ADDR(&addr6, PP_HTONL(0xfd627073UL), 0, 0, PP_HTONL(1));
    s8_t idx = -1;
    BOOST_REQUIRE_EQUAL(netif_add_ip6_address(&loop, &addr6, &idx), ERR_OK);
    netif_ip6_addr_set_state(&loop, idx, IP6_ADDR_PREFERRED);
    netif_set_up(&loop);
    netif_set_link_up(&loop);

    ip_addr_t v4;
    ip_addr_copy_from_ip4(v4, addr);
    RoundTrip(&loop, v4, v4);

    ip_addr_t v6;
    ip_addr_copy_from_ip6(v6, addr6);
    RoundTrip(&loop, v6, v6);

    netif_remove(&loop);
}

BOOST_AUTO_TEST_SUITE_END()
