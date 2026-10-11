// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netbase.h>
#include <overlay/radio.h>
#include <overlay/select.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

using namespace overlay;

BOOST_FIXTURE_TEST_SUITE(radio_tests, BasicTestingSetup)

namespace {

roster::KeyBytes Key(unsigned char fill)
{
    roster::KeyBytes k;
    k.fill(fill);
    return k;
}

std::string PeersJson(int64_t updated, int64_t heard, const std::string& key_hex, int port)
{
    return strprintf(R"({"version": 1, "network": "main", "destination": "00112233445566778899aabbccddeeff",
        "updated": %d, "interfaces": ["RNodeInterface[LoRa 868]"],
        "peers": [{"key": "%s", "port": %d, "destination": "ffeeddccbbaa99887766554433221100",
                   "hops": 1, "heard": %d, "link": false}]})",
        updated, key_hex, port, heard);
}

} // namespace

BOOST_AUTO_TEST_CASE(what_the_bridge_writes_is_read)
{
    RadioState state;
    std::string error;
    BOOST_REQUIRE(ParseRadioPeers(PeersJson(1000, 990, HexStr(Key(7)), 40001), state, error));
    BOOST_CHECK(state.bridge_seen);
    BOOST_CHECK_EQUAL(state.updated, 1000);
    BOOST_CHECK_EQUAL(state.network, "main");
    BOOST_REQUIRE_EQUAL(state.interfaces.size(), 1U);
    BOOST_REQUIRE_EQUAL(state.peers.size(), 1U);
    const RadioPeer& p = state.peers[0];
    BOOST_CHECK(p.has_key);
    BOOST_CHECK(p.key == Key(7));
    // A neighbour is only ever a port on this computer.
    BOOST_CHECK_EQUAL(p.local.ToString(), "127.0.0.1:40001");
    BOOST_CHECK_EQUAL(p.hops, 1);
    BOOST_CHECK_EQUAL(p.heard, 990);

    // A port out of range, or a key that is not 32 bytes, is not a usable peer.
    BOOST_REQUIRE(ParseRadioPeers(PeersJson(1000, 990, HexStr(Key(7)), 70000), state, error));
    BOOST_CHECK(state.peers.empty());
    BOOST_REQUIRE(ParseRadioPeers(PeersJson(1000, 990, "abcd", 40001), state, error));
    BOOST_REQUIRE_EQUAL(state.peers.size(), 1U);
    BOOST_CHECK(!state.peers[0].has_key);

    BOOST_CHECK(!ParseRadioPeers("not json", state, error));
    BOOST_CHECK(!ParseRadioPeers(R"({"version": 2, "peers": []})", state, error));
}

BOOST_AUTO_TEST_CASE(neighbours_are_those_heard_lately_through_a_live_bridge)
{
    const fs::path dir = GetDataDir() / "radio";
    Radio radio(dir, "main");
    std::string error;
    BOOST_REQUIRE(radio.WriteNodeInfo(48931, Key(1), error));
    BOOST_CHECK(fs::exists(dir / "node.json"));

    const int64_t now = 1700000000;
    radio.Refresh();
    BOOST_CHECK(!radio.BridgeAlive(now));
    BOOST_CHECK(radio.Neighbours(now).empty());

    {
        std::ofstream f((dir / "peers.json").string());
        f << PeersJson(now - 5, now - 100, HexStr(Key(7)), 40001);
    }
    radio.Refresh();
    BOOST_CHECK(radio.BridgeAlive(now));
    BOOST_REQUIRE_EQUAL(radio.Neighbours(now).size(), 1U);
    CService at;
    BOOST_REQUIRE(radio.AddressFor(Key(7), now, at));
    BOOST_CHECK_EQUAL(at.ToString(), "127.0.0.1:40001");
    BOOST_CHECK(radio.IsRadioAddress(at));
    BOOST_CHECK(!radio.AddressFor(Key(8), now, at));

    // Not heard for longer than the announces come: no longer used.
    BOOST_CHECK(radio.Neighbours(now - 100 + RADIO_PEER_TTL + 1).empty());
    // A bridge that has stopped writing is gone, and its neighbours with it.
    BOOST_CHECK(!radio.BridgeAlive(now + RADIO_BRIDGE_TIMEOUT + 10));
    BOOST_CHECK(radio.Neighbours(now + RADIO_BRIDGE_TIMEOUT + 10).empty());

    // A bridge running for another network is ignored.
    Radio other(dir, "test");
    other.Refresh();
    BOOST_CHECK(other.Neighbours(now).empty());
}

BOOST_AUTO_TEST_CASE(waits_follow_the_radio_speed)
{
    const fs::path dir = GetDataDir() / "radio";
    fs::create_directories(dir);
    g_radio = MakeUnique<Radio>(dir, "main");
    const int64_t now = 1700000000;
    {
        // LoRa at SF8 next door; SF12 behind a repeater; an older bridge that reports no speed.
        std::ofstream f((dir / "peers.json").string());
        f << strprintf(R"({"version": 1, "network": "main", "updated": %d, "peers": [
            {"key": "%s", "port": 40001, "hops": 1, "heard": %d, "link": true, "bitrate": 3125},
            {"key": "%s", "port": 40002, "hops": 2, "heard": %d, "link": true, "bitrate": 293},
            {"key": "%s", "port": 40003, "hops": 1, "heard": %d, "link": true}]})",
            now, HexStr(Key(1)), now, HexStr(Key(2)), now, HexStr(Key(3)), now);
    }
    g_radio->Refresh();
    const CService next_door(LookupNumeric("127.0.0.1", 40001)), via_repeater(LookupNumeric("127.0.0.1", 40002)),
        unreported(LookupNumeric("127.0.0.1", 40003)), internet(LookupNumeric("192.0.2.1", 8346));
    BOOST_REQUIRE_EQUAL(g_radio->State().peers.size(), 3U);
    BOOST_CHECK_EQUAL(g_radio->State().peers[0].bitrate, 3125);
    BOOST_CHECK_EQUAL(g_radio->RateTo(next_door), 3125);
    // Each hop sends on the same channel, so two share it.
    BOOST_CHECK_EQUAL(g_radio->RateTo(via_repeater), 146);
    BOOST_CHECK_EQUAL(g_radio->RateTo(unreported), RADIO_DEFAULT_BITRATE);
    BOOST_CHECK_EQUAL(g_radio->RateTo(internet), 0);

    // A full datagram, framing counted: 1200 B x 8 x 1.5 at 3125 bit/s.
    BOOST_CHECK_EQUAL(RadioAirtime(next_door, 1200).count(), 4608);
    BOOST_CHECK_EQUAL(RadioAirtime(via_repeater, 1200).count(), 98630);
    // Nothing added off the radio.
    BOOST_CHECK_EQUAL(RadioAirtime(internet, 1200).count(), 0);
    BOOST_CHECK(RadioStepTimeout(next_door) == RADIO_STEP_TIMEOUT + 6 * std::chrono::milliseconds{4608});
    BOOST_CHECK(RadioStepTimeout(via_repeater) > RadioStepTimeout(next_door));
    g_radio.reset();
    BOOST_CHECK_EQUAL(RadioAirtime(next_door, 1200).count(), 0);
}

BOOST_AUTO_TEST_CASE(a_relay_reaches_the_next_hop_over_radio_only_when_it_must)
{
    const fs::path dir = GetDataDir() / "radio";
    fs::create_directories(dir);
    g_radio = MakeUnique<Radio>(dir, "main");
    const int64_t now = GetTime();
    {
        std::ofstream f((dir / "peers.json").string());
        f << strprintf(R"({"version": 1, "network": "main", "updated": %d, "peers": [
            {"key": "%s", "port": 40001, "hops": 1, "heard": %d, "link": true, "bitrate": 3125}]})",
            now, HexStr(Key(1)), now);
    }
    g_radio->Refresh();

    const CService radio_local(LookupNumeric("127.0.0.1", 40001));
    const CService on_internet(LookupNumeric("8.8.8.8", 48931));   // routable and reachable
    const CService unreachable(LookupNumeric("10.0.0.1", 48931));  // private, not routable
    bool slow = true;

    // A relay reachable at its listed address is reached there, not over radio.
    BOOST_CHECK(NextHopForRelay(Key(1), on_internet, slow) == on_internet);
    BOOST_CHECK(!slow);

    // One with no route from here, but heard on the radio, is reached over it.
    BOOST_CHECK(NextHopForRelay(Key(1), unreachable, slow) == radio_local);
    BOOST_CHECK(slow);

    // One with no route and not a radio neighbour stays at its listed address:
    // there is nothing better to do, and the dial simply fails.
    slow = true;
    BOOST_CHECK(NextHopForRelay(Key(2), unreachable, slow) == unreachable);
    BOOST_CHECK(!slow);

    // With no radio at all, the listed address is used unchanged.
    g_radio.reset();
    BOOST_CHECK(NextHopForRelay(Key(1), unreachable, slow) == unreachable);
    BOOST_CHECK(!slow);
}

BOOST_AUTO_TEST_CASE(a_radio_neighbour_that_is_a_listed_relay_is_the_entry)
{
    PathSelector selector(2, /* local_relays */ true);
    std::vector<RelayCandidate> relays;
    for (unsigned char i = 1; i <= 6; ++i) {
        RelayCandidate c;
        c.key = Key(i);
        c.addr = CService(LookupNumeric("127.0.0.1", 40000 + i));
        relays.push_back(c);
    }
    selector.SetRelays(relays);
    std::vector<RelayCandidate> out;

    // Not listed: no effect.
    selector.SetPreferredEntries({Key(9)});
    BOOST_REQUIRE(selector.Select(3, out));
    BOOST_CHECK(!(out[0].key == Key(9)));

    selector.SetPreferredEntries({Key(5)});
    for (int i = 0; i < 20; ++i) {
        BOOST_REQUIRE(selector.Select(3, out));
        BOOST_CHECK(out[0].key == Key(5));
        // Not used twice on one path.
        BOOST_CHECK(!(out[1].key == Key(5)) && !(out[2].key == Key(5)));
    }

    // When the neighbour is the destination, the guards serve as before.
    RelayCandidate dest = relays[4];
    BOOST_REQUIRE(selector.Select(2, out, dest));
    BOOST_CHECK(!(out[0].key == Key(5)));

    selector.SetPreferredEntries({});
    bool other = false;
    for (int i = 0; i < 20; ++i) {
        BOOST_REQUIRE(selector.Select(1, out));
        if (!(out[0].key == Key(5))) other = true;
    }
    BOOST_CHECK(other || selector.Guards().size() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
