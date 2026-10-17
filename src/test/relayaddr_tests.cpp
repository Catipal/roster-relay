// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <netbase.h>
#include <roster/relayaddr.h>
#include <test/util/setup_common.h>
#include <util/system.h>

#include <boost/test/unit_test.hpp>

#include <cstring>

using namespace roster;

namespace {

const std::string CHAIN = "regtest";
const int64_t NOW = 1800000000;

CKey MakeKey(uint8_t seed)
{
    unsigned char vch[32];
    std::memset(vch, 1, sizeof(vch));
    vch[31] = seed;
    CKey key;
    key.Set(vch, vch + sizeof(vch), true);
    return key;
}

KeyBytes XOnly(const CKey& key)
{
    const CPubKey pk = key.GetPubKey();
    KeyBytes out;
    std::memcpy(out.data(), pk.data() + 1, RECORD_KEY_SIZE);
    return out;
}

Endpoint V4(uint8_t last, uint16_t port = 48930)
{
    Endpoint ep;
    ep.network = EP_IPV4;
    ep.addr = {203, 0, 113, last};
    ep.port = port;
    return ep;
}

Endpoint V6(uint8_t last, uint16_t port = 48930)
{
    Endpoint ep;
    ep.network = EP_IPV6;
    ep.addr = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last};
    ep.port = port;
    return ep;
}

RelayAddress Signed(const CKey& key, int64_t time, std::vector<Endpoint> endpoints, const std::string& chain = CHAIN)
{
    RelayAddress a;
    a.key = XOnly(key);
    a.time = time;
    a.endpoints = std::move(endpoints);
    BOOST_REQUIRE(SignRelayAddress(a, key, chain));
    return a;
}

std::vector<unsigned char> Raw(const CKey& key, int64_t time, std::vector<Endpoint> endpoints)
{
    return SerializeRelayAddress(Signed(key, time, std::move(endpoints)));
}

const RelayAddressBook::RelayCheck ANY_RELAY = [](const KeyBytes&) { return true; };

CNetAddr Ip(const std::string& s)
{
    CNetAddr out;
    BOOST_REQUIRE(LookupHost(s, out, false));
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(relayaddr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signed_round_trip)
{
    const CKey key = MakeKey(1);
    const RelayAddress a = Signed(key, NOW, {V4(7), V6(9)});
    const std::vector<unsigned char> raw = SerializeRelayAddress(a);
    BOOST_CHECK_EQUAL(raw.size(), MAX_RELAY_ADDR_SIZE - 12); // one IPv4 in place of an IPv6

    RelayAddress b;
    BOOST_REQUIRE(ParseRelayAddress(raw, b));
    BOOST_CHECK(b.key == a.key);
    BOOST_CHECK_EQUAL(b.time, NOW);
    BOOST_REQUIRE_EQUAL(b.endpoints.size(), 2U);
    BOOST_CHECK(b.endpoints[0] == V4(7));
    BOOST_CHECK(b.endpoints[1] == V6(9));
    BOOST_CHECK(VerifyRelayAddress(b, CHAIN));

    // Another chain's announcement, or one changed on the way, does not verify.
    BOOST_CHECK(!VerifyRelayAddress(b, "main"));
    RelayAddress moved = b;
    moved.endpoints[0].port = 48931;
    BOOST_CHECK(!VerifyRelayAddress(moved, CHAIN));
    RelayAddress later = b;
    later.time += 1;
    BOOST_CHECK(!VerifyRelayAddress(later, CHAIN));

    // Signed only by the key it names.
    RelayAddress other;
    other.key = XOnly(MakeKey(2));
    other.time = NOW;
    other.endpoints = {V4(7)};
    BOOST_CHECK(!SignRelayAddress(other, key, CHAIN));
}

BOOST_AUTO_TEST_CASE(parse_refuses_what_it_cannot_carry)
{
    const CKey key = MakeKey(1);
    const std::vector<unsigned char> good = Raw(key, NOW, {V4(7)});
    RelayAddress out;
    BOOST_CHECK(ParseRelayAddress(good, out));

    std::vector<unsigned char> bad = good;
    bad[0] = 2; // unknown version
    BOOST_CHECK(!ParseRelayAddress(bad, out));

    bad = good;
    bad.push_back(0); // a byte the signature would not cover
    BOOST_CHECK(!ParseRelayAddress(bad, out));

    bad = good;
    bad.pop_back();
    BOOST_CHECK(!ParseRelayAddress(bad, out));

    // No address, or more than one of each family.
    RelayAddress none;
    none.key = XOnly(key);
    none.time = NOW;
    BOOST_CHECK(!ParseRelayAddress(SerializeRelayAddress(none), out));
    RelayAddress three = Signed(key, NOW, {V4(1), V6(2)});
    three.endpoints.push_back(V4(3));
    BOOST_CHECK(!ParseRelayAddress(SerializeRelayAddress(three), out));

    // Only networks that carry the overlay's datagrams, and a real port.
    RelayAddress onion;
    onion.key = XOnly(key);
    onion.time = NOW;
    Endpoint ep;
    ep.network = EP_TORV3;
    ep.addr.assign(ADDR_SIZE_TORV3, 0x42);
    ep.port = 9050;
    onion.endpoints = {ep};
    BOOST_CHECK(!ParseRelayAddress(SerializeRelayAddress(onion), out));
    RelayAddress portless;
    portless.key = XOnly(key);
    portless.time = NOW;
    portless.endpoints = {V4(7, 0)};
    BOOST_CHECK(!ParseRelayAddress(SerializeRelayAddress(portless), out));
}

BOOST_AUTO_TEST_CASE(book_keeps_the_newest)
{
    const CKey key = MakeKey(1);
    RelayAddressBook book(CHAIN);
    const uint64_t g0 = book.Generation();

    const std::vector<unsigned char> first = Raw(key, NOW, {V4(7)});
    BOOST_CHECK(book.Add(first, NOW, ANY_RELAY) == RelayAddressBook::AddResult::NEW);
    BOOST_CHECK(book.Add(first, NOW, ANY_RELAY) == RelayAddressBook::AddResult::KNOWN);
    BOOST_CHECK(book.Generation() != g0);

    // Too soon after the last is not taken, so a relay cannot make everyone
    // pass on one a second.
    const std::vector<unsigned char> soon = Raw(key, NOW + RELAY_ADDR_MIN_INTERVAL - 1, {V4(8)});
    BOOST_CHECK(book.Add(soon, NOW + RELAY_ADDR_MIN_INTERVAL - 1, ANY_RELAY) == RelayAddressBook::AddResult::KNOWN);

    const int64_t later = NOW + RELAY_ADDR_MIN_INTERVAL;
    const std::vector<unsigned char> moved = Raw(key, later, {V4(8)});
    const uint64_t g1 = book.Generation();
    BOOST_CHECK(book.Add(moved, later, ANY_RELAY) == RelayAddressBook::AddResult::NEW);
    BOOST_CHECK(book.Generation() != g1);
    RelayAddress current;
    BOOST_REQUIRE(book.Current(XOnly(key), later, current));
    BOOST_CHECK(current.endpoints[0] == V4(8));

    // The older one, arriving late, changes nothing.
    BOOST_CHECK(book.Add(first, later, ANY_RELAY) == RelayAddressBook::AddResult::KNOWN);
    BOOST_REQUIRE(book.Current(XOnly(key), later, current));
    BOOST_CHECK(current.endpoints[0] == V4(8));
    BOOST_CHECK_EQUAL(book.Size(), 1U);
}

BOOST_AUTO_TEST_CASE(book_counts_for_three_hours)
{
    const CKey a = MakeKey(1), b = MakeKey(2);
    RelayAddressBook book(CHAIN);

    // Signed too far ahead of this clock, or too long ago: a difference of
    // clocks, not of honesty.
    BOOST_CHECK(book.Add(Raw(a, NOW + RELAY_ADDR_FUTURE + 1, {V4(7)}), NOW, ANY_RELAY) == RelayAddressBook::AddResult::STALE);
    BOOST_CHECK(book.Add(Raw(a, NOW - RELAY_ADDR_TTL, {V4(7)}), NOW, ANY_RELAY) == RelayAddressBook::AddResult::STALE);
    BOOST_CHECK(book.Add(Raw(a, NOW + RELAY_ADDR_FUTURE, {V4(7)}), NOW, ANY_RELAY) == RelayAddressBook::AddResult::NEW);

    BOOST_CHECK(book.Add(Raw(b, NOW - 60, {V4(9)}), NOW, ANY_RELAY) == RelayAddressBook::AddResult::NEW);
    // Newest first, at most as many as asked for.
    std::vector<std::vector<unsigned char>> fresh = book.FreshRaw(NOW, 10);
    BOOST_REQUIRE_EQUAL(fresh.size(), 2U);
    RelayAddress first;
    BOOST_REQUIRE(ParseRelayAddress(fresh[0], first));
    BOOST_CHECK(first.key == XOnly(a));
    BOOST_CHECK_EQUAL(book.FreshRaw(NOW, 1).size(), 1U);

    // b stops counting three hours after it signed; a, signed later, not yet.
    const int64_t after = NOW - 60 + RELAY_ADDR_TTL;
    RelayAddress out;
    BOOST_CHECK(!book.Current(XOnly(b), after, out));
    BOOST_CHECK(book.Current(XOnly(a), after, out));
    BOOST_CHECK_EQUAL(book.FreshRaw(after, 10).size(), 1U);
    const uint64_t g = book.Generation();
    book.Expire(after);
    BOOST_CHECK_EQUAL(book.Size(), 1U);
    BOOST_CHECK(book.Generation() != g);
}

BOOST_AUTO_TEST_CASE(book_takes_listed_relays_only)
{
    const CKey relay = MakeKey(1), stranger = MakeKey(2);
    const KeyBytes listed = XOnly(relay);
    const RelayAddressBook::RelayCheck only_listed = [&listed](const KeyBytes& k) { return k == listed; };
    RelayAddressBook book(CHAIN);

    BOOST_CHECK(book.Add(Raw(stranger, NOW, {V4(7)}), NOW, only_listed) == RelayAddressBook::AddResult::NOT_RELAY);
    BOOST_CHECK(book.Add(Raw(relay, NOW, {V4(7)}), NOW, only_listed) == RelayAddressBook::AddResult::NEW);
    BOOST_CHECK_EQUAL(book.Size(), 1U);

    // Signed for another chain, or garbled: the sender's fault.
    RelayAddressBook main_book("main");
    BOOST_CHECK(main_book.Add(Raw(relay, NOW, {V4(7)}), NOW, ANY_RELAY) == RelayAddressBook::AddResult::INVALID);
    std::vector<unsigned char> garbled = Raw(relay, NOW + RELAY_ADDR_MIN_INTERVAL, {V4(7)});
    garbled[50] ^= 1;
    BOOST_CHECK(book.Add(garbled, NOW + RELAY_ADDR_MIN_INTERVAL, ANY_RELAY) == RelayAddressBook::AddResult::INVALID);
    BOOST_CHECK(book.Add(std::vector<unsigned char>(MAX_RELAY_ADDR_SIZE + 1, 1), NOW, ANY_RELAY) ==
                RelayAddressBook::AddResult::INVALID);
}

BOOST_AUTO_TEST_CASE(when_a_relay_announces)
{
    const CKey key = MakeKey(1);
    const RelayAddress last = Signed(key, NOW, {V4(7)});

    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(7)}, nullptr, NOW), NOW);
    BOOST_CHECK_EQUAL(NextAnnouncementTime({}, nullptr, NOW), 0);
    // Unchanged: only when it is due again.
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(7)}, &last, NOW + RELAY_ADDR_REFRESH - 1), 0);
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(7)}, &last, NOW + RELAY_ADDR_REFRESH), NOW + RELAY_ADDR_REFRESH);
    // Changed: at once, dated where the network takes it.
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(8)}, &last, NOW + 1), NOW + RELAY_ADDR_MIN_INTERVAL);
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(8)}, &last, NOW + RELAY_ADDR_MIN_INTERVAL + 9), NOW + RELAY_ADDR_MIN_INTERVAL + 9);
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(7), V6(1)}, &last, NOW), NOW + RELAY_ADDR_MIN_INTERVAL);
    // ...but never so far ahead the network would refuse it: one already
    // dated ahead makes the next wait.
    const RelayAddress ahead = Signed(key, NOW + RELAY_ADDR_MIN_INTERVAL, {V4(8)});
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(9)}, &ahead, NOW), 0);
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(9)}, &ahead, NOW + 60), NOW + 2 * RELAY_ADDR_MIN_INTERVAL);
    // Expired counts as none.
    BOOST_CHECK_EQUAL(NextAnnouncementTime({V4(7)}, &last, NOW + RELAY_ADDR_TTL), NOW + RELAY_ADDR_TTL);

    // Taken by the network as dated: a changed address goes round at once.
    RelayAddressBook book(CHAIN);
    BOOST_CHECK(book.Add(SerializeRelayAddress(last), NOW, ANY_RELAY) == RelayAddressBook::AddResult::NEW);
    const int64_t at = NextAnnouncementTime({V4(8)}, &last, NOW + 1);
    BOOST_CHECK(book.Add(Raw(key, at, {V4(8)}), NOW + 1, ANY_RELAY) == RelayAddressBook::AddResult::NEW);
}

BOOST_AUTO_TEST_CASE(own_announcement_survives_a_restart)
{
    const CKey key = MakeKey(1);
    const fs::path path = GetDataDir() / "relay_address.dat";
    const std::vector<unsigned char> raw = Raw(key, NOW, {V4(7), V6(9)});
    RelayAddress out;
    std::vector<unsigned char> raw_out;
    BOOST_CHECK(!ReadOwnRelayAddress(path, CHAIN, out, raw_out));
    BOOST_REQUIRE(WriteOwnRelayAddress(path, raw));
    BOOST_REQUIRE(ReadOwnRelayAddress(path, CHAIN, out, raw_out));
    BOOST_CHECK(raw_out == raw);
    BOOST_CHECK_EQUAL(out.time, NOW);
    // Another chain's, or a damaged file, is not taken.
    BOOST_CHECK(!ReadOwnRelayAddress(path, "main", out, raw_out));
    std::vector<unsigned char> damaged = raw;
    damaged[45] ^= 1;
    BOOST_REQUIRE(WriteOwnRelayAddress(path, damaged));
    BOOST_CHECK(!ReadOwnRelayAddress(path, CHAIN, out, raw_out));
}

BOOST_AUTO_TEST_CASE(which_address_a_relay_announces)
{
    // Public addresses: the documentation ranges are not routable.
    const uint16_t port = 48930;
    const std::vector<unsigned char> A = {5, 6, 7, 8}, B = {5, 6, 7, 9}, C = {9, 9, 9, 1}, F = {80, 81, 82, 83};
    std::vector<Endpoint> out;

    // Told to: that, and nothing it sees.
    CService fixed;
    BOOST_REQUIRE(Lookup("80.81.82.83", fixed, port, false));
    out = ChooseRelayEndpoints({fixed}, {Ip("5.6.7.8"), Ip("5.6.7.8")}, {}, port, false);
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK(out[0].addr == F);
    BOOST_CHECK_EQUAL(out[0].port, port);

    // What most outbound peers see, when at least two agree.
    out = ChooseRelayEndpoints({}, {Ip("5.6.7.8"), Ip("5.6.7.8"), Ip("5.6.7.9")}, {}, port, false);
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK(out[0].addr == A);
    BOOST_CHECK(ChooseRelayEndpoints({}, {Ip("5.6.7.8")}, {}, port, false).empty());
    BOOST_CHECK(ChooseRelayEndpoints({}, {Ip("5.6.7.8"), Ip("5.6.7.8"), Ip("5.6.7.9"), Ip("9.9.9.1")},
                                     {}, port, false).empty());

    // A family the peers do not settle comes from what the node knows of itself.
    out = ChooseRelayEndpoints({}, {Ip("5.6.7.9"), Ip("5.6.7.9")}, {Ip("9.9.9.1"), Ip("2a01:4f8::5")}, port, false);
    BOOST_REQUIRE_EQUAL(out.size(), 2U);
    BOOST_CHECK(out[0].addr == B);
    BOOST_CHECK_EQUAL(out[1].network, EP_IPV6);
    BOOST_CHECK_EQUAL(out[1].addr[15], 5);
    out = ChooseRelayEndpoints({}, {}, {Ip("9.9.9.1")}, port, false);
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK(out[0].addr == C);

    // Never a private address, except on regtest.
    BOOST_CHECK(ChooseRelayEndpoints({}, {}, {Ip("192.168.1.4"), Ip("127.0.0.1")}, port, false).empty());
    out = ChooseRelayEndpoints({}, {}, {Ip("127.0.0.1")}, port, true);
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK(out[0].addr == std::vector<unsigned char>({127, 0, 0, 1}));
}

BOOST_AUTO_TEST_SUITE_END()
