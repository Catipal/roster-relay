// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Splitting a block reward among the peers a relay lists.
//
// The arithmetic is small and the consequences are not: this is the mechanism
// design note 001 section 8 rests its whole anti-sybil argument on, so every
// way it can be wrong is a way the argument stops holding. It is a pure
// function precisely so it can be argued with here rather than on a chain.
//

#include <roster/keystore.h>
#include <roster/payout.h>
#include <script/standard.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(rosterpayout_tests, BasicTestingSetup)

namespace {

//! A roster key, as a record would carry it: 32 bytes, x only.
roster::KeyBytes MakeKey()
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    roster::KeyBytes out{};
    std::copy(pubkey.begin() + 1, pubkey.begin() + 33, out.begin());
    return out;
}

std::vector<roster::KeyBytes> MakeKeys(size_t n)
{
    std::vector<roster::KeyBytes> keys;
    for (size_t i = 0; i < n; ++i) keys.push_back(MakeKey());
    return keys;
}

const CAmount DUST = 546;

} // namespace

BOOST_AUTO_TEST_CASE(payout_splits_evenly)
{
    const std::vector<roster::KeyBytes> users = MakeKeys(4);
    std::vector<roster::Payout> out;

    // 20% of 100 coins, four ways.
    const CAmount total = roster::PlanPayouts(100 * COIN, 20, users, DUST, out);

    BOOST_CHECK_EQUAL(out.size(), 4U);
    BOOST_CHECK_EQUAL(total, 20 * COIN);
    for (size_t i = 0; i < out.size(); ++i) {
        BOOST_CHECK_EQUAL(out[i].amount, 5 * COIN);
        BOOST_CHECK(!out[i].script.empty());
    }
}

// The relay keeps what does not divide. Handing it to whichever key sorts first
// would make the split depend on key ordering for no defensible reason.
BOOST_AUTO_TEST_CASE(payout_remainder_stays_with_the_staker)
{
    const std::vector<roster::KeyBytes> users = MakeKeys(3);
    std::vector<roster::Payout> out;

    // 10% of 100 satoshi is 10, which does not divide by 3.
    const CAmount total = roster::PlanPayouts(100, 10, users, 1, out);

    BOOST_CHECK_EQUAL(out.size(), 3U);
    BOOST_CHECK_EQUAL(out[0].amount, 3);
    BOOST_CHECK_EQUAL(total, 9);
    BOOST_CHECK_MESSAGE(total < 10, "the undividable satoshi must not be paid out");
}

// An output below the dust threshold costs more to spend than it carries, so
// paying it is worse for the peer than not paying at all.
BOOST_AUTO_TEST_CASE(payout_refuses_to_pay_dust)
{
    const std::vector<roster::KeyBytes> users = MakeKeys(1000);
    std::vector<roster::Payout> out;

    // A 4.6875 BPS reward shared 1% among a thousand peers is ~4687 satoshi
    // each... which clears dust. Ten percent of a much smaller reward does not.
    const CAmount total = roster::PlanPayouts(10000, 1, users, DUST, out);

    BOOST_CHECK_EQUAL(total, 0);
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_CASE(payout_is_off_unless_asked_for)
{
    const std::vector<roster::KeyBytes> users = MakeKeys(3);
    std::vector<roster::Payout> out;

    BOOST_CHECK_EQUAL(roster::PlanPayouts(100 * COIN, 0, users, DUST, out), 0);
    BOOST_CHECK(out.empty());
    BOOST_CHECK_EQUAL(roster::PlanPayouts(100 * COIN, -5, users, DUST, out), 0);
    BOOST_CHECK(out.empty());
    BOOST_CHECK_EQUAL(roster::DEFAULT_RELAY_SHARE, 0);
}

BOOST_AUTO_TEST_CASE(payout_handles_nobody_and_nothing)
{
    std::vector<roster::Payout> out;
    const std::vector<roster::KeyBytes> none;
    BOOST_CHECK_EQUAL(roster::PlanPayouts(100 * COIN, 50, none, DUST, out), 0);

    const std::vector<roster::KeyBytes> users = MakeKeys(2);
    BOOST_CHECK_EQUAL(roster::PlanPayouts(0, 50, users, DUST, out), 0);
    BOOST_CHECK_EQUAL(roster::PlanPayouts(-1, 50, users, DUST, out), 0);
}

// Sharing everything is legal; sharing more than everything is not a thing a
// percentage can express, and must not become one by arithmetic.
BOOST_AUTO_TEST_CASE(payout_never_exceeds_the_reward)
{
    const std::vector<roster::KeyBytes> users = MakeKeys(7);
    std::vector<roster::Payout> out;

    // 100 coins seven ways: each gets 1428571428, and the four satoshi that do
    // not divide stay with the staker.
    BOOST_CHECK_EQUAL(roster::PlanPayouts(100 * COIN, 100, users, DUST, out), 9999999996);
    BOOST_CHECK(roster::PlanPayouts(100 * COIN, 100, users, DUST, out) <= 100 * COIN);

    // Clamped, not wrapped.
    const CAmount over = roster::PlanPayouts(100 * COIN, 400, users, DUST, out);
    BOOST_CHECK(over <= 100 * COIN);
}

// A key that is not a point on the curve cannot be paid, and must not be
// counted when dividing either - otherwise everyone else is short by its share
// and the relay silently keeps the difference.
BOOST_AUTO_TEST_CASE(payout_skips_keys_that_name_nothing)
{
    std::vector<roster::KeyBytes> users = MakeKeys(3);
    roster::KeyBytes broken{};
    broken.fill(0xff); // above the field prime
    users.push_back(broken);

    std::vector<roster::Payout> out;
    const CAmount total = roster::PlanPayouts(100 * COIN, 20, users, DUST, out);

    BOOST_CHECK_EQUAL(out.size(), 3U);
    BOOST_CHECK_MESSAGE(out[0].amount == 20 * COIN / 3,
                        "the three real peers must divide the pool between them");
    BOOST_CHECK_EQUAL(total, (20 * COIN / 3) * 3);
}

// The address a peer is paid at is the one derived from its published key, so a
// relay can pay a peer it has never spoken to.
BOOST_AUTO_TEST_CASE(payout_pays_the_address_the_listing_names)
{
    const roster::KeyBytes key = MakeKey();
    std::vector<roster::Payout> out;
    roster::PlanPayouts(100 * COIN, 10, {key}, DUST, out);

    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    CPubKey expected;
    BOOST_REQUIRE(roster::StakerPubKeyFromRoster(key, expected));
    BOOST_CHECK(out[0].script == GetScriptForDestination(PKHash(expected)));
}

BOOST_AUTO_TEST_SUITE_END()
