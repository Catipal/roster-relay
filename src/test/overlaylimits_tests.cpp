// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/frame.h>
#include <overlay/limits.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using overlay::TrafficLimits;

BOOST_FIXTURE_TEST_SUITE(overlaylimits_tests, BasicTestingSetup)

//! With nothing configured, nothing is limited: the defaults come from init,
//! and a relay built without them must carry everything as before.
BOOST_AUTO_TEST_CASE(unlimited_by_default)
{
    TrafficLimits limits;
    for (int i = 0; i < 10000; ++i) BOOST_CHECK(limits.Forward(1, 1200, 0));
    BOOST_CHECK(limits.AdmitPath(0));
    const TrafficLimits::Stats s = limits.GetStats(0);
    BOOST_CHECK_EQUAL(s.today, 10000U * 1200U);
    BOOST_CHECK(s.accepting);
}

//! A path gets a second's worth at once and the rate after that; another path
//! has its own allowance.
BOOST_AUTO_TEST_CASE(rate_per_path)
{
    TrafficLimits limits;
    limits.Configure(0, 10000);
    for (int i = 0; i < 10; ++i) BOOST_CHECK(limits.Forward(7, 1000, 0));
    BOOST_CHECK(!limits.Forward(7, 1000, 0));
    // Another path is not held back by the first.
    BOOST_CHECK(limits.Forward(8, 1000, 0));
    // A tenth of a second later, a tenth of the rate has come back.
    BOOST_CHECK(limits.Forward(7, 1000, 100));
    BOOST_CHECK(!limits.Forward(7, 1000, 100));
    // Never more than a second's worth, however long it sat idle.
    for (int i = 0; i < 10; ++i) BOOST_CHECK(limits.Forward(7, 1000, 60 * 60 * 1000));
    BOOST_CHECK(!limits.Forward(7, 1000, 60 * 60 * 1000));

    const TrafficLimits::Stats s = limits.GetStats(60 * 60 * 1000);
    BOOST_CHECK_EQUAL(s.dropped_rate, 3U);
    BOOST_CHECK_EQUAL(s.path_rate, 10000U);
}

//! A cap below a few datagrams a second still lets whole datagrams through
//! rather than refusing every one of them.
BOOST_AUTO_TEST_CASE(low_rate_still_passes_datagrams)
{
    TrafficLimits limits;
    limits.Configure(0, 100);
    for (int i = 0; i < 4; ++i) BOOST_CHECK(limits.Forward(1, overlay::SAFE_DATAGRAM, 0));
    BOOST_CHECK(!limits.Forward(1, overlay::SAFE_DATAGRAM, 0));
    // And refills at the rate it was given: 100 bytes a second.
    BOOST_CHECK(!limits.Forward(1, overlay::SAFE_DATAGRAM, 11 * 1000));
    BOOST_CHECK(limits.Forward(1, overlay::SAFE_DATAGRAM, 13 * 1000));
}

//! Once the day's budget is spent no new path is admitted; open ones run a
//! tenth over and then stop; the next UTC day starts afresh.
BOOST_AUTO_TEST_CASE(daily_budget)
{
    TrafficLimits limits;
    limits.Configure(10000, 0);
    const int64_t noon = 3 * TrafficLimits::DAY_MS + TrafficLimits::DAY_MS / 2;

    for (int i = 0; i < 10; ++i) BOOST_CHECK(limits.Forward(1, 1000, noon));
    BOOST_CHECK(!limits.AdmitPath(noon));
    BOOST_CHECK(!limits.GetStats(noon).accepting);
    // The overrun: a tenth more, then nothing.
    BOOST_CHECK(limits.Forward(1, 1000, noon));
    BOOST_CHECK(!limits.Forward(1, 1000, noon));
    BOOST_CHECK(!limits.Forward(2, 1, noon));

    TrafficLimits::Stats s = limits.GetStats(noon);
    BOOST_CHECK_EQUAL(s.today, 11000U);
    BOOST_CHECK_EQUAL(s.refused_paths, 1U);
    BOOST_CHECK_EQUAL(s.dropped_budget, 2U);
    BOOST_CHECK_EQUAL(s.daily_budget, 10000U);

    // A millisecond before midnight it is still the same day.
    const int64_t midnight = 4 * TrafficLimits::DAY_MS;
    BOOST_CHECK(!limits.AdmitPath(midnight - 1));
    // Then everything starts again.
    BOOST_CHECK(limits.AdmitPath(midnight));
    BOOST_CHECK(limits.Forward(1, 1000, midnight));
    s = limits.GetStats(midnight);
    BOOST_CHECK_EQUAL(s.today, 1000U);
    BOOST_CHECK_EQUAL(s.refused_paths, 0U);
    BOOST_CHECK_EQUAL(s.dropped_budget, 0U);
    BOOST_CHECK(s.accepting);
}

//! Both at once: a datagram dropped for its rate does not count against the day.
BOOST_AUTO_TEST_CASE(rate_drops_do_not_spend_the_budget)
{
    TrafficLimits limits;
    limits.Configure(1 << 20, 5000);
    for (int i = 0; i < 5; ++i) BOOST_CHECK(limits.Forward(1, 1000, 0));
    for (int i = 0; i < 100; ++i) BOOST_CHECK(!limits.Forward(1, 1000, 0));
    BOOST_CHECK_EQUAL(limits.GetStats(0).today, 5000U);
}

//! More paths than the table holds: the stalest buckets are forgotten, which
//! costs those paths no more than a fresh second's allowance.
BOOST_AUTO_TEST_CASE(many_paths_stay_bounded)
{
    TrafficLimits limits;
    limits.Configure(0, 2000);
    const uint64_t paths = TrafficLimits::MAX_BUCKETS + 500;
    for (uint64_t p = 0; p < paths; ++p) {
        BOOST_CHECK(limits.Forward(p, 1000, (int64_t)p));
    }
    // A path forgotten long ago comes back with a full allowance.
    BOOST_CHECK(limits.Forward(0, 1000, (int64_t)paths + TrafficLimits::BUCKET_IDLE_MS + 1));
}

//! Changing the limits takes effect at once.
BOOST_AUTO_TEST_CASE(reconfigure)
{
    TrafficLimits limits;
    limits.Configure(0, 10000);
    for (int i = 0; i < 10; ++i) BOOST_CHECK(limits.Forward(1, 1000, 0));
    BOOST_CHECK(!limits.Forward(1, 1000, 0));
    limits.Configure(0, 0);
    BOOST_CHECK(limits.Forward(1, 1000, 0));
}

BOOST_AUTO_TEST_SUITE_END()
