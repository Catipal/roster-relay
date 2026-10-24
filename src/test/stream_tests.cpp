// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/stream.h>

#include <random.h>
#include <test/util/setup_common.h>

#include <map>

#include <boost/test/unit_test.hpp>

namespace {

/** Two ends of a path that loses, delays, reorders and repeats datagrams. */
struct Link {
    double loss{0};
    double dup{0};
    int64_t delay{30};   //!< ms one way, at least
    int64_t jitter{0};   //!< ms more, at random, which reorders
    bool cut{false};     //!< nothing gets through either way
    bool cut_to_b{false};
    //! Like a relay's per-path cap: bytes a second for both ways together,
    //! counted with the layers around each cell; what goes over is dropped.
    double cap{0};
    double overhead{1.5};
    double bucket{0};
    int64_t bucket_at{0};
    int dropped{0};
    FastRandomContext rng{true};
    std::multimap<int64_t, std::pair<int, std::vector<unsigned char>>> wire;

    void Send(int to, const std::vector<unsigned char>& msg, int64_t now)
    {
        if (cut || (to == 1 && cut_to_b)) return;
        if (cap > 0) {
            bucket = std::min(cap, bucket + (double)(now - bucket_at) * cap / 1000.0);
            bucket_at = now;
            const double cost = (double)msg.size() * overhead;
            if (bucket < cost) {
                ++dropped;
                return;
            }
            bucket -= cost;
        }
        if (rng.randrange(1000000) < loss * 1000000) return;
        const int64_t at = now + delay + (jitter > 0 ? (int64_t)rng.randrange(jitter) : 0);
        wire.emplace(at, std::make_pair(to, msg));
        if (rng.randrange(1000000) < dup * 1000000) wire.emplace(at + 7, std::make_pair(to, msg));
    }
};

/** One end: a stream, what it still has to write, and what it has read. */
struct End {
    overlay::ReliableStream stream;
    std::vector<unsigned char> to_send;
    size_t sent{0};
    std::vector<unsigned char> got;
    bool reading{true};
    bool closing{true}; //!< shut down once everything is written
    explicit End(uint32_t id) : stream(id) {}

    void App()
    {
        if (sent < to_send.size()) sent += stream.Write(to_send.data() + sent, to_send.size() - sent);
        if (sent == to_send.size() && closing) stream.Shutdown();
        if (reading) {
            const std::vector<unsigned char> part = stream.Read(64 * 1024);
            got.insert(got.end(), part.begin(), part.end());
        }
    }
};

std::vector<unsigned char> Pattern(size_t n, unsigned char seed)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = (unsigned char)((i * 131 + seed) ^ (i >> 9));
    return v;
}

/** Run both ends until both are finished or one is dead, or `limit_ms` passes. Returns the time taken. */
int64_t Run(End& a, End& b, Link& link, int64_t limit_ms, const std::function<void(int64_t)>& hook = {})
{
    int64_t now = 0;
    for (; now < limit_ms; now += 5) {
        if (hook) hook(now);
        while (!link.wire.empty() && link.wire.begin()->first <= now) {
            const auto item = link.wire.begin()->second;
            link.wire.erase(link.wire.begin());
            (item.first == 0 ? a : b).stream.Receive(item.second, now);
        }
        a.App();
        b.App();
        for (const auto& m : a.stream.Poll(now)) link.Send(1, m, now);
        for (const auto& m : b.stream.Poll(now)) link.Send(0, m, now);
        if ((a.stream.Finished() && b.stream.Finished()) || a.stream.Dead() || b.stream.Dead()) break;
    }
    return now;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(stream_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cells_fit_a_path_datagram)
{
    overlay::ReliableStream s(7);
    const std::vector<unsigned char> data = Pattern(3 * overlay::STREAM_CELL, 1);
    BOOST_CHECK_EQUAL(s.Write(data.data(), data.size()), data.size());
    for (const auto& m : s.Poll(0)) {
        BOOST_CHECK(m.size() <= overlay::MAX_PATH_APP_PAYLOAD);
        uint32_t id = 0;
        BOOST_CHECK(overlay::ServiceStreamId(m, id));
        BOOST_CHECK_EQUAL(id, 7U);
    }
}

BOOST_AUTO_TEST_CASE(both_ways_on_a_clean_path)
{
    End a(1), b(1);
    a.to_send = Pattern(300 * 1024, 2);
    b.to_send = Pattern(120 * 1024, 3);
    Link link;
    const int64_t took = Run(a, b, link, 600000);
    BOOST_CHECK(a.stream.Finished());
    BOOST_CHECK(b.stream.Finished());
    BOOST_CHECK(b.got == a.to_send);
    BOOST_CHECK(a.got == b.to_send);
    // The pace starts at 16 KiB/s and climbs to 48 KiB/s as cells are
    // acknowledged: some fifteen seconds for 300 KiB.
    BOOST_CHECK_MESSAGE(took < 20000, "took " << took << " ms");
}

BOOST_AUTO_TEST_CASE(a_path_that_loses_reorders_and_repeats)
{
    End a(2), b(2);
    a.to_send = Pattern(200 * 1024, 4);
    b.to_send = Pattern(64 * 1024, 5);
    Link link;
    link.loss = 0.10;
    link.dup = 0.03;
    link.delay = 150;
    link.jitter = 200;
    const int64_t took = Run(a, b, link, 600000);
    BOOST_CHECK(a.stream.Finished());
    BOOST_CHECK(b.stream.Finished());
    BOOST_CHECK(b.got == a.to_send);
    BOOST_CHECK(a.got == b.to_send);
    BOOST_CHECK_MESSAGE(took < 120000, "took " << took << " ms");
}

BOOST_AUTO_TEST_CASE(a_path_with_a_relays_cap)
{
    // Both ways at once through a cap of 64 KiB/s that counts the layers
    // around each cell: each way finds the pace that fits instead of
    // overrunning the cap and waiting out timeouts.
    End a(5), b(5);
    a.to_send = Pattern(200 * 1024, 9);
    b.to_send = Pattern(200 * 1024, 10);
    Link link;
    link.cap = 64 * 1024;
    link.delay = 40;
    const int64_t took = Run(a, b, link, 600000);
    BOOST_CHECK(a.stream.Finished());
    BOOST_CHECK(b.stream.Finished());
    BOOST_CHECK(b.got == a.to_send);
    BOOST_CHECK(a.got == b.to_send);
    // 400 KiB through a 64 KiB/s cap at 1.5 times its size is ten seconds at
    // the very best.
    BOOST_CHECK_MESSAGE(took < 40000, "took " << took << " ms, " << link.dropped << " dropped");
}

BOOST_AUTO_TEST_CASE(a_reader_that_stops_for_a_while)
{
    // The far end's room fills while its program does not read. The sender
    // waits, probing, without counting it as loss; the stream survives a
    // pause longer than all its retries would last, and completes after.
    End a(3), b(3);
    a.to_send = Pattern(overlay::STREAM_BUFFER * 2, 6);
    Link link;
    link.delay = 100;
    b.reading = false;
    const int64_t took = Run(a, b, link, 900000, [&](int64_t now) { b.reading = now > 300000; });
    BOOST_CHECK(!a.stream.Dead());
    BOOST_CHECK(a.stream.Finished());
    BOOST_CHECK(b.got == a.to_send);
    BOOST_CHECK(took > 300000);
}

BOOST_AUTO_TEST_CASE(a_far_end_that_is_gone)
{
    // Nothing comes back: the stream gives up, after its retries, and says so.
    End a(4), b(4);
    a.to_send = Pattern(10 * 1024, 7);
    Link link;
    link.cut_to_b = true;
    b.closing = false; // so b has nothing of its own to give up on
    const int64_t took = Run(a, b, link, 3600000);
    BOOST_CHECK(a.stream.Dead());
    BOOST_CHECK_MESSAGE(took < 600000, "took " << took << " ms");
}

BOOST_AUTO_TEST_CASE(a_reset_ends_it)
{
    overlay::ReliableStream s(9);
    const std::vector<unsigned char> data = Pattern(1000, 8);
    s.Write(data.data(), data.size());
    s.Poll(0);
    // Another stream's reset is not this one's.
    s.Receive(overlay::ReliableStream::ResetMessage(10), 5);
    BOOST_CHECK(!s.Dead());
    s.Receive(overlay::ReliableStream::ResetMessage(9), 5);
    BOOST_CHECK(s.Dead());
    BOOST_CHECK(s.Poll(10).empty());
    BOOST_CHECK_EQUAL(s.Write(data.data(), data.size()), 0U);
}

BOOST_AUTO_TEST_CASE(malformed_messages_are_ignored)
{
    overlay::ReliableStream s(11);
    std::vector<unsigned char> data_msg{overlay::SVC_DATA, 11, 0, 0, 0, 0, 0, 0}; // header cut short
    s.Receive(data_msg, 0);
    std::vector<unsigned char> ack{overlay::SVC_ACK, 11, 0, 0, 0, 9, 9, 9, 9}; // wrong length
    s.Receive(ack, 0);
    std::vector<unsigned char> far_ack{overlay::SVC_ACK, 11, 0, 0, 0};
    far_ack.resize(20, 0);
    far_ack[5] = 50; // acknowledges cells never sent
    s.Receive(far_ack, 0);
    BOOST_CHECK(!s.Dead());
    BOOST_CHECK_EQUAL(s.Readable(), 0U);
    BOOST_CHECK_EQUAL(s.InFlight(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
