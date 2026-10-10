// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/protocol.h>
#include <overlay/cells.h>
#include <sync.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <thread>

using namespace overlay;

BOOST_FIXTURE_TEST_SUITE(cells_tests, BasicTestingSetup)

namespace {

const uint8_t TAG = 0x42;

/** op byte for a request and its answer in these tests. */
const uint8_t PING = 0x01;
const uint8_t PONG = 0x81;

std::vector<unsigned char> Msg(uint8_t op, const std::vector<unsigned char>& body)
{
    std::vector<unsigned char> m(CELL_MESSAGE_HEADER, 0);
    m[0] = op;
    m.insert(m.end(), body.begin(), body.end());
    return m;
}

/**
 * Two channels joined back to back, with no network: what one sends, the
 * other is handed at once, as if it had come down a path.
 */
struct Pair {
    Mutex mutex;
    std::vector<std::vector<unsigned char>> sent_by_client GUARDED_BY(mutex);
    std::vector<std::vector<unsigned char>> sent_by_server GUARDED_BY(mutex);
    std::atomic<int> served{0};
    std::atomic<bool> deliver_answers{true};

    // Each side sees the other as the far end of a path.
    const Hop client_seen_by_server = Hop::Path(1);
    const Hop server_seen_by_client = Hop::Path(2);

    CellChannel client{TAG,
                       [this](const Hop&, const std::vector<unsigned char>& cell) {
                           {
                               LOCK(mutex);
                               sent_by_client.push_back(cell);
                           }
                           server.Handle(client_seen_by_server, std::vector<unsigned char>(cell));
                           return true;
                       },
                       [](uint8_t op) { return op == PING || op == PONG; }};
    CellChannel server{TAG,
                       [this](const Hop&, const std::vector<unsigned char>& cell) {
                           {
                               LOCK(mutex);
                               sent_by_server.push_back(cell);
                           }
                           if (deliver_answers) client.Handle(server_seen_by_client, std::vector<unsigned char>(cell));
                           return true;
                       },
                       [](uint8_t op) { return op == PING || op == PONG; }};
};

} // namespace

BOOST_AUTO_TEST_CASE(mail_cells_are_unchanged_on_the_wire)
{
    // Sharing the cell layer must not change a byte of what mail sends:
    // MAIL_CELL || transfer LE64 || index LE16 || count LE16 || data.
    const std::vector<std::vector<unsigned char>> cells = mail::SplitCells(0x0102030405060708, {0xaa, 0xbb});
    BOOST_REQUIRE_EQUAL(cells.size(), 1u);
    const std::vector<unsigned char> expected{0x10, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                                              0x00, 0x00, 0x01, 0x00, 0xaa, 0xbb};
    BOOST_CHECK(cells[0] == expected);
    BOOST_CHECK_EQUAL(mail::CELL_DATA, CELL_DATA);
    BOOST_CHECK_EQUAL(mail::MAX_MESSAGE_SIZE, MAX_CELL_MESSAGE_SIZE);
}

BOOST_AUTO_TEST_CASE(cells_belong_to_their_tag)
{
    std::vector<unsigned char> message(CELL_DATA * 2 + 5, 0x5a);
    const std::vector<std::vector<unsigned char>> cells = SplitCells(TAG, 7, message);
    BOOST_REQUIRE_EQUAL(cells.size(), 3u);
    for (const std::vector<unsigned char>& c : cells) BOOST_CHECK_EQUAL(c[0], TAG);

    // Another service's reassembler does not take them, and mail's does not either.
    CellReassembler other(TAG + 1);
    mail::Reassembler mail_re;
    CellReassembler ours(TAG);
    std::vector<unsigned char> out;
    uint64_t transfer = 0;
    const Hop from = Hop::Path(9);
    for (const std::vector<unsigned char>& c : cells) {
        BOOST_CHECK(!other.Add(from, c, 1000, out, transfer));
        BOOST_CHECK(!mail_re.Add(from, c, 1000, out, transfer));
    }
    BOOST_CHECK_EQUAL(other.Pending(), 0u);
    bool done = false;
    for (const std::vector<unsigned char>& c : cells) done = ours.Add(from, c, 1000, out, transfer);
    BOOST_CHECK(done);
    BOOST_CHECK(out == message);
    BOOST_CHECK_EQUAL(transfer, 7u);
}

BOOST_AUTO_TEST_CASE(ask_is_answered_and_repeats_get_the_same_answer)
{
    Pair p;
    p.server.SetServer([&p](CellChannel::Request&& r) {
        ++p.served;
        std::vector<unsigned char> body(r.message.begin() + CELL_MESSAGE_HEADER, r.message.end());
        body.push_back(0xee);
        std::vector<unsigned char> answer = Msg(PONG, body);
        std::copy(r.message.begin() + 1, r.message.begin() + CELL_MESSAGE_HEADER, answer.begin() + 1);
        p.server.Answer(r.from, r.transfer, answer);
    });

    std::vector<unsigned char> answer;
    std::string error;
    BOOST_REQUIRE(p.client.Ask(p.server_seen_by_client, Msg(PING, {1, 2, 3}), answer, std::chrono::seconds{3}, error));
    BOOST_CHECK_EQUAL(answer[0], PONG);
    BOOST_CHECK(std::vector<unsigned char>(answer.begin() + CELL_MESSAGE_HEADER, answer.end()) ==
                std::vector<unsigned char>({1, 2, 3, 0xee}));
    BOOST_CHECK_EQUAL(p.served.load(), 1);
    BOOST_CHECK_EQUAL(p.server.InFlight(), 0u);

    // The same request arriving again - its answer was lost - is answered
    // from what was given, not served a second time.
    std::vector<std::vector<unsigned char>> request_cells;
    size_t answers_before = 0;
    {
        LOCK(p.mutex);
        request_cells = p.sent_by_client;
        answers_before = p.sent_by_server.size();
    }
    for (const std::vector<unsigned char>& c : request_cells) {
        p.server.Handle(p.client_seen_by_server, std::vector<unsigned char>(c));
    }
    BOOST_CHECK_EQUAL(p.served.load(), 1);
    LOCK(p.mutex);
    BOOST_CHECK_EQUAL(p.sent_by_server.size(), answers_before + 1);
    BOOST_CHECK(p.sent_by_server.back() == p.sent_by_server[answers_before - 1]);
}

BOOST_AUTO_TEST_CASE(a_slow_answer_is_served_once)
{
    // The server answers later, from another thread, as a wallet would. The
    // asker's retries arrive meanwhile and must not be served again.
    Pair p;
    Mutex held_mutex;
    std::vector<CellChannel::Request> held;
    p.server.SetServer([&](CellChannel::Request&& r) {
        ++p.served;
        LOCK(held_mutex);
        held.push_back(std::move(r));
    });

    std::vector<unsigned char> answer;
    std::string error;
    bool ok = false;
    std::thread asker([&] {
        ok = p.client.Ask(p.server_seen_by_client, Msg(PING, {9}), answer, std::chrono::milliseconds{1500}, error);
    });
    // Long enough for the asker to resend at least once.
    UninterruptibleSleep(std::chrono::milliseconds{700});
    BOOST_CHECK_EQUAL(p.served.load(), 1);
    BOOST_CHECK_EQUAL(p.server.InFlight(), 1u);
    {
        LOCK(p.mutex);
        BOOST_CHECK_GE(p.sent_by_client.size(), 2u);
    }
    CellChannel::Request r;
    {
        LOCK(held_mutex);
        BOOST_REQUIRE_EQUAL(held.size(), 1u);
        r = held[0];
    }
    std::vector<unsigned char> reply = Msg(PONG, {8});
    std::copy(r.message.begin() + 1, r.message.begin() + CELL_MESSAGE_HEADER, reply.begin() + 1);
    p.server.Answer(r.from, r.transfer, reply);
    asker.join();
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(answer.back(), 8);
    BOOST_CHECK_EQUAL(p.served.load(), 1);
    BOOST_CHECK_EQUAL(p.server.InFlight(), 0u);
}

BOOST_AUTO_TEST_CASE(unknown_ops_and_shutdown)
{
    Pair p;
    p.server.SetServer([&p](CellChannel::Request&&) { ++p.served; });

    // An op the service does not know is dropped before the server sees it.
    for (const std::vector<unsigned char>& c : SplitCells(TAG, 5, Msg(0x07, {1}))) {
        p.server.Handle(p.client_seen_by_server, std::vector<unsigned char>(c));
    }
    BOOST_CHECK_EQUAL(p.served.load(), 0);

    // Nothing answers: the asker gives up inside its timeout.
    std::vector<unsigned char> answer;
    std::string error;
    BOOST_CHECK(!p.client.Ask(p.server_seen_by_client, Msg(PING, {}), answer, std::chrono::milliseconds{300}, error));
    BOOST_CHECK_EQUAL(error, "No answer came back.");

    // After an interrupt every ask gives up at once.
    p.client.Interrupt();
    error.clear();
    BOOST_CHECK(!p.client.Ask(p.server_seen_by_client, Msg(PING, {}), answer, std::chrono::seconds{30}, error));
    BOOST_CHECK_EQUAL(error, "Shutting down.");

    // Too large to send at all.
    error.clear();
    BOOST_CHECK(!p.server.Ask(p.client_seen_by_server, Msg(PING, std::vector<unsigned char>(MAX_CELL_MESSAGE_SIZE)),
                              answer, std::chrono::milliseconds{100}, error));
    BOOST_CHECK_EQUAL(error, "The message is too large to send.");
}

BOOST_AUTO_TEST_SUITE_END()
