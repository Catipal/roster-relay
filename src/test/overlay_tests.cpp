// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/frame.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(overlay_tests, BasicTestingSetup)

namespace {

overlay::FrameKey TestKey(unsigned char fill)
{
    overlay::FrameKey key;
    key.fill(fill);
    return key;
}

std::vector<unsigned char> Payload(size_t n, unsigned char first = 0)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<unsigned char>(first + i);
    return v;
}

} // namespace

BOOST_AUTO_TEST_CASE(frame_roundtrip)
{
    const overlay::FrameKey key = TestKey(0x11);
    const std::vector<unsigned char> payload = Payload(400);

    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 0xAABBCCDD11223344ULL,
                                   7, payload, sealed));
    BOOST_CHECK_EQUAL(sealed.size(), payload.size() + overlay::FRAME_OVERHEAD);
    // The payload must not appear in the clear anywhere in the datagram.
    BOOST_CHECK(std::search(sealed.begin(), sealed.end(), payload.begin(),
                            payload.end()) == sealed.end());

    overlay::FrameType type;
    uint64_t session = 0, counter = 0;
    std::vector<unsigned char> opened;
    BOOST_CHECK(overlay::OpenFrame(key, sealed.data(), sealed.size(), type,
                                   session, counter, opened));
    BOOST_CHECK(type == overlay::FrameType::DATA);
    BOOST_CHECK_EQUAL(session, 0xAABBCCDD11223344ULL);
    BOOST_CHECK_EQUAL(counter, 7);
    BOOST_CHECK(opened == payload);
}

BOOST_AUTO_TEST_CASE(frame_empty_payload_is_legal)
{
    const overlay::FrameKey key = TestKey(0x22);
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::HANDSHAKE_INIT, 1, 0,
                                   std::vector<unsigned char>(), sealed));
    BOOST_CHECK_EQUAL(sealed.size(), overlay::FRAME_OVERHEAD);

    overlay::FrameType type;
    uint64_t session = 0, counter = 99;
    std::vector<unsigned char> opened;
    BOOST_CHECK(overlay::OpenFrame(key, sealed.data(), sealed.size(), type,
                                   session, counter, opened));
    BOOST_CHECK(type == overlay::FrameType::HANDSHAKE_INIT);
    BOOST_CHECK_EQUAL(counter, 0);
    BOOST_CHECK(opened.empty());
}

BOOST_AUTO_TEST_CASE(frame_wrong_key_fails)
{
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(TestKey(0x33), overlay::FrameType::DATA, 5, 1,
                                   Payload(64), sealed));

    overlay::FrameType type;
    uint64_t session, counter;
    std::vector<unsigned char> opened;
    BOOST_CHECK(!overlay::OpenFrame(TestKey(0x34), sealed.data(), sealed.size(),
                                    type, session, counter, opened));
}

BOOST_AUTO_TEST_CASE(frame_header_is_authenticated)
{
    // The header travels in clear so a receiver can find the session, but it is
    // covered by the tag, so none of it can be altered in flight.
    const overlay::FrameKey key = TestKey(0x44);
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 9, 3,
                                   Payload(32), sealed));

    for (size_t i = 0; i < overlay::FRAME_HEADER_SIZE; ++i) {
        std::vector<unsigned char> tampered = sealed;
        tampered[i] ^= 0x01;
        overlay::FrameType type;
        uint64_t session, counter;
        std::vector<unsigned char> opened;
        BOOST_CHECK_MESSAGE(!overlay::OpenFrame(key, tampered.data(), tampered.size(),
                                                type, session, counter, opened),
                            "header byte " << i << " was not authenticated");
    }
}

BOOST_AUTO_TEST_CASE(frame_ciphertext_and_tag_are_authenticated)
{
    const overlay::FrameKey key = TestKey(0x55);
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 9, 3,
                                   Payload(48), sealed));

    for (size_t i = overlay::FRAME_HEADER_SIZE; i < sealed.size(); ++i) {
        std::vector<unsigned char> tampered = sealed;
        tampered[i] ^= 0x80;
        overlay::FrameType type;
        uint64_t session, counter;
        std::vector<unsigned char> opened;
        BOOST_CHECK_MESSAGE(!overlay::OpenFrame(key, tampered.data(), tampered.size(),
                                                type, session, counter, opened),
                            "byte " << i << " was not authenticated");
    }
}

BOOST_AUTO_TEST_CASE(frame_rejects_malformed)
{
    const overlay::FrameKey key = TestKey(0x66);
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 1, 1,
                                   Payload(16), sealed));

    overlay::FrameType type;
    uint64_t session, counter;
    std::vector<unsigned char> opened;

    // Truncated below the fixed overhead.
    BOOST_CHECK(!overlay::OpenFrame(key, sealed.data(), overlay::FRAME_OVERHEAD - 1,
                                    type, session, counter, opened));
    // Truncated anywhere else - the tag no longer covers what is there.
    BOOST_CHECK(!overlay::OpenFrame(key, sealed.data(), sealed.size() - 1,
                                    type, session, counter, opened));

    std::vector<unsigned char> bad_magic = sealed;
    bad_magic[0] = 'X';
    BOOST_CHECK(!overlay::OpenFrame(key, bad_magic.data(), bad_magic.size(),
                                    type, session, counter, opened));

    std::vector<unsigned char> bad_version = sealed;
    bad_version[4] = overlay::FRAME_VERSION + 1;
    BOOST_CHECK(!overlay::OpenFrame(key, bad_version.data(), bad_version.size(),
                                    type, session, counter, opened));

    std::vector<unsigned char> bad_type = sealed;
    bad_type[5] = 0x7f;
    BOOST_CHECK(!overlay::OpenFrame(key, bad_type.data(), bad_type.size(),
                                    type, session, counter, opened));
}

BOOST_AUTO_TEST_CASE(frame_size_budget)
{
    // A sealed frame at the payload limit must still fit the datagram that
    // crosses the internet without IP fragmentation. If this fails, every
    // number in frame.h needs revisiting together rather than one of them
    // being nudged.
    BOOST_CHECK_EQUAL(overlay::FRAME_OVERHEAD, 38u);
    BOOST_CHECK_EQUAL(overlay::MAX_FRAME_PAYLOAD + overlay::FRAME_OVERHEAD,
                      overlay::SAFE_DATAGRAM);
    BOOST_CHECK_EQUAL(overlay::MAX_FRAGMENT_PAYLOAD,
                      overlay::MAX_FRAME_PAYLOAD - overlay::FRAGMENT_HEADER_SIZE);

    const overlay::FrameKey key = TestKey(0x77);
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 1, 1,
                                   Payload(overlay::MAX_FRAME_PAYLOAD), sealed));
    BOOST_CHECK_EQUAL(sealed.size(), overlay::SAFE_DATAGRAM);

    // One byte over is refused rather than silently producing a datagram that
    // will be fragmented and dropped by middleboxes.
    BOOST_CHECK(!overlay::SealFrame(key, overlay::FrameType::DATA, 1, 2,
                                    Payload(overlay::MAX_FRAME_PAYLOAD + 1), sealed));
}

BOOST_AUTO_TEST_CASE(frame_counter_changes_the_keystream)
{
    // Same key, same payload, different counter must not produce the same
    // ciphertext - that would mean the keystream repeats, which is the one
    // failure this construction cannot survive.
    const overlay::FrameKey key = TestKey(0x88);
    const std::vector<unsigned char> payload = Payload(128);

    std::vector<unsigned char> a, b;
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 1, 1, payload, a));
    BOOST_CHECK(overlay::SealFrame(key, overlay::FrameType::DATA, 1, 2, payload, b));

    const size_t off = overlay::FRAME_HEADER_SIZE;
    BOOST_CHECK(!std::equal(a.begin() + off, a.begin() + off + payload.size(),
                            b.begin() + off));
}

BOOST_AUTO_TEST_CASE(replay_window_basics)
{
    overlay::ReplayWindow w;
    BOOST_CHECK(w.Accept(0));
    BOOST_CHECK(!w.Accept(0)); // exact replay
    BOOST_CHECK(w.Accept(1));
    BOOST_CHECK(w.Accept(2));
    BOOST_CHECK(!w.Accept(1)); // replay of an accepted counter
}

BOOST_AUTO_TEST_CASE(replay_window_tolerates_reordering)
{
    // UDP reorders, so insisting on a strictly increasing counter would drop
    // honest traffic. Arriving late is fine; arriving twice is not.
    overlay::ReplayWindow w;
    BOOST_CHECK(w.Accept(10));
    BOOST_CHECK(w.Accept(8));
    BOOST_CHECK(w.Accept(9));
    BOOST_CHECK(!w.Accept(8));
    BOOST_CHECK(w.Accept(11));
    BOOST_CHECK_EQUAL(w.Highest(), 11u);
}

BOOST_AUTO_TEST_CASE(replay_window_drops_the_far_past)
{
    overlay::ReplayWindow w;
    BOOST_CHECK(w.Accept(1000));
    // Inside the window.
    BOOST_CHECK(w.Accept(1000 - 63));
    // Beyond it: no longer provable as fresh, so refused rather than guessed.
    BOOST_CHECK(!w.Accept(1000 - 64));
    BOOST_CHECK(!w.Accept(0));
}

BOOST_AUTO_TEST_CASE(replay_window_survives_a_large_jump)
{
    // A jump of 64 or more must clear the window rather than shift by an
    // amount that is undefined behaviour for a 64-bit type.
    overlay::ReplayWindow w;
    BOOST_CHECK(w.Accept(1));
    BOOST_CHECK(w.Accept(1 + 64));
    BOOST_CHECK(!w.Accept(1)); // now outside the window
    BOOST_CHECK(w.Accept(1 + 64 + 1));
    BOOST_CHECK(w.Accept(1 + 1000000));
    BOOST_CHECK(!w.Accept(1 + 64 + 1));
}

BOOST_AUTO_TEST_SUITE_END()
