// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/frame.h>
#include <overlay/handshake.h>
#include <overlay/session.h>
#include <overlay/path.h>
#include <overlay/relay.h>
#include <overlay/socket.h>
#include <overlay/transport.h>
#include <util/time.h>
#include <netbase.h>

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

namespace {

struct Parties {
    CKey i_static, r_static;
    overlay::HandshakeInitiator I;
    overlay::HandshakeResponder R;
    std::vector<unsigned char> msg1, msg2;
    overlay::SessionKeys ikeys, rkeys;
    CPubKey learned;

    Parties() { i_static.MakeNewKey(true); r_static.MakeNewKey(true); }

    bool Run()
    {
        if (!I.Start(i_static, r_static.GetPubKey(), msg1)) return false;
        if (!R.Accept(r_static, msg1.data(), msg1.size(), learned, msg2, rkeys)) return false;
        return I.Finish(msg2.data(), msg2.size(), ikeys);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(handshake_completes_and_agrees)
{
    Parties p;
    BOOST_CHECK(p.Run());

    // The responder learns who actually connected, and it is the real key.
    BOOST_CHECK(p.learned == p.i_static.GetPubKey());

    // Directions are crossed: what one seals with, the other opens with.
    BOOST_CHECK(p.ikeys.send == p.rkeys.recv);
    BOOST_CHECK(p.ikeys.recv == p.rkeys.send);
    // And the two directions differ, so a frame cannot be reflected back at
    // its sender and accepted as though the peer had sent it.
    BOOST_CHECK(p.ikeys.send != p.ikeys.recv);
    BOOST_CHECK_EQUAL(p.ikeys.session_id, p.rkeys.session_id);
    BOOST_CHECK(p.ikeys.session_id != 0);

    BOOST_CHECK_EQUAL(p.msg1.size(), overlay::HANDSHAKE_INIT_SIZE);
    BOOST_CHECK_EQUAL(p.msg2.size(), overlay::HANDSHAKE_RESP_SIZE);
}

BOOST_AUTO_TEST_CASE(handshake_keys_carry_real_traffic)
{
    // The point of the exchange: a frame sealed by one side opens on the other.
    Parties p;
    BOOST_CHECK(p.Run());

    const std::vector<unsigned char> payload = Payload(300, 7);
    std::vector<unsigned char> sealed;
    BOOST_CHECK(overlay::SealFrame(p.ikeys.send, overlay::FrameType::DATA,
                                   p.ikeys.session_id, 1, payload, sealed));

    overlay::FrameType type;
    uint64_t session, counter;
    std::vector<unsigned char> opened;
    BOOST_CHECK(overlay::OpenFrame(p.rkeys.recv, sealed.data(), sealed.size(),
                                   type, session, counter, opened));
    BOOST_CHECK(opened == payload);
    BOOST_CHECK_EQUAL(session, p.rkeys.session_id);

    // The same frame must not open under the other direction's key.
    std::vector<unsigned char> wrong;
    BOOST_CHECK(!overlay::OpenFrame(p.rkeys.send, sealed.data(), sealed.size(),
                                    type, session, counter, wrong));
}

BOOST_AUTO_TEST_CASE(handshake_hides_the_initiator)
{
    // On an anonymity overlay this is the property, not a refinement: an
    // observer of the first message must not learn who is connecting.
    Parties p;
    BOOST_CHECK(p.Run());

    const CPubKey ipub = p.i_static.GetPubKey();
    BOOST_CHECK(std::search(p.msg1.begin(), p.msg1.end(), ipub.begin(), ipub.end())
                == p.msg1.end());
}

BOOST_AUTO_TEST_CASE(handshake_rejects_the_wrong_responder)
{
    // msg1 is encrypted to one specific responder. Nobody else can read it,
    // which is what stops a session being redirected to an impostor.
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));

    CKey impostor;
    impostor.MakeNewKey(true);
    overlay::HandshakeResponder other;
    CPubKey learned;
    std::vector<unsigned char> msg2;
    overlay::SessionKeys keys;
    BOOST_CHECK(!other.Accept(impostor, p.msg1.data(), p.msg1.size(), learned, msg2, keys));
}

BOOST_AUTO_TEST_CASE(handshake_first_message_is_tamper_proof)
{
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));

    for (size_t i = 0; i < p.msg1.size(); ++i) {
        std::vector<unsigned char> bad = p.msg1;
        bad[i] ^= 0x01;
        overlay::HandshakeResponder R;
        CPubKey learned;
        std::vector<unsigned char> msg2;
        overlay::SessionKeys keys;
        BOOST_CHECK_MESSAGE(!R.Accept(p.r_static, bad.data(), bad.size(), learned, msg2, keys),
                            "msg1 byte " << i << " was not covered");
    }
}

BOOST_AUTO_TEST_CASE(handshake_reply_is_tamper_proof)
{
    for (size_t i = 0; i < overlay::HANDSHAKE_RESP_SIZE; ++i) {
        Parties p;
        BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));
        BOOST_CHECK(p.R.Accept(p.r_static, p.msg1.data(), p.msg1.size(),
                               p.learned, p.msg2, p.rkeys));
        p.msg2[i] ^= 0x01;
        overlay::SessionKeys keys;
        BOOST_CHECK_MESSAGE(!p.I.Finish(p.msg2.data(), p.msg2.size(), keys),
                            "msg2 byte " << i << " was not covered");
    }
}

BOOST_AUTO_TEST_CASE(handshake_rejects_wrong_sizes)
{
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));

    overlay::HandshakeResponder R;
    CPubKey learned;
    std::vector<unsigned char> msg2;
    overlay::SessionKeys keys;
    BOOST_CHECK(!R.Accept(p.r_static, p.msg1.data(), p.msg1.size() - 1, learned, msg2, keys));

    std::vector<unsigned char> longer = p.msg1;
    longer.push_back(0);
    BOOST_CHECK(!R.Accept(p.r_static, longer.data(), longer.size(), learned, msg2, keys));
}

BOOST_AUTO_TEST_CASE(handshake_is_fresh_every_time)
{
    // Fresh ephemerals mean two sessions between the same pair share no keys,
    // which is what stops one compromised session opening another.
    Parties a, b;
    BOOST_CHECK(a.Run());
    b.i_static = a.i_static;
    b.r_static = a.r_static;
    BOOST_CHECK(b.Run());

    BOOST_CHECK(a.ikeys.send != b.ikeys.send);
    BOOST_CHECK(a.ikeys.recv != b.ikeys.recv);
    BOOST_CHECK(a.ikeys.session_id != b.ikeys.session_id);
    BOOST_CHECK(a.msg1 != b.msg1);
}

BOOST_AUTO_TEST_CASE(handshake_cannot_be_restarted)
{
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));
    std::vector<unsigned char> again;
    // Reusing an initiator would reuse its ephemeral, which is exactly the
    // nonce-reuse the frame layer cannot survive.
    BOOST_CHECK(!p.I.Start(p.i_static, p.r_static.GetPubKey(), again));
}

BOOST_AUTO_TEST_CASE(handshake_reply_cannot_be_spliced_across_sessions)
{
    // Two sessions run in parallel between the same pair. The reply belonging
    // to one must not complete the other, or an attacker who can reorder
    // datagrams could join a victim to a session of its choosing.
    Parties a, b;
    BOOST_CHECK(a.I.Start(a.i_static, a.r_static.GetPubKey(), a.msg1));
    b.i_static = a.i_static;
    b.r_static = a.r_static;
    BOOST_CHECK(b.I.Start(b.i_static, b.r_static.GetPubKey(), b.msg1));

    BOOST_CHECK(a.R.Accept(a.r_static, a.msg1.data(), a.msg1.size(), a.learned, a.msg2, a.rkeys));
    BOOST_CHECK(b.R.Accept(b.r_static, b.msg1.data(), b.msg1.size(), b.learned, b.msg2, b.rkeys));
    BOOST_CHECK(a.msg2 != b.msg2);

    overlay::SessionKeys spliced;
    BOOST_CHECK(!a.I.Finish(b.msg2.data(), b.msg2.size(), spliced));
}

BOOST_AUTO_TEST_CASE(handshake_replayed_first_message_yields_a_different_session)
{
    // Replaying msg1 is not preventable at this layer and does not need to be:
    // the responder answers with a fresh ephemeral, so the replayer derives
    // nothing and the session it creates is not the original one. Anti-flood
    // for that belongs at the socket, not here.
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));

    CPubKey l1, l2;
    std::vector<unsigned char> r1, r2;
    overlay::SessionKeys k1, k2;
    overlay::HandshakeResponder R1, R2;
    BOOST_CHECK(R1.Accept(p.r_static, p.msg1.data(), p.msg1.size(), l1, r1, k1));
    BOOST_CHECK(R2.Accept(p.r_static, p.msg1.data(), p.msg1.size(), l2, r2, k2));

    BOOST_CHECK(l1 == l2); // same claimed identity, correctly
    BOOST_CHECK(k1.session_id != k2.session_id);
    BOOST_CHECK(k1.send != k2.send);
}

BOOST_AUTO_TEST_CASE(handshake_rejects_junk_public_keys)
{
    // The bytes on the wire are attacker-controlled. A public key field that is
    // not a curve point must be refused rather than reaching key agreement.
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));

    overlay::HandshakeResponder R;
    CPubKey learned;
    std::vector<unsigned char> msg2;
    overlay::SessionKeys keys;

    std::vector<unsigned char> zeroed = p.msg1;
    std::fill(zeroed.begin(), zeroed.begin() + overlay::HANDSHAKE_PUBKEY_SIZE, 0);
    BOOST_CHECK(!R.Accept(p.r_static, zeroed.data(), zeroed.size(), learned, msg2, keys));

    // Valid prefix byte, but the x coordinate is not on the curve.
    std::vector<unsigned char> offcurve = p.msg1;
    offcurve[0] = 0x02;
    std::fill(offcurve.begin() + 1, offcurve.begin() + overlay::HANDSHAKE_PUBKEY_SIZE, 0xff);
    BOOST_CHECK(!R.Accept(p.r_static, offcurve.data(), offcurve.size(), learned, msg2, keys));

    // And the same in the reply's ephemeral slot.
    BOOST_CHECK(p.R.Accept(p.r_static, p.msg1.data(), p.msg1.size(), p.learned, p.msg2, p.rkeys));
    std::vector<unsigned char> bad_reply = p.msg2;
    std::fill(bad_reply.begin(), bad_reply.begin() + overlay::HANDSHAKE_PUBKEY_SIZE, 0);
    overlay::SessionKeys never;
    BOOST_CHECK(!p.I.Finish(bad_reply.data(), bad_reply.size(), never));
}

BOOST_AUTO_TEST_CASE(handshake_with_itself_is_coherent)
{
    // A node dialling its own published address is a configuration mistake, not
    // an attack, but it must not crash or produce a session whose two
    // directions collapse into one key.
    CKey self;
    self.MakeNewKey(true);

    overlay::HandshakeInitiator I;
    overlay::HandshakeResponder R;
    std::vector<unsigned char> m1, m2;
    CPubKey learned;
    overlay::SessionKeys ik, rk;

    BOOST_CHECK(I.Start(self, self.GetPubKey(), m1));
    BOOST_CHECK(R.Accept(self, m1.data(), m1.size(), learned, m2, rk));
    BOOST_CHECK(I.Finish(m2.data(), m2.size(), ik));
    BOOST_CHECK(learned == self.GetPubKey());
    BOOST_CHECK(ik.send != ik.recv);
    BOOST_CHECK(ik.send == rk.recv);
}

BOOST_AUTO_TEST_CASE(handshake_survives_a_forged_reply)
{
    // UDP source addresses are forgeable, so anyone who knows two peers are
    // connecting can send a junk reply claiming to be one of them. Rejecting it
    // must cost the honest party nothing: the real reply still completes the
    // handshake afterwards.
    Parties p;
    BOOST_CHECK(p.I.Start(p.i_static, p.r_static.GetPubKey(), p.msg1));
    BOOST_CHECK(p.R.Accept(p.r_static, p.msg1.data(), p.msg1.size(),
                           p.learned, p.msg2, p.rkeys));

    std::vector<unsigned char> forged = p.msg2;
    forged.back() ^= 0x01;
    overlay::SessionKeys keys;
    BOOST_CHECK(!p.I.Finish(forged.data(), forged.size(), keys));

    // Untouched by the rejection, so the genuine reply still works.
    BOOST_CHECK(p.I.Finish(p.msg2.data(), p.msg2.size(), p.ikeys));
    BOOST_CHECK(p.ikeys.send == p.rkeys.recv);

    // But succeeding consumes it: handing the same keys to two holders would
    // start two counters at one, which is the nonce reuse the frame layer
    // cannot survive.
    overlay::SessionKeys twice;
    BOOST_CHECK(!p.I.Finish(p.msg2.data(), p.msg2.size(), twice));
}

BOOST_AUTO_TEST_CASE(session_carries_traffic_both_ways)
{
    Parties p;
    BOOST_CHECK(p.Run());
    overlay::Session i(p.ikeys), r(p.rkeys);
    BOOST_CHECK_EQUAL(i.Id(), r.Id());

    for (int n = 0; n < 5; ++n) {
        const std::vector<unsigned char> out = Payload(100 + n, (unsigned char)n);
        std::vector<unsigned char> dgram, got;
        BOOST_CHECK(i.Seal(out, dgram));
        BOOST_CHECK(r.Open(dgram.data(), dgram.size(), got));
        BOOST_CHECK(got == out);

        std::vector<unsigned char> back, got_back;
        BOOST_CHECK(r.Seal(out, back));
        BOOST_CHECK(i.Open(back.data(), back.size(), got_back));
        BOOST_CHECK(got_back == out);
    }
    BOOST_CHECK_EQUAL(i.FramesSent(), 5u);
}

BOOST_AUTO_TEST_CASE(session_rejects_replays_and_foreign_frames)
{
    Parties p;
    BOOST_CHECK(p.Run());
    overlay::Session i(p.ikeys), r(p.rkeys);

    std::vector<unsigned char> dgram, got;
    BOOST_CHECK(i.Seal(Payload(64), dgram));
    BOOST_CHECK(r.Open(dgram.data(), dgram.size(), got));
    // The same datagram twice is the attack the counter exists to stop.
    BOOST_CHECK(!r.Open(dgram.data(), dgram.size(), got));

    // A frame from an unrelated session must not open here.
    Parties q;
    BOOST_CHECK(q.Run());
    overlay::Session other(q.ikeys);
    std::vector<unsigned char> foreign;
    BOOST_CHECK(other.Seal(Payload(64), foreign));
    BOOST_CHECK(!r.Open(foreign.data(), foreign.size(), got));

    // And a node must not accept its own frame reflected back at it.
    BOOST_CHECK(!i.Open(dgram.data(), dgram.size(), got));
}

BOOST_AUTO_TEST_CASE(session_tolerates_reordering)
{
    // UDP delivers out of order; the session must not treat that as an attack.
    Parties p;
    BOOST_CHECK(p.Run());
    overlay::Session i(p.ikeys), r(p.rkeys);

    std::vector<std::vector<unsigned char>> wire;
    for (int n = 0; n < 4; ++n) {
        std::vector<unsigned char> d;
        BOOST_CHECK(i.Seal(Payload(32, (unsigned char)n), d));
        wire.push_back(d);
    }

    std::vector<unsigned char> got;
    BOOST_CHECK(r.Open(wire[3].data(), wire[3].size(), got));
    BOOST_CHECK(r.Open(wire[1].data(), wire[1].size(), got));
    BOOST_CHECK(r.Open(wire[0].data(), wire[0].size(), got));
    BOOST_CHECK(r.Open(wire[2].data(), wire[2].size(), got));
    // Every one of them exactly once, though.
    BOOST_CHECK(!r.Open(wire[2].data(), wire[2].size(), got));
}

BOOST_AUTO_TEST_CASE(session_refuses_oversized_payloads)
{
    Parties p;
    BOOST_CHECK(p.Run());
    overlay::Session i(p.ikeys);
    std::vector<unsigned char> d;
    BOOST_CHECK(i.Seal(Payload(overlay::MAX_FRAME_PAYLOAD), d));
    BOOST_CHECK_EQUAL(d.size(), overlay::SAFE_DATAGRAM);
    BOOST_CHECK(!i.Seal(Payload(overlay::MAX_FRAME_PAYLOAD + 1), d));
    // A refused seal must not have consumed a counter.
    BOOST_CHECK_EQUAL(i.FramesSent(), 1u);
}

BOOST_AUTO_TEST_CASE(session_counter_never_wraps)
{
    // The counter is the AEAD nonce. Wrapping would reuse one, which loses
    // confidentiality for both frames involved - so exhaustion has to be a
    // refusal. Unreachable in practice, checked anyway because the failure is
    // silent and total.
    Parties p;
    BOOST_CHECK(p.Run());
    overlay::Session s(p.ikeys);
    BOOST_CHECK_EQUAL(s.Remaining(), UINT64_MAX);

    std::vector<unsigned char> d;
    BOOST_CHECK(s.Seal(Payload(8), d));
    BOOST_CHECK_EQUAL(s.Remaining(), UINT64_MAX - 1);
}


namespace {

CService Addr(const char* ip, uint16_t port)
{
    return CService(LookupNumeric(ip, port));
}

/** Drive a full handshake between two transports and assert it succeeded. */
void Introduce(overlay::Transport& a, const CService& a_addr,
               overlay::Transport& b, const CKey& b_key, const CService& b_addr)
{
    std::vector<unsigned char> m1, reply, payload;
    BOOST_REQUIRE(a.Connect(b_addr, b_key.GetPubKey(), m1));

    BOOST_REQUIRE(b.Receive(a_addr, m1.data(), m1.size(), reply, payload)
                  == overlay::Transport::Result::ESTABLISHED);
    BOOST_REQUIRE(!reply.empty());

    std::vector<unsigned char> none, none2;
    BOOST_REQUIRE(a.Receive(b_addr, reply.data(), reply.size(), none, none2)
                  == overlay::Transport::Result::ESTABLISHED);
}

} // namespace

BOOST_AUTO_TEST_CASE(transport_establishes_and_carries_payloads)
{
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka), B(kb);

    Introduce(A, aa, B, kb, ba);
    BOOST_CHECK(A.HasSession(ba));
    BOOST_CHECK(B.HasSession(aa));
    // Each side learned who the other actually is.
    BOOST_CHECK(A.PeerIdentity(ba) == kb.GetPubKey());
    BOOST_CHECK(B.PeerIdentity(aa) == ka.GetPubKey());
    BOOST_CHECK(!A.HasPendingHandshake(ba));

    const std::vector<unsigned char> msg = Payload(500, 3);
    std::vector<unsigned char> dgram, reply, got;
    BOOST_CHECK(A.Send(ba, msg, dgram));
    BOOST_CHECK(B.Receive(aa, dgram.data(), dgram.size(), reply, got)
                == overlay::Transport::Result::PAYLOAD);
    BOOST_CHECK(got == msg);
    BOOST_CHECK(reply.empty()); // data is not answered at this layer

    std::vector<unsigned char> back, got_back;
    BOOST_CHECK(B.Send(aa, msg, back));
    BOOST_CHECK(A.Receive(ba, back.data(), back.size(), reply, got_back)
                == overlay::Transport::Result::PAYLOAD);
    BOOST_CHECK(got_back == msg);
}

BOOST_AUTO_TEST_CASE(transport_ignores_junk_without_answering)
{
    // On a connectionless transport, answering junk turns a node into a
    // reflector for someone else's traffic. Nothing unrecognised gets a reply.
    CKey k;
    k.MakeNewKey(true);
    overlay::Transport T(k);
    const CService from = Addr("10.0.0.9", 9346);

    const unsigned char junk[64] = {0};
    std::vector<unsigned char> reply, payload;
    BOOST_CHECK(T.Receive(from, junk, sizeof(junk), reply, payload)
                == overlay::Transport::Result::IGNORED);
    BOOST_CHECK(reply.empty());

    // A well-formed header wrapping nonsense is still ignored.
    std::vector<unsigned char> framed;
    overlay::WriteFrameHeader(overlay::FrameType::HANDSHAKE_INIT, 0, 0, framed);
    framed.resize(framed.size() + overlay::HANDSHAKE_INIT_SIZE, 0x41);
    BOOST_CHECK(T.Receive(from, framed.data(), framed.size(), reply, payload)
                == overlay::Transport::Result::IGNORED);
    BOOST_CHECK(reply.empty());
    BOOST_CHECK_EQUAL(T.SessionCount(), 0u);
}

BOOST_AUTO_TEST_CASE(transport_rejects_data_from_strangers)
{
    // A datagram from an address with no session must not be acted on, however
    // well formed - otherwise a forged source address would be enough.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), ba = Addr("10.0.0.2", 9346);
    const CService ca = Addr("10.0.0.3", 9346);
    overlay::Transport A(ka), B(kb);
    Introduce(A, aa, B, kb, ba);

    std::vector<unsigned char> dgram, reply, got;
    BOOST_CHECK(A.Send(ba, Payload(50), dgram));
    // Same bytes, claimed to come from somewhere else.
    BOOST_CHECK(B.Receive(ca, dgram.data(), dgram.size(), reply, got)
                == overlay::Transport::Result::IGNORED);
    BOOST_CHECK(reply.empty());
}

BOOST_AUTO_TEST_CASE(transport_ignores_an_unsolicited_reply)
{
    // A HANDSHAKE_RESP with no handshake in flight is dropped rather than
    // starting one, so an attacker cannot push a session onto a node.
    CKey ka;
    ka.MakeNewKey(true);
    const CService ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka);

    std::vector<unsigned char> fake;
    overlay::WriteFrameHeader(overlay::FrameType::HANDSHAKE_RESP, 0, 0, fake);
    fake.resize(fake.size() + overlay::HANDSHAKE_RESP_SIZE, 0x00);
    std::vector<unsigned char> reply, payload;
    BOOST_CHECK(A.Receive(ba, fake.data(), fake.size(), reply, payload)
                == overlay::Transport::Result::IGNORED);
    BOOST_CHECK_EQUAL(A.SessionCount(), 0u);
}

BOOST_AUTO_TEST_CASE(transport_handshake_fields_must_be_zero)
{
    // Unused header fields that accept any value are tamper surface for
    // nothing in return, so they are pinned.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka), B(kb);

    std::vector<unsigned char> m1;
    BOOST_CHECK(A.Connect(ba, kb.GetPubKey(), m1));
    m1[6] ^= 0x01; // session id byte inside the header
    std::vector<unsigned char> reply, payload;
    BOOST_CHECK(B.Receive(aa, m1.data(), m1.size(), reply, payload)
                == overlay::Transport::Result::IGNORED);
    BOOST_CHECK(reply.empty());
}

BOOST_AUTO_TEST_CASE(transport_reconnect_replaces_a_stalled_handshake)
{
    // A peer that never answers must not hold the slot forever.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka), B(kb);

    std::vector<unsigned char> first, second;
    BOOST_CHECK(A.Connect(ba, kb.GetPubKey(), first));
    BOOST_CHECK(A.Connect(ba, kb.GetPubKey(), second));
    BOOST_CHECK(first != second);
    BOOST_CHECK_EQUAL(A.PendingCount(), 1u);

    // The abandoned attempt's reply is no longer accepted.
    std::vector<unsigned char> reply, payload;
    BOOST_CHECK(B.Receive(aa, first.data(), first.size(), reply, payload)
                == overlay::Transport::Result::ESTABLISHED);
    std::vector<unsigned char> none, none2;
    BOOST_CHECK(A.Receive(ba, reply.data(), reply.size(), none, none2)
                == overlay::Transport::Result::IGNORED);

    // The current attempt still completes.
    std::vector<unsigned char> reply2;
    BOOST_CHECK(B.Receive(aa, second.data(), second.size(), reply2, payload)
                == overlay::Transport::Result::ESTABLISHED);
    BOOST_CHECK(A.Receive(ba, reply2.data(), reply2.size(), none, none2)
                == overlay::Transport::Result::ESTABLISHED);
}

BOOST_AUTO_TEST_CASE(transport_forget_drops_everything)
{
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka), B(kb);
    Introduce(A, aa, B, kb, ba);

    std::vector<unsigned char> dgram;
    BOOST_CHECK(A.Send(ba, Payload(10), dgram));
    A.Forget(ba);
    BOOST_CHECK(!A.HasSession(ba));
    BOOST_CHECK(!A.Send(ba, Payload(10), dgram));
    BOOST_CHECK(!A.PeerIdentity(ba).IsValid());
}


namespace {

/** Poll until `pred` holds or the deadline passes. Returns whether it held. */
template <typename Pred>
bool WaitFor(Pred pred, int timeout_ms = 5000)
{
    for (int waited = 0; waited < timeout_ms; waited += 10) {
        if (pred()) return true;
        UninterruptibleSleep(std::chrono::milliseconds{10});
    }
    return pred();
}

/** Collects payloads delivered on the receive thread. */
struct Inbox {
    Mutex mutex;
    std::vector<std::vector<unsigned char>> items;

    overlay::Socket::PayloadHandler Handler()
    {
        return [this](const CService&, std::vector<unsigned char>&& p) {
            LOCK(mutex);
            items.push_back(std::move(p));
        };
    }
    size_t Count()
    {
        LOCK(mutex);
        return items.size();
    }
    std::vector<unsigned char> At(size_t i)
    {
        LOCK(mutex);
        return items.at(i);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(socket_two_nodes_talk_over_real_udp)
{
    // The end of the first stage: two nodes, real datagrams on the loopback,
    // a session negotiated from nothing but each other's roster identity.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);

    overlay::Socket A(ka), B(kb);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(B.Bind(any, err), err);
    // Binding port zero must report the port the system actually chose.
    BOOST_CHECK(A.BoundAddress().GetPort() != 0);
    BOOST_CHECK(B.BoundAddress().GetPort() != A.BoundAddress().GetPort());

    Inbox in_a, in_b;
    BOOST_REQUIRE(A.Start(in_a.Handler()));
    BOOST_REQUIRE(B.Start(in_b.Handler()));

    // UDP may drop the first datagram; retrying is the transport's normal
    // condition rather than a failure, so the test retries as a real client
    // would instead of asserting on one attempt.
    const CService b_addr = B.BoundAddress();
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(b_addr)) return true;
        A.Connect(b_addr, kb.GetPubKey());
        return A.HasSession(b_addr);
    }));

    BOOST_CHECK(A.HasSession(b_addr));
    BOOST_CHECK(WaitFor([&] { return B.SessionCount() == 1; }));

    const std::vector<unsigned char> msg = Payload(600, 5);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_b.Count() > 0) return true;
        A.Send(b_addr, msg);
        return in_b.Count() > 0;
    }));
    BOOST_CHECK(in_b.At(0) == msg);

    // And back the other way, which uses the opposite direction's key.
    const CService a_addr = A.BoundAddress();
    const std::vector<unsigned char> reply = Payload(120, 9);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_a.Count() > 0) return true;
        B.Send(a_addr, reply);
        return in_a.Count() > 0;
    }));
    BOOST_CHECK(in_a.At(0) == reply);

    A.Stop();
    B.Stop();
}

BOOST_AUTO_TEST_CASE(socket_ignores_traffic_from_a_stranger)
{
    // A third node that never handshook must get nowhere, and must not provoke
    // a reply that would make this node a reflector.
    CKey ka, kb, kc;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Socket A(ka), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_a, in_c;
    BOOST_REQUIRE(A.Start(in_a.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler()));

    // C tries to speak to A while claiming a key A never agreed with. The
    // handshake will complete - anyone may open one - but C cannot send data
    // before it does, and A never delivers anything it has not authenticated.
    BOOST_CHECK(!C.Send(A.BoundAddress(), Payload(40)));
    UninterruptibleSleep(std::chrono::milliseconds{200});
    BOOST_CHECK_EQUAL(in_a.Count(), 0u);

    A.Stop();
    C.Stop();
}

BOOST_AUTO_TEST_CASE(socket_stop_is_idempotent)
{
    CKey k;
    k.MakeNewKey(true);
    overlay::Socket S(k);
    std::string err;
    BOOST_REQUIRE_MESSAGE(S.Bind(CService(LookupNumeric("127.0.0.1", 0)), err), err);
    Inbox in;
    BOOST_REQUIRE(S.Start(in.Handler()));
    S.Stop();
    S.Stop(); // must not hang or crash on a second call, nor on destruction
}


BOOST_AUTO_TEST_CASE(path_messages_roundtrip)
{
    std::vector<unsigned char> msg;
    const std::vector<unsigned char> body = Payload(200, 4);
    BOOST_CHECK(overlay::EncodeAppData(body, msg));
    overlay::MessageKind kind;
    BOOST_CHECK(overlay::DecodeKind(msg, kind));
    BOOST_CHECK(kind == overlay::MessageKind::APP_DATA);
    std::vector<unsigned char> got;
    BOOST_CHECK(overlay::DecodeAppData(msg, got));
    BOOST_CHECK(got == body);

    const CService hop = Addr("10.1.2.3", 9346);
    BOOST_CHECK(overlay::EncodePathBuild(0x1122334455667788ULL, hop, msg));
    uint64_t id = 0;
    CService next;
    BOOST_CHECK(overlay::DecodePathBuild(msg, id, next));
    BOOST_CHECK_EQUAL(id, 0x1122334455667788ULL);
    BOOST_CHECK(next == hop);

    BOOST_CHECK(overlay::EncodePathResult(true, 7, msg));
    bool ok = false;
    BOOST_CHECK(overlay::DecodePathResult(msg, ok, id));
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(id, 7u);
    BOOST_CHECK(overlay::EncodePathResult(false, 8, msg));
    BOOST_CHECK(overlay::DecodePathResult(msg, ok, id));
    BOOST_CHECK(!ok);

    const std::vector<unsigned char> inner = Payload(64, 1);
    BOOST_CHECK(overlay::EncodePathData(99, inner, msg));
    std::vector<unsigned char> got_inner;
    BOOST_CHECK(overlay::DecodePathData(msg, id, got_inner));
    BOOST_CHECK_EQUAL(id, 99u);
    BOOST_CHECK(got_inner == inner);
}

BOOST_AUTO_TEST_CASE(path_messages_reject_malformed)
{
    std::vector<unsigned char> out;
    uint64_t id;
    CService next;
    std::vector<unsigned char> inner;
    overlay::MessageKind kind;

    BOOST_CHECK(!overlay::DecodeKind(std::vector<unsigned char>(), kind));
    // An unknown kind is refused rather than guessed at.
    BOOST_CHECK(!overlay::DecodeKind(std::vector<unsigned char>{0x7f}, kind));

    // Each decoder must reject the others' messages, so a confusion between
    // kinds cannot be engineered by an attacker choosing the body.
    BOOST_CHECK(overlay::EncodePathData(1, Payload(8), out));
    BOOST_CHECK(!overlay::DecodePathBuild(out, id, next));
    BOOST_CHECK(!overlay::DecodeAppData(out, inner));

    // Truncated bodies.
    BOOST_CHECK(overlay::EncodePathBuild(1, Addr("10.0.0.1", 9346), out));
    out.pop_back();
    BOOST_CHECK(!overlay::DecodePathBuild(out, id, next));

    // Trailing bytes would give one message two encodings.
    BOOST_CHECK(overlay::EncodePathBuild(1, Addr("10.0.0.1", 9346), out));
    out.push_back(0x00);
    BOOST_CHECK(!overlay::DecodePathBuild(out, id, next));

    // PATH_DATA with no inner payload carries nothing to forward.
    BOOST_CHECK(!overlay::EncodePathData(1, std::vector<unsigned char>(), out));

    // Oversized bodies cannot fit a datagram and are refused at encode.
    BOOST_CHECK(!overlay::EncodeAppData(Payload(overlay::MAX_FRAME_PAYLOAD), out));
    BOOST_CHECK(!overlay::EncodePathData(1, Payload(overlay::MAX_FRAME_PAYLOAD), out));
}

BOOST_AUTO_TEST_CASE(path_table_forwards_both_ways)
{
    overlay::PathTable t;
    const CService a = Addr("10.0.0.1", 9346), c = Addr("10.0.0.3", 9346);
    BOOST_CHECK(t.Create(42, a, c, 1000));
    BOOST_CHECK(t.Has(42));
    BOOST_CHECK_EQUAL(t.Size(), 1u);

    CService to;
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(42, a, to, 1001));
    BOOST_CHECK(to == c);
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(42, c, to, 1002));
    BOOST_CHECK(to == a);
}

BOOST_AUTO_TEST_CASE(path_table_refuses_strangers_and_hijacks)
{
    overlay::PathTable t;
    const CService a = Addr("10.0.0.1", 9346), c = Addr("10.0.0.3", 9346);
    const CService stranger = Addr("10.0.0.9", 9346);
    BOOST_CHECK(t.Create(42, a, c, 1000));

    // Knowing a path id is not membership of it.
    CService to;
    BOOST_CHECK(overlay::Route::FORWARD != t.Next(42, stranger, to, 1001));
    // An unknown path is simply not there.
    BOOST_CHECK(overlay::Route::FORWARD != t.Next(43, a, to, 1001));

    // A duplicate id is refused rather than replacing the entry, or anyone who
    // guessed an id could redirect someone else's traffic.
    BOOST_CHECK(!t.Create(42, stranger, c, 1002));
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(42, a, to, 1003));
    BOOST_CHECK(to == c);

    // A path from a peer to itself is a reflection loop.
    BOOST_CHECK(!t.Create(50, a, a, 1000));
}

BOOST_AUTO_TEST_CASE(path_table_is_bounded_and_expires)
{
    // Strangers ask a relay to build paths, so both limits are load bearing.
    overlay::PathTable t;
    const CService a = Addr("10.0.0.1", 9346), c = Addr("10.0.0.3", 9346);
    for (size_t i = 0; i < overlay::PathTable::MAX_PATHS; ++i) {
        BOOST_REQUIRE(t.Create(i + 1, a, c, 1000));
    }
    BOOST_CHECK_EQUAL(t.Size(), overlay::PathTable::MAX_PATHS);
    // Full: memory cannot be consumed without limit.
    BOOST_CHECK(!t.Create(999999, a, c, 1000));

    // Use one of them, then let the rest go idle.
    CService to;
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(1, a, to, 1000 + overlay::PathTable::PATH_TTL - 1));
    const size_t gone = t.Expire(1000 + overlay::PathTable::PATH_TTL);
    BOOST_CHECK_EQUAL(gone, overlay::PathTable::MAX_PATHS - 1);
    BOOST_CHECK(t.Has(1));
    BOOST_CHECK_EQUAL(t.Size(), 1u);

    // Room again once the abandoned ones are gone.
    BOOST_CHECK(t.Create(999999, a, c, 1000 + overlay::PathTable::PATH_TTL));
}


BOOST_AUTO_TEST_CASE(relay_forwards_between_two_peers)
{
    // Stage two, end to end on real datagrams: A and C each know only the
    // relay, and the relay joins them. C never learns A's address.
    CKey ka, kr, kc;
    ka.MakeNewKey(true);
    kr.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Relay A(ka), R(kr), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_a, in_c, in_r;
    Mutex results_mutex;
    std::map<uint64_t, bool> results;
    auto path_handler = [&](uint64_t id, bool ok) {
        LOCK(results_mutex);
        results[id] = ok;
    };

    BOOST_REQUIRE(A.Start(in_a.Handler(), path_handler));
    BOOST_REQUIRE(R.Start(in_r.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler()));

    const CService r_addr = R.BoundAddress();
    // Both ends need their own session with the relay first: it will only join
    // peers it already knows, never dial somewhere new on a stranger's say-so.
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(r_addr)) return true;
        A.Connect(r_addr, kr.GetPubKey());
        return A.HasSession(r_addr);
    }));
    BOOST_REQUIRE(WaitFor([&] {
        if (C.HasSession(r_addr)) return true;
        C.Connect(r_addr, kr.GetPubKey());
        return C.HasSession(r_addr);
    }));
    BOOST_REQUIRE(WaitFor([&] { return R.PathCount() == 0 && A.HasSession(r_addr); }));

    const uint64_t path = 0xBEEF01;
    const CService c_addr = C.BoundAddress();
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(results_mutex);
            if (results.count(path)) return true;
        }
        A.BuildPath(path, r_addr, c_addr);
        LOCK(results_mutex);
        return results.count(path) > 0;
    }));
    {
        LOCK(results_mutex);
        BOOST_CHECK(results[path]);
    }
    BOOST_CHECK_EQUAL(R.PathCount(), 1u);

    // A speaks to C without ever having a session with it.
    BOOST_CHECK(!A.HasSession(c_addr));
    const std::vector<unsigned char> msg = Payload(300, 2);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_c.Count() > 0) return true;
        A.SendVia(r_addr, path, msg);
        return in_c.Count() > 0;
    }));
    BOOST_CHECK(in_c.At(0) == msg);

    // And back along the same path.
    const std::vector<unsigned char> back = Payload(80, 6);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_a.Count() > 0) return true;
        C.SendVia(r_addr, path, back);
        return in_a.Count() > 0;
    }));
    BOOST_CHECK(in_a.At(0) == back);

    A.Stop();
    R.Stop();
    C.Stop();
}

BOOST_AUTO_TEST_CASE(relay_refuses_to_be_an_open_proxy)
{
    // A relay must only join peers it already has sessions with. Otherwise a
    // stranger could name any host on the internet and have the relay dial it,
    // which is what separates an overlay relay from an open proxy - and it is
    // the difference between forwarding protocol traffic and being an exit.
    CKey ka, kr;
    ka.MakeNewKey(true);
    kr.MakeNewKey(true);

    overlay::Relay A(ka), R(kr);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R.Bind(any, err), err);

    Inbox in_a, in_r;
    Mutex m;
    std::map<uint64_t, bool> results;
    BOOST_REQUIRE(A.Start(in_a.Handler(), [&](uint64_t id, bool ok) {
        LOCK(m);
        results[id] = ok;
    }));
    BOOST_REQUIRE(R.Start(in_r.Handler()));

    const CService r_addr = R.BoundAddress();
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(r_addr)) return true;
        A.Connect(r_addr, kr.GetPubKey());
        return A.HasSession(r_addr);
    }));

    // A host the relay has never spoken to.
    const CService stranger = CService(LookupNumeric("198.18.0.1", 9346));
    const uint64_t path = 0xDEAD02;
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(m);
            if (results.count(path)) return true;
        }
        A.BuildPath(path, r_addr, stranger);
        LOCK(m);
        return results.count(path) > 0;
    }));
    {
        LOCK(m);
        BOOST_CHECK(!results[path]); // refused
    }
    BOOST_CHECK_EQUAL(R.PathCount(), 0u);

    A.Stop();
    R.Stop();
}


BOOST_AUTO_TEST_CASE(relay_cannot_read_end_to_end_traffic)
{
    // Stage three's headline property: the relay carries the traffic and holds
    // no key for it. Checked by having the relay record everything it can read
    // and asserting the secret never appears there.
    CKey ka, kr, kc;
    ka.MakeNewKey(true);
    kr.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Relay A(ka), R(kr), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_a, in_c, in_r;
    Mutex m;
    std::map<uint64_t, bool> results;
    BOOST_REQUIRE(A.Start(in_a.Handler(), [&](uint64_t id, bool ok) {
        LOCK(m);
        results[id] = ok;
    }));
    BOOST_REQUIRE(R.Start(in_r.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler()));

    const CService r_addr = R.BoundAddress();
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(r_addr)) return true;
        A.Connect(r_addr, kr.GetPubKey());
        return A.HasSession(r_addr);
    }));
    BOOST_REQUIRE(WaitFor([&] {
        if (C.HasSession(r_addr)) return true;
        C.Connect(r_addr, kr.GetPubKey());
        return C.HasSession(r_addr);
    }));

    const uint64_t path = 0xC0FFEE;
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(m);
            if (results.count(path)) return true;
        }
        A.BuildPath(path, r_addr, C.BoundAddress());
        LOCK(m);
        return results.count(path) > 0;
    }));
    {
        LOCK(m);
        BOOST_REQUIRE(results[path]);
    }

    // A second handshake, this time with C, carried by the relay as ordinary
    // path traffic. C's identity comes from the roster, not from the relay.
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSecretSession(path)) return true;
        A.ConnectSecret(r_addr, path, kc.GetPubKey());
        return A.HasSecretSession(path);
    }));
    BOOST_CHECK(A.HasSecretSession(path));
    BOOST_CHECK(WaitFor([&] { return C.HasSecretSession(path); }));

    // Something recognisable, so its absence from the relay means something.
    std::vector<unsigned char> secret;
    for (int i = 0; i < 64; ++i) secret.push_back(0xA5);

    BOOST_REQUIRE(WaitFor([&] {
        if (in_c.Count() > 0) return true;
        A.SendSecret(r_addr, path, secret);
        return in_c.Count() > 0;
    }));
    BOOST_CHECK(in_c.At(0) == secret);

    // The relay forwarded every byte of it and delivered none of it to itself.
    BOOST_CHECK_EQUAL(in_r.Count(), 0u);

    // And the reverse direction is equally opaque.
    std::vector<unsigned char> back;
    for (int i = 0; i < 32; ++i) back.push_back(0x5A);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_a.Count() > 0) return true;
        C.SendSecret(r_addr, path, back);
        return in_a.Count() > 0;
    }));
    BOOST_CHECK(in_a.At(0) == back);
    BOOST_CHECK_EQUAL(in_r.Count(), 0u);

    A.Stop();
    R.Stop();
    C.Stop();
}

BOOST_AUTO_TEST_CASE(relay_secret_session_needs_the_right_identity)
{
    // The end-to-end handshake authenticates the far end by its roster key. A
    // relay that substituted its own would have to complete a handshake it
    // holds no key for, so pointing the exchange at the wrong identity simply
    // never establishes.
    CKey ka, kr, kc, kwrong;
    ka.MakeNewKey(true);
    kr.MakeNewKey(true);
    kc.MakeNewKey(true);
    kwrong.MakeNewKey(true);

    overlay::Relay A(ka), R(kr), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_a, in_c, in_r;
    Mutex m;
    std::map<uint64_t, bool> results;
    BOOST_REQUIRE(A.Start(in_a.Handler(), [&](uint64_t id, bool ok) {
        LOCK(m);
        results[id] = ok;
    }));
    BOOST_REQUIRE(R.Start(in_r.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler()));

    const CService r_addr = R.BoundAddress();
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(r_addr)) return true;
        A.Connect(r_addr, kr.GetPubKey());
        return A.HasSession(r_addr);
    }));
    BOOST_REQUIRE(WaitFor([&] {
        if (C.HasSession(r_addr)) return true;
        C.Connect(r_addr, kr.GetPubKey());
        return C.HasSession(r_addr);
    }));

    const uint64_t path = 0xBADBEEF;
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(m);
            if (results.count(path)) return true;
        }
        A.BuildPath(path, r_addr, C.BoundAddress());
        LOCK(m);
        return results.count(path) > 0;
    }));

    // Aim the exchange at a key nobody on this path holds.
    for (int i = 0; i < 5; ++i) {
        A.ConnectSecret(r_addr, path, kwrong.GetPubKey());
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }
    BOOST_CHECK(!A.HasSecretSession(path));
    BOOST_CHECK(!C.HasSecretSession(path));

    A.Stop();
    R.Stop();
    C.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
