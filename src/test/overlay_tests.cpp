// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/frame.h>
#include <overlay/handshake.h>
#include <overlay/session.h>
#include <overlay/path.h>
#include <overlay/relay.h>
#include <overlay/rendezvous.h>
#include <overlay/select.h>
#include <set>
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
    BOOST_CHECK(i.Seal(Payload(overlay::MAX_SESSION_PAYLOAD), d));
    BOOST_CHECK_EQUAL(d.size(), overlay::SAFE_DATAGRAM);
    BOOST_CHECK(!i.Seal(Payload(overlay::MAX_SESSION_PAYLOAD + 1), d));
    // A refused seal must not have consumed a counter.
    BOOST_CHECK_EQUAL(i.FramesSent(), 1u);
}

BOOST_AUTO_TEST_CASE(session_pads_away_message_length)
{
    // Content is encrypted but length is not, and lengths alone fingerprint
    // traffic. Payloads inside one bucket must be indistinguishable on the wire.
    Parties p;
    BOOST_CHECK(p.Run());
    overlay::Session i(p.ikeys), r(p.rkeys);

    std::vector<unsigned char> a, b;
    BOOST_CHECK(i.Seal(Payload(1), a));
    BOOST_CHECK(i.Seal(Payload(40), b));
    BOOST_CHECK_EQUAL(a.size(), b.size());

    // And every size still round-trips exactly, padding stripped.
    const size_t sizes[] = {0, 1, 61, 62, 63, 254, 300, 638, 700,
                            overlay::MAX_SESSION_PAYLOAD};
    for (size_t n = 0; n < sizeof(sizes) / sizeof(sizes[0]); ++n) {
        const std::vector<unsigned char> msg = Payload(sizes[n], 3);
        std::vector<unsigned char> sealed, got;
        BOOST_REQUIRE(i.Seal(msg, sealed));
        BOOST_REQUIRE_MESSAGE(r.Open(sealed.data(), sealed.size(), got),
                              "size " << sizes[n] << " did not open");
        BOOST_CHECK_MESSAGE(got == msg, "size " << sizes[n] << " round-tripped wrong");
        // Only a handful of distinct sizes ever appear on the wire.
        BOOST_CHECK_EQUAL(sealed.size(),
                          overlay::PaddedSize(sizes[n]) + overlay::FRAME_OVERHEAD);
    }
}

BOOST_AUTO_TEST_CASE(session_padding_buckets_are_few_and_bounded)
{
    // The point of buckets is that many lengths collapse onto few. If this
    // grew, padding would stop hiding anything.
    std::set<size_t> distinct;
    for (size_t n = 0; n <= overlay::MAX_SESSION_PAYLOAD; ++n) {
        distinct.insert(overlay::PaddedSize(n));
    }
    BOOST_CHECK_LE(distinct.size(), 4u);
    // The largest bucket must still fit a datagram once sealed.
    BOOST_CHECK_EQUAL(overlay::PaddedSize(overlay::MAX_SESSION_PAYLOAD),
                      overlay::MAX_FRAME_PAYLOAD);
    // Padding never shrinks a message below what it needs.
    for (size_t n = 0; n <= overlay::MAX_SESSION_PAYLOAD; n += 37) {
        BOOST_CHECK_GE(overlay::PaddedSize(n), n + overlay::SESSION_LENGTH_PREFIX);
    }
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

overlay::Hop H(const CService& s) { return overlay::Hop::Direct(s); }

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

//! A node that is not a relay shows the relay it connects to a key made for
//! that connection, so the relay learns where it is and not who: a fresh one
//! each time, so not across addresses either. The relay still proves itself.
BOOST_AUTO_TEST_CASE(throwaway_hop_keys)
{
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), moved = Addr("10.0.0.9", 9346), ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka), B(kb), B2(kb);
    const auto introduce = [&](const CService& from, overlay::Transport& b, bool throwaway) {
        std::vector<unsigned char> m1, reply, payload, none, none2;
        BOOST_REQUIRE(A.Connect(ba, kb.GetPubKey(), m1, throwaway));
        BOOST_REQUIRE(b.Receive(from, m1.data(), m1.size(), reply, payload) == overlay::Transport::Result::ESTABLISHED);
        BOOST_REQUIRE(A.Receive(ba, reply.data(), reply.size(), none, none2) == overlay::Transport::Result::ESTABLISHED);
    };

    introduce(aa, B, true);
    BOOST_CHECK(A.PeerIdentity(ba) == kb.GetPubKey());
    const CPubKey first = B.PeerIdentity(aa);
    BOOST_CHECK(first.IsValid());
    BOOST_CHECK(first != ka.GetPubKey());

    // The same node from another address: another key, nothing to match.
    A.Forget(ba);
    introduce(moved, B2, true);
    const CPubKey second = B2.PeerIdentity(moved);
    BOOST_CHECK(second.IsValid());
    BOOST_CHECK(second != ka.GetPubKey());
    BOOST_CHECK(second != first);

    // A relay, or a radio neighbour: its own key again.
    A.Forget(ba);
    overlay::Transport B3(kb);
    introduce(aa, B3, false);
    BOOST_CHECK(B3.PeerIdentity(aa) == ka.GetPubKey());
}

BOOST_AUTO_TEST_CASE(quiet_hop_sessions_are_doubted)
{
    // A relay that restarts forgets its half of every session and says
    // nothing. What is left on this side must stop being trusted, or every
    // path sent through it vanishes.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    const CService aa = Addr("10.0.0.1", 9346), ba = Addr("10.0.0.2", 9346);
    overlay::Transport A(ka), B(kb);
    int64_t now = 1700000000;
    SetMockTime(now);
    Introduce(A, aa, B, kb, ba);
    BOOST_CHECK(A.Live(ba, now));
    BOOST_CHECK(B.Live(aa, now));

    // Quiet for a minute: doubted, though nothing is known to be wrong.
    BOOST_CHECK(A.Live(ba, now + overlay::HOP_QUIET - 1));
    BOOST_CHECK(!A.Live(ba, now + overlay::HOP_QUIET));
    BOOST_CHECK(!A.Live(Addr("10.0.0.3", 9346), now)); // no session at all

    // A word from the peer, and it is trusted again.
    now += overlay::HOP_QUIET;
    SetMockTime(now);
    const std::vector<unsigned char> msg = Payload(40, 1);
    std::vector<unsigned char> dgram, reply, got;
    BOOST_REQUIRE(B.Send(aa, msg, dgram));
    BOOST_REQUIRE(A.Receive(ba, dgram.data(), dgram.size(), reply, got) == overlay::Transport::Result::PAYLOAD);
    BOOST_CHECK(A.Live(ba, now));

    // The peer restarts. What A sends is dropped there without an answer...
    overlay::Transport B2(kb);
    BOOST_REQUIRE(A.Send(ba, msg, dgram));
    BOOST_CHECK(B2.Receive(aa, dgram.data(), dgram.size(), reply, got) == overlay::Transport::Result::IGNORED);
    BOOST_CHECK(reply.empty());
    // ...and once it has waited long enough, A doubts the session.
    BOOST_CHECK(A.Live(ba, now + overlay::HOP_ANSWER - 1));
    BOOST_CHECK(!A.Live(ba, now + overlay::HOP_ANSWER));
    BOOST_CHECK(A.HasSession(ba)); // still there: only a handshake can tell

    // Shaking hands again settles it.
    now += overlay::HOP_ANSWER;
    SetMockTime(now);
    Introduce(A, aa, B2, kb, ba);
    BOOST_CHECK(A.Live(ba, now));
    BOOST_REQUIRE(A.Send(ba, msg, dgram));
    BOOST_CHECK(B2.Receive(aa, dgram.data(), dgram.size(), reply, got) == overlay::Transport::Result::PAYLOAD);
    BOOST_CHECK(got == msg);
    SetMockTime(0);
}

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

    /** For a bare Socket, which reports the address a datagram came from. */
    overlay::Socket::PayloadHandler SocketHandler()
    {
        return [this](const CService&, std::vector<unsigned char>&& p) {
            LOCK(mutex);
            items.push_back(std::move(p));
        };
    }
    /** For a Relay, where the sender may be a path rather than an address. */
    overlay::Relay::AppHandler Handler()
    {
        return [this](const overlay::Hop&, std::vector<unsigned char>&& p) {
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
    BOOST_REQUIRE(A.Start(in_a.SocketHandler()));
    BOOST_REQUIRE(B.Start(in_b.SocketHandler()));

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
    BOOST_REQUIRE(A.Start(in_a.SocketHandler()));
    BOOST_REQUIRE(C.Start(in_c.SocketHandler()));

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
    BOOST_REQUIRE(S.Start(in.SocketHandler()));
    S.Stop();
    S.Stop(); // must not hang or crash on a second call, nor on destruction
}

#ifndef __APPLE__ // macOS sets up only 127.0.0.1 on its loopback
BOOST_AUTO_TEST_CASE(socket_answers_from_the_address_it_was_written_to)
{
    // A node listening on every address, written to at one of several. On
    // Linux and Windows the whole of 127.0.0.0/8 is this computer, and a plain
    // reply to a peer at 127.0.0.1 leaves from 127.0.0.1, not from the
    // 127.0.0.2 the peer wrote to: the peer never hears its handshake
    // answered. The same happens to a relay with two addresses on a network.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);

    overlay::Socket A(ka), B(kb);
    std::string err;
    BOOST_REQUIRE_MESSAGE(A.Bind(CService(LookupNumeric("0.0.0.0", 0)), err), err);
    BOOST_REQUIRE_MESSAGE(B.Bind(CService(LookupNumeric("127.0.0.1", 0)), err), err);
    Inbox in_a, in_b;
    BOOST_REQUIRE(A.Start(in_a.SocketHandler()));
    BOOST_REQUIRE(B.Start(in_b.SocketHandler()));

    const CService a_second = CService(LookupNumeric("127.0.0.2", A.BoundAddress().GetPort()));
    BOOST_REQUIRE(WaitFor([&] {
        if (B.HasSession(a_second)) return true;
        B.Connect(a_second, ka.GetPubKey());
        return B.HasSession(a_second);
    }));

    // A knows which of its addresses B wrote to, and data back leaves from it too.
    const CService b_addr = B.BoundAddress();
    const overlay::Socket::LocalAddress local = A.LocalAddressFor(b_addr);
    BOOST_CHECK_EQUAL(local.family, AF_INET);
    BOOST_CHECK_EQUAL(local.addr[3], 2);
    const std::vector<unsigned char> reply = Payload(80, 3);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_b.Count() > 0) return true;
        A.Send(b_addr, reply);
        return in_b.Count() > 0;
    }));
    BOOST_CHECK(in_b.At(0) == reply);

    A.Stop();
    B.Stop();
}
#endif


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
    BOOST_CHECK(t.Create(42, H(a), H(c), 1000));
    BOOST_CHECK(t.Has(42));
    BOOST_CHECK_EQUAL(t.Size(), 1u);

    overlay::Hop to;
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(42, H(a), to, 1001));
    BOOST_CHECK(to == H(c));
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(42, H(c), to, 1002));
    BOOST_CHECK(to == H(a));
}

BOOST_AUTO_TEST_CASE(path_table_refuses_strangers_and_hijacks)
{
    overlay::PathTable t;
    const CService a = Addr("10.0.0.1", 9346), c = Addr("10.0.0.3", 9346);
    const CService stranger = Addr("10.0.0.9", 9346);
    BOOST_CHECK(t.Create(42, H(a), H(c), 1000));

    // Knowing a path id is not membership of it.
    overlay::Hop to;
    BOOST_CHECK(overlay::Route::FORWARD != t.Next(42, H(stranger), to, 1001));
    // An unknown path is simply not there.
    BOOST_CHECK(overlay::Route::FORWARD != t.Next(43, H(a), to, 1001));

    // A duplicate id is refused rather than replacing the entry, or anyone who
    // guessed an id could redirect someone else's traffic.
    BOOST_CHECK(!t.Create(42, H(stranger), H(c), 1002));
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(42, H(a), to, 1003));
    BOOST_CHECK(to == H(c));

    // A path from a peer to itself is a reflection loop.
    BOOST_CHECK(!t.Create(50, H(a), H(a), 1000));
}

BOOST_AUTO_TEST_CASE(path_table_is_bounded_and_expires)
{
    // Strangers ask a relay to build paths, so both limits are load bearing.
    overlay::PathTable t;
    const CService a = Addr("10.0.0.1", 9346), c = Addr("10.0.0.3", 9346);
    for (size_t i = 0; i < overlay::PathTable::MAX_PATHS; ++i) {
        BOOST_REQUIRE(t.Create(i + 1, H(a), H(c), 1000));
    }
    BOOST_CHECK_EQUAL(t.Size(), overlay::PathTable::MAX_PATHS);
    // Full: memory cannot be consumed without limit.
    BOOST_CHECK(!t.Create(999999, H(a), H(c), 1000));

    // Use one of them, then let the rest go idle.
    overlay::Hop to;
    BOOST_CHECK(overlay::Route::FORWARD == t.Next(1, H(a), to, 1000 + overlay::PathTable::PATH_TTL - 1));
    const size_t gone = t.Expire(1000 + overlay::PathTable::PATH_TTL);
    BOOST_CHECK_EQUAL(gone, overlay::PathTable::MAX_PATHS - 1);
    BOOST_CHECK(t.Has(1));
    BOOST_CHECK_EQUAL(t.Size(), 1u);

    // Room again once the abandoned ones are gone.
    BOOST_CHECK(t.Create(999999, H(a), H(c), 1000 + overlay::PathTable::PATH_TTL));
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
        A.BuildPath(path, H(r_addr), c_addr);
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
        A.SendOnPath(path, msg);
        return in_c.Count() > 0;
    }));
    BOOST_CHECK(in_c.At(0) == msg);

    // And back along the same path.
    const std::vector<unsigned char> back = Payload(80, 6);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_a.Count() > 0) return true;
        C.SendOnPath(path, back);
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
        A.BuildPath(path, H(r_addr), stranger);
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
        A.BuildPath(path, H(r_addr), C.BoundAddress());
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
        A.ConnectSecret(path, kc.GetPubKey());
        return A.HasSecretSession(path);
    }));
    BOOST_CHECK(A.HasSecretSession(path));
    BOOST_CHECK(WaitFor([&] { return C.HasSecretSession(path); }));

    // Something recognisable, so its absence from the relay means something.
    std::vector<unsigned char> secret;
    for (int i = 0; i < 64; ++i) secret.push_back(0xA5);

    BOOST_REQUIRE(WaitFor([&] {
        if (in_c.Count() > 0) return true;
        A.SendSecret(path, secret);
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
        C.SendSecret(path, back);
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
        A.BuildPath(path, H(r_addr), C.BoundAddress());
        LOCK(m);
        return results.count(path) > 0;
    }));

    // Aim the exchange at a key nobody on this path holds.
    for (int i = 0; i < 5; ++i) {
        A.ConnectSecret(path, kwrong.GetPubKey());
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }
    BOOST_CHECK(!A.HasSecretSession(path));
    BOOST_CHECK(!C.HasSecretSession(path));

    A.Stop();
    R.Stop();
    C.Stop();
}


BOOST_AUTO_TEST_CASE(relay_two_hop_path_splits_the_knowledge)
{
    // A -> R1 -> R2 -> C. The property one hop cannot give: neither relay is in
    // a position to know both ends. R1 sees A but not C; R2 sees C but reaches
    // A only as a path, having no address for it at all.
    CKey ka, k1, k2, kc;
    ka.MakeNewKey(true);
    k1.MakeNewKey(true);
    k2.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Relay A(ka), R1(k1), R2(k2), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R1.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R2.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_a, in_1, in_2, in_c;
    Mutex m;
    std::map<uint64_t, bool> results;
    auto note = [&](uint64_t id, bool ok) {
        LOCK(m);
        results[id] = ok;
    };
    BOOST_REQUIRE(A.Start(in_a.Handler(), note));
    BOOST_REQUIRE(R1.Start(in_1.Handler()));
    BOOST_REQUIRE(R2.Start(in_2.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler()));

    const CService a1 = R1.BoundAddress(), a2 = R2.BoundAddress(), ac = C.BoundAddress();

    // Adjacent sessions: A-R1, R1-R2, R2-C. Each relay only ever joins peers it
    // already knows, so the chain has to exist before a path can use it.
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(a1)) return true;
        A.Connect(a1, k1.GetPubKey());
        return A.HasSession(a1);
    }));
    BOOST_REQUIRE(WaitFor([&] {
        if (R1.HasSession(a2)) return true;
        R1.Connect(a2, k2.GetPubKey());
        return R1.HasSession(a2);
    }));
    BOOST_REQUIRE(WaitFor([&] {
        if (R2.HasSession(ac)) return true;
        R2.Connect(ac, kc.GetPubKey());
        return R2.HasSession(ac);
    }));

    // First leg: A asks R1 to carry to R2, then talks to R2 through it.
    const uint64_t p1 = 0x1111;
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(m);
            if (results.count(p1)) return true;
        }
        A.BuildPath(p1, H(a1), a2);
        LOCK(m);
        return results.count(p1) > 0;
    }));
    {
        LOCK(m);
        BOOST_REQUIRE(results[p1]);
    }
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSecretSession(p1)) return true;
        A.ConnectSecret(p1, k2.GetPubKey());
        return A.HasSecretSession(p1);
    }));

    // Second leg: the request to extend travels through the first, so R2 is
    // asked by a path rather than by an address.
    const uint64_t p2 = 0x2222;
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(m);
            if (results.count(p2)) return true;
        }
        A.BuildPath(p2, overlay::Hop::Path(p1), ac);
        LOCK(m);
        return results.count(p2) > 0;
    }, 10000));
    {
        LOCK(m);
        BOOST_REQUIRE(results[p2]);
    }

    // End to end with C, two relays away.
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSecretSession(p2)) return true;
        A.ConnectSecret(p2, kc.GetPubKey());
        return A.HasSecretSession(p2);
    }, 10000));
    BOOST_CHECK(WaitFor([&] { return C.HasSecretSession(p2); }));

    std::vector<unsigned char> secret;
    for (int i = 0; i < 48; ++i) secret.push_back(0x7E);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_c.Count() > 0) return true;
        A.SendSecret(p2, secret);
        return in_c.Count() > 0;
    }, 10000));
    BOOST_CHECK(in_c.At(0) == secret);

    // Neither relay read a byte of it.
    BOOST_CHECK_EQUAL(in_1.Count(), 0u);
    BOOST_CHECK_EQUAL(in_2.Count(), 0u);

    // And the reverse direction works, which exercises the return leg through
    // both tunnels.
    std::vector<unsigned char> back;
    for (int i = 0; i < 24; ++i) back.push_back(0xE7);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_a.Count() > 0) return true;
        C.SendSecret(p2, back);
        return in_a.Count() > 0;
    }, 10000));
    BOOST_CHECK(in_a.At(0) == back);
    BOOST_CHECK_EQUAL(in_1.Count(), 0u);
    BOOST_CHECK_EQUAL(in_2.Count(), 0u);

    // A never spoke to R2 or C directly, and C never spoke to A.
    BOOST_CHECK(!A.HasSession(a2));
    BOOST_CHECK(!A.HasSession(ac));
    BOOST_CHECK(!C.HasSession(A.BoundAddress()));

    A.Stop();
    R1.Stop();
    R2.Stop();
    C.Stop();
}


namespace {

roster::KeyBytes RvKey(unsigned char fill, unsigned char tail = 0)
{
    roster::KeyBytes k;
    k.fill(fill);
    k[31] = tail;
    return k;
}

std::vector<roster::KeyBytes> RvRoster(size_t n)
{
    std::vector<roster::KeyBytes> r;
    for (size_t i = 0; i < n; ++i) {
        r.push_back(RvKey(static_cast<unsigned char>(i / 256),
                          static_cast<unsigned char>(i % 256)));
    }
    std::sort(r.begin(), r.end()); // canonical order, as the roster supplies it
    return r;
}

} // namespace

BOOST_AUTO_TEST_CASE(rendezvous_both_sides_compute_the_same_points)
{
    // The whole point: nobody is asked, so nobody can answer selectively. Two
    // parties with the same roster reach the same meeting points every time.
    const std::vector<roster::KeyBytes> roster = RvRoster(50);
    const roster::KeyBytes service = RvKey(0xAA, 0x01);

    const std::vector<roster::KeyBytes> mine =
        overlay::RendezvousPoints(service, 7, roster);
    const std::vector<roster::KeyBytes> theirs =
        overlay::RendezvousPoints(service, 7, roster);
    BOOST_CHECK(mine == theirs);
    BOOST_CHECK_EQUAL(mine.size(), overlay::RENDEZVOUS_POINTS);

    // Distinct relays, so losing one does not lose the service.
    std::set<roster::KeyBytes> distinct(mine.begin(), mine.end());
    BOOST_CHECK_EQUAL(distinct.size(), mine.size());
    for (size_t i = 0; i < mine.size(); ++i) {
        BOOST_CHECK(std::find(roster.begin(), roster.end(), mine[i]) != roster.end());
    }
}

BOOST_AUTO_TEST_CASE(rendezvous_rotates_and_differs_per_service)
{
    const std::vector<roster::KeyBytes> roster = RvRoster(200);
    const roster::KeyBytes a = RvKey(0x11, 0x01);
    const roster::KeyBytes b = RvKey(0x22, 0x02);

    // Rotation stops an adversary installing itself as one service's meeting
    // point permanently and simply waiting.
    BOOST_CHECK(overlay::RendezvousPoints(a, 1, roster) !=
                overlay::RendezvousPoints(a, 2, roster));
    // Two services do not share a fate.
    BOOST_CHECK(overlay::RendezvousPoints(a, 1, roster) !=
                overlay::RendezvousPoints(b, 1, roster));
}

BOOST_AUTO_TEST_CASE(rendezvous_spreads_across_the_roster)
{
    // If the draw favoured part of the roster, an adversary could sit there.
    // Not a statistical proof, but it would catch a derivation that collapsed
    // onto a handful of relays.
    const std::vector<roster::KeyBytes> roster = RvRoster(64);
    std::set<roster::KeyBytes> hit;
    for (uint64_t epoch = 0; epoch < 60; ++epoch) {
        for (unsigned char s = 0; s < 20; ++s) {
            const std::vector<roster::KeyBytes> pts =
                overlay::RendezvousPoints(RvKey(s, s), epoch, roster);
            hit.insert(pts.begin(), pts.end());
        }
    }
    // Nearly the whole roster should get used across many services and epochs.
    BOOST_CHECK_GT(hit.size(), roster.size() * 3 / 4);
}

BOOST_AUTO_TEST_CASE(rendezvous_handles_small_and_empty_rosters)
{
    const roster::KeyBytes service = RvKey(0x33, 0x03);

    // Bootstrap: no relays means nowhere to meet, which is a state rather than
    // an error.
    BOOST_CHECK(overlay::RendezvousPoints(service, 1,
                                          std::vector<roster::KeyBytes>()).empty());

    // A roster smaller than the number of points wanted yields all of it and
    // does not spin looking for more.
    const std::vector<roster::KeyBytes> two = RvRoster(2);
    const std::vector<roster::KeyBytes> pts = overlay::RendezvousPoints(service, 1, two);
    BOOST_CHECK_EQUAL(pts.size(), 2u);
    std::set<roster::KeyBytes> distinct(pts.begin(), pts.end());
    BOOST_CHECK_EQUAL(distinct.size(), 2u);

    // One relay, one point.
    BOOST_CHECK_EQUAL(overlay::RendezvousPoints(service, 1, RvRoster(1)).size(), 1u);
    // Asking for none gets none.
    BOOST_CHECK(overlay::RendezvousPoints(service, 1, two, 0).empty());
}

BOOST_AUTO_TEST_CASE(rendezvous_epoch_follows_height)
{
    BOOST_CHECK_EQUAL(overlay::RendezvousEpoch(0), 0u);
    BOOST_CHECK_EQUAL(overlay::RendezvousEpoch(overlay::RENDEZVOUS_EPOCH_BLOCKS - 1), 0u);
    BOOST_CHECK_EQUAL(overlay::RendezvousEpoch(overlay::RENDEZVOUS_EPOCH_BLOCKS), 1u);
    // By height rather than clock, so nodes agree without synchronised time.
    BOOST_CHECK_EQUAL(overlay::RendezvousEpoch(overlay::RENDEZVOUS_EPOCH_BLOCKS * 5 + 3), 5u);
    // A height before genesis is not a thing, and must not underflow.
    BOOST_CHECK_EQUAL(overlay::RendezvousEpoch(-1), 0u);
}

BOOST_AUTO_TEST_CASE(rendezvous_survives_rosters_that_differ_a_little)
{
    // Two nodes rarely hold exactly the same relay set - one has seen a
    // revocation the other has not, or reads a listing a block later. With a
    // draw by modulo one relay more or less moved every point and they never
    // met; scored, they still share all but at most one.
    const std::vector<roster::KeyBytes> roster = RvRoster(50);
    const roster::KeyBytes service = RvKey(0xAA, 0x01);
    const std::vector<roster::KeyBytes> pts = overlay::RendezvousPoints(service, 7, roster);

    // Order does not matter.
    std::vector<roster::KeyBytes> shuffled(roster.rbegin(), roster.rend());
    BOOST_CHECK(overlay::RendezvousPoints(service, 7, shuffled) == pts);

    auto shared = [](const std::vector<roster::KeyBytes>& a, const std::vector<roster::KeyBytes>& b) {
        size_t n = 0;
        for (const roster::KeyBytes& k : a) n += std::count(b.begin(), b.end(), k);
        return n;
    };
    for (size_t drop = 0; drop < roster.size(); ++drop) {
        std::vector<roster::KeyBytes> fewer = roster;
        fewer.erase(fewer.begin() + drop);
        BOOST_CHECK_GE(shared(pts, overlay::RendezvousPoints(service, 7, fewer)), pts.size() - 1);
    }
    std::vector<roster::KeyBytes> more = roster;
    more.push_back(RvKey(0xFE, 0xFE));
    BOOST_CHECK_GE(shared(pts, overlay::RendezvousPoints(service, 7, more)), pts.size() - 1);

    // A service is never its own meeting point: it would have to take its
    // visitors at its own address.
    std::vector<roster::KeyBytes> with_self = roster;
    with_self.push_back(service);
    for (uint64_t epoch = 0; epoch < 50; ++epoch) {
        const std::vector<roster::KeyBytes> p = overlay::RendezvousPoints(service, epoch, with_self);
        BOOST_CHECK(std::find(p.begin(), p.end(), service) == p.end());
    }
}

BOOST_AUTO_TEST_CASE(rendezvous_epochs_overlap_at_their_edges)
{
    const int E = overlay::RENDEZVOUS_EPOCH_BLOCKS;
    // The relay set is read a few blocks before the epoch starts.
    BOOST_CHECK_EQUAL(overlay::RendezvousAnchor(0), 0);
    BOOST_CHECK_EQUAL(overlay::RendezvousAnchor(2), 2 * E - overlay::RENDEZVOUS_ANCHOR_DEPTH);

    using V = std::vector<uint64_t>;
    // Mid-epoch: one epoch only.
    BOOST_CHECK(overlay::EpochsToRegister(2 * E + 200) == V({2}));
    // From the next epoch's anchor, its points too, so a visitor a block ahead finds it.
    BOOST_CHECK(overlay::EpochsToRegister(3 * E - overlay::RENDEZVOUS_ANCHOR_DEPTH - 1) == V({2}));
    BOOST_CHECK(overlay::EpochsToRegister(3 * E - overlay::RENDEZVOUS_ANCHOR_DEPTH) == V({2, 3}));
    // Into a new epoch: the old one's points for a while, for visitors behind.
    BOOST_CHECK(overlay::EpochsToRegister(3 * E) == V({3, 2}));
    BOOST_CHECK(overlay::EpochsToRegister(3 * E + overlay::RENDEZVOUS_OVERLAP - 1) == V({3, 2}));
    BOOST_CHECK(overlay::EpochsToRegister(3 * E + overlay::RENDEZVOUS_OVERLAP) == V({3}));
    // The first epoch has no previous one.
    BOOST_CHECK(overlay::EpochsToRegister(0) == V({0}));
    BOOST_CHECK(overlay::EpochsToRegister(-1).empty());

    // A visitor tries its own epoch, then the one before.
    BOOST_CHECK(overlay::EpochsToTry(3 * E + 5) == V({3, 2}));
    BOOST_CHECK(overlay::EpochsToTry(5) == V({0}));
}


BOOST_AUTO_TEST_CASE(rendezvous_client_reaches_a_service_that_never_published_an_address)
{
    // The whole design in one test. S is reachable at a meeting point it never
    // told anyone about - the point was computed from its roster key. C works
    // out the same point by the same arithmetic, asks nobody, and is spliced to
    // S. Neither learns the other's address, and no relay reads the traffic.
    //
    //   S -> R1 -> RV <- R2 <- C
    CKey ks, k1, krv, k2, kc;
    ks.MakeNewKey(true);
    k1.MakeNewKey(true);
    krv.MakeNewKey(true);
    k2.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Relay S(ks), R1(k1), RV(krv), R2(k2), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(S.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R1.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(RV.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R2.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_s, in_1, in_rv, in_2, in_c;
    Mutex m;
    std::map<uint64_t, bool> results;
    auto note = [&](uint64_t id, bool ok) {
        LOCK(m);
        results[id] = ok;
    };
    BOOST_REQUIRE(S.Start(in_s.Handler(), note));
    BOOST_REQUIRE(R1.Start(in_1.Handler()));
    BOOST_REQUIRE(RV.Start(in_rv.Handler()));
    BOOST_REQUIRE(R2.Start(in_2.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler(), note));

    const CService a1 = R1.BoundAddress(), arv = RV.BoundAddress();
    const CService a2 = R2.BoundAddress();

    auto dial = [&](overlay::Relay& from, const CService& to, const CKey& to_key) {
        BOOST_REQUIRE(WaitFor([&] {
            if (from.HasSession(to)) return true;
            from.Connect(to, to_key.GetPubKey());
            return from.HasSession(to);
        }));
    };
    dial(S, a1, k1);
    dial(R1, arv, krv);
    dial(C, a2, k2);
    dial(R2, arv, krv);

    auto build = [&](overlay::Relay& who, uint64_t id, const CService& via,
                     const CService& dest, const CKey& dest_key, bool anonymous) {
        BOOST_REQUIRE(WaitFor([&] {
            {
                LOCK(m);
                if (results.count(id)) return true;
            }
            who.BuildPath(id, H(via), dest);
            LOCK(m);
            return results.count(id) > 0;
        }, 10000));
        {
            LOCK(m);
            BOOST_REQUIRE(results[id]);
        }
        BOOST_REQUIRE(WaitFor([&] {
            if (who.HasSecretSession(id)) return true;
            who.ConnectSecret(id, dest_key.GetPubKey(), anonymous);
            return who.HasSecretSession(id);
        }, 10000));
    };

    // Each side reaches the meeting point through one relay, so the meeting
    // point never learns where either of them is. The service shows the
    // meeting point its roster key, which registering requires; the client
    // stays anonymous.
    const uint64_t p_s = 0xA1, p_c = 0xB1;
    build(S, p_s, a1, arv, krv, /* anonymous */ false);
    build(C, p_c, a2, arv, krv, /* anonymous */ true);

    // The service registers under its roster identity - 32 bytes, the same
    // x-only key the roster publishes.
    const CPubKey s_pub = ks.GetPubKey();
    roster::KeyBytes service;
    std::copy(s_pub.begin() + 1, s_pub.begin() + 33, service.begin());

    BOOST_REQUIRE(WaitFor([&] {
        if (RV.IntroductionCount() > 0) return true;
        S.Introduce(p_s, service);
        return RV.IntroductionCount() > 0;
    }, 10000));
    BOOST_CHECK_EQUAL(RV.IntroductionCount(), 1u);

    // C asks to be spliced. It looked nothing up: in a live network the
    // meeting point comes from RendezvousPoints over the roster.
    const uint64_t meet = 0xEE01;
    BOOST_REQUIRE(WaitFor([&] {
        {
            LOCK(m);
            if (results.count(meet)) return true;
        }
        C.Meet(p_c, service, meet);
        LOCK(m);
        return results.count(meet) > 0;
    }, 10000));
    {
        LOCK(m);
        BOOST_REQUIRE(results[meet]);
    }

    // End to end across the splice, authenticated by the service's roster key.
    BOOST_REQUIRE(WaitFor([&] {
        if (C.HasSecretSession(meet)) return true;
        C.ConnectSecret(meet, s_pub);
        return C.HasSecretSession(meet);
    }, 15000));
    BOOST_CHECK(WaitFor([&] { return S.HasSecretSession(meet); }));

    std::vector<unsigned char> hello;
    for (int i = 0; i < 40; ++i) hello.push_back(0x3C);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_s.Count() > 0) return true;
        C.SendSecret(meet, hello);
        return in_s.Count() > 0;
    }, 15000));
    BOOST_CHECK(in_s.At(0) == hello);

    // No relay on either side read a byte, the meeting point included.
    BOOST_CHECK_EQUAL(in_1.Count(), 0u);
    BOOST_CHECK_EQUAL(in_2.Count(), 0u);
    BOOST_CHECK_EQUAL(in_rv.Count(), 0u);

    // And neither end ever held a session with the other, or with the other's
    // relay - which is what "never published an address" means in practice.
    BOOST_CHECK(!C.HasSession(S.BoundAddress()));
    BOOST_CHECK(!S.HasSession(C.BoundAddress()));
    BOOST_CHECK(!C.HasSession(a1));
    BOOST_CHECK(!S.HasSession(a2));

    S.Stop();
    R1.Stop();
    RV.Stop();
    R2.Stop();
    C.Stop();
}


BOOST_AUTO_TEST_CASE(socket_meters_inbound_handshakes)
{
    // A responder does two Diffie-Hellman operations before it learns anything
    // about who is asking, so an unmetered handshake is free CPU for whoever
    // sends it. This is the one place a limit helps: past it the work is done.
    CKey ka, kb;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);

    overlay::Socket A(ka), B(kb);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(B.Bind(any, err), err);

    Inbox in_a, in_b;
    BOOST_REQUIRE(A.Start(in_a.SocketHandler()));
    BOOST_REQUIRE(B.Start(in_b.SocketHandler()));
    BOOST_CHECK_EQUAL(B.HandshakesRefused(), 0u);

    // Far more attempts than the per-source allowance, as fast as they go.
    const CService b_addr = B.BoundAddress();
    for (int i = 0; i < 60; ++i) A.Connect(b_addr, kb.GetPubKey());
    BOOST_CHECK(WaitFor([&] { return B.HandshakesRefused() > 0; }, 3000));

    // Refused before any key agreement, which is the whole point - counting
    // sessions would prove nothing, since sessions are keyed by address and one
    // source can only ever produce one.
    BOOST_CHECK_GT(B.HandshakesRefused(), 0u);

    A.Stop();
    B.Stop();
}

BOOST_AUTO_TEST_CASE(socket_flood_does_not_lock_out_an_honest_peer)
{
    // The limit must refuse excess without refusing everyone: a second peer
    // arriving during a flood still gets through, because the global cap is far
    // above the per-source one.
    CKey ka, kb, kc;
    ka.MakeNewKey(true);
    kb.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Socket A(ka), B(kb), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(B.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    Inbox in_a, in_b, in_c;
    BOOST_REQUIRE(A.Start(in_a.SocketHandler()));
    BOOST_REQUIRE(B.Start(in_b.SocketHandler()));
    BOOST_REQUIRE(C.Start(in_c.SocketHandler()));

    const CService b_addr = B.BoundAddress();
    for (int i = 0; i < 60; ++i) A.Connect(b_addr, kb.GetPubKey());
    BOOST_CHECK(WaitFor([&] { return B.HandshakesRefused() > 0; }, 3000));

    // C retries with a backoff longer than the round trip, because each attempt
    // discards the one before it - a tight loop never completes.
    BOOST_REQUIRE(WaitFor([&] {
        if (C.HasSession(b_addr)) return true;
        C.Connect(b_addr, kb.GetPubKey());
        UninterruptibleSleep(std::chrono::milliseconds{150});
        return C.HasSession(b_addr);
    }, 8000));
    BOOST_CHECK(C.HasSession(b_addr));

    A.Stop();
    B.Stop();
    C.Stop();
}


namespace {

overlay::RelayCandidate Cand(unsigned char id, const char* ip)
{
    overlay::RelayCandidate c;
    c.key.fill(id);
    c.addr = CService(LookupNumeric(ip, 9346));
    return c;
}

/** A roster spread across distinct address blocks. */
std::vector<overlay::RelayCandidate> SpreadRoster(size_t n)
{
    std::vector<overlay::RelayCandidate> r;
    for (size_t i = 0; i < n; ++i) {
        char ip[32];
        snprintf(ip, sizeof(ip), "%u.%u.0.1",
                 (unsigned)(11 + i / 200), (unsigned)(1 + i % 200));
        r.push_back(Cand(static_cast<unsigned char>(i), ip));
    }
    return r;
}

} // namespace

BOOST_AUTO_TEST_CASE(select_keeps_its_entry_relays)
{
    // The counterintuitive rule: entry relays are kept, not rotated. Rotating
    // them would make an adversary's chance of being seen at least once rise
    // toward certainty over many paths.
    overlay::PathSelector sel;
    sel.SetRelays(SpreadRoster(40));

    std::vector<overlay::RelayCandidate> first;
    BOOST_REQUIRE(sel.Select(3, first));
    const std::vector<overlay::RelayCandidate> guards = sel.Guards();
    BOOST_CHECK_EQUAL(guards.size(), overlay::PathSelector::GUARD_COUNT);

    for (int i = 0; i < 50; ++i) {
        std::vector<overlay::RelayCandidate> path;
        BOOST_REQUIRE(sel.Select(3, path));
        BOOST_CHECK_EQUAL(path.size(), 3u);
        // The entry is always one of the held guards, every time.
        bool from_guards = false;
        for (size_t g = 0; g < guards.size(); ++g) {
            if (path[0].key == guards[g].key) from_guards = true;
        }
        BOOST_CHECK(from_guards);
    }
    // And the guard set did not drift over fifty paths.
    BOOST_CHECK(sel.Guards() == guards);
}

BOOST_AUTO_TEST_CASE(select_rotates_the_later_hops)
{
    // Later hops are fresh per path: rotating them costs nothing, and an
    // adversary who is not the entry learns far less by being one.
    overlay::PathSelector sel;
    sel.SetRelays(SpreadRoster(40));

    std::set<roster::KeyBytes> seen;
    for (int i = 0; i < 40; ++i) {
        std::vector<overlay::RelayCandidate> path;
        BOOST_REQUIRE(sel.Select(3, path));
        seen.insert(path[2].key);
    }
    // The exit position should have moved around a lot across forty paths.
    BOOST_CHECK_GT(seen.size(), 5u);
}

BOOST_AUTO_TEST_CASE(select_refuses_two_hops_behind_one_operator)
{
    // Two relays in one address block are plausibly one party, and a path
    // through both is a path with one hop.
    std::vector<overlay::RelayCandidate> same_block;
    for (unsigned char i = 0; i < 8; ++i) {
        char ip[32];
        snprintf(ip, sizeof(ip), "12.34.0.%u", (unsigned)(i + 1));
        same_block.push_back(Cand(i, ip));
    }
    overlay::PathSelector sel;
    sel.SetRelays(same_block);

    std::vector<overlay::RelayCandidate> path;
    // One hop is all this roster can honestly supply.
    BOOST_CHECK(sel.Select(1, path));
    // Two is refused rather than quietly satisfied with the same operator
    // twice, which would leave the caller believing something untrue.
    BOOST_CHECK(!sel.Select(2, path));
    BOOST_CHECK(path.empty());
}

BOOST_AUTO_TEST_CASE(select_survives_a_guard_going_down)
{
    overlay::PathSelector sel;
    sel.SetRelays(SpreadRoster(40));
    std::vector<overlay::RelayCandidate> path;
    BOOST_REQUIRE(sel.Select(2, path));

    const std::vector<overlay::RelayCandidate> before = sel.Guards();
    BOOST_REQUIRE_EQUAL(before.size(), 2u);
    sel.DropGuard(before[0].key);
    BOOST_CHECK_EQUAL(sel.Guards().size(), 1u);

    // A replacement is drawn, and the surviving guard is still held - losing
    // one must not reshuffle the other.
    BOOST_REQUIRE(sel.Select(2, path));
    const std::vector<overlay::RelayCandidate> after = sel.Guards();
    BOOST_CHECK_EQUAL(after.size(), 2u);
    bool survivor_kept = false;
    for (size_t i = 0; i < after.size(); ++i) {
        if (after[i].key == before[1].key) survivor_kept = true;
    }
    BOOST_CHECK(survivor_kept);
}

BOOST_AUTO_TEST_CASE(select_keeps_guards_across_a_roster_change)
{
    // A guard that rotated whenever the roster shifted would give back the
    // cumulative exposure it exists to prevent.
    overlay::PathSelector sel;
    const std::vector<overlay::RelayCandidate> roster = SpreadRoster(40);
    sel.SetRelays(roster);
    std::vector<overlay::RelayCandidate> path;
    BOOST_REQUIRE(sel.Select(2, path));
    const std::vector<overlay::RelayCandidate> guards = sel.Guards();

    // The roster grows; guards must not move.
    sel.SetRelays(SpreadRoster(80));
    BOOST_CHECK(sel.Guards() == guards);

    // A guard leaving the roster is dropped, because it is no longer eligible.
    std::vector<overlay::RelayCandidate> without;
    const std::vector<overlay::RelayCandidate> all = SpreadRoster(40);
    for (size_t i = 0; i < all.size(); ++i) {
        if (!(all[i].key == guards[0].key)) without.push_back(all[i]);
    }
    sel.SetRelays(without);
    BOOST_CHECK_EQUAL(sel.Guards().size(), guards.size() - 1);
}

BOOST_AUTO_TEST_CASE(select_handles_an_empty_or_tiny_roster)
{
    overlay::PathSelector sel;
    std::vector<overlay::RelayCandidate> path;
    // Bootstrap: no relays is a state, not an error.
    BOOST_CHECK(!sel.Select(1, path));
    BOOST_CHECK_EQUAL(sel.CandidateCount(), 0u);

    sel.SetRelays(SpreadRoster(1));
    BOOST_CHECK(sel.Select(1, path));
    BOOST_CHECK_EQUAL(path.size(), 1u);
    // Asking for more than exists is refused.
    BOOST_CHECK(!sel.Select(2, path));
    // Asking for none is refused too, rather than returning an empty path a
    // caller might treat as usable.
    BOOST_CHECK(!sel.Select(0, path));
}

namespace {

/** Collects payloads together with the hop each came from. */
struct HopInbox {
    Mutex mutex;
    std::vector<std::pair<overlay::Hop, std::vector<unsigned char>>> items;

    overlay::Relay::AppHandler Handler()
    {
        return [this](const overlay::Hop& h, std::vector<unsigned char>&& p) {
            LOCK(mutex);
            items.emplace_back(h, std::move(p));
        };
    }
    size_t Count()
    {
        LOCK(mutex);
        return items.size();
    }
    std::pair<overlay::Hop, std::vector<unsigned char>> At(size_t i)
    {
        LOCK(mutex);
        return items.at(i);
    }
};

/** A dial policy from a fixed roster of (address, key). */
overlay::Relay::DialPolicy Listed(const std::vector<std::pair<CService, CPubKey>>& listed)
{
    return [listed](const CService& dest, const CPubKey& key) {
        for (const std::pair<CService, CPubKey>& l : listed) {
            if (l.first == dest && l.second == key) return true;
        }
        return false;
    };
}

overlay::RelayCandidate LocalCand(unsigned char id, uint16_t port)
{
    overlay::RelayCandidate c;
    c.key.fill(id);
    c.addr = CService(LookupNumeric("127.0.0.1", port));
    return c;
}

} // namespace

BOOST_AUTO_TEST_CASE(relay_three_hop_circuit_through_relays_it_had_to_dial)
{
    // A -> R1 -> R2 -> R3 -> C, the shape of every path a node now builds.
    // Nobody was connected beforehand: each relay dials the next because the
    // roster lists it there with that key, and only because it does.
    CKey ka, k1, k2, k3, kc;
    ka.MakeNewKey(true);
    k1.MakeNewKey(true);
    k2.MakeNewKey(true);
    k3.MakeNewKey(true);
    kc.MakeNewKey(true);

    overlay::Relay A(ka), R1(k1), R2(k2), R3(k3), C(kc);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R1.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R2.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R3.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(C.Bind(any, err), err);

    HopInbox in_a, in_c;
    Inbox in_1, in_2, in_3;
    BOOST_REQUIRE(A.Start(in_a.Handler()));
    BOOST_REQUIRE(R1.Start(in_1.Handler()));
    BOOST_REQUIRE(R2.Start(in_2.Handler()));
    BOOST_REQUIRE(R3.Start(in_3.Handler()));
    BOOST_REQUIRE(C.Start(in_c.Handler()));

    const CService a1 = R1.BoundAddress(), a2 = R2.BoundAddress(), a3 = R3.BoundAddress();
    const CService ac = C.BoundAddress();
    const overlay::Relay::DialPolicy roster = Listed({{a1, k1.GetPubKey()}, {a2, k2.GetPubKey()},
                                                      {a3, k3.GetPubKey()}, {ac, kc.GetPubKey()}});
    R1.SetDialPolicy(roster);
    R2.SetDialPolicy(roster);
    R3.SetDialPolicy(roster);

    std::vector<overlay::Relay::CircuitHop> hops(4);
    hops[0].addr = a1;
    hops[0].key = k1.GetPubKey();
    hops[1].addr = a2;
    hops[1].key = k2.GetPubKey();
    hops[2].addr = a3;
    hops[2].key = k3.GetPubKey();
    hops[3].addr = ac;
    hops[3].key = kc.GetPubKey();
    uint64_t path = 0;
    BOOST_REQUIRE_MESSAGE(A.BuildCircuit(hops, path, err, std::chrono::milliseconds{6000}), err);
    BOOST_CHECK_EQUAL(A.CircuitLegs(path).size(), 3u);
    BOOST_CHECK(WaitFor([&] { return C.HasSecretSession(path); }));

    // The largest payload a path carries arrives whole. One byte more does
    // not fit inside three layers and is refused rather than truncated.
    const std::vector<unsigned char> big(overlay::MAX_PATH_APP_PAYLOAD, 0x5A);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_c.Count() > 0) return true;
        A.SendSecret(path, big);
        return in_c.Count() > 0;
    }, 10000));
    BOOST_CHECK(in_c.At(0).second == big);
    BOOST_CHECK(!A.SendSecret(path, std::vector<unsigned char>(overlay::MAX_PATH_APP_PAYLOAD + 1, 0x5A)));

    // And back, on the path C was reached by.
    const overlay::Hop back = in_c.At(0).first;
    BOOST_REQUIRE(back.via_path);
    BOOST_CHECK_EQUAL(back.path, path);
    const std::vector<unsigned char> reply(100, 0xA5);
    BOOST_REQUIRE(WaitFor([&] {
        if (in_a.Count() > 0) return true;
        C.SendSecret(back.path, reply);
        return in_a.Count() > 0;
    }, 10000));
    BOOST_CHECK(in_a.At(0).second == reply);

    // No relay read a byte.
    BOOST_CHECK_EQUAL(in_1.Count(), 0u);
    BOOST_CHECK_EQUAL(in_2.Count(), 0u);
    BOOST_CHECK_EQUAL(in_3.Count(), 0u);

    // C cannot tell who built the path: the key proved to it was made for that
    // one handshake. The same holds at R2 and R3, which A also reached end to
    // end.
    const CPubKey seen = C.SecretPeerIdentity(path);
    BOOST_CHECK(seen.IsValid());
    BOOST_CHECK(seen != ka.GetPubKey());

    // Only the entry relay ever spoke to A directly.
    BOOST_CHECK(A.HasSession(a1));
    BOOST_CHECK(!A.HasSession(a2));
    BOOST_CHECK(!A.HasSession(a3));
    BOOST_CHECK(!A.HasSession(ac));
    BOOST_CHECK(!R2.HasSession(A.BoundAddress()));
    BOOST_CHECK(!R3.HasSession(A.BoundAddress()));
    BOOST_CHECK(!C.HasSession(A.BoundAddress()));

    // Closing forgets it here.
    A.ClosePath(A.CircuitLegs(path));
    BOOST_CHECK(!A.HasSecretSession(path));

    A.Stop();
    R1.Stop();
    R2.Stop();
    R3.Stop();
    C.Stop();
}

BOOST_AUTO_TEST_CASE(relay_dials_only_what_the_roster_lists)
{
    CKey ka, k1, kx, ku, kwrong;
    ka.MakeNewKey(true);
    k1.MakeNewKey(true);
    kx.MakeNewKey(true);
    ku.MakeNewKey(true);
    kwrong.MakeNewKey(true);

    overlay::Relay A(ka), R1(k1), X(kx), U(ku);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(A.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R1.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(X.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(U.Bind(any, err), err);
    Inbox in_a, in_1, in_x, in_u;
    BOOST_REQUIRE(A.Start(in_a.Handler()));
    BOOST_REQUIRE(R1.Start(in_1.Handler()));
    BOOST_REQUIRE(X.Start(in_x.Handler()));
    BOOST_REQUIRE(U.Start(in_u.Handler()));

    const CService a1 = R1.BoundAddress(), ax = X.BoundAddress(), au = U.BoundAddress();
    R1.SetDialPolicy(Listed({{ax, kx.GetPubKey()}}));
    BOOST_REQUIRE(WaitFor([&] {
        if (A.HasSession(a1)) return true;
        A.Connect(a1, k1.GetPubKey());
        return A.HasSession(a1);
    }));

    // Named with a key the roster does not list there: refused, not dialled.
    BOOST_REQUIRE(A.BuildPath(0x31, H(a1), ax, kwrong.GetPubKey()));
    BOOST_CHECK_EQUAL(A.AwaitPath(0x31, std::chrono::milliseconds{3000}), 0);
    BOOST_CHECK(!R1.HasSession(ax));
    BOOST_CHECK(!R1.HasPendingHandshake(ax));

    // A relay the roster does not list at all: refused, not dialled.
    BOOST_REQUIRE(A.BuildPath(0x32, H(a1), au, ku.GetPubKey()));
    BOOST_CHECK_EQUAL(A.AwaitPath(0x32, std::chrono::milliseconds{3000}), 0);
    BOOST_CHECK(!R1.HasSession(au));

    // Named as listed: dialled, then joined.
    BOOST_REQUIRE(A.BuildPath(0x33, H(a1), ax, kx.GetPubKey()));
    BOOST_CHECK_EQUAL(A.AwaitPath(0x33, std::chrono::milliseconds{5000}), 1);
    BOOST_CHECK(R1.HasSession(ax));
    // Asked again, as after a lost answer: granted again, not refused as a
    // duplicate - the path exists.
    BOOST_REQUIRE(A.BuildPath(0x33, H(a1), ax, kx.GetPubKey()));
    BOOST_CHECK_EQUAL(A.AwaitPath(0x33, std::chrono::milliseconds{3000}), 1);

    // Without a key, only an existing session is joined, as before.
    BOOST_REQUIRE(A.BuildPath(0x34, H(a1), au));
    BOOST_CHECK_EQUAL(A.AwaitPath(0x34, std::chrono::milliseconds{3000}), 0);

    A.Stop();
    R1.Stop();
    X.Stop();
    U.Stop();
}

BOOST_AUTO_TEST_CASE(meeting_point_registers_only_the_service_itself)
{
    // A service registering at its meeting point has to be that service. With
    // anonymous path sessions now the default, anyone could otherwise claim
    // any key and be spliced to its clients.
    CKey ks, k1, krv, kother;
    ks.MakeNewKey(true);
    k1.MakeNewKey(true);
    krv.MakeNewKey(true);
    kother.MakeNewKey(true);
    overlay::Relay S(ks), R1(k1), RV(krv);
    std::string err;
    const CService any = CService(LookupNumeric("127.0.0.1", 0));
    BOOST_REQUIRE_MESSAGE(S.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(R1.Bind(any, err), err);
    BOOST_REQUIRE_MESSAGE(RV.Bind(any, err), err);
    Inbox in_s, in_1, in_rv;
    BOOST_REQUIRE(S.Start(in_s.Handler()));
    BOOST_REQUIRE(R1.Start(in_1.Handler()));
    BOOST_REQUIRE(RV.Start(in_rv.Handler()));
    const CService a1 = R1.BoundAddress(), arv = RV.BoundAddress();
    R1.SetDialPolicy(Listed({{arv, krv.GetPubKey()}}));

    std::vector<overlay::Relay::CircuitHop> hops(2);
    hops[0].addr = a1;
    hops[0].key = k1.GetPubKey();
    hops[1].addr = arv;
    hops[1].key = krv.GetPubKey();
    uint64_t anon = 0;
    BOOST_REQUIRE_MESSAGE(S.BuildCircuit(hops, anon, err), err);

    roster::KeyBytes service, other;
    const CPubKey s_pub = ks.GetPubKey(), o_pub = kother.GetPubKey();
    std::copy(s_pub.begin() + 1, s_pub.end(), service.begin());
    std::copy(o_pub.begin() + 1, o_pub.end(), other.begin());

    // Over an anonymous session, nothing registers - not even the truth.
    for (int i = 0; i < 5; ++i) {
        S.Introduce(anon, service);
        S.Introduce(anon, other);
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }
    BOOST_CHECK_EQUAL(RV.IntroductionCount(), 0u);

    // A path whose far end was shown the service's own key registers that
    // key, and no other.
    const uint64_t named = 0x5151;
    BOOST_REQUIRE(S.BuildPath(named, H(a1), arv, krv.GetPubKey()));
    BOOST_REQUIRE_EQUAL(S.AwaitPath(named, std::chrono::milliseconds{5000}), 1);
    BOOST_REQUIRE(WaitFor([&] {
        if (S.HasSecretSession(named)) return true;
        S.ConnectSecret(named, krv.GetPubKey(), /* anonymous */ false);
        return S.HasSecretSession(named);
    }, 10000));
    for (int i = 0; i < 5; ++i) {
        S.Introduce(named, other);
        UninterruptibleSleep(std::chrono::milliseconds{50});
    }
    BOOST_CHECK_EQUAL(RV.IntroductionCount(), 0u);
    BOOST_CHECK(WaitFor([&] {
        if (RV.IntroductionCount() > 0) return true;
        S.Introduce(named, service);
        return RV.IntroductionCount() > 0;
    }, 10000));
    BOOST_CHECK_EQUAL(RV.IntroductionCount(), 1u);

    S.Stop();
    R1.Stop();
    RV.Stop();
}

BOOST_AUTO_TEST_CASE(select_builds_three_hops_around_the_destination)
{
    BOOST_CHECK_EQUAL(overlay::DEFAULT_PATH_HOPS, 3u);
    const std::vector<overlay::RelayCandidate> roster = SpreadRoster(6);
    overlay::PathSelector sel;
    sel.SetRelays(roster);
    sel.SetSelf(roster[0].key);

    for (int i = 0; i < 40; ++i) {
        const overlay::RelayCandidate& dest = roster[1 + i % 5];
        std::vector<overlay::RelayCandidate> path;
        BOOST_REQUIRE(sel.Select(overlay::DEFAULT_PATH_HOPS, path, dest));
        BOOST_CHECK_EQUAL(path.size(), 3u);
        for (const overlay::RelayCandidate& hop : path) {
            // Never through the destination, and never through itself.
            BOOST_CHECK(!(hop.key == dest.key));
            BOOST_CHECK(!(hop.key == roster[0].key));
        }
    }

    // A destination run by the same operator as a relay - here the same /16 -
    // keeps that relay off the path: it would make the path one hop shorter
    // than it claims to be.
    overlay::RelayCandidate twin = Cand(99, "11.2.0.9"); // roster[1] is 11.2.0.1
    std::vector<overlay::RelayCandidate> wide = roster;
    wide.push_back(twin);
    sel.SetRelays(wide);
    for (int i = 0; i < 20; ++i) {
        std::vector<overlay::RelayCandidate> path;
        BOOST_REQUIRE(sel.Select(3, path, twin));
        for (const overlay::RelayCandidate& hop : path) BOOST_CHECK(!(hop.key == roster[1].key));
    }

    // Itself, the destination and two others are not enough for three.
    overlay::PathSelector small;
    small.SetRelays(SpreadRoster(4));
    small.SetSelf(SpreadRoster(4)[0].key);
    std::vector<overlay::RelayCandidate> path;
    BOOST_CHECK(!small.Select(3, path, SpreadRoster(4)[1]));
}

BOOST_AUTO_TEST_CASE(select_counts_local_relays_only_when_told_to)
{
    // On regtest every node is 127.0.0.1. The address manager calls that one
    // group, which is right on a real network and would make every test path
    // impossible; regtest counts each address and port as its own operator.
    std::vector<overlay::RelayCandidate> roster;
    for (unsigned char i = 0; i < 5; ++i) roster.push_back(LocalCand(i, 20000 + i));
    std::vector<overlay::RelayCandidate> path;

    overlay::PathSelector strict;
    strict.SetRelays(roster);
    BOOST_CHECK(!strict.Select(3, path));

    overlay::PathSelector local(overlay::PathSelector::GUARD_COUNT, /* local_relays */ true);
    local.SetRelays(roster);
    BOOST_CHECK(local.Select(3, path, roster[4]));
    BOOST_CHECK_EQUAL(path.size(), 3u);
}

BOOST_AUTO_TEST_SUITE_END()
