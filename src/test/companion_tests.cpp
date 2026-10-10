// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/policy.h>
#include <companion/protocol.h>
#include <companion/store.h>
#include <key.h>
#include <random.h>
#include <script/standard.h>
#include <util/system.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace companion;

BOOST_FIXTURE_TEST_SUITE(companion_tests, BasicTestingSetup)

namespace {

const int64_t NOW = 1790000000;

CKey NewKey()
{
    CKey k;
    k.MakeNewKey(true);
    return k;
}

uint256 Rand256()
{
    uint256 u;
    GetRandBytes(u.begin(), u.size());
    return u;
}

PairingTicket SomeTicket(size_t relays)
{
    PairingTicket t;
    t.network = "main";
    t.node = NewKey().GetPubKey();
    t.node_addr = "203.0.113.7:48931";
    t.token = Rand256();
    t.expires = NOW + 600;
    for (size_t i = 0; i < relays; ++i) {
        RelayEntry r;
        r.key = NewKey().GetPubKey();
        r.addr = "198.51.100." + std::to_string(10 + i) + ":48931";
        t.relays.push_back(r);
    }
    return t;
}

} // namespace

BOOST_AUTO_TEST_CASE(messages_say_exactly_one_thing)
{
    PrepareRequest p;
    p.to = "alice";
    p.amount = 5 * COIN;
    p.subtract_fee = true;
    const Message m = Make(Op::PREPARE, 7, p);
    Message back;
    BOOST_REQUIRE(DecodeMessage(EncodeMessage(m), back));
    BOOST_CHECK(back.op == Op::PREPARE);
    BOOST_CHECK_EQUAL(back.req, 7u);
    PrepareRequest q;
    BOOST_REQUIRE(Read(back, Op::PREPARE, q));
    BOOST_CHECK_EQUAL(q.to, "alice");
    BOOST_CHECK_EQUAL(q.amount, 5 * COIN);
    BOOST_CHECK(q.subtract_fee);

    // Read as another op, with bytes left over, or cut short: not the message.
    BOOST_CHECK(!Read(back, Op::SEND, q));
    Message longer = back;
    longer.body.push_back(0);
    BOOST_CHECK(!Read(longer, Op::PREPARE, q));
    Message shorter = back;
    shorter.body.pop_back();
    BOOST_CHECK(!Read(shorter, Op::PREPARE, q));

    // A destination longer than any address or name is refused on reading.
    p.to = std::string(MAX_DESTINATION + 1, 'a');
    BOOST_CHECK(!Read(Make(Op::PREPARE, 1, p), Op::PREPARE, q));

    // Unknown ops never decode.
    std::vector<unsigned char> raw = EncodeMessage(m);
    raw[0] = 0x7f;
    BOOST_CHECK(!DecodeMessage(raw, back));

    ResultAnswer r;
    BOOST_REQUIRE(Read(Result(3, true, "fine"), Op::RESULT, r));
    BOOST_CHECK(r.ok);
    BOOST_CHECK_EQUAL(r.text, "fine");
}

BOOST_AUTO_TEST_CASE(tickets_survive_a_qr_code_and_a_paste)
{
    const PairingTicket t = SomeTicket(TICKET_RELAYS);
    const std::string text = EncodeTicket(t);
    BOOST_CHECK(text.rfind(TICKET_PREFIX, 0) == 0);
    // QR alphanumeric mode: upper case, digits and the colon.
    for (const char c : text) BOOST_CHECK((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == ':' || c == '1');
    // Small enough to scan comfortably.
    BOOST_CHECK_LT(text.size(), 1100u);

    PairingTicket back;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DecodeTicket(text, back, error), error);
    BOOST_CHECK_EQUAL(back.network, t.network);
    BOOST_CHECK(back.node == t.node);
    BOOST_CHECK_EQUAL(back.node_addr, t.node_addr);
    BOOST_CHECK(back.token == t.token);
    BOOST_CHECK_EQUAL(back.expires, t.expires);
    BOOST_REQUIRE_EQUAL(back.relays.size(), t.relays.size());
    BOOST_CHECK(back.relays[3].key == t.relays[3].key);

    // Lower case, broken across lines by a chat app: still the same ticket.
    std::string pasted;
    for (size_t i = 0; i < text.size(); ++i) {
        pasted.push_back(std::tolower(static_cast<unsigned char>(text[i])));
        if (i % 60 == 59) pasted += "\r\n ";
    }
    BOOST_REQUIRE_MESSAGE(DecodeTicket(pasted, back, error), error);
    BOOST_CHECK(back.token == t.token);

    // Damaged, cut short, or not a ticket at all.
    std::string damaged = text;
    damaged[text.size() / 2] = damaged[text.size() / 2] == 'A' ? 'B' : 'A';
    PairingTicket dummy;
    // A changed character usually breaks the structure; when it does not, it
    // still cannot yield the same ticket.
    if (DecodeTicket(damaged, dummy, error)) {
        BOOST_CHECK(EncodeTicket(dummy) != text);
    }
    BOOST_CHECK(!DecodeTicket(text.substr(0, text.size() - 20), dummy, error));
    BOOST_CHECK(!DecodeTicket("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT", dummy, error));
    BOOST_CHECK(!DecodeTicket("", dummy, error));
}

BOOST_AUTO_TEST_CASE(pairing_code_binds_token_device_and_node)
{
    const uint256 token = Rand256();
    const CPubKey device = NewKey().GetPubKey();
    const CPubKey node = NewKey().GetPubKey();
    const std::string code = PairingCode(token, device, node);
    BOOST_CHECK_EQUAL(code.size(), 6u);
    for (const char c : code) BOOST_CHECK(c >= '0' && c <= '9');
    BOOST_CHECK_EQUAL(PairingCode(token, device, node), code);

    // Someone else answering the same ticket shows a different code. One in a
    // million collides, so this compares against several.
    int same = 0;
    for (int i = 0; i < 5; ++i) {
        if (PairingCode(token, NewKey().GetPubKey(), node) == code) ++same;
        if (PairingCode(Rand256(), device, node) == code) ++same;
        if (PairingCode(token, device, NewKey().GetPubKey()) == code) ++same;
    }
    BOOST_CHECK_LE(same, 1);
}

BOOST_AUTO_TEST_CASE(send_signature_binds_the_whole_payment)
{
    const CKey device = NewKey();
    const CPubKey node = NewKey().GetPubKey();
    const uint256 id = Rand256();
    const CScript payee = GetScriptForDestination(PKHash(NewKey().GetPubKey()));
    const uint256 digest = SendDigest(node, id, payee, 3 * COIN, 1000);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(device.Sign(digest, sig));
    BOOST_CHECK(device.GetPubKey().Verify(digest, sig));

    // Any part changed - another home node, payment, payee, amount or fee -
    // and the same signature no longer fits.
    const CScript other = GetScriptForDestination(PKHash(NewKey().GetPubKey()));
    BOOST_CHECK(!device.GetPubKey().Verify(SendDigest(NewKey().GetPubKey(), id, payee, 3 * COIN, 1000), sig));
    BOOST_CHECK(!device.GetPubKey().Verify(SendDigest(node, Rand256(), payee, 3 * COIN, 1000), sig));
    BOOST_CHECK(!device.GetPubKey().Verify(SendDigest(node, id, other, 3 * COIN, 1000), sig));
    BOOST_CHECK(!device.GetPubKey().Verify(SendDigest(node, id, payee, 3 * COIN + 1, 1000), sig));
    BOOST_CHECK(!device.GetPubKey().Verify(SendDigest(node, id, payee, 3 * COIN, 1001), sig));
}

BOOST_AUTO_TEST_CASE(pins_are_six_to_twelve_digits)
{
    BOOST_CHECK(ValidPin("123456"));
    BOOST_CHECK(ValidPin("000000000000"));
    BOOST_CHECK(!ValidPin("12345"));
    BOOST_CHECK(!ValidPin("1234567890123"));
    BOOST_CHECK(!ValidPin("12345a"));
    BOOST_CHECK(!ValidPin("123 456"));
    BOOST_CHECK(!ValidPin(""));
}

BOOST_AUTO_TEST_CASE(limits_count_a_rolling_day)
{
    std::string reason;
    Limits limits;
    BOOST_CHECK(!ValidLimits(limits, reason)); // nothing set is not "no limit"
    limits.per_tx = 10 * COIN;
    limits.per_day = 5 * COIN;
    BOOST_CHECK(!ValidLimits(limits, reason));
    limits.per_day = 25 * COIN;
    BOOST_CHECK(ValidLimits(limits, reason));

    std::vector<Spend> spends;
    BOOST_CHECK(WithinLimits(limits, spends, 10 * COIN, NOW, reason));
    BOOST_CHECK(!WithinLimits(limits, spends, 10 * COIN + 1, NOW, reason));
    BOOST_CHECK(reason.find("one payment") != std::string::npos);
    BOOST_CHECK(!WithinLimits(limits, spends, 0, NOW, reason));

    // 20 spent: 8 just inside the window, 12 well inside; 5 more fits, 6 does not.
    spends.push_back(Spend{NOW - SPEND_WINDOW + 1, 8 * COIN, Rand256()});
    spends.push_back(Spend{NOW - 3600, 12 * COIN, Rand256()});
    spends.push_back(Spend{NOW - SPEND_WINDOW, 9 * COIN, Rand256()}); // just outside
    BOOST_CHECK_EQUAL(SpentInWindow(spends, NOW), 20 * COIN);
    BOOST_CHECK(WithinLimits(limits, spends, 5 * COIN, NOW, reason));
    BOOST_CHECK(!WithinLimits(limits, spends, 5 * COIN + 1, NOW, reason));
    BOOST_CHECK(reason.find("left of this phone's limit") != std::string::npos);
    // A second later the 8 has left the window.
    BOOST_CHECK(WithinLimits(limits, spends, 10 * COIN, NOW + 1, reason));

    PruneSpends(spends, NOW);
    BOOST_CHECK_EQUAL(spends.size(), 2u);
}

BOOST_AUTO_TEST_CASE(pin_verifiers_are_salted_and_keyed)
{
    const uint256 secret = Rand256();
    const PinVerifier v = MakePinVerifier("482916", secret);
    BOOST_CHECK(CheckPin(v, "482916", secret));
    BOOST_CHECK(!CheckPin(v, "482917", secret));
    BOOST_CHECK(!CheckPin(v, "482916", Rand256())); // the database without the node secret
    const PinVerifier w = MakePinVerifier("482916", secret);
    BOOST_CHECK(w.salt != v.salt);
    BOOST_CHECK(w.hash != v.hash);
    BOOST_CHECK(!CheckPin(PinVerifier(), "482916", secret));
}

BOOST_AUTO_TEST_CASE(pin_attempts_are_capped_across_devices)
{
    AttemptLimiter limiter(3, 60);
    BOOST_CHECK(limiter.Allow(NOW));
    BOOST_CHECK(limiter.Allow(NOW + 1));
    BOOST_CHECK(limiter.Allow(NOW + 2));
    BOOST_CHECK(!limiter.Allow(NOW + 3));
    BOOST_CHECK(!limiter.Allow(NOW + 59));
    BOOST_CHECK(limiter.Allow(NOW + 60));
}

BOOST_AUTO_TEST_CASE(store_keeps_devices_and_its_secret)
{
    const fs::path dir = GetDataDir() / "companion";
    const CKey a = NewKey(), b = NewKey();
    uint256 secret;
    {
        Store store(dir);
        secret = store.Secret();
        BOOST_CHECK(!secret.IsNull());

        Device d;
        d.key = a.GetPubKey();
        d.name = "Pixel";
        d.created = NOW;
        d.limits = Limits{2 * COIN, 10 * COIN};
        d.pin = MakePinVerifier("123456", secret);
        d.spends.push_back(Spend{NOW, COIN, Rand256()});
        BOOST_REQUIRE(store.Put(d));
        d.key = b.GetPubKey();
        d.name = "Librem";
        BOOST_REQUIRE(store.Put(d));
        BOOST_CHECK_EQUAL(store.All().size(), 2u);
    }
    // Reopened: the same secret, so the same PINs still check.
    Store store(dir);
    BOOST_CHECK(store.Secret() == secret);
    Device got;
    BOOST_REQUIRE(store.Get(a.GetPubKey(), got));
    BOOST_CHECK_EQUAL(got.name, "Pixel");
    BOOST_CHECK_EQUAL(got.limits.per_day, 10 * COIN);
    BOOST_REQUIRE_EQUAL(got.spends.size(), 1u);
    BOOST_CHECK(CheckPin(got.pin, "123456", store.Secret()));
    BOOST_CHECK(!got.Locked());
    got.failures = MAX_PIN_FAILURES;
    BOOST_CHECK(got.Locked());

    BOOST_REQUIRE(store.Erase(a.GetPubKey()));
    BOOST_CHECK(!store.Get(a.GetPubKey(), got));
    const std::vector<Device> left = store.All();
    BOOST_REQUIRE_EQUAL(left.size(), 1u);
    BOOST_CHECK_EQUAL(left[0].name, "Librem");
}

BOOST_AUTO_TEST_SUITE_END()
