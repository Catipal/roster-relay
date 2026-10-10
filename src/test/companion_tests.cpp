// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/policy.h>
#include <companion/protocol.h>
#include <companion/service.h>
#include <companion/store.h>
#include <companion/wallethook.h>
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

namespace {

/**
 * An allowance wallet with no wallet behind it: it records what it was asked
 * to do, so the service's rules can be checked without coins or a chain.
 */
struct FakeWallet {
    CAmount balance{50 * COIN};
    CAmount fee{1000};
    bool reject_send{false};
    int prepared{0};
    int sent{0};
    int cancelled{0};
    uint256 next_txid;

    WalletHooks Hooks()
    {
        WalletHooks h;
        h.status = [this](const std::string&, CAmount& b, CAmount& p, std::string&) {
            b = balance;
            p = 0;
            return true;
        };
        h.new_address = [](const std::string&, std::string& address, std::string&) {
            address = "bpsaddress";
            return true;
        };
        h.history = [](const std::string&, size_t, size_t, std::vector<HistoryItem>&, std::string&) { return true; };
        h.prepare = [this](const std::string&, const std::string& to, CAmount amount, bool subtract_fee,
                           PreparedPayment& out, std::string& error) {
            if (to == "nobody") {
                error = "nobody does not take payments by name.";
                return false;
            }
            ++prepared;
            out = PreparedPayment();
            out.amount = subtract_fee ? amount - fee : amount;
            out.fee = fee;
            out.payee = to;
            out.payee_script = CScript() << OP_TRUE << std::vector<unsigned char>(to.begin(), to.end());
            return true;
        };
        h.send = [this](const std::string&, const PreparedPayment&, uint256& txid, bool& rejected, std::string& error) {
            if (reject_send) {
                rejected = true;
                error = "The network refused it. Nothing was spent.";
                return false;
            }
            ++sent;
            txid = next_txid = Rand256();
            return true;
        };
        h.cancel = [this](const std::string&, const PreparedPayment&) { ++cancelled; };
        return h;
    }
};

/** A service on its own: no overlay, no chain, a fake wallet. */
struct ServiceFixture {
    CKey node = NewKey();
    CKey device = NewKey();
    FakeWallet wallet;
    std::unique_ptr<Service> service;

    explicit ServiceFixture(const fs::path& dir)
    {
        SetWalletHooks(wallet.Hooks());
        NodeHooks hooks;
        hooks.height = [] { return 1234; };
        hooks.relays = [] {
            std::vector<RelayEntry> r(3);
            for (RelayEntry& e : r) {
                e.key = NewKey().GetPubKey();
                e.addr = "198.51.100.1:48931";
            }
            return r;
        };
        service = MakeUnique<Service>(dir, "allowance", node.GetPubKey(), hooks, /* memory_only */ true);
    }
    ~ServiceFixture() { SetWalletHooks(WalletHooks()); }

    Message Ask(const CKey& who, Op op, const Message& body)
    {
        Message m = body;
        m.op = op;
        return service->Serve(who.GetPubKey(), m, now);
    }
    template <typename T>
    Message Ask(const CKey& who, Op op, const T& body)
    {
        return service->Serve(who.GetPubKey(), Make(op, 1, body), now);
    }
    Message AskEmpty(const CKey& who, Op op)
    {
        Message m;
        m.op = op;
        m.req = 1;
        return service->Serve(who.GetPubKey(), m, now);
    }

    /** Ticket, answer, accept: a paired device. */
    void Pair(const CKey& who, const Limits& limits, const std::string& pin = "246810")
    {
        const PairingTicket t = service->NewTicket("regtest", "127.0.0.1:1", {}, now);
        PairRequest req;
        req.token = t.token;
        req.name = "Pixel";
        req.pin = pin;
        ResultAnswer r;
        BOOST_REQUIRE(Read(Ask(who, Op::PAIR, req), Op::RESULT, r));
        BOOST_REQUIRE_MESSAGE(r.ok, r.text);
        std::string error;
        BOOST_REQUIRE_MESSAGE(service->Accept(t.token, limits, now, error), error);
    }

    /** Prepare a payment; the answer, or a failed RESULT's text in `error`. */
    bool Prepare(const CKey& who, const std::string& to, CAmount amount, PrepareAnswer& out, std::string& error)
    {
        PrepareRequest req;
        req.to = to;
        req.amount = amount;
        const Message reply = Ask(who, Op::PREPARE, req);
        if (Read(reply, Op::PREPARED, out)) return true;
        ResultAnswer r;
        Read(reply, Op::RESULT, r);
        error = r.text;
        return false;
    }

    /** Send a prepared payment, signed by `signer`. */
    Message Send(const CKey& who, const PrepareAnswer& p, const std::string& pin, const CKey* signer = nullptr)
    {
        SendRequest req;
        req.prepare_id = p.prepare_id;
        req.pin = pin;
        (signer ? *signer : who).Sign(SendDigest(node.GetPubKey(), p.prepare_id, p.payee_script, p.amount, p.fee),
                                       req.signature);
        return Ask(who, Op::SEND, req);
    }

    int64_t now{NOW};
};

std::string ResultText(const Message& m)
{
    ResultAnswer r;
    return Read(m, Op::RESULT, r) ? r.text : std::string("(not a result)");
}

} // namespace

BOOST_AUTO_TEST_CASE(service_pairs_a_phone_only_once_accepted)
{
    ServiceFixture f(GetDataDir() / "companion_pair");
    const CKey other = NewKey();

    // Unpaired: nothing but pairing is answered.
    BOOST_CHECK_EQUAL(ResultText(f.AskEmpty(f.device, Op::STATUS)), "This phone is not paired with this home node, or has been unpaired.");
    // And nothing at all without a key proved on a path.
    Message anon;
    anon.op = Op::STATUS;
    BOOST_CHECK(ResultText(f.service->Serve(CPubKey(), anon, f.now)).find("over a path") != std::string::npos);

    const PairingTicket t = f.service->NewTicket("regtest", "127.0.0.1:1", {}, f.now);
    PairRequest req;
    req.token = t.token;
    req.name = "Pixel\x01";
    req.pin = "12345";
    BOOST_CHECK_EQUAL(ResultText(f.Ask(f.device, Op::PAIR, req)), "A PIN is six to twelve digits.");
    req.pin = "246810";
    ResultAnswer r;
    BOOST_REQUIRE(Read(f.Ask(f.device, Op::PAIR, req), Op::RESULT, r));
    BOOST_CHECK(r.ok);
    // Its first answer lost, the same phone may ask again; another phone may not.
    BOOST_REQUIRE(Read(f.Ask(f.device, Op::PAIR, req), Op::RESULT, r));
    BOOST_CHECK(r.ok);
    BOOST_CHECK(ResultText(f.Ask(other, Op::PAIR, req)).find("already been used") != std::string::npos);

    // The home node sees the phone's name, cleaned, and the code it should show.
    std::vector<Pairing> pairings = f.service->Pairings(f.now);
    BOOST_REQUIRE_EQUAL(pairings.size(), 1u);
    BOOST_CHECK_EQUAL(pairings[0].name, "Pixel");
    BOOST_CHECK_EQUAL(pairings[0].code, PairingCode(t.token, f.device.GetPubKey(), f.node.GetPubKey()));

    // Waiting until accepted; nobody else can even ask.
    PairStatusRequest status;
    status.token = t.token;
    PairStateAnswer s;
    BOOST_REQUIRE(Read(f.Ask(f.device, Op::PAIR_STATUS, status), Op::PAIR_STATE, s));
    BOOST_CHECK_EQUAL(s.state, (uint8_t)PairState::WAITING);
    BOOST_REQUIRE(Read(f.Ask(other, Op::PAIR_STATUS, status), Op::PAIR_STATE, s));
    BOOST_CHECK_EQUAL(s.state, (uint8_t)PairState::UNKNOWN);
    BOOST_CHECK(ResultText(f.AskEmpty(f.device, Op::STATUS)).find("not paired") != std::string::npos);

    std::string error;
    BOOST_CHECK(!f.service->Accept(t.token, Limits(), f.now, error)); // limits have to be set
    BOOST_REQUIRE_MESSAGE(f.service->Accept(t.token, Limits(5 * COIN, 20 * COIN), f.now, error), error);
    BOOST_REQUIRE(Read(f.Ask(f.device, Op::PAIR_STATUS, status), Op::PAIR_STATE, s));
    BOOST_CHECK_EQUAL(s.state, (uint8_t)PairState::ACCEPTED);
    BOOST_CHECK_EQUAL(s.per_day, 20 * COIN);

    StatusAnswer st;
    BOOST_REQUIRE(Read(f.AskEmpty(f.device, Op::STATUS), Op::STATUS_INFO, st));
    BOOST_CHECK_EQUAL(st.balance, 50 * COIN);
    BOOST_CHECK_EQUAL(st.per_tx, 5 * COIN);
    BOOST_CHECK_EQUAL(st.height, 1234);
    BOOST_CHECK(!st.locked);

    // A ticket is good for ten minutes and no longer.
    const PairingTicket late = f.service->NewTicket("regtest", "127.0.0.1:1", {}, f.now);
    req.token = late.token;
    f.now += TICKET_TTL + 1;
    BOOST_CHECK(ResultText(f.Ask(other, Op::PAIR, req)).find("expired") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(service_pays_within_the_limits_and_the_pin)
{
    ServiceFixture f(GetDataDir() / "companion_pay");
    f.Pair(f.device, Limits(5 * COIN, 6 * COIN));

    PrepareAnswer p;
    std::string error;
    BOOST_REQUIRE_MESSAGE(f.Prepare(f.device, "alice", 2 * COIN, p, error), error);
    BOOST_CHECK_EQUAL(p.amount, 2 * COIN);
    BOOST_CHECK_EQUAL(p.fee, 1000);
    BOOST_CHECK_EQUAL(p.expires, f.now + PREPARE_TTL);

    // A wrong PIN, then a signature from another key: refused, nothing sent.
    BOOST_CHECK_EQUAL(ResultText(f.Send(f.device, p, "135790")), "Wrong PIN. 4 tries left before this phone is locked.");
    const CKey stranger = NewKey();
    BOOST_CHECK(ResultText(f.Send(f.device, p, "246810", &stranger)).find("signature") != std::string::npos);
    BOOST_CHECK_EQUAL(f.wallet.sent, 0);

    SendAnswer sent;
    BOOST_REQUIRE(Read(f.Send(f.device, p, "246810"), Op::SENT, sent));
    BOOST_CHECK(sent.txid == f.wallet.next_txid);
    // Its answer lost, the phone asks again: the same payment, not a second one.
    SendAnswer again;
    BOOST_REQUIRE(Read(f.Send(f.device, p, "246810"), Op::SENT, again));
    BOOST_CHECK(again.txid == sent.txid);
    BOOST_CHECK_EQUAL(f.wallet.sent, 1);

    StatusAnswer st;
    BOOST_REQUIRE(Read(f.AskEmpty(f.device, Op::STATUS), Op::STATUS_INFO, st));
    BOOST_CHECK_EQUAL(st.spent_today, 2 * COIN + 1000);

    // Over one payment's limit: refused before the wallet is asked.
    const int prepared = f.wallet.prepared;
    BOOST_CHECK(!f.Prepare(f.device, "alice", 5 * COIN + 1, p, error));
    BOOST_CHECK(error.find("one payment") != std::string::npos);
    BOOST_CHECK_EQUAL(f.wallet.prepared, prepared);
    // Exactly what is left of the day, which only the fee takes over: built,
    // refused, and its coins let go.
    BOOST_CHECK(!f.Prepare(f.device, "alice", 4 * COIN - 1000, p, error));
    BOOST_CHECK(error.find("left of this phone's limit") != std::string::npos);
    BOOST_CHECK_EQUAL(f.wallet.cancelled, 1);

    // The network refusing a payment does not count it against the day.
    BOOST_REQUIRE(f.Prepare(f.device, "alice", 3 * COIN, p, error));
    f.wallet.reject_send = true;
    BOOST_CHECK(ResultText(f.Send(f.device, p, "246810")).find("refused") != std::string::npos);
    f.wallet.reject_send = false;
    BOOST_REQUIRE(Read(f.AskEmpty(f.device, Op::STATUS), Op::STATUS_INFO, st));
    BOOST_CHECK_EQUAL(st.spent_today, 2 * COIN + 1000);

    // A prepared payment not sent in time is let go.
    BOOST_REQUIRE(f.Prepare(f.device, "alice", COIN, p, error));
    const int cancelled = f.wallet.cancelled;
    f.service->Expire(f.now + PREPARE_TTL + 1);
    BOOST_CHECK_EQUAL(f.wallet.cancelled, cancelled + 1);
    BOOST_CHECK(ResultText(f.Send(f.device, p, "246810")).find("no longer waiting") != std::string::npos);

    // A day later the window has moved on.
    f.now += SPEND_WINDOW;
    BOOST_REQUIRE_MESSAGE(f.Prepare(f.device, "alice", 5 * COIN - 1000, p, error), error);
}

BOOST_AUTO_TEST_CASE(service_locks_a_phone_after_wrong_pins)
{
    ServiceFixture f(GetDataDir() / "companion_lock");
    f.Pair(f.device, Limits(5 * COIN, 20 * COIN));
    PrepareAnswer p;
    std::string error;
    BOOST_REQUIRE(f.Prepare(f.device, "alice", COIN, p, error));
    for (int i = 0; i < MAX_PIN_FAILURES - 1; ++i) {
        f.now += 10; // under the shared cap
        BOOST_CHECK(ResultText(f.Send(f.device, p, "000000")).find("Wrong PIN") != std::string::npos);
    }
    BOOST_CHECK(ResultText(f.Send(f.device, p, "000000")).find("now locked") != std::string::npos);
    // Locked: not even the right PIN, nor a new payment.
    BOOST_CHECK(ResultText(f.Send(f.device, p, "246810")).find("locked") != std::string::npos);
    BOOST_CHECK(!f.Prepare(f.device, "alice", COIN, p, error));
    BOOST_CHECK(error.find("locked") != std::string::npos);
    StatusAnswer st;
    BOOST_REQUIRE(Read(f.AskEmpty(f.device, Op::STATUS), Op::STATUS_INFO, st));
    BOOST_CHECK(st.locked);
    BOOST_CHECK_EQUAL(f.wallet.sent, 0);

    // Only the home node unlocks it.
    BOOST_REQUIRE(f.service->Unlock(f.device.GetPubKey(), error));
    BOOST_REQUIRE(f.Prepare(f.device, "alice", COIN, p, error));
    SendAnswer sent;
    BOOST_CHECK(Read(f.Send(f.device, p, "246810"), Op::SENT, sent));

    // The PIN can be changed, knowing the old one.
    SetPinRequest change;
    change.old_pin = "246810";
    change.new_pin = "97531086";
    BOOST_CHECK_EQUAL(ResultText(f.Ask(f.device, Op::SET_PIN, change)), "PIN changed.");
    BOOST_REQUIRE(f.Prepare(f.device, "alice", COIN, p, error));
    BOOST_CHECK(ResultText(f.Send(f.device, p, "246810")).find("Wrong PIN") != std::string::npos);
    BOOST_CHECK(Read(f.Send(f.device, p, "97531086"), Op::SENT, sent));
}

BOOST_AUTO_TEST_CASE(service_pin_guesses_are_capped_across_phones)
{
    // Ten phones guessing one PIN each still make ten guesses a minute, at most.
    ServiceFixture f(GetDataDir() / "companion_cap");
    std::vector<CKey> phones(PIN_ATTEMPTS + 1);
    std::vector<PrepareAnswer> prepared(phones.size());
    std::string error;
    for (size_t i = 0; i < phones.size(); ++i) {
        phones[i].MakeNewKey(true);
        f.Pair(phones[i], Limits(5 * COIN, 20 * COIN));
        BOOST_REQUIRE(f.Prepare(phones[i], "alice", COIN, prepared[i], error));
    }
    for (size_t i = 0; i < PIN_ATTEMPTS; ++i) {
        BOOST_CHECK(ResultText(f.Send(phones[i], prepared[i], "000000")).find("Wrong PIN") != std::string::npos);
    }
    BOOST_CHECK(ResultText(f.Send(phones.back(), prepared.back(), "246810")).find("Too many PIN attempts") !=
                std::string::npos);
    f.now += PIN_WINDOW;
    SendAnswer sent;
    BOOST_CHECK(Read(f.Send(phones.back(), prepared.back(), "246810"), Op::SENT, sent));
}

BOOST_AUTO_TEST_CASE(service_forgets_a_revoked_phone)
{
    ServiceFixture f(GetDataDir() / "companion_revoke");
    f.Pair(f.device, Limits(5 * COIN, 20 * COIN));
    PrepareAnswer p;
    std::string error;
    BOOST_REQUIRE(f.Prepare(f.device, "alice", COIN, p, error));
    BOOST_REQUIRE(f.service->Revoke(f.device.GetPubKey()));
    BOOST_CHECK_EQUAL(f.wallet.cancelled, 1); // its prepared payment let go
    BOOST_CHECK(ResultText(f.Send(f.device, p, "246810")).find("not paired") != std::string::npos);
    BOOST_CHECK(f.service->Devices().empty());

    // A phone can unpair itself too.
    f.Pair(f.device, Limits(5 * COIN, 20 * COIN));
    BOOST_CHECK_EQUAL(ResultText(f.AskEmpty(f.device, Op::UNPAIR)), "Unpaired.");
    BOOST_CHECK(f.service->Devices().empty());
}

BOOST_AUTO_TEST_SUITE_END()
