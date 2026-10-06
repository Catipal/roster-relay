// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mlkem768.h>
#include <key.h>
#include <mail/client.h>
#include <mail/letter.h>
#include <mail/mailbox.h>
#include <mail/protocol.h>
#include <overlay/relay.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>

using namespace mail;

BOOST_FIXTURE_TEST_SUITE(mail_tests, BasicTestingSetup)

namespace {

const std::string CHAIN = "regtest";
const int64_t NOW = 1790000000;

CKey NewKey()
{
    CKey k;
    k.MakeNewKey(true);
    return k;
}

/** A recipient's key pair and the lookup Open needs. */
struct Recipient {
    CKey identity = NewKey();
    PreKey key;
    PreKeySecret secret;
    bool have{true};

    explicit Recipient(uint64_t key_id = 1)
    {
        BOOST_REQUIRE(MakePreKey(identity, CHAIN, key_id, NOW, key, secret));
    }
    roster::KeyBytes Self() const { return XOnly(identity.GetPubKey()); }
    SecretLookup Lookup() const
    {
        return [this](uint64_t id) -> const PreKeySecret* {
            return have && id == secret.key_id ? &secret : nullptr;
        };
    }
};

std::vector<unsigned char> SealTo(const CKey& sender, const Recipient& to, const std::string& subject,
                                  const std::string& body)
{
    Letter letter;
    letter.to = to.Self();
    letter.subject = subject;
    letter.body = body;
    letter.sent = NOW;
    std::vector<unsigned char> envelope;
    std::string error;
    BOOST_REQUIRE_MESSAGE(Seal(sender, to.key, letter, CHAIN, envelope, error), error);
    return envelope;
}

bool Contains(const std::vector<unsigned char>& hay, const unsigned char* needle, size_t len)
{
    return std::search(hay.begin(), hay.end(), needle, needle + len) != hay.end();
}

} // namespace

BOOST_AUTO_TEST_CASE(mail_key_is_signed_by_its_owner)
{
    Recipient r;
    BOOST_CHECK(VerifyPreKey(r.key, CHAIN));
    BOOST_CHECK_EQUAL(r.key.expires, NOW + PREKEY_LIFETIME + PREKEY_GRACE);

    const std::vector<unsigned char> raw = SerializePreKey(r.key);
    BOOST_CHECK_EQUAL(raw.size(), PREKEY_SIZE);
    PreKey back;
    BOOST_REQUIRE(ParsePreKey(raw, back));
    BOOST_CHECK(VerifyPreKey(back, CHAIN));

    // A mailbox swapping in a key of its own making is caught: the signature
    // covers both halves.
    PreKey swapped = back;
    swapped.kem_key[100] ^= 1;
    BOOST_CHECK(!VerifyPreKey(swapped, CHAIN));
    swapped = back;
    swapped.ec_key = NewKey().GetPubKey();
    BOOST_CHECK(!VerifyPreKey(swapped, CHAIN));
    // And it is worthless on another chain.
    BOOST_CHECK(!VerifyPreKey(back, "main"));

    // The published half can be made again from the stored secret.
    PreKey again;
    BOOST_REQUIRE(PublicPreKey(r.identity, CHAIN, r.secret, again));
    BOOST_CHECK(SerializePreKey(again) == raw);
}

BOOST_AUTO_TEST_CASE(letter_round_trips)
{
    const CKey sender = NewKey();
    Recipient r;
    const std::vector<unsigned char> envelope = SealTo(sender, r, "Hello", "First letter over BPS mail.");

    roster::KeyBytes to;
    uint64_t key_id = 0;
    BOOST_REQUIRE(ReadEnvelope(envelope, to, key_id));
    BOOST_CHECK(to == r.Self());
    BOOST_CHECK_EQUAL(key_id, 1u);
    BOOST_CHECK_EQUAL((envelope.size() - ENVELOPE_HEADER_SIZE - 16) % PAD_TO, 0u);

    Letter opened;
    BOOST_REQUIRE(Open(envelope, r.Self(), r.Lookup(), CHAIN, opened) == OpenResult::OK);
    BOOST_CHECK(opened.from == XOnly(sender.GetPubKey()));
    BOOST_CHECK(opened.to == r.Self());
    BOOST_CHECK_EQUAL(opened.sent, NOW);
    BOOST_CHECK_EQUAL(opened.subject, "Hello");
    BOOST_CHECK_EQUAL(opened.body, "First letter over BPS mail.");

    // The longest letter allowed still fits the size every layer assumes.
    const std::string longest(MAX_BODY, 'x');
    const std::vector<unsigned char> big = SealTo(sender, r, std::string(MAX_SUBJECT, 's'), longest);
    BOOST_CHECK(big.size() <= MAX_ENVELOPE_SIZE);
    BOOST_REQUIRE(Open(big, r.Self(), r.Lookup(), CHAIN, opened) == OpenResult::OK);
    BOOST_CHECK(opened.body == longest);
}

BOOST_AUTO_TEST_CASE(letter_hides_its_sender_and_length)
{
    const CKey sender = NewKey();
    Recipient r;
    const std::vector<unsigned char> envelope = SealTo(sender, r, "s", "short");

    // Sealed sender: neither form of the sender's key appears anywhere a
    // mailbox can see.
    const CPubKey pub = sender.GetPubKey();
    BOOST_CHECK(!Contains(envelope, pub.begin() + 1, 32));
    BOOST_CHECK(!Contains(envelope, pub.begin(), 33));

    // Lengths are padded: a one-word letter and a few lines look the same.
    const std::vector<unsigned char> longer = SealTo(sender, r, "s", std::string(300, 'y'));
    BOOST_CHECK_EQUAL(envelope.size(), longer.size());

    // Two letters with the same words share nothing a mailbox could link.
    const std::vector<unsigned char> again = SealTo(sender, r, "s", "short");
    BOOST_CHECK(again != envelope);
    BOOST_CHECK(EnvelopeId(again) != EnvelopeId(envelope));
}

BOOST_AUTO_TEST_CASE(letter_refuses_what_it_should)
{
    const CKey sender = NewKey();
    Recipient r;
    const std::vector<unsigned char> envelope = SealTo(sender, r, "Hi", "Body");
    Letter out;

    // Any change to the sealed part or to the header fails as a whole.
    std::vector<unsigned char> bad = envelope;
    bad[bad.size() - 40] ^= 1;
    BOOST_CHECK(Open(bad, r.Self(), r.Lookup(), CHAIN, out) == OpenResult::DAMAGED);
    bad = envelope;
    bad[ENVELOPE_HEADER_SIZE - 10] ^= 1; // inside the ML-KEM ciphertext
    BOOST_CHECK(Open(bad, r.Self(), r.Lookup(), CHAIN, out) == OpenResult::DAMAGED);

    // Sealed on another chain, it does not open on this one.
    BOOST_CHECK(Open(envelope, r.Self(), r.Lookup(), "main", out) == OpenResult::DAMAGED);

    // Somebody else's letter.
    Recipient other;
    BOOST_CHECK(Open(envelope, other.Self(), other.Lookup(), CHAIN, out) == OpenResult::NOT_FOR_US);

    // A mail key since deleted.
    r.have = false;
    BOOST_CHECK(Open(envelope, r.Self(), r.Lookup(), CHAIN, out) == OpenResult::KEY_GONE);
    r.have = true;

    // Not a letter at all.
    std::vector<unsigned char> junk(envelope.begin(), envelope.begin() + 100);
    BOOST_CHECK(Open(junk, r.Self(), r.Lookup(), CHAIN, out) == OpenResult::MALFORMED);

    // Too long to send.
    Letter letter;
    letter.to = r.Self();
    letter.body = std::string(MAX_BODY + 1, 'z');
    std::vector<unsigned char> sealed;
    std::string error;
    BOOST_CHECK(!Seal(sender, r.key, letter, CHAIN, sealed, error));
    // Sealed to a key that is not the recipient's.
    letter.body = "x";
    letter.to = other.Self();
    BOOST_CHECK(!Seal(sender, r.key, letter, CHAIN, sealed, error));
}

BOOST_AUTO_TEST_CASE(old_mail_keys_are_deleted)
{
    // Forward secrecy, end to end on the client: a letter sealed to a mail key
    // opens while that key could still be in use, and not once it is gone.
    MailClient client(fs::path("mailtest"), NewKey(), CHAIN, std::chrono::seconds{300}, /* memory_only */ true);
    BOOST_CHECK(client.RotateKeys(NOW));
    BOOST_CHECK_EQUAL(client.KeysHeld(), 1u);
    PreKey first;
    BOOST_REQUIRE(client.CurrentPreKey(first));
    BOOST_CHECK(VerifyPreKey(first, CHAIN));

    const CKey sender = NewKey();
    auto seal = [&](const PreKey& to, const std::string& body) {
        Letter letter;
        letter.to = client.Self();
        letter.body = body;
        std::vector<unsigned char> envelope;
        std::string error;
        BOOST_REQUIRE_MESSAGE(Seal(sender, to, letter, CHAIN, envelope, error), error);
        return envelope;
    };
    const std::vector<unsigned char> early = seal(first, "early");
    const std::vector<unsigned char> late = seal(first, "late");

    // A week on, a new key is made and the old one kept: mail sealed to it may
    // still be waiting.
    BOOST_CHECK(!client.RotateKeys(NOW + 1));
    BOOST_CHECK(client.RotateKeys(NOW + PREKEY_LIFETIME));
    BOOST_CHECK_EQUAL(client.KeysHeld(), 2u);
    PreKey second;
    BOOST_REQUIRE(client.CurrentPreKey(second));
    BOOST_CHECK_EQUAL(second.key_id, first.key_id + 1);
    uint256 id;
    BOOST_CHECK(client.Receive(early, NOW + PREKEY_LIFETIME, id) == OpenResult::OK);
    BOOST_CHECK(client.HaveLetter(id));

    // Once nothing sealed to it can be left in any mailbox, it is deleted, and
    // a letter sealed to it no longer opens - which is the point.
    const int64_t gone = first.expires + RETENTION + 1;
    BOOST_CHECK(client.RotateKeys(gone));
    BOOST_CHECK(client.Receive(late, gone, id) == OpenResult::KEY_GONE);
    BOOST_CHECK(!client.HaveLetter(id));
    // What was already collected stays readable.
    StoredLetter kept;
    BOOST_REQUIRE(client.Get(EnvelopeId(early), kept));
    BOOST_CHECK_EQUAL(kept.body, "early");
    BOOST_CHECK(!kept.read);
    BOOST_CHECK(client.MarkRead(kept.id));
    BOOST_REQUIRE(client.Get(kept.id, kept));
    BOOST_CHECK(kept.read);
    BOOST_CHECK(client.Delete(kept.id));
    BOOST_CHECK(!client.HaveLetter(kept.id));
}

BOOST_AUTO_TEST_CASE(stored_letter_round_trips)
{
    StoredLetter l;
    l.id = InsecureRand256();
    l.folder = Folder::SENT;
    l.from[0] = 1;
    l.to[31] = 2;
    l.sent = NOW;
    l.received = NOW + 5;
    l.subject = "Subject";
    l.body = std::string(1000, 'b');
    l.read = true;
    l.delivered = 3;
    StoredLetter back;
    BOOST_REQUIRE(ParseStored(SerializeStored(l), back));
    BOOST_CHECK(back.id == l.id && back.folder == l.folder && back.from == l.from && back.to == l.to);
    BOOST_CHECK(back.sent == l.sent && back.received == l.received && back.subject == l.subject);
    BOOST_CHECK(back.body == l.body && back.read && back.delivered == 3);
    std::vector<unsigned char> raw = SerializeStored(l);
    raw.pop_back();
    BOOST_CHECK(!ParseStored(raw, back));
}

BOOST_AUTO_TEST_CASE(mailboxes_come_from_arithmetic)
{
    std::vector<roster::KeyBytes> relays;
    for (int i = 0; i < 40; ++i) relays.push_back(XOnly(NewKey().GetPubKey()));
    const roster::KeyBytes owner = XOnly(NewKey().GetPubKey());

    const std::vector<roster::KeyBytes> boxes = MailboxesFor(owner, relays);
    BOOST_CHECK_EQUAL(boxes.size(), MAILBOX_COUNT);
    // The same on every node, whatever order the relays were read in.
    std::vector<roster::KeyBytes> shuffled = relays;
    std::reverse(shuffled.begin(), shuffled.end());
    BOOST_CHECK(MailboxesFor(owner, shuffled) == boxes);

    // A relay joining moves at most one mailbox, so mail is not reshuffled
    // whenever the roster changes.
    relays.push_back(XOnly(NewKey().GetPubKey()));
    const std::vector<roster::KeyBytes> after = MailboxesFor(owner, relays);
    size_t kept = 0;
    for (const roster::KeyBytes& k : after) {
        if (std::find(boxes.begin(), boxes.end(), k) != boxes.end()) ++kept;
    }
    BOOST_CHECK(kept >= MAILBOX_COUNT - 1);

    // The owner is never its own mailbox, and a small roster gives what it has.
    std::vector<roster::KeyBytes> two = {owner, relays[0], relays[1]};
    const std::vector<roster::KeyBytes> few = MailboxesFor(owner, two);
    BOOST_CHECK_EQUAL(few.size(), 2u);
    BOOST_CHECK(std::find(few.begin(), few.end(), owner) == few.end());
    BOOST_CHECK(MailboxesFor(owner, {}).empty());
}

BOOST_AUTO_TEST_CASE(mailbox_holds_and_hands_back)
{
    const CKey self = NewKey();
    Mailbox box(fs::path("mailbox"), 1 << 20, XOnly(self.GetPubKey()), CHAIN, /* memory_only */ true);
    const CKey sender = NewKey();
    Recipient r;

    std::string reason;
    // Keys: the owner's own, newest kept.
    BOOST_CHECK(box.PutPreKey(r.key, NOW, reason));
    PreKey held;
    BOOST_REQUIRE(box.GetPreKey(r.Self(), NOW, held));
    BOOST_CHECK(SerializePreKey(held) == SerializePreKey(r.key));
    PreKey newer, older;
    PreKeySecret unused;
    BOOST_REQUIRE(MakePreKey(r.identity, CHAIN, 2, NOW + 100, newer, unused));
    BOOST_REQUIRE(MakePreKey(r.identity, CHAIN, 0, NOW - 100, older, unused));
    BOOST_CHECK(box.PutPreKey(newer, NOW + 100, reason));
    BOOST_CHECK(!box.PutPreKey(older, NOW + 100, reason));
    BOOST_REQUIRE(box.GetPreKey(r.Self(), NOW + 100, held));
    BOOST_CHECK_EQUAL(held.key_id, 2u);
    // Not anyone's key but the signer's.
    PreKey forged = r.key;
    forged.kem_key[0] ^= 1;
    BOOST_CHECK(!box.PutPreKey(forged, NOW, reason));
    // Not handed out once expired.
    BOOST_CHECK(!box.GetPreKey(r.Self(), newer.expires, held));

    // Letters.
    const std::vector<unsigned char> a = SealTo(sender, r, "a", "one");
    const std::vector<unsigned char> b = SealTo(sender, r, "b", "two");
    uint256 id_a, id_b, again;
    BOOST_REQUIRE(box.Deposit(a, NOW, id_a, reason));
    BOOST_REQUIRE(box.Deposit(b, NOW + 1, id_b, reason));
    // A sender retrying after a lost answer is told yes, and nothing is doubled.
    BOOST_REQUIRE(box.Deposit(a, NOW + 2, again, reason));
    BOOST_CHECK(again == id_a);
    BOOST_CHECK_EQUAL(box.List(r.Self()).size(), 2u);
    BOOST_CHECK_EQUAL(box.GetStats().items, 2u);
    BOOST_CHECK_EQUAL(box.GetStats().owners, 1u);

    std::vector<unsigned char> fetched;
    BOOST_REQUIRE(box.Fetch(r.Self(), id_a, fetched));
    BOOST_CHECK(fetched == a);
    // Only the owner's own mail is under the owner's key.
    Recipient other;
    BOOST_CHECK(!box.Fetch(other.Self(), id_a, fetched));
    BOOST_CHECK(box.List(other.Self()).empty());

    BOOST_CHECK_EQUAL(box.Remove(r.Self(), {id_a}), 1u);
    BOOST_CHECK_EQUAL(box.Remove(r.Self(), {id_a}), 0u);
    BOOST_CHECK_EQUAL(box.List(r.Self()).size(), 1u);

    // Held two weeks, then dropped unread.
    BOOST_CHECK_EQUAL(box.Expire(NOW + RETENTION), 0u);
    BOOST_CHECK_EQUAL(box.Expire(NOW + 1 + RETENTION + 1), 1u);
    BOOST_CHECK(box.List(r.Self()).empty());
    BOOST_CHECK_EQUAL(box.GetStats().bytes, 0u);

    // Not a letter.
    BOOST_CHECK(!box.Deposit(std::vector<unsigned char>(100, 1), NOW, again, reason));
}

BOOST_AUTO_TEST_CASE(mailbox_is_bounded)
{
    const CKey self = NewKey();
    const CKey sender = NewKey();
    Recipient r;
    const std::vector<unsigned char> one = SealTo(sender, r, "", "1");
    // Room for two letters and no more.
    Mailbox box(fs::path("mailbox"), 2 * one.size() + 10, XOnly(self.GetPubKey()), CHAIN, true);
    std::string reason;
    uint256 id;
    BOOST_CHECK(box.Deposit(one, NOW, id, reason));
    BOOST_CHECK(box.Deposit(SealTo(sender, r, "", "2"), NOW, id, reason));
    BOOST_CHECK(!box.Deposit(SealTo(sender, r, "", "3"), NOW, id, reason));
    BOOST_CHECK(reason.find("no room") != std::string::npos);

    // Only people this relay is a mailbox for.
    Mailbox picky(fs::path("picky"), 1 << 20, XOnly(self.GetPubKey()), CHAIN, true);
    picky.SetOwnerCheck([](const roster::KeyBytes&) { return false; });
    BOOST_CHECK(!picky.Deposit(one, NOW, id, reason));
    BOOST_CHECK(!picky.PutPreKey(r.key, NOW, reason));
}

BOOST_AUTO_TEST_CASE(mailbox_requests_are_signed_and_fresh)
{
    const CKey self = NewKey();
    const roster::KeyBytes me = XOnly(self.GetPubKey());
    Mailbox box(fs::path("mailbox"), 1 << 20, me, CHAIN, true);
    const CKey owner = NewKey();
    std::string reason;

    Auth auth;
    BOOST_REQUIRE(MakeAuth(owner, me, CHAIN, NOW, auth));
    const std::vector<unsigned char> raw = SerializeAuth(auth);
    BOOST_CHECK_EQUAL(raw.size(), AUTH_SIZE);
    Auth back;
    BOOST_REQUIRE(ParseAuth(raw.data(), raw.size(), back));
    BOOST_CHECK(box.CheckAuth(back, NOW, reason));
    // Once only.
    BOOST_CHECK(!box.CheckAuth(back, NOW, reason));

    // Signed for a different mailbox: worthless here.
    BOOST_REQUIRE(MakeAuth(owner, XOnly(NewKey().GetPubKey()), CHAIN, NOW, auth));
    BOOST_CHECK(!box.CheckAuth(auth, NOW, reason));
    // Too old, or claiming another owner.
    BOOST_REQUIRE(MakeAuth(owner, me, CHAIN, NOW - AUTH_WINDOW - 1, auth));
    BOOST_CHECK(!box.CheckAuth(auth, NOW, reason));
    BOOST_REQUIRE(MakeAuth(owner, me, CHAIN, NOW, auth));
    auth.owner = XOnly(NewKey().GetPubKey());
    BOOST_CHECK(!box.CheckAuth(auth, NOW, reason));
}

BOOST_AUTO_TEST_CASE(cells_fit_a_path_and_reassemble)
{
    // A message the size of the largest letter, in shuffled and repeated cells.
    std::vector<unsigned char> message(MAX_ENVELOPE_SIZE + 41);
    for (size_t i = 0; i < message.size(); ++i) message[i] = (unsigned char)(i * 7);
    const std::vector<std::vector<unsigned char>> cells = SplitCells(0x1234, message);
    BOOST_REQUIRE(!cells.empty());
    BOOST_CHECK(cells.size() <= MAX_CELLS);
    for (const std::vector<unsigned char>& c : cells) BOOST_CHECK(c.size() <= overlay::MAX_PATH_APP_PAYLOAD);

    Reassembler re;
    const overlay::Hop from = overlay::Hop::Path(77);
    std::vector<unsigned char> out;
    uint64_t transfer = 0;
    std::vector<size_t> order;
    for (size_t i = 0; i < cells.size(); ++i) order.push_back(cells.size() - 1 - i);
    bool done = false;
    for (size_t n = 0; n < order.size(); ++n) {
        BOOST_CHECK(!done);
        done = re.Add(from, cells[order[n]], NOW, out, transfer);
        // A repeated cell changes nothing.
        if (!done) BOOST_CHECK(!re.Add(from, cells[order[n]], NOW, out, transfer));
    }
    BOOST_REQUIRE(done);
    BOOST_CHECK(out == message);
    BOOST_CHECK_EQUAL(transfer, 0x1234u);
    BOOST_CHECK_EQUAL(re.Pending(), 0u);

    // Cells of one transfer from two different paths are two transfers.
    BOOST_CHECK(!re.Add(overlay::Hop::Path(1), cells[0], NOW, out, transfer));
    BOOST_CHECK(!re.Add(overlay::Hop::Path(2), cells[1], NOW, out, transfer));
    BOOST_CHECK_EQUAL(re.Pending(), 2u);
    // And a partial message is dropped once it has waited a minute.
    BOOST_CHECK(!re.Add(overlay::Hop::Path(3), cells[0], NOW + Reassembler::TTL, out, transfer));
    BOOST_CHECK_EQUAL(re.Pending(), 1u);

    // Too large, or malformed.
    BOOST_CHECK(SplitCells(1, std::vector<unsigned char>(MAX_MESSAGE_SIZE + 1)).empty());
    std::vector<unsigned char> bad = cells[0];
    bad[11] = 0; // count of zero
    bad[12] = 0;
    BOOST_CHECK(!re.Add(from, bad, NOW, out, transfer));
}

BOOST_AUTO_TEST_CASE(mailbox_serves_requests)
{
    const CKey self = NewKey();
    const roster::KeyBytes me = XOnly(self.GetPubKey());
    Mailbox box(fs::path("mailbox"), 1 << 20, me, CHAIN, true);
    Recipient r;
    const CKey sender = NewKey();
    bool ok = false;
    std::string text;

    auto serve = [&](Op op, std::vector<unsigned char> body) {
        Message req;
        req.op = op;
        req.req = 42;
        req.body = std::move(body);
        Message decoded;
        BOOST_REQUIRE(DecodeMessage(EncodeMessage(req), decoded));
        Message ans = Serve(box, decoded, NOW);
        BOOST_CHECK_EQUAL(ans.req, 42u);
        return ans;
    };

    // The recipient leaves its key; a sender fetches it.
    BOOST_CHECK(ReadResult(serve(Op::PUT_KEY, SerializePreKey(r.key)), ok, text) && ok);
    const roster::KeyBytes owner = r.Self();
    Message key = serve(Op::GET_KEY, std::vector<unsigned char>(owner.begin(), owner.end()));
    BOOST_REQUIRE(key.op == Op::KEY);
    PreKey fetched;
    BOOST_REQUIRE(ParsePreKey(key.body, fetched));
    BOOST_CHECK(VerifyPreKey(fetched, CHAIN));

    // The sender leaves a letter.
    const std::vector<unsigned char> envelope = SealTo(sender, r, "Subject", "Body");
    BOOST_CHECK(ReadResult(serve(Op::DEPOSIT, envelope), ok, text) && ok);
    BOOST_CHECK_EQUAL(text, EnvelopeId(envelope).GetHex());

    // The recipient lists, fetches and removes, each request signed.
    auto signed_by = [&](const CKey& who) {
        Auth auth;
        BOOST_REQUIRE(MakeAuth(who, me, CHAIN, NOW, auth));
        return SerializeAuth(auth);
    };
    Message items = serve(Op::LIST, signed_by(r.identity));
    BOOST_REQUIRE(items.op == Op::ITEMS);
    BOOST_REQUIRE_EQUAL(items.body.size(), 2u + 44u);
    uint256 id;
    std::copy(items.body.begin() + 2, items.body.begin() + 34, id.begin());
    BOOST_CHECK(id == EnvelopeId(envelope));

    std::vector<unsigned char> fetch = signed_by(r.identity);
    fetch.insert(fetch.end(), id.begin(), id.end());
    Message item = serve(Op::FETCH, fetch);
    BOOST_REQUIRE(item.op == Op::ITEM);
    const std::vector<unsigned char> got(item.body.begin() + 32, item.body.end());
    BOOST_CHECK(got == envelope);
    Letter letter;
    BOOST_CHECK(Open(got, r.Self(), r.Lookup(), CHAIN, letter) == OpenResult::OK);

    // Somebody else asking for the recipient's list sees only their own.
    Message theirs = serve(Op::LIST, signed_by(sender));
    BOOST_REQUIRE(theirs.op == Op::ITEMS);
    BOOST_CHECK_EQUAL(theirs.body.size(), 2u);
    // And an unsigned request is refused.
    BOOST_CHECK(ReadResult(serve(Op::LIST, std::vector<unsigned char>(AUTH_SIZE, 0)), ok, text) && !ok);

    std::vector<unsigned char> remove = signed_by(r.identity);
    remove.push_back(1);
    remove.insert(remove.end(), id.begin(), id.end());
    BOOST_CHECK(ReadResult(serve(Op::REMOVE, remove), ok, text) && ok);
    BOOST_CHECK_EQUAL(text, "1");
    BOOST_CHECK(box.List(r.Self()).empty());
}

BOOST_AUTO_TEST_SUITE_END()
