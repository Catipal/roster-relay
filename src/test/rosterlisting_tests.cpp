// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <netbase.h>
#include <roster/listing.h>
#include <roster/record.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>

using namespace roster;

namespace {

const std::string CHAIN = "regtest";
const int NEXT_HEIGHT = 1000;

CKey MakeKey(uint8_t seed)
{
    unsigned char vch[32];
    std::memset(vch, 1, sizeof(vch));
    vch[31] = seed;
    CKey key;
    key.Set(vch, vch + sizeof(vch), true);
    return key;
}

KeyBytes XOnly(const CKey& key)
{
    const CPubKey pk = key.GetPubKey();
    KeyBytes out;
    std::memcpy(out.data(), pk.data() + 1, RECORD_KEY_SIZE);
    return out;
}

//! A month-long announcement, signed, as a peer's node would build it.
std::vector<unsigned char> SignedAnnounce(const CKey& key, uint32_t expiry = NEXT_HEIGHT + MIN_TTL + 144)
{
    Record rec;
    rec.type = RecordType::ANNOUNCE;
    rec.op_key = XOnly(key);
    rec.expiry_height = expiry;
    const std::vector<unsigned char> unsigned_raw = SerializeRecord(rec);
    const uint256 sighash = RecordSigHash(unsigned_raw, rec.type, CHAIN);
    BOOST_REQUIRE(key.SignSchnorr(sighash, Span<unsigned char>(rec.sig.data(), rec.sig.size())));
    return SerializeRecord(rec);
}

ListingContext ContextFor(const CKey& requester)
{
    ListingContext ctx;
    ctx.requester = XOnly(requester);
    ctx.next_height = NEXT_HEIGHT;
    ctx.chain_id = CHAIN;
    return ctx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(rosterlisting_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(request_round_trip)
{
    const std::vector<unsigned char> raw = SignedAnnounce(MakeKey(1));
    std::vector<unsigned char> msg;
    BOOST_REQUIRE(EncodeListingRequest(0x0123456789abcdefULL, raw, msg));
    BOOST_CHECK_EQUAL(msg[0], (uint8_t)AppMessage::LISTING_REQUEST);

    uint64_t id = 0;
    std::vector<unsigned char> back;
    BOOST_REQUIRE(DecodeListingRequest(msg, id, back));
    BOOST_CHECK_EQUAL(id, 0x0123456789abcdefULL);
    BOOST_CHECK(back == raw);

    // An empty or oversized record is not a request.
    BOOST_CHECK(!EncodeListingRequest(1, {}, msg));
    BOOST_CHECK(!EncodeListingRequest(1, std::vector<unsigned char>(MAX_RECORD_SIZE + 1, 0), msg));
    // Nor is a result, or a truncated request.
    std::vector<unsigned char> wrong_kind = msg;
    wrong_kind[0] = (uint8_t)AppMessage::LISTING_RESULT;
    BOOST_CHECK(!DecodeListingRequest(wrong_kind, id, back));
    BOOST_CHECK(!DecodeListingRequest(std::vector<unsigned char>(msg.begin(), msg.begin() + 9), id, back));
}

BOOST_AUTO_TEST_CASE(result_round_trip)
{
    ListingOutcome paid;
    paid.ok = true;
    paid.txid = uint256S("00000000000000000000000000000000000000000000000000000000deadbeef");
    std::vector<unsigned char> msg;
    BOOST_REQUIRE(EncodeListingResult(7, paid, msg));

    uint64_t id = 0;
    ListingOutcome back;
    BOOST_REQUIRE(DecodeListingResult(msg, id, back));
    BOOST_CHECK_EQUAL(id, 7U);
    BOOST_CHECK(back.ok);
    BOOST_CHECK(back.txid == paid.txid);

    ListingOutcome refused;
    refused.reason = "This relay is not taking on more peers.";
    BOOST_REQUIRE(EncodeListingResult(8, refused, msg));
    BOOST_REQUIRE(DecodeListingResult(msg, id, back));
    BOOST_CHECK(!back.ok);
    BOOST_CHECK_EQUAL(back.reason, refused.reason);
}

BOOST_AUTO_TEST_CASE(refusal_is_bounded_and_sanitised)
{
    // A relay is a stranger and its refusal is shown to a person: length is
    // capped on the way out and anything unprintable dropped on the way in.
    ListingOutcome refused;
    refused.reason = std::string(MAX_REFUSAL_LENGTH * 2, 'x');
    std::vector<unsigned char> msg;
    BOOST_REQUIRE(EncodeListingResult(1, refused, msg));
    uint64_t id = 0;
    ListingOutcome back;
    BOOST_REQUIRE(DecodeListingResult(msg, id, back));
    BOOST_CHECK_EQUAL(back.reason.size(), MAX_REFUSAL_LENGTH);

    std::vector<unsigned char> hostile = {(uint8_t)AppMessage::LISTING_RESULT, 1, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::string text = "full\x1b[2Jnow";
    hostile.insert(hostile.end(), text.begin(), text.end());
    BOOST_REQUIRE(DecodeListingResult(hostile, id, back));
    BOOST_CHECK(back.reason.find('\x1b') == std::string::npos);

    // An ok result carries exactly a txid.
    std::vector<unsigned char> short_ok = {(uint8_t)AppMessage::LISTING_RESULT, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa};
    BOOST_CHECK(!DecodeListingResult(short_ok, id, back));
}

BOOST_AUTO_TEST_CASE(pays_for_the_requesters_own_record)
{
    const CKey peer = MakeKey(2);
    Record rec;
    std::string reason;
    uint32_t needed = 0;
    BOOST_CHECK_MESSAGE(CheckListingRequest(SignedAnnounce(peer), ContextFor(peer), rec, reason, needed), reason);
    BOOST_CHECK(rec.op_key == XOnly(peer));
}

BOOST_AUTO_TEST_CASE(refuses_a_record_for_someone_else)
{
    // The session proves who is asking. Paying for a different key would let
    // any peer spend this relay's coins listing whoever it liked.
    const CKey peer = MakeKey(3);
    const CKey other = MakeKey(4);
    Record rec;
    std::string reason;
    uint32_t needed = 0;
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(other), ContextFor(peer), rec, reason, needed));
    BOOST_CHECK(reason.find("different key") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(refuses_what_the_index_would_drop)
{
    const CKey peer = MakeKey(5);
    Record rec;
    std::string reason;
    uint32_t needed = 0;

    std::vector<unsigned char> tampered = SignedAnnounce(peer);
    tampered[40] ^= 1; // inside the signed part
    BOOST_CHECK(!CheckListingRequest(tampered, ContextFor(peer), rec, reason, needed));

    ListingContext other_chain = ContextFor(peer);
    other_chain.chain_id = "main";
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer), other_chain, rec, reason, needed));

    // Too short a life for a record confirming at the next height.
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer, NEXT_HEIGHT + 10), ContextFor(peer), rec, reason, needed));
    BOOST_CHECK(reason.find("out of range") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(refuses_to_pay_twice)
{
    const CKey peer = MakeKey(6);
    Record rec;
    std::string reason;
    uint32_t needed = 0;

    // Already paid and still confirming.
    ListingContext pending = ContextFor(peer);
    pending.pending_height = NEXT_HEIGHT - 10;
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer), pending, rec, reason, needed));
    BOOST_CHECK(reason.find("waiting to confirm") != std::string::npos);

    // Long enough ago that it should have confirmed: asking again is a renewal.
    pending.pending_height = NEXT_HEIGHT - (int)MIN_TTL;
    BOOST_CHECK_MESSAGE(CheckListingRequest(SignedAnnounce(peer), pending, rec, reason, needed), reason);

    // Listed with most of the month still to run.
    ListingContext listed = ContextFor(peer);
    listed.live_expiry = NEXT_HEIGHT + MIN_TTL - 100;
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer), listed, rec, reason, needed));
    BOOST_CHECK(reason.find("Renew in its last three days") != std::string::npos);

    // Four days left is still too early.
    listed.live_expiry = NEXT_HEIGHT + RENEW_WINDOW + 480;
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer), listed, rec, reason, needed));

    // In the last three days, renewing is what the relay is for.
    listed.live_expiry = NEXT_HEIGHT + RENEW_WINDOW;
    BOOST_CHECK_MESSAGE(CheckListingRequest(SignedAnnounce(peer), listed, rec, reason, needed), reason);
}

BOOST_AUTO_TEST_CASE(a_full_relay_still_renews_its_own_peers)
{
    const CKey peer = MakeKey(7);
    Record rec;
    std::string reason;
    uint32_t needed = 0;

    ListingContext full = ContextFor(peer);
    full.listed_users = 3;
    full.max_users = 3;
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer), full, rec, reason, needed));
    BOOST_CHECK(reason.find("not taking on more") != std::string::npos);

    full.already_user = true;
    BOOST_CHECK_MESSAGE(CheckListingRequest(SignedAnnounce(peer), full, rec, reason, needed), reason);
}

BOOST_AUTO_TEST_CASE(needs_window_round_trip)
{
    ListingOutcome longer;
    longer.needed_window = 600;
    std::vector<unsigned char> msg;
    BOOST_REQUIRE(EncodeListingResult(9, longer, msg));
    uint64_t id = 0;
    ListingOutcome back;
    BOOST_REQUIRE(DecodeListingResult(msg, id, back));
    BOOST_CHECK(!back.ok);
    BOOST_CHECK_EQUAL(back.needed_window, 600U);

    // A window no record could have is not something to sign for.
    std::vector<unsigned char> absurd = {(uint8_t)AppMessage::LISTING_RESULT, 1, 0, 0, 0, 0, 0, 0, 0, 2,
                                         0xff, 0xff, 0xff, 0xff};
    BOOST_CHECK(!DecodeListingResult(absurd, id, back));
}

BOOST_AUTO_TEST_CASE(window_follows_the_relays_stake)
{
    // Staking as much as the rest of the network together: a block every other
    // block or so, so the ordinary window is plenty.
    BOOST_CHECK_EQUAL(NeededConfirmWindow(1000, 2000), DEFAULT_CONFIRM_WINDOW);
    // A hundredth of the network: one block in a hundred, three of those.
    BOOST_CHECK_EQUAL(NeededConfirmWindow(1, 100), 300U);
    // So rare that no legal record could wait long enough.
    BOOST_CHECK_EQUAL(NeededConfirmWindow(1, 1000000000), 0U);
    // Not staking at all.
    BOOST_CHECK_EQUAL(NeededConfirmWindow(0, 1000), 0U);
}

BOOST_AUTO_TEST_CASE(asks_for_a_longer_window_rather_than_paying_in_vain)
{
    // The relay puts the listing in a block it stakes itself. If the record
    // would stop counting before that block is likely to come, paying for it
    // buys nothing, so the relay says how long a window it needs instead.
    const CKey peer = MakeKey(8);
    Record rec;
    std::string reason;
    uint32_t needed = 0;

    ListingContext slow = ContextFor(peer);
    slow.needed_window = 600;
    BOOST_CHECK(!CheckListingRequest(SignedAnnounce(peer), slow, rec, reason, needed));
    BOOST_CHECK_EQUAL(needed, 600U);

    // Signed again with that window, it is paid for.
    BOOST_CHECK_MESSAGE(CheckListingRequest(SignedAnnounce(peer, NEXT_HEIGHT + MIN_TTL + 600), slow, rec, reason, needed),
                        reason);
    BOOST_CHECK_EQUAL(needed, 0U);
}

BOOST_AUTO_TEST_CASE(overlay_listens_one_above_the_published_port)
{
    CService endpoint;
    BOOST_REQUIRE(Lookup("203.0.113.7", endpoint, 9345, false));
    BOOST_CHECK_EQUAL(OverlayAddressFor(endpoint).ToString(), "203.0.113.7:9346");
}

BOOST_AUTO_TEST_SUITE_END()
