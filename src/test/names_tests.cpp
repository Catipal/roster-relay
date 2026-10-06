// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <names/name.h>
#include <names/record.h>
#include <names/state.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace names;

BOOST_FIXTURE_TEST_SUITE(names_tests, BasicTestingSetup)

namespace {

const std::string CHAIN = "regtest";

struct Person {
    CKey key;
    roster::KeyBytes x{};
    Person()
    {
        key.MakeNewKey(true);
        const CPubKey pub = key.GetPubKey();
        std::copy(pub.begin() + 1, pub.begin() + 33, x.begin());
    }
};

Salt MakeSalt(unsigned char fill)
{
    Salt s;
    s.fill(fill);
    return s;
}

IndexedRecord At(int height, const std::vector<unsigned char>& raw, CAmount burned = 0)
{
    IndexedRecord r;
    r.raw = raw;
    r.burned = burned;
    r.height = height;
    return r;
}

std::vector<unsigned char> CommitRecord(const std::string& name, const Salt& salt, const Person& owner)
{
    NameRecord rec;
    rec.type = NameRecordType::COMMIT;
    rec.commitment = Commitment(name, salt, owner.x);
    return SerializeNameRecord(rec);
}

std::vector<unsigned char> ClaimRecord(const std::string& name, const Salt& salt, const Person& owner,
                                       uint32_t expiry, const Person* signer = nullptr)
{
    NameRecord rec;
    rec.type = NameRecordType::CLAIM;
    rec.key = owner.x;
    rec.name = name;
    rec.salt = salt;
    rec.expiry_height = expiry;
    std::vector<unsigned char> raw;
    BOOST_REQUIRE(SignNameRecord((signer ? signer : &owner)->key, rec, CHAIN, raw));
    return raw;
}

std::vector<unsigned char> TransferRecord(const std::string& name, const Person& to, const Person& signer)
{
    NameRecord rec;
    rec.type = NameRecordType::TRANSFER;
    rec.name = name;
    rec.key = to.x;
    std::vector<unsigned char> raw;
    BOOST_REQUIRE(SignNameRecord(signer.key, rec, CHAIN, raw));
    return raw;
}

std::vector<unsigned char> SubnameRecord(const std::string& root, const std::string& label,
                                         const roster::KeyBytes& key, uint32_t expiry, const Person& signer)
{
    NameRecord rec;
    rec.type = NameRecordType::SUBNAME;
    rec.name = root;
    rec.label = label;
    rec.key = key;
    rec.expiry_height = expiry;
    std::vector<unsigned char> raw;
    BOOST_REQUIRE(SignNameRecord(signer.key, rec, CHAIN, raw));
    return raw;
}

/** Register `name` for `owner`: commit at `at`, claim COMMIT_MIN_AGE later for a year. */
int Register(NameState& state, const std::string& name, const Person& owner, int at, unsigned char salt_fill = 1)
{
    const Salt salt = MakeSalt(salt_fill);
    BOOST_REQUIRE_EQUAL(state.Apply(At(at, CommitRecord(name, salt, owner))), "");
    const int claim_at = at + (int)COMMIT_MIN_AGE;
    const uint32_t expiry = claim_at + BLOCKS_PER_YEAR;
    BOOST_REQUIRE_EQUAL(state.Apply(At(claim_at, ClaimRecord(name, salt, owner, expiry),
                                       Price(name.size(), BLOCKS_PER_YEAR))), "");
    return claim_at;
}

} // namespace

BOOST_AUTO_TEST_CASE(names_have_one_spelling)
{
    std::string out;
    BOOST_CHECK(Normalize("Pilot", out) && out == "pilot");
    BOOST_CHECK(!Normalize("luig\xc4\xb1", out)); // a Turkish dotless i: not ASCII, refused
    BOOST_CHECK(IsValidLabel("a"));
    BOOST_CHECK(IsValidLabel("bps-relay"));
    BOOST_CHECK(IsValidLabel("node7"));
    BOOST_CHECK(!IsValidLabel(""));
    BOOST_CHECK(!IsValidLabel("-bps"));
    BOOST_CHECK(!IsValidLabel("bps-"));
    BOOST_CHECK(!IsValidLabel("xn--bps"));
    BOOST_CHECK(!IsValidLabel("Pilot"));
    BOOST_CHECK(!IsValidLabel("pi_lot"));
    BOOST_CHECK(!IsValidLabel(std::string(MAX_LABEL_LENGTH + 1, 'a')));
    BOOST_CHECK(!IsValidRoot("ab"));
    BOOST_CHECK(IsValidRoot("abc"));

    std::string root, label;
    BOOST_CHECK(SplitName("pilot", root, label) && root == "pilot" && label.empty());
    BOOST_CHECK(SplitName("alice.pilot", root, label) && root == "pilot" && label == "alice");
    BOOST_CHECK(SplitName("a.pilot", root, label));
    BOOST_CHECK(!SplitName("a.b.pilot", root, label));
    BOOST_CHECK(!SplitName("alice.lu", root, label));
    BOOST_CHECK(!SplitName(".pilot", root, label));
}

BOOST_AUTO_TEST_CASE(look_alikes_share_a_skeleton)
{
    BOOST_CHECK_EQUAL(Skeleton("pilot"), Skeleton("pi1ot"));
    BOOST_CHECK_EQUAL(Skeleton("google"), Skeleton("g00gle"));
    BOOST_CHECK_EQUAL(Skeleton("modern"), Skeleton("rnodern"));
    BOOST_CHECK_EQUAL(Skeleton("wallet"), Skeleton("vvallet"));
    // Names that merely resemble each other stay distinct.
    BOOST_CHECK(Skeleton("mail") != Skeleton("mall"));
    BOOST_CHECK(Skeleton("my-name") != Skeleton("myname"));
}

BOOST_AUTO_TEST_CASE(shorter_names_cost_more)
{
    BOOST_CHECK_EQUAL(PricePerYear(2), 0);
    BOOST_CHECK_EQUAL(PricePerYear(3), 100 * COIN);
    BOOST_CHECK_EQUAL(PricePerYear(4), 20 * COIN);
    BOOST_CHECK_EQUAL(PricePerYear(5), 5 * COIN);
    BOOST_CHECK_EQUAL(PricePerYear(6), COIN);
    BOOST_CHECK_EQUAL(PricePerYear(32), COIN);
    BOOST_CHECK_EQUAL(Price(6, BLOCKS_PER_YEAR), COIN);
    BOOST_CHECK_EQUAL(Price(6, BLOCKS_PER_YEAR / 2), COIN / 2);
    BOOST_CHECK_EQUAL(Price(3, 2 * BLOCKS_PER_YEAR), 200 * COIN);
    // Rounded up, so a fraction of a block is never free.
    BOOST_CHECK_EQUAL(Price(6, 1), (COIN + BLOCKS_PER_YEAR - 1) / BLOCKS_PER_YEAR);
}

BOOST_AUTO_TEST_CASE(name_records_round_trip_and_are_signed)
{
    Person a, b;
    const std::vector<std::vector<unsigned char>> records = {
        CommitRecord("pilot", MakeSalt(7), a),
        ClaimRecord("pilot", MakeSalt(7), a, 200000),
        TransferRecord("pilot", b, a),
        SubnameRecord("pilot", "alice", b.x, 200000, a),
    };
    for (const std::vector<unsigned char>& raw : records) {
        NameRecord rec;
        BOOST_REQUIRE(ParseNameRecord(raw, rec));
        BOOST_CHECK(SerializeNameRecord(rec) == raw);
        BOOST_CHECK(raw.size() <= roster::MAX_RECORD_SIZE);
        BOOST_CHECK(VerifyNameRecord(rec, raw, a.x, CHAIN));
        if (rec.type != NameRecordType::COMMIT) {
            BOOST_CHECK(!VerifyNameRecord(rec, raw, b.x, CHAIN));
            BOOST_CHECK(!VerifyNameRecord(rec, raw, a.x, "main"));
        }
        // Not a roster record: a roster reader skips it.
        roster::Record roster_rec;
        BOOST_CHECK(roster::ParseRecord(raw, roster_rec) != roster::ParseError::OK);
        // Trailing bytes are a second spelling, and refused.
        std::vector<unsigned char> longer = raw;
        longer.push_back(0);
        BOOST_CHECK(!ParseNameRecord(longer, rec));
    }
    // Only the one valid spelling of a name parses.
    std::vector<unsigned char> raw = records[1];
    raw[4 + 32 + 1] = 'L';
    NameRecord rec;
    BOOST_CHECK(!ParseNameRecord(raw, rec));
}

BOOST_AUTO_TEST_CASE(registering_takes_a_matured_commitment_and_the_price)
{
    NameState state(CHAIN);
    Person a;
    const Salt salt = MakeSalt(3);
    const std::string name = "pilot";
    const CAmount price = Price(name.size(), BLOCKS_PER_YEAR);

    // A claim with no commitment does not count.
    BOOST_CHECK(state.Apply(At(100, ClaimRecord(name, salt, a, 100 + BLOCKS_PER_YEAR), price)) != "");

    BOOST_CHECK_EQUAL(state.Apply(At(100, CommitRecord(name, salt, a))), "");
    BOOST_CHECK_EQUAL(state.CommitHeight(Commitment(name, salt, a.x)), 100);

    // Too soon after the commitment.
    const int early = 100 + (int)COMMIT_MIN_AGE - 1;
    BOOST_CHECK(state.Apply(At(early, ClaimRecord(name, salt, a, early + BLOCKS_PER_YEAR), price)) != "");
    BOOST_CHECK(state.StatusOf(name, early) == Status::FREE);

    const int at = 100 + (int)COMMIT_MIN_AGE;
    // Burning too little.
    BOOST_CHECK(state.Apply(At(at, ClaimRecord(name, salt, a, at + BLOCKS_PER_YEAR), price - 1)) != "");
    // Signed by someone else.
    Person mallory;
    BOOST_CHECK(state.Apply(At(at, ClaimRecord(name, salt, a, at + BLOCKS_PER_YEAR, &mallory), price)) != "");
    // A term under a month.
    BOOST_CHECK(state.Apply(At(at, ClaimRecord(name, salt, a, at + MIN_TERM - 1), price)) != "");
    // Done properly.
    BOOST_CHECK_EQUAL(state.Apply(At(at, ClaimRecord(name, salt, a, at + BLOCKS_PER_YEAR), price)), "");
    BOOST_CHECK(state.StatusOf(name, at) == Status::LIVE);

    Resolution res;
    std::string why;
    BOOST_REQUIRE(state.Resolve("Pilot", at, res, why));
    BOOST_CHECK(res.key == a.x);
    BOOST_CHECK_EQUAL(res.expiry, (uint32_t)(at + BLOCKS_PER_YEAR));
    BOOST_CHECK_EQUAL(res.registered, at);
    BOOST_CHECK_EQUAL(state.CountLive(at), 1u);
}

BOOST_AUTO_TEST_CASE(a_claim_seen_in_a_mempool_cannot_be_stolen)
{
    // The holder's claim reveals the name. Someone who sees it and races it
    // has only a fresh commitment, which is too young, and by the time it is
    // old enough the name is taken.
    NameState state(CHAIN);
    Person a, thief;
    const int at = Register(state, "pilot", a, 100);
    BOOST_CHECK_EQUAL(state.Apply(At(at, CommitRecord("pilot", MakeSalt(9), thief))), "");
    const int later = at + (int)COMMIT_MIN_AGE;
    BOOST_CHECK(state.Apply(At(later, ClaimRecord("pilot", MakeSalt(9), thief, later + BLOCKS_PER_YEAR),
                               Price(5, BLOCKS_PER_YEAR))) != "");
    Resolution res;
    std::string why;
    BOOST_REQUIRE(state.Resolve("pilot", later, res, why));
    BOOST_CHECK(res.key == a.x);
}

BOOST_AUTO_TEST_CASE(holders_renew_by_hand_and_lapsed_names_come_free)
{
    NameState state(CHAIN);
    Person a, b;
    const int at = Register(state, "pilot", a, 100);
    const uint32_t expiry = at + BLOCKS_PER_YEAR;

    // Only the holder renews, and only into the future, at most two years ahead.
    const int mid = at + 1000;
    BOOST_CHECK(state.Apply(At(mid, ClaimRecord("pilot", Salt{}, b, expiry + BLOCKS_PER_YEAR), 100 * COIN)) != "");
    BOOST_CHECK(state.Apply(At(mid, ClaimRecord("pilot", Salt{}, a, expiry), 100 * COIN)) != "");
    BOOST_CHECK(state.Apply(At(mid, ClaimRecord("pilot", Salt{}, a, mid + MAX_TERM + 1), 100 * COIN)) != "");
    // Paying for the added year only, not for the time already paid.
    BOOST_CHECK(state.Apply(At(mid, ClaimRecord("pilot", Salt{}, a, expiry + BLOCKS_PER_YEAR),
                               Price(5, BLOCKS_PER_YEAR) - 1)) != "");
    BOOST_CHECK_EQUAL(state.Apply(At(mid, ClaimRecord("pilot", Salt{}, a, expiry + BLOCKS_PER_YEAR),
                                     Price(5, BLOCKS_PER_YEAR))), "");
    const uint32_t renewed = expiry + BLOCKS_PER_YEAR;
    BOOST_CHECK_EQUAL(state.Find("pilot")->expiry, renewed);

    // Past expiry it stops resolving, but stays the holder's for a month.
    Resolution res;
    std::string why;
    BOOST_CHECK(state.StatusOf("pilot", renewed) == Status::GRACE);
    BOOST_CHECK(!state.Resolve("pilot", renewed, res, why));
    BOOST_CHECK(state.CheckAvailable("pilot", b.x, renewed) != "");

    // After the grace period anyone may register it, with a commitment.
    const int free_at = renewed + GRACE;
    BOOST_CHECK(state.StatusOf("pilot", free_at) == Status::FREE);
    BOOST_CHECK_EQUAL(state.CheckAvailable("pilot", b.x, free_at), "");
    Register(state, "pilot", b, free_at, 5);
    BOOST_REQUIRE(state.Resolve("pilot", free_at + (int)COMMIT_MIN_AGE, res, why));
    BOOST_CHECK(res.key == b.x);
}

BOOST_AUTO_TEST_CASE(look_alikes_of_a_held_name_are_refused)
{
    NameState state(CHAIN);
    Person a, b;
    const int at = Register(state, "pilot", a, 100);
    BOOST_CHECK(state.CheckAvailable("pi1ot", b.x, at + 1) != "");
    const Salt salt = MakeSalt(4);
    BOOST_CHECK_EQUAL(state.Apply(At(at, CommitRecord("pi1ot", salt, b))), "");
    const int claim = at + (int)COMMIT_MIN_AGE;
    BOOST_CHECK(state.Apply(At(claim, ClaimRecord("pi1ot", salt, b, claim + BLOCKS_PER_YEAR), 5 * COIN)) != "");
    // The holder may have its own look-alikes.
    BOOST_CHECK_EQUAL(state.CheckAvailable("pi1ot", a.x, claim), "");
}

BOOST_AUTO_TEST_CASE(holders_transfer_and_issue_subnames)
{
    NameState state(CHAIN);
    Person a, b, alice, mallory;
    const int at = Register(state, "pilot", a, 100);
    const int h = at + 10;

    // Subnames: by the holder only, free, gone when removed.
    BOOST_CHECK(state.Apply(At(h, SubnameRecord("pilot", "alice", alice.x, at + BLOCKS_PER_YEAR, mallory))) != "");
    BOOST_CHECK_EQUAL(state.Apply(At(h, SubnameRecord("pilot", "alice", alice.x, at + 2 * BLOCKS_PER_YEAR, a))), "");
    Resolution res;
    std::string why;
    BOOST_REQUIRE(state.Resolve("alice.pilot", h, res, why));
    BOOST_CHECK(res.key == alice.x);
    BOOST_CHECK(res.subname);
    // A subname never outlives the name above it.
    BOOST_CHECK_EQUAL(res.expiry, (uint32_t)(at + BLOCKS_PER_YEAR));
    BOOST_CHECK(!state.Resolve("bob.pilot", h, res, why));

    // Transfer: by the holder only.
    BOOST_CHECK(state.Apply(At(h + 1, TransferRecord("pilot", mallory, mallory))) != "");
    BOOST_CHECK_EQUAL(state.Apply(At(h + 1, TransferRecord("pilot", b, a))), "");
    BOOST_REQUIRE(state.Resolve("pilot", h + 1, res, why));
    BOOST_CHECK(res.key == b.x);
    // The old holder can no longer renew or issue.
    BOOST_CHECK(state.Apply(At(h + 2, SubnameRecord("pilot", "x", a.x, at + BLOCKS_PER_YEAR, a))) != "");
    BOOST_CHECK(state.Apply(At(h + 2, ClaimRecord("pilot", Salt{}, a, at + 2 * BLOCKS_PER_YEAR), 100 * COIN)) != "");
    // The new one can remove what the old one issued.
    BOOST_CHECK_EQUAL(state.Apply(At(h + 3, SubnameRecord("pilot", "alice", roster::KeyBytes{}, 0, b))), "");
    BOOST_CHECK(!state.Resolve("alice.pilot", h + 3, res, why));
}

BOOST_AUTO_TEST_CASE(a_commitment_cannot_be_used_twice_or_too_late)
{
    NameState state(CHAIN);
    Person a;
    const Salt salt = MakeSalt(2);
    BOOST_CHECK_EQUAL(state.Apply(At(100, CommitRecord("relay", salt, a))), "");
    const int late = 100 + (int)COMMIT_MAX_AGE + 1;
    BOOST_CHECK(state.Apply(At(late, ClaimRecord("relay", salt, a, late + BLOCKS_PER_YEAR), 5 * COIN)) != "");
    BOOST_CHECK(state.StatusOf("relay", late) == Status::FREE);
}

BOOST_AUTO_TEST_CASE(names_count_only_from_the_networks_start)
{
    // Mainnet has no start height yet, so nothing on it counts.
    NameState state("main");
    Person a;
    const Salt salt = MakeSalt(1);
    BOOST_CHECK(state.Apply(At(100, CommitRecord("pilot", salt, a))) != "");
    BOOST_CHECK(state.CheckAvailable("pilot", a.x, 1000) != "");
}

BOOST_AUTO_TEST_SUITE_END()
