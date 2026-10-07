// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <names/name.h>
#include <names/record.h>
#include <names/sale.h>
#include <names/state.h>
#include <script/standard.h>

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

/** A sale of `name` by `seller`, on a sale coin at `coin`, as sellname makes it. */
struct Sale {
    COutPoint coin;
    CScript coin_script;
    CScript payout;
    CAmount payout_value{0};
    std::vector<unsigned char> raw;
};

Sale MakeSale(const std::string& name, const Person& seller, CAmount price, unsigned char coin_fill)
{
    Sale s;
    uint256 txid;
    std::fill(txid.begin(), txid.end(), coin_fill);
    s.coin = COutPoint(txid, 0);
    CKey payee;
    payee.MakeNewKey(true);
    s.payout = GetScriptForDestination(PKHash(payee.GetPubKey()));
    s.payout_value = price + SALE_COIN_VALUE;
    CKey sale_key;
    BOOST_REQUIRE(SaleKey(seller.key, name, s.payout, sale_key));
    s.coin_script = SaleCoinScript(sale_key.GetPubKey());
    NameRecord rec;
    rec.type = NameRecordType::SELL;
    rec.name = name;
    rec.coin = s.coin;
    rec.payout_value = s.payout_value;
    rec.payout = s.payout;
    BOOST_REQUIRE(SignSale(sale_key, s.coin, s.coin_script, s.payout_value, s.payout, rec.coin_sig));
    BOOST_REQUIRE(SignNameRecord(seller.key, rec, CHAIN, s.raw));
    return s;
}

/** A SELL as the index files it: its transaction spent the sale coin's transaction. */
IndexedRecord SellAt(int height, const Sale& sale)
{
    IndexedRecord r = At(height, sale.raw);
    r.coin_funded = true;
    return r;
}

/** A transaction `txid` spending `coin`, as the index files it. */
IndexedRecord SpendAt(int height, const COutPoint& coin, const uint256& txid)
{
    IndexedRecord r;
    r.spend = true;
    r.spent = coin;
    r.height = height;
    r.txid = txid;
    return r;
}

std::vector<unsigned char> BuyRecord(const std::string& name, const Person& buyer, uint32_t expiry)
{
    NameRecord rec;
    rec.type = NameRecordType::BUY;
    rec.key = buyer.x;
    rec.name = name;
    rec.expiry_height = expiry;
    std::vector<unsigned char> raw;
    BOOST_REQUIRE(SignNameRecord(buyer.key, rec, CHAIN, raw));
    return raw;
}

IndexedRecord BuyAt(int height, const std::vector<unsigned char>& raw, CAmount burned, const uint256& txid)
{
    IndexedRecord r = At(height, raw, burned);
    r.txid = txid;
    return r;
}

uint256 Txid(unsigned char fill)
{
    uint256 h;
    std::fill(h.begin(), h.end(), fill);
    return h;
}

/** Register `name` for `owner`: commit at `at`, claim COMMIT_MIN_AGE later for a year. */
int Register(NameState& state, const std::string& name, const Person& owner, int at, unsigned char salt_fill = 1)
{
    const Salt salt = MakeSalt(salt_fill);
    BOOST_REQUIRE_EQUAL(state.Apply(At(at, CommitRecord(name, salt, owner))), "");
    const int claim_at = at + (int)COMMIT_MIN_AGE;
    const uint32_t expiry = claim_at + BLOCKS_PER_YEAR;
    BOOST_REQUIRE_EQUAL(state.Apply(At(claim_at, ClaimRecord(name, salt, owner, expiry))), "");
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
    // One and two letters are names like any other.
    BOOST_CHECK(IsValidRoot("a"));
    BOOST_CHECK(IsValidRoot("ab"));
    BOOST_CHECK(IsValidRoot("7"));
    BOOST_CHECK(!IsValidRoot(""));

    std::string root, label;
    BOOST_CHECK(SplitName("pilot", root, label) && root == "pilot" && label.empty());
    BOOST_CHECK(SplitName("alice.pilot", root, label) && root == "pilot" && label == "alice");
    BOOST_CHECK(SplitName("a.pilot", root, label));
    BOOST_CHECK(!SplitName("a.b.pilot", root, label));
    BOOST_CHECK(SplitName("alice.lu", root, label) && root == "lu" && label == "alice");
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

BOOST_AUTO_TEST_CASE(names_of_any_length_cost_only_the_fee)
{
    // Nothing is burned to register or renew, whatever the length.
    NameState state(CHAIN);
    Person a;
    for (const std::string& name : {"x", "ab", "q1", "pilot"}) {
        const int at = Register(state, name, a, 100);
        BOOST_CHECK(state.StatusOf(name, at) == Status::LIVE);
        const uint32_t expiry = state.Find(name)->expiry;
        BOOST_CHECK_EQUAL(state.Apply(At(at + 10, ClaimRecord(name, Salt{}, a, expiry + BLOCKS_PER_YEAR))), "");
        BOOST_CHECK_EQUAL(state.Find(name)->expiry, expiry + BLOCKS_PER_YEAR);
    }
    BOOST_CHECK_EQUAL(state.CountLive(200), 4u);
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

BOOST_AUTO_TEST_CASE(registering_takes_a_matured_commitment)
{
    NameState state(CHAIN);
    Person a;
    const Salt salt = MakeSalt(3);
    const std::string name = "pilot";
    const CAmount price = 0;

    // A claim with no commitment does not count.
    BOOST_CHECK(state.Apply(At(100, ClaimRecord(name, salt, a, 100 + BLOCKS_PER_YEAR), price)) != "");

    BOOST_CHECK_EQUAL(state.Apply(At(100, CommitRecord(name, salt, a))), "");
    BOOST_CHECK_EQUAL(state.CommitHeight(Commitment(name, salt, a.x)), 100);

    // Too soon after the commitment.
    const int early = 100 + (int)COMMIT_MIN_AGE - 1;
    BOOST_CHECK(state.Apply(At(early, ClaimRecord(name, salt, a, early + BLOCKS_PER_YEAR), price)) != "");
    BOOST_CHECK(state.StatusOf(name, early) == Status::FREE);

    const int at = 100 + (int)COMMIT_MIN_AGE;
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
    BOOST_CHECK(state.Apply(At(later, ClaimRecord("pilot", MakeSalt(9), thief, later + BLOCKS_PER_YEAR))) != "");
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
    // For the fee alone.
    BOOST_CHECK_EQUAL(state.Apply(At(mid, ClaimRecord("pilot", Salt{}, a, expiry + BLOCKS_PER_YEAR))), "");
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
    // Mainnet opened at 1,220,000: nothing before counts, everything after does.
    NameState state("main");
    BOOST_CHECK_EQUAL(state.StartHeight(), 1220000);
    Person a;
    const Salt salt = MakeSalt(1);
    BOOST_CHECK(state.Apply(At(100, CommitRecord("pilot", salt, a))) != "");
    BOOST_CHECK(state.CheckAvailable("pilot", a.x, 1000) != "");
    BOOST_CHECK_EQUAL(state.CheckAvailable("pilot", a.x, 1220001), "");
}

BOOST_AUTO_TEST_CASE(sale_records_round_trip_and_the_coin_signature_spends_the_coin)
{
    for (int i = 0; i < 50; ++i) {
        Person seller;
        const Sale sale = MakeSale("pilot", seller, (i + 1) * COIN, (unsigned char)i);
        NameRecord parsed;
        BOOST_REQUIRE(ParseNameRecord(sale.raw, parsed));
        BOOST_CHECK(parsed.type == NameRecordType::SELL);
        BOOST_CHECK(parsed.coin == sale.coin);
        BOOST_CHECK_EQUAL(parsed.payout_value, sale.payout_value);
        BOOST_CHECK(parsed.payout == sale.payout);
        BOOST_CHECK(SerializeNameRecord(parsed) == sale.raw);
        BOOST_CHECK(VerifyNameRecord(parsed, sale.raw, seller.x, CHAIN));
        BOOST_CHECK(sale.raw.size() <= roster::MAX_RECORD_SIZE);
        // The signature spends the coin only into the payout it names.
        const CTxOut coin(SALE_COIN_VALUE, sale.coin_script);
        BOOST_CHECK(CheckSale(sale.coin, coin, sale.payout_value, sale.payout, parsed.coin_sig));
        BOOST_CHECK(!CheckSale(sale.coin, coin, sale.payout_value - 1, sale.payout, parsed.coin_sig));
        BOOST_CHECK(!CheckSale(sale.coin, coin, sale.payout_value, sale.coin_script, parsed.coin_sig));
        BOOST_CHECK(!CheckSale(COutPoint(sale.coin.hash, 1), coin, sale.payout_value, sale.payout, parsed.coin_sig));
    }
    Person buyer;
    NameRecord buy;
    BOOST_REQUIRE(ParseNameRecord(BuyRecord("pilot", buyer, 5000), buy));
    BOOST_CHECK(buy.type == NameRecordType::BUY);
    BOOST_CHECK(buy.key == buyer.x);
    BOOST_CHECK_EQUAL(buy.expiry_height, 5000U);
}

BOOST_AUTO_TEST_CASE(a_name_for_sale_is_bought_in_the_transaction_that_spends_its_coin)
{
    NameState state(CHAIN);
    Person seller, buyer, other;
    const int at = Register(state, "pilot", seller, 100);
    const int h = at + 10;
    BOOST_REQUIRE_EQUAL(state.Apply(At(h, SubnameRecord("pilot", "alice", other.x, at + BLOCKS_PER_YEAR, seller))), "");

    // Only the holder can sell, and only once its sale coin is on the chain.
    BOOST_CHECK(state.Apply(SellAt(h, MakeSale("pilot", other, 7 * COIN, 1))) != "");
    const Sale sale = MakeSale("pilot", seller, 7 * COIN, 2);
    BOOST_CHECK(state.Apply(At(h, sale.raw)) != "");
    BOOST_REQUIRE_EQUAL(state.Apply(SellAt(h, sale)), "");
    BOOST_REQUIRE(state.ActiveOffer("pilot", h + 1) != nullptr);
    BOOST_CHECK_EQUAL(state.CheckSell("pilot", seller.x, h + 1), "pilot is up for sale already; take it off sale first.");

    // While the coin is unspent the seller can neither re-list nor give it away.
    BOOST_CHECK(state.Apply(SellAt(h + 1, MakeSale("pilot", seller, 1 * COIN, 3))) != "");
    BOOST_CHECK(state.Apply(At(h + 1, TransferRecord("pilot", other, seller))) != "");

    // A BUY in a transaction that did not spend the coin does nothing.
    const uint32_t expiry = state.BuyExpiry("pilot", 1, h + 2);
    BOOST_CHECK_EQUAL(expiry, (uint32_t)(at + 2 * BLOCKS_PER_YEAR));
    BOOST_CHECK_EQUAL(state.CheckBuy("pilot", buyer.x, expiry, h + 2), "");
    BOOST_CHECK(state.CheckBuy("pilot", seller.x, expiry, h + 2) != "");
    const std::vector<unsigned char> buy = BuyRecord("pilot", buyer, expiry);
    BOOST_CHECK(state.Apply(BuyAt(h + 2, buy, 0, Txid(9))) != "");

    // The one that spends it moves the name, clean of the seller's subnames.
    state.ApplyBlock(h + 2, {SpendAt(h + 2, sale.coin, Txid(10)), BuyAt(h + 2, buy, 0, Txid(10))});
    Resolution res;
    std::string why;
    BOOST_REQUIRE(state.Resolve("pilot", h + 2, res, why));
    BOOST_CHECK(res.key == buyer.x);
    BOOST_CHECK_EQUAL(res.expiry, expiry);
    BOOST_CHECK(!state.Resolve("alice.pilot", h + 2, res, why));
    BOOST_CHECK(state.ActiveOffer("pilot", h + 3) == nullptr);

    // The coin is gone, so nobody can buy it again, and the new holder can sell.
    BOOST_CHECK(state.CheckBuy("pilot", other.x, expiry, h + 3) != "");
    BOOST_CHECK_EQUAL(state.CheckSell("pilot", buyer.x, h + 3), "");
}

BOOST_AUTO_TEST_CASE(a_sale_ends_when_its_coin_is_spent_without_a_purchase)
{
    NameState state(CHAIN);
    Person seller, buyer, friend_;
    const int at = Register(state, "relay", seller, 100);
    const int h = at + 10;
    const Sale sale = MakeSale("relay", seller, 3 * COIN, 4);
    BOOST_REQUIRE_EQUAL(state.Apply(SellAt(h, sale)), "");

    // Cancelling is spending the coin; a BUY in a later transaction is too late.
    state.ApplyBlock(h + 1, {SpendAt(h + 1, sale.coin, Txid(20))});
    BOOST_CHECK(state.ActiveOffer("relay", h + 2) == nullptr);
    const uint32_t expiry = state.BuyExpiry("relay", 1, h + 2);
    state.ApplyBlock(h + 2, {BuyAt(h + 2, BuyRecord("relay", buyer, expiry), 100 * COIN, Txid(20))});
    Resolution res;
    std::string why;
    BOOST_REQUIRE(state.Resolve("relay", h + 2, res, why));
    BOOST_CHECK(res.key == seller.x);

    // Off sale, the holder can transfer it again.
    BOOST_CHECK_EQUAL(state.Apply(At(h + 3, TransferRecord("relay", friend_, seller))), "");
    BOOST_REQUIRE(state.Resolve("relay", h + 3, res, why));
    BOOST_CHECK(res.key == friend_.x);
}

BOOST_AUTO_TEST_CASE(a_purchase_keeps_or_renews_the_term_up_to_two_years_ahead)
{
    NameState state(CHAIN);
    Person seller, buyer;
    const int at = Register(state, "names", seller, 100);
    const int h = at + 10;
    const Sale sale = MakeSale("names", seller, COIN, 5);
    BOOST_REQUIRE_EQUAL(state.Apply(SellAt(h, sale)), "");
    const uint32_t from = at + BLOCKS_PER_YEAR;
    // Not shorter than it is, not past two years; keeping it as it is, or
    // renewing it for nothing, are both fine.
    BOOST_CHECK(state.CheckBuy("names", buyer.x, from - 1, h) != "");
    BOOST_CHECK_EQUAL(state.CheckBuy("names", buyer.x, from, h), "");
    BOOST_CHECK_EQUAL(state.CheckBuy("names", buyer.x, from + MIN_TERM, h), "");
    BOOST_CHECK(state.CheckBuy("names", buyer.x, h + MAX_TERM + 1, h) != "");
    // Two years asked for stop at the limit.
    BOOST_CHECK_EQUAL(state.BuyExpiry("names", 2, h), (uint32_t)h + MAX_TERM);
}

BOOST_AUTO_TEST_CASE(only_a_key_itself_says_where_it_is_paid)
{
    NameState state(CHAIN);
    Person a, mallory;
    CKey spend, other_spend;
    spend.MakeNewKey(true);
    other_spend.MakeNewKey(true);
    NameRecord rec;
    rec.type = NameRecordType::PAYKEY;
    rec.key = a.x;
    rec.point = spend.GetPubKey();
    std::vector<unsigned char> raw, forged;
    BOOST_REQUIRE(SignNameRecord(a.key, rec, CHAIN, raw));
    BOOST_REQUIRE(SignNameRecord(mallory.key, rec, CHAIN, forged));
    BOOST_CHECK_EQUAL(raw.size(), 133U);
    NameRecord back;
    BOOST_REQUIRE(ParseNameRecord(raw, back));
    BOOST_CHECK(SerializeNameRecord(back) == raw);
    BOOST_CHECK(back.point == spend.GetPubKey());
    // A spending key that is not a point on the curve does not parse.
    std::vector<unsigned char> bad = raw;
    bad[4 + 32] = 0x05;
    BOOST_CHECK(!ParseNameRecord(bad, back));

    BOOST_CHECK(!state.PaymentKey(a.x));
    // Nobody else can point a's payments at their own wallet.
    BOOST_CHECK(state.Apply(At(100, forged)) != "");
    BOOST_CHECK(!state.PaymentKey(a.x));
    BOOST_CHECK_EQUAL(state.Apply(At(101, raw)), "");
    const PayKey* pk = state.PaymentKey(a.x);
    BOOST_REQUIRE(pk);
    BOOST_CHECK(pk->spend == spend.GetPubKey());
    BOOST_CHECK_EQUAL(pk->height, 101);
    // A later key takes over, from its own height.
    rec.point = other_spend.GetPubKey();
    BOOST_REQUIRE(SignNameRecord(a.key, rec, CHAIN, raw));
    BOOST_CHECK_EQUAL(state.Apply(At(150, raw)), "");
    pk = state.PaymentKey(a.x);
    BOOST_REQUIRE(pk);
    BOOST_CHECK(pk->spend == other_spend.GetPubKey());
    BOOST_CHECK_EQUAL(pk->height, 150);

    // A payment's marker says nothing about names, so it changes nothing.
    CKey e;
    e.MakeNewKey(true);
    NameRecord marker;
    marker.type = NameRecordType::PAYMENT;
    marker.point = e.GetPubKey();
    const std::vector<unsigned char> marker_raw = SerializeNameRecord(marker);
    BOOST_CHECK_EQUAL(marker_raw.size(), 37U);
    BOOST_REQUIRE(ParseNameRecord(marker_raw, back));
    BOOST_CHECK(back.point == e.GetPubKey());
    BOOST_CHECK(state.Apply(At(151, marker_raw)) != "");
    BOOST_CHECK(!state.PaymentKey(mallory.x));
}

BOOST_AUTO_TEST_SUITE_END()
