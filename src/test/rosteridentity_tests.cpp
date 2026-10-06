// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Identities, rotation, vetoes and age (design note 001, §5 and §7), and the
// one rule for who is in the roster that the node, its snapshots and the
// commitment in blocks share.

#include <roster/commitment.h>
#include <roster/identity.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace roster;

BOOST_FIXTURE_TEST_SUITE(rosteridentity_tests, BasicTestingSetup)

namespace {

KeyBytes K(unsigned char fill)
{
    KeyBytes k;
    k.fill(fill);
    return k;
}

uint32_t g_ordinal = 0;

HeldRecord Announce(const KeyBytes& op, int height, uint32_t prev, uint32_t expiry = 0)
{
    HeldRecord h;
    h.rec.type = RecordType::ANNOUNCE;
    h.rec.op_key = op;
    h.rec.prev_height = prev;
    h.rec.expiry_height = expiry ? expiry : height + MIN_TTL;
    h.height = height;
    h.ordinal = g_ordinal++;
    return h;
}

HeldRecord Delegate(const KeyBytes& id, const KeyBytes& op, int height, uint32_t expiry,
                    const Optional<uint256>& commit = nullopt)
{
    HeldRecord h;
    h.rec.type = RecordType::DELEGATE;
    h.rec.id_key = id;
    h.rec.op_key = op;
    h.rec.expiry_height = expiry;
    h.rec.recovery_commit = commit;
    h.height = height;
    h.ordinal = g_ordinal++;
    return h;
}

HeldRecord Rotate(const KeyBytes& from, const KeyBytes& to, int height)
{
    HeldRecord h;
    h.rec.type = RecordType::ROTATE;
    h.rec.id_key = from;
    h.rec.new_id_key = to;
    h.height = height;
    h.ordinal = g_ordinal++;
    return h;
}

HeldRecord Veto(const KeyBytes& id, const KeyBytes& recovery, int height)
{
    HeldRecord h;
    h.rec.type = RecordType::VETO;
    h.rec.id_key = id;
    h.rec.recovery_key = recovery;
    h.height = height;
    h.ordinal = g_ordinal++;
    return h;
}

WindowAnnouncement At(const KeyBytes& key, int height, uint32_t expiry, unsigned char tag)
{
    WindowAnnouncement a;
    a.key = key;
    a.height = height;
    a.ordinal = g_ordinal++;
    a.expiry = expiry;
    a.raw = {tag, (unsigned char)(expiry & 0xff), (unsigned char)(expiry >> 8)};
    return a;
}

} // namespace

BOOST_AUTO_TEST_CASE(an_age_chain_follows_prev_height_back)
{
    const KeyBytes op = K(1);
    std::vector<HeldRecord> history = {Announce(op, 100, 0), Announce(op, 200, 100), Announce(op, 300, 200)};
    AgeChain chain = WalkAgeChain(op, history, 1000);
    BOOST_CHECK_EQUAL(chain.links.size(), 3U);
    BOOST_CHECK_EQUAL(chain.anchor, 100);
    BOOST_CHECK(!chain.delegation);

    // A link pointing nowhere ends the chain there: history cannot be claimed.
    history = {Announce(op, 100, 0), Announce(op, 300, 150)};
    chain = WalkAgeChain(op, history, 1000);
    BOOST_CHECK_EQUAL(chain.anchor, 300);

    // Nor can a link point forwards.
    history = {Announce(op, 300, 400), Announce(op, 400, 0)};
    chain = WalkAgeChain(op, history, 350);
    BOOST_CHECK_EQUAL(chain.anchor, 300);

    // Records after the height asked about do not count.
    chain = WalkAgeChain(op, {Announce(op, 500, 0)}, 400);
    BOOST_CHECK_EQUAL(chain.anchor, -1);
}

BOOST_AUTO_TEST_CASE(a_key_accepts_an_identity_by_linking_to_its_delegation)
{
    const KeyBytes op = K(1), id = K(2), other = K(3);
    // The identity delegates at 150; the key's next announcement links to it.
    std::vector<HeldRecord> history = {Announce(op, 100, 0), Delegate(id, op, 150, 150 + MAX_TTL),
                                       Announce(op, 200, 150)};
    AgeChain chain = WalkAgeChain(op, history, 1000);
    BOOST_REQUIRE(chain.delegation);
    BOOST_CHECK(chain.delegation->rec.id_key == id);
    BOOST_CHECK_EQUAL(chain.anchor, 150);

    // Somebody else's delegation the key never linked to claims nothing.
    history = {Announce(op, 100, 0), Delegate(other, op, 120, 120 + MAX_TTL), Announce(op, 200, 100)};
    chain = WalkAgeChain(op, history, 1000);
    BOOST_CHECK(!chain.delegation);
    BOOST_CHECK_EQUAL(chain.anchor, 100);

    // Two delegations in the block the key pointed at: it accepted neither.
    history = {Delegate(id, op, 150, 150 + MAX_TTL), Delegate(other, op, 150, 150 + MAX_TTL), Announce(op, 200, 150)};
    chain = WalkAgeChain(op, history, 1000);
    BOOST_CHECK(!chain.delegation);
}

BOOST_AUTO_TEST_CASE(only_the_first_delegation_commits_to_a_recovery_key)
{
    const KeyBytes id = K(2), recovery = K(9), thief = K(8);
    IdentityBook book;
    book.Build({Delegate(id, K(1), 100, 100 + MAX_TTL, RecoveryCommitment(recovery)),
                Delegate(id, K(4), 200, 200 + MAX_TTL, RecoveryCommitment(thief))}, 300);
    const IdentityState* s = book.Find(id);
    BOOST_REQUIRE(s);
    BOOST_CHECK(*s->recovery_commit == RecoveryCommitment(recovery));
    BOOST_CHECK_EQUAL(s->first_height, 100);
    BOOST_CHECK(book.Delegates(id, K(1), 300));
    BOOST_CHECK(book.Delegates(id, K(4), 300));
    // A delegation lapses at its expiry.
    BOOST_CHECK(!book.Delegates(id, K(1), 100 + MAX_TTL));
}

BOOST_AUTO_TEST_CASE(a_rotation_takes_effect_after_the_veto_window_and_carries_age)
{
    const KeyBytes old_id = K(2), new_id = K(3), op = K(1);
    std::vector<HeldRecord> records = {Delegate(old_id, op, 100, 100 + MAX_TTL, RecoveryCommitment(K(9))),
                                       Rotate(old_id, new_id, 500), Delegate(new_id, op, 501, 501 + MAX_TTL)};
    IdentityBook book;
    book.Build(records, 500 + ROTATE_VETO - 1);
    BOOST_CHECK(book.Find(old_id)->rotating);
    BOOST_CHECK(!book.Find(old_id)->retired);
    BOOST_CHECK(book.Current(old_id) == old_id);
    // Until then the new key is a young identity of its own.
    BOOST_CHECK_EQUAL(book.Find(new_id)->first_height, 501);

    book.Build(records, 500 + ROTATE_VETO);
    const IdentityState* old_s = book.Find(old_id);
    const IdentityState* new_s = book.Find(new_id);
    BOOST_CHECK(old_s->retired);
    BOOST_CHECK(book.Current(old_id) == new_id);
    // The new key carries the age and the recovery commitment.
    BOOST_CHECK_EQUAL(new_s->first_height, 100);
    BOOST_CHECK(*new_s->recovery_commit == RecoveryCommitment(K(9)));
    // The old key's delegations stop counting; it may be in other hands now.
    BOOST_CHECK(!book.Delegates(old_id, op, 600 + ROTATE_VETO));
    BOOST_CHECK(book.Delegates(new_id, op, 600 + ROTATE_VETO));
}

BOOST_AUTO_TEST_CASE(the_recovery_key_vetoes_a_rotation_in_its_window_only)
{
    const KeyBytes id = K(2), thief = K(7), recovery = K(9);
    const HeldRecord first = Delegate(id, K(1), 100, 100 + MAX_TTL, RecoveryCommitment(recovery));

    // In time, with the right key: cancelled, and the identity stays.
    IdentityBook book;
    book.Build({first, Rotate(id, thief, 500), Veto(id, recovery, 600)}, 2000);
    BOOST_CHECK(!book.Find(id)->retired);
    BOOST_CHECK(!book.Find(id)->rotating);
    BOOST_CHECK_EQUAL(book.Find(id)->vetoed.size(), 1U);

    // The wrong key does nothing.
    book.Build({first, Rotate(id, thief, 500), Veto(id, K(6), 600)}, 2000);
    BOOST_CHECK(book.Find(id)->retired);
    BOOST_CHECK(book.Current(id) == thief);

    // Too late does nothing either.
    book.Build({first, Rotate(id, thief, 500), Veto(id, recovery, 500 + ROTATE_VETO)}, 2000);
    BOOST_CHECK(book.Find(id)->retired);

    // One rotation at a time: the first to confirm holds the slot.
    book.Build({first, Rotate(id, thief, 500), Rotate(id, K(5), 501)}, 2000);
    BOOST_CHECK(book.Current(id) == thief);

    // After a veto the owner rotates away for good.
    book.Build({first, Rotate(id, thief, 500), Veto(id, recovery, 600), Rotate(id, K(5), 601)}, 2000);
    BOOST_CHECK(book.Current(id) == K(5));
}

BOOST_AUTO_TEST_CASE(a_rotation_cannot_graft_onto_a_key_with_its_own_past)
{
    const KeyBytes young = K(2), old = K(3);
    IdentityBook book;
    book.Build({Delegate(old, K(1), 50, 50 + MAX_TTL), Delegate(young, K(4), 400, 400 + MAX_TTL),
                Rotate(young, old, 500)}, 2000);
    BOOST_CHECK(!book.Find(young)->retired);
    BOOST_CHECK_EQUAL(book.Find(old)->first_height, 50);
}

BOOST_AUTO_TEST_CASE(the_latest_announcement_decides_and_a_replay_is_not_later)
{
    const KeyBytes a = K(1), b = K(2), c = K(3);
    std::vector<WindowAnnouncement> window = {
        At(a, 100, 100000, 1), At(a, 200, 5000, 2), // a renewed for less: it ends at 5000
        At(b, 100, 100000, 3), At(b, 200, 90000, 4), At(b, 300, 100000, 3), // b's first record replayed
        At(c, 100, 100000, 5),
    };
    std::vector<WindowAnnouncement> live = SelectLive(window, 6000, [&](const KeyBytes& k) { return k == c; });
    BOOST_REQUIRE_EQUAL(live.size(), 1U);
    BOOST_CHECK(live[0].key == b);
    // The replay at 300 did not wind b back to its first record.
    BOOST_CHECK_EQUAL(live[0].height, 200);
    BOOST_CHECK_EQUAL(live[0].expiry, 90000U);

    live = SelectLive(window, 4000, nullptr);
    BOOST_CHECK_EQUAL(live.size(), 3U);
}

BOOST_AUTO_TEST_SUITE_END()
