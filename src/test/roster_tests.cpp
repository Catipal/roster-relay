// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <index/rosterindex.h>
#include <key.h>
#include <primitives/block.h>
#include <roster/commitment.h>
#include <roster/record.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>

using namespace roster;

namespace {

const std::string CHAIN_MAIN = "main";
const std::string CHAIN_TEST = "test";

//! A valid, distinct secret key per seed. Byte 31 varies so no seed can
//! produce the all-zero key, which is not a valid scalar.
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
    // Drop the compression prefix; the x-only key is the remaining 32 bytes.
    KeyBytes out;
    std::memcpy(out.data(), pk.data() + 1, RECORD_KEY_SIZE);
    return out;
}

Endpoint EpIPv4(uint16_t port)
{
    Endpoint ep;
    ep.network = EP_IPV4;
    ep.addr = {192, 0, 2, 1};
    ep.port = port;
    return ep;
}

Endpoint EpIPv6(uint16_t port)
{
    Endpoint ep;
    ep.network = EP_IPV6;
    ep.addr.assign(ADDR_SIZE_IPV6, 0xab);
    ep.port = port;
    return ep;
}

Endpoint EpOnion(uint16_t port)
{
    Endpoint ep;
    ep.network = EP_TORV3;
    ep.addr.assign(ADDR_SIZE_TORV3, 0x5c);
    ep.port = port;
    return ep;
}

Record MakeAnnounce(const CKey& key)
{
    Record rec;
    rec.type = RecordType::ANNOUNCE;
    rec.op_key = XOnly(key);
    rec.expiry_height = 1233421;
    rec.services = SERVICE_RESERVED_RELAY;
    rec.prev_height = 1219021;
    rec.endpoints.push_back(EpIPv4(9345));
    return rec;
}

//! Sign in place. The signature covers everything preceding it, so the
//! placeholder bytes present at serialisation time do not affect the hash.
void SignInPlace(Record& rec, const CKey& key, const std::string& chain)
{
    const std::vector<unsigned char> raw = SerializeRecord(rec);
    const uint256 sighash = RecordSigHash(raw, rec.type, chain);
    BOOST_REQUIRE(key.SignSchnorr(sighash, Span<unsigned char>(rec.sig.data(), rec.sig.size())));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(roster_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(announce_roundtrip)
{
    const CKey key = MakeKey(1);
    const Record in = MakeAnnounce(key);

    const std::vector<unsigned char> raw = SerializeRecord(in);
    Record out;
    BOOST_CHECK_EQUAL(ParseErrorString(ParseRecord(raw, out)), "ok");

    BOOST_CHECK(out.type == RecordType::ANNOUNCE);
    BOOST_CHECK(out.op_key == in.op_key);
    BOOST_CHECK_EQUAL(out.expiry_height, in.expiry_height);
    BOOST_CHECK_EQUAL(out.services, in.services);
    BOOST_CHECK_EQUAL(out.prev_height, in.prev_height);
    BOOST_CHECK_EQUAL(out.endpoints.size(), 1U);
    BOOST_CHECK(out.endpoints[0] == in.endpoints[0]);
    BOOST_CHECK(!out.meta_hash.has_value());

    // Canonical encoding: re-serialising a parsed record reproduces the bytes.
    BOOST_CHECK(SerializeRecord(out) == raw);
}

//! The sizes quoted in design note 001 §1. If one of these moves, the growth
//! arithmetic in §4 moves with it, so they are asserted rather than assumed.
BOOST_AUTO_TEST_CASE(documented_record_sizes)
{
    const CKey key = MakeKey(2);
    const CKey key2 = MakeKey(3);

    Record ann = MakeAnnounce(key);
    BOOST_CHECK_EQUAL(SerializeRecord(ann).size(), 120U); // single IPv4

    ann.endpoints.clear();
    ann.services |= SERVICE_RESERVED_RENDEZVOUS;
    BOOST_CHECK_EQUAL(SerializeRecord(ann).size(), 113U); // no endpoints: listed, not dialable

    ann.endpoints = {EpOnion(9345)};
    BOOST_CHECK_EQUAL(SerializeRecord(ann).size(), 148U); // onion-only

    ann.endpoints = {EpIPv4(9345), EpOnion(9345)};
    BOOST_CHECK_EQUAL(SerializeRecord(ann).size(), 155U); // dual-stack

    ann.endpoints = {EpIPv4(9345)};
    ann.meta_hash = uint256::ONE;
    BOOST_CHECK_EQUAL(SerializeRecord(ann).size(), 152U); // 120 + 32

    Record rev;
    rev.type = RecordType::REVOKE;
    rev.op_key = XOnly(key);
    BOOST_CHECK_EQUAL(SerializeRecord(rev).size(), 100U);

    Record del;
    del.type = RecordType::DELEGATE;
    del.id_key = XOnly(key);
    del.op_key = XOnly(key2);
    del.expiry_height = 1233421;
    BOOST_CHECK_EQUAL(SerializeRecord(del).size(), 136U);
    del.recovery_commit = uint256::ONE;
    BOOST_CHECK_EQUAL(SerializeRecord(del).size(), 168U);

    Record rot;
    rot.type = RecordType::ROTATE;
    rot.id_key = XOnly(key);
    rot.new_id_key = XOnly(key2);
    BOOST_CHECK_EQUAL(SerializeRecord(rot).size(), 132U);

    Record veto;
    veto.type = RecordType::VETO;
    veto.id_key = XOnly(key);
    veto.recovery_key = XOnly(key2);
    BOOST_CHECK_EQUAL(SerializeRecord(veto).size(), 132U);
}

BOOST_AUTO_TEST_CASE(all_types_roundtrip)
{
    const CKey a = MakeKey(4);
    const CKey b = MakeKey(5);

    std::vector<Record> records;
    {
        Record r;
        r.type = RecordType::REVOKE;
        r.op_key = XOnly(a);
        records.push_back(r);
    }
    {
        Record r;
        r.type = RecordType::DELEGATE;
        r.id_key = XOnly(a);
        r.op_key = XOnly(b);
        r.expiry_height = 99;
        r.recovery_commit = uint256::ONE;
        records.push_back(r);
    }
    {
        Record r;
        r.type = RecordType::ROTATE;
        r.id_key = XOnly(a);
        r.new_id_key = XOnly(b);
        records.push_back(r);
    }
    {
        Record r;
        r.type = RecordType::VETO;
        r.id_key = XOnly(a);
        r.recovery_key = XOnly(b);
        records.push_back(r);
    }

    for (const Record& in : records) {
        const std::vector<unsigned char> raw = SerializeRecord(in);
        Record out;
        BOOST_CHECK_EQUAL(ParseErrorString(ParseRecord(raw, out)), "ok");
        BOOST_CHECK(out.type == in.type);
        BOOST_CHECK(SerializeRecord(out) == raw);
    }
}

BOOST_AUTO_TEST_CASE(parse_rejects_malformed)
{
    const CKey key = MakeKey(6);
    const std::vector<unsigned char> good = SerializeRecord(MakeAnnounce(key));
    Record out;

    auto expect = [&](std::vector<unsigned char> bytes, ParseError want) {
        BOOST_CHECK_EQUAL(ParseErrorString(ParseRecord(bytes, out)), ParseErrorString(want));
    };

    {
        std::vector<unsigned char> b = good;
        b[0] = 'X';
        expect(b, ParseError::BAD_MAGIC);
    }
    {
        std::vector<unsigned char> b = good;
        b[3] = (2 << 4) | 0x01; // version 2
        expect(b, ParseError::BAD_VERSION);
    }
    {
        std::vector<unsigned char> b = good;
        b[3] = (1 << 4) | 0x00; // type 0
        expect(b, ParseError::BAD_TYPE);
        b[3] = (1 << 4) | 0x06; // type 6
        expect(b, ParseError::BAD_TYPE);
    }
    {
        std::vector<unsigned char> b = good;
        b.pop_back();
        expect(b, ParseError::BAD_LENGTH);
    }
    {
        // A trailing byte must not be silently tolerated: the same logical
        // record at two encodings means two txids for one announcement.
        std::vector<unsigned char> b = good;
        b.insert(b.end() - RECORD_SIG_SIZE, 0x00);
        expect(b, ParseError::TRAILING_BYTES);
    }
    {
        std::vector<unsigned char> b = good;
        b[RECORD_HEADER_SIZE + 44] = 4; // ep_count = 4
        expect(b, ParseError::BAD_ENDPOINT_COUNT);
    }
    {
        // Tor v2 is a recognised BIP155 id that we refuse to carry.
        std::vector<unsigned char> b = good;
        b[RECORD_HEADER_SIZE + 45] = EP_TORV2;
        expect(b, ParseError::BAD_ENDPOINT_NETWORK);
    }
    {
        std::vector<unsigned char> b = good;
        b[RECORD_HEADER_SIZE + 45] = 99; // unknown network
        expect(b, ParseError::BAD_ENDPOINT_NETWORK);
    }
    {
        expect(std::vector<unsigned char>(MAX_RECORD_SIZE + 1, 0), ParseError::TOO_LONG);
        expect(std::vector<unsigned char>(10, 0), ParseError::TOO_SHORT);
    }
}

BOOST_AUTO_TEST_CASE(meta_hash_bit_stays_consistent)
{
    const CKey key = MakeKey(7);
    Record rec = MakeAnnounce(key);

    // Setting the bit without supplying a hash must not produce a record that
    // fails to parse back; the serialiser keeps declaration and content in step.
    rec.services |= SERVICE_META_PRESENT;
    std::vector<unsigned char> raw = SerializeRecord(rec);
    Record out;
    BOOST_CHECK_EQUAL(ParseErrorString(ParseRecord(raw, out)), "ok");
    BOOST_CHECK(!out.meta_hash.has_value());
    BOOST_CHECK((out.services & SERVICE_META_PRESENT) == 0);

    rec.meta_hash = uint256::ONE;
    raw = SerializeRecord(rec);
    BOOST_CHECK_EQUAL(ParseErrorString(ParseRecord(raw, out)), "ok");
    BOOST_CHECK(out.meta_hash.has_value());
    BOOST_CHECK(*out.meta_hash == uint256::ONE);
    BOOST_CHECK((out.services & SERVICE_META_PRESENT) != 0);
}

BOOST_AUTO_TEST_CASE(signature_verifies_and_fails_closed)
{
    const CKey key = MakeKey(8);
    const CKey wrong = MakeKey(9);

    Record rec = MakeAnnounce(key);
    SignInPlace(rec, key, CHAIN_MAIN);

    std::vector<unsigned char> raw = SerializeRecord(rec);
    Record parsed;
    BOOST_REQUIRE_EQUAL(ParseErrorString(ParseRecord(raw, parsed)), "ok");
    BOOST_CHECK(VerifyRecord(parsed, raw, CHAIN_MAIN));
    BOOST_CHECK(ParseAndVerify(raw, CHAIN_MAIN, parsed));

    // Cross-chain replay: identical bytes, different chain id, no longer valid.
    // This is the whole reason the chain id lives in the tag instead of on the
    // wire, so it is worth an explicit test rather than an inspection.
    BOOST_CHECK(!VerifyRecord(parsed, raw, CHAIN_TEST));

    // Any change to the signed portion invalidates.
    for (size_t i : {RECORD_HEADER_SIZE + 0, RECORD_HEADER_SIZE + 36, RECORD_HEADER_SIZE + 45}) {
        std::vector<unsigned char> tampered = raw;
        tampered[i] ^= 0x01;
        Record t;
        if (ParseRecord(tampered, t) == ParseError::OK) {
            BOOST_CHECK(!VerifyRecord(t, tampered, CHAIN_MAIN));
        }
    }

    // A signature from the wrong key must not verify.
    Record other = MakeAnnounce(key);
    SignInPlace(other, wrong, CHAIN_MAIN);
    const std::vector<unsigned char> other_raw = SerializeRecord(other);
    Record other_parsed;
    BOOST_REQUIRE_EQUAL(ParseErrorString(ParseRecord(other_raw, other_parsed)), "ok");
    BOOST_CHECK(!VerifyRecord(other_parsed, other_raw, CHAIN_MAIN));
}

//! Each type must be authenticated by the key §1 and §7 say authorises it.
BOOST_AUTO_TEST_CASE(signing_key_per_type)
{
    const CKey id = MakeKey(10);
    const CKey op = MakeKey(11);
    const CKey recovery = MakeKey(12);

    {
        Record r;
        r.type = RecordType::DELEGATE;
        r.id_key = XOnly(id);
        r.op_key = XOnly(op);
        r.expiry_height = 500 + MIN_TTL;
        BOOST_CHECK(SigningKeyBytes(r) == XOnly(id));
        SignInPlace(r, id, CHAIN_MAIN);
        BOOST_CHECK(VerifyRecord(r, SerializeRecord(r), CHAIN_MAIN));

        // The delegated operational key must not be able to authorise itself.
        SignInPlace(r, op, CHAIN_MAIN);
        BOOST_CHECK(!VerifyRecord(r, SerializeRecord(r), CHAIN_MAIN));
    }
    {
        Record r;
        r.type = RecordType::VETO;
        r.id_key = XOnly(id);
        r.recovery_key = XOnly(recovery);
        BOOST_CHECK(SigningKeyBytes(r) == XOnly(recovery));
        SignInPlace(r, recovery, CHAIN_MAIN);
        BOOST_CHECK(VerifyRecord(r, SerializeRecord(r), CHAIN_MAIN));

        // A compromised identity key cannot cancel its own rotation.
        SignInPlace(r, id, CHAIN_MAIN);
        BOOST_CHECK(!VerifyRecord(r, SerializeRecord(r), CHAIN_MAIN));
    }
}

//! Distinct tags per record type stop a signature being lifted from one record
//! into another of a different type that happens to share a byte prefix.
BOOST_AUTO_TEST_CASE(tags_are_distinct)
{
    BOOST_CHECK_EQUAL(RecordTag(RecordType::ANNOUNCE, "main"), "BPS/announce/v1/main");
    BOOST_CHECK_EQUAL(RecordTag(RecordType::REVOKE, "main"), "BPS/revoke/v1/main");
    BOOST_CHECK(RecordTag(RecordType::ROTATE, "main") != RecordTag(RecordType::VETO, "main"));
    BOOST_CHECK(RecordTag(RecordType::ANNOUNCE, "main") != RecordTag(RecordType::ANNOUNCE, "test"));
}

//! The window bounds decide whether a cold roster build stays O(MAX_TTL), so
//! both edges are pinned rather than assumed.
BOOST_AUTO_TEST_CASE(expiry_window_bounds)
{
    // The floor. Below it a peer could renew every block, which costs 56.8 MB
    // of permanent chain a year from a single identity.
    BOOST_CHECK(!ExpiryInRange(100, 100));                       // already stale
    BOOST_CHECK(!ExpiryInRange(99, 100));                        // in the past
    BOOST_CHECK(!ExpiryInRange(101, 100));                       // one block of life
    BOOST_CHECK(!ExpiryInRange(100 + MIN_TTL - 1, 100));         // one short of the floor
    BOOST_CHECK(ExpiryInRange(100 + MIN_TTL, 100));              // exactly the floor

    // The cap. Beyond it the roster stops being a function of a bounded window.
    BOOST_CHECK(ExpiryInRange(100 + MAX_TTL, 100));              // exactly the cap
    BOOST_CHECK(!ExpiryInRange(100 + MAX_TTL + 1, 100));         // one past the cap

    BOOST_CHECK(!ExpiryInRange(5, -1));                          // no chain yet

    // Must not wrap. A near-maximal uint32 expiry against a realistic height is
    // exactly the input that 32-bit arithmetic would overflow into accepting.
    BOOST_CHECK(!ExpiryInRange(0xFFFFFFFFu, 1219021));

    // A month is the shortest renewal cycle and a year the longest, so those
    // are the two cadences the design actually offers.
    BOOST_CHECK_EQUAL(MIN_TTL, 14400U);                          // ~30 days at 180 s
    BOOST_CHECK_EQUAL(MAX_TTL, 175320U);                         // ~1 year at 180 s
}

//! What a record contributes to a block filter, and what authorises it. These
//! two differ on purpose for the identity records, and confusing them would be
//! an authentication bug rather than a cosmetic one.
BOOST_AUTO_TEST_CASE(record_keys_and_signer_per_type)
{
    const CKey id = MakeKey(20);
    const CKey op = MakeKey(21);
    const CKey recovery = MakeKey(22);

    {
        Record r;
        r.type = RecordType::ANNOUNCE;
        r.op_key = XOnly(op);
        BOOST_CHECK_EQUAL(RecordKeys(r).size(), 1U);
        BOOST_CHECK(SigningKeyBytes(r) == XOnly(op));
    }
    {
        Record r;
        r.type = RecordType::DELEGATE;
        r.id_key = XOnly(id);
        r.op_key = XOnly(op);
        const auto keys = RecordKeys(r);
        BOOST_CHECK_EQUAL(keys.size(), 2U);
        BOOST_CHECK(keys[0] == XOnly(id));
        BOOST_CHECK(keys[1] == XOnly(op));
        // Watched under both, but only the identity may authorise it.
        BOOST_CHECK(SigningKeyBytes(r) == XOnly(id));
    }
    {
        Record r;
        r.type = RecordType::ROTATE;
        r.id_key = XOnly(id);
        r.new_id_key = XOnly(op);
        const auto keys = RecordKeys(r);
        BOOST_CHECK_EQUAL(keys.size(), 2U);
        // Both ends must be filterable, or a watcher of the new identity would
        // never see the move that created it.
        BOOST_CHECK(keys[1] == XOnly(op));
    }
    {
        Record r;
        r.type = RecordType::VETO;
        r.id_key = XOnly(id);
        r.recovery_key = XOnly(recovery);
        BOOST_CHECK_EQUAL(RecordKeys(r).size(), 2U);
        BOOST_CHECK(SigningKeyBytes(r) == XOnly(recovery));
    }
}

namespace {

CommitmentEntry MakeEntry(const CKey& key, uint32_t height)
{
    CommitmentEntry entry;
    entry.key = XOnly(key);
    entry.height = height;

    Record rec;
    rec.type = RecordType::ANNOUNCE;
    rec.op_key = entry.key;
    rec.expiry_height = height + MIN_TTL;
    rec.endpoints.push_back(EpIPv4(9345));
    entry.raw = SerializeRecord(rec);
    return entry;
}

} // namespace

/**
 * The commitment is consensus-critical once activated, so the root must depend
 * on the roster's contents and on nothing else — in particular not on the
 * order a node happened to walk its database in.
 */
BOOST_AUTO_TEST_CASE(commitment_root_is_order_independent)
{
    const CommitmentEntry a = MakeEntry(MakeKey(30), 100);
    const CommitmentEntry b = MakeEntry(MakeKey(31), 101);
    const CommitmentEntry c = MakeEntry(MakeKey(32), 102);

    const uint256 r1 = MerkleRoot({a, b, c});
    const uint256 r2 = MerkleRoot({c, a, b});
    const uint256 r3 = MerkleRoot({b, c, a});

    BOOST_CHECK(r1 == r2);
    BOOST_CHECK(r2 == r3);
    BOOST_CHECK(r1 != uint256());

    // An empty roster commits to a value no populated roster can produce.
    BOOST_CHECK(MerkleRoot({}) == uint256());
}

BOOST_AUTO_TEST_CASE(commitment_covers_height_and_membership)
{
    const CKey key = MakeKey(33);

    // Height is committed explicitly because §1 keeps time out of the record:
    // without this a record could be proved present without proving when.
    BOOST_CHECK(MerkleRoot({MakeEntry(key, 100)}) != MerkleRoot({MakeEntry(key, 101)}));

    // Membership changes the root, including at odd counts, where the merkle
    // construction duplicates a trailing leaf.
    const CommitmentEntry a = MakeEntry(MakeKey(34), 1);
    const CommitmentEntry b = MakeEntry(MakeKey(35), 2);
    const CommitmentEntry c = MakeEntry(MakeKey(36), 3);
    BOOST_CHECK(MerkleRoot({a, b}) != MerkleRoot({a, b, c}));

    // Duplicate keys are a caller error, not something to hash anyway: the
    // trailing-leaf duplication is only unambiguous while leaves are unique.
    bool duplicate = false;
    BOOST_CHECK(MerkleRoot({a, a}, &duplicate) == uint256());
    BOOST_CHECK(duplicate);
    duplicate = true;
    MerkleRoot({a, b}, &duplicate);
    BOOST_CHECK(!duplicate);
}

BOOST_AUTO_TEST_CASE(commitment_script_roundtrip)
{
    const uint256 root = MerkleRoot({MakeEntry(MakeKey(37), 500)});

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    BOOST_CHECK_EQUAL(GetCommitmentIndex(block), NO_ROSTER_COMMITMENT);

    coinbase.vout.push_back(CTxOut(0, MakeCommitmentScript(root)));
    block.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK_EQUAL(GetCommitmentIndex(block), 1);

    uint256 found;
    BOOST_CHECK(GetCommitmentRoot(block, found));
    BOOST_CHECK(found == root);

    // A miner may only append, so the last commitment is the authoritative one
    // — the same rule the witness commitment follows.
    const uint256 later = MerkleRoot({MakeEntry(MakeKey(38), 501)});
    coinbase.vout.push_back(CTxOut(0, MakeCommitmentScript(later)));
    block.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK_EQUAL(GetCommitmentIndex(block), 2);
    BOOST_CHECK(GetCommitmentRoot(block, found) && found == later);

    // A corrupted header must not be read as a commitment at all.
    CScript wrong_header = MakeCommitmentScript(root);
    wrong_header[2] ^= 0x01;
    CMutableTransaction only_bad;
    only_bad.vin.resize(1);
    only_bad.vout.push_back(CTxOut(0, wrong_header));
    CBlock bad_block;
    bad_block.vtx.push_back(MakeTransactionRef(only_bad));
    BOOST_CHECK_EQUAL(GetCommitmentIndex(bad_block), NO_ROSTER_COMMITMENT);
}

namespace {

/**
 * Exposes WriteBlock, which is protected on the real index.
 *
 * The window is passed straight to the constructor, bypassing init.cpp's
 * floor of MAX_TTL. That floor is an operator guard — a window narrower than
 * the rolling window would make the live roster wrong — and it has nothing to
 * do with whether the pruning machinery works. Driving it with a window of ten
 * blocks tests the same code in a few milliseconds instead of mining 14,400.
 */
class TestableRosterIndex : public RosterIndex
{
public:
    TestableRosterIndex(int start_height, int window)
        : RosterIndex(1 << 20, /*f_memory=*/true, /*f_wipe=*/false, start_height, window) {}
    using RosterIndex::WriteBlock;
};

//! A block carrying one transaction per payload. Records never live in the
//! coinbase, so there is always one in front of them.
CBlock BlockWith(const std::vector<std::vector<unsigned char>>& payloads)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.resize(1);
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(coinbase));

    for (const std::vector<unsigned char>& payload : payloads) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.push_back(CTxOut(0, CScript() << OP_RETURN << payload));
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

std::vector<unsigned char> SignedAnnounceAt(const CKey& key, int height)
{
    Record rec;
    rec.type = RecordType::ANNOUNCE;
    rec.op_key = XOnly(key);
    rec.expiry_height = height + MIN_TTL;
    rec.endpoints.push_back(EpIPv4(9345));
    SignInPlace(rec, key, Params().NetworkIDString());
    return SerializeRecord(rec);
}

std::vector<unsigned char> SignedRevoke(const CKey& key)
{
    Record rec;
    rec.type = RecordType::REVOKE;
    rec.op_key = XOnly(key);
    SignInPlace(rec, key, Params().NetworkIDString());
    return SerializeRecord(rec);
}

CBlockIndex IndexAt(int height)
{
    CBlockIndex bi;
    bi.nHeight = height;
    return bi;
}

} // namespace

BOOST_AUTO_TEST_CASE(index_stores_and_reads_back)
{
    TestableRosterIndex index(0, 0);
    const CKey key = MakeKey(40);
    CBlockIndex bi = IndexAt(500);

    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(key, 500)}), &bi));

    std::vector<RosterEntry> found;
    BOOST_REQUIRE(index.ReadRecordsAtHeight(500, found));
    BOOST_REQUIRE_EQUAL(found.size(), 1U);
    BOOST_CHECK_EQUAL(found[0].height, 500);

    Record parsed;
    BOOST_CHECK(found[0].Parse(parsed));
    BOOST_CHECK(parsed.op_key == XOnly(key));

    // Filed under its key as well, which is what makes the age chain readable.
    std::vector<RosterEntry> by_key;
    BOOST_REQUIRE(index.ReadRecordsForKey(XOnly(key), by_key));
    BOOST_CHECK_EQUAL(by_key.size(), 1U);
}

//! A record whose signature does not check must never reach the database, so
//! that no reader has to remember to verify.
BOOST_AUTO_TEST_CASE(index_rejects_unverifiable_records)
{
    TestableRosterIndex index(0, 0);
    const CKey key = MakeKey(45);
    CBlockIndex bi = IndexAt(600);

    std::vector<unsigned char> tampered = SignedAnnounceAt(key, 600);
    tampered[RECORD_HEADER_SIZE + 40] ^= 0x01; // flip a services bit, breaking the signature

    BOOST_REQUIRE(index.WriteBlock(BlockWith({tampered}), &bi));

    std::vector<RosterEntry> found;
    BOOST_REQUIRE(index.ReadRecordsAtHeight(600, found));
    BOOST_CHECK(found.empty());
}

BOOST_AUTO_TEST_CASE(index_skips_below_start_height)
{
    TestableRosterIndex index(1000, 0);
    const CKey key = MakeKey(44);

    CBlockIndex below = IndexAt(999);
    CBlockIndex at = IndexAt(1000);
    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(key, 999)}), &below));
    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(key, 1000)}), &at));

    std::vector<RosterEntry> found;
    BOOST_REQUIRE(index.ReadRecordsAtHeight(999, found));
    BOOST_CHECK(found.empty());
    BOOST_REQUIRE(index.ReadRecordsAtHeight(1000, found));
    BOOST_CHECK_EQUAL(found.size(), 1U);
}

//! The retention window, exercised against a real LevelDB rather than reasoned
//! about: entries must leave as the tip advances past them, in both key
//! families, and nothing inside the window may be lost.
BOOST_AUTO_TEST_CASE(index_prunes_outside_the_window)
{
    const int window = 10;
    const int tip = 30;
    TestableRosterIndex index(0, window);
    const CKey key = MakeKey(41);

    for (int h = 1; h <= tip; ++h) {
        CBlockIndex bi = IndexAt(h);
        BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(key, h)}), &bi));
    }

    std::vector<RosterEntry> found;
    for (int h = 1; h < tip - window; ++h) {
        BOOST_REQUIRE(index.ReadRecordsAtHeight(h, found));
        BOOST_CHECK_MESSAGE(found.empty(), "height " << h << " should have been pruned");
    }
    for (int h = tip - window; h <= tip; ++h) {
        BOOST_REQUIRE(index.ReadRecordsAtHeight(h, found));
        BOOST_CHECK_MESSAGE(found.size() == 1U, "height " << h << " should still be present");
    }

    // The by-key family must shrink with it. Leaving those behind would strand
    // entries pointing at height rows that no longer exist.
    std::vector<RosterEntry> by_key;
    BOOST_REQUIRE(index.ReadRecordsForKey(XOnly(key), by_key));
    BOOST_CHECK_EQUAL(by_key.size(), static_cast<size_t>(window + 1));

    // An unwindowed index keeps everything, so the window is doing the work
    // rather than some other limit.
    TestableRosterIndex archival(0, 0);
    for (int h = 1; h <= tip; ++h) {
        CBlockIndex bi = IndexAt(h);
        BOOST_REQUIRE(archival.WriteBlock(BlockWith({SignedAnnounceAt(key, h)}), &bi));
    }
    BOOST_REQUIRE(archival.ReadRecordsForKey(XOnly(key), by_key));
    BOOST_CHECK_EQUAL(by_key.size(), static_cast<size_t>(tip));
}

//! Rewriting a height must replace it, not merge into it. A reorg that
//! substitutes a block carrying fewer records would otherwise leave the
//! surplus entries of its predecessor in the roster.
BOOST_AUTO_TEST_CASE(index_write_is_idempotent_across_reorg)
{
    TestableRosterIndex index(0, 0);
    const CKey a = MakeKey(42);
    const CKey b = MakeKey(43);
    CBlockIndex bi = IndexAt(700);

    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(a, 700), SignedAnnounceAt(b, 700)}), &bi));
    std::vector<RosterEntry> found;
    BOOST_REQUIRE(index.ReadRecordsAtHeight(700, found));
    BOOST_REQUIRE_EQUAL(found.size(), 2U);

    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(a, 700)}), &bi));
    BOOST_REQUIRE(index.ReadRecordsAtHeight(700, found));
    BOOST_CHECK_EQUAL(found.size(), 1U);

    // The dropped record must be gone from the key family too.
    std::vector<RosterEntry> for_b;
    BOOST_REQUIRE(index.ReadRecordsForKey(XOnly(b), for_b));
    BOOST_CHECK(for_b.empty());
}

//! Revocation is terminal: a later announcement under a revoked key must not
//! bring the identity back.
BOOST_AUTO_TEST_CASE(build_roster_honours_revocation)
{
    TestableRosterIndex index(0, 0);
    const CKey live = MakeKey(46);
    const CKey doomed = MakeKey(47);

    CBlockIndex h800 = IndexAt(800);
    CBlockIndex h801 = IndexAt(801);
    CBlockIndex h802 = IndexAt(802);

    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(live, 800), SignedAnnounceAt(doomed, 800)}), &h800));

    std::map<KeyBytes, RosterEntry> roster;
    BOOST_REQUIRE(index.BuildRoster(800, roster));
    BOOST_CHECK_EQUAL(roster.size(), 2U);

    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedRevoke(doomed)}), &h801));
    BOOST_REQUIRE(index.BuildRoster(801, roster));
    BOOST_CHECK_EQUAL(roster.size(), 1U);
    BOOST_CHECK(roster.count(XOnly(live)) == 1);
    BOOST_CHECK(roster.count(XOnly(doomed)) == 0);

    // Announcing again after revocation must not resurrect the identity.
    BOOST_REQUIRE(index.WriteBlock(BlockWith({SignedAnnounceAt(doomed, 802)}), &h802));
    BOOST_REQUIRE(index.BuildRoster(802, roster));
    BOOST_CHECK_EQUAL(roster.size(), 1U);
    BOOST_CHECK(roster.count(XOnly(doomed)) == 0);
}

//! An expiry that has passed leaves the roster by arithmetic, with no
//! deletion pass and no record on chain.
BOOST_AUTO_TEST_CASE(build_roster_drops_expired)
{
    TestableRosterIndex index(0, 0);
    const CKey key = MakeKey(48);

    Record rec;
    rec.type = RecordType::ANNOUNCE;
    rec.op_key = XOnly(key);
    rec.expiry_height = 900 + MIN_TTL; // the shortest life a record may claim
    rec.endpoints.push_back(EpIPv4(9345));
    SignInPlace(rec, key, Params().NetworkIDString());

    CBlockIndex bi = IndexAt(900);
    BOOST_REQUIRE(index.WriteBlock(BlockWith({SerializeRecord(rec)}), &bi));

    std::map<KeyBytes, RosterEntry> roster;
    BOOST_REQUIRE(index.BuildRoster(900 + MIN_TTL - 1, roster));
    BOOST_CHECK_EQUAL(roster.size(), 1U);

    BOOST_REQUIRE(index.BuildRoster(900 + MIN_TTL, roster));
    BOOST_CHECK_EQUAL(roster.size(), 0U); // expiry_height is not inclusive
}

BOOST_AUTO_TEST_SUITE_END()
