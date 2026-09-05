// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
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
    ep.network = NET_IPV4;
    ep.addr = {192, 0, 2, 1};
    ep.port = port;
    return ep;
}

Endpoint EpIPv6(uint16_t port)
{
    Endpoint ep;
    ep.network = NET_IPV6;
    ep.addr.assign(ADDR_SIZE_IPV6, 0xab);
    ep.port = port;
    return ep;
}

Endpoint EpOnion(uint16_t port)
{
    Endpoint ep;
    ep.network = NET_TORV3;
    ep.addr.assign(ADDR_SIZE_TORV3, 0x5c);
    ep.port = port;
    return ep;
}

Record MakeAnnounce(const CKey& key)
{
    Record rec;
    rec.type = RecordType::ANNOUNCE;
    rec.op_key = XOnly(key);
    rec.expiry_height = 1'233'421;
    rec.services = SERVICE_RELAY_CAPABLE;
    rec.prev_height = 1'219'021;
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
    ann.services |= SERVICE_RENDEZVOUS_ONLY;
    BOOST_CHECK_EQUAL(SerializeRecord(ann).size(), 113U); // rendezvous-only

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
    del.expiry_height = 1'233'421;
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
        b[RECORD_HEADER_SIZE + 45] = NET_TORV2;
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
        r.expiry_height = 500;
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
    BOOST_CHECK(!ExpiryInRange(100, 100));                 // equal: already stale
    BOOST_CHECK(!ExpiryInRange(99, 100));                  // in the past
    BOOST_CHECK(ExpiryInRange(101, 100));                  // one block ahead
    BOOST_CHECK(ExpiryInRange(100 + MAX_TTL, 100));        // exactly the cap
    BOOST_CHECK(!ExpiryInRange(100 + MAX_TTL + 1, 100));   // one past the cap
    BOOST_CHECK(!ExpiryInRange(5, -1));                    // no chain yet

    // Must not wrap. A near-maximal uint32 expiry against a realistic height is
    // exactly the input that a naive confirm_height + MAX_TTL would overflow.
    BOOST_CHECK(!ExpiryInRange(0xFFFFFFFFu, 1219021));
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

BOOST_AUTO_TEST_SUITE_END()
