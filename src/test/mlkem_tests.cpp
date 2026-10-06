// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mlkem768.h>
#include <crypto/sha256.h>
#include <random.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(mlkem_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Sha(const std::string& s)
{
    std::vector<unsigned char> out(CSHA256::OUTPUT_SIZE);
    CSHA256().Write((const unsigned char*)s.data(), s.size()).Finalize(out.data());
    return out;
}

std::string ShaHex(const std::vector<unsigned char>& v)
{
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(v.data(), v.size()).Finalize(out);
    return HexStr(out);
}

/**
 * Answers computed by a second, independent implementation: Go 1.27's
 * crypto/mlkem (FIPS 140-3 validated), with crypto/mlkem/mlkemtest for the
 * deterministic encapsulation. The inputs are hashes of fixed strings, so the
 * program that produced these is a dozen lines and anyone can rerun it:
 *
 *   seed = SHA256("bps mlkem d <i>") || SHA256("bps mlkem z <i>")
 *   m    = SHA256("bps mlkem m <i>")
 *   dk   = mlkem.NewDecapsulationKey768(seed)
 *   ss, ct = mlkemtest.Encapsulate768(dk.EncapsulationKey(), m)
 *   rej  = dk.Decapsulate(ct with its first byte flipped)
 *
 * Keys and ciphertexts are compared by hash to keep the table short.
 */
struct Vector {
    int i;
    const char* public_key_sha256;
    const char* ciphertext_sha256;
    const char* shared_secret;
    const char* rejection_secret;
};

const Vector VECTORS[] = {
    {0, "89c1a16674bf6be91dcb078e8057163b46c6479e4db9cbab58964e0adb0d0a28", "e6cc3d42a833da4eb2d9cc303d170da92a1e35a26ea71e7b4bb3b6678a247305", "4781f9eaf67af9f946ed731c2108dec6d996bc3bf71f2459b82a6c3dbc980eed", "ac3a62d8780e6ab5fb31c95d326c776cda9e85f3992619f8804183fcd09bb4cd"},
    {1, "ee9ce2d17fda26edbd92d66cdad5b568ecd5a81a840a9633b2b483ac30b29fab", "e7216b3b7b3db929857af506ec83a6d16ab8678c77d027c9e3adce5b9d888cb8", "9135827a376e3c39b813e11504e030fcea3ab4349f60a29abb2234652b36aa3f", "675042d216c3e7399daa9876fcba0da92f37925fef5c245766e438db4957417d"},
    {2, "78ca866055037d33a8352a13a391bde8db1a8346aa4627f26f67138fdb5f68ac", "04dee3ff43eb2f90b2cd9af397e01c0704a420f099c793c83fcdfd4733dacb78", "1c49f2bb31dba8fbbcc7b7595f34f57bf9890232d205ec40206a849975918384", "a0c5623547b5bdb1edde20098adc00e8e43d48c7cf431e4f8cce04247106bd51"},
    {3, "b659362155ecc340f8e2174cdacbc9fe5816ce0504b30bc39a901db6c3964f77", "874f550ae68f37bf2ccd486ea23df5780f44b96b9209397bc2f2525b2fbd428e", "3aa9c141271445864e040aed30f10c202a3ec826ed6b9490827a049016c2eec6", "808e0c07af0bac122d22de8b4b8b5a89a71c7c319f3cdff218266393eed8183b"},
};

} // namespace

BOOST_AUTO_TEST_CASE(mlkem_agrees_with_an_independent_implementation)
{
    for (const Vector& v : VECTORS) {
        const std::string n = std::to_string(v.i);
        std::vector<unsigned char> seed = Sha("bps mlkem d " + n);
        const std::vector<unsigned char> z = Sha("bps mlkem z " + n);
        seed.insert(seed.end(), z.begin(), z.end());
        const std::vector<unsigned char> m = Sha("bps mlkem m " + n);

        std::vector<unsigned char> pk, sk, ct;
        BOOST_REQUIRE(mlkem768::KeyPairFromSeed(seed.data(), pk, sk));
        BOOST_CHECK_EQUAL(ShaHex(pk), v.public_key_sha256);

        mlkem768::SharedSecret ss, opened, rejected;
        BOOST_REQUIRE(mlkem768::Encapsulate(pk, m.data(), ct, ss));
        BOOST_CHECK_EQUAL(ShaHex(ct), v.ciphertext_sha256);
        BOOST_CHECK_EQUAL(HexStr(ss), v.shared_secret);

        BOOST_REQUIRE(mlkem768::Decapsulate(sk, ct, opened));
        BOOST_CHECK(opened == ss);

        // Implicit rejection: a damaged ciphertext still decapsulates, to a
        // secret derived from the key's z and the ciphertext, and both
        // implementations derive the same one.
        ct[0] ^= 1;
        BOOST_REQUIRE(mlkem768::Decapsulate(sk, ct, rejected));
        BOOST_CHECK_EQUAL(HexStr(rejected), v.rejection_secret);
        BOOST_CHECK(rejected != ss);
    }
}

BOOST_AUTO_TEST_CASE(mlkem_round_trips_with_fresh_randomness)
{
    for (int i = 0; i < 8; ++i) {
        // GetStrongRandBytes gives at most 32 bytes a call.
        unsigned char seed[mlkem768::SEED_SIZE], coins[mlkem768::COINS_SIZE];
        GetStrongRandBytes(seed, 32);
        GetStrongRandBytes(seed + 32, 32);
        GetStrongRandBytes(coins, sizeof(coins));
        std::vector<unsigned char> pk, sk, ct;
        BOOST_REQUIRE(mlkem768::KeyPairFromSeed(seed, pk, sk));
        BOOST_CHECK_EQUAL(pk.size(), mlkem768::PUBLIC_KEY_SIZE);
        BOOST_CHECK_EQUAL(sk.size(), mlkem768::SECRET_KEY_SIZE);
        mlkem768::SharedSecret a, b;
        BOOST_REQUIRE(mlkem768::Encapsulate(pk, coins, ct, a));
        BOOST_CHECK_EQUAL(ct.size(), mlkem768::CIPHERTEXT_SIZE);
        BOOST_REQUIRE(mlkem768::Decapsulate(sk, ct, b));
        BOOST_CHECK(a == b);
    }
}

BOOST_AUTO_TEST_CASE(mlkem_refuses_what_is_not_a_key)
{
    unsigned char seed[mlkem768::SEED_SIZE] = {7};
    unsigned char coins[mlkem768::COINS_SIZE] = {9};
    std::vector<unsigned char> pk, sk, ct;
    BOOST_REQUIRE(mlkem768::KeyPairFromSeed(seed, pk, sk));
    mlkem768::SharedSecret ss;

    // Wrong sizes, either way.
    std::vector<unsigned char> short_pk(pk.begin(), pk.end() - 1);
    BOOST_CHECK(!mlkem768::Encapsulate(short_pk, coins, ct, ss));
    BOOST_CHECK(ct.empty());
    BOOST_REQUIRE(mlkem768::Encapsulate(pk, coins, ct, ss));
    std::vector<unsigned char> long_ct = ct;
    long_ct.push_back(0);
    BOOST_CHECK(!mlkem768::Decapsulate(sk, long_ct, ss));

    // A public key whose first coefficient is out of range fails FIPS 203's
    // modulus check: 0xFFF in the first twelve bits is 4095, above q = 3329.
    std::vector<unsigned char> bad = pk;
    bad[0] = 0xFF;
    bad[1] |= 0x0F;
    BOOST_CHECK(!mlkem768::Encapsulate(bad, coins, ct, ss));

    // A secret key whose embedded public key hash no longer matches fails
    // its own check rather than quietly decapsulating to garbage.
    std::vector<unsigned char> bad_sk = sk;
    bad_sk[mlkem768::SECRET_KEY_SIZE - 64] ^= 1;
    BOOST_REQUIRE(mlkem768::Encapsulate(pk, coins, ct, ss));
    BOOST_CHECK(!mlkem768::Decapsulate(bad_sk, ct, ss));
}

BOOST_AUTO_TEST_SUITE_END()
