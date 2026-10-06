// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MLKEM768_H
#define BITCOIN_CRYPTO_MLKEM768_H

#include <array>
#include <stddef.h>
#include <stdint.h>
#include <vector>

/**
 * ML-KEM-768 (FIPS 203), the post-quantum half of mail encryption.
 *
 * A thin wrapper over mlkem-native (src/mlkem-native, Apache-2.0/ISC/MIT, the
 * implementation AWS-LC uses, with formally verified C). Nothing here is
 * cryptography of this tree's own: the wrapper only fixes sizes and turns C
 * return codes into bools.
 *
 * Every function takes its randomness as an argument. Callers pass bytes from
 * GetStrongRandBytes; tests pass fixed bytes and compare against another
 * implementation's answers. Keeping the library free of a random source also
 * keeps it free of any dependency on the rest of the tree, which is what lets
 * it sit at the very end of every link line.
 */
namespace mlkem768 {

static constexpr size_t PUBLIC_KEY_SIZE = 1184;
static constexpr size_t SECRET_KEY_SIZE = 2400;
static constexpr size_t CIPHERTEXT_SIZE = 1088;
static constexpr size_t SHARED_SECRET_SIZE = 32;
/** d || z from FIPS 203: the whole key pair follows from these 64 bytes. */
static constexpr size_t SEED_SIZE = 64;
/** The m of FIPS 203's encapsulation. */
static constexpr size_t COINS_SIZE = 32;

using SharedSecret = std::array<unsigned char, SHARED_SECRET_SIZE>;

/** A key pair from 64 random bytes. False only on a library failure. */
bool KeyPairFromSeed(const unsigned char seed[SEED_SIZE],
                     std::vector<unsigned char>& public_key_out,
                     std::vector<unsigned char>& secret_key_out);

/**
 * Encapsulate to a public key.
 *
 * False when the key is the wrong size or fails FIPS 203's modulus check -
 * that is, when it is not a key at all. A key from a stranger has to be
 * treated as possibly malformed, and this is where that is caught.
 */
bool Encapsulate(const std::vector<unsigned char>& public_key,
                 const unsigned char coins[COINS_SIZE],
                 std::vector<unsigned char>& ciphertext_out,
                 SharedSecret& secret_out);

/**
 * Decapsulate.
 *
 * A ciphertext that was tampered with does not fail: ML-KEM's implicit
 * rejection returns an unrelated secret instead, so the caller learns nothing
 * about why. The AEAD sealed under that secret is what then fails. False only
 * for wrong sizes or a secret key that fails its own hash check.
 */
bool Decapsulate(const std::vector<unsigned char>& secret_key,
                 const std::vector<unsigned char>& ciphertext,
                 SharedSecret& secret_out);

} // namespace mlkem768

#endif // BITCOIN_CRYPTO_MLKEM768_H
