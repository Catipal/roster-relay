// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mlkem768.h>

#define MLK_CONFIG_FILE "crypto/mlkem768_config.h"
#include <mlkem-native/mlkem/mlkem_native.h>

static_assert(MLKEM768_PUBLICKEYBYTES == mlkem768::PUBLIC_KEY_SIZE, "public key size");
static_assert(MLKEM768_SECRETKEYBYTES == mlkem768::SECRET_KEY_SIZE, "secret key size");
static_assert(MLKEM768_CIPHERTEXTBYTES == mlkem768::CIPHERTEXT_SIZE, "ciphertext size");
static_assert(MLKEM_BYTES == mlkem768::SHARED_SECRET_SIZE, "shared secret size");
static_assert(2 * MLKEM_SYMBYTES == mlkem768::SEED_SIZE, "seed size");
static_assert(MLKEM_SYMBYTES == mlkem768::COINS_SIZE, "coins size");

namespace mlkem768 {

bool KeyPairFromSeed(const unsigned char seed[SEED_SIZE],
                     std::vector<unsigned char>& public_key_out,
                     std::vector<unsigned char>& secret_key_out)
{
    public_key_out.assign(PUBLIC_KEY_SIZE, 0);
    secret_key_out.assign(SECRET_KEY_SIZE, 0);
    if (bps_mlkem768_keypair_derand(public_key_out.data(), secret_key_out.data(), seed) != 0) {
        public_key_out.clear();
        secret_key_out.clear();
        return false;
    }
    return true;
}

bool Encapsulate(const std::vector<unsigned char>& public_key,
                 const unsigned char coins[COINS_SIZE],
                 std::vector<unsigned char>& ciphertext_out,
                 SharedSecret& secret_out)
{
    ciphertext_out.clear();
    if (public_key.size() != PUBLIC_KEY_SIZE) return false;
    std::vector<unsigned char> ct(CIPHERTEXT_SIZE, 0);
    if (bps_mlkem768_enc_derand(ct.data(), secret_out.data(), public_key.data(), coins) != 0) {
        return false;
    }
    ciphertext_out.swap(ct);
    return true;
}

bool Decapsulate(const std::vector<unsigned char>& secret_key,
                 const std::vector<unsigned char>& ciphertext,
                 SharedSecret& secret_out)
{
    if (secret_key.size() != SECRET_KEY_SIZE || ciphertext.size() != CIPHERTEXT_SIZE) return false;
    return bps_mlkem768_dec(secret_out.data(), ciphertext.data(), secret_key.data()) == 0;
}

} // namespace mlkem768
