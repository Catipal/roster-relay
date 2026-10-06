// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * How mlkem-native is built here.
 *
 * Kept outside src/mlkem-native so that directory stays exactly as upstream
 * shipped it; mlkem-native reads this file in place of its own default config
 * because MLK_CONFIG_FILE names it. Both the library (mlkem768_impl.c) and the
 * code calling it (mlkem768.cpp) define MLK_CONFIG_FILE before including
 * anything, so the two always agree on the parameter set and symbol names.
 *
 * C, not C++: mlkem-native includes it from C, and it must not depend on
 * anything in this tree.
 */

#ifndef BITCOIN_CRYPTO_MLKEM768_CONFIG_H
#define BITCOIN_CRYPTO_MLKEM768_CONFIG_H

/* ML-KEM-768, the parameter set Signal, iMessage and TLS deployments chose. */
#define MLK_CONFIG_PARAMETER_SET 768

/* Public symbols become bps_mlkem768_keypair_derand and so on, so they cannot
 * collide with another copy of mlkem-native a library might bring in. */
#define MLK_CONFIG_NAMESPACE_PREFIX bps_mlkem768

/* Only the deterministic entry points. Randomness comes from this tree's own
 * GetStrongRandBytes and is passed in, so mlkem-native needs no randombytes()
 * and there is exactly one source of randomness in the program. */
#define MLK_CONFIG_NO_RANDOMIZED_API

#if defined(MLK_BUILD_INTERNAL)
/* The whole library is one compilation unit (mlkem_native.c), so everything
 * that is not the public API can be static. */
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#endif /* MLK_BUILD_INTERNAL */

/* Upstream's config defines this unconditionally; its own headers expect it. */
#define MLK_DEFAULT_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM768

#endif /* BITCOIN_CRYPTO_MLKEM768_CONFIG_H */
