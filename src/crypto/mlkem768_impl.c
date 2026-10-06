/* Copyright (c) 2026 The Bitcoin PoS Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

/*
 * mlkem-native, built as the single compilation unit upstream provides for
 * exactly this purpose, with the configuration in mlkem768_config.h.
 *
 * Portable C only. The assembly backends are faster but are one more thing to
 * build for every release target (seven of them, two cross-compiled for other
 * operating systems), and mail does one encapsulation per letter.
 */

#define MLK_CONFIG_FILE "crypto/mlkem768_config.h"
#include "mlkem-native/mlkem/mlkem_native.c"
