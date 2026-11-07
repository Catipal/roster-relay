# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# The phone's half of the companion, built from the node's own sources.
#
# A phone links what it needs to reach its home node and nothing of a node:
# the overlay client, the companion protocol, keys and the hashes under them.
# No chain, no validation, no wallet, no roster index, no boost, no leveldb.
# The handful of node files that would drag those in - logging, util/system,
# util/time, fs - are replaced by ../compat, which comes first on the include
# path, so a shared source that reaches for more of the node fails to build
# here instead of quietly pulling it in.
#
# Builds for Linux (desktop and phones) and, with Qt's Android toolchain file,
# for Android. Every file is compiled from the node's sources: ../../src in
# the BPS tree, or ../shared/src in the app's own repository, which carries a
# copy of just the files the client needs (listed in the BPS tree's
# mobile/standalone/shared-files.txt, and in ../shared/files.txt).

cmake_minimum_required(VERSION 3.16)
project(bps_companion_core LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../shared/src")
  get_filename_component(BPS_SRC "${CMAKE_CURRENT_LIST_DIR}/../shared/src" ABSOLUTE)
  set(BPS_VERSION_FILE "${CMAKE_CURRENT_LIST_DIR}/../shared/version.ac")
else()
  get_filename_component(BPS_SRC "${CMAKE_CURRENT_LIST_DIR}/../../src" ABSOLUTE)
  set(BPS_VERSION_FILE "${BPS_SRC}/../configure.ac")
endif()
get_filename_component(BPS_COMPAT "${CMAKE_CURRENT_LIST_DIR}/../compat" ABSOLUTE)

find_package(Threads REQUIRED)
include(CheckIncludeFile)
include(CheckSymbolExists)

# What the sources check for when there is no autotools config header.
set(BPS_PLATFORM_DEFINES "")
check_include_file(endian.h HAVE_ENDIAN_H)
check_include_file(sys/endian.h HAVE_SYS_ENDIAN_H)
check_include_file(byteswap.h HAVE_BYTESWAP_H)
check_symbol_exists(getrandom "sys/random.h" HAVE_SYS_GETRANDOM)
foreach(flag HAVE_ENDIAN_H HAVE_SYS_ENDIAN_H HAVE_BYTESWAP_H HAVE_SYS_GETRANDOM)
  if(${flag})
    list(APPEND BPS_PLATFORM_DEFINES ${flag}=1)
  endif()
endforeach()
# compat/byteswap.h and compat.h define their own bswap_* and strnlen unless
# told the platform has them; on glibc and Bionic it does, as macros or
# declarations their fallbacks would collide with.
if(HAVE_BYTESWAP_H)
  check_symbol_exists(bswap_16 "byteswap.h" HAVE_DECL_BSWAP_16)
  check_symbol_exists(bswap_32 "byteswap.h" HAVE_DECL_BSWAP_32)
  check_symbol_exists(bswap_64 "byteswap.h" HAVE_DECL_BSWAP_64)
endif()
check_symbol_exists(strnlen "string.h" HAVE_DECL_STRNLEN)
foreach(flag HAVE_DECL_BSWAP_16 HAVE_DECL_BSWAP_32 HAVE_DECL_BSWAP_64 HAVE_DECL_STRNLEN)
  if(${flag})
    list(APPEND BPS_PLATFORM_DEFINES ${flag}=1)
  else()
    list(APPEND BPS_PLATFORM_DEFINES ${flag}=0)
  endif()
endforeach()

# The node's version, from the one place it is set (randomenv.cpp mixes it in);
# in the app's own repository, the lines copied from there.
file(STRINGS "${BPS_VERSION_FILE}" BPS_VERSION_LINES
     REGEX "^define\\(_(CLIENT_VERSION_(MAJOR|MINOR|REVISION|BUILD)|COPYRIGHT_YEAR), [0-9]+\\)")
foreach(line ${BPS_VERSION_LINES})
  string(REGEX REPLACE "^define\\(_([A-Z_]+), ([0-9]+)\\)$" "\\1=\\2" def "${line}")
  list(APPEND BPS_PLATFORM_DEFINES ${def})
endforeach()
list(APPEND BPS_PLATFORM_DEFINES CLIENT_VERSION_IS_RELEASE=true)

# libsecp256k1, the tree's own copy, configured as the node configures it but
# portable C: no assembly, and the tables built at startup rather than ahead.
add_library(bps_secp256k1 STATIC "${BPS_SRC}/secp256k1/src/secp256k1.c")
target_include_directories(bps_secp256k1
  PUBLIC "${BPS_SRC}/secp256k1/include"
  PRIVATE "${BPS_SRC}/secp256k1" "${BPS_SRC}/secp256k1/src")
target_compile_definitions(bps_secp256k1 PRIVATE
  ECMULT_GEN_PREC_BITS=4 ECMULT_WINDOW_SIZE=15
  ENABLE_MODULE_ECDH=1 ENABLE_MODULE_EXTRAKEYS=1 ENABLE_MODULE_RECOVERY=1 ENABLE_MODULE_SCHNORRSIG=1
  USE_NUM_NONE=1 USE_FIELD_INV_BUILTIN=1 USE_SCALAR_INV_BUILTIN=1)

set(BPS_CORE_SOURCES
  companion/client.cpp
  companion/protocol.cpp
  overlay/cells.cpp
  overlay/frame.cpp
  overlay/handshake.cpp
  overlay/limits.cpp
  overlay/path.cpp
  overlay/relay.cpp
  overlay/select.cpp
  overlay/session.cpp
  overlay/socket.cpp
  overlay/transport.cpp
  crypto/chacha20.cpp
  crypto/hkdf_sha256_32.cpp
  crypto/hmac_sha256.cpp
  crypto/hmac_sha512.cpp
  crypto/poly1305.cpp
  crypto/ripemd160.cpp
  crypto/sha256.cpp
  crypto/sha3.cpp
  crypto/sha512.cpp
  hash.cpp
  key.cpp
  netaddress.cpp
  netbase.cpp
  pubkey.cpp
  random.cpp
  randomenv.cpp
  support/cleanse.cpp
  support/lockedpool.cpp
  threadinterrupt.cpp
  uint256.cpp
  util/asmap.cpp
  util/moneystr.cpp
  util/strencodings.cpp
  util/threadnames.cpp)
list(TRANSFORM BPS_CORE_SOURCES PREPEND "${BPS_SRC}/")

add_library(bps_companion_core STATIC ${BPS_CORE_SOURCES} "${BPS_COMPAT}/compat.cpp")
# The compat directory first: its logging.h, fs.h and util/system.h stand in
# for the node's.
target_include_directories(bps_companion_core BEFORE PUBLIC "${BPS_COMPAT}")
target_include_directories(bps_companion_core PUBLIC "${BPS_SRC}" "${BPS_SRC}/secp256k1/include")
# BPS_MOBILE leaves out the little the shared files keep for a node alone:
# EnsureLowS in key.cpp, block validation's only reason to link OpenSSL.
target_compile_definitions(bps_companion_core PUBLIC ${BPS_PLATFORM_DEFINES} BPS_MOBILE=1)
target_link_libraries(bps_companion_core PUBLIC bps_secp256k1 Threads::Threads)

# The phone without a screen, rebuilt here from the same file the autotools
# build uses: proof that the line between phone and node holds.
option(BPS_COMPANION_CLI "Build bps-companion-cli" ON)
if(BPS_COMPANION_CLI)
  file(GLOB BPS_UNIVALUE_SOURCES "${BPS_SRC}/univalue/lib/*.cpp")
  add_library(bps_univalue STATIC ${BPS_UNIVALUE_SOURCES})
  target_include_directories(bps_univalue PUBLIC "${BPS_SRC}/univalue/include")
  add_executable(bps-companion-cli "${BPS_SRC}/bps-companion-cli.cpp")
  target_link_libraries(bps-companion-cli PRIVATE bps_companion_core bps_univalue)
endif()
