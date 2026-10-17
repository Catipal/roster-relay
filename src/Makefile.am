# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_INCLUDES=-I$(builddir) -I$(srcdir)/secp256k1/include $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS)

BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBBITCOIN_COMMON=libbitcoin_common.a
LIBBITCOIN_CONSENSUS=libbitcoin_consensus.a
LIBBITCOIN_CLI=libbitcoin_cli.a
LIBBITCOIN_UTIL=libbitcoin_util.a
LIBBITCOIN_CRYPTO_BASE=crypto/libbitcoin_crypto_base.a
LIBBITCOINQT=qt/libbitcoinqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libbitcoin_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBBITCOINCONSENSUS=libbitcoinconsensus.la
endif
if ENABLE_WALLET
LIBBITCOIN_WALLET=libbitcoin_wallet.a
LIBBITCOIN_WALLET_TOOL=libbitcoin_wallet_tool.a
endif

LIBBITCOIN_CRYPTO= $(LIBBITCOIN_CRYPTO_BASE)
if ENABLE_SSE41
LIBBITCOIN_CRYPTO_SSE41 = crypto/libbitcoin_crypto_sse41.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBBITCOIN_CRYPTO_AVX2 = crypto/libbitcoin_crypto_avx2.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_CRYPTO_AVX2)
endif
if ENABLE_SHANI
LIBBITCOIN_CRYPTO_SHANI = crypto/libbitcoin_crypto_shani.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_CRYPTO_SHANI)
endif
LIBBITCOIN_CRYPTO_MLKEM = crypto/libbitcoin_crypto_mlkem.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_CRYPTO_MLKEM)
# lwIP, the gateway's TCP/IP stack. Linked with the libraries every binary
# takes, after the server library whose overlay code calls into it.
LIBBITCOIN_LWIP = libbitcoin_lwip.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_LWIP)
LWIP_CPPFLAGS = -I$(srcdir)/overlay/lwip -I$(srcdir)/lwip/include

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CLI) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_WALLET_TOOL) \
  $(LIBBITCOIN_ZMQ)

lib_LTLIBRARIES = $(LIBBITCOINCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += bitcoin-posd
endif

if BUILD_BITCOIN_NODE
  bin_PROGRAMS += bitcoin-pos-node
endif

if BUILD_BITCOIN_CLI
  bin_PROGRAMS += bitcoin-pos-cli
endif
if BUILD_BITCOIN_TX
  bin_PROGRAMS += bitcoin-pos-tx
endif
if ENABLE_WALLET
if BUILD_BITCOIN_WALLET
  bin_PROGRAMS += bitcoin-pos-wallet
endif
endif

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
  addrdb.h \
  addrman.h \
  addressbook.h \
  attributes.h \
  banman.h \
  base58.h \
  bech32.h \
  blockencodings.h \
  blockfilter.h \
  bloom.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/cpuid.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_check.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  dbwrapper.h \
  flatfile.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  index/base.h \
  index/blockfilterindex.h \
  index/nameindex.h \
  index/rosterindex.h \
  index/disktxpos.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  interfaces/chain.h \
  interfaces/handler.h \
  interfaces/node.h \
  interfaces/wallet.h \
  key.h \
  key_io.h \
  logging.h \
  logging/timer.h \
  mail/client.h \
  mail/letter.h \
  mail/mailbox.h \
  mail/protocol.h \
  names/name.h \
  names/payment.h \
  names/petnames.h \
  names/record.h \
  names/registrar.h \
  names/resolve.h \
  names/sale.h \
  names/state.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_permissions.h \
  net_processing.h \
  net_types.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  node/coin.h \
  node/coinstats.h \
  node/context.h \
  node/psbt.h \
  node/transaction.h \
  node/ui_interface.h \
  node/utxo_snapshot.h \
  noui.h \
  optional.h \
  outputtype.h \
  policy/feerate.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  policy/settings.h \
  pow.h \
  pos.h \
  protocol.h \
  psbt.h \
  random.h \
  randomenv.h \
  reverse_iterator.h \
  overlay/frame.h \
  overlay/handshake.h \
  overlay/chainsync.h \
  overlay/exitpolicy.h \
  overlay/dnsanswer.h \
  overlay/gateway.h \
  overlay/gatewayclient.h \
  overlay/gatewayproto.h \
  overlay/ippacket.h \
  overlay/limits.h \
  overlay/localproxy.h \
  overlay/meeting.h \
  overlay/netstack.h \
  overlay/sysif.h \
  overlay/lwip/lwipopts.h \
  overlay/lwip/arch/cc.h \
  overlay/path.h \
  overlay/radio.h \
  overlay/relay.h \
  overlay/rendezvous.h \
  overlay/select.h \
  overlay/socket.h \
  overlay/session.h \
  overlay/transport.h \
  roster/commitment.h \
  roster/extract.h \
  roster/identity.h \
  roster/keystore.h \
  roster/ledger.h \
  roster/listing.h \
  roster/payout.h \
  roster/peers.h \
  roster/record.h \
  roster/view.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mining.h \
  rpc/protocol.h \
  rpc/hint.h \
  rpc/rawtransaction_util.h \
  rpc/register.h \
  rpc/request.h \
  rpc/server.h \
  rpc/util.h \
  scheduler.h \
  script/descriptor.h \
  script/keyorigin.h \
  script/sigcache.h \
  script/sign.h \
  script/signingprovider.h \
  script/standard.h \
  shutdown.h \
  signet.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadinterrupt.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txrequest.h \
  txmempool.h \
  undo.h \
  util/asmap.h \
  util/bip32.h \
  util/bytevectorhash.h \
  util/check.h \
  util/error.h \
  util/fees.h \
  util/golombrice.h \
  util/macros.h \
  util/memory.h \
  util/message.h \
  util/moneystr.h \
  util/rbf.h \
  util/ref.h \
  util/settings.h \
  util/spanparsing.h \
  util/string.h \
  util/system.h \
  util/threadnames.h \
  util/time.h \
  util/translation.h \
  util/ui_change_type.h \
  util/url.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  versionbitsinfo.h \
  wallet/bdb.h \
  wallet/coincontrol.h \
  wallet/coinselection.h \
  wallet/context.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/ismine.h \
  wallet/load.h \
  wallet/namepay.h \
  wallet/rpcnames.h \
  wallet/rpcwallet.h \
  wallet/salvage.h \
  wallet/scriptpubkeyman.h \
  wallet/sqlite.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  walletinitinterface.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  zmq/zmqutil.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libbitcoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between bitcoind and bitcoin-qt
# Contains code accessing mempool and chain state that is meant to be separated
# from wallet and gui code (see node/README.md). Shared code should go in
# libbitcoin_common or libbitcoin_util libraries, instead.
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS) $(LWIP_CPPFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  banman.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  checkpoints.cpp \
  consensus/tx_verify.cpp \
  dbwrapper.cpp \
  flatfile.cpp \
  httprpc.cpp \
  httpserver.cpp \
  index/base.cpp \
  index/blockfilterindex.cpp \
  index/nameindex.cpp \
  index/rosterindex.cpp \
  roster/view.cpp \
  roster/ledger.cpp \
  index/txindex.cpp \
  init.cpp \
  roster/listing.cpp \
  mail/client.cpp \
  mail/letter.cpp \
  mail/mailbox.cpp \
  mail/protocol.cpp \
  overlay/chainsync.cpp \
  overlay/dnsanswer.cpp \
  overlay/gateway.cpp \
  overlay/gatewayclient.cpp \
  overlay/localproxy.cpp \
  overlay/meeting.cpp \
  overlay/netstack.cpp \
  overlay/sysif.cpp \
  names/name.cpp \
  names/petnames.cpp \
  names/record.cpp \
  names/registrar.cpp \
  names/resolve.cpp \
  names/sale.cpp \
  names/state.cpp \
  interfaces/chain.cpp \
  interfaces/node.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  node/coin.cpp \
  node/coinstats.cpp \
  node/context.cpp \
  node/psbt.cpp \
  node/transaction.cpp \
  node/ui_interface.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  pow.cpp \
  pos.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mail.cpp \
  rpc/mining.cpp \
  rpc/names.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/roster.cpp \
  rpc/rostercommitment.cpp \
  rpc/rosteridentity.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  shutdown.cpp \
  signet.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txrequest.cpp \
  txmempool.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_WALLET
libbitcoin_server_a_SOURCES += wallet/init.cpp
endif
if !ENABLE_WALLET
libbitcoin_server_a_SOURCES += dummywallet.cpp
endif

if ENABLE_ZMQ
libbitcoin_zmq_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp \
  zmq/zmqutil.cpp
endif


# wallet: shared between bitcoind and bitcoin-qt, but only linked
# when wallet enabled
libbitcoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(SQLITE_CFLAGS)
libbitcoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_wallet_a_SOURCES = \
  interfaces/wallet.cpp \
  addressbook.cpp \
  names/payment.cpp \
  wallet/bdb.cpp \
  wallet/coincontrol.cpp \
  wallet/context.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/load.cpp \
  wallet/namepay.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcnames.cpp \
  wallet/rpcwallet.cpp \
  wallet/salvage.cpp \
  wallet/scriptpubkeyman.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  $(BITCOIN_CORE_H)

if USE_SQLITE
libbitcoin_wallet_a_SOURCES += wallet/sqlite.cpp
endif

libbitcoin_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_libbitcoin_crypto_base_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_base_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_base_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha_poly_aead.h \
  crypto/chacha_poly_aead.cpp \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hkdf_sha256_32.cpp \
  crypto/hkdf_sha256_32.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/poly1305.h \
  crypto/poly1305.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha3.cpp \
  crypto/sha3.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h

if USE_ASM
crypto_libbitcoin_crypto_base_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libbitcoin_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libbitcoin_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
crypto_libbitcoin_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libbitcoin_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libbitcoin_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
crypto_libbitcoin_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp

crypto_libbitcoin_crypto_shani_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_shani_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_shani_a_CXXFLAGS += $(SHANI_CXXFLAGS)
crypto_libbitcoin_crypto_shani_a_CPPFLAGS += -DENABLE_SHANI
crypto_libbitcoin_crypto_shani_a_SOURCES = crypto/sha256_shani.cpp

# ML-KEM-768 for mail, from mlkem-native (src/mlkem-native). A library of its
# own because it is C, and so it stays out of libbitcoinconsensus, which takes
# its sources from the base library. It depends on nothing else in the tree.
crypto_libbitcoin_crypto_mlkem_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_mlkem_a_CFLAGS = $(AM_CFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_mlkem_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_mlkem_a_SOURCES = \
  crypto/mlkem768.cpp \
  crypto/mlkem768.h \
  crypto/mlkem768_config.h \
  crypto/mlkem768_impl.c

# lwIP 2.2.1 for the gateway (src/lwip, vendored unmodified; BPS's settings
# are in overlay/lwip). C, a library of its own, and only the TCP/IP core:
# overlay/lwip/lwipopts.h switches off what these files would otherwise add.
libbitcoin_lwip_a_CPPFLAGS = $(AM_CPPFLAGS) $(LWIP_CPPFLAGS)
libbitcoin_lwip_a_CFLAGS = $(AM_CFLAGS) $(PIE_FLAGS)
libbitcoin_lwip_a_SOURCES = \
  lwip/core/init.c \
  lwip/core/def.c \
  lwip/core/inet_chksum.c \
  lwip/core/ip.c \
  lwip/core/mem.c \
  lwip/core/memp.c \
  lwip/core/netif.c \
  lwip/core/pbuf.c \
  lwip/core/stats.c \
  lwip/core/sys.c \
  lwip/core/tcp.c \
  lwip/core/tcp_in.c \
  lwip/core/tcp_out.c \
  lwip/core/timeouts.c \
  lwip/core/ipv4/ip4.c \
  lwip/core/ipv4/ip4_addr.c \
  lwip/core/ipv4/icmp.c \
  lwip/core/ipv4/ip4_frag.c \
  lwip/core/ipv6/ip6.c \
  lwip/core/ipv6/ip6_addr.c \
  lwip/core/ipv6/icmp6.c \
  lwip/core/ipv6/inet6.c \
  lwip/core/ipv6/nd6.c \
  lwip/core/ipv6/mld6.c \
  lwip/core/ipv6/ip6_frag.c

# consensus: shared between all executables that validate any consensus rules.
libbitcoin_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tx_check.cpp \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  span.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/strencodings.cpp \
  util/strencodings.h \
  version.h

# common: shared between bitcoind, and bitcoin-qt and non-server tools
libbitcoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_common_a_SOURCES = \
  base58.cpp \
  bech32.cpp \
  bloom.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  key.cpp \
  key_io.cpp \
  merkleblock.cpp \
  netaddress.cpp \
  netbase.cpp \
  net_permissions.cpp \
  outputtype.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  protocol.cpp \
  psbt.cpp \
  overlay/frame.cpp \
  overlay/exitpolicy.cpp \
  overlay/gatewayproto.cpp \
  overlay/handshake.cpp \
  overlay/ippacket.cpp \
  overlay/limits.cpp \
  overlay/path.cpp \
  overlay/radio.cpp \
  overlay/relay.cpp \
  overlay/rendezvous.cpp \
  overlay/select.cpp \
  overlay/socket.cpp \
  overlay/session.cpp \
  overlay/transport.cpp \
  roster/commitment.cpp \
  roster/extract.cpp \
  roster/identity.cpp \
  roster/keystore.cpp \
  roster/payout.cpp \
  roster/peers.cpp \
  roster/record.cpp \
  rpc/hint.cpp \
  rpc/rawtransaction_util.cpp \
  rpc/util.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/sign.cpp \
  script/signingprovider.cpp \
  script/standard.cpp \
  versionbitsinfo.cpp \
  warnings.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libbitcoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  interfaces/handler.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  rpc/request.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util/asmap.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/error.cpp \
  util/fees.cpp \
  util/system.cpp \
  util/message.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/settings.cpp \
  util/threadnames.cpp \
  util/spanparsing.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/time.cpp \
  $(BITCOIN_CORE_H)

if USE_LIBEVENT
libbitcoin_util_a_SOURCES += util/url.cpp
endif

if GLIBC_BACK_COMPAT
libbitcoin_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# cli: shared between bitcoin-cli and bitcoin-qt
libbitcoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_cli_a_SOURCES = \
  compat/stdin.h \
  compat/stdin.cpp \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)

nodist_libbitcoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind & bitcoin-node binaries #
bitcoin_daemon_sources = bitcoind.cpp
bitcoin_bin_cppflags = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
bitcoin_bin_cxxflags = $(AM_CXXFLAGS) $(PIE_FLAGS)
bitcoin_bin_ldflags = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
bitcoin_daemon_sources += bitcoind-res.rc
endif

bitcoin_bin_ldadd = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

bitcoin_bin_ldadd += $(BOOST_LIBS) $(BDB_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(SQLITE_LIBS)

bitcoin_posd_SOURCES = $(bitcoin_daemon_sources)
bitcoin_posd_CPPFLAGS = $(bitcoin_bin_cppflags)
bitcoin_posd_CXXFLAGS = $(bitcoin_bin_cxxflags)
bitcoin_posd_LDFLAGS = $(bitcoin_bin_ldflags)
bitcoin_posd_LDADD = $(LIBBITCOIN_SERVER) $(bitcoin_bin_ldadd)

bitcoin_pos_node_SOURCES = $(bitcoin_daemon_sources)
bitcoin_pos_node_CPPFLAGS = $(bitcoin_bin_cppflags)
bitcoin_pos_node_CXXFLAGS = $(bitcoin_bin_cxxflags)
bitcoin_pos_node_LDFLAGS = $(bitcoin_bin_ldflags)
bitcoin_pos_node_LDADD = $(LIBBITCOIN_SERVER) $(bitcoin_bin_ldadd)

# bitcoin-cli binary #
bitcoin_pos_cli_SOURCES = bitcoin-cli.cpp
bitcoin_pos_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
bitcoin_pos_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
bitcoin_pos_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
bitcoin_pos_cli_SOURCES += bitcoin-cli-res.rc
endif

bitcoin_pos_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO)

bitcoin_pos_cli_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# bitcoin-tx binary #
bitcoin_pos_tx_SOURCES = bitcoin-tx.cpp
bitcoin_pos_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
bitcoin_pos_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
bitcoin_pos_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
bitcoin_pos_tx_SOURCES += bitcoin-tx-res.rc
endif

bitcoin_pos_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSECP256K1)

bitcoin_pos_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# bitcoin-wallet binary #
bitcoin_pos_wallet_SOURCES = bitcoin-wallet.cpp
bitcoin_pos_wallet_CPPFLAGS = $(bitcoin_bin_cppflags)
bitcoin_pos_wallet_CXXFLAGS = $(bitcoin_bin_cxxflags)
bitcoin_pos_wallet_LDFLAGS = $(bitcoin_bin_ldflags)
bitcoin_pos_wallet_LDADD = $(LIBBITCOIN_SERVER) $(LIBBITCOIN_WALLET_TOOL) $(bitcoin_bin_ldadd)

if TARGET_WINDOWS
bitcoin_pos_wallet_SOURCES += bitcoin-wallet-res.rc
endif
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libbitcoinconsensus_la_SOURCES = support/cleanse.cpp $(crypto_libbitcoin_crypto_base_a_SOURCES) $(libbitcoin_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libbitcoinconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libbitcoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libbitcoinconsensus_la_LIBADD = $(LIBSECP256K1)
libbitcoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libbitcoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

MLKEM_DIST =  mlkem-native/LICENSE
MLKEM_DIST += mlkem-native/mlkem/mlkem_native.c
MLKEM_DIST += mlkem-native/mlkem/mlkem_native.h
MLKEM_DIST += mlkem-native/mlkem/mlkem_native_config.h
MLKEM_DIST += mlkem-native/mlkem/src/cbmc.h
MLKEM_DIST += mlkem-native/mlkem/src/common.h
MLKEM_DIST += mlkem-native/mlkem/src/compress.c
MLKEM_DIST += mlkem-native/mlkem/src/compress.h
MLKEM_DIST += mlkem-native/mlkem/src/context.h
MLKEM_DIST += mlkem-native/mlkem/src/debug.c
MLKEM_DIST += mlkem-native/mlkem/src/debug.h
MLKEM_DIST += mlkem-native/mlkem/src/fips202/fips202.c
MLKEM_DIST += mlkem-native/mlkem/src/fips202/fips202.h
MLKEM_DIST += mlkem-native/mlkem/src/fips202/fips202x4.c
MLKEM_DIST += mlkem-native/mlkem/src/fips202/fips202x4.h
MLKEM_DIST += mlkem-native/mlkem/src/fips202/keccakf1600.c
MLKEM_DIST += mlkem-native/mlkem/src/fips202/keccakf1600.h
MLKEM_DIST += mlkem-native/mlkem/src/indcpa.c
MLKEM_DIST += mlkem-native/mlkem/src/indcpa.h
MLKEM_DIST += mlkem-native/mlkem/src/kem.c
MLKEM_DIST += mlkem-native/mlkem/src/kem.h
MLKEM_DIST += mlkem-native/mlkem/src/params.h
MLKEM_DIST += mlkem-native/mlkem/src/poly.c
MLKEM_DIST += mlkem-native/mlkem/src/poly.h
MLKEM_DIST += mlkem-native/mlkem/src/poly_k.c
MLKEM_DIST += mlkem-native/mlkem/src/poly_k.h
MLKEM_DIST += mlkem-native/mlkem/src/randombytes.h
MLKEM_DIST += mlkem-native/mlkem/src/sampling.c
MLKEM_DIST += mlkem-native/mlkem/src/sampling.h
MLKEM_DIST += mlkem-native/mlkem/src/symmetric.h
MLKEM_DIST += mlkem-native/mlkem/src/sys.h
MLKEM_DIST += mlkem-native/mlkem/src/verify.c
MLKEM_DIST += mlkem-native/mlkem/src/verify.h
MLKEM_DIST += mlkem-native/mlkem/src/zetas.inc

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crc32c/src/*.gcda crc32c/src/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += index/*.gcda index/*.gcno
CLEANFILES += interfaces/*.gcda interfaces/*.gcno
CLEANFILES += node/*.gcda node/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rpc/*.gcda rpc/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += util/*.gcda util/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

LWIP_DIST = lwip/COPYING
LWIP_DIST += lwip/core/altcp.c
LWIP_DIST += lwip/core/altcp_alloc.c
LWIP_DIST += lwip/core/altcp_tcp.c
LWIP_DIST += lwip/core/def.c
LWIP_DIST += lwip/core/dns.c
LWIP_DIST += lwip/core/inet_chksum.c
LWIP_DIST += lwip/core/init.c
LWIP_DIST += lwip/core/ip.c
LWIP_DIST += lwip/core/mem.c
LWIP_DIST += lwip/core/memp.c
LWIP_DIST += lwip/core/netif.c
LWIP_DIST += lwip/core/pbuf.c
LWIP_DIST += lwip/core/raw.c
LWIP_DIST += lwip/core/stats.c
LWIP_DIST += lwip/core/sys.c
LWIP_DIST += lwip/core/tcp.c
LWIP_DIST += lwip/core/tcp_in.c
LWIP_DIST += lwip/core/tcp_out.c
LWIP_DIST += lwip/core/timeouts.c
LWIP_DIST += lwip/core/udp.c
LWIP_DIST += lwip/core/ipv4/acd.c
LWIP_DIST += lwip/core/ipv4/autoip.c
LWIP_DIST += lwip/core/ipv4/dhcp.c
LWIP_DIST += lwip/core/ipv4/etharp.c
LWIP_DIST += lwip/core/ipv4/icmp.c
LWIP_DIST += lwip/core/ipv4/igmp.c
LWIP_DIST += lwip/core/ipv4/ip4.c
LWIP_DIST += lwip/core/ipv4/ip4_addr.c
LWIP_DIST += lwip/core/ipv4/ip4_frag.c
LWIP_DIST += lwip/core/ipv6/dhcp6.c
LWIP_DIST += lwip/core/ipv6/ethip6.c
LWIP_DIST += lwip/core/ipv6/icmp6.c
LWIP_DIST += lwip/core/ipv6/inet6.c
LWIP_DIST += lwip/core/ipv6/ip6.c
LWIP_DIST += lwip/core/ipv6/ip6_addr.c
LWIP_DIST += lwip/core/ipv6/ip6_frag.c
LWIP_DIST += lwip/core/ipv6/mld6.c
LWIP_DIST += lwip/core/ipv6/nd6.c
LWIP_DIST += lwip/include/compat/posix/netdb.h
LWIP_DIST += lwip/include/compat/posix/arpa/inet.h
LWIP_DIST += lwip/include/compat/posix/net/if.h
LWIP_DIST += lwip/include/compat/posix/sys/socket.h
LWIP_DIST += lwip/include/compat/stdc/errno.h
LWIP_DIST += lwip/include/lwip/acd.h
LWIP_DIST += lwip/include/lwip/altcp.h
LWIP_DIST += lwip/include/lwip/altcp_tcp.h
LWIP_DIST += lwip/include/lwip/altcp_tls.h
LWIP_DIST += lwip/include/lwip/api.h
LWIP_DIST += lwip/include/lwip/arch.h
LWIP_DIST += lwip/include/lwip/autoip.h
LWIP_DIST += lwip/include/lwip/debug.h
LWIP_DIST += lwip/include/lwip/def.h
LWIP_DIST += lwip/include/lwip/dhcp.h
LWIP_DIST += lwip/include/lwip/dhcp6.h
LWIP_DIST += lwip/include/lwip/dns.h
LWIP_DIST += lwip/include/lwip/err.h
LWIP_DIST += lwip/include/lwip/errno.h
LWIP_DIST += lwip/include/lwip/etharp.h
LWIP_DIST += lwip/include/lwip/ethip6.h
LWIP_DIST += lwip/include/lwip/icmp.h
LWIP_DIST += lwip/include/lwip/icmp6.h
LWIP_DIST += lwip/include/lwip/if_api.h
LWIP_DIST += lwip/include/lwip/igmp.h
LWIP_DIST += lwip/include/lwip/inet.h
LWIP_DIST += lwip/include/lwip/inet_chksum.h
LWIP_DIST += lwip/include/lwip/init.h
LWIP_DIST += lwip/include/lwip/init.h.cmake.in
LWIP_DIST += lwip/include/lwip/ip.h
LWIP_DIST += lwip/include/lwip/ip4.h
LWIP_DIST += lwip/include/lwip/ip4_addr.h
LWIP_DIST += lwip/include/lwip/ip4_frag.h
LWIP_DIST += lwip/include/lwip/ip6.h
LWIP_DIST += lwip/include/lwip/ip6_addr.h
LWIP_DIST += lwip/include/lwip/ip6_frag.h
LWIP_DIST += lwip/include/lwip/ip6_zone.h
LWIP_DIST += lwip/include/lwip/ip_addr.h
LWIP_DIST += lwip/include/lwip/mem.h
LWIP_DIST += lwip/include/lwip/memp.h
LWIP_DIST += lwip/include/lwip/mld6.h
LWIP_DIST += lwip/include/lwip/nd6.h
LWIP_DIST += lwip/include/lwip/netbuf.h
LWIP_DIST += lwip/include/lwip/netdb.h
LWIP_DIST += lwip/include/lwip/netif.h
LWIP_DIST += lwip/include/lwip/netifapi.h
LWIP_DIST += lwip/include/lwip/opt.h
LWIP_DIST += lwip/include/lwip/pbuf.h
LWIP_DIST += lwip/include/lwip/raw.h
LWIP_DIST += lwip/include/lwip/sio.h
LWIP_DIST += lwip/include/lwip/snmp.h
LWIP_DIST += lwip/include/lwip/sockets.h
LWIP_DIST += lwip/include/lwip/stats.h
LWIP_DIST += lwip/include/lwip/sys.h
LWIP_DIST += lwip/include/lwip/tcp.h
LWIP_DIST += lwip/include/lwip/tcpbase.h
LWIP_DIST += lwip/include/lwip/tcpip.h
LWIP_DIST += lwip/include/lwip/timeouts.h
LWIP_DIST += lwip/include/lwip/udp.h
LWIP_DIST += lwip/include/lwip/apps/FILES
LWIP_DIST += lwip/include/lwip/apps/altcp_proxyconnect.h
LWIP_DIST += lwip/include/lwip/apps/altcp_tls_mbedtls_opts.h
LWIP_DIST += lwip/include/lwip/apps/fs.h
LWIP_DIST += lwip/include/lwip/apps/http_client.h
LWIP_DIST += lwip/include/lwip/apps/httpd.h
LWIP_DIST += lwip/include/lwip/apps/httpd_opts.h
LWIP_DIST += lwip/include/lwip/apps/lwiperf.h
LWIP_DIST += lwip/include/lwip/apps/mdns.h
LWIP_DIST += lwip/include/lwip/apps/mdns_domain.h
LWIP_DIST += lwip/include/lwip/apps/mdns_opts.h
LWIP_DIST += lwip/include/lwip/apps/mdns_out.h
LWIP_DIST += lwip/include/lwip/apps/mdns_priv.h
LWIP_DIST += lwip/include/lwip/apps/mqtt.h
LWIP_DIST += lwip/include/lwip/apps/mqtt_opts.h
LWIP_DIST += lwip/include/lwip/apps/mqtt_priv.h
LWIP_DIST += lwip/include/lwip/apps/netbiosns.h
LWIP_DIST += lwip/include/lwip/apps/netbiosns_opts.h
LWIP_DIST += lwip/include/lwip/apps/smtp.h
LWIP_DIST += lwip/include/lwip/apps/smtp_opts.h
LWIP_DIST += lwip/include/lwip/apps/snmp.h
LWIP_DIST += lwip/include/lwip/apps/snmp_core.h
LWIP_DIST += lwip/include/lwip/apps/snmp_mib2.h
LWIP_DIST += lwip/include/lwip/apps/snmp_opts.h
LWIP_DIST += lwip/include/lwip/apps/snmp_scalar.h
LWIP_DIST += lwip/include/lwip/apps/snmp_snmpv2_framework.h
LWIP_DIST += lwip/include/lwip/apps/snmp_snmpv2_usm.h
LWIP_DIST += lwip/include/lwip/apps/snmp_table.h
LWIP_DIST += lwip/include/lwip/apps/snmp_threadsync.h
LWIP_DIST += lwip/include/lwip/apps/snmpv3.h
LWIP_DIST += lwip/include/lwip/apps/sntp.h
LWIP_DIST += lwip/include/lwip/apps/sntp_opts.h
LWIP_DIST += lwip/include/lwip/apps/tftp_client.h
LWIP_DIST += lwip/include/lwip/apps/tftp_common.h
LWIP_DIST += lwip/include/lwip/apps/tftp_opts.h
LWIP_DIST += lwip/include/lwip/apps/tftp_server.h
LWIP_DIST += lwip/include/lwip/priv/altcp_priv.h
LWIP_DIST += lwip/include/lwip/priv/api_msg.h
LWIP_DIST += lwip/include/lwip/priv/mem_priv.h
LWIP_DIST += lwip/include/lwip/priv/memp_priv.h
LWIP_DIST += lwip/include/lwip/priv/memp_std.h
LWIP_DIST += lwip/include/lwip/priv/nd6_priv.h
LWIP_DIST += lwip/include/lwip/priv/raw_priv.h
LWIP_DIST += lwip/include/lwip/priv/sockets_priv.h
LWIP_DIST += lwip/include/lwip/priv/tcp_priv.h
LWIP_DIST += lwip/include/lwip/priv/tcpip_priv.h
LWIP_DIST += lwip/include/lwip/prot/acd.h
LWIP_DIST += lwip/include/lwip/prot/autoip.h
LWIP_DIST += lwip/include/lwip/prot/dhcp.h
LWIP_DIST += lwip/include/lwip/prot/dhcp6.h
LWIP_DIST += lwip/include/lwip/prot/dns.h
LWIP_DIST += lwip/include/lwip/prot/etharp.h
LWIP_DIST += lwip/include/lwip/prot/ethernet.h
LWIP_DIST += lwip/include/lwip/prot/iana.h
LWIP_DIST += lwip/include/lwip/prot/icmp.h
LWIP_DIST += lwip/include/lwip/prot/icmp6.h
LWIP_DIST += lwip/include/lwip/prot/ieee.h
LWIP_DIST += lwip/include/lwip/prot/igmp.h
LWIP_DIST += lwip/include/lwip/prot/ip.h
LWIP_DIST += lwip/include/lwip/prot/ip4.h
LWIP_DIST += lwip/include/lwip/prot/ip6.h
LWIP_DIST += lwip/include/lwip/prot/mld6.h
LWIP_DIST += lwip/include/lwip/prot/nd6.h
LWIP_DIST += lwip/include/lwip/prot/tcp.h
LWIP_DIST += lwip/include/lwip/prot/udp.h
LWIP_DIST += lwip/include/netif/bridgeif.h
LWIP_DIST += lwip/include/netif/bridgeif_opts.h
LWIP_DIST += lwip/include/netif/etharp.h
LWIP_DIST += lwip/include/netif/ethernet.h
LWIP_DIST += lwip/include/netif/ieee802154.h
LWIP_DIST += lwip/include/netif/lowpan6.h
LWIP_DIST += lwip/include/netif/lowpan6_ble.h
LWIP_DIST += lwip/include/netif/lowpan6_common.h
LWIP_DIST += lwip/include/netif/lowpan6_opts.h
LWIP_DIST += lwip/include/netif/slipif.h
LWIP_DIST += lwip/include/netif/zepif.h
LWIP_DIST += lwip/include/netif/ppp/ccp.h
LWIP_DIST += lwip/include/netif/ppp/chap-md5.h
LWIP_DIST += lwip/include/netif/ppp/chap-new.h
LWIP_DIST += lwip/include/netif/ppp/chap_ms.h
LWIP_DIST += lwip/include/netif/ppp/eap.h
LWIP_DIST += lwip/include/netif/ppp/ecp.h
LWIP_DIST += lwip/include/netif/ppp/eui64.h
LWIP_DIST += lwip/include/netif/ppp/fsm.h
LWIP_DIST += lwip/include/netif/ppp/ipcp.h
LWIP_DIST += lwip/include/netif/ppp/ipv6cp.h
LWIP_DIST += lwip/include/netif/ppp/lcp.h
LWIP_DIST += lwip/include/netif/ppp/magic.h
LWIP_DIST += lwip/include/netif/ppp/mppe.h
LWIP_DIST += lwip/include/netif/ppp/ppp.h
LWIP_DIST += lwip/include/netif/ppp/ppp_impl.h
LWIP_DIST += lwip/include/netif/ppp/ppp_opts.h
LWIP_DIST += lwip/include/netif/ppp/pppapi.h
LWIP_DIST += lwip/include/netif/ppp/pppcrypt.h
LWIP_DIST += lwip/include/netif/ppp/pppdebug.h
LWIP_DIST += lwip/include/netif/ppp/pppoe.h
LWIP_DIST += lwip/include/netif/ppp/pppol2tp.h
LWIP_DIST += lwip/include/netif/ppp/pppos.h
LWIP_DIST += lwip/include/netif/ppp/upap.h
LWIP_DIST += lwip/include/netif/ppp/vj.h
LWIP_DIST += lwip/include/netif/ppp/polarssl/arc4.h
LWIP_DIST += lwip/include/netif/ppp/polarssl/des.h
LWIP_DIST += lwip/include/netif/ppp/polarssl/md4.h
LWIP_DIST += lwip/include/netif/ppp/polarssl/md5.h
LWIP_DIST += lwip/include/netif/ppp/polarssl/sha1.h

EXTRA_DIST = $(CTAES_DIST) $(MLKEM_DIST) $(LWIP_DIST)


config/bitcoin-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/bitcoin-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/bitcoin-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/bitcoin-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if TARGET_DARWIN
	@echo "Checking macOS dynamic libraries..."
	$(AM_V_at) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if TARGET_WINDOWS
	@echo "Checking Windows dynamic libraries..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

if EMBEDDED_LEVELDB
include Makefile.crc32c.include
include Makefile.leveldb.include
endif

include Makefile.test_util.include
include Makefile.test_fuzz.include

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
include Makefile.bpsqt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
