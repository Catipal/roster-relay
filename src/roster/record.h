// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_RECORD_H
#define BITCOIN_ROSTER_RECORD_H

#include <optional.h>
#include <pubkey.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Chain-anchored peer roster records.
 *
 * Every record is a self-contained, detached-signed object carried in an
 * OP_RETURN output; the transaction is freight and is never consulted. Parsing
 * is therefore a pure function over bytes with no chain state, no consensus
 * interaction, and no policy — which is what makes it exhaustively testable in
 * isolation.
 *
 * Design note 001 is the reference for the wire format and for why each field
 * is present or deliberately absent.
 */
namespace roster {

/** Wire magic, "BPS". Lets an indexer reject non-records in a single compare. */
static constexpr unsigned char RECORD_MAGIC[3] = {0x42, 0x50, 0x53};

/** The only record version currently defined. */
static constexpr uint8_t RECORD_VERSION = 1;

enum class RecordType : uint8_t {
    ANNOUNCE = 0x01,
    REVOKE = 0x02,
    DELEGATE = 0x03,
    ROTATE = 0x04,
    VETO = 0x05,
};

//! services bitfield. Bit 31 is structural (it changes the record's length);
//! the low bits are advisory and carry no parsing consequence.
static constexpr uint32_t SERVICE_RELAY_CAPABLE = 1U << 0;
static constexpr uint32_t SERVICE_RENDEZVOUS_ONLY = 1U << 1;
static constexpr uint32_t SERVICE_META_PRESENT = 1U << 31;

static constexpr size_t RECORD_HEADER_SIZE = 4; //!< magic(3) + ver/type(1)
static constexpr size_t RECORD_KEY_SIZE = 32;
static constexpr size_t RECORD_SIG_SIZE = 64;
static constexpr size_t RECORD_HASH_SIZE = 32;
static constexpr size_t MAX_ENDPOINTS = 3;

/**
 * The largest legal record, and the cheap bound used to reject obvious
 * non-records before any real work.
 *
 * A 3-endpoint ANNOUNCE with meta_hash present, every endpoint an onion v3:
 *
 *     header  4 + op_key 32 + expiry 4 + services 4 + prev_height 4
 *           + ep_count 1 + 3 x (1 + 32 + 2) + meta 32 + sig 64  =  250
 *
 * Carried in an OP_RETURN this needs 253 script bytes: OP_RETURN, then
 * OP_PUSHDATA1 and a length byte, since any push above 75 bytes needs them.
 * MAX_DATACARRIER_FOR_ROSTER records that, because a relay limit below it
 * would silently make some legal records unpublishable.
 */
static constexpr size_t MAX_RECORD_SIZE = 250;

/** Script bytes an OP_RETURN needs to carry a record: opcode, pushdata, length. */
static constexpr size_t OP_RETURN_OVERHEAD = 3;

/** The smallest -datacarriersize that can carry every legal record. */
static constexpr size_t MAX_DATACARRIER_FOR_ROSTER = MAX_RECORD_SIZE + OP_RETURN_OVERHEAD;

/**
 * Network ids for Endpoint::network.
 *
 * These match BIP155 by design, but are defined here rather than borrowed.
 * CNetAddr::BIP155Network is private, and more to the point the roster's wire
 * format should own the identifiers it commits to permanently rather than
 * track an internal detail of the address class.
 */
enum : uint8_t {
    EP_IPV4 = 1,
    EP_IPV6 = 2,
    EP_TORV2 = 3, //!< named only so that it can be rejected deliberately
    EP_TORV3 = 4,
    EP_I2P = 5,
    EP_CJDNS = 6,
};

//! Address byte counts for the networks above. Declared here rather than taken
//! from netaddress.h for the same reason as the ids: these are consensus-
//! visible wire constants, and a future change to the address classes must not
//! be able to silently alter how existing records parse.
static constexpr size_t ADDR_SIZE_IPV4 = 4;
static constexpr size_t ADDR_SIZE_IPV6 = 16;
static constexpr size_t ADDR_SIZE_TORV3 = 32;
static constexpr size_t ADDR_SIZE_I2P = 32;
static constexpr size_t ADDR_SIZE_CJDNS = 16;

/** Address length for a network id, or 0 if the network is not carried. */
size_t EndpointAddrSize(uint8_t network);

/**
 * The rolling window, in blocks. ~30 days at 180-second spacing.
 *
 * This is the single most consequential constant in the design. It caps how
 * far in the future an expiry may sit, which is what makes the live roster a
 * function of the last MAX_TTL blocks rather than of the whole chain — so a
 * cold roster build stays O(MAX_TTL) forever.
 */
static constexpr uint32_t MAX_TTL = 14400;

/**
 * Whether an absolute expiry height is legal for a record confirmed at
 * `confirm_height`.
 *
 * Both halves are load-bearing. An expiry at or before confirmation is already
 * stale and would let a record be published dead; an expiry beyond the window
 * would escape the bounded scan and quietly make the roster O(chain).
 */
bool ExpiryInRange(uint32_t expiry_height, int confirm_height);

/** A reachable address, encoded as BIP155: net(1) || addr(n) || port(2, BE). */
struct Endpoint {
    uint8_t network{0}; //!< CNetAddr::BIP155Network
    std::vector<unsigned char> addr;
    uint16_t port{0};
};

bool operator==(const Endpoint& a, const Endpoint& b);

/**
 * A 32-byte x-only public key, held as bytes rather than as XOnlyPubKey.
 *
 * XOnlyPubKey has no default constructor in this tree, and a parsed record is
 * a plain data object that must be default-constructible and comparable. Bytes
 * also keep the record module honest: a key that fails to lift to a curve point
 * is a signature-verification failure, not a parse failure, and storing bytes
 * makes that separation impossible to blur.
 */
using KeyBytes = std::array<unsigned char, RECORD_KEY_SIZE>;

/**
 * One parsed record. Which fields are meaningful depends on `type`; the
 * accessors below rather than the raw members are the safe way to ask.
 */
struct Record {
    RecordType type{RecordType::ANNOUNCE};

    //! ANNOUNCE and REVOKE: the signer. DELEGATE: the key being authorised.
    KeyBytes op_key{};

    //! DELEGATE, ROTATE, VETO: the identity key. For ROTATE, the *old* identity.
    KeyBytes id_key{};

    //! ROTATE only: the identity being rotated to.
    KeyBytes new_id_key{};

    //! VETO only: the revealed recovery key, which is also the signer.
    KeyBytes recovery_key{};

    //! ANNOUNCE and DELEGATE: an absolute height, never a TTL. See §1.
    uint32_t expiry_height{0};

    //! ANNOUNCE only.
    uint32_t services{0};
    uint32_t prev_height{0};
    std::vector<Endpoint> endpoints;
    Optional<uint256> meta_hash;

    //! DELEGATE only, present on an identity's first delegation.
    Optional<uint256> recovery_commit;

    std::array<unsigned char, RECORD_SIG_SIZE> sig{};
};

/**
 * Why a parse was rejected.
 *
 * Distinct values rather than a bool: a roster indexer runs this over every
 * OP_RETURN on the chain, and "this was not a record at all" needs to be
 * cheaply distinguishable from "this was a malformed record", which is a
 * finding worth logging.
 */
enum class ParseError {
    OK,
    TOO_SHORT,
    TOO_LONG,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_TYPE,
    BAD_LENGTH,           //!< length disagrees with what the type requires
    BAD_ENDPOINT_COUNT,
    BAD_ENDPOINT_NETWORK, //!< unknown, or a network we refuse to carry
    TRAILING_BYTES,
};

/** Human-readable form, for logs and test failures. */
std::string ParseErrorString(ParseError err);

/**
 * Parse one record from raw OP_RETURN payload bytes.
 *
 * Structural validation only — no signature check, no chain state, no policy.
 * Deliberately strict: anything ambiguous is rejected rather than normalised,
 * because a record that two implementations parse differently is far worse
 * than one that neither accepts.
 *
 * `out` is left unspecified on failure.
 */
ParseError ParseRecord(Span<const unsigned char> raw, Record& out);

/** Serialise a record. Round-trips exactly with ParseRecord(). */
std::vector<unsigned char> SerializeRecord(const Record& rec);

/**
 * Every key this record names.
 *
 * Used to decide what a record contributes to a block filter, so that a client
 * watching one identity is told about the delegations, rotations and vetoes
 * that shaped it — not only about its announcements.
 */
std::vector<KeyBytes> RecordKeys(const Record& rec);

/** The key whose signature authenticates a record of this type. */
const KeyBytes& SigningKeyBytes(const Record& rec);

/** The same key, as an XOnlyPubKey ready to verify with. */
XOnlyPubKey SigningKey(const Record& rec);

/**
 * BIP340 tag for a record type on a given chain, e.g. "BPS/announce/v1/main".
 *
 * The chain id lives in the tag rather than on the wire, so cross-chain and
 * testnet replay are prevented at zero byte cost.
 */
std::string RecordTag(RecordType type, const std::string& chain_id);

/** The bytes a signature commits to: everything preceding the signature. */
Span<const unsigned char> SignedPortion(Span<const unsigned char> raw);

/** The message hash a record's signature is made over. */
uint256 RecordSigHash(Span<const unsigned char> raw, RecordType type, const std::string& chain_id);

/**
 * Verify the detached BIP340 signature.
 *
 * `raw` must be exactly the bytes ParseRecord() accepted; passing a
 * re-serialisation is equivalent, since the encoding is canonical.
 */
bool VerifyRecord(const Record& rec, Span<const unsigned char> raw, const std::string& chain_id);

/** Parse and verify in one step, for callers that want only a yes or no. */
bool ParseAndVerify(Span<const unsigned char> raw, const std::string& chain_id, Record& out);

} // namespace roster

#endif // BITCOIN_ROSTER_RECORD_H
