// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIL_LETTER_H
#define BITCOIN_MAIL_LETTER_H

#include <key.h>
#include <pubkey.h>
#include <roster/record.h>
#include <uint256.h>

#include <array>
#include <functional>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * Mail between roster keys: what a letter is, and how it is sealed.
 *
 * Design note 001 §11·5 takes the three properties Session announced for its
 * Protocol V2 and gives each a standard construction:
 *
 *   FORWARD SECRECY. A recipient publishes a mail key that rotates every week
 *   and deletes the private half once nothing sealed to it can still be
 *   waiting in a mailbox (PreKey below, and the client's key store). A device
 *   taken later holds no key that opens mail it fetched before.
 *
 *   POST-QUANTUM. Each letter's key comes from two exchanges at once:
 *   secp256k1 Diffie-Hellman, the curve every key here already uses, and
 *   ML-KEM-768 (FIPS 203). Both feed one HKDF, so the letter stays sealed
 *   unless both are broken - recorded today, opened by a quantum computer
 *   later, is exactly the attack this exists for.
 *
 *   SEALED SENDER. The sender's key and its signature travel inside the
 *   encryption. A mailbox holding a letter learns who it is for, its size
 *   rounded up, and nothing about who wrote it.
 *
 * The signature covers the recipient and the exact encryption it arrived
 * under, so a recipient cannot re-seal a signed letter to a third party and
 * have it look as though the sender wrote to them.
 *
 * Several devices per account, Session's third V2 change, is not here yet:
 * one node is one mailbox owner.
 */
namespace mail {

static constexpr uint8_t MAIL_VERSION = 1;

/** Longest subject, in bytes of UTF-8. */
static constexpr size_t MAX_SUBJECT = 200;
/** Longest body. Text, not attachments: a letter is held on somebody else's disk. */
static constexpr size_t MAX_BODY = 32 * 1024;
/** Sealed letters are padded to a multiple of this, so their size says little. */
static constexpr size_t PAD_TO = 512;

/** How long a mail key is the one senders are given: a week. */
static constexpr int64_t PREKEY_LIFETIME = 7 * 24 * 60 * 60;
/**
 * How long past its week a mail key is still accepted by senders, for an owner
 * who was offline when the next one was due.
 */
static constexpr int64_t PREKEY_GRACE = 2 * 24 * 60 * 60;

/** The public half of a mail key, signed by the roster key it belongs to. */
struct PreKey {
    roster::KeyBytes owner{};
    uint64_t key_id{0};
    int64_t created{0};
    int64_t expires{0};
    CPubKey ec_key;
    std::vector<unsigned char> kem_key;
    std::array<unsigned char, 64> sig{};
};

/** version(1) owner(32) key_id(8) created(8) expires(8) ec_key(33) kem_key(1184) sig(64) */
static constexpr size_t PREKEY_SIZE = 1 + 32 + 8 + 8 + 8 + 33 + 1184 + 64;

/** The private half, which never leaves the device that made it. */
struct PreKeySecret {
    uint64_t key_id{0};
    int64_t created{0};
    int64_t expires{0};
    CKey ec_secret;
    std::vector<unsigned char> kem_secret;
    std::vector<unsigned char> kem_public;
};

std::vector<unsigned char> SerializePreKey(const PreKey& key);
bool ParsePreKey(const std::vector<unsigned char>& raw, PreKey& out);

/**
 * Make a mail key for `owner`, valid from `now` for PREKEY_LIFETIME plus grace.
 * Randomness comes from GetStrongRandBytes.
 */
bool MakePreKey(const CKey& owner, const std::string& chain_id, uint64_t key_id, int64_t now,
                PreKey& public_out, PreKeySecret& secret_out);

/** The public half again, from a stored secret: what is republished. */
bool PublicPreKey(const CKey& owner, const std::string& chain_id, const PreKeySecret& secret,
                  PreKey& out);

/** Signed by the key it names, for this chain. Expiry is the caller's to check. */
bool VerifyPreKey(const PreKey& key, const std::string& chain_id);

/** A letter, as written and as read. */
struct Letter {
    roster::KeyBytes from{};
    roster::KeyBytes to{};
    int64_t sent{0};
    std::string subject;
    std::string body;
};

/** version(1) recipient(32) key_id(8) ephemeral(33) kem_ciphertext(1088) */
static constexpr size_t ENVELOPE_HEADER_SIZE = 1 + 32 + 8 + 33 + 1088;
/** The largest sealed letter: header, the longest letter padded, and the tag. */
static constexpr size_t MAX_ENVELOPE_SIZE =
    ENVELOPE_HEADER_SIZE +
    ((1 + 32 + 8 + 1 + MAX_SUBJECT + 4 + MAX_BODY + 64 + PAD_TO - 1) / PAD_TO) * PAD_TO + 16;

/** Who a sealed letter is for, and under which of their keys - all a mailbox can read. */
bool ReadEnvelope(const std::vector<unsigned char>& envelope, roster::KeyBytes& recipient_out,
                  uint64_t& key_id_out);

/** A sealed letter's name: the hash of its bytes, so every copy has the same one. */
uint256 EnvelopeId(const std::vector<unsigned char>& envelope);

/**
 * Seal a letter to a recipient's mail key.
 *
 * `letter.to` must be the key's owner; `letter.from` and `letter.sent` are
 * filled in from `sender` and the clock. False with `error` set when the
 * letter is too long or the key is not usable.
 */
bool Seal(const CKey& sender, const PreKey& to, Letter& letter, const std::string& chain_id,
          std::vector<unsigned char>& envelope_out, std::string& error);

/** Finds the private half of one of this node's mail keys, or null. */
using SecretLookup = std::function<const PreKeySecret*(uint64_t key_id)>;

enum class OpenResult {
    OK,
    MALFORMED,  //!< not a sealed letter at all
    NOT_FOR_US, //!< addressed to someone else
    KEY_GONE,   //!< sealed to a mail key this node no longer has
    DAMAGED,    //!< did not decrypt: altered, or not sealed to that key
    FORGED,     //!< decrypted, but the sender's signature does not hold
};

std::string OpenResultString(OpenResult r);

/** Open a sealed letter addressed to `self`. */
OpenResult Open(const std::vector<unsigned char>& envelope, const roster::KeyBytes& self,
                const SecretLookup& secrets, const std::string& chain_id, Letter& out);

/** The x-only roster key a full key is published as. */
roster::KeyBytes XOnly(const CPubKey& key);

} // namespace mail

#endif // BITCOIN_MAIL_LETTER_H
