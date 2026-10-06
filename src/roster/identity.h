// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_IDENTITY_H
#define BITCOIN_ROSTER_IDENTITY_H

#include <optional.h>
#include <roster/record.h>
#include <uint256.h>

#include <map>
#include <set>
#include <vector>

/**
 * Who runs a key, and since when: identities, rotation and age.
 *
 * Design note 001 §5 and §7. Two tiers of key. The operational key is hot,
 * on the node, signs announcements and is what the transport proves. The
 * identity key is cold, signs only DELEGATE and ROTATE, and anchors history.
 * An announcement names only its operational key; which identity runs it is
 * read off the chain, and so is how long it has been running.
 *
 * Everything here is a pure function of records and the heights they
 * confirmed at, so every node draws the same conclusions and the rules can be
 * tested without a chain. None of it is consensus.
 */
namespace roster {

/** Blocks a ROTATE waits before it takes effect, in which a VETO cancels it (about 1.4 days). */
static constexpr int ROTATE_VETO = 672;

/**
 * Confirmations before a record counts towards age, or enters the roster
 * commitment. Deep reorgs are a live concern on proof of stake; a record
 * younger than this is still a fine dial hint.
 */
static constexpr int AGE_DEPTH = 100;

/**
 * Beyond this many blocks' worth of time (about 30 days) a roster is stale:
 * still used to reach peers, but not trusted for anything that matters,
 * because revocations made since are missing from it.
 */
static constexpr int ROSTER_STALE = 14400;

/**
 * How old a relay must be before it is preferred as an entry relay: a month,
 * the shortest listing. Preferred, not required - a policy that shuts out
 * every new relay also shuts out honest operators who lost a key (§7).
 */
static constexpr int GUARD_MIN_AGE = 14400;

/** What a DELEGATE commits to: a tagged hash of the recovery key. */
uint256 RecoveryCommitment(const KeyBytes& recovery_key);

/** A record together with where it confirmed. Chain order is (height, ordinal). */
struct HeldRecord {
    Record rec;
    int height{0};
    uint32_t ordinal{0};
    uint256 txid;
    uint32_t vout{0};

    bool operator<(const HeldRecord& o) const
    {
        return height != o.height ? height < o.height : ordinal < o.ordinal;
    }
};

/**
 * One key's age chain, walked backwards from its latest announcement.
 *
 * Each announcement's prev_height names the height of the record before it
 * in this key's history: an earlier announcement by the same key, or the
 * DELEGATE that put the key under an identity. Linking to a DELEGATE is also
 * how a key accepts it - a DELEGATE is signed by the identity alone, so
 * without the key's own say-so anyone could claim any node as theirs.
 */
struct AgeChain {
    //! Newest first: the latest announcement, then each link behind it.
    std::vector<HeldRecord> links;
    //! The oldest height the chain reaches, or -1 when the key has never announced.
    int anchor{-1};
    //! The delegation the key accepted, if its chain reaches one.
    Optional<HeldRecord> delegation;
};

/**
 * Walk `key`'s chain from its latest announcement at or below `tip`.
 * `history` is every record naming the key, in any order.
 */
AgeChain WalkAgeChain(const KeyBytes& key, const std::vector<HeldRecord>& history, int tip);

/** One identity as the chain has it at some height. */
struct IdentityState {
    KeyBytes key{};
    //! Earliest record of this identity or of one it rotated from: what its age counts from.
    int first_height{-1};
    Optional<uint256> recovery_commit;
    //! Whether it has signed a DELEGATE yet; only the first may set the recovery commitment.
    bool had_delegate{false};
    //! Rotated away from. Its records no longer count, nor do its delegations.
    bool retired{false};
    KeyBytes successor{};
    std::vector<KeyBytes> predecessors;
    //! A rotation waiting out its veto window.
    bool rotating{false};
    KeyBytes rotating_to{};
    int rotate_height{0};
    //! Rotations cancelled by a VETO, by the height of the ROTATE.
    std::vector<int> vetoed;
    //! Operational keys it delegated to, by key, with the delegation's height and expiry.
    std::map<KeyBytes, std::pair<int, uint32_t>> delegations;
};

/**
 * The identity rules of §7, applied to records in chain order.
 *
 *   - DELEGATE: an identity authorises an operational key until an expiry.
 *     Its first DELEGATE may carry the commitment to a recovery key, and only
 *     the first: an attacker holding the identity key must not be able to
 *     add one later.
 *   - ROTATE: moves an identity to a new key, effective ROTATE_VETO blocks
 *     later. One at a time; the first to confirm holds the slot. The new key
 *     must not already have had a history of its own, or rotating would be a
 *     way to graft an old identity's age onto an unrelated one.
 *   - VETO: the recovery key, revealed, cancels a rotation still waiting.
 *   - When a rotation takes effect the old key is retired: its later records
 *     and its delegations stop counting, and the new key carries its age and,
 *     unless it committed to one of its own, its recovery commitment.
 */
class IdentityBook
{
public:
    /** Apply every record, in chain order, up to and including `tip`. */
    void Build(std::vector<HeldRecord> records, int tip);

    /** The state of `key` as an identity, or null if it has none. */
    const IdentityState* Find(const KeyBytes& key) const;

    /** Follow rotations from `key` to the identity's current key. */
    KeyBytes Current(const KeyBytes& key) const;

    /**
     * Whether `id` delegates to `op` at `tip`, through a delegation that
     * still counts: unexpired, and made before `id` was retired.
     */
    bool Delegates(const KeyBytes& id, const KeyBytes& op, int tip) const;

private:
    void Settle(int height);
    void Apply(const HeldRecord& held);
    IdentityState& Touch(const KeyBytes& key, int height);

    std::map<KeyBytes, IdentityState> m_ids;
};

} // namespace roster

#endif // BITCOIN_ROSTER_IDENTITY_H
