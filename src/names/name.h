// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_NAME_H
#define BITCOIN_NAMES_NAME_H

#include <amount.h>

#include <stddef.h>
#include <stdint.h>
#include <string>

/**
 * Names: what a name may be.
 *
 * Design note 001 section 11. A name resolves to a roster key - never to an
 * address - so one name serves every payment and every letter without linking
 * any of them.
 *
 * Names cost nothing but the network fee of the transactions that register and
 * renew them: nothing is burned (the owner's decision, 2026-10-07). A name
 * someone holds costs what its holder asks for it, if they put it up for sale.
 * The brakes on squatting are commit-reveal, renewal by hand and the
 * look-alike rule, not a price.
 *
 * Everything here is a pure function, and every node must compute the same
 * answers: two nodes that disagree about whether a name is valid, or what it
 * costs, resolve it to different keys.
 */
namespace names {

/** Shortest root name: one letter or digit. */
static constexpr size_t MIN_ROOT_LENGTH = 1;
/** Longest root name or subname label. */
static constexpr size_t MAX_LABEL_LENGTH = 32;

/** A year at 180-second blocks, the unit terms are chosen in. */
static constexpr uint32_t BLOCKS_PER_YEAR = 175320;
/** Shortest registration: a month. */
static constexpr uint32_t MIN_TERM = 14400;
/** Longest a name can be paid ahead: two years from the block that pays. */
static constexpr uint32_t MAX_TERM = 2 * BLOCKS_PER_YEAR;
/**
 * A month after expiry in which only the holder may renew. The name does not
 * resolve meanwhile, so nothing is sent to a holder who has stopped paying,
 * but a holder who forgot does not lose it to whoever was watching.
 */
static constexpr uint32_t GRACE = 14400;

/**
 * Registration is commit, then reveal. A claim seen in a mempool could
 * otherwise be copied and staked into a block ahead of it; a commitment hides
 * the name, and the claim must point at a commitment at least this many
 * blocks old - deeper than a front-runner could reorganise.
 */
static constexpr uint32_t COMMIT_MIN_AGE = 6;
/** And at most this old (about nine days), so commitments do not pile up. */
static constexpr uint32_t COMMIT_MAX_AGE = 4320;

/**
 * Blocks since a name last pointed somewhere new - a new holder, or a subname
 * a new key - before resolution is called settled: 500, about a day. A wrong
 * payment is lost for good, so anything that spends on a name's say-so waits
 * for this, and so long that a key stolen and used to move a name is likely
 * to be revoked first; a letter need not wait. Deeper than AGE_DEPTH on
 * purpose (design note 001, section 11). A renewal by the same holder does
 * not restart it: the money would go where it went before.
 */
static constexpr uint32_t SETTLE_DEPTH = 500;

/**
 * Lowercase ASCII, or nothing. Upper case is folded; anything outside ASCII is
 * refused outright, which removes look-alike letters from other scripts (a
 * Turkish dotless i in place of the i of pilot, say) by construction rather
 * than by a table that has to be complete.
 */
bool Normalize(const std::string& in, std::string& out);

/** a-z, 0-9 and single inner hyphens, 1 to MAX_LABEL_LENGTH long. */
bool IsValidLabel(const std::string& label);

/** A label at least MIN_ROOT_LENGTH long. */
bool IsValidRoot(const std::string& root);

/**
 * "alice.pilot" into root "pilot" and label "alice"; "pilot" into root
 * "pilot" and an empty label. One level of subname only. False when either
 * part is invalid.
 */
bool SplitName(const std::string& full, std::string& root, std::string& label);

/**
 * What a name looks like, for spotting look-alikes within ASCII: 0 and o, 1 and
 * l, rn and m, vv and w. A new name whose skeleton matches a live name held by
 * someone else is refused. Deliberately short: every pair added here also
 * refuses honest names that merely resemble each other.
 */
std::string Skeleton(const std::string& label);

/**
 * First height at which names count on this network. Records before it are
 * ignored, and an index does not read the blocks before it.
 */
int StartHeight(const std::string& chain_id);

} // namespace names

#endif // BITCOIN_NAMES_NAME_H
