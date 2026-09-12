// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_PAYOUT_H
#define BITCOIN_ROSTER_PAYOUT_H

#include <amount.h>
#include <roster/record.h>
#include <script/script.h>

#include <string>
#include <vector>

/**
 * Sharing a block reward with the peers this node lists.
 *
 * Design note 001 section 8, made to happen. A relay's income is its share of
 * block rewards and it splits that among the peers listed through it, so
 * attracting a share of the network's users costs a share of the stake. That is
 * the whole anti-sybil argument, and until now nothing in the tree did it.
 *
 * The payment rides inside the relay's own coinstake, which is what makes it
 * free. Every cold-staking rule keys off HasP2CSOutputs(), so a relay staking
 * its own coins produces a plain coinstake where none of them engage: no
 * COLD_STAKER_FEE cap, no limit of one differing output, no extra transaction
 * and no chain bytes beyond the outputs themselves. A cold stake cannot do this
 * and must not try - consensus allows exactly one output differing from the
 * delegation, so a second payout would make the block invalid.
 *
 * WHAT THIS IS NOT. Nothing enforces the share. A relay that pays nothing
 * produces a perfectly valid block, and no promise it made is recorded
 * anywhere. That is the model working as designed rather than a gap in it: the
 * relay pays because a relay with no users protects nobody, itself included,
 * and a peer that stops being paid leaves. Describing the percentage as a
 * guarantee would be wrong.
 */
namespace roster {

/** Share of the block reward handed to listed peers. Off unless asked for. */
static const int DEFAULT_RELAY_SHARE = 0;

/** One peer's share of one block. */
struct Payout {
    KeyBytes key;
    CScript script;
    CAmount amount{0};
};

/**
 * Work out what each listed peer is owed from one block's reward.
 *
 * Pure, so it can be argued with exhaustively and without a chain. Returns the
 * total to be deducted from the staker's own output, and fills `out`.
 *
 * @param reward      the block's reward, before anything is taken out
 * @param share       percent to share, clamped to 0..100
 * @param users       peers to pay, in any order
 * @param min_payout  below this an output is dust and worth less than it costs
 *                    to spend, so nobody is paid at all rather than paid in
 *                    tokens that cannot be moved
 *
 * The remainder of an uneven division stays with the staker. Paying it to
 * whichever peer sorts first would make the split depend on key ordering for no
 * reason anyone could defend.
 *
 * Peers whose published bytes do not lift to a point on the curve are skipped:
 * a record carrying them could never have verified, so their presence means the
 * list has been edited by hand.
 */
CAmount PlanPayouts(CAmount reward, int share, const std::vector<KeyBytes>& users,
                    CAmount min_payout, std::vector<Payout>& out);

/**
 * The peers this node lists and pays for, kept in <datadir>/roster_users.
 *
 * Deliberately local. Section 8 has the user hand a signed record to a relay,
 * which pays the fee - so the relay knows its own roll because the peers came
 * to it, and nothing about the relationship needs to be published. Putting it
 * on chain would hand an adversary the map of who a relay carries, which is the
 * graph edge that section spends three paragraphs rejecting.
 */
bool LoadUsers(std::vector<KeyBytes>& out, std::string& error);
bool SaveUsers(const std::vector<KeyBytes>& users, std::string& error);

/** Where that list lives, for logging and error messages. */
std::string UsersPath();

} // namespace roster

#endif // BITCOIN_ROSTER_PAYOUT_H
