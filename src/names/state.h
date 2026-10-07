// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NAMES_STATE_H
#define BITCOIN_NAMES_STATE_H

#include <amount.h>
#include <names/record.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <roster/record.h>
#include <uint256.h>

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

/**
 * Who holds which name: the rules, applied to the chain in order.
 *
 * Not consensus. A block carrying an invalid name record is a valid block; the
 * record simply does not count. But every node applies the same rules to the
 * same records in the same order, so every node arrives at the same holders,
 * which is what a name needs. Rules are written once, here, and are pure
 * functions of the records and their heights.
 *
 *   - A name is registered by a CLAIM that reveals a COMMIT made at least
 *     COMMIT_MIN_AGE blocks earlier, and runs MIN_TERM to MAX_TERM. Nothing is
 *     burned: a name costs the network fee. First valid claim wins; nobody
 *     adjudicates.
 *   - The holder renews with a CLAIM (no commit needed), for the fee, up to a
 *     month after expiry. After that the name is free again.
 *   - A name that looks like a live name held by someone else (Skeleton) is
 *     refused.
 *   - The holder may transfer it, and may issue subnames under it for free.
 *   - The holder may put it up for sale (SELL). While the sale coin is
 *     unspent the name cannot be transferred or put up again, so a buyer
 *     cannot be outrun by its own seller. A BUY counts only in the very
 *     transaction that spends the sale coin, which pays the seller; it may
 *     also renew the name for the buyer, as a CLAIM would.
 *     The buyer gets the name clean: subnames go with the old holder.
 */
namespace names {

/**
 * One name record as the index found it on the chain, or - when `spend` is
 * set - a transaction spending a coin some SELL record named. Spends come
 * before the records of the same transaction, as inputs come before outputs.
 */
struct IndexedRecord {
    std::vector<unsigned char> raw;
    CAmount burned{0};
    int height{0};
    uint256 txid;
    uint32_t vout{0};
    bool spend{false};
    COutPoint spent;
    //! SELL only: whether its transaction spent an output of the transaction
    //! that made the sale coin, which puts the coin on the chain first.
    bool coin_funded{false};
};

/** The spending key a roster key takes payments by name on (names/payment.h). */
struct PayKey {
    CPubKey spend;
    int height{0};
};

/** A name up for sale. */
struct Offer {
    COutPoint coin;
    CAmount payout_value{0};
    CScript payout;
    std::vector<unsigned char> coin_sig;
    roster::KeyBytes seller{};
    int height{0};
};

struct Subname {
    roster::KeyBytes key{};
    uint32_t expiry{0};
    int height{0};
};

struct NameEntry {
    roster::KeyBytes owner{};
    uint32_t expiry{0};
    int registered{0};  //!< height of the claim that registered it to this holder
    int changed{0};     //!< last height its holder or term changed
    std::map<std::string, Subname> subnames;
    //! Set from a SELL until its sale coin is spent.
    bool for_sale{false};
    Offer offer;
};

enum class Status {
    FREE,
    LIVE,
    GRACE, //!< expired, renewable by its holder only, and does not resolve
};
std::string StatusString(Status status);

struct Resolution {
    std::string name;
    roster::KeyBytes key{};   //!< what the name resolves to
    roster::KeyBytes owner{}; //!< who holds the root name
    uint32_t expiry{0};
    int registered{0};
    int changed{0};
    bool subname{false};
};

class NameState
{
public:
    explicit NameState(const std::string& chain_id);

    /** Apply one block's records, in the order they appear in it. */
    void ApplyBlock(int height, const std::vector<IndexedRecord>& records);

    /** Apply one record. Empty when it took effect; otherwise why it did not. */
    std::string Apply(const IndexedRecord& rec);

    Status StatusOf(const std::string& root, int height) const;
    const NameEntry* Find(const std::string& root) const;

    /** What a name, or label.name, resolves to at `height`. */
    bool Resolve(const std::string& full, int height, Resolution& out, std::string& why) const;

    /**
     * Whether `owner` could register `name` fresh at `height`, before it
     * commits anything. Empty when it could.
     */
    std::string CheckAvailable(const std::string& name, const roster::KeyBytes& owner, int height) const;

    /**
     * Whether a CLAIM with these terms would take effect at `height`. A wallet
     * asks this before paying the fee for one that would not count.
     */
    std::string CheckClaim(const std::string& name, const roster::KeyBytes& owner, const Salt& salt,
                           uint32_t expiry, int height) const;

    /**
     * Whether `owner` could put `name` up for sale at `height`. Empty when it
     * could.
     */
    std::string CheckSell(const std::string& name, const roster::KeyBytes& owner, int height) const;

    /**
     * Whether a BUY with these terms would count at `height`, in a transaction
     * that spends the name's sale coin. Empty when it would.
     */
    std::string CheckBuy(const std::string& name, const roster::KeyBytes& buyer, uint32_t expiry, int height) const;

    /** The term a buyer gets: `years` from when the name ends now, up to two years ahead. */
    uint32_t BuyExpiry(const std::string& name, int years, int height) const;

    /** The spending key `key` takes payments on, or null when it takes none. */
    const PayKey* PaymentKey(const roster::KeyBytes& key) const;

    /** The sale `name` is under at `height`, or null. */
    const Offer* ActiveOffer(const std::string& name, int height) const;

    /** Height a commitment was first seen at, or -1. */
    int CommitHeight(const uint256& commitment) const;

    /** Every name `owner` holds or held, with its entry. */
    std::vector<std::pair<std::string, NameEntry>> OwnedBy(const roster::KeyBytes& owner) const;
    /** Every name ever registered, in alphabetical order, whatever its status. */
    std::vector<std::pair<std::string, NameEntry>> Everything() const;

    size_t CountLive(int height) const;
    int StartHeight() const { return m_start; }

private:
    std::string CheckFresh(const std::string& name, const roster::KeyBytes& owner, int height) const;
    void Prune(int height);

    std::string m_chain_id;
    int m_start;
    std::map<std::string, NameEntry> m_names;
    std::map<std::string, std::set<std::string>> m_skeletons;
    std::map<uint256, int> m_commits;
    std::set<uint256> m_used;
    //! Roster key -> the spending key it published last.
    std::map<roster::KeyBytes, PayKey> m_paykeys;
    //! Sale coin -> the name it is selling.
    std::map<COutPoint, std::string> m_sale_coins;
    //! Names whose sale coin a transaction of the block being applied spent,
    //! with who was selling. A BUY counts only in that same transaction.
    std::map<uint256, std::map<std::string, roster::KeyBytes>> m_sold_in;
};

} // namespace names

#endif // BITCOIN_NAMES_STATE_H
