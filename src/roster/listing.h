// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_LISTING_H
#define BITCOIN_ROSTER_LISTING_H

#include <key.h>
#include <netaddress.h>
#include <pubkey.h>
#include <roster/record.h>
#include <uint256.h>

#include <chrono>
#include <functional>
#include <stdint.h>
#include <string>
#include <vector>

namespace overlay {
struct Hop;
} // namespace overlay

/**
 * A peer with no coins asking a relay to put its listing on the chain.
 *
 * Design note 001 settles who does what: the user signs its own record, month
 * by month, and the relay it uses pays the fee (§2, §8). What it left open is
 * how the signed record reaches the relay. This is that: the record travels
 * over the overlay session the user already has with its entry relay, as
 * application data, so nothing new is opened and the relay learns nothing it
 * did not already know from the handshake.
 *
 * The session is what makes the request meaningful. The overlay authenticates
 * each side's static key, which is the same operational key the roster
 * publishes, so a relay can insist that the record it pays for names the key
 * of the peer actually connected to it. That is the "relay watches its own
 * connections" half of the settled model: the relay pays for the peers it
 * serves, and it is the only party that can see who those are.
 *
 * Paying is opt-in on the relay's side and off by default. Spending a wallet's
 * coins because a stranger asked is something an operator should choose, not
 * discover.
 *
 * One listing is asked for over a path instead: a relay's gateway key
 * (design note §8·7). The relay's own key carries its address, so asking from
 * where it is - or paying from its own wallet, whose coins the chain ties to
 * the relay's own listing - would say where that gateway is. Over a path that
 * proves the gateway key and nothing else, the relay that pays learns the key
 * and not the address. Relays pay that way only for a gateway's listing: the
 * bit, and no address.
 *
 * A relay also has to be staking, and that is what makes this work before the
 * rest of the network upgrades (settled 2026-09-07). A record is larger than
 * the 83 bytes a 0.21 node will relay, so until most nodes run this version a
 * listing reaches a block only through a staker that does. The relay is that
 * staker: the listing it pays for sits in its own mempool and goes into the
 * next block it stakes, with no relay path needed at all. For the same reason
 * the record must stay valid until then, so a relay that stakes rarely asks
 * for a record that waits longer (ListingOutcome::needed_window).
 */
namespace roster {

/** First byte of every overlay application payload. */
enum class AppMessage : uint8_t {
    LISTING_REQUEST = 0x01, //!< a peer asking this relay to pay for its listing
    LISTING_RESULT = 0x02,  //!< the relay's answer
};

/** Whether this node pays for listings peers ask it to publish. */
static const bool DEFAULT_ACCEPT_LISTINGS = false;
/** Most peers this node keeps listed and shares its rewards with. */
static const unsigned int DEFAULT_MAX_LISTED_USERS = 100;
/** A refusal is shown to a person, so it is short and bounded. */
static constexpr size_t MAX_REFUSAL_LENGTH = 200;
/**
 * A listing can be renewed in its last three days and not before: 3 days of
 * 180-second blocks. Earlier, a renewal buys nothing but a fee and cuts short
 * a month already paid for. Renewing stays something the peer does by hand,
 * so a peer that has left stops costing its relay simply by not renewing.
 */
static constexpr uint32_t RENEW_WINDOW = 3 * 24 * 60 * 60 / 180;
/**
 * Blocks a freshly signed record leaves for confirming before it no longer
 * counts: it stays valid for any block up to expiry - MIN_TTL. The default a
 * signer uses; a relay that needs longer says so.
 */
static constexpr uint32_t DEFAULT_CONFIRM_WINDOW = 144;
/**
 * How many of its own average intervals between staked blocks a relay wants a
 * record to wait for. Staking is a Poisson process, so three intervals is a
 * 95% chance (1 - e^-3) of staking a block in time.
 */
static constexpr uint32_t CONFIRM_SAFETY = 3;

/** What a relay did with a request, or what a requester heard back. */
struct ListingOutcome {
    bool ok{false};
    uint256 txid;       //!< the transaction carrying the record, when ok
    std::string reason; //!< why not, when refused
    //! Set instead of a plain refusal when the record would expire before this
    //! relay can expect to stake a block: sign again leaving this many blocks.
    uint32_t needed_window{0};
};

bool EncodeListingRequest(uint64_t id, const std::vector<unsigned char>& record,
                          std::vector<unsigned char>& out);
bool DecodeListingRequest(const std::vector<unsigned char>& msg, uint64_t& id_out,
                          std::vector<unsigned char>& record_out);
bool EncodeListingResult(uint64_t id, const ListingOutcome& outcome,
                         std::vector<unsigned char>& out);
bool DecodeListingResult(const std::vector<unsigned char>& msg, uint64_t& id_out,
                         ListingOutcome& outcome_out);

/** Everything a relay knows when deciding, gathered so the decision can be tested alone. */
struct ListingContext {
    KeyBytes requester{};        //!< key the overlay session authenticated
    bool over_path{false};       //!< asked through a path, so from no address
    int next_height{0};          //!< earliest height the record could confirm at
    std::string chain_id;
    uint32_t live_expiry{0};     //!< expiry of the requester's live listing, 0 if none
    int pending_height{0};       //!< height this relay last paid for it, 0 if never
    size_t listed_users{0};      //!< peers this relay already keeps listed
    size_t max_users{DEFAULT_MAX_LISTED_USERS};
    bool already_user{false};    //!< the requester is one of them
    uint32_t needed_window{DEFAULT_CONFIRM_WINDOW}; //!< blocks this relay needs to stake one
};

/**
 * The confirm window a relay needs, from its stake weight and the network's.
 * Zero when it stakes too rarely to meet even the longest record allowed.
 */
uint32_t NeededConfirmWindow(uint64_t own_weight, uint64_t network_weight);

/**
 * Decide whether to pay for a peer's record, before any coin is touched.
 *
 * Refuses a record that would not be indexed, one naming a key other than the
 * requester's, anything but a gateway's listing when asked over a path, a renewal asked for before the current listing's last three days, a second payment while the first is still confirming, and a new peer
 * once the relay is full. Each of those would cost the relay a fee and gain
 * nobody anything.
 *
 * A record that would stop counting before this relay can expect to stake it
 * is not refused outright: `needed_window_out` says how long a window to sign
 * with, and the requester signs again.
 */
bool CheckListingRequest(const std::vector<unsigned char>& raw, const ListingContext& ctx,
                         Record& rec_out, std::string& reason, uint32_t& needed_window_out);

/**
 * How this node pays, and how much it stakes. The wallet installs both when it
 * loads, so a node built or run without a wallet refuses rather than failing
 * somewhere deeper. `stake_weight` counts only wallets that are staking now,
 * because a listing paid for by a relay that is not staking may never reach a
 * block.
 */
using ListingPublisher = std::function<ListingOutcome(const std::vector<unsigned char>& record)>;
using StakeWeightSource = std::function<uint64_t()>;
void SetListingPublisher(ListingPublisher publisher, StakeWeightSource stake_weight);

/**
 * The overlay's consumer of application data. Installed at startup; answers
 * listing requests as a relay and collects answers as a requester.
 */
void HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload);

/** Expiry of a key's live listing at `tip`, or 0 when it has none. Needs the roster index. */
uint32_t LiveExpiry(const KeyBytes& key, int tip);

/**
 * Where a relay's overlay listens, given the endpoint its record publishes.
 *
 * A record carries the peer-to-peer port only. The overlay listens one above
 * it by default, so that is where a relay is looked for; a relay that moves
 * its overlay elsewhere has to be named explicitly.
 */
CService OverlayAddressFor(const CService& endpoint);

/**
 * Ask a relay to publish `record`, and wait for its answer.
 *
 * Opens an overlay session with the relay if there is none, checking that the
 * key answering at that address is the one asked for. `answered` is false
 * when the relay could not be reached or said nothing in time, so a caller can
 * tell silence from a refusal.
 */
ListingOutcome RequestListing(const CService& relay_addr, const CPubKey& relay_key,
                              const std::vector<unsigned char>& record,
                              std::chrono::seconds connect_timeout,
                              std::chrono::seconds answer_timeout, bool& answered);

/**
 * Ask the listed relay `relay` to publish a gateway's `record`, through a path
 * of `hops` relays whose session proves `as` - the key the record names - and
 * nothing about where this node is. For a relay's gateway key, which must not
 * be asked for from the relay's own address.
 */
ListingOutcome RequestListingOverPath(const KeyBytes& relay, const CKey& as,
                                      const std::vector<unsigned char>& record, int hops,
                                      std::chrono::seconds answer_timeout, bool& answered);

} // namespace roster

#endif // BITCOIN_ROSTER_LISTING_H
