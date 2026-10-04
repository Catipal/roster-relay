// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ROSTER_LISTING_H
#define BITCOIN_ROSTER_LISTING_H

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

/** What a relay did with a request, or what a requester heard back. */
struct ListingOutcome {
    bool ok{false};
    uint256 txid;       //!< the transaction carrying the record, when ok
    std::string reason; //!< why not, when refused
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
    int next_height{0};          //!< earliest height the record could confirm at
    std::string chain_id;
    uint32_t live_expiry{0};     //!< expiry of the requester's live listing, 0 if none
    int pending_height{0};       //!< height this relay last paid for it, 0 if never
    size_t listed_users{0};      //!< peers this relay already keeps listed
    size_t max_users{DEFAULT_MAX_LISTED_USERS};
    bool already_user{false};    //!< the requester is one of them
};

/**
 * Decide whether to pay for a peer's record, before any coin is touched.
 *
 * Refuses a record that would not be indexed, one naming a key other than the
 * requester's, a renewal asked for while more than half the current listing is
 * left, a second payment while the first is still confirming, and a new peer
 * once the relay is full. Each of those would cost the relay a fee and gain
 * nobody anything.
 */
bool CheckListingRequest(const std::vector<unsigned char>& raw, const ListingContext& ctx,
                         Record& rec_out, std::string& reason);

/**
 * Pays to publish a record. The wallet installs one when it loads, so a node
 * built or run without a wallet refuses rather than failing somewhere deeper.
 */
using ListingPublisher = std::function<ListingOutcome(const std::vector<unsigned char>& record)>;
void SetListingPublisher(ListingPublisher publisher);

/**
 * The overlay's consumer of application data. Installed at startup; answers
 * listing requests as a relay and collects answers as a requester.
 */
void HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload);

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

} // namespace roster

#endif // BITCOIN_ROSTER_LISTING_H
