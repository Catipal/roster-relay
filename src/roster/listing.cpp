// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/listing.h>

#include <chainparams.h>
#include <crypto/common.h>
#include <index/rosterindex.h>
#include <logging.h>
#include <overlay/meeting.h>
#include <overlay/radio.h>
#include <overlay/relay.h>
#include <random.h>
#include <roster/keystore.h>
#include <roster/payout.h>
#include <rpc/server.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <map>

namespace roster {

namespace {

constexpr size_t ID_SIZE = 8;
constexpr uint8_t RESULT_OK = 0;
constexpr uint8_t RESULT_REFUSED = 1;
constexpr uint8_t RESULT_NEEDS_WINDOW = 2;

ListingOutcome Refused(const std::string& reason)
{
    ListingOutcome out;
    out.reason = reason.substr(0, MAX_REFUSAL_LENGTH);
    return out;
}

bool SameKey(const CPubKey& pubkey, const KeyBytes& key)
{
    return pubkey.IsValid() && pubkey.size() == CPubKey::COMPRESSED_SIZE &&
           std::memcmp(pubkey.data() + 1, key.data(), key.size()) == 0;
}

// --- relay side -------------------------------------------------------------

Mutex g_relay_mutex;
ListingPublisher g_publisher GUARDED_BY(g_relay_mutex);
StakeWeightSource g_stake_weight GUARDED_BY(g_relay_mutex);
//! Height this node last paid for each peer's listing. Kept so a second
//! request while the first payment is still unconfirmed does not pay twice;
//! the chain answers the question once it confirms.
std::map<KeyBytes, int> g_paid_at GUARDED_BY(g_relay_mutex);
//! For each address a listing was asked for from directly (AddressLimitKey),
//! the last key paid for from it and the height. Kept for a month, the
//! length of a listing a relay pays for; like g_paid_at, not across restarts.
std::map<std::vector<unsigned char>, std::pair<KeyBytes, int>> g_paid_from GUARDED_BY(g_relay_mutex);

//! Answers given, by who asked and the request's id, so a request repeated
//! because its answer was lost gets that answer again instead of being
//! decided twice - the second time it would be refused as a double payment.
//! Bounded, because asking is something strangers do.
struct GivenAnswer {
    int64_t at{0};
    ListingOutcome outcome;
};
std::map<std::pair<KeyBytes, uint64_t>, GivenAnswer> g_given GUARDED_BY(g_relay_mutex);
constexpr int64_t GIVEN_TTL = 15 * 60;
constexpr size_t MAX_GIVEN = 256;

} // namespace

std::vector<unsigned char> AddressLimitKey(const CNetAddr& addr)
{
    std::vector<unsigned char> out;
    if (addr.IsIPv4()) {
        out = addr.GetAddrBytes();
        out.insert(out.begin(), 4);
    } else if (addr.IsIPv6()) {
        out = addr.GetAddrBytes();
        out.resize(8); // the /64
        out.insert(out.begin(), 6);
    }
    return out;
}

uint32_t LiveExpiry(const KeyBytes& key, int tip)
{
    if (!g_rosterindex) return 0;
    std::vector<RosterEntry> entries;
    if (!g_rosterindex->ReadRecordsForKey(key, entries)) return 0;
    uint32_t best = 0;
    for (const RosterEntry& entry : entries) {
        Record rec;
        if (entry.height > tip || !entry.Parse(rec)) continue;
        if (rec.type != RecordType::ANNOUNCE) continue;
        best = std::max(best, rec.expiry_height);
    }
    return best > (uint32_t)tip ? best : 0;
}

namespace {

void Answer(const overlay::Hop& to, uint64_t id, const ListingOutcome& outcome)
{
    std::vector<unsigned char> msg;
    if (!overlay::g_overlay || !EncodeListingResult(id, outcome, msg)) return;
    if (to.via_path) {
        overlay::g_overlay->SendSecret(to.path, msg);
    } else {
        overlay::g_overlay->SendApp(to.addr, msg);
    }
}

/**
 * The key the asker proved: for a path in the end-to-end handshake, where a
 * requester proves its key on purpose and every other path a throwaway one;
 * directly, in the hop's handshake, which only a relay still makes with its
 * own key - every other node shows a key made for the connection.
 */
CPubKey RequesterIdentity(const overlay::Hop& from)
{
    return from.via_path ? overlay::g_overlay->SecretPeerIdentity(from.path)
                         : overlay::g_overlay->PeerIdentity(from.addr);
}

ListingOutcome Decide(const overlay::Hop& from, const std::vector<unsigned char>& raw)
{
    if (!gArgs.GetBoolArg("-acceptlistings", DEFAULT_ACCEPT_LISTINGS)) {
        return Refused("This relay does not pay for listings.");
    }

    // The overlay authenticated this key in the handshake. It is the only
    // identity in the exchange that cannot be claimed by just saying so.
    const CPubKey identity = RequesterIdentity(from);
    if (!identity.IsValid() || identity.size() != CPubKey::COMPRESSED_SIZE) {
        return Refused("No session with this peer.");
    }

    ListingContext ctx;
    std::copy(identity.begin() + 1, identity.begin() + 33, ctx.requester.begin());
    ctx.chain_id = Params().NetworkIDString();
    int tip;
    uint64_t network_weight;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Height();
        network_weight = (uint64_t)GetPoSKernelPS();
    }
    ctx.next_height = tip + 1;
    ctx.live_expiry = LiveExpiry(ctx.requester, tip);

    std::vector<KeyBytes> users;
    std::string error;
    if (!LoadUsers(users, error)) {
        LogPrintf("roster: cannot read the peers this node lists: %s\n", error);
        return Refused("This relay cannot read its own list of peers.");
    }
    // Only peers still listed count towards the limit, and a peer that
    // lapsed and comes back is a new peer: leaving is not renewing.
    users = LiveUsers(users);
    ctx.listed_users = users.size();
    ctx.already_user = std::find(users.begin(), users.end(), ctx.requester) != users.end();
    ctx.max_users = (size_t)std::max<int64_t>(0, gArgs.GetArg("-maxlistedusers", DEFAULT_MAX_LISTED_USERS));

    // Asked directly, the relay sees where from: one key per address a month
    // (AddressLimitKey). A radio neighbour's address is a port of the bridge
    // on this computer, shared by every neighbour, so it is not counted.
    std::vector<unsigned char> from_address;
    if (!from.via_path && !(overlay::g_radio && overlay::g_radio->IsRadioAddress(from.addr))) {
        from_address = AddressLimitKey(from.addr);
    }

    ListingPublisher publisher;
    StakeWeightSource stake_weight;
    {
        LOCK(g_relay_mutex);
        std::map<KeyBytes, int>::const_iterator it = g_paid_at.find(ctx.requester);
        if (it != g_paid_at.end()) ctx.pending_height = it->second;
        if (!from_address.empty()) {
            const auto paid = g_paid_from.find(from_address);
            if (paid != g_paid_from.end() && paid->second.first != ctx.requester) {
                ctx.address_paid_height = paid->second.second;
            }
        }
        publisher = g_publisher;
        stake_weight = g_stake_weight;
    }
    if (!publisher || !stake_weight) return Refused("This relay has no wallet to pay from.");

    // The relay puts what it pays for into its own blocks; that is how a
    // listing confirms while most nodes still refuse to relay it. A relay that
    // is not staking would be paying for a transaction nobody may ever mine.
    const uint64_t own_weight = stake_weight();
    if (own_weight == 0) {
        return Refused("This relay is not staking, so it could not get your listing into a block.");
    }
    ctx.needed_window = NeededConfirmWindow(own_weight, network_weight);
    if (ctx.needed_window == 0) {
        return Refused("This relay stakes too rarely to get a listing into a block before it would expire.");
    }

    Record rec;
    std::string reason;
    uint32_t needed_window = 0;
    if (!CheckListingRequest(raw, ctx, rec, reason, needed_window)) {
        ListingOutcome refused = Refused(reason);
        refused.needed_window = needed_window;
        return refused;
    }

    ListingOutcome outcome = publisher(raw);
    if (!outcome.ok) return Refused(outcome.reason);

    {
        LOCK(g_relay_mutex);
        g_paid_at[ctx.requester] = ctx.next_height;
        if (!from_address.empty()) {
            for (auto it = g_paid_from.begin(); it != g_paid_from.end();) {
                it = ctx.next_height - it->second.second >= (int)MIN_TTL ? g_paid_from.erase(it) : std::next(it);
            }
            g_paid_from[from_address] = {ctx.requester, ctx.next_height};
        }
    }
    // Paying for a peer's listing is what makes it one of this relay's users,
    // and the users are who the relay shares its rewards with (§8). Saving
    // the live list also drops the peers that have left.
    if (!ctx.already_user) users.push_back(ctx.requester);
    if (!SaveUsers(users, error)) {
        LogPrintf("roster: listed peer %s but could not record it: %s\n", HexStr(ctx.requester), error);
    }
    LogPrintf("roster: paid to list peer %s until block %u (tx %s)\n",
              HexStr(ctx.requester), rec.expiry_height, outcome.txid.GetHex());
    return outcome;
}

void HandleRequest(const overlay::Hop& from, const std::vector<unsigned char>& payload)
{
    // From an adjacent peer, or through a path whose session proved a key: a
    // gateway's, the one listing a node asks for from no address
    // (CheckListingRequest refuses any other over a path).
    if (!overlay::g_overlay) return;

    uint64_t id = 0;
    std::vector<unsigned char> raw;
    if (!DecodeListingRequest(payload, id, raw)) return;

    const CPubKey identity = RequesterIdentity(from);
    KeyBytes requester{};
    if (identity.IsValid() && identity.size() == CPubKey::COMPRESSED_SIZE) {
        std::copy(identity.begin() + 1, identity.begin() + 33, requester.begin());
    }
    const std::pair<KeyBytes, uint64_t> asked(requester, id);
    const int64_t now = GetTime();
    bool repeated = false;
    ListingOutcome before;
    {
        LOCK(g_relay_mutex);
        for (auto it = g_given.begin(); it != g_given.end();) {
            it = now - it->second.at >= GIVEN_TTL ? g_given.erase(it) : std::next(it);
        }
        std::map<std::pair<KeyBytes, uint64_t>, GivenAnswer>::const_iterator it = g_given.find(asked);
        if (it != g_given.end()) {
            repeated = true;
            before = it->second.outcome;
        }
    }
    if (repeated) {
        Answer(from, id, before);
        return;
    }

    const ListingOutcome outcome = Decide(from, raw);
    if (!outcome.ok) {
        LogPrint(BCLog::NET, "roster: declined a listing request from %s: %s\n",
                 from.via_path ? strprintf("path %016x", from.path) : from.addr.ToString(), outcome.reason);
    }
    {
        LOCK(g_relay_mutex);
        if (g_given.size() < MAX_GIVEN) {
            GivenAnswer given;
            given.at = now;
            given.outcome = outcome;
            g_given[asked] = given;
        }
    }
    Answer(from, id, outcome);
}

// --- requester side ---------------------------------------------------------

struct PendingRequest {
    CService relay;
    uint64_t path{0}; //!< asked through this path instead, when not 0
    bool done{false};
    ListingOutcome outcome;
};

Mutex g_requests_mutex;
std::condition_variable g_requests_cv;
std::map<uint64_t, PendingRequest> g_requests GUARDED_BY(g_requests_mutex);

void HandleResult(const overlay::Hop& from, const std::vector<unsigned char>& payload)
{
    uint64_t id = 0;
    ListingOutcome outcome;
    if (!DecodeListingResult(payload, id, outcome)) return;

    LOCK(g_requests_mutex);
    std::map<uint64_t, PendingRequest>::iterator it = g_requests.find(id);
    // Answers are accepted only from the relay that was asked - on the path
    // it was asked through, when it was - so a third party who learned the
    // id cannot answer on its behalf.
    if (it == g_requests.end() || it->second.done) return;
    if (from.via_path ? it->second.path == 0 || it->second.path != from.path
                      : it->second.path != 0 || it->second.relay != from.addr) {
        return;
    }
    it->second.done = true;
    it->second.outcome = outcome;
    g_requests_cv.notify_all();
}

} // namespace

bool EncodeListingRequest(uint64_t id, const std::vector<unsigned char>& record,
                          std::vector<unsigned char>& out)
{
    if (record.empty() || record.size() > MAX_RECORD_SIZE) return false;
    out.assign(1 + ID_SIZE, 0);
    out[0] = static_cast<uint8_t>(AppMessage::LISTING_REQUEST);
    WriteLE64(out.data() + 1, id);
    out.insert(out.end(), record.begin(), record.end());
    return true;
}

bool DecodeListingRequest(const std::vector<unsigned char>& msg, uint64_t& id_out,
                          std::vector<unsigned char>& record_out)
{
    if (msg.size() < 1 + ID_SIZE + 1 || msg.size() > 1 + ID_SIZE + MAX_RECORD_SIZE) return false;
    if (msg[0] != static_cast<uint8_t>(AppMessage::LISTING_REQUEST)) return false;
    id_out = ReadLE64(msg.data() + 1);
    record_out.assign(msg.begin() + 1 + ID_SIZE, msg.end());
    return true;
}

bool EncodeListingResult(uint64_t id, const ListingOutcome& outcome,
                         std::vector<unsigned char>& out)
{
    out.assign(1 + ID_SIZE + 1, 0);
    out[0] = static_cast<uint8_t>(AppMessage::LISTING_RESULT);
    WriteLE64(out.data() + 1, id);
    if (outcome.ok) {
        out[1 + ID_SIZE] = RESULT_OK;
        out.insert(out.end(), outcome.txid.begin(), outcome.txid.end());
    } else if (outcome.needed_window > 0) {
        out[1 + ID_SIZE] = RESULT_NEEDS_WINDOW;
        unsigned char window[4];
        WriteLE32(window, outcome.needed_window);
        out.insert(out.end(), window, window + 4);
    } else {
        out[1 + ID_SIZE] = RESULT_REFUSED;
        const std::string reason = outcome.reason.substr(0, MAX_REFUSAL_LENGTH);
        out.insert(out.end(), reason.begin(), reason.end());
    }
    return true;
}

bool DecodeListingResult(const std::vector<unsigned char>& msg, uint64_t& id_out,
                         ListingOutcome& outcome_out)
{
    if (msg.size() < 1 + ID_SIZE + 1) return false;
    if (msg[0] != static_cast<uint8_t>(AppMessage::LISTING_RESULT)) return false;
    id_out = ReadLE64(msg.data() + 1);
    const uint8_t status = msg[1 + ID_SIZE];
    const size_t body = 1 + ID_SIZE + 1;
    outcome_out = ListingOutcome();
    if (status == RESULT_OK) {
        if (msg.size() != body + 32) return false;
        outcome_out.ok = true;
        std::memcpy(outcome_out.txid.begin(), msg.data() + body, 32);
        return true;
    }
    if (status == RESULT_NEEDS_WINDOW) {
        if (msg.size() != body + 4) return false;
        outcome_out.needed_window = ReadLE32(msg.data() + body);
        if (outcome_out.needed_window == 0 || outcome_out.needed_window > MAX_TTL - MIN_TTL) return false;
        outcome_out.reason = strprintf("The relay needs a listing that can wait %u blocks to confirm.",
                                       outcome_out.needed_window);
        return true;
    }
    if (status != RESULT_REFUSED || msg.size() > body + MAX_REFUSAL_LENGTH) return false;
    // Shown to a person, so anything that is not printable text is dropped
    // rather than passed through: the relay is a stranger.
    std::string reason(msg.begin() + body, msg.end());
    outcome_out.reason = SanitizeString(reason);
    return true;
}

uint32_t NeededConfirmWindow(uint64_t own_weight, uint64_t network_weight)
{
    if (own_weight == 0) return 0;
    // This relay stakes one block in every network/own on average.
    const uint64_t interval = std::max<uint64_t>(1, network_weight / own_weight);
    const uint64_t longest = MAX_TTL - MIN_TTL;
    if (interval > longest / CONFIRM_SAFETY) return 0;
    return (uint32_t)std::max<uint64_t>(DEFAULT_CONFIRM_WINDOW, CONFIRM_SAFETY * interval);
}

bool CheckListingRequest(const std::vector<unsigned char>& raw, const ListingContext& ctx,
                         Record& rec, std::string& reason, uint32_t& needed_window_out)
{
    needed_window_out = 0;
    if (!ParseAndVerify(raw, ctx.chain_id, rec)) {
        reason = "That is not a valid listing for this chain.";
        return false;
    }
    if (rec.type != RecordType::ANNOUNCE) {
        reason = "Only announcements are published on a peer's behalf.";
        return false;
    }
    if (rec.op_key != ctx.requester) {
        reason = "The listing names a different key from the one connected here.";
        return false;
    }
    if (!ExpiryInRange(rec.expiry_height, ctx.next_height)) {
        reason = strprintf("The listing ends at block %u, which is out of range for one confirming at %d.",
                           rec.expiry_height, ctx.next_height);
        return false;
    }
    // A renewal is welcome in a listing's last three days and not before:
    // earlier, it buys nothing but a fee.
    if (ctx.live_expiry > 0 && (int64_t)ctx.live_expiry - ctx.next_height > RENEW_WINDOW) {
        reason = strprintf("You are listed until block %u already. Renew in its last three days.",
                           ctx.live_expiry);
        return false;
    }
    const int half = (int)MIN_TTL / 2;
    if (ctx.pending_height > 0 && ctx.next_height - ctx.pending_height < half) {
        reason = "This relay has already paid for your listing; it is waiting to confirm.";
        return false;
    }
    if (ctx.address_paid_height > 0 && ctx.next_height - ctx.address_paid_height < (int)MIN_TTL) {
        reason = "This relay has already paid for a listing asked for from your address this month.";
        return false;
    }
    if (!ctx.already_user && ctx.listed_users >= ctx.max_users) {
        reason = "This relay is not taking on more peers.";
        return false;
    }
    // Last, so a peer is only asked to sign again when nothing else stands in
    // the way. The record counts in a block at any height up to
    // expiry - MIN_TTL; this relay has to be able to stake one of those.
    const int64_t window = (int64_t)rec.expiry_height - MIN_TTL - ctx.next_height + 1;
    if (window < (int64_t)ctx.needed_window) {
        needed_window_out = ctx.needed_window;
        reason = strprintf("This relay needs a listing that can wait %u blocks to confirm.", ctx.needed_window);
        return false;
    }
    return true;
}

void SetListingPublisher(ListingPublisher publisher, StakeWeightSource stake_weight)
{
    LOCK(g_relay_mutex);
    g_publisher = std::move(publisher);
    g_stake_weight = std::move(stake_weight);
}

void HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload)
{
    if (payload.empty()) return;
    // Unknown kinds are dropped without an answer, as the overlay does: the
    // sender is authenticated, so this is a version difference, not an attack.
    switch (static_cast<AppMessage>(payload[0])) {
    case AppMessage::LISTING_REQUEST:
        HandleRequest(from, payload);
        return;
    case AppMessage::LISTING_RESULT:
        HandleResult(from, payload);
        return;
    }
    LogPrint(BCLog::NET, "overlay: %u bytes of unknown application data from %s\n", payload.size(),
             from.via_path ? strprintf("path %016x", from.path) : from.addr.ToString());
}

CService OverlayAddressFor(const CService& endpoint)
{
    return CService(endpoint, overlay::OverlayPortFor(endpoint.GetPort()));
}

ListingOutcome RequestListing(const CService& relay_addr, const CPubKey& relay_key,
                              const std::vector<unsigned char>& record,
                              std::chrono::seconds connect_timeout,
                              std::chrono::seconds answer_timeout, bool& answered,
                              bool prove_roster_key)
{
    answered = false;
    if (!overlay::g_overlay) return Refused("The overlay is off, so there is no way to reach a relay.");
    if (!relay_key.IsFullyValid()) return Refused("That is not a valid relay key.");

    // To a radio neighbour (requestlisting): over the radio this node proves
    // its roster key, which its radio announcement shows anyway. Over the
    // internet only to an entry relay the user chose to show it to.
    CKey own;
    if (prove_roster_key && !ReadOperationalKey(own)) {
        return Refused("This node has no roster key to prove.");
    }
    //
    // A fresh handshake every time rather than trusting a session left over
    // from before: if the relay has restarted since, its half of the old
    // session is gone and anything sent on it vanishes without a word. One
    // handshake a month costs nothing; a request that never arrives does.
    //
    // Retried after a pause rather than in a loop, because a new attempt
    // discards the one whose answer may still be on its way.
    const auto deadline = std::chrono::steady_clock::now() + connect_timeout;
    // Over a radio hop the pause also covers the greeting's airtime both ways,
    // or every try would replace one that had not had time to arrive.
    const auto pause = std::chrono::milliseconds{3000} + overlay::RadioAirtime(relay_addr, overlay::RADIO_GREETING_BYTES);
    bool connected = false;
    while (!connected && std::chrono::steady_clock::now() < deadline) {
        const bool started = prove_roster_key ? overlay::g_overlay->ConnectAs(relay_addr, relay_key, own)
                                              : overlay::g_overlay->Connect(relay_addr, relay_key);
        if (!started) {
            return Refused("Could not start a session with the relay.");
        }
        const auto retry = std::min(deadline, std::chrono::steady_clock::now() + pause);
        while (overlay::g_overlay->HasPendingHandshake(relay_addr) && std::chrono::steady_clock::now() < retry) {
            UninterruptibleSleep(std::chrono::milliseconds{100});
        }
        connected = !overlay::g_overlay->HasPendingHandshake(relay_addr) &&
                    overlay::g_overlay->HasSession(relay_addr);
    }
    if (!connected) {
        return Refused(strprintf("The relay at %s did not answer.", relay_addr.ToString()));
    }

    // A session may already have existed with whoever holds that address now.
    KeyBytes expected;
    std::copy(relay_key.begin() + 1, relay_key.begin() + 33, expected.begin());
    if (!SameKey(overlay::g_overlay->PeerIdentity(relay_addr), expected)) {
        return Refused("A different key answered at the relay's address.");
    }

    const uint64_t id = GetRand(std::numeric_limits<uint64_t>::max());
    std::vector<unsigned char> msg;
    if (!EncodeListingRequest(id, record, msg)) return Refused("The listing is too large to send.");
    {
        LOCK(g_requests_mutex);
        g_requests[id].relay = relay_addr;
    }
    // Sent again, under the same id, while no answer comes: a datagram can be
    // lost, which on a radio hop is ordinary. The relay answers a repeat with
    // the answer it already gave rather than deciding twice. Each try allows
    // for the request, the answer and, on a radio hop, a link set up again.
    const auto answer_deadline = std::chrono::steady_clock::now() + answer_timeout;
    const auto resend_every = std::chrono::milliseconds{10000} +
                              2 * overlay::RadioAirtime(relay_addr, msg.size() + overlay::RADIO_GREETING_BYTES);
    PendingRequest result;
    while (true) {
        if (!overlay::g_overlay->SendApp(relay_addr, msg)) {
            LOCK(g_requests_mutex);
            g_requests.erase(id);
            return Refused("Could not send the request to the relay.");
        }
        WAIT_LOCK(g_requests_mutex, lock);
        const auto until = std::min(answer_deadline, std::chrono::steady_clock::now() + resend_every);
        g_requests_cv.wait_until(lock, until, [&]() EXCLUSIVE_LOCKS_REQUIRED(g_requests_mutex) {
            return g_requests[id].done;
        });
        if (g_requests[id].done || std::chrono::steady_clock::now() >= answer_deadline) {
            result = g_requests[id];
            g_requests.erase(id);
            break;
        }
    }
    if (!result.done) return Refused("The relay did not answer in time.");
    answered = true;
    return result.outcome;
}

ListingOutcome RequestListingOverPath(const KeyBytes& relay, const std::vector<unsigned char>& record, int hops,
                                      std::chrono::seconds answer_timeout, bool& answered)
{
    answered = false;
    if (!overlay::g_overlay) return Refused("The overlay is off, so there is no way to reach a relay.");

    // The relay proves itself as the path's far end; this node proves its
    // roster key to it and to nobody else on the way.
    overlay::Reached reached;
    std::string error;
    if (!overlay::ReachRelay(relay, hops, /* prove_last */ true, reached, error)) {
        return Refused("Could not reach the relay through a path: " + error + ".");
    }

    const uint64_t id = GetRand(std::numeric_limits<uint64_t>::max());
    std::vector<unsigned char> msg;
    if (!EncodeListingRequest(id, record, msg)) {
        overlay::g_overlay->ClosePath(reached.legs);
        return Refused("The listing is too large to send.");
    }
    {
        LOCK(g_requests_mutex);
        g_requests[id].path = reached.path;
    }
    // Sent again under the same id while no answer comes, as above; each try
    // allows for the step timeout of every relay on the way and back.
    // A path that starts on the radio takes longer a step, both ways.
    const auto answer_deadline = std::chrono::steady_clock::now() + answer_timeout + 6 * reached.step;
    const auto resend_every = std::chrono::milliseconds{10000} + 2 * reached.step;
    PendingRequest result;
    while (true) {
        if (!overlay::g_overlay->SendSecret(reached.path, msg)) {
            LOCK(g_requests_mutex);
            g_requests.erase(id);
            overlay::g_overlay->ClosePath(reached.legs);
            return Refused("Could not send the request through the path.");
        }
        WAIT_LOCK(g_requests_mutex, lock);
        const auto until = std::min(answer_deadline, std::chrono::steady_clock::now() + resend_every);
        g_requests_cv.wait_until(lock, until, [&]() EXCLUSIVE_LOCKS_REQUIRED(g_requests_mutex) {
            return g_requests[id].done;
        });
        if (g_requests[id].done || std::chrono::steady_clock::now() >= answer_deadline) {
            result = g_requests[id];
            g_requests.erase(id);
            break;
        }
    }
    overlay::g_overlay->ClosePath(reached.legs);
    if (!result.done) return Refused("The relay did not answer in time.");
    answered = true;
    return result.outcome;
}

} // namespace roster
