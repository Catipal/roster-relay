// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_SERVICE_H
#define BITCOIN_COMPANION_SERVICE_H

#include <companion/policy.h>
#include <companion/protocol.h>
#include <companion/store.h>
#include <companion/wallethook.h>
#include <fs.h>
#include <overlay/cells.h>
#include <pubkey.h>
#include <sync.h>

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * The home node's side of the phone companion.
 *
 * A paired phone reaches this node at the end of a three-hop path, proving its
 * device key there, and asks it to pay from the allowance wallet. Requests
 * arrive on the overlay's receive thread and are served on a thread of their
 * own, because serving one may mean waiting on the wallet, and the receive
 * thread carries everyone's traffic.
 *
 * Locks: cs_companion guards the pairings, prepared payments and device store,
 * and is never held while the wallet or the node is called - those take
 * cs_wallet and cs_main, in that order, and must not find this one under them.
 */
namespace companion {

static constexpr bool DEFAULT_COMPANION = false;
/** How long a pairing ticket can be answered. */
static constexpr int64_t TICKET_TTL = 10 * 60;
/** How long a finished pairing is remembered, so the phone can ask how it went. */
static constexpr int64_t PAIRING_KEEP = 20 * 60;
/** How long a prepared payment waits for the phone to send it. */
static constexpr int64_t PREPARE_TTL = 2 * 60;
static constexpr size_t MAX_PAIRINGS = 4;
static constexpr size_t MAX_PREPARED = 16;
static constexpr size_t MAX_SENT = 256;
static constexpr size_t MAX_QUEUE = 64;
/** PIN checks per minute across every device. */
static constexpr size_t PIN_ATTEMPTS = 10;
static constexpr int64_t PIN_WINDOW = 60;
/** How often a device's last-seen time is written down at most. */
static constexpr int64_t SEEN_GRANULARITY = 60;

/** What the service needs from the node, as functions, so that it can be tested without one. */
struct NodeHooks {
    /** The chain's height. */
    std::function<int()> height;
    /** Relays a phone can build its paths through; not this node. */
    std::function<std::vector<RelayEntry>()> relays;
    /** The key proved at the far end of `hop`, or an invalid one. */
    std::function<CPubKey(const overlay::Hop& hop)> identify;
    /** Puts one cell on the wire. */
    overlay::CellChannel::Sender sender;
};

/** A pairing from the moment its ticket is shown until it is accepted or forgotten. */
struct Pairing {
    uint256 token;
    int64_t created{0};
    int64_t expires{0};
    PairState state{PairState::WAITING};
    bool answered{false}; //!< a phone has sent PAIR with this ticket
    CPubKey device;
    std::string name;
    PinVerifier pin;
    std::string code; //!< the six digits both screens show
    Limits limits;    //!< set on acceptance
};

class Service
{
public:
    Service(const fs::path& dir, const std::string& wallet, const CPubKey& node_key, NodeHooks node,
            bool memory_only = false);
    ~Service();

    void Start();
    /** Stop serving and join the worker. Requests arriving after are dropped. */
    void Stop();

    bool IsOurs(const std::vector<unsigned char>& payload) const { return m_channel.IsOurs(payload); }
    /** Overlay application data tagged COMPANION_CELL. Called on the overlay's receive thread. */
    void HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload);

    /** A ticket for a new pairing, good for TICKET_TTL. */
    PairingTicket NewTicket(const std::string& network, const std::string& node_addr,
                            const std::vector<RelayEntry>& relays, int64_t now);
    std::vector<Pairing> Pairings(int64_t now);
    /** Pair the phone that answered `token`, with these limits. */
    bool Accept(const uint256& token, const Limits& limits, int64_t now, std::string& error);
    bool Reject(const uint256& token, std::string& error);

    std::vector<Device> Devices();
    bool SetLimits(const CPubKey& key, const Limits& limits, std::string& error);
    /** Forget a device: it can do nothing more until paired again. */
    bool Revoke(const CPubKey& key);
    /** Let a device locked by wrong PINs try again. */
    bool Unlock(const CPubKey& key, std::string& error);

    const std::string& WalletName() const { return m_wallet; }
    const CPubKey& NodeKey() const { return m_node_key; }

    /**
     * Answer one request from `device` - invalid when the path it came on
     * proved no key. Everything the service does, without a network.
     */
    Message Serve(const CPubKey& device, const Message& request, int64_t now);

    /** Let go of prepared payments and pairings whose time is up. */
    void Expire(int64_t now);

private:
    struct Prepared {
        CPubKey device;
        PreparedPayment payment;
        int64_t expires{0};
    };
    struct Sent {
        CPubKey device;
        uint256 txid;
    };

    void Work();

    Message Pair(const CPubKey& device, const Message& request, int64_t now);
    Message PairStatus(const CPubKey& device, const Message& request, int64_t now);
    Message Status(const CPubKey& device, const Message& request, int64_t now);
    Message Address(const Message& request);
    Message History(const Message& request);
    Message Prepare(const CPubKey& device, const Message& request, int64_t now);
    Message Send(const CPubKey& device, const Message& request, int64_t now);
    Message Cancel(const CPubKey& device, const Message& request);
    Message Relays(const Message& request);
    Message SetPin(const CPubKey& device, const Message& request, int64_t now);
    Message Unpair(const CPubKey& device, const Message& request);

    /**
     * Check `pin` against a device's verifier, counting failures and the
     * shared cap. Empty when it matched; otherwise what to tell the phone.
     */
    std::string CheckDevicePin(Device& device, const std::string& pin, int64_t now)
        EXCLUSIVE_LOCKS_REQUIRED(cs_companion);

    const std::string m_wallet;
    const CPubKey m_node_key;
    const NodeHooks m_node;
    overlay::CellChannel m_channel;

    Mutex cs_companion;
    Store m_store GUARDED_BY(cs_companion);
    std::map<uint256, Pairing> m_pairings GUARDED_BY(cs_companion);
    std::map<uint256, Prepared> m_prepared GUARDED_BY(cs_companion);
    std::map<uint256, Sent> m_sent GUARDED_BY(cs_companion);
    std::deque<uint256> m_sent_order GUARDED_BY(cs_companion);
    AttemptLimiter m_pin_limiter GUARDED_BY(cs_companion){PIN_ATTEMPTS, PIN_WINDOW};

    Mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::deque<overlay::CellChannel::Request> m_queue GUARDED_BY(m_queue_mutex);
    bool m_stopping GUARDED_BY(m_queue_mutex){false};
    std::thread m_worker;
};

/** The running service, or null when -companion is off. */
extern std::unique_ptr<Service> g_companion;

} // namespace companion

#endif // BITCOIN_COMPANION_SERVICE_H
