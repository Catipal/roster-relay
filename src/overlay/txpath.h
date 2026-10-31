// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_TXPATH_H
#define BITCOIN_OVERLAY_TXPATH_H

#include <overlay/hosting.h>
#include <overlay/path.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * A node's own transactions leave through a path (design note §8·7, stage 1).
 *
 * Announced on the peer-to-peer network, a transaction first comes from the
 * address of the node that made it, and whoever is connected to many nodes
 * can tell which that was - the broadcast-origin leak §8 named. So this
 * node's own transactions go instead through TXPATH_HOPS relays to a relay
 * that is not one of its entry relays, which puts them in its mempool and
 * announces them as it does any other. It learns the transaction and not
 * where it came from; the relays before it learn nothing.
 *
 * If no relay will take it, the peer-to-peer network carries it after all,
 * and the log says so: a transaction that never leaves is worse than one
 * whose origin can be guessed.
 */
namespace overlay {

static constexpr uint8_t TX_SEND = 0x15; //!< chunked: one transaction, for the relay to announce
static constexpr uint8_t TX_ACK = 0x16;  //!< the relay's answer: taken, or why not

//! On wherever the overlay runs (-txpath).
static const bool DEFAULT_TXPATH = true;
//! Relays between this node and the relay that announces its transaction.
static constexpr int TXPATH_HOPS = 2;
//! Relays tried before the peer-to-peer network carries it after all.
static constexpr int TXPATH_TRIES = 3;
//! Largest transaction carried: the standard weight limit, in bytes at most.
static constexpr size_t MAX_TXPATH_TX = 400000;
//! Transactions a relay takes from one path, and from all, in a minute.
static constexpr size_t TXPATH_PER_PATH_MINUTE = 20;
static constexpr size_t TXPATH_ALL_MINUTE = 600;
/** Own transactions remembered until a peer announces them back, and for how long. */
static constexpr size_t MAX_HEARD_BACK = 1000;
static constexpr int64_t HEARD_BACK_TTL = 3600;

bool IsTxPathPayload(const std::vector<unsigned char>& payload);

class TxPath
{
public:
    /** What a relay does with a transaction from a path: its mempool and announce it. Empty on success, else why not. */
    using Accept = std::function<std::string(const CTransactionRef&)>;
    /** What this node does when no relay took its transaction: the peer-to-peer network. */
    using Fallback = std::function<void(const CTransactionRef&)>;

    TxPath(const roster::KeyBytes& self, Accept accept, Fallback fallback);
    ~TxPath();

    void Start();
    void Stop();

    /** Queue this node's own transaction to leave through a path. */
    void Send(const CTransactionRef& tx);
    /** A transaction message from the far end of a path. Never blocks. */
    void HandleApp(const Hop& from, const std::vector<unsigned char>& payload);

    /**
     * A peer announced `hash` (a txid or a wtxid): if it is one of this node's
     * own that left through a path, the network has it now. Gives back both
     * ids, once, for the caller to relay it as it would anyone's.
     */
    bool HeardBack(const uint256& hash, uint256& txid, uint256& wtxid);

    struct Stats {
        uint64_t through_path{0};  //!< own transactions a relay took
        uint64_t over_p2p{0};      //!< own transactions the peer-to-peer network carried after all
        uint64_t refused_own{0};   //!< own transactions a relay found invalid
        uint64_t for_others{0};    //!< others' transactions this node announced
        uint64_t turned_away{0};   //!< others' transactions refused: invalid, too many, too large
        size_t queued{0};
    };
    Stats GetStats() const;

private:
    struct Waiting {
        bool done{false};
        bool ok{false};
        std::string reason;
    };
    struct Incoming {
        ChunkAssembler parts;
        int64_t started{0};
    };

    void ThreadSend();
    void ThreadAccept();
    bool SendOne(const CTransactionRef& tx, std::string& last_error, bool& definitive);

    const roster::KeyBytes m_self;
    const Accept m_accept;
    const Fallback m_fallback;
    std::atomic<bool> m_running{false};
    std::thread m_sender;
    std::thread m_acceptor;

    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<CTransactionRef> m_outbox GUARDED_BY(m_mutex);
    std::map<uint64_t, Waiting> m_waiting GUARDED_BY(m_mutex);
    std::map<std::pair<Hop, uint64_t>, Incoming> m_incoming GUARDED_BY(m_mutex);
    std::deque<std::pair<std::pair<Hop, uint64_t>, CTransactionRef>> m_to_accept GUARDED_BY(m_mutex);
    std::map<Hop, std::deque<int64_t>> m_recent GUARDED_BY(m_mutex); //!< when each path's last transactions came
    std::deque<int64_t> m_recent_all GUARDED_BY(m_mutex);
    //! Own transactions that left through a path, by txid and by wtxid: (txid, wtxid, when).
    struct Sent {
        uint256 txid;
        uint256 wtxid;
        int64_t at{0};
    };
    std::map<uint256, Sent> m_sent GUARDED_BY(m_mutex);
    Stats m_stats GUARDED_BY(m_mutex);
};

/** The running path for transactions, or null when -txpath or the overlay is off. */
extern std::unique_ptr<TxPath> g_txpath;

/**
 * For BroadcastTransaction: true when `tx`, this node's own, has been handed
 * to a path; false to announce it on the peer-to-peer network as before.
 */
bool SendOwnTransaction(const CTransactionRef& tx);

/**
 * For the peer-to-peer side: a peer announced `hash`. True, once, when it is
 * this node's own transaction that left through a path, so that it is now
 * relayed like anyone else's. A node that never passed on its own
 * transactions would stand out as their sender among its peers - and a peer
 * that only hears from it would never get them.
 */
bool OwnTransactionHeardBack(const uint256& hash, uint256& txid, uint256& wtxid);

void HandleTxPathApp(const Hop& from, const std::vector<unsigned char>& payload);

} // namespace overlay

#endif // BITCOIN_OVERLAY_TXPATH_H
