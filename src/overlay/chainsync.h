// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_CHAINSYNC_H
#define BITCOIN_OVERLAY_CHAINSYNC_H

#include <overlay/path.h>
#include <roster/record.h>
#include <sync.h>
#include <threadinterrupt.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

class CChainParams;

/**
 * Blocks over the overlay, between radio neighbours (design note §8·7).
 *
 * The overlay carries mail and listings; the block chain travels the internet.
 * A node with only radio therefore never learns the roster, which is what every
 * service here is found through. This closes that gap for a radio neighbourhood:
 * a node with the internet passes new blocks over the overlay to the radio
 * neighbours it hears, and a node with no internet pulls them from a neighbour
 * that is ahead, one block at a time, validating each as the peer-to-peer layer
 * would. Its own transactions go out the same way, handed to a neighbour that
 * has the internet to broadcast them.
 *
 * It runs only between adjacent radio neighbours, reached directly rather than
 * over a path: block propagation is not anonymous and does not need to be, and
 * the neighbour relationship is already in the open. What crosses an internet
 * link is handled by the ordinary peer-to-peer network, so this neither
 * replaces nor races it; a node that is kept at the tip by the internet has
 * nothing to pull.
 *
 * This is not initial sync: LoRa cannot carry a chain from genesis, and does
 * not have to. A radio-only node starts from a recent copy and this keeps it
 * current. Only a few blocks behind the tip are ever fetched this way.
 */
namespace overlay {

/** Whether a node feeds blocks to, and pulls them from, its radio neighbours (-overlayblocks). */
static const bool DEFAULT_OVERLAY_BLOCKS = true;

/** Overlay application-data tags for the chain feed. */
static constexpr uint8_t CHAIN_GETTIP = 0x20; //!< asking a neighbour for its best block
static constexpr uint8_t CHAIN_TIP = 0x21;    //!< a neighbour's best (height, hash), also sent unasked when it changes
static constexpr uint8_t CHAIN_GETBLOCK = 0x22; //!< asking for the block at a height on the sender's chain
static constexpr uint8_t CHAIN_BLOCK = 0x23;  //!< a block, in chunks (height then serialization)
static constexpr uint8_t CHAIN_NOBLOCK = 0x24; //!< the sender has no block at that height

/** Whether a payload is for the chain feed (one of the tags above). */
bool IsChainPayload(const std::vector<unsigned char>& payload);

/** How far behind a neighbour a node will follow over the overlay; further back needs a fresh copy. */
static constexpr int CHAIN_MAX_BEHIND = 500;

class ChainSync
{
public:
    ChainSync(const CChainParams& params, const roster::KeyBytes& self, bool pull);
    ~ChainSync();

    void Start();
    void Stop();

    /**
     * Whether this node has no peer-to-peer connection delivering blocks, so it
     * depends on the radio. When it returns false the node still serves blocks
     * to its radio neighbours, but does not poll or pull over the radio - the
     * internet keeps it current, and the radio's airtime is better left alone.
     * Without a check set, the node behaves as isolated.
     */
    void SetIsolatedCheck(std::function<bool()> isolated);

    /** Handle one chain-feed message from an adjacent peer. */
    void HandleApp(const CService& from, const std::vector<unsigned char>& payload);

    /** What each neighbour last told us its height was. */
    struct PeerView {
        roster::KeyBytes key{};
        CService addr;
        int height{-1};
        int64_t heard{0};
    };
    std::vector<PeerView> Neighbours() const;
    bool Pulls() const { return m_pull; }

    /** One round, exposed for tests: refresh neighbours, announce a changed tip, pull if behind. */
    void Tick();

private:
    void ThreadSync();
    /** Direct session with a radio neighbour, dialled from the key its bridge announced. */
    bool Reach(const PeerView& peer);
    void Send(const CService& to, const std::vector<unsigned char>& msg);
    void SendTip(const CService& to);
    void ServeBlock(const CService& to, int height);
    void SendBlockChunks(const CService& to, const std::vector<unsigned char>& payload);
    void OnBlock(const CService& from, std::vector<unsigned char>&& payload);
    int LocalHeight() const;

    const CChainParams& m_params;
    const roster::KeyBytes m_self; //!< this node's roster key, so only one side of a pair opens the session
    const bool m_pull; //!< whether this node pulls blocks it is missing (a node the internet keeps current need not)

    mutable Mutex m_mutex;
    //! What each neighbour (by local address) last advertised, and our fetch state with it.
    struct State {
        roster::KeyBytes key{};
        int height{-1};
        int64_t heard{0};
        int64_t asked_at{0};   //!< when we last sent it a GETBLOCK, 0 if none outstanding
        int asked_height{-1};
        int64_t polled_at{0};  //!< when we last asked it for its tip
        // One in-flight block transfer from this peer.
        uint64_t transfer{0};
        uint32_t total{0};
        std::vector<unsigned char> buf;
        int64_t buf_at{0};
    };
    std::map<std::string, State> m_peers GUARDED_BY(m_mutex);
    std::function<bool()> m_isolated GUARDED_BY(m_mutex);

    std::thread m_thread;
    CThreadInterrupt m_interrupt;
};

extern std::unique_ptr<ChainSync> g_chainsync;

} // namespace overlay

#endif // BITCOIN_OVERLAY_CHAINSYNC_H
