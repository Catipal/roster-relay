// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_RADIO_H
#define BITCOIN_OVERLAY_RADIO_H

#include <fs.h>
#include <netaddress.h>
#include <roster/record.h>
#include <sync.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

/**
 * Radio links: the overlay over Reticulum (LoRa through an RNode, packet
 * radio, serial lines - whatever Reticulum has an interface for).
 *
 * Reticulum is a Python stack with its own licence, so it runs beside the
 * node, in contrib/reticulum/bps-rns-bridge.py, and is never linked in. The
 * two meet in the data directory and on 127.0.0.1:
 *
 *   radio/node.json   written here: the overlay port, the roster key, the network
 *   radio/peers.json  written by the bridge: each BPS node it hears on the
 *                     radio, with a local UDP port standing for it
 *
 * To the overlay a radio neighbour is a peer at 127.0.0.1 and that port. The
 * bridge carries the datagrams over a Reticulum link and never sees inside
 * them; the handshake still proves the far end holds the key it announced.
 *
 * What it is for: a node with no internet, or none it wants to use, reaches
 * the overlay through a radio neighbour that is a listed relay, used as its
 * entry relay. Everything after that hop travels as before. A radio hop is
 * slow - a LoRa link moves a few hundred bytes a second - so waits on a path
 * that starts with one are longer.
 */
namespace overlay {

static const bool DEFAULT_RADIO = true;
static const bool DEFAULT_RADIO_ENTRY = true;
/** How long the bridge may stay silent before it is taken to be gone. */
static constexpr int64_t RADIO_BRIDGE_TIMEOUT = 60;
/** How long a neighbour is used after it was last heard; the bridge announces every half hour. */
static constexpr int64_t RADIO_PEER_TTL = 3 * 60 * 60;
/**
 * Each step of a path whose first hop is a radio link may take this long, on
 * top of the airtime its datagrams need (RadioStepTimeout).
 */
static constexpr std::chrono::milliseconds RADIO_STEP_TIMEOUT{30000};
/**
 * The speed assumed for a radio the bridge does not report one for: LoRa at
 * spreading factor 8 and 125 kHz, a common setting for Reticulum.
 */
static constexpr int64_t RADIO_DEFAULT_BITRATE = 3125;
/**
 * What the radio spends on each byte of overlay datagram, in percent. A full
 * datagram goes as three Reticulum packets, whose headers and link encryption
 * add about a fifth, and an RNode sends each as two LoRa packets with a
 * preamble apiece. Rounded up, because a wait that is too short costs far more
 * airtime than one that is too long.
 */
static constexpr int64_t RADIO_FRAMING_PERCENT = 150;
/**
 * What a first greeting over the radio puts on the air, both ways: the overlay
 * handshake and its answer, and the Reticulum link the bridge sets up for them.
 */
static constexpr size_t RADIO_GREETING_BYTES = 800;

struct RadioPeer {
    roster::KeyBytes key{};
    bool has_key{false};
    CService local;           //!< 127.0.0.1 and the bridge's port for it
    std::string destination;  //!< its Reticulum destination, hex
    int hops{-1};
    int64_t heard{0};
    bool link_up{false};
    int64_t bitrate{0};       //!< of the radio the way to it starts on, bits a second; 0 if not reported
};

struct RadioState {
    bool bridge_seen{false};   //!< peers.json exists and could be read
    int64_t updated{0};        //!< when the bridge last wrote it
    std::string destination;   //!< this node's Reticulum destination
    std::string network;
    std::vector<std::string> interfaces;
    std::vector<RadioPeer> peers;
};

/** Read what the bridge writes. False with `error` set when it is not that. */
bool ParseRadioPeers(const std::string& json, RadioState& out, std::string& error);

class Radio
{
public:
    Radio(const fs::path& dir, const std::string& network);

    /** Tell the bridge where this node's overlay is and who it is. */
    bool WriteNodeInfo(uint16_t overlay_port, const roster::KeyBytes& key, std::string& error);

    /** Read the bridge's latest view. */
    void Refresh();

    RadioState State() const;
    /** Whether the bridge has written lately. */
    bool BridgeAlive(int64_t now) const;
    /** Neighbours heard lately, with a roster key: those the overlay can use. */
    std::vector<RadioPeer> Neighbours(int64_t now) const;
    /** Where to reach `key` over the radio, if it is a neighbour. */
    bool AddressFor(const roster::KeyBytes& key, int64_t now, CService& out) const;
    /** Whether an overlay address is one of the bridge's ports. */
    bool IsRadioAddress(const CService& addr) const;
    /**
     * Bits a second the radio carries towards the neighbour at `addr`, shared
     * between the radio hops on the way since each one sends on the same
     * channel. 0 when `addr` is not one of the bridge's ports.
     */
    int64_t RateTo(const CService& addr) const;

    fs::path Dir() const { return m_dir; }

private:
    const fs::path m_dir;
    const std::string m_network;
    mutable Mutex m_mutex;
    RadioState m_state GUARDED_BY(m_mutex);
};

extern std::unique_ptr<Radio> g_radio;
/** Whether paths start at a radio neighbour when one is a listed relay (-radioentry). */
extern bool g_radio_entry;

/**
 * Where to send the first hop of a path to the relay `key`, listed at
 * `internet`: its radio port when it is a neighbour and -radioentry is on,
 * otherwise `internet`. `slow` is set when it is the radio.
 */
CService FirstHopAddress(const roster::KeyBytes& key, const CService& internet, bool& slow);

/**
 * Where a relay reaches the next hop `key`, listed at `internet`: its radio
 * port when it is a neighbour this node has no working internet route to
 * (the address is not routable or not reachable from here), otherwise
 * `internet`. `slow` is set when it is the radio. This is what lets a path
 * cross a stretch that has only radio, one relay bridging to the next.
 */
CService NextHopForRelay(const roster::KeyBytes& key, const CService& internet, bool& slow);

/**
 * Roughly how long the radio takes to carry `bytes` of overlay datagrams to
 * the neighbour at `addr`, framing counted. Zero when `addr` is not a radio
 * neighbour, so callers can add it to any wait.
 *
 * Waits on a radio hop have to grow with this rather than be fixed: a greeting
 * re-sent before the first could have arrived replaces it, and a request
 * re-sent while its answer is still on the air doubles the airtime, so a
 * fixed wait that suits LoRa's fastest setting never completes at its slowest.
 */
std::chrono::milliseconds RadioAirtime(const CService& addr, size_t bytes);

/** How long each step of a path may take when its first hop is the radio neighbour at `addr`. */
std::chrono::milliseconds RadioStepTimeout(const CService& addr);

} // namespace overlay

#endif // BITCOIN_OVERLAY_RADIO_H
