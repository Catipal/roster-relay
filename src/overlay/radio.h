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

static const bool DEFAULT_RADIO = false;
static const bool DEFAULT_RADIO_ENTRY = true;
/** How long the bridge may stay silent before it is taken to be gone. */
static constexpr int64_t RADIO_BRIDGE_TIMEOUT = 60;
/** How long a neighbour is used after it was last heard; the bridge announces every half hour. */
static constexpr int64_t RADIO_PEER_TTL = 3 * 60 * 60;
/** Each step of a path whose first hop is a radio link may take this long. */
static constexpr std::chrono::milliseconds RADIO_STEP_TIMEOUT{30000};

struct RadioPeer {
    roster::KeyBytes key{};
    bool has_key{false};
    CService local;           //!< 127.0.0.1 and the bridge's port for it
    std::string destination;  //!< its Reticulum destination, hex
    int hops{-1};
    int64_t heard{0};
    bool link_up{false};
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

} // namespace overlay

#endif // BITCOIN_OVERLAY_RADIO_H
