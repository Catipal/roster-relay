// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/radio.h>

#include <net.h>
#include <netbase.h>
#include <overlay/frame.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>

#include <univalue.h>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace overlay {

std::unique_ptr<Radio> g_radio;
bool g_radio_entry{DEFAULT_RADIO_ENTRY};

bool ParseRadioPeers(const std::string& json, RadioState& out, std::string& error)
{
    out = RadioState();
    UniValue v;
    if (!v.read(json) || !v.isObject()) {
        error = "not JSON";
        return false;
    }
    if (find_value(v, "version").isNum() && find_value(v, "version").get_int() != 1) {
        error = "written by a bridge of another version";
        return false;
    }
    const UniValue& updated = find_value(v, "updated");
    if (updated.isNum()) out.updated = updated.get_int64();
    if (find_value(v, "destination").isStr()) out.destination = find_value(v, "destination").get_str();
    if (find_value(v, "network").isStr()) out.network = find_value(v, "network").get_str();
    const UniValue& interfaces = find_value(v, "interfaces");
    if (interfaces.isArray()) {
        for (size_t i = 0; i < interfaces.size(); ++i) {
            if (interfaces[i].isStr()) out.interfaces.push_back(interfaces[i].get_str());
        }
    }
    const UniValue& peers = find_value(v, "peers");
    if (!peers.isArray()) {
        error = "no peers";
        return false;
    }
    for (size_t i = 0; i < peers.size(); ++i) {
        const UniValue& p = peers[i];
        if (!p.isObject()) continue;
        RadioPeer peer;
        const UniValue& port = find_value(p, "port");
        if (!port.isNum() || port.get_int() <= 0 || port.get_int() > 65535) continue;
        // Only ever a port on this computer: the bridge never names anywhere else.
        peer.local = CService(LookupNumeric("127.0.0.1", (uint16_t)port.get_int()));
        const UniValue& key = find_value(p, "key");
        if (key.isStr() && IsHex(key.get_str())) {
            const std::vector<unsigned char> raw = ParseHex(key.get_str());
            if (raw.size() == 32) {
                std::copy(raw.begin(), raw.end(), peer.key.begin());
                peer.has_key = true;
            }
        }
        if (find_value(p, "destination").isStr()) peer.destination = find_value(p, "destination").get_str();
        if (find_value(p, "hops").isNum()) peer.hops = find_value(p, "hops").get_int();
        if (find_value(p, "heard").isNum()) peer.heard = find_value(p, "heard").get_int64();
        peer.link_up = find_value(p, "link").isTrue();
        // Bridges before this field was added report none.
        if (find_value(p, "bitrate").isNum()) peer.bitrate = std::max<int64_t>(0, find_value(p, "bitrate").get_int64());
        out.peers.push_back(peer);
    }
    out.bridge_seen = true;
    return true;
}

Radio::Radio(const fs::path& dir, const std::string& network) : m_dir(dir), m_network(network) {}

bool Radio::WriteNodeInfo(uint16_t overlay_port, const roster::KeyBytes& key, std::string& error)
{
    try {
        fs::create_directories(m_dir);
    } catch (const fs::filesystem_error& e) {
        error = e.what();
        return false;
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("version", 1);
    o.pushKV("network", m_network);
    o.pushKV("overlay_port", (int)overlay_port);
    o.pushKV("key", HexStr(key));
    const fs::path path = m_dir / "node.json";
    const fs::path tmp = m_dir / "node.json.new";
    {
        fsbridge::ofstream f(tmp, std::ios::out | std::ios::trunc);
        if (!f) {
            error = "could not write " + tmp.string();
            return false;
        }
        f << o.write(1) << "\n";
    }
    if (!RenameOver(tmp, path)) {
        error = "could not replace " + path.string();
        return false;
    }
    return true;
}

void Radio::Refresh()
{
    std::string json;
    {
        fsbridge::ifstream f(m_dir / "peers.json");
        if (!f) {
            LOCK(m_mutex);
            m_state = RadioState();
            return;
        }
        std::stringstream s;
        s << f.rdbuf();
        json = s.str();
    }
    RadioState state;
    std::string error;
    if (!ParseRadioPeers(json, state, error)) {
        // Caught mid-write, or garbage: keep what was read before.
        LogPrint(BCLog::NET, "radio: peers.json unreadable (%s)\n", error);
        return;
    }
    if (!state.network.empty() && state.network != m_network) {
        LogPrintf("radio: the bridge is running for %s, this node is %s; ignoring it\n", state.network, m_network);
        state.peers.clear();
    }
    LOCK(m_mutex);
    m_state = state;
}

RadioState Radio::State() const
{
    LOCK(m_mutex);
    return m_state;
}

bool Radio::BridgeAlive(int64_t now) const
{
    LOCK(m_mutex);
    return m_state.bridge_seen && now - m_state.updated <= RADIO_BRIDGE_TIMEOUT;
}

std::vector<RadioPeer> Radio::Neighbours(int64_t now) const
{
    std::vector<RadioPeer> out;
    LOCK(m_mutex);
    if (!m_state.bridge_seen || now - m_state.updated > RADIO_BRIDGE_TIMEOUT) return out;
    for (const RadioPeer& p : m_state.peers) {
        if (p.has_key && (p.link_up || now - p.heard <= RADIO_PEER_TTL)) out.push_back(p);
    }
    return out;
}

bool Radio::AddressFor(const roster::KeyBytes& key, int64_t now, CService& out) const
{
    for (const RadioPeer& p : Neighbours(now)) {
        if (p.key == key) {
            out = p.local;
            return true;
        }
    }
    return false;
}

bool Radio::IsRadioAddress(const CService& addr) const
{
    LOCK(m_mutex);
    for (const RadioPeer& p : m_state.peers) {
        if (p.local == addr) return true;
    }
    return false;
}

int64_t Radio::RateTo(const CService& addr) const
{
    LOCK(m_mutex);
    for (const RadioPeer& p : m_state.peers) {
        if (p.local != addr) continue;
        const int64_t bitrate = p.bitrate > 0 ? p.bitrate : RADIO_DEFAULT_BITRATE;
        return std::max<int64_t>(1, bitrate / std::max(1, p.hops));
    }
    return 0;
}

CService FirstHopAddress(const roster::KeyBytes& key, const CService& internet, bool& slow)
{
    slow = false;
    CService radio;
    if (g_radio && g_radio_entry && g_radio->AddressFor(key, GetTime(), radio)) {
        slow = true;
        return radio;
    }
    return internet;
}

CService NextHopForRelay(const roster::KeyBytes& key, const CService& internet, bool& slow)
{
    slow = false;
    // Prefer the internet when there is a working route: it is faster, and a
    // relay reached over radio is one with no other way in. Routable and
    // reachable are both properties of the address and this node, not of the
    // far relay, so two relays with internet between them never fall to radio.
    if (g_radio && (!internet.IsRoutable() || !IsReachable(internet))) {
        CService radio;
        if (g_radio->AddressFor(key, GetTime(), radio)) {
            slow = true;
            return radio;
        }
    }
    return internet;
}

std::chrono::milliseconds RadioAirtime(const CService& addr, size_t bytes)
{
    const int64_t rate = g_radio ? g_radio->RateTo(addr) : 0;
    if (rate <= 0) return std::chrono::milliseconds{0};
    const int64_t bits = (int64_t)bytes * 8 * RADIO_FRAMING_PERCENT / 100;
    return std::chrono::milliseconds{bits * 1000 / rate};
}

std::chrono::milliseconds RadioStepTimeout(const CService& addr)
{
    // Each of a step's three tries carries a datagram out and one back.
    return RADIO_STEP_TIMEOUT + 6 * RadioAirtime(addr, SAFE_DATAGRAM);
}

} // namespace overlay
