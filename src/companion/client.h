// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_CLIENT_H
#define BITCOIN_COMPANION_CLIENT_H

#include <companion/protocol.h>
#include <key.h>
#include <overlay/cells.h>
#include <overlay/relay.h>
#include <roster/record.h>
#include <sync.h>

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <vector>

/**
 * A phone's side of the companion: one device key, one home node, and the
 * relays to reach it through. No chain, no wallet, no roster: everything it
 * knows about the network its home node told it.
 *
 * Each time it is asked something with no path open, it builds one - three
 * relays it picks itself, then the home node - and proves its device key at
 * the end and nowhere else. It never carries anyone's traffic.
 */
namespace companion {

/** The home node, as a phone remembers it between runs. */
struct Home {
    std::string network;
    CPubKey node;
    std::string node_addr;
    std::vector<RelayEntry> relays;
};

class Client
{
public:
    /** `local_relays` counts each 127.0.0.1 port as its own operator: regtest only. */
    Client(const CKey& device, bool local_relays = false);
    ~Client();

    /** Open a UDP socket of its own and start listening for answers. */
    bool Start(std::string& error);
    void Stop();

    void SetHome(const Home& home);
    Home GetHome();
    const CKey& Device() const { return m_device; }

    /**
     * Ask the home node and wait for its answer, building a path first if
     * none is open, and once more if the one open has stopped answering.
     */
    bool Ask(const Message& request, Message& answer, std::string& error,
             std::chrono::milliseconds timeout = std::chrono::seconds{15});

    bool Pair(const uint256& token, const std::string& name, const std::string& pin, std::string& error);
    bool PairStatus(const uint256& token, PairStateAnswer& out, std::string& error);
    bool Status(StatusAnswer& out, std::string& error);
    bool Address(std::string& out, std::string& error);
    bool History(size_t skip, size_t count, std::vector<HistoryItem>& out, std::string& error);
    bool Prepare(const std::string& to, CAmount amount, bool subtract_fee, PrepareAnswer& out, std::string& error);
    /** Send what was prepared, signed with the device key. */
    bool Send(const PrepareAnswer& prepared, const std::string& pin, uint256& txid, std::string& error);
    bool Cancel(const uint256& prepare_id, std::string& error);
    /** Replace the relays with the home node's current list. */
    bool RefreshRelays(std::string& error);
    bool SetPin(const std::string& old_pin, const std::string& new_pin, std::string& error);
    bool Unpair(std::string& error);

    /** The circuit open now, or 0. */
    uint64_t PathId();

private:
    bool Connect(std::string& error);
    void Disconnect();
    /** Ask, and read the answer as `expected` - or as a RESULT, whose text becomes `error`. */
    template <typename T>
    bool Exchange(const Message& request, Op expected, T& out, std::string& error);
    bool ExchangeResult(const Message& request, std::string& error);

    const CKey m_device;
    const bool m_local_relays;
    std::unique_ptr<overlay::Relay> m_relay;
    std::unique_ptr<overlay::CellChannel> m_channel;

    /** Seconds a relay that failed a path is left out of new ones. */
    static constexpr int64_t SHUN_SECONDS = 600;

    Mutex m_mutex;
    Home m_home GUARDED_BY(m_mutex);
    uint64_t m_path GUARDED_BY(m_mutex){0};
    std::vector<uint64_t> m_legs GUARDED_BY(m_mutex);
    std::map<roster::KeyBytes, int64_t> m_shunned GUARDED_BY(m_mutex);
};

} // namespace companion

#endif // BITCOIN_COMPANION_CLIENT_H
