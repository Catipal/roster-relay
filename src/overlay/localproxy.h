// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_LOCALPROXY_H
#define BITCOIN_OVERLAY_LOCALPROXY_H

#include <compat.h>
#include <overlay/ippacket.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

struct tcp_pcb;
struct pbuf;

/**
 * The local proxy: how programs on this computer use the network's internet
 * without the system-wide interface (design note §8·7, §11·6).
 *
 * A SOCKS5 proxy, listening on 127.0.0.1 only, run by the node itself - part
 * of BPS Relay, not a program of its own. A browser or any program that can
 * use a SOCKS proxy asks it for a host and port; the proxy opens the
 * connection in the node's own TCP/IP stack, whose packets go to a gateway
 * across a meeting (overlay/gatewayclient.h), each connection to the next
 * gateway in turn.
 *
 * Names are never looked up on this computer: a name is sent to a gateway
 * and looked up there, so this computer's own resolver and its provider see
 * nothing. A .bps or .onion name, or one that only means something on a home
 * network, is never sent out at all: it is refused here, so no gateway learns
 * which hidden site someone wanted.
 *
 * CONNECT only, no authentication: the listener is on loopback, and anything
 * that can reach it is already a program on this computer.
 */
namespace overlay {

class GatewayClient;

/** -gatewayproxy: run the local proxy (on in BPS Relay, off in bitcoin-posd). */
static const bool DEFAULT_GATEWAY_PROXY = false;

class LocalProxy
{
public:
    static constexpr size_t MAX_SESSIONS = 256;
    static constexpr int64_t HANDSHAKE_TIMEOUT_MS = 10 * 1000;
    static constexpr int64_t CONNECT_TIMEOUT_MS = 30 * 1000;
    /** Bytes held for a connection in either direction before reading stops. */
    static constexpr size_t MAX_BUFFER = 256 * 1024;

    LocalProxy(GatewayClient& client, uint16_t port);
    ~LocalProxy();

    /** Needs the stack and the client running. */
    bool Start(std::string& error);
    void Stop();
    uint16_t Port() const { return m_port; }
    size_t Sessions() const { return m_session_count; }
    uint64_t Served() const { return m_served; }

    // From the stack's C callbacks. Stack thread only.
    int8_t OnConnected(uint64_t id, int8_t err);
    int8_t OnRecv(uint64_t id, struct tcp_pcb* pcb, struct pbuf* p);
    int8_t OnSent(uint64_t id);
    void OnError(uint64_t id, int8_t err);

private:
    enum class Stage { GREETING, REQUEST, RESOLVING, CONNECTING, RELAY };
    struct Session {
        uint64_t id{0};
        SOCKET sock{INVALID_SOCKET};
        Stage stage{Stage::GREETING};
        std::vector<uint8_t> in;  //!< from the program: handshake, then bytes for the site
        std::vector<uint8_t> out; //!< to the program
        size_t ours{0};           //!< bytes at the front of `out` the proxy wrote itself
        struct tcp_pcb* pcb{nullptr};
        IpAddr dst;
        uint16_t dst_port{0};
        uint16_t local_port{0};
        uint64_t path{0};
        bool flow{false};
        bool local_eof{false};
        bool remote_eof{false};
        bool remote_shut{false};
        bool local_shut{false};
        bool closing{false};
        int64_t deadline{0};
    };

    void OnListen();
    void OnSocket(uint64_t id, bool readable, bool writable, bool failed);
    /** Act on the handshake bytes read so far. False if the session ended. */
    bool Handshake(Session& s);
    void Connect(Session& s);
    void Reply(Session& s, uint8_t code);
    /** Move bytes both ways as far as they will go. */
    void Pump(uint64_t id);
    void UpdateInterest(const Session& s);
    void Close(Session& s);
    void OnGatewayGone(uint64_t path);
    void Tick();

    GatewayClient& m_client;
    const uint16_t m_port;
    SOCKET m_listen{INVALID_SOCKET};
    int m_tick{0};
    uint64_t m_next_id{0};
    std::map<uint64_t, Session> m_sessions;
    std::atomic<size_t> m_session_count{0};
    std::atomic<uint64_t> m_served{0};
};

/** The running proxy, or null. */
extern std::unique_ptr<LocalProxy> g_local_proxy;

} // namespace overlay

#endif // BITCOIN_OVERLAY_LOCALPROXY_H
