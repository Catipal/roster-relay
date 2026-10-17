// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SYSIF_H
#define BITCOIN_OVERLAY_SYSIF_H

#include <overlay/dnsanswer.h>
#include <overlay/ippacket.h>

#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

/**
 * The system-wide interface: all of a computer's traffic through the
 * network's gateways (design note §8·7).
 *
 * The operating system sends its packets to a network interface of BPS
 * Relay's - the kernel's TUN device on Linux - as it would to any network,
 * and they go to the gateways as they are: "packets, not connections". Each
 * new connection goes to the next open gateway that carries its port, as
 * the local proxy's do, and stays with it. TCP runs from the computer's own
 * programs to the gateway, which opens its own connection to the site.
 *
 * What comes back is let in only for a connection the computer opened, from
 * the gateway that connection went to: a gateway is a stranger, and the
 * interface is a door into the computer.
 *
 * The interface answers name lookups at its own resolver address
 * (InterfaceResolver), and any lookup sent through it to another resolver
 * too: a name is looked up at a gateway, never by the computer, and a .bps,
 * .onion or home-network name is never sent anywhere (overlay/dnsanswer.h).
 *
 * Packets from the computer wait in a short queue per gateway and leave no
 * faster than the relays on the way will carry them (PACE_SHARE of their
 * per-path cap), so the computer's own TCP sees a slow link rather than
 * losses at every relay. A full queue drops, as a router's does.
 *
 * Setting the interface up - its addresses, routes and the computer's
 * resolver - needs an administrator, once; that is outside this class. Here
 * the device is opened by name and served.
 */
namespace overlay {

class GatewayClient;

/** The computer's side of the interface: something that carries its IP packets. */
class PacketDevice
{
public:
    using Receive = std::function<void(std::vector<uint8_t>&& pkt)>;
    virtual ~PacketDevice() {}
    /** Stack thread. Open the device and hand what the computer sends to `receive`, on the stack thread. */
    virtual bool Start(Receive receive, std::string& error) = 0;
    /** Stack thread. */
    virtual void Stop() = 0;
    /** Stack thread. One packet to the computer. */
    virtual bool Write(const std::vector<uint8_t>& pkt) = 0;
    virtual std::string Name() const = 0;
};

/**
 * The interface. On Linux the TUN device `name`: made once by an
 * administrator for the user BPS Relay runs as (ip tuntap add dev bps0 mode
 * tun user ...) and opened with no rights of BPS Relay's own, or made by the
 * node itself when it may manage the network. On Windows the Wintun adapter
 * of BPS Relay's network service, reached over its pipe (overlay/netservice.h);
 * with `route_computer` the service also routes the whole computer through
 * it. Null where there is no such device yet.
 */
std::unique_ptr<PacketDevice> MakeTunDevice(const std::string& name, bool route_computer = false);

/** The computer's addresses on the interface, and the resolver it is told to ask. */
IpAddr InterfaceAddress(uint8_t version);
IpAddr InterfaceResolver(uint8_t version);

/** The largest packet the interface takes: two overlay datagrams' worth (§8·7). */
static constexpr size_t INTERFACE_MTU = MAX_GATEWAY_PACKET;

class SystemInterface
{
public:
    /** Bytes waiting for one gateway before the next packet is dropped. */
    static constexpr size_t MAX_QUEUE_BYTES = 128 * 1024;
    /** Connections open at once through the interface. */
    static constexpr size_t MAX_FLOWS = 2048;
    static constexpr int64_t TCP_IDLE_MS = 15 * 60 * 1000;
    static constexpr int64_t TCP_CLOSED_MS = 15 * 1000;
    static constexpr int64_t UDP_IDLE_MS = 2 * 60 * 1000;
    /** Lookups waiting at gateways at once. */
    static constexpr size_t MAX_LOOKUPS = 64;
    static constexpr size_t MAX_CACHED_NAMES = 1024;

    SystemInterface(GatewayClient& client, std::unique_ptr<PacketDevice> device);
    ~SystemInterface();

    /** Needs the client started. */
    bool Start(std::string& error);
    void Stop();

    struct Stats {
        std::string device;
        bool running{false};
        uint64_t flows{0};
        uint64_t packets_out{0}, packets_in{0};
        uint64_t bytes_out{0}, bytes_in{0};
        uint64_t refused{0};      //!< connections no gateway would take, or not to be sent
        uint64_t dropped{0};      //!< packets dropped: queue full, unreadable, or not for a connection here
        uint64_t lookups{0};      //!< names asked of the interface's resolver
        uint64_t kept_local{0};   //!< of those, names never sent out
    };
    Stats GetStats() const;

    // Stack thread. Public for tests.
    void FromComputer(std::vector<uint8_t>&& pkt);
    void FromGateway(uint64_t path, std::vector<uint8_t>&& pkt);
    void Tick();

private:
    //! protocol, the computer's address and port, the far address and port
    using FlowKey = std::tuple<uint8_t, IpAddr, uint16_t, IpAddr, uint16_t>;
    struct Flow {
        uint64_t path{0};
        int64_t last{0};
        PacketInfo last_out;     //!< TCP: the computer's last segment, for a reset that it accepts
        bool fin_out{false}, fin_in{false};
        int64_t closed_at{0};
    };
    struct Queue {
        std::deque<std::vector<uint8_t>> packets;
        size_t bytes{0};
    };
    struct Cached {
        DnsRcode rcode{DnsRcode::OK};
        std::vector<IpAddr> addrs;
        uint32_t ttl{0};
        int64_t until{0};
    };

    void ToComputer(const std::vector<uint8_t>& pkt);
    void Refuse(const PacketInfo& info);
    void Send(uint64_t path, std::vector<uint8_t>&& pkt);
    void RemoveFlow(std::map<FlowKey, Flow>::iterator it);
    void OnGatewayGone(uint64_t path);
    void Lookup(const PacketInfo& info, const std::vector<uint8_t>& pkt);
    void AnswerLookup(const PacketInfo& info, const DnsQuery& q, DnsRcode rcode, const std::vector<IpAddr>& addrs,
                      uint32_t ttl);

    GatewayClient& m_client;
    std::unique_ptr<PacketDevice> m_device;
    std::atomic<bool> m_running{false};

    // Stack thread only.
    int m_tick{0};
    int m_gone{0};
    std::map<FlowKey, Flow> m_flows;
    std::map<uint64_t, Queue> m_queues;
    std::map<std::pair<std::string, uint16_t>, Cached> m_cache;
    size_t m_lookups_waiting{0};
    //! Held by lookups still out at gateways; their answers are dropped once it is gone.
    std::shared_ptr<bool> m_alive;

    std::atomic<uint64_t> m_flow_count{0}, m_packets_out{0}, m_packets_in{0}, m_bytes_out{0}, m_bytes_in{0},
        m_refused{0}, m_dropped{0}, m_lookups{0}, m_kept_local{0};
};

/** The running interface, or null. */
extern std::unique_ptr<SystemInterface> g_system_interface;

} // namespace overlay

#endif // BITCOIN_OVERLAY_SYSIF_H
