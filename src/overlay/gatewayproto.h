// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_GATEWAYPROTO_H
#define BITCOIN_OVERLAY_GATEWAYPROTO_H

#include <overlay/ippacket.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

/**
 * What a visitor and a gateway say to each other across a meeting (design
 * note §8·7). Every message is sealed end to end on the meeting path
 * (Relay::SendSecret), so the relays that carry it cannot read it, and is
 * at most MAX_PATH_APP_PAYLOAD bytes:
 *
 *   GATEWAY_TAG  kind  body
 *
 *   PACKET    one IP packet, whole
 *   FRAG      id(2) index(1) count(1) piece - a packet too big for one
 *             datagram (QUIC's are 1,200 bytes and more), in pieces
 *   RESOLVE   id(4) family(1) length(1) name - look a name up
 *   RESOLVED  id(4) status(1) ttl(4) count(1) then family(1) address
 *   STATUS    state(1) n(1) TCP ports(2 each) m(1) UDP ports(2 each)
 *   HELLO     nothing - asks for STATUS
 *
 * TCP is carried as packets, so the visitor's own stack and the gateway's
 * keep the connection reliable between them, and nothing here retransmits.
 */
namespace overlay {

/** Overlay application data tag for gateway traffic. */
static constexpr uint8_t GATEWAY_TAG = 0x13;

enum class GatewayKind : uint8_t {
    PACKET = 0x01,
    FRAG = 0x02,
    RESOLVE = 0x03,
    RESOLVED = 0x04,
    STATUS = 0x05,
    HELLO = 0x06,
};

/** Whether a gateway is taking new connections. */
enum class GatewayState : uint8_t {
    OPEN = 0,
    CLOSED_TODAY = 1, //!< its daily budget is spent
    OFF = 2,          //!< switched off, or not listed as a gateway
};

enum class ResolveStatus : uint8_t {
    OK = 0,
    NO_SUCH_NAME = 1,
    FAILED = 2,
    REFUSED = 3,
};

/** Address families a lookup asks for. */
static constexpr uint8_t RESOLVE_ANY = 0;
static constexpr uint8_t RESOLVE_V4 = 4;
static constexpr uint8_t RESOLVE_V6 = 6;

/** Longest name looked up, as DNS allows. */
static constexpr size_t MAX_RESOLVE_NAME = 253;
/** Most addresses one answer carries. */
static constexpr size_t MAX_RESOLVED = 8;
/** Pieces of one packet, at most: a 1,280-byte packet takes three. */
static constexpr uint8_t MAX_FRAGS = 4;

/** A message, decoded. Which fields mean something depends on `kind`. */
struct GatewayMessage {
    GatewayKind kind{GatewayKind::HELLO};
    std::vector<uint8_t> bytes;    //!< PACKET: the packet; FRAG: the piece
    uint16_t frag_id{0};
    uint8_t frag_index{0};
    uint8_t frag_count{0};
    uint32_t request{0};           //!< RESOLVE, RESOLVED
    uint8_t family{RESOLVE_ANY};   //!< RESOLVE
    std::string name;              //!< RESOLVE
    ResolveStatus status{ResolveStatus::OK};
    uint32_t ttl{0};
    std::vector<IpAddr> addrs;     //!< RESOLVED
    GatewayState state{GatewayState::OPEN};
    std::vector<uint16_t> tcp_ports, udp_ports; //!< STATUS
};

bool IsGatewayPayload(const std::vector<uint8_t>& payload);

/** Decode one message. False for anything malformed. */
bool DecodeGatewayMessage(const std::vector<uint8_t>& payload, GatewayMessage& out);

/**
 * A packet as the messages that carry it: one PACKET if it fits a datagram,
 * otherwise FRAGs under `frag_id`. Empty if it is too big to carry at all.
 */
std::vector<std::vector<uint8_t>> EncodePacket(const std::vector<uint8_t>& packet, uint16_t frag_id);

std::vector<uint8_t> EncodeResolve(uint32_t request, uint8_t family, const std::string& name);
std::vector<uint8_t> EncodeResolved(uint32_t request, ResolveStatus status, uint32_t ttl,
                                    const std::vector<IpAddr>& addrs);
std::vector<uint8_t> EncodeStatus(GatewayState state, const std::vector<uint16_t>& tcp_ports,
                                  const std::vector<uint16_t>& udp_ports);
std::vector<uint8_t> EncodeHello();

/** Whether `name` is a host name a gateway will look up: letters, digits, '-', '_' and dots. */
bool IsResolvableName(const std::string& name);

/**
 * Puts fragmented packets back together, per source (a meeting's path).
 *
 * Bounded, because the pieces come from strangers: a packet is let go if
 * its pieces do not all arrive within REASSEMBLY_MS, each source may have
 * MAX_PARTIAL packets in pieces at once, and pieces must agree with each
 * other about how many there are.
 */
class Reassembler
{
public:
    static constexpr int64_t REASSEMBLY_MS = 3000;
    static constexpr size_t MAX_PARTIAL = 16;

    /** Add a piece. True with the whole packet in `packet` once it is complete. */
    bool Add(uint64_t source, const GatewayMessage& frag, int64_t now_ms, std::vector<uint8_t>& packet);
    /** Forget a source's pieces, when its meeting ends. */
    void Forget(uint64_t source);
    size_t PartialCount() const { return m_partial.size(); }

private:
    struct Partial {
        uint8_t count{0};
        std::vector<std::vector<uint8_t>> pieces;
        size_t have{0};
        int64_t started{0};
    };
    void Expire(int64_t now_ms);

    std::map<std::pair<uint64_t, uint16_t>, Partial> m_partial;
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_GATEWAYPROTO_H
