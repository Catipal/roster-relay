// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_PROTOCOL_H
#define BITCOIN_COMPANION_PROTOCOL_H

#include <amount.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <version.h>

#include <ios>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * What a phone and its home node say to each other.
 *
 * The phone holds no coin keys. Its home node - a listed relay, always on -
 * holds a small allowance wallet and spends from it when the phone asks,
 * within limits the phone cannot change, after checking a PIN the phone cannot
 * check for itself. The phone holds one device key, made on the phone, which
 * it proves to the home node at the end of a three-hop path and nowhere else.
 *
 * Messages travel as overlay cells tagged COMPANION_CELL (overlay/cells.h) and
 * are op(1) || request id(8) || body, the body serialized as below. This file
 * has no node in it: the phone links it as it is.
 */
namespace companion {

static constexpr uint8_t COMPANION_CELL = 0x11;

/** Bounds on what a stranger can make the other side read. */
static constexpr size_t MAX_DEVICE_NAME = 32;
static constexpr size_t MAX_PIN = 12;
static constexpr size_t MIN_PIN = 6;
static constexpr size_t MAX_DESTINATION = 100;
static constexpr size_t MAX_RESULT_TEXT = 200;
static constexpr size_t MAX_RELAYS = 30;
/** Relays in a pairing ticket: enough to build the first path, small enough for a QR code. */
static constexpr size_t TICKET_RELAYS = 8;
static constexpr size_t MAX_HISTORY = 10;

enum class Op : uint8_t {
    PAIR = 0x01,        //!< PairRequest: here is the ticket's token; this device wants pairing
    PAIR_STATUS = 0x02, //!< PairStatusRequest: has my pairing been accepted?
    STATUS = 0x03,      //!< (empty): balance and what is left of today's limit
    ADDRESS = 0x04,     //!< (empty): an address to be paid at
    HISTORY = 0x05,     //!< HistoryRequest
    PREPARE = 0x06,     //!< PrepareRequest: build this payment, do not send it
    SEND = 0x07,        //!< SendRequest: send what was prepared
    CANCEL = 0x08,      //!< CancelRequest
    RELAYS = 0x09,      //!< (empty): relays to build the next path through
    SET_PIN = 0x0a,     //!< SetPinRequest
    UNPAIR = 0x0b,      //!< (empty): forget this device

    RESULT = 0x81,        //!< ResultAnswer
    PAIR_STATE = 0x82,    //!< PairStateAnswer
    STATUS_INFO = 0x83,   //!< StatusAnswer
    ADDRESS_INFO = 0x84,  //!< AddressAnswer
    HISTORY_ITEMS = 0x85, //!< HistoryAnswer
    PREPARED = 0x86,      //!< PrepareAnswer
    SENT = 0x87,          //!< SendAnswer
    RELAY_LIST = 0x88,    //!< RelaysAnswer
};

bool KnownOp(uint8_t raw);
inline bool IsAnswer(Op op) { return static_cast<uint8_t>(op) & 0x80; }

struct Message {
    Op op{Op::RESULT};
    uint64_t req{0};
    std::vector<unsigned char> body;
};

std::vector<unsigned char> EncodeMessage(const Message& msg);
bool DecodeMessage(const std::vector<unsigned char>& raw, Message& out);

/** A message whose body is `body` serialized. */
template <typename T>
Message Make(Op op, uint64_t req, const T& body)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << body;
    Message m;
    m.op = op;
    m.req = req;
    m.body.assign(s.begin(), s.end());
    return m;
}

/** Read a body. False when the op is not the one expected, or the body is not exactly one T. */
template <typename T>
bool Read(const Message& msg, Op expected, T& out)
{
    if (msg.op != expected) return false;
    try {
        CDataStream s(msg.body, SER_NETWORK, PROTOCOL_VERSION);
        s >> out;
        return s.empty();
    } catch (const std::ios_base::failure&) {
        return false;
    }
}

struct ResultAnswer {
    bool ok{false};
    std::string text;
    SERIALIZE_METHODS(ResultAnswer, obj) { READWRITE(obj.ok, LIMITED_STRING(obj.text, MAX_RESULT_TEXT)); }
};
Message Result(uint64_t req, bool ok, const std::string& text = std::string());

struct PairRequest {
    uint256 token;
    std::string name;
    std::string pin;
    SERIALIZE_METHODS(PairRequest, obj)
    {
        READWRITE(obj.token, LIMITED_STRING(obj.name, MAX_DEVICE_NAME), LIMITED_STRING(obj.pin, MAX_PIN));
    }
};

struct PairStatusRequest {
    uint256 token;
    SERIALIZE_METHODS(PairStatusRequest, obj) { READWRITE(obj.token); }
};

enum class PairState : uint8_t {
    WAITING = 0,  //!< the phone has asked; nobody has accepted on the home node yet
    ACCEPTED = 1, //!< paired
    REJECTED = 2,
    EXPIRED = 3,
    UNKNOWN = 4, //!< no such pairing, or not this device's
};

struct PairStateAnswer {
    uint8_t state{static_cast<uint8_t>(PairState::UNKNOWN)};
    CAmount per_tx{0};  //!< limits set on acceptance
    CAmount per_day{0};
    SERIALIZE_METHODS(PairStateAnswer, obj) { READWRITE(obj.state, obj.per_tx, obj.per_day); }
};

struct StatusAnswer {
    CAmount balance{0}; //!< confirmed, spendable
    CAmount pending{0}; //!< not yet confirmed
    CAmount per_tx{0};
    CAmount per_day{0};
    CAmount spent_today{0}; //!< inside the last 24 hours, fees included
    int32_t height{0};
    bool locked{false}; //!< too many wrong PINs: only the home node can unlock it
    SERIALIZE_METHODS(StatusAnswer, obj)
    {
        READWRITE(obj.balance, obj.pending, obj.per_tx, obj.per_day, obj.spent_today, obj.height, obj.locked);
    }
};

struct AddressAnswer {
    std::string address;
    SERIALIZE_METHODS(AddressAnswer, obj) { READWRITE(LIMITED_STRING(obj.address, MAX_DESTINATION)); }
};

struct HistoryRequest {
    uint16_t skip{0};
    uint8_t count{MAX_HISTORY};
    SERIALIZE_METHODS(HistoryRequest, obj) { READWRITE(obj.skip, obj.count); }
};

struct HistoryItem {
    uint256 txid;
    CAmount amount{0}; //!< into the allowance wallet if positive, out of it if negative
    CAmount fee{0};
    int64_t time{0};
    int32_t confirmations{0};
    std::string counterparty; //!< the address or name paid, when known
    SERIALIZE_METHODS(HistoryItem, obj)
    {
        READWRITE(obj.txid, obj.amount, obj.fee, obj.time, obj.confirmations,
                  LIMITED_STRING(obj.counterparty, MAX_DESTINATION));
    }
};

struct HistoryAnswer {
    std::vector<HistoryItem> items;
    SERIALIZE_METHODS(HistoryAnswer, obj) { READWRITE(obj.items); }
};

struct PrepareRequest {
    std::string to; //!< an address, or a BPS name
    CAmount amount{0};
    bool subtract_fee{false};
    SERIALIZE_METHODS(PrepareRequest, obj)
    {
        READWRITE(LIMITED_STRING(obj.to, MAX_DESTINATION), obj.amount, obj.subtract_fee);
    }
};

struct PrepareAnswer {
    uint256 prepare_id;
    CAmount amount{0}; //!< what the payee receives
    CAmount fee{0};
    CScript payee_script;
    std::string payee; //!< the address that will be paid, resolved from a name if one was given
    int64_t expires{0};
    SERIALIZE_METHODS(PrepareAnswer, obj)
    {
        READWRITE(obj.prepare_id, obj.amount, obj.fee, obj.payee_script, LIMITED_STRING(obj.payee, MAX_DESTINATION),
                  obj.expires);
    }
};

struct SendRequest {
    uint256 prepare_id;
    std::string pin;
    std::vector<unsigned char> signature; //!< the device key's, over SendDigest
    SERIALIZE_METHODS(SendRequest, obj) { READWRITE(obj.prepare_id, LIMITED_STRING(obj.pin, MAX_PIN), obj.signature); }
};

struct SendAnswer {
    uint256 txid;
    SERIALIZE_METHODS(SendAnswer, obj) { READWRITE(obj.txid); }
};

struct CancelRequest {
    uint256 prepare_id;
    SERIALIZE_METHODS(CancelRequest, obj) { READWRITE(obj.prepare_id); }
};

struct SetPinRequest {
    std::string old_pin;
    std::string new_pin;
    SERIALIZE_METHODS(SetPinRequest, obj)
    {
        READWRITE(LIMITED_STRING(obj.old_pin, MAX_PIN), LIMITED_STRING(obj.new_pin, MAX_PIN));
    }
};

/** A relay a phone can build a path through: its key, and where its overlay listens. */
struct RelayEntry {
    CPubKey key;
    std::string addr; //!< "host:port"
    SERIALIZE_METHODS(RelayEntry, obj) { READWRITE(obj.key, LIMITED_STRING(obj.addr, 64)); }
};

struct RelaysAnswer {
    std::vector<RelayEntry> relays;
    SERIALIZE_METHODS(RelaysAnswer, obj) { READWRITE(obj.relays); }
};

/**
 * Everything a phone needs to find its home node the first time, shown on the
 * home node's screen as a QR code or a code to paste.
 */
/** Room in a ticket for the home node's addresses: six IPv4 ones, or a few IPv6. */
static constexpr size_t MAX_NODE_ADDR = 160;

struct PairingTicket {
    uint8_t version{1};
    std::string network; //!< "main", "test", "regtest" or "signet"
    CPubKey node;        //!< the home relay's key: the end of every path
    std::string node_addr; //!< where the home node's overlay listens: one or more addresses, comma separated, best first
    uint256 token; //!< single use, and only until `expires`
    int64_t expires{0};
    std::vector<RelayEntry> relays;
    SERIALIZE_METHODS(PairingTicket, obj)
    {
        READWRITE(obj.version, LIMITED_STRING(obj.network, 16), obj.node, LIMITED_STRING(obj.node_addr, MAX_NODE_ADDR), obj.token,
                  obj.expires, obj.relays);
    }
};

/** Prefix of a ticket's text form. Upper case, so a QR code can use its compact alphanumeric mode. */
static constexpr const char* TICKET_PREFIX = "BPSC1:";

std::string EncodeTicket(const PairingTicket& ticket);
bool DecodeTicket(const std::string& text, PairingTicket& out, std::string& error);

/**
 * The six digits both screens show while pairing. If they differ, whoever
 * answered the ticket was not this phone - someone who saw the code first.
 */
std::string PairingCode(const uint256& token, const CPubKey& device, const CPubKey& node);

/**
 * What the device key signs to send a prepared payment: the payment itself,
 * bound to this home node, so the signature means nothing anywhere else.
 */
uint256 SendDigest(const CPubKey& node, const uint256& prepare_id, const CScript& payee, CAmount amount, CAmount fee);

/** Six to twelve digits. */
bool ValidPin(const std::string& pin);

} // namespace companion

#endif // BITCOIN_COMPANION_PROTOCOL_H
