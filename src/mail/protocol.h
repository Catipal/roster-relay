// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIL_PROTOCOL_H
#define BITCOIN_MAIL_PROTOCOL_H

#include <mail/mailbox.h>
#include <overlay/path.h>
#include <overlay/relay.h>

#include <chrono>
#include <map>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

/**
 * How mail moves over the overlay.
 *
 * A path carries at most MAX_PATH_APP_PAYLOAD bytes a datagram and a sealed
 * letter can be thirty-five thousand, so every mail message travels as cells:
 *
 *   MAIL_CELL(1) || transfer(8) || index(2) || count(2) || up to CELL_DATA bytes
 *
 * and is put back together at the far end. Datagrams get lost, so a sender
 * that hears nothing sends the whole message again under the same transfer
 * id; the receiver keeps what it had and fills in the gaps. An answer goes
 * back under the request's id with its top bit set, so a repeated request
 * fills in a lost answer the same way.
 *
 * Inside, a message is op(1) || request id(8) || fields. Requests are what a
 * mailbox serves; answers have the top bit of op set.
 */
namespace mail {

/** First byte of mail's overlay messages. Listing requests use 0x01 and 0x02. */
static constexpr uint8_t MAIL_CELL = 0x10;
static constexpr size_t CELL_HEADER_SIZE = 1 + 8 + 2 + 2;
static constexpr size_t CELL_DATA = overlay::MAX_PATH_APP_PAYLOAD - CELL_HEADER_SIZE;
/** Enough cells for the largest answer: a letter and its id. */
static constexpr size_t MAX_CELLS = 64;
static constexpr size_t MAX_MESSAGE_SIZE = CELL_DATA * MAX_CELLS;
static_assert(MAX_MESSAGE_SIZE >= MAX_ENVELOPE_SIZE + 64, "a letter must fit in one message");

/** The top bit of a transfer id marks it as an answer. */
static constexpr uint64_t ANSWER_BIT = uint64_t{1} << 63;

enum class Op : uint8_t {
    PUT_KEY = 0x01, //!< req || mail key: keep this as my current key
    GET_KEY = 0x02, //!< req || owner: whose key do you hold
    DEPOSIT = 0x03, //!< req || sealed letter
    LIST = 0x04,    //!< req || auth: what do you hold for me
    FETCH = 0x05,   //!< req || auth || id
    REMOVE = 0x06,  //!< req || auth || n(1) || ids: I have these now

    RESULT = 0x81,  //!< req || ok(1) || text
    KEY = 0x82,     //!< req || mail key
    ITEMS = 0x83,   //!< req || n(2) || (id(32) size(4) received(8))*
    ITEM = 0x84,    //!< req || id(32) || sealed letter
};

struct Message {
    Op op{Op::RESULT};
    uint64_t req{0};
    std::vector<unsigned char> body;
};

std::vector<unsigned char> EncodeMessage(const Message& msg);
bool DecodeMessage(const std::vector<unsigned char>& raw, Message& out);

/** A RESULT answer. */
Message Result(uint64_t req, bool ok, const std::string& text = std::string());
/** Read a RESULT answer. Text from a stranger is cleaned for display. */
bool ReadResult(const Message& msg, bool& ok_out, std::string& text_out);

bool IsMailPayload(const std::vector<unsigned char>& payload);

/** A message as the cells that carry it. Empty when it is too large. */
std::vector<std::vector<unsigned char>> SplitCells(uint64_t transfer,
                                                   const std::vector<unsigned char>& message);

/** Puts messages back together from their cells. Not thread safe. */
class Reassembler
{
public:
    /** Seconds a partial message is kept for its missing cells. */
    static constexpr int64_t TTL = 60;
    /** Bounds, because sending cells is something strangers do. */
    static constexpr size_t MAX_TRANSFERS = 256;
    static constexpr size_t MAX_BUFFERED = 8 * 1024 * 1024;

    /**
     * Add one cell. True when it completed a message, which is then in
     * `message_out` with its transfer id in `transfer_out`.
     */
    bool Add(const overlay::Hop& from, const std::vector<unsigned char>& cell, int64_t now,
             std::vector<unsigned char>& message_out, uint64_t& transfer_out);

    size_t Pending() const { return m_partial.size(); }

private:
    struct Partial {
        std::vector<std::vector<unsigned char>> cells;
        size_t have{0};
        size_t bytes{0};
        int64_t started{0};
    };
    void Expire(int64_t now);
    void Drop(std::map<std::pair<overlay::Hop, uint64_t>, Partial>::iterator it);

    std::map<std::pair<overlay::Hop, uint64_t>, Partial> m_partial;
    size_t m_bytes{0};
};

/**
 * A mailbox's answer to one request. Separate from the network so that it can
 * be tested without one, and so that a node that is itself one of the
 * mailboxes it needs can ask itself directly.
 */
Message Serve(Mailbox& box, const Message& request, int64_t now);

/** Overlay application data that starts with MAIL_CELL. */
void HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload);

/**
 * Send `request` to `to` and wait for the answer.
 *
 * Retries twice inside `timeout`, resending under the same transfer id so
 * nothing already delivered is wasted. False with `error` set when nothing
 * came back.
 */
bool Ask(const overlay::Hop& to, Message request, Message& answer, std::chrono::milliseconds timeout,
         std::string& error);

/** Make every Ask in progress, and every later one, give up at once. For shutdown. */
void InterruptAsks();

} // namespace mail

#endif // BITCOIN_MAIL_PROTOCOL_H
