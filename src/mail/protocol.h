// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIL_PROTOCOL_H
#define BITCOIN_MAIL_PROTOCOL_H

#include <mail/mailbox.h>
#include <overlay/cells.h>
#include <overlay/path.h>
#include <overlay/relay.h>

#include <chrono>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * How mail moves over the overlay.
 *
 * A path carries at most MAX_PATH_APP_PAYLOAD bytes a datagram and a sealed
 * letter can be thirty-five thousand, so every mail message travels as cells
 * tagged MAIL_CELL (overlay/cells.h) and is put back together at the far end.
 *
 * Inside, a message is op(1) || request id(8) || fields. Requests are what a
 * mailbox serves; answers have the top bit of op set.
 */
namespace mail {

/** First byte of mail's overlay messages. Listing requests use 0x01 and 0x02. */
static constexpr uint8_t MAIL_CELL = 0x10;
static constexpr size_t CELL_HEADER_SIZE = overlay::CELL_HEADER_SIZE;
static constexpr size_t CELL_DATA = overlay::CELL_DATA;
static constexpr size_t MAX_CELLS = overlay::MAX_CELLS;
static constexpr size_t MAX_MESSAGE_SIZE = overlay::MAX_CELL_MESSAGE_SIZE;
static_assert(MAX_MESSAGE_SIZE >= MAX_ENVELOPE_SIZE + 64, "a letter must fit in one message");

/** The top bit of a transfer id marks it as an answer. */
static constexpr uint64_t ANSWER_BIT = overlay::ANSWER_BIT;

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

/** Puts mail messages back together from their cells. Not thread safe. */
class Reassembler : public overlay::CellReassembler
{
public:
    Reassembler() : overlay::CellReassembler(MAIL_CELL) {}
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
 * nothing already delivered is wasted. A try does not end while cells of the
 * answer are still arriving: a long answer on a slow path is not a lost one.
 * False with `error` set when nothing came back.
 *
 * `per_cell` is how long one cell takes on a radio hop the path starts with,
 * zero otherwise; each try then also waits for the request's cells to go out
 * and the answer's first to come back.
 */
bool Ask(const overlay::Hop& to, Message request, Message& answer, std::chrono::milliseconds timeout,
         std::string& error, std::chrono::milliseconds per_cell = std::chrono::milliseconds{0});

/** Make every Ask in progress, and every later one, give up at once. For shutdown. */
void InterruptAsks();

} // namespace mail

#endif // BITCOIN_MAIL_PROTOCOL_H
