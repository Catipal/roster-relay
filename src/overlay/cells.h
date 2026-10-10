// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_CELLS_H
#define BITCOIN_OVERLAY_CELLS_H

#include <overlay/path.h>
#include <overlay/relay.h>
#include <sync.h>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

/**
 * Messages larger than a datagram, asked and answered over the overlay.
 *
 * A path carries at most MAX_PATH_APP_PAYLOAD bytes a datagram, so a service's
 * messages travel as cells:
 *
 *   tag(1) || transfer(8) || index(2) || count(2) || up to CELL_DATA bytes
 *
 * and are put back together at the far end. The tag says which service a cell
 * is for - mail is 0x10, the companion 0x11; listing requests, which predate
 * this, use 0x01 and 0x02. Datagrams get lost, so a sender that hears nothing
 * sends the whole message again under the same transfer id; the receiver keeps
 * what it had and fills in the gaps. An answer goes back under the request's
 * transfer id with its top bit set, so a repeated request fills in a lost
 * answer the same way.
 *
 * Inside, a message is op(1) || request id(8) || body. Answers have the top bit
 * of op set and are matched to the Ask waiting for them by request id.
 *
 * Mail was the first user. Sharing this changed none of its bytes on the wire.
 */
namespace overlay {

static constexpr size_t CELL_HEADER_SIZE = 1 + 8 + 2 + 2;
static constexpr size_t CELL_DATA = MAX_PATH_APP_PAYLOAD - CELL_HEADER_SIZE;
/** Enough cells for mail's largest answer, a letter and its id. */
static constexpr size_t MAX_CELLS = 64;
static constexpr size_t MAX_CELL_MESSAGE_SIZE = CELL_DATA * MAX_CELLS;
/** op(1) || request id(8), at the front of every message. */
static constexpr size_t CELL_MESSAGE_HEADER = 1 + 8;
/** The top bit of a transfer id marks it as an answer. */
static constexpr uint64_t ANSWER_BIT = uint64_t{1} << 63;

/** A message as the cells that carry it. Empty when it is too large. */
std::vector<std::vector<unsigned char>> SplitCells(uint8_t tag, uint64_t transfer,
                                                   const std::vector<unsigned char>& message);

/** Puts messages back together from their cells. Not thread safe. */
class CellReassembler
{
public:
    /** Seconds a partial message is kept for its missing cells. */
    static constexpr int64_t TTL = 60;
    /** Bounds, because sending cells is something strangers do. */
    static constexpr size_t MAX_TRANSFERS = 256;
    static constexpr size_t MAX_BUFFERED = 8 * 1024 * 1024;

    explicit CellReassembler(uint8_t tag) : m_tag(tag) {}

    /**
     * Add one cell. True when it completed a message, which is then in
     * `message_out` with its transfer id in `transfer_out`.
     */
    bool Add(const Hop& from, const std::vector<unsigned char>& cell, int64_t now,
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
    void Drop(std::map<std::pair<Hop, uint64_t>, Partial>::iterator it);

    const uint8_t m_tag;
    std::map<std::pair<Hop, uint64_t>, Partial> m_partial;
    size_t m_bytes{0};
};

/**
 * One service's side of the cells: it serves requests that arrive under its
 * tag and asks requests of others.
 *
 * Serving may finish later, on another thread: the server is handed a Request
 * and calls Answer once it has one. Until then repeats of that request are
 * dropped rather than served again, and once answered a repeat gets the same
 * answer back - which for a signed request means it is not refused as a replay,
 * and for one that spends means it does not spend twice.
 */
class CellChannel
{
public:
    /** Puts one cell on the wire towards `to`. */
    using Sender = std::function<bool(const Hop& to, const std::vector<unsigned char>& cell)>;
    /** Whether an op byte means anything to this service. Unknown ones are dropped. */
    using OpCheck = std::function<bool(uint8_t op)>;

    struct Request {
        Hop from;
        uint64_t transfer{0};
        std::vector<unsigned char> message; //!< op || request id || body
        int64_t received{0};
    };
    using Server = std::function<void(Request&& request)>;

    /** Answers kept for repeats, by count, bytes and age. */
    static constexpr int64_t GIVEN_TTL = 120;
    static constexpr size_t MAX_GIVEN = 256;
    static constexpr size_t MAX_GIVEN_BYTES = 4 * 1024 * 1024;
    /** Requests handed to the server and not yet answered. */
    static constexpr size_t MAX_IN_FLIGHT = 64;

    CellChannel(uint8_t tag, Sender sender, OpCheck known_op, Server server = Server());

    void SetServer(Server server);

    bool IsOurs(const std::vector<unsigned char>& payload) const { return !payload.empty() && payload[0] == m_tag; }

    /** Overlay application data. Ignored unless it starts with this channel's tag. */
    void Handle(const Hop& from, std::vector<unsigned char>&& payload);

    /** Answer a request the server was handed. */
    void Answer(const Hop& to, uint64_t transfer, const std::vector<unsigned char>& answer);

    /**
     * Send `request` (op || anything || body; the request id is filled in here)
     * to `to` and wait for the answer.
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
    bool Ask(const Hop& to, std::vector<unsigned char> request, std::vector<unsigned char>& answer,
             std::chrono::milliseconds timeout, std::string& error,
             std::chrono::milliseconds per_cell = std::chrono::milliseconds{0});

    /** Make every Ask in progress, and every later one, give up at once. For shutdown. */
    void Interrupt();

    size_t InFlight() const;

private:
    bool SendCells(const Hop& to, uint64_t transfer, const std::vector<unsigned char>& message);
    void ExpireGiven(int64_t now) EXCLUSIVE_LOCKS_REQUIRED(m_given_mutex);

    const uint8_t m_tag;
    const Sender m_sender;
    const OpCheck m_known_op;

    mutable Mutex m_server_mutex;
    Server m_server GUARDED_BY(m_server_mutex);

    Mutex m_cells_mutex;
    CellReassembler m_reassembler GUARDED_BY(m_cells_mutex);

    struct Waiting {
        bool done{false};
        std::vector<unsigned char> answer;
        //! When the last cell of the answer arrived, so a long answer still
        //! coming in is not mistaken for a lost one.
        std::chrono::steady_clock::time_point progress{};
    };
    Mutex m_wait_mutex;
    std::condition_variable m_wait_cv;
    std::map<uint64_t, Waiting> m_waiting GUARDED_BY(m_wait_mutex);
    /** The request each transfer an Ask is waiting on carries. */
    std::map<uint64_t, uint64_t> m_transfers GUARDED_BY(m_wait_mutex);
    bool m_interrupted GUARDED_BY(m_wait_mutex){false};

    struct Given {
        int64_t at{0};
        std::vector<unsigned char> message;
    };
    mutable Mutex m_given_mutex;
    std::map<std::pair<Hop, uint64_t>, Given> m_given GUARDED_BY(m_given_mutex);
    size_t m_given_bytes GUARDED_BY(m_given_mutex){0};
    std::map<std::pair<Hop, uint64_t>, int64_t> m_in_flight GUARDED_BY(m_given_mutex);
};

/**
 * A Sender over `relay`, looked up at each send so that it may come and go:
 * end-to-end for a path, plain for an adjacent peer.
 */
CellChannel::Sender RelaySender(std::function<Relay*()> relay);

} // namespace overlay

#endif // BITCOIN_OVERLAY_CELLS_H
