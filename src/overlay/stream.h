// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_STREAM_H
#define BITCOIN_OVERLAY_STREAM_H

#include <overlay/relay.h>

#include <cstdint>
#include <deque>
#include <map>
#include <vector>

/**
 * A reliable, ordered byte stream over the overlay's datagrams (design note
 * §11·6, services).
 *
 * A path loses, reorders and now and then repeats datagrams, and a service -
 * a web application, a chat server, a game on the host's own computer - needs
 * its bytes whole and in order. So bytes go in numbered cells of one datagram
 * each; the far end says which it has, the cells below the first gap and
 * which of the next 64 (selective acknowledgement), and how many more it can
 * hold; whatever is not acknowledged in time is sent again. How many cells
 * are out at once follows the rule TCP uses and the pieces of a site use:
 * start small, grow with every acknowledgement, halve on a loss. How fast
 * they leave follows the same rule, between STREAM_MIN_RATE and
 * SERVICE_SEND_RATE: a relay drops what goes over its per-path cap, which
 * both directions of a path share and which counts every layer around a cell,
 * so the pace that fits depends on what else the path carries.
 *
 * Pure: no socket and no clock of its own. It is fed messages and the time,
 * and says what to send, so a lossy link can be tested exactly.
 */
namespace overlay {

/** Overlay application-data tags for services. */
static constexpr uint8_t SVC_OPEN = 0x38;     //!< visitor: open a stream to a named service
static constexpr uint8_t SVC_OPENED = 0x39;   //!< host: it is open
static constexpr uint8_t SVC_REFUSED = 0x3a;  //!< host: no such service, or it would not connect
static constexpr uint8_t SVC_DATA = 0x3b;     //!< one cell of bytes
static constexpr uint8_t SVC_ACK = 0x3c;      //!< what has arrived, and room for more
static constexpr uint8_t SVC_FIN = 0x3d;      //!< no bytes after this
static constexpr uint8_t SVC_RESET = 0x3e;    //!< the stream is gone

bool IsServicePayload(const std::vector<unsigned char>& payload);
/** The stream a service message is for. False when it carries none. */
bool ServiceStreamId(const std::vector<unsigned char>& payload, uint32_t& id);

//! Bytes in one cell: one datagram over a path, less the cell's header.
static constexpr size_t STREAM_CELL = MAX_PATH_APP_PAYLOAD - 9;
//! Bytes each side holds for the other: unsent or unacknowledged, and
//! received but not yet read.
static constexpr size_t STREAM_BUFFER = 256 * 1024;
//! Bytes a second one stream sends at most, under -relaypathrate; where it
//! starts; and the least it falls to after losses.
static constexpr uint64_t SERVICE_SEND_RATE = 48 * 1024;
static constexpr uint64_t STREAM_START_RATE = 16 * 1024;
static constexpr uint64_t STREAM_MIN_RATE = 4 * 1024;

class ReliableStream
{
public:
    explicit ReliableStream(uint32_t id);

    uint32_t Id() const { return m_id; }

    // --- the program's side ---------------------------------------------

    /** Take as many of `n` bytes as there is room for; how many were taken. */
    size_t Write(const unsigned char* data, size_t n);
    /** Room for more bytes to send. */
    size_t SendSpace() const;
    /** No more bytes will be written: the far end hears so once all are delivered. */
    void Shutdown();
    /** Bytes received in order, up to `max`, taken out of the stream. */
    std::vector<unsigned char> Read(size_t max);
    size_t Readable() const { return m_readbuf.size(); }
    /** The far end said it has sent all it will, and all of it has been read. */
    bool ReadClosed() const;
    /** Everything sent has been acknowledged, the end included, and the far end's end has been read. */
    bool Finished() const;
    /** Given up: a cell went unanswered too many times, or the far end reset the stream. */
    bool Dead() const { return m_dead; }

    // --- the network's side ---------------------------------------------

    /** One message from the far end: SVC_DATA, SVC_ACK, SVC_FIN or SVC_RESET for this stream. */
    void Receive(const std::vector<unsigned char>& msg, int64_t now_ms);
    /** What to send at `now_ms`: new cells, cells again, the end, acknowledgements. */
    std::vector<std::vector<unsigned char>> Poll(int64_t now_ms);
    /** When Poll has something to do next, at the latest; now when it has already. */
    int64_t NextWake(int64_t now_ms) const;

    /** A message saying this stream is gone, for when the program on either end is. */
    static std::vector<unsigned char> ResetMessage(uint32_t id);

    // For tests and getserviceinfo.
    size_t InFlight() const { return m_unacked.size(); }
    double Window() const { return m_cwnd; }
    int64_t Rto() const { return m_rto; }
    double Rate() const { return m_rate; }

    //! Cells a stream may have out at most, and starts with.
    static constexpr double MAX_WINDOW = 128;
    static constexpr double START_WINDOW = 4;
    //! Times one cell is sent before the stream gives up.
    static constexpr int MAX_TRIES = 8;
    //! Retransmission timeout before any round trip is measured, and its bounds.
    static constexpr int64_t START_RTO_MS = 3000;
    static constexpr int64_t MIN_RTO_MS = 1000;
    static constexpr int64_t MAX_RTO_MS = 30000;
    //! How long an acknowledgement may wait for a second cell to share it.
    static constexpr int64_t ACK_DELAY_MS = 40;

private:
    struct Cell {
        std::vector<unsigned char> data;
        int64_t sent_at{0};
        int tries{0};
        bool fast{false}; //!< already sent again on a selective acknowledgement
    };

    std::vector<unsigned char> DataMessage(uint32_t seq, const Cell& cell) const;
    std::vector<unsigned char> AckMessage() const;
    void OnAck(uint32_t next, uint64_t sack, uint16_t window, bool fin_seen, int64_t now_ms);
    void OnData(uint32_t seq, const unsigned char* data, size_t n, int64_t now_ms);
    void Sample(int64_t rtt_ms);
    void Lost(int64_t now_ms, bool timeout);
    bool Spend(size_t bytes, int64_t now_ms);
    uint16_t WindowToOffer() const;

    const uint32_t m_id;
    bool m_dead{false};

    // Sending.
    std::deque<unsigned char> m_sendbuf; //!< written, not yet cut into cells
    std::map<uint32_t, Cell> m_unacked;  //!< sent, not yet acknowledged
    uint32_t m_next_seq{0};              //!< the next new cell's number
    bool m_shutdown{false};
    bool m_fin_acked{false};
    int64_t m_fin_sent_at{-1};
    int m_fin_tries{0};
    double m_cwnd{START_WINDOW};
    double m_ssthresh{MAX_WINDOW};
    uint32_t m_recover{0};               //!< cells below this were out when the last loss was seen
    bool m_in_recovery{false};
    int64_t m_srtt{-1};
    int64_t m_rttvar{0};
    int64_t m_rto{START_RTO_MS};
    uint16_t m_peer_window{64};
    double m_rate{STREAM_START_RATE};    //!< bytes a second, now
    double m_tokens{0};
    int64_t m_tokens_at{-1};

    // Receiving.
    uint32_t m_rcv_next{0};                                    //!< every cell below this has come
    std::map<uint32_t, std::vector<unsigned char>> m_ooo;      //!< cells past a gap
    size_t m_ooo_bytes{0};
    std::deque<unsigned char> m_readbuf;                       //!< in order, not yet read
    bool m_peer_fin{false};
    uint32_t m_peer_end{0};
    bool m_ack_due{false};
    int64_t m_ack_at{0};
    int m_cells_since_ack{0};                                  //!< cells taken since the last acknowledgement
    uint16_t m_offered{0};                                     //!< the room the last acknowledgement offered
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_STREAM_H
