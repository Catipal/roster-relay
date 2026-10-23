// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAIL_BRIDGE_H
#define BITCOIN_MAIL_BRIDGE_H

#include <compat.h>
#include <sync.h>
#include <threadinterrupt.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * A local bridge that lets an ordinary mail client - Thunderbird, Apple Mail,
 * K-9 - read and write BPS mail (design note 001 §11·5).
 *
 * It speaks POP3 (to read) and SMTP submission (to send) on the loopback
 * interface only. The node opens and seals letters itself, over the overlay,
 * exactly as its own commands do; the client only ever sees cleartext over
 * 127.0.0.1, and a letter still leaves the computer sealed to the recipient's
 * key. Nothing here speaks to the internet's mail network: "sending" hands the
 * letter to mail::g_mail, which carries it over the overlay to a roster key,
 * never to an SMTP server somewhere. A recipient is written `<name>@bps` or
 * `<64-hex-key>@bps`; the part after @ is ignored.
 *
 * It is off by default. While it is on, any program that can reach the
 * loopback port can read this node's mail and send as it, so it is for a
 * person running their own client on their own machine, not a shared host.
 */
namespace mail {

//! Off by default: it exposes decrypted mail on a local port.
static const bool DEFAULT_MAILBRIDGE = false;
//! Loopback ports the client connects to. Above 1024 so no privilege is needed.
static const uint16_t DEFAULT_MAILBRIDGE_POP3_PORT = 1100;
static const uint16_t DEFAULT_MAILBRIDGE_SMTP_PORT = 1587;

class MailBridge
{
public:
    MailBridge(uint16_t pop3_port, uint16_t smtp_port);
    ~MailBridge();

    /** Bind both loopback ports and start accepting. False with `error` on trouble. */
    bool Start(std::string& error);
    void Stop();

private:
    //! One listening socket and the thread that accepts on it.
    enum class Proto { POP3, SMTP };
    struct Listener {
        Listener(Proto p, uint16_t pt) : proto(p), port(pt) {}
        Proto proto;
        uint16_t port;
        SOCKET sock{INVALID_SOCKET};
        std::thread thread;
    };
    //! A connection being served, so Stop() can close it and join its thread.
    struct Conn {
        SOCKET sock{INVALID_SOCKET};
        std::shared_ptr<std::atomic<bool>> done;
        std::thread thread;
    };

    bool Listen(Listener& l, std::string& error);
    void Accept(Listener* l);
    void Serve(Proto proto, SOCKET sock);
    //! Close and join any finished connection threads (called while holding m_mutex).
    void Reap() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const uint16_t m_pop3_port;
    const uint16_t m_smtp_port;

    CThreadInterrupt m_interrupt;
    std::atomic<bool> m_running{false};
    Listener m_pop3{Proto::POP3, 0};
    Listener m_smtp{Proto::SMTP, 0};

    Mutex m_mutex;
    std::vector<Conn> m_conns GUARDED_BY(m_mutex);
};

/** The running bridge, or null when it is off. */
extern std::unique_ptr<MailBridge> g_mail_bridge;

} // namespace mail

#endif // BITCOIN_MAIL_BRIDGE_H
