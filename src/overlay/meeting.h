// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_MEETING_H
#define BITCOIN_OVERLAY_MEETING_H

#include <key.h>
#include <overlay/path.h>
#include <overlay/select.h>
#include <roster/record.h>
#include <sync.h>
#include <threadinterrupt.h>

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * Being reached without an address, and reaching what has none (design note
 * §8·7, §11·6).
 *
 * A node listed with no endpoint - a gateway, a hidden site, a computer at
 * home - keeps itself registered at its meeting points: relays both sides
 * compute from the roster (overlay/rendezvous.h). It reaches each through
 * relays of its own, so a meeting point learns its key and not its address,
 * and the relay in front of it its address and not its key. A visitor reaches
 * the same point through relays of its own and asks to be joined; from then
 * on the two hold an end-to-end session across the join, and nobody on the
 * way can read it or knows both ends.
 *
 * How many relays stand on each side is each side's choice (-meethops); one
 * by default, which with the meeting point in the middle gives the four-node
 * path a visitor uses to reach a gateway: as Tor's guard, middle and exit for
 * the visitor, and no single relay knowing both the gateway's key and where it
 * is.
 */
namespace overlay {

/** Relays between a side and its meeting point, by default. */
static const int DEFAULT_MEET_HOPS = 1;
/** And at most. */
static constexpr int MAX_MEET_HOPS = 3;
/** Whether this node keeps itself registered at its meeting points (-meetable). */
static const bool DEFAULT_MEETABLE = false;
/**
 * How often a registration is repeated over the internet. The answer comes
 * back along the whole path, so it is the echo that says the path still
 * works: a relay on it that restarts, crashes or moves forgets the path
 * without telling anyone, and the meeting point goes on joining visitors to
 * it. Unanswered, the node builds a new path at once, and the meeting point
 * keeps the newest registration for each key, so a node is out of reach for
 * about this long plus a rebuild - half a minute, where it was four.
 * It also keeps the path from idling out (PathTable::PATH_TTL).
 */
static constexpr int64_t MEET_REFRESH = 30;
/** The same over a path that starts on the radio, whose airtime is too scarce for it. */
static constexpr int64_t MEET_REFRESH_RADIO = 240;
/** Overlay application data tag: "are you there" across a meeting, and its answer. */
static constexpr uint8_t MEET_ECHO = 0x12;
/**
 * Overlay application data tag: a byte to an adjacent relay that means
 * nothing, sent so that the home router in front of a node keeps its UDP
 * mapping open. Receivers drop it; nodes that predate it drop it as unknown.
 */
static constexpr uint8_t KEEPALIVE_TAG = 0x14;
/**
 * How often a registered node sends one to the relay in front of each of its
 * registrations. Home routers forget a UDP mapping after half a minute to two
 * minutes, and the registration refresh (MEET_REFRESH) comes far too seldom to
 * hold it, so without this a node at home falls out of reach between refreshes
 * - every gateway at home among them (design note §11·6, §8·7).
 */
static constexpr int64_t KEEPALIVE_GUARD = 25;

/**
 * The meeting points of `service` in `epoch`, from the relay set at the
 * epoch's anchor. False with `error` when the roster cannot be read or the
 * anchor is not reached yet.
 */
bool MeetingPointsFor(const roster::KeyBytes& service, uint64_t epoch, std::vector<roster::KeyBytes>& out,
                      std::string& error);

/** A path built through this node's own relays to a relay the roster lists. */
struct Reached {
    uint64_t path{0};              //!< send on this to reach the relay
    std::vector<uint64_t> legs;    //!< for ClosePath
    std::vector<roster::KeyBytes> through; //!< the relays before it
    //! How long a step along it may take: longer when it starts on the radio.
    std::chrono::milliseconds step{4000};
};

/**
 * Build a path to the listed relay `key` through `hops` relays of this node's
 * choosing. With `prove_last` the relay is shown this node's roster key, as a
 * meeting point must be to register it; every relay before it sees only a key
 * made for the occasion.
 */
bool ReachRelay(const roster::KeyBytes& key, int hops, bool prove_last, Reached& out, std::string& error);

/** One registration of this node at a meeting point. */
struct Registration {
    roster::KeyBytes point{};
    std::vector<uint64_t> epochs;  //!< the epochs it is a point for
    bool listed{false};            //!< the meeting point this node's listing names
    Reached reached;
    int64_t since{0};              //!< first acknowledged
    int64_t refreshed{0};          //!< last acknowledged
};

/** Keeps this node registered at its meeting points, epoch after epoch. */
class MeetingService
{
public:
    /** Keep `self`, this node's roster key, registered. */
    MeetingService(const roster::KeyBytes& self, int hops);
    ~MeetingService();

    void Start();
    void Stop();

    std::vector<Registration> Registrations() const;
    int Hops() const { return m_hops; }
    /** What went wrong last, if the last round left a point unregistered. */
    std::string LastError() const;

    /** One round: register where needed, refresh what is due, drop what is past. For tests. */
    void Tick();

private:
    void ThreadMeeting();
    /** A keep-alive to the relay in front of each registration, over the internet only. */
    void KeepGuardsAwake();

    const roster::KeyBytes m_self;
    const int m_hops;
    //! This node's own operational key. A relay can be one of its own meeting
    //! points, and a path to itself cannot be built, so that point is left out.
    roster::KeyBytes m_node{};
    mutable Mutex m_mutex;
    std::map<roster::KeyBytes, Registration> m_regs GUARDED_BY(m_mutex);
    std::string m_error GUARDED_BY(m_mutex);
    std::thread m_thread;
    CThreadInterrupt m_interrupt;
};

/** The running service, or null when -meetable is off. */
extern std::unique_ptr<MeetingService> g_meeting;

/** A visitor's side of a meeting: an end-to-end session with the service. */
struct Meeting {
    uint64_t path{0};              //!< SendSecret on this reaches the service
    std::vector<uint64_t> legs;    //!< this side's legs, for CloseMeeting
    roster::KeyBytes point{};
    uint64_t epoch{0};
    int hops{0};
    bool listed{false};            //!< met at the point its listing names
};

/**
 * Meet `service` through `hops` relays of this node's choosing and one of its
 * meeting points, trying the current epoch's, then the previous one's, then
 * the one its listing names for the listing's life. With `listed_only`, that
 * last one alone.
 */
bool MeetService(const roster::KeyBytes& service, int hops, Meeting& out, std::string& error,
                 bool listed_only = false);
void CloseMeeting(const Meeting& m);

/**
 * Ask the service across a meeting whether it is there, and wait for its
 * answer. True with the round trip in `rtt`.
 */
bool EchoAcross(const Meeting& m, std::chrono::milliseconds timeout, std::chrono::milliseconds& rtt);

/** Overlay application data starting with MEET_ECHO. */
void HandleMeetEcho(const Hop& from, const std::vector<unsigned char>& payload);

} // namespace overlay

#endif // BITCOIN_OVERLAY_MEETING_H
