// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_LIMITS_H
#define BITCOIN_OVERLAY_LIMITS_H

#include <sync.h>

#include <cstddef>
#include <cstdint>
#include <map>

/**
 * How much of other people's traffic a relay carries (design note §11·6, §8·7).
 *
 * Paying relays per byte was rejected because nobody can prove who carried
 * what; limits do that job instead. Two of them, both on traffic this node
 * forwards for others - never on its own:
 *
 *  - a rate cap per path, so no single visitor, site or gateway fills a
 *    relay's line. A datagram over the cap is dropped, which is what a full
 *    link does anyway, and TCP inside the overlay slows down in answer;
 *  - a daily budget. Once it is spent the relay accepts no new paths until
 *    the day turns, and paths already open may run a tenth over it before
 *    they are cut too, so a day's total stays near what the owner set.
 *
 * Relays cannot tell mail from a site from a gateway's traffic, since every
 * path is sealed, so the limits apply to all path traffic alike. Days are UTC
 * days, so the arithmetic needs no clock but the one the node already has.
 */
namespace overlay {

/** -relaybandwidth: MiB of others' traffic a relay carries in a day. 0 = no budget. */
static constexpr uint64_t DEFAULT_RELAY_BANDWIDTH_MIB = 1024;
/** -relaypathrate: KiB/s one path may move through a relay. 0 = no cap. */
static constexpr uint64_t DEFAULT_RELAY_PATH_RATE_KIB = 64;

class TrafficLimits
{
public:
    static constexpr int64_t DAY_MS = 24 * 60 * 60 * 1000;
    /** Paths already open may run this fraction over the day's budget. */
    static constexpr uint64_t OVERRUN_DIVISOR = 10;
    /** Rate buckets idle this long are forgotten (PathTable::PATH_TTL). */
    static constexpr int64_t BUCKET_IDLE_MS = 600 * 1000;
    /** Past this many buckets, idle ones are pruned. */
    static constexpr size_t MAX_BUCKETS = 4096;

    struct Stats {
        uint64_t daily_budget{0};   //!< bytes, 0 for none
        uint64_t path_rate{0};      //!< bytes per second, 0 for none
        uint64_t today{0};          //!< bytes forwarded so far today
        uint64_t dropped_rate{0};   //!< datagrams dropped today for a path's rate
        uint64_t dropped_budget{0}; //!< datagrams dropped today past the budget
        uint64_t refused_paths{0};  //!< new paths refused today
        bool accepting{true};       //!< whether a new path would be accepted now
    };

    /** Bytes a day and bytes a second; 0 switches either off. */
    void Configure(uint64_t daily_budget, uint64_t path_rate);

    /**
     * One datagram of `bytes` about to be forwarded on `path_id`. False when it
     * is to be dropped: over the path's rate, or past the day's overrun.
     */
    bool Forward(uint64_t path_id, size_t bytes, int64_t now_ms);

    /** Whether a new path may start through this node. Counts a refusal. */
    bool AdmitPath(int64_t now_ms);

    Stats GetStats(int64_t now_ms) const;

private:
    struct Bucket {
        uint64_t millibytes{0}; //!< tokens, in thousandths of a byte
        int64_t last_ms{0};
    };

    void RollDay(int64_t now_ms) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool BudgetSpent() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Prune(int64_t now_ms) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    mutable Mutex m_mutex;
    uint64_t m_daily GUARDED_BY(m_mutex){0};
    uint64_t m_rate GUARDED_BY(m_mutex){0};
    // Mutable so that reading the stats can turn the day over, as any other
    // look at the counters would.
    mutable int64_t m_day GUARDED_BY(m_mutex){-1};
    mutable uint64_t m_today GUARDED_BY(m_mutex){0};
    mutable uint64_t m_dropped_rate GUARDED_BY(m_mutex){0};
    mutable uint64_t m_dropped_budget GUARDED_BY(m_mutex){0};
    mutable uint64_t m_refused GUARDED_BY(m_mutex){0};
    std::map<uint64_t, Bucket> m_buckets GUARDED_BY(m_mutex);
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_LIMITS_H
