// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/limits.h>

#include <overlay/frame.h>

#include <algorithm>
#include <limits>

namespace overlay {

constexpr int64_t TrafficLimits::DAY_MS;
constexpr uint64_t TrafficLimits::OVERRUN_DIVISOR;
constexpr int64_t TrafficLimits::BUCKET_IDLE_MS;
constexpr size_t TrafficLimits::MAX_BUCKETS;

void TrafficLimits::Configure(uint64_t daily_budget, uint64_t path_rate)
{
    LOCK(m_mutex);
    m_daily = daily_budget;
    m_rate = path_rate;
    m_buckets.clear();
}

void TrafficLimits::RollDay(int64_t now_ms) const
{
    const int64_t day = now_ms / DAY_MS;
    if (day == m_day) return;
    m_day = day;
    m_today = 0;
    m_dropped_rate = 0;
    m_dropped_budget = 0;
    m_refused = 0;
}

bool TrafficLimits::BudgetSpent() const
{
    return m_daily != 0 && m_today >= m_daily;
}

void TrafficLimits::Prune(int64_t now_ms)
{
    for (auto it = m_buckets.begin(); it != m_buckets.end();) {
        if (now_ms - it->second.last_ms > BUCKET_IDLE_MS) {
            it = m_buckets.erase(it);
        } else {
            ++it;
        }
    }
    // Still full of live ones: forget the stalest, which costs that path at
    // most a fresh second's allowance.
    while (m_buckets.size() >= MAX_BUCKETS) {
        auto stalest = std::min_element(m_buckets.begin(), m_buckets.end(),
            [](const std::pair<const uint64_t, Bucket>& a, const std::pair<const uint64_t, Bucket>& b) {
                return a.second.last_ms < b.second.last_ms;
            });
        m_buckets.erase(stalest);
    }
}

bool TrafficLimits::Forward(uint64_t path_id, size_t bytes, int64_t now_ms)
{
    LOCK(m_mutex);
    RollDay(now_ms);

    if (m_daily != 0 && m_today >= m_daily + m_daily / OVERRUN_DIVISOR) {
        ++m_dropped_budget;
        return false;
    }

    if (m_rate != 0) {
        Bucket& b = Refill(path_id, now_ms);
        const uint64_t cost = (uint64_t)bytes * 1000;
        if (b.millibytes < cost) {
            ++m_dropped_rate;
            return false;
        }
        b.millibytes -= cost;
    }

    m_today += bytes;
    return true;
}

TrafficLimits::Bucket& TrafficLimits::Refill(uint64_t path_id, int64_t now_ms)
{
    // A second's worth, and never less than a few full datagrams, so a low
    // cap still lets a path through rather than strangling it outright.
    const uint64_t capacity = std::max<uint64_t>(m_rate, 4 * SAFE_DATAGRAM) * 1000;
    std::map<uint64_t, Bucket>::iterator it = m_buckets.find(path_id);
    if (it == m_buckets.end()) {
        if (m_buckets.size() >= MAX_BUCKETS) Prune(now_ms);
        Bucket fresh;
        fresh.millibytes = capacity;
        fresh.last_ms = now_ms;
        it = m_buckets.emplace(path_id, fresh).first;
    }
    Bucket& b = it->second;
    if (now_ms > b.last_ms) {
        // Rate is bytes a second, so it is also thousandths of a byte a
        // millisecond. Past a full refill the elapsed time stops mattering,
        // which also keeps the product from overflowing.
        const uint64_t elapsed = (uint64_t)(now_ms - b.last_ms);
        const uint64_t full_after = capacity / m_rate + 1;
        b.millibytes = elapsed >= full_after ? capacity : std::min(capacity, b.millibytes + elapsed * m_rate);
        b.last_ms = now_ms;
    }
    return b;
}

uint64_t TrafficLimits::Available(uint64_t path_id, int64_t now_ms)
{
    LOCK(m_mutex);
    if (m_rate == 0) return std::numeric_limits<uint64_t>::max();
    return Refill(path_id, now_ms).millibytes / 1000;
}

bool TrafficLimits::Spend(size_t bytes, int64_t now_ms)
{
    LOCK(m_mutex);
    RollDay(now_ms);
    if (m_daily != 0 && m_today >= m_daily + m_daily / OVERRUN_DIVISOR) {
        ++m_dropped_budget;
        return false;
    }
    m_today += bytes;
    return true;
}

bool TrafficLimits::AdmitPath(int64_t now_ms)
{
    LOCK(m_mutex);
    RollDay(now_ms);
    if (BudgetSpent()) {
        ++m_refused;
        return false;
    }
    return true;
}

TrafficLimits::Stats TrafficLimits::GetStats(int64_t now_ms) const
{
    LOCK(m_mutex);
    RollDay(now_ms);
    Stats s;
    s.daily_budget = m_daily;
    s.path_rate = m_rate;
    s.today = m_today;
    s.dropped_rate = m_dropped_rate;
    s.dropped_budget = m_dropped_budget;
    s.refused_paths = m_refused;
    s.accepting = !BudgetSpent();
    return s;
}

} // namespace overlay
