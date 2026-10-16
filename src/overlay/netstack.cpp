// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/netstack.h>

#include <random.h>

#include <lwip/init.h>

#include <chrono>
#include <mutex>

/*
 * What lwIP asks of the platform, with C linkage because lwIP is C: a
 * millisecond clock for its timers, and randomness for initial sequence
 * numbers and ports (overlay/lwip/arch/cc.h).
 */
extern "C" u32_t sys_now(void)
{
    // Monotonic: lwIP's timers measure intervals, and a wall clock that steps
    // would fire them early or hold them back. It wraps every 49 days, which
    // lwIP's arithmetic expects.
    return (u32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

extern "C" uint32_t bps_lwip_rand(void)
{
    return (uint32_t)GetRand(std::numeric_limits<uint32_t>::max());
}

namespace overlay {

void InitNetStack()
{
    static std::once_flag once;
    std::call_once(once, [] { lwip_init(); });
}

} // namespace overlay
