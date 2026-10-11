// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_COMPAT_LOGGING_H
#define BPS_MOBILE_COMPAT_LOGGING_H

// The phone build's logging.h. The node's logger writes debug.log in a data
// directory, rotates it, timestamps it and reads -debug from the arguments;
// a phone has none of that, and the file machinery needs boost. The overlay
// code it shares with the node only ever calls LogPrintf and LogPrint, so
// this gives it those and sends the lines wherever the app says - nowhere,
// unless it asks.

#include <compat.h> // the node's logging.h reaches the POSIX headers through boost; files lean on that
#include <tinyformat.h>

#include <cstdint>
#include <functional>
#include <string>

namespace BCLog {
// The categories the shared code logs under. Values do not matter here.
enum LogFlags : uint32_t {
    NONE = 0,
    NET = (1 << 0),
    PROXY = (1 << 1),
    RAND = (1 << 2),
    ALL = ~(uint32_t)0,
};
} // namespace BCLog

namespace companion {
/** Where log lines go: a phone app can show them, or keep them for a bug report. */
void SetLogSink(std::function<void(const std::string&)> sink, bool debug);
bool LogAccepts(BCLog::LogFlags category);
void LogLine(const std::string& line);
} // namespace companion

static inline bool LogAcceptCategory(BCLog::LogFlags category)
{
    return companion::LogAccepts(category);
}

template <typename... Args>
static inline void LogPrintf(const char* fmt, const Args&... args)
{
    std::string line;
    try {
        line = tfm::format(fmt, args...);
    } catch (const tinyformat::format_error& e) {
        line = "Error \"" + std::string(e.what()) + "\" while formatting log message: " + fmt;
    }
    companion::LogLine(line);
}

#define LogPrint(category, ...)                \
    do {                                       \
        if (LogAcceptCategory((category))) {   \
            LogPrintf(__VA_ARGS__);            \
        }                                      \
    } while (0)

#endif // BPS_MOBILE_COMPAT_LOGGING_H
