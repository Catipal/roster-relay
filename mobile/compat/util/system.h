// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_COMPAT_UTIL_SYSTEM_H
#define BPS_MOBILE_COMPAT_UTIL_SYSTEM_H

// The phone build's util/system.h. The node's version is arguments, config
// files, data directories and settings - a node's life, and boost's. What the
// shared code takes from it is TraceThread; the companion CLI also wants
// SetupEnvironment and TryCreateDirectories. Nothing else exists here, so
// anything new that reaches for more fails to compile rather than quietly
// pulling a node into a phone.

#include <fs.h>
#include <logging.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/threadnames.h>
#include <util/time.h>

#include <exception>
#include <string>

template <typename Callable>
void TraceThread(const char* name, Callable func)
{
    util::ThreadRename(name);
    try {
        LogPrintf("%s thread start\n", name);
        func();
        LogPrintf("%s thread exit\n", name);
    } catch (const std::exception& e) {
        LogPrintf("%s thread stopped by an exception: %s\n", name, e.what());
        throw;
    }
}

/** Log an error and return false, as the node's version does. */
template <typename... Args>
bool error(const char* fmt, const Args&... args)
{
    LogPrintf("ERROR: %s\n", tfm::format(fmt, args...));
    return false;
}

void SetupEnvironment();
bool TryCreateDirectories(const fs::path& p);

#endif // BPS_MOBILE_COMPAT_UTIL_SYSTEM_H
