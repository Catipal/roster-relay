// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// What the phone build provides in place of the node's logging.cpp,
// util/system.cpp and util/time.cpp: the same functions, without boost and
// without a data directory.

#include <logging.h>
#include <util/system.h>
#include <util/time.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <mutex>
#include <thread>

namespace companion {

namespace {
std::mutex g_log_mutex;
std::function<void(const std::string&)> g_log_sink;
std::atomic<bool> g_log_debug{false};
} // namespace

void SetLogSink(std::function<void(const std::string&)> sink, bool debug)
{
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_sink = std::move(sink);
    g_log_debug = debug;
}

bool LogAccepts(BCLog::LogFlags category)
{
    return g_log_debug.load();
}

void LogLine(const std::string& line)
{
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_sink) g_log_sink(line);
}

} // namespace companion

void SetupEnvironment() {}

bool TryCreateDirectories(const fs::path& p)
{
    std::error_code ec;
    return fs::create_directories(p, ec);
}

// util/time.h, on std::chrono alone.

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

void InterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<int64_t> g_mock_time(0);

int64_t GetTime()
{
    const int64_t mocked = g_mock_time.load(std::memory_order_relaxed);
    if (mocked) return mocked;
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

template <typename T>
T GetTime()
{
    const std::chrono::seconds mocked{g_mock_time.load(std::memory_order_relaxed)};
    return std::chrono::duration_cast<T>(
        mocked.count() ? mocked : std::chrono::microseconds{GetTimeMicros()});
}
template std::chrono::seconds GetTime();
template std::chrono::milliseconds GetTime();
template std::chrono::microseconds GetTime();

void SetMockTime(int64_t mock) { g_mock_time.store(mock, std::memory_order_relaxed); }

int64_t GetMockTime() { return g_mock_time.load(std::memory_order_relaxed); }

int64_t GetTimeMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t GetTimeMicros()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t GetSystemTimeInSeconds() { return GetTimeMicros() / 1000000; }

std::string FormatISO8601DateTime(int64_t time)
{
    const std::time_t t = time;
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string FormatISO8601Date(int64_t time)
{
    return FormatISO8601DateTime(time).substr(0, 10);
}
