// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_COMPAT_OPTIONAL_H
#define BPS_MOBILE_COMPAT_OPTIONAL_H

// The phone build's optional.h: std::optional where the node's is boost's.
// roster/record.h reaches for it; a Linux host has boost's headers lying
// around and let that pass unnoticed, a phone's toolchain does not.

#include <optional>
#include <utility>

template <typename T>
using Optional = std::optional<T>;

template <typename T>
Optional<T> MakeOptional(bool condition, T&& value)
{
    if (!condition) return std::nullopt;
    return std::forward<T>(value);
}

static constexpr auto& nullopt = std::nullopt;

#endif // BPS_MOBILE_COMPAT_OPTIONAL_H
