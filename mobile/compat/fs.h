// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BPS_MOBILE_COMPAT_FS_H
#define BPS_MOBILE_COMPAT_FS_H

// The phone build's fs.h: std::filesystem where the node uses boost's.

#include <filesystem>

namespace fs = std::filesystem;

#endif // BPS_MOBILE_COMPAT_FS_H
