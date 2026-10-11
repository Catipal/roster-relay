// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/rendezvous.h>

#include <crypto/common.h>
#include <hash.h>
#include <uint256.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace overlay {

uint64_t RendezvousEpoch(int height)
{
    if (height < 0) return 0;
    return static_cast<uint64_t>(height) / RENDEZVOUS_EPOCH_BLOCKS;
}

int RendezvousAnchor(uint64_t epoch)
{
    const int64_t start = static_cast<int64_t>(epoch) * RENDEZVOUS_EPOCH_BLOCKS;
    return static_cast<int>(std::max<int64_t>(0, start - RENDEZVOUS_ANCHOR_DEPTH));
}

std::vector<uint64_t> EpochsToRegister(int height)
{
    std::vector<uint64_t> out;
    if (height < 0) return out;
    const uint64_t epoch = RendezvousEpoch(height);
    out.push_back(epoch);
    if (height >= RendezvousAnchor(epoch + 1)) out.push_back(epoch + 1);
    const int into = height - static_cast<int>(epoch * RENDEZVOUS_EPOCH_BLOCKS);
    if (epoch > 0 && into < RENDEZVOUS_OVERLAP) out.push_back(epoch - 1);
    return out;
}

std::vector<uint64_t> EpochsToTry(int height)
{
    std::vector<uint64_t> out;
    if (height < 0) return out;
    const uint64_t epoch = RendezvousEpoch(height);
    out.push_back(epoch);
    if (epoch > 0) out.push_back(epoch - 1);
    return out;
}

std::vector<roster::KeyBytes> RendezvousPoints(const roster::KeyBytes& service_key,
                                               uint64_t epoch,
                                               const std::vector<roster::KeyBytes>& relays,
                                               size_t count)
{
    unsigned char epoch_be[8];
    WriteBE64(epoch_be, epoch);

    std::vector<std::pair<uint256, roster::KeyBytes>> scored;
    scored.reserve(relays.size());
    for (const roster::KeyBytes& relay : relays) {
        // A service meeting its visitors at itself would have to accept them
        // at its own address, which is the thing it is hiding.
        if (relay == service_key) continue;
        // Tagged so this hash cannot collide with any other use of the same
        // key material, which is the reason the roster's own hashes are
        // tagged too. v2: v1 drew by modulo over an ordered list.
        CHashWriter h = TaggedHash("BPS/meet/v2");
        h.write(reinterpret_cast<const char*>(service_key.data()), service_key.size());
        h.write(reinterpret_cast<const char*>(epoch_be), sizeof(epoch_be));
        h.write(reinterpret_cast<const char*>(relay.data()), relay.size());
        scored.emplace_back(h.GetSHA256(), relay);
    }
    // Highest first, compared as bytes, ties (which need a collision) by key:
    // all an ordering needs to be the same on every node.
    std::sort(scored.begin(), scored.end(),
              [](const std::pair<uint256, roster::KeyBytes>& a, const std::pair<uint256, roster::KeyBytes>& b) {
                  const int c = std::memcmp(a.first.begin(), b.first.begin(), 32);
                  return c != 0 ? c > 0 : a.second < b.second;
              });
    std::vector<roster::KeyBytes> out;
    for (size_t i = 0; i < scored.size() && out.size() < count; ++i) {
        // A list with a repeated key still yields distinct points.
        if (std::find(out.begin(), out.end(), scored[i].second) == out.end()) out.push_back(scored[i].second);
    }
    return out;
}

} // namespace overlay
