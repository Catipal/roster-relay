// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/rendezvous.h>

#include <crypto/common.h>
#include <hash.h>
#include <uint256.h>

#include <set>

namespace overlay {

uint64_t RendezvousEpoch(int height)
{
    if (height < 0) return 0;
    return static_cast<uint64_t>(height) / RENDEZVOUS_EPOCH_BLOCKS;
}

std::vector<roster::KeyBytes> RendezvousPoints(const roster::KeyBytes& service_key,
                                               uint64_t epoch,
                                               const std::vector<roster::KeyBytes>& relays,
                                               size_t count)
{
    std::vector<roster::KeyBytes> out;
    if (relays.empty() || count == 0) return out;

    std::set<size_t> taken;
    // Each attempt is an independent draw. Collisions are expected on a small
    // roster, so keep drawing until enough distinct relays are found or the
    // roster is exhausted - a service on a three-relay network gets three
    // points, not a silent failure.
    const size_t want = std::min(count, relays.size());
    for (uint32_t attempt = 0; out.size() < want && attempt < 1000; ++attempt) {
        unsigned char epoch_be[8];
        WriteBE64(epoch_be, epoch);
        unsigned char attempt_be[4];
        WriteBE32(attempt_be, attempt);

        // Tagged so this hash cannot collide with any other use of the same
        // key material, which is the reason the roster's own hashes are tagged
        // too.
        CHashWriter h = TaggedHash("BPS/rv/v1");
        h.write(reinterpret_cast<const char*>(service_key.data()), service_key.size());
        h.write(reinterpret_cast<const char*>(epoch_be), sizeof(epoch_be));
        h.write(reinterpret_cast<const char*>(attempt_be), sizeof(attempt_be));
        const uint256 digest = h.GetSHA256();

        // Modulo over the roster length. The bias this introduces is far below
        // anything an adversary could steer, because they do not choose the
        // digest - it is fixed by the service key and the epoch.
        const uint64_t draw = ReadBE64(digest.begin());
        const size_t index = static_cast<size_t>(draw % relays.size());
        if (taken.insert(index).second) out.push_back(relays[index]);
    }

    return out;
}

} // namespace overlay
