// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_STORE_H
#define BITCOIN_COMPANION_STORE_H

#include <companion/policy.h>
#include <companion/protocol.h>
#include <fs.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

#include <memory>
#include <string>
#include <vector>

class CDBWrapper;

namespace companion {

/** A paired phone, as its home node remembers it. */
struct Device {
    uint8_t version{1};
    CPubKey key; //!< the device key it proves at the end of every path
    std::string name;
    int64_t created{0};
    int64_t last_seen{0};
    Limits limits;
    PinVerifier pin;
    int32_t failures{0}; //!< wrong PINs in a row
    std::vector<Spend> spends; //!< the last 24 hours, for the daily limit

    bool Locked() const { return failures >= MAX_PIN_FAILURES; }

    SERIALIZE_METHODS(Device, obj)
    {
        READWRITE(obj.version, obj.key, LIMITED_STRING(obj.name, MAX_DEVICE_NAME), obj.created, obj.last_seen,
                  obj.limits, obj.pin, obj.failures, obj.spends);
    }
};

/**
 * The paired devices, in <datadir>/companion. Every write is synced: the spend
 * log in it is what stops a restart from forgetting what was already sent today.
 */
class Store
{
public:
    explicit Store(const fs::path& dir, bool memory_only = false);
    ~Store();

    /** The node secret PIN verifiers are keyed with. Made once, the first time, and kept. */
    const uint256& Secret() const { return m_secret; }

    bool Get(const CPubKey& key, Device& out);
    bool Put(const Device& device);
    bool Erase(const CPubKey& key);
    std::vector<Device> All();

private:
    std::unique_ptr<CDBWrapper> m_db;
    uint256 m_secret;
};

} // namespace companion

#endif // BITCOIN_COMPANION_STORE_H
