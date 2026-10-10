// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPANION_POLICY_H
#define BITCOIN_COMPANION_POLICY_H

#include <amount.h>
#include <serialize.h>
#include <uint256.h>

#include <deque>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * The rules a home node holds a phone to. All of them are checked on the home
 * node and none of them can be changed from the phone: limits are set when a
 * pairing is accepted and edited only there, and the PIN is checked there,
 * where a stolen phone cannot try it offline.
 */
namespace companion {

struct Limits {
    CAmount per_tx{0};  //!< most one payment may send, fee included
    CAmount per_day{0}; //!< most all payments may send in any 24 hours, fees included

    Limits() {}
    Limits(CAmount tx, CAmount day) : per_tx(tx), per_day(day) {}
    SERIALIZE_METHODS(Limits, obj) { READWRITE(obj.per_tx, obj.per_day); }
};

/** Limits a home node accepts: both set, neither negative, a payment no larger than a day. */
bool ValidLimits(const Limits& limits, std::string& reason);

/** One payment counted against a device's limits. */
struct Spend {
    int64_t time{0};
    CAmount total{0}; //!< amount and fee
    uint256 txid;     //!< null while the payment is being made

    Spend() {}
    Spend(int64_t t, CAmount amount, const uint256& id) : time(t), total(amount), txid(id) {}
    SERIALIZE_METHODS(Spend, obj) { READWRITE(obj.time, obj.total, obj.txid); }
};

static constexpr int64_t SPEND_WINDOW = 24 * 60 * 60;

/** What was spent in the window ending at `now`. */
CAmount SpentInWindow(const std::vector<Spend>& spends, int64_t now);

/** Drop what has left the window; nothing in it can count again. */
void PruneSpends(std::vector<Spend>& spends, int64_t now);

/** Whether a payment of `total` fits both limits. `reason` says which it breaks. */
bool WithinLimits(const Limits& limits, const std::vector<Spend>& spends, CAmount total, int64_t now,
                  std::string& reason);

/** Wrong PINs in a row before a device is locked until the home node unlocks it. */
static constexpr int MAX_PIN_FAILURES = 5;
/** HMAC rounds per PIN check: slow enough to matter in bulk, quick enough for one tap. */
static constexpr int PIN_ROUNDS = 20000;

/**
 * What a home node keeps instead of a PIN. Keyed with a secret that lives only
 * on the home node, so a copy of its database alone is no help in guessing.
 */
struct PinVerifier {
    uint256 salt;
    uint256 hash;
    SERIALIZE_METHODS(PinVerifier, obj) { READWRITE(obj.salt, obj.hash); }
};

PinVerifier MakePinVerifier(const std::string& pin, const uint256& node_secret);
bool CheckPin(const PinVerifier& verifier, const std::string& pin, const uint256& node_secret);

/**
 * At most `max` attempts in any `window` seconds, across every device: a
 * cap on PIN guessing that no number of paired phones adds up past.
 */
class AttemptLimiter
{
public:
    AttemptLimiter(size_t max, int64_t window) : m_max(max), m_window(window) {}
    /** True, and the attempt counted, if one is allowed now. */
    bool Allow(int64_t now);

private:
    const size_t m_max;
    const int64_t m_window;
    std::deque<int64_t> m_times;
};

} // namespace companion

#endif // BITCOIN_COMPANION_POLICY_H
