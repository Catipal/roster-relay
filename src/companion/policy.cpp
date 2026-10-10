// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/policy.h>

#include <crypto/hmac_sha256.h>
#include <policy/feerate.h>
#include <random.h>
#include <support/cleanse.h>
#include <util/moneystr.h>

#include <algorithm>
#include <cstring>

namespace companion {

bool ValidLimits(const Limits& limits, std::string& reason)
{
    if (limits.per_tx <= 0 || limits.per_day <= 0) {
        reason = "Both limits have to be set, and above zero.";
        return false;
    }
    if (!MoneyRange(limits.per_tx) || !MoneyRange(limits.per_day)) {
        reason = "A limit is larger than all the money there is.";
        return false;
    }
    if (limits.per_tx > limits.per_day) {
        reason = "One payment cannot be allowed more than a whole day.";
        return false;
    }
    return true;
}

CAmount SpentInWindow(const std::vector<Spend>& spends, int64_t now)
{
    CAmount total = 0;
    for (const Spend& s : spends) {
        if (now - s.time < SPEND_WINDOW) total += s.total;
    }
    return total;
}

void PruneSpends(std::vector<Spend>& spends, int64_t now)
{
    spends.erase(std::remove_if(spends.begin(), spends.end(),
                                [now](const Spend& s) { return now - s.time >= SPEND_WINDOW; }),
                 spends.end());
}

bool WithinLimits(const Limits& limits, const std::vector<Spend>& spends, CAmount total, int64_t now,
                  std::string& reason)
{
    if (total <= 0) {
        reason = "Nothing to send.";
        return false;
    }
    if (total > limits.per_tx) {
        reason = "That is more than this phone may send in one payment (" + FormatMoney(limits.per_tx) + " " + CURRENCY_UNIT + ").";
        return false;
    }
    const CAmount spent = SpentInWindow(spends, now);
    if (spent + total > limits.per_day) {
        const CAmount left = std::max<CAmount>(0, limits.per_day - spent);
        reason = "That is more than is left of this phone's limit for the day (" + FormatMoney(left) + " " + CURRENCY_UNIT + ").";
        return false;
    }
    return true;
}

namespace {

uint256 Stretch(const std::string& pin, const uint256& salt, const uint256& node_secret)
{
    unsigned char block[CHMAC_SHA256::OUTPUT_SIZE];
    {
        CHMAC_SHA256 h(node_secret.begin(), node_secret.size());
        h.Write(salt.begin(), salt.size());
        h.Write(reinterpret_cast<const unsigned char*>(pin.data()), pin.size());
        h.Finalize(block);
    }
    for (int i = 1; i < PIN_ROUNDS; ++i) {
        CHMAC_SHA256 h(node_secret.begin(), node_secret.size());
        h.Write(block, sizeof(block));
        h.Finalize(block);
    }
    uint256 out;
    std::memcpy(out.begin(), block, out.size());
    memory_cleanse(block, sizeof(block));
    return out;
}

} // namespace

PinVerifier MakePinVerifier(const std::string& pin, const uint256& node_secret)
{
    PinVerifier v;
    GetStrongRandBytes(v.salt.begin(), v.salt.size());
    v.hash = Stretch(pin, v.salt, node_secret);
    return v;
}

bool CheckPin(const PinVerifier& verifier, const std::string& pin, const uint256& node_secret)
{
    const uint256 got = Stretch(pin, verifier.salt, node_secret);
    // Compared in full, whatever the first difference.
    unsigned char diff = 0;
    for (size_t i = 0; i < got.size(); ++i) diff |= got.begin()[i] ^ verifier.hash.begin()[i];
    return diff == 0 && !verifier.hash.IsNull();
}

bool AttemptLimiter::Allow(int64_t now)
{
    while (!m_times.empty() && now - m_times.front() >= m_window) m_times.pop_front();
    if (m_times.size() >= m_max) return false;
    m_times.push_back(now);
    return true;
}

} // namespace companion
