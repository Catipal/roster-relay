// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/payout.h>

#include <fs.h>
#include <logging.h>
#include <pubkey.h>
#include <roster/keystore.h>
#include <script/standard.h>
#include <sync.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <algorithm>
#include <set>

namespace roster {

namespace {

fs::path ListPath() { return GetDataDir() / "roster_users"; }

} // namespace

std::string UsersPath() { return ListPath().string(); }

CAmount PlanPayouts(CAmount reward, int share, const std::vector<KeyBytes>& users,
                    CAmount min_payout, std::vector<Payout>& out)
{
    out.clear();
    if (reward <= 0 || users.empty()) return 0;

    const int clamped = std::max(0, std::min(share, 100));
    if (clamped == 0) return 0;

    // Build the payable set first: a key that does not lift to a point cannot be
    // paid, and must not be counted when dividing either, or everyone else is
    // short-changed by its share.
    std::vector<Payout> payable;
    payable.reserve(users.size());
    for (size_t i = 0; i < users.size(); ++i) {
        CPubKey pubkey;
        if (!StakerPubKeyFromRoster(users[i], pubkey)) {
            LogPrintf("roster: listed peer %s is not a key; skipping it in the split\n",
                      HexStr(users[i]));
            continue;
        }
        Payout p;
        p.key = users[i];
        p.script = GetScriptForDestination(PKHash(pubkey));
        payable.push_back(p);
    }
    if (payable.empty()) return 0;

    // Multiply before dividing. Dividing first throws away up to 99 satoshi of
    // the reward before the share is even taken, and there is no overflow to
    // avoid: a reward times 100 is nowhere near the range of the type.
    const CAmount pool = (reward * clamped) / 100;
    const CAmount each = pool / (CAmount)payable.size();

    // Under the dust limit an output costs more to spend than it carries, so
    // paying it is worse than not paying: it hands the peer something it cannot
    // move and costs the relay the bytes. Pay nobody and keep the pool.
    if (each < min_payout) {
        LogPrint(BCLog::COINSTAKE,
                 "roster: %u listed peers would receive %d each, below the %d floor; "
                 "paying none this block\n",
                 payable.size(), each, min_payout);
        return 0;
    }

    CAmount total = 0;
    for (size_t i = 0; i < payable.size(); ++i) {
        payable[i].amount = each;
        total += each;
    }
    out = payable;
    return total;
}

bool LoadUsers(std::vector<KeyBytes>& out, std::string& error)
{
    out.clear();
    const fs::path path = ListPath();
    if (!fs::exists(path)) return true; // no list is an empty list, not a failure

    fsbridge::ifstream file(path);
    if (!file.is_open()) {
        error = "Cannot open " + path.string();
        return false;
    }

    std::set<KeyBytes> seen;
    std::string line;
    int number = 0;
    while (std::getline(file, line)) {
        ++number;
        // Tolerate blank lines, comments and stray carriage returns: this file
        // is meant to be editable by hand.
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        if (!IsHex(line) || line.size() != RECORD_KEY_SIZE * 2) {
            error = strprintf("%s line %d is not a 32-byte key", path.string(), number);
            return false;
        }
        const std::vector<unsigned char> raw = ParseHex(line);
        KeyBytes key{};
        std::copy(raw.begin(), raw.end(), key.begin());
        if (!seen.insert(key).second) continue; // listed twice is listed once
        out.push_back(key);
    }
    return true;
}

namespace {
Mutex g_liveness_mutex;
LivenessCheck g_liveness GUARDED_BY(g_liveness_mutex);
} // namespace

void SetLivenessCheck(LivenessCheck check)
{
    LOCK(g_liveness_mutex);
    g_liveness = std::move(check);
}

std::vector<KeyBytes> LiveUsers(const std::vector<KeyBytes>& users)
{
    LivenessCheck check;
    {
        LOCK(g_liveness_mutex);
        check = g_liveness;
    }
    if (!check) return users;
    std::vector<KeyBytes> live;
    live.reserve(users.size());
    for (const KeyBytes& key : users) {
        if (check(key)) live.push_back(key);
    }
    return live;
}

bool SaveUsers(const std::vector<KeyBytes>& users, std::string& error)
{
    const fs::path path = ListPath();
    fsbridge::ofstream file(path, std::ios::trunc);
    if (!file.is_open()) {
        error = "Cannot write " + path.string();
        return false;
    }

    file << "# Peers this node lists and shares its block reward with.\n"
         << "# One 32-byte roster key per line. See -relayshare.\n";
    for (size_t i = 0; i < users.size(); ++i) {
        file << HexStr(users[i]) << "\n";
    }
    file.close();
    return true;
}

} // namespace roster
