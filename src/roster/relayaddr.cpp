// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/relayaddr.h>

#include <crypto/common.h>
#include <fs.h>
#include <hash.h>
#include <key.h>
#include <netaddress.h>
#include <pubkey.h>
#include <roster/peers.h>
#include <util/system.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace roster {

std::unique_ptr<RelayAddressBook> g_relay_addresses;

namespace {

constexpr unsigned char VERSION = 1;
constexpr size_t FIXED = 1 + 32 + 8 + 1;
constexpr size_t SIG = 64;

uint256 SigHash(const std::vector<unsigned char>& raw, const std::string& chain_id)
{
    // Its own tag, so no chain record and no other message signs the same bytes.
    CHashWriter writer = TaggedHash("BPS/relayaddr/v1/" + chain_id);
    writer.write((const char*)raw.data(), raw.size() - SIG);
    return writer.GetSHA256();
}

bool CarriedNetwork(uint8_t network)
{
    // The overlay is UDP: only networks that carry it.
    return network == EP_IPV4 || network == EP_IPV6;
}

} // namespace

std::vector<unsigned char> SerializeRelayAddress(const RelayAddress& a)
{
    std::vector<unsigned char> out;
    out.push_back(VERSION);
    out.insert(out.end(), a.key.begin(), a.key.end());
    unsigned char t[8];
    WriteLE64(t, (uint64_t)a.time);
    out.insert(out.end(), t, t + 8);
    out.push_back((unsigned char)a.endpoints.size());
    for (const Endpoint& ep : a.endpoints) {
        out.push_back(ep.network);
        out.insert(out.end(), ep.addr.begin(), ep.addr.end());
        out.push_back((unsigned char)(ep.port >> 8));
        out.push_back((unsigned char)ep.port);
    }
    out.insert(out.end(), a.sig.begin(), a.sig.end());
    return out;
}

bool ParseRelayAddress(const std::vector<unsigned char>& raw, RelayAddress& out)
{
    out = RelayAddress();
    if (raw.size() < FIXED + SIG || raw[0] != VERSION) return false;
    std::copy(raw.begin() + 1, raw.begin() + 33, out.key.begin());
    out.time = (int64_t)ReadLE64(raw.data() + 33);
    const size_t count = raw[41];
    if (count == 0 || count > MAX_RELAY_ADDR_ENDPOINTS) return false;
    size_t at = FIXED;
    for (size_t i = 0; i < count; ++i) {
        if (at + 1 > raw.size() - SIG) return false;
        Endpoint ep;
        ep.network = raw[at++];
        if (!CarriedNetwork(ep.network)) return false;
        const size_t len = EndpointAddrSize(ep.network);
        if (len == 0 || at + len + 2 > raw.size() - SIG) return false;
        ep.addr.assign(raw.begin() + at, raw.begin() + at + len);
        at += len;
        ep.port = (uint16_t)((raw[at] << 8) | raw[at + 1]);
        at += 2;
        if (ep.port == 0) return false;
        out.endpoints.push_back(ep);
    }
    // Exactly the signature left: nothing trailing that the signature would not cover.
    if (at + SIG != raw.size()) return false;
    std::copy(raw.end() - SIG, raw.end(), out.sig.begin());
    return true;
}

bool SignRelayAddress(RelayAddress& a, const CKey& key, const std::string& chain_id)
{
    const CPubKey pub = key.GetPubKey();
    if (!std::equal(a.key.begin(), a.key.end(), pub.begin() + 1)) return false;
    const std::vector<unsigned char> raw = SerializeRelayAddress(a);
    return key.SignSchnorr(SigHash(raw, chain_id), Span<unsigned char>(a.sig.data(), a.sig.size()));
}

bool VerifyRelayAddress(const RelayAddress& a, const std::string& chain_id)
{
    const std::vector<unsigned char> raw = SerializeRelayAddress(a);
    const XOnlyPubKey pub(Span<const unsigned char>(a.key.data(), a.key.size()));
    return pub.VerifySchnorr(SigHash(raw, chain_id), Span<const unsigned char>(a.sig.data(), a.sig.size()));
}

RelayAddressBook::AddResult RelayAddressBook::Add(const std::vector<unsigned char>& raw, int64_t now,
                                                  const RelayCheck& is_relay)
{
    RelayAddress a;
    if (raw.size() > MAX_RELAY_ADDR_SIZE || !ParseRelayAddress(raw, a)) return AddResult::INVALID;
    if (a.time > now + RELAY_ADDR_FUTURE || a.time + RELAY_ADDR_TTL <= now) return AddResult::STALE;
    {
        // Cheap checks before the signature: something already held as new,
        // newer, or only just older is not worth verifying again.
        LOCK(m_mutex);
        std::map<KeyBytes, Entry>::const_iterator it = m_entries.find(a.key);
        if (it != m_entries.end() && a.time < it->second.parsed.time + RELAY_ADDR_MIN_INTERVAL) return AddResult::KNOWN;
    }
    if (!VerifyRelayAddress(a, m_chain_id)) return AddResult::INVALID;
    if (!is_relay || !is_relay(a.key)) return AddResult::NOT_RELAY;
    LOCK(m_mutex);
    std::map<KeyBytes, Entry>::iterator it = m_entries.find(a.key);
    if (it != m_entries.end()) {
        if (a.time < it->second.parsed.time + RELAY_ADDR_MIN_INTERVAL) return AddResult::KNOWN;
    } else if (m_entries.size() >= MAX_RELAY_ADDRESSES) {
        // Full of relays the roster lists: the oldest announcement goes.
        std::map<KeyBytes, Entry>::iterator oldest = m_entries.begin();
        for (std::map<KeyBytes, Entry>::iterator e = m_entries.begin(); e != m_entries.end(); ++e) {
            if (e->second.parsed.time < oldest->second.parsed.time) oldest = e;
        }
        m_entries.erase(oldest);
    }
    Entry& e = m_entries[a.key];
    e.parsed = a;
    e.raw = raw;
    ++m_generation;
    return AddResult::NEW;
}

bool RelayAddressBook::Current(const KeyBytes& key, int64_t now, RelayAddress& out) const
{
    LOCK(m_mutex);
    std::map<KeyBytes, Entry>::const_iterator it = m_entries.find(key);
    if (it == m_entries.end() || it->second.parsed.time + RELAY_ADDR_TTL <= now) return false;
    out = it->second.parsed;
    return true;
}

std::vector<std::vector<unsigned char>> RelayAddressBook::FreshRaw(int64_t now, size_t max) const
{
    std::vector<std::pair<int64_t, const std::vector<unsigned char>*>> fresh;
    LOCK(m_mutex);
    for (const std::pair<const KeyBytes, Entry>& e : m_entries) {
        if (e.second.parsed.time + RELAY_ADDR_TTL > now) fresh.emplace_back(e.second.parsed.time, &e.second.raw);
    }
    std::sort(fresh.begin(), fresh.end(),
              [](const std::pair<int64_t, const std::vector<unsigned char>*>& a,
                 const std::pair<int64_t, const std::vector<unsigned char>*>& b) { return a.first > b.first; });
    std::vector<std::vector<unsigned char>> out;
    for (size_t i = 0; i < fresh.size() && i < max; ++i) out.push_back(*fresh[i].second);
    return out;
}

uint64_t RelayAddressBook::Generation() const
{
    LOCK(m_mutex);
    return m_generation;
}

void RelayAddressBook::Expire(int64_t now)
{
    LOCK(m_mutex);
    for (std::map<KeyBytes, Entry>::iterator it = m_entries.begin(); it != m_entries.end();) {
        if (it->second.parsed.time + RELAY_ADDR_TTL <= now) {
            it = m_entries.erase(it);
            ++m_generation;
        } else {
            ++it;
        }
    }
}

int64_t NextAnnouncementTime(const std::vector<Endpoint>& current, const RelayAddress* last, int64_t now)
{
    if (current.empty()) return 0;
    if (last == nullptr || last->time + RELAY_ADDR_TTL <= now) return now;
    if (last->endpoints != current) {
        const int64_t at = std::max(now, last->time + RELAY_ADDR_MIN_INTERVAL);
        // A minute short of the limit, for clocks a little behind this one.
        return at <= now + RELAY_ADDR_FUTURE - 60 ? at : 0;
    }
    return now >= last->time + RELAY_ADDR_REFRESH ? now : 0;
}

bool ReadOwnRelayAddress(const fs::path& path, const std::string& chain_id, RelayAddress& out,
                         std::vector<unsigned char>& raw_out)
{
    FILE* file = fsbridge::fopen(path, "rb");
    if (file == nullptr) return false;
    std::vector<unsigned char> raw(MAX_RELAY_ADDR_SIZE + 1);
    const size_t n = fread(raw.data(), 1, raw.size(), file);
    fclose(file);
    raw.resize(n);
    if (!ParseRelayAddress(raw, out) || !VerifyRelayAddress(out, chain_id)) return false;
    raw_out = raw;
    return true;
}

bool WriteOwnRelayAddress(const fs::path& path, const std::vector<unsigned char>& raw)
{
    // Written beside and renamed over, so a crash leaves the old one whole.
    const fs::path tmp = path.string() + ".new";
    FILE* file = fsbridge::fopen(tmp, "wb");
    if (file == nullptr) return false;
    const bool written = fwrite(raw.data(), 1, raw.size(), file) == raw.size();
    if (fclose(file) != 0 || !written) return false;
    return RenameOver(tmp, path);
}

std::vector<Endpoint> ChooseRelayEndpoints(const std::vector<CService>& fixed, const std::vector<CNetAddr>& seen,
                                           const std::vector<CNetAddr>& local, uint16_t port, bool allow_local)
{
    std::vector<Endpoint> out;
    bool have4 = false, have6 = false;
    auto usable = [allow_local](const CNetAddr& a) {
        return (a.IsIPv4() || a.IsIPv6()) && (allow_local || a.IsRoutable());
    };
    auto take = [&](const CService& s) {
        if (!usable(s)) return;
        bool& have = s.IsIPv4() ? have4 : have6;
        if (have) return;
        Endpoint ep;
        if (!ServiceToEndpoint(s, ep)) return;
        have = true;
        out.push_back(ep);
    };
    if (!fixed.empty()) {
        for (const CService& s : fixed) take(s);
        return out;
    }
    // One vote per outbound peer: the address it saw this node connect from.
    std::map<CNetAddr, int> votes;
    int total4 = 0, total6 = 0;
    for (const CNetAddr& a : seen) {
        if (!usable(a)) continue;
        ++votes[a];
        ++(a.IsIPv4() ? total4 : total6);
    }
    for (int family = 0; family < 2; ++family) {
        const CNetAddr* best = nullptr;
        int best_votes = 0;
        for (const std::pair<const CNetAddr, int>& v : votes) {
            if (v.first.IsIPv4() != (family == 0)) continue;
            if (v.second > best_votes) {
                best = &v.first;
                best_votes = v.second;
            }
        }
        const int total = family == 0 ? total4 : total6;
        if (best != nullptr && best_votes >= 2 && 2 * best_votes > total) take(CService(*best, port));
    }
    for (const CNetAddr& a : local) take(CService(a, port));
    return out;
}

size_t RelayAddressBook::Size() const
{
    LOCK(m_mutex);
    return m_entries.size();
}

void RelayAddressBook::SetOwn(const KeyBytes& key)
{
    LOCK(m_mutex);
    m_own = key;
    m_have_own = true;
}

bool RelayAddressBook::OwnRaw(int64_t now, std::vector<unsigned char>& raw_out) const
{
    LOCK(m_mutex);
    if (!m_have_own) return false;
    std::map<KeyBytes, Entry>::const_iterator it = m_entries.find(m_own);
    if (it == m_entries.end() || it->second.parsed.time + RELAY_ADDR_TTL <= now) return false;
    raw_out = it->second.raw;
    return true;
}

} // namespace roster
