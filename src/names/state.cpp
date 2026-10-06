// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/state.h>

#include <names/name.h>
#include <tinyformat.h>
#include <util/moneystr.h>

#include <algorithm>

namespace names {

namespace {

bool IsZero(const roster::KeyBytes& k)
{
    return std::all_of(k.begin(), k.end(), [](unsigned char c) { return c == 0; });
}

std::string Coins(CAmount amount)
{
    return FormatMoney(amount) + " BPS";
}

} // namespace

std::string StatusString(Status status)
{
    switch (status) {
    case Status::FREE: return "free";
    case Status::LIVE: return "live";
    case Status::GRACE: return "grace";
    }
    return "unknown";
}

NameState::NameState(const std::string& chain_id) : m_chain_id(chain_id), m_start(names::StartHeight(chain_id)) {}

Status NameState::StatusOf(const std::string& root, int height) const
{
    const auto it = m_names.find(root);
    if (it == m_names.end()) return Status::FREE;
    if ((int64_t)height < (int64_t)it->second.expiry) return Status::LIVE;
    if ((int64_t)height < (int64_t)it->second.expiry + GRACE) return Status::GRACE;
    return Status::FREE;
}

const NameEntry* NameState::Find(const std::string& root) const
{
    const auto it = m_names.find(root);
    return it == m_names.end() ? nullptr : &it->second;
}

int NameState::CommitHeight(const uint256& commitment) const
{
    const auto it = m_commits.find(commitment);
    return it == m_commits.end() ? -1 : it->second;
}

std::vector<std::pair<std::string, NameEntry>> NameState::Everything() const
{
    return std::vector<std::pair<std::string, NameEntry>>(m_names.begin(), m_names.end());
}

size_t NameState::CountLive(int height) const
{
    size_t n = 0;
    for (const auto& entry : m_names) {
        if (StatusOf(entry.first, height) == Status::LIVE) ++n;
    }
    return n;
}

std::vector<std::pair<std::string, NameEntry>> NameState::OwnedBy(const roster::KeyBytes& owner) const
{
    std::vector<std::pair<std::string, NameEntry>> out;
    for (const auto& entry : m_names) {
        if (entry.second.owner == owner) out.push_back(entry);
    }
    return out;
}

std::string NameState::CheckFresh(const std::string& name, const roster::KeyBytes& owner, int height) const
{
    if (height < m_start) return "Names have not started on this network yet.";
    if (!IsValidRoot(name)) {
        return strprintf("A name is %u to %u letters, digits or inner hyphens.", (unsigned)MIN_ROOT_LENGTH,
                         (unsigned)MAX_LABEL_LENGTH);
    }
    const Status status = StatusOf(name, height);
    if (status != Status::FREE) {
        const NameEntry* entry = Find(name);
        if (entry && entry->owner == owner) {
            return status == Status::LIVE ? "You hold this name already; renew it instead."
                                          : "This name has expired but is yours to renew for a while yet.";
        }
        return status == Status::LIVE ? "This name is taken."
                                      : "This name has just expired; its holder can still renew it.";
    }
    // Look-alikes of a name somebody else holds, live or in grace.
    const auto it = m_skeletons.find(Skeleton(name));
    if (it != m_skeletons.end()) {
        for (const std::string& other : it->second) {
            if (other == name || StatusOf(other, height) == Status::FREE) continue;
            if (Find(other)->owner == owner) continue;
            return strprintf("This name looks too much like %s, which someone else holds.", other);
        }
    }
    return std::string();
}

std::string NameState::CheckAvailable(const std::string& name, const roster::KeyBytes& owner, int height) const
{
    return CheckFresh(name, owner, height);
}

std::string NameState::CheckClaim(const std::string& name, const roster::KeyBytes& owner, const Salt& salt,
                                  uint32_t expiry, CAmount burn, int height) const
{
    const Status status = StatusOf(name, height);
    const NameEntry* entry = Find(name);
    if (status != Status::FREE) {
        // A renewal.
        if (entry->owner != owner) return "This name is held by someone else.";
        if (expiry <= entry->expiry) return "A renewal has to end later than the name ends now.";
        if ((int64_t)expiry - height > MAX_TERM) return "A name can be paid at most two years ahead.";
        const uint32_t from = std::max<uint32_t>(entry->expiry, (uint32_t)height);
        const CAmount price = Price(name.size(), expiry - from);
        if (burn < price) return strprintf("Renewing costs %s; this burns %s.", Coins(price), Coins(burn));
        return std::string();
    }
    const std::string fresh = CheckFresh(name, owner, height);
    if (!fresh.empty()) return fresh;
    const uint256 c = Commitment(name, salt, owner);
    const int committed = CommitHeight(c);
    if (committed < 0) return "There is no commitment on the chain for this registration.";
    if (height - committed < (int)COMMIT_MIN_AGE) {
        return strprintf("The commitment needs %d more blocks before the name can be claimed.",
                         (int)COMMIT_MIN_AGE - (height - committed));
    }
    if (height - committed > (int)COMMIT_MAX_AGE) return "The commitment is too old; commit again.";
    if (m_used.count(c)) return "That commitment has been used already.";
    if ((int64_t)expiry <= height || (int64_t)expiry - height < MIN_TERM) return "A name is registered for at least a month.";
    if ((int64_t)expiry - height > MAX_TERM) return "A name can be paid at most two years ahead.";
    const CAmount price = Price(name.size(), expiry - height);
    if (burn < price) return strprintf("Registering costs %s; this burns %s.", Coins(price), Coins(burn));
    return std::string();
}

void NameState::Prune(int height)
{
    for (auto it = m_commits.begin(); it != m_commits.end();) {
        if (height - it->second > (int)COMMIT_MAX_AGE) {
            m_used.erase(it->first);
            it = m_commits.erase(it);
        } else {
            ++it;
        }
    }
}

void NameState::ApplyBlock(int height, const std::vector<IndexedRecord>& records)
{
    Prune(height);
    for (const IndexedRecord& rec : records) {
        if (rec.height == height) Apply(rec);
    }
}

std::string NameState::Apply(const IndexedRecord& indexed)
{
    const int h = indexed.height;
    if (h < m_start) return "before names started on this network";
    NameRecord rec;
    if (!ParseNameRecord(indexed.raw, rec)) return "not a name record";

    switch (rec.type) {
    case NameRecordType::COMMIT:
        // The first sighting counts: a later copy of the same commitment cannot
        // make it look younger.
        m_commits.emplace(rec.commitment, h);
        return std::string();

    case NameRecordType::CLAIM: {
        if (!VerifyNameRecord(rec, indexed.raw, rec.key, m_chain_id)) return "not signed by the owner it names";
        const std::string why = CheckClaim(rec.name, rec.key, rec.salt, rec.expiry_height, indexed.burned, h);
        if (!why.empty()) return why;
        const Status status = StatusOf(rec.name, h);
        if (status != Status::FREE) {
            NameEntry& entry = m_names[rec.name];
            entry.expiry = rec.expiry_height;
            entry.changed = h;
            return std::string();
        }
        NameEntry entry;
        entry.owner = rec.key;
        entry.expiry = rec.expiry_height;
        entry.registered = h;
        entry.changed = h;
        m_names[rec.name] = entry;
        m_skeletons[Skeleton(rec.name)].insert(rec.name);
        m_used.insert(Commitment(rec.name, rec.salt, rec.key));
        return std::string();
    }

    case NameRecordType::TRANSFER: {
        if (StatusOf(rec.name, h) != Status::LIVE) return "only a live name can be transferred";
        NameEntry& entry = m_names[rec.name];
        if (!VerifyNameRecord(rec, indexed.raw, entry.owner, m_chain_id)) return "not signed by the holder";
        if (IsZero(rec.key)) return "no new holder";
        entry.owner = rec.key;
        entry.changed = h;
        return std::string();
    }

    case NameRecordType::SUBNAME: {
        if (StatusOf(rec.name, h) != Status::LIVE) return "subnames are issued under a live name only";
        NameEntry& entry = m_names[rec.name];
        if (!VerifyNameRecord(rec, indexed.raw, entry.owner, m_chain_id)) return "not signed by the holder";
        if (IsZero(rec.key) || (int64_t)rec.expiry_height <= h) {
            entry.subnames.erase(rec.label);
            return std::string();
        }
        if ((int64_t)rec.expiry_height - h > MAX_TERM) return "a subname can run at most two years ahead";
        Subname sub;
        sub.key = rec.key;
        sub.expiry = rec.expiry_height;
        sub.height = h;
        entry.subnames[rec.label] = sub;
        return std::string();
    }
    }
    return "unknown record";
}

bool NameState::Resolve(const std::string& full, int height, Resolution& out, std::string& why) const
{
    std::string normal, root, label;
    if (!Normalize(full, normal) || !SplitName(normal, root, label)) {
        why = "That is not a valid name.";
        return false;
    }
    const Status status = StatusOf(root, height);
    if (status == Status::FREE) {
        why = strprintf("Nobody holds %s.", root);
        return false;
    }
    if (status == Status::GRACE) {
        why = strprintf("%s has expired; its holder has not renewed it.", root);
        return false;
    }
    const NameEntry& entry = *Find(root);
    out = Resolution();
    out.name = normal;
    out.owner = entry.owner;
    out.registered = entry.registered;
    if (label.empty()) {
        out.key = entry.owner;
        out.expiry = entry.expiry;
        out.changed = entry.changed;
        return true;
    }
    const auto it = entry.subnames.find(label);
    if (it == entry.subnames.end() || (int64_t)it->second.expiry <= height) {
        why = strprintf("%s has no subname %s.", root, label);
        return false;
    }
    out.subname = true;
    out.key = it->second.key;
    out.expiry = std::min(it->second.expiry, entry.expiry);
    out.changed = std::max(entry.changed, it->second.height);
    return true;
}

} // namespace names
