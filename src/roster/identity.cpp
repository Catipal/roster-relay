// Copyright (c) 2026 The BPS developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <roster/identity.h>

#include <hash.h>

#include <algorithm>

namespace roster {

uint256 RecoveryCommitment(const KeyBytes& recovery_key)
{
    CHashWriter writer = TaggedHash("BPS/recovery/v1");
    writer.write((const char*)recovery_key.data(), recovery_key.size());
    return writer.GetSHA256();
}

AgeChain WalkAgeChain(const KeyBytes& key, const std::vector<HeldRecord>& history, int tip)
{
    AgeChain chain;
    std::vector<HeldRecord> sorted;
    for (const HeldRecord& h : history) {
        if (h.height <= tip) sorted.push_back(h);
    }
    std::sort(sorted.begin(), sorted.end());

    const HeldRecord* cur = nullptr;
    for (auto it = sorted.rbegin(); it != sorted.rend(); ++it) {
        if (it->rec.type == RecordType::ANNOUNCE && it->rec.op_key == key) {
            cur = &*it;
            break;
        }
    }
    if (!cur) return chain;
    chain.links.push_back(*cur);
    chain.anchor = cur->height;

    while (cur->rec.type == RecordType::ANNOUNCE) {
        const uint32_t prev = cur->rec.prev_height;
        // Heights only fall along the chain; anything else is not a link.
        if (prev == 0 || (int64_t)prev >= cur->height) break;
        const HeldRecord* announce = nullptr;
        const HeldRecord* delegate = nullptr;
        int delegates = 0;
        for (const HeldRecord& h : sorted) {
            if (h.height != (int)prev) continue;
            if (h.rec.type == RecordType::ANNOUNCE && h.rec.op_key == key) {
                announce = &h;
            } else if (h.rec.type == RecordType::DELEGATE && h.rec.op_key == key) {
                delegate = &h;
                ++delegates;
            }
        }
        // Two identities delegating to this key in the block it pointed at
        // leave it unclear which it accepted, so it accepted neither.
        const HeldRecord* next = announce ? announce : (delegates == 1 ? delegate : nullptr);
        if (!next) break;
        chain.links.push_back(*next);
        chain.anchor = next->height;
        if (next->rec.type == RecordType::DELEGATE) {
            chain.delegation = *next;
            break;
        }
        cur = next;
    }
    return chain;
}

IdentityState& IdentityBook::Touch(const KeyBytes& key, int height)
{
    auto it = m_ids.find(key);
    if (it == m_ids.end()) {
        IdentityState s;
        s.key = key;
        s.first_height = height;
        it = m_ids.emplace(key, s).first;
    }
    return it->second;
}

void IdentityBook::Settle(int height)
{
    // Collected first: taking effect touches the map.
    std::vector<KeyBytes> due;
    for (const auto& item : m_ids) {
        const IdentityState& s = item.second;
        if (s.rotating && s.rotate_height + ROTATE_VETO <= height) due.push_back(item.first);
    }
    for (const KeyBytes& key : due) {
        IdentityState& old = m_ids[key];
        const KeyBytes to = old.rotating_to;
        const int effective = old.rotate_height + ROTATE_VETO;
        old.rotating = false;
        old.retired = true;
        old.successor = to;
        const int first = old.first_height;
        const Optional<uint256> commit = old.recovery_commit;
        std::vector<KeyBytes> before = old.predecessors;
        before.push_back(key);
        IdentityState& next = Touch(to, effective);
        next.first_height = next.first_height < 0 ? first : std::min(next.first_height, first);
        if (!next.recovery_commit) next.recovery_commit = commit;
        next.predecessors.insert(next.predecessors.end(), before.begin(), before.end());
    }
}

void IdentityBook::Apply(const HeldRecord& held)
{
    const Record& rec = held.rec;
    const int h = held.height;
    switch (rec.type) {
    case RecordType::DELEGATE: {
        auto existing = m_ids.find(rec.id_key);
        if (existing != m_ids.end() && existing->second.retired) return;
        IdentityState& s = Touch(rec.id_key, h);
        if (!s.had_delegate) {
            s.had_delegate = true;
            if (rec.recovery_commit) s.recovery_commit = rec.recovery_commit;
        }
        s.delegations[rec.op_key] = std::make_pair(h, rec.expiry_height);
        return;
    }
    case RecordType::ROTATE: {
        auto it = m_ids.find(rec.id_key);
        if (it == m_ids.end() || it->second.retired || it->second.rotating) return;
        if (rec.new_id_key == rec.id_key) return;
        const auto target = m_ids.find(rec.new_id_key);
        if (target != m_ids.end() && (target->second.retired || target->second.first_height < h)) return;
        it->second.rotating = true;
        it->second.rotating_to = rec.new_id_key;
        it->second.rotate_height = h;
        return;
    }
    case RecordType::VETO: {
        auto it = m_ids.find(rec.id_key);
        if (it == m_ids.end()) return;
        IdentityState& s = it->second;
        if (!s.rotating || !s.recovery_commit) return;
        if (RecoveryCommitment(rec.recovery_key) != *s.recovery_commit) return;
        if (h >= s.rotate_height + ROTATE_VETO) return;
        s.rotating = false;
        s.vetoed.push_back(s.rotate_height);
        return;
    }
    case RecordType::ANNOUNCE:
    case RecordType::REVOKE:
        return;
    }
}

void IdentityBook::Build(std::vector<HeldRecord> records, int tip)
{
    m_ids.clear();
    std::sort(records.begin(), records.end());
    for (const HeldRecord& held : records) {
        if (held.height > tip) break;
        Settle(held.height);
        Apply(held);
    }
    Settle(tip);
}

const IdentityState* IdentityBook::Find(const KeyBytes& key) const
{
    const auto it = m_ids.find(key);
    return it == m_ids.end() ? nullptr : &it->second;
}

KeyBytes IdentityBook::Current(const KeyBytes& key) const
{
    KeyBytes cur = key;
    // Bounded: a retired key's successor never leads back, but do not trust that.
    for (size_t i = 0; i <= m_ids.size(); ++i) {
        const IdentityState* s = Find(cur);
        if (!s || !s->retired) return cur;
        cur = s->successor;
    }
    return cur;
}

bool IdentityBook::Delegates(const KeyBytes& id, const KeyBytes& op, int tip) const
{
    const IdentityState* s = Find(id);
    if (!s || s->retired) return false;
    const auto it = s->delegations.find(op);
    return it != s->delegations.end() && (int64_t)it->second.second > tip;
}

} // namespace roster
