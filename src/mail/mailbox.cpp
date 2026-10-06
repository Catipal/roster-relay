// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/mailbox.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <dbwrapper.h>
#include <hash.h>
#include <random.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace mail {

std::unique_ptr<Mailbox> g_mailbox;

namespace {

const char DB_ITEM = 'i';
const char DB_KEY = 'k';

using ItemKey = std::pair<char, std::pair<uint256, uint256>>;
using ItemValue = std::pair<int64_t, std::vector<unsigned char>>;
using OwnerKey = std::pair<char, uint256>;

uint256 AsU256(const roster::KeyBytes& k)
{
    uint256 out;
    std::memcpy(out.begin(), k.data(), 32);
    return out;
}

roster::KeyBytes AsKey(const uint256& u)
{
    roster::KeyBytes out;
    std::memcpy(out.data(), u.begin(), 32);
    return out;
}

uint256 AuthHash(const Auth& auth, const roster::KeyBytes& mailbox, const std::string& chain_id)
{
    unsigned char buf[32 + 32 + 8 + 8];
    std::memcpy(buf, mailbox.data(), 32);
    std::memcpy(buf + 32, auth.owner.data(), 32);
    WriteLE64(buf + 64, (uint64_t)auth.time);
    WriteLE64(buf + 72, auth.nonce);
    CHashWriter writer = TaggedHash("BPS/mailbox-auth/v" + std::to_string(MAIL_VERSION) + "/" + chain_id);
    writer.write((const char*)buf, sizeof(buf));
    return writer.GetSHA256();
}

} // namespace

std::vector<roster::KeyBytes> MailboxesFor(const roster::KeyBytes& owner,
                                           const std::vector<roster::KeyBytes>& relays,
                                           size_t count)
{
    std::vector<std::pair<uint256, roster::KeyBytes>> scored;
    scored.reserve(relays.size());
    static const std::string TAG = "BPS mailbox";
    for (const roster::KeyBytes& relay : relays) {
        if (relay == owner) continue;
        uint256 score;
        CSHA256()
            .Write((const unsigned char*)TAG.data(), TAG.size())
            .Write(owner.data(), owner.size())
            .Write(relay.data(), relay.size())
            .Finalize(score.begin());
        scored.emplace_back(score, relay);
    }
    // Highest first. Compared as bytes, which is all an ordering needs to be
    // the same on every node.
    std::sort(scored.begin(), scored.end(),
              [](const std::pair<uint256, roster::KeyBytes>& a, const std::pair<uint256, roster::KeyBytes>& b) {
                  const int c = std::memcmp(a.first.begin(), b.first.begin(), 32);
                  return c != 0 ? c > 0 : a.second < b.second;
              });
    std::vector<roster::KeyBytes> out;
    for (size_t i = 0; i < scored.size() && out.size() < count; ++i) {
        if (std::find(out.begin(), out.end(), scored[i].second) == out.end()) out.push_back(scored[i].second);
    }
    return out;
}

std::vector<unsigned char> SerializeAuth(const Auth& auth)
{
    std::vector<unsigned char> out(auth.owner.begin(), auth.owner.end());
    unsigned char b[8];
    WriteLE64(b, (uint64_t)auth.time);
    out.insert(out.end(), b, b + 8);
    WriteLE64(b, auth.nonce);
    out.insert(out.end(), b, b + 8);
    out.insert(out.end(), auth.sig.begin(), auth.sig.end());
    return out;
}

bool ParseAuth(const unsigned char* data, size_t len, Auth& out)
{
    if (len != AUTH_SIZE) return false;
    std::copy(data, data + 32, out.owner.begin());
    out.time = (int64_t)ReadLE64(data + 32);
    out.nonce = ReadLE64(data + 40);
    std::copy(data + 48, data + 112, out.sig.begin());
    return true;
}

bool MakeAuth(const CKey& owner, const roster::KeyBytes& mailbox, const std::string& chain_id,
              int64_t now, Auth& out)
{
    out = Auth();
    out.owner = XOnly(owner.GetPubKey());
    out.time = now;
    out.nonce = GetRand(std::numeric_limits<uint64_t>::max());
    return owner.SignSchnorr(AuthHash(out, mailbox, chain_id), Span<unsigned char>(out.sig.data(), out.sig.size()));
}

Mailbox::Mailbox(const fs::path& dir, uint64_t max_bytes, const roster::KeyBytes& self,
                 const std::string& chain_id, bool memory_only)
    : m_max_bytes(max_bytes), m_self(self), m_chain_id(chain_id)
{
    LOCK(m_mutex);
    m_db.reset(new CDBWrapper(dir, 1 << 20, memory_only, false, false));
    LoadUsage();
}

Mailbox::~Mailbox() {}

void Mailbox::SetOwnerCheck(OwnerCheck check)
{
    LOCK(m_mutex);
    m_owner_check = std::move(check);
}

bool Mailbox::Allowed(const roster::KeyBytes& owner)
{
    // Asked without the mailbox lock held: the check reads the roster, and
    // nothing here should be able to wait on that while holding mail.
    OwnerCheck check;
    {
        LOCK(m_mutex);
        check = m_owner_check;
    }
    return !check || check(owner);
}

void Mailbox::LoadUsage()
{
    m_usage.clear();
    m_total_bytes = 0;
    m_keys = 0;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(ItemKey(DB_ITEM, std::make_pair(uint256(), uint256()))); it->Valid(); it->Next()) {
        ItemKey key;
        if (!it->GetKey(key) || key.first != DB_ITEM) break;
        ItemValue value;
        if (!it->GetValue(value)) continue;
        Usage& u = m_usage[AsKey(key.second.first)];
        ++u.items;
        u.bytes += value.second.size();
        m_total_bytes += value.second.size();
    }
    for (it->Seek(OwnerKey(DB_KEY, uint256())); it->Valid(); it->Next()) {
        OwnerKey key;
        if (!it->GetKey(key) || key.first != DB_KEY) break;
        ++m_keys;
    }
}

bool Mailbox::PutPreKey(const PreKey& key, int64_t now, std::string& reason)
{
    if (!VerifyPreKey(key, m_chain_id)) {
        reason = "That mail key is not signed by the key it names.";
        return false;
    }
    if (key.expires <= now) {
        reason = "That mail key has expired.";
        return false;
    }
    if (key.created > now + AUTH_WINDOW) {
        reason = "That mail key is dated in the future.";
        return false;
    }
    if (!Allowed(key.owner)) {
        reason = "This relay is not one of that person's mailboxes.";
        return false;
    }
    LOCK(m_mutex);
    const OwnerKey db_key(DB_KEY, AsU256(key.owner));
    std::vector<unsigned char> raw;
    PreKey held;
    const bool had = m_db->Read(db_key, raw) && ParsePreKey(raw, held);
    if (had && held.created > key.created) {
        reason = "A newer mail key is held here already.";
        return false;
    }
    if (!m_db->Write(db_key, SerializePreKey(key))) {
        reason = "This relay could not store the key.";
        return false;
    }
    if (!had) ++m_keys;
    return true;
}

bool Mailbox::GetPreKey(const roster::KeyBytes& owner, int64_t now, PreKey& out)
{
    LOCK(m_mutex);
    std::vector<unsigned char> raw;
    if (!m_db->Read(OwnerKey(DB_KEY, AsU256(owner)), raw)) return false;
    if (!ParsePreKey(raw, out)) return false;
    return out.expires > now;
}

bool Mailbox::Deposit(const std::vector<unsigned char>& envelope, int64_t now, uint256& id_out,
                      std::string& reason)
{
    roster::KeyBytes owner;
    uint64_t key_id = 0;
    if (!ReadEnvelope(envelope, owner, key_id)) {
        reason = "That is not a sealed letter.";
        return false;
    }
    id_out = EnvelopeId(envelope);
    if (!Allowed(owner)) {
        reason = "This relay is not one of that person's mailboxes.";
        return false;
    }
    LOCK(m_mutex);
    const ItemKey key(DB_ITEM, std::make_pair(AsU256(owner), id_out));
    if (m_db->Exists(key)) return true;

    Usage& u = m_usage[owner];
    if (u.items >= MAX_ITEMS_PER_OWNER || u.bytes + envelope.size() > MAX_BYTES_PER_OWNER) {
        reason = "That person's mailbox here is full.";
        return false;
    }
    if (m_total_bytes + envelope.size() > m_max_bytes) {
        reason = "This relay has no room for more mail.";
        return false;
    }
    if (!m_db->Write(key, ItemValue(now, envelope))) {
        reason = "This relay could not store the letter.";
        return false;
    }
    ++u.items;
    u.bytes += envelope.size();
    m_total_bytes += envelope.size();
    return true;
}

bool Mailbox::CheckAuth(const Auth& auth, int64_t now, std::string& reason)
{
    if (auth.time < now - AUTH_WINDOW || auth.time > now + AUTH_WINDOW) {
        reason = "The request's clock is too far from this relay's.";
        return false;
    }
    const XOnlyPubKey owner(Span<const unsigned char>(auth.owner.data(), auth.owner.size()));
    if (!owner.VerifySchnorr(AuthHash(auth, m_self, m_chain_id),
                             Span<const unsigned char>(auth.sig.data(), auth.sig.size()))) {
        reason = "The request is not signed by the mailbox's owner.";
        return false;
    }
    LOCK(m_mutex);
    // Forget nonces once their time could no longer pass the clock check.
    for (auto it = m_seen.begin(); it != m_seen.end();) {
        if (it->second < now - 2 * AUTH_WINDOW) {
            it = m_seen.erase(it);
        } else {
            ++it;
        }
    }
    const std::pair<roster::KeyBytes, uint64_t> seen(auth.owner, auth.nonce);
    if (m_seen.count(seen)) {
        reason = "That request was made already.";
        return false;
    }
    if (m_seen.size() >= 100000) {
        reason = "This relay is too busy.";
        return false;
    }
    m_seen[seen] = auth.time;
    return true;
}

std::vector<ItemInfo> Mailbox::List(const roster::KeyBytes& owner)
{
    LOCK(m_mutex);
    std::vector<ItemInfo> out;
    const uint256 who = AsU256(owner);
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(ItemKey(DB_ITEM, std::make_pair(who, uint256()))); it->Valid(); it->Next()) {
        ItemKey key;
        if (!it->GetKey(key) || key.first != DB_ITEM || key.second.first != who) break;
        ItemValue value;
        if (!it->GetValue(value)) continue;
        ItemInfo info;
        info.id = key.second.second;
        info.size = (uint32_t)value.second.size();
        info.received = value.first;
        out.push_back(info);
    }
    return out;
}

bool Mailbox::Fetch(const roster::KeyBytes& owner, const uint256& id, std::vector<unsigned char>& out)
{
    LOCK(m_mutex);
    ItemValue value;
    if (!m_db->Read(ItemKey(DB_ITEM, std::make_pair(AsU256(owner), id)), value)) return false;
    out = value.second;
    return true;
}

size_t Mailbox::Remove(const roster::KeyBytes& owner, const std::vector<uint256>& ids)
{
    LOCK(m_mutex);
    size_t removed = 0;
    for (const uint256& id : ids) {
        const ItemKey key(DB_ITEM, std::make_pair(AsU256(owner), id));
        ItemValue value;
        if (!m_db->Read(key, value)) continue;
        if (!m_db->Erase(key)) continue;
        Usage& u = m_usage[owner];
        u.items -= std::min<size_t>(u.items, 1);
        u.bytes -= std::min<uint64_t>(u.bytes, value.second.size());
        m_total_bytes -= std::min<uint64_t>(m_total_bytes, value.second.size());
        if (u.items == 0) m_usage.erase(owner);
        ++removed;
    }
    return removed;
}

size_t Mailbox::Expire(int64_t now)
{
    LOCK(m_mutex);
    std::vector<ItemKey> old_items;
    std::vector<OwnerKey> old_keys;
    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    for (it->Seek(ItemKey(DB_ITEM, std::make_pair(uint256(), uint256()))); it->Valid(); it->Next()) {
        ItemKey key;
        if (!it->GetKey(key) || key.first != DB_ITEM) break;
        ItemValue value;
        if (it->GetValue(value) && value.first + RETENTION < now) old_items.push_back(key);
    }
    for (it->Seek(OwnerKey(DB_KEY, uint256())); it->Valid(); it->Next()) {
        OwnerKey key;
        if (!it->GetKey(key) || key.first != DB_KEY) break;
        std::vector<unsigned char> raw;
        PreKey held;
        if (it->GetValue(raw) && (!ParsePreKey(raw, held) || held.expires <= now)) old_keys.push_back(key);
    }
    it.reset();
    if (old_items.empty() && old_keys.empty()) return 0;
    CDBBatch batch(*m_db);
    for (const ItemKey& k : old_items) batch.Erase(k);
    for (const OwnerKey& k : old_keys) batch.Erase(k);
    m_db->WriteBatch(batch);
    LoadUsage();
    return old_items.size();
}

Mailbox::Stats Mailbox::GetStats()
{
    LOCK(m_mutex);
    Stats s;
    s.owners = m_usage.size();
    for (const auto& u : m_usage) s.items += u.second.items;
    s.bytes = m_total_bytes;
    s.max_bytes = m_max_bytes;
    s.keys = m_keys;
    return s;
}

} // namespace mail
