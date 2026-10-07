// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/state.h>

#include <names/name.h>
#include <tinyformat.h>

#include <algorithm>

namespace names {

namespace {

bool IsZero(const roster::KeyBytes& k)
{
    return std::all_of(k.begin(), k.end(), [](unsigned char c) { return c == 0; });
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
                                  uint32_t expiry, int height) const
{
    const Status status = StatusOf(name, height);
    const NameEntry* entry = Find(name);
    if (status != Status::FREE) {
        // A renewal, for the fee alone.
        if (entry->owner != owner) return "This name is held by someone else.";
        if (expiry <= entry->expiry) return "A renewal has to end later than the name ends now.";
        if ((int64_t)expiry - height > MAX_TERM) return "A name can be renewed at most two years ahead.";
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
    if ((int64_t)expiry - height > MAX_TERM) return "A name can be registered at most two years ahead.";
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
    m_sold_in.clear();
    for (const IndexedRecord& rec : records) {
        if (rec.height == height) Apply(rec);
    }
    m_sold_in.clear();
}

const PayKey* NameState::PaymentKey(const roster::KeyBytes& key) const
{
    const auto it = m_paykeys.find(key);
    return it == m_paykeys.end() ? nullptr : &it->second;
}

const Offer* NameState::ActiveOffer(const std::string& name, int height) const
{
    const NameEntry* entry = Find(name);
    if (!entry || !entry->for_sale || StatusOf(name, height) == Status::FREE) return nullptr;
    return &entry->offer;
}

std::string NameState::CheckSell(const std::string& name, const roster::KeyBytes& owner, int height) const
{
    if (height < m_start) return "Names have not started on this network yet.";
    const NameEntry* entry = Find(name);
    if (!entry || StatusOf(name, height) != Status::LIVE || entry->owner != owner) {
        return strprintf("Only the holder of a live %s can sell it.", name);
    }
    if (entry->for_sale) return strprintf("%s is up for sale already; take it off sale first.", name);
    return std::string();
}

uint32_t NameState::BuyExpiry(const std::string& name, int years, int height) const
{
    const NameEntry* entry = Find(name);
    const uint32_t from = std::max<uint32_t>(entry ? entry->expiry : 0, (uint32_t)height);
    return std::min<uint32_t>(from + (uint32_t)years * BLOCKS_PER_YEAR, (uint32_t)height + MAX_TERM);
}

std::string NameState::CheckBuy(const std::string& name, const roster::KeyBytes& buyer, uint32_t expiry,
                                int height) const
{
    if (height < m_start) return "Names have not started on this network yet.";
    const Offer* offer = ActiveOffer(name, height);
    if (!offer) return strprintf("%s is not for sale.", name);
    const NameEntry& entry = *Find(name);
    if (entry.owner == buyer) return strprintf("This key holds %s already.", name);
    // The buyer keeps the term the name has, and may renew it in the same
    // breath - for nothing, as the holder would - up to two years ahead.
    const uint32_t from = std::max<uint32_t>(entry.expiry, (uint32_t)height);
    if (expiry < from) return "A purchase cannot shorten the name's term.";
    if ((int64_t)expiry - height > MAX_TERM) return "A name can be renewed at most two years ahead.";
    return std::string();
}

std::string NameState::Apply(const IndexedRecord& indexed)
{
    const int h = indexed.height;
    if (h < m_start) return "before names started on this network";
    if (indexed.spend) {
        const auto coin = m_sale_coins.find(indexed.spent);
        if (coin == m_sale_coins.end()) return "not a sale coin";
        const std::string name = coin->second;
        m_sale_coins.erase(coin);
        const auto it = m_names.find(name);
        if (it == m_names.end() || !it->second.for_sale || it->second.offer.coin != indexed.spent) {
            return "a sale that had already ended";
        }
        // Spending the coin ends the sale whoever spent it. If this transaction
        // also carries a BUY, the name goes with it.
        it->second.for_sale = false;
        m_sold_in[indexed.txid][name] = it->second.offer.seller;
        return std::string();
    }
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
        const std::string why = CheckClaim(rec.name, rec.key, rec.salt, rec.expiry_height, h);
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
        // Otherwise a seller who saw a buyer's transaction waiting could give
        // the name away first and be paid for nothing.
        if (entry.for_sale) return "the name is up for sale; its sale coin has to be spent first";
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

    case NameRecordType::SELL: {
        if (StatusOf(rec.name, h) != Status::LIVE) return "only a live name can be put up for sale";
        NameEntry& entry = m_names[rec.name];
        if (!VerifyNameRecord(rec, indexed.raw, entry.owner, m_chain_id)) return "not signed by the holder";
        // Selling again, or re-pricing, means spending the old sale coin first:
        // a second offer that could replace the first would let a seller swap
        // it out from under a buyer's transaction.
        if (entry.for_sale) return "already up for sale";
        // Otherwise a sale could point at a coin that never confirms, and the
        // name could then be neither sold nor taken off sale.
        if (!indexed.coin_funded) return "the sale coin's transaction is not on the chain before it";
        const auto other = m_sale_coins.find(rec.coin);
        if (other != m_sale_coins.end()) {
            const auto it = m_names.find(other->second);
            if (it != m_names.end() && it->second.for_sale && it->second.offer.coin == rec.coin) {
                return "that coin is selling another name";
            }
        }
        entry.for_sale = true;
        entry.offer.coin = rec.coin;
        entry.offer.payout_value = rec.payout_value;
        entry.offer.payout = rec.payout;
        entry.offer.coin_sig = rec.coin_sig;
        entry.offer.seller = entry.owner;
        entry.offer.height = h;
        m_sale_coins[rec.coin] = rec.name;
        return std::string();
    }

    case NameRecordType::PAYKEY: {
        // Any roster key may take payments; only it can say on what.
        if (!VerifyNameRecord(rec, indexed.raw, rec.key, m_chain_id)) return "not signed by the key it is for";
        if (!rec.point.IsCompressed()) return "a spending key is compressed";
        PayKey& pk = m_paykeys[rec.key];
        pk.spend = rec.point;
        pk.height = h;
        return std::string();
    }

    case NameRecordType::PAYMENT:
        return "a payment marker is not a name record";

    case NameRecordType::BUY: {
        const auto sold = m_sold_in.find(indexed.txid);
        if (sold == m_sold_in.end() || !sold->second.count(rec.name)) {
            return "this transaction did not spend the name's sale coin";
        }
        const roster::KeyBytes seller = sold->second[rec.name];
        sold->second.erase(rec.name);
        if (StatusOf(rec.name, h) == Status::FREE) return "nobody holds this name";
        NameEntry& entry = m_names[rec.name];
        if (entry.owner != seller) return "the name changed hands after it was put up";
        if (!VerifyNameRecord(rec, indexed.raw, rec.key, m_chain_id)) return "not signed by the buyer";
        // The sale was closed a moment ago by this same transaction; the terms
        // are checked as they stood with it open.
        entry.for_sale = true;
        const std::string why = CheckBuy(rec.name, rec.key, rec.expiry_height, h);
        entry.for_sale = false;
        if (!why.empty()) return why;
        entry.owner = rec.key;
        entry.expiry = rec.expiry_height;
        entry.registered = h;
        entry.changed = h;
        entry.subnames.clear();
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
