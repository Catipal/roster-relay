// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <names/registrar.h>

#include <core_io.h>
#include <index/nameindex.h>
#include <names/name.h>
#include <names/state.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <algorithm>

namespace names {

std::unique_ptr<Registrar> g_registrar;

namespace {

Mutex g_publisher_mutex;
ClaimPublisher g_publisher GUARDED_BY(g_publisher_mutex);

//! Finished and lost registrations stay listed this long, so people see how they ended.
constexpr int KEEP_FINISHED = 2000;
//! A claim that has not taken effect after this many blocks never will.
constexpr int CLAIM_PATIENCE = 30;

UniValue ToJSON(const PendingRegistration& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("name", p.name);
    o.pushKV("salt", HexStr(p.salt));
    o.pushKV("owner", HexStr(p.owner));
    o.pushKV("years", (int)p.years);
    o.pushKV("wallet", p.wallet);
    o.pushKV("commit_txid", p.commit_txid.GetHex());
    o.pushKV("started", p.started);
    o.pushKV("status", p.status);
    o.pushKV("claim_txid", p.claim_txid.GetHex());
    o.pushKV("claimed", p.claimed);
    o.pushKV("note", p.note);
    return o;
}

bool FromJSON(const UniValue& o, PendingRegistration& p)
{
    const std::vector<unsigned char> salt = ParseHex(find_value(o, "salt").getValStr());
    const std::vector<unsigned char> owner = ParseHex(find_value(o, "owner").getValStr());
    if (salt.size() != p.salt.size() || owner.size() != p.owner.size()) return false;
    std::copy(salt.begin(), salt.end(), p.salt.begin());
    std::copy(owner.begin(), owner.end(), p.owner.begin());
    p.name = find_value(o, "name").getValStr();
    p.years = (uint32_t)std::max(1, find_value(o, "years").isNum() ? find_value(o, "years").get_int() : 1);
    p.wallet = find_value(o, "wallet").getValStr();
    p.commit_txid = uint256S(find_value(o, "commit_txid").getValStr());
    p.started = find_value(o, "started").isNum() ? find_value(o, "started").get_int() : 0;
    p.status = find_value(o, "status").getValStr();
    p.claim_txid = uint256S(find_value(o, "claim_txid").getValStr());
    p.claimed = find_value(o, "claimed").isNum() ? find_value(o, "claimed").get_int() : 0;
    p.note = find_value(o, "note").getValStr();
    return !p.name.empty();
}

} // namespace

Registrar::Registrar(const fs::path& file) : m_file(file) {}

bool Registrar::Load(std::string& error)
{
    LOCK(m_mutex);
    m_pending.clear();
    if (!fs::exists(m_file)) return true;
    fsbridge::ifstream in(m_file);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue doc;
    if (!doc.read(text) || !doc.isObject()) {
        error = "the pending registrations file is not valid JSON";
        return false;
    }
    const UniValue& list = find_value(doc, "pending");
    if (!list.isArray()) return true;
    for (size_t i = 0; i < list.size(); ++i) {
        PendingRegistration p;
        if (FromJSON(list[i], p)) m_pending.push_back(p);
    }
    return true;
}

bool Registrar::Save()
{
    UniValue list(UniValue::VARR);
    for (const PendingRegistration& p : m_pending) list.push_back(ToJSON(p));
    UniValue doc(UniValue::VOBJ);
    doc.pushKV("version", 1);
    doc.pushKV("pending", list);
    const fs::path fresh = m_file.string() + ".new";
    {
        fsbridge::ofstream out(fresh);
        out << doc.write(2) << "\n";
        if (!out.good()) return false;
    }
    return RenameOver(fresh, m_file);
}

UniValue PendingToJSON(const PendingRegistration& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("name", p.name);
    o.pushKV("status", p.status);
    o.pushKV("note", p.note);
    o.pushKV("years", (int)p.years);
    o.pushKV("price", ValueFromAmount(Price(p.name.size(), std::min<uint32_t>(p.years * BLOCKS_PER_YEAR, MAX_TERM))));
    o.pushKV("wallet", p.wallet);
    o.pushKV("commit_txid", p.commit_txid.GetHex());
    if (!p.claim_txid.IsNull()) o.pushKV("claim_txid", p.claim_txid.GetHex());
    o.pushKV("started_height", p.started);
    return o;
}

void SetClaimPublisher(ClaimPublisher publisher)
{
    LOCK(g_publisher_mutex);
    g_publisher = std::move(publisher);
}

void Registrar::Add(const PendingRegistration& pending)
{
    LOCK(m_mutex);
    m_pending.push_back(pending);
    if (!Save()) LogPrintf("names: could not save pending registrations to %s\n", m_file.string());
}

std::vector<PendingRegistration> Registrar::All() const
{
    LOCK(m_mutex);
    return m_pending;
}

bool Registrar::Find(const std::string& name, PendingRegistration& out) const
{
    LOCK(m_mutex);
    for (const PendingRegistration& p : m_pending) {
        if (p.name == name && (p.status == "committed" || p.status == "claimed")) {
            out = p;
            return true;
        }
    }
    return false;
}

void Registrar::Process()
{
    LOCK(m_process_mutex);
    if (!g_nameindex) return;
    std::shared_ptr<const NameState> state;
    int height = 0;
    if (!g_nameindex->GetState(state, height)) return;

    std::vector<PendingRegistration> work;
    ClaimPublisher publisher;
    {
        LOCK(m_mutex);
        work = m_pending;
    }
    {
        LOCK(g_publisher_mutex);
        publisher = g_publisher;
    }
    // A claim sent now confirms at the next block at the earliest.
    const int next = height + 1;
    bool changed = false;
    for (PendingRegistration& p : work) {
        const PendingRegistration before = p;
        if (p.status == "committed") {
            const int at = state->CommitHeight(Commitment(p.name, p.salt, p.owner));
            if (at < 0) {
                if (next - p.started > (int)COMMIT_MAX_AGE) {
                    p.status = "lost";
                    p.note = "The commitment never confirmed.";
                } else {
                    p.note = "Waiting for the commitment to confirm.";
                }
            } else if (next - at < (int)COMMIT_MIN_AGE) {
                p.note = strprintf("The name is claimed in %d blocks.", (int)COMMIT_MIN_AGE - (next - at));
            } else if (next - at > (int)COMMIT_MAX_AGE) {
                p.status = "lost";
                p.note = "The commitment grew too old before it could be claimed.";
            } else {
                // Checked against the chain as it is now: a claim that would
                // not count still burns its coins.
                const std::string why = state->CheckAvailable(p.name, p.owner, next);
                if (!why.empty()) {
                    p.status = "lost";
                    p.note = why + " Nothing was burned.";
                } else if (!publisher) {
                    p.note = "Waiting for a wallet to pay with.";
                } else {
                    uint256 txid;
                    std::string error;
                    if (publisher(p, txid, error)) {
                        p.status = "claimed";
                        p.claim_txid = txid;
                        p.claimed = next;
                        p.note = "Claimed; waiting for the claim to confirm.";
                        LogPrintf("names: claimed %s in %s\n", p.name, txid.GetHex());
                    } else {
                        p.note = error;
                    }
                }
            }
        } else if (p.status == "claimed") {
            const NameEntry* entry = state->Find(p.name);
            if (entry && entry->owner == p.owner && entry->registered >= p.claimed &&
                state->StatusOf(p.name, height) == Status::LIVE) {
                p.status = "done";
                p.note = "Registered.";
            } else if (height - p.claimed > CLAIM_PATIENCE) {
                p.status = "lost";
                p.note = "The claim did not take effect.";
            }
        }
        if (p.status != before.status || p.note != before.note || p.claim_txid != before.claim_txid) changed = true;
    }

    LOCK(m_mutex);
    for (const PendingRegistration& p : work) {
        for (PendingRegistration& q : m_pending) {
            if (q.name == p.name && q.commit_txid == p.commit_txid) q = p;
        }
    }
    const size_t before = m_pending.size();
    m_pending.erase(std::remove_if(m_pending.begin(), m_pending.end(), [&](const PendingRegistration& p) {
        return (p.status == "done" || p.status == "lost") && height - p.started > KEEP_FINISHED;
    }), m_pending.end());
    if ((changed || m_pending.size() != before) && !Save()) {
        LogPrintf("names: could not save pending registrations to %s\n", m_file.string());
    }
}

} // namespace names
