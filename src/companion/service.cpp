// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/service.h>

#include <logging.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>

#include <algorithm>

namespace companion {

std::unique_ptr<Service> g_companion;

namespace {

Mutex g_hooks_mutex;
WalletHooks g_hooks GUARDED_BY(g_hooks_mutex);

uint256 RandomId()
{
    uint256 id;
    GetStrongRandBytes(id.begin(), id.size());
    return id;
}

const char* const NOT_PAIRED = "This phone is not paired with this home node, or has been unpaired.";
const char* const NO_WALLET = "This home node has no wallet to pay from.";

} // namespace

void SetWalletHooks(WalletHooks hooks)
{
    LOCK(g_hooks_mutex);
    g_hooks = std::move(hooks);
}

WalletHooks GetWalletHooks()
{
    LOCK(g_hooks_mutex);
    return g_hooks;
}

Service::Service(const fs::path& dir, const std::string& wallet, const CPubKey& node_key, NodeHooks node,
                 bool memory_only)
    : m_wallet(wallet),
      m_node_key(node_key),
      m_node(std::move(node)),
      m_channel(COMPANION_CELL, m_node.sender, KnownOp,
                [this](overlay::CellChannel::Request&& request) {
                    // On the receive thread: only queued here, served by Work.
                    LOCK(m_queue_mutex);
                    if (m_stopping || m_queue.size() >= MAX_QUEUE) return;
                    m_queue.push_back(std::move(request));
                    m_queue_cv.notify_one();
                }),
      m_store(dir, memory_only)
{
}

Service::~Service()
{
    Stop();
}

void Service::Start()
{
    m_worker = std::thread(&TraceThread<std::function<void()>>, "companion", std::function<void()>([this] { Work(); }));
}

void Service::Stop()
{
    {
        LOCK(m_queue_mutex);
        m_stopping = true;
    }
    m_queue_cv.notify_all();
    m_channel.Interrupt();
    if (m_worker.joinable()) m_worker.join();
}

void Service::HandleOverlayApp(const overlay::Hop& from, std::vector<unsigned char>&& payload)
{
    m_channel.Handle(from, std::move(payload));
}

void Service::Work()
{
    int64_t last_expiry = 0;
    while (true) {
        overlay::CellChannel::Request request;
        bool have = false;
        {
            WAIT_LOCK(m_queue_mutex, lock);
            m_queue_cv.wait_for(lock, std::chrono::seconds{1}, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_queue_mutex) {
                return m_stopping || !m_queue.empty();
            });
            if (m_stopping) return;
            if (!m_queue.empty()) {
                request = std::move(m_queue.front());
                m_queue.pop_front();
                have = true;
            }
        }
        const int64_t now = GetTime();
        if (now - last_expiry >= 5) {
            Expire(now);
            last_expiry = now;
        }
        if (!have) continue;

        // The key the sender proved, at the end of a path or directly: the device, or nobody.
        const CPubKey device = m_node.identify ? m_node.identify(request.from) : CPubKey();
        Message msg;
        if (!DecodeMessage(request.message, msg)) continue;
        const Message reply = Serve(device, msg, now);
        m_channel.Answer(request.from, request.transfer, EncodeMessage(reply));
    }
}

Message Service::Serve(const CPubKey& device, const Message& request, int64_t now)
{
    if (IsAnswer(request.op)) return Result(request.req, false, "Not a request.");
    // Everything comes from a sender that proved a key, over a path or directly.
    if (!device.IsFullyValid()) return Result(request.req, false, "Requests have to come from a phone that proves its key.");

    switch (request.op) {
    case Op::PAIR: return Pair(device, request, now);
    case Op::PAIR_STATUS: return PairStatus(device, request, now);
    default: break;
    }

    {
        LOCK(cs_companion);
        Device d;
        if (!m_store.Get(device, d)) return Result(request.req, false, NOT_PAIRED);
        if (now - d.last_seen >= SEEN_GRANULARITY) {
            d.last_seen = now;
            m_store.Put(d);
        }
    }

    switch (request.op) {
    case Op::STATUS: return Status(device, request, now);
    case Op::ADDRESS: return Address(request);
    case Op::HISTORY: return History(request);
    case Op::PREPARE: return Prepare(device, request, now);
    case Op::SEND: return Send(device, request, now);
    case Op::CANCEL: return Cancel(device, request);
    case Op::RELAYS: return Relays(request);
    case Op::SET_PIN: return SetPin(device, request, now);
    case Op::UNPAIR: return Unpair(device, request);
    default: return Result(request.req, false, "Not a request.");
    }
}

PairingTicket Service::NewTicket(const std::string& network, const std::string& node_addr,
                                 const std::vector<RelayEntry>& relays, int64_t now)
{
    PairingTicket t;
    t.network = network;
    t.node = m_node_key;
    t.node_addr = node_addr;
    t.token = RandomId();
    t.expires = now + TICKET_TTL;
    t.relays = relays;
    if (t.relays.size() > TICKET_RELAYS) t.relays.resize(TICKET_RELAYS);

    Pairing p;
    p.token = t.token;
    p.created = now;
    p.expires = t.expires;
    LOCK(cs_companion);
    // A handful at once is plenty for a person pairing their own phones.
    while (m_pairings.size() >= MAX_PAIRINGS) {
        auto oldest = std::min_element(m_pairings.begin(), m_pairings.end(), [](const std::pair<const uint256, Pairing>& a,
                                                                                  const std::pair<const uint256, Pairing>& b) {
            return a.second.created < b.second.created;
        });
        m_pairings.erase(oldest);
    }
    m_pairings[t.token] = p;
    return t;
}

std::vector<Pairing> Service::Pairings(int64_t now)
{
    Expire(now);
    LOCK(cs_companion);
    std::vector<Pairing> out;
    for (const auto& entry : m_pairings) out.push_back(entry.second);
    return out;
}

bool Service::Accept(const uint256& token, const Limits& limits, int64_t now, std::string& error)
{
    if (!ValidLimits(limits, error)) return false;
    LOCK(cs_companion);
    auto it = m_pairings.find(token);
    if (it == m_pairings.end()) {
        error = "No such pairing. Its ticket may have expired; show a new one.";
        return false;
    }
    Pairing& p = it->second;
    if (p.state != PairState::WAITING || now > p.expires) {
        error = "That pairing is no longer waiting to be accepted.";
        return false;
    }
    if (!p.answered) {
        error = "No phone has answered that ticket yet.";
        return false;
    }
    Device existing;
    if (m_store.Get(p.device, existing)) {
        error = "That phone is already paired.";
        return false;
    }
    Device d;
    d.key = p.device;
    d.name = p.name;
    d.created = now;
    d.last_seen = now;
    d.limits = limits;
    d.pin = p.pin;
    if (!m_store.Put(d)) {
        error = "Could not write the device down.";
        return false;
    }
    p.state = PairState::ACCEPTED;
    p.limits = limits;
    LogPrintf("companion: paired %s (%s)\n", SanitizeString(d.name), HexStr(d.key).substr(0, 16));
    return true;
}

bool Service::Reject(const uint256& token, std::string& error)
{
    LOCK(cs_companion);
    auto it = m_pairings.find(token);
    if (it == m_pairings.end() || it->second.state != PairState::WAITING) {
        error = "That pairing is no longer waiting.";
        return false;
    }
    it->second.state = PairState::REJECTED;
    return true;
}

std::vector<Device> Service::Devices()
{
    LOCK(cs_companion);
    return m_store.All();
}

bool Service::SetLimits(const CPubKey& key, const Limits& limits, std::string& error)
{
    if (!ValidLimits(limits, error)) return false;
    LOCK(cs_companion);
    Device d;
    if (!m_store.Get(key, d)) {
        error = "No such device.";
        return false;
    }
    d.limits = limits;
    return m_store.Put(d);
}

std::vector<PreparedPayment> Service::TakePrepared(const CPubKey& device)
{
    std::vector<PreparedPayment> taken;
    LOCK(cs_companion);
    for (auto it = m_prepared.begin(); it != m_prepared.end();) {
        if (it->second.device == device) {
            taken.push_back(it->second.payment);
            it = m_prepared.erase(it);
        } else {
            ++it;
        }
    }
    return taken;
}

bool Service::Revoke(const CPubKey& key)
{
    const std::vector<PreparedPayment> release = TakePrepared(key);
    {
        LOCK(cs_companion);
        Device d;
        if (!m_store.Get(key, d)) return false;
        m_store.Erase(key);
        LogPrintf("companion: unpaired %s\n", SanitizeString(d.name));
    }
    const WalletHooks hooks = GetWalletHooks();
    for (const PreparedPayment& p : release) {
        if (hooks.cancel) hooks.cancel(m_wallet, p);
    }
    return true;
}

bool Service::Unlock(const CPubKey& key, std::string& error)
{
    LOCK(cs_companion);
    Device d;
    if (!m_store.Get(key, d)) {
        error = "No such device.";
        return false;
    }
    d.failures = 0;
    return m_store.Put(d);
}

void Service::Expire(int64_t now)
{
    std::vector<PreparedPayment> release;
    {
        LOCK(cs_companion);
        for (auto it = m_prepared.begin(); it != m_prepared.end();) {
            if (now > it->second.expires) {
                release.push_back(it->second.payment);
                it = m_prepared.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = m_pairings.begin(); it != m_pairings.end();) {
            Pairing& p = it->second;
            if (p.state == PairState::WAITING && now > p.expires) p.state = PairState::EXPIRED;
            if (now - p.created > PAIRING_KEEP) {
                it = m_pairings.erase(it);
            } else {
                ++it;
            }
        }
    }
    const WalletHooks hooks = GetWalletHooks();
    for (const PreparedPayment& p : release) {
        if (hooks.cancel) hooks.cancel(m_wallet, p);
    }
}

Message Service::Pair(const CPubKey& device, const Message& request, int64_t now)
{
    PairRequest req;
    if (!Read(request, Op::PAIR, req)) return Result(request.req, false, "Malformed request.");
    if (!ValidPin(req.pin)) return Result(request.req, false, "A PIN is six to twelve digits.");
    std::string name = SanitizeString(req.name);
    if (name.empty()) name = "Phone";
    // Slow on purpose, so worked out without the lock.
    uint256 secret;
    {
        LOCK(cs_companion);
        secret = m_store.Secret();
    }
    const PinVerifier verifier = MakePinVerifier(req.pin, secret);

    LOCK(cs_companion);
    auto it = m_pairings.find(req.token);
    if (it == m_pairings.end() || it->second.state == PairState::EXPIRED || now > it->second.expires) {
        return Result(request.req, false, "This pairing code has expired. Show a new one on the home node.");
    }
    Pairing& p = it->second;
    if (p.answered) {
        // The same phone asking again - its first answer was lost - is fine.
        if (p.device == device) return Result(request.req, true, "Waiting to be accepted on the home node.");
        return Result(request.req, false,
                      "This pairing code has already been used. Show a new one on the home node.");
    }
    if (p.state != PairState::WAITING) {
        return Result(request.req, false, "This pairing code is no longer waiting. Show a new one on the home node.");
    }
    Device existing;
    if (m_store.Get(device, existing)) return Result(request.req, false, "This phone is already paired with this home node.");
    p.answered = true;
    p.device = device;
    p.name = name;
    p.pin = verifier;
    p.code = PairingCode(p.token, device, m_node_key);
    return Result(request.req, true, "Waiting to be accepted on the home node.");
}

Message Service::PairStatus(const CPubKey& device, const Message& request, int64_t now)
{
    PairStatusRequest req;
    if (!Read(request, Op::PAIR_STATUS, req)) return Result(request.req, false, "Malformed request.");
    PairStateAnswer a;
    LOCK(cs_companion);
    auto it = m_pairings.find(req.token);
    if (it != m_pairings.end() && it->second.answered && it->second.device == device) {
        const Pairing& p = it->second;
        PairState state = p.state;
        if (state == PairState::WAITING && now > p.expires) state = PairState::EXPIRED;
        a.state = static_cast<uint8_t>(state);
        if (state == PairState::ACCEPTED) {
            a.per_tx = p.limits.per_tx;
            a.per_day = p.limits.per_day;
        }
    }
    return Make(Op::PAIR_STATE, request.req, a);
}

Message Service::Status(const CPubKey& device, const Message& request, int64_t now)
{
    StatusAnswer a;
    {
        LOCK(cs_companion);
        Device d;
        if (!m_store.Get(device, d)) return Result(request.req, false, NOT_PAIRED);
        a.per_tx = d.limits.per_tx;
        a.per_day = d.limits.per_day;
        a.spent_today = SpentInWindow(d.spends, now);
        a.locked = d.Locked();
    }
    // Answered with or without a wallet to pay from: the phone is paired
    // either way, and says why it cannot spend yet.
    const WalletHooks hooks = GetWalletHooks();
    std::string error = NO_WALLET;
    if (!hooks.status || !hooks.status(m_wallet, a.balance, a.pending, error)) {
        a.balance = a.pending = 0;
        a.wallet_problem = error;
    }
    a.height = m_node.height ? m_node.height() : 0;
    return Make(Op::STATUS_INFO, request.req, a);
}

Message Service::Address(const Message& request)
{
    const WalletHooks hooks = GetWalletHooks();
    if (!hooks.new_address) return Result(request.req, false, NO_WALLET);
    AddressAnswer a;
    std::string error;
    if (!hooks.new_address(m_wallet, a.address, error)) return Result(request.req, false, error);
    return Make(Op::ADDRESS_INFO, request.req, a);
}

Message Service::History(const Message& request)
{
    HistoryRequest req;
    if (!Read(request, Op::HISTORY, req)) return Result(request.req, false, "Malformed request.");
    const WalletHooks hooks = GetWalletHooks();
    HistoryAnswer a;
    std::string error;
    // No wallet yet, no payments yet: an empty history, not an error, so a
    // phone paired before the wallet was made still shows its screens.
    CAmount balance, pending;
    if (!hooks.history || !hooks.status || !hooks.status(m_wallet, balance, pending, error)) {
        return Make(Op::HISTORY_ITEMS, request.req, a);
    }
    const size_t count = std::min<size_t>(req.count, MAX_HISTORY);
    if (!hooks.history(m_wallet, req.skip, count, a.items, error)) return Result(request.req, false, error);
    return Make(Op::HISTORY_ITEMS, request.req, a);
}

Message Service::Prepare(const CPubKey& device, const Message& request, int64_t now)
{
    PrepareRequest req;
    if (!Read(request, Op::PREPARE, req)) return Result(request.req, false, "Malformed request.");
    Device d;
    {
        LOCK(cs_companion);
        if (!m_store.Get(device, d)) return Result(request.req, false, NOT_PAIRED);
    }
    if (d.Locked()) {
        return Result(request.req, false, "This phone is locked after too many wrong PINs. Unlock it on the home node.");
    }
    std::string why;
    // Checked before anything is built, and again with the fee once it is.
    if (!WithinLimits(d.limits, d.spends, req.amount, now, why)) return Result(request.req, false, why);

    const WalletHooks hooks = GetWalletHooks();
    if (!hooks.prepare) return Result(request.req, false, NO_WALLET);
    // A phone reviews one payment at a time: a new one replaces any it had
    // waiting, whose coins would otherwise stay locked until it expired - all
    // of them, in an allowance that holds a single coin.
    for (const PreparedPayment& old : TakePrepared(device)) {
        if (hooks.cancel) hooks.cancel(m_wallet, old);
    }
    PreparedPayment payment;
    if (!hooks.prepare(m_wallet, req.to, req.amount, req.subtract_fee, payment, why)) {
        return Result(request.req, false, why);
    }
    if (!WithinLimits(d.limits, d.spends, payment.amount + payment.fee, now, why)) {
        if (hooks.cancel) hooks.cancel(m_wallet, payment);
        return Result(request.req, false, why);
    }

    PrepareAnswer a;
    a.prepare_id = RandomId();
    a.amount = payment.amount;
    a.fee = payment.fee;
    a.payee_script = payment.payee_script;
    a.payee = payment.payee;
    a.expires = now + PREPARE_TTL;

    std::vector<PreparedPayment> release;
    {
        LOCK(cs_companion);
        while (m_prepared.size() >= MAX_PREPARED) {
            auto oldest = std::min_element(m_prepared.begin(), m_prepared.end(),
                                           [](const std::pair<const uint256, Prepared>& x,
                                              const std::pair<const uint256, Prepared>& y) {
                                               return x.second.expires < y.second.expires;
                                           });
            release.push_back(oldest->second.payment);
            m_prepared.erase(oldest);
        }
        Prepared p;
        p.device = device;
        p.payment = payment;
        p.expires = a.expires;
        m_prepared[a.prepare_id] = p;
    }
    for (const PreparedPayment& r : release) {
        if (hooks.cancel) hooks.cancel(m_wallet, r);
    }
    return Make(Op::PREPARED, request.req, a);
}

std::string Service::CheckDevicePin(Device& d, const std::string& pin, int64_t now)
{
    if (d.Locked()) return "This phone is locked after too many wrong PINs. Unlock it on the home node.";
    if (!m_pin_limiter.Allow(now)) return "Too many PIN attempts on this home node. Wait a minute and try again.";
    if (CheckPin(d.pin, pin, m_store.Secret())) {
        if (d.failures != 0) {
            d.failures = 0;
            m_store.Put(d);
        }
        return std::string();
    }
    ++d.failures;
    m_store.Put(d);
    if (d.Locked()) {
        LogPrintf("companion: %s locked after %d wrong PINs\n", SanitizeString(d.name), d.failures);
        return "Wrong PIN. This phone is now locked: unlock it on the home node.";
    }
    const int left = MAX_PIN_FAILURES - d.failures;
    return strprintf("Wrong PIN. %d %s left before this phone is locked.", left, left == 1 ? "try" : "tries");
}

Message Service::Send(const CPubKey& device, const Message& request, int64_t now)
{
    SendRequest req;
    if (!Read(request, Op::SEND, req)) return Result(request.req, false, "Malformed request.");

    PreparedPayment payment;
    {
        LOCK(cs_companion);
        // Sent already, and the answer was lost: the same answer again,
        // never a second payment.
        auto sent = m_sent.find(req.prepare_id);
        if (sent != m_sent.end() && sent->second.device == device) {
            SendAnswer a;
            a.txid = sent->second.txid;
            return Make(Op::SENT, request.req, a);
        }
        auto it = m_prepared.find(req.prepare_id);
        if (it == m_prepared.end() || it->second.device != device || now > it->second.expires) {
            return Result(request.req, false, "That payment is no longer waiting. Review it again.");
        }
        Device d;
        if (!m_store.Get(device, d)) return Result(request.req, false, NOT_PAIRED);
        const std::string pin_error = CheckDevicePin(d, req.pin, now);
        if (!pin_error.empty()) return Result(request.req, false, pin_error);

        const PreparedPayment& p = it->second.payment;
        // Bound to this node and this exact payment, so neither a relay nor
        // anyone holding an old message can turn it into another.
        const uint256 digest = SendDigest(m_node_key, req.prepare_id, p.payee_script, p.amount, p.fee);
        if (!d.key.Verify(digest, req.signature)) {
            return Result(request.req, false, "The phone's signature does not match this payment.");
        }
        PruneSpends(d.spends, now);
        std::string why;
        if (!WithinLimits(d.limits, d.spends, p.amount + p.fee, now, why)) return Result(request.req, false, why);

        // Counted before it is sent: if this node stops in the middle, what
        // may have gone still counts against the day.
        d.spends.push_back(Spend(now, p.amount + p.fee, req.prepare_id));
        if (!m_store.Put(d)) return Result(request.req, false, "Could not record the payment. Nothing was sent.");
        payment = p;
        m_prepared.erase(it);
    }

    const WalletHooks hooks = GetWalletHooks();
    uint256 txid;
    bool rejected = false;
    std::string error;
    const bool ok = hooks.send && hooks.send(m_wallet, payment, txid, rejected, error);
    if (!hooks.send) {
        rejected = true;
        error = NO_WALLET;
    }

    {
        LOCK(cs_companion);
        Device d;
        if (m_store.Get(device, d)) {
            for (auto it = d.spends.begin(); it != d.spends.end(); ++it) {
                if (it->txid != req.prepare_id) continue;
                if (ok) {
                    it->txid = txid;
                } else if (rejected) {
                    d.spends.erase(it);
                }
                break;
            }
            m_store.Put(d);
        }
        if (ok) {
            Sent s;
            s.device = device;
            s.txid = txid;
            m_sent[req.prepare_id] = s;
            m_sent_order.push_back(req.prepare_id);
            while (m_sent_order.size() > MAX_SENT) {
                m_sent.erase(m_sent_order.front());
                m_sent_order.pop_front();
            }
        }
    }
    if (ok) {
        LogPrintf("companion: sent %s for a paired phone\n", txid.GetHex());
        SendAnswer a;
        a.txid = txid;
        return Make(Op::SENT, request.req, a);
    }
    if (rejected) {
        if (hooks.cancel) hooks.cancel(m_wallet, payment);
        return Result(request.req, false, error);
    }
    return Result(request.req, false, error + " It may or may not have been sent: check the activity before trying again.");
}

Message Service::Cancel(const CPubKey& device, const Message& request)
{
    CancelRequest req;
    if (!Read(request, Op::CANCEL, req)) return Result(request.req, false, "Malformed request.");
    PreparedPayment payment;
    {
        LOCK(cs_companion);
        auto it = m_prepared.find(req.prepare_id);
        if (it == m_prepared.end() || it->second.device != device) return Result(request.req, true);
        payment = it->second.payment;
        m_prepared.erase(it);
    }
    const WalletHooks hooks = GetWalletHooks();
    if (hooks.cancel) hooks.cancel(m_wallet, payment);
    return Result(request.req, true);
}

Message Service::Relays(const Message& request)
{
    RelaysAnswer a;
    if (m_node.relays) a.relays = m_node.relays();
    if (a.relays.size() > MAX_RELAYS) a.relays.resize(MAX_RELAYS);
    return Make(Op::RELAY_LIST, request.req, a);
}

Message Service::SetPin(const CPubKey& device, const Message& request, int64_t now)
{
    SetPinRequest req;
    if (!Read(request, Op::SET_PIN, req)) return Result(request.req, false, "Malformed request.");
    if (!ValidPin(req.new_pin)) return Result(request.req, false, "A PIN is six to twelve digits.");
    LOCK(cs_companion);
    Device d;
    if (!m_store.Get(device, d)) return Result(request.req, false, NOT_PAIRED);
    const std::string pin_error = CheckDevicePin(d, req.old_pin, now);
    if (!pin_error.empty()) return Result(request.req, false, pin_error);
    d.pin = MakePinVerifier(req.new_pin, m_store.Secret());
    if (!m_store.Put(d)) return Result(request.req, false, "Could not write the new PIN down.");
    return Result(request.req, true, "PIN changed.");
}

Message Service::Unpair(const CPubKey& device, const Message& request)
{
    Revoke(device);
    return Result(request.req, true, "Unpaired.");
}

} // namespace companion
