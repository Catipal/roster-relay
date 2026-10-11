// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <companion/client.h>

#include <netbase.h>
#include <overlay/select.h>
#include <tinyformat.h>
#include <util/time.h>
#include <util/strencodings.h>

#include <algorithm>
#include <map>

namespace companion {

namespace {

roster::KeyBytes XOnly(const CPubKey& pub)
{
    roster::KeyBytes x{};
    if (pub.size() == CPubKey::COMPRESSED_SIZE) std::copy(pub.begin() + 1, pub.end(), x.begin());
    return x;
}

/**
 * Text from the home node, fit to show a person: printable characters only.
 * Not SanitizeString, whose safe set has no apostrophe or quote marks.
 */
std::string Printable(const std::string& text)
{
    std::string out;
    for (const char c : text) {
        if (c >= 0x20 && c <= 0x7e) out.push_back(c);
    }
    return out;
}

bool ParseAddr(const std::string& text, CService& out)
{
    // Numbers only: a phone resolving names would tell its resolver where it goes.
    return Lookup(text, out, 0, /* fAllowLookup */ false) && out.IsValid() && out.GetPort() != 0;
}

} // namespace

Client::Client(const CKey& device, bool local_relays) : m_device(device), m_local_relays(local_relays) {}

Client::~Client()
{
    Stop();
}

bool Client::Start(std::string& error)
{
    // The relays a phone enters through see this key, so it is made for this
    // run and means nothing anywhere else. The device key is shown only to
    // the home node, at the end of the path.
    CKey hop_key;
    hop_key.MakeNewKey(true);
    m_relay.reset(new overlay::Relay(hop_key));
    m_relay->SetClientOnly(true);
    if (!m_relay->Bind(LookupNumeric("0.0.0.0", 0), error)) return false;
    m_channel.reset(new overlay::CellChannel(
        COMPANION_CELL, overlay::RelaySender([this] { return m_relay.get(); }), KnownOp));
    if (!m_relay->Start([this](const overlay::Hop& from, std::vector<unsigned char>&& payload) {
            if (m_channel) m_channel->Handle(from, std::move(payload));
        })) {
        error = "Could not start listening for answers.";
        return false;
    }
    return true;
}

void Client::Stop()
{
    if (m_channel) m_channel->Interrupt();
    if (m_relay) {
        m_relay->Interrupt();
        m_relay->Stop();
    }
}

void Client::SetHome(const Home& home)
{
    LOCK(m_mutex);
    m_home = home;
}

Home Client::GetHome()
{
    LOCK(m_mutex);
    return m_home;
}

uint64_t Client::PathId()
{
    LOCK(m_mutex);
    return m_path;
}

bool Client::Connect(std::string& error)
{
    const Home home = GetHome();
    if (!home.node.IsFullyValid()) {
        error = "There is no home node yet: pair this phone first.";
        return false;
    }
    overlay::RelayCandidate dest;
    dest.key = XOnly(home.node);
    if (!ParseAddr(home.node_addr, dest.addr)) {
        error = "The home node's address is not one this phone can use.";
        return false;
    }

    std::map<roster::KeyBytes, CPubKey> keys;
    std::vector<overlay::RelayCandidate> listed;
    for (const RelayEntry& r : home.relays) {
        overlay::RelayCandidate c;
        c.key = XOnly(r.key);
        if (!r.key.IsFullyValid() || c.key == dest.key || !ParseAddr(r.addr, c.addr)) continue;
        listed.push_back(c);
        keys[c.key] = r.key;
    }

    for (int attempt = 0; attempt < 3; ++attempt) {
        // Relays that just failed a path stay out of the next ones for a while:
        // a relay that has gone is still listed, and others may still believe
        // they can reach it.
        std::vector<overlay::RelayCandidate> candidates;
        {
            const int64_t now = GetTime();
            LOCK(m_mutex);
            for (const overlay::RelayCandidate& c : listed) {
                std::map<roster::KeyBytes, int64_t>::const_iterator it = m_shunned.find(c.key);
                if (it == m_shunned.end() || it->second <= now) candidates.push_back(c);
            }
        }
        overlay::PathSelector selector(overlay::PathSelector::GUARD_COUNT, m_local_relays);
        selector.SetRelays(candidates);
        std::vector<overlay::RelayCandidate> chosen;
        if (!selector.Select(overlay::DEFAULT_PATH_HOPS, chosen, dest)) {
            error = strprintf("This phone knows fewer than %u relays run by different people to reach its home node "
                              "through. Pair it again to learn more.",
                              (unsigned)overlay::DEFAULT_PATH_HOPS);
            return false;
        }
        std::vector<overlay::Relay::CircuitHop> hops;
        for (const overlay::RelayCandidate& c : chosen) {
            overlay::Relay::CircuitHop h;
            h.addr = c.addr;
            h.key = keys[c.key];
            hops.push_back(h);
        }
        overlay::Relay::CircuitHop last;
        last.addr = dest.addr;
        last.key = home.node;
        hops.push_back(last);

        uint64_t path = 0;
        size_t failed_at = 0;
        if (m_relay->BuildCircuit(hops, path, error, std::chrono::milliseconds{4000},
                                  /* prove_last */ false, &m_device, &failed_at)) {
            LOCK(m_mutex);
            m_path = path;
            m_legs = m_relay->CircuitLegs(path);
            return true;
        }
        // The home node itself is never left out; a relay is.
        if (failed_at < chosen.size()) {
            LOCK(m_mutex);
            m_shunned[chosen[failed_at].key] = GetTime() + SHUN_SECONDS;
        }
    }
    error = "Could not reach the home node: " + error;
    return false;
}

void Client::Disconnect()
{
    std::vector<uint64_t> legs;
    {
        LOCK(m_mutex);
        legs = m_legs;
        m_legs.clear();
        m_path = 0;
    }
    if (m_relay && !legs.empty()) m_relay->ClosePath(legs);
}

bool Client::Ask(const Message& request, Message& answer, std::string& error, std::chrono::milliseconds timeout)
{
    if (!m_relay || !m_channel) {
        error = "Not started.";
        return false;
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        uint64_t path = PathId();
        if (path == 0) {
            if (!Connect(error)) return false;
            path = PathId();
        }
        std::vector<unsigned char> raw;
        if (m_channel->Ask(overlay::Hop::Path(path), EncodeMessage(request), raw, timeout, error)) {
            if (!DecodeMessage(raw, answer)) {
                error = "The home node's answer was garbled.";
                return false;
            }
            return true;
        }
        // The path may have gone - a relay restarted, or forgot it while it was
        // idle. One more, freshly built. Sending again is safe: the home node
        // answers a repeated payment with the first one's result.
        Disconnect();
    }
    return false;
}

template <typename T>
bool Client::Exchange(const Message& request, Op expected, T& out, std::string& error)
{
    Message answer;
    if (!Ask(request, answer, error)) return false;
    if (Read(answer, expected, out)) return true;
    ResultAnswer r;
    if (Read(answer, Op::RESULT, r)) {
        error = Printable(r.text);
        return false;
    }
    error = "The home node answered something this version does not understand.";
    return false;
}

bool Client::ExchangeResult(const Message& request, std::string& error)
{
    Message answer;
    if (!Ask(request, answer, error)) return false;
    ResultAnswer r;
    if (!Read(answer, Op::RESULT, r)) {
        error = "The home node answered something this version does not understand.";
        return false;
    }
    error = Printable(r.text);
    return r.ok;
}

namespace {

Message Empty(Op op)
{
    Message m;
    m.op = op;
    return m;
}

} // namespace

bool Client::Pair(const uint256& token, const std::string& name, const std::string& pin, std::string& error)
{
    PairRequest req;
    req.token = token;
    req.name = name.substr(0, MAX_DEVICE_NAME);
    req.pin = pin;
    return ExchangeResult(Make(Op::PAIR, 0, req), error);
}

bool Client::PairStatus(const uint256& token, PairStateAnswer& out, std::string& error)
{
    PairStatusRequest req;
    req.token = token;
    return Exchange(Make(Op::PAIR_STATUS, 0, req), Op::PAIR_STATE, out, error);
}

bool Client::Status(StatusAnswer& out, std::string& error)
{
    return Exchange(Empty(Op::STATUS), Op::STATUS_INFO, out, error);
}

bool Client::Address(std::string& out, std::string& error)
{
    AddressAnswer a;
    if (!Exchange(Empty(Op::ADDRESS), Op::ADDRESS_INFO, a, error)) return false;
    out = a.address;
    return true;
}

bool Client::History(size_t skip, size_t count, std::vector<HistoryItem>& out, std::string& error)
{
    HistoryRequest req;
    req.skip = (uint16_t)std::min<size_t>(skip, 0xffff);
    req.count = (uint8_t)std::min<size_t>(count, MAX_HISTORY);
    HistoryAnswer a;
    if (!Exchange(Make(Op::HISTORY, 0, req), Op::HISTORY_ITEMS, a, error)) return false;
    out = a.items;
    return true;
}

bool Client::Prepare(const std::string& to, CAmount amount, bool subtract_fee, PrepareAnswer& out, std::string& error)
{
    PrepareRequest req;
    req.to = to;
    req.amount = amount;
    req.subtract_fee = subtract_fee;
    return Exchange(Make(Op::PREPARE, 0, req), Op::PREPARED, out, error);
}

bool Client::Send(const PrepareAnswer& prepared, const std::string& pin, uint256& txid, std::string& error)
{
    const Home home = GetHome();
    SendRequest req;
    req.prepare_id = prepared.prepare_id;
    req.pin = pin;
    const uint256 digest =
        SendDigest(home.node, prepared.prepare_id, prepared.payee_script, prepared.amount, prepared.fee);
    if (!m_device.Sign(digest, req.signature)) {
        error = "Could not sign with this phone's key.";
        return false;
    }
    SendAnswer a;
    if (!Exchange(Make(Op::SEND, 0, req), Op::SENT, a, error)) return false;
    txid = a.txid;
    return true;
}

bool Client::Cancel(const uint256& prepare_id, std::string& error)
{
    CancelRequest req;
    req.prepare_id = prepare_id;
    return ExchangeResult(Make(Op::CANCEL, 0, req), error);
}

bool Client::RefreshRelays(std::string& error)
{
    RelaysAnswer a;
    if (!Exchange(Empty(Op::RELAYS), Op::RELAY_LIST, a, error)) return false;
    // Too few to build a path through is worse than the list already held.
    if (a.relays.size() < overlay::DEFAULT_PATH_HOPS) return true;
    LOCK(m_mutex);
    m_home.relays = a.relays;
    return true;
}

bool Client::SetPin(const std::string& old_pin, const std::string& new_pin, std::string& error)
{
    SetPinRequest req;
    req.old_pin = old_pin;
    req.new_pin = new_pin;
    return ExchangeResult(Make(Op::SET_PIN, 0, req), error);
}

bool Client::Unpair(std::string& error)
{
    return ExchangeResult(Empty(Op::UNPAIR), error);
}

} // namespace companion
