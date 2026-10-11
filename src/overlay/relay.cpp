// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/relay.h>

#include <logging.h>
#include <random.h>
#include <tinyformat.h>
#include <util/time.h>

#include <algorithm>
#include <limits>

namespace overlay {

std::unique_ptr<Relay> g_overlay;

constexpr int64_t Relay::PENDING_BUILD_TTL;
constexpr size_t Relay::MAX_PENDING_BUILDS;

namespace {

/** Whether a full public key is the one a roster x-only key names. */
bool SameX(const CPubKey& pub, const roster::KeyBytes& x)
{
    if (!pub.IsValid() || pub.size() != CPubKey::COMPRESSED_SIZE) return false;
    return std::equal(pub.begin() + 1, pub.end(), x.begin());
}

} // namespace

Relay::Relay(const CKey& static_key) : m_socket(static_key), m_secret(static_key) {}

bool Relay::Bind(const CService& listen_addr, std::string& error)
{
    return m_socket.Bind(listen_addr, error);
}

bool Relay::Start(AppHandler app, PathHandler path)
{
    m_app = std::move(app);
    m_path = std::move(path);
    return m_socket.Start(
        [this](const CService& from, std::vector<unsigned char>&& msg) {
            OnMessage(Hop::Direct(from), std::move(msg));
        },
        [this](const CService& peer) { OnEstablished(peer); });
}

void Relay::Stop() { m_socket.Stop(); }

void Relay::Interrupt()
{
    {
        LOCK(m_results_mutex);
        m_interrupted = true;
    }
    m_results_cv.notify_all();
}

void Relay::SetDialPolicy(DialPolicy policy)
{
    LOCK(m_mutex);
    m_dial = std::move(policy);
}

void Relay::SetIntroducePolicy(IntroducePolicy policy)
{
    LOCK(m_mutex);
    m_introduce = std::move(policy);
}

void Relay::SetNextHopResolver(NextHopResolver resolver)
{
    LOCK(m_mutex);
    m_next_hop = std::move(resolver);
}

constexpr int64_t Relay::RADIO_DIAL_TTL;

bool Relay::Connect(const CService& peer, const CPubKey& peer_static)
{
    return m_socket.Connect(peer, peer_static);
}

bool Relay::SendApp(const CService& peer, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> msg;
    if (!EncodeAppData(payload, msg)) return false;
    return m_socket.Send(peer, msg);
}

bool Relay::SendToHop(const Hop& to, const std::vector<unsigned char>& msg, bool wrapping)
{
    if (!to.via_path) return m_socket.Send(to.addr, msg);

    // A path hop: seal for the far end of that path, wrap as path traffic, and
    // hand it to whichever hop carries that path. The recursion is the onion -
    // one wrapping per leg, applied from the inside out. Only the innermost
    // layer is padded; see MAX_PATH_APP_PAYLOAD for why.
    std::vector<unsigned char> sealed;
    Hop carrier;
    {
        LOCK(m_mutex);
        if (!m_secret.Send(to.path, msg, sealed, /* pad */ !wrapping)) return false;
        if (!m_paths.Carrier(to.path, carrier)) return false;
    }

    std::vector<unsigned char> wrapped;
    if (!EncodePathData(to.path, sealed, wrapped)) return false;
    return SendToHop(carrier, wrapped, /* wrapping */ true);
}

bool Relay::BuildPath(uint64_t path_id, const Hop& via, const CService& dest,
                      const CPubKey& dest_key)
{
    std::vector<unsigned char> msg;
    if (!EncodePathBuild(path_id, dest, msg, dest_key)) return false;
    return SendToHop(via, msg);
}

void Relay::NoteResult(uint64_t path_id, bool ok)
{
    {
        LOCK(m_results_mutex);
        // Answers nobody waits for (a caller using the PathHandler instead)
        // would otherwise pile up for the life of the node.
        if (m_results.size() >= PathTable::MAX_PATHS) m_results.clear();
        m_results[path_id] = ok;
    }
    m_results_cv.notify_all();
}

int Relay::AwaitPath(uint64_t path_id, std::chrono::milliseconds timeout)
{
    WAIT_LOCK(m_results_mutex, lock);
    const bool answered = m_results_cv.wait_for(lock, timeout, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_results_mutex) {
        return m_results.count(path_id) > 0 || m_interrupted;
    });
    if (!answered || m_results.count(path_id) == 0) return -1;
    const bool ok = m_results[path_id];
    m_results.erase(path_id);
    return ok ? 1 : 0;
}

bool Relay::SendOnPath(uint64_t path_id, const std::vector<unsigned char>& inner)
{
    Hop carrier;
    {
        LOCK(m_mutex);
        if (!m_paths.Carrier(path_id, carrier)) return false;
    }
    std::vector<unsigned char> msg;
    if (!EncodePathData(path_id, inner, msg)) return false;
    // What rides a path is either a handshake, which has a fixed size, or a
    // layer already padded where it was sealed.
    return SendToHop(carrier, msg, /* wrapping */ true);
}

bool Relay::ConnectSecret(uint64_t path_id, const CPubKey& far_static, bool anonymous)
{
    std::vector<unsigned char> hello;
    {
        LOCK(m_mutex);
        if (anonymous) {
            // Made for this handshake and dropped with it. The far end sees a
            // key it has never seen and never will again.
            CKey once;
            once.MakeNewKey(true);
            if (!m_secret.ConnectAs(path_id, far_static, once, hello)) return false;
        } else if (!m_secret.Connect(path_id, far_static, hello)) {
            return false;
        }
    }
    // The handshake rides the path as ordinary traffic. Relays forward it and
    // cannot complete it: only the holder of far_static can.
    return SendOnPath(path_id, hello);
}

bool Relay::HasSecretSession(uint64_t path_id)
{
    LOCK(m_mutex);
    return m_secret.HasSession(path_id);
}

CPubKey Relay::SecretPeerIdentity(uint64_t path_id)
{
    LOCK(m_mutex);
    return m_secret.PeerIdentity(path_id);
}

bool Relay::SendSecretRaw(uint64_t path_id, const std::vector<unsigned char>& msg)
{
    std::vector<unsigned char> sealed;
    {
        LOCK(m_mutex);
        if (!m_secret.Send(path_id, msg, sealed)) return false;
    }
    return SendOnPath(path_id, sealed);
}

bool Relay::SendSecret(uint64_t path_id, const std::vector<unsigned char>& payload)
{
    // Wrapped as a message before sealing, because what comes out of an
    // end-to-end session is dispatched rather than delivered - that is how a
    // relay is asked to extend a path, and application data has to be
    // distinguishable from that asking.
    std::vector<unsigned char> msg;
    if (!EncodeAppData(payload, msg)) return false;
    return SendSecretRaw(path_id, msg);
}

bool Relay::BuildCircuit(const std::vector<CircuitHop>& hops, uint64_t& path_out,
                         std::string& error, std::chrono::milliseconds step_timeout, bool prove_last)
{
    path_out = 0;
    if (hops.size() < 2) {
        error = "a path needs at least one relay before its destination";
        return false;
    }
    for (const CircuitHop& h : hops) {
        if (!h.addr.IsValid() || !h.key.IsFullyValid()) {
            error = "a stop on the path has no usable address or key";
            return false;
        }
    }
    // Each step gets three tries inside its budget: datagrams get lost, and
    // a lost question looks exactly like a slow answer.
    const std::chrono::milliseconds attempt_timeout = step_timeout / 3;

    // The entry relay is the one hop reached directly. A session left over
    // from before is used only if the right key is still on it.
    const CircuitHop& entry = hops[0];
    bool linked = m_socket.HasSession(entry.addr) && m_socket.PeerIdentity(entry.addr) == entry.key;
    for (int attempt = 0; !linked && attempt < 3 && !m_interrupted; ++attempt) {
        if (!m_socket.Connect(entry.addr, entry.key)) break;
        const auto until = std::chrono::steady_clock::now() + attempt_timeout;
        while (std::chrono::steady_clock::now() < until && m_socket.HasPendingHandshake(entry.addr) &&
               !m_interrupted) {
            UninterruptibleSleep(std::chrono::milliseconds{20});
        }
        linked = m_socket.HasSession(entry.addr) && m_socket.PeerIdentity(entry.addr) == entry.key;
    }
    if (!linked) {
        error = strprintf("the entry relay at %s did not answer", entry.addr.ToString());
        return false;
    }

    Hop via = Hop::Direct(entry.addr);
    std::vector<uint64_t> legs;
    for (size_t i = 1; i < hops.size(); ++i) {
        const uint64_t id = GetRand(std::numeric_limits<uint64_t>::max() - 1) + 1;
        int answer = -1;
        for (int attempt = 0; answer < 0 && attempt < 3 && !m_interrupted; ++attempt) {
            if (!BuildPath(id, via, hops[i].addr, hops[i].key)) break;
            answer = AwaitPath(id, attempt_timeout);
        }
        if (answer != 1) {
            error = strprintf(answer == 0 ? "stop %u of the path refused to reach the next one"
                                          : "stop %u of the path did not answer",
                              (unsigned)i);
            ClosePath(legs);
            return false;
        }
        legs.push_back(id);

        bool secret = false;
        for (int attempt = 0; !secret && attempt < 3 && !m_interrupted; ++attempt) {
            // Every stop sees a key made for this handshake alone, except, when
            // asked, the last: a meeting point registers a service only over a
            // session that proved the service's own key.
            const bool anonymous = !(prove_last && i + 1 == hops.size());
            if (!ConnectSecret(id, hops[i].key, anonymous)) break;
            const auto until = std::chrono::steady_clock::now() + attempt_timeout;
            while (std::chrono::steady_clock::now() < until && !HasSecretSession(id) && !m_interrupted) {
                UninterruptibleSleep(std::chrono::milliseconds{20});
            }
            secret = HasSecretSession(id);
        }
        if (!secret) {
            error = strprintf("stop %u of the path did not complete its handshake", (unsigned)i);
            ClosePath(legs);
            return false;
        }
        via = Hop::Path(id);
    }

    {
        LOCK(m_mutex);
        if (m_circuits.size() >= PathTable::MAX_PATHS) m_circuits.erase(m_circuits.begin());
        m_circuits[legs.back()] = legs;
    }
    path_out = legs.back();
    return true;
}

std::vector<uint64_t> Relay::CircuitLegs(uint64_t path_id)
{
    LOCK(m_mutex);
    std::map<uint64_t, std::vector<uint64_t>>::const_iterator it = m_circuits.find(path_id);
    if (it == m_circuits.end()) return std::vector<uint64_t>(1, path_id);
    return it->second;
}

void Relay::ClosePath(const std::vector<uint64_t>& legs)
{
    LOCK(m_mutex);
    for (uint64_t id : legs) {
        m_paths.Remove(id);
        m_secret.Forget(id);
        m_circuits.erase(id);
    }
}

bool Relay::Introduce(uint64_t path_id, const roster::KeyBytes& service)
{
    std::vector<unsigned char> msg;
    if (!EncodeIntroduce(service, msg)) return false;
    // Sealed, so the relays carrying the path cannot see which service is
    // registering - only the rendezvous point at the far end learns that.
    return SendSecretRaw(path_id, msg);
}

bool Relay::Meet(uint64_t path_id, const roster::KeyBytes& service, uint64_t meet_id)
{
    std::vector<unsigned char> msg;
    if (!EncodeMeet(service, meet_id, msg)) return false;
    return SendSecretRaw(path_id, msg);
}

size_t Relay::IntroductionCount()
{
    LOCK(m_mutex);
    m_paths.Expire(GetTime());
    PruneIntros();
    return m_intros.size();
}

void Relay::PruneIntros()
{
    for (std::map<roster::KeyBytes, uint64_t>::iterator it = m_intros.begin(); it != m_intros.end();) {
        it = m_paths.Has(it->second) ? std::next(it) : m_intros.erase(it);
    }
}

size_t Relay::PathCount()
{
    LOCK(m_mutex);
    return m_paths.Size();
}

void Relay::FinishBuild(uint64_t path_id, const Hop& from, const CService& dest)
{
    const Hop dest_hop = Hop::Direct(dest);
    bool ok = dest_hop != from && m_socket.HasSession(dest);
    bool fresh = false;
    if (ok) {
        LOCK(m_mutex);
        m_paths.Expire(GetTime());
        // A repeat of a request already granted is granted again: the answer
        // may be what got lost, and refusing the retry would end a path that
        // exists.
        if (m_paths.Joins(path_id, from, dest_hop)) {
            ok = true;
        } else {
            ok = m_paths.Create(path_id, from, dest_hop, GetTime());
            fresh = ok;
        }
    }

    if (fresh) {
        // Tell the far end it is this path's endpoint, or it would drop
        // everything forwarded to it, having never asked for a path.
        std::vector<unsigned char> bind;
        if (EncodePathBind(path_id, bind)) SendToHop(dest_hop, bind);
    }

    std::vector<unsigned char> reply;
    if (EncodePathResult(ok, path_id, reply)) SendToHop(from, reply);
}

void Relay::ExpirePendingBuilds()
{
    std::vector<PendingBuild> late;
    {
        LOCK(m_mutex);
        const int64_t now = GetTime();
        std::vector<PendingBuild>::iterator it = m_pending_builds.begin();
        while (it != m_pending_builds.end()) {
            if (it->deadline <= now) {
                late.push_back(*it);
                it = m_pending_builds.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (const PendingBuild& p : late) {
        std::vector<unsigned char> reply;
        if (EncodePathResult(false, p.path_id, reply)) SendToHop(p.from, reply);
    }
}

void Relay::OnEstablished(const CService& peer)
{
    std::vector<PendingBuild> ready;
    {
        LOCK(m_mutex);
        std::vector<PendingBuild>::iterator it = m_pending_builds.begin();
        while (it != m_pending_builds.end()) {
            if (it->dest == peer) {
                ready.push_back(*it);
                it = m_pending_builds.erase(it);
            } else {
                ++it;
            }
        }
    }
    const CPubKey identity = m_socket.PeerIdentity(peer);
    for (const PendingBuild& p : ready) {
        if (identity == p.key) {
            FinishBuild(p.path_id, p.from, p.dest);
        } else {
            // Somebody else answered at that address. The path was asked for
            // to a key, not to an address, so it is refused.
            std::vector<unsigned char> reply;
            if (EncodePathResult(false, p.path_id, reply)) SendToHop(p.from, reply);
        }
    }
    ExpirePendingBuilds();
}

void Relay::OnMessage(const Hop& from, std::vector<unsigned char>&& msg)
{
    MessageKind kind;
    // Unrecognised messages are dropped without a reply. The sender is
    // authenticated, so this is a version difference rather than an attack, and
    // answering it tells an observer the two disagree.
    if (!DecodeKind(msg, kind)) return;

    switch (kind) {
    case MessageKind::APP_DATA: {
        std::vector<unsigned char> payload;
        if (!DecodeAppData(msg, payload)) return;
        if (m_app) m_app(from, std::move(payload));
        return;
    }

    case MessageKind::PATH_BUILD: {
        uint64_t path_id = 0;
        CService dest;
        CPubKey dest_key;
        if (!DecodePathBuild(msg, path_id, dest, dest_key)) return;
        ExpirePendingBuilds();

        // The next relay may be one this node reaches over radio rather than at
        // the address the roster lists - a radio neighbour of a node with no
        // internet to it. The resolver (set from overlay/radio.h) returns that
        // local port, and `slow` sizes the wait. `dest` stays the roster
        // address, which is what the dial policy is checked against.
        CService reach = dest;
        bool slow = false;
        {
            NextHopResolver resolve;
            {
                LOCK(m_mutex);
                resolve = m_next_hop;
            }
            if (resolve && dest_key.IsValid()) reach = resolve(dest_key, dest, slow);
        }

        // A session that exists already is used only if it is with the key
        // the path was asked for; an address is not an identity.
        bool linked = m_socket.HasSession(reach);
        if (linked && dest_key.IsValid() && m_socket.PeerIdentity(reach) != dest_key) linked = false;

        if (!linked && dest_key.IsValid() && Hop::Direct(reach) != from) {
            // Dial only a relay the roster lists, at the address it lists, with
            // the key it lists. Building a path to a host this node has never
            // heard of would let a stranger name any address and have the
            // relay dial it, which is an open proxy rather than an overlay.
            DialPolicy dial;
            {
                LOCK(m_mutex);
                dial = m_dial;
            }
            if (dial && dial(dest, dest_key)) {
                bool waiting = false;
                {
                    LOCK(m_mutex);
                    for (const PendingBuild& p : m_pending_builds) {
                        if (p.path_id == path_id) waiting = true;
                    }
                    if (!waiting && m_pending_builds.size() < MAX_PENDING_BUILDS) {
                        // A radio handshake takes longer than an internet one.
                        m_pending_builds.push_back(
                            PendingBuild{path_id, from, reach, dest_key,
                                         GetTime() + (slow ? RADIO_DIAL_TTL : PENDING_BUILD_TTL)});
                        waiting = true;
                    }
                }
                if (waiting) {
                    if (!m_socket.HasPendingHandshake(reach)) m_socket.Connect(reach, dest_key);
                    LogPrint(BCLog::NET, "overlay: dialling %s to extend a path%s\n", reach.ToString(),
                             slow ? " over radio" : "");
                    return; // answered once the session completes, or when it times out
                }
            }
        }

        if (!linked) {
            std::vector<unsigned char> reply;
            if (EncodePathResult(false, path_id, reply)) SendToHop(from, reply);
            return;
        }
        FinishBuild(path_id, from, reach);
        return;
    }

    case MessageKind::PATH_OK:
    case MessageKind::PATH_FAIL: {
        bool ok = false;
        uint64_t path_id = 0;
        if (!DecodePathResult(msg, ok, path_id)) return;
        if (ok) {
            // The originator is an end of its own path too. Without an entry
            // here it sends fine and drops every reply, because return traffic
            // arrives on a path it has not recorded itself as an end of.
            LOCK(m_mutex);
            m_paths.CreateEndpoint(path_id, from, GetTime());
        }
        NoteResult(path_id, ok);
        if (m_path) m_path(path_id, ok);
        return;
    }

    case MessageKind::PATH_BIND: {
        uint64_t path_id = 0;
        if (!DecodePathBind(msg, path_id)) return;
        LOCK(m_mutex);
        m_paths.Expire(GetTime());
        m_paths.CreateEndpoint(path_id, from, GetTime());
        return;
    }

    case MessageKind::INTRODUCE: {
        roster::KeyBytes service;
        if (!DecodeIntroduce(msg, service)) return;
        // Only over a path: a service registering from an address would have
        // just told the relay where it is, which is the one thing it must not.
        if (!from.via_path) return;
        IntroducePolicy policy;
        {
            LOCK(m_mutex);
            // And only by the service itself. The end-to-end session proved a
            // key; registering under any other would let anyone take over a
            // service's meeting point and be spliced to its clients in its place.
            if (!SameX(m_secret.PeerIdentity(from.path), service)) return;
            policy = m_introduce;
        }
        // And only for a key the roster lists, asked outside the lock since
        // it reads the roster.
        bool ok = !policy || policy(service);
        if (ok) {
            LOCK(m_mutex);
            m_paths.Expire(GetTime());
            PruneIntros();
            // Bounded, because registering is something strangers do.
            ok = m_intros.size() < PathTable::MAX_PATHS || m_intros.count(service);
            if (ok) m_intros[service] = from.path;
        }
        // Answered, so the service knows it can be met here. Repeating the
        // registration is also how it keeps the path from idling out.
        std::vector<unsigned char> answer;
        if (EncodeIntroduced(ok, service, answer)) SendSecretRaw(from.path, answer);
        return;
    }

    case MessageKind::INTRODUCED: {
        bool ok = false;
        roster::KeyBytes service;
        if (!DecodeIntroduced(msg, ok, service) || !from.via_path) return;
        // Only the meeting point at the far end of the registration path can
        // send this: it arrived sealed in the session with it.
        NoteResult(from.path, ok);
        return;
    }

    case MessageKind::MEET: {
        roster::KeyBytes service;
        uint64_t meet_id = 0;
        if (!DecodeMeet(msg, service, meet_id)) return;
        if (!from.via_path) return;

        Hop service_hop;
        bool ok = false;
        {
            LOCK(m_mutex);
            m_paths.Expire(GetTime());
            // A registration whose path has gone would splice the visitor to
            // nothing and still answer that it worked.
            PruneIntros();
            std::map<roster::KeyBytes, uint64_t>::const_iterator it = m_intros.find(service);
            if (it != m_intros.end()) {
                service_hop = Hop::Path(it->second);
                m_paths.Expire(GetTime());
                // The splice: two paths joined, and this relay is the only
                // node that touches both. It still knows neither end's
                // address, because it reaches both of them through paths.
                ok = (service_hop != from) &&
                     m_paths.Create(meet_id, from, service_hop, GetTime());
            }
        }

        if (ok) {
            std::vector<unsigned char> bind;
            if (EncodePathBind(meet_id, bind)) SendToHop(service_hop, bind);
        }
        std::vector<unsigned char> reply;
        if (EncodePathResult(ok, meet_id, reply)) SendToHop(from, reply);
        return;
    }

    case MessageKind::PATH_DATA: {
        uint64_t path_id = 0;
        std::vector<unsigned char> inner;
        if (!DecodePathData(msg, path_id, inner)) return;

        Hop next;
        Route route;
        {
            LOCK(m_mutex);
            route = m_paths.Next(path_id, from, next, GetTime());
        }

        if (route == Route::FORWARD) {
            // Re-wrapped rather than passed through: each leg has its own
            // encryption, so the bytes arriving from one hop are never the
            // bytes leaving for the next. Not padded again: what is inside
            // was padded where it began.
            std::vector<unsigned char> out;
            if (!EncodePathData(path_id, inner, out)) return;
            SendToHop(next, out, /* wrapping */ true);
            return;
        }
        if (route != Route::DELIVER) return;

        // The end of the path. These bytes may be an end-to-end handshake or a
        // payload sealed for us, which the relays that carried them hold no key
        // for - or plain path traffic they could read.
        std::vector<unsigned char> reply, opened;
        PathTransport::Result r;
        {
            LOCK(m_mutex);
            r = m_secret.Receive(path_id, inner.data(), inner.size(), reply, opened);
        }
        if (!reply.empty()) SendOnPath(path_id, reply);

        switch (r) {
        case PathTransport::Result::PAYLOAD:
            // Sealed traffic from the far end. Dispatched rather than
            // delivered: this is how a relay is asked to extend a path, since
            // the asking arrives through the part already built.
            OnMessage(Hop::Path(path_id), std::move(opened));
            return;
        case PathTransport::Result::ESTABLISHED:
            LogPrint(BCLog::NET, "overlay: end-to-end session on path %016x\n", path_id);
            return;
        default:
            // Not end-to-end traffic, so it is plain path data for us -
            // readable by every relay that carried it, which is the difference
            // SendSecret exists to remove.
            if (m_app) m_app(from, std::move(inner));
            return;
        }
    }
    }
}

} // namespace overlay
