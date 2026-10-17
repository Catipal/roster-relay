// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/meeting.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <crypto/common.h>
#include <index/rosterindex.h>
#include <logging.h>
#include <overlay/radio.h>
#include <overlay/relay.h>
#include <overlay/rendezvous.h>
#include <random.h>
#include <roster/keystore.h>
#include <roster/listing.h>
#include <roster/peers.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/time.h>

#include <algorithm>
#include <condition_variable>
#include <limits>
#include <set>

namespace overlay {

std::unique_ptr<MeetingService> g_meeting;

namespace {

/** How long a meeting point has to answer one registration or one request to meet. */
constexpr std::chrono::milliseconds ANSWER_WAIT{5000};

int TipHeight()
{
    return g_rosterindex ? g_rosterindex->GetSummary().best_block_height : -1;
}

/** Register `self` over `path` and wait for the meeting point's answer, a few tries. */
bool Register(uint64_t path, const roster::KeyBytes& self, std::chrono::milliseconds wait)
{
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (!g_overlay || !g_overlay->Introduce(path, self)) return false;
        const int answer = g_overlay->AwaitPath(path, wait);
        if (answer >= 0) return answer == 1;
    }
    return false;
}

Mutex g_echo_mutex;
std::condition_variable g_echo_cv;
std::map<uint64_t, bool> g_echoes GUARDED_BY(g_echo_mutex);

std::vector<unsigned char> EchoMessage(bool answer, uint64_t nonce)
{
    std::vector<unsigned char> msg{MEET_ECHO, static_cast<unsigned char>(answer ? 1 : 0)};
    unsigned char n[8];
    WriteLE64(n, nonce);
    msg.insert(msg.end(), n, n + sizeof(n));
    return msg;
}

} // namespace

bool MeetingPointsFor(const roster::KeyBytes& service, uint64_t epoch, std::vector<roster::KeyBytes>& out,
                      std::string& error)
{
    out.clear();
    if (!g_rosterindex) {
        error = "the roster index is off (-rosterindex)";
        return false;
    }
    const int anchor = RendezvousAnchor(epoch);
    if (anchor > TipHeight()) {
        error = "the chain has not reached that epoch's anchor yet";
        return false;
    }
    std::vector<roster::KeyBytes> relays;
    // On regtest every node is on 127.0.0.1, so local endpoints count there.
    const bool local = Params().NetworkIDString() == CBaseChainParams::REGTEST;
    if (!roster::AgreedRelays(*g_rosterindex, anchor, relays, local)) {
        error = "could not read the roster";
        return false;
    }
    out = RendezvousPoints(service, epoch, relays);
    if (out.empty()) error = "the roster lists no relays to meet at";
    return !out.empty();
}

bool ReachRelay(const roster::KeyBytes& key, int hops, bool prove_last, Reached& out, std::string& error)
{
    out = Reached();
    if (!g_overlay) {
        error = "the overlay is off";
        return false;
    }
    hops = std::max(1, std::min(MAX_MEET_HOPS, hops));
    RelayCandidate dest;
    bool found = false;
    for (const roster::RelayInfo& r : roster::FreshRelays()) {
        if (r.key == key) {
            dest.key = r.key;
            dest.addr = r.addr;
            found = true;
            break;
        }
    }
    if (!found) {
        error = "the roster lists no address this node can reach that relay at";
        return false;
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        std::vector<RelayCandidate> chosen;
        {
            LOCK(g_selector_mutex);
            if (!g_selector || !g_selector->Select(hops, chosen, dest)) {
                error = strprintf("the roster does not list %d relays run by different people to go through", hops);
                return false;
            }
        }
        chosen.push_back(dest);
        std::vector<Relay::CircuitHop> circuit;
        bool slow = false;
        for (const RelayCandidate& c : chosen) {
            Relay::CircuitHop h;
            h.addr = roster::OverlayAddressFor(c.addr);
            // The first hop may be a radio neighbour (overlay/radio.h).
            if (circuit.empty()) h.addr = FirstHopAddress(c.key, h.addr, slow);
            if (!roster::StakerPubKeyFromRoster(c.key, h.key)) {
                error = "a relay's listed key is not a point on the curve";
                return false;
            }
            circuit.push_back(h);
        }
        // A hidden node may be reached across a radio hop anywhere on the path
        // - a relay bridging to the next over radio - which the builder cannot
        // see and cannot size a timeout from. So budget for radio on every step
        // (RadioStepTimeout is the radio step even when the first hop is not
        // radio), or a slow later hop times the handshake out before its answer
        // returns. Success still returns as soon as each step completes.
        const std::chrono::milliseconds step = RadioStepTimeout(circuit[0].addr);
        uint64_t path = 0;
        if (g_overlay->BuildCircuit(circuit, path, error, step, prove_last)) {
            out.path = path;
            out.legs = g_overlay->CircuitLegs(path);
            for (size_t i = 0; i + 1 < chosen.size(); ++i) out.through.push_back(chosen[i].key);
            out.step = step;
            return true;
        }
        // An entry relay that does not answer stops being one; the next try
        // picks another. Any other failure is a later relay, chosen afresh.
        if (error.rfind("the entry relay", 0) == 0) {
            LOCK(g_selector_mutex);
            if (g_selector) g_selector->DropGuard(chosen[0].key);
        }
    }
    return false;
}

MeetingService::MeetingService(const roster::KeyBytes& self, int hops)
    : m_self(self), m_hops(std::max(1, std::min(MAX_MEET_HOPS, hops)))
{
    CKey node;
    if (roster::ReadOperationalKey(node)) m_node = roster::KeyBytesOf(node);
}

MeetingService::~MeetingService() { Stop(); }

void MeetingService::Start()
{
    if (m_thread.joinable()) return;
    m_interrupt.reset();
    m_thread = std::thread(&TraceThread<std::function<void()>>, "meeting",
                           std::function<void()>([this] { ThreadMeeting(); }));
}

void MeetingService::Stop()
{
    m_interrupt();
    if (m_thread.joinable()) m_thread.join();
}

std::vector<Registration> MeetingService::Registrations() const
{
    std::vector<Registration> out;
    LOCK(m_mutex);
    for (const auto& r : m_regs) out.push_back(r.second);
    return out;
}

std::string MeetingService::LastError() const
{
    LOCK(m_mutex);
    return m_error;
}

void MeetingService::KeepGuardsAwake()
{
    if (!g_overlay) return;
    std::vector<roster::KeyBytes> guards;
    {
        LOCK(m_mutex);
        for (const auto& r : m_regs) {
            const std::vector<roster::KeyBytes>& through = r.second.reached.through;
            if (!through.empty() && std::find(guards.begin(), guards.end(), through.front()) == guards.end()) {
                guards.push_back(through.front());
            }
        }
    }
    if (guards.empty()) return;
    const std::vector<unsigned char> ping{KEEPALIVE_TAG};
    for (const roster::RelayInfo& info : roster::FreshRelays()) {
        if (std::find(guards.begin(), guards.end(), info.key) == guards.end()) continue;
        bool slow = false;
        const CService at = FirstHopAddress(info.key, roster::OverlayAddressFor(info.addr), slow);
        // Radio has no router to keep awake, and airtime is too scarce to spend on nothing.
        if (slow) continue;
        g_overlay->SendApp(at, ping);
    }
}

void MeetingService::ThreadMeeting()
{
    // A first round once the roster has had a moment to be read, then every
    // few seconds; each round does only what is due.
    int64_t next = GetTime() + 5;
    int64_t next_keepalive = GetTime() + KEEPALIVE_GUARD;
    while (m_interrupt.sleep_for(std::chrono::seconds{1})) {
        if (GetTime() >= next_keepalive) {
            KeepGuardsAwake();
            next_keepalive = GetTime() + KEEPALIVE_GUARD;
        }
        if (GetTime() < next) continue;
        Tick();
        next = GetTime() + 10;
    }
}

void MeetingService::Tick()
{
    if (!g_overlay || !g_rosterindex) return;
    const int height = TipHeight();

    // Where this node should be registered now, and for which epochs. One
    // registration serves a relay that is a point for two epochs at once.
    std::map<roster::KeyBytes, std::vector<uint64_t>> want;
    std::string error, last_error;
    for (uint64_t epoch : EpochsToRegister(height)) {
        std::vector<roster::KeyBytes> points;
        if (!MeetingPointsFor(m_self, epoch, points, error)) {
            last_error = error;
            continue;
        }
        for (const roster::KeyBytes& p : points) {
            // Visitors who try this node as the point find no registration and
            // go on to the others; nobody else learns anything from it.
            if (p == m_node) continue;
            want[p].push_back(epoch);
        }
    }
    // And the one its listing names, for as long as the listing lasts: the
    // chain holds it, so visitors can count on it whatever the epoch.
    roster::KeyBytes listed{};
    const bool have_listed = roster::ListedMeetingPoint(*g_rosterindex, m_self, height, listed) && listed != m_node;
    if (have_listed) want[listed];

    // Registrations no epoch needs any more lapse with their paths.
    std::vector<Registration> gone;
    {
        LOCK(m_mutex);
        for (auto it = m_regs.begin(); it != m_regs.end();) {
            auto w = want.find(it->first);
            if (w == want.end()) {
                gone.push_back(it->second);
                it = m_regs.erase(it);
            } else {
                it->second.epochs = w->second;
                it->second.listed = have_listed && it->first == listed;
                ++it;
            }
        }
    }
    for (const Registration& r : gone) g_overlay->ClosePath(r.reached.legs);

    for (const auto& w : want) {
        if (m_interrupt) return;
        const int64_t now = GetTime();
        Registration reg;
        bool have = false;
        {
            LOCK(m_mutex);
            auto it = m_regs.find(w.first);
            if (it != m_regs.end()) {
                reg = it->second;
                have = true;
            }
        }
        // A path that starts on the radio takes longer a step (Reached::step).
        const bool radio = reg.reached.step > Reached().step;
        if (have && now - reg.refreshed < (radio ? MEET_REFRESH_RADIO : MEET_REFRESH)) continue;

        // Repeated over the path it was made on, which keeps that path alive;
        // made afresh if the path or the registration is gone.
        bool ok = have && Register(reg.reached.path, m_self, std::max(ANSWER_WAIT, reg.reached.step / 3));
        if (!ok) {
            if (have) g_overlay->ClosePath(reg.reached.legs);
            Reached fresh;
            if (ReachRelay(w.first, m_hops, /* prove_last */ true, fresh, error)) {
                ok = Register(fresh.path, m_self, std::max(ANSWER_WAIT, fresh.step / 3));
                if (!ok) {
                    g_overlay->ClosePath(fresh.legs);
                    error = "the meeting point did not register this node";
                }
            }
            if (ok) {
                reg = Registration();
                reg.point = w.first;
                reg.reached = fresh;
                reg.since = now;
                LogPrint(BCLog::NET, "overlay: registered at meeting point %s through %u relays\n",
                         HexStr(w.first).substr(0, 16), (unsigned)fresh.through.size());
            }
        }
        LOCK(m_mutex);
        if (!ok) {
            m_regs.erase(w.first);
            last_error = strprintf("meeting point %s: %s", HexStr(w.first).substr(0, 16), error);
            continue;
        }
        reg.refreshed = now;
        reg.epochs = w.second;
        reg.listed = have_listed && w.first == listed;
        m_regs[w.first] = reg;
    }
    LOCK(m_mutex);
    m_error = last_error;
}

bool MeetService(const roster::KeyBytes& service, int hops, Meeting& out, std::string& error, bool listed_only)
{
    out = Meeting();
    if (!g_overlay || !g_rosterindex) {
        error = !g_overlay ? "the overlay is off" : "the roster index is off (-rosterindex)";
        return false;
    }
    CPubKey service_pub;
    if (!roster::StakerPubKeyFromRoster(service, service_pub)) {
        error = "that is not a key on the curve";
        return false;
    }
    hops = std::max(1, std::min(MAX_MEET_HOPS, hops));
    std::string why = "no meeting point was found";
    FastRandomContext rng;
    // Today's points first, so visits spread over relays that change every
    // epoch; the one the listing names for its whole life is the one left
    // when they fail, and is the same for every visitor all month.
    struct Try {
        roster::KeyBytes point;
        uint64_t epoch;
        bool listed;
    };
    std::vector<Try> tries;
    const int tip = TipHeight();
    if (!listed_only) {
        for (uint64_t epoch : EpochsToTry(tip)) {
            std::vector<roster::KeyBytes> points;
            if (!MeetingPointsFor(service, epoch, points, why)) continue;
            // In no fixed order, so visitors spread over all three.
            Shuffle(points.begin(), points.end(), rng);
            for (const roster::KeyBytes& p : points) tries.push_back(Try{p, epoch, false});
        }
    }
    roster::KeyBytes named{};
    if (roster::ListedMeetingPoint(*g_rosterindex, service, tip, named)) {
        tries.push_back(Try{named, RendezvousEpoch(tip), true});
    } else if (listed_only) {
        why = "its listing names no meeting point";
    }
    // Never this node itself: a path to itself cannot be built, and when it
    // is one of the service's points, the others serve as well.
    std::set<roster::KeyBytes> tried;
    CKey own;
    if (roster::ReadOperationalKey(own)) tried.insert(roster::KeyBytesOf(own));
    for (const Try& t : tries) {
        const roster::KeyBytes& point = t.point;
        const uint64_t epoch = t.epoch;
        if (!tried.insert(point).second) continue;
        {
            Reached r;
            if (!ReachRelay(point, hops, /* prove_last */ false, r, why)) continue;
            const std::chrono::milliseconds wait = std::max(ANSWER_WAIT, r.step / 3);
            const uint64_t meet_id = GetRand(std::numeric_limits<uint64_t>::max() - 1) + 1;
            int answer = -1;
            for (int attempt = 0; answer < 0 && attempt < 3; ++attempt) {
                if (!g_overlay->Meet(r.path, service, meet_id)) break;
                answer = g_overlay->AwaitPath(meet_id, wait);
            }
            if (answer != 1) {
                g_overlay->ClosePath(r.legs);
                why = answer == 0 ? "the meeting point has no registration for that key"
                                  : "the meeting point did not answer";
                continue;
            }
            // End to end across the join, to the key the roster names: a
            // meeting point that joined the visitor to anyone else could not
            // complete this. The visitor shows a key made for this alone.
            bool secret = false;
            for (int attempt = 0; !secret && attempt < 3; ++attempt) {
                if (!g_overlay->ConnectSecret(meet_id, service_pub, /* anonymous */ true)) break;
                const auto until = std::chrono::steady_clock::now() + wait;
                while (std::chrono::steady_clock::now() < until && !g_overlay->HasSecretSession(meet_id)) {
                    UninterruptibleSleep(std::chrono::milliseconds{20});
                }
                secret = g_overlay->HasSecretSession(meet_id);
            }
            std::vector<uint64_t> legs = r.legs;
            legs.push_back(meet_id);
            if (!secret) {
                g_overlay->ClosePath(legs);
                why = "the service did not answer across its meeting point";
                continue;
            }
            out.path = meet_id;
            out.legs = legs;
            out.point = point;
            out.epoch = epoch;
            out.hops = hops;
            out.listed = t.listed;
            return true;
        }
    }
    error = why;
    return false;
}

void CloseMeeting(const Meeting& m)
{
    if (g_overlay && !m.legs.empty()) g_overlay->ClosePath(m.legs);
}

bool EchoAcross(const Meeting& m, std::chrono::milliseconds timeout, std::chrono::milliseconds& rtt)
{
    if (!g_overlay) return false;
    const uint64_t nonce = GetRand(std::numeric_limits<uint64_t>::max());
    {
        LOCK(g_echo_mutex);
        g_echoes[nonce] = false;
    }
    const auto start = std::chrono::steady_clock::now();
    bool answered = false;
    for (int attempt = 0; !answered && attempt < 3; ++attempt) {
        if (!g_overlay->SendSecret(m.path, EchoMessage(false, nonce))) break;
        WAIT_LOCK(g_echo_mutex, lock);
        g_echo_cv.wait_for(lock, timeout / 3, [&]() EXCLUSIVE_LOCKS_REQUIRED(g_echo_mutex) { return g_echoes[nonce]; });
        answered = g_echoes[nonce];
    }
    LOCK(g_echo_mutex);
    g_echoes.erase(nonce);
    rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    return answered;
}

void HandleMeetEcho(const Hop& from, const std::vector<unsigned char>& payload)
{
    // Only across a path: the question is whether a meeting works.
    if (payload.size() != 10 || payload[0] != MEET_ECHO || !from.via_path || !g_overlay) return;
    const uint64_t nonce = ReadLE64(payload.data() + 2);
    if (payload[1] == 0) {
        g_overlay->SendSecret(from.path, EchoMessage(true, nonce));
    } else if (payload[1] == 1) {
        LOCK(g_echo_mutex);
        std::map<uint64_t, bool>::iterator it = g_echoes.find(nonce);
        if (it != g_echoes.end()) it->second = true;
        g_echo_cv.notify_all();
    }
}

} // namespace overlay
