// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/hosting.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <logging.h>
#include <overlay/frame.h>
#include <overlay/relay.h>
#include <pubkey.h>
#include <random.h>
#include <index/rosterindex.h>
#include <overlay/meeting.h>
#include <roster/keystore.h>
#include <roster/listing.h>
#include <roster/peers.h>
#include <roster/view.h>
#include <shutdown.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <limits>

namespace overlay {

namespace {

void PutU32(std::vector<unsigned char>& out, uint32_t v) { unsigned char b[4]; WriteLE32(b, v); out.insert(out.end(), b, b + 4); }
void PutU64(std::vector<unsigned char>& out, uint64_t v) { unsigned char b[8]; WriteLE64(b, v); out.insert(out.end(), b, b + 8); }

uint256 TaggedManifestHash(const std::vector<unsigned char>& body)
{
    CHashWriter h = TaggedHash("BPS/site/v1");
    h.write(reinterpret_cast<const char*>(body.data()), body.size());
    return h.GetSHA256();
}

//! A relative, forward-slash path with no "." or ".." components, so a site
//! cannot name a file outside its own directory.
bool SafeRelPath(const std::string& p)
{
    if (p.empty() || p.size() > MAX_SITE_PATH || p.front() == '/') return false;
    size_t start = 0;
    while (start <= p.size()) {
        const size_t slash = p.find('/', start);
        const std::string part = p.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (part.find('\\') != std::string::npos) return false;
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return true;
}

} // namespace

bool IsSitePayload(const std::vector<unsigned char>& payload)
{
    if (payload.empty()) return false;
    switch (payload[0]) {
    case SITE_GETMANIFEST:
    case SITE_MANIFEST:
    case SITE_GETPIECE:
    case SITE_PIECE:
    case SITE_NOTFOUND:
        return true;
    }
    return false;
}

// --- manifest ----------------------------------------------------------------

std::vector<unsigned char> SiteManifest::Body() const
{
    std::vector<unsigned char> out;
    PutU32(out, version);
    PutU32(out, (uint32_t)files.size());
    for (const SiteFile& f : files) {
        PutU32(out, (uint32_t)f.path.size());
        out.insert(out.end(), f.path.begin(), f.path.end());
        PutU64(out, f.size);
        PutU32(out, (uint32_t)f.pieces.size());
        for (const uint256& h : f.pieces) out.insert(out.end(), h.begin(), h.end());
    }
    return out;
}

bool SiteManifest::Serialize(std::vector<unsigned char>& out) const
{
    if (sig.size() != 64) return false;
    out = Body();
    out.insert(out.end(), sig.begin(), sig.end());
    return true;
}

bool SiteManifest::Deserialize(const std::vector<unsigned char>& in)
{
    *this = SiteManifest();
    if (in.size() < 64 + 8) return false;
    const size_t body_len = in.size() - 64;
    size_t at = 0;
    auto need = [&](size_t n) { return at + n <= body_len; };
    if (!need(8)) return false;
    version = ReadLE32(in.data() + at); at += 4;
    const uint32_t count = ReadLE32(in.data() + at); at += 4;
    if (count > MAX_SITE_FILES) return false;
    for (uint32_t i = 0; i < count; ++i) {
        if (!need(4)) return false;
        const uint32_t plen = ReadLE32(in.data() + at); at += 4;
        if (plen > MAX_SITE_PATH || !need(plen + 8 + 4)) return false;
        SiteFile f;
        f.path.assign(in.begin() + at, in.begin() + at + plen); at += plen;
        f.size = ReadLE64(in.data() + at); at += 8;
        const uint32_t npieces = ReadLE32(in.data() + at); at += 4;
        // The piece count must match the size, so a manifest cannot claim a
        // short file with many hashes or the other way round.
        const uint64_t expect = f.size == 0 ? 0 : (f.size + SITE_PIECE_SIZE - 1) / SITE_PIECE_SIZE;
        if (npieces != expect || f.size > MAX_SITE_SIZE || !SafeRelPath(f.path)) return false;
        if (!need((size_t)npieces * 32)) return false;
        f.pieces.resize(npieces);
        for (uint32_t p = 0; p < npieces; ++p) { std::copy(in.begin() + at, in.begin() + at + 32, f.pieces[p].begin()); at += 32; }
        files.push_back(std::move(f));
    }
    if (at != body_len) return false;
    sig.assign(in.end() - 64, in.end());
    return true;
}

const SiteFile* SiteManifest::Find(const std::string& path) const
{
    for (const SiteFile& f : files) if (f.path == path) return &f;
    return nullptr;
}

bool BuildSiteManifest(const fs::path& dir, uint32_t version, SiteManifest& out, std::string& error)
{
    out = SiteManifest();
    out.version = version;
    if (!fs::is_directory(dir)) { error = "not a directory: " + dir.string(); return false; }
    uint64_t total = 0;
    std::vector<fs::path> paths;
    try {
        for (fs::recursive_directory_iterator it(dir), end; it != end; ++it) {
            if (!fs::is_regular_file(it->path())) continue;
            paths.push_back(it->path());
        }
    } catch (const std::exception& e) { error = e.what(); return false; }
    std::sort(paths.begin(), paths.end());

    for (const fs::path& p : paths) {
        // The path relative to the site root, with forward slashes.
        std::string rel = p.string().substr(dir.string().size());
        std::replace(rel.begin(), rel.end(), '\\', '/');
        while (!rel.empty() && rel.front() == '/') rel.erase(rel.begin());
        if (!SafeRelPath(rel)) { error = "unusable file name: " + rel; return false; }

        SiteFile f;
        f.path = rel;
        fsbridge::ifstream in(p, std::ios::binary);
        if (!in) { error = "cannot read " + rel; return false; }
        std::vector<unsigned char> piece(SITE_PIECE_SIZE);
        while (in) {
            in.read(reinterpret_cast<char*>(piece.data()), SITE_PIECE_SIZE);
            const std::streamsize got = in.gcount();
            if (got <= 0) break;
            uint256 h;
            CSHA256().Write(piece.data(), (size_t)got).Finalize(h.begin());
            f.pieces.push_back(h);
            f.size += (uint64_t)got;
            total += (uint64_t)got;
            if (total > MAX_SITE_SIZE) { error = "the site is larger than the limit"; return false; }
        }
        out.files.push_back(std::move(f));
        if (out.files.size() > MAX_SITE_FILES) { error = "too many files"; return false; }
    }
    if (out.files.empty()) { error = "the directory has no files"; return false; }
    return true;
}

bool SignSiteManifest(SiteManifest& m, const CKey& key)
{
    m.sig.assign(64, 0);
    return key.SignSchnorr(TaggedManifestHash(m.Body()), m.sig);
}

bool VerifySiteManifest(const SiteManifest& m, const roster::KeyBytes& site_key)
{
    if (m.sig.size() != 64) return false;
    uint256 keybytes;
    std::copy(site_key.begin(), site_key.end(), keybytes.begin());
    const XOnlyPubKey pub(keybytes);
    return pub.VerifySchnorr(TaggedManifestHash(m.Body()), m.sig);
}

uint64_t SiteManifest::TotalSize() const
{
    uint64_t n = 0;
    for (const SiteFile& f : files) n += f.size;
    return n;
}

// --- chunks ------------------------------------------------------------------

bool ChunkAssembler::Add(uint32_t total, uint32_t offset, const unsigned char* data, size_t n)
{
    if (total > MAX_SITE_SIZE || (uint64_t)offset + n > total) return false;
    if (n == 0 && total != 0) return false;
    if (!m_started) {
        m_started = true;
        m_total = total;
        m_buf.assign(total, 0);
    } else if (total != m_total) {
        return false;
    }
    if (n == 0) return true; // the one chunk of an empty answer
    std::map<uint32_t, uint32_t>::iterator next = m_got.lower_bound(offset);
    if (next != m_got.end() && next->first == offset) {
        // Sent twice: the same bytes again, or a contradiction.
        return next->second == n && std::equal(data, data + n, m_buf.begin() + offset);
    }
    if (next != m_got.end() && (uint64_t)offset + n > next->first) return false;
    if (next != m_got.begin()) {
        std::map<uint32_t, uint32_t>::iterator prev = std::prev(next);
        if ((uint64_t)prev->first + prev->second > offset) return false;
    }
    std::copy(data, data + n, m_buf.begin() + offset);
    m_got.emplace(offset, (uint32_t)n);
    m_have += n;
    return true;
}

std::vector<std::vector<unsigned char>> MakeChunks(uint8_t tag, uint64_t reqid,
                                                   const std::vector<unsigned char>& payload, size_t chunk)
{
    std::vector<std::vector<unsigned char>> out;
    const uint32_t total = (uint32_t)payload.size();
    uint32_t offset = 0;
    do {
        const uint32_t n = (uint32_t)std::min<uint64_t>(chunk, total - offset);
        std::vector<unsigned char> msg{tag};
        PutU64(msg, reqid);
        PutU32(msg, total);
        PutU32(msg, offset);
        msg.insert(msg.end(), payload.begin() + offset, payload.begin() + offset + n);
        out.push_back(std::move(msg));
        offset += n;
    } while (offset < total);
    return out;
}

namespace {

bool SendTo(const Hop& to, const std::vector<unsigned char>& msg)
{
    if (!g_overlay) return false;
    return to.via_path ? g_overlay->SendSecret(to.path, msg) : g_overlay->SendApp(to.addr, msg);
}

size_t ChunkFor(const Hop& to) { return to.via_path ? SITE_CHUNK_PATH : SITE_CHUNK_DIRECT; }

std::vector<unsigned char> NotFound(uint64_t reqid)
{
    std::vector<unsigned char> msg{SITE_NOTFOUND};
    PutU64(msg, reqid);
    return msg;
}

} // namespace

// --- serving -----------------------------------------------------------------

HostingServer::HostingServer(const fs::path& dir, const SiteManifest& manifest)
    : m_dir(dir), m_manifest(manifest) {}

HostingServer::~HostingServer() { Stop(); }

void HostingServer::Start()
{
    if (m_thread.joinable()) return;
    m_interrupt.reset();
    m_thread = std::thread(&TraceThread<std::function<void()>>, "hosting",
                           std::function<void()>([this] { ThreadSend(); }));
}

void HostingServer::Stop()
{
    m_interrupt();
    {
        LOCK(m_mutex);
        m_cv.notify_all();
    }
    if (m_thread.joinable()) m_thread.join();
}

bool HostingServer::ReadPiece(size_t file, uint32_t piece, std::vector<unsigned char>& out) const
{
    if (file >= m_manifest.files.size()) return false;
    const SiteFile& f = m_manifest.files[file];
    if (piece >= f.pieces.size() || !SafeRelPath(f.path)) return false;
    const uint64_t offset = (uint64_t)piece * SITE_PIECE_SIZE;
    if (offset >= f.size) return false;
    const size_t n = (size_t)std::min<uint64_t>(SITE_PIECE_SIZE, f.size - offset);
    fsbridge::ifstream in(m_dir / fs::path(f.path), std::ios::binary);
    if (!in) return false;
    in.seekg((std::streamoff)offset);
    out.assign(n, 0);
    in.read(reinterpret_cast<char*>(out.data()), n);
    if ((size_t)in.gcount() != n) return false;
    // The bytes on disk must still match what the manifest promised, or a file
    // changed under us after it was published; refuse rather than serve a piece
    // whose hash will not check out at the visitor.
    uint256 h;
    CSHA256().Write(out.data(), n).Finalize(h.begin());
    return h == f.pieces[piece];
}

void HostingServer::HandleRequest(const Hop& from, const std::vector<unsigned char>& payload)
{
    if (payload.size() < 1 + 8) return;
    Request r;
    r.from = from;
    r.tag = payload[0];
    r.reqid = ReadLE64(payload.data() + 1);
    if (r.tag == SITE_GETPIECE) {
        if (payload.size() != 1 + 8 + 4 + 4) return;
        r.file = ReadLE32(payload.data() + 9);
        r.piece = ReadLE32(payload.data() + 13);
    } else if (r.tag != SITE_GETMANIFEST) {
        return;
    }
    LOCK(m_mutex);
    // Bounded per visitor and in all: a visitor asks again for what it does
    // not get, so a request dropped here costs a wait, never a wrong answer.
    size_t total = m_requests.size(), mine = 0;
    for (const Request& q : m_requests) if (q.from == from) ++mine;
    for (const auto& o : m_out) {
        total += o.second.answers.size();
        if (o.first == from) mine += o.second.answers.size();
    }
    if (mine >= MAX_QUEUED_PER_HOP || total >= MAX_QUEUED) {
        ++m_stats.refused;
        return;
    }
    m_requests.push_back(std::move(r));
    m_cv.notify_all();
}

HostingServer::Stats HostingServer::GetStats() const
{
    LOCK(m_mutex);
    Stats s = m_stats;
    s.queued = m_requests.size();
    for (const auto& o : m_out) s.queued += o.second.answers.size();
    return s;
}

void HostingServer::ThreadSend()
{
    std::vector<unsigned char> manifest_raw;
    m_manifest.Serialize(manifest_raw);
    int64_t next_check = 0;

    while (!m_interrupt) {
        // Whether this site has to be met at its meeting points can change as
        // the roster moves, so it is looked at again every minute.
        if (GetTime() >= next_check) {
            UpdateSiteMeeting();
            next_check = GetTime() + 60;
        }

        // Turn requests into answers, reading from disk outside the lock.
        std::deque<Request> todo;
        {
            LOCK(m_mutex);
            todo.swap(m_requests);
        }
        for (const Request& r : todo) {
            std::vector<std::vector<unsigned char>> chunks;
            bool piece = false;
            if (r.tag == SITE_GETMANIFEST) {
                chunks = MakeChunks(SITE_MANIFEST, r.reqid, manifest_raw, ChunkFor(r.from));
            } else {
                std::vector<unsigned char> bytes;
                if (ReadPiece(r.file, r.piece, bytes)) {
                    chunks = MakeChunks(SITE_PIECE, r.reqid, bytes, ChunkFor(r.from));
                    piece = true;
                } else {
                    chunks.push_back(NotFound(r.reqid));
                }
            }
            LOCK(m_mutex);
            if (r.tag == SITE_GETMANIFEST) ++m_stats.manifests;
            if (piece) ++m_stats.pieces;
            m_out[r.from].answers.push_back(std::move(chunks));
        }

        // Send the chunk due soonest. Each visitor's chunks go out no faster
        // than SITE_SEND_RATE, so a relay's per-path cap never drops them.
        Hop to;
        std::vector<unsigned char> msg;
        {
            WAIT_LOCK(m_mutex, lock);
            const auto now = std::chrono::steady_clock::now();
            std::map<Hop, Outgoing>::iterator best = m_out.end();
            for (std::map<Hop, Outgoing>::iterator it = m_out.begin(); it != m_out.end();) {
                if (it->second.answers.empty()) {
                    // Forget a visitor that has had nothing for a while.
                    if (it->second.next_at + std::chrono::seconds{30} < now) {
                        it = m_out.erase(it);
                        continue;
                    }
                } else if (best == m_out.end() || it->second.next_at < best->second.next_at) {
                    best = it;
                }
                ++it;
            }
            if (!m_requests.empty()) continue;
            if (best == m_out.end()) {
                m_cv.wait_for(lock, std::chrono::seconds{1});
                continue;
            }
            if (best->second.next_at > now) {
                m_cv.wait_until(lock, best->second.next_at);
                continue;
            }
            Outgoing& o = best->second;
            to = best->first;
            msg = std::move(o.answers.front()[o.next_chunk]);
            if (++o.next_chunk == o.answers.front().size()) {
                o.answers.pop_front();
                o.next_chunk = 0;
            }
            o.next_at = std::max(o.next_at, now) +
                        std::chrono::microseconds{(int64_t)(msg.size() * 1000000 / SITE_SEND_RATE)};
            m_stats.bytes += msg.size();
        }
        SendTo(to, msg);
    }
}

// --- publishing --------------------------------------------------------------

namespace {

Mutex g_hosting_mutex;
std::shared_ptr<HostingServer> g_hosting GUARDED_BY(g_hosting_mutex);
roster::KeyBytes g_site_key GUARDED_BY(g_hosting_mutex){};

fs::path SavedSiteFile() { return GetDataDir() / "site_folder"; }

void SetHosting(std::shared_ptr<HostingServer> next, const roster::KeyBytes& key)
{
    if (next) next->Start();
    std::shared_ptr<HostingServer> old;
    {
        LOCK(g_hosting_mutex);
        old = std::move(g_hosting);
        g_hosting = std::move(next);
        g_site_key = key;
    }
    if (old) old->Stop();
}

roster::KeyBytes SiteKey()
{
    LOCK(g_hosting_mutex);
    return g_site_key;
}

} // namespace

std::shared_ptr<HostingServer> GetHosting()
{
    LOCK(g_hosting_mutex);
    return g_hosting;
}

bool PublishSite(const fs::path& dir, const CKey& key, SiteManifest& out, std::string& error)
{
    SiteManifest m;
    const fs::path abs = fs::absolute(dir);
    if (!BuildSiteManifest(abs, (uint32_t)GetTime(), m, error)) return false;
    if (m.TotalSize() > MAX_SITE_SIZE) {
        error = strprintf("the folder holds %u bytes, more than a site's %u", m.TotalSize(), MAX_SITE_SIZE);
        return false;
    }
    if (!SignSiteManifest(m, key)) {
        error = "could not sign the manifest";
        return false;
    }
    const CPubKey pub = key.GetPubKey();
    roster::KeyBytes self{};
    std::copy(pub.begin() + 1, pub.begin() + 33, self.begin());
    SetHosting(std::make_shared<HostingServer>(abs, m), self);

    // Remembered for the next start. Losing it costs only a publishsite.
    fsbridge::ofstream f(SavedSiteFile(), std::ios::trunc);
    if (f) f << abs.string() << "\n";

    UpdateSiteMeeting();
    out = m;
    LogPrintf("hosting: publishing %s, %u files, %u bytes\n", abs.string(), m.files.size(), m.TotalSize());
    return true;
}

void RepublishSavedSite(const CKey& key)
{
    fsbridge::ifstream f(SavedSiteFile());
    if (!f) return;
    std::string line;
    std::getline(f, line);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    if (line.empty()) return;
    SiteManifest m;
    std::string error;
    if (!PublishSite(fs::path(line), key, m, error)) {
        LogPrintf("hosting: not publishing %s again: %s\n", line, error);
    }
}

void UnpublishSite()
{
    SetHosting(nullptr, roster::KeyBytes{});
    fs::remove(SavedSiteFile());
    SetMeetNeed(MEET_FOR_SITE, false);
}

void StopHosting()
{
    SetHosting(nullptr, roster::KeyBytes{});
    SetMeetNeed(MEET_FOR_SITE, false);
}

namespace {

//! This node's live listing, while it publishes a site.
bool OwnListing(roster::Record& own)
{
    if (!GetHosting() || !g_rosterindex) return false;
    const roster::KeyBytes self = SiteKey();
    return !roster::SeenRevoked(self) &&
           roster::LiveAnnouncement(*g_rosterindex, self, g_rosterindex->GetSummary().best_block_height, own);
}

} // namespace

bool SiteIsListed()
{
    roster::Record own;
    return OwnListing(own);
}

bool SiteIsHidden()
{
    // Unlisted, nobody can find it either way, and a meeting point would turn
    // the registration down.
    roster::Record own;
    return OwnListing(own) && roster::IsListedThroughOverlay(own.services, own.endpoints.size());
}

void UpdateSiteMeeting()
{
    SetMeetNeed(MEET_FOR_SITE, SiteIsHidden());
}

// --- answers to this node's own fetches --------------------------------------

namespace {

struct Transfer {
    Hop from;            //!< the only place the answer may come from
    ChunkAssembler parts;
    bool done{false};
    bool failed{false};
};
Mutex g_fetch_mutex;
std::condition_variable g_fetch_cv;
std::map<uint64_t, Transfer> g_fetches GUARDED_BY(g_fetch_mutex);

} // namespace

void HandleSiteApp(const Hop& from, const std::vector<unsigned char>& payload)
{
    if (payload.size() < 1 + 8) return;
    const uint8_t tag = payload[0];
    const uint64_t reqid = ReadLE64(payload.data() + 1);

    // A request this node serves.
    if (tag == SITE_GETMANIFEST || tag == SITE_GETPIECE) {
        if (std::shared_ptr<HostingServer> h = GetHosting()) {
            h->HandleRequest(from, payload);
        } else {
            // No site here: say so, rather than leave the visitor to time out.
            SendTo(from, NotFound(reqid));
        }
        return;
    }

    // An answer to a fetch in progress, and only from where it was asked.
    bool wake = false;
    {
        LOCK(g_fetch_mutex);
        std::map<uint64_t, Transfer>::iterator it = g_fetches.find(reqid);
        if (it == g_fetches.end() || it->second.done || !(it->second.from == from)) return;
        Transfer& t = it->second;
        if (tag == SITE_NOTFOUND) {
            t.failed = t.done = wake = true;
        } else if (payload.size() >= SITE_CHUNK_HEADER) {
            const uint32_t total = ReadLE32(payload.data() + 9);
            const uint32_t offset = ReadLE32(payload.data() + 13);
            if (!t.parts.Add(total, offset, payload.data() + SITE_CHUNK_HEADER, payload.size() - SITE_CHUNK_HEADER)) {
                t.failed = t.done = wake = true;
            } else if (t.parts.Complete()) {
                t.done = wake = true;
            }
        }
    }
    if (wake) g_fetch_cv.notify_all();
}

// --- visiting ----------------------------------------------------------------

namespace {

/** A path to one site, kept for the next file. */
struct SiteVisit {
    roster::KeyBytes key{};
    SiteRoute route;
    Hop to;                     //!< where requests go and answers come from
    std::vector<uint64_t> legs; //!< for ClosePath
    Mutex manifest_mutex;
    bool have_manifest GUARDED_BY(manifest_mutex){false};
    SiteManifest manifest GUARDED_BY(manifest_mutex);
    std::atomic<int64_t> last_used{0};

    ~SiteVisit()
    {
        if (g_overlay && !legs.empty()) g_overlay->ClosePath(legs);
    }
};

Mutex g_visits_mutex;
std::map<roster::KeyBytes, std::shared_ptr<SiteVisit>> g_visits GUARDED_BY(g_visits_mutex);

void PruneVisits(int64_t now) EXCLUSIVE_LOCKS_REQUIRED(g_visits_mutex)
{
    for (auto it = g_visits.begin(); it != g_visits.end();) {
        it = now - it->second->last_used > SITE_VISIT_IDLE ? g_visits.erase(it) : std::next(it);
    }
}

void DropVisit(const std::shared_ptr<SiteVisit>& v)
{
    LOCK(g_visits_mutex);
    std::map<roster::KeyBytes, std::shared_ptr<SiteVisit>>::iterator it = g_visits.find(v->key);
    if (it != g_visits.end() && it->second == v) g_visits.erase(it);
}

bool OpenVisit(const roster::KeyBytes& key, std::shared_ptr<SiteVisit>& out, std::string& error)
{
    const int64_t now = GetTime();
    {
        LOCK(g_visits_mutex);
        PruneVisits(now);
        std::map<roster::KeyBytes, std::shared_ptr<SiteVisit>>::iterator it = g_visits.find(key);
        if (it != g_visits.end()) {
            out = it->second;
            out->last_used = now;
            return true;
        }
    }
    if (!g_overlay) { error = "the overlay is off"; return false; }

    std::shared_ptr<SiteVisit> v = std::make_shared<SiteVisit>();
    v->key = key;
    bool listed_at_address = false;
    for (const roster::RelayInfo& r : roster::FreshRelays()) {
        if (r.key == key) { listed_at_address = true; break; }
    }
    if (listed_at_address) {
        // A public site: through relays to the host, which sees only the last.
        Reached reached;
        if (!ReachRelay(key, SITE_PUBLIC_HOPS, /*prove_last=*/false, reached, error)) return false;
        v->to = Hop::Path(reached.path);
        v->legs = reached.legs;
        v->route.hidden = false;
        v->route.hops = SITE_PUBLIC_HOPS;
    } else {
        if (!g_rosterindex || roster::LiveExpiry(key, g_rosterindex->GetSummary().best_block_height) == 0) {
            error = "the roster does not list that key";
            return false;
        }
        // A hidden site: met at one of its meeting points.
        Meeting m;
        if (!MeetService(key, (int)gArgs.GetArg("-meethops", DEFAULT_MEET_HOPS), m, error)) {
            error = "could not meet the site's host: " + error;
            return false;
        }
        v->to = Hop::Path(m.path);
        v->legs = m.legs;
        v->route.hidden = true;
        v->route.hops = m.hops;
        v->route.point = m.point;
    }
    v->last_used = now;
    LOCK(g_visits_mutex);
    std::map<roster::KeyBytes, std::shared_ptr<SiteVisit>>::iterator it = g_visits.find(key);
    if (it != g_visits.end()) {
        out = it->second; // another fetch opened one meanwhile; ours closes as it goes
    } else {
        g_visits[key] = v;
        out = v;
    }
    return true;
}

uint64_t NewRequest(const Hop& to)
{
    LOCK(g_fetch_mutex);
    uint64_t id;
    do id = GetRand(std::numeric_limits<uint64_t>::max() - 1) + 1; while (g_fetches.count(id));
    g_fetches[id].from = to;
    return id;
}

void ForgetRequest(uint64_t id)
{
    LOCK(g_fetch_mutex);
    g_fetches.erase(id);
}

std::vector<unsigned char> ManifestRequest(uint64_t id)
{
    std::vector<unsigned char> req{SITE_GETMANIFEST};
    PutU64(req, id);
    return req;
}

std::vector<unsigned char> PieceRequest(uint64_t id, uint32_t file, uint32_t piece)
{
    std::vector<unsigned char> req{SITE_GETPIECE};
    PutU64(req, id);
    PutU32(req, file);
    PutU32(req, piece);
    return req;
}

/** The manifest over the visit's path, asked up to three times. `definitive` when the host said no. */
bool AskManifest(SiteVisit& v, std::vector<unsigned char>& raw, std::string& error, bool& definitive)
{
    definitive = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const uint64_t id = NewRequest(v.to);
        if (!SendTo(v.to, ManifestRequest(id))) {
            ForgetRequest(id);
            error = "could not send to the site";
            return false;
        }
        WAIT_LOCK(g_fetch_mutex, lock);
        // In short waits, so a node shutting down is not held up by a site.
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds{20};
        while (!g_fetches[id].done && !ShutdownRequested() && std::chrono::steady_clock::now() < until) {
            g_fetch_cv.wait_for(lock, std::chrono::seconds{1});
        }
        const Transfer t = g_fetches[id];
        g_fetches.erase(id);
        if (t.done && !t.failed) {
            raw = t.parts.Bytes();
            return true;
        }
        if (t.done) {
            error = "the host has no site under that key";
            definitive = true;
            return false;
        }
        if (ShutdownRequested()) {
            error = "the node is shutting down";
            definitive = true;
            return false;
        }
    }
    error = "the host sent no manifest";
    return false;
}

bool GetManifest(SiteVisit& v, SiteManifest& out, std::string& error, bool& definitive)
{
    definitive = false;
    LOCK(v.manifest_mutex);
    if (!v.have_manifest) {
        std::vector<unsigned char> raw;
        if (!AskManifest(v, raw, error, definitive)) return false;
        SiteManifest m;
        // A manifest that does not parse or check out came from the host:
        // another path brings the same.
        definitive = true;
        if (!m.Deserialize(raw)) { error = "the manifest did not parse"; return false; }
        if (m.TotalSize() > MAX_SITE_SIZE) { error = "the site is larger than a site may be"; return false; }
        if (!VerifySiteManifest(m, v.key)) { error = "the manifest is not signed by that site key"; return false; }
        definitive = false;
        v.manifest = std::move(m);
        v.have_manifest = true;
    }
    out = v.manifest;
    return true;
}

void ForgetManifest(SiteVisit& v)
{
    LOCK(v.manifest_mutex);
    v.have_manifest = false;
}

bool WrongAnswer(const std::string& error)
{
    return error.find("did not match") != std::string::npos || error.find("does not have") != std::string::npos;
}

/**
 * Every piece of one file, several asked for at once: the window starts at
 * SITE_WINDOW_START, grows by one for each piece that arrives whole, and
 * halves when one is lost (design note §11·6). Each piece is checked against
 * the manifest the moment it is complete.
 */
bool FetchPieces(SiteVisit& v, const SiteFile& f, uint32_t file_index, std::vector<unsigned char>& out,
                 std::string& error)
{
    struct Asked {
        uint32_t piece;
        std::chrono::steady_clock::time_point deadline;
    };
    const uint32_t count = (uint32_t)f.pieces.size();
    std::vector<std::vector<unsigned char>> got(count);
    std::vector<int> tries(count, 0);
    std::deque<uint32_t> waiting;
    for (uint32_t p = 0; p < count; ++p) waiting.push_back(p);
    std::map<uint64_t, Asked> asked;
    size_t window = SITE_WINDOW_START;
    uint32_t have = 0;
    bool any = false; // whether anything came back on this path at all

    bool ok = true;
    while (ok && have < count) {
        if (ShutdownRequested()) {
            error = "the node is shutting down";
            ok = false;
            break;
        }
        // Keep the window full.
        while (asked.size() < window && !waiting.empty()) {
            const uint32_t p = waiting.front();
            waiting.pop_front();
            if (++tries[p] > 5) {
                error = strprintf("the host did not send piece %u", p);
                ok = false;
                break;
            }
            const uint64_t id = NewRequest(v.to);
            // A piece at the back of a full window waits behind the others at
            // the host's pace, so its time to arrive grows with the window.
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{8} +
                                  std::chrono::milliseconds{(int64_t)(asked.size() * SITE_PIECE_SIZE * 1000 / SITE_SEND_RATE)};
            asked[id] = Asked{p, deadline};
            if (!SendTo(v.to, PieceRequest(id, file_index, p))) {
                error = "could not send to the site";
                ok = false;
                break;
            }
        }
        if (!ok) break;

        // Wait for an answer or the first deadline.
        std::vector<std::pair<uint64_t, Transfer>> finished;
        {
            WAIT_LOCK(g_fetch_mutex, lock);
            // A second at most, so a node shutting down is not held up by a site.
            auto first = std::chrono::steady_clock::now() + std::chrono::seconds{1};
            for (const auto& a : asked) first = std::min(first, a.second.deadline);
            g_fetch_cv.wait_until(lock, first, [&]() EXCLUSIVE_LOCKS_REQUIRED(g_fetch_mutex) {
                for (const auto& a : asked) if (g_fetches[a.first].done) return true;
                return false;
            });
            for (const auto& a : asked) {
                if (g_fetches[a.first].done) {
                    finished.emplace_back(a.first, g_fetches[a.first]);
                    g_fetches.erase(a.first);
                }
            }
        }
        for (const auto& fin : finished) {
            const uint32_t p = asked[fin.first].piece;
            asked.erase(fin.first);
            if (fin.second.failed) {
                error = strprintf("the host does not have piece %u of %s", p, f.path);
                ok = false;
                break;
            }
            const std::vector<unsigned char>& bytes = fin.second.parts.Bytes();
            uint256 h;
            CSHA256().Write(bytes.data(), bytes.size()).Finalize(h.begin());
            if (h != f.pieces[p]) {
                // A relay or the host changed it. Caught here, at the first
                // piece touched, and not asked for again from the same place.
                error = strprintf("piece %u did not match its hash", p);
                ok = false;
                break;
            }
            got[p] = bytes;
            ++have;
            any = true;
            window = std::min(window + 1, SITE_WINDOW_MAX);
        }
        // Lost on the way: ask again, with a smaller window.
        const auto now = std::chrono::steady_clock::now();
        bool lost = false;
        for (auto it = asked.begin(); it != asked.end();) {
            if (it->second.deadline <= now) {
                waiting.push_front(it->second.piece);
                ForgetRequest(it->first);
                it = asked.erase(it);
                lost = true;
            } else {
                ++it;
            }
        }
        if (lost) window = std::max<size_t>(1, window / 2);
        // Nothing back twice over: the path is gone (a relay restarted, the
        // host left its meeting point), not slow. A new path will do better.
        if (lost && !any && !waiting.empty() && tries[waiting.front()] >= 2) {
            error = "the site stopped answering";
            ok = false;
        }
    }
    for (const auto& a : asked) ForgetRequest(a.first);
    if (!ok) return false;

    out.clear();
    out.reserve(f.size);
    for (const std::vector<unsigned char>& piece : got) out.insert(out.end(), piece.begin(), piece.end());
    if (out.size() != f.size) { error = "the file came back the wrong length"; return false; }
    return true;
}

/** A file of this node's own site, straight from disk. */
bool ReadOwnFile(const HostingServer& h, const std::string& path, std::vector<unsigned char>& out, std::string& error)
{
    const SiteFile* f = h.Manifest().Find(path);
    if (!f) { error = "the site has no file at that path"; return false; }
    fsbridge::ifstream in(h.Dir() / fs::path(f->path), std::ios::binary);
    if (!in) { error = "the file is gone from the published folder"; return false; }
    out.assign((size_t)f->size, 0);
    in.read(reinterpret_cast<char*>(out.data()), out.size());
    if ((uint64_t)in.gcount() != f->size) { error = "the file changed since it was published"; return false; }
    return true;
}

} // namespace

bool OpenSitePath(const roster::KeyBytes& site_key, Hop& to, std::shared_ptr<void>& hold, SiteRoute* route,
                  std::string& error)
{
    std::shared_ptr<SiteVisit> v;
    if (!OpenVisit(site_key, v, error)) return false;
    v->last_used = GetTime();
    to = v->to;
    hold = v;
    if (route) *route = v->route;
    return true;
}

void DropSitePath(const roster::KeyBytes& site_key, const Hop& to)
{
    LOCK(g_visits_mutex);
    std::map<roster::KeyBytes, std::shared_ptr<SiteVisit>>::iterator it = g_visits.find(site_key);
    if (it != g_visits.end() && it->second->to == to) g_visits.erase(it);
}

bool FetchSiteManifest(const roster::KeyBytes& site_key, SiteManifest& out, std::string& error, SiteRoute* route)
{
    if (std::shared_ptr<HostingServer> h = GetHosting()) {
        if (SiteKey() == site_key) {
            out = h->Manifest();
            if (route) *route = SiteRoute();
            return true;
        }
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::shared_ptr<SiteVisit> v;
        if (!OpenVisit(site_key, v, error)) return false;
        if (route) *route = v->route;
        bool definitive = false;
        if (GetManifest(*v, out, error, definitive)) return true;
        if (definitive) return false;
        // The path may have died under us (a relay restarted, the host moved
        // to new meeting points): once more on a new one.
        DropVisit(v);
    }
    return false;
}

bool FetchSiteFile(const roster::KeyBytes& site_key, const std::string& path, std::vector<unsigned char>& out,
                   std::string& error, SiteRoute* route)
{
    out.clear();
    if (std::shared_ptr<HostingServer> h = GetHosting()) {
        if (SiteKey() == site_key) {
            if (route) *route = SiteRoute();
            return ReadOwnFile(*h, path, out, error);
        }
    }
    bool reread = false;     // the manifest was read again once already
    uint32_t stale_version = 0;
    std::string wrong;
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::shared_ptr<SiteVisit> v;
        if (!OpenVisit(site_key, v, error)) return false;
        if (route) *route = v->route;
        SiteManifest m;
        bool definitive = false;
        if (!GetManifest(*v, m, error, definitive)) {
            if (definitive) return false;
            DropVisit(v);
            continue;
        }
        if (reread && m.version == stale_version) {
            // Read again and unchanged: the answer was wrong, not out of date.
            error = wrong;
            return false;
        }
        uint32_t index = (uint32_t)m.files.size();
        for (uint32_t i = 0; i < m.files.size(); ++i) {
            if (m.files[i].path == path) { index = i; break; }
        }
        if (index == m.files.size()) { error = "the site has no file at that path"; return false; }
        if (FetchPieces(*v, m.files[index], index, out, error)) {
            v->last_used = GetTime();
            return true;
        }
        if (WrongAnswer(error)) {
            // The host may have published again since this visit read its
            // manifest; a piece of the new site cannot match the old one. Read
            // the manifest once more - a wrong answer under the same version
            // is a wrong answer.
            if (reread) return false;
            reread = true;
            stale_version = m.version;
            wrong = error;
            ForgetManifest(*v);
            continue;
        }
        DropVisit(v);
    }
    return false;
}

void CloseSiteVisits()
{
    LOCK(g_visits_mutex);
    g_visits.clear();
}

} // namespace overlay
