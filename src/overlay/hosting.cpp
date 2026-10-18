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
#include <roster/keystore.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <condition_variable>
#include <fstream>
#include <limits>

namespace overlay {

std::unique_ptr<HostingServer> g_hosting;

namespace {

//! Data bytes per chunk, under the padded datagram so each is one.
constexpr size_t CHUNK_DATA = 900;
constexpr int64_t FETCH_TRANSFER_TTL = 60;

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

// --- a client-side fetch in progress ----------------------------------------

struct Transfer {
    bool done{false};
    bool failed{false};
    uint32_t total{0};
    std::vector<unsigned char> buf;
    int64_t at{0};
};
Mutex g_fetch_mutex;
std::condition_variable g_fetch_cv;
std::map<uint64_t, Transfer> g_fetches GUARDED_BY(g_fetch_mutex);

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

// --- serving -----------------------------------------------------------------

HostingServer::HostingServer(const fs::path& dir, const SiteManifest& manifest)
    : m_dir(dir), m_manifest(manifest) {}

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

namespace {

void SendChunked(const CService& to, uint8_t tag, uint64_t reqid, const std::vector<unsigned char>& payload)
{
    if (!g_overlay) return;
    const uint32_t total = (uint32_t)payload.size();
    for (uint32_t offset = 0; offset < total || offset == 0; offset += CHUNK_DATA) {
        const uint32_t n = std::min<uint32_t>(CHUNK_DATA, total - offset);
        std::vector<unsigned char> msg{tag};
        PutU64(msg, reqid);
        PutU32(msg, total);
        PutU32(msg, offset);
        msg.insert(msg.end(), payload.begin() + offset, payload.begin() + offset + n);
        g_overlay->SendApp(to, msg);
        if (total <= CHUNK_DATA) break;
        UninterruptibleSleep(std::chrono::milliseconds{1});
    }
}

} // namespace

void HostingServer::HandleApp(const CService& from, const std::vector<unsigned char>& payload)
{
    if (payload.size() < 1 + 8) return;
    const uint64_t reqid = ReadLE64(payload.data() + 1);
    if (payload[0] == SITE_GETMANIFEST) {
        std::vector<unsigned char> raw;
        if (!m_manifest.Serialize(raw)) return;
        SendChunked(from, SITE_MANIFEST, reqid, raw);
        return;
    }
    if (payload[0] == SITE_GETPIECE) {
        if (payload.size() != 1 + 8 + 4 + 4) return;
        const uint32_t file = ReadLE32(payload.data() + 9);
        const uint32_t piece = ReadLE32(payload.data() + 13);
        std::vector<unsigned char> bytes;
        if (!ReadPiece(file, piece, bytes)) {
            std::vector<unsigned char> msg{SITE_NOTFOUND};
            PutU64(msg, reqid);
            if (g_overlay) g_overlay->SendApp(from, msg);
            return;
        }
        SendChunked(from, SITE_PIECE, reqid, bytes);
        return;
    }
}

void HandleSiteApp(const CService& from, const std::vector<unsigned char>& payload)
{
    if (payload.size() < 1 + 8) return;
    const uint8_t tag = payload[0];
    const uint64_t reqid = ReadLE64(payload.data() + 1);

    // A request this node serves.
    if (tag == SITE_GETMANIFEST || tag == SITE_GETPIECE) {
        if (g_hosting) g_hosting->HandleApp(from, payload);
        return;
    }

    // A response to a fetch in progress.
    const int64_t now = GetTime();
    std::vector<unsigned char> complete;
    bool failed = false;
    {
        LOCK(g_fetch_mutex);
        std::map<uint64_t, Transfer>::iterator it = g_fetches.find(reqid);
        if (it == g_fetches.end()) return; // not waiting for this
        Transfer& t = it->second;
        if (tag == SITE_NOTFOUND) {
            t.failed = t.done = true;
            failed = true;
        } else if (payload.size() >= 1 + 8 + 4 + 4) {
            const uint32_t total = ReadLE32(payload.data() + 9);
            const uint32_t offset = ReadLE32(payload.data() + 13);
            const size_t n = payload.size() - 17;
            if (total <= MAX_SITE_SIZE && (uint64_t)offset + n <= total) {
                if (t.buf.size() != total) { t.buf.assign(total, 0); t.total = total; }
                std::copy(payload.begin() + 17, payload.end(), t.buf.begin() + offset);
                t.at = now;
                if (offset + n == total) { complete = t.buf; t.done = true; }
            }
        }
    }
    if (!complete.empty() || failed) g_fetch_cv.notify_all();
}

// --- fetching ----------------------------------------------------------------

namespace {

//! Send one request and wait for the reassembled answer. False on timeout or
//! a NOTFOUND. `req` already carries the tag and an 8-byte reqid at offset 1.
bool AskSite(const CService& addr, uint64_t reqid, const std::vector<unsigned char>& req,
             std::vector<unsigned char>& answer, std::chrono::seconds timeout)
{
    {
        LOCK(g_fetch_mutex);
        g_fetches[reqid] = Transfer();
        g_fetches[reqid].at = GetTime();
    }
    bool ok = false;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (int attempt = 0; attempt < 3 && !ok; ++attempt) {
        if (!g_overlay || !g_overlay->SendApp(addr, req)) break;
        WAIT_LOCK(g_fetch_mutex, lock);
        const auto until = std::min(deadline, std::chrono::steady_clock::now() + timeout / 3);
        g_fetch_cv.wait_until(lock, until, [&]() EXCLUSIVE_LOCKS_REQUIRED(g_fetch_mutex) {
            return g_fetches[reqid].done;
        });
        if (g_fetches[reqid].done) {
            ok = !g_fetches[reqid].failed;
            if (ok) answer = g_fetches[reqid].buf;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) break;
    }
    LOCK(g_fetch_mutex);
    g_fetches.erase(reqid);
    return ok;
}

} // namespace

bool FetchSiteFile(const roster::KeyBytes& site_key, const CService& addr, const std::string& path,
                   std::vector<unsigned char>& out, std::string& error)
{
    out.clear();
    if (!g_overlay) { error = "the overlay is off"; return false; }
    CPubKey pub;
    if (!roster::StakerPubKeyFromRoster(site_key, pub)) { error = "that is not a valid site key"; return false; }

    // A fresh session with the host, as the listing client does.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{15};
    while (!g_overlay->HasSession(addr) && std::chrono::steady_clock::now() < deadline) {
        if (!g_overlay->Connect(addr, pub)) { error = "could not reach the host"; return false; }
        const auto retry = std::min(deadline, std::chrono::steady_clock::now() + std::chrono::seconds{3});
        while (g_overlay->HasPendingHandshake(addr) && std::chrono::steady_clock::now() < retry) {
            UninterruptibleSleep(std::chrono::milliseconds{50});
        }
    }
    if (!g_overlay->HasSession(addr)) { error = "the host did not answer"; return false; }

    const uint64_t rm = GetRand(std::numeric_limits<uint64_t>::max());
    std::vector<unsigned char> req{SITE_GETMANIFEST};
    { unsigned char b[8]; WriteLE64(b, rm); req.insert(req.end(), b, b + 8); }
    std::vector<unsigned char> raw;
    if (!AskSite(addr, rm, req, raw, std::chrono::seconds{30})) { error = "the host sent no manifest"; return false; }

    SiteManifest m;
    if (!m.Deserialize(raw)) { error = "the manifest did not parse"; return false; }
    if (!VerifySiteManifest(m, site_key)) { error = "the manifest is not signed by that site key"; return false; }

    size_t index = m.files.size();
    for (size_t i = 0; i < m.files.size(); ++i) if (m.files[i].path == path) { index = i; break; }
    if (index == m.files.size()) { error = "the site has no file at that path"; return false; }
    const SiteFile& f = m.files[index];

    for (uint32_t p = 0; p < f.pieces.size(); ++p) {
        const uint64_t rp = GetRand(std::numeric_limits<uint64_t>::max());
        std::vector<unsigned char> preq{SITE_GETPIECE};
        { unsigned char b[8]; WriteLE64(b, rp); preq.insert(preq.end(), b, b + 8); }
        PutU32(preq, (uint32_t)index);
        PutU32(preq, p);
        std::vector<unsigned char> piece;
        if (!AskSite(addr, rp, preq, piece, std::chrono::seconds{30})) {
            error = strprintf("the host did not send piece %u", p);
            return false;
        }
        // Checked against the manifest's hash the moment it lands: a host or a
        // relay that changed a byte is caught here.
        uint256 h;
        CSHA256().Write(piece.data(), piece.size()).Finalize(h.begin());
        if (h != f.pieces[p]) { error = strprintf("piece %u did not match its hash", p); return false; }
        out.insert(out.end(), piece.begin(), piece.end());
    }
    if (out.size() != f.size) { error = "the file came back the wrong length"; return false; }
    return true;
}

} // namespace overlay
