// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_HOSTING_H
#define BITCOIN_OVERLAY_HOSTING_H

#include <fs.h>
#include <overlay/path.h>
#include <overlay/relay.h>
#include <roster/record.h>
#include <sync.h>
#include <threadinterrupt.h>
#include <uint256.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

class CKey;

/**
 * Hosting sites over the overlay (design note §11·6).
 *
 * A site is a folder published under a roster key. Its manifest lists every
 * file, its length, and the hash of each 16 KiB piece, and is signed by the
 * site's key. A visitor fetches the manifest, checks the signature against the
 * key it asked for, then fetches the pieces it needs and checks each against
 * its hash as it lands - so a relay or a host that tampers is caught by the
 * first piece it touches, and the chain's non-equivocation carries all the way
 * to the bytes on the page.
 *
 * Nobody learns where the other is. A visitor reaches a host listed with an
 * address (a public site) through SITE_PUBLIC_HOPS relays, as mail reaches a
 * mailbox, so the host never sees the visitor; a host listed with none (a
 * hidden site) is met at its meeting points (overlay/meeting.h), which it keeps
 * registered at while it publishes, so neither sees the other.
 */
namespace overlay {

//! A file is cut into pieces of this size; the last is short. The manifest
//! carries one hash per piece, and each is checked as it arrives.
static constexpr uint32_t SITE_PIECE_SIZE = 16384;
//! Largest site published or fetched, version 1.
static constexpr uint64_t MAX_SITE_SIZE = 64ull * 1024 * 1024;
static constexpr size_t MAX_SITE_FILES = 4096;
static constexpr size_t MAX_SITE_PATH = 512;

//! Header of every chunk: tag, request id, total length, offset.
static constexpr size_t SITE_CHUNK_HEADER = 1 + 8 + 4 + 4;
//! Data bytes per chunk over a path: one chunk, one datagram.
static constexpr size_t SITE_CHUNK_PATH = MAX_PATH_APP_PAYLOAD - SITE_CHUNK_HEADER;
//! Data bytes per chunk to an adjacent peer, under the padded datagram.
static constexpr size_t SITE_CHUNK_DIRECT = 900;
//! How fast a host sends down one path: under the relays' per-path cap
//! (-relaypathrate, 64 KiB/s by default), so what it sends is not dropped.
static constexpr uint64_t SITE_SEND_RATE = 48 * 1024;
//! Relays between a visitor and a public host, as mail reaches a mailbox.
static constexpr int SITE_PUBLIC_HOPS = 3;
//! Pieces a visitor keeps asked for at once: it starts here, adds one for
//! each piece that arrives whole, and halves on a loss (design note §11·6).
static constexpr size_t SITE_WINDOW_START = 2;
static constexpr size_t SITE_WINDOW_MAX = 32;
//! A visit's path is kept this long after its last use, so a page and what it
//! shows travel on one path.
static constexpr int64_t SITE_VISIT_IDLE = 120;

/** Overlay application-data tags for hosting. */
static constexpr uint8_t SITE_GETMANIFEST = 0x30;
static constexpr uint8_t SITE_MANIFEST = 0x31; //!< chunked: the signed manifest
static constexpr uint8_t SITE_GETPIECE = 0x32;
static constexpr uint8_t SITE_PIECE = 0x33;    //!< chunked: one file piece
static constexpr uint8_t SITE_NOTFOUND = 0x34; //!< no such site, file or piece here

bool IsSitePayload(const std::vector<unsigned char>& payload);

/** One file in a site: where it sits, how long it is, and a hash per piece. */
struct SiteFile {
    std::string path;
    uint64_t size{0};
    std::vector<uint256> pieces; //!< SHA256 of each SITE_PIECE_SIZE slice
};

/**
 * A site's manifest: its files and a signature by the site key over all of it.
 * The signature is BIP340 over TaggedHash("BPS/site/v1", body), where body is
 * the files serialized; a verifier checks it against the key it looked the
 * site up by.
 */
struct SiteManifest {
    uint32_t version{0};
    std::vector<SiteFile> files;
    std::vector<unsigned char> sig; //!< 64 bytes

    bool Serialize(std::vector<unsigned char>& out) const;      //!< body + signature
    bool Deserialize(const std::vector<unsigned char>& in);
    //! The file by its path, or nullptr.
    const SiteFile* Find(const std::string& path) const;
    //! Bytes signed: everything but the signature.
    std::vector<unsigned char> Body() const;
    uint64_t TotalSize() const;
};

/** Build the (unsigned) manifest for the files under `dir`; false with `error` on trouble. */
bool BuildSiteManifest(const fs::path& dir, uint32_t version, SiteManifest& out, std::string& error);
/** Sign a built manifest with the site's key, filling its signature. */
bool SignSiteManifest(SiteManifest& m, const CKey& key);
/** Verify a manifest's signature against the x-only site key. */
bool VerifySiteManifest(const SiteManifest& m, const roster::KeyBytes& site_key);

/**
 * Puts one answer back together from its chunks, which may arrive in any
 * order, twice, or not at all. Complete once every byte has come.
 */
class ChunkAssembler
{
public:
    /** Take one chunk; false if it contradicts what came before. */
    bool Add(uint32_t total, uint32_t offset, const unsigned char* data, size_t n);
    bool Complete() const { return m_started && m_have == m_total; }
    const std::vector<unsigned char>& Bytes() const { return m_buf; }

private:
    bool m_started{false};
    uint32_t m_total{0};
    uint64_t m_have{0};
    std::vector<unsigned char> m_buf;
    std::map<uint32_t, uint32_t> m_got; //!< offset -> length
};

/** Cut `payload` into chunk messages for `tag` and `reqid`, `chunk` data bytes each. */
std::vector<std::vector<unsigned char>> MakeChunks(uint8_t tag, uint64_t reqid,
                                                   const std::vector<unsigned char>& payload, size_t chunk);

/**
 * The site this node publishes, and the thread that answers visitors: every
 * answer goes back the way its request came, paced under the relays' cap.
 */
class HostingServer
{
public:
    HostingServer(const fs::path& dir, const SiteManifest& manifest);
    ~HostingServer();

    void Start();
    void Stop();

    /** Queue the answer to one request; never blocks the receive thread. */
    void HandleRequest(const Hop& from, const std::vector<unsigned char>& payload);

    const SiteManifest& Manifest() const { return m_manifest; }
    const fs::path& Dir() const { return m_dir; }

    struct Stats {
        uint64_t manifests{0}; //!< manifests sent
        uint64_t pieces{0};    //!< pieces sent
        uint64_t bytes{0};     //!< bytes sent, chunk headers included
        uint64_t refused{0};   //!< requests dropped while too much was queued
        size_t queued{0};      //!< answers waiting to go
    };
    Stats GetStats() const;

    //! Answers waiting for one visitor, and for all, before more are refused.
    static constexpr size_t MAX_QUEUED_PER_HOP = 64;
    static constexpr size_t MAX_QUEUED = 2048;

private:
    bool ReadPiece(size_t file, uint32_t piece, std::vector<unsigned char>& out) const;
    void ThreadSend();

    /** A request waiting to be answered: read from disk on the hosting thread. */
    struct Request {
        Hop from;
        uint8_t tag{0};
        uint64_t reqid{0};
        uint32_t file{0};
        uint32_t piece{0};
    };
    /** Answers going to one visitor, paced. */
    struct Outgoing {
        std::deque<std::vector<std::vector<unsigned char>>> answers; //!< each a list of chunks
        size_t next_chunk{0};
        std::chrono::steady_clock::time_point next_at{};
    };

    const fs::path m_dir;
    const SiteManifest m_manifest;
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<Request> m_requests GUARDED_BY(m_mutex);
    std::map<Hop, Outgoing> m_out GUARDED_BY(m_mutex);
    Stats m_stats GUARDED_BY(m_mutex);
    std::thread m_thread;
    CThreadInterrupt m_interrupt;
};

/** The site this node publishes, or null. Safe from any thread. */
std::shared_ptr<HostingServer> GetHosting();

/**
 * Publish the folder `dir` under `key`, this node's roster key: build and
 * sign the manifest, start serving it, and remember the folder so it is
 * published again at the next start. Replaces a site already published.
 */
bool PublishSite(const fs::path& dir, const CKey& key, SiteManifest& out, std::string& error);
/** Publish again the folder published last, if there is one. At startup. */
void RepublishSavedSite(const CKey& key);
/** Stop publishing, and forget the folder. */
void UnpublishSite();
/** Stop serving without forgetting the folder. At shutdown. */
void StopHosting();

/**
 * Whether this node, publishing a site, must be met at its meeting points:
 * its live listing has no address and it is not a relay. Rechecked as the
 * roster moves; registers or stops through SetMeetNeed (overlay/meeting.h).
 */
bool SiteIsHidden();
void UpdateSiteMeeting();
/** Whether this node has a live listing at all; without one, nobody can find its site. */
bool SiteIsListed();

/** Route a hosting message: a request to the server, an answer to a fetch in progress. */
void HandleSiteApp(const Hop& from, const std::vector<unsigned char>& payload);

/** How a visitor reached a site. */
struct SiteRoute {
    bool hidden{false};    //!< met at a meeting point, rather than reached at its address
    int hops{0};           //!< relays on this side
    roster::KeyBytes point{}; //!< the meeting point, when hidden
};

/**
 * Fetch `path` from the site published under `site_key`: over a path to its
 * host when the roster lists an address for it, at its meeting points when
 * not. Checks the manifest's signature and every piece's hash. The path is
 * kept a while for the next file of the same site. False with `error`.
 */
bool FetchSiteFile(const roster::KeyBytes& site_key, const std::string& path,
                   std::vector<unsigned char>& out, std::string& error, SiteRoute* route = nullptr);
/** The site's manifest alone, verified against its key. */
bool FetchSiteManifest(const roster::KeyBytes& site_key, SiteManifest& out, std::string& error,
                       SiteRoute* route = nullptr);
/** Close every visit's path, at shutdown. */
void CloseSiteVisits();

/**
 * The path to the host of `site_key` that page fetches use, for a service's
 * stream (overlay/service.h). The path stays open while `hold` is kept, even
 * after the visit has been idle long enough to be dropped.
 */
bool OpenSitePath(const roster::KeyBytes& site_key, Hop& to, std::shared_ptr<void>& hold, SiteRoute* route,
                  std::string& error);
/** Forget that path, after it failed, so the next visit builds another. */
void DropSitePath(const roster::KeyBytes& site_key, const Hop& to);

} // namespace overlay

#endif // BITCOIN_OVERLAY_HOSTING_H
