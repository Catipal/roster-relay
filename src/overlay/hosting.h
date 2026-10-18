// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_HOSTING_H
#define BITCOIN_OVERLAY_HOSTING_H

#include <fs.h>
#include <overlay/path.h>
#include <roster/record.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
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
 * This slice serves and fetches a site over a direct overlay session, for a
 * host listed with an endpoint (a public site). A host listed with no address,
 * reached at its meeting points (overlay/meeting.h), and the viewer and the
 * browser gateway that render a fetched site, are the pieces still to come;
 * the manifest and the piece-by-piece verification here do not change for them.
 */
namespace overlay {

//! A file is cut into pieces of this size; the last is short. The manifest
//! carries one hash per piece, and each is checked as it arrives.
static constexpr uint32_t SITE_PIECE_SIZE = 16384;
//! Largest site published or fetched, version 1.
static constexpr uint64_t MAX_SITE_SIZE = 64ull * 1024 * 1024;
static constexpr size_t MAX_SITE_FILES = 4096;
static constexpr size_t MAX_SITE_PATH = 512;

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
};

/** Build the (unsigned) manifest for the files under `dir`; false with `error` on trouble. */
bool BuildSiteManifest(const fs::path& dir, uint32_t version, SiteManifest& out, std::string& error);
/** Sign a built manifest with the site's key, filling its signature. */
bool SignSiteManifest(SiteManifest& m, const CKey& key);
/** Verify a manifest's signature against the x-only site key. */
bool VerifySiteManifest(const SiteManifest& m, const roster::KeyBytes& site_key);

/**
 * The site this node publishes (at most one in this slice), and the request
 * handler that serves it to adjacent overlay peers.
 */
class HostingServer
{
public:
    HostingServer(const fs::path& dir, const SiteManifest& manifest);

    /** Serve one request from an adjacent peer, replying on the same session. */
    void HandleApp(const CService& from, const std::vector<unsigned char>& payload);

    const SiteManifest& Manifest() const { return m_manifest; }

private:
    bool ReadPiece(size_t file, uint32_t piece, std::vector<unsigned char>& out) const;

    const fs::path m_dir;
    const SiteManifest m_manifest;
};

extern std::unique_ptr<HostingServer> g_hosting;
/** Route a hosting message to the server, or to a fetch in progress. */
void HandleSiteApp(const CService& from, const std::vector<unsigned char>& payload);

/**
 * Fetch `path` from the site published under `site_key`, over a direct overlay
 * session with the host listed at `addr`. Checks the manifest's signature and
 * every piece's hash. False with `error` otherwise.
 */
bool FetchSiteFile(const roster::KeyBytes& site_key, const CService& addr, const std::string& path,
                   std::vector<unsigned char>& out, std::string& error);

} // namespace overlay

#endif // BITCOIN_OVERLAY_HOSTING_H
