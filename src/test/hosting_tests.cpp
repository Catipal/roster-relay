// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/hosting.h>
#include <overlay/siteproxy.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <key.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <util/system.h>

#include <algorithm>
#include <set>
#include <fstream>

#include <boost/test/unit_test.hpp>

namespace {

std::vector<unsigned char> Bytes(size_t n, unsigned char seed)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = (unsigned char)(i * 31 + seed);
    return v;
}

//! Feed one chunk message, as HandleSiteApp would.
bool Feed(overlay::ChunkAssembler& a, const std::vector<unsigned char>& msg)
{
    const uint32_t total = ReadLE32(msg.data() + 9);
    const uint32_t offset = ReadLE32(msg.data() + 13);
    return a.Add(total, offset, msg.data() + overlay::SITE_CHUNK_HEADER, msg.size() - overlay::SITE_CHUNK_HEADER);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(hosting_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(chunks_fit_a_path_datagram)
{
    // One chunk, one datagram: a chunk over a path must fit what a path carries.
    const std::vector<unsigned char> piece = Bytes(overlay::SITE_PIECE_SIZE, 1);
    const auto chunks = overlay::MakeChunks(overlay::SITE_PIECE, 7, piece, overlay::SITE_CHUNK_PATH);
    BOOST_CHECK_EQUAL(chunks.size(), (piece.size() + overlay::SITE_CHUNK_PATH - 1) / overlay::SITE_CHUNK_PATH);
    for (const auto& c : chunks) {
        BOOST_CHECK(c.size() <= overlay::MAX_PATH_APP_PAYLOAD);
        BOOST_CHECK_EQUAL(c[0], overlay::SITE_PIECE);
        BOOST_CHECK_EQUAL(ReadLE64(c.data() + 1), 7U);
    }
    // An empty answer is one chunk with no data.
    const auto none = overlay::MakeChunks(overlay::SITE_PIECE, 8, {}, overlay::SITE_CHUNK_PATH);
    BOOST_REQUIRE_EQUAL(none.size(), 1U);
    BOOST_CHECK_EQUAL(none[0].size(), overlay::SITE_CHUNK_HEADER);
}

BOOST_AUTO_TEST_CASE(chunks_come_back_in_any_order)
{
    const std::vector<unsigned char> piece = Bytes(overlay::SITE_PIECE_SIZE - 100, 2);
    auto chunks = overlay::MakeChunks(overlay::SITE_PIECE, 1, piece, overlay::SITE_CHUNK_PATH);

    // Shuffled, with every chunk twice: complete only once all have come, and
    // never early because the last chunk happened to arrive first.
    std::vector<std::vector<unsigned char>> order = chunks;
    order.insert(order.end(), chunks.begin(), chunks.end());
    Shuffle(order.begin(), order.end(), FastRandomContext());
    std::swap(*std::find(order.begin(), order.end(), chunks.back()), order.front());

    overlay::ChunkAssembler a;
    size_t distinct = 0;
    std::set<std::vector<unsigned char>> seen;
    for (const auto& c : order) {
        BOOST_CHECK(Feed(a, c));
        if (seen.insert(c).second) ++distinct;
        BOOST_CHECK_EQUAL(a.Complete(), distinct == chunks.size());
    }
    BOOST_CHECK(a.Complete());
    BOOST_CHECK(a.Bytes() == piece);
}

BOOST_AUTO_TEST_CASE(chunks_that_contradict_are_refused)
{
    const std::vector<unsigned char> piece = Bytes(2000, 3);
    const auto chunks = overlay::MakeChunks(overlay::SITE_PIECE, 1, piece, 600);

    {
        // The same offset again with other bytes.
        overlay::ChunkAssembler a;
        BOOST_CHECK(Feed(a, chunks[0]));
        std::vector<unsigned char> changed = chunks[0];
        changed.back() ^= 1;
        BOOST_CHECK(!Feed(a, changed));
    }
    {
        // Another total partway through.
        overlay::ChunkAssembler a;
        BOOST_CHECK(Feed(a, chunks[0]));
        BOOST_CHECK(!a.Add(2001, 600, piece.data() + 600, 600));
    }
    {
        // Overlapping a chunk already held, or running past the end.
        overlay::ChunkAssembler a;
        BOOST_CHECK(Feed(a, chunks[1]));
        BOOST_CHECK(!a.Add(2000, 300, piece.data() + 300, 600));
        BOOST_CHECK(!a.Add(2000, 1900, piece.data(), 200));
    }
    {
        // Larger than a site may be.
        overlay::ChunkAssembler a;
        BOOST_CHECK(!a.Add((uint32_t)overlay::MAX_SITE_SIZE + 1, 0, piece.data(), 10));
    }
    {
        // Nothing, for an empty file, is complete at once.
        overlay::ChunkAssembler a;
        BOOST_CHECK(a.Add(0, 0, nullptr, 0));
        BOOST_CHECK(a.Complete());
        BOOST_CHECK(a.Bytes().empty());
    }
}

BOOST_AUTO_TEST_CASE(manifest_is_bound_to_its_key)
{
    const fs::path dir = GetDataDir() / "site";
    fs::create_directories(dir / "img");
    const std::vector<unsigned char> page = Bytes(100, 4), big = Bytes(overlay::SITE_PIECE_SIZE * 2 + 5, 5);
    {
        fsbridge::ofstream f(dir / "index.html", std::ios::binary);
        f.write(reinterpret_cast<const char*>(page.data()), page.size());
        fsbridge::ofstream g(dir / "img" / "big.bin", std::ios::binary);
        g.write(reinterpret_cast<const char*>(big.data()), big.size());
    }
    overlay::SiteManifest m;
    std::string error;
    BOOST_REQUIRE_MESSAGE(overlay::BuildSiteManifest(dir, 42, m, error), error);
    BOOST_CHECK_EQUAL(m.files.size(), 2U);
    BOOST_CHECK_EQUAL(m.TotalSize(), page.size() + big.size());
    const overlay::SiteFile* f = m.Find("img/big.bin");
    BOOST_REQUIRE(f);
    BOOST_CHECK_EQUAL(f->pieces.size(), 3U);
    uint256 h;
    CSHA256().Write(big.data() + 2 * overlay::SITE_PIECE_SIZE, 5).Finalize(h.begin());
    BOOST_CHECK(f->pieces[2] == h);

    CKey key, other;
    key.MakeNewKey(true);
    other.MakeNewKey(true);
    BOOST_REQUIRE(overlay::SignSiteManifest(m, key));
    roster::KeyBytes kb{}, ob{};
    std::copy(key.GetPubKey().begin() + 1, key.GetPubKey().begin() + 33, kb.begin());
    std::copy(other.GetPubKey().begin() + 1, other.GetPubKey().begin() + 33, ob.begin());
    BOOST_CHECK(overlay::VerifySiteManifest(m, kb));
    BOOST_CHECK(!overlay::VerifySiteManifest(m, ob));

    // Through the wire and back, still bound to its key.
    std::vector<unsigned char> raw;
    BOOST_REQUIRE(m.Serialize(raw));
    overlay::SiteManifest back;
    BOOST_REQUIRE(back.Deserialize(raw));
    BOOST_CHECK(overlay::VerifySiteManifest(back, kb));
    BOOST_CHECK_EQUAL(back.version, 42U);

    // A hash changed on the way breaks the signature.
    raw[raw.size() - 64 - 1] ^= 1;
    overlay::SiteManifest bent;
    BOOST_REQUIRE(bent.Deserialize(raw));
    BOOST_CHECK(!overlay::VerifySiteManifest(bent, kb));
}

BOOST_AUTO_TEST_CASE(browser_addresses)
{
    // A key fits a browser's host name as 52 letters of base32, and back.
    roster::KeyBytes key{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = (unsigned char)(i * 37 + 11);
    const std::string label = overlay::SiteKeyLabel(key);
    BOOST_CHECK_EQUAL(label.size(), 52U);
    BOOST_CHECK(label.find('=') == std::string::npos);
    roster::KeyBytes back{};
    BOOST_REQUIRE(overlay::KeyFromSiteLabel(label, back));
    BOOST_CHECK(back == key);
    BOOST_CHECK(!overlay::KeyFromSiteLabel("pilot", back));
    BOOST_CHECK(!overlay::KeyFromSiteLabel(label.substr(1), back));
    BOOST_CHECK(!overlay::KeyFromSiteLabel(std::string(52, '1'), back));
}

BOOST_AUTO_TEST_CASE(browser_requests)
{
    std::string site, path;
    // The ordinary way: a .bps.localhost name on this port.
    BOOST_CHECK(overlay::ParseSiteRequest("/", "pilot.bps.localhost:9348", 9348, site, path));
    BOOST_CHECK_EQUAL(site, "pilot");
    BOOST_CHECK_EQUAL(path, "index.html");
    BOOST_CHECK(overlay::ParseSiteRequest("/blog/a%20b.html?x=1#top", "Alice.Pilot.BPS.localhost:9348", 9348, site, path));
    BOOST_CHECK_EQUAL(site, "alice.pilot");
    BOOST_CHECK_EQUAL(path, "blog/a b.html");
    BOOST_CHECK(overlay::ParseSiteRequest("/img/", "pilot.bps.localhost", 9348, site, path));
    BOOST_CHECK_EQUAL(path, "img/index.html");
    // Climbing out of the site goes nowhere.
    BOOST_CHECK(overlay::ParseSiteRequest("/../../etc/passwd", "pilot.bps.localhost:9348", 9348, site, path));
    BOOST_CHECK_EQUAL(path, "etc/passwd");
    // As a proxy for .bps names.
    BOOST_CHECK(overlay::ParseSiteRequest("http://pilot.bps/page.html", "pilot.bps", 9348, site, path));
    BOOST_CHECK_EQUAL(site, "pilot");
    BOOST_CHECK_EQUAL(path, "page.html");

    // Anything else is refused: another name pointed at 127.0.0.1, another
    // port, the bare address, a proxy request for an ordinary site.
    BOOST_CHECK(!overlay::ParseSiteRequest("/", "evil.example:9348", 9348, site, path));
    BOOST_CHECK(!overlay::ParseSiteRequest("/", "pilot.bps.localhost:9349", 9348, site, path));
    BOOST_CHECK(!overlay::ParseSiteRequest("/", "127.0.0.1:9348", 9348, site, path));
    BOOST_CHECK(!overlay::ParseSiteRequest("/", "bps.localhost:9348", 9348, site, path));
    BOOST_CHECK(!overlay::ParseSiteRequest("http://example.com/", "example.com", 9348, site, path));
    BOOST_CHECK(!overlay::ParseSiteRequest("*", "pilot.bps.localhost:9348", 9348, site, path));
    BOOST_CHECK(!overlay::ParseSiteRequest("/", "pi_lot.bps.localhost:9348", 9348, site, path));

    BOOST_CHECK_EQUAL(overlay::SiteContentType("a/b.HTML"), "text/html; charset=utf-8");
    BOOST_CHECK_EQUAL(overlay::SiteContentType("x.png"), "image/png");
    BOOST_CHECK_EQUAL(overlay::SiteContentType("noext"), "application/octet-stream");
}

BOOST_AUTO_TEST_SUITE_END()
