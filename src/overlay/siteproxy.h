// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_SITEPROXY_H
#define BITCOIN_OVERLAY_SITEPROXY_H

#include <compat.h>
#include <roster/record.h>
#include <sync.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * Sites in an ordinary browser (design note §11·6).
 *
 * A small web server on 127.0.0.1 that answers http://<site>.bps.localhost:<port>/
 * with the site's files, fetched over the overlay exactly as BPS Relay's
 * viewer fetches them. <site> is a name (pilot, alice.pilot) or the site's key
 * in base32, 52 letters, which fits where 64 hexadecimal ones would not.
 * Chromium-based browsers and Firefox send any .localhost name to the
 * computer they run on, so nothing has to be set up; a browser that does not
 * can use this as an HTTP proxy for .bps names. A separate name per site
 * keeps one site's cookies and storage away from another's.
 *
 * Every answer carries a content security policy that lets a page load only
 * from its own site, so it cannot pull a script, font or image from the open
 * internet and so learn its reader's address; no referrer; no framing by
 * other sites. A request not addressed to a .bps name on this port is
 * refused, so a page elsewhere cannot use the server by pointing a name of
 * its own at 127.0.0.1.
 *
 * A host with no pages but a service named "web" (overlay/service.h) is
 * served the same way: the request is carried to that program on the host's
 * loopback as a stream, with Connection: close, and its answer comes back
 * with the same headers added, any of its own of those kinds removed but its
 * content security policy, which a browser applies together with this one.
 * Any method goes to a web service; a site of pages answers GET and HEAD.
 *
 * What it cannot stop: WebRTC can still show a script the computer's
 * addresses in some browsers, and a link the reader follows to an ordinary
 * site leaves as any link does. BPS Relay's viewer, which runs no scripts,
 * stays the safe way to read a hidden site.
 */
namespace overlay {

//! Off in the node, on in BPS Relay (which soft-sets it).
static const bool DEFAULT_SITE_PROXY = false;
//! The port, by default three above the peer-to-peer one.
inline uint16_t DefaultSiteProxyPort(uint16_t p2p_port) { return (uint16_t)(p2p_port + 3); }

/** A site's key as a browser address label: base32, lowercase, 52 letters. */
std::string SiteKeyLabel(const roster::KeyBytes& key);
/** The key back from such a label; false when it is not one. */
bool KeyFromSiteLabel(const std::string& label, roster::KeyBytes& out);

/**
 * Which site and file an HTTP request asks for: `target` as in the request
 * line, `host` the Host header. Accepted are http://<site>.bps.localhost:<port>/path
 * (`port` must match this server's) and, as a proxy, http://<site>.bps/path.
 * `path` comes back without its leading slash, "index.html" for a folder.
 * False for anything else.
 */
bool ParseSiteRequest(const std::string& target, const std::string& host, uint16_t port,
                      std::string& site, std::string& path);

/** The content type a file is served with, by its extension. */
std::string SiteContentType(const std::string& path);

class SiteProxy
{
public:
    explicit SiteProxy(uint16_t port);
    ~SiteProxy();

    bool Start(std::string& error);
    void Stop();
    uint16_t Port() const { return m_port; }

    //! Connections served at once; more wait for one to finish.
    static constexpr size_t MAX_CONNECTIONS = 16;
    //! How long a host found to have no pages is not asked for one again:
    //! every request to its web application would otherwise cross the
    //! overlay twice.
    static constexpr int64_t NO_PAGES_SECONDS = 60;

private:
    struct Conn {
        SOCKET sock{INVALID_SOCKET};
        std::shared_ptr<std::atomic<bool>> done;
        std::shared_ptr<std::atomic<bool>> handed; //!< the socket went to the service hub, which closes it
        std::thread thread;
    };

    void Accept();
    /** Answer one request. True when the socket was handed to a web service, which owns it from then. */
    bool Serve(SOCKET sock);
    void Reap() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const uint16_t m_port;
    SOCKET m_listen{INVALID_SOCKET};
    std::atomic<bool> m_running{false};
    std::thread m_thread;
    Mutex m_mutex;
    std::vector<Conn> m_conns GUARDED_BY(m_mutex);
    //! Hosts found to have no pages, and until when that is believed.
    std::map<roster::KeyBytes, int64_t> m_no_pages GUARDED_BY(m_mutex);
};

/** The running server, or null when -siteproxy is off. */
extern std::unique_ptr<SiteProxy> g_site_proxy;

} // namespace overlay

#endif // BITCOIN_OVERLAY_SITEPROXY_H
