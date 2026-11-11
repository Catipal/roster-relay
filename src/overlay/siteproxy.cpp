// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/siteproxy.h>

#include <logging.h>
#include <names/resolve.h>
#include <netbase.h>
#include <overlay/hosting.h>
#include <overlay/service.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/threadnames.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>

namespace overlay {

std::unique_ptr<SiteProxy> g_site_proxy;

namespace {

#ifdef MSG_NOSIGNAL
const int SEND_FLAGS = MSG_NOSIGNAL;
#else
const int SEND_FLAGS = 0;
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

using SiteResponseFilter = ServiceHub::Filter;

//! The request line and headers, together.
constexpr size_t MAX_REQUEST_HEAD = 16 * 1024;
const char* SUFFIX_LOCAL = ".bps.localhost";
const char* SUFFIX_PROXY = ".bps";

/**
 * A page may load only from its own site: no script, stylesheet, font or
 * image from the open internet, which would tell that site where its reader
 * is. Scripts from the site itself may run; they can reach nothing but it.
 */
const char* CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                  "img-src 'self' data:; font-src 'self' data:; media-src 'self'; connect-src 'self'; "
                  "object-src 'none'; frame-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'";

std::string Lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

bool EndsWith(const std::string& s, const std::string& suffix)
{
    return s.size() > suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

//! A path from a URL: decoded, without query or fragment, with no "." or
//! ".." left, and index.html for a folder.
std::string CleanPath(const std::string& raw)
{
    std::string p = raw.substr(0, raw.find_first_of("?#"));
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= p.size()) {
        const size_t slash = p.find('/', start);
        std::string part = p.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (!part.empty() && part != ".") {
            if (part == "..") {
                if (!parts.empty()) parts.pop_back();
            } else {
                // Percent-decoding, so "my%20page.html" names "my page.html".
                std::string out;
                for (size_t i = 0; i < part.size(); ++i) {
                    if (part[i] == '%' && i + 2 < part.size() && IsHex(part.substr(i + 1, 2))) {
                        out += (char)std::stoi(part.substr(i + 1, 2), nullptr, 16);
                        i += 2;
                    } else {
                        out += part[i];
                    }
                }
                parts.push_back(out);
            }
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    std::string out;
    for (const std::string& part : parts) out += (out.empty() ? "" : "/") + part;
    const bool folder = p.empty() || p.back() == '/' || out.empty();
    if (folder) out += out.empty() ? "index.html" : "/index.html";
    return out;
}

bool SendAll(SOCKET s, const std::string& data)
{
    size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(s, data.data() + sent, (int)std::min<size_t>(data.size() - sent, 65536), SEND_FLAGS);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

void Respond(SOCKET s, int code, const std::string& reason, const std::string& type, const std::string& body,
             bool head_only)
{
    std::string out = strprintf("HTTP/1.1 %d %s\r\n", code, reason);
    out += "Content-Type: " + type + "\r\n";
    out += strprintf("Content-Length: %u\r\n", body.size());
    out += std::string("Content-Security-Policy: ") + CSP + "\r\n";
    out += "Referrer-Policy: no-referrer\r\n";
    out += "X-Frame-Options: SAMEORIGIN\r\n";
    out += "X-Content-Type-Options: nosniff\r\n";
    out += "Cache-Control: no-cache\r\n";
    out += "Connection: close\r\n\r\n";
    if (!head_only) out += body;
    SendAll(s, out);
}

void RespondText(SOCKET s, int code, const std::string& reason, const std::string& text, bool head_only)
{
    const std::string page = "<!doctype html><meta charset=\"utf-8\"><title>" + reason + "</title><p>" + text + "</p>\n";
    Respond(s, code, reason, "text/html; charset=utf-8", page, head_only);
}

/**
 * A request's head as it goes to a web service: the target in origin form,
 * and one request per connection, so each answer can be told apart.
 */
std::string ForwardedHead(const std::string& head, const std::string& target)
{
    const size_t eol = head.find("\r\n");
    const std::string line = head.substr(0, eol);
    std::string origin = target;
    if (Lower(origin.substr(0, 7)) == "http://") {
        const size_t slash = origin.find('/', 7);
        origin = slash == std::string::npos ? "/" : origin.substr(slash);
    }
    const size_t sp1 = line.find(' ');
    const size_t sp2 = line.find(' ', sp1 + 1);
    std::string out = line.substr(0, sp1) + " " + origin + line.substr(sp2) + "\r\n";
    size_t at = eol;
    while (at != std::string::npos && at < head.size()) {
        const size_t next = head.find("\r\n", at + 2);
        const std::string h = head.substr(at + 2, next == std::string::npos ? std::string::npos : next - at - 2);
        const std::string name = Lower(h.substr(0, h.find(':')));
        // Nothing that says where the request came from leaves this computer.
        if (name != "connection" && name != "proxy-connection" && name != "keep-alive" && !IsForwardingHeader(name) &&
            !h.empty()) {
            out += h + "\r\n";
        }
        at = next;
    }
    return out + "Connection: close\r\n\r\n";
}

/**
 * The web service's answer on its way back: its head held until whole, then
 * passed on with this proxy's headers in it; the body as it comes.
 */
SiteResponseFilter WebFilter()
{
    std::shared_ptr<bool> past_head = std::make_shared<bool>(false);
    return [past_head](std::vector<unsigned char>& held, bool end) -> std::vector<unsigned char> {
        std::vector<unsigned char> out;
        if (*past_head) {
            out.swap(held);
            return out;
        }
        const std::string text(held.begin(), held.end());
        const size_t stop = text.find("\r\n\r\n");
        if (stop == std::string::npos) {
            // A head that never ends is passed on as it is, not held for ever.
            if (end || held.size() > MAX_REQUEST_HEAD) {
                *past_head = true;
                out.swap(held);
            }
            return out;
        }
        const std::string head = text.substr(0, stop);
        std::string rewritten;
        size_t at = 0;
        bool first = true;
        while (at <= head.size()) {
            const size_t next = head.find("\r\n", at);
            const std::string h = head.substr(at, next == std::string::npos ? std::string::npos : next - at);
            const std::string name = Lower(h.substr(0, h.find(':')));
            if (first || (name != "connection" && name != "referrer-policy" && name != "x-frame-options" &&
                          name != "keep-alive")) {
                rewritten += h + "\r\n";
            }
            first = false;
            if (next == std::string::npos) break;
            at = next + 2;
        }
        rewritten += std::string("Content-Security-Policy: ") + CSP + "\r\n";
        rewritten += "Referrer-Policy: no-referrer\r\nX-Frame-Options: SAMEORIGIN\r\nX-Content-Type-Options: nosniff\r\n";
        rewritten += "Connection: close\r\n\r\n";
        out.assign(rewritten.begin(), rewritten.end());
        out.insert(out.end(), held.begin() + stop + 4, held.end());
        held.clear();
        *past_head = true;
        return out;
    };
}

} // namespace

std::string SiteKeyLabel(const roster::KeyBytes& key)
{
    return EncodeBase32(Span<const unsigned char>(key.data(), key.size()), /*pad=*/false);
}

bool KeyFromSiteLabel(const std::string& label, roster::KeyBytes& out)
{
    if (label.size() != 52) return false;
    for (char c : label) {
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'))) return false;
    }
    bool invalid = false;
    const std::vector<unsigned char> bytes = DecodeBase32((label + "====").c_str(), &invalid);
    if (invalid || bytes.size() != out.size()) return false;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return true;
}

bool ParseSiteRequest(const std::string& target, const std::string& host_header, uint16_t port,
                      std::string& site, std::string& path)
{
    std::string host, rest;
    bool as_proxy = false;
    const std::string t = target;
    if (Lower(t.substr(0, 7)) == "http://") {
        // Absolute form: a browser using this as its proxy for .bps names.
        const size_t slash = t.find('/', 7);
        host = Lower(t.substr(7, slash == std::string::npos ? std::string::npos : slash - 7));
        rest = slash == std::string::npos ? "/" : t.substr(slash);
        as_proxy = true;
    } else if (!t.empty() && t[0] == '/') {
        host = Lower(host_header);
        rest = t;
    } else {
        return false;
    }
    // The port, if the host carries one, must be this server's own.
    const size_t colon = host.rfind(':');
    if (colon != std::string::npos) {
        const std::string p = host.substr(colon + 1);
        host = host.substr(0, colon);
        if (!as_proxy && p != std::to_string(port)) return false;
    }
    if (EndsWith(host, SUFFIX_LOCAL)) {
        site = host.substr(0, host.size() - strlen(SUFFIX_LOCAL));
    } else if (as_proxy && EndsWith(host, SUFFIX_PROXY)) {
        site = host.substr(0, host.size() - strlen(SUFFIX_PROXY));
    } else {
        return false;
    }
    if (site.empty() || site.size() > 255) return false;
    for (char c : site) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
    }
    path = CleanPath(rest.substr(1));
    return true;
}

std::string SiteContentType(const std::string& path)
{
    const size_t dot = path.rfind('.');
    const std::string ext = dot == std::string::npos ? "" : Lower(path.substr(dot + 1));
    if (ext == "html" || ext == "htm") return "text/html; charset=utf-8";
    if (ext == "css") return "text/css; charset=utf-8";
    if (ext == "js" || ext == "mjs") return "text/javascript; charset=utf-8";
    if (ext == "json") return "application/json";
    if (ext == "txt" || ext == "md") return "text/plain; charset=utf-8";
    if (ext == "xml") return "application/xml";
    if (ext == "svg") return "image/svg+xml";
    if (ext == "png") return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "gif") return "image/gif";
    if (ext == "webp") return "image/webp";
    if (ext == "ico") return "image/x-icon";
    if (ext == "woff") return "font/woff";
    if (ext == "woff2") return "font/woff2";
    if (ext == "pdf") return "application/pdf";
    if (ext == "mp4") return "video/mp4";
    if (ext == "webm") return "video/webm";
    if (ext == "mp3") return "audio/mpeg";
    return "application/octet-stream";
}

// --- the server ----------------------------------------------------------------

SiteProxy::SiteProxy(uint16_t port) : m_port(port) {}

SiteProxy::~SiteProxy() { Stop(); }

bool SiteProxy::Start(std::string& error)
{
    m_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listen == INVALID_SOCKET) {
        error = strprintf("could not make a socket (%s)", NetworkErrorString(WSAGetLastError()));
        return false;
    }
    int one = 1;
    setsockopt(m_listen, SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // this computer only, never the network
    sa.sin_port = htons(m_port);
    if (::bind(m_listen, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        error = strprintf("cannot bind 127.0.0.1:%u (%s); another program may be using it, or set -siteproxyport",
                          m_port, NetworkErrorString(WSAGetLastError()));
        CloseSocket(m_listen);
        return false;
    }
    if (listen(m_listen, SOMAXCONN) == SOCKET_ERROR) {
        error = strprintf("cannot listen on 127.0.0.1:%u (%s)", m_port, NetworkErrorString(WSAGetLastError()));
        CloseSocket(m_listen);
        return false;
    }
    SetSocketNonBlocking(m_listen, true);
    m_running = true;
    m_thread = std::thread([this] { util::ThreadRename("siteproxy"); Accept(); });
    LogPrintf("sites: open them in a browser at http://<name or key>.bps.localhost:%u/\n", m_port);
    return true;
}

void SiteProxy::Accept()
{
    while (m_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_listen, &fds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;
        const int r = select(m_listen + 1, &fds, nullptr, nullptr, &tv);
        if (!m_running) break;
        bool full;
        {
            LOCK(m_mutex);
            Reap();
            full = m_conns.size() >= MAX_CONNECTIONS;
        }
        if (full) {
            // The waiting connection keeps until one ends.
            std::this_thread::sleep_for(std::chrono::milliseconds{50});
            continue;
        }
        if (r <= 0) continue;
        struct sockaddr_in from;
        socklen_t len = sizeof(from);
        SOCKET c = accept(m_listen, (struct sockaddr*)&from, &len);
        if (c == INVALID_SOCKET) continue;
        if (from.sin_family != AF_INET || (ntohl(from.sin_addr.s_addr) >> 24) != 127) {
            CloseSocket(c);
            continue;
        }
        SetSocketNonBlocking(c, false);
        // A browser that opens a connection and sends nothing must not hold
        // a thread for ever.
#ifdef WIN32
        DWORD timeout = 30000;
#else
        struct timeval timeout{30, 0};
#endif
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (sockopt_arg_type)&timeout, sizeof(timeout));
        LOCK(m_mutex);
        Conn conn;
        conn.sock = c;
        conn.done = std::make_shared<std::atomic<bool>>(false);
        conn.handed = std::make_shared<std::atomic<bool>>(false);
        std::shared_ptr<std::atomic<bool>> done = conn.done;
        std::shared_ptr<std::atomic<bool>> handed = conn.handed;
        conn.thread = std::thread([this, c, done, handed] {
            util::ThreadRename("siteproxy-conn");
            if (Serve(c)) handed->store(true);
            done->store(true);
        });
        m_conns.push_back(std::move(conn));
    }
}

bool SiteProxy::Serve(SOCKET sock)
{
    std::string raw;
    char buf[4096];
    while (raw.find("\r\n\r\n") == std::string::npos) {
        if (raw.size() > MAX_REQUEST_HEAD) return false;
        const int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        raw.append(buf, n);
    }
    const std::string head = raw.substr(0, raw.find("\r\n\r\n"));
    // Bytes of a request's body that came with its head.
    const std::string body_start = raw.substr(head.size() + 4);

    // The request line, then the Host header.
    const size_t eol = head.find("\r\n");
    const std::string line = head.substr(0, eol);
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        RespondText(sock, 400, "Bad Request", "That is not an HTTP request.", false);
        return false;
    }
    const std::string method = line.substr(0, sp1);
    const std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string host;
    size_t at = eol;
    while (at != std::string::npos && at < head.size()) {
        const size_t next = head.find("\r\n", at + 2);
        const std::string h = head.substr(at + 2, next == std::string::npos ? std::string::npos : next - at - 2);
        const size_t colon = h.find(':');
        if (colon != std::string::npos && Lower(h.substr(0, colon)) == "host") {
            host = h.substr(colon + 1);
            host.erase(0, host.find_first_not_of(" \t"));
            host.erase(host.find_last_not_of(" \t") + 1);
        }
        at = next;
    }

    const bool head_only = method == "HEAD";
    std::string site, path;
    if (!ParseSiteRequest(target, host, m_port, site, path)) {
        // Not addressed to a BPS site on this port: refused, so a page
        // elsewhere cannot point a name of its own here and use this server.
        RespondText(sock, 403, "Forbidden", "This answers only BPS sites: http://&lt;name&gt;.bps.localhost:" +
                    std::to_string(m_port) + "/", head_only);
        return false;
    }

    roster::KeyBytes key{};
    if (!KeyFromSiteLabel(site, key)) {
        names::Target t;
        std::string error;
        if (!names::ResolveTarget(site, t, error)) {
            RespondText(sock, 404, "Not Found", "No name " + site + " is registered, and it is not a site's key.",
                        head_only);
            return false;
        }
        key = t.key;
    }

    // A site of pages answers reading; a web service anything.
    const bool reading = method == "GET" || method == "HEAD";
    // Whether to ask for a page at all: not from a host that had none a moment ago.
    bool pages = true;
    {
        LOCK(m_mutex);
        const auto it = m_no_pages.find(key);
        pages = it == m_no_pages.end() || GetTime() >= it->second;
    }
    std::vector<unsigned char> bytes;
    std::string error;
    if (reading && pages && FetchSiteFile(key, path, bytes, error)) {
        Respond(sock, 200, "OK", SiteContentType(path), std::string(bytes.begin(), bytes.end()), head_only);
        return false;
    }
    if (reading && pages && error.find("no file at that path") != std::string::npos) {
        RespondText(sock, 404, "Not Found", "The site has no " + path + ".", head_only);
        return false;
    }
    if (g_services && (!reading || !pages || error.find("no site under that key") != std::string::npos)) {
        // No pages there: the host's web application, if it runs one.
        if (reading && pages) {
            LOCK(m_mutex);
            if (m_no_pages.size() >= 256) m_no_pages.clear();
            m_no_pages[key] = GetTime() + NO_PAGES_SECONDS;
        }
        const std::string request = ForwardedHead(head, target) + body_start;
        g_services->Attach(sock, key, WEB_SERVICE, std::vector<unsigned char>(request.begin(), request.end()), WebFilter());
        return true;
    }
    RespondText(sock, 502, "Bad Gateway", "The site could not be reached over BPS: " + error + ".", head_only);
    return false;
}

void SiteProxy::Reap()
{
    for (size_t i = 0; i < m_conns.size();) {
        if (m_conns[i].done && m_conns[i].done->load()) {
            if (m_conns[i].thread.joinable()) m_conns[i].thread.join();
            if (!m_conns[i].handed->load()) CloseSocket(m_conns[i].sock);
            m_conns.erase(m_conns.begin() + i);
        } else {
            ++i;
        }
    }
}

void SiteProxy::Stop()
{
    if (!m_running.exchange(false)) return;
    if (m_thread.joinable()) m_thread.join();
    CloseSocket(m_listen);
    std::vector<Conn> conns;
    {
        LOCK(m_mutex);
        conns.swap(m_conns);
    }
    for (Conn& c : conns) {
        if (c.sock != INVALID_SOCKET && !c.handed->load()) shutdown(c.sock, SHUT_RDWR);
    }
    for (Conn& c : conns) {
        if (c.thread.joinable()) c.thread.join();
        if (!c.handed->load()) CloseSocket(c.sock);
    }
}

} // namespace overlay
