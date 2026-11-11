// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/webrequest.h>

#include <crypto/sha256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace overlay {

namespace {

std::string Lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

bool StartsWith(const std::string& s, const char* prefix)
{
    return s.compare(0, strlen(prefix), prefix) == 0;
}

/** A header's name as HTTP allows it: letters, digits and a few signs, nothing else. */
bool ValidHeaderName(const std::string& name)
{
    if (name.empty()) return false;
    for (unsigned char c : name) {
        if (!(std::isalnum(c) || strchr("!#$%&'*+-.^_`|~", c))) return false;
    }
    return true;
}

/** Headers about the connection, which is this node's to decide: one request, then closed. */
bool IsConnectionHeader(const std::string& name)
{
    return name == "connection" || name == "keep-alive" || name == "proxy-connection" || name == "upgrade" ||
           name == "te" || name == "trailer" || name == "expect";
}

} // namespace

bool IsForwardingHeader(const std::string& name)
{
    return StartsWith(name, "cf-") || StartsWith(name, "x-forwarded-") || StartsWith(name, "x-bps-") ||
           name == "forwarded" || name == "via" || name == "x-real-ip" || name == "true-client-ip" ||
           name == "x-client-ip" || name == "x-cluster-client-ip" || name == "fastly-client-ip" ||
           name == "fly-client-ip";
}

std::string VisitorLabel(const uint256& secret, const Hop& from)
{
    CSHA256 hasher;
    hasher.Write(secret.begin(), secret.size());
    const unsigned char kind = from.via_path ? 1 : 0;
    hasher.Write(&kind, 1);
    if (from.via_path) {
        unsigned char id[8];
        for (int i = 0; i < 8; ++i) id[i] = (unsigned char)(from.path >> (8 * i));
        hasher.Write(id, sizeof(id));
    } else {
        const std::string addr = from.addr.ToString();
        hasher.Write((const unsigned char*)addr.data(), addr.size());
    }
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);
    return HexStr(Span<const unsigned char>(hash, 8));
}

bool WebRequestGate::Rewrite(const std::string& head, std::string& out)
{
    // Split at CR LF only; a line with either character left in it is one
    // the program might end somewhere else.
    std::vector<std::string> lines;
    size_t at = 0;
    while (true) {
        const size_t next = head.find("\r\n", at);
        lines.push_back(head.substr(at, next == std::string::npos ? std::string::npos : next - at));
        if (next == std::string::npos) break;
        at = next + 2;
    }
    for (const std::string& line : lines) {
        for (unsigned char c : line) {
            if (c == '\r' || c == '\n' || c == 0) return false;
        }
    }

    // METHOD SP target SP HTTP/1.x
    const std::string& request = lines[0];
    const size_t sp1 = request.find(' ');
    const size_t sp2 = sp1 == std::string::npos ? std::string::npos : request.find(' ', sp1 + 1);
    if (sp1 == 0 || sp2 == std::string::npos || sp2 == sp1 + 1) return false;
    const std::string version = request.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0") return false;
    for (size_t i = 0; i < sp1; ++i) {
        if (!std::isupper((unsigned char)request[i])) return false;
    }
    if (request.find_first_of(" \t", sp1 + 1) != sp2) return false;

    out = request + "\r\n";
    bool have_length = false;
    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        const size_t colon = line.find(':');
        if (colon == std::string::npos) return false;
        const std::string name = Lower(line.substr(0, colon));
        // Also turns away a folded line, which starts with a space.
        if (!ValidHeaderName(name)) return false;
        if (name == "transfer-encoding") return false;
        if (name == "content-length") {
            std::string value = line.substr(colon + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            if (value.empty() || value.size() > 18 || value.find_first_not_of("0123456789") != std::string::npos) return false;
            const uint64_t length = std::stoull(value);
            if (have_length && length != m_body_left) return false;
            if (have_length) continue;
            have_length = true;
            m_body_left = length;
        }
        if (IsConnectionHeader(name) || IsForwardingHeader(name)) continue;
        out += line + "\r\n";
    }
    out += std::string(VISITOR_HEADER) + ": " + m_visitor + "\r\nConnection: close\r\n\r\n";
    return true;
}

bool WebRequestGate::Feed(const unsigned char* data, size_t n, std::vector<unsigned char>& out)
{
    out.clear();
    if (!m_past_head) {
        m_held.insert(m_held.end(), data, data + n);
        static const unsigned char END[] = {'\r', '\n', '\r', '\n'};
        const auto stop = std::search(m_held.begin(), m_held.end(), END, END + 4);
        if (stop == m_held.end()) return m_held.size() <= MAX_WEB_REQUEST_HEAD;
        const size_t head_size = stop - m_held.begin();
        if (head_size > MAX_WEB_REQUEST_HEAD) return false;
        std::string rewritten;
        if (!Rewrite(std::string(m_held.begin(), stop), rewritten)) return false;
        out.assign(rewritten.begin(), rewritten.end());
        m_past_head = true;
        // What came with the head is the start of the body.
        std::vector<unsigned char> rest(stop + 4, m_held.end());
        m_held.swap(rest);
        data = m_held.data();
        n = m_held.size();
    }
    // The one request's body, and nothing after it.
    const size_t take = (size_t)std::min<uint64_t>(n, m_body_left);
    out.insert(out.end(), data, data + take);
    m_body_left -= take;
    m_held.clear();
    return true;
}

} // namespace overlay
