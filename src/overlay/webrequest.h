// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OVERLAY_WEBREQUEST_H
#define BITCOIN_OVERLAY_WEBREQUEST_H

#include <overlay/path.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * What a host's node does to a request before its web program sees it
 * (design note §11·6).
 *
 * Every request to a web service reaches the program from 127.0.0.1, where a
 * program that also sits behind a reverse proxy believes what the request
 * says about where it came from: CF-Connecting-IP, X-Forwarded-For. A
 * visitor writes its own request, so left alone it could be anyone it liked
 * to the program's rate limits, and all honest visitors would be one.
 *
 * So the host's node - the only party the program can trust - passes on one
 * request per stream, with every header of that kind taken out and one of
 * its own put in: X-BPS-Visitor, a label that is the same for every request
 * arriving on one path and tells nothing about who built it. A visitor gets
 * a new one by building a new path, which costs it seconds each time; that
 * is as much as a network with no addresses can say.
 *
 * The head is checked strictly, because the program parses it again and the
 * two must not disagree about where a header or a request ends: no bare line
 * feeds, no folded lines, no chunked bodies, one length. What comes after
 * the one request's body is dropped.
 */
namespace overlay {

//! The service a browser is given when a host has no pages.
static const char* const WEB_SERVICE = "web";
//! The header the host's node adds to every request to a web service.
static const char* const VISITOR_HEADER = "X-BPS-Visitor";
//! Largest head of a request to a web service.
static constexpr size_t MAX_WEB_REQUEST_HEAD = 32 * 1024;

/**
 * Whether a request header, its name in lower case, is one a reverse proxy
 * uses to say where a request came from, or this node's own.
 */
bool IsForwardingHeader(const std::string& lower_name);

/** The label of whoever is at the far end of `from`: 16 hex digits, the same for one path, under this node's `secret`. */
std::string VisitorLabel(const uint256& secret, const Hop& from);

class WebRequestGate
{
public:
    explicit WebRequestGate(std::string visitor) : m_visitor(std::move(visitor)) {}

    /**
     * Bytes from the visitor. `out` is given what may go to the program now.
     * False when the request is not one this lets through: nothing more of
     * it should reach the program.
     */
    bool Feed(const unsigned char* data, size_t n, std::vector<unsigned char>& out);

private:
    bool Rewrite(const std::string& head, std::string& out);

    const std::string m_visitor;
    std::vector<unsigned char> m_held;
    bool m_past_head{false};
    uint64_t m_body_left{0};
};

} // namespace overlay

#endif // BITCOIN_OVERLAY_WEBREQUEST_H
