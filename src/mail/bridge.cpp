// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mail/bridge.h>

#include <compat.h>
#include <logging.h>
#include <mail/client.h>
#include <names/resolve.h>
#include <netbase.h>
#include <roster/record.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/threadnames.h>
#include <util/time.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace mail {

std::unique_ptr<MailBridge> g_mail_bridge;

namespace {

#ifdef MSG_NOSIGNAL
const int SEND_FLAGS = MSG_NOSIGNAL;
#else
const int SEND_FLAGS = 0;
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2 // SD_BOTH on Windows; both are 2
#endif

//! Wake a thread blocked in recv() on this socket; closing it from elsewhere
//! does not reliably do that on Linux, but a half-close does.
void WakeSocket(SOCKET s)
{
    if (s != INVALID_SOCKET) shutdown(s, SHUT_RDWR);
}

//! Longest command line and longest line inside a message we will read.
const size_t MAX_CMD_LINE = 8 * 1024;
const size_t MAX_DATA_LINE = 1024 * 1024;
//! A whole message a client may submit at once.
const size_t MAX_MESSAGE = 1024 * 1024;

//! Blocking, line-oriented I/O over one loopback connection.
class Line
{
public:
    explicit Line(SOCKET s) : m_sock(s) {}

    //! One line without its CR/LF. False on close, error, or an over-long line.
    bool Read(std::string& out, size_t max_len)
    {
        while (true) {
            const size_t nl = m_buf.find('\n');
            if (nl != std::string::npos) {
                out = m_buf.substr(0, nl);
                m_buf.erase(0, nl + 1);
                if (!out.empty() && out.back() == '\r') out.pop_back();
                return true;
            }
            if (m_buf.size() > max_len) return false;
            char tmp[4096];
            const int n = recv(m_sock, tmp, sizeof(tmp), 0);
            if (n <= 0) return false;
            m_buf.append(tmp, n);
        }
    }

    bool Write(const std::string& s)
    {
        size_t sent = 0;
        while (sent < s.size()) {
            const int chunk = (int)std::min<size_t>(s.size() - sent, 65536);
            const int n = send(m_sock, s.data() + sent, chunk, SEND_FLAGS);
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }

private:
    SOCKET m_sock;
    std::string m_buf;
};

std::string Trimmed(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
    return s.substr(a, b - a);
}

//! The command word of a line, upper-cased (the first token).
std::string Verb(const std::string& line)
{
    size_t end = line.find_first_of(" \t");
    std::string v = line.substr(0, end);
    for (char& c : v) c = ToUpper(c);
    return v;
}

//! The e-mail address inside <...>, or the first token after a ':'.
std::string AddressOf(const std::string& line)
{
    const size_t lt = line.find('<');
    const size_t gt = line.find('>', lt == std::string::npos ? 0 : lt);
    if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
        return Trimmed(line.substr(lt + 1, gt - lt - 1));
    }
    const size_t colon = line.find(':');
    if (colon == std::string::npos) return std::string();
    return Trimmed(line.substr(colon + 1));
}

//! Map `name@bps`, `<64-hex>@bps`, a bare name or a bare key to a roster key.
//! The part after '@' is ignored. False with `err` when it cannot be resolved.
bool ResolveRecipient(const std::string& address, roster::KeyBytes& out, std::string& err)
{
    std::string local = Trimmed(address);
    const size_t at = local.find('@');
    if (at != std::string::npos) local = local.substr(0, at);
    if (local.empty()) { err = "empty recipient"; return false; }

    if (local.size() == out.size() * 2 && IsHex(local)) {
        const std::vector<unsigned char> raw = ParseHex(local);
        if (raw.size() == out.size()) {
            std::copy(raw.begin(), raw.end(), out.begin());
            return true;
        }
    }
    names::Target target;
    std::string e;
    if (names::ResolveTarget(local, target, e)) { out = target.key; return true; }
    err = e.empty() ? strprintf("cannot resolve recipient '%s'", local) : e;
    return false;
}

//! A fixed, locale-independent RFC 822 date, always in UTC.
std::string Rfc822Date(int64_t t)
{
    const time_t tt = (time_t)t;
    struct tm g;
#ifdef _WIN32
    gmtime_s(&g, &tt);
#else
    gmtime_r(&tt, &g);
#endif
    static const char* dow[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    return strprintf("%s, %02d %s %d %02d:%02d:%02d +0000", dow[g.tm_wday % 7], g.tm_mday,
                     mon[g.tm_mon % 12], g.tm_year + 1900, g.tm_hour, g.tm_min, g.tm_sec);
}

//! Render a stored letter as an RFC 822 message, CRLF line endings, dot-stuffed.
std::string RenderLetter(const StoredLetter& l)
{
    std::string out;
    out += strprintf("From: %s@bps\r\n", HexStr(l.from));
    out += strprintf("To: %s@bps\r\n", HexStr(l.to));
    out += "Subject: " + l.subject + "\r\n";
    out += "Date: " + Rfc822Date(l.received ? l.received : l.sent) + "\r\n";
    out += strprintf("Message-ID: <%s@bps>\r\n", l.id.GetHex());
    out += "MIME-Version: 1.0\r\n";
    out += "Content-Type: text/plain; charset=utf-8\r\n";
    out += "\r\n";
    // Body: normalise to CRLF and dot-stuff lines that begin with a dot.
    std::string line;
    const std::string body = l.body;
    size_t i = 0;
    while (i <= body.size()) {
        const size_t nl = body.find('\n', i);
        const size_t end = nl == std::string::npos ? body.size() : nl;
        line = body.substr(i, end - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty() && line.front() == '.') out += '.';
        out += line;
        out += "\r\n";
        if (nl == std::string::npos) break;
        i = nl + 1;
    }
    return out;
}

//! Pull Subject and body out of a submitted message (headers, blank line, body).
void ParseMessage(const std::string& data, std::string& subject, std::string& body)
{
    subject.clear();
    body.clear();
    bool have_subject = false;
    size_t pos = 0;
    size_t body_start = std::string::npos;
    while (pos < data.size()) {
        const size_t nl = data.find('\n', pos);
        const size_t end = nl == std::string::npos ? data.size() : nl;
        std::string line = data.substr(pos, end - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) { // the blank line: the body is everything after it
            body_start = nl == std::string::npos ? data.size() : nl + 1;
            break;
        }
        // Other headers (and folded Subject continuations) are ignored.
        if (!have_subject && line.size() >= 8 && ToLower(line.substr(0, 8)) == "subject:") {
            subject = Trimmed(line.substr(8));
            have_subject = true;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    if (body_start != std::string::npos) body = data.substr(body_start);
    // The message terminator leaves one trailing line break; drop it.
    if (!body.empty() && body.back() == '\n') body.pop_back();
    if (!body.empty() && body.back() == '\r') body.pop_back();
}

} // namespace

// --- SMTP submission ---------------------------------------------------------

static void HandleSmtp(SOCKET sock)
{
    Line io(sock);
    io.Write("220 BPS mail bridge ready\r\n");

    std::vector<roster::KeyBytes> recipients;
    std::string cmd;
    while (io.Read(cmd, MAX_CMD_LINE)) {
        const std::string verb = Verb(cmd);
        if (verb == "HELO") {
            io.Write("250 BPS mail bridge\r\n");
        } else if (verb == "EHLO") {
            io.Write("250-BPS mail bridge\r\n");
            io.Write(strprintf("250-SIZE %u\r\n", (unsigned)MAX_MESSAGE));
            io.Write("250-8BITMIME\r\n");
            io.Write("250 AUTH PLAIN LOGIN\r\n");
        } else if (verb == "AUTH") {
            // Loopback only, so any credentials are accepted; the dialogue is
            // run so a client that insists on logging in is satisfied.
            const std::string rest = Trimmed(cmd.size() > 4 ? cmd.substr(4) : std::string());
            const std::string mech = Verb(rest);
            if (mech == "LOGIN") {
                std::string scratch;
                io.Write("334 VXNlcm5hbWU6\r\n"); // "Username:"
                if (!io.Read(scratch, MAX_CMD_LINE)) break;
                io.Write("334 UGFzc3dvcmQ6\r\n"); // "Password:"
                if (!io.Read(scratch, MAX_CMD_LINE)) break;
            } else if (mech == "PLAIN" && rest.size() <= 6) {
                std::string scratch;
                io.Write("334 \r\n");
                if (!io.Read(scratch, MAX_CMD_LINE)) break;
            }
            io.Write("235 2.7.0 Authentication successful\r\n");
        } else if (verb == "STARTTLS") {
            io.Write("454 4.7.0 TLS not available on the loopback bridge\r\n");
        } else if (verb == "MAIL") {
            recipients.clear();
            io.Write("250 2.1.0 OK\r\n");
        } else if (verb == "RCPT") {
            roster::KeyBytes key;
            std::string err;
            if (ResolveRecipient(AddressOf(cmd), key, err)) {
                recipients.push_back(key);
                io.Write("250 2.1.5 OK\r\n");
            } else {
                io.Write(strprintf("550 5.1.1 %s\r\n", err));
            }
        } else if (verb == "DATA") {
            if (recipients.empty()) {
                io.Write("503 5.5.1 need a recipient first\r\n");
                continue;
            }
            io.Write("354 End with <CRLF>.<CRLF>\r\n");
            std::string data, line;
            bool overflow = false;
            while (io.Read(line, MAX_DATA_LINE)) {
                if (line == ".") break;
                if (!line.empty() && line.front() == '.') line.erase(0, 1);
                if (data.size() + line.size() + 1 > MAX_MESSAGE) { overflow = true; continue; }
                data += line;
                data += "\n";
            }
            if (overflow) {
                io.Write("552 5.3.4 message too large\r\n");
                recipients.clear();
                continue;
            }
            std::string subject, body;
            ParseMessage(data, subject, body);
            if (!g_mail) {
                io.Write("554 5.3.0 mail is off on this node\r\n");
                recipients.clear();
                continue;
            }
            std::string first_error;
            int sent = 0;
            for (const roster::KeyBytes& to : recipients) {
                const SendResult r = g_mail->Send(to, subject, body);
                if (r.ok) ++sent;
                else if (first_error.empty()) first_error = r.error;
            }
            if (sent == (int)recipients.size()) {
                io.Write("250 2.0.0 Carried over the overlay\r\n");
            } else if (sent > 0) {
                io.Write(strprintf("451 4.3.0 sent to %d of %d; %s\r\n", sent,
                                   (int)recipients.size(), first_error));
            } else {
                io.Write(strprintf("554 5.3.0 could not send: %s\r\n",
                                   first_error.empty() ? "no recipient reachable" : first_error));
            }
            recipients.clear();
        } else if (verb == "RSET") {
            recipients.clear();
            io.Write("250 2.0.0 OK\r\n");
        } else if (verb == "NOOP") {
            io.Write("250 2.0.0 OK\r\n");
        } else if (verb == "QUIT") {
            io.Write("221 2.0.0 Bye\r\n");
            break;
        } else if (verb == "VRFY" || verb == "EXPN") {
            io.Write("252 2.1.0 Cannot verify\r\n");
        } else {
            io.Write("500 5.5.2 Command not recognised\r\n");
        }
    }
}

// --- POP3 --------------------------------------------------------------------

static void HandlePop3(SOCKET sock)
{
    Line io(sock);
    io.Write("+OK BPS mail bridge ready\r\n");

    bool authed = false;
    std::vector<StoredLetter> inbox; // snapshot once authenticated, oldest first
    std::vector<bool> deleted;
    std::string cmd;
    while (io.Read(cmd, MAX_CMD_LINE)) {
        const std::string verb = Verb(cmd);
        const std::string arg = Trimmed(cmd.size() > verb.size() ? cmd.substr(verb.size()) : std::string());

        if (!authed) {
            if (verb == "USER") {
                io.Write("+OK\r\n");
            } else if (verb == "PASS") {
                // Loopback only: the password is not checked. Snapshot the inbox.
                authed = true;
                inbox.clear();
                if (g_mail) {
                    std::vector<StoredLetter> all = g_mail->List(); // newest first
                    for (auto it = all.rbegin(); it != all.rend(); ++it) {
                        if (it->folder == Folder::INBOX) inbox.push_back(*it);
                    }
                }
                deleted.assign(inbox.size(), false);
                io.Write(strprintf("+OK mailbox with %u messages\r\n", (unsigned)inbox.size()));
            } else if (verb == "CAPA") {
                io.Write("+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n");
            } else if (verb == "QUIT") {
                io.Write("+OK Bye\r\n");
                break;
            } else {
                io.Write("-ERR authenticate first\r\n");
            }
            continue;
        }

        auto valid = [&](unsigned n) { return n >= 1 && n <= inbox.size() && !deleted[n - 1]; };

        if (verb == "STAT") {
            size_t count = 0, bytes = 0;
            for (size_t i = 0; i < inbox.size(); ++i) {
                if (deleted[i]) continue;
                ++count;
                bytes += RenderLetter(inbox[i]).size();
            }
            io.Write(strprintf("+OK %u %u\r\n", (unsigned)count, (unsigned)bytes));
        } else if (verb == "LIST" || verb == "UIDL") {
            const bool uidl = verb == "UIDL";
            if (!arg.empty()) {
                const unsigned n = (unsigned)atoi(arg.c_str());
                if (!valid(n)) { io.Write("-ERR no such message\r\n"); continue; }
                if (uidl) io.Write(strprintf("+OK %u %s\r\n", n, inbox[n - 1].id.GetHex()));
                else io.Write(strprintf("+OK %u %u\r\n", n, (unsigned)RenderLetter(inbox[n - 1]).size()));
            } else {
                io.Write("+OK\r\n");
                for (size_t i = 0; i < inbox.size(); ++i) {
                    if (deleted[i]) continue;
                    if (uidl) io.Write(strprintf("%u %s\r\n", (unsigned)(i + 1), inbox[i].id.GetHex()));
                    else io.Write(strprintf("%u %u\r\n", (unsigned)(i + 1), (unsigned)RenderLetter(inbox[i]).size()));
                }
                io.Write(".\r\n");
            }
        } else if (verb == "RETR") {
            const unsigned n = (unsigned)atoi(arg.c_str());
            if (!valid(n)) { io.Write("-ERR no such message\r\n"); continue; }
            const std::string msg = RenderLetter(inbox[n - 1]);
            io.Write(strprintf("+OK %u octets\r\n", (unsigned)msg.size()));
            io.Write(msg);
            io.Write(".\r\n");
            if (g_mail && !inbox[n - 1].read) g_mail->MarkRead(inbox[n - 1].id);
        } else if (verb == "TOP") {
            unsigned n = 0, lines = 0;
            sscanf(arg.c_str(), "%u %u", &n, &lines);
            if (!valid(n)) { io.Write("-ERR no such message\r\n"); continue; }
            const std::string msg = RenderLetter(inbox[n - 1]);
            io.Write("+OK\r\n");
            const size_t sep = msg.find("\r\n\r\n");
            std::string head = sep == std::string::npos ? msg : msg.substr(0, sep + 4);
            io.Write(head);
            size_t pos = sep == std::string::npos ? msg.size() : sep + 4;
            for (unsigned k = 0; k < lines && pos < msg.size(); ++k) {
                const size_t nl = msg.find("\r\n", pos);
                const size_t end = nl == std::string::npos ? msg.size() : nl + 2;
                io.Write(msg.substr(pos, end - pos));
                if (nl == std::string::npos) break;
                pos = end;
            }
            io.Write(".\r\n");
        } else if (verb == "DELE") {
            const unsigned n = (unsigned)atoi(arg.c_str());
            if (!valid(n)) { io.Write("-ERR no such message\r\n"); continue; }
            deleted[n - 1] = true;
            io.Write("+OK marked for deletion\r\n");
        } else if (verb == "RSET") {
            deleted.assign(inbox.size(), false);
            io.Write("+OK\r\n");
        } else if (verb == "NOOP") {
            io.Write("+OK\r\n");
        } else if (verb == "CAPA") {
            io.Write("+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n");
        } else if (verb == "QUIT") {
            // Commit deletions now, as POP3 requires.
            if (g_mail) {
                for (size_t i = 0; i < inbox.size(); ++i) {
                    if (deleted[i]) g_mail->Delete(inbox[i].id);
                }
            }
            io.Write("+OK Bye\r\n");
            break;
        } else {
            io.Write("-ERR unknown command\r\n");
        }
    }
}

// --- the listener ------------------------------------------------------------

MailBridge::MailBridge(uint16_t pop3_port, uint16_t smtp_port)
    : m_pop3_port(pop3_port), m_smtp_port(smtp_port) {}

MailBridge::~MailBridge() { Stop(); }

bool MailBridge::Listen(Listener& l, std::string& error)
{
    l.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l.sock == INVALID_SOCKET) {
        error = strprintf("could not make a socket (%s)", NetworkErrorString(WSAGetLastError()));
        return false;
    }
    int one = 1;
    setsockopt(l.sock, SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only, never the network
    sa.sin_port = htons(l.port);
    if (::bind(l.sock, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        error = strprintf("cannot bind 127.0.0.1:%u (%s); another program may be using it, or set "
                          "-mailbridgepop3port / -mailbridgesmtpport",
                          l.port, NetworkErrorString(WSAGetLastError()));
        CloseSocket(l.sock);
        return false;
    }
    if (listen(l.sock, SOMAXCONN) == SOCKET_ERROR) {
        error = strprintf("cannot listen on 127.0.0.1:%u (%s)", l.port, NetworkErrorString(WSAGetLastError()));
        CloseSocket(l.sock);
        return false;
    }
    // Non-blocking, so the accept loop can wake to check for shutdown.
    SetSocketNonBlocking(l.sock, true);
    return true;
}

bool MailBridge::Start(std::string& error)
{
    m_pop3.port = m_pop3_port;
    m_smtp.port = m_smtp_port;
    if (!Listen(m_pop3, error)) return false;
    if (!Listen(m_smtp, error)) {
        CloseSocket(m_pop3.sock);
        return false;
    }
    m_running = true;
    m_pop3.thread = std::thread([this] { util::ThreadRename("mail-pop3"); Accept(&m_pop3); });
    m_smtp.thread = std::thread([this] { util::ThreadRename("mail-smtp"); Accept(&m_smtp); });
    LogPrintf("mail bridge: reading on 127.0.0.1:%u (POP3), sending on 127.0.0.1:%u (SMTP)\n",
              m_pop3_port, m_smtp_port);
    return true;
}

void MailBridge::Accept(Listener* l)
{
    while (m_running) {
        // Wait up to 200 ms for a connection, so Stop() is noticed promptly.
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(l->sock, &fds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;
        const int r = select(l->sock + 1, &fds, nullptr, nullptr, &tv);
        if (!m_running) break;
        if (r <= 0) continue; // timeout or an interrupted select; look again

        struct sockaddr_in from;
        socklen_t len = sizeof(from);
        SOCKET c = accept(l->sock, (struct sockaddr*)&from, &len);
        if (c == INVALID_SOCKET) continue;
        // Belt and braces: we bound to loopback, but refuse anything that is not.
        if (from.sin_family != AF_INET || (ntohl(from.sin_addr.s_addr) >> 24) != 127) {
            CloseSocket(c);
            continue;
        }
        SetSocketNonBlocking(c, false); // the handler does blocking line I/O
        const Proto proto = l->proto;
        LOCK(m_mutex);
        Reap();
        Conn conn;
        conn.sock = c;
        conn.done = std::make_shared<std::atomic<bool>>(false);
        std::shared_ptr<std::atomic<bool>> done = conn.done;
        conn.thread = std::thread([this, proto, c, done] {
            util::ThreadRename("mail-conn");
            Serve(proto, c);
            done->store(true);
        });
        m_conns.push_back(std::move(conn));
    }
}

void MailBridge::Serve(Proto proto, SOCKET sock)
{
    // The socket is closed by its owner (Reap or Stop) after the thread is
    // joined, never here, so its fd number cannot be reused under us.
    if (proto == Proto::SMTP) HandleSmtp(sock);
    else HandlePop3(sock);
}

void MailBridge::Reap()
{
    for (size_t i = 0; i < m_conns.size();) {
        if (m_conns[i].done && m_conns[i].done->load()) {
            if (m_conns[i].thread.joinable()) m_conns[i].thread.join();
            CloseSocket(m_conns[i].sock);
            m_conns.erase(m_conns.begin() + i);
        } else {
            ++i;
        }
    }
}

void MailBridge::Stop()
{
    if (!m_running.exchange(false)) return;
    m_interrupt();
    // The accept loops wake within 200 ms on m_running and leave.
    if (m_pop3.thread.joinable()) m_pop3.thread.join();
    if (m_smtp.thread.joinable()) m_smtp.thread.join();
    CloseSocket(m_pop3.sock);
    CloseSocket(m_smtp.sock);

    std::vector<Conn> conns;
    {
        LOCK(m_mutex);
        conns.swap(m_conns);
    }
    for (Conn& c : conns) WakeSocket(c.sock); // unblock any recv() in its handler
    for (Conn& c : conns) {
        if (c.thread.joinable()) c.thread.join();
        CloseSocket(c.sock);
    }
    LogPrintf("mail bridge: stopped\n");
}

} // namespace mail
