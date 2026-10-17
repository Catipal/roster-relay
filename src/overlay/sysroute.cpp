// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <overlay/sysroute.h>

#include <logging.h>
#include <overlay/sysif.h>
#include <tinyformat.h>

#include <cstring>

#ifdef WIN32
#include <compat.h>
#include <iphlpapi.h>
#include <overlay/netservice.h>
#endif

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace overlay {

std::unique_ptr<SystemRoutes> g_system_routes;

namespace {

std::string Num(uint32_t v) { return strprintf("%u", v); }

std::string Prefix(const IpAddr& a) { return a.ToString() + (a.version == 6 ? "/128" : "/32"); }

} // namespace

std::vector<RouteStep> PlanRoutesUp(const std::string& dev, bool resolver)
{
    const std::string table = Num(ROUTE_TABLE);
    const std::string mark = strprintf("0x%x", ROUTE_MARK);
    std::vector<RouteStep> s;
    auto add = [&s](std::vector<std::string> argv, bool required) {
        RouteStep step;
        step.argv = std::move(argv);
        step.required = required;
        s.push_back(step);
    };
    add({"ip", "link", "set", "dev", dev, "mtu", Num((uint32_t)INTERFACE_MTU), "up"}, true);
    add({"ip", "-4", "addr", "replace", Prefix(InterfaceAddress(4)), "dev", dev}, true);
    // IPv6 may be switched off on the computer; the IPv4 half still stands.
    add({"ip", "-6", "addr", "replace", Prefix(InterfaceAddress(6)), "dev", dev}, false);
    add({"ip", "-4", "route", "replace", "default", "dev", dev, "table", table}, true);
    add({"ip", "-6", "route", "replace", "default", "dev", dev, "table", table}, false);
    // The computer's own networks first: every main route but the default.
    add({"ip", "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", Num(ROUTE_PRIORITY)}, true);
    add({"ip", "-4", "rule", "add", "not", "fwmark", mark, "table", table, "priority", Num(ROUTE_PRIORITY + 1)}, true);
    add({"ip", "-6", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", Num(ROUTE_PRIORITY)}, false);
    add({"ip", "-6", "rule", "add", "not", "fwmark", mark, "table", table, "priority", Num(ROUTE_PRIORITY + 1)}, false);
    if (resolver) {
        add({"resolvectl", "dns", dev, InterfaceResolver(4).ToString(), InterfaceResolver(6).ToString()}, false);
        add({"resolvectl", "domain", dev, "~."}, false);
        add({"resolvectl", "default-route", dev, "true"}, false);
    }
    return s;
}

std::vector<RouteStep> PlanRoutesDown(const std::string& dev, bool resolver)
{
    const std::string table = Num(ROUTE_TABLE);
    std::vector<RouteStep> s;
    auto add = [&s](std::vector<std::string> argv) {
        RouteStep step;
        step.argv = std::move(argv);
        step.required = false;
        s.push_back(step);
    };
    if (resolver) add({"resolvectl", "revert", dev});
    for (const char* family : {"-4", "-6"}) {
        add({"ip", family, "rule", "del", "priority", Num(ROUTE_PRIORITY + 1)});
        add({"ip", family, "rule", "del", "priority", Num(ROUTE_PRIORITY)});
        add({"ip", family, "route", "flush", "table", table});
    }
    return s;
}

#ifdef __linux__
namespace {

constexpr int NET_ADMIN = 12; // CAP_NET_ADMIN

bool EffectiveNetAdmin()
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, data) != 0) return false;
    return (data[NET_ADMIN / 32].effective >> (NET_ADMIN % 32)) & 1;
}

/** Child side, between fork and exec: pass the right on to the one program run. Async-signal-safe calls only. */
void PassNetAdmin()
{
    if (geteuid() == 0) return; // root's children have it anyway
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, data) != 0) return;
    data[NET_ADMIN / 32].inheritable |= 1U << (NET_ADMIN % 32);
    if (syscall(SYS_capset, &hdr, data) != 0) return;
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, NET_ADMIN, 0, 0);
}

std::string FindProgram(const std::string& name)
{
    for (const char* dir : {"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"}) {
        const std::string path = dir + name;
        if (access(path.c_str(), X_OK) == 0) return path;
    }
    return "";
}

/** Run one step. Returns its exit status, -1 when it could not run; what it said on stderr in `said`. */
int Run(const RouteStep& step, std::string& said)
{
    said.clear();
    const std::string path = FindProgram(step.argv[0]);
    if (path.empty()) {
        said = step.argv[0] + " is not installed";
        return -1;
    }
    // Everything the child needs, made before forking: the child of a
    // threaded process may not allocate.
    std::vector<char*> argv;
    for (const std::string& a : step.argv) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    int err[2];
    if (pipe(err) != 0) return -1;
    const pid_t pid = fork();
    if (pid < 0) {
        close(err[0]);
        close(err[1]);
        return -1;
    }
    if (pid == 0) {
        const int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, 0);
            dup2(null, 1);
        }
        dup2(err[1], 2);
        close(err[0]);
        PassNetAdmin();
        execv(path.c_str(), argv.data());
        _exit(127);
    }
    close(err[1]);
    char buf[512];
    ssize_t n;
    while ((n = read(err[0], buf, sizeof(buf))) > 0) {
        if (said.size() < 1024) said.append(buf, (size_t)n);
    }
    close(err[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    while (!said.empty() && (said.back() == '\n' || said.back() == '\r')) said.pop_back();
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

std::string Joined(const std::vector<std::string>& argv)
{
    std::string out;
    for (const std::string& a : argv) out += (out.empty() ? "" : " ") + a;
    return out;
}

/** systemd-resolved runs, and this process is in the network namespace it manages. */
bool ResolvedHere()
{
    struct stat st;
    if (stat("/run/systemd/resolve", &st) != 0 || FindProgram("resolvectl").empty()) return false;
    struct stat mine, init;
    // Unreadable without rights over process 1: then assume the usual case.
    if (stat("/proc/self/ns/net", &mine) != 0 || stat("/proc/1/ns/net", &init) != 0) return true;
    return mine.st_ino == init.st_ino && mine.st_dev == init.st_dev;
}

void RunDown(const std::string& dev, bool resolver)
{
    std::string said;
    for (const RouteStep& step : PlanRoutesDown(dev, resolver)) {
        // A stale start can have left a rule twice.
        for (int i = 0; i < 4; ++i) {
            if (Run(step, said) != 0) break;
            if (step.argv.size() < 4 || step.argv[2] != "rule") break;
        }
    }
}

} // namespace
#endif

bool HaveNetAdmin(std::string& how)
{
#ifdef __linux__
    if (EffectiveNetAdmin()) return true;
    char exe[512];
    const ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    const std::string self = n > 0 ? std::string(exe, (size_t)n) : "<this program>";
    how = strprintf("let it manage the network once, as an administrator: sudo setcap cap_net_admin+ep %s", self);
    return false;
#elif defined(WIN32)
    bool running = false;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE service = OpenServiceW(scm, NET_SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS st;
            running = QueryServiceStatus(service, &st) && st.dwCurrentState == SERVICE_RUNNING;
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }
    if (!running) {
        how = "install BPS Relay's network service once, from the Server page (it asks for an administrator), "
              "or as an administrator: bps-relay-net install <your user SID>";
    }
    return running;
#else
    how = "not on this system yet";
    return false;
#endif
}

bool DefaultInterfaces(uint32_t& v4_index, uint32_t& v6_index)
{
    v4_index = v6_index = 0;
#ifdef WIN32
    // The interface the computer would use for the internet now, before any
    // route of the service's: asked of Windows, nothing is sent.
    struct sockaddr_in a4;
    std::memset(&a4, 0, sizeof(a4));
    a4.sin_family = AF_INET;
    a4.sin_addr.s_addr = htonl(0x01010101); // 1.1.1.1
    DWORD index = 0;
    if (GetBestInterfaceEx((struct sockaddr*)&a4, &index) == NO_ERROR) v4_index = index;
    struct sockaddr_in6 a6;
    std::memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    const uint8_t cf[16] = {0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
    std::memcpy(&a6.sin6_addr, cf, sizeof(cf));
    index = 0;
    if (GetBestInterfaceEx((struct sockaddr*)&a6, &index) == NO_ERROR) v6_index = index;
#endif
    return v4_index != 0 || v6_index != 0;
}

SystemRoutes::~SystemRoutes()
{
    Undo();
}

bool SystemRoutes::Apply(const std::string& dev, std::string& error)
{
#ifdef __linux__
    std::string how;
    if (!HaveNetAdmin(how)) {
        error = "routing the computer through the interface needs the right to manage the network: " + how;
        return false;
    }
    m_dev = dev;
    m_resolver = ResolvedHere();
    RunDown(dev, m_resolver);
    std::string said;
    for (const RouteStep& step : PlanRoutesUp(dev, m_resolver)) {
        const int rc = Run(step, said);
        if (rc == 0) continue;
        LogPrintf("system routes: \"%s\" failed (%d): %s\n", Joined(step.argv), rc, said);
        if (step.required) {
            RunDown(dev, m_resolver);
            error = strprintf("cannot route the computer through %s: \"%s\" said: %s", dev, Joined(step.argv),
                              said.empty() ? "nothing" : said);
            return false;
        }
    }
    m_active = true;
    LogPrintf("system routes: this computer's traffic goes through %s, apart from its own networks and the node's own "
              "sockets%s\n", dev, m_resolver ? "; its resolver asks the interface" : "");
    return true;
#else
    (void)dev;
    error = "routing the computer through the interface is not available on this system yet";
    return false;
#endif
}

void SystemRoutes::Undo()
{
#ifdef __linux__
    if (!m_active) return;
    m_active = false;
    RunDown(m_dev, m_resolver);
    LogPrintf("system routes: taken down; this computer is back on its own line\n");
#endif
}

} // namespace overlay
