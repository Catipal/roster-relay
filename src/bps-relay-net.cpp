// Copyright (c) 2026 The Bitcoin PoS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * BPS Relay's network service on Windows (design note §8·7).
 *
 * The system-wide interface needs an administrator on
 * Windows, and a small service installed once provides it, so that BPS Relay
 * itself never runs with those rights. This is that service. It is part of
 * BPS Relay, installed from BPS Relay's Server page, and does one thing:
 *
 *  - it owns a Wintun adapter, "BPS Relay", with the interface's addresses
 *    (10.77.1.2, fd62:7073:6966::2), a packet size of 1,280 and the
 *    interface's resolver (10.77.1.53);
 *  - it passes IP packets between that adapter and BPS Relay over a named
 *    pipe that only SYSTEM and the user who installed it may open;
 *  - while BPS Relay asks for it, it routes the whole computer through the
 *    adapter (0.0.0.0/1 and 128.0.0.0/1, ::/1 and 8000::/1 - more specific
 *    than any default route, less than the computer's own networks), and
 *    takes those routes down the moment BPS Relay goes.
 *
 * BPS Relay's own connections pass the adapter by: it binds them to the
 * computer's own interface (IP_UNICAST_IF), which no route can redirect.
 *
 * Usage, as an administrator:
 *   bps-relay-net.exe install <user SID>   copy itself and wintun.dll to
 *                                          %ProgramFiles%\BPS Relay\network,
 *                                          register and start the service
 *   bps-relay-net.exe uninstall            stop and remove it
 * The service itself is started by Windows.
 *
 * Wintun is WireGuard LLC's driver, used only through wintun.h
 * (src/wintun/README.md).
 */

#ifndef WIN32
#error "bps-relay-net is the Windows network service"
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <overlay/netservice.h>
#include <wintun/wintun.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifndef PIPE_REJECT_REMOTE_CLIENTS
#define PIPE_REJECT_REMOTE_CLIENTS 0x00000008
#endif

using namespace overlay;

namespace {

const wchar_t* const DISPLAY_NAME = L"BPS Relay network";
const wchar_t* const DESCRIPTION =
    L"Lets BPS Relay carry this computer's traffic through the network's gateways: owns the \"BPS Relay\" "
    L"network adapter and, while BPS Relay asks, the routes through it.";
const wchar_t* const PARAMETERS_KEY = L"SYSTEM\\CurrentControlSet\\Services\\BPSRelayNet\\Parameters";
const wchar_t* const TUNNEL_TYPE = L"BPS Relay";
// Fixed, so Windows keeps one network profile for the adapter rather than a new one each start.
const GUID ADAPTER_GUID = {0x62707372, 0x656c, 0x6179, {0x8e, 0x74, 0x5a, 0x0b, 0x9c, 0x31, 0x77, 0x01}};
const DWORD RING_CAPACITY = 0x400000; // 4 MiB

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status;
HANDLE g_stop = nullptr;

// --- the log ---------------------------------------------------------------

std::wstring LogPath()
{
    wchar_t base[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, base))) return L"";
    std::wstring dir = std::wstring(base) + L"\\BPS Relay";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\network.log";
}

void Log(const std::string& line)
{
    static const std::wstring path = LogPath();
    if (path.empty()) return;
    WIN32_FILE_ATTRIBUTE_DATA info;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info) && info.nFileSizeLow > (1u << 20)) {
        DeleteFileW(path.c_str());
    }
    FILE* f = _wfopen(path.c_str(), L"ab");
    if (!f) return;
    SYSTEMTIME t;
    GetSystemTime(&t);
    fprintf(f, "%04u-%02u-%02uT%02u:%02u:%02uZ %s\r\n", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
            line.c_str());
    fclose(f);
}

std::string Narrow(const std::wstring& w)
{
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, nullptr, nullptr);
    return out;
}

std::string LastError(DWORD err = GetLastError())
{
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   err, 0, (LPWSTR)&buf, 0, nullptr);
    std::string out = buf ? Narrow(buf) : "error " + std::to_string(err);
    if (buf) LocalFree(buf);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

// --- Wintun, loaded from beside this program ------------------------------------

struct Wintun {
    HMODULE dll{nullptr};
    WINTUN_CREATE_ADAPTER_FUNC* Create{nullptr};
    WINTUN_OPEN_ADAPTER_FUNC* Open{nullptr};
    WINTUN_CLOSE_ADAPTER_FUNC* Close{nullptr};
    WINTUN_START_SESSION_FUNC* StartSession{nullptr};
    WINTUN_END_SESSION_FUNC* EndSession{nullptr};
    WINTUN_GET_READ_WAIT_EVENT_FUNC* ReadWaitEvent{nullptr};
    WINTUN_RECEIVE_PACKET_FUNC* Receive{nullptr};
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* Release{nullptr};
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* Allocate{nullptr};
    WINTUN_SEND_PACKET_FUNC* Send{nullptr};

    bool Load(const std::wstring& dir)
    {
        const std::wstring path = dir + L"\\wintun.dll";
        dll = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!dll) {
            Log("cannot load " + Narrow(path) + ": " + LastError());
            return false;
        }
#define BPS_WINTUN(field, name) field = (decltype(field))(void*)GetProcAddress(dll, name)
        BPS_WINTUN(Create, "WintunCreateAdapter");
        BPS_WINTUN(Open, "WintunOpenAdapter");
        BPS_WINTUN(Close, "WintunCloseAdapter");
        BPS_WINTUN(StartSession, "WintunStartSession");
        BPS_WINTUN(EndSession, "WintunEndSession");
        BPS_WINTUN(ReadWaitEvent, "WintunGetReadWaitEvent");
        BPS_WINTUN(Receive, "WintunReceivePacket");
        BPS_WINTUN(Release, "WintunReleaseReceivePacket");
        BPS_WINTUN(Allocate, "WintunAllocateSendPacket");
        BPS_WINTUN(Send, "WintunSendPacket");
#undef BPS_WINTUN
        if (!Create || !Open || !Close || !StartSession || !EndSession || !ReadWaitEvent || !Receive || !Release ||
            !Allocate || !Send) {
            Log("wintun.dll lacks a function this service needs");
            return false;
        }
        return true;
    }
};

std::wstring OwnDirectory()
{
    wchar_t path[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p(path, n);
    const size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

// --- netsh, for the adapter's addresses and the routes ---------------------------

bool Netsh(const std::wstring& args)
{
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring cmd = L"\"" + std::wstring(sys) + L"\\netsh.exe\" " + args;
    std::vector<wchar_t> line(cmd.begin(), cmd.end());
    line.push_back(0);
    STARTUPINFOW si;
    std::memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(nullptr, line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        Log("cannot run netsh: " + LastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (code != 0) Log("netsh " + Narrow(args) + " exited with " + std::to_string(code));
    return code == 0;
}

const std::wstring ADAPTER_ARG = L"\"BPS Relay\"";

void ConfigureAdapter()
{
    Netsh(L"interface ipv4 set address name=" + ADAPTER_ARG + L" source=static address=10.77.1.2 mask=255.255.255.255");
    Netsh(L"interface ipv4 set subinterface " + ADAPTER_ARG + L" mtu=1280 store=active");
    Netsh(L"interface ipv4 set interface " + ADAPTER_ARG + L" metric=1");
    Netsh(L"interface ipv4 set dnsservers name=" + ADAPTER_ARG + L" source=static address=10.77.1.53 register=none validate=no");
    Netsh(L"interface ipv6 add address " + ADAPTER_ARG + L" fd62:7073:6966::2/128 store=active");
    Netsh(L"interface ipv6 set subinterface " + ADAPTER_ARG + L" mtu=1280 store=active");
    Netsh(L"interface ipv6 set dnsservers name=" + ADAPTER_ARG + L" source=static address=fd62:7073:6966::53 register=none validate=no");
}

const wchar_t* const ROUTES4[] = {L"0.0.0.0/1", L"128.0.0.0/1"};
const wchar_t* const ROUTES6[] = {L"::/1", L"8000::/1"};

void Routes(bool add)
{
    const std::wstring verb = add ? L"add" : L"delete";
    for (const wchar_t* r : ROUTES4) {
        Netsh(L"interface ipv4 " + verb + L" route prefix=" + r + L" interface=" + ADAPTER_ARG + (add ? L" metric=0" : L"") + L" store=active");
    }
    for (const wchar_t* r : ROUTES6) {
        Netsh(L"interface ipv6 " + verb + L" route prefix=" + r + L" interface=" + ADAPTER_ARG + (add ? L" metric=0" : L"") + L" store=active");
    }
    Log(add ? "routes up: this computer's traffic goes through the BPS Relay adapter" : "routes down");
}

// --- the pipe ---------------------------------------------------------------------

std::wstring AllowedUser()
{
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PARAMETERS_KEY, 0, KEY_READ, &key) != ERROR_SUCCESS) return L"";
    wchar_t buf[256];
    DWORD size = sizeof(buf), type = 0;
    std::wstring out;
    if (RegQueryValueExW(key, L"AllowedUser", nullptr, &type, (BYTE*)buf, &size) == ERROR_SUCCESS && type == REG_SZ) {
        out.assign(buf, size / sizeof(wchar_t));
        while (!out.empty() && out.back() == 0) out.pop_back();
    }
    RegCloseKey(key);
    return out;
}

HANDLE MakePipe(const std::wstring& sid)
{
    // SYSTEM, and the one user it was installed for; nobody else, and
    // nothing from another computer.
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GRGW;;;" + sid + L")";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        Log("cannot make the pipe's permissions: " + LastError());
        return INVALID_HANDLE_VALUE;
    }
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    HANDLE pipe = CreateNamedPipeW(NET_SERVICE_PIPE, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                                   1 << 20, 1 << 20, 0, &sa);
    LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) Log("cannot make the pipe: " + LastError());
    return pipe;
}

/** Wait for an overlapped operation, or for `stop`/`gone`. False when it did not finish. */
bool Finish(HANDLE pipe, OVERLAPPED& ov, HANDLE gone, DWORD& done)
{
    HANDLE waits[3] = {ov.hEvent, g_stop, gone};
    const DWORD n = gone ? 3 : 2;
    const DWORD r = WaitForMultipleObjects(n, waits, FALSE, INFINITE);
    if (r != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        GetOverlappedResult(pipe, &ov, &done, TRUE);
        return false;
    }
    return GetOverlappedResult(pipe, &ov, &done, FALSE) != 0;
}

bool ReadExact(HANDLE pipe, uint8_t* buf, size_t len, HANDLE gone)
{
    OVERLAPPED ov;
    std::memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    size_t got = 0;
    bool ok = true;
    while (got < len && ok) {
        ResetEvent(ov.hEvent);
        DWORD done = 0;
        if (!ReadFile(pipe, buf + got, (DWORD)(len - got), &done, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING || !Finish(pipe, ov, gone, done)) ok = false;
        }
        if (ok && done == 0) ok = false;
        got += done;
    }
    CloseHandle(ov.hEvent);
    return ok;
}

bool WriteFrame(HANDLE pipe, uint8_t type, const uint8_t* data, size_t len, HANDLE gone)
{
    if (len > NS_MAX_FRAME) return false;
    std::vector<uint8_t> frame(NS_HEADER + len);
    frame[0] = type;
    frame[1] = 0;
    frame[2] = (uint8_t)(len & 0xff);
    frame[3] = (uint8_t)(len >> 8);
    if (len) std::memcpy(frame.data() + NS_HEADER, data, len);
    OVERLAPPED ov;
    std::memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD done = 0;
    bool ok = WriteFile(pipe, frame.data(), (DWORD)frame.size(), &done, &ov) != 0;
    if (!ok && GetLastError() == ERROR_IO_PENDING) ok = Finish(pipe, ov, gone, done);
    CloseHandle(ov.hEvent);
    return ok && done == frame.size();
}

void Note(HANDLE pipe, const std::string& text)
{
    WriteFrame(pipe, NS_NOTE, (const uint8_t*)text.data(), text.size(), nullptr);
}

/** One BPS Relay, from its HELLO until it goes. */
void Serve(const Wintun& wt, WINTUN_ADAPTER_HANDLE adapter, HANDLE pipe)
{
    uint8_t header[NS_HEADER];
    if (!ReadExact(pipe, header, sizeof(header), nullptr) || header[0] != NS_HELLO) return;
    const size_t hello_len = header[2] | (header[3] << 8);
    std::vector<uint8_t> hello(hello_len);
    if (hello_len && !ReadExact(pipe, hello.data(), hello_len, nullptr)) return;
    const bool route = hello_len >= 1 && (hello[0] & NS_ROUTE_COMPUTER);

    WINTUN_SESSION_HANDLE session = wt.StartSession(adapter, RING_CAPACITY);
    if (!session) {
        Note(pipe, "the service cannot open the adapter: " + LastError());
        return;
    }
    ConfigureAdapter();
    if (route) Routes(true);
    Note(pipe, route ? "adapter ready; this computer's traffic goes through it" : "adapter ready");
    Log("BPS Relay connected");

    HANDLE gone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread to_relay([&] {
        while (WaitForSingleObject(gone, 0) == WAIT_TIMEOUT && WaitForSingleObject(g_stop, 0) == WAIT_TIMEOUT) {
            DWORD size = 0;
            BYTE* packet = wt.Receive(session, &size);
            if (packet) {
                const bool ok = WriteFrame(pipe, NS_PACKET, packet, size, gone);
                wt.Release(session, packet);
                if (!ok) SetEvent(gone);
                continue;
            }
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                SetEvent(gone);
                break;
            }
            HANDLE waits[3] = {wt.ReadWaitEvent(session), gone, g_stop};
            WaitForMultipleObjects(3, waits, FALSE, INFINITE);
        }
    });
    std::vector<uint8_t> buf;
    while (true) {
        if (!ReadExact(pipe, header, sizeof(header), gone)) break;
        const size_t len = header[2] | (header[3] << 8);
        buf.resize(len);
        if (len && !ReadExact(pipe, buf.data(), len, gone)) break;
        if (header[0] != NS_PACKET || len == 0) continue;
        BYTE* out = wt.Allocate(session, (DWORD)len);
        if (!out) continue; // ring full: dropped, as a busy link drops
        std::memcpy(out, buf.data(), len);
        wt.Send(session, out);
    }
    SetEvent(gone);
    to_relay.join();
    CloseHandle(gone);
    if (route) Routes(false);
    wt.EndSession(session);
    Log("BPS Relay disconnected");
}

void Run()
{
    Wintun wt;
    if (!wt.Load(OwnDirectory())) return;
    WINTUN_ADAPTER_HANDLE adapter = wt.Open(NET_SERVICE_ADAPTER);
    if (!adapter) adapter = wt.Create(NET_SERVICE_ADAPTER, TUNNEL_TYPE, &ADAPTER_GUID);
    if (!adapter) {
        Log("cannot make the BPS Relay adapter: " + LastError());
        WaitForSingleObject(g_stop, INFINITE);
        return;
    }
    const std::wstring sid = AllowedUser();
    if (sid.empty()) {
        Log("no user is allowed to use the service; install it again from BPS Relay");
        WaitForSingleObject(g_stop, INFINITE);
        wt.Close(adapter);
        return;
    }
    while (WaitForSingleObject(g_stop, 0) == WAIT_TIMEOUT) {
        HANDLE pipe = MakePipe(sid);
        if (pipe == INVALID_HANDLE_VALUE) {
            WaitForSingleObject(g_stop, 5000);
            continue;
        }
        OVERLAPPED ov;
        std::memset(&ov, 0, sizeof(ov));
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        bool connected = ConnectNamedPipe(pipe, &ov) != 0;
        if (!connected) {
            const DWORD err = GetLastError();
            DWORD done = 0;
            connected = err == ERROR_PIPE_CONNECTED || (err == ERROR_IO_PENDING && Finish(pipe, ov, nullptr, done));
        }
        CloseHandle(ov.hEvent);
        if (connected) Serve(wt, adapter, pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    wt.Close(adapter);
}

void SetStatus(DWORD state, DWORD exit_code = NO_ERROR)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwWaitHint = 10000;
    SetServiceStatus(g_status_handle, &g_status);
}

DWORD WINAPI Control(DWORD control, DWORD, LPVOID, LPVOID)
{
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        SetStatus(SERVICE_STOP_PENDING);
        SetEvent(g_stop);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_status_handle = RegisterServiceCtrlHandlerExW(NET_SERVICE_NAME, Control, nullptr);
    if (!g_status_handle) return;
    std::memset(&g_status, 0, sizeof(g_status));
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetStatus(SERVICE_RUNNING);
    Log("service started");
    Run();
    Log("service stopped");
    SetStatus(SERVICE_STOPPED);
}

// --- install and uninstall ---------------------------------------------------------

std::wstring InstallDirectory()
{
    wchar_t base[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, base))) return L"";
    return std::wstring(base) + L"\\BPS Relay\\network";
}

bool StopService(SC_HANDLE service)
{
    SERVICE_STATUS st;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &st) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) return false;
    for (int i = 0; i < 100; ++i) {
        if (!QueryServiceStatus(service, &st) || st.dwCurrentState == SERVICE_STOPPED) return true;
        Sleep(100);
    }
    return false;
}

int Install(const std::wstring& sid_text)
{
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sid_text.c_str(), &sid)) {
        fprintf(stderr, "not a user's SID: %s\n", Narrow(sid_text).c_str());
        return 2;
    }
    LocalFree(sid);
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        fprintf(stderr, "installing the service needs an administrator: %s\n", LastError().c_str());
        return 3;
    }
    // From a folder only administrators can write to: a program that runs as
    // SYSTEM must not be one an ordinary user could swap.
    const std::wstring dir = InstallDirectory();
    const std::wstring parent = dir.substr(0, dir.find_last_of(L'\\'));
    CreateDirectoryW(parent.c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    SC_HANDLE existing = OpenServiceW(scm, NET_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (existing) StopService(existing);
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const std::wstring exe = dir + L"\\bps-relay-net.exe";
    const std::wstring dll = dir + L"\\wintun.dll";
    if ((_wcsicmp(self, exe.c_str()) != 0 && !CopyFileW(self, exe.c_str(), FALSE)) ||
        !CopyFileW((OwnDirectory() + L"\\wintun.dll").c_str(), dll.c_str(), FALSE)) {
        fprintf(stderr, "cannot copy the service and wintun.dll to %s: %s\n", Narrow(dir).c_str(), LastError().c_str());
        if (existing) CloseServiceHandle(existing);
        CloseServiceHandle(scm);
        return 4;
    }
    HKEY key;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, PARAMETERS_KEY, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"AllowedUser", 0, REG_SZ, (const BYTE*)sid_text.c_str(),
                       (DWORD)((sid_text.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
    }
    const std::wstring command = L"\"" + exe + L"\"";
    SC_HANDLE service = existing;
    if (service) {
        ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(),
                             nullptr, nullptr, nullptr, nullptr, nullptr, DISPLAY_NAME);
    } else {
        service = CreateServiceW(scm, NET_SERVICE_NAME, DISPLAY_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr,
                                 nullptr, nullptr);
    }
    if (!service) {
        fprintf(stderr, "cannot register the service: %s\n", LastError().c_str());
        CloseServiceHandle(scm);
        return 5;
    }
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(DESCRIPTION);
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);
    const bool started = StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    if (!started) {
        fprintf(stderr, "the service is installed but did not start: %s\n", LastError().c_str());
        return 6;
    }
    printf("installed in %s and started\n", Narrow(dir).c_str());
    return 0;
}

int Uninstall()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        fprintf(stderr, "removing the service needs an administrator: %s\n", LastError().c_str());
        return 3;
    }
    SC_HANDLE service = OpenServiceW(scm, NET_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service) {
        StopService(service);
        DeleteService(service);
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, PARAMETERS_KEY);
    const std::wstring dir = InstallDirectory();
    for (const wchar_t* f : {L"\\bps-relay-net.exe", L"\\wintun.dll"}) {
        const std::wstring path = dir + f;
        if (!DeleteFileW(path.c_str())) MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    printf("removed\n");
    return 0;
}

} // namespace

int main()
{
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;
    if (argc >= 2 && _wcsicmp(argv[1], L"install") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: bps-relay-net install <the SID of the user who runs BPS Relay>\n");
            return 2;
        }
        return Install(argv[2]);
    }
    if (argc >= 2 && _wcsicmp(argv[1], L"uninstall") == 0) return Uninstall();
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(NET_SERVICE_NAME), ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        fprintf(stderr, "bps-relay-net is BPS Relay's network service on Windows; Windows starts it.\n"
                        "To install it, as an administrator: bps-relay-net install <user SID>\n"
                        "To remove it: bps-relay-net uninstall\n");
        return 1;
    }
    return 0;
}
