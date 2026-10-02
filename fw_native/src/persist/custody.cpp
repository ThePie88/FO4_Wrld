#include "custody.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../config.h"
#include "../log.h"

#pragma comment(lib, "ws2_32.lib")

namespace fw::persist::custody {

namespace {

constexpr std::size_t   kHeaderLen   = 128;
constexpr std::size_t   kReplyLen    = 16;
constexpr std::uint8_t  kVersion     = 1;
constexpr std::uint8_t  kOpPut       = 1;
constexpr std::uint8_t  kOpGet       = 2;
constexpr std::uint32_t kMaxSave     = 256u * 1024u * 1024u;   // the record's own ceiling
constexpr std::uint32_t kMaxManifest = 1024u * 1024u;
constexpr int           kConnectMs   = 5000;
constexpr DWORD         kIoMs        = 30000;
constexpr int           kAttempts    = 2;
constexpr DWORD         kRetryMs     = 3000;

struct Job {
    std::string   name;
    std::uint8_t  sha[32] = {};
    std::uint32_t size = 0;
    std::wstring  fos;
    std::wstring  manifest;
};

std::mutex               g_mx;
std::condition_variable  g_cv;
std::string              g_host;
std::uint16_t            g_port = 0;
std::uint8_t             g_token[32] = {};
bool                     g_have_token = false;
bool                     g_wsa = false;
std::deque<Job>          g_jobs;
bool                     g_busy = false;
bool                     g_stop = false;
bool                     g_worker_started = false;   // the thread is detached: never a joinable global
std::vector<std::string> g_uploaded;                 // names the server holds since this process started

const char* status_name(int s) noexcept {
    switch (s) {
    case 0: return "ok";
    case 1: return "bad request";
    case 2: return "bad token";
    case 3: return "not this peer's checkpoint";
    case 4: return "sha256 mismatch";
    case 5: return "not in custody";
    case 6: return "too big";
    case 7: return "server error";
    default: return "?";
    }
}

bool read_file(const std::wstring& path, std::vector<std::uint8_t>& out) {
    out.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > kMaxSave) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<std::size_t>(sz.QuadPart));
    std::size_t done = 0;
    while (done < out.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(out.size() - done, 1u << 20));
        if (!ReadFile(h, out.data() + done, want, &got, nullptr) || got == 0) {
            CloseHandle(h);
            return false;
        }
        done += got;
    }
    CloseHandle(h);
    return true;
}

bool write_file(const std::wstring& path, const std::uint8_t* data, std::size_t n) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::size_t done = 0;
    while (done < n) {
        DWORD put = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(n - done, 1u << 20));
        if (!WriteFile(h, data + done, want, &put, nullptr) || put == 0) {
            CloseHandle(h);
            return false;
        }
        done += put;
    }
    FlushFileBuffers(h);
    CloseHandle(h);
    return true;
}

// A connected, blocking socket with I/O timeouts, or INVALID_SOCKET (err
// says why). The connect itself is bounded by select: a blocking connect
// to a dead address would sit for the TCP retry time.
SOCKET connect_to(const std::string& host, std::uint16_t port, char* err, std::size_t n) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char ps[8];
    std::snprintf(ps, sizeof(ps), "%u", unsigned(port));
    addrinfo* res = nullptr;
    const int rc = getaddrinfo(host.c_str(), ps, &hints, &res);
    if (rc != 0 || !res) {
        std::snprintf(err, n, "getaddrinfo(%s) failed: %d", host.c_str(), rc);
        return INVALID_SOCKET;
    }
    SOCKET s = INVALID_SOCKET;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int c = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (c == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            fd_set ef;
            FD_ZERO(&ef);
            FD_SET(s, &ef);
            timeval tv{ kConnectMs / 1000, (kConnectMs % 1000) * 1000 };
            const int sel = select(0, nullptr, &wf, &ef, &tv);
            int soerr = 0;
            int sl = sizeof(soerr);
            if (sel > 0 && FD_ISSET(s, &wf)
                    && getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &sl) == 0
                    && soerr == 0) {
                c = 0;
            } else {
                c = SOCKET_ERROR;
            }
        }
        if (c == 0) {
            nb = 0;
            ioctlsocket(s, FIONBIO, &nb);
            const DWORD to = kIoMs;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
            break;
        }
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) {
        std::snprintf(err, n, "connect to %s:%u failed (%d ms)", host.c_str(), unsigned(port), kConnectMs);
    }
    return s;
}

bool send_all(SOCKET s, const void* p, std::size_t n) {
    const char* c = static_cast<const char*>(p);
    while (n) {
        const int chunk = static_cast<int>(std::min<std::size_t>(n, 1u << 20));
        const int w = send(s, c, chunk, 0);
        if (w <= 0) return false;
        c += w;
        n -= static_cast<std::size_t>(w);
    }
    return true;
}

bool recv_all(SOCKET s, void* p, std::size_t n) {
    char* c = static_cast<char*>(p);
    while (n) {
        const int chunk = static_cast<int>(std::min<std::size_t>(n, 1u << 20));
        const int r = recv(s, c, chunk, 0);
        if (r <= 0) return false;
        c += r;
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

void make_header(std::uint8_t* h, std::uint8_t op, const std::uint8_t token[32], const char* name,
                 const std::uint8_t sha[32], std::uint32_t size, std::uint32_t mlen) {
    std::memset(h, 0, kHeaderLen);
    std::memcpy(h, "FWBK", 4);
    h[4] = kVersion;
    h[5] = op;
    std::memcpy(h + 8, token, 32);
    std::snprintf(reinterpret_cast<char*>(h + 40), 48, "%s", name);
    std::memcpy(h + 88, sha, 32);
    std::memcpy(h + 120, &size, 4);
    std::memcpy(h + 124, &mlen, 4);
}

bool parse_reply(const std::uint8_t* r, std::uint8_t* status, std::uint32_t* size, std::uint32_t* mlen) {
    if (std::memcmp(r, "FWBR", 4) != 0) return false;
    *status = r[4];
    std::memcpy(size, r + 8, 4);
    std::memcpy(mlen, r + 12, 4);
    return true;
}

// One PUT: the server's status (0 = held), or -1 when the transfer itself
// failed (err says why).
int do_put(const Job& j, const std::string& host, std::uint16_t port, const std::uint8_t token[32],
           char* err, std::size_t n) {
    std::vector<std::uint8_t> fos, man;
    if (!read_file(j.fos, fos) || fos.empty()) {
        std::snprintf(err, n, "the save could not be read");
        return -1;
    }
    if (fos.size() != j.size) {
        std::snprintf(err, n, "the save is %zu bytes on disk, %u on record", fos.size(), j.size);
        return -1;
    }
    if (!j.manifest.empty()) (void)read_file(j.manifest, man);   // optional
    if (man.size() > kMaxManifest) man.clear();
    SOCKET s = connect_to(host, port, err, n);
    if (s == INVALID_SOCKET) return -1;
    std::uint8_t h[kHeaderLen];
    make_header(h, kOpPut, token, j.name.c_str(), j.sha, static_cast<std::uint32_t>(fos.size()),
                static_cast<std::uint32_t>(man.size()));
    std::uint8_t r[kReplyLen] = {};
    std::uint8_t status = 0;
    std::uint32_t rs = 0, rm = 0;
    const bool ok = send_all(s, h, kHeaderLen)
                 && send_all(s, fos.data(), fos.size())
                 && (man.empty() || send_all(s, man.data(), man.size()))
                 && recv_all(s, r, kReplyLen)
                 && parse_reply(r, &status, &rs, &rm);
    const int wsa = ok ? 0 : WSAGetLastError();
    closesocket(s);
    if (!ok) {
        std::snprintf(err, n, "the transfer broke off (winsock %d)", wsa);
        return -1;
    }
    return status;
}

// One GET into the .part file. 0 = fetched, 2 = refused, 3 = failed.
int do_get(const char* name, const std::uint8_t sha[32], std::uint32_t size, const std::string& host,
           std::uint16_t port, const std::uint8_t token[32], const wchar_t* part_path,
           const wchar_t* manifest_path, char* err, std::size_t n) {
    SOCKET s = connect_to(host, port, err, n);
    if (s == INVALID_SOCKET) return 3;
    std::uint8_t h[kHeaderLen];
    make_header(h, kOpGet, token, name, sha, 0, 0);
    std::uint8_t r[kReplyLen] = {};
    std::uint8_t status = 0;
    std::uint32_t rs = 0, rm = 0;
    if (!send_all(s, h, kHeaderLen) || !recv_all(s, r, kReplyLen) || !parse_reply(r, &status, &rs, &rm)) {
        const int wsa = WSAGetLastError();
        closesocket(s);
        std::snprintf(err, n, "the transfer broke off (winsock %d)", wsa);
        return 3;
    }
    if (status != 0) {
        closesocket(s);
        std::snprintf(err, n, "the server answered: %s", status_name(status));
        return 2;
    }
    if (rs == 0 || rs != size || rs > kMaxSave || rm > kMaxManifest) {
        closesocket(s);
        std::snprintf(err, n, "the server offers %u bytes, the record says %u", rs, size);
        return 3;
    }
    std::vector<std::uint8_t> fos(rs), man(rm);
    const bool ok = recv_all(s, fos.data(), fos.size()) && (rm == 0 || recv_all(s, man.data(), man.size()));
    const int wsa = ok ? 0 : WSAGetLastError();
    closesocket(s);
    if (!ok) {
        std::snprintf(err, n, "the transfer broke off after %u bytes (winsock %d)", rs, wsa);
        return 3;
    }
    if (!write_file(part_path, fos.data(), fos.size())) {
        std::snprintf(err, n, "the fetched save could not be written (error %lu)", GetLastError());
        return 3;
    }
    if (rm && manifest_path && *manifest_path) {
        if (!write_file(manifest_path, man.data(), man.size())) {
            FW_WRN("[custody] the world manifest of '%s' could not be written: its saved copies "
                   "will not be purged", name);
        }
    }
    return 0;
}

void worker_main() {
    for (;;) {
        Job j;
        std::string host;
        std::uint16_t port = 0;
        std::uint8_t token[32];
        {
            std::unique_lock<std::mutex> lk(g_mx);
            g_cv.wait(lk, [] { return g_stop || !g_jobs.empty(); });
            if (g_stop) return;
            j = std::move(g_jobs.front());
            g_jobs.pop_front();
            g_busy = true;
            host = g_host;
            port = g_port;
            std::memcpy(token, g_token, sizeof(token));
        }
        const ULONGLONG t0 = GetTickCount64();
        int status = -1;
        char err[160] = "";
        for (int attempt = 1; attempt <= kAttempts; ++attempt) {
            status = do_put(j, host, port, token, err, sizeof(err));
            if (status == 0) break;
            if (status == -1 && attempt < kAttempts) {
                FW_WRN("[custody] upload of '%s' (attempt %d) failed: %s; again in %lu ms",
                       j.name.c_str(), attempt, err, kRetryMs);
                Sleep(kRetryMs);
                continue;
            }
            break;
        }
        const unsigned ms = static_cast<unsigned>(GetTickCount64() - t0);
        {
            std::lock_guard<std::mutex> lk(g_mx);
            g_busy = false;
            if (status == 0) g_uploaded.push_back(j.name);
        }
        if (status == 0) {
            FW_LOG("[custody] '%s' uploaded: %u bytes in %u ms, the server holds it now",
                   j.name.c_str(), j.size, ms);
        } else if (status > 0) {
            FW_WRN("[custody] upload of '%s' REFUSED by the server: %s", j.name.c_str(),
                   status_name(status));
        } else {
            FW_WRN("[custody] upload of '%s' failed: %s (it stays on this disk; the next session "
                   "tries again)", j.name.c_str(), err);
        }
        g_cv.notify_all();
    }
}

bool service_locked() noexcept {
    return g_wsa && g_port != 0 && g_have_token && !g_host.empty();
}

} // namespace

void configure(const fw::config::Settings& cfg) {
    std::lock_guard<std::mutex> lk(g_mx);
    g_host = cfg.server_host;
    if (!g_wsa) {
        WSADATA d{};
        g_wsa = WSAStartup(MAKEWORD(2, 2), &d) == 0;
        if (!g_wsa) FW_WRN("[custody] WSAStartup failed: no checkpoint transfers this session");
    }
    FW_LOG("[custody] transport armed for %s: the bulk port and the token come with the boot word",
           g_host.c_str());
}

void set_word(std::uint16_t bulk_port, const std::uint8_t token[32]) {
    bool any = false;
    for (int i = 0; i < 32; ++i) any = any || token[i] != 0;
    std::lock_guard<std::mutex> lk(g_mx);
    g_port = bulk_port;
    if (any) {
        std::memcpy(g_token, token, sizeof(g_token));
        g_have_token = true;
    } else {
        g_have_token = false;
    }
}

bool available() {
    std::lock_guard<std::mutex> lk(g_mx);
    return service_locked();
}

void enqueue_upload(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
                    const wchar_t* fos_path, const wchar_t* manifest_path) {
    if (!name || !*name || !fos_path) return;
    std::lock_guard<std::mutex> lk(g_mx);
    if (!service_locked()) {
        FW_LOG("[custody] '%s' stays on this disk: no custody service this session", name);
        return;
    }
    for (const Job& j : g_jobs) if (j.name == name) return;
    for (const std::string& u : g_uploaded) if (u == name) return;
    Job j;
    j.name = name;
    std::memcpy(j.sha, sha256, sizeof(j.sha));
    j.size = size;
    j.fos = fos_path;
    j.manifest = manifest_path ? manifest_path : L"";
    g_jobs.push_back(std::move(j));
    if (!g_worker_started) {
        g_worker_started = true;
        std::thread(worker_main).detach();
    }
    g_cv.notify_all();
}

bool wait_idle(unsigned ms) {
    std::unique_lock<std::mutex> lk(g_mx);
    if (g_jobs.empty() && !g_busy) return true;
    const std::size_t pending = g_jobs.size() + (g_busy ? 1u : 0u);
    FW_LOG("[custody] waiting up to %u ms for %zu upload(s) to finish", ms, pending);
    const bool idle = g_cv.wait_for(lk, std::chrono::milliseconds(ms),
                                    [] { return g_jobs.empty() && !g_busy; });
    if (!idle) {
        FW_WRN("[custody] %zu upload(s) still pending after %u ms: the next session uploads them",
               g_jobs.size() + (g_busy ? 1u : 0u), ms);
    }
    return idle;
}

int fetch(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
          const wchar_t* fos_part_path, const wchar_t* manifest_path,
          char* why, std::size_t why_len) {
    if (why && why_len) why[0] = '\0';
    std::string host;
    std::uint16_t port = 0;
    std::uint8_t token[32];
    {
        std::lock_guard<std::mutex> lk(g_mx);
        if (!service_locked()) {
            if (why) std::snprintf(why, why_len, "no custody service");
            return 1;
        }
        host = g_host;
        port = g_port;
        std::memcpy(token, g_token, sizeof(token));
    }
    char err[160] = "";
    const int rc = do_get(name, sha256, size, host, port, token, fos_part_path, manifest_path,
                          err, sizeof(err));
    if (rc != 0 && why) std::snprintf(why, why_len, "%s", err);
    return rc;
}

void stop() {
    std::lock_guard<std::mutex> lk(g_mx);
    g_stop = true;
    g_cv.notify_all();
}

} // namespace fw::persist::custody
