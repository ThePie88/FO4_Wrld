#include "udp_socket.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
#include <mutex>
#include <string>

#include "../log.h"

#pragma comment(lib, "ws2_32.lib")

namespace fw::net {

namespace {

std::mutex g_wsa_mutex;
int g_wsa_refcount = 0;

bool wsa_startup_once() {
    std::lock_guard lk(g_wsa_mutex);
    if (g_wsa_refcount == 0) {
        WSADATA d{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &d);
        if (rc != 0) {
            FW_ERR("net: WSAStartup failed: %d", rc);
            return false;
        }
    }
    ++g_wsa_refcount;
    return true;
}

void wsa_cleanup_once() {
    std::lock_guard lk(g_wsa_mutex);
    if (g_wsa_refcount == 0) return;
    if (--g_wsa_refcount == 0) {
        WSACleanup();
    }
}

} // namespace

std::uintptr_t UdpSocket::invalid_value() noexcept {
    return static_cast<std::uintptr_t>(INVALID_SOCKET);
}

UdpSocket::~UdpSocket() {
    close();
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : sock_(other.sock_), last_error_(other.last_error_)
{
    std::memcpy(server_sa_, other.server_sa_, sizeof(server_sa_));
    other.sock_ = invalid_value();
    other.last_error_ = 0;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        close();
        sock_ = other.sock_;
        last_error_ = other.last_error_;
        std::memcpy(server_sa_, other.server_sa_, sizeof(server_sa_));
        other.sock_ = invalid_value();
        other.last_error_ = 0;
    }
    return *this;
}

bool UdpSocket::open(const std::string& server_host, std::uint16_t server_port) {
    if (!wsa_startup_once()) return false;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        FW_ERR("net: socket() failed: %d", last_error_);
        wsa_cleanup_once();
        return false;
    }

    // Bind to any local port. OS picks an ephemeral.
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        FW_ERR("net: bind() failed: %d", last_error_);
        closesocket(s);
        wsa_cleanup_once();
        return false;
    }

    // Resolve the server. We prefer a literal IP but accept hostname.
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(server_port);
    const int gai = getaddrinfo(server_host.c_str(), port_str.c_str(), &hints, &res);
    if (gai != 0 || !res) {
        last_error_ = gai;
        FW_ERR("net: getaddrinfo(%s:%u) failed: %d",
               server_host.c_str(), server_port, gai);
        closesocket(s);
        wsa_cleanup_once();
        return false;
    }
    static_assert(sizeof(server_sa_) >= sizeof(sockaddr_in),
                  "server_sa_ buffer too small");
    std::memcpy(server_sa_, res->ai_addr, sizeof(sockaddr_in));
    freeaddrinfo(res);

    sock_ = static_cast<std::uintptr_t>(s);

    // Log the resolved peer for sanity.
    sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(server_sa_);
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
    FW_LOG("net: UDP open peer=%s:%u local_port=<ephemeral>",
           ip, ntohs(sa->sin_port));
    return true;
}

void UdpSocket::close() {
    if (sock_ != invalid_value()) {
        closesocket(static_cast<SOCKET>(sock_));
        sock_ = invalid_value();
        wsa_cleanup_once();
    }
}

bool UdpSocket::send(const void* data, std::size_t len) {
    if (sock_ == invalid_value()) return false;
    sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(server_sa_);
    const int n = sendto(static_cast<SOCKET>(sock_),
                         reinterpret_cast<const char*>(data),
                         static_cast<int>(len), 0,
                         reinterpret_cast<sockaddr*>(sa), sizeof(*sa));
    if (n == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        // Don't spam log for transient issues; caller can check last_error.
        return false;
    }
    return static_cast<std::size_t>(n) == len;
}

int UdpSocket::recv(void* buffer, std::size_t buffer_len, int timeout_ms) {
    if (sock_ == invalid_value()) return -1;

    // Wait for readiness with select() so we don't spin.
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(static_cast<SOCKET>(sock_), &rfds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int sel = select(0, &rfds, nullptr, nullptr, &tv);
    if (sel == 0) return 0;
    if (sel == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        return -1;
    }

    sockaddr_in from{};
    int from_len = sizeof(from);
    const int n = recvfrom(static_cast<SOCKET>(sock_),
                           reinterpret_cast<char*>(buffer),
                           static_cast<int>(buffer_len), 0,
                           reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        // WSAECONNRESET happens on Windows when a previous send got ICMP
        // port-unreachable. Not fatal. Just return 0.
        if (last_error_ == WSAECONNRESET) return 0;
        return -1;
    }

    // Drop datagrams from anyone but the configured server.
    sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(server_sa_);
    if (from.sin_addr.s_addr != sa->sin_addr.s_addr ||
        from.sin_port != sa->sin_port) {
        // Silent: defense-in-depth. In normal operation this never fires.
        return 0;
    }

    return n;
}

} // namespace fw::net
