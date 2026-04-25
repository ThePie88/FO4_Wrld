// Thin Winsock2 wrapper for UDP. One socket, one fixed peer address
// (the FoM server). Non-blocking recv with timeout via `select()` so we
// don't spin.
//
// Not thread-safe by itself — callers serialize send/recv via the
// client loop thread. UdpSocket is move-only.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace fw::net {

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    // Opens the socket, binds to 0.0.0.0:0 (OS-assigned port), caches the
    // server address. Returns false on any failure (check last_error()).
    bool open(const std::string& server_host, std::uint16_t server_port);

    // Sends `data` to the cached server address. Returns true on success.
    bool send(const void* data, std::size_t len);

    // Blocks up to `timeout_ms` waiting for a datagram. On receipt, fills
    // `buffer` and returns the number of bytes received. Returns 0 on
    // timeout, -1 on error. Silently drops datagrams NOT from the
    // configured server (defense-in-depth).
    int recv(void* buffer, std::size_t buffer_len, int timeout_ms);

    bool is_open() const noexcept { return sock_ != invalid_value(); }
    int last_error() const noexcept { return last_error_; }

    void close();

private:
    static std::uintptr_t invalid_value() noexcept;

    std::uintptr_t sock_ = invalid_value();
    // Server sockaddr_in stored raw to avoid dragging ws2 headers into this .h
    unsigned char server_sa_[16] = {0};
    int last_error_ = 0;
};

} // namespace fw::net
