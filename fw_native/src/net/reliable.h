// Reliable UDP channel — port of net/channel.py (Python SSOT).
//
// Scope MVP: assign monotonic seq, retransmit in-flight frames on timeout,
// dedupe incoming reliable frames via (expected_seq + 32-bit SACK bitmap),
// emit cumulative ACKs. RTT is fixed to 300 ms initial timeout with
// exponential backoff up to 2 s. A full RFC6298 SRTT/RTTVAR implementation
// can come later; for our localhost-first workload this is enough.
//
// The channel does NOT own the UDP socket — the client loop passes frames
// in/out. This separation matches channel.py and lets us unit-test the
// reliability logic independently.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "protocol.h"

namespace fw::net {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// One reliable message waiting for ACK.
struct InFlight {
    std::vector<std::uint8_t> frame;  // full encoded bytes (header + payload)
    TimePoint                 first_sent_at;
    TimePoint                 last_sent_at;
    std::uint32_t             retransmits = 0;
    std::uint32_t             current_timeout_ms = 300;
};

// Delivered incoming frame (already deduplicated).
struct Delivered {
    FrameHeader header;
    std::vector<std::uint8_t> payload;  // copied out of the recv buffer
};

class ReliableChannel {
public:
    // Monotonic seq, starts at 1 (server-compat with Python channel.py).
    ReliableChannel();

    // -------------- SEND SIDE --------------

    // Encode + enqueue a reliable frame; returns the bytes ready for the
    // UdpSocket. The channel retains a copy for retransmit.
    std::vector<std::uint8_t> send_reliable(
        MessageType msg_type, const void* payload, std::size_t payload_len);

    // Encode an unreliable frame (POS_STATE, HEARTBEAT). Not tracked.
    std::vector<std::uint8_t> send_unreliable(
        MessageType msg_type, const void* payload, std::size_t payload_len);

    // Periodic tick: retransmit any in-flight frames whose timeout expired.
    // Returns a list of frame payloads ready to re-send (caller hands them
    // to the UdpSocket). Also rotates expired timers.
    std::vector<std::vector<std::uint8_t>> tick(TimePoint now);

    // True if any in-flight frame exceeded MAX_RETRANSMITS — channel is
    // considered dead, caller should reconnect.
    bool is_dead() const noexcept { return dead_; }

    std::size_t in_flight_count() const noexcept { return in_flight_.size(); }

    // -------------- RECEIVE SIDE --------------

    // Feed one raw datagram from the socket. Handles:
    //  - ACK frames (clears matching in_flight entries)
    //  - Reliable frames (dedupe + return for dispatch)
    //  - Unreliable frames (return for dispatch)
    // If a reliable frame needs an immediate ACK, writes it to `ack_out`.
    //
    // Returns a populated Delivered on success, empty optional if the
    // datagram was malformed, duplicate, or pure ACK.
    std::optional<Delivered> on_receive(
        const std::uint8_t* data, std::size_t len,
        TimePoint now,
        std::vector<std::uint8_t>* ack_out);

    // Force an ACK emission (e.g. on tick when pending acks accumulate).
    // Returns true and fills `ack_out` if there's anything to ack.
    bool maybe_emit_ack(std::vector<std::uint8_t>* ack_out);

private:
    // --- Send state ---
    std::uint32_t next_seq_ = 1;
    std::unordered_map<std::uint32_t, InFlight> in_flight_;
    bool dead_ = false;

    // 2026-05-07: bumped 8 → 32 after live test showed channel-dead with
    // bursty modded-equip traffic. With exponential backoff capping at
    // MAX_TIMEOUT_MS, 32 retransmits ≈ 60+ seconds tolerance — survives
    // a P2P relay hiccup or temporary server stall during heavy equip
    // events. The MESH_BLOB_OP path that drove most of the burst has
    // also been disabled (see weapon_capture.cpp).
    static constexpr std::uint32_t MAX_RETRANSMITS = 32;
    static constexpr std::uint32_t INITIAL_TIMEOUT_MS = 300;
    static constexpr std::uint32_t MAX_TIMEOUT_MS = 2000;

    // --- Receive state ---
    std::uint32_t highest_contiguous_seq_ = 0;  // last in-order seq accepted
    std::uint32_t sack_bitmap_ = 0;             // bits for seq+1..seq+32
    bool          ack_pending_ = false;
    std::uint32_t received_since_ack_ = 0;
    static constexpr std::uint32_t ACK_BATCH = 8;

    // Encode an ACK payload (AckPayload struct) to bytes and prepend header.
    void build_ack_frame(std::vector<std::uint8_t>& out) const;

    // Advance the receive window as much as possible given the current bitmap.
    void compact_receive_window();
};

} // namespace fw::net
