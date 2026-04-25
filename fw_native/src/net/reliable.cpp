#include "reliable.h"

#include <algorithm>
#include <cstring>

#include "../log.h"

namespace fw::net {

namespace {

std::chrono::milliseconds ms_since(TimePoint a, TimePoint b) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(b - a);
}

} // namespace

ReliableChannel::ReliableChannel() = default;

// -------------------------------------------------------------- send

std::vector<std::uint8_t> ReliableChannel::send_reliable(
    MessageType msg_type, const void* payload, std::size_t payload_len)
{
    if (dead_) return {};
    const std::uint32_t seq = next_seq_++;

    std::vector<std::uint8_t> frame;
    encode_frame(frame, msg_type, seq, payload, payload_len, /*reliable=*/true);

    InFlight f{};
    f.frame = frame;
    f.first_sent_at = Clock::now();
    f.last_sent_at  = f.first_sent_at;
    f.retransmits   = 0;
    f.current_timeout_ms = INITIAL_TIMEOUT_MS;
    in_flight_.emplace(seq, std::move(f));

    return frame;
}

std::vector<std::uint8_t> ReliableChannel::send_unreliable(
    MessageType msg_type, const void* payload, std::size_t payload_len)
{
    // CRITICAL: unreliable frames use seq=0 (sentinel) — they MUST NOT
    // consume `next_seq_`. Otherwise at 20 Hz POS_STATE, the reliable
    // sequence runs so far ahead of the peer's receive window that
    // the peer drops any subsequent reliable frame as "out of SACK range"
    // (gap > 32). Python channel.py uses the same convention.
    std::vector<std::uint8_t> frame;
    encode_frame(frame, msg_type, 0, payload, payload_len, /*reliable=*/false);
    return frame;
}

std::vector<std::vector<std::uint8_t>> ReliableChannel::tick(TimePoint now) {
    std::vector<std::vector<std::uint8_t>> to_resend;
    if (dead_) return to_resend;

    for (auto it = in_flight_.begin(); it != in_flight_.end();) {
        InFlight& f = it->second;
        const auto waited_ms = ms_since(f.last_sent_at, now).count();
        if (static_cast<std::uint32_t>(waited_ms) >= f.current_timeout_ms) {
            if (f.retransmits >= MAX_RETRANSMITS) {
                FW_ERR("net: reliable channel dead — seq %u hit MAX_RETRANSMITS",
                       it->first);
                dead_ = true;
                ++it;
                continue;
            }
            f.retransmits++;
            f.last_sent_at = now;
            // Exponential backoff, capped.
            f.current_timeout_ms = std::min(f.current_timeout_ms * 2, MAX_TIMEOUT_MS);
            to_resend.push_back(f.frame);
            FW_WRN("net: retransmit seq=%u (attempt %u)",
                   it->first, f.retransmits);
        }
        ++it;
    }
    return to_resend;
}

// -------------------------------------------------------------- receive

std::optional<Delivered> ReliableChannel::on_receive(
    const std::uint8_t* data, std::size_t len,
    TimePoint /*now*/,
    std::vector<std::uint8_t>* ack_out)
{
    FrameHeader h{};
    if (!decode_header(data, len, &h)) return std::nullopt;

    // --- ACK frame: clear in_flight entries ---
    if (h.msg_type == static_cast<std::uint16_t>(MessageType::ACK)) {
        if (h.payload_len < sizeof(AckPayload)) return std::nullopt;
        AckPayload ack{};
        std::memcpy(&ack, data + HEADER_SIZE, sizeof(ack));

        // Remove everything with seq <= highest_contiguous_seq.
        for (auto it = in_flight_.begin(); it != in_flight_.end();) {
            const std::uint32_t seq = it->first;
            bool ack_matched = (seq <= ack.highest_contiguous_seq);
            if (!ack_matched && seq > ack.highest_contiguous_seq) {
                const std::uint32_t gap = seq - ack.highest_contiguous_seq - 1;
                if (gap < 32 && ((ack.sack_bitmap >> gap) & 1u)) {
                    ack_matched = true;
                }
            }
            if (ack_matched) it = in_flight_.erase(it);
            else ++it;
        }
        return std::nullopt;
    }

    // --- Reliable frame: dedupe + track for ACK ---
    if (h.flags & FLAG_RELIABLE) {
        const std::uint32_t seq = h.seq;

        if (seq <= highest_contiguous_seq_) {
            // Already delivered — duplicate, mark that we need to ACK so
            // the sender stops retransmitting, but don't redeliver.
            ack_pending_ = true;
            ++received_since_ack_;
            if (received_since_ack_ >= ACK_BATCH && ack_out) {
                build_ack_frame(*ack_out);
                ack_pending_ = false;
                received_since_ack_ = 0;
            }
            return std::nullopt;
        }

        const std::uint32_t gap = seq - highest_contiguous_seq_ - 1;
        if (gap >= 32) {
            // Out of our SACK window. Drop + ask peer to rewind via ACK.
            ack_pending_ = true;
            if (ack_out) {
                build_ack_frame(*ack_out);
                ack_pending_ = false;
                received_since_ack_ = 0;
            }
            return std::nullopt;
        }

        // Duplicate within SACK window?
        if (gap < 32 && ((sack_bitmap_ >> gap) & 1u)) {
            ack_pending_ = true;
            ++received_since_ack_;
            if (received_since_ack_ >= ACK_BATCH && ack_out) {
                build_ack_frame(*ack_out);
                ack_pending_ = false;
                received_since_ack_ = 0;
            }
            return std::nullopt;
        }

        // Accept new frame.
        sack_bitmap_ |= (1u << gap);
        compact_receive_window();
        ack_pending_ = true;
        ++received_since_ack_;
        if (received_since_ack_ >= ACK_BATCH && ack_out) {
            build_ack_frame(*ack_out);
            ack_pending_ = false;
            received_since_ack_ = 0;
        }

        Delivered d{};
        d.header = h;
        d.payload.assign(data + HEADER_SIZE, data + HEADER_SIZE + h.payload_len);
        return d;
    }

    // --- Unreliable frame: just deliver ---
    Delivered d{};
    d.header = h;
    d.payload.assign(data + HEADER_SIZE, data + HEADER_SIZE + h.payload_len);
    return d;
}

bool ReliableChannel::maybe_emit_ack(std::vector<std::uint8_t>* ack_out) {
    if (!ack_pending_ || !ack_out) return false;
    build_ack_frame(*ack_out);
    ack_pending_ = false;
    received_since_ack_ = 0;
    return true;
}

// -------------------------------------------------------------- internals

void ReliableChannel::build_ack_frame(std::vector<std::uint8_t>& out) const {
    AckPayload ack{};
    ack.highest_contiguous_seq = highest_contiguous_seq_;
    ack.sack_bitmap = sack_bitmap_;
    // ACK frames use seq=0 (server doesn't retransmit ACKs).
    encode_frame(out, MessageType::ACK, 0, &ack, sizeof(ack), /*reliable=*/false);
}

void ReliableChannel::compact_receive_window() {
    // Shift bit 0 into the contiguous seq as long as it's set.
    while (sack_bitmap_ & 1u) {
        highest_contiguous_seq_ += 1;
        sack_bitmap_ >>= 1;
    }
}

} // namespace fw::net
