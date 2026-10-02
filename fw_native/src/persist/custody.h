// L5 stage 3b (2026-09-28) — custody: the checkpoint bytes on the server.
//
// Stage 3a left every checkpoint on the disk of the machine that wrote it,
// so another machine, or a wiped Saves folder, booted the genesis save.
// From this stage the bytes go to the server too: after a checkpoint is
// written and reported, it is uploaded (a PUT on a TCP connection to the
// bulk service the server runs next to its UDP port, under a token the
// boot word CKPT_BOOT hands out per session), and a boot whose file is
// not on this disk, or differs from the record, fetches it back (a GET)
// before loading. The exit upload is best effort (the process is
// leaving: a few seconds at most, see checkpoint::wait_uploads); what did
// not make it is uploaded at the next session, when the boot word lists
// the checkpoints the server holds no bytes for.
//
// This module is the transport only: a worker thread with a queue for the
// uploads, a synchronous fetch for the boot. What is uploaded, and what a
// fetched file is held to (its sha256 against the record) is
// checkpoint.cpp's business.
//
// Framing (little-endian, fixed headers; the Python twin is
// net/server/custody.py):
//   request 128 B: "FWBK", version 1, op (1 PUT, 2 GET), reserved u16,
//                  token[32], name[48], sha256[32], size u32, manifest u32,
//                  then for a PUT `size` bytes of the .fos and `manifest`
//                  bytes of the world manifest;
//   reply    16 B: "FWBR", status, reserved[3], size u32, manifest u32,
//                  then for a GET that succeeded the same two bodies.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::persist::custody {

// The server host from the config; Winsock. No thread starts here.
void configure(const fw::config::Settings& cfg);

// The boot word's part (every session, any thread): the bulk port (0 =
// no service) and the token this session transfers under.
void set_word(std::uint16_t bulk_port, const std::uint8_t token[32]);

// A port and a token are known.
bool available();

// Queue one upload (any thread). `manifest_path` may be null or missing;
// a name already queued or uploaded this session is not queued again.
// Without a service the name is logged as staying on this disk.
void enqueue_upload(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
                    const wchar_t* fos_path, const wchar_t* manifest_path);

// Blocks up to `ms` for the queue to drain (the exit paths). True = idle.
bool wait_idle(unsigned ms);

// One GET on the calling thread: the .fos bytes land in `fos_part_path`,
// the world manifest in `manifest_path` (when the server has one).
// 0 = fetched (not yet verified: the caller hashes the .part), 1 = no
// service, 2 = the server refused (why says how), 3 = the transfer failed.
int fetch(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
          const wchar_t* fos_part_path, const wchar_t* manifest_path,
          char* why, std::size_t why_len);

// Process exit: the worker stops at its next look.
void stop();

} // namespace fw::persist::custody
