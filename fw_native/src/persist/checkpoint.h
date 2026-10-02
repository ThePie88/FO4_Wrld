// L5 stage 2/3 (2026-09-27/28) — the commanded save.
//
// Every save the engine attempts is refused by the lifecycle module; the
// only save ever written is the one this module writes, and it writes one
// for three reasons: the server asked (CKPT_REQUEST, on its cadence), the
// player is leaving (the exit save request, stage 3a), or the test key was
// pressed (F10, stage 2). All three go through the same steps at the
// engine's own save point, on the main thread, as the console's SaveGame
// does: the inventory capture and its digest, the save-device check, the
// render capture, the named save under a SaveGrant, then the hash of the
// file as written and a CKPT_DONE to the server with name, sha256, size and
// digest. The name carries the identity ("fwck_<client id>_<date>_<time>"),
// the last three per identity stay on disk, older ones are deleted.
//
// A commanded checkpoint waits for a quiet moment (a world, the scene
// settled, no load in flight, the engine's own gate) up to the deadline the
// server gave, then reports "deferred"; the exit one has no time to wait
// and reports whatever it finds. Nothing here runs with persist_lifecycle
// off: the grant machinery is what makes the save possible.
//
// The other half is the boot: the server names the checkpoint to load
// (CKPT_BOOT, first bootstrap stage), main_menu_hook verifies the file on
// disk through verify_file and loads it instead of the genesis save.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }
namespace fw::net { struct CkptCandidate; }

namespace fw::persist::checkpoint {

// Reads the switches, the identity and where the manifests go.
void configure(const fw::config::Settings& cfg, const wchar_t* output_dir);

// Asks for one test checkpoint (any thread; the F10 key).
void request_test(const char* why);

// The server's request (net thread): served at the save point within
// `deadline_s`, else answered "deferred". A newer request replaces an
// older one still waiting.
void request_commanded(std::uint32_t seq, std::uint8_t reason, std::uint16_t deadline_s);

// Writes a checkpoint NOW, synchronously, on the main thread: the exit
// path. A closed gate is reported, not waited for. `reason` is a
// fw::net::kCkptReason* code.
void run_now(void* save_load_mgr, std::uint8_t reason);

// The same, resolving the save manager itself: the window-close path,
// which has no manager at hand. `immediate` reports through the client's
// send-at-once path, ahead of the goodbye that ends the session.
void run_now_here(std::uint8_t reason, bool immediate);

// Called by the lifecycle module at the top of the task processor's detour,
// once per frame on the main thread. Serves a pending request when the
// gates allow it, reports it when the deadline passes.
void run_pending(void* save_load_mgr);

// The lifecycle module, at every load request the policy allows, BEFORE
// the engine loads: the world manifest written with that checkpoint (the
// objects of ours its save carries) is handed to world_spawn, which purges
// their restored copies once the world is back. A name that is not one of
// our checkpoints (the genesis save), or null (the load failed after all),
// clears whatever was queued.
void note_load_request(const char* name);

// L5 stage 3b — custody. The boot word's part (net thread, every
// session): the bulk port and the token go to the transport, and every
// candidate the server holds no bytes for is uploaded now when its file
// on this disk matches the record (the exit upload that did not make it,
// the checkpoints from before this stage).
void note_custody_word(std::uint16_t bulk_port, const std::uint8_t token[32],
                       const fw::net::CkptCandidate* candidates, std::size_t n);

// The boot: the bytes of `name` from the server's custody into Saves,
// held to the record's sha256 and size before they land under the real
// name. 0 = fetched and verified (verify_file says 0 now), 1 = no custody
// service, 2 = the server refused, 3 = the transfer failed, 4 = the
// fetched bytes differ from the record. `why` gets a short reason.
int fetch_from_custody(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
                       char* why, std::size_t why_len);

// The exit paths: block up to `ms` for the uploads in flight (the exit
// checkpoint's). True = nothing pending.
bool wait_uploads(unsigned ms);

// The boot: a named save on this disk against the server's record.
// Returns 0 = it matches, 2 = the file is missing, 3 = hash or size differ.
// `why` gets a short reason. Any thread (file reads only).
int verify_file(const char* name, const std::uint8_t sha256[32], std::uint32_t size,
                char* why, std::size_t why_len);

} // namespace fw::persist::checkpoint
