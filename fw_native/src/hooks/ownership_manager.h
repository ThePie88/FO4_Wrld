// Build 65 — DLL-side mirror of the server's NPC ownership registry.
//
// Server-authoritative: the Python `OwnershipRegistry` elects an owner
// per NPC and broadcasts every transition via NPC_OWNERSHIP_HANDOFF_PHASE_2
// (single-phase model for Phase A). The DLL never elects on its own; it
// only mirrors what the server says. The local view drives cheap
// per-hook predicates `is_owner_of(fid)` and `is_non_owner_tracked(fid)`,
// which the AI/motion suppression hooks consult to decide whether to bail
// or run vanilla engine code.
//
// Threading: the net thread writes (via on_phase2 / on_bcast); hooks read
// (via is_*_of). A single std::shared_mutex protects the map. Reads are
// far hotter than writes (Update_PerFrame fires for every loaded actor at
// 60 Hz; ownership changes happen O(few-per-second)) so a shared_lock on
// readers is essential.
//
// Phase A scope (Build 65.c, the file you're reading):
//   - RX-only: server PHASE_2 + BCAST update the local map.
//   - Predicates exposed for future hook wiring (npc_ai_suppress flip
//     in Build 65.d).
//   - No TX yet: NPC_OBSERVED / HEARTBEAT / STATE_FROM_OWNER emission
//     lands in 65.c.2 once the predicate flip is verified.

#pragma once

#include <cstdint>
#include <string>

#include "../net/protocol.h"

namespace fw::ownership {

// Initialise the manager. Idempotent: subsequent calls are no-ops.
// Called from dll_main on attach.
void init();

// Set the local peer's identity. Called from net thread after WELCOME
// arrives. `peer_id` is the ASCII string the client used in HELLO
// (NUL-padded to 16 B on the wire); the manager stores it in canonical
// 16 B padded form for byte-compare against PHASE_2 / BCAST entries.
void set_local_peer_id(const std::string& peer_id);

// Reset on disconnect / shutdown. Drops every tracked NPC.
void shutdown();

// Net-thread entry points. All operate under the writer lock.

// Apply an NPC_OWNERSHIP_HANDOFF_PHASE_2 (server-authoritative). Inserts
// or replaces the local entry. An all-zero `new_owner_peer_id` removes
// the entry (NPC becomes unowned).
void on_phase2(const fw::net::NPCOwnershipHandoffPhase2Payload& payload);

// Apply an NPC_OWNERSHIP_BCAST snapshot (bootstrap on join, or post-
// handoff cleanup). Overwrites every entry in `entries[]` — does NOT
// remove unmentioned entries (server sends partial chunks).
void on_bcast(const fw::net::NPCOwnershipBcastEntry* entries,
              std::size_t                            count);

// ----- read-only predicates (hooks consume these) -----

// True iff form_id is in the local map AND its owner_peer_id matches
// our local peer_id (set via set_local_peer_id). False for untracked
// NPCs, unowned entries (all-zero peer_id), or NPCs owned by a peer.
bool is_owner_of(std::uint32_t form_id);

// True iff form_id is in the local map AND it's owned by a peer OTHER
// than us. The suppression-hooks predicate: bail engine AI for this
// actor. False for untracked or for the locally-owned actor (engine
// runs vanilla AI in that case).
bool is_non_owner_tracked(std::uint32_t form_id);

// Look up the current epoch for an NPC. Returns false if not tracked.
// Receivers of NPC_STATE_FROM_OWNER use this to drop entries whose
// epoch doesn't match the current registry value.
bool epoch_for(std::uint32_t form_id, std::uint32_t* out_epoch);

// Diagnostic: how many NPCs are currently in the local map.
std::uint64_t tracked_count();

// Diagnostic: number of (PHASE_2, BCAST entry) applications since init.
std::uint64_t phase2_applied();
std::uint64_t bcast_applied();

// ----- TX side (Build 65.c.2) -----
//
// Called from the suppression detour (main thread, per-actor per-frame)
// for every Actor it ticks. The manager:
//   - Dedups observations: only the FIRST sighting per (form_id, session)
//     triggers an NPC_OBSERVED enqueue. Subsequent calls are O(1) no-ops.
//   - For NPCs we own (`is_owner_of` true), stashes the latest readable
//     pos/yaw/anim_state/hp_pct snapshot into an in-memory cache. The
//     periodic emit drains that cache.
//
// `pos[3]` and `yaw` are SEH-protected reads from the caller (npc_ai_
// suppress does this already for Actor+0xD0 / +0xC0). `dist_sq` is
// (Actor.pos - PC.pos).length_squared() — caller computes once and
// passes here so the manager doesn't need engine access of its own.
void notify_observation(std::uint32_t form_id,
                        std::uint32_t base_id,
                        std::uint32_t cell_id,
                        float pos_x, float pos_y, float pos_z,
                        float dist_sq);

// Called from suppression detour when `is_owner_of(form_id)` is true.
// Captures the latest engine-read fields for the next emit cycle.
// Fields beyond pos/yaw/anim/hp default to zero; full anim/aim/velocity
// capture lands when the engine-side helpers (sub_140CCFDF0,
// CombatAimController) ship in 65.c.3+.
void record_owned_state(std::uint32_t form_id,
                        float pos_x, float pos_y, float pos_z,
                        float yaw_rad,
                        std::uint8_t anim_state,
                        std::uint8_t hp_pct);

// Called from the net thread's run_loop on every iteration. Internally
// rate-limits: HEARTBEAT every 500 ms, STATE every 100 ms (10 Hz).
// `now_ms` is the wall clock in ms (matches Python server side).
void tick_periodic(std::uint64_t now_ms);

} // namespace fw::ownership
