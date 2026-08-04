// B6.5w4 — Per-Actor AI tick suppression.
//
// MinHook detour on Actor::Update_PerFrame@RVA 0xC636A0 (single funnel
// for all per-Actor AI work, RE'd in re/B6.5_npc_pipeline_AGENT_A.md).
// For Actors whose form_id is in fw::dispatch::g_tracked_npc_set
// (registered by the net thread on each NPC_STATE_BCAST), the detour
// returns without calling the original — vanilla AI is silenced and our
// server-authoritative pos/yaw/anim writes from B6.5w3 become the only
// authority over the NPC's state.
//
// Without this hook, vanilla AI runs at 60 Hz vs our 10 Hz pos write →
// engine wins 5 of 6 frames → NPC jitters + drifts to vanilla goal +
// each client diverges (independent AI processes on each side).
//
// Side effects of suppression for tracked NPCs:
//   - No pathfinding
//   - No anim graph update by AI (good — SetGraphVariable from w3.b wins)
//   - No gravity/collision check (NPC may float on Z mismatches)
//   - No combat/dialogue
// All intentional — server brain is authoritative.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the MinHook detour on Actor::Update_PerFrame@0xC636A0.
// Returns true on success. Idempotent: subsequent calls return true if
// already installed.
bool install_npc_ai_suppress(std::uintptr_t module_base);

// Build 69 — A/B control for the c.36b mirror combat suppression, driven by
// `suppress_mirror_combat` in fw_config.ini (default true = shipping
// behaviour). Passing false stops the non-owner writing HighProcess+0x189,
// which RE identified as the engine's own StopCombat request flag. Exists so
// the hp-churn probe can be run with the suppression off WITHOUT a rebuild —
// see the comment on Settings::suppress_mirror_combat. Expect the pre-c.36b
// symptoms (mirrors aiming at the local player, combat-crouch sliding) while
// it is off.
void set_mirror_combat_suppression(bool enabled) noexcept;

// Build 69c — called by the kill hook when the LOCAL player (form 0x14) dies.
// Starts a stand-down window during which mirrored NPCs are allowed to stop
// combat normally, so nothing we hold alive can outlive the respawn teleport
// and the cell swap that follow. See the comment on detour_request_stop_combat.
void note_local_player_death() noexcept;

// Build 69d — true while the local player's death stand-down is running.
// During it, NOTHING should write engine state for any NPC: the respawn
// teleport re-elects ownership on proximity (13 flips in one second were
// measured), and every flip switches an actor between owner-capture and
// mirror-apply while the old cell is being unloaded. Two AVs at two different
// addresses landed ~150 ms after that teleport. Callers on the network apply
// path must consult this too — the per-frame detour bails on its own.
bool in_local_death_standdown() noexcept;

// Build 69r (2026-08-04) — A/B lever for the Build 69q death-recohere sweep,
// default OFF (see config.h `death_recohere_sweep` for the full post-mortem:
// decomp proved the MoveTo(cell=NULL) does NO cell re-file and instead plants
// ExtraBadPosition + a "moved" changeform on every swept actor — payloads the
// LoadGame walkers then consume). Called once from install_all with the
// config value.
void set_death_recohere_sweep(bool enabled) noexcept;

// Diagnostic counters (atomic, lock-free reads).
//   suppress: count of detour fires where form_id matched tracked set
//             and original was skipped.
//   passthrough: count of detour fires where form_id was NOT tracked
//                and original was invoked (normal AI tick).
//   seh_failures: count of detour fires where form_id read SEH-faulted.
std::uint64_t get_npc_ai_suppress_fires();
std::uint64_t get_npc_ai_passthrough_fires();
std::uint64_t get_npc_ai_seh_failures();

// B6.5w17 v3 — SHARED dynamic bail set.
// Once an actor was ever auto-bailed (via InCombat-flag detection or
// any other Path inside npc_ai_suppress.cpp's detour), its form_id is
// inserted into a process-wide set. This query lets the OTHER ghost-AI
// hooks (havok_step, actor_setpos, pos_belt, movement) also bail their
// respective code paths for the same actor — without this, only
// Update_PerFrame is silenced and Havok/anim/setpos continue to drive
// the actor visually.
//
// Thread-safe (internal std::mutex). Cheap: O(log N) or O(1) hash.
bool is_actor_bail_tracked(std::uint32_t form_id);

// Count of distinct actors currently in the shared dynamic bail set.
// Diagnostic, lock-free read of an atomic counter (so it can race
// slightly behind the set's actual size, but never undercounts what we
// announced).
std::uint64_t get_dyn_bail_tracked_count();

// B6.6w0 hook #3 (fire) helper: AIProcess* → form_id reverse map.
//
// The fire-decision hook (`ghost_ai_fire.cpp`) walks a TLS chain that
// lands on the per-actor AIProcess struct (per disasm of sub_14086FCA0:
// thread+0x158 deref → +0x68 deref = AIProcess). AIProcess does NOT
// store the owner Actor pointer at any known offset, so we cannot
// invert "which raider is firing this tick?" from the AIProcess alone.
//
// Strategy: `npc_ai_suppress` already fires for EVERY actor on EVERY
// Update_PerFrame. On each fire we read `Actor+0x328 = AIProcess*` (per
// disasm of sub_140C5CCE0 = SyncCombatTargetFromAIProcess) and register
// (aiproc -> form_id) in a process-wide map. The fire hook then queries
// this map to identify owner. Population is lazy (only actors that
// actually tick get cached), eviction is implicit (actor destruction
// stops feeding new entries; stale entries cause MISS → safe
// passthrough, not false positive).
//
// Map is shared-mutex protected; reads dominate writes (writes only
// once per actor's first tick or when AIProcess pointer changes —
// engine never moves AIProcess in vanilla, so realistically writes
// are bounded by total actor count).
//
// Returns true if mapped; fills *out_fid only on true. nullptr in
// aiproc returns false. Lookup is O(1) hash.
bool get_fid_for_aiproc(const void* aiproc, std::uint32_t* out_fid);

// Diagnostic: how many distinct AIProcess pointers we've mapped.
std::uint64_t get_aiproc_map_size();

// B6.6w0 unified bail predicate.
//
// Returns true if the actor with this form_id should be frozen/silenced
// by ALL freeze + B6.6 hooks. Consults TWO sources, OR'd:
//
//   1. Server-pushed cache (`fw::dispatch::get_cached_npc_state` →
//      `movement_override != 0`) — populated immediately on
//      NPC_STATE_BCAST. Catches raiders in `concord_museum_mvp.json`
//      even before the engine ticks them locally.
//
//   2. Local dynamic set (`is_actor_bail_tracked`) — populated by
//      npc_ai_suppress when InCombat flag (Actor+0x2D0 bit 0x4000)
//      is detected during Update_PerFrame. Catches raiders that aren't
//      in server config but became combat-engaged with the local player.
//
// The OR is essential: live test 2026-05-12 showed clients sometimes
// diverge on which raiders enter local InCombat first, leaving the
// dynamic set out of sync. The server cache is the symmetric ground
// truth.
//
// Used by EVERY pos/freeze hook (Update_PerFrame, Havok step, pos_belt,
// actor_setpos, process_movement). These always bail when this returns
// true. The B6.6 COMBAT hooks (combat_orchestrator, dispatch_attack,
// fire_decide, hit_applier) use the split `should_silence_combat`
// predicate instead — it conditionalises on server cache having an
// active opinion, so the engine resumes combat when the server says so
// while pos stays locked.
//
// Cheap (atomic size check + at most one shared_lock on miss).
bool should_freeze_actor(std::uint32_t form_id);

// B6.6w0 — combat-hook bail predicate, distinct from pos-hook one.
//
// Returns true iff combat hooks should BAIL for this actor.
//
// Three states for a tracked NPC:
//
//   A. Not tracked at all (random vanilla actor, player) →
//      false: combat hooks passthrough; engine runs combat normally.
//
//   B. Tracked + server has NO active combat opinion
//      (`cache.combat_target_form_id == 0`) → true: combat hooks
//      bail; actor stays passive (this is the current "NUKE" mode).
//
//   C. Tracked + server has an ACTIVE combat opinion
//      (`cache.combat_target_form_id != 0`) → false: combat hooks
//      passthrough; engine runs combat normally. Position hooks still
//      bail in parallel (via `should_freeze_actor`) so the actor
//      attacks while standing still.
//
// Symmetric across peers because the server pushes the same cache
// state via NPC_STATE_BCAST. Each client interprets the local
// `0x14` (= local PlayerCharacter form_id) when the server-pushed
// per-peer projection picks them as the target peer, and `0`
// otherwise.
bool should_silence_combat(std::uint32_t form_id);

// ============================================================================
// Build 65.c.47 — WEDGE3 death-sync. STICKY "dying" set.
//
// When a NON-OWNER applies a relayed owner death (drain_npc_death_apply_queue),
// the engine Actor::Kill is asynchronous: the KnockState bits (Actor+0x130
// bits 21-24, read by actor_knocked_or_dead) lag ~1 frame behind the actual
// transition. Without a sticky marker, the c.41b keyframe machine's `want_kf`
// predicate (= is_non_owner_tracked && !actor_knocked_or_dead) would still see
// "alive" for that frame and RE-KEYFRAME the body — re-freezing the ragdoll
// (a Keyframed body can't flop).
//
// `mark_dying(fid)` adds the fid to a process-wide set; `is_dying(fid)` is
// AND'd into want_kf so the corpse is never re-keyframed once death apply
// begins. The flag is cleared on ownership re-acquire / cell unload (wherever
// the per-fid keyframe state is reset) via clear_dying(fid) so a fresh spawn
// of the same form_id (e.g. respawn / reload) starts clean.
//
// Thread-safe (internal std::mutex). Cheap O(1) hash lookup on the hot path.
void mark_dying(std::uint32_t form_id);
bool is_dying(std::uint32_t form_id);
void clear_dying(std::uint32_t form_id);

} // namespace fw::hooks
