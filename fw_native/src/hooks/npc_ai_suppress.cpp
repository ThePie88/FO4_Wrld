#include "npc_ai_suppress.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cmath>      // B6.6 pos-meas diagnostic: std::sqrt for drift magnitude

#include "../hook_manager.h"
#include "../log.h"
#include "../audit.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"  // Build 29: get_ghost_actor() for fixed-selector install
#include "../net/client.h"        // B6.6w2: enqueue_npc_discover on auto-track
#include "ghost_ai_package.h"   // B6.5w12 bridge: write current actor fid for the
                                // ghost-AI predicate hook to consume
#include "puppet_update_perframe.h"  // B6.6w0 puppet replacement body
#include "ownership_manager.h"      // Build 65: owner-driven gate + observation
#include "../native/scene_inject.h"  // c.37.0: capture_and_send_npc_pose

#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace fw::hooks {

namespace {

// Engine signature (from re/B6.5_npc_pipeline_AGENT_A.md):
//   void __fastcall sub_140C636A0(Actor* this, float simTime);
using ActorUpdatePerFrameFn = void (*)(void* actor, float sim_time);

ActorUpdatePerFrameFn g_orig_actor_update_perframe = nullptr;

// Build 69 — RequestStopCombat(manager, actor). Dedicated event-98 emitter;
// see offsets::REQUEST_STOP_COMBAT_RVA for the full derivation. The Actor is
// the SECOND argument (RDX).
using RequestStopCombatFn = char (*)(void* manager, void* actor);
RequestStopCombatFn g_orig_request_stop_combat = nullptr;

// Counters for the same INFO snapshot the other suppression stats use.
std::atomic<std::uint64_t> g_stopcombat_blocked{0};
std::atomic<std::uint64_t> g_stopcombat_passed{0};

// Diagnostics. Relaxed because exact ordering doesn't matter; we only
// read these for periodic INFO snapshots. fetch_add at this volume
// (thousands per second) is cheap — single locked-xadd instruction.
std::atomic<std::uint64_t> g_suppress_fires{0};
std::atomic<std::uint64_t> g_passthrough_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

// B6.5w17 v3 — SHARED dynamic bail set (file-scope so OTHER hooks can
// query via is_actor_bail_tracked()). Was a function-local static in v2,
// which meant only npc_ai_suppress's detour saw it. Promoting it to
// file-scope lets all 5 ghost-AI hooks bail the same actors uniformly.
//
// v4 (2026-05-12, post-crash): swap std::mutex for std::shared_mutex.
// is_actor_bail_tracked() is called from FIVE hot-path hooks (havok_step
// fires on the physics worker thread, the others on main thread). With a
// plain mutex, contention serializes them all — havok blocked on main,
// main blocked on havok, etc. Under heavy combat (~thousands of
// fires/sec) this could explain the post-2-minute crash. With
// shared_mutex, the rare WRITE path (AUTO-TRACK insert) takes
// std::unique_lock; the hot READ paths take std::shared_lock and run
// concurrently. Atomic size mirror lets stats fetches skip locking
// entirely.
std::shared_mutex                 g_dyn_mtx;
std::unordered_set<std::uint32_t> g_dyn_tracked;
std::atomic<std::uint64_t>        g_dyn_auto_adds{0};
std::atomic<std::uint64_t>        g_dyn_set_size{0};

// Build 31 Phase 2 — per-tick purge counters (no dedup; see detour body).
// Kept for future re-introduction if profiling shows per-tick purge cost.
// g_purged_count incremented inside purge_stale_actor_state via its own
// counters in engine_calls.cpp; not duplicated here.

// B6.6w0 hook #3 support: AIProcess* → form_id reverse map.
// Populated lazily from this detour (every Actor we tick gives us the
// (aiproc, fid) pair). Read by ghost_ai_fire.cpp's DecideAndFire hook
// to identify which raider is making the fire decision.
//
// Sized to hold at most a few hundred entries (= every loaded Actor in
// current cells). No eviction yet — stale entries are harmless misses
// in lookup. If memory pressure ever matters, add a periodic prune on
// actors whose form_id is no longer findable.
std::shared_mutex                                 g_aiproc_mtx;
std::unordered_map<const void*, std::uint32_t>    g_aiproc_to_fid;
std::atomic<std::uint64_t>                        g_aiproc_map_size{0};

// Per disasm of sub_140C5CCE0 (SyncCombatTargetFromAIProcess):
//   mov rcx, [rbx+328h]      ; AIProcess* = *(Actor + 0x328)
// Used here to populate the AIProcess → form_id map.
constexpr std::size_t ACTOR_AIPROCESS_OFFSET = 0x328;

// SEH-safe pointer read at a known offset. Local copy to avoid include
// loops with other hooks (we deliberately don't share these tiny helpers
// via a header).
static const void* safe_read_ptr_at_local(const void* base,
                                          std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// SEH-safe form_id read. Returning 0 on fault makes the detour fall
// through to passthrough (safer than skipping — at worst the engine
// ticks an actor we couldn't identify, no crash).
static std::uint32_t safe_read_form_id(const void* actor) noexcept {
    if (!actor) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;   // sentinel — see detour
    }
}

// B6.5w17: read Actor+0x2D0 (flags_720) safely. InCombat = bit 0x4000.
static std::uint32_t safe_read_actor_flags(const void* actor) noexcept {
    if (!actor) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) + 0x2D0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// B6.6w2: SEH-safe read of (base_id, cell_id, pos_xyz) off a tracked
// Actor*. Must be in its own function (NOT inlined into the detour)
// because the detour function has non-trivial-destructor locals
// (std::shared_lock / std::unique_lock) and MSVC C2712 forbids __try
// in such functions.
//
// Returns true on full success. On any SEH, returns false with all
// out-params zeroed. Caller may still send NPC_DISCOVER with zeros
// for base/cell — server treats 0 as "unknown" sentinel.
static bool safe_read_actor_identity(const void* actor,
                                     std::uint32_t* out_base_id,
                                     std::uint32_t* out_cell_id,
                                     float* out_px, float* out_py, float* out_pz) noexcept {
    if (out_base_id) *out_base_id = 0;
    if (out_cell_id) *out_cell_id = 0;
    if (out_px) *out_px = 0.0f;
    if (out_py) *out_py = 0.0f;
    if (out_pz) *out_pz = 0.0f;
    if (!actor) return false;
    __try {
        auto* const a8 = reinterpret_cast<const std::uint8_t*>(actor);
        const void* const base_form = *reinterpret_cast<const void* const*>(
            a8 + fw::offsets::BASE_FORM_OFF);
        if (base_form && out_base_id) {
            *out_base_id = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(base_form) +
                fw::offsets::FORMID_OFF);
        }
        const void* const cell = *reinterpret_cast<const void* const*>(
            a8 + fw::offsets::PARENT_CELL_OFF);
        if (cell && out_cell_id) {
            *out_cell_id = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(cell) +
                fw::offsets::FORMID_OFF);
        }
        const auto* const pos = reinterpret_cast<const float*>(
            a8 + fw::offsets::POS_OFF);
        if (out_px) *out_px = pos[0];
        if (out_py) *out_py = pos[1];
        if (out_pz) *out_pz = pos[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Build 65 — SEH-safe Z-axis (yaw) read from Actor+0xC0+8 (rot[2]).
// Used by owner-driven state capture to fill NPCOwnerStateEntry.yaw_rad
// without faulting on transiently-invalid Actors.
static bool safe_read_actor_yaw(const void* actor, float* out_yaw) noexcept {
    if (out_yaw) *out_yaw = 0.0f;
    if (!actor || !out_yaw) return false;
    __try {
        const auto* rot = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::ROT_OFF);
        *out_yaw = rot[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// B6.6w0 puppet Step 1 (v2 baseline restored, 2026-05-12 evening):
// force a coherent InCombat state without an AI tick running.
//
// v3 attempt (bit 0x4000000 at Actor+0x2D0) was REVERTED — live test
// proved that bit STRIPS EQUIPMENT VISUALS (raiders went naked, 4/5
// observed). The RE audit agent classified bit 26 as "relationship-
// aware combat-eligibility" reading sub_140C7AD40, but its empirical
// effect is on rendering. Whatever the engine's IsHostile chain really
// reads, it's NOT this bit. We DO NOT touch +0x2D0 outside bit 0x4000
// until the hostility/compass field is identified by a different path.
//
// Triple-write per frame for tracked NPCs:
//   1. `Actor+0x2D0 |= 0x4000` — InCombat bit (`bts ecx, 0Eh` in
//      sub_140C5CCE0 disasm). Drives Papyrus IsInCombat only.
//   2. `*(Actor+0x328 + 0x6C) = 0x14` — AIProcess::combat_target_fid
//      (the source-of-truth the engine combat brain reads, per A1
//      dossier writer at sub_14087AB30).
//   3. `Actor+0x380 = 0x14` — the Papyrus mirror that
//      sub_140C5CCE0 would normally update from AIProcess+0x6C.
//
// Net effect: Papyrus checks pass; HUD compass / Attack prompt do NOT
// change (still neutral). To force red marker we need to find a path
// that doesn't write to Actor+0x2D0's high bits.
//
// SEH-safe. No-op on null actor or any fault.
static void safe_force_in_combat_flag(void* actor) noexcept {
    if (!actor) return;
    __try {
        auto* flags = reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x2D0);
        *flags |= 0x4000u;
        fw::audit::wnote(fw::audit::WSite::kInCombat, flags,
                         flags, 4);  // Build 69o — bytes = post-RMW value

        // Actor+0x380 mirror — what `GetCombatTarget` Papyrus reads.
        const std::uint32_t pc_fid = 0x14u;
        *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x380) = pc_fid;
        fw::audit::wnote(fw::audit::WSite::kInCombat,
                         reinterpret_cast<std::uint8_t*>(actor) + 0x380,
                         &pc_fid, 4);  // Build 69o

        // AIProcess+0x6C — the real combat-target field. AIProcess
        // pointer lives at Actor+0x328 (per sub_140C5CCE0 disasm).
        void* aiproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x328);
        if (aiproc) {
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C) = pc_fid;
            fw::audit::wnote(fw::audit::WSite::kInCombat,
                             reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C,
                             &pc_fid, 4);  // Build 69o
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // swallow — better than crashing
    }
}

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;
constexpr std::uint32_t ACTOR_FLAG_IN_COMBAT = 0x4000u;

// The detour. Hot path: ~thousands of calls per second across all
// loaded Actors. Keep it tight.
//
// B6.5w12 deprecation (2026-05-11): rounds 1-11 POST-hook
// apply_npc_state_to_actor path is CLOSED.
//
// Previous logic (round 2 strategy): call original FIRST so the engine's
// housekeeping (NIF sync, anim graph evaluation, collision) ran
// normally, then POST-overwrite pos/yaw/anim from our cache. The
// "engine's internal NIF sync" wasn't where the renderer ultimately
// read from in the way we hoped — the race against engine's own
// transforms below Update_PerFrame was unwinnable at this level. The
// MoveTo-based output-override path (scene_render_hook) reached the
// same dead-end via a different route. See NPCs.md.
//
// The hook install + form_id read + tracked-set lookup pattern are
// kept as scaffolding. Ghost AI hooks (B6.5w12+) will reuse THIS entry
// point structure but ALSO install separate detours at the decision-
// point functions upstream — combat target setter, package predicate,
// movement wrapper, aim writer, anim state transitions, etc.
//
// The diagnostic counters keep firing — they're useful for "how many
// tracked NPCs is the engine ticking per frame on this client" stat.
// Build 62.7 — free helper for the natural-HighProcess gate in the
// per-tick install_fixed_selector block. Free function to avoid MSVC
// C2712 (the detour body owns shared_lock locals which forbid __try
// in the same frame).
bool actor_has_native_highproc(void* actor) noexcept {
    if (!actor) return false;
    __try {
        const auto hp = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x328);
        return hp != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Build 65.c.47 — WEDGE3 death-sync. STICKY "dying" set (see header doc).
// Marked when a non-owner begins applying a relayed owner death; AND'd into
// want_kf so the corpse is never re-keyframed while the async Actor::Kill's
// KnockState bits lag. Cleared on ownership re-acquire / cell unload.
std::mutex                        g_dying_mtx;
std::unordered_set<std::uint32_t> g_dying;

// c.41b — true if the actor is knocked down / ragdolling / dead (KnockState
// bits 21-24 of the packed flags dword at Actor+0x130). Used to UN-keyframe the
// Havok body so the ragdoll/get-up physics can actually play (a Keyframed body
// can't ragdoll). Free function (noexcept + __try) to avoid MSVC C2712.
bool actor_knocked_or_dead(void* actor) noexcept {
    if (!actor) return false;
    __try {
        const std::uint32_t v = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) + 0x130);
        return ((v >> 21) & 0xFu) != 0u;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Build 65.c.36b — kill switch for the mirror combat-suppression. Default ON.
std::atomic<bool> g_c36b_enable{true};

}  // namespace  (re-opened below; the setter must be externally linkable)

void set_mirror_combat_suppression(bool enabled) noexcept {
    g_c36b_enable.store(enabled, std::memory_order_relaxed);
    FW_LOG("[npc-ai-suppress] c.36b mirror combat suppression = %s "
           "(HighProcess+0x189 %s on mirrors)",
           enabled ? "ON" : "OFF",
           enabled ? "driven to 1" : "left untouched");
}

// Build 69r — see npc_ai_suppress.h / config.h for the 69q post-mortem.
std::atomic<bool> g_death_recohere_sweep_enabled{false};

void set_death_recohere_sweep(bool enabled) noexcept {
    g_death_recohere_sweep_enabled.store(enabled, std::memory_order_relaxed);
    FW_LOG("[npc-ai-suppress] 69q death-recohere sweep = %s%s",
           enabled ? "ON" : "OFF",
           enabled ? " (A/B lever — decomp says this ARMS the load, "
                     "see config.h death_recohere_sweep)" : "");
}

namespace {

// Build 65.c.36b — set/clear the engine's combat "skip-tick" flag on a live
// HighProcess (Actor+0x328 → +0x189). Setting it to 1 makes the post-pick gate
// sub_14087A900 return 1 → the combat orchestrator vt[255] sub_140CCFDF0 drops
// the target + skips the WHOLE engage/aim/cover block (incl. the
// CombatBehaviorCrouch/TakeCover tree). So a NON-OWNER mirror raider stops
// aiming at its LOCAL player AND stops the local combat-crouch (no more
// crouch+relayed-run "sliding"). Locomotion + anim graph live in the separate
// UN-gated inner body, so the raider still moves (relayed pos) with matching
// legs and faces the ghost via the relayed yaw. The engine NEVER clears this
// flag (savegame-persisted), so we drive it every frame from ownership: =1 for
// mirrors, =0 for raiders we own (un-stick). SEH-caged; no-op if no
// HighProcess. Crash-safe: one byte, never touches the AddTarget/known_targets
// BSTArray path. Cross-checked by the 8+3+2-agent arenas (re/c36b_design_*,
// re/posture_sync_*). NOTE the ceiling: this gives up combat-specific anim
// (crouch/blindfire/lunges) — faithful anim needs full-pose replication
// (re/fullpose_freezedrive_* in flight).
void set_combat_skip_tick(void* actor, bool suppress) noexcept {
    if (!actor) return;
    __try {
        void* hp = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x328);
        if (!hp) return;   // no combat HighProcess → nothing to gate
        const std::uint8_t v = suppress ? 1u : 0u;
        *(reinterpret_cast<std::uint8_t*>(hp) + 0x189) = v;
        // Build 69o — write ring. HighProcess is exactly the block the
        // hp-churn probe watched go 0x5555 (freed) mid-session; this byte
        // through a stale Actor+0x328 would land in recycled heap.
        fw::audit::wnote(fw::audit::WSite::kSkipTick,
                         reinterpret_cast<std::uint8_t*>(hp) + 0x189, &v, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // actor/HP torn down between read and write — ignore.
    }
}

// ============ Build 69 — block StopCombat requests on mirrors =============
//
// THE DEFECT THIS FIXES, measured rather than argued (2026-08-02 A/B run):
// with our HighProcess+0x189 write active, ZERO of 196,384 sampled ticks kept
// a mirrored NPC's HighProcess alive and all 106 allocations died within
// exactly 1 tick; with the write withheld on client B, the same four raiders
// (0x246CD2/3/4/5) held theirs for up to 160 ticks (2.7 s). The byte is not a
// "skip this tick" flag — RE found its only two vanilla writers are the two
// Actor::StopCombat implementations, and the gate that reads it,
// sub_14087A900, is ShouldStopCombat(). So we were asking the engine to end
// combat 60 times a second and it obliged, taking the combat-target handle
// with it. That is why a non-owner could never observe "this NPC wants me".
//
// WHY HERE AND NOT SOMEWHERE ELSE. In sub_140CCFDF0 the single value `v10`
// controls BOTH the skip of the engage/aim/cover block AND the tail call that
// dispatches event 98 — they cannot be separated by tuning the byte. So we
// keep the byte (the suppression stays behaviourally identical: with v10 == 1
// the whole `if (!v10 && ...)` block is skipped, including BOTH combat-tick
// helpers sub_140879630 and sub_1408793F0) and drop only the dispatch.
//
// Alternatives rejected, with the reason:
//   * Swap to HighProcess+0x18B. sub_1408793F0's body IS gated by both bytes
//     (funcs_0240.md:4612 `if (!*(a1+393) && !*(a1+395))`), but the sibling
//     sub_140879630 — taken when sub_140CA6580(a1) is true — is gated by
//     NEITHER, so the combat tick keeps running on that branch and the
//     mirrors-aim-at-you symptom returns.
//   * Hook sub_140CCFDF0 itself: v10 is shared, so it would mean
//     reimplementing a per-frame per-combat-group-member function rather than
//     wrapping it.
//
// BLAST RADIUS, stated honestly. This dispatcher has exactly three callers:
// the orchestrator (ours), Actor::Update_PerFrame's combat-timeout path, and
// sub_140C60BE0's state/movement path. Blocking it for mirrors blocks all
// three FOR MIRRORED ACTORS ONLY, which is the architecturally correct
// answer: a mirrored NPC must not make its own stop-combat decisions, the
// owner is authoritative. Destruction paths that do NOT route through here —
// death, cell unload, Papyrus StopCombat — still free the HighProcess, so
// this cannot strand the allocation.
// FAIL-SAFE WINDOWS (Build 69c). Client A took an AV 160 ms after the
// post-death respawn teleport, inside BSExtraDataList::GetByType on a list
// whose presence-bitfield pointer had been overwritten with recycled heap
// (0x0200000002000000) — a use-after-free during the cell swap. The Build 69
// hooks were behaviourally inert on that client (zero blocks; the player's own
// StopCombat does not even route through here, because PlayerCharacter
// overrides vtable slot 256 with sub_140D9B150), so nothing proves we caused
// it. But refusing a teardown request is precisely the class of change that
// leaves a structure alive past the point the engine assumed it was gone, and
// death + reload is where that bites. So the block now stands down whenever
// the engine has a legitimate reason to be tearing something down:
//
//   * the actor is knocked out or dead        -> let it stop combat and die
//   * the actor is in our sticky dying set    -> death-sync is mid-flight
//   * the local player died in the last few s -> respawn teleport + cell swap
//
// The cost is nil in the steady state we care about: mirrors are suppressed
// while alive and fighting, which is the only window in which keeping the
// HighProcess buys us anything.
// Build 69e — the stand-down window is EVENT-DRIVEN, not a fixed timeout.
//
// It used to be a flat 15 s from the moment of death. That covered the three
// runs we measured (the respawn teleport landed 6.85 / 6.90 / 7.00 s after
// death every time), but a flat timer is a guess about load times: a slower
// disk or a heavier destination cell pushes the teleport past the deadline and
// re-exposes the exact instant that produced two AVs. So instead we watch for
// the thing we actually care about — the respawn teleport itself — and hold
// the stand-down until it has happened AND the cell streaming behind it has
// had time to settle.
//
//   death            -> window opens, we look for the teleport
//   teleport seen    -> window stays open kSettleAfterRespawnMs longer
//   nothing seen     -> window closes at kHardCeilingMs no matter what, so a
//                       death that never respawns (quit to menu, save load)
//                       cannot leave us suspended forever
//
// The teleport is detected as a jump from the position recorded at death.
// Measured jumps were ~19,000 units; normal locomotion is a few units per
// frame, so the threshold has three orders of magnitude of headroom.
constexpr std::uint64_t kSettleAfterRespawnMs = 5000;
constexpr std::uint64_t kHardCeilingMs        = 90000;
constexpr float         kRespawnJumpUnits     = 5000.0f;

std::atomic<std::uint64_t> g_local_player_died_ms{0};
std::atomic<std::uint64_t> g_respawn_seen_ms{0};
std::atomic<bool>          g_standdown_active{false};
float g_death_pos[3] = {0.0f, 0.0f, 0.0f};   // main thread only

// Forward decl: defined further down, next to the other engine readers.
static bool read_local_player_pos(float* out_x, float* out_y, float* out_z) noexcept;

}  // namespace  (reopened below; other translation units need the predicate)

// Pure atomic read — safe from ANY thread, including the network apply path.
// The state behind it is only ever advanced by update_death_standdown() on the
// main thread, so no engine memory is touched here.
bool in_local_death_standdown() noexcept {
    return g_standdown_active.load(std::memory_order_relaxed);
}

// Build 69q — one-shot trigger for the death-time cell re-coherence sweep.
// Set inside the kill dispatch below, consumed by update_death_standdown on
// the NEXT per-frame tick, so the engine MoveTo calls run outside the kill
// event's own dispatch.
static std::atomic<bool> g_death_recohere_pending{false};

void note_local_player_death() noexcept {
    g_local_player_died_ms.store(GetTickCount64(), std::memory_order_relaxed);
    // Build 69k — spend the calm ragdoll window doing the teardown that would
    // otherwise land during the cell unload. See release_all_npc_bone_pins.
    fw::native::release_all_npc_bone_pins();
    // Build 69m — snapshot every actor we have mutated, with its LIVE cell,
    // coordinates and form flags. Two deaths with opposite outcomes now differ
    // in a file we can diff.
    fw::audit::dump("local-player-death");
    // Build 69q — DESPAWN THE OWNERSHIP SPHERE NOW. The engine is about to
    // drop the dead player as a combat target (event 98 passes freely on
    // OWNED raiders — we only block it on mirrors), so our authority over
    // these NPCs is fiction from this frame on. Explicit NPC_UNLOAD per
    // owned fid → the server releases immediately → the surviving peer
    // re-observes and claims on its next frame, instead of waiting out the
    // 8s heartbeat timeout with frozen mirrors ("raiders turn to B only
    // when the body despawns").
    fw::ownership::release_all_owned_on_death();
    // Build 69q — arm the cell re-coherence sweep (see run_death_cell_
    // recohere below).
    // Build 69r (2026-08-04) — DEFAULT OFF. The 10-agent audit's decomp read
    // (funcs_0175.md:8877-8930, funcs_0301.md:6090-6127) proved the sweep's
    // premise false: MoveTo(cell=NULL, marker=NULL) performs NO cell
    // re-file — it queues a "moved" changeform and unconditionally plants
    // ExtraBadPosition on every swept actor, payloads consumed by exactly
    // the LoadGame walkers we were trying to protect. At the 17:46:18 crash
    // the sweep (running BEFORE the release wave, ordering flip) was the
    // only fw touch the victim raider ever had. Keeping the code as an A/B
    // lever: config `death_recohere_sweep = true` re-arms it.
    if (g_death_recohere_sweep_enabled.load(std::memory_order_relaxed)) {
        g_death_recohere_pending.store(true, std::memory_order_relaxed);
    } else {
        FW_LOG("[death-recohere] sweep DISABLED (Build 69r default) — "
               "death release only, no MoveTo churn before the load");
    }
    g_respawn_seen_ms.store(0, std::memory_order_relaxed);
    g_standdown_active.store(true, std::memory_order_relaxed);
    // Best-effort: if the read fails we simply never match the jump and fall
    // back to the hard ceiling, which is the safe direction.
    if (!read_local_player_pos(&g_death_pos[0], &g_death_pos[1], &g_death_pos[2])) {
        g_death_pos[0] = g_death_pos[1] = g_death_pos[2] = 0.0f;
    }
    FW_LOG("[npc-ai-suppress] local player died — stand-down OPEN, holding "
           "until the respawn teleport + %llums settle (ceiling %llums)",
           static_cast<unsigned long long>(kSettleAfterRespawnMs),
           static_cast<unsigned long long>(kHardCeilingMs));
}

namespace {

// Build 69q (2026-08-04) — DEATH-TIME CELL RE-COHERENCE.
//
// The 69p crash forensics finally named the killer: TESObjectCELL 0xDD5D was
// freed and recycled (its "vtable" read back as a POINTER TO CELL 0xDD3C)
// while mirrored raider 0x19174F still referenced it, detonating in
// TESObjectCELL::DetachReference during the respawn LoadGame. Root-cause
// trail: we drive mirror positions ~30 Hz via vt[202] SetPosition
// (ring: 57,632 engsetpos, streaming on THAT raider up to the death
// instant), which re-hashes the actor in its CURRENT parentCell's spatial
// grid but NEVER re-resolves which cell the actor should belong to —
// minutes of coordinates-vs-parentCell divergence that the load teardown
// then walks, 1-in-3 depending on teardown order.
//
// This sweep runs ONCE, on the first per-frame tick after death (outside
// the kill dispatch, ~7 s before the player can even press Load): for every
// tracked NPC (owned + mirrors) still loaded, one engine MoveTo at its
// CURRENT coords with do_process_update=1 — the same process+cell reattach
// primitive the c.44 handoff uses — so parentCell and coordinates agree
// BEFORE LoadGame walks the refs. Skips: the player, dying/dead NPCs
// (MoveTo on a corpse mid-death-anim is asking for trouble), unloaded refs
// (nothing to re-attach; MoveTo could force-load them).
bool read_actor_pos_yaw_loaded(void* actor, float* x, float* y, float* z,
                               float* yaw) noexcept {
    if (!actor) return false;
    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(actor);
        void* lrd = *reinterpret_cast<void* const*>(
            b + fw::offsets::LOADED_REF_DATA_OFF);
        if (!lrd) return false;   // not loaded
        const float* p = reinterpret_cast<const float*>(
            b + fw::offsets::POS_OFF);
        *x = p[0]; *y = p[1]; *z = p[2];
        *yaw = *reinterpret_cast<const float*>(
            b + fw::offsets::ROT_OFF + 8);   // AngleZ
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void run_death_cell_recohere() noexcept {
    std::uint32_t fids[96];
    const std::size_t n = fw::ownership::collect_tracked_fids(fids, 96);
    int done = 0, skipped = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint32_t fid = fids[i];
        if (fid == 0x14u || is_dying(fid)) { ++skipped; continue; }
        void* actor = fw::engine::lookup_by_form_id(fid);
        if (!actor) { ++skipped; continue; }
        float x = 0.0f, y = 0.0f, z = 0.0f, yaw = 0.0f;
        if (!read_actor_pos_yaw_loaded(actor, &x, &y, &z, &yaw)) {
            ++skipped;
            continue;
        }
        if (fw::engine::actor_teleport_handoff(actor, x, y, z, yaw)) {
            ++done;
        }
    }
    FW_LOG("[death-recohere] re-attached cell membership for %d/%zu tracked "
           "actors (%d skipped: player/dying/unloaded) before the load "
           "walks them", done, n, skipped);
}

// MAIN THREAD ONLY — called from the per-frame detour. Advances the little
// state machine above and publishes the result into g_standdown_active.
void update_death_standdown() noexcept {
    if (!g_standdown_active.load(std::memory_order_relaxed)) return;

    // Build 69q — one-shot: the first frame after death, before the state
    // machine below does anything else. The kill dispatch is over, the
    // death-cam ragdoll is playing, the load is seconds away.
    if (g_death_recohere_pending.exchange(false, std::memory_order_relaxed)) {
        run_death_cell_recohere();
    }

    const std::uint64_t now   = GetTickCount64();
    const std::uint64_t died  = g_local_player_died_ms.load(std::memory_order_relaxed);
    const std::uint64_t seen  = g_respawn_seen_ms.load(std::memory_order_relaxed);

    if (seen != 0) {
        if ((now - seen) >= kSettleAfterRespawnMs) {
            g_standdown_active.store(false, std::memory_order_relaxed);
            FW_LOG("[npc-ai-suppress] stand-down CLOSED — %llums after the "
                   "respawn teleport, resuming NPC sync",
                   static_cast<unsigned long long>(now - seen));
            // Build 69s — apply the PHASE_2 claims parked during the window
            // (ownership quiescence). The world is loaded and settled; the
            // mirrors re-track NOW, not mid-load.
            fw::ownership::drain_deferred_phase2_claims();
        }
        return;
    }

    float x, y, z;
    if (read_local_player_pos(&x, &y, &z)) {
        const float dx = x - g_death_pos[0];
        const float dy = y - g_death_pos[1];
        const float dz = z - g_death_pos[2];
        const float d2 = dx * dx + dy * dy + dz * dz;
        if (d2 > (kRespawnJumpUnits * kRespawnJumpUnits)) {
            g_respawn_seen_ms.store(now, std::memory_order_relaxed);
            FW_LOG("[npc-ai-suppress] respawn teleport detected %llums after "
                   "death (jump %.0f units) — holding stand-down %llums more",
                   static_cast<unsigned long long>(now - died),
                   static_cast<double>(std::sqrt(d2)),
                   static_cast<unsigned long long>(kSettleAfterRespawnMs));
            return;
        }
    }

    if ((now - died) >= kHardCeilingMs) {
        g_standdown_active.store(false, std::memory_order_relaxed);
        FW_WRN("[npc-ai-suppress] stand-down hit the %llums ceiling without "
               "ever seeing a respawn teleport — resuming NPC sync anyway",
               static_cast<unsigned long long>(kHardCeilingMs));
        fw::ownership::drain_deferred_phase2_claims();   // Build 69s
    }
}

bool in_local_death_window() noexcept {
    return g_standdown_active.load(std::memory_order_relaxed);
}

char detour_request_stop_combat(void* manager, void* actor) noexcept {
    if (actor && g_c36b_enable.load(std::memory_order_relaxed)) {
        const std::uint32_t fid = safe_read_form_id(actor);
        if (fid != 0 && fid != 0xFFFFFFFFu &&
            fw::ownership::is_non_owner_tracked(fid) &&
            !actor_knocked_or_dead(actor) &&
            !is_dying(fid) &&
            !in_local_death_window()) {
            fw::audit::note(fid, fw::audit::kStopCombatBlocked, actor);
            const auto n = g_stopcombat_blocked.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 20 || (n % 4000) == 0) {
                FW_LOG("[npc-ai-suppress] StopCombat request BLOCKED on mirror "
                       "fid=0x%08X (#%llu) — keeping the HighProcess alive",
                       fid, static_cast<unsigned long long>(n + 1));
            }
            // The engine ignores the return of every call site we traced
            // (all three discard it), so 0 is safe and means "not handled".
            return 0;
        }
    }
    g_stopcombat_passed.fetch_add(1, std::memory_order_relaxed);
    return g_orig_request_stop_combat
        ? g_orig_request_stop_combat(manager, actor)
        : 0;
}

// ===================== Build 69 — HighProcess churn probe =================
// PURPOSE. `set_combat_skip_tick` above writes 1 to HighProcess+0x189 on every
// mirrored NPC, every frame. RE (2026-08-02) established that the ONLY two
// vanilla writers of that byte are the two `Actor::StopCombat` implementations
// (Papyrus native sub_1410FBD50, console sub_1405C2340), and that the reader
// sub_14087A900 is not a "skip this tick" predicate but ShouldStopCombat() —
// returning 1 makes the orchestrator sub_140CCFDF0 dispatch event 98, which is
// Actor::StopCombat (vt slot 256 = sub_140CCFFC0). That function FREES the
// 400-byte HighProcess, NULLs Actor+0x328, and zeroes the combat-target handle
// at Actor+0x380.
//
// So the open question is whether our own suppression is tearing down the very
// combat state we then complain is missing. The field logs cannot answer it:
// the existing OWNER-CAPTURE sampler is decimated `t < 30 || t % 2000`, which
// is start-of-session biased (everything IDLE), and it yielded only 12 samples
// in a combat anim state across both clients.
//
// WHY NULLNESS IS NOT ENOUGH. A freed 0x190 block is returned to a pooled
// allocator that keeps the pages committed and can hand the SAME address back
// immediately. Sampling only `hp == nullptr` would miss a free+realloc that
// lands on the same pointer. So we sample the PAIR (pointer, our marker byte):
// if the address is unchanged but our 1 has become 0, the block was recycled
// underneath us — the case pointer-only instrumentation cannot see.
//
//   00 STABLE  hp valid, same address, marker still 1  (our write survived)
//   01 GONE    hp == nullptr                           (torn down)
//   10 MOVED   hp valid but at a different address      (reallocated)
//   11 WIPED   hp valid, same address, marker cleared   (recycled in place)
//
// VOLUME. 2 bits/tick packed into a u64 = one log line per 32 ticks (~0.53 s)
// per tracked NPC, and all-STABLE words are decimated 16:1 on top of that. The
// Build 68.2 logger stutter (0.525 ms/line with fsync) is the reason this is
// packed rather than sampled — FW_LOG at Info level no longer fsyncs (68.3),
// but volume still matters. Anomalies are NEVER decimated: any word containing
// a non-STABLE tick is emitted whole.
//
// Kill switch: g_hp_churn_probe. Mirror-only by construction — it is called
// from the non-owner branch, which is the side whose combat state is in doubt.
std::atomic<bool> g_hp_churn_probe{true};

struct HpProbeState {
    void*         last_hp = nullptr;
    std::uint64_t word    = 0;
    unsigned      filled  = 0;
    std::uint64_t words   = 0;
    std::uint64_t quiet   = 0;   // consecutive all-STABLE words suppressed
};

std::mutex                                      g_hp_probe_mtx;
std::unordered_map<std::uint32_t, HpProbeState> g_hp_probe;

// SEH-caged read of the pair. MUST be a free function: the detour frame owns
// shared_lock/lock_guard locals and MSVC C2712 forbids __try there (same
// reason actor_has_native_highproc and safe_or_in_combat_bit are file-scope).
bool read_hp_and_marker(void* actor, void** hp_out,
                        std::uint8_t* mark_out) noexcept {
    __try {
        void* hp = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x328);
        *hp_out   = hp;
        *mark_out = hp ? *(reinterpret_cast<std::uint8_t*>(hp) + 0x189) : 0u;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============ Build 69g — WHO DOES A MIRRORED NPC WANT TO ATTACK? =========
//
// THE ONE FACT WE STILL DO NOT HAVE. RE established everything except the
// reading itself:
//   * HighProcess+0x6C is the combat-target ObjectRefHandle, and
//     sub_14087AB30 (AIProcess::SetCombatTarget) is its ONLY writer binary-wide.
//   * It carries the same value as Actor+0x380 — one variable stored to both on
//     adjacent lines (funcs_0240.md:5985-5987) — so resolve_handle_to_formid
//     works on it unchanged.
//   * The engine writes it INDEPENDENTLY of our suppression: the target
//     promoter sub_14087B080 runs BEFORE the gate sub_14087A900 inside the
//     orchestrator and never reads our +0x189 byte (funcs_0307.md:4706-4707).
//   * And the HighProcess now survives on mirrors — ~6,170 stable ticks,
//     ~32 s per raider, same pointer throughout, in the 2026-08-03 18:07 run.
// What has never been observed is the VALUE: does a mirrored raider's +0x6C
// actually resolve to the local player (form 0x14)?
//
// WHY THIS MATTERS MORE THAN IT LOOKS. The engage signal we feed the server
// today is worthless: on both clients the owner-capture totals are
// `any == s0` EXACTLY (A 7552/7552, B 2581/2581), and s0 is merely
// "Actor+0x328 != NULL". So the owner relays "AIMING" because the NPC HAS a
// combat process, carrying zero information about WHOM it fights. Both peers
// then score the same +10 engage and the multiplicative FLIP_MARGIN can never
// separate them — measured: 80 of 80 threat rows above the proximity ceiling
// have BOTH sides above it, median gap 0.53 on ~15.4.
// Counterfactual against the same 734 logged rows: an EXCLUSIVE signal flips
// 80/80 within one tick; a common-mode one flips 0/734. So the whole value of
// this work rides on +0x6C naming a specific actor rather than announcing that
// combat exists.
//
// READ-ONLY. No engine memory is written here. Decimated hard: one line per
// (fid, resolved-target) transition plus a periodic heartbeat, because the
// interesting event is the CHANGE, not the steady state — and because a
// per-frame log on the mirror path is what caused the Build 68.2 stutter.
struct MirrorTargetState {
    std::uint32_t last_fid_target = 0xFFFFFFFFu;   // sentinel: never sampled
    std::uint64_t samples         = 0;
    std::uint64_t hits_local      = 0;             // resolved to form 0x14
};
std::mutex                                            g_mtgt_mtx;
std::unordered_map<std::uint32_t, MirrorTargetState>  g_mtgt;

// SEH-caged: HighProcess may be freed between the null check and the read.
// Free function for the usual C2712 reason (the detour frame owns lock guards).
bool read_mirror_target_handle(void* actor, std::uint32_t* out_handle) noexcept {
    __try {
        void* hp = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x328);
        if (!hp) return false;
        *out_handle = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(hp) +
            fw::offsets::AIPROCESS_COMBAT_TARGET_HANDLE_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// `owner_side` = true when we are the OWNER of this NPC, i.e. its vanilla AI
// is running normally. That arm is the CONTROL, and without it the experiment
// is uninterpretable: the first run returned target=0 on every mirrored raider
// for the whole session, which is equally consistent with "the mirror has no
// combat target" and with "we are reading the wrong offset". The owner arm
// settles it — an owner whose raider is actively shooting the local player
// MUST show a non-zero handle resolving to form 0x14. If it does not, the
// read is wrong and the mirror result means nothing.
void probe_mirror_target(void* actor, std::uint32_t fid,
                         bool owner_side) noexcept {
    std::uint32_t raw = 0;
    if (!read_mirror_target_handle(actor, &raw)) return;   // no HighProcess yet

    // 0 is the engine's "no target" sentinel (dword_1430DA180 == 0).
    const std::uint32_t tgt =
        (raw == 0) ? 0u : fw::engine::resolve_handle_to_formid(raw);

    std::lock_guard<std::mutex> lk(g_mtgt_mtx);
    // Keyed on (fid, side): the same NPC can be sampled on both arms across an
    // ownership flip, and one arm must never overwrite the other's history.
    MirrorTargetState& st = g_mtgt[fid ^ (owner_side ? 0x80000000u : 0u)];
    ++st.samples;
    if (tgt == fw::offsets::PLAYER_FORMID) ++st.hits_local;

    // Emit on TRANSITION only, plus a heartbeat every ~4000 samples so a
    // long steady state still leaves a trace.
    const bool changed   = (tgt != st.last_fid_target);
    const bool heartbeat = (st.samples % 4000) == 0;
    if (!changed && !heartbeat) return;
    st.last_fid_target = tgt;

    FW_LOG("[mirror-target] %s fid=0x%08X -> target=0x%08X %s "
           "(raw_handle=0x%08X, samples=%llu, local_hits=%llu)",
           owner_side ? "OWNER  " : "MIRROR", fid, tgt,
           (tgt == fw::offsets::PLAYER_FORMID) ? "== LOCAL PLAYER"
                                               : (tgt == 0 ? "(none)" : ""),
           raw,
           static_cast<unsigned long long>(st.samples),
           static_cast<unsigned long long>(st.hits_local));
}
// ==========================================================================

// Call PRE-orig and BEFORE set_combat_skip_tick, so we observe the state the
// engine left after the previous frame rather than reading back our own write.
void probe_hp_churn(void* actor, std::uint32_t fid) noexcept {
    if (!g_hp_churn_probe.load(std::memory_order_relaxed) || !actor) return;

    void* hp = nullptr;
    std::uint8_t mark = 0;
    if (!read_hp_and_marker(actor, &hp, &mark)) return;

    std::lock_guard<std::mutex> lk(g_hp_probe_mtx);
    HpProbeState& st = g_hp_probe[fid];

    // The marker is only meaningful in the arm where we actually write it.
    // With the suppression off nobody sets +0x189, so a surviving HighProcess
    // would otherwise be misfiled as WIPED and the control run would read as
    // a catastrophe instead of a success.
    const bool armed = g_c36b_enable.load(std::memory_order_relaxed);

    unsigned code;
    if (!hp)                          code = 1;   // GONE
    else if (hp != st.last_hp)        code = 2;   // MOVED (incl. first sight)
    else if (armed && mark != 1u)     code = 3;   // WIPED in place
    else                              code = 0;   // STABLE (survived the frame)
    st.last_hp = hp;

    st.word |= (static_cast<std::uint64_t>(code) << (2u * st.filled));
    if (++st.filled < 32u) return;

    const std::uint64_t w = st.word;
    st.word = 0; st.filled = 0; ++st.words;

    // Anomaly-preserving decimation: an all-STABLE word is 0, and only those
    // are dropped. Anything else is a datum we cannot reconstruct later.
    if (w == 0) {
        if (++st.quiet % 16u != 0u) return;
    } else {
        st.quiet = 0;
    }

    unsigned n[4] = {0, 0, 0, 0};
    for (unsigned i = 0; i < 32u; ++i) ++n[(w >> (2u * i)) & 3u];
    FW_LOG("[hp-churn] fid=0x%08X w#%llu %016llX stable=%u gone=%u moved=%u "
           "wiped=%u hp=%p", fid,
           static_cast<unsigned long long>(st.words),
           static_cast<unsigned long long>(w),
           n[0], n[1], n[2], n[3], hp);
}
// ==========================================================================

// Build 65.c.22 — SEH-safe OR del bit 0x4000 a Actor+0x2D0. Helper a
// scope file perché il detour body ha shared_lock locals che vietano
// __try (MSVC C2712). Chiamato 60Hz DOPO orig call su non-owner tracked
// NPCs quando l'owner riporta combat (anim_state >= 3).
//
// Razionale: l'engine perception walker INSIDE orig clear questo bit
// perché non perceive enemy locale (player_B su B vede solo player_B,
// non player_A). Senza il bit, behavior tree drives idle/patrol anim.
// Forzare 60Hz da QUI (dopo orig) → il bit persiste tra orig consecutivi
// → behavior tree drives combat anim → user vede raider in combat stance.
static void safe_or_in_combat_bit(void* actor) noexcept {
    if (!actor) return;
    __try {
        auto* const flags = reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x2D0);
        *flags |= 0x4000u;   // ACTOR_FLAG_IN_COMBAT
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Actor torn down between detour entry and post-orig write. No-op.
    }
}

// Build 65.c.24 — SEH-safe read of CombatController+0x98 ("in combat" root
// indicator per Agent 2 dossier B65_c23_combat_flag_AGENT_2.md).
//
// Chain: Actor+0x328 → AIProcess. AIProcess+0x40 → CombatController.
// CombatController+0x98 (u32) = 0 disengaged, !=0 engaged.
// Set path: sub_140E99350 (engage). Clear path: sub_140E9A3E0 (disengage).
//
// This is the UPSTREAM source of bit 0x4000 at Actor+0x2D0 — sub_140C5CCE0
// mirrors +0x98 into the bit every frame. The bit lags by 1 tick + can be
// stomped intra-frame; reading +0x98 directly removes the mirror lag.
//
// Note: per Judge audit, +0x98 alone is NOT sufficient — same upstream that
// already shows as 0 when the engine's perception walker decides "no LOS
// this frame". c.24 uses this as Signal 2 of a 3-signal OR (S1 = bit at
// +0x2D0, S2 = this value, S3 = recently_fired) to get a robust combat
// detection that survives per-frame oscillation.
//
// Lifetime safety: chain has 2 dereferences; either can be null mid-cell-
// streaming or when raider is in low AI tier. SEH cage catches AV. The
// caller treats a `false` return as "S2 = 0", not "error" — combined with
// S1/S3 the multi-signal aggregate yields a usable verdict regardless.
static bool safe_read_combat_controller_active(void* actor) noexcept {
    if (!actor) return false;
    __try {
        auto* const aiproc = *reinterpret_cast<void* const*>(
            reinterpret_cast<const std::uint8_t*>(actor) + 0x328);
        if (!aiproc) return false;
        auto* const cc = *reinterpret_cast<void* const*>(
            reinterpret_cast<const std::uint8_t*>(aiproc) + 0x40);
        if (!cc) return false;
        const std::uint32_t flag = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(cc) + 0x98);
        return flag != 0u;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// c.39a — cached module base (set at install) for reading the player singleton.
std::atomic<std::uintptr_t> g_module_base{0};

// Build 69b — the Actor::StopCombat OBSERVER lived here and has been REMOVED.
//
// It answered its question completely, on both clients. The callers of
// Actor::StopCombat are: sub_140C4CE00+0x2323 (the event-98 dispatcher itself,
// 1236 calls with on_mirror=0, which proves the emitter-side block holds),
// sub_140515C90+0x23B (dispatcher case 74 — the SECOND destroyer, the only
// site with on_mirror>0), sub_140C2CAD0+0xEB and sub_140C9A400+0x121.
// ACTOR_STOP_COMBAT_RVA stays documented in offsets.h in case it is needed.
//
// Removed because it was finished work carrying live risk: a MinHook detour
// that takes a mutex and does synchronous file I/O inside an engine teardown
// function is a timing perturbation on a path that runs during cell unload and
// the post-death reload — exactly the window in which client A took an AV. An
// audit found it deadlock-free, re-entry-safe and free of engine writes, so it
// is NOT proven to have caused that crash; but "no proven harm" is not a
// reason to keep an instrument whose measurement is complete.


// c.39a — the LOCAL player's current combat-target (read from its own
// PlayerCharacter at Actor+0x380, written every frame by the engine's combat-
// target mirror sub_140C5CCE0). This is the fix for the dead handoff trigger:
// a NON-owner reads THIS on its own player to know "I'm fighting NPC X" — which
// works even though X's mirror AI is suppressed and never sets X's own InCombat
// bit. Returns 0 (no target) on null/SEH.
//
// Build 68.1 — HANDLE FIX (decomp-verified): the u32 at +0x380 is an
// ObjectRefHandle, NOT a form id (engine reader funcs_0188.md:8261-8276
// resolves it through the 0x1430DA390 handle table with generation checks).
// Every pre-68.1 consumer compared this raw handle to a form id = permanent
// false-negative (the [c39b-diag] "player_combat_target=0x0021D625" values
// were handles all along). Resolve to the target's REAL form id first.
static std::uint32_t read_local_player_combat_target_fid() noexcept {
    const std::uintptr_t base = g_module_base.load(std::memory_order_relaxed);
    if (!base) return 0;
    std::uint32_t raw_handle = 0;
    __try {
        void* player = *reinterpret_cast<void* const*>(
            base + fw::offsets::PLAYER_SINGLETON_RVA);
        if (!player) return 0;
        raw_handle = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(player) +
            fw::offsets::ACTOR_COMBAT_TARGET_FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (raw_handle == 0) return 0;
    return fw::engine::resolve_handle_to_formid(raw_handle);
}

// Sphere proximity seed (idle-ownership upgrade) — kill-switch + hysteretic
// radii. When ON, ANY nearby actor (except the local player) is observed so an
// IDLE / unowned NPC enters the SAME ownership pipeline as a combat observe and
// is force-mirrored on every client — fixing idle-desync (idle raiders/settlers
// diverged because they were never owned). Bounded by the sphere distance + the
// existing one-shot observe dedup → no UDP storm (the c.8 storm was UNBOUNDED
// per-frame observation of ~170 actors; distance + dedup cap this to a one-time
// burst, then 0/s). The server treats a proximity-only observe (NEGATIVE dist²)
// as a no-engagement seed that yields INSTANTLY to a real fighter
// (ownership.py PROXIMITY_SEED_ENABLED). Radii are GAME UNITS (~60-100 u/m, so
// R_in ≈ 100-165 m) — small on purpose: sync kicks in "when a player can see
// them", and at that range the owner renders the NPC full-detail = best pose
// capture. Tune live. kProximitySphereEnabled=false → exact pre-upgrade gate.
// Radii tuned down after the first live test: at R_in=10000 the sphere reached
// raiders in a NEIGHBOURING streaming-edge cell (0xDD80, ~10000u away) that the
// owner LOADS but does NOT high-process → it can't stream them → 2.5s heartbeat
// timeout → release → reseed loop (~3s epoch churn = "synced only on aggro").
// 7000u keeps the sphere INSIDE the owner's high-process bubble (the actors it
// actually simulates every frame), so seeding sticks. Sync now starts a bit
// closer ("when you're in the area"), which is the intended trade.
static constexpr bool  kProximitySphereEnabled = true;
// Build 67.2 — radius +20% (user call, empirical test for the distant-aggro
// regression: distant raiders no longer go hostile on gunshots since the
// sphere landed). 7000→8400 in, 9500→11400 out (hysteresis ratio preserved).
static constexpr float kSphereR2_in  = 8400.0f * 8400.0f;    // own inside this
static constexpr float kSphereR2_out = 11400.0f * 11400.0f;  // release past this

// SEH-safe read of the LOCAL player's world position (PlayerCharacter singleton
// + POS_OFF). Clone of read_local_player_combat_target_fid above — reads the
// player singleton ONLY (never the raider actor), so it cannot fault on an
// unloading NPC. Returns false on null/SEH (outs left untouched).
static bool read_local_player_pos(float* out_x, float* out_y,
                                  float* out_z) noexcept {
    const std::uintptr_t base = g_module_base.load(std::memory_order_relaxed);
    if (!base) return false;
    __try {
        void* player = *reinterpret_cast<void* const*>(
            base + fw::offsets::PLAYER_SINGLETON_RVA);
        if (!player) return false;
        const float* p = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(player) + fw::offsets::POS_OFF);
        *out_x = p[0];
        *out_y = p[1];
        *out_z = p[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void __fastcall detour_actor_update_perframe(void* actor, float sim_time) {
    const std::uint32_t fid = safe_read_form_id(actor);

    // Build 69d — TOTAL STAND-DOWN while the local player is dead.
    //
    // Measured twice, 2026-08-02: client A took an AV ~150 ms after the
    // post-death respawn teleport, at TWO DIFFERENT addresses (0x2A007D in
    // BSExtraDataList::GetByType, then 0x4CC644). Two distinct faults in the
    // same 150 ms window is the signature of touching structures the engine is
    // concurrently tearing down, not of one specific bug.
    //
    // What happens in that window, from the logs: the player dies, respawns
    // ~19,000 units away, and the server re-elects ownership on proximity —
    // 13 ownership changes landed in the SAME SECOND as the second crash
    // (16:15:45), handing this client 7 NPCs at the destination and taking
    // away 6 at the raider camp it was leaving. Every one of those flips
    // switches our per-frame handling of that actor between owner-capture and
    // mirror-apply, and mirror-apply writes engine state: position through
    // vt[202], Havok keyframing, bone transforms. So we start writing into
    // actors of the OLD cell exactly while that cell is being unloaded.
    //
    // The player is dead and staring at a load screen: there is nothing to
    // keep in sync and nothing to see. So we do NOTHING to any actor —
    // straight passthrough to vanilla — until the dust settles. This is
    // deliberately blunt: a narrower per-actor guard cannot know which actors
    // the engine is mid-way through unloading, which is the whole problem.
    // Advance the death-standdown state machine once per frame (it watches for
    // the respawn teleport and closes the window kSettleAfterRespawnMs after).
    // Cheap no-op unless the window is open. Runs before the check below so the
    // very frame that detects the teleport is handled consistently.
    update_death_standdown();

    if (in_local_death_window()) {
        static std::atomic<std::uint64_t> s_standdown_ticks{0};
        const auto n = s_standdown_ticks.fetch_add(1, std::memory_order_relaxed);
        if (n == 0 || (n % 2000) == 0) {
            FW_LOG("[npc-ai-suppress] death stand-down active — passing every "
                   "actor straight to vanilla (tick #%llu)",
                   static_cast<unsigned long long>(n + 1));
        }
        if (g_orig_actor_update_perframe) {
            g_orig_actor_update_perframe(actor, sim_time);
        }
        return;
    }

    // B6.6w5 Build 28k — UNCONDITIONAL bail for our ghost proxy.
    //
    // The proxy is a PlaceAtMe-spawned Actor registered under our
    // ghost_form_id (0xFF000001) in client-side lookup. Engine's
    // ProcessLists adds it during the spawn's ctor chain → walker
    // visits it per-frame → sub_140CC8920 anim-graph state evaluator
    // reads partially-init state → AV at sub_140256B80 (Build 28i/j).
    //
    // We don't need the engine to tick the proxy's AI. The proxy
    // exists solely as a combat-target handle slot: raiders' aiproc+
    // 0x6C is set to proxy's handle, raider aim/fire reads that and
    // dereferences proxy (refr+0xD0 pos, etc.). Those reads don't
    // require AI ticking the proxy.
    //
    // Bailing Update_PerFrame on the proxy:
    //   - Prevents anim-graph state walker from running
    //   - Prevents AI orchestrator from advancing proxy's combat brain
    //   - Leaves the proxy's pos/rot fields fully readable
    //   - Engine's per-frame combat-target reads on raiders STILL run
    //
    // This is the cleanest "tocchiamo le radici" — instead of patching
    // each downstream walker, kill the per-frame entry point for our
    // proxy.
    if (fid == fw::offsets::GHOST_FORMID_BASE) {
        // Build 35 (2026-05-16) — ONE-HOOK BASEFORM SWAP, ghost-side.
        //
        // Every visit of the walker is a chance to perform the one-shot
        // swap of ghost+0xE0 from PlayerNPC (fid 0x07) to a vanilla
        // non-PlayerNPC TESNPC. The swap requires:
        //   1. A cached safe TESNPC pointer (filled by the non-ghost
        //      branch below on whichever raider/settler is first
        //      walked this session).
        //   2. The ghost's current baseForm == PlayerNPC (sanity check
        //      against double-swap).
        //
        // Both conditions are validated inside try_swap_ghost_baseform;
        // it's idempotent + fast-path early-out (atomic-load) once the
        // swap is done. Calling it every ghost-visit costs ~1 atomic
        // load per frame — negligible.
        //
        // After the swap, every engine reader of `*(ghost+0xE0)` —
        // damage/aim/perception/faction/relation — gets a vanilla NPC
        // pointer instead of PlayerNPC. The 155+ player-special branches
        // never fire on this ghost. The entire crash CLASS we've been
        // patching per-leaf (F2/F5/F9 + sub_140CC9150 + …) is removed
        // at the source.
        fw::engine::try_swap_ghost_baseform(actor);

        static std::atomic<std::uint64_t> g_ghost_bails{0};
        const auto bn = g_ghost_bails.fetch_add(
            1, std::memory_order_relaxed);
        if (bn < 5 || (bn % 1000) == 0) {
            FW_LOG("[npc-ai-suppress] GHOST-BAIL #%llu actor=%p "
                   "fid=0x%08X — Update_PerFrame skipped for proxy",
                   static_cast<unsigned long long>(bn), actor, fid);
        }
        return;
    }

    // === Build 65 — owner-driven NPC sync gate (Solver 2) ==================
    //
    // Three decisions, in evaluation order:
    //
    //   1. Observation: if we don't yet know about this NPC, send NPC_OBSERVED
    //      so the server's election can include it. Deduplicated inside
    //      `notify_observation` (one-shot per fid per session).
    //
    //   2. Non-owner of a tracked NPC → bail. Some other peer is the
    //      authority; their NPC_STATE_FROM_OWNER drives our visuals via
    //      the receiver-side apply (lands in 65.c.3). Skipping the original
    //      Update_PerFrame here means we don't fight the owner's pos
    //      writes with our own engine AI ticks.
    //
    //   3. Owner of this NPC → record current Actor pos/yaw into the TX
    //      cache, then run vanilla AI normally. The next periodic tick
    //      (~10 Hz) drains the cache into NPC_STATE_FROM_OWNER for the
    //      server to relay.
    //
    //   4. Untracked (ownership map empty for this fid) → fall through to
    //      the existing Build 64 logic. Critical fallback: when the
    //      server hasn't elected anyone yet, the DLL behaves exactly as
    //      it did pre-Build 65. This avoids regression in the first few
    //      seconds after spawn while OBSERVED → PHASE_2 is in flight.
    //
    // Cheap: predicates are `unordered_map::find` under a shared_lock.
    if (fid != 0 && fid != 0xFFFFFFFFu && actor) {
        std::uint32_t base_id = 0, cell_id = 0;
        float px = 0.0f, py = 0.0f, pz = 0.0f;
        const bool id_ok = safe_read_actor_identity(
            actor, &base_id, &cell_id, &px, &py, &pz);
        // Build 65.c.8 (fixed in 65.c.9) — gate observations on the
        // InCombat flag (Actor+0x2D0 bit 0x4000). Without this, the
        // detour observed EVERY loaded actor (~170: settlers, vendors,
        // Codsworth, civilians) and the server claimed each one →
        // 278 PHASE_2/sec reliable frames → UDP retransmit storm
        // (1417 retries at attempt 9) → ghost POS arrives late → stutter.
        //
        // 65.c.8 first tried `is_actor_bail_tracked` but that predicate
        // is hardcoded to return false (deprecated since B6.6w3) — so
        // zero NPCs were ever observed. This time we read the engine's
        // own InCombat flag directly; SEH-safe via `safe_read_actor_flags`.
        // Cuts the working set to the raiders actively fighting, which
        // is exactly the owner-driven sync scope.
        // c.48 — OBSERVATION gate broadened from the volatile InCombat bit (S1)
        // alone to S1 || S2 || S3 (the same combat detection the c.36a OWNER-
        // CAPTURE already uses, minus raw S0). RCA agent + decomp-verified root
        // cause: the InCombat bit S1 ≡ CombatController+0x98 (writer sub_140C5CCE0)
        // is set ONLY by the perception-driven combat path. The MQ102 Museum/
        // Concord QUEST raiders (e.g. 0x46458/0x46459) fight via a SCRIPTED package
        // scene → that bit is STRUCTURALLY never set (not "decayed") → they were
        // observed NEVER → never owned → idle-desync on the non-owner. They DO
        // fire, so S3 (recently_fired ≤1.5s) is the unforgeable "real combatant"
        // signal that catches them WITHOUT re-opening the c.8 UDP-observation storm
        // (raw S0=HighProcess would observe idle settlers/Codsworth/companions —
        // do NOT add it here). S2 is cheap insurance for the melee edge.
        // KNOWN GAP: a pure-melee quest enemy that never fires AND never sets
        // CombatController+0x98 (a possible future boss) still wouldn't be caught —
        // revisit with a hostile-baseform-bounded S0 when we get to the boss.
        // Build 68 (A1) — S4: the LOCAL player is actively fighting THIS npc
        // (its combat target points at this fid). This is the fix for the
        // 2026-06-11 ownership asymmetry: a peer fighting an NPC owned by the
        // OTHER client generated NEITHER engage NOR damage threat, because on a
        // mirror the NPC's own combat signals S1/S2/S3 are cleared by the c.36b
        // +0x189 suppression and a keyframed body doesn't register Health
        // damage. Result: the fighting non-owner stayed at proximity-only threat
        // (~1.0) and the server's ABS_DELTA(3) hysteresis locked it out of ever
        // re-acquiring the raider it was shooting. The player's OWN combat target
        // is unsuppressed (it lives on the local PlayerCharacter, not the
        // mirror), so it is a faithful "I am fighting this" signal → send a
        // combat observe (engage, weight 10), not a proximity seed. Now the
        // engage term reflects who is actually fighting, so ownership follows the
        // fighter and ABS_DELTA works as designed (engage ~10 clears the 3 gap).
        // Short-circuits: read_local_player_combat_target_fid() only runs when
        // S1/S2/S3 are all false; fid != 0 is guaranteed above, so a 0 (no
        // target) return cannot false-match.
        const std::uint32_t actor_flags = safe_read_actor_flags(actor);
        const bool combat_relevant =
            (actor_flags & ACTOR_FLAG_IN_COMBAT) != 0                                 // S1: InCombat bit
            || safe_read_combat_controller_active(actor)                              // S2: CombatController+0x98
            || fw::dispatch::recently_fired(fid, fw::dispatch::RECENT_FIRE_WINDOW_MS) // S3: fired ≤1.5s
            || (read_local_player_combat_target_fid() == fid);                        // S4: local player fighting THIS npc

        // S4 — sphere proximity seed (OR'd on, nothing removed). Any nearby
        // actor except the local player (0x14) gets observed so an idle/unowned
        // NPC enters ownership and is force-synced. Hysteresis via the existing
        // tracked predicates (own inside R_in, keep until R_out — no new state).
        bool proximity_seed = false;
        float seed_dist2 = 0.0f;
        if (kProximitySphereEnabled && id_ok && fid != 0x00000014u) {
            float lx = 0.0f, ly = 0.0f, lz = 0.0f;
            if (read_local_player_pos(&lx, &ly, &lz)) {
                const float dx = px - lx, dy = py - ly, dz = pz - lz;
                seed_dist2 = dx * dx + dy * dy + dz * dz;
                const bool already = fw::ownership::is_owner_of(fid)
                                  || fw::ownership::is_non_owner_tracked(fid);
                proximity_seed = (seed_dist2 <= (already ? kSphereR2_out
                                                         : kSphereR2_in));
            }
        }

        if (id_ok && (combat_relevant || proximity_seed)) {
            // Combat observe keeps its 0.0f (byte-identical to pre-upgrade). A
            // PROXIMITY-ONLY seed carries the NEGATIVE-encoded dist² (-(d+1) is
            // strictly <0 even at d==0) → the server reads the sign bit and
            // treats it as a no-engagement idle seed.
            const float wire_dist = combat_relevant
                ? 0.0f
                : -(seed_dist2 + 1.0f);
            fw::ownership::notify_observation(
                fid, base_id, cell_id, px, py, pz, wire_dist);
        }

        // Build 65.c.36b — mirror combat suppression + un-stick (PRE-orig, so
        // the value is in place before the engine ticks this actor's combat).
        //   - non-owner mirror  → +0x189=1  (stop aiming at the local player +
        //                                     stop the local combat-crouch →
        //                                     no sliding; relayed yaw/pos drive)
        //   - raider we own      → +0x189=0  (un-stick: the engine never clears
        //                                     it, and it's savegame-persisted)
        //   - untracked actor    → leave the engine's flag untouched (vanilla)
        if (fid != 0 && fid != 0xFFFFFFFFu) {
            const bool mirror = fw::ownership::is_non_owner_tracked(fid);

            // Build 69 — the probe MUST sit OUTSIDE g_c36b_enable. It was
            // first written inside that guard, which made the whole control
            // run useless: turning the suppression off to measure its effect
            // also turned off the measurement, and client B produced zero
            // [hp-churn] lines. The probe is the instrument, not part of the
            // treatment — it runs in both arms of the A/B.
            //
            // Still placed BEFORE set_combat_skip_tick so it observes the
            // state the engine left last frame rather than our own write.
            if (mirror) {
                probe_hp_churn(actor, fid);
                // Build 69g — read-only: does this mirrored NPC's combat
                // target resolve to OUR player? Same placement rationale.
                probe_mirror_target(actor, fid, /*owner_side=*/false);
            } else if (fw::ownership::is_owner_of(fid)) {
                // Build 69h — the CONTROL arm. Same read, same offset, on an
                // NPC whose vanilla AI is running. If this never shows a
                // non-zero target either, the offset is wrong and the mirror
                // result is meaningless.
                probe_mirror_target(actor, fid, /*owner_side=*/true);
            }

            if (g_c36b_enable.load(std::memory_order_relaxed)) {
                if (mirror) {
                    fw::audit::note(fid, fw::audit::kSkipTickWritten, actor);
                    set_combat_skip_tick(actor, true);
                } else if (fw::ownership::is_owner_of(fid)) {
                    set_combat_skip_tick(actor, false);
                }
            }
        }

        // (2) Non-owner: NO LONGER SUPPRESS Update_PerFrame here.
        //
        // Build 65.c.20 REVERT (Build 45 NEVER SILENCE principle):
        // bailing Update_PerFrame on non-owner blocked the engine's
        // anim/perception walker (sub_140CE1720) → bIsAttacking /
        // bIsAimingGun never written → behavior tree stuck in IDLE
        // node → raider visually "tronco di legno" on the non-owner's
        // screen even though pos+yaw apply landed.
        //
        // Validation source: L1 safety agent analysis (build 65.c.19
        // → c.20 transition). Mathematical proofs:
        //   - pos drift: 0 (ghost_ai_pos_belt leaf-hook bails on
        //     non-owner before sub_140513A80 writes Actor+0xD0)
        //   - anim drift: engine 60Hz vs apply 10Hz, engine wins 6/7
        //     frames per cycle, our STATE_FROM_OWNER apply wins 1/7.
        //     Visible 100ms stutter, tolerable; both writers converge
        //     toward consistent state because their decisions are
        //     correlated (both observe same raider+PC distance/LOS).
        //   - crash class: Build 64 ran this path unconditionally
        //     without regression; only Build 65 added the bail.
        //   - dual-fire risk: mitigated by sibling fix below in
        //     ghost_ai_fire (non-owner bails CombatBehaviorGunFire so
        //     the engine doesn't spawn duplicate projectiles).
        //
        // Track non-owner ticks for diagnostics. Counter cresce normally
        // (non più "suppress" perché abbiamo smesso di sopprimere).
        if (fw::ownership::is_non_owner_tracked(fid)) {
            g_passthrough_fires.fetch_add(
                1, std::memory_order_relaxed);

            // Build 65.c.23 — COMBAT-DRIVEN HANDOFF emission.
            //
            // If THIS peer's local engine has the InCombat flag set
            // (Actor+0x2D0 bit 0x4000) on a tracked non-owned NPC, this
            // peer's player is the actual combat opponent — not a
            // heuristic, not a guess: the engine's own combat-decide
            // chain (sub_140C7AD40 hostility resolver) put the bit
            // there because IsHostileToActor(this_NPC, local_player)
            // returned true.
            //
            // Send NPC_ENGAGEMENT_CLAIM so the server can force handoff
            // if the current owner hasn't been reporting engagement.
            //
            // Dedup: 2 s cooldown per fid (see client.cpp). At 60 Hz
            // detour rate × N tracked we'd otherwise flood; the cool-
            // down strikes a balance vs the 3 s server grace window.
            //
            // Build 65.c.26 Tier 3 — TIGHTEN CLAIM GATE.
            //
            // Per Agent 1 forensics post-c.25: server granted B's handoff
            // on owner_engagement_age=38593ms (stale-owner grace timeout),
            // NOT on actual sustained combat. B had only 2 InCombat
            // OBSERVED events for the entire 2-min session — both at the
            // same 6 ms window of the claim TX. The "1-frame ping = full
            // ownership transfer" anti-pattern transferred the raider to
            // a peer that wasn't really engaged.
            //
            // Fix: require COMBAT_STREAK >= 2 consecutive detour fires
            // with combat_relevant=true before allowing the claim emit.
            // At 60 Hz detour rate, 2 consecutive = ~33 ms minimum
            // continuous engagement. Eliminates 1-frame transient blips
            // (e.g., raider rotated FOV across player_B for 1 frame then
            // lost LOS) from triggering handoff.
            //
            // Per-fid streak map. Streak resets to 0 on combat_relevant=
            // false (= bit cleared this frame). Map under mutex, hot path
            // is 60 Hz × N tracked but each call does single map lookup +
            // increment — cheap. No memory leak since fids are bounded
            // by ownership table size.
            // c.39a — THE HANDOFF-TRIGGER FIX. The streak used `combat_relevant`
            // = the NPC MIRROR's InCombat bit. On a non-owner the mirror's AI is
            // suppressed, so that bit is NEVER set → the streak never advanced →
            // a never-owner could not claim → aggro froze on the first owner.
            // Read the LOCAL PLAYER's own combat target instead (independent of
            // the NPC's suppression): "is my player fighting THIS npc right now?"
            const bool local_targeting =
                (read_local_player_combat_target_fid() == fid);
            {
                static std::mutex                                  s_streak_mtx;
                static std::unordered_map<std::uint32_t,
                                          std::uint32_t>           s_combat_streak;
                std::uint32_t streak_after = 0;
                {
                    std::lock_guard lk(s_streak_mtx);
                    auto& ref = s_combat_streak[fid];
                    if (local_targeting) {
                        ref = ref + 1;
                    } else {
                        ref = 0;
                    }
                    streak_after = ref;
                }
                if (streak_after >= 2) {
                    fw::net::client().enqueue_engagement_claim_dedup(fid);
                    static std::atomic<std::uint64_t> s_clm{0};
                    const auto cn = s_clm.fetch_add(1, std::memory_order_relaxed);
                    if (cn < 20 || (cn % 200) == 0) {
                        FW_LOG("[c39a-claim] fid=0x%08X local player combat-target "
                               "== this NPC → engagement claim (#%llu)", fid,
                               static_cast<unsigned long long>(cn));
                    }
                }
            }

            // Fall through. Vanilla Update_PerFrame runs below.
            // Server-relay STATE_FROM_OWNER apply (drain_npc_owner_
            // state_apply_queue) sovrascrive pos/yaw/anim_state al
            // suo cadence di 10Hz; non-owner engine state e nostro
            // override convergono.
        }
        // (3) Owner: state capture MOVED to POST-orig (see end of detour
        //     for Build 65.c.24 multi-signal anim_state). Capturing
        //     pre-orig misses the engine's just-updated InCombat flag —
        //     Agent 2 RE proved sub_140C5CCE0 (the ONLY function that
        //     writes Actor+0x2D0 bit 0x4000) is part of the per-frame
        //     chain inside orig. Pre-orig read sees stale state from N-1.
        //
        //     Post-orig also lets us read px/py/pz reflecting engine's
        //     just-applied motion this frame, so receivers extrapolate
        //     from the freshest possible sample.
        //
        //     We DON'T early-return here — Build 32+ fixed-selector
        //     install and diagnostic gates still need to fire under the
        //     owner's authoritative tick.
        // (4) Else: fall through (Build 64 behavior).
    }

    // Build 31.2 — REVERTED per-tick purge.
    //
    // Build 31.1 ran `purge_stale_actor_state` for EVERY actor every tick.
    // Live test 2026-05-16 17:21 (user did `coc concordext` to teleport
    // to Concord) showed this races with cell-load: while the engine is
    // mid-allocating combat state for streaming-in actors, our purge
    // walks transient/partially-init controllers and (despite the SEH
    // cage neutralizing OUR direct fault) leaves the engine in a state
    // where its OWN later access to `controller+0x08` (208-byte detection
    // records, NOT touched by us) crashes with the data ptr still at
    // sentinel `0x1`.
    //
    // Decision: the per-tick purge was redundant. The actual fix lives
    // inside `engine::install_fixed_selector_on_raider` →
    // `install_fixed_selector_seh` which calls BOTH
    // `purge_stale_aiproc_handles` + `purge_stale_known_targets` BEFORE
    // AddTarget. That path fires only when the raider has fully
    // transitioned to combat tier (NPC_DISCOVER + InCombat flag observed),
    // at which point the combat AIProcess is guaranteed allocated and
    // the engine is past the cell-load race window.
    //
    // Keeps `fw::engine::purge_stale_actor_state` available for future
    // manual invocations (e.g., if we add a one-shot post-LoadGame
    // global sweep). No call from this hot path.

    // B6.6w0 hook #3 support: register (aiproc -> fid) lazily. Cheap —
    // shared_lock to check membership, only escalate to unique_lock on
    // insert/update. Skips on SEH-failed fid (don't poison map with
    // sentinel) and on missing actor.
    if (fid != 0 && fid != 0xFFFFFFFFu && actor) {
        const void* aiproc =
            safe_read_ptr_at_local(actor, ACTOR_AIPROCESS_OFFSET);
        if (aiproc) {
            bool need_write = false;
            {
                std::shared_lock<std::shared_mutex> lk(g_aiproc_mtx);
                const auto it = g_aiproc_to_fid.find(aiproc);
                if (it == g_aiproc_to_fid.end() || it->second != fid) {
                    need_write = true;
                }
            }
            if (need_write) {
                std::unique_lock<std::shared_mutex> lk(g_aiproc_mtx);
                auto [it, inserted] =
                    g_aiproc_to_fid.insert_or_assign(aiproc, fid);
                if (inserted) {
                    g_aiproc_map_size.store(g_aiproc_to_fid.size(),
                                            std::memory_order_relaxed);
                }
            }
        }
    }

    // Build 35 (2026-05-16) — ONE-HOOK BASEFORM SWAP, donor-side.
    //
    // Every NON-ghost actor is a potential donor: its baseForm is, with
    // overwhelming probability, a vanilla TESNPC record (formType 0x2D)
    // in the engine's loaded forms table. We only care about the
    // pointer; we never mutate the donor. Once the cache is filled, the
    // function is a single atomic-load + early-return.
    //
    // We deliberately call this for EVERY non-ghost actor (skipping
    // only player + SEH-failed reads), not just for tracked NPCs. The
    // earliest possible cache seed is the goal: as soon as ANY non-
    // player actor (worker, raider, settler, doctor, vendor, …) gets
    // walked, we have a safe baseForm pointer ready, so the very next
    // ghost visit can swap.
    //
    // Excluding the player: the player's baseForm IS PlayerNPC. We'd
    // pick it up and then refuse it (formID check rejects 0x07), but
    // skipping the call entirely on PLAYER_FORM_ID avoids the noise.
    if (fid != 0 && fid != 0xFFFFFFFFu && fid != PLAYER_FORM_ID && actor) {
        fw::engine::try_acquire_safe_npc_base(actor);
    }

    // B6.5w12 Ghost AI bridge: write the current actor's form_id to the
    // shared atomic BEFORE calling original. Any sub-call within the AI
    // tick (package selector, quest condition eval, dialog topic check,
    // ...) that fires our inner predicate hook (sub_140768CC0) will read
    // this atomic to identify which actor's AI is currently being ticked.
    // Save the prior value and restore after orig to keep recursion-safe
    // (engine doesn't recurse Update_PerFrame in practice, but defensive).
    //
    // Skip on SEH-failed reads (fid == 0xFFFFFFFFu) — better to leave
    // atomic at its prior state than poison it with sentinel.
    const std::uint32_t prev_bridge_fid =
        fw::hooks::g_current_actor_fid.load(std::memory_order_relaxed);
    const void* const   prev_bridge_ptr =
        fw::hooks::g_current_actor_ptr.load(std::memory_order_relaxed);
    if (fid != 0xFFFFFFFFu) {
        fw::hooks::g_current_actor_fid.store(
            fid, std::memory_order_relaxed);
        fw::hooks::g_current_actor_ptr.store(
            actor, std::memory_order_relaxed);
    }

    // B6.5w16 NUCLEAR OPTION: bail Update_PerFrame ENTIRELY for tracked
    // NPCs with movement_override. Per B6.5w4 round 1 (original Ghost AI
    // discovery): "bail Update_PerFrame → tracked NPCs frozen visually
    // at last AI-tick pose. AI tick stops, anim graph stops, NIF sync
    // stops." Originally rejected because they wanted rendering to keep
    // running normally with server pos override. WE WANT THE FREEZE.
    //
    // Live tests of 18 hooks have shown the engine has multiple parallel
    // pos write paths (NIF.local→NIF.world via UpdateWorldData, Havok
    // body sync, anim root motion, character proxy controller) — bailing
    // any one leaves others to drive motion. The only thing UP-tree of
    // ALL of these is Update_PerFrame itself.
    //
    // Trade-off: tracked NPCs become statues (no anim, no logic). For
    // the MVP "raider freezes for sync demonstration" this is acceptable.
    // The Ghost AI Phase 5 will RESTORE rendering by either reanimating
    // them via server-driven anim graph commands or by accepting visual
    // freeze + handling server-decided pos.
    //
    // B6.5w17 v2: STICKY AUTO-TRACK pattern.
    //   Path 0 (NEW): check the runtime auto-tracked set first. Once an
    //     actor was ever bailed, stay bailed forever. No flag oscillation,
    //     no AI re-evaluation can un-freeze them.
    //   Path 1: server-pushed tracked set with movement_override.
    //   Path 2: actor is in COMBAT — engine flag 0x4000 at Actor+0x2D0.
    //   Path 3: actor has any "active combat substate" — bit 0x80000 also
    //     observed as combat-related in some engine code.
    //   Auto-add: on first bail via any path, insert into dynamic set.
    //
    // Excludes player always.
    //
    // B6.6w3 (2026-05-12 night) — RE-ARCHITECTURE per user feedback:
    // "i primi hook sono il problema, gli npc ostili sono FRIENDLY".
    //
    // Previous behavior: any InCombat flag (Path 2) auto-tracked the
    // actor → all 5 hooks bailed → raider became a statue → vanilla AI
    // never re-engaged → decayed to neutral compass marker. The
    // permanent-bail-once-bailed semantics killed combat entirely.
    //
    // New split:
    //   DISCOVERY (g_dyn_tracked): one-shot per fid. When InCombat
    //     flag is observed, we tell the server "register this actor"
    //     via NPC_DISCOVER. The set just prevents duplicate sends.
    //     **Does NOT trigger bail anywhere.**
    //   BAIL (cache.movement_override): only when the server has
    //     explicitly registered the actor AND pushed movement_override=1
    //     do the 5 hooks bail. Until that happens, vanilla AI runs
    //     normally on the raider — it sees the player, engages, fires,
    //     attacks.
    //
    // Effect: a raider that engages combat:
    //   1. T+0ms: engine sets InCombat flag. Our detour observes,
    //      sends NPC_DISCOVER (one-shot), DOES NOT BAIL.
    //   2. T+~100ms: vanilla AI ticks, raider locks onto player,
    //      fires weapon (visible muzzle flash + projectile). Player
    //      takes damage from vanilla projectile.
    //   3. T+~100-300ms: server receives DISCOVER, registers, starts
    //      broadcasting movement_override=1 for this raider.
    //   4. T+~300-500ms: client cache updates, npc_ai_suppress
    //      detour finally bails Update_PerFrame for this actor. From
    //      this point on, server drives via NPC_FIRE + pos broadcast.
    //
    // The brief vanilla-AI window during steps 1-3 IS THE FEATURE,
    // not a bug — it's the only way raiders look hostile and shoot
    // without us reimplementing combat in C++.

    // B6.6w4 (2026-05-12 night, post-swarm-RE) — NO BAIL of vanilla
    // Update_PerFrame. Past attempts to bail it (B6.5w17 + puppet
    // body) broke perception → CombatController+0x98 decayed →
    // InCombat mirror cleared → compass white → raider "FRIENDLY".
    //
    // Replacement architecture (proven via funcs_0301/0321 file:line):
    //   1. NEVER bail this detour. Vanilla AI runs every tick.
    //   2. On first InCombat observation: send NPC_DISCOVER to server.
    //   3. On first observation that cache.movement_override == 1:
    //      call engine::disable_actor_movement(actor). This sets
    //      *(MovementController+0x1A1) = 1 → Actor::TickMovementController
    //      bails its own body. Engine-native, vanilla AI tolerated.
    //   4. Both (2) and (3) deduped via g_dyn_tracked. The set is
    //      now multi-purpose: "we've taken action for this fid".

    // B6.6w5 v2 — dedup ONLY for discover. The old code inserted into
    // g_dyn_tracked also on server_wants_freeze (= all JSON raiders at
    // boot), blocking discover_send forever even when raider later
    // engaged combat. Fix: insert into g_dyn_tracked ONLY when we
    // actually send NPC_DISCOVER.
    bool need_discover_send = false;
    if (fid != PLAYER_FORM_ID && fid != 0 && fid != 0xFFFFFFFFu) {
        const std::uint32_t flags = safe_read_actor_flags(actor);
        const bool in_combat = (flags & ACTOR_FLAG_IN_COMBAT) != 0;

        // Build 55d (2026-05-23) — diagnostic: log flag bytes per fid
        // to verify if InCombat bit is ever observed on the wire raider
        // population. Past sessions (Build 51-55a) had NPC_DISCOVER fire
        // for raiders 4B2BA/46458/etc. Current session shows 0 DISCOVER
        // — either bit not observed or something else broken. Sample
        // 1-of-N fires per fid to keep log volume bounded.
        {
            static std::mutex s_flag_log_mtx;
            static std::unordered_map<std::uint32_t,
                std::uint64_t> s_per_fid_count;
            std::uint64_t cnt;
            {
                std::lock_guard lk(s_flag_log_mtx);
                cnt = ++s_per_fid_count[fid];
            }
            // Log first 3 samples per fid + every 5000th + every time
            // InCombat bit appears (with throttle).
            if (cnt <= 3 || (cnt % 5000) == 0) {
                FW_DBG("[npc-ai-suppress] flag-sample fid=0x%08X flags=0x%08X "
                       "in_combat=%d cnt=%llu",
                       fid, flags, in_combat ? 1 : 0,
                       static_cast<unsigned long long>(cnt));
            }
            if (in_combat) {
                static std::atomic<std::uint64_t> s_ic_obs{0};
                const auto ico = s_ic_obs.fetch_add(
                    1, std::memory_order_relaxed);
                if (ico < 30 || (ico % 200) == 0) {
                    FW_LOG("[npc-ai-suppress] InCombat OBSERVED fid=0x%08X "
                           "flags=0x%08X total_obs=%llu",
                           fid, flags,
                           static_cast<unsigned long long>(ico));
                }
            }
        }

        if (in_combat) {
            std::shared_lock<std::shared_mutex> lk(g_dyn_mtx);
            if (g_dyn_tracked.find(fid) == g_dyn_tracked.end()) {
                need_discover_send = true;
            }
        }

        if (need_discover_send) {
            std::unique_lock<std::shared_mutex> lk(g_dyn_mtx);
            if (!g_dyn_tracked.insert(fid).second) {
                need_discover_send = false;   // race lost
            } else {
                const auto sz = g_dyn_tracked.size();
                g_dyn_set_size.store(sz, std::memory_order_relaxed);
                const auto an = g_dyn_auto_adds.fetch_add(
                    1, std::memory_order_relaxed);
                if (an < 20) {
                    FW_LOG("[npc-ai-suppress] DISCOVER #%llu fid=0x%08X "
                           "(InCombat observed, set size %zu)",
                           static_cast<unsigned long long>(an), fid, sz);
                }
            }
        }

        if (need_discover_send) {
            // Tell the server about this actor so it can broadcast
            // sync state across peers.
            std::uint32_t base_id = 0, cell_id = 0;
            float px = 0.0f, py = 0.0f, pz = 0.0f;
            const bool id_ok = safe_read_actor_identity(
                actor, &base_id, &cell_id, &px, &py, &pz);
            fw::net::client().enqueue_npc_discover(
                fid, base_id, cell_id, px, py, pz);
            FW_LOG("[npc-ai-suppress] NPC_DISCOVER tx fid=0x%08X "
                   "base=0x%08X cell=0x%08X pos=(%.1f,%.1f,%.1f) "
                   "id_read_ok=%d",
                   fid, base_id, cell_id, px, py, pz, id_ok ? 1 : 0);
        }
    }

    // Build 34 (2026-05-16) — Fixed-selector install attempt per-tick.
    //
    // Previously gated inside the `need_discover_send` block (one-shot
    // per fid via g_dyn_tracked dedup), but live test 2026-05-16 19:18
    // showed this races with server response latency: client observes
    // InCombat at T=0, sends NPC_DISCOVER, checks cache (still empty
    // because server hasn't responded). Decision: skip install. Then
    // dedup says "DISCOVER sent" → block never re-runs → install never
    // retried → all raiders end up with vanilla local-player targeting
    // even when server later decides cross-peer aggro.
    //
    // Build 34 fix: separate the install attempt from DISCOVER. Run it
    // EVERY TICK while raider is observed in combat. Internal dedup in
    // `install_fixed_selector_on_raider` (per-aiproc set) makes
    // re-calls cheap no-ops once installed.
    //
    // Gate logic (same as Build 32, just re-located):
    //   - server.combat_target_form_id == 0      → skip (no opinion yet)
    //   - server.combat_target_form_id == 0x14   → skip (vanilla local-target correct)
    //   - server.combat_target_form_id == other  → install (cross-peer ghost target)
    //
    // The "other" case is when server has decided this raider, on THIS
    // client's view, should attack the OTHER peer's representation
    // (= our local ghost_form_id 0xFF000001).
    //
    // ----------------------------------------------------------------
    // DORMANT — 2026-05-17 log analysis (kept enabled, but observed to
    // never fire the success branch; documented here so we don't waste
    // RE cycles on it again).
    //
    // LOG PROOF: Client A `fw_native.log` 17:29-17:39 contains ZERO
    // `[fixed-sel] installed #N` lines. The diagnostic
    // `[fixed-sel] skip install` is also absent because the InCombat
    // gate (Actor+0x2D0 bit 0x4000) requires the engine to have
    // entered combat — for the 5 server-aggro'd Concord raiders
    // (74E50/74E51/19E13C-E), this never happens on Client A while
    // player_A stays in Sanctuary. Engine never queries them with the
    // ghost as a hostile candidate (cross-cell distance ~26000 units,
    // hostility=0 even if queried because of safe baseForm swap).
    //
    // The "skip install (server.target=0xFF000001 but raider not in
    // combat)" log line is also absent because the InCombat-gate above
    // hides this branch entirely.
    //
    // KEEP RUNNING. The install gate is correct and would fire IF a
    // raider DID enter combat AND server decided cross-peer aggro. The
    // diagnostic counter `g_install_skipped` would then start
    // incrementing if `combat_target_form_id == 0` (server cache lag)
    // or `== 0x14` (vanilla local target case). The successful install
    // would log `[fixed-sel] installed`. Neither has been observed.
    //
    // The architectural fix (puppet-fire bypass per
    // re/AI_pipeline/section_08 §0/§16.3) does NOT need this install
    // path. Puppet fire writes directly to weapon-state + aim, skipping
    // the entire selector subsystem. This block stays only as
    // scaffolding for "if a future redesign makes natural combat tier
    // engagement possible" — which it currently isn't.
    // ----------------------------------------------------------------
    // ====================================================================
    // Build 65.c.25.1 — ROLLBACK c.25 — Fixed Selector install DISABLED.
    //
    // c.25 live test (23:23:26 UTC) achieved FIRST EVER successful install
    // of CombatTargetSelectorFixed on a raider with ghost as target
    // (g_fixed_sel_install_successes 0→1 for fid 0x4B2BA). The function
    // body was correct as `engine_calls.cpp:7484-7515` had documented.
    //
    // HOWEVER — never-before-tested teardown behavior caused crash at
    // teleport completion (Client B): cell-stream triggered AIProc
    // teardown → walked aiproc+0x100 selectors → our Fixed selector
    // points to ghost actor in transient state during cell change →
    // stale handle / cascading SEH → drain queue starved (67→88 entries
    // unprocessed in 3s) → main-thread freeze → Windows kill.
    //
    // Additional risk per Agent 3 dossier (`re/B65_c22_fixed_selector_
    // AGENT_3.md`): AddTarget broadcasts target to CombatGroup allies
    // via `sub_140C96970` (funcs_0337.md:1964). Forcing ghost target on
    // one raider propagates to ALL allies in same combat group, with
    // unknown teardown semantics.
    //
    // KEY INSIGHT — the user's instinct "dormant API has a reason" was
    // correct. The dormant comment in engine_calls.cpp:7484-7515 said
    // "preconditions never triggered" — it didn't characterize teardown
    // behavior because nobody had ever exercised the path in production.
    //
    // Path forward: skip Fixed Selector entirely. Cross-peer target sync
    // will need a different approach (D3D11 partial render or accept the
    // asymmetry). Block kept here behind `if (false)` for diagnostic
    // record + easy re-enable if a future cell-stream-safe install
    // strategy is found.
    // ====================================================================
    if (false &&
        fid != 0 && fid != 0xFFFFFFFFu && actor &&
        fid != fw::offsets::GHOST_FORMID_BASE &&
        fw::ownership::is_non_owner_tracked(fid))
    {
        void* const ghost = fw::ghost::get_ghost_actor();
        if (ghost && ghost != actor) {
            const bool installed_now =
                fw::engine::install_fixed_selector_on_raider(actor, ghost);
            static std::atomic<std::uint64_t> g_c25_attempts{0};
            static std::atomic<std::uint64_t> g_c25_returns_true{0};
            const auto a = g_c25_attempts.fetch_add(
                1, std::memory_order_relaxed);
            if (installed_now) {
                g_c25_returns_true.fetch_add(1, std::memory_order_relaxed);
            }
            if (a < 20 || (a % 5000) == 0) {
                FW_LOG("[fixed-sel] c.25 cross-peer attempt #%llu "
                       "fid=0x%08X actor=%p ghost=%p ret=%d "
                       "returns_true_total=%llu",
                       static_cast<unsigned long long>(a),
                       fid, actor, ghost, installed_now ? 1 : 0,
                       static_cast<unsigned long long>(
                           g_c25_returns_true.load(
                               std::memory_order_relaxed)));
            }
        }
    }

    // ====================================================================
    // Build 65.c.25 ORIGINAL — disabled by Build 65.c.25.1 ROLLBACK above.
    //
    // The c.24 multi-signal anim_state propagation works on Client A (80%
    // any=1) but failed on Client B (0%) due to engine asymmetry. The
    // user reports the residual problem is **target choice inconsistency
    // cross-peer**:
    //   - On A's view: raiders aggro A (A's vanilla engine picks player_A
    //     as the natural local target).
    //   - On B's view: raiders aggro B (B's vanilla engine picks player_B
    //     as the natural local target).
    //   - User never sees raiders attack ghost_B on A's screen, only
    //     occasionally ghost_A on B's screen.
    //
    // Fix per Agent 3 dossier (`re/B65_c22_fixed_selector_AGENT_3.md` +
    // Judge audit `re/B65_c23_JUDGE.md`):
    //   - When THIS peer is NON-OWNER of a raider (= some other peer is
    //     the authority running its AI), install a CombatTargetSelector-
    //     Fixed at priority 3 that pins the raider's combat target to
    //     OUR local ghost actor (= the proxy representing the owner-peer
    //     on our screen).
    //   - Vanilla engine combat brain's per-frame promoter (sub_14087B080)
    //     sorts selectors by priority DESC; our Fixed (3) beats vanilla
    //     Standard (1). Result: aiproc+0x6C is written with the ghost's
    //     handle every promoter tick, engine combat brain orients toward
    //     ghost = where the owner-peer's player is rendered.
    //
    // ALL ENGINE PLUMBING ALREADY IMPLEMENTED in
    // `engine_calls.cpp::install_fixed_selector_on_raider`:
    //   - Faction-hostility dry-run via sub_140E924A0 (the silent-fail
    //     mode killer #2 Agent 3 flagged).
    //   - SEH cage at every step (block alloc, ctor, AddTarget).
    //   - Per-aiproc dedup map prevents double-install / 40-B block leak.
    //   - 3rd arg passed as Actor* (NOT &fid) — Agent 3 killer #1 already
    //     baked in by Build 29.
    //
    // What changes in c.25: the GATE that decides when to call it. Build
    // 41 gated on legacy `CachedNPCState.combat_target_form_id`, which has
    // been dormant since c.13 silenced raider_brain. We replace the gate
    // with owner-driven `is_non_owner_tracked(fid)`.
    //
    // Trigger cadence: per-frame on every npc_ai_suppress detour fire
    // (= ~60 Hz per loaded raider). Internal dedup makes it a cheap
    // atomic-load no-op after the first successful install. Re-install
    // path is naturally exercised on AIProc rebuild (cell unload/reload)
    // when the dedup set entry's aiproc pointer no longer matches.
    //
    // ====================================================================
    if (false /* DISABLED by c.25.1 rollback above; see banner */ &&
        fid != 0 && fid != 0xFFFFFFFFu && actor &&
        fid != fw::offsets::GHOST_FORMID_BASE &&
        fw::ownership::is_non_owner_tracked(fid))
    {
        void* const ghost = fw::ghost::get_ghost_actor();
        if (ghost && ghost != actor) {
            const bool installed_now =
                fw::engine::install_fixed_selector_on_raider(actor, ghost);
            static std::atomic<std::uint64_t> g_c25_attempts{0};
            static std::atomic<std::uint64_t> g_c25_returns_true{0};
            const auto a = g_c25_attempts.fetch_add(
                1, std::memory_order_relaxed);
            if (installed_now) {
                g_c25_returns_true.fetch_add(1, std::memory_order_relaxed);
            }
            // Throttled: first 20 attempts + first 20 actual transitions
            // + every 5000th (covers the steady-state "already installed,
            // return true" path which is the common case after the first
            // successful install).
            if (a < 20 || (a % 5000) == 0) {
                FW_LOG("[fixed-sel] c.25 cross-peer attempt #%llu "
                       "fid=0x%08X actor=%p ghost=%p ret=%d "
                       "returns_true_total=%llu",
                       static_cast<unsigned long long>(a),
                       fid, actor, ghost, installed_now ? 1 : 0,
                       static_cast<unsigned long long>(
                           g_c25_returns_true.load(
                               std::memory_order_relaxed)));
            }
        }
    }

    // ====================================================================
    // Build 41 legacy fixed-sel install (DORMANT — legacy combat-target
    // path never fires under owner-driven sync). Kept for the on-disk
    // diagnostic if a future redesign reactivates legacy CachedNPCState
    // population.
    // ====================================================================
    if (false &&
        fid != 0 && fid != 0xFFFFFFFFu && actor &&
        fid != fw::offsets::GHOST_FORMID_BASE)
    {
        const std::uint32_t flags = safe_read_actor_flags(actor);
        const bool in_combat = (flags & ACTOR_FLAG_IN_COMBAT) != 0;
        if (in_combat) {
            // Build 62.7 (2026-05-24) — GATE on natural-HighProcess.
            // See helper `actor_has_native_highproc()` defined above this
            // function (free function to avoid MSVC C2712 — this function
            // body owns shared_lock locals).
            const bool has_native_highproc =
                actor_has_native_highproc(actor);
            fw::dispatch::CachedNPCState st_for_install{};
            const bool has_server_opinion =
                fw::dispatch::get_cached_npc_state(fid, &st_for_install)
                && st_for_install.combat_target_form_id != 0
                && st_for_install.combat_target_form_id != PLAYER_FORM_ID;
            if (has_server_opinion && !has_native_highproc) {
                void* ghost = fw::ghost::get_ghost_actor();
                if (ghost) {
                    fw::engine::install_fixed_selector_on_raider(
                        actor, ghost);
                }
            } else if (has_server_opinion && has_native_highproc) {
                // Throttled diagnostic so we know the gate is firing.
                static std::atomic<std::uint64_t> g_native_owned{0};
                const auto no = g_native_owned.fetch_add(
                    1, std::memory_order_relaxed);
                if (no < 10 || (no % 5000) == 0) {
                    FW_DBG("[fixed-sel] skip-native-owned #%llu fid=0x%08X "
                           "(Build 62.7 — raider has native HighProcess; "
                           "engine combat tier drives selector, no install)",
                           static_cast<unsigned long long>(no), fid);
                }
            } else {
                // Throttled diagnostic so we know per-tick gate is alive.
                static std::atomic<std::uint64_t> g_install_skipped{0};
                const auto sk = g_install_skipped.fetch_add(
                    1, std::memory_order_relaxed);
                if (sk < 20 || (sk % 500) == 0) {
                    FW_LOG("[fixed-sel] skip install fid=0x%08X "
                           "server.target=0x%08X (no cross-peer ghost "
                           "decision yet; vanilla AI for now)",
                           fid, st_for_install.combat_target_form_id);
                }
            }
        }
    }

    // B6.6w4 — NEVER bail Update_PerFrame. Always passthrough to
    // vanilla AI so combat / aim / fire / hostility persist. Position
    // freeze is delegated to MovementController disable (above).
    constexpr bool bail_this_actor = false;
    if (bail_this_actor) {
        // B6.6w1 (2026-05-12 late evening) — ROLLBACK to yesterday's
        // bail behavior. The puppet body + InCombat triple-write
        // (introduced earlier today) appear to have broken aggro:
        //
        //   * safe_force_in_combat_flag() rewrote Actor+0x2D0 / +0x380 /
        //     AIProcess+0x6C every frame, overwriting whatever the
        //     engine combat brain had decided this frame. With 60 Hz
        //     overwrite + ~30 Hz orchestrator tick, the AI never
        //     stabilizes on a target.
        //   * puppet_update_perframe() calls ~9 vanilla engine fns
        //     (DeathFade, MountSwim, TickRenderState, OnTickPostExtra,
        //     StaticBlockCheck...). Some of these mutate Actor+0x43C
        //     and similar flag bytes that the perception/orchestrator
        //     pipeline reads.
        //
        // Yesterday's behavior (ed326a1) = bail UpdateFrame, return
        // immediately. Trade-off: NPCs T-pose mid-anim (no NIF sync,
        // no anim transitions), AND activation prompt becomes "Talk"
        // because hostility state doesn't refresh. Both are cosmetic.
        // The crash on activate-E is prevented by door_hook bailing
        // activation for tracked actors.
        //
        // If yesterday raiders attacked, today they should too — the
        // pos hooks still bail (raider stuck in place), the combat
        // hooks still let vanilla AI run when server has a designated
        // aggro target (should_silence_combat returns false when
        // cache.combat_target_form_id != 0).

        static std::atomic<std::uint64_t> g_full_bails{0};
        const auto bn = g_full_bails.fetch_add(1, std::memory_order_relaxed);
        if (bn < 10) {
            FW_LOG("[npc-ai-suppress] BAIL #%llu actor_fid=0x%08X — "
                   "Update_PerFrame skipped (no puppet body, no flag "
                   "writes; vanilla orchestrator owns combat state)",
                   static_cast<unsigned long long>(bn), fid);
        } else if ((bn % 5000) == 0) {
            FW_DBG("[npc-ai-suppress] BAIL #%llu (heartbeat)",
                   static_cast<unsigned long long>(bn));
        }
        // Restore bridge atomic, then return (skipping original entirely).
        fw::hooks::g_current_actor_fid.store(prev_bridge_fid,
                                             std::memory_order_relaxed);
        fw::hooks::g_current_actor_ptr.store(prev_bridge_ptr,
                                             std::memory_order_relaxed);
        g_suppress_fires.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Step 1: untracked / no override → always call original.
    if (g_orig_actor_update_perframe) {
        g_orig_actor_update_perframe(actor, sim_time);
    }

    // Build 55f (2026-05-23) — POST orig rotation override for ghost-
    // targeted raiders. See the helper just below this function for
    // full rationale. SEH cage is inside the helper (this function
    // has std::shared_lock locals so __try is forbidden here, MSVC C2712).
    if (fid != 0 && fid != 0xFFFFFFFFu) {
        float yaw_rad = 0.f;
        if (fw::dispatch::get_ghost_targeted_yaw(fid, &yaw_rad)) {
            fw::engine::aim_actor_at_target_rotation_only(actor, yaw_rad);
        }
    }

    // ====================================================================
    // c.37.1 — MIRROR POSE DRIVE (RX). We are now POST-orig, i.e. AFTER the
    // engine's Update_PerFrame → sub_140CE1720 wrote this actor's bone+0x30
    // from its LOCAL anim graph. For a non-owner tracked NPC with a fresh
    // relayed pose, overwrite those bones with the owner's rotations NOW, so
    // OUR write is the last one before the render bake. This is the freeze:
    // it runs every frame (60Hz), so it beats the engine's 60Hz anim write
    // that the old 16Hz message-pump apply could not (→ the flicker is gone).
    // Owners skip this (they drive their NPCs natively + TX below).
    // Freshness-gated so a handoff/owner-drop falls back to native anim after
    // kNpcPoseStaleMs.
    //
    // Build 68.4 — CORRECTION to the old claim on this block ("All engine
    // access is SEH-caged inside apply_npc_pose_to_actor"): SEH was NEVER a
    // safety guarantee here and that sentence is what gave us false confidence
    // for weeks. A heap block that the engine freed and its allocator recycled
    // is still committed and still writable, so a write through a stale bone
    // pointer SUCCEEDS SILENTLY and raises nothing for __except to catch — it
    // just corrupts whichever object now owns that memory (proven: the
    // 2026-07-28 20:02:23 crash, our quaternion 1.0f found sitting in a
    // MovementMessagePathEvent's smart-pointer slot). Safety now comes from
    // OWNING the bones (refcount pin) plus a semantic detach test, both in
    // scene_inject.cpp — not from the exception cage.
    //
    // Build 68.4 — DEATH GATE. This was the only block in this function
    // lacking the guard the file already applies at the keyframe machine: once
    // a relayed death lands, drain_npc_death_apply_queue un-keyframes the body
    // and calls Actor::Kill, handing it to the Havok ragdoll solver — and we
    // were still writing bone locals and running a subtree rebake on it for up
    // to kNpcPoseHoldMs (500 ms) afterwards.
    if (fid != 0 && fid != 0xFFFFFFFFu && actor &&
        fw::ownership::is_non_owner_tracked(fid) &&
        !fw::hooks::is_dying(fid) &&
        !actor_knocked_or_dead(actor)) {
        fw::native::apply_npc_pose_to_actor(actor, fid);
    }

    // ====================================================================
    // Build 65.c.24 — POST-orig OWNER state capture with multi-signal
    // anim_state aggregation.
    //
    // Moved from PRE-orig (was in the early observation block above) for
    // 2 reasons identified by the c.23 post-mortem (forensics + Judge):
    //
    //   1. anim_state was always 0 in INTERP-APPLY logs (= owner sent 0).
    //      Cause: pre-orig captured BEFORE the engine's per-frame combat
    //      brain updated the InCombat bit (sub_140C5CCE0, the only setter,
    //      runs inside orig). Capturing post-orig sees the most-recent
    //      verdict.
    //
    //   2. The bit and CombatController+0x98 are both volatile — engine
    //      perception walker clears them mid-frame when "no LOS this tick".
    //      Reading either alone is insufficient. Multi-signal OR:
    //
    //         S1 = (Actor+0x2D0 & 0x4000) != 0            (current bit)
    //         S2 = CombatController+0x98 != 0             (upstream root)
    //         S3 = recently_fired(fid, 1500 ms)           (sticky proof
    //              from ghost_ai_fire hook — survives per-frame oscillation)
    //
    //      anim_state = AIMING (3) if any signal is true, else IDLE (0).
    //
    // Pos/yaw are also re-read post-orig: engine may have integrated
    // motion during orig; non-owners interpolate from the freshest sample.
    //
    // hp_pct stays hardcoded at 100 for c.24 — HP authority is the next
    // wedge (c.25 NPC_DAMAGE_TO_OWNER per re/B65_c23_damage_architecture
    // _AGENT_3.md). 100 keeps the legacy wire payload populated until then.
    //
    // Diagnostic logging: per-signal counters, throttled, so the next
    // forensics agent can correlate which signal was the deciding factor
    // and tune the window/path balance.
    if (fid != 0 && fid != 0xFFFFFFFFu && actor &&
        fw::ownership::is_owner_of(fid))
    {
        // Re-read pos+yaw post-orig (engine may have integrated motion).
        std::uint32_t base_id_p = 0, cell_id_p = 0;
        float opx = 0.0f, opy = 0.0f, opz = 0.0f;
        const bool oid_ok = safe_read_actor_identity(
            actor, &base_id_p, &cell_id_p, &opx, &opy, &opz);
        float oyaw = 0.0f;
        safe_read_actor_yaw(actor, &oyaw);

        if (oid_ok) {
            // Build 65.c.36a — S0 (PRIMARY): combat HighProcess slot present
            // (Actor+0x328 != NULL). This is the reliable SUSTAINED-combat
            // latch — allocated on EnterCombat, freed on ExitCombat — so it
            // stays true for the WHOLE encounter, unlike S1/S2 below which are
            // the same volatile per-tick "perceived-target this frame" value
            // that decays to 0 within ~600 ms even while the raider keeps
            // fighting (8-agent arena A1+A2, decomp-proven: S1 ≡ +0x328 gated
            // by a per-tick predicate via sub_140C5CCE0). Reading S0 fixes the
            // "owner relays anim=0 → non-owner shows a frozen log" symptom and
            // makes note_owner_engagement fire reliably (→ the server threat
            // engage signal goes live → ownership stops thrashing on distance).
            const bool s0 = actor_has_native_highproc(actor);

            // S1 — bit 0x4000 at Actor+0x2D0 (post-orig snapshot). DIAGNOSTIC
            // only now (volatile mirror of S2; kept for log correlation).
            const std::uint32_t post_orig_flags = safe_read_actor_flags(actor);
            const bool s1 = (post_orig_flags & ACTOR_FLAG_IN_COMBAT) != 0;

            // S2 — CombatController+0x98 (chain Actor+0x328→AIProc+0x40→+0x98).
            // DIAGNOSTIC only now (same volatile value as S1).
            const bool s2 = safe_read_combat_controller_active(actor);

            // S3 — recently_fired within 1500 ms (stamped by ghost_ai_fire)
            const bool s3 = fw::dispatch::recently_fired(
                fid, fw::dispatch::RECENT_FIRE_WINDOW_MS);

            // c.36a — S0 is now the dominant signal (sustained combat); S1/S2/S3
            // OR'd in so a fire/edge still counts even at the combat boundary.
            const bool any_combat_signal = s0 || s1 || s2 || s3;
            // c.40a — STICKY anim_state. The signals (esp. the volatile InCombat
            // bit) flicker to 0 mid-fight, so the mirror snaps to IDLE → patrol
            // anim on the bones we don't drive. Latch AIMING for a hold window
            // after ANY signal so the relayed stance stays steady through gaps.
            std::uint8_t anim_state;
            {
                constexpr std::uint64_t kAnimLatchMs = 700;
                static std::mutex s_anim_latch_mtx;
                static std::unordered_map<std::uint32_t, std::uint64_t>
                    s_anim_latch;   // fid -> last combat-signal tick
                const std::uint64_t now_tc = GetTickCount64();
                std::lock_guard lk(s_anim_latch_mtx);
                if (any_combat_signal) s_anim_latch[fid] = now_tc;
                const auto it = s_anim_latch.find(fid);
                const bool latched = (it != s_anim_latch.end())
                                  && (now_tc - it->second < kAnimLatchMs);
                anim_state = latched ? 3u /* AIMING */ : 0u /* IDLE */;
            }

            // Build 68.7 — LOCOMOTION. Measured 2026-07-29: every owned actor
            // that actually MOVED (13 of them, travelling 493 to 4,353 units)
            // relayed anim=0 for its entire life — combat samples were 0, 1 or
            // 3 in total. The mirror was therefore told "I am standing still"
            // while its body translated across the map, so its anim graph did
            // the only correct thing for that input and played IDLE: the
            // "raider slides like a wooden log" report. Bones were never the
            // cause (they are only ~4-7 aim-chain joints); legs have ALWAYS
            // been driven by the mirror's own graph, and a graph needs a SPEED
            // input to walk.
            //
            // The protocol and the receiver already support this and always
            // have: anim_state 1 = WALKING -> SpeedSampled 100, 2 = RUNNING ->
            // SpeedSampled 200 (engine_calls.h:294-296). The owner simply
            // never produced those values. Derive them from the position delta
            // we are ALREADY sampling at 60 Hz — no new engine reads, no new
            // wire fields, nothing to race with the engine's own writers.
            // Combat states keep priority: a raider aiming while strafing must
            // stay AIMING, otherwise we would trade a broken walk for a broken
            // stance.
            if (anim_state == 0u) {
                struct LocoSample { float x, y, z; std::uint64_t t_ms; };
                static std::mutex s_loco_mtx;
                static std::unordered_map<std::uint32_t, LocoSample> s_loco;
                const std::uint64_t now_tc = GetTickCount64();
                std::lock_guard lk(s_loco_mtx);
                auto it = s_loco.find(fid);
                if (it != s_loco.end()) {
                    const std::uint64_t dt = now_tc - it->second.t_ms;
                    // Sample over >=100 ms so 60 Hz jitter cannot masquerade as
                    // speed, and drop stale samples (a gap means a teleport /
                    // re-load, whose delta is meaningless).
                    if (dt >= 100 && dt <= 1000) {
                        const float dx = opx - it->second.x;
                        const float dy = opy - it->second.y;
                        const float dz = opz - it->second.z;
                        const float dist = std::sqrt(dx * dx + dy * dy + dz * dz);
                        // units per second. Vanilla FO4: walk ~130, run ~400.
                        const float ups = dist * 1000.0f
                                        / static_cast<float>(dt);
                        if (ups >= 260.0f)      anim_state = 2u;  // RUNNING
                        else if (ups >= 40.0f)  anim_state = 1u;  // WALKING
                        it->second = LocoSample{opx, opy, opz, now_tc};
                    } else if (dt > 1000) {
                        it->second = LocoSample{opx, opy, opz, now_tc};
                    }
                } else {
                    s_loco.emplace(fid, LocoSample{opx, opy, opz, now_tc});
                }
            }

            // Throttled per-signal diagnostic. Resolution: first 30 logged,
            // then every 2000th. Per-signal counters give us "of N captures,
            // how many had S1 true / S2 true / S3 true / OR true" — exactly
            // the data the next forensics needs to validate the design.
            static std::atomic<std::uint64_t> g_owner_capture_total{0};
            static std::atomic<std::uint64_t> g_s0_true{0};
            static std::atomic<std::uint64_t> g_s1_true{0};
            static std::atomic<std::uint64_t> g_s2_true{0};
            static std::atomic<std::uint64_t> g_s3_true{0};
            static std::atomic<std::uint64_t> g_any_true{0};
            const auto t = g_owner_capture_total.fetch_add(
                1, std::memory_order_relaxed);
            if (s0) g_s0_true.fetch_add(1, std::memory_order_relaxed);
            if (s1) g_s1_true.fetch_add(1, std::memory_order_relaxed);
            if (s2) g_s2_true.fetch_add(1, std::memory_order_relaxed);
            if (s3) g_s3_true.fetch_add(1, std::memory_order_relaxed);
            if (any_combat_signal)
                g_any_true.fetch_add(1, std::memory_order_relaxed);
            if (t < 30 || (t % 2000) == 0) {
                FW_LOG("[npc-ai-suppress] c.36a OWNER-CAPTURE #%llu "
                       "fid=0x%08X anim=%u "
                       "S0(hp328)=%d S1(bit)=%d S2(cc98)=%d S3(fire)=%d any=%d "
                       "totals: s0=%llu s1=%llu s2=%llu s3=%llu any=%llu",
                       static_cast<unsigned long long>(t),
                       fid, anim_state,
                       s0 ? 1 : 0, s1 ? 1 : 0, s2 ? 1 : 0, s3 ? 1 : 0,
                       any_combat_signal ? 1 : 0,
                       static_cast<unsigned long long>(
                           g_s0_true.load(std::memory_order_relaxed)),
                       static_cast<unsigned long long>(
                           g_s1_true.load(std::memory_order_relaxed)),
                       static_cast<unsigned long long>(
                           g_s2_true.load(std::memory_order_relaxed)),
                       static_cast<unsigned long long>(
                           g_s3_true.load(std::memory_order_relaxed)),
                       static_cast<unsigned long long>(
                           g_any_true.load(std::memory_order_relaxed)));
            }

            fw::ownership::record_owned_state(
                fid, opx, opy, opz, oyaw, anim_state, /*hp_pct=*/100);

            // c.37.0 — full pose replication. Walk this owned NPC's render
            // skeleton and broadcast its per-bone rotations so mirror peers
            // animate it bone-by-bone (the real fix for the "log on the
            // ground" / sliding desync) instead of the coarse anim_state
            // enum. Self-throttled to ~16 Hz per fid inside the call; runs
            // for owned NPCs whether idle or in combat. All engine memory
            // access is SEH-caged inside scene_inject.
            fw::native::capture_and_send_npc_pose(actor, fid);
        }
    }
    // ====================================================================

    // Build 65.c.23 — POST-orig 60Hz interpolated pos+yaw apply for
    // non-owner tracked NPCs.
    //
    // Diagnosis (Agent 1 forensics post-c.22): even after InCombat
    // propagation, the user reported all 5 raiders "flickerano". Cause:
    // the receiver-side drain applies pos+yaw at the cadence of
    // STATE_FROM_OWNER arrival (~10 Hz = ~100 ms intervals). Between
    // drains the actor sits at the last drained pos. New drain arrives
    // → pos jumps. Visual = snap-teleport pattern every 100 ms.
    //
    // Fix: drain still stores prev/cur snapshot in `g_latest_owner_state`.
    // Here, POST orig (so engine's own writes are already in place — we
    // get the LAST word), we read the interpolated pos via
    // `get_interpolated_owner_state` with current GetTickCount64() and
    // apply via the same engine API the drain uses (apply_npc_pos =
    // Actor::vt[202] with a3=0 → Actor+0xD0 + NIF root sync; and
    // aim_actor_at_target_rotation_only = Actor::SetRotation @
    // sub_140513790 → Actor+0xC0[2]).
    //
    // Cadence: this detour runs at Update_PerFrame rate per actor (~60 Hz
    // for ProcessLists-active actors). So pos is written 60 Hz, smoothly
    // extrapolating along the prev→cur velocity vector. 10 Hz snap-
    // teleport becomes ~16 ms-grain smooth motion.
    //
    // Gate: only non-owner_tracked. Owner-side writes pos via vanilla
    // engine AI tick which we PASS THROUGH (Build 65.c.20).
    //
    // The c.22 InCombat force-bit (below) still runs — anim_state is
    // bundled in the same returned struct so we update it from this
    // call's `snap.anim_state` to keep cache coherent on read.
    // Build 65.c.28/c.46 — TELEPORT FREEZE GUARD (now SUSPENDED-SAFE, not skip).
    // apply_npc_pos (vt[202]) → sub_140513A80 → the cell spatial-grid remove/
    // re-add pair grabs a PROCESS-GLOBAL spinlock the streaming thread can hold
    // mid-cell-load → main-thread deadlock (root cause of the c.25/c.27 freezes,
    // confirmed via drain-starvation forensics — DO NOT re-introduce). The
    // ORIGINAL c.28 fix SKIPPED the interp apply entirely during the window;
    // but recently_teleported() false-positives on exterior cell-edge streaming
    // (arms 1500ms on any local-player cell-cross), so the non-owner keyframed
    // raider's pos FROZE for ~1.5s while its pose kept streaming ("runs in
    // place") then SNAPPED forward. c.46: during the window, keep pinning via
    // the DEADLOCK-SAFE apply_npc_pos_raw (Actor+0xD0 + NIF local/world, no grid
    // lock) so the keyframed body stays FRESH — no freeze, no snap. Only the
    // ELSE-branch (handoff commit = MoveTo, which ALSO hits the grid lock) stays
    // deferred during the window. KILL-SWITCH: kRawPinDuringTeleport=false →
    // revert to the old skip-during-window behaviour.
    static constexpr bool kRawPinDuringTeleport = true;
    // Build 67.1 — REVERTED the Build 67 is_load_in_progress() widening
    // (matches the 10Hz drain revert): the engine load byte measured TRUE in
    // ~94-97% of normal-gameplay drains, so the widening silently starved the
    // 60Hz yaw apply (stale facing on every mirror = "running backwards").
    const bool suspended = fw::engine::recently_teleported();
    if (fid != 0 && fid != 0xFFFFFFFFu && actor &&
        (!suspended || kRawPinDuringTeleport)) {
        if (fw::ownership::is_non_owner_tracked(fid)) {
            fw::dispatch::InterpolatedOwnerState isnap{};
            if (fw::dispatch::get_interpolated_owner_state(
                    fid, GetTickCount64(), &isnap))
            {
                // ===== B6.6 POS-MEAS (read-only diagnostic) ==============
                // This detour is POST-orig: Actor+0xD0 here = the pos the
                // engine computed for the raider THIS frame, BEFORE our
                // override below. isnap = the owner's synced target. The
                // delta measures how far the engine's own AI moved the
                // raider away from sync since our last re-pin:
                //   drift~0  -> engine isn't competing; our apply holds and
                //               the raider IS synced          [posfix_idle]
                //   drift>0  -> engine runs its own path; between our 60Hz
                //               re-pins the body sits at the engine pos, so
                //               sync is "us vs engine"     [posfix_foundation]
                // Settles the two contradicting agents with a number.
                {
                    float eng_x = 0.0f, eng_y = 0.0f, eng_z = 0.0f;
                    if (safe_read_actor_identity(actor, nullptr, nullptr,
                                                 &eng_x, &eng_y, &eng_z)) {
                        const float ddx = eng_x - isnap.pos_x;
                        const float ddy = eng_y - isnap.pos_y;
                        const float ddz = eng_z - isnap.pos_z;
                        const float drift =
                            std::sqrt(ddx * ddx + ddy * ddy + ddz * ddz);
                        static std::atomic<std::uint64_t> g_posmeas_no{0};
                        const auto pm = g_posmeas_no.fetch_add(
                            1, std::memory_order_relaxed);
                        if (pm < 40 || (pm % 20) == 0 || drift > 75.0f) {
                            FW_LOG("[pos-meas] NONOWNER fid=0x%08X "
                                   "eng=(%.0f,%.0f,%.0f) "
                                   "synced=(%.0f,%.0f,%.0f) drift=%.1f%s",
                                   fid, eng_x, eng_y, eng_z,
                                   isnap.pos_x, isnap.pos_y, isnap.pos_z,
                                   drift,
                                   drift > 75.0f ? "  <<< ENGINE COMPETES"
                                                 : "");
                        }
                    }
                }
                if (suspended) {
                    // SAFE pin: raw writes only, skip vt[202] + SetRotation.
                    fw::engine::apply_npc_pos_raw(
                        actor, isnap.pos_x, isnap.pos_y, isnap.pos_z);
                } else {
                    fw::engine::apply_npc_pos(actor,
                                              isnap.pos_x, isnap.pos_y, isnap.pos_z);
                    (void)fw::engine::aim_actor_at_target_rotation_only(
                        actor, isnap.yaw_rad);
                    // Build 68.7 — LOCOMOTION INPUT. This is the strict
                    // !suspended, 60 Hz, POST-orig, main-thread slot — every
                    // safety condition the c.21 graph-var crash needed (that
                    // crash was calling the setter mid cell-stream). Feed the
                    // mirror's own anim graph the owner's WALKING(1)/RUNNING(2)
                    // speed so the legs actually move; the engine keeps
                    // overwriting SpeedSampled toward 0 (the warp zeroes body
                    // velocity), so we MUST win as the last writer each frame,
                    // exactly like the c.22 InCombat bit. Only drive 1/2 — for
                    // IDLE the engine's own 0 is correct and re-asserts within a
                    // frame when a raider stops, so we skip it and pay the
                    // setter cost only for actively-moving mirrors. Combat
                    // stances (>=3) are owned by the aim/suppress path;
                    // apply_npc_locomotion returns false for them.
                    if (isnap.anim_state == 1u || isnap.anim_state == 2u) {
                        (void)fw::engine::apply_npc_locomotion(
                            actor, isnap.anim_state);
                    }
                }

                // Build 65.c.30 — stash the pose we just applied as the FROM
                // anchor for a future handoff blend (see else-branch below).
                // Pure data store — safe in or out of the suspend window.
                fw::dispatch::note_non_owner_interp_pose(
                    fid, isnap.pos_x, isnap.pos_y, isnap.pos_z, isnap.yaw_rad);

                static std::atomic<std::uint64_t> g_interp_writes{0};
                const auto n = g_interp_writes.fetch_add(
                    1, std::memory_order_relaxed);
                if (n < 20 || (n % 5000) == 0) {
                    FW_DBG("[npc-ai-suppress] c.23 INTERP-APPLY #%llu "
                           "fid=0x%08X pos=(%.1f,%.1f,%.1f) yaw=%.2f "
                           "anim=%u",
                           static_cast<unsigned long long>(n),
                           fid, isnap.pos_x, isnap.pos_y, isnap.pos_z,
                           isnap.yaw_rad, isnap.anim_state);
                }
            }
        } else {
            // ===== B6.6 POS-MEAS (read-only) — owner-side actual pos.
            // This client OWNS the raider (vanilla AI drives it = the
            // authoritative ground-truth). The OTHER client logs NONOWNER
            // synced=(...) for the same fid; that synced target should track
            // THIS pos if the relay is fresh. Owner-pos vs the other client's
            // synced diverging => relay/freshness gap, not an apply gap.
            if (fw::ownership::is_owner_of(fid)) {
                float omx = 0.0f, omy = 0.0f, omz = 0.0f;
                if (safe_read_actor_identity(actor, nullptr, nullptr,
                                             &omx, &omy, &omz)) {
                    static std::atomic<std::uint64_t> g_posmeas_o{0};
                    const auto pmo = g_posmeas_o.fetch_add(
                        1, std::memory_order_relaxed);
                    if (pmo < 40 || (pmo % 20) == 0) {
                        FW_LOG("[pos-meas] OWNER fid=0x%08X "
                               "pos=(%.0f,%.0f,%.0f)", fid, omx, omy, omz);
                    }
                }
            }
            // Build 65.c.44 — HANDOFF COMMIT (replaces the c.30 visible-blend).
            // The c.30 blend smoothed the VISIBLE pos from the last-synced pose
            // (near the owner) TOWARD B's engine pose — which is B's internally-
            // DIVERGED ground-truth (≈ the raider's pre-aggro DEFAULT spot,
            // because on B the raider had no valid local target so its AI never
            // moved it). So the raider still ENDED at default = "shoot a raider →
            // it despawns/respawns ~20m at its pre-aggro spot" (user 2026-05-31).
            // Root cause is in our own c.30 comment: apply_npc_pos / vt[202] pins
            // ONLY the visible pos (Actor+0xD0 + NIF); B's engine AI+cell+Havok
            // keep an independent, diverged pos that surfaces the instant the
            // override stops.
            // FIX: on the handoff frame, commit the last-synced pose to B's
            // ENGINE via Actor::MoveTo with doProcessUpdate=1 (reattaches the
            // AI-process + cell + Havok, not just the display). Now B's
            // ground-truth = the synced pos → no revert to default. One-shot
            // (MoveTo flushes the anim graph — fine once per handoff, fatal at
            // 60Hz). DEFERRED while suspended: actor_teleport_handoff = MoveTo
            // (do_process_update=1) goes through sub_140513A80 → the same global
            // cell-grid spinlock → it would DEADLOCK mid-cell-stream. c.46 made
            // the outer gate enter during the suspend window (for the raw pin),
            // so we must re-require !suspended here. consume_handoff_commit is a
            // one-shot consume — NOT calling it while suspended keeps the entry
            // armed so it commits on the first post-window frame (unchanged
            // semantics vs the old outer guard). KILL-SWITCH: flip to false.
            static constexpr bool kHandoffCommitEnabled = true;
            if (kHandoffCommitEnabled && !suspended) {
                float cx = 0.0f, cy = 0.0f, cz = 0.0f, cyaw = 0.0f;
                if (fw::dispatch::consume_handoff_commit(
                        fid, &cx, &cy, &cz, &cyaw)) {
                    // FIX (resurrection) — NEVER MoveTo-revive a dying raider.
                    // The c.44 MoveTo(do_process_update=1) reattaches AI+cell+
                    // Havok = brings the corpse back to life → the "MORTO MA NON
                    // MORTO" zombie + the 0xC0F510 form-deserialize crash feeder.
                    // We already consumed the armed entry above; for a dying fid
                    // just skip the teleport (is_dying is set by the death-apply
                    // drain). 2-agent RCA: re/shareddmg_zombie_AGENT.md.
                    const bool skip_revive = is_dying(fid);
                    const bool tp_ok = skip_revive
                        ? false
                        : fw::engine::actor_teleport_handoff(actor, cx, cy, cz, cyaw);
                    if (skip_revive) {
                        FW_LOG("[npc-ai-suppress] c.44 HANDOFF-COMMIT SKIP "
                               "fid=0x%08X (is_dying — no MoveTo revive)", fid);
                    } else {
                        FW_LOG("[npc-ai-suppress] c.44 HANDOFF-COMMIT fid=0x%08X -> "
                               "MoveTo synced (%.1f,%.1f,%.1f) yaw=%.2f ok=%d "
                               "(engine ground-truth <- synced pos; no respawn-at-default)",
                               fid, cx, cy, cz, cyaw, tp_ok ? 1 : 0);
                    }

                    // c.45-light — kill the ~1s re-aggro idle SAFELY. The OLD c.45
                    // (enter_combat_raider_vs_ghost) is the WRONG primitive: its
                    // is_player path still calls CCF810 which ALLOCATES HighProcess
                    // +CombatController — that (a) amplifies the 0xC0F510 form-
                    // deserialize UAF on a stale dead mirror, and (b) has 3 disable
                    // records (c.25 ghost teardown, Build-45 FRIENDLY decay,
                    // Build-64 "unstable, crashes within seconds"). So we do NOT
                    // call it. Instead the LIGHT re-engage (2-agent RCA,
                    // re/c45_fix_design_AGENT.md + re/c45_crash_RCA_AGENT.md):
                    //   1. un-gate the combat tick (+0x189=0),
                    //   2. seed the combat-target HANDLE = local player directly
                    //      (Build-15 no-alloc primitive, AIProcess+0x6C),
                    //   3. set the InCombat bit.
                    // The engine's re-acquire sweep is distance-only (no LOS
                    // raycast) and the c.44 MoveTo just placed the raider on the
                    // player → it engages at once. ZERO alloc → no 0xC0F510
                    // amplification, no Fixed-Selector (c.25), no FRIENDLY/tronco.
                    // GUARD: never on a dead/dying/knocked raider (the zombie that
                    // feeds 0xC0F510) — tp_ok is already false for is_dying (c.44
                    // skip above), plus the explicit guard here.
                    // KILL-SWITCH: kLightReengageOnHandoff=false.
                    static constexpr bool kLightReengageOnHandoff = true;
                    if (kLightReengageOnHandoff && tp_ok
                        && fw::ownership::is_owner_of(fid)
                        && !is_dying(fid) && !actor_knocked_or_dead(actor)) {
                        void* player = fw::engine::get_local_player();
                        if (player && player != actor) {
                            // No inline __try (C2712 — this fn owns lock_guards):
                            // every callee is noexcept + SEH-caged internally.
                            set_combat_skip_tick(actor, false);   // un-gate +0x189
                            const bool seed =
                                fw::engine::seed_combat_target_handle(actor, player);
                            safe_or_in_combat_bit(actor);         // InCombat 0x4000
                            FW_LOG("[npc-ai-suppress] c.45-light RE-ENGAGE "
                                   "fid=0x%08X seed=%d (un-gate + target=local "
                                   "player + InCombat; no EnterCombat)",
                                   fid, seed ? 1 : 0);
                        }
                    }
                }
            }
        }
    }

    // Build 65.c.22 — Force InCombat bit (0x4000 a Actor+0x2D0) 60Hz su
    // non-owner tracked NPCs quando l'owner riporta combat.
    //
    // Root cause Agent 2 forensics: drain setta il bit 10Hz, ma engine
    // perception walker INSIDE orig (questo Update_PerFrame appena
    // chiamato) clear il bit perché su B's view non c'è enemy perceived
    // (player_A è remote, rappresentato dal ghost ma non come "enemy
    // in perception list" del raider). Senza il bit, behavior tree
    // legge "raider in patrol state" → idle anim → user vede "animazioni
    // come avrebbe contro client B" (engine drive idle).
    //
    // Fix: re-set il bit DOPO orig, 60Hz. Bit ora persiste fino al
    // prossimo Update_PerFrame quando il ciclo si ripete. Behavior tree
    // sample del bit (durante anim graph eval, che è dopo Update_PerFrame
    // nello stesso frame) vede 0x4000 set → drives combat anim.
    //
    // Gate: solo per non-owner tracked NPCs (non sovrascrivere autonomy
    // del owner-side engine AI) E solo se owner sta riportando anim_state
    // >= 3 (AIMING/FIRING/STAGGERED, vedi enum apply_npc_state_to_actor).
    // Cache get_latest_owner_anim_state aggiornata dal drain 10Hz; entry
    // stale >2s → return false → no force (lasciamo engine decay
    // naturalmente).
    //
    // Diagnostic counter: throttled per non spammare il log (60Hz × N
    // tracked raiders è hot path).
    if (fid != 0 && fid != 0xFFFFFFFFu) {
        if (fw::ownership::is_non_owner_tracked(fid)) {
            std::uint8_t latest_anim = 0;
            if (fw::dispatch::get_latest_owner_anim_state(fid, &latest_anim)
                && latest_anim >= 3 && latest_anim <= 5)
            {
                fw::audit::note(fid, fw::audit::kInCombatForced, actor);
                safe_or_in_combat_bit(actor);
                static std::atomic<std::uint64_t> g_forced_combat_bits{0};
                const auto n = g_forced_combat_bits.fetch_add(
                    1, std::memory_order_relaxed);
                if (n < 20 || (n % 5000) == 0) {
                    FW_DBG("[npc-ai-suppress] c.22 FORCE-IN-COMBAT #%llu "
                           "fid=0x%08X anim=%u (engine cleared, re-set "
                           "post-orig)",
                           static_cast<unsigned long long>(n),
                           fid, latest_anim);
                }
            }
        }
    }

    // Restore the bridge atomic for the caller's frame.
    fw::hooks::g_current_actor_fid.store(prev_bridge_fid,
                                         std::memory_order_relaxed);
    fw::hooks::g_current_actor_ptr.store(prev_bridge_ptr,
                                         std::memory_order_relaxed);

    // Step 2: SEH-failed form_id read → no work possible.
    if (fid == 0xFFFFFFFFu) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Step 3: cache lookup for tracked-set membership (diagnostic only
    // post-deprecation — we no longer apply state here).
    if (fid == 0) {
        g_passthrough_fires.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    fw::dispatch::CachedNPCState st{};
    if (!fw::dispatch::get_cached_npc_state(fid, &st)) {
        // Not a tracked NPC; vanilla state is fine.
        g_passthrough_fires.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Tracked NPC — diagnostic counter only. Ghost AI substitutes
    // decision-point inputs upstream; no post-hoc state apply here.
    g_suppress_fires.fetch_add(1, std::memory_order_relaxed);

    // B6.5w15: round 7 keyframed motion REVIVED. For tracked NPCs with
    // movement_override (i.e. server wants them frozen), set Havok motion
    // type to Keyframed (=2) ONCE per actor. After this, Havok stops
    // integrating the rigid body — it sits at its current pos regardless
    // of velocity, anim root motion, or forces.
    //
    // Why HERE: npc_ai_suppress fires Update_PerFrame for every loaded
    // actor every frame. On the FIRST fire where actor is tracked + has
    // movement_override, we apply Keyframed. Subsequent fires are no-ops
    // (already in the set). Cheap.
    //
    // Why this addresses the bypass: we've confirmed (B6.5w15 RE) the
    // engine has multiple parallel pos writers (Actor+0xD0, NIF+0xA0
    // via UpdateWorldData, Havok body world transform via FinishPhysicsStep).
    // Bailing individual writers leaves others to drive motion. Setting
    // Keyframed at the Havok level upstream-blocks the rigid body itself,
    // which is what the renderer ultimately reads.
    // Build 62.8 (2026-05-25) — GATE on native HighProcess.
    //
    // User observation Build 62.7: "raiders stationary like logs, tracking
    // ghost but immobile". Root cause: cell-load era keyframed the Havok
    // body for every actor with movement_override=1. Once natural combat
    // tier engages via trigger_npc_perception, the raider has HighProcess
    // but Havok body is still locked Keyframed → engine wants to move it
    // but Havok won't integrate the rigid body.
    //
    // Gate: only keyframe NPCs that DON'T have native HighProcess (i.e.
    // patrollers/companions like Dogmeat that should stay frozen). Skip
    // keyframe for any actor with native HP (= in combat tier, needs to
    // move). The trigger_npc_perception SUCCESS path also calls
    // set_actor_motion_dynamic to un-keyframe raiders that were already
    // keyframed before entering combat tier.
    // ============================================================
    // Build 64 (2026-05-25) — KEYFRAMED HAVOK FREEZE DISABLED.
    //
    // Under the BUILD64 MVP-A strategy (re/BUILD64_strategy/STRATEGY.md)
    // each client runs vanilla engine AI on raiders. They must be FREE to
    // walk under engine control. Keyframing the Havok body locks the
    // rigid body in place — engine AI tries to move it but Havok refuses
    // → raiders look "logged in place" (the exact symptom that broke
    // Build 62.7).
    //
    // We deliberately accept the consequence: server's 10Hz pos snap
    // and the engine's 60Hz movement integration COMPETE. Expected
    // visual jitter is documented in STRATEGY.md §6 ("Live-test
    // expectations").
    //
    // The block is left in place (commented) so we can re-enable it
    // quickly if a future strategy needs frozen raiders again.
    // c.41b — KEYFRAME the non-owner's Havok body so it FOLLOWS our 60Hz pos
    // override instead of free-simulating. ROOT CAUSE of the user's "shoot a
    // raider owned by the other client → it teleports to its real position and
    // takes aggro": while the mirror is suppressed, the Havok rigid body DRIFTS
    // (FinishPhysicsStep→Actor sync is bailed, but the body still integrates).
    // Our override pins Actor+0xD0 (the displayed pos, handoff dist=0) but NOT
    // the Havok body. On the ownership handoff, FinishPhysicsStep re-activates
    // and writes the DRIFTED Havok pos back to the actor → the teleport. A
    // Keyframed body tracks the actor transform (our override) instead → on
    // handoff there is no drifted pos to surface. De-keyframe → Dynamic when we
    // BECOME the owner (handoff) OR the raider is knocked/dead (so ragdoll/get-
    // up physics plays). Agents de-risked it: no crash history (the old "logs"
    // symptom was no pos feed — now there is one + the 60Hz pose drive); the
    // Dynamic type-4→1 no-op is fixed in engine_calls. Revert = gate to false.
    {
        static std::mutex                              s_kf_mtx;
        static std::unordered_map<std::uint32_t, bool> s_kf;  // fid → keyframed?
        // c.43 — REMOVED the !recently_teleported() term: it was the VERIFIED
        // teleport-FLAP source (10-agent investigation, Agent 1+2+9+10, HIGH).
        // recently_teleported() false-positives on exterior cell-streaming — it
        // arms a 1500ms window on ANY local-player parentCell change/null, i.e.
        // every time the player walks across a Concord cell edge. With it inside
        // want_kf, each cell-cross flipped want_kf=false → UN-KEYFRAMED every
        // non-owner raider to Dynamic for ~1.5s → the Havok body free-simulated
        // and DRIFTED → surfaced as the teleport. The keyframe does NOT need a
        // cell-load guard: SetMotionType is a local Havok op, not a cell-lock op
        // (Agent 2). Keeping the body ALWAYS Keyframed while non-owner (except
        // genuinely knocked/dead, so ragdoll/get-up can play) means it never
        // drifts → BOTH the cell-cross flap AND the ownership-handoff seam stop
        // surfacing a divergent pos (at handoff the body is already at the synced
        // pos, so going Dynamic hands off cleanly). NOTE: the pos-pin's OWN
        // recently_teleported() gate (a real vt[202] cell-rehash deadlock guard)
        // is intentionally LEFT untouched — only the keyframe term is removed.
        // c.47 WEDGE3 — never re-keyframe a corpse. is_dying(fid) is set
        // sticky by drain_npc_death_apply_queue the instant a relayed owner
        // death starts applying; without this term the machine could re-freeze
        // the ragdoll for ~1 frame while the async Actor::Kill's KnockState
        // bits lag (actor_knocked_or_dead still reads "alive"). Clear it when
        // we (re)acquire ownership — a fresh live entity (respawn/handoff) of
        // the same form_id must start clean.
        if (fw::ownership::is_owner_of(fid)) {
            fw::hooks::clear_dying(fid);
        }
        const bool want_kf =
            fw::ownership::is_non_owner_tracked(fid) &&
            !actor_knocked_or_dead(actor) &&
            !fw::hooks::is_dying(fid);
        std::lock_guard<std::mutex> lk(s_kf_mtx);
        const bool cur = s_kf[fid];
        if (want_kf && !cur) {
            if (fw::engine::set_actor_motion_keyframed(actor)) {
                s_kf[fid] = true;
                static std::atomic<std::uint64_t> s_n{0};
                const auto n = s_n.fetch_add(1, std::memory_order_relaxed);
                if (n < 20 || (n % 200) == 0)
                    FW_LOG("[npc-ai-suppress] c.41b KEYFRAME fid=0x%08X — non-owner "
                           "Havok frozen (follows override; kills handoff teleport)",
                           fid);
            }
        } else if (!want_kf && cur) {
            if (fw::engine::set_actor_motion_dynamic(actor)) {
                s_kf[fid] = false;
                static std::atomic<std::uint64_t> s_m{0};
                const auto m = s_m.fetch_add(1, std::memory_order_relaxed);
                if (m < 20 || (m % 200) == 0)
                    FW_LOG("[npc-ai-suppress] c.41b UN-KEYFRAME fid=0x%08X — owner/"
                           "knocked/dead → Dynamic (physics resumes)", fid);
            }
        }
    }

#if 0
    // ===== ROUND 2 (CLOSED) — kept for reference =======================
    // POST-overwrite of pos/yaw/anim from cache.  Don't re-enable: the
    // race against engine's own NIF sync is unwinnable at this level.
    // Architecturally superseded by Ghost AI decision-point hooks.
    fw::engine::apply_npc_state_to_actor(
        actor,
        st.pos_x, st.pos_y, st.pos_z,
        st.yaw_deg_math, st.anim_state,
        /*skip_anim_graph=*/false);
#endif  // ===== end round 2 reference block ===========================
}

} // namespace

bool install_npc_ai_suppress(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[npc-ai-suppress] already installed; skipping");
        return true;
    }
    g_module_base.store(module_base, std::memory_order_release);  // c.39a
    const auto target_ea =
        module_base + fw::offsets::ACTOR_UPDATE_PERFRAME_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_actor_update_perframe),
        reinterpret_cast<void**>(&g_orig_actor_update_perframe));
    // Build 69 — second detour: drop event-98 (StopCombat) requests aimed at
    // mirrored NPCs. Installed independently of the one above: if it fails we
    // are back to the measured-broken behaviour, not to a crash, so a failure
    // here must not abort the primary install.
    {
        const auto rsc_ea =
            module_base + fw::offsets::REQUEST_STOP_COMBAT_RVA;
        const bool rsc_ok = install(
            reinterpret_cast<void*>(rsc_ea),
            reinterpret_cast<void*>(&detour_request_stop_combat),
            reinterpret_cast<void**>(&g_orig_request_stop_combat));
        if (rsc_ok) {
            FW_LOG("[npc-ai-suppress] RequestStopCombat hook installed at "
                   "0x%llX (RVA 0x%lX) — mirrors keep their HighProcess",
                   static_cast<unsigned long long>(rsc_ea),
                   static_cast<unsigned long>(
                       fw::offsets::REQUEST_STOP_COMBAT_RVA));
        } else {
            FW_ERR("[npc-ai-suppress] RequestStopCombat hook FAILED at 0x%llX "
                   "— mirrored NPCs will keep losing their combat state every "
                   "frame (measured: 106/106 allocations dead within 1 tick)",
                   static_cast<unsigned long long>(rsc_ea));
        }
    }

    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[npc-ai-suppress] Actor::Update_PerFrame hook installed at 0x%llX "
               "(RVA 0x%lX) — tracked NPCs will skip vanilla AI tick",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::ACTOR_UPDATE_PERFRAME_RVA));
    } else {
        FW_ERR("[npc-ai-suppress] hook FAILED at 0x%llX — vanilla AI will "
               "continue fighting our pos writes at 60 Hz",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_npc_ai_suppress_fires() {
    return g_suppress_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_npc_ai_passthrough_fires() {
    return g_passthrough_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_npc_ai_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

// B6.6w3 — g_dyn_tracked is now a DISCOVERY DEDUP SET. It does NOT
// drive bail decisions in any hook. Pos/AI hooks should check
// `should_freeze_actor` (server-explicit movement_override) instead.
//
// Kept for backwards compat — returns whether we've sent NPC_DISCOVER
// for this fid. Some hooks may still call this; until they're audited
// and migrated to `should_freeze_actor`, this function returns FALSE
// unconditionally so legacy "if (is_actor_bail_tracked(fid)) bail;"
// callers do NOT bail. The discovery state is queried internally via
// the file-scope set; external code shouldn't make decisions on it.
bool is_actor_bail_tracked(std::uint32_t /*form_id*/) {
    return false;
}

std::uint64_t get_dyn_bail_tracked_count() {
    return g_dyn_set_size.load(std::memory_order_relaxed);
}

// B6.6w0 hook #3 helper: AIProcess* → form_id reverse lookup.
// Shared-read lock; multiple ghost-AI hooks can query concurrently.
bool get_fid_for_aiproc(const void* aiproc, std::uint32_t* out_fid) {
    if (!aiproc) return false;
    if (g_aiproc_map_size.load(std::memory_order_relaxed) == 0) return false;
    std::shared_lock<std::shared_mutex> lk(g_aiproc_mtx);
    const auto it = g_aiproc_to_fid.find(aiproc);
    if (it == g_aiproc_to_fid.end()) return false;
    if (out_fid) *out_fid = it->second;
    return true;
}

std::uint64_t get_aiproc_map_size() {
    return g_aiproc_map_size.load(std::memory_order_relaxed);
}

// B6.6w3 — POS-hook bail predicate.
//
// Returns true iff the SERVER has explicitly registered this actor and
// flagged movement_override=1 in the broadcast cache. The local-only
// "auto-tracked via InCombat flag" path is removed (was making raiders
// statues before vanilla AI could engage combat — user feedback "i
// raider sono FRIENDLY").
//
// Symmetry: both clients receive the same broadcast → they freeze the
// raider at the same position simultaneously.
bool should_freeze_actor(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    if (form_id == 0x00000014u) return false;   // never freeze player

    fw::dispatch::CachedNPCState st{};
    return fw::dispatch::get_cached_npc_state(form_id, &st)
        && st.movement_override != 0;
}

// B6.6w3 — combat-hook bail predicate.
//
// Returns false (= "don't silence, let vanilla combat run") unless:
//   - Server has registered the actor (movement_override = 1), AND
//   - Server has NOT designated this peer as the combat target
//     (combat_target_form_id == 0).
//
// Rationale: server is authoritative on which peer the raider is aggro'd
// to. If THIS peer is the target, vanilla combat runs (raider attacks).
// If another peer is the target, our combat is silenced so we don't
// have desync. Local-only auto-track is no longer a silencing source
// (user wanted vanilla AI to run for not-yet-server-tracked raiders).
bool should_silence_combat(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    if (form_id == 0x00000014u) return false;   // never silence player

    // Build 43 (2026-05-17) — STICKY bypass for cross-peer-engaged raiders.
    //
    // Previously: returned true (silence) whenever cache says
    // combat_target_form_id == 0. Problem: NPC_STATE_BCAST cache oscillates
    // back to 0 between per-peer projection bursts → fire/dispatch hooks
    // BAIL → raider brain dies in seconds (no fire, no swing, no grenade).
    //
    // Fix: once `install_fixed_selector_on_raider` has registered this fid
    // for the ghost (engine_calls.cpp populates g_ghost_engaged_raider_fids),
    // NEVER silence its combat. Engine's vanilla AI handles fire-decide,
    // dispatch-attack, grenade-throw — all naturally, all the time. Server
    // cache flicker no longer drops the brain into idle.
    if (fw::engine::is_ghost_engaged_raider_fid(form_id)) return false;

    // ----------------------------------------------------------------
    // Build 45 (2026-05-17 evening) — NEVER SILENCE. Period.
    //
    // The previous Build 43 logic silenced fire/dispatch whenever
    // `movement_override == 1 && combat_target_form_id == 0`. Live
    // test 2026-05-17 (Client A log 17:32:06+) proved this is wrong:
    //   - Raider 0x46459 was naturally aggro'd on player_A (engine
    //     entered combat tier; HighProcess populated; muzzle flashes
    //     visible PRIOR to first NPC_DISCOVER).
    //   - Server received NPC_DISCOVER → registered raider →
    //     movement_override = 1 on next NPC_STATE_BCAST.
    //   - Server's per-tick projection sometimes had combat_target = 0
    //     (transition window between aggro switches, or no cross-peer
    //     opinion yet).
    //   - This branch returned true → ghost_ai_fire BAIL → raider
    //     stopped firing AT PLAYER_A even though server had no
    //     conflicting opinion.
    //   - User observation: "raiders go idle, ignore the ghost" was
    //     partly THIS bug — engine wanted to fire, we silenced.
    //
    // New semantics: never silence. Three correct cases:
    //   (a) server says target=0 (no opinion): vanilla AI runs.
    //       Raider fires at whoever it naturally aggro'd (player_A
    //       locally for client A).
    //   (b) server says target=0x14 (= peer ON THIS client): vanilla
    //       AI runs (player_A is already a valid local target).
    //   (c) server says target=ghost_form_id (= cross-peer aggro):
    //       apply_npc_combat_target writes aiproc+0x6C = ghost_handle
    //       on receipt. Engine's combat brain re-targets ghost on its
    //       next tick. Vanilla AI runs against ghost as target.
    //
    // In NONE of these cases should we silence the engine's natural
    // fire/dispatch. The fire-handler hook (ghost_ai_fire) bails are
    // unnecessary friction.
    //
    // (Code left in for reference; the conditions evaluate but the
    // final return is always false.)
    //
    fw::dispatch::CachedNPCState st{};
    const bool cached =
        fw::dispatch::get_cached_npc_state(form_id, &st);
    (void)cached;  // diagnostic only
    (void)st;
    return false;
}

// ============================================================================
// Build 65.c.47 — WEDGE3 death-sync. STICKY "dying" set accessors.
// ============================================================================
void mark_dying(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    std::lock_guard<std::mutex> lk(g_dying_mtx);
    g_dying.insert(form_id);
}

bool is_dying(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    std::lock_guard<std::mutex> lk(g_dying_mtx);
    return g_dying.find(form_id) != g_dying.end();
}

void clear_dying(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    std::lock_guard<std::mutex> lk(g_dying_mtx);
    g_dying.erase(form_id);
}

} // namespace fw::hooks
