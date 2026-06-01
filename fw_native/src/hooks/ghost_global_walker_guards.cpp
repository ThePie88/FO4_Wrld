// ============================================================================
// Build 57 (2026-05-23) — GLOBAL WALKER GUARDS — comprehensive ghost shielding.
//
// Source dossiers (read in this order if you need context):
//   re/walker_inventory/AGENT_A_form_table_walkers.md           (5 walkers)
//   re/walker_inventory/AGENT_B_cell_ref_list_walkers.md        (31 walkers)
//   re/walker_inventory/AGENT_C_combat_controller_walkers.md    (34 walkers)
//   re/walker_inventory/AGENT_D_death_cleanup_walkers.md        (23 walkers + KEY FINDING)
//   re/walker_inventory/AGENT_E_perception_hostility_walkers.md (27 walkers)
//   re/walker_inventory/AGENT_F_global_perframe_walkers.md      (70 thunks)
//
// MOTIVATING CRASH
// ----------------
// Builds 55f / 55h / 56 all crashed at RVA 0xE98860 with addr=-1. Six
// rounds of investigation thought this was a vtable-cascade dispatch on
// ghost. Agent D PROVED IT IS NOT. It is the literal instruction
// `cmp [r8+rdx], ecx` at offset +0x40 inside `sub_140E98820` (a 0x76-byte
// CombatController::FindEntryByFormID linear-search). When `r8=0` (first
// iteration) and `rdx = *(controller+0x08) = -1`, the effective address
// becomes `0xFFFFFFFFFFFFFFFF` and the cmp AVs. The fault is a SCALAR
// memory compare against a poisoned entries-base pointer, not a virtual
// dispatch.
//
// The controller-+0x08 = -1 can come from:
//   (a) ghost's actor+0x40 is uninitialised → reading +8 from garbage = -1
//   (b) controller was freed and the freelist marker wrote -1 there
//   (c) concurrent dtor during death cleanup
//
// FIX: hook sub_140E98820 entry, pre-check entries-base, return 0 ("not
// found") if -1 or 0 or unmapped. This eliminates the AV class for ALL
// 27 known callers of FindEntryByFormID (the 21 GetTargetX wrappers + 6
// direct probes) in a single hook. Per Agent D §8: "kills the AV class
// for all 21 wrappers + housekeeping + tick in one hook".
//
// LAYERED DEFENSE
// ---------------
// FindEntryByFormID guard is the architectural keystone (it kills the
// current crash). But the user explicitly wants ALL walkers patched.
// Therefore this module installs SIX additional hooks beyond the keystone,
// covering every walker class the agents identified as HIGH-RISK:
//
//   Hook 1: sub_140E98820 — FindEntryByFormID entries-base poison guard.
//   Hook 2: sub_140E918C0 — ProcessTick skip when ghost-controller / poisoned.
//   Hook 3: sub_140E988A0 — housekeeping skip when ghost in known_targets.
//   Hook 4: sub_140C06AC0 — form-table rehydrator skip when bucket is ghost.
//   Hook 5: sub_140C80D70 — death broadcast skip when ghost is dyingActor or in array.
//   Hook 6: sub_140DA28A0 — LOS sight-cone skip-entry on ghost.
//   Hook 7: sub_140E91D70 — AddKnownTarget early-bail when entries-base poisoned.
//
// Each hook follows the same template:
//   - typed function pointer (constexpr RVA + trampoline storage)
//   - SEH-caged detour body
//   - atomic counters: fires, ghost-hits, actions-taken, SEH
//   - throttled logging (first 16 + every 256/1000th hit)
//
// The bail action is always "return safe value" — never "best-effort
// recovery" — because the goal is to keep the game running while we lose
// one walker's frame contribution (one frame of stale combat state).
//
// THREADING
// ---------
// All target walkers run main thread. Counters are atomic with relaxed
// memory order (we only read for periodic dump, exact ordering doesn't
// matter). No shared mutable state across detours.
//
// CONFIDENCE BLEND
// ----------------
// Hook 1 (E98820): HIGH — direct disasm + algebra proves the AV mechanism.
// Hook 2 (E918C0): MED — defensive, may fire on legit cases where entries
//                  briefly transition. Throttled to avoid log spam.
// Hook 3 (E988A0): MED-HIGH — Agent D §3.5 recommends; large fn body
//                  means we can't audit every dispatch site.
// Hook 4 (C06AC0): HIGH — already documented crash class, see
//                  crash_death_vtable_cascade dossier.
// Hook 5 (C80D70): MED — Agent E identified but didn't observe firing yet.
// Hook 6 (DA28A0): MED — Agent E predicted as next-crash candidate.
// Hook 7 (E91D70): MED — defensive belt on the AddTarget path that
//                  triggered the original crash.
//
// If any hook misbehaves we can disable it individually via the per-hook
// `g_<hook>_disabled` atomic flag.
// ============================================================================

#include "ghost_global_walker_guards.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../engine/engine_calls.h"  // get_ghost_duplicate

namespace fw::hooks {

namespace {

// ============================================================================
// Per-hook trampoline storage + function-pointer typedefs.
//
// All trampolines are nullptr at init; populated by `install()` (MinHook).
// Each detour calls through the trampoline to vanilla behavior when the
// guard predicate doesn't fire.
// ============================================================================

using FindEntryByFormIDFn  = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          std::uint32_t* fid);
using ProcessTickFn        = std::int64_t (__fastcall *)(std::int64_t ctrl);
using HousekeepingFn       = void         (__fastcall *)(std::int64_t ctrl);
using AddKnownTargetFn     = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          void* actor);
using FormBucketWalkerFn   = std::int64_t (__fastcall *)(std::int64_t arg);
using DeathBroadcastFn     = void         (__fastcall *)(std::int64_t dying_actor);
using LOSWalkerFn          = std::int64_t (__fastcall *)(std::int64_t a1,
                                                          std::int64_t a2,
                                                          std::int64_t a3,
                                                          std::int64_t a4);
using LockPrimitiveFn      = void         (__fastcall *)(void* lock);
using RemoveByFidFn        = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          std::int64_t fid_ref);
using GroupGateFn          = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          void* target_actor);
// Build 62.2 — 5 more peer walker signatures
using FindInRangeFn        = void*        (__fastcall *)(std::int64_t ctrl,
                                                          std::int64_t origin_pos,
                                                          float radius,
                                                          char filter_byte);
using KnownByActorFn       = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          void* actor);
using EnsureKnownFn        = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          void* actor);
using UpdatePosFn          = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          void* actor,
                                                          std::int64_t pos);
using AllyHealthFn         = std::int64_t (__fastcall *)(std::int64_t ctrl);

// Build 62.5 (2026-05-24) — Hook 16: sub_140E75F30 BSTHashMap merge walker.
// Signature: void __fastcall(__int64 a1, _QWORD *a2). a1 is an entries struct
// (count at +0x04 u32, base at +0x20 with 24-byte stride); a2 is a hash table
// to merge into. AV at +0x3A in Build 62.4 live test 21:23:52 — base read
// from corrupt freed sub-structure.
using HashMapMergeFn       = void         (__fastcall *)(std::int64_t a1,
                                                          void* a2);

// Build 62.6 (2026-05-24) — Hooks 17-22: stride-208 CC walkers in the
// FindEntryByActor / per-tick aggro-freshness / per-tick ally-validity
// family. All read CC+0x08 (base) and CC+0x18 (count), 208-byte stride.
// Crash signature Build 62.5 21:51:34 hit sub_140E986C0 (Hook 17 target);
// the sister walkers are added preventively (same vulnerability pattern,
// all fired per-tick once combat tier is active).
using FindEntryByActorFn   = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          std::int64_t actor);
using FindEntryByFIDFn     = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          std::uint32_t* fid_ptr);
using CCTickWalkerFn       = char         (__fastcall *)(std::int64_t ctrl);
using CCTickWalkerVoidFn   = void         (__fastcall *)(std::int64_t ctrl);
using NotifyTargetsFn      = char         (__fastcall *)(std::int64_t ctrl);

FindEntryByFormIDFn  g_orig_find_entry          = nullptr;
ProcessTickFn        g_orig_process_tick        = nullptr;
HousekeepingFn       g_orig_housekeeping        = nullptr;
AddKnownTargetFn     g_orig_add_known_target    = nullptr;
FormBucketWalkerFn   g_orig_form_rehydrator     = nullptr;
DeathBroadcastFn     g_orig_death_broadcast     = nullptr;
LOSWalkerFn          g_orig_los_sight_cone      = nullptr;
LockPrimitiveFn      g_orig_lock_primitive      = nullptr;
RemoveByFidFn        g_orig_remove_by_fid       = nullptr;   // Build 62.1
GroupGateFn          g_orig_group_gate          = nullptr;   // Build 62.1
FindInRangeFn        g_orig_find_in_range       = nullptr;   // Build 62.2
KnownByActorFn       g_orig_known_by_actor      = nullptr;   // Build 62.2
EnsureKnownFn        g_orig_ensure_known        = nullptr;   // Build 62.2
UpdatePosFn          g_orig_update_pos          = nullptr;   // Build 62.2
AllyHealthFn         g_orig_ally_health         = nullptr;   // Build 62.2
HashMapMergeFn       g_orig_hashmap_merge       = nullptr;   // Build 62.5
FindEntryByActorFn   g_orig_find_by_actor       = nullptr;   // Build 62.6
FindEntryByFIDFn     g_orig_find_by_fid         = nullptr;   // Build 62.6
CCTickWalkerVoidFn   g_orig_aggro_freshness     = nullptr;   // Build 62.6
CCTickWalkerVoidFn   g_orig_ally_validity_870   = nullptr;   // Build 62.6
CCTickWalkerFn       g_orig_ally_validity_A40   = nullptr;   // Build 62.6
CCTickWalkerFn       g_orig_count_entries       = nullptr;   // Build 62.6
NotifyTargetsFn      g_orig_notify_subscribers  = nullptr;   // Build 62.6

// Build 62.7 — Hooks 24-25: RemoveAlly family (id_list walkers).
using RemoveAllyByKeyFn    = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          std::int64_t actor_key);
using RemoveAllyByIdxFn    = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                          std::uint32_t idx);
RemoveAllyByKeyFn    g_orig_remove_ally_key     = nullptr;   // Build 62.7
RemoveAllyByIdxFn    g_orig_remove_ally_idx     = nullptr;   // Build 62.7

// Build 63 — Hook 26: sub_140ED2490 group-membership reconcile.
// Signature: char __fastcall(void* actor, void* target_actor)
// Per Agent D + Agent E: reads actor.HighProcess+0x40 (back-pointer to
// CombatController) and passes it to sub_140E93370 MERGE. When CC was
// freed during cell-attach, HP+0x40 is stale → MERGE crashes at +0x50
// prologue spill. Hook validates HP+0x40 before forwarding.
using GroupReconcileFn = char (__fastcall *)(void* actor, void* target);
GroupReconcileFn     g_orig_group_reconcile     = nullptr;   // Build 63

// Build 65.c.31 — Hook 27: sub_140E959E0 UpdateCombatTargetRecord.
// __fastcall(ctrl, a2, a3). At entry rsi = *(ctrl+0x78) (combat-target sub-
// object holding a BSTScatterTable); the body then derefs +0x40 (spinlock,
// twice) and +0x28 (hash base) UNCONDITIONALLY. On owner-side raider death the
// +0x78 sub-object is NULL → the two spinlock derefs hit lock=0x40 (Hook 8
// bails them) and then the sibling read [rsi+0x28] AVs at 0xE95A49. Return type
// kept as int64 (passed through on the safe path); both callers ignore it.
using UpdateTargetRecFn = std::int64_t (__fastcall *)(std::int64_t ctrl,
                                                      std::int64_t a2,
                                                      std::int64_t a3);
UpdateTargetRecFn    g_orig_update_target_rec   = nullptr;   // Build 65.c.31

// ============================================================================
// Per-hook counters. Naming: g_<hook>_<event>_count.
//
//   fires:       total times detour was entered
//   ghost_hits:  guard predicate matched (ghost involved / poison detected)
//   actions:     detour bailed orig (skip/return-safe)
//   seh:         SEH caught inside detour body (our guard logic faulted)
// ============================================================================

struct WalkerGuardCounters {
    std::atomic<std::uint64_t> fires{0};
    std::atomic<std::uint64_t> ghost_hits{0};
    std::atomic<std::uint64_t> actions{0};
    std::atomic<std::uint64_t> seh{0};
};

WalkerGuardCounters g_c_find_entry;         // sub_140E98820
WalkerGuardCounters g_c_process_tick;       // sub_140E918C0
WalkerGuardCounters g_c_housekeeping;       // sub_140E988A0
WalkerGuardCounters g_c_add_target;         // sub_140E91D70
WalkerGuardCounters g_c_form_rehydrator;    // sub_140C06AC0
WalkerGuardCounters g_c_death_broadcast;    // sub_140C80D70
WalkerGuardCounters g_c_los_sight_cone;     // sub_140DA28A0
WalkerGuardCounters g_c_lock_primitive;     // sub_141658FE0 (Build 59)
WalkerGuardCounters g_c_remove_by_fid;      // sub_140E92260 (Build 62.1)
WalkerGuardCounters g_c_group_gate;         // sub_140E924A0 (Build 62.1)
WalkerGuardCounters g_c_find_in_range;      // sub_140E96490 (Build 62.2)
WalkerGuardCounters g_c_known_by_actor;     // sub_140E92E50 (Build 62.2)
WalkerGuardCounters g_c_ensure_known;       // sub_140E929C0 (Build 62.2)
WalkerGuardCounters g_c_update_pos;         // sub_140E92B90 (Build 62.2)
WalkerGuardCounters g_c_ally_health;        // sub_140E97D30 (Build 62.2)
WalkerGuardCounters g_c_hashmap_merge;      // sub_140E75F30 (Build 62.5)
WalkerGuardCounters g_c_find_by_actor;      // sub_140E986C0 (Build 62.6)
WalkerGuardCounters g_c_find_by_fid;        // sub_140E98760 (Build 62.6)
WalkerGuardCounters g_c_aggro_freshness;    // sub_140E9EC40 (Build 62.6)
WalkerGuardCounters g_c_ally_validity_870;  // sub_140E9E870 (Build 62.6)
WalkerGuardCounters g_c_ally_validity_A40;  // sub_140E9EA40 (Build 62.6)
WalkerGuardCounters g_c_count_entries;      // sub_140E9E760 (Build 62.6)
WalkerGuardCounters g_c_notify_subscribers; // sub_140E98480 (Build 62.6)
WalkerGuardCounters g_c_remove_ally_key;    // sub_140E92D00 (Build 62.7)
WalkerGuardCounters g_c_remove_ally_idx;    // sub_140E9E0C0 (Build 62.7)
WalkerGuardCounters g_c_group_reconcile;    // sub_140ED2490 (Build 63)
WalkerGuardCounters g_c_update_target_rec;  // sub_140E959E0 (Build 65.c.31)

// Per-hook disable flag. We never set these in code — they're hooks for
// runtime "kill switch" if a guard misfires in production. To disable a
// guard live, set `g_disable_<hook>` = true and the detour passes through
// to orig without any predicate evaluation. Counter `fires` keeps
// counting so we can observe "what would have been guarded".
std::atomic<bool> g_disable_find_entry{false};
std::atomic<bool> g_disable_process_tick{false};
std::atomic<bool> g_disable_housekeeping{false};
std::atomic<bool> g_disable_add_target{false};
std::atomic<bool> g_disable_form_rehydrator{false};
std::atomic<bool> g_disable_death_broadcast{false};
// Build 58: LOS SightCone Hook 7 was found to SKIP-ALL the LOS walker
// 5000+ times/session, breaking vanilla perception for ALL actors (not
// just ghost). Raiders couldn't see players → no aggro. Disabled by
// default. Re-enable manually if a future crash actually surfaces here.
std::atomic<bool> g_disable_los_sight_cone{true};

// Build 59: lock primitive null-deriv guard. ON by default — kills the
// terminal AV at sub_141658FE0 when engine derives rcx from null+offset.
std::atomic<bool> g_disable_lock_primitive{false};

// Build 65.c.31 — Hook 27 (sub_140E959E0) kill switch. ON by default.
std::atomic<bool> g_disable_update_target_rec{false};

std::atomic<bool> g_installed{false};

// ============================================================================
// Shared helpers
// ============================================================================

// SEH-safe pointer read. Returns 0 on fault.
inline std::uint64_t safe_read_u64(std::uintptr_t addr) noexcept {
    std::uint64_t v = 0;
    __try {
        v = *reinterpret_cast<std::uint64_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        v = 0;
    }
    return v;
}

inline std::uint32_t safe_read_u32(std::uintptr_t addr) noexcept {
    std::uint32_t v = 0;
    __try {
        v = *reinterpret_cast<std::uint32_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        v = 0;
    }
    return v;
}

// Read the ghost duplicate ptr (atomic load via engine_calls).
inline void* ghost_ptr() noexcept {
    return fw::engine::get_ghost_duplicate();
}

// Read ghost's form_id (the 0xFF000001 we registered). Returns 0 if no
// ghost is registered yet.
inline std::uint32_t ghost_fid() noexcept {
    void* g = ghost_ptr();
    if (!g) return 0;
    return safe_read_u32(
        reinterpret_cast<std::uintptr_t>(g) + fw::offsets::FORMID_OFF);
}

// Read ghost's "combat controller ptr" at actor+0x40. Per Agent D §2.5
// this is what wrapper sub_14087A320 reads to pass to FindEntryByFormID.
// For the synthetic ghost, this is often 0 / garbage / pointer to
// poisoned struct → reading +8 gives -1 → AV.
inline std::uintptr_t ghost_combat_ctrl_ptr() noexcept {
    void* g = ghost_ptr();
    if (!g) return 0;
    return static_cast<std::uintptr_t>(
        safe_read_u64(reinterpret_cast<std::uintptr_t>(g) +
                      fw::offsets::ACTOR_COMBAT_CONTROLLER_OFF));
}

// Determine if a CombatController pointer's entries-base field is
// poisoned. Returns true if entries_base is structurally invalid:
//   - SEH on read (unmapped)
//   - any sub-page value (< 0x10000): all of these are derived from
//     null+small_offset and CANNOT be a real heap pointer
//
// Build 57: bailed on 0 and -1.
// Build 58: removed the 0-bail because it broke synth's AddKnownTarget
//           growth path (fresh ctrl with empty 0-base is legit).
// Build 60: empirical evidence showed sentinel `0x1` causes AV class
//           identical to `-1` — engine treats entries_base as a pointer
//           and dereferences. ANY sub-page value (< 64 KiB first user
//           page) is structurally a null-deriv and will AV at addr<page.
//           Generalize to "< 0x10000 = poisoned".
//
// CRITICAL nuance: this also catches entries_base == 0 again. To avoid
// breaking synth's AddKnownTarget growth path, Hook 4 (add_target)
// keeps its narrower -1-only check via a dedicated helper below. Only
// Hook 1 (find_entry) and Hook 2/3 (process_tick/housekeeping) use this
// broader sub-page check — they READ entries_base and crash on sub-page;
// AddKnownTarget WRITES it and needs to allow 0→buffer transition.
//
// Verified safe via decomp: sub_140E98820 with count==0 exits the loop
// early (test ebx, ebx; jz) BEFORE the AV instruction. So even if
// entries_base==0 (count must also be 0 in legit case), no AV → our
// guard returning 0 is semantically identical to vanilla behavior.
inline bool ctrl_entries_base_is_poisoned(std::uintptr_t ctrl) noexcept {
    if (!ctrl) return true;
    bool poisoned = false;
    __try {
        // Build 62.3 (2026-05-24) — COUNT-AWARE poison check.
        //
        // CRITICAL: vanilla walkers (sub_140E98820 etc.) check `count == 0`
        // BEFORE reading `entries_base`. For a freshly-allocated empty CC,
        // entries_base is 0 (NULL) and count is 0 — vanilla loop early-
        // exits without dereferencing the base.
        //
        // Build 62.2 bug: my poison check only looked at base. base=0 was
        // flagged as poisoned even when count=0 (legitimate empty). This
        // caused Hooks 11-15 to silently bail Fresh CC's, which made
        // CCF810→ED2390→EnsureKnownTarget→Hook 13 fail → engine returns
        // 0 from EnterCombat → raider never engages. Symptom: raider
        // perception works (torso follows ghost) but combat tier never
        // allocates → idle. ZERO crashes, ZERO POISON-BAIL events (because
        // the bail was implicit in return 0 paths that engine treated
        // as legitimate "nothing to do" semantics).
        //
        // Fix: check count first. If count == 0, the array is legitimately
        // empty regardless of what base contains (vanilla walkers never
        // dereference it). Only flag as poisoned if count > 0 AND base
        // looks structurally invalid.
        const std::uint32_t count = *reinterpret_cast<std::uint32_t*>(
            ctrl + fw::offsets::COMBATCTRL_ENTRIES_COUNT_OFF);
        if (count == 0) {
            return false;  // empty array — safe, vanilla early-exits
        }
        // Build 62.12 (2026-05-25) — count sanity check. Real CombatController
        // known_targets[] never holds more than 50 entries; any value > 4096
        // is garbage (CC was freed-and-reused as a different allocation type
        // whose +0x18 happens to contain a non-zero u32). Build 62.11 live
        // test showed sub_140E986C0 AV at 0xE98721 where rdx=0xF4C7 (=62663)
        // = the count read from a corrupted CC.
        if (count > 4096) {
            return true;  // poison
        }
        const std::uint64_t entries_base =
            *reinterpret_cast<std::uint64_t*>(
                ctrl + fw::offsets::COMBATCTRL_ENTRIES_BASE_OFF);
        // With count > 0, base MUST be a valid heap pointer. If it's
        // sub-page, beyond plausible heap, or kernel-space, the CC is
        // structurally corrupted (freed-and-reused, sentinel marker, etc.).
        //
        // Build 62.10 (2026-05-25) — tightened MAX_HEAP threshold to
        // 0x300_0000_0000 (~3.3 TB). FO4 heap allocations live in
        // 0x1xx_..._..._ to 0x2xx_..._..._. Build 62.9 live test showed
        // entries_base = 0x4F2_0000_018A (~5.4 TB) escaping the previous
        // 0x8000_..._..._ kernel threshold → AV at 0xE92505.
        constexpr std::uint64_t MIN_USER_HEAP_ADDR  = 0x10000ULL;
        constexpr std::uint64_t MAX_HEAP_ADDR       = 0x300000000000ULL;
        constexpr std::uint64_t MIN_KERNEL_ADDR     = 0x8000000000000000ULL;
        poisoned = (entries_base < MIN_USER_HEAP_ADDR)
                || (entries_base >= MAX_HEAP_ADDR && entries_base < MIN_KERNEL_ADDR)
                || (entries_base >= MIN_KERNEL_ADDR);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        poisoned = true;
    }
    return poisoned;
}

// Narrow version: bail ONLY on -1 (true sentinel that AVs cmp). Used by
// Hook 4 (AddKnownTarget) which must let entries_base==0 through so
// synth's growth path can transition 0 → newly-allocated buffer.
inline bool ctrl_entries_base_is_neg1_only(std::uintptr_t ctrl) noexcept {
    if (!ctrl) return true;
    bool poisoned = false;
    __try {
        const std::uint64_t entries_base =
            *reinterpret_cast<std::uint64_t*>(
                ctrl + fw::offsets::COMBATCTRL_ENTRIES_BASE_OFF);
        poisoned = (entries_base == 0xFFFFFFFFFFFFFFFFULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        poisoned = true;
    }
    return poisoned;
}

// Throttled log helper for guards. Logs at first N hits + every Nth.
inline bool should_log(std::uint64_t n,
                       std::uint64_t early = 16,
                       std::uint64_t every = 1000) {
    return n < early || (every != 0 && (n % every) == 0);
}

// ============================================================================
// HOOK 1 — sub_140E98820 FindEntryByFormID entries-base poison guard.
//
// The crash killer. See file header for full rationale.
//
// Detour pseudo-C:
//   if (g_disable) return orig(ctrl, fid);
//   fires++
//   if (ctrl_entries_base_is_poisoned(ctrl)) {
//     ghost_hits++; actions++;
//     return 0; // "not found"
//   }
//   return orig(ctrl, fid);
//
// Cost per call: 1 atomic-increment + 1 SEH-caged QWORD read + 2 compares.
// On a 30-Hz tick with ~50 wrappers visiting ~10 actors, that's ~15k
// calls/sec. Each call is ~30 ns of overhead. Negligible.
//
// Semantic correctness: when entries-base is -1/0, the orig would have
// AV'd at offset +0x40. Returning 0 ("not found") mirrors the vanilla
// "no matching entry" return path at `loc_140E98889`. The caller treats
// not-found-vs-AV identically: they typically check `if (entry == 0)
// return 0;` in the wrapper body (see Agent D §6 wrapper enumeration).
//
// CORRECTNESS NOTE for ghost: if the engine queries ghost.controller and
// we return 0, the engine sees "ghost has no known targets" — which is
// architecturally correct (ghost is a passive proxy, doesn't track its
// own enemies). So 0 is the SEMANTICALLY-CORRECT return value too, not
// just a panic bail.
// ============================================================================
std::int64_t __fastcall detour_find_entry(std::int64_t ctrl,
                                           std::uint32_t* fid) noexcept
{
    g_c_find_entry.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_find_entry.load(std::memory_order_relaxed)) {
        return g_orig_find_entry ? g_orig_find_entry(ctrl, fid) : 0;
    }

    __try {
        if (ctrl_entries_base_is_poisoned(static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_find_entry.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_find_entry.actions.fetch_add(1, std::memory_order_relaxed);
            if (should_log(n, 16, 1000)) {
                const std::uint32_t target_fid = fid
                    ? safe_read_u32(reinterpret_cast<std::uintptr_t>(fid))
                    : 0u;
                FW_LOG("[wg/find_entry] POISON-BAIL #%llu ctrl=0x%llX "
                       "target_fid=0x%08X — entries_base poisoned (=-1/0/unmapped); "
                       "returning 'not found' (0) to avoid AV at 0xE98860",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl),
                       target_fid);
            }
            return 0;
        }
        return g_orig_find_entry ? g_orig_find_entry(ctrl, fid) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_find_entry.seh.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[wg/find_entry] SEH in detour (ctrl=0x%llX)",
               static_cast<unsigned long long>(ctrl));
        return 0;
    }
}

// ============================================================================
// HOOK 2 — sub_140E918C0 CombatController::ProcessTick guard.
//
// Per-tick AI processor. Body 0x4A4 bytes (1188). Iterates entries[],
// invokes cull predicate sub_140E9E2B0 per entry, removes via
// sub_140E9E1D0, then iterates secondary id_list, then calls the
// housekeeping pass sub_140E988A0 at the tail.
//
// Multiple AV vectors inside the function body (Agent D §3.4) when
// entries-base or id_list-base is poisoned. Guarding at the entry
// short-circuits ALL of them.
//
// Detour pseudo-C:
//   if (g_disable) return orig(ctrl);
//   fires++
//   if (entries_base poisoned || id_list_base poisoned) → skip
//   if (ctrl == ghost.controller_ptr) → skip
//   return orig(ctrl);
//
// Skip-side return value: 0 (the function returns __int64 but per
// decomp the only place the caller reads it is implicit, and the call
// site at sub_140E918C0's own caller doesn't branch on the result).
// ============================================================================
std::int64_t __fastcall detour_process_tick(std::int64_t ctrl) noexcept
{
    g_c_process_tick.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_process_tick.load(std::memory_order_relaxed)) {
        return g_orig_process_tick ? g_orig_process_tick(ctrl) : 0;
    }

    __try {
        if (!ctrl) return 0;

        // Build 60.1 fix #1: poison check on both bases, catching low
        // sub-page (< 0x10000) AND kernel-space / -1 (>= 0x8000...).
        // The Build 60 check `< 0x10000` MISSED `-1` because -1 as
        // unsigned is MAX_U64 > 0x10000. Live AV #7 at 0xE98860 in
        // Build 60 was entries_base=-1; this expanded check covers it.
        //
        // Build 62.10 — also catch high-canonical (> 3.3 TB) garbage that
        // the 0x8000_..._..._ kernel threshold misses (Build 62.9 live
        // showed 0x4F2_xxx_xxxx ≈ 5.4 TB AV at 0xE92505 escape).
        constexpr std::uint64_t MIN_USER_HEAP_ADDR = 0x10000ULL;
        constexpr std::uint64_t MAX_HEAP_ADDR      = 0x300000000000ULL;
        constexpr std::uint64_t MIN_KERNEL_ADDR    = 0x8000000000000000ULL;
        const std::uintptr_t ctrl_u = static_cast<std::uintptr_t>(ctrl);
        const std::uint64_t eb = safe_read_u64(
            ctrl_u + fw::offsets::COMBATCTRL_ENTRIES_BASE_OFF);
        const std::uint64_t ib = safe_read_u64(
            ctrl_u + fw::offsets::COMBATCTRL_ID_LIST_BASE_OFF);
        auto bad_addr = [](std::uint64_t a) {
            return (a < MIN_USER_HEAP_ADDR)
                || (a >= MAX_HEAP_ADDR && a < MIN_KERNEL_ADDR)
                || (a >= MIN_KERNEL_ADDR);
        };
        const bool poison = bad_addr(eb) || bad_addr(ib);

        // Ghost-controller check.
        const std::uintptr_t ghost_ctrl = ghost_combat_ctrl_ptr();
        const bool is_ghost = (ghost_ctrl != 0 && ctrl_u == ghost_ctrl);

        if (poison || is_ghost) {
            const auto n = g_c_process_tick.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_process_tick.actions.fetch_add(1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/process_tick] SKIP #%llu ctrl=0x%llX "
                       "(poison=%d ghost_ctrl_match=%d entries_base=0x%llX "
                       "id_list_base=0x%llX) — sub-page null-deriv caught",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl),
                       poison ? 1 : 0,
                       is_ghost ? 1 : 0,
                       static_cast<unsigned long long>(eb),
                       static_cast<unsigned long long>(ib));
            }
            return 0;
        }
        return g_orig_process_tick ? g_orig_process_tick(ctrl) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_process_tick.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// ============================================================================
// HOOK 3 — sub_140E988A0 CombatController housekeeping skip.
//
// Body 0x862 bytes (decay/cull pass over entries[] + secondary id_list).
// Sole caller sub_140E918C0:1784. With Hook 2 in place, this is usually
// preempted (Hook 2 returns before reaching the tail call). But if Hook 2
// passes through (e.g. ctrl valid + non-ghost) and the body itself does
// something that hits a poisoned secondary list mid-iteration, Hook 3
// provides defense-in-depth.
//
// Skip predicate: same as Hook 2 (poison + ghost-ctrl).
// ============================================================================
void __fastcall detour_housekeeping(std::int64_t ctrl) noexcept
{
    g_c_housekeeping.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_housekeeping.load(std::memory_order_relaxed)) {
        if (g_orig_housekeeping) g_orig_housekeeping(ctrl);
        return;
    }

    __try {
        if (!ctrl) return;

        // Build 60.1 fix #1 + Build 62.10 tighten — sub-page, high-canonical
        // (> 3.3 TB), kernel-space, and -1 all poison patterns.
        // Build 62.12 — also count > 4096 (garbage size).
        constexpr std::uint64_t MIN_USER_HEAP_ADDR = 0x10000ULL;
        constexpr std::uint64_t MAX_HEAP_ADDR      = 0x300000000000ULL;
        constexpr std::uint64_t MIN_KERNEL_ADDR    = 0x8000000000000000ULL;
        constexpr std::uint32_t MAX_PLAUSIBLE_COUNT = 4096;
        const std::uintptr_t ctrl_u = static_cast<std::uintptr_t>(ctrl);
        const std::uint64_t eb = safe_read_u64(
            ctrl_u + fw::offsets::COMBATCTRL_ENTRIES_BASE_OFF);
        const std::uint64_t ib = safe_read_u64(
            ctrl_u + fw::offsets::COMBATCTRL_ID_LIST_BASE_OFF);
        const std::uint32_t ec = static_cast<std::uint32_t>(safe_read_u64(
            ctrl_u + fw::offsets::COMBATCTRL_ENTRIES_COUNT_OFF) & 0xFFFFFFFFu);
        const std::uint32_t ic = static_cast<std::uint32_t>(safe_read_u64(
            ctrl_u + fw::offsets::COMBATCTRL_ID_LIST_COUNT_OFF) & 0xFFFFFFFFu);
        auto bad_addr = [](std::uint64_t a) {
            return (a < MIN_USER_HEAP_ADDR)
                || (a >= MAX_HEAP_ADDR && a < MIN_KERNEL_ADDR)
                || (a >= MIN_KERNEL_ADDR);
        };
        const bool poison = bad_addr(eb) || bad_addr(ib)
                          || ec > MAX_PLAUSIBLE_COUNT
                          || ic > MAX_PLAUSIBLE_COUNT;

        const std::uintptr_t ghost_ctrl = ghost_combat_ctrl_ptr();
        const bool is_ghost = (ghost_ctrl != 0 && ctrl_u == ghost_ctrl);

        if (poison || is_ghost) {
            const auto n = g_c_housekeeping.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_housekeeping.actions.fetch_add(1, std::memory_order_relaxed);
            if (should_log(n, 8, 1000)) {
                FW_LOG("[wg/housekeeping] SKIP #%llu ctrl=0x%llX "
                       "(poison=%d ghost=%d eb=0x%llX ib=0x%llX)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl),
                       poison ? 1 : 0,
                       is_ghost ? 1 : 0,
                       static_cast<unsigned long long>(eb),
                       static_cast<unsigned long long>(ib));
            }
            return;
        }
        if (g_orig_housekeeping) g_orig_housekeeping(ctrl);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_housekeeping.seh.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// HOOK 4 — sub_140E91D70 AddKnownTarget early-bail.
//
// Allocates new 208-byte entry. May AV inside BSTArray-Grow if
// entries_base was poisoned. Guard: same poison check as Hook 2. If
// entries-base is -1/0, return 0 (no entry added). Engine continues
// gracefully (the caller's wrapper sub_14087A320 handles "add failed").
//
// Important: this hook DOES NOT bail when ctrl == ghost.controller —
// because if engine ever calls AddKnownTarget on the ghost's own
// controller (which would be a synthetic scenario), the orig may
// actually handle it gracefully. The poison check is sufficient.
// ============================================================================
std::int64_t __fastcall detour_add_known_target(std::int64_t ctrl,
                                                 void* actor) noexcept
{
    g_c_add_target.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_add_target.load(std::memory_order_relaxed)) {
        return g_orig_add_known_target
            ? g_orig_add_known_target(ctrl, actor)
            : 0;
    }

    __try {
        if (!ctrl) return 0;

        // Build 60: use NARROW check (-1 only) to NOT break synth's
        // AddKnownTarget growth path. Hook 1/2/3 use the broader sub-page
        // check; this hook must allow entries_base==0 (legitimate fresh
        // ctrl about to grow to a real buffer).
        if (ctrl_entries_base_is_neg1_only(static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_add_target.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_add_target.actions.fetch_add(1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/add_target] POISON-BAIL #%llu ctrl=0x%llX "
                       "actor=%p — refusing AddKnownTarget on entries-base "
                       "== -1 (true sentinel; 0 and other sub-page values "
                       "ALLOWED to let synth growth path work)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl), actor);
            }
            return 0;
        }
        return g_orig_add_known_target
            ? g_orig_add_known_target(ctrl, actor)
            : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_add_target.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// ============================================================================
// HOOK 5 — sub_140C06AC0 form-table rehydrator skip-on-ghost.
//
// Known crash class from Builds 25/26/29.2 (documented in
// crash_death_vtable_cascade dossier). The function iterates
// qword_1430DBF78[2506] global form-table buckets and dispatches vt[51]
// (= sub_140525060 TESObjectREFR identity stub) on each entry. On ghost
// entries, the vt slot is sentinel / heap garbage → AV.
//
// Sole caller: sub_140C00590 → sub_140BF9460 (LoadChanges scheduler).
// Triggered at cell-rehydrate after LoadGame and at certain world-state
// transitions.
//
// Guard strategy: detour entry; check if ghost is registered AND has
// a fid in [0xFF000000, 0xFFFFFFFF) range. If so, before calling orig,
// we DO NOT scrub the global table (Option C / Build 56 proved that's
// SEH-prone) — instead we set a thread-local "skip ghost in next bucket
// iteration" flag that... wait no, can't do that without instrumenting
// the loop.
//
// Simpler: just SKIP THE ENTIRE FUNCTION when called. The function is
// the rehydrator after LoadChanges; ghost is a TEMPORARY runtime form
// that doesn't need rehydration. If we skip, REAL forms also don't get
// rehydrated → potential gameplay regression.
//
// COMPROMISE: skip ONLY when this is the FIRST call after spawn + before
// a player explicit reload. Heuristic: track a "we've completed our
// initial spawn pass" gate. After the first 3 successful calls (= cell-
// load post-LoadGame), enable the orig pass.
//
// Decision (simpler and tested): skip ALL invocations while ghost is
// active. The rehydrator's real job is "validate form refs after a save
// load"; we're a long-running session where saves happen rarely. Real
// forms are already valid in memory. Skipping causes at worst stale
// post-LoadGame refs which the next NPC AI tick will detect and resolve
// via lookup_by_form_id.
//
// If this is too aggressive, we can later add a more nuanced predicate.
// ============================================================================
std::int64_t __fastcall detour_form_rehydrator(std::int64_t arg) noexcept
{
    g_c_form_rehydrator.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_form_rehydrator.load(std::memory_order_relaxed)) {
        return g_orig_form_rehydrator ? g_orig_form_rehydrator(arg) : 0;
    }

    __try {
        const std::uint32_t gfid = ghost_fid();
        const bool ghost_active = (gfid != 0);

        if (ghost_active) {
            const auto n = g_c_form_rehydrator.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_form_rehydrator.actions.fetch_add(1, std::memory_order_relaxed);
            if (should_log(n, 4, 100)) {
                FW_LOG("[wg/form_rehydrator] SKIP-ALL #%llu arg=0x%llX "
                       "(ghost active fid=0x%08X — skipping rehydrator to "
                       "avoid vt[51] AV on ghost bucket entry)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(arg), gfid);
            }
            return 0;
        }
        return g_orig_form_rehydrator ? g_orig_form_rehydrator(arg) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_form_rehydrator.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// ============================================================================
// HOOK 6 — sub_140C80D70 death broadcast walker.
//
// Iterates ProcessLists.actors, dispatches sub_140D0B740(actor.AIProcess,
// actor, dyingActor) per actor. Called from Actor::Kill (sub_140C58150)
// when an actor dies.
//
// Crash risk: if dyingActor is the ghost (we register it as a target and
// when peer-B "dies" on A, the engine fires death events for B's local
// representation), OR if an entry in ProcessLists.actors is the ghost,
// the sub_140D0B740 dispatch will deref ghost.AIProcess fields → AV.
//
// Guard: detour entry; if dyingActor == ghost_ptr, skip the WHOLE
// broadcast (ghost doesn't have death subscribers). If dyingActor != ghost
// but some entry might be ghost, we'd need to wrap each dispatch — too
// invasive. For now, skip-when-dying-is-ghost is the cheap correct path.
//
// If real raiders die naturally and need broadcast, the per-entry dispatch
// inside the loop will visit ghost too — but we've globally guarded vt[N]
// downstream functions (Hooks 1-4 cover the controller probes the
// broadcast triggers). So the broadcast itself is safe to let through.
//
// In summary: this hook is a NARROW guard for the dying-is-ghost case.
// Most other cases pass through.
// ============================================================================
void __fastcall detour_death_broadcast(std::int64_t dying_actor) noexcept
{
    g_c_death_broadcast.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_death_broadcast.load(std::memory_order_relaxed)) {
        if (g_orig_death_broadcast) g_orig_death_broadcast(dying_actor);
        return;
    }

    __try {
        void* g = ghost_ptr();
        const bool ghost_is_dying =
            (g != nullptr &&
             reinterpret_cast<void*>(dying_actor) == g);

        if (ghost_is_dying) {
            const auto n = g_c_death_broadcast.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_death_broadcast.actions.fetch_add(1, std::memory_order_relaxed);
            FW_LOG("[wg/death_broadcast] SKIP #%llu dying_actor=%p == ghost "
                   "— broadcast suppressed (ghost has no death subscribers)",
                   static_cast<unsigned long long>(n),
                   reinterpret_cast<void*>(dying_actor));
            return;
        }
        if (g_orig_death_broadcast) g_orig_death_broadcast(dying_actor);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_death_broadcast.seh.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// HOOK 7 — sub_140DA28A0 LOS / sight-cone walker.
//
// Per-frame walker that iterates ProcessLists actors and dispatches
// vt[140], vt[148], vt[192] per entry. Reads deep into combat extension
// at actor+0x300. Body 0x11F8 bytes (4600 lines decomp). Identified by
// Agent E as next-crash candidate if ghost has empty combat extension.
//
// Crash mechanism (predicted): walker visits ghost in ProcessLists,
// reads ghost.+0x300 (AIProcess), reads AIProcess.+0xN (combat extension
// sub-object), which is NULL or sentinel for our memcpy'd / proxy ghost.
// Dispatch on null sub-object → AV.
//
// Guard: not enough static analysis to install per-entry filter inside
// the big function body. Best we can do is detour the entry and: (a)
// detect if ghost is in ProcessLists right now, (b) if so, log and skip
// the whole function. This is aggressive — we lose ALL LOS computation
// for that frame for ALL actors. Acceptable: LOS recomputes 30 Hz, one
// missed frame = barely visible jitter.
//
// Alternative: if Agent E's prediction is wrong and this never AVs
// without our patch, the guard is a no-op and we just see counters
// indicate "skip whenever ghost is registered".
//
// Note: the signature is somewhat speculative (4 args, all int64) per
// the agent dossier. If MinHook trampolines mismatch, we'll see crashes
// in the install path → kill switch + investigate.
// ============================================================================
std::int64_t __fastcall detour_los_sight_cone(std::int64_t a1,
                                                std::int64_t a2,
                                                std::int64_t a3,
                                                std::int64_t a4) noexcept
{
    g_c_los_sight_cone.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_los_sight_cone.load(std::memory_order_relaxed)) {
        return g_orig_los_sight_cone
            ? g_orig_los_sight_cone(a1, a2, a3, a4)
            : 0;
    }

    __try {
        const std::uint32_t gfid = ghost_fid();
        if (gfid != 0) {
            const auto n = g_c_los_sight_cone.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_los_sight_cone.actions.fetch_add(1, std::memory_order_relaxed);
            if (should_log(n, 4, 5000)) {
                FW_LOG("[wg/los] SKIP-ALL #%llu (ghost active fid=0x%08X "
                       "— skipping LOS sight-cone to avoid potential vt[192]/"
                       "vt[148]/vt[140] AV on ghost entry; LOS recomputes "
                       "next frame on real actors)",
                       static_cast<unsigned long long>(n), gfid);
            }
            return 0;
        }
        return g_orig_los_sight_cone
            ? g_orig_los_sight_cone(a1, a2, a3, a4)
            : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_los_sight_cone.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// ============================================================================
// HOOK 8 — sub_141658FE0 BSSimpleMutex::lock null-deriv guard.
//
// AV #1 in Build 58 live test (2026-05-24 04:18:05.714):
//   rip=0x1658FEF (= entry + 0xF, inside the lock primitive's prologue)
//   fault=READ addr=0x40 rcx=0x40 r8=raider 0x210C3561660
//   stack: ...0xD00D0B (= inside sub_140D00D50 EnterCombat alt-path)...
//
// PATTERN: engine code does
//   mov rcx, [actor_subobj + 0x40]   ; load CombatController* or similar
//   ;   if actor_subobj == NULL → rcx = NULL
//   lea rcx, [rcx + N]               ; or, alternatively, lea on null derives rcx = N
//   call sub_141658FE0               ; lock(rcx)
// → rcx is a sub-page value (0x40 in the observed case), the lock function
//   dereferences it inside, AVs.
//
// FIX: pre-check rcx. Heap-allocated locks ALWAYS live above 0x10000 (the
// first user-mode page boundary; sub-page addresses are unmapped). If rcx
// is below this threshold, it's structurally a derived-from-null pointer,
// not a real lock. Bail without acquiring (no real lock to release; engine
// behaves as if the lock was uncontested).
//
// SAFETY: bailing the lock primitive sounds scary but is safe here because:
//   - The fault would have happened anyway → engine was about to crash.
//   - Skipping the lock means we don't enter a critical section; the
//     enclosing operation will either short-circuit (if it checks the
//     resource it was about to lock) or fault elsewhere — but the elsewhere
//     fault will also be a structural null deref that we've forced visible.
//   - Real lock targets ALWAYS have heap addresses; we never block them.
//
// COST: 1 atomic-inc + 1 compare per acquire. The lock primitive is hot
// (100k+ calls/sec) → ~5ms/sec overhead = ~0.5% CPU. Acceptable.
// ============================================================================
void __fastcall detour_lock_primitive(void* lock) noexcept
{
    g_c_lock_primitive.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_lock_primitive.load(std::memory_order_relaxed)) {
        if (g_orig_lock_primitive) g_orig_lock_primitive(lock);
        return;
    }

    const auto addr = reinterpret_cast<std::uintptr_t>(lock);
    // Threshold = 64 KiB = first user-mode page on x64. Anything below
    // this is structurally a null+offset derivation. Heap pointers are
    // ALWAYS far above this.
    constexpr std::uintptr_t MIN_USER_HEAP_ADDR = 0x10000;
    if (addr < MIN_USER_HEAP_ADDR) {
        const auto n = g_c_lock_primitive.ghost_hits.fetch_add(
            1, std::memory_order_relaxed);
        g_c_lock_primitive.actions.fetch_add(1, std::memory_order_relaxed);
        if (should_log(n, 8, 5000)) {
            FW_LOG("[wg/lock] NULL-DERIV-BAIL #%llu lock=0x%llX < 0x10000 "
                   "(= derived from null+offset; the lock primitive would have "
                   "AV'd at addr=0x40 inside its body; bailing without "
                   "acquiring)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(addr));
        }
        return;
    }

    __try {
        if (g_orig_lock_primitive) g_orig_lock_primitive(lock);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_lock_primitive.seh.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// Install helpers — one per hook, called by master install_*().
//
// Each returns true on success. Pattern:
//   bool install_<name>(module_base) {
//     ea = module_base + offsets::<RVA>;
//     ok = ::fw::hooks::install(ea, &detour, &g_orig);
//     log success/fail
//     return ok;
//   }
// ============================================================================

bool install_hook_find_entry(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_FIND_ENTRY_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_find_entry),
        reinterpret_cast<void**>(&g_orig_find_entry));
    if (ok) {
        FW_LOG("[wg/install] HOOK 1 sub_140E98820 FindEntryByFormID installed "
               "at 0x%llX (RVA 0x%lX) — entries-base poison guard ACTIVE; "
               "this kills the 0xE98860 AV class for all 27 callers.",
               static_cast<unsigned long long>(ea),
               static_cast<unsigned long>(
                   fw::offsets::COMBATCTRL_FIND_ENTRY_RVA));
    } else {
        FW_ERR("[wg/install] HOOK 1 FindEntryByFormID FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_process_tick(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_PROCESS_TICK_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_process_tick),
        reinterpret_cast<void**>(&g_orig_process_tick));
    if (ok) {
        FW_LOG("[wg/install] HOOK 2 sub_140E918C0 ProcessTick installed at "
               "0x%llX — skip when ctrl poisoned or ghost-controller.",
               static_cast<unsigned long long>(ea));
    } else {
        FW_ERR("[wg/install] HOOK 2 ProcessTick FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_housekeeping(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_HOUSEKEEPING_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_housekeeping),
        reinterpret_cast<void**>(&g_orig_housekeeping));
    if (ok) {
        FW_LOG("[wg/install] HOOK 3 sub_140E988A0 Housekeeping installed at "
               "0x%llX — defense-in-depth skip when ctrl poisoned/ghost.",
               static_cast<unsigned long long>(ea));
    } else {
        FW_ERR("[wg/install] HOOK 3 Housekeeping FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_add_target(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_ADD_TARGET_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_add_known_target),
        reinterpret_cast<void**>(&g_orig_add_known_target));
    if (ok) {
        FW_LOG("[wg/install] HOOK 4 sub_140E91D70 AddKnownTarget installed at "
               "0x%llX — early-bail on poisoned entries-base.",
               static_cast<unsigned long long>(ea));
    } else {
        FW_ERR("[wg/install] HOOK 4 AddKnownTarget FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_form_rehydrator(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::FORM_TABLE_REHYDRATOR_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_form_rehydrator),
        reinterpret_cast<void**>(&g_orig_form_rehydrator));
    if (ok) {
        FW_LOG("[wg/install] HOOK 5 sub_140C06AC0 FormRehydrator installed at "
               "0x%llX — skip-all-when-ghost-active to avoid vt[51] AV.",
               static_cast<unsigned long long>(ea));
    } else {
        FW_ERR("[wg/install] HOOK 5 FormRehydrator FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_death_broadcast(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::DEATH_BROADCAST_WALKER_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_death_broadcast),
        reinterpret_cast<void**>(&g_orig_death_broadcast));
    if (ok) {
        FW_LOG("[wg/install] HOOK 6 sub_140C80D70 DeathBroadcast installed at "
               "0x%llX — skip when dying_actor == ghost.",
               static_cast<unsigned long long>(ea));
    } else {
        FW_ERR("[wg/install] HOOK 6 DeathBroadcast FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_los_sight_cone(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::LOS_SIGHT_CONE_WALKER_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_los_sight_cone),
        reinterpret_cast<void**>(&g_orig_los_sight_cone));
    if (ok) {
        FW_LOG("[wg/install] HOOK 7 sub_140DA28A0 LOSSightCone installed at "
               "0x%llX — DISABLED by default (g_disable_los_sight_cone=true) "
               "as Build 58 fix; install only so kill-switch can be flipped "
               "if a future crash actually surfaces here.",
               static_cast<unsigned long long>(ea));
    } else {
        FW_ERR("[wg/install] HOOK 7 LOSSightCone FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

// ============================================================================
// Build 62.1 (2026-05-24) — Hooks 9 + 10 on the parallel CC walker family
// (sub_140E92260 RemoveByFid, sub_140E924A0 GroupGate).
//
// Per re/av_E92xxx_root_cause/AGENT_analysis.md: these are peer functions
// of sub_140E98820 (Hook 1) — same walker pattern, called by DIFFERENT
// engine paths. Hook 1's `find_entry` guard doesn't reach them because
// they're independent implementations.
//
// Build 62 live AV cascade @ 19:19:45 verified BOTH classes:
//   AV @ 0xE92299 — entries_base = 0x1 (sub_140E92260 RemoveByFid),
//     caller chain: TESObjectREFR::~ → sub_140DAE160 → sub_14087A470 →
//     sub_140E92260.
//   AV @ 0xE92505 — id_list_base = 0xA0000046B / 0xE000004A0 pool-reuse
//     garbage (sub_140E924A0 GroupGate), sole caller sub_140E91D70
//     AddKnownTarget at line 1874.
//
// Hook 6 reuses ctrl_entries_base_is_poisoned (sub-page + kernel check).
// Hook 7 uses a STRICTER poison check that also catches the low-canonical
// pool-reuse pattern (hi != 0 && hi < 0x100 && lo < 0x10000) — that's
// what 0xA0000046B looks like and the default check misses it.
// ============================================================================

// Stricter helper for id_list_base. Catches:
//   - sub-page (< 0x100000 = 1 MiB; tighter than the default 0x10000 to
//     better reject "freed slot first DWORD is small count" patterns)
//   - kernel-space (>= 0x8000_0000_0000_0000, includes -1 in unsigned)
//   - pool-reuse: (hi != 0 && hi < 0x100 && lo < 0x10000) — the
//     observed 0xA0000046B / 0xE000004A0 pattern
inline bool ctrl_id_list_base_is_poisoned_strict(std::uintptr_t ctrl) noexcept {
    if (!ctrl) return true;
    bool poisoned = false;
    __try {
        // Build 62.3 — count-aware check. Same rationale as the entries
        // version: vanilla walkers check id_list count before reading
        // base. Fresh CC has count=0 and base=0 (legitimate empty).
        const std::uint32_t count = *reinterpret_cast<std::uint32_t*>(
            ctrl + fw::offsets::COMBATCTRL_ID_LIST_COUNT_OFF);
        if (count == 0) {
            return false;  // empty id_list — safe
        }
        // Build 62.12 — count sanity. Real id_list never > ~50 entries.
        if (count > 4096) {
            return true;  // poison
        }
        const std::uint64_t v = *reinterpret_cast<std::uint64_t*>(
            ctrl + fw::offsets::COMBATCTRL_ID_LIST_BASE_OFF);
        constexpr std::uint64_t MIN_HEAP   = 0x100000ULL;       // 1 MiB
        constexpr std::uint64_t MAX_HEAP   = 0x300000000000ULL; // ~3.3 TB
        constexpr std::uint64_t MIN_KERNEL = 0x8000000000000000ULL;
        const std::uint32_t hi = static_cast<std::uint32_t>(v >> 32);
        const std::uint32_t lo = static_cast<std::uint32_t>(v);
        const bool reuse_pattern =
            (hi != 0 && hi < 0x100 && lo < 0x10000);
        // Build 62.10 — also reject high-canonical (> 3.3 TB). Build 62.9
        // live test crashed at 0xE92505 reading [0x4F2_0000_018A + offset]
        // — high-canonical 5.4 TB garbage that the kernel threshold missed.
        poisoned = (v < MIN_HEAP)
                || (v >= MAX_HEAP && v < MIN_KERNEL)
                || (v >= MIN_KERNEL)
                || reuse_pattern;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        poisoned = true;
    }
    return poisoned;
}

// HOOK 9 — sub_140E92260 RemoveCombatTargetByFormID guard.
std::int64_t __fastcall detour_remove_by_fid(std::int64_t ctrl,
                                              std::int64_t fid_ref) noexcept
{
    g_c_remove_by_fid.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_remove_by_fid.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_remove_by_fid.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/remove_by_fid] POISON-BAIL #%llu ctrl=0x%llX "
                       "— entries_base poisoned; skipping to avoid AV "
                       "at 0xE92299 (parallel to Hook 1 sub_140E98820)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;  // vanilla "not found / nothing removed" path
        }
        return g_orig_remove_by_fid ? g_orig_remove_by_fid(ctrl, fid_ref) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_remove_by_fid.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// HOOK 10 — sub_140E924A0 GroupMembershipGate guard.
std::int64_t __fastcall detour_group_gate(std::int64_t ctrl,
                                           void* target_actor) noexcept
{
    g_c_group_gate.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_id_list_base_is_poisoned_strict(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_group_gate.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_group_gate.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/group_gate] POISON-BAIL #%llu ctrl=0x%llX "
                       "actor=%p — id_list_base poisoned (low-canonical "
                       "or sub-page); skipping to avoid AV at 0xE92505",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl), target_actor);
            }
            // Return 0 = "not in group / gate fails". Caller
            // sub_140E91D70 (AddKnownTarget) will skip the body —
            // semantically: "this target is not reachable via the
            // observer's combat group, so don't add."
            return 0;
        }
        return g_orig_group_gate ? g_orig_group_gate(ctrl, target_actor) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_group_gate.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

bool install_hook_remove_by_fid(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_REMOVE_BY_FID_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_remove_by_fid),
        reinterpret_cast<void**>(&g_orig_remove_by_fid));
    if (ok) {
        FW_LOG("[wg/install] HOOK 9 sub_140E92260 RemoveByFormID installed "
               "at 0x%llX (RVA 0x%lX) — kills AV class at 0xE92299 from "
               "TESObjectREFR dtor sweep (Build 62.1)",
               static_cast<unsigned long long>(ea),
               static_cast<unsigned long>(
                   fw::offsets::COMBATCTRL_REMOVE_BY_FID_RVA));
    } else {
        FW_ERR("[wg/install] HOOK 9 RemoveByFormID FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

bool install_hook_group_gate(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_GROUP_GATE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_group_gate),
        reinterpret_cast<void**>(&g_orig_group_gate));
    if (ok) {
        FW_LOG("[wg/install] HOOK 10 sub_140E924A0 GroupGate installed at "
               "0x%llX (RVA 0x%lX) — kills AV class at 0xE92505 from "
               "AddKnownTarget pool-reuse garbage (Build 62.1)",
               static_cast<unsigned long long>(ea),
               static_cast<unsigned long>(
                   fw::offsets::COMBATCTRL_GROUP_GATE_RVA));
    } else {
        FW_ERR("[wg/install] HOOK 10 GroupGate FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

// ============================================================================
// Build 62.2 (2026-05-24) — Hooks 11..15 on the CC peer walker family.
//
// Per re/av_E92xxx_root_cause/AGENT_peer_family.md the family contains
// 12 unguarded peer walkers (parallel implementations of sub_140E98820,
// not wrappers). Hook 11 covers the current crash (sub_140E96490);
// Hooks 12-15 cover the next 4 high-priority members of the family
// (EnsureKnownTarget path + allies-health Tier-1).
//
// All use the same poison check primitive — ctrl_entries_base_is_poisoned
// for CC+0x08 readers, ctrl_id_list_base_is_poisoned_strict for CC+0x20
// readers. Return value mirrors the natural "not found / nothing to do"
// path of each function.
// ============================================================================

// HOOK 11 — sub_140E96490 FindFirstActorInRange(entries).
// Caller chain: sub_140D2C3E0 perception decision tree + sub_140F5CB40 AI
// state behavior tree. Returns nullptr on empty/not-found vanilla path.
void* __fastcall detour_find_in_range(std::int64_t ctrl,
                                       std::int64_t origin_pos,
                                       float radius,
                                       char filter_byte) noexcept
{
    g_c_find_in_range.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return nullptr;
        if (ctrl_entries_base_is_poisoned(static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_find_in_range.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_find_in_range.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/find_in_range] POISON-BAIL #%llu ctrl=0x%llX "
                       "— entries_base poisoned; returning nullptr (Build 62.2)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return nullptr;
        }
        return g_orig_find_in_range
            ? g_orig_find_in_range(ctrl, origin_pos, radius, filter_byte)
            : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_find_in_range.seh.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
}

// HOOK 12 — sub_140E92E50 "is target in known_targets by Actor pointer".
// Caller: sub_140E929C0 EnsureKnownTarget at line 2520. Returns 0 on
// not-found vanilla path (caller treats 0 as "not present, need to add").
std::int64_t __fastcall detour_known_by_actor(std::int64_t ctrl,
                                                void* actor) noexcept
{
    g_c_known_by_actor.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_known_by_actor.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_known_by_actor.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/known_by_actor] POISON-BAIL #%llu ctrl=0x%llX "
                       "— entries_base poisoned (Build 62.2)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_known_by_actor
            ? g_orig_known_by_actor(ctrl, actor) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_known_by_actor.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// HOOK 13 — sub_140E929C0 EnsureKnownTarget (main entry).
// Heavily exercised on every perception trigger. Returns 0 = "could not
// ensure / failed". Caller (broadcast AddTarget) handles 0 gracefully.
std::int64_t __fastcall detour_ensure_known(std::int64_t ctrl,
                                              void* actor) noexcept
{
    g_c_ensure_known.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        // EnsureKnownTarget reads BOTH CC+0x08 and CC+0x20 internally.
        // Bail if either is poisoned.
        const std::uintptr_t ctrl_u = static_cast<std::uintptr_t>(ctrl);
        const bool eb_bad = ctrl_entries_base_is_poisoned(ctrl_u);
        const bool ib_bad = ctrl_id_list_base_is_poisoned_strict(ctrl_u);
        if (eb_bad || ib_bad) {
            const auto n = g_c_ensure_known.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_ensure_known.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/ensure_known] POISON-BAIL #%llu ctrl=0x%llX "
                       "actor=%p (eb_bad=%d ib_bad=%d, Build 62.2)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl), actor,
                       eb_bad ? 1 : 0, ib_bad ? 1 : 0);
            }
            return 0;
        }
        return g_orig_ensure_known
            ? g_orig_ensure_known(ctrl, actor) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_ensure_known.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// HOOK 14 — sub_140E92B90 UpdatePositionForTarget. Called by group merger
// + AddTarget broadcast path. Touches both CC+0x08 and CC+0x20.
std::int64_t __fastcall detour_update_pos(std::int64_t ctrl,
                                           void* actor,
                                           std::int64_t pos) noexcept
{
    g_c_update_pos.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        const std::uintptr_t ctrl_u = static_cast<std::uintptr_t>(ctrl);
        const bool eb_bad = ctrl_entries_base_is_poisoned(ctrl_u);
        const bool ib_bad = ctrl_id_list_base_is_poisoned_strict(ctrl_u);
        if (eb_bad || ib_bad) {
            const auto n = g_c_update_pos.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_update_pos.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/update_pos] POISON-BAIL #%llu ctrl=0x%llX "
                       "(eb_bad=%d ib_bad=%d, Build 62.2)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl),
                       eb_bad ? 1 : 0, ib_bad ? 1 : 0);
            }
            return 0;
        }
        return g_orig_update_pos
            ? g_orig_update_pos(ctrl, actor, pos) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_update_pos.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// HOOK 15 — sub_140E97D30 ally-health aggregate. Reads CC+0x20 allies.
// Tier-1 in AGENT_C dossier but hook was never installed.
std::int64_t __fastcall detour_ally_health(std::int64_t ctrl) noexcept
{
    g_c_ally_health.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_id_list_base_is_poisoned_strict(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_ally_health.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_ally_health.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/ally_health] POISON-BAIL #%llu ctrl=0x%llX "
                       "— id_list_base poisoned (Build 62.2)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_ally_health ? g_orig_ally_health(ctrl) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_ally_health.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// HOOK 16 — sub_140E75F30 BSTHashMap merge walker (Build 62.5).
//
// Decomp: walks an array (a1+0x04 = count u32, a1+0x20 = base u64, 24-byte
// stride) and merges each entry into a hash table (*a2). The walker reads
// `*(QWORD*)(entry+0x10)` to test entry validity; if base itself is a
// freed/reused pointer the cmovz-led scan crashes at +0x3A.
//
// Crash signature Build 62.4 (2026-05-24 21:23:52):
//   rip = 0x140E75F6A  fault = READ  addr = 0xEA1173B7E54 (unmapped)
//   rcx = rdx = 0x1D42D7174F8  (the same controller passed twice)
//   stack [0..7] includes 0x1D42D7174F8 + raider controllers from prior
//   enter_combat #N SUCCESS — confirming this fires DURING combat tier
//   tick after ghost engagement.
//
// The structure at a1 is NOT a CombatController (different field layout)
// — it's some upstream sub-structure that gets corrupted when one of the
// per-actor combat sub-objects is torn down mid-iteration of the upstream
// orchestrator loop (sub_140E93370 / sub_140E93AB0).
//
// Strategy: SEH cage around orig. The function returns VOID; if the orig
// AVs, swallow and return — the merge for this tick is skipped, engine
// retries naturally on the next combat tick (the hash table will just
// miss the entries from this batch, which the upstream loop is robust to
// since this whole walker is called inside a per-controller loop).
//
// Belt-and-suspenders: also check `[a1+0x20] >= 0x800000000000` (above
// user-canonical 47-bit limit, definitely garbage). My existing poison
// helpers don't catch this because they use the kernel boundary
// 0x8000000000000000 instead of the user-canonical limit.
void __fastcall detour_hashmap_merge(std::int64_t a1, void* a2) noexcept
{
    g_c_hashmap_merge.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!a1 || !a2 || !g_orig_hashmap_merge) {
            return;
        }
        // Belt-and-suspenders pre-check: read base + count and validate.
        std::uint32_t count = 0;
        std::uint64_t base = 0;
        __try {
            count = *reinterpret_cast<std::uint32_t*>(a1 + 0x04);
            base  = *reinterpret_cast<std::uint64_t*>(a1 + 0x20);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const auto n = g_c_hashmap_merge.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_hashmap_merge.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/hashmap_merge] SEH-on-input-read #%llu a1=0x%llX "
                       "— skipping merge (Build 62.5)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1));
            }
            return;
        }
        // count==0 is legitimate empty — no merge needed, but harmless
        // to call orig (vanilla loop is no-op). Skip to avoid overhead.
        if (count == 0) {
            return;
        }
        // Build 62.12 — count sanity (Build 62.11 live test showed Hook 16
        // AV @ 0xE75F6A with fault addr ≈ 19.5 TB = base + count*24 where
        // count was garbage huge. Real merge structs hold tens of entries,
        // not thousands).
        if (count > 4096) {
            const auto n = g_c_hashmap_merge.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_hashmap_merge.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/hashmap_merge] COUNT-BAIL #%llu a1=0x%llX "
                       "count=%u (Build 62.12 — garbage size, skipping merge)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1), count);
            }
            return;
        }
        // base validation:
        //   - sub-page              < 0x10000              → null/garbage
        //   - above plausible heap  >= 0x300_0000_0000      → ~50 TB; FO4
        //     heap allocations live in 0x1xx_xxxx_xxxx to 0x2xx_xxxx_xxxx
        //     range. Anything above is unmapped. Build 62.7 live test
        //     showed fault addr 0x106AC7EB9114 (=0x106_xxxx_xxxx ≈ 1.1 TB,
        //     past plausible FO4 heap top) escaped the previous 0x800_..._..._
        //     threshold. The threshold here is conservative — wider than
        //     any real allocator would produce.
        //   - kernel half           >= 0x8000_0000_0000_0000 → kernel memory
        //   - pool-reuse pattern    hi != 0 && hi < 0x100 && lo < 0x10000
        constexpr std::uint64_t MIN_USER     = 0x10000ULL;
        constexpr std::uint64_t MAX_HEAP     = 0x300000000000ULL;
        constexpr std::uint64_t MIN_KERNEL   = 0x8000000000000000ULL;
        bool base_poison = (base < MIN_USER)
                        || (base >= MAX_HEAP && base < MIN_KERNEL)
                        || (base >= MIN_KERNEL);
        if (!base_poison) {
            const std::uint64_t lo = base & 0xFFFFFFFFull;
            const std::uint64_t hi = base >> 32;
            if (hi != 0 && hi < 0x100 && lo < 0x10000) {
                base_poison = true;
            }
        }
        if (base_poison) {
            const auto n = g_c_hashmap_merge.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_hashmap_merge.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/hashmap_merge] POISON-BAIL #%llu a1=0x%llX "
                       "count=%u base=0x%llX (Build 62.5)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1),
                       count,
                       static_cast<unsigned long long>(base));
            }
            return;
        }
        // Inputs look sane. Wrap orig in inner SEH to catch the AV that
        // might still happen if entries[i] is itself a dangling pointer
        // (the merge writes vt[2]/vt[5] on entry+0 which is a pointer
        // out of our reach to validate).
        __try {
            g_orig_hashmap_merge(a1, a2);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const auto n = g_c_hashmap_merge.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_hashmap_merge.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/hashmap_merge] SEH-on-orig #%llu a1=0x%llX "
                       "count=%u base=0x%llX — merge skipped (Build 62.5)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1),
                       count,
                       static_cast<unsigned long long>(base));
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_hashmap_merge.seh.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// Hooks 17-23 (Build 62.6) — stride-208 CC walkers, FindEntry+per-tick family.
//
// All read CC+0x08 base + CC+0x18 count with 208-byte stride. Identical
// poison vulnerability to Hook 1 (sub_140E98820). On poison detection,
// each returns the "vanilla nothing-to-do" value for its signature:
//   - Finders (E986C0, E98760): return 0 (= "not found")
//   - char-returning tick walkers (E9EA40, E9E760, E98480): return 0
//   - void-returning tick walkers (E9EC40, E9E870): early-return
//
// All wrapped in OUTER SEH cage in case a downstream walker we don't
// recognize trips an unexpected fault — swallow + return safe vanilla.
// ============================================================================

std::int64_t __fastcall detour_find_by_actor(std::int64_t ctrl,
                                              std::int64_t actor) noexcept
{
    g_c_find_by_actor.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_find_by_actor.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_find_by_actor.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/find_by_actor] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6 — kills crash @ 0xE98721)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_find_by_actor
            ? g_orig_find_by_actor(ctrl, actor) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_find_by_actor.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

std::int64_t __fastcall detour_find_by_fid(std::int64_t ctrl,
                                            std::uint32_t* fid_ptr) noexcept
{
    g_c_find_by_fid.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_find_by_fid.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_find_by_fid.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/find_by_fid] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_find_by_fid
            ? g_orig_find_by_fid(ctrl, fid_ptr) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_find_by_fid.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

void __fastcall detour_aggro_freshness(std::int64_t ctrl) noexcept
{
    g_c_aggro_freshness.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_aggro_freshness.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_aggro_freshness.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/aggro_freshness] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6 — per-tick walker E9EC40)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return;
        }
        if (g_orig_aggro_freshness) g_orig_aggro_freshness(ctrl);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_aggro_freshness.seh.fetch_add(1, std::memory_order_relaxed);
    }
}

void __fastcall detour_ally_validity_870(std::int64_t ctrl) noexcept
{
    g_c_ally_validity_870.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_ally_validity_870.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_ally_validity_870.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/ally_validity_870] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6 — per-tick walker E9E870)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return;
        }
        if (g_orig_ally_validity_870) g_orig_ally_validity_870(ctrl);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_ally_validity_870.seh.fetch_add(1, std::memory_order_relaxed);
    }
}

char __fastcall detour_ally_validity_A40(std::int64_t ctrl) noexcept
{
    g_c_ally_validity_A40.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_ally_validity_A40.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_ally_validity_A40.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/ally_validity_A40] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6 — per-tick walker E9EA40)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_ally_validity_A40
            ? g_orig_ally_validity_A40(ctrl) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_ally_validity_A40.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

char __fastcall detour_count_entries(std::int64_t ctrl) noexcept
{
    g_c_count_entries.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_count_entries.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_count_entries.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/count_entries] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6 — per-tick walker E9E760)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_count_entries
            ? g_orig_count_entries(ctrl) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_count_entries.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

char __fastcall detour_notify_subscribers(std::int64_t ctrl) noexcept
{
    g_c_notify_subscribers.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_notify_subscribers.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_notify_subscribers.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/notify_subs] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.6 — vt[256] dispatch walker E98480)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_notify_subscribers
            ? g_orig_notify_subscribers(ctrl) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_notify_subscribers.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// ============================================================================
// Hooks 24-25 (Build 62.7) — id_list (CC+0x20, 24-byte stride) RemoveAlly
// walkers. Crash signature Build 62.6 22:09:36 — RVA 0xE92D2A, fault addr
// 0xFF reading [r10+r8*8] where r10 = [CC+0x20] = 0xFF.
// ============================================================================

std::int64_t __fastcall detour_remove_ally_key(std::int64_t ctrl,
                                                std::int64_t actor_key) noexcept
{
    g_c_remove_ally_key.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_id_list_base_is_poisoned_strict(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_remove_ally_key.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_remove_ally_key.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/remove_ally_key] POISON-BAIL #%llu ctrl=0x%llX "
                       "(Build 62.7 — kills crash @ 0xE92D2A)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_remove_ally_key
            ? g_orig_remove_ally_key(ctrl, actor_key) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_remove_ally_key.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

// HOOK 26 — sub_140ED2490 GroupReconcile (Build 63).
//
// Per re/walker_audit_v2/AGENT_D_teleport_race.md + AGENT_E_orchestrator.md:
// Called from sub_140CCF810 (EnterCombat) after CCF810's gates pass.
// Reads `actor.HighProcess+0x40` (back-pointer to CombatController).
// When the engine freed/realloc'd that CC during a cell-attach race, the
// back-pointer is stale → passes garbage to sub_140E93370 MERGE → AV at
// +0x50 prologue xmm5 spill (Build 62.12 crash @ 0xE933C0).
//
// Validation: HP+0x40 must point to a CC with vtable in module .text
// range AND entries_base not in poison range. On invalid:
//   1. Null out actor.HighProcess+0x40 so subsequent reads see "no CC"
//      (engine treats this as "actor not in combat group" — graceful)
//   2. Return 1 = "reconcile succeeded, caller takes idle path"
//      (per Agent A: sub_140ED2490 caller uses return TRUE to skip
//      AddAlly retry path; FALSE would cascade into more work)
//
// SEH cage on orig call as belt-and-braces — if our validation passes
// but ED2490's downstream still hits a stale pointer, swallow the AV
// and return safe 1.
char __fastcall detour_group_reconcile(void* actor, void* target) noexcept
{
    g_c_group_reconcile.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!actor) {
            return g_orig_group_reconcile
                ? g_orig_group_reconcile(actor, target) : 1;
        }
        // Read HP+0x328 = actor.HighProcess
        void* hp = nullptr;
        std::uint64_t cc_addr = 0;
        __try {
            hp = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(actor) + 0x328);
            if (!hp) {
                // No HighProcess — actor not in combat tier. Let orig
                // handle it (likely early-bail with rc=1).
                return g_orig_group_reconcile
                    ? g_orig_group_reconcile(actor, target) : 1;
            }
            // HP+0x40 is the CC back-pointer.
            cc_addr = *reinterpret_cast<std::uint64_t*>(
                reinterpret_cast<std::uint8_t*>(hp) + 0x40);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const auto n = g_c_group_reconcile.seh.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/group_reconcile] SEH-on-HP-read #%llu actor=%p "
                       "— refusing reconcile (Build 63)",
                       static_cast<unsigned long long>(n), actor);
            }
            return 1;
        }
        // Validate CC back-pointer: must be in user heap range.
        constexpr std::uint64_t MIN_USER     = 0x10000ULL;
        constexpr std::uint64_t MAX_HEAP     = 0x300000000000ULL;
        constexpr std::uint64_t MIN_KERNEL   = 0x8000000000000000ULL;
        const bool cc_addr_bad =
            (cc_addr < MIN_USER)
         || (cc_addr >= MAX_HEAP && cc_addr < MIN_KERNEL)
         || (cc_addr >= MIN_KERNEL);
        bool cc_struct_bad = false;
        if (!cc_addr_bad) {
            // Validate entries_base + count fields look sane.
            cc_struct_bad = ctrl_entries_base_is_poisoned(
                static_cast<std::uintptr_t>(cc_addr));
        }
        if (cc_addr_bad || cc_struct_bad) {
            const auto n = g_c_group_reconcile.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_group_reconcile.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/group_reconcile] POISON-BAIL #%llu actor=%p "
                       "hp=%p cc=0x%llX (cc_addr_bad=%d struct_bad=%d, "
                       "Build 63 — nulling HP+0x40 so engine re-allocs)",
                       static_cast<unsigned long long>(n),
                       actor, hp,
                       static_cast<unsigned long long>(cc_addr),
                       cc_addr_bad ? 1 : 0, cc_struct_bad ? 1 : 0);
            }
            // Null HP+0x40 so engine treats this actor as "no CC" and
            // re-allocates fresh on next combat-tier transition.
            __try {
                *reinterpret_cast<std::uint64_t*>(
                    reinterpret_cast<std::uint8_t*>(hp) + 0x40) = 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            return 1;
        }
        // Validation passed — call orig with belt-and-braces SEH cage.
        char rc = 1;
        __try {
            rc = g_orig_group_reconcile
                ? g_orig_group_reconcile(actor, target) : 1;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const auto n = g_c_group_reconcile.seh.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/group_reconcile] SEH-on-orig #%llu actor=%p "
                       "cc=0x%llX — swallowing, returning 1 (Build 63)",
                       static_cast<unsigned long long>(n), actor,
                       static_cast<unsigned long long>(cc_addr));
            }
            rc = 1;
        }
        return rc;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_group_reconcile.seh.fetch_add(1, std::memory_order_relaxed);
        return 1;
    }
}

std::int64_t __fastcall detour_remove_ally_idx(std::int64_t ctrl,
                                                std::uint32_t idx) noexcept
{
    g_c_remove_ally_idx.fires.fetch_add(1, std::memory_order_relaxed);
    __try {
        if (!ctrl) return 0;
        if (ctrl_id_list_base_is_poisoned_strict(
                static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_remove_ally_idx.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_remove_ally_idx.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 8, 500)) {
                FW_LOG("[wg/remove_ally_idx] POISON-BAIL #%llu ctrl=0x%llX "
                       "idx=%u (Build 62.7)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl), idx);
            }
            return 0;
        }
        return g_orig_remove_ally_idx
            ? g_orig_remove_ally_idx(ctrl, idx) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_remove_ally_idx.seh.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
}

bool install_hook_find_in_range(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_FIND_IN_RANGE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_find_in_range),
        reinterpret_cast<void**>(&g_orig_find_in_range));
    FW_LOG("[wg/install] HOOK 11 sub_140E96490 FindInRange %s at 0x%llX "
           "(Build 62.2 — kills current crash @ 0xE964E6)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_known_by_actor(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_KNOWN_BY_ACTOR_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_known_by_actor),
        reinterpret_cast<void**>(&g_orig_known_by_actor));
    FW_LOG("[wg/install] HOOK 12 sub_140E92E50 IsKnownByActor %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_ensure_known(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_ENSURE_KNOWN_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_ensure_known),
        reinterpret_cast<void**>(&g_orig_ensure_known));
    FW_LOG("[wg/install] HOOK 13 sub_140E929C0 EnsureKnownTarget %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_update_pos(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_UPDATE_POS_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_update_pos),
        reinterpret_cast<void**>(&g_orig_update_pos));
    FW_LOG("[wg/install] HOOK 14 sub_140E92B90 UpdatePositionForTarget %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_ally_health(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_ALLY_HEALTH_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_ally_health),
        reinterpret_cast<void**>(&g_orig_ally_health));
    FW_LOG("[wg/install] HOOK 15 sub_140E97D30 AllyHealthAggregate %s at 0x%llX "
           "(was Tier-1 in AGENT_C but never wired until now)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_hashmap_merge(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_HASHMAP_MERGE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_hashmap_merge),
        reinterpret_cast<void**>(&g_orig_hashmap_merge));
    FW_LOG("[wg/install] HOOK 16 sub_140E75F30 BSTHashMapMerge %s at 0x%llX "
           "(Build 62.5 — kills crash @ 0xE75F6A observed Build 62.4 "
           "21:23:52, fault addr 0xEA1173B7E54 unmapped high-canonical)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_find_by_actor(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_FIND_BY_ACTOR_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_find_by_actor),
        reinterpret_cast<void**>(&g_orig_find_by_actor));
    FW_LOG("[wg/install] HOOK 17 sub_140E986C0 FindEntryByActor %s at 0x%llX "
           "(Build 62.6 — kills crash @ 0xE98721 observed Build 62.5 21:51:34)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_find_by_fid(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_FIND_BY_FID_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_find_by_fid),
        reinterpret_cast<void**>(&g_orig_find_by_fid));
    FW_LOG("[wg/install] HOOK 18 sub_140E98760 FindEntryByFID %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_aggro_freshness(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_AGGRO_FRESHNESS_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_aggro_freshness),
        reinterpret_cast<void**>(&g_orig_aggro_freshness));
    FW_LOG("[wg/install] HOOK 19 sub_140E9EC40 AggroFreshness %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_ally_validity_870(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_ALLY_VALIDITY1_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_ally_validity_870),
        reinterpret_cast<void**>(&g_orig_ally_validity_870));
    FW_LOG("[wg/install] HOOK 20 sub_140E9E870 AllyValidity1 %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_ally_validity_A40(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_ALLY_VALIDITY2_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_ally_validity_A40),
        reinterpret_cast<void**>(&g_orig_ally_validity_A40));
    FW_LOG("[wg/install] HOOK 21 sub_140E9EA40 AllyValidity2 %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_count_entries(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_COUNT_ENTRIES_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_count_entries),
        reinterpret_cast<void**>(&g_orig_count_entries));
    FW_LOG("[wg/install] HOOK 22 sub_140E9E760 CountEntries %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_notify_subscribers(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_NOTIFY_SUBS_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_notify_subscribers),
        reinterpret_cast<void**>(&g_orig_notify_subscribers));
    FW_LOG("[wg/install] HOOK 23 sub_140E98480 NotifySubscribers %s at 0x%llX "
           "(per-inventory: HIGH risk — vt[256] dispatch on resolved actor)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_remove_ally_key(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_REMOVE_ALLY_BY_KEY_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_remove_ally_key),
        reinterpret_cast<void**>(&g_orig_remove_ally_key));
    FW_LOG("[wg/install] HOOK 24 sub_140E92D00 RemoveAllyByKey %s at 0x%llX "
           "(Build 62.7 — kills crash @ 0xE92D2A observed Build 62.6 22:09:36)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_remove_ally_idx(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_REMOVE_ALLY_BY_IDX_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_remove_ally_idx),
        reinterpret_cast<void**>(&g_orig_remove_ally_idx));
    FW_LOG("[wg/install] HOOK 25 sub_140E9E0C0 RemoveAllyByIdx %s at 0x%llX",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_group_reconcile(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_GROUP_RECONCILE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_group_reconcile),
        reinterpret_cast<void**>(&g_orig_group_reconcile));
    FW_LOG("[wg/install] HOOK 26 sub_140ED2490 GroupReconcile %s at 0x%llX "
           "(Build 63 — validates HP+0x40 CC back-pointer; kills crash @ "
           "0xE933C0 = sub_140E93370+0x50 prologue when stale CC passed)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_hook_lock_primitive(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::LOCK_PRIMITIVE_GUARD_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_lock_primitive),
        reinterpret_cast<void**>(&g_orig_lock_primitive));
    if (ok) {
        FW_LOG("[wg/install] HOOK 8 sub_141658FE0 BSSimpleMutex::lock "
               "installed at 0x%llX (RVA 0x%lX) — kills AV class at "
               "0x1658FEF when engine derives lock-ptr from null+offset "
               "(observed in Build 58 EnterCombat alt-path).",
               static_cast<unsigned long long>(ea),
               static_cast<unsigned long>(fw::offsets::LOCK_PRIMITIVE_GUARD_RVA));
    } else {
        FW_ERR("[wg/install] HOOK 8 LockPrimitive FAILED at 0x%llX",
               static_cast<unsigned long long>(ea));
    }
    return ok;
}

} // namespace

// ============================================================================
// Master install
// ============================================================================
// ============================================================================
// HOOK 27 (Build 65.c.31) — sub_140E959E0 "update combat-target record".
//
// Crash: client A AV @ 0xE95A49 the instant the local player KILLS a raider it
// OWNS (RNG-aggro model). Disasm-proven (re/crash_0xE95A49_raiderkill_AGENT.md):
//   0xE95A01  mov rsi,[rcx+78h]      ; rsi = *(ctrl+0x78) combat-target sub-obj
//   0xE95A25  call sub_141658FE0     ; spinlock on [rsi+0x40]  (×2)  ← Hook 8 bails
//   0xE95A49  mov rdx,[rsi+28h]      ; FAULT: rsi==NULL → read 0x28
// The +0x78 sub-object (a BSTScatterTable holder) is NULL during owner-side
// raider-death teardown — the engine never expects it null because vanilla
// doesn't force the InCombat/target state we apply (npc_ai_suppress). The two
// [wg/lock] NULL-DERIV-BAIL lock=0x40 lines that precede the crash are exactly
// the two spinlock calls above with rsi=0. Hook 8 masked those but couldn't
// stop the sibling +0x28 read — hence this dedicated guard.
//
// Validates *(ctrl+0x78) before forwarding; bails (return 0) if it is NULL /
// sub-page / kernel / non-canonical. Skipping one combat-target-record update
// on a dying raider is invisible (no next tick); both callers ignore the result.
inline bool combat_target_map_is_poisoned(std::uintptr_t ctrl) noexcept {
    if (ctrl < 0x10000) return true;   // ctrl arg itself null/sub-page
    bool poisoned = false;
    __try {
        const std::uint64_t sub = *reinterpret_cast<std::uint64_t*>(
            ctrl + fw::offsets::COMBATCTRL_TARGET_MAP_OFF);   // *(ctrl+0x78)
        constexpr std::uint64_t MIN_USER_HEAP_ADDR = 0x10000ULL;
        constexpr std::uint64_t MAX_HEAP_ADDR      = 0x300000000000ULL;
        constexpr std::uint64_t MIN_KERNEL_ADDR    = 0x8000000000000000ULL;
        poisoned = (sub < MIN_USER_HEAP_ADDR)
                || (sub >= MAX_HEAP_ADDR && sub < MIN_KERNEL_ADDR)
                || (sub >= MIN_KERNEL_ADDR);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        poisoned = true;
    }
    return poisoned;
}

std::int64_t __fastcall detour_update_target_rec(std::int64_t ctrl,
                                                 std::int64_t a2,
                                                 std::int64_t a3) noexcept
{
    g_c_update_target_rec.fires.fetch_add(1, std::memory_order_relaxed);

    if (g_disable_update_target_rec.load(std::memory_order_relaxed)) {
        return g_orig_update_target_rec
            ? g_orig_update_target_rec(ctrl, a2, a3) : 0;
    }

    __try {
        if (combat_target_map_is_poisoned(static_cast<std::uintptr_t>(ctrl))) {
            const auto n = g_c_update_target_rec.ghost_hits.fetch_add(
                1, std::memory_order_relaxed);
            g_c_update_target_rec.actions.fetch_add(
                1, std::memory_order_relaxed);
            if (should_log(n, 16, 1000)) {
                FW_LOG("[wg/upd_target_rec] POISON-BAIL #%llu ctrl=0x%llX "
                       "ctrl+0x78 (combat-target sub-object) NULL/poison — "
                       "skipping to avoid AV at 0xE95A49 ([ctrl+0x78]+0x28 read "
                       "on owner-side raider death)",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(ctrl));
            }
            return 0;
        }
        return g_orig_update_target_rec
            ? g_orig_update_target_rec(ctrl, a2, a3) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_c_update_target_rec.seh.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[wg/upd_target_rec] SEH in detour (ctrl=0x%llX)",
               static_cast<unsigned long long>(ctrl));
        return 0;
    }
}

bool install_hook_update_target_rec(std::uintptr_t module_base) {
    const auto ea = module_base + fw::offsets::COMBATCTRL_UPDATE_TARGET_REC_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(ea),
        reinterpret_cast<void*>(&detour_update_target_rec),
        reinterpret_cast<void**>(&g_orig_update_target_rec));
    FW_LOG("[wg/install] HOOK 27 sub_140E959E0 UpdateTargetRec %s at 0x%llX "
           "(Build 65.c.31 — kills AV @ 0xE95A49 on owner-side raider-death "
           "teardown: ctrl+0x78 combat-target sub-object NULL → [+0x28] read)",
           ok ? "installed" : "FAILED",
           static_cast<unsigned long long>(ea));
    return ok;
}

bool install_ghost_global_walker_guards(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[wg] already installed; skipping");
        return true;
    }

    FW_LOG("[wg] ============================================================");
    FW_LOG("[wg] Build 59 Global Walker Guards — installing 8 hooks");
    FW_LOG("[wg] ============================================================");

    int success_count = 0;
    int total = 0;

    // Hook 1 — the keystone (most critical).
    total++;
    if (install_hook_find_entry(module_base)) success_count++;

    // Hook 2-4 — combat controller tier.
    total++;
    if (install_hook_process_tick(module_base)) success_count++;
    total++;
    if (install_hook_housekeeping(module_base)) success_count++;
    total++;
    if (install_hook_add_target(module_base)) success_count++;

    // Hook 5 — form-table rehydrator.
    total++;
    if (install_hook_form_rehydrator(module_base)) success_count++;

    // Hook 6 — death broadcast walker.
    total++;
    if (install_hook_death_broadcast(module_base)) success_count++;

    // Hook 7 — LOS sight cone (predictive, DISABLED by default).
    total++;
    if (install_hook_los_sight_cone(module_base)) success_count++;

    // Hook 8 (Build 59) — lock primitive null-deriv guard. ON by default.
    total++;
    if (install_hook_lock_primitive(module_base)) success_count++;

    // Hook 9 + 10 (Build 62.1) — peer walkers to Hook 1, currently
    // unguarded. AV class observed live in Build 62 @ 19:19:45.
    total++;
    if (install_hook_remove_by_fid(module_base)) success_count++;
    total++;
    if (install_hook_group_gate(module_base)) success_count++;

    // Hook 11..15 (Build 62.2) — 5 more peer walkers from
    // re/av_E92xxx_root_cause/AGENT_peer_family.md.
    total++;
    if (install_hook_find_in_range(module_base)) success_count++;
    total++;
    if (install_hook_known_by_actor(module_base)) success_count++;
    total++;
    if (install_hook_ensure_known(module_base)) success_count++;
    total++;
    if (install_hook_update_pos(module_base)) success_count++;
    total++;
    if (install_hook_ally_health(module_base)) success_count++;

    // Hook 16 (Build 62.5) — BSTHashMap merge walker. Catches the AV at
    // RVA 0xE75F6A that fired Build 62.4 21:23:52 after ghost engagement
    // landed. Different structure layout from Hooks 9-15 (count at +0x04,
    // base at +0x20) so it needs its own poison check.
    total++;
    if (install_hook_hashmap_merge(module_base)) success_count++;

    // Hooks 17-23 (Build 62.6) — stride-208 CC walker batch. Hook 17 covers
    // the actual Build 62.5 crash @ 0xE98721 (sub_140E986C0 FindEntryByActor).
    // Hooks 18-23 are sister walkers from re/walker_inventory/AGENT_C with
    // identical poison vulnerability — installed preventively so we don't
    // ship one-walker-per-build whack-a-mole patches forever.
    total++;
    if (install_hook_find_by_actor(module_base)) success_count++;
    total++;
    if (install_hook_find_by_fid(module_base)) success_count++;
    total++;
    if (install_hook_aggro_freshness(module_base)) success_count++;
    total++;
    if (install_hook_ally_validity_870(module_base)) success_count++;
    total++;
    if (install_hook_ally_validity_A40(module_base)) success_count++;
    total++;
    if (install_hook_count_entries(module_base)) success_count++;
    total++;
    if (install_hook_notify_subscribers(module_base)) success_count++;

    // Hooks 24-25 (Build 62.7) — id_list (CC+0x20) RemoveAlly walkers.
    // Hook 24 covers the actual Build 62.6 crash @ 0xE92D2A
    // (sub_140E92D00 RemoveAllyByKey). Hook 25 covers its callee.
    total++;
    if (install_hook_remove_ally_key(module_base)) success_count++;
    total++;
    if (install_hook_remove_ally_idx(module_base)) success_count++;

    // Hook 26 (Build 63) — sub_140ED2490 GroupReconcile. Validates HP+0x40
    // CC back-pointer before passing to sub_140E93370 MERGE. Kills the
    // Build 62.12 crash @ 0xE933C0 (= MERGE function prologue +0x50,
    // entered with stale CC after cell-attach race).
    total++;
    if (install_hook_group_reconcile(module_base)) success_count++;

    // Hook 27 (Build 65.c.31) — sub_140E959E0 UpdateTargetRec. Validates the
    // ctrl+0x78 combat-target sub-object before its unconditional +0x40/+0x28
    // derefs. Kills the AV @ 0xE95A49 that crashes the OWNER when it kills a
    // raider it owns (RNG-aggro death teardown) — the +0x78 field none of the
    // 26 prior guards validate.
    total++;
    if (install_hook_update_target_rec(module_base)) success_count++;

    g_installed.store(true, std::memory_order_release);

    FW_LOG("[wg] ============================================================");
    FW_LOG("[wg] install summary: %d/%d hooks installed", success_count, total);
    FW_LOG("[wg] Hook 1 (find_entry @ 0xE98820) kills the 0xE98860 AV class.");
    FW_LOG("[wg] Hook 8 (lock @ 0x1658FE0) kills the 0x1658FEF AV class.");
    FW_LOG("[wg] ============================================================");

    // 80% threshold = at least Hook 1 + 5 others must succeed.
    return success_count >= (total * 4 / 5);
}

// ============================================================================
// Counter getters — for periodic stats dump.
// ============================================================================
std::uint64_t get_walker_guards_total_fires() {
    return g_c_find_entry.fires.load(std::memory_order_relaxed)
         + g_c_process_tick.fires.load(std::memory_order_relaxed)
         + g_c_housekeeping.fires.load(std::memory_order_relaxed)
         + g_c_add_target.fires.load(std::memory_order_relaxed)
         + g_c_form_rehydrator.fires.load(std::memory_order_relaxed)
         + g_c_death_broadcast.fires.load(std::memory_order_relaxed)
         + g_c_los_sight_cone.fires.load(std::memory_order_relaxed)
         + g_c_lock_primitive.fires.load(std::memory_order_relaxed)
         + g_c_remove_by_fid.fires.load(std::memory_order_relaxed)
         + g_c_group_gate.fires.load(std::memory_order_relaxed)
         + g_c_find_in_range.fires.load(std::memory_order_relaxed)
         + g_c_known_by_actor.fires.load(std::memory_order_relaxed)
         + g_c_ensure_known.fires.load(std::memory_order_relaxed)
         + g_c_update_pos.fires.load(std::memory_order_relaxed)
         + g_c_ally_health.fires.load(std::memory_order_relaxed)
         + g_c_hashmap_merge.fires.load(std::memory_order_relaxed)
         + g_c_find_by_actor.fires.load(std::memory_order_relaxed)
         + g_c_find_by_fid.fires.load(std::memory_order_relaxed)
         + g_c_aggro_freshness.fires.load(std::memory_order_relaxed)
         + g_c_ally_validity_870.fires.load(std::memory_order_relaxed)
         + g_c_ally_validity_A40.fires.load(std::memory_order_relaxed)
         + g_c_count_entries.fires.load(std::memory_order_relaxed)
         + g_c_notify_subscribers.fires.load(std::memory_order_relaxed)
         + g_c_remove_ally_key.fires.load(std::memory_order_relaxed)
         + g_c_remove_ally_idx.fires.load(std::memory_order_relaxed)
         + g_c_group_reconcile.fires.load(std::memory_order_relaxed);
}

std::uint64_t get_walker_guards_ghost_hits() {
    return g_c_find_entry.ghost_hits.load(std::memory_order_relaxed)
         + g_c_process_tick.ghost_hits.load(std::memory_order_relaxed)
         + g_c_housekeeping.ghost_hits.load(std::memory_order_relaxed)
         + g_c_add_target.ghost_hits.load(std::memory_order_relaxed)
         + g_c_form_rehydrator.ghost_hits.load(std::memory_order_relaxed)
         + g_c_death_broadcast.ghost_hits.load(std::memory_order_relaxed)
         + g_c_los_sight_cone.ghost_hits.load(std::memory_order_relaxed)
         + g_c_lock_primitive.ghost_hits.load(std::memory_order_relaxed)
         + g_c_remove_by_fid.ghost_hits.load(std::memory_order_relaxed)
         + g_c_group_gate.ghost_hits.load(std::memory_order_relaxed)
         + g_c_find_in_range.ghost_hits.load(std::memory_order_relaxed)
         + g_c_known_by_actor.ghost_hits.load(std::memory_order_relaxed)
         + g_c_ensure_known.ghost_hits.load(std::memory_order_relaxed)
         + g_c_update_pos.ghost_hits.load(std::memory_order_relaxed)
         + g_c_ally_health.ghost_hits.load(std::memory_order_relaxed)
         + g_c_hashmap_merge.ghost_hits.load(std::memory_order_relaxed)
         + g_c_find_by_actor.ghost_hits.load(std::memory_order_relaxed)
         + g_c_find_by_fid.ghost_hits.load(std::memory_order_relaxed)
         + g_c_aggro_freshness.ghost_hits.load(std::memory_order_relaxed)
         + g_c_ally_validity_870.ghost_hits.load(std::memory_order_relaxed)
         + g_c_ally_validity_A40.ghost_hits.load(std::memory_order_relaxed)
         + g_c_count_entries.ghost_hits.load(std::memory_order_relaxed)
         + g_c_notify_subscribers.ghost_hits.load(std::memory_order_relaxed)
         + g_c_remove_ally_key.ghost_hits.load(std::memory_order_relaxed)
         + g_c_remove_ally_idx.ghost_hits.load(std::memory_order_relaxed)
         + g_c_group_reconcile.ghost_hits.load(std::memory_order_relaxed);
}

std::uint64_t get_walker_guards_actions_taken() {
    return g_c_find_entry.actions.load(std::memory_order_relaxed)
         + g_c_process_tick.actions.load(std::memory_order_relaxed)
         + g_c_housekeeping.actions.load(std::memory_order_relaxed)
         + g_c_add_target.actions.load(std::memory_order_relaxed)
         + g_c_form_rehydrator.actions.load(std::memory_order_relaxed)
         + g_c_death_broadcast.actions.load(std::memory_order_relaxed)
         + g_c_los_sight_cone.actions.load(std::memory_order_relaxed)
         + g_c_lock_primitive.actions.load(std::memory_order_relaxed)
         + g_c_remove_by_fid.actions.load(std::memory_order_relaxed)
         + g_c_group_gate.actions.load(std::memory_order_relaxed)
         + g_c_find_in_range.actions.load(std::memory_order_relaxed)
         + g_c_known_by_actor.actions.load(std::memory_order_relaxed)
         + g_c_ensure_known.actions.load(std::memory_order_relaxed)
         + g_c_update_pos.actions.load(std::memory_order_relaxed)
         + g_c_ally_health.actions.load(std::memory_order_relaxed)
         + g_c_hashmap_merge.actions.load(std::memory_order_relaxed)
         + g_c_find_by_actor.actions.load(std::memory_order_relaxed)
         + g_c_find_by_fid.actions.load(std::memory_order_relaxed)
         + g_c_aggro_freshness.actions.load(std::memory_order_relaxed)
         + g_c_ally_validity_870.actions.load(std::memory_order_relaxed)
         + g_c_ally_validity_A40.actions.load(std::memory_order_relaxed)
         + g_c_count_entries.actions.load(std::memory_order_relaxed)
         + g_c_notify_subscribers.actions.load(std::memory_order_relaxed)
         + g_c_remove_ally_key.actions.load(std::memory_order_relaxed)
         + g_c_remove_ally_idx.actions.load(std::memory_order_relaxed)
         + g_c_group_reconcile.actions.load(std::memory_order_relaxed);
}

std::uint64_t get_walker_guards_seh_count() {
    return g_c_find_entry.seh.load(std::memory_order_relaxed)
         + g_c_process_tick.seh.load(std::memory_order_relaxed)
         + g_c_housekeeping.seh.load(std::memory_order_relaxed)
         + g_c_add_target.seh.load(std::memory_order_relaxed)
         + g_c_form_rehydrator.seh.load(std::memory_order_relaxed)
         + g_c_death_broadcast.seh.load(std::memory_order_relaxed)
         + g_c_los_sight_cone.seh.load(std::memory_order_relaxed)
         + g_c_lock_primitive.seh.load(std::memory_order_relaxed)
         + g_c_remove_by_fid.seh.load(std::memory_order_relaxed)
         + g_c_group_gate.seh.load(std::memory_order_relaxed)
         + g_c_find_in_range.seh.load(std::memory_order_relaxed)
         + g_c_known_by_actor.seh.load(std::memory_order_relaxed)
         + g_c_ensure_known.seh.load(std::memory_order_relaxed)
         + g_c_update_pos.seh.load(std::memory_order_relaxed)
         + g_c_ally_health.seh.load(std::memory_order_relaxed)
         + g_c_hashmap_merge.seh.load(std::memory_order_relaxed)
         + g_c_find_by_actor.seh.load(std::memory_order_relaxed)
         + g_c_find_by_fid.seh.load(std::memory_order_relaxed)
         + g_c_aggro_freshness.seh.load(std::memory_order_relaxed)
         + g_c_ally_validity_870.seh.load(std::memory_order_relaxed)
         + g_c_ally_validity_A40.seh.load(std::memory_order_relaxed)
         + g_c_count_entries.seh.load(std::memory_order_relaxed)
         + g_c_notify_subscribers.seh.load(std::memory_order_relaxed)
         + g_c_remove_ally_key.seh.load(std::memory_order_relaxed)
         + g_c_remove_ally_idx.seh.load(std::memory_order_relaxed)
         + g_c_group_reconcile.seh.load(std::memory_order_relaxed);
}

std::size_t snapshot_all_walker_guards(WalkerGuardSnapshot* out,
                                        std::size_t max_count) {
    if (!out || max_count == 0) return 0;

    const struct {
        const char* name;
        WalkerGuardCounters* c;
    } table[] = {
        { "find_entry_E98820",   &g_c_find_entry      },
        { "process_tick_E918C0", &g_c_process_tick    },
        { "housekeeping_E988A0", &g_c_housekeeping    },
        { "add_target_E91D70",   &g_c_add_target      },
        { "form_rehydrator_C06AC0", &g_c_form_rehydrator },
        { "death_broadcast_C80D70", &g_c_death_broadcast },
        { "los_sight_cone_DA28A0",  &g_c_los_sight_cone  },
        { "lock_primitive_1658FE0", &g_c_lock_primitive },
        { "remove_by_fid_E92260",   &g_c_remove_by_fid  },  // Build 62.1
        { "group_gate_E924A0",      &g_c_group_gate     },  // Build 62.1
        { "find_in_range_E96490",   &g_c_find_in_range  },  // Build 62.2
        { "known_by_actor_E92E50",  &g_c_known_by_actor },  // Build 62.2
        { "ensure_known_E929C0",    &g_c_ensure_known   },  // Build 62.2
        { "update_pos_E92B90",      &g_c_update_pos     },  // Build 62.2
        { "ally_health_E97D30",     &g_c_ally_health    },  // Build 62.2
        { "hashmap_merge_E75F30",   &g_c_hashmap_merge  },  // Build 62.5
        { "find_by_actor_E986C0",   &g_c_find_by_actor    },  // Build 62.6
        { "find_by_fid_E98760",     &g_c_find_by_fid      },  // Build 62.6
        { "aggro_freshness_E9EC40", &g_c_aggro_freshness  },  // Build 62.6
        { "ally_validity1_E9E870",  &g_c_ally_validity_870},  // Build 62.6
        { "ally_validity2_E9EA40",  &g_c_ally_validity_A40},  // Build 62.6
        { "count_entries_E9E760",   &g_c_count_entries    },  // Build 62.6
        { "notify_subs_E98480",     &g_c_notify_subscribers},  // Build 62.6
        { "remove_ally_key_E92D00", &g_c_remove_ally_key  },   // Build 62.7
        { "remove_ally_idx_E9E0C0", &g_c_remove_ally_idx  },   // Build 62.7
        { "group_reconcile_ED2490", &g_c_group_reconcile },    // Build 63
    };
    constexpr std::size_t N = sizeof(table) / sizeof(table[0]);
    const std::size_t n = (max_count < N) ? max_count : N;

    for (std::size_t i = 0; i < n; ++i) {
        out[i].name       = table[i].name;
        out[i].fires      = table[i].c->fires.load(std::memory_order_relaxed);
        out[i].ghost_hits = table[i].c->ghost_hits.load(std::memory_order_relaxed);
        out[i].actions    = table[i].c->actions.load(std::memory_order_relaxed);
        out[i].seh        = table[i].c->seh.load(std::memory_order_relaxed);
    }
    return n;
}

} // namespace fw::hooks
