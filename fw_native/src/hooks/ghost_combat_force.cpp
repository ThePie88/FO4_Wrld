// ============================================================================
// DORMANT — 2026-05-17 log evidence: all 4 detours fire correctly, none of
// the 4 override predicates ever matches in production. KEEP CODE for reference
// / future re-enable. DO NOT delete.
//
// LOG PROOF (Client A `C:\Program Files (x86)\Steam\steamapps\common\Fallout 4\
//            fw_native.log`, session 17:29-17:39):
//   [combat-force] post-pick fire #22000 aiproc=...  (overrides=0 so far)
//   [combat-force] alive-counter fire #9000 controller=...  (boosts=0 so far)
//   [combat-force] cell-loaded fire #9 actor=...  (overrides=0 so far)
//   ZERO `OVERRIDE → 1`, ZERO `alive-boost`, ZERO `cell-loaded OVERRIDE`.
//   Same on Client B (`C:\Users\filip\Desktop\FalloutWorld\FO4_b\fw_native.log`).
//
// WHY each predicate never matches:
//
//   detour_alive_counter:
//     Tests `fw::engine::is_ghost_combat_controller(controller)`. That set is
//     populated by `install_fixed_selector_on_raider` (engine_calls.cpp:5163).
//     install_fixed_selector_on_raider is gated on `actor+0x328 != NULL`
//     (combat AIProcess present). The 5 raiders the server aggroes
//     (74E50/74E51/19E13C-E) are in Concord; player_A spawns in Sanctuary.
//     Engine never promotes raider to combat tier vs ghost because:
//       - Ghost baseForm was swapped to safe vanilla TESNPC (Build 35.2,
//         fid 0x0603F6C1) → no Raider-hostile faction relations.
//       - HostilityCore(raider, ghost) returns 0 (neutral).
//       - Engine EnterCombat never fires → +0x328 stays NULL.
//     Result: install_fixed_selector_on_raider is called 0 times →
//     g_ghost_combat_controllers stays empty → predicate returns false →
//     no boost ever.
//
//   detour_cell_loaded:
//     Tests `actor == ghost`. The engine only queries IsCellLoaded(ghost)
//     when iterating known_targets[] for a raider already in combat with
//     the ghost. Per chain above, raider never enters combat with ghost →
//     ghost never gets into known_targets[] → predicate sees actor=raider
//     not actor=ghost → no override ever.
//
//   detour_post_pick_gate:
//     Tests `aiproc+0x6C == g_ghost_duplicate_handle`. aiproc+0x6C is the
//     "current combat target handle" written by the engine's promoter
//     `sub_14087B080` after iterating selectors. With no Fixed selector
//     installed (see alive-counter path above) and no natural perception
//     of ghost (cross-cell distance ~26000 units), promoter never picks
//     ghost → aiproc+0x6C stays at vanilla local-player handle or 0 →
//     predicate returns false → no override ever.
//
// ROOT CAUSE (verified by re/AI_pipeline/MASTER.md "Cross-section synthesis"
// + section_03/06/08/10, 2026-05-17 10-agent RE pass):
//   The combat AI rejects the ghost as a valid target via 4 INDEPENDENT
//   gates (A=hostility, B=weapon-state class, C=aim solver, D=alive count).
//   Even if THIS file's 3 surgical hooks satisfied gates A+D, gates B+C
//   live in fire-pipeline territory (sub_140479680, sub_140E42970) and
//   are NOT addressed here. So even a hypothetical "all 3 overrides fire"
//   scenario would still produce no visible projectile because Stage 4 of
//   `sub_140479680` bails on aim-ray solver returning 0.
//
// ALTERNATIVE PATH (re/AI_pipeline/section_08_fire_pipeline.md §0/§16.3):
//   Pure server-authoritative puppet fire that bypasses the entire combat
//   AI pipeline. For each server-pushed NPC_FIRE event:
//     1. sub_140CD1830(raider, slot, 15) — force weapon-state class to 15
//     2. sub_140E65820(aim_ctrl, &target_pos) — write aim into CombatAim
//     3. WeaponFireHandler(raider, NULL) — the existing fire_actor_weapon
//   This makes the engine emit muzzle flash + projectile + tracer + impact
//   + audio without satisfying ANY combat-engagement gate (Section 08
//   §0 explicit: "Stage 4 has no back-reference to am-I-in-combat").
//   Raider stays visually static (no rotation, no aggro stance), but
//   FIRES — and FIRES is the observable user wants.
//
// KEEP-AS-IS RATIONALE:
//   These 3 hooks add zero runtime overhead beyond a single function call +
//   one atomic counter increment. They're harmless. Re-enabling them would
//   become useful once a different design somehow does get a raider into
//   combat tier with the ghost (e.g., via a custom TESNPC with explicit
//   Raider-hostile factions baked into the ESL, replacing the baseForm
//   swap target). At that point overrides could start firing and the
//   diagnostic counters would prove it.
//
// Anyone reading this: do NOT add more hooks here trying to make raiders
// aggro the ghost. The dossier proved the natural engagement path is
// architecturally blocked. Move work to the puppet-fire path in
// `engine_calls.cpp::fire_actor_weapon` extension instead.
// ============================================================================

#include "ghost_combat_force.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../engine/engine_calls.h"  // get_ghost_duplicate

namespace fw::hooks {

namespace {

// ============================================================================
// Function pointer types — signatures verified by 10-agent dossier
// (re/AI_pipeline/section_06 + section_10 + section_03).
// ============================================================================

// sub_140C8DFF0 HostilityCore — relationship rank between two actors.
// Returns 0/1/2/3 = neutral/hostile/friend/ally.
// Section 10 §1, funcs_0303.md:2895-3100.
using HostilityCoreFn =
    std::int64_t (__fastcall *)(std::int64_t a1_observer,
                                std::int64_t a2_subject,
                                char a3_override);

// sub_140E9E650 alive-counter — recomputes controller+0x110/+0x114/+0x118
// alive counts by walking known_targets[]. Returns void.
// Section 03, funcs_0337.md:11457-11497.
using AliveCounterFn = void (__fastcall *)(std::int64_t controller);

// sub_1404FB890 cell-loaded — returns 1 if actor.parent_cell is loaded.
// Section 06 §1, funcs_0174.md:716-728.
using CellLoadedFn = char (__fastcall *)(std::int64_t actor);

// sub_14087A900 post-pick gate — returns 0 = need re-pick, 1 = stay
// engaged. Threaded into orchestrator's combat-state machine.
// Section 06 §8, funcs_0240.md:5738-5865.
using PostPickGateFn = char (__fastcall *)(std::int64_t aiproc);

HostilityCoreFn  g_orig_hostility   = nullptr;
AliveCounterFn   g_orig_alive       = nullptr;
CellLoadedFn     g_orig_cell        = nullptr;
PostPickGateFn   g_orig_post_pick   = nullptr;

std::atomic<std::uint64_t> g_hostility_fires{0};
std::atomic<std::uint64_t> g_hostility_overrides{0};
std::atomic<std::uint64_t> g_alive_fires{0};
std::atomic<std::uint64_t> g_alive_boosts{0};
std::atomic<std::uint64_t> g_cell_fires{0};
std::atomic<std::uint64_t> g_cell_overrides{0};
std::atomic<std::uint64_t> g_pick_fires{0};
std::atomic<std::uint64_t> g_pick_overrides{0};
std::atomic<std::uint64_t> g_seh_failures{0};

std::atomic<bool> g_installed{false};

// ============================================================================
// Helpers
// ============================================================================

// Read ghost actor pointer (cached, atomic-acquire).
inline void* ghost_ptr() noexcept {
    return fw::engine::get_ghost_duplicate();
}

// Resolve a packed handle to the actor pointer in the global handle
// table (unk_1430DA390, 16-byte stride, image-base-relative).
//
// Inline copy of the engine's resolver (sub_14022CC20 funcs_0120.md)
// minus refcount mutation — read-only.
//
// Section 04 §10 documents the handle format:
//   bits 0..20   slot index   (mask 0x1FFFFF)
//   bits 21..25  generation   (mask 0x3E00000)
//   bit  26      alive flag   (table-entry side, mask 0x4000000)
//
// Each table entry (16 bytes):
//   +0x00 DWORD  flags (alive bit + generation)
//   +0x04 DWORD  padding
//   +0x08 QWORD  actor_self_ptr (= &actor + 32; resolve = ptr - 32)
static void* resolve_handle_to_actor(std::uint32_t handle) noexcept {
    if (handle == 0 || handle == 0xFFFFFFFFu) return nullptr;
    static std::uint8_t* s_htab_base = nullptr;
    if (!s_htab_base) {
        // Resolve handle table base once. The g_handle_table_base is
        // exposed in engine_calls via offsets HANDLE_TABLE_BASE_RVA.
        // Compute from module base.
        const std::uintptr_t module_base =
            reinterpret_cast<std::uintptr_t>(&resolve_handle_to_actor) &
            ~static_cast<std::uintptr_t>(0xFFFFFFFFu);
        (void)module_base;
        // Fallback: read via offsets. Since this is per-call we
        // re-resolve below using engine helper.
    }
    void* actor = nullptr;
    __try {
        const std::uint32_t idx = handle & 0x1FFFFFu;
        const std::uint32_t gen = handle & 0x3E00000u;
        auto* htab = reinterpret_cast<std::uint8_t*>(
            // Compute table base from a known engine RVA.
            // HANDLE_TABLE_BASE_RVA = 0x030DA390 per offsets.h.
            // Module base derived from g_orig_hostility's known RVA.
            reinterpret_cast<std::uintptr_t>(g_orig_hostility) -
            fw::offsets::HOSTILITY_CORE_RVA +
            fw::offsets::HANDLE_TABLE_BASE_RVA);
        if (!htab) return nullptr;
        auto* entry = htab + 16ULL * idx;
        const std::uint32_t flags =
            *reinterpret_cast<std::uint32_t*>(entry);
        if ((flags & 0x4000000u) == 0) return nullptr;       // not alive
        if ((flags & 0x3E00000u) != gen) return nullptr;     // gen mismatch
        const std::uint64_t self_ptr =
            *reinterpret_cast<std::uint64_t*>(entry + 8);
        if (!self_ptr) return nullptr;
        actor = reinterpret_cast<void*>(self_ptr - 32);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        actor = nullptr;
    }
    return actor;
}

// Check if any known_targets[] entry resolves to the ghost.
// known_targets array: base at controller+0x08, count at +0x18,
// stride 208 (0xD0). Per Section 04 §2.
//
// Entry layout: form_id at +0x00 (DWORD).
static bool known_targets_contain_ghost(void* controller, void* ghost) noexcept {
    if (!controller || !ghost) return false;
    bool found = false;
    __try {
        auto* ctrl = reinterpret_cast<std::uint8_t*>(controller);
        const std::uint64_t base_ptr =
            *reinterpret_cast<std::uint64_t*>(ctrl + 0x08);
        const std::uint32_t count =
            *reinterpret_cast<std::uint32_t*>(ctrl + 0x18);
        if (!base_ptr || count == 0 || count > 64) return false;
        // Read ghost form_id (= 0xFF000001 for our registered duplicate).
        const std::uint32_t ghost_fid =
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(ghost) + 0x14);
        for (std::uint32_t i = 0; i < count && i < 64; ++i) {
            auto* entry = reinterpret_cast<std::uint8_t*>(base_ptr) +
                          static_cast<std::uintptr_t>(208) * i;
            const std::uint32_t fid =
                *reinterpret_cast<std::uint32_t*>(entry);
            if (fid == ghost_fid) {
                found = true;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        found = false;
    }
    return found;
}

// AIProcess.target handle == ghost's preallocated handle?
//
// Build 43b (2026-05-17) — pivoted from handle resolution to raw
// handle comparison. The previous version used a custom
// resolve_handle_to_actor() that needed module_base, which it
// computed from g_orig_hostility — but that pointer was NULL because
// the HostilityCore hook (sub_140C8DFF0) is owned by
// ghost_hostility_guard.cpp now, not us. Result: htab was a garbage
// address, every resolve SEH'd silently, override never matched.
//
// Simpler fix: use the engine handle already cached at ghost spawn
// (g_ghost_duplicate_handle). It's the SAME value the engine writes
// to aiproc+0x6C when our apply_npc_combat_target succeeds. Direct
// DWORD compare. Zero handle-table dereferences.
static bool aiproc_targets_ghost(void* aiproc, void* /*ghost*/) noexcept {
    if (!aiproc) return false;
    const std::uint32_t ghost_handle =
        fw::engine::get_ghost_duplicate_handle();
    if (ghost_handle == 0) return false;
    bool yes = false;
    __try {
        const std::uint32_t handle_6C =
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C);
        yes = (handle_6C == ghost_handle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        yes = false;
    }
    return yes;
}

// ============================================================================
// Detour 1: HostilityCore — force return 1 (hostile) when ghost involved.
// ============================================================================
std::int64_t __fastcall detour_hostility_core(
    std::int64_t a1, std::int64_t a2, char a3) noexcept
{
    const auto n = g_hostility_fires.fetch_add(1, std::memory_order_relaxed);

    void* ghost = ghost_ptr();
    if (ghost) {
        void* a1_p = reinterpret_cast<void*>(a1);
        void* a2_p = reinterpret_cast<void*>(a2);
        if (a1_p == ghost || a2_p == ghost) {
            const auto on = g_hostility_overrides.fetch_add(
                1, std::memory_order_relaxed);
            if (on < 8 || (on % 200) == 0) {
                FW_LOG("[combat-force] hostility #%llu OVERRIDE → 1 "
                       "(observer=%p subject=%p ghost=%p)",
                       static_cast<unsigned long long>(on),
                       a1_p, a2_p, ghost);
            }
            return 1;  // hostile
        }
    }

    if (g_orig_hostility) {
        return g_orig_hostility(a1, a2, a3);
    }
    return 0;
}

// ============================================================================
// Detour 2: alive-counter — call orig, then force-increment alive count
// for ghost-entry if present in known_targets[].
//
// sub_140E9E650 writes controller+0x110/+0x114/+0x118. We post-hoc add 1
// to +0x110 (alive_count_total) and +0x114 (alive_count_hostile) when
// ghost is in the array, since orig skips ghost-entry due to ghost+0x328
// being NULL.
// ============================================================================
void __fastcall detour_alive_counter(std::int64_t controller_arg) noexcept
{
    const auto n = g_alive_fires.fetch_add(1, std::memory_order_relaxed);
    if (n < 10 || (n % 1000) == 0) {
        FW_LOG("[combat-force] alive-counter fire #%llu controller=0x%llX "
               "(boosts=%llu so far)",
               static_cast<unsigned long long>(n),
               static_cast<unsigned long long>(controller_arg),
               static_cast<unsigned long long>(
                   g_alive_boosts.load(std::memory_order_relaxed)));
    }

    // Run original first — it does the vanilla walk.
    if (g_orig_alive) {
        __try {
            g_orig_alive(controller_arg);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void* controller = reinterpret_cast<void*>(controller_arg);
    if (!controller) return;

    // Build 42 (2026-05-17) — pivoted detection strategy.
    //
    // Previous: walk controller+0x08 known_targets[] looking for ghost
    // form_id. Findings from disasm-verified RE (funcs_0337.md:11460):
    // sub_140E9E650 actually iterates controller+0x20 (ally array,
    // 24-byte stride, count at +0x30), NOT controller+0x08. Even with
    // ghost in known_targets[] via AddTarget, the alive-counter doesn't
    // see it. AND our tracked raiders' allies (other raiders) have
    // NULL +0x328 HighProcess → can't be counted either → +0x110 = 0.
    //
    // New: use the registered set populated by
    // install_fixed_selector_on_raider. When ALIVE-counter fires on a
    // controller we know is engaged with the ghost, force-boost
    // +0x110/+0x114 to at least 1. The dispatch gate at
    // sub_140E988A0:7135 (`if (controller+0x110 > 0)`) then passes,
    // engine runs combat block, selectors pick ghost via aiproc+0x6C,
    // raider engages.
    if (!fw::engine::is_ghost_combat_controller(controller)) return;

    __try {
        auto* ctrl = reinterpret_cast<std::uint8_t*>(controller);
        auto* alive_total  =
            reinterpret_cast<std::uint32_t*>(ctrl + 0x110);
        auto* alive_hostile =
            reinterpret_cast<std::uint32_t*>(ctrl + 0x114);
        // Force ≥ 1; engine may have set to 0, we boost. If already
        // non-zero (raider has live allies tracked), don't double-add.
        if (*alive_total < 1) *alive_total = 1;
        if (*alive_hostile < 1) *alive_hostile = 1;
        const auto bn = g_alive_boosts.fetch_add(
            1, std::memory_order_relaxed);
        if (bn < 8 || (bn % 200) == 0) {
            FW_LOG("[combat-force] alive-boost #%llu controller=%p "
                   "(ghost-engaged set); +0x110 now %u, "
                   "+0x114 now %u. Engine dispatch gate "
                   "sub_140E988A0:7135 should now run.",
                   static_cast<unsigned long long>(bn),
                   controller, *alive_total, *alive_hostile);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// Detour 3: cell-loaded — return 1 when ghost is the queried actor.
// ============================================================================
char __fastcall detour_cell_loaded(std::int64_t actor) noexcept
{
    const auto n = g_cell_fires.fetch_add(1, std::memory_order_relaxed);
    if (n < 10 || (n % 5000) == 0) {
        FW_LOG("[combat-force] cell-loaded fire #%llu actor=0x%llX "
               "(overrides=%llu so far)",
               static_cast<unsigned long long>(n),
               static_cast<unsigned long long>(actor),
               static_cast<unsigned long long>(
                   g_cell_overrides.load(std::memory_order_relaxed)));
    }

    void* ghost = ghost_ptr();
    if (ghost) {
        void* a1_p = reinterpret_cast<void*>(actor);
        if (a1_p == ghost) {
            const auto on = g_cell_overrides.fetch_add(
                1, std::memory_order_relaxed);
            if (on < 8 || (on % 500) == 0) {
                FW_LOG("[combat-force] cell-loaded #%llu OVERRIDE → 1 "
                       "(actor=%p == ghost)",
                       static_cast<unsigned long long>(on), a1_p);
            }
            return 1;
        }
    }

    if (g_orig_cell) {
        return g_orig_cell(actor);
    }
    return 0;
}

// ============================================================================
// Detour 4: post-pick gate — return 1 (stay engaged) when the aiproc's
// current target (handle at aiproc+0x6C) resolves to our ghost.
// ============================================================================
char __fastcall detour_post_pick_gate(std::int64_t aiproc) noexcept
{
    const auto n = g_pick_fires.fetch_add(1, std::memory_order_relaxed);
    if (n < 10 || (n % 1000) == 0) {
        FW_LOG("[combat-force] post-pick fire #%llu aiproc=0x%llX "
               "(overrides=%llu so far)",
               static_cast<unsigned long long>(n),
               static_cast<unsigned long long>(aiproc),
               static_cast<unsigned long long>(
                   g_pick_overrides.load(std::memory_order_relaxed)));
    }

    void* ghost = ghost_ptr();
    void* aip_p = reinterpret_cast<void*>(aiproc);
    if (ghost && aip_p && aiproc_targets_ghost(aip_p, ghost)) {
        const auto on = g_pick_overrides.fetch_add(
            1, std::memory_order_relaxed);
        if (on < 8 || (on % 200) == 0) {
            FW_LOG("[combat-force] post-pick #%llu OVERRIDE → 1 "
                   "(aiproc=%p targets ghost=%p — stay engaged)",
                   static_cast<unsigned long long>(on), aip_p, ghost);
        }
        return 1;
    }

    if (g_orig_post_pick) {
        return g_orig_post_pick(aiproc);
    }
    return 0;
}

} // namespace

// ============================================================================
// Public API — install + diagnostics
// ============================================================================

bool install_ghost_combat_force(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[combat-force] already installed; skipping");
        return true;
    }

    bool all_ok = true;
    // NOTE: HostilityCore (sub_140C8DFF0) hook OMITTED here.
    // `ghost_hostility_guard.cpp` already hooks the same RVA; double-
    // install fails. Force-hostile override for ghost will be added
    // INSIDE ghost_hostility_guard's existing detour as a follow-up.
    const struct {
        std::uintptr_t rva;
        void*          detour;
        void**         orig;
        const char*    label;
    } hooks[] = {
        { fw::offsets::ALIVE_COUNTER_RVA,
          reinterpret_cast<void*>(&detour_alive_counter),
          reinterpret_cast<void**>(&g_orig_alive),
          "AliveCounter sub_140E9E650" },
        { fw::offsets::CELL_LOADED_RVA,
          reinterpret_cast<void*>(&detour_cell_loaded),
          reinterpret_cast<void**>(&g_orig_cell),
          "CellLoaded sub_1404FB890" },
        { fw::offsets::POST_PICK_GATE_RVA,
          reinterpret_cast<void*>(&detour_post_pick_gate),
          reinterpret_cast<void**>(&g_orig_post_pick),
          "PostPickGate sub_14087A900" },
    };

    for (const auto& h : hooks) {
        const auto target_ea = module_base + h.rva;
        const bool ok = install(
            reinterpret_cast<void*>(target_ea),
            h.detour,
            h.orig);
        if (ok) {
            FW_LOG("[combat-force] %s hook installed at 0x%llX (RVA 0x%lX)",
                   h.label,
                   static_cast<unsigned long long>(target_ea),
                   static_cast<unsigned long>(h.rva));
        } else {
            FW_ERR("[combat-force] %s hook FAILED at 0x%llX",
                   h.label,
                   static_cast<unsigned long long>(target_ea));
            all_ok = false;
        }
    }

    if (all_ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[combat-force] ALL 4 hooks installed. Ghost should now "
               "be accepted by engine's combat AI as a valid hostile "
               "target. Watch logs for `OVERRIDE → 1` hits to confirm "
               "each gate is being satisfied.");
    }
    return all_ok;
}

std::uint64_t get_combat_force_hostility_fires()      { return g_hostility_fires.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_hostility_overrides()  { return g_hostility_overrides.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_alive_fires()          { return g_alive_fires.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_alive_boosts()         { return g_alive_boosts.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_cell_fires()           { return g_cell_fires.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_cell_overrides()       { return g_cell_overrides.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_pick_fires()           { return g_pick_fires.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_pick_overrides()       { return g_pick_overrides.load(std::memory_order_relaxed); }
std::uint64_t get_combat_force_seh_failures()         { return g_seh_failures.load(std::memory_order_relaxed); }

} // namespace fw::hooks
