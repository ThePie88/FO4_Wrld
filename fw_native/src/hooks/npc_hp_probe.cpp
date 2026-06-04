// ============================================================================
// N3 (shared HP) — HP-funnel hook on sub_140CC9650. See npc_hp_probe.h.
//
// Round 2: CAPTURE + CLAMP.
//   CAPTURE  — for tracked raiders, when the local player deals Health damage,
//              report the FINAL applied amount (-delta) + the raider max HP so
//              the server runs ONE shared pool (validated round 1).
//   CLAMP    — keep the raider's ABSOLUTE Health >= HP_FLOOR so the engine never
//              starts its death cascade. Death is then SERVER-driven only (the
//              server fires NPC_DEATH when the shared pool hits 0; the existing
//              N2 death-sync applies the kill). This stops a raider from dying
//              on whichever client solo-deals its local HP — the boss must die
//              from the COMBINED pool. [Agent-2 RE: clamp is the safe gate, NOT
//              gating Actor::Kill, which re-fires forever + leaves a ragdolled
//              live actor.]
//
// Knowing PRE-write that a write targets Health (needed to clamp before the
// engine writes <= 0) is done by LEARNING the Health AVInfo pointer the first
// time a write actually changes the Health cell (the proven round-1 post-write
// trick) — no extra engine call (no sub_140263120). The first-ever Health hit
// can't clamp yet (form not learned), but it captures, and one hit never brings
// a full-HP raider to 0.
//
// All reads SEH-caged in helpers; the detour stays __try-free (C2712-proof).
// Kill-switches: set_hp_capture_enabled / set_hp_clamp_enabled.
// ============================================================================
#include "npc_hp_probe.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"       // N3 — enqueue_npc_damage_claim (shared HP pool)
#include "ownership_manager.h"   // is_owner_of / is_non_owner_tracked
#include "npc_ai_suppress.h"     // is_dying (don't clamp a raider being killed)

namespace fw::hooks {

namespace {

using HpFunnelFn = std::int64_t (__fastcall*)(void* a1, int avIdx, void* a3,
                                              float delta, void* source);
HpFunnelFn g_orig = nullptr;

std::atomic<std::uintptr_t> g_module_base{0};
std::atomic<bool>           g_enabled{true};          // diagnostic logging
std::atomic<bool>           g_capture_enabled{true};  // report damage to the pool
std::atomic<bool>           g_clamp_enabled{true};    // round 2 — floor local HP
std::atomic<const void*>    g_health_form{nullptr};   // learned Health AVInfo*
std::atomic<std::uint64_t>  g_fires{0};
std::atomic<std::uint64_t>  g_captures{0};
std::atomic<std::uint64_t>  g_clamps{0};
std::atomic<std::uint64_t>  g_seh{0};

constexpr int   HEALTH_AP_COLUMN = 2;     // avIdx for the HP/AP runtime column
constexpr float HP_FLOOR         = 1.0f;  // keep absolute Health >= this

// ---- SEH-caged read helpers (the detour stays __try-free → C2712-proof) -----

std::uint32_t safe_read_u32(const void* base, std::size_t off) noexcept {
    if (!base) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return 0xFFFFFFFFu;
    }
}

const void* safe_read_ptr(const void* base, std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
}

// Health MODIFIER sum = the 3 floats in the Health cell (Actor+0x444): 0 at
// full, negative as damage lands. NOT the absolute HP (base lives in the AVO).
float safe_health_sum(const void* actor) noexcept {
    if (!actor) return -1.0f;
    __try {
        const float* c = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::ACTOR_HEALTH_CELL_OFF);
        return c[0] + c[1] + c[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return -1.0f;
    }
}

// ABSOLUTE current Health via the AVO getter (vtable +8 = GetActorValue(form)).
// Engine-thread, the same read the engine does constantly. < 0 on fault.
float safe_avo_current_hp(const void* actor, void* health_form) noexcept {
    if (!actor || !health_form) return -1.0f;
    __try {
        const std::uint8_t* avo = reinterpret_cast<const std::uint8_t*>(actor)
            + fw::offsets::ACTOR_AVOWNER_OFF;
        const void* const* vtbl =
            *reinterpret_cast<const void* const* const*>(avo);
        using GetAvFn = float (__fastcall*)(const void*, void*);
        GetAvFn fn = reinterpret_cast<GetAvFn>(
            vtbl[fw::offsets::AVOWNER_GET_CURRENT_VTBL / sizeof(void*)]);
        return fn(avo, health_form);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return -1.0f;
    }
}

bool fid_is_tracked(std::uint32_t fid) noexcept {
    if (fid == 0 || fid == 0xFFFFFFFFu) return false;
    return fw::ownership::is_owner_of(fid) ||
           fw::ownership::is_non_owner_tracked(fid);
}

std::int64_t __fastcall detour_hp_funnel(void* a1, int avIdx, void* a3,
                                         float delta, void* source) {
    // Cheap pre-gate: HP/AP column, a damage delta, on a tracked raider.
    bool          tracked = false;
    std::uint32_t fid     = 0;
    if (avIdx == HEALTH_AP_COLUMN && a1 && delta < 0.0f &&
        (g_enabled.load(std::memory_order_relaxed) ||
         g_capture_enabled.load(std::memory_order_relaxed) ||
         g_clamp_enabled.load(std::memory_order_relaxed))) {
        fid = safe_read_u32(a1, fw::offsets::FORMID_OFF);
        tracked = fid_is_tracked(fid);
    }

    // PRE-WRITE: when we already KNOW a3 is the Health form, decide the clamp
    // before the engine writes a possibly-lethal value. Skip while the raider is
    // being killed (server death applying) so the corpse isn't pinned alive.
    float use_delta    = delta;
    float abs_before   = -1.0f;
    const bool known_health =
        tracked && (a3 == g_health_form.load(std::memory_order_relaxed));
    bool clamped = false;
    if (known_health && g_clamp_enabled.load(std::memory_order_relaxed) &&
        !is_dying(fid)) {
        abs_before = safe_avo_current_hp(a1, a3);
        if (abs_before > 0.0f && (abs_before + delta) < HP_FLOOR) {
            use_delta = HP_FLOOR - abs_before;       // -> new absolute == HP_FLOOR
            if (use_delta > 0.0f) use_delta = 0.0f;  // never convert damage to heal
            clamped = true;
        }
    }

    const float old_cell = tracked ? safe_health_sum(a1) : 0.0f;

    // The write (clamped or original).
    const std::int64_t result = g_orig
        ? g_orig(a1, avIdx, a3, use_delta, source)
        : 0;

    if (tracked) {
        const float new_cell = safe_health_sum(a1);
        const float applied  = old_cell - new_cell;   // >0 ⟺ Health cell changed

        // Learn the Health AVInfo the first time a write actually changes the
        // Health cell (proven round-1 detection) → enables the pre-write clamp.
        if (applied > 0.0f &&
            g_health_form.load(std::memory_order_relaxed) == nullptr) {
            g_health_form.store(a3, std::memory_order_relaxed);
            FW_LOG("[hp-probe] learned Health AVInfo=%p (fid=0x%08X)", a3, fid);
        }

        const bool is_health = known_health || (applied > 0.0f);
        if (is_health) {
            // Absolute AFTER the write (reuse the pre-read if we have it).
            float abs_after = (abs_before >= 0.0f)
                ? (abs_before + use_delta)
                : safe_avo_current_hp(a1, a3);
            float max_hp = (abs_after > 0.0f) ? (abs_after - new_cell) : 0.0f;
            if (max_hp < abs_after) max_hp = abs_after;

            const std::uint32_t src_fid = source
                ? safe_read_u32(source, fw::offsets::FORMID_OFF) : 0u;
            const std::uintptr_t base = g_module_base.load(std::memory_order_relaxed);
            const void* player = base
                ? safe_read_ptr(reinterpret_cast<const void*>(base),
                                fw::offsets::PLAYER_SINGLETON_RVA) : nullptr;
            const bool  by_player = (source != nullptr && source == player);
            const float damage    = -delta;   // INTENDED final dmg (== applied unclamped)

            if (g_capture_enabled.load(std::memory_order_relaxed) && by_player &&
                damage > 0.0f && damage < 1.0e6f) {
                fw::net::client().enqueue_npc_damage_claim(fid, damage, max_hp);
                g_captures.fetch_add(1, std::memory_order_relaxed);
            }

            if (clamped) {
                const auto cn = g_clamps.fetch_add(1, std::memory_order_relaxed);
                if (cn < 60 || (cn % 100) == 0) {
                    FW_LOG("[hp-clamp] #%llu fid=0x%08X abs=%.1f delta=%.1f -> "
                           "floored use_delta=%.1f (max=%.0f) — server drives death",
                           static_cast<unsigned long long>(cn), fid,
                           static_cast<double>(abs_before),
                           static_cast<double>(delta),
                           static_cast<double>(use_delta),
                           static_cast<double>(max_hp));
                }
            }

            if (g_enabled.load(std::memory_order_relaxed)) {
                const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
                if (n < 60 || (n % 100) == 0) {
                    FW_LOG("[hp-probe] #%llu fid=0x%08X abs=%.1f dmg=%.2f max=%.0f "
                           "src=0x%08X by_player=%d clamped=%d",
                           static_cast<unsigned long long>(n), fid,
                           static_cast<double>(abs_after),
                           static_cast<double>(damage), static_cast<double>(max_hp),
                           src_fid, by_player ? 1 : 0, clamped ? 1 : 0);
                }
            }
        }
    }
    return result;
}

} // namespace

bool install_npc_hp_probe(std::uintptr_t module_base) {
    g_module_base.store(module_base, std::memory_order_release);
    void* target = reinterpret_cast<void*>(
        module_base + fw::offsets::ACTOR_HP_FUNNEL_RVA);
    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_hp_funnel),
        reinterpret_cast<void**>(&g_orig));
    if (ok) {
        FW_LOG("[hp-probe] HP-funnel hook installed at 0x%llX (RVA 0x%lX) — "
               "N3 round2: CAPTURE (final dmg + max) + CLAMP (floor abs HP >= %.0f; "
               "server drives death)",
               static_cast<unsigned long long>(
                   reinterpret_cast<std::uintptr_t>(target)),
               static_cast<unsigned long>(fw::offsets::ACTOR_HP_FUNNEL_RVA),
               static_cast<double>(HP_FLOOR));
    } else {
        FW_ERR("[hp-probe] install FAILED at 0x%llX",
               static_cast<unsigned long long>(
                   reinterpret_cast<std::uintptr_t>(target)));
    }
    return ok;
}

void set_hp_probe_enabled(bool on) noexcept {
    g_enabled.store(on, std::memory_order_relaxed);
}
void set_hp_capture_enabled(bool on) noexcept {
    g_capture_enabled.store(on, std::memory_order_relaxed);
}
void set_hp_clamp_enabled(bool on) noexcept {
    g_clamp_enabled.store(on, std::memory_order_relaxed);
}
std::uint64_t get_hp_probe_fires() noexcept {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_hp_probe_captures() noexcept {
    return g_captures.load(std::memory_order_relaxed);
}
std::uint64_t get_hp_probe_clamps() noexcept {
    return g_clamps.load(std::memory_order_relaxed);
}
std::uint64_t get_hp_probe_seh() noexcept {
    return g_seh.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
