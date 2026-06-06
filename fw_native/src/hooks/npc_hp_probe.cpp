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

// InCombat gate (defence-in-depth for the first-shot capture). True iff the local
// Actor has the engine InCombat bit set (Actor+0x2D0 & 0x4000) — the aggro shot
// itself sets it, so it is already true on the frame we capture; passive damage to
// a settler/companion/critter leaves it clear → those are NOT pooled. Faults → false.
constexpr std::uint32_t ACTOR_INCOMBAT_BIT = 0x4000u;
bool safe_actor_in_combat(const void* actor) noexcept {
    if (!actor) return false;
    __try {
        const std::uint32_t flags = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::ACTOR_FLAGS_720_OFF);
        return (flags & ACTOR_INCOMBAT_BIT) != 0u;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return false;
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

// ABSOLUTE max value via the AVO vtable (GetMaxValue) — EXACTLY the divisor the
// enemy-bar fraction sub_140C63130 uses (vt+0x10). PROVEN by disasm: it takes ONE
// arg (avo only) and returns a FLOAT (text_0137.asm:12232 — ucomiss/divss). The
// earlier double-return read mangled the float-in-xmm0 to ~0 (the GetMax==0 bug).
// Whatever it returns, the bar divides by it, so target = thisMax * pool_frac
// always renders pool_frac. < 0 on fault. re/hpbar_avo_fix_AGENT.md.
float safe_avo_max_value(const void* actor) noexcept {
    if (!actor) return -1.0f;
    __try {
        const std::uint8_t* avo = reinterpret_cast<const std::uint8_t*>(actor)
            + fw::offsets::ACTOR_AVOWNER_OFF;
        const void* const* vtbl =
            *reinterpret_cast<const void* const* const*>(avo);
        using GetMaxFn = float (__fastcall*)(const void*);   // (avo) -> float, 1-arg
        GetMaxFn fn = reinterpret_cast<GetMaxFn>(
            vtbl[fw::offsets::AVOWNER_GET_MAX_VTBL / sizeof(void*)]);   // slot[2] = byte 0x10
        return fn(avo);                                      // NO second arg, NO double read
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return -1.0f;
    }
}

// The Health ActorValueInfo* (same singleton for every actor). Prefer the one
// hp_probe already learned; fall back to the engine AV registry getter
// sub_140263120()[27] so the set works even on a client that never dealt Health
// damage itself (the non-owner "just aiming" case). Cached after first resolve.
constexpr std::uintptr_t AV_REGISTRY_RVA = 0x00263120;  // sub_140263120 → &AVInfo[125]
std::atomic<const void*> g_health_avinfo_cached{nullptr};

const void* resolve_health_avinfo() noexcept {
    const void* learned = g_health_form.load(std::memory_order_relaxed);
    if (learned) return learned;
    const void* cached = g_health_avinfo_cached.load(std::memory_order_relaxed);
    if (cached) return cached;
    const std::uintptr_t base = g_module_base.load(std::memory_order_relaxed);
    if (!base) return nullptr;
    __try {
        using AvRegFn = const void* const* (__fastcall*)();
        AvRegFn fn = reinterpret_cast<AvRegFn>(base + AV_REGISTRY_RVA);
        const void* const* arr = fn();
        if (!arr) return nullptr;
        const void* hf = arr[27];                 // [27] = Health (NOT [1] = ActionPoints)
        g_health_avinfo_cached.store(hf, std::memory_order_relaxed);
        return hf;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
}

// SEH-caged call of the ORIGINAL funnel (g_orig = MinHook trampoline, NOT the
// detour) → the value write bypasses our own detour entirely, so there is no
// re-entry/recursion and no spurious capture or clamp can fire.
void safe_call_funnel(void* actor, void* health_form, float delta) noexcept {
    if (!g_orig || !actor || !health_form) return;
    __try {
        g_orig(actor, HEALTH_AP_COLUMN, health_form, delta, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
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

    // Health-cell snapshot BEFORE the write — read whenever the av/delta window
    // matches (NOT gated on tracked) so the post-write `applied>0` Health detection
    // works for an untracked (first-shot) fid too.
    const bool  av_in_window = (avIdx == HEALTH_AP_COLUMN && a1 && delta < 0.0f);
    const float old_cell     = av_in_window ? safe_health_sum(a1) : 0.0f;

    // The write (clamped or original).
    const std::int64_t result = g_orig
        ? g_orig(a1, avIdx, a3, use_delta, source)
        : 0;

    // CAPTURE / DETECT — runs for ANY actor in the av/delta window, tracked or not.
    // First-shot fix: the aggro shot lands BEFORE the NPC is in the local ownership
    // mirror (tracked=false), so it must still be claimed. The CLAMP stays strictly
    // tracked-only (above); only the CAPTURE is widened, gated by InCombat.
    if (av_in_window) {
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

            // CAPTURE: claim by_player Health damage REGARDLESS of `tracked`, so the
            // aggro (first) shot is reported. NO client InCombat gate — the raiders'
            // InCombat bit reads 0 (cleared on the mirror by the perception walker),
            // so gating on it dropped the real captures. Friendlies are excluded
            // SERVER-side: a pool is only ever born from an InCombat-gated NPC_OBSERVED,
            // so a stray settler/companion claim is stashed then expires, never pooled.
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
                           "src=0x%08X by_player=%d tracked=%d incombat=%d clamped=%d",
                           static_cast<unsigned long long>(n), fid,
                           static_cast<double>(abs_after),
                           static_cast<double>(damage), static_cast<double>(max_hp),
                           src_fid, by_player ? 1 : 0, tracked ? 1 : 0,
                           safe_actor_in_combat(a1) ? 1 : 0, clamped ? 1 : 0);
                }
            }
        }
    }
    return result;
}

} // namespace

// vita-locale-dal-pool — set the actor's LOCAL Health so the vanilla enemy-health
// bar (which reads GetCurrent(Health)/GetMax via sub_140C63130) renders the SHARED
// pool fraction. target_current = AVO.GetMax * (pool_cur/pool_max) — the GetMax
// cancels in the bar's own division, so the displayed % == pool_frac regardless of
// the actor's true max. Floored ≥1 (never 0 → no local death cascade; death stays
// server-driven). Applied as a delta through the ORIGINAL funnel (g_orig → no
// detour re-entry). MAIN THREAD ONLY (AVO vtable deref + funnel are main-thread).
std::atomic<std::uint64_t> g_pool_applies{0};

void apply_pool_health_to_actor(void* actor, float pool_cur, float pool_max) noexcept {
    if (!actor || pool_max <= 0.0f) return;
    const auto n = g_pool_applies.fetch_add(1, std::memory_order_relaxed);
    const bool dolog = (n < 40 || (n % 500) == 0);
    const std::uint32_t fid = safe_read_u32(actor, fw::offsets::FORMID_OFF);
    void* hf = const_cast<void*>(resolve_health_avinfo());
    if (!hf) {
        if (dolog) FW_LOG("[hp-pool] #%llu fid=0x%08X SKIP: no Health AVInfo "
                          "(learned=null + registry getter failed)",
                          static_cast<unsigned long long>(n), fid);
        return;
    }
    const float cur = safe_avo_current_hp(actor, hf);
    if (cur < 0.0f) {
        if (dolog) FW_LOG("[hp-pool] #%llu fid=0x%08X SKIP: GetCurrent faulted",
                          static_cast<unsigned long long>(n), fid);
        return;
    }
    // MAX = the permanent base Health = GetCurrent(absolute) - cell_modifier_sum.
    // This is the bar's own divisor (GetMax) WITHOUT calling the AVO GetMax leaf
    // (which faults/zeroes under every signature we tried). It is the exact math the
    // capture path already uses for max_hp (abs - cell). cell ≤ 0 when damaged.
    const float cell = safe_health_sum(actor);
    const float maxv = cur - cell;
    if (maxv <= 0.0f) {
        if (dolog) FW_LOG("[hp-pool] #%llu fid=0x%08X SKIP: max<=0 (cur=%.1f cell=%.1f)",
                          static_cast<unsigned long long>(n), fid,
                          static_cast<double>(cur), static_cast<double>(cell));
        return;
    }
    float frac = pool_cur / pool_max;
    if (frac < 0.0f) frac = 0.0f;
    if (frac > 1.0f) frac = 1.0f;
    float target = maxv * frac;
    if (target < 1.0f)  target = 1.0f;            // never 0 (empty bar = death-cascade risk)
    if (target > maxv)  target = maxv;
    const float delta = target - cur;
    if (delta > -0.5f && delta < 0.5f) {
        if (dolog) FW_LOG("[hp-pool] #%llu fid=0x%08X noop: cur=%.1f≈target=%.1f "
                          "max=%.1f (pool %.0f/%.0f)",
                          static_cast<unsigned long long>(n), fid,
                          static_cast<double>(cur), static_cast<double>(target),
                          static_cast<double>(maxv),
                          static_cast<double>(pool_cur), static_cast<double>(pool_max));
        return;
    }
    safe_call_funnel(actor, hf, delta);
    if (dolog) {
        const float after = safe_avo_current_hp(actor, hf);   // did the write land?
        FW_LOG("[hp-pool] #%llu fid=0x%08X SET cur %.1f->%.1f (target=%.1f max=%.1f "
               "pool %.0f/%.0f frac=%.2f delta=%.1f)",
               static_cast<unsigned long long>(n), fid,
               static_cast<double>(cur), static_cast<double>(after),
               static_cast<double>(target), static_cast<double>(maxv),
               static_cast<double>(pool_cur), static_cast<double>(pool_max),
               static_cast<double>(frac), static_cast<double>(delta));
    }
}

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
