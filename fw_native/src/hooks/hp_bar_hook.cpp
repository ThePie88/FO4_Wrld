// ============================================================================
// HP-bar sync (vita-locale-dal-pool). The enemy-health bar value comes from the
// crosshair/auto-aim target's LOCAL Health AV (sub_140C63130 = GetCurrent/GetMax).
// N3 keeps a SHARED SERVER POOL; the server broadcasts it (NPC_HP_POOL_BCAST →
// set_npc_pool_hp). Instead of fighting the opaque HUD widget value pipeline
// (3 failed builds: the value-latch Invoke fires ~3×/session, not per-frame), we
// drive the bar through the engine's OWN path: set the mirror's LOCAL Health AV =
// pool fraction (deferred to the MAIN thread → apply_pool_health_to_actor in
// npc_hp_probe), and the vanilla bar reads it + repaints live on every change.
//
// One hook remains:
//   G2 (sub_140A34090) — FORCE the bar VISIBLE for a tracked raider even when it
//      is the neutral non-owner mirror (hostility-gated off otherwise). HUD-only
//      single caller → crash-safe (re/hpbar_minstate_AGENT.md).
//   The VALUE comes from the local-Health set, not a widget hook anymore.
// re/hpbar_localhp_AGENT.md (vita-locale-dal-pool, VALIDATED).
// ============================================================================
#include "hp_bar_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"   // enqueue_npc_pool_health (main-thread Health set)
#include "ownership_manager.h"         // is_owner_of / is_non_owner_tracked

namespace fw::hooks {

namespace {

std::atomic<std::uintptr_t> g_module_base{0};
std::atomic<bool>           g_enabled{true};

// ── G2 — FORCE the enemy bar VISIBLE for a tracked raider via the producer's own
// show/hide switch sub_140A34090. The neutral non-owner mirror fails G2's
// hostility clauses → bar hides; we return 1 when the bar's currently-latched
// target (resolved as G2 does: *(QWORD*)sub_140A351F0(a1[1]) → actor+0x14) is a
// tracked raider. G2 has a SINGLE caller (the HUD producer): returning 1
// allocates nothing, never touches combat → off the crash rap-sheet.
using ProducerShowFn = bool (__fastcall*)(std::uint64_t* a1);
ProducerShowFn             g_orig_g2 = nullptr;
std::atomic<std::uint64_t> g_g2_forces{0};

constexpr std::uintptr_t PRODUCER_SHOW_RVA = 0x00A34090;  // sub_140A34090 (G2 show/hide switch)
constexpr std::uintptr_t LOOKUP_REF_RVA    = 0x00A351F0;  // sub_140A351F0 (latched handle → holder)

// SEH-caged: the FormID of the producer's currently-latched bar target, exactly
// as G2 resolves it — *(QWORD*)sub_140A351F0(a1[1]) = actor, +0x14 = fid.
std::uint32_t resolve_g2_target_fid(std::uint64_t* a1) noexcept {
    const std::uintptr_t base = g_module_base.load(std::memory_order_relaxed);
    if (!base || !a1) return 0;
    __try {
        using LookupFn = void* (__fastcall*)(std::uint64_t);
        const auto lookup = reinterpret_cast<LookupFn>(base + LOOKUP_REF_RVA);
        void* holder = lookup(a1[1]);
        if (!holder) return 0;
        void* actor = *reinterpret_cast<void* const*>(holder);
        if (!actor) return 0;
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) + fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// LIVE REFRESH — the HUD producer sub_140A32EA0 recomputes the bar percent from the
// target's live Health every frame but DISPATCHES the repaint only on a change of its
// cached percent (funcs_0266.md:13248-13290). So a remote pool→local-Health change that
// equals the prior dispatched value, or that the producer's per-frame poll happens to
// miss, leaves the bar stale. We poison the producer's percent cache (producer_state+184,
// where producer_state == the G2 arg's a1[0] == HUDMenu+1472) with a sentinel so the
// next compare ALWAYS misses → it dispatches EVERY frame the bar shows a tracked raider →
// the bar re-reads local Health (= pool) live. One float in our own hook, SEH-caged.
// re/hpbar_refresh_AGENT.md. Kill-switch: kHpBarLiveRefresh.
static constexpr bool kHpBarLiveRefresh = true;
constexpr std::size_t PRODUCER_PERCENT_CACHE_OFF = 184;  // producer_state + 0xB8

void safe_poison_producer_percent(std::uint64_t* a1) noexcept {
    if (!a1) return;
    __try {
        const std::uintptr_t producer_state = static_cast<std::uintptr_t>(a1[0]);
        if (producer_state < 0x10000) return;   // sanity: must be a plausible pointer
        *reinterpret_cast<float*>(producer_state + PRODUCER_PERCENT_CACHE_OFF) = -1.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

bool __fastcall detour_g2_show(std::uint64_t* a1) {
    const bool orig = g_orig_g2 ? g_orig_g2(a1) : false;
    if (!g_enabled.load(std::memory_order_relaxed)) return orig;
    const std::uint32_t fid = resolve_g2_target_fid(a1);
    if (fid == 0 || fid == 0xFFFFFFFFu) return orig;
    const bool tracked = fw::ownership::is_owner_of(fid) ||
                         fw::ownership::is_non_owner_tracked(fid);
    if (!tracked) return orig;
    // Force a per-frame repaint for the tracked raider so the bar tracks the live
    // pool-driven local Health (the bar WILL show — orig=true or we force it below).
    if (kHpBarLiveRefresh) safe_poison_producer_percent(a1);
    if (!orig) {
        const auto n = g_g2_forces.fetch_add(1, std::memory_order_relaxed);
        if (n < 30 || (n % 500) == 0) {
            FW_LOG("[hp-bar] G2 force-show fid=0x%08X (bar visible on tracked mirror)", fid);
        }
        return true;   // force the bar visible for the neutral mirror
    }
    return orig;
}

} // namespace

std::atomic<std::uint64_t> g_pool_rx{0};

void set_npc_pool_hp(std::uint32_t form_id, float hp_cur, float hp_max) noexcept {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    const auto n = g_pool_rx.fetch_add(1, std::memory_order_relaxed);
    if (n < 40 || (n % 500) == 0) {
        FW_LOG("[hp-bar] RX pool fid=0x%08X cur=%.0f/%.0f -> enqueue local-Health set",
               form_id, static_cast<double>(hp_cur), static_cast<double>(hp_max));
    }
    // vita-locale-dal-pool: drive the NPC's LOCAL Health = pool fraction on the
    // MAIN thread → the vanilla enemy-health bar reads it + repaints live. Runs on
    // the net RX thread, so we only ENQUEUE here (the engine AVO call is deferred).
    fw::dispatch::PendingNpcPoolHealth op{form_id, hp_cur, hp_max};
    fw::dispatch::enqueue_npc_pool_health(op);
}

bool install_npc_hp_bar(std::uintptr_t module_base) {
    g_module_base.store(module_base, std::memory_order_release);
    void* g2 = reinterpret_cast<void*>(module_base + PRODUCER_SHOW_RVA);
    const bool ok = install(g2, reinterpret_cast<void*>(&detour_g2_show),
                            reinterpret_cast<void**>(&g_orig_g2));
    if (ok) {
        FW_LOG("[hp-bar] producer show-gate hook @0x%llX (RVA 0x%lX) — force the enemy "
               "bar visible on tracked raiders; value via local-Health-from-pool",
               static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(g2)),
               static_cast<unsigned long>(PRODUCER_SHOW_RVA));
    } else {
        FW_ERR("[hp-bar] producer show-gate install FAILED at 0x%llX",
               static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(g2)));
    }
    return ok;
}

std::uint64_t get_hp_bar_overrides() noexcept {
    return g_g2_forces.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
