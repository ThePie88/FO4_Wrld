#include "npc_ai_suppress.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "../engine/engine_calls.h"

namespace fw::hooks {

namespace {

// Engine signature (from re/B6.5_npc_pipeline_AGENT_A.md):
//   void __fastcall sub_140C636A0(Actor* this, float simTime);
using ActorUpdatePerFrameFn = void (*)(void* actor, float sim_time);

ActorUpdatePerFrameFn g_orig_actor_update_perframe = nullptr;

// Diagnostics. Relaxed because exact ordering doesn't matter; we only
// read these for periodic INFO snapshots. fetch_add at this volume
// (thousands per second) is cheap — single locked-xadd instruction.
std::atomic<std::uint64_t> g_suppress_fires{0};
std::atomic<std::uint64_t> g_passthrough_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

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
void __fastcall detour_actor_update_perframe(void* actor, float sim_time) {
    const std::uint32_t fid = safe_read_form_id(actor);

    // Step 1: always call original. The engine needs to run its
    // per-frame work for the actor (and future Ghost AI hooks rely on
    // the engine's natural pipeline continuing to fire).
    if (g_orig_actor_update_perframe) {
        g_orig_actor_update_perframe(actor, sim_time);
    }

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
    const auto target_ea =
        module_base + fw::offsets::ACTOR_UPDATE_PERFRAME_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_actor_update_perframe),
        reinterpret_cast<void**>(&g_orig_actor_update_perframe));
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

} // namespace fw::hooks
