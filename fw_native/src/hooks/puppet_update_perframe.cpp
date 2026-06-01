// ============================================================================
// DORMANT — 2026-05-17. `puppet_init()` is called at boot from install_all.cpp:64
// (resolves 10 engine fn pointers). But `puppet_update_perframe(actor, sim_time)`
// is NEVER called in production because:
//
//   `npc_ai_suppress.cpp::detour_actor_update_perframe` has:
//     constexpr bool bail_this_actor = false;
//
//   That `if (bail_this_actor)` block (lines ~593-640) was where puppet body
//   would have replaced the engine's vanilla Update_PerFrame. With the flag
//   forced false, vanilla AI runs every tick (no puppet replacement), and
//   puppet_update_perframe stays dead code paths.
//
// LOG PROOF: Client A `fw_native.log` 17:29-17:39 has the `[puppet] init at
// module_base=...` line (one-time at boot) but ZERO `[puppet] fire #N` lines.
// Puppet body never executes.
//
// WHY DISABLED:
//   B6.6w1 (2026-05-12 late evening, see npc_ai_suppress.cpp:597 comment block)
//   ROLLBACK from puppet body to vanilla passthrough. Live test showed puppet
//   body's InCombat triple-write + 9 vanilla fn calls (DeathFade, MountSwim,
//   TickRenderState, OnTickPostExtra, StaticBlockCheck, etc.) broke aggro:
//     - safe_force_in_combat_flag() overwrote Actor+0x2D0/+0x380/AIProcess+0x6C
//       every frame, racing the engine's combat brain.
//     - Puppet's anim-graph-dispatch step (step 9) deref'd uninit aiproc_inner
//       and AV'd deep inside engine code.
//
// KEEP-AS-IS RATIONALE:
//   The per-step __try cage + counters are the right post-mortem tool if
//   anyone ever revives the puppet approach. The 10 fn-ptr resolutions
//   establish stable RVAs for the "what does Update_PerFrame call internally"
//   sub-functions (useful reference for selectively bypassing parts of
//   the engine's per-actor tick).
// ============================================================================

#include "puppet_update_perframe.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../log.h"
#include "../offsets.h"

namespace fw::hooks {

namespace {

// ------------- Engine function pointer types ----------------------------

// sub_140C960C0 — Actor::ApplyDeathFadeAndDeferDeath(this, flag).
using DeathFadeFn        = void (*)(void* actor, int flag);
// sub_140C5AD90 — Actor::UpdateMountSwimFlags(this).
using MountSwimFn        = void (*)(void* actor);
// sub_140DA8F60 — BSAnimGraphMgr::PushUnprocessedEvents(gm).
using EventDrainFn       = void (*)(void* graphmgr);
// sub_140CE1720 — Actor::TickRenderState_PerFrame(this, sim_time).
using TickRenderStateFn  = void (*)(void* actor, float sim_time);
// sub_140C9B860 — Actor::ProcessShutdownTransition(this).
using ShutdownFn         = void (*)(void* actor);
// sub_140CEEBD0 — AIProcess::AnimGraph TickWithDelta(inner, actor, delta).
using AnimDispatchFn     = void (*)(void* aiproc_inner, void* actor, float delta);
// sub_140CEEB90 — AIProcess::AnimGraph TickIdle(inner, actor).
using AnimIdleDispatchFn = void (*)(void* aiproc_inner, void* actor);
// sub_140CF2290 — AIProcess::OnTickPostExtra(actor+8, actor).
using PostExtraTickFn    = void (*)(void* arg, void* actor);
// sub_140C65F50 — Actor::OnFrameStaticBlockCheck(actor).
using StaticBlockFn      = void (*)(void* actor);
// sub_140DC8170 — BSAnimGraphMgr::IsLoading(gm) → 0/1.
using GraphMgrIsLoadingFn = char (*)(void* graphmgr);

// vt[8] on BSAnimGraphMgr — `(gm, delta, ctx_struct*)`.
using GraphMgrUpdateFn   = void (*)(void* gm, float delta, void* ctx);
// vt[81] on Actor — UpdateLoadedRef(actor, bDeferred).
using ActorUpdateLoadedRefFn = void (*)(void* actor, char bDeferred);

// ------------- Resolved engine pointers (init-once) ---------------------

std::atomic<bool> g_initialized{false};

DeathFadeFn         g_death_fade        = nullptr;
MountSwimFn         g_mount_swim        = nullptr;
EventDrainFn        g_event_drain       = nullptr;
TickRenderStateFn   g_tick_render       = nullptr;
ShutdownFn          g_shutdown          = nullptr;
AnimDispatchFn      g_anim_disp_delta   = nullptr;
AnimIdleDispatchFn  g_anim_disp_idle    = nullptr;
PostExtraTickFn     g_post_extra        = nullptr;
StaticBlockFn       g_static_block      = nullptr;
GraphMgrIsLoadingFn g_gm_is_loading     = nullptr;

// ------------- Diagnostic counters --------------------------------------

std::atomic<std::uint64_t> g_puppet_fires{0};
std::atomic<std::uint64_t> g_puppet_seh{0};

// Per-step fault counters. The body has 11 logical steps; we wrap each
// one in its own __try so a fault inside (e.g.) the anim graph tick
// doesn't poison the timer decrement or the static-block call. The
// counter for step N increments when step N's __try catches.
constexpr int PUPPET_NUM_STEPS = 11;
std::atomic<std::uint64_t> g_step_seh[PUPPET_NUM_STEPS]{};

// ------------- SEH helpers ----------------------------------------------

static const void* safe_read_ptr(const void* base, std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

} // namespace

void puppet_init(std::uintptr_t mb) noexcept {
    if (g_initialized.exchange(true)) return;

    g_death_fade        = reinterpret_cast<DeathFadeFn>(
        mb + fw::offsets::PUPPET_DEATH_FADE_RVA);
    g_mount_swim        = reinterpret_cast<MountSwimFn>(
        mb + fw::offsets::PUPPET_MOUNT_SWIM_FLAGS_RVA);
    g_event_drain       = reinterpret_cast<EventDrainFn>(
        mb + fw::offsets::PUPPET_ANIM_EVENT_DRAIN_RVA);
    g_tick_render       = reinterpret_cast<TickRenderStateFn>(
        mb + fw::offsets::PUPPET_TICK_RENDER_STATE_RVA);
    g_shutdown          = reinterpret_cast<ShutdownFn>(
        mb + fw::offsets::PUPPET_SHUTDOWN_TRANSITION_RVA);
    g_anim_disp_delta   = reinterpret_cast<AnimDispatchFn>(
        mb + fw::offsets::PUPPET_ANIM_DISPATCH_DELTA_RVA);
    g_anim_disp_idle    = reinterpret_cast<AnimIdleDispatchFn>(
        mb + fw::offsets::PUPPET_ANIM_DISPATCH_IDLE_RVA);
    g_post_extra        = reinterpret_cast<PostExtraTickFn>(
        mb + fw::offsets::PUPPET_AIPROC_POST_EXTRA_RVA);
    g_static_block      = reinterpret_cast<StaticBlockFn>(
        mb + fw::offsets::PUPPET_STATIC_BLOCK_CHECK_RVA);
    g_gm_is_loading     = reinterpret_cast<GraphMgrIsLoadingFn>(
        mb + fw::offsets::PUPPET_GRAPHMGR_IS_LOADING_RVA);

    FW_LOG("[puppet] init at module_base=0x%llX — 10 engine fns resolved "
           "(replacement body ready)",
           static_cast<unsigned long long>(mb));
}

// Helper: run one step under its own __try. A fault is counted under
// the per-step counter and the first 5 are logged with the actor +
// sim_time. Returning to the caller after a fault — the next step runs.
//
// Variadic so the step body can contain commas (function call args).
#define PUPPET_STEP(step_idx, step_name, ...)                               \
    do {                                                                    \
        __try {                                                             \
            __VA_ARGS__                                                     \
        } __except (EXCEPTION_EXECUTE_HANDLER) {                            \
            const auto sn = g_step_seh[step_idx].fetch_add(                 \
                1, std::memory_order_relaxed);                              \
            g_puppet_seh.fetch_add(1, std::memory_order_relaxed);           \
            if (sn < 5) {                                                   \
                FW_ERR("[puppet] step %d (%s) SEH #%llu (actor=%p "         \
                       "sim_time=%.4f)",                                    \
                       (step_idx) + 1, (step_name),                         \
                       static_cast<unsigned long long>(sn),                 \
                       actor, sim_time);                                    \
            }                                                               \
        }                                                                   \
    } while (0)

// SEH-safe replacement body. Vanilla equivalent is `sub_140C636A0` for
// the KEEP-ALWAYS subset only — all AI decision callees are skipped.
// Mirrors §6 "MUST-CALL" list of the structural dossier.
//
// Each of the 11 steps runs inside its OWN __try. That way a fault in
// one (e.g. vt[81] read on a partially-loaded actor) doesn't skip the
// rest. Per-step counters identify which step is the troublemaker for
// post-mortem diagnosis. Critically: an unguarded exception propagating
// out of this function would unwind to the engine and crash. Per-step
// guards keep that contained.
void puppet_update_perframe(void* actor, float sim_time) noexcept {
    if (!actor) return;
    if (!g_initialized.load(std::memory_order_acquire)) return;

    const auto fire = g_puppet_fires.fetch_add(
        1, std::memory_order_relaxed);
    const bool first10 = fire < 10;

    auto* const a8 = reinterpret_cast<std::uint8_t*>(actor);

    // Step 1 — Death-fade / deferred-load bookkeeping.
    PUPPET_STEP(0, "death_fade",
        if (g_death_fade) g_death_fade(actor, 0);
    );

    // Step 2 — vt[81] Actor::UpdateLoadedRef(this, bDeferred=1).
    //   The vtable layout for THIS object isn't verified live; this
    //   call is the most likely candidate to fault on a fresh actor.
    PUPPET_STEP(1, "vt81_update_loaded_ref",
        void* const vtbl = const_cast<void*>(
            safe_read_ptr(actor, 0));
        if (vtbl) {
            auto* slot_addr = reinterpret_cast<std::uint8_t*>(vtbl)
                + fw::offsets::ACTOR_VT_UPDATELOADEDREF_OFF;
            auto fn = *reinterpret_cast<ActorUpdateLoadedRefFn*>(slot_addr);
            if (fn) fn(actor, 1);
        }
    );

    // Step 3 — Mount/swim flag sync (writes Actor+0x43C bits).
    PUPPET_STEP(2, "mount_swim",
        if (g_mount_swim) g_mount_swim(actor);
    );

    // Step 4 — Delta. Vanilla scales by global time-scale; for puppet
    //   simplicity we pass sim_time straight through. Not __try-wrapped:
    //   pure scalar math on stack.
    float dt = sim_time;
    if (dt < 0.0f) dt = 0.0f;

    void* gm = nullptr;
    PUPPET_STEP(3, "read_graphmgr",
        gm = const_cast<void*>(
            safe_read_ptr(actor, fw::offsets::ACTOR_GRAPHMGR_SMARTPTR_OFF));
    );

    // Step 5 — BSAnimGraphMgr::Update via vt[8] on graphmgr.
    //   DISABLED 2026-05-12 — depends on step 9 for state transitions
    //   to coordinate. Running step 5 without step 9 leaves the graph
    //   half-advanced. Raiders without this step stay in their last
    //   pose but engine state stays internally consistent.
    //   If anim transitions become needed later, re-enable AFTER
    //   solving step 9's aiproc_inner-pointer-validity problem.
    (void)gm;  // silence unused warning when step 5 disabled
    /*
    PUPPET_STEP(4, "vt8_graphmgr_update",
        if (gm && g_gm_is_loading && !g_gm_is_loading(gm)) {
            void* const gm_vtbl = const_cast<void*>(
                safe_read_ptr(gm, 0));
            if (gm_vtbl) {
                auto* slot_addr = reinterpret_cast<std::uint8_t*>(gm_vtbl)
                    + fw::offsets::GRAPHMGR_VT_UPDATE_OFF;
                auto fn = *reinterpret_cast<GraphMgrUpdateFn*>(slot_addr);
                if (fn) {
                    std::uint64_t ctx[4] = {0, 0, 0, 0};
                    fn(gm, dt, ctx);
                }
            }
        }
    );
    */

    // Step 6 — Anim event drain.
    PUPPET_STEP(5, "anim_event_drain",
        if (gm && g_event_drain) g_event_drain(gm);
    );

    // Step 7 — TickRenderState.
    PUPPET_STEP(6, "tick_render_state",
        if (g_tick_render) g_tick_render(actor, 0.0f);
    );

    // Step 8 — Timer countdowns.
    PUPPET_STEP(7, "timer_countdowns",
        auto* t1 = reinterpret_cast<float*>(
            a8 + fw::offsets::ACTOR_TIMER1_OFF);
        if (*t1 > 0.0f) {
            *t1 -= dt;
            if (*t1 < 0.0f) *t1 = 0.0f;
        } else {
            *reinterpret_cast<std::int32_t*>(
                a8 + fw::offsets::ACTOR_TIMER1_INT_OFF) = 0;
        }
        auto* t2 = reinterpret_cast<float*>(
            a8 + fw::offsets::ACTOR_TIMER2_OFF);
        if (*t2 > 0.0f) {
            *t2 -= dt;
            if (*t2 < 0.0f) *t2 = 0.0f;
        }
    );

    // Step 9 — Anim graph state-machine dispatch via AIProcess inner.
    //   DISABLED 2026-05-12 — root-cause of every observed SEH in the
    //   first puppet run. The dispatched fn (TickIdle / TickWithDelta)
    //   trusts `aiproc_inner = *(aiproc+0x10)` with no validation; on
    //   fresh actors that pointer reads as uninitialized garbage and
    //   the dispatch AVs deep inside. safe_read_ptr can't catch this
    //   because the read at +0x10 succeeds (memory is mapped) — only
    //   the contents are garbage.
    //   Without this step, raiders never transition anim states. For
    //   the MVP that's acceptable: server pushes shoot/aim from cache.
    //   To re-enable: first verify aiproc_inner is a real AIProcess::
    //   AnimGraphManager pointer (range check + likely bytes-test).
    /*
    PUPPET_STEP(8, "anim_graph_dispatch",
        const void* aiproc =
            safe_read_ptr(actor, fw::offsets::ACTOR_AIPROCESS_PTR_OFF);
        if (aiproc) {
            const void* aiproc_inner =
                safe_read_ptr(aiproc, fw::offsets::ACTOR_AIPROC_INNER_OFF);
            if (aiproc_inner) {
                if (dt > 0.0f && g_anim_disp_delta) {
                    g_anim_disp_delta(const_cast<void*>(aiproc_inner),
                                      actor, dt);
                } else if (g_anim_disp_idle) {
                    g_anim_disp_idle(const_cast<void*>(aiproc_inner),
                                     actor);
                }
            }
        }
    );
    */

    // Step 10 — AIProcess::OnTickPostExtra(actor+8, actor).
    PUPPET_STEP(9, "post_extra_tick",
        if (g_post_extra) g_post_extra(a8 + 0x8, actor);
    );

    // Step 11 — Static-block / water broadcast.
    PUPPET_STEP(10, "static_block_check",
        if (g_static_block) g_static_block(actor);
    );

    if (first10) {
        FW_LOG("[puppet] fire #%llu actor=%p sim_time=%.4f — "
               "11 steps attempted (per-step __try)",
               static_cast<unsigned long long>(fire), actor, sim_time);
    } else if ((fire % 5000) == 0) {
        FW_DBG("[puppet] fire #%llu heartbeat — step_seh: "
               "s1=%llu s2=%llu s3=%llu s4=%llu s5=%llu s6=%llu "
               "s7=%llu s8=%llu s9=%llu s10=%llu s11=%llu",
               static_cast<unsigned long long>(fire),
               g_step_seh[0].load(std::memory_order_relaxed),
               g_step_seh[1].load(std::memory_order_relaxed),
               g_step_seh[2].load(std::memory_order_relaxed),
               g_step_seh[3].load(std::memory_order_relaxed),
               g_step_seh[4].load(std::memory_order_relaxed),
               g_step_seh[5].load(std::memory_order_relaxed),
               g_step_seh[6].load(std::memory_order_relaxed),
               g_step_seh[7].load(std::memory_order_relaxed),
               g_step_seh[8].load(std::memory_order_relaxed),
               g_step_seh[9].load(std::memory_order_relaxed),
               g_step_seh[10].load(std::memory_order_relaxed));
    }
}

std::uint64_t get_puppet_fires() noexcept {
    return g_puppet_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_puppet_seh_failures() noexcept {
    return g_puppet_seh.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
