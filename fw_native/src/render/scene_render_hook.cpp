#include "scene_render_hook.h"
#include "body_render.h"

#include <windows.h>
#include <atomic>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "../engine/engine_calls.h"

#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace fw::render {

namespace {

// sub_140C38F80 signature. Taken from RE report: "walks an array at
// a1+8 (count a1+24)" — so a1 is the only documented parameter. We
// declare 4 pointer args because x64 __fastcall always materializes
// RCX/RDX/R8/R9; if the function ignores the extra three that's a
// no-op, if it uses them they pass through unchanged via our detour.
using SceneWalkFn = void (__fastcall*)(void* a1, void* a2, void* a3, void* a4);

SceneWalkFn       g_orig_scene_walk = nullptr;
std::atomic<bool> g_hooked{false};
std::atomic<std::uint64_t> g_frame_count{0};

void __fastcall detour_scene_walk(void* a1, void* a2, void* a3, void* a4) {
    // B6.5w4 round 7 — Atomic teleport (silver bullet from agent B).
    //
    // 4-agent RE arena consensus: stop fighting individual fields.
    // Instead, call the engine's own `Actor::MoveTo` worker per server
    // tick. It atomically writes pos + NIF.world + Havok + anim graph +
    // cell attachment. Bypasses ALL the caches and computed transforms
    // that previous rounds couldn't reach.
    //
    // Strategy:
    //   1. On FIRST sight of each tracked NPC: set motion type to
    //      Keyframed (=2). Havok stops driving the body.
    //   2. On each cache UPDATE (timestamp change = 10 Hz from server):
    //      call atomic_teleport with the new pos/yaw. Engine cascades
    //      the update through every transform.
    //   3. Between cache updates (~100ms windows): no-op. Engine state
    //      stays put because Keyframed = no Havok push, no anim driven.
    //
    // No more 60 Hz field-writing fight. Just 10 Hz atomic teleports
    // per tracked NPC. Estimated cost: ~3 µs × 10 Hz × 2 NPCs = 60 µs/s.

    if (g_orig_scene_walk) {
        g_orig_scene_walk(a1, a2, a3, a4);
    }

    const auto npcs = fw::dispatch::get_all_cached_npcs();

    // Per-form_id state: "have we set Keyframed yet" + "last applied timestamp".
    static std::mutex                              s_state_mtx;
    static std::unordered_set<std::uint32_t>       s_keyframed_set;
    static std::unordered_map<std::uint32_t,
                              std::uint64_t>       s_last_applied_ts;

    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kDegToRad = kPi / 180.0f;

    std::size_t teleports_this_frame = 0;
    std::size_t keyframe_inits_this_frame = 0;

    // Round 9: get a local-clock "now" once per frame for interpolation.
    const std::uint64_t now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    // Round 11: read+increment frame counter UP FRONT so the parity gate
    // for 30 Hz teleport (every other frame) can use it inside the loop.
    // Replaces the old "n = fetch_add at trailing edge" pattern.
    const auto n = g_frame_count.fetch_add(1, std::memory_order_relaxed);
    const bool teleport_this_frame_gate = ((n & 1u) == 0);

    for (const auto& [fid, st] : npcs) {
        void* actor = fw::engine::lookup_by_form_id(fid);
        if (!actor) continue;

        // ---- one-shot Keyframed motion type ----
        bool need_keyframe = false;
        {
            std::lock_guard lk(s_state_mtx);
            if (s_keyframed_set.find(fid) == s_keyframed_set.end()) {
                s_keyframed_set.insert(fid);
                need_keyframe = true;
            }
        }
        if (need_keyframe) {
            const bool ok = fw::engine::set_actor_motion_keyframed(actor);
            FW_LOG("[scene_hook] r7: SetMotionType(Keyframed) form=0x%X actor=%p ok=%d",
                   fid, actor, ok ? 1 : 0);
            ++keyframe_inits_this_frame;
        }

        // ---- B6.5w4 round 11: 30 Hz atomic_teleport (every other frame).
        //
        // Round 10 was 60 Hz teleport. Functional but anim graph flush
        // inside Actor::MoveTo fires every frame → no anim transition
        // ever completes → "Star Citizen NPC" anim look.
        //
        // Round 11: every-other-frame teleport. Anim has 33ms between
        // flushes — enough for short transitions to play. Motion still
        // smooth at 30 Hz visual rate (well above human flicker fusion).
        //
        // Use frame_count parity for the 50% gating. Atomic_teleport
        // itself runs with the lightest flag set (doProcessUpdate=0,
        // both skip_*=1, see engine_calls.cpp round 11 flags).
        fw::dispatch::InterpolatedNPCState interp{};
        if (fw::dispatch::get_interpolated_npc_state(fid, now_ms, &interp)) {
            if (teleport_this_frame_gate) {
                const float yaw_beth_rad = (90.0f - interp.yaw_deg_math) * kDegToRad;
                fw::engine::actor_atomic_teleport(
                    actor, interp.pos_x, interp.pos_y, interp.pos_z, yaw_beth_rad);
                ++teleports_this_frame;
            }

            // Anim graph variable suite — every frame. SetGraphVariable
            // is idempotent (same value = no transition), so even at
            // 60 Hz it doesn't flicker. Useful to override AI's between-
            // frame variable changes.
            fw::engine::apply_npc_state_to_actor(
                actor,
                interp.pos_x, interp.pos_y, interp.pos_z,
                interp.yaw_deg_math, interp.anim_state,
                /*skip_anim_graph=*/false);
        }
    }

    // (frame counter `n` was incremented at the top of the detour for the
    // round 11 parity gate; we reuse it here for log throttling.)
    if (n < 5) {
        FW_LOG("[scene_hook] frame #%llu — round 11 30Hz atomic-teleport "
               "(%zu tracked, %zu teleports this frame, %zu keyframe inits)",
               n, npcs.size(), teleports_this_frame, keyframe_inits_this_frame);
    } else if ((n % 600) == 0) {
        FW_DBG("[scene_hook] frame #%llu tick (heartbeat, tracked=%zu)",
               n, npcs.size());
    }
}

#if 0  // ROUND-5 AI-DISABLE STRATEGY — DISABLED (caused frozen NIF; see round 6 comment above)
{
    // B6.5w4 round 4-5 — Late-frame NPC override + one-time AI disable.
    //
    // Round 5 add: the FIRST time we see each form_id, call
    // `Actor.EnableAI(false)` to clear bit 2 of `flags_720`. The tier
    // walkers gate on this bit → Update_PerFrame stops firing for the
    // actor → AI fully silenced. Our pos/NIF writes from here become
    // uncontested. We track first-sight in a local set so we don't spam
    // the engine fn (which dispatches re-equip on each call).
    //
    // Round 4 base: pos/NIF.world.translate + NIF.local.translate
    // overwritten here as the LAST writes before render reads the NIF.
    //
    // skip_anim_graph=true: setter calls already happened in
    // npc_ai_suppress post-hook (or, with AI fully off, would no longer
    // run there either — but harmless to skip here regardless).
    static std::mutex          s_ai_disabled_mtx;
    static std::unordered_set<std::uint32_t> s_ai_disabled_set;

    const auto npcs = fw::dispatch::get_all_cached_npcs();
    for (const auto& [fid, st] : npcs) {
        void* actor = fw::engine::lookup_by_form_id(fid);
        if (!actor) continue;

        // One-shot AI silencer (per form_id).
        bool first_sight = false;
        {
            std::lock_guard lk(s_ai_disabled_mtx);
            if (s_ai_disabled_set.find(fid) == s_ai_disabled_set.end()) {
                s_ai_disabled_set.insert(fid);
                first_sight = true;
            }
        }
        if (first_sight) {
            FW_LOG("[scene_hook] AI-disabling tracked NPC form_id=0x%X actor=%p — "
                   "tier walker will now skip Update_PerFrame for this actor",
                   fid, actor);
            fw::engine::set_actor_ai_enabled(actor, false);
        }

        // Late-frame state apply (pos + NIF world/local + yaw).
        fw::engine::apply_npc_state_to_actor(
            actor,
            st.pos_x, st.pos_y, st.pos_z,
            st.yaw_deg_math, st.anim_state,
            /*skip_anim_graph=*/true);
    }

    // β.6 IMPORTANT: body draw via this hook is DISABLED.
    //
    // Live test 2026-04-22 showed NiCamera+0x120 at this hook point
    // does NOT hold the scene VP we need — it's some other matrix
    // (shadow? HUD overlay?) that produces nonsensical NDC for a
    // body in front of the camera. See scene_render_hook.h for
    // details. The hook remains installed because:
    //   (a) it's a proven useful render-stage entry point,
    //   (b) we'll reuse it for depth-buffer capture / integration
    //       once we source the scene VP from the correct place
    //       (RenderGlobals or CB_Map_A/B intercept).
    //
    // For now body falls back to Present-time draw (body_render sees
    // g_body.scene_hook_active=false via its own check and draws at
    // Present). Result: body visible WITH shake — known limit until
    // correct VP source is located.
}
#endif

} // namespace

bool install_scene_render_hook(std::uintptr_t module_base) {
    if (g_hooked.load(std::memory_order_acquire)) {
        FW_DBG("[scene_hook] already installed");
        return true;
    }
    if (!module_base) {
        FW_ERR("[scene_hook] install: module_base=0");
        return false;
    }

    void* target = reinterpret_cast<void*>(
        module_base + offsets::SCENE_RENDER_RVA);

    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_scene_walk),
        reinterpret_cast<void**>(&g_orig_scene_walk));
    if (!ok) {
        FW_ERR("[scene_hook] MinHook install FAILED at target=%p "
               "(RVA 0x%llX)",
               target,
               static_cast<unsigned long long>(offsets::SCENE_RENDER_RVA));
        return false;
    }

    g_hooked.store(true, std::memory_order_release);
    FW_LOG("[scene_hook] installed at %p (RVA 0x%llX) — body draw "
           "will run at scene-end instead of Present",
           target,
           static_cast<unsigned long long>(offsets::SCENE_RENDER_RVA));
    return true;
}

} // namespace fw::render
