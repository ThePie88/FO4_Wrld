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
    // B6.5w12 deprecation (2026-05-11): rounds 7-11 atomic-teleport
    // path is CLOSED.
    //
    // Previous logic (round 11): for each tracked NPC, call
    // Actor::MoveTo every other frame (30 Hz parity gate) with
    // server-interpolated pos + write humanoid anim graph bool suite
    // every frame.
    //
    // WORKS for pos sync (verified live on Dogmeat + Codsworth at
    // Sanctuary). FAILS for anim sync: Actor::MoveTo internally flushes
    // the anim graph every call, so at 30+ Hz the graph never completes
    // a transition → "Star Citizen NPC" look (glitchy poses, anims
    // restart constantly). Cannot deliver fluid combat AI at the scale
    // the survival-MMO vision needs.
    //
    // The hook install remains so the file scaffolds future render-
    // stage work (e.g. body draw at scene-end vs Present, B5 follow-
    // up) without re-RE'ing the entry point. The original-pass-through
    // call below preserves vanilla render exactly.
    //
    // Next direction: hook AI DECISION POINTS upstream of the per-frame
    // pipeline ("Ghost AI" pattern — see NPCs.md "Next direction"). The
    // scene-render hook is not where Ghost AI lives; this file stays
    // dormant until B5 / depth-buffer work resumes.

    if (g_orig_scene_walk) {
        g_orig_scene_walk(a1, a2, a3, a4);
    }

#if 0
    // ===== ROUND 7-11 (CLOSED) — kept for reference =====================
    //
    // Do NOT re-enable wholesale. The atomic-teleport @ 30 Hz approach
    // is architecturally wrong for combat AI sync. See NPCs.md "Session
    // recap — 2026-05-11" for the 11-round narrative.
    //
    // Round 7 silver bullet: call Actor::MoveTo per cache update at
    // 10 Hz. Engine cascades the update through every transform.
    // Round 8: added humanoid bool anim graph variable suite (silently
    // no-ops on Dogmeat/Codsworth which use creature anim graphs).
    // Round 9: cache prev+current + linear extrapolation at 60 Hz —
    // pos-only writes to Actor+0xD0 + NIF.world DIDN'T propagate to
    // render between MoveTo calls (lesson re-learned).
    // Round 10: atomic teleport at 60 Hz — anim graph flushed every
    // frame, never completes a transition.
    // Round 11: 30 Hz parity gate to give anim 33ms breathing room.
    // Marginal improvement only — structural limit.

    const auto npcs = fw::dispatch::get_all_cached_npcs();
    static std::mutex                              s_state_mtx;
    static std::unordered_set<std::uint32_t>       s_keyframed_set;
    static std::unordered_map<std::uint32_t,
                              std::uint64_t>       s_last_applied_ts;
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kDegToRad = kPi / 180.0f;
    std::size_t teleports_this_frame = 0;
    std::size_t keyframe_inits_this_frame = 0;
    const std::uint64_t now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    const auto n_r11 = g_frame_count.load(std::memory_order_relaxed);
    const bool teleport_this_frame_gate = ((n_r11 & 1u) == 0);
    for (const auto& [fid, st] : npcs) {
        void* actor = fw::engine::lookup_by_form_id(fid);
        if (!actor) continue;
        bool need_keyframe = false;
        {
            std::lock_guard lk(s_state_mtx);
            if (s_keyframed_set.find(fid) == s_keyframed_set.end()) {
                s_keyframed_set.insert(fid);
                need_keyframe = true;
            }
        }
        if (need_keyframe) {
            fw::engine::set_actor_motion_keyframed(actor);
            ++keyframe_inits_this_frame;
        }
        fw::dispatch::InterpolatedNPCState interp{};
        if (fw::dispatch::get_interpolated_npc_state(fid, now_ms, &interp)) {
            if (teleport_this_frame_gate) {
                const float yaw_beth_rad = (90.0f - interp.yaw_deg_math) * kDegToRad;
                fw::engine::actor_atomic_teleport(
                    actor, interp.pos_x, interp.pos_y, interp.pos_z, yaw_beth_rad);
                ++teleports_this_frame;
            }
            fw::engine::apply_npc_state_to_actor(
                actor,
                interp.pos_x, interp.pos_y, interp.pos_z,
                interp.yaw_deg_math, interp.anim_state,
                /*skip_anim_graph=*/false);
        }
    }
#endif  // ===== end round 7-11 reference block ============================

    // Frame counter for log heartbeat only (no per-frame work above).
    const auto n = g_frame_count.fetch_add(1, std::memory_order_relaxed);
    if (n < 5) {
        FW_LOG("[scene_hook] frame #%llu — DEPRECATED PASSTHROUGH "
               "(rounds 7-11 atomic-teleport closed, awaiting Ghost AI)",
               static_cast<unsigned long long>(n));
    } else if ((n % 600) == 0) {
        FW_DBG("[scene_hook] frame #%llu tick (heartbeat, deprecated passthrough)",
               static_cast<unsigned long long>(n));
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
