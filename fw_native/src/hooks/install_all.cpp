#include "install_all.h"

#include "kill_hook.h"
#include "container_hook.h"
#include "put_hook.h"
#include "pickup_hook.h"
#include "player_pos_hook.h"
#include "main_menu_hook.h"
#include "worldstate_hook.h"
#include "door_hook.h"
#include "lock_hook.h"
#include "npc_ai_suppress.h" // B6.5w4: Actor::Update_PerFrame detour
#include "ghost_ai_package.h" // B6.5w12 hook #1: TESPackage::EvaluateConditions
#include "ghost_ai_combat_target.h" // B6.5w12 hook #2: SyncCombatTargetFromAIProcess
#include "ghost_ai_aim.h"           // B6.5w12 hook #3: CombatAimController::SetAimTarget
#include "ghost_ai_movement.h"      // B6.5w12 hook #4: Actor::TickMovementController
#include "ghost_ai_pos_belt.h"      // B6.5w13 hook #5: SetPosition_NiPoint3 (belt-and-braces)
#include "ghost_ai_actor_setpos.h"  // B6.5w14 hook #6: vt[202] Actor::SetPosition full
#include "ghost_ai_havok_step.h"   // B6.5w15 hook #7: bhkCharRigidBodyController FinishPhysicsStep DIAGNOSTIC
#include "ghost_ai_fire.h"         // B6.6w0 hook #3 (fire decision): CombatBehaviorGunFire::DecideAndFire
#include "ghost_ai_dispatch_attack.h"     // B6.6w0 (universal attack funnel): Actor::DispatchAttackAction
#include "ghost_ai_process_movement.h"    // B6.6w0 (movement intent funnel): AIProcess::ProcessPackages_Movement
#include "ghost_ai_set_combat_target.h"   // B6.6w0 (REAL combat target writer DIAG): AIProcess::SetCombatTarget
#include "ghost_ai_hit_applier.h"         // B6.6w0 (hit applier BAIL): sub_140CD2780 — anti-crash on damage to frozen NPC
#include "ghost_ai_combat_orchestrator.h" // B6.6w0 NUKE (top-level combat orchestrator BAIL): sub_140CCFDF0 = Actor::vt[255]
#include "../render/scene_render_hook.h" // B6.5w4 r4: late-frame NPC override
#include "equip_cycle.h"     // B8: post-LoadGame BipedAnim normalize
#include "equip_hook.h"      // M9 wedge 1: equipment-event sender hook
#include "engine_tracer.h"
#include "subrefload_hook.h" // M9 closure: live capture of sub_1404580C0 args
#include "bsmodelproc_hook.h" // M9 closure: live capture of BSModelProcessor post-hook

#include "../log.h"
#include "../native/nif_path_cache.h"  // M9 w4 witness pattern step 1
#include "../native/bsgeo_input_cache.h" // M9 w4 Path B-alt-1: factory input capture
#include "../native/ni_alloc_tracker.h"   // M9 w4 Path B-alt-2: alloc caller-RIP tracker
#include "../native/clone_factory_tracker.h" // M9 w4: clone factory hex-dump + source map

namespace fw::hooks {

InstallSummary install_all(std::uintptr_t module_base,
                           const fw::config::Settings& cfg)
{
    InstallSummary s{};
    FW_LOG("hooks: installing set on module base 0x%llX",
           static_cast<unsigned long long>(module_base));

    s.kill_ok        = install_kill_hook(module_base);
    s.container_ok   = install_container_hook(module_base);
    // B1.k: must run after install_container_hook (shares MinHook manager);
    // captures PUT which vt[0x7A] doesn't see (live test 2026-04-21).
    s.put_ok         = install_put_hook(module_base);
    // B1.n: PlayerCharacter::vt[0xEC] world pickup. Orthogonal to vt[0x7A]
    // (no feedback loop confirmed by BFS in RE agent); shares the
    // ApplyingRemoteGuard TLS flag with container_hook for feedback safety.
    s.pickup_ok      = install_pickup_hook(module_base);
    s.player_pos_ok  = start_player_pos_poll(module_base);
    s.main_menu_ok   = install_main_menu_hook(module_base, cfg);
    s.worldstate_ok  = install_worldstate_hooks(module_base);
    // B6.0: door Activate worker hook (open/close sync).
    s.door_ok        = install_door_hook(module_base);
    // B6.3 v0.5.3: ForceUnlock + ForceLock detours (lock state sync).
    s.lock_ok        = install_lock_hook(module_base);
    // B6.5w4: Actor::Update_PerFrame@0xC636A0 detour. For form_ids in
    // the tracked-NPC set (registered by net thread on NPC_STATE_BCAST),
    // the detour bails before invoking original — vanilla AI does NOT
    // tick that NPC and our server-authoritative pos/yaw writes win
    // uncontested. Single funnel for all 3 ProcessLists tier walkers
    // + forced-tick sites; one hook covers everything.
    s.npc_ai_suppress_ok = install_npc_ai_suppress(module_base);
    // B6.5w12 Ghost AI hook #1: TESPackage::EvaluateConditions detour.
    //   SKELETON for this step — log + passthrough only. Phase 4 will
    //   wire the actual "return TRUE iff pkg.form_id == server.package_form_id
    //   for tracked NPCs" logic. The skeleton's job is to prove the hook
    //   installs at the right address and fires during live AI activity.
    s.ghost_ai_package_ok = install_ghost_ai_package(module_base);
    // B6.5w12 Ghost AI hook #2: Actor::SyncCombatTargetFromAIProcess.
    //   SKELETON for this step — log + passthrough. Phase 4 step B will
    //   wire the actual "write Actor+0x380 = server.combat_target_form_id"
    //   substitution for tracked NPCs.
    s.ghost_ai_combat_target_ok = install_ghost_ai_combat_target(module_base);
    // B6.5w12 Ghost AI hook #3: CombatAimController::SetAimTarget.
    //   SKELETON for this step — log first 5 fires with full diagnostic
    //   dump of candidate offsets on the controller (self+8/+16/+24/...
    //   and CombatController child offsets), so we can identify which
    //   offset reaches the OWNER Actor from live data.
    s.ghost_ai_aim_ok = install_ghost_ai_aim(module_base);
    // B6.5w12 Ghost AI hook #4: Actor::TickMovementController. When
    // cache.movement_override is set for a tracked NPC, the detour
    // SKIPS the original — engine's MovementControllerNPC::Tick does
    // not fire — so the actor doesn't move this frame. For the MVP
    // visible test, this is hooked together with hook #2 (combat
    // target): tracked raiders get target=0x14 + bail-movement → they
    // stand still while still in combat state. Easy to verify by eye.
    s.ghost_ai_movement_ok = install_ghost_ai_movement(module_base);
    // B6.5w13 hook #5: TESObjectREFR::SetPosition_NiPoint3 (belt-and-
    // braces). Catches all 82 callers that write Actor+0xD0 — including
    // AIPackage warp paths that bypass MovementController. With hook #4
    // (wrapper bail) + hook #5 (SetPosition bail), tracked NPCs cannot
    // have their pos written by any engine path. Combined with
    // bAnimationDriven=0 (in hook #4 detour), this yields full freeze.
    s.ghost_ai_pos_belt_ok = install_ghost_ai_pos_belt(module_base);
    // B6.5w14 hook #6: Actor::SetPosition full (vt[202] = sub_140C60630).
    // Per re/B6.5w14_pair_AGENT_1A.md: vt[202] calls SetPosition_NiPoint3
    // (caught by hook #5) BUT ALSO writes NIF+0x60 directly afterwards.
    // The NIF+0x60 write bypasses hook #5 → UpdateWorldData propagates
    // local → world per frame → renderer reads world → raider moves
    // visually even with hook #5 bailing Actor+0xD0. Bailing vt[202]
    // wholesale stops BOTH paths.
    s.ghost_ai_actor_setpos_ok = install_ghost_ai_actor_setpos(module_base);
    // B6.5w15 hook #7: bhkCharRigidBodyController FinishPhysicsStep
    // DIAGNOSTIC. Per re/B6.5w14_pair_AGENT_5A.md, this is the candidate
    // for the missing per-frame pos writer that bypasses our other hooks.
    // Hook logs ONLY (no bail) to verify (a) function fires per-frame
    // for combat raiders, (b) owner Actor accessible via +32, (c)
    // form_id at owner+0x14 matches a tracked raider during combat.
    s.ghost_ai_havok_step_ok = install_ghost_ai_havok_step(module_base);
    // B6.6w0 hook #3 (fire decision, single-shot only) — RESTORED to
    // sub_14086FCA0 = CombatBehaviorGunFire::DecideAndFire. The
    // FireWeapon (sub_140479680) detour was disabled after C1's
    // identification proved wrong (live test confirmed rcx is a
    // stack buffer, not Actor*). This hook works for single-shot
    // weapons; burst/suppressive are caught by ghost_ai_dispatch_attack
    // below.
    s.ghost_ai_fire_ok = install_ghost_ai_fire(module_base);

    // B6.6w0 (universal attack funnel) — Actor::DispatchAttackAction
    // @ 0xE6F830. Per C1 §3, this is the function any CBT leaf calls
    // to dispatch the attack action that emits "WeaponFire" anim event.
    // Actor* in rcx — direct read. Catches single-shot + burst +
    // suppressive + melee + power. BAIL strategy on tracked NPCs.
    (void)install_ghost_ai_dispatch_attack(module_base);

    // B6.6w0 (movement intent funnel) — AIProcess::ProcessPackages_Movement
    // @ 0xCEEC30 per B1. The package iterator + per-package movement
    // dispatcher that ultimately calls SetPosition_NiPoint3 (which we
    // also hook at hook #5 ghost_ai_pos_belt). Bailing here skips the
    // package walk entirely — frozen NPCs don't even compute
    // pathfinding targets.
    (void)install_ghost_ai_process_movement(module_base);

    // B6.6w0 (REAL combat target writer DIAG) — AIProcess::SetCombatTarget
    // @ 0x87AB30 per A1+A2. NOT the mirror we previously hooked. This
    // is the canonical writer of AIProcess+0x6C = target.formID, the
    // field AI's aim/fire pipeline actually reads. PHASE 1 = log
    // first fires + owner identification via aiproc→fid map; PHASE 2
    // will substitute server-chosen target.
    (void)install_ghost_ai_set_combat_target(module_base);

    // B6.6w0 (central hit applier orchestrator BAIL) — sub_140CD2780
    // @ 0xCD2780 per D2 dossier. Single funnel for ALL damage paths.
    // Target Actor at hit_data+0x300 (disasm verified). BAIL on tracked
    // NPCs prevents stagger/hit-react anim writes onto FROZEN anim
    // graphs — the crash 2026-05-12 evening matched exactly this
    // hypothesis. CRITICAL for crash prevention.
    (void)install_ghost_ai_hit_applier(module_base);

    // B6.6w0 NUKE — sub_140CCFDF0 = Actor::vt[255] combat orchestrator
    // @ 0xCCFDF0 per A1 chain. THIS is the per-actor per-frame entry
    // for the entire combat brain. Bailing it skips: target promotion,
    // fire decide chain, dispatch attack, aim update, all combat
    // decisions in one shot. Hooked at the TOP of the per-actor combat
    // pipeline. User's "stiamo sbagliando hooks" prompted this pivot
    // from suppressing individual outputs to nuking the orchestrator.
    (void)install_ghost_ai_combat_orchestrator(module_base);
    // B6.5w4 round 4: scene_render hook for LATE-frame NPC pos/NIF
    // override. Fires once per frame at the trailing edge of the 3D
    // scene walker — after Havok physics + per-actor NIF sync. Writes
    // here are the last before renderer reads NIF.world.translate.
    // Previously installed lazily by body_render's first-frame init;
    // we now install it unconditionally at boot so NPC sync works even
    // when no ghost-body is active (single-peer scenarios, etc.).
    (void)fw::render::install_scene_render_hook(module_base);
    // M9 wedge 1: ActorEquipManager Equip + Unequip detours (OBSERVE-only).
    //   Detect local-player equip changes → broadcast EQUIP_OP. Receivers
    //   in wedge 1 just log RX; wedge 2 will swap visuals on the M8P3
    //   ghost. Critical: this hook is OBSERVE-only — no nullify of skin
    //   bindings, no cull-flag manipulation, no detach-from-SSN. Yesterday's
    //   M9 attempts that did those things crashed in 3 different walkers
    //   (re/M9_y_post_bmod_crash_dossier.txt). Pure observation + broadcast
    //   is safe; B8 force-equip-cycle (above, fired post-LoadGame) handles
    //   the BipedAnim normalize that lets the ghost subsequently coexist
    //   with equip changes.
    s.equip_ok       = install_equip_hook(module_base);
    // B8: NOTE — arm call MOVED to main_menu_hook::fw_wndproc post-LoadGame
    //   callback (instead of armed here at install time). Reason:
    //   the prior install-time arm with 20s delay was measured from DLL
    //   inject (T+0), which yielded "10s post in-world" — too long.
    //   User requested earlier firing ("Prima cazzo, fai 10 secondi o 5
    //   dopo il loading nel mondo" 2026-04-28). Solution: arm AFTER
    //   load_game_by_name() returns, so the worker delay is measured
    //   from LoadGame call time. With 10s delay we get ~5s in-world.
    //   See main_menu_hook.cpp + offsets.h "B8" block.
    // M6.3: engine_tracer disabled post-discovery.
    //   2026-04-24 enabled → captured vanilla head NIF paths
    //     (BaseMaleHead.nif, MaleHeadRear.nif) during Museum gameplay.
    //   Re-enable if we need to observe other engine calls for M7
    //   animations or M8 facegen.
    //
    // ⚠ engine_tracer also hooks sub_1417B3E90 — it conflicts with the
    //   M9 w4 nif_path_cache below. Re-enabling engine_tracer requires
    //   either folding its trace logic into the cache detour, or
    //   uninstalling the cache first.
    // (void)install_engine_tracer(module_base);

    // M9 wedge 4 (witness pattern, step 1) — RE-ENABLED 2026-04-30 22:00.
    //
    // The witness pipeline is now structured as a TWO-stage broadcast:
    //   1. enqueue_equip_op fires BEFORE g_orig_equip with mods only
    //      (no nif_descs). Receiver does base attach. Crash-safe.
    //   2. After g_orig_equip returns successfully, walker queries the
    //      cache and produces a DELTA enqueue with nif_descs. Receiver
    //      sees "already attached + nif_descs present" and applies just
    //      the mod-attach loop on the existing weapon node.
    //
    // If g_orig_equip SEH AVs (engine bug, see equip_cycle.cpp:367), the
    // delta enqueue is skipped — peers see the base weapon attached but
    // not the mods. Acceptable degraded mode; never a crash, never a
    // missing weapon. The SEH-wrap on the chain itself is a separate
    // hardening task tracked in the todo list.
    const bool nif_cache_ok =
        fw::native::nif_path_cache::install(module_base);
    if (!nif_cache_ok) {
        FW_WRN("hooks: nif_path_cache install FAILED (witness pattern "
               "won't see mod NIFs — sender extraction will be empty)");
    }

    // M9 wedge 4 Path B-alt-1 — capture geometry factory inputs at the
    // moment of NIF parse, BEFORE positions get freed (iter 11c finding).
    // Diagnostic-only first: confirms whether weapon NIFs trigger the
    // factory at all. If they do, mesh data is in our cache for later
    // walker query keyed on BSTriShape*.
    const bool bsgeo_cache_ok =
        fw::native::bsgeo_input_cache::install(module_base);
    if (!bsgeo_cache_ok) {
        FW_WRN("hooks: bsgeo_input_cache install FAILED");
    }

    // M9 wedge 4 Path B-alt-2 — capture caller RIPs of every BSTriShape /
    // BSDynamicTriShape allocation. After 4 layers of hook misses (public
    // API, worker, cache resolver, factory), we go to the ROOT: the pool
    // allocator that every NiObject derives from. The RIP tells us who
    // is constructing each shape — from there we identify the secret
    // weapon NIF parser.
    const bool alloc_trk_ok =
        fw::native::ni_alloc_tracker::install(module_base);
    if (!alloc_trk_ok) {
        FW_WRN("hooks: ni_alloc_tracker install FAILED");
    }

    // ============================================================
    // DEAD-END diagnostic hooks DISABLED (2026-05-08, post-M9 cleanup)
    // ============================================================
    // Both hooks below were RE diagnostics during M9.w4 to learn the
    // engine's modded-weapon assembly mechanism. The working path
    // turned out to be `sub_140434DA0` per-OMOD attach + BSConnectPoint
    // pairing (see CHANGELOG v0.5.0), which neither hook touches.
    // Files kept on disk with DEAD-END headers as memory of hours
    // passed; install calls disabled here to avoid wasted boot work
    // and log noise. To re-enable for future RE rounds: uncomment
    // the original blocks below.
    //
    // M9 closure (2026-05-07) — diagnostic hook on sub_1404580C0.
    // GAMMA's vt[170] path was refuted (sub_140513760 is a flag-setter,
    // not a loader). DELTA §8 candidate: sub_1404580C0 = direct
    // load+clone+wrap, opts byte 0x08 triggers BSModelProcessor → OMOD
    // apply. The 4th arg `modelExtraData` carries OMOD context but its
    // shape is unknown statically. This hook captures every fire's
    // raw args + hex dumps so we can reverse the layout from live data.
    // Trigger: open Pipboy, hover modded weapons. First 24 fires logged.
    //
    //   const bool subload_ok = install_subload_hook(module_base);
    //   if (!subload_ok) {
    //       FW_WRN("hooks: subrefload install FAILED");
    //   }

    // M9 closure (2026-05-07) — diagnostic hook on sub_1402FC0E0
    // (BSModelProcessor post-hook). Per ALPHA's dossier, this is THE
    // function where OMODs get attached to a freshly-parsed BSFadeNode.
    // Triggered any time the engine parses a NIF with opts.flag&0x08
    // set + the BSModelProcessor singleton non-null. EQUIP of a modded
    // weapon fires this on the receiving end. Logging captures: args,
    // node ptr, extra-data chain (the post-hook reads node+0x18), and
    // what the form-info path gives us. Goal: discover what state must
    // be present in memory for the OMOD branch to fire so we can
    // reproduce it on a synthetic load. First 32 weapon/armor fires
    // logged; everything else silently passed through.
    //
    //   const bool bsmp_ok = install_bsmodelproc_hook(module_base);
    //   if (!bsmp_ok) {
    //       FW_WRN("hooks: bsmodelproc install FAILED");
    //   }

    // M9 wedge 4 — hook the BSTriShape CLONE FACTORY (sub_1416D99E0).
    // The alloc tracker (above) identified ALL weapon BSTriShape leaves
    // come from caller_rva 0x16D9A5C, which is inside this clone factory.
    // This hook captures the SOURCE TEMPLATE pointer (a1) and dumps hex
    // bytes of the mysterious +0x148 struct for layout discovery.
    const bool clone_trk_ok =
        fw::native::clone_factory_tracker::install(module_base);
    if (!clone_trk_ok) {
        FW_WRN("hooks: clone_factory_tracker install FAILED");
    }

    FW_LOG("hooks: install summary kill=%d container=%d put=%d pickup=%d "
           "pos=%d main_menu=%d worldstate=%d door=%d equip=%d "
           "lock=%d npc_ai_suppress=%d ghost_ai_pkg=%d "
           "ghost_ai_combat=%d ghost_ai_aim=%d ghost_ai_mov=%d "
           "ghost_ai_pos_belt=%d ghost_ai_actor_setpos=%d "
           "ghost_ai_havok_step=%d ghost_ai_fire=%d nif_cache=%d "
           "(total %zu/19)",
           int(s.kill_ok), int(s.container_ok), int(s.put_ok), int(s.pickup_ok),
           int(s.player_pos_ok), int(s.main_menu_ok), int(s.worldstate_ok),
           int(s.door_ok), int(s.equip_ok),
           int(s.lock_ok), int(s.npc_ai_suppress_ok), int(s.ghost_ai_package_ok),
           int(s.ghost_ai_combat_target_ok), int(s.ghost_ai_aim_ok),
           int(s.ghost_ai_movement_ok),
           int(s.ghost_ai_pos_belt_ok),
           int(s.ghost_ai_actor_setpos_ok),
           int(s.ghost_ai_havok_step_ok),
           int(s.ghost_ai_fire_ok),
           int(nif_cache_ok),
           s.success_count());
    return s;
}

void stop_all() {
    stop_player_pos_poll();
    // kill / container / main_menu hooks are torn down by MinHook's global
    // shutdown in hook_manager::shutdown() — no per-hook cleanup needed.
}

} // namespace fw::hooks
