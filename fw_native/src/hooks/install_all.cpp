// ============================================================================
// 2026-05-25 BUILD 64 ARCHITECTURAL STATUS — read this before changing hooks.
// ----------------------------------------------------------------------------
//
// CURRENT GOAL (MVP-A): both clients see raiders at the same world position;
// combat itself runs vanilla per-client (each client's raiders attack each
// client's local PC). Pos sync via server's NPC_STATE_BCAST + apply_npc_pos.
//
// Full strategy decision in re/BUILD64_strategy/STRATEGY.md.
// Implementation summary in re/BUILD64_strategy/IMPLEMENTATION.md.
//
// HISTORY:
//   Builds 39-44  — surgical 4-hook attempt at cross-peer aggro (FAILED:
//                   4 independent engine gates can't all be satisfied).
//   Builds 45-55  — puppet-fire bypass (FAILED: HighProcess missing on
//                   ghost-aggro raiders blocks AimController writes).
//   Builds 56-62  — global walker guards + native combat tier via CCF810
//                   (FAILED: corruption surface intractable; teleport-race
//                   crashes; engagement collapse via missing AddAlly).
//   Build 63      — proposed Fix #1 (AddAlly) + Hook 26 (cellload merge)
//                   (NOT SHIPPED; user paused after 13 builds).
//   Build 64      — STRATEGIC ROLLBACK. All AI-control hooks disabled.
//                   Vanilla engine AI runs. Server pos sync only.
//
// HOOKS STILL INSTALLED (KEEP):
//   install_kill_hook                  - kill broadcast (orthogonal)
//   install_container_hook             - container ops (orthogonal)
//   install_put_hook                   - deposit ops (orthogonal)
//   install_pickup_hook                - pickup ops (orthogonal)
//   start_player_pos_poll              - player pos send (20Hz) — REQUIRED
//   install_main_menu_hook             - auto-load + WndProc subclass
//   install_worldstate_hooks           - GlobalVariable.SetValue sync
//   install_door_hook                  - door activate sync (orthogonal)
//   install_lock_hook                  - lock state sync (orthogonal)
//   install_equip_hook                 - equipment broadcast
//   install_scene_render_hook          - late-frame NPC pos commit
//   install_npc_ai_suppress            - PASSTHROUGH ONLY (bail_this_actor
//                                        constexpr false). Provides
//                                        aiproc→fid map + NPC_DISCOVER tx.
//                                        KEYFRAMED HAVOK BLOCK DISABLED
//                                        (Build 64). Vanilla AI runs.
//   install_ghost_vt197_guard          - PURE CRASH PREVENTION (no AI ctrl)
//   install_ghost_is_attachable        - TLS-gated PlaceAtMe bypass (proxy)
//   install_ghost_global_walker_guards - 26 hooks, PURE CRASH PREVENTION
//   install_nif_path_cache             - M9 witness pattern
//   install_bsgeo_input_cache          - M9 factory input capture
//   install_ni_alloc_tracker           - M9 allocator tracking
//   install_clone_factory_tracker      - M9 clone factory hex-dump
//   install_subload_hook               - M9 closure
//   install_bsmodelproc_hook           - M9 closure
//
// HOOKS DISABLED IN BUILD 64 (look for BUILD64_DISABLED markers below):
//   install_ghost_ai_movement          - TickMovementController bail
//   install_ghost_ai_pos_belt          - SetPosition bail
//   install_ghost_ai_actor_setpos      - vt[202] setpos bail
//   install_ghost_ai_set_combat_target - target setter mirror
//   install_ghost_ai_action_execute    - action exec bail
//   install_ghost_ai_package           - selector substitute, diag
//   install_ghost_ai_combat_target     - mirror, diag
//   install_ghost_ai_aim               - aim, diag
//   install_ghost_ai_fire              - DecideAndFire bail
//   install_ghost_ai_dispatch_attack   - DispatchAttackAction bail
//   install_ghost_ai_havok_step        - FinishPhysicsStep bail
//   install_ghost_ai_combat_orchestrator - vt[255]
//   install_ghost_ai_process_movement  - process movement bail
//   install_ghost_combat_force         - 4-hook surgical
//   install_ghost_hostility_guard      - HostilityCore validator
//   install_ghost_hostility_guard_layer1 - sub_140C7AD40 layer-1
//   install_event_dispatch_guard       - vt[3] UAF guard (no longer needed
//                                        without combat tier paths)
//   install_cross_cell_gate            - swap branch unreachable
//
// Sites in main_thread_dispatch / engine_calls / client.cpp that previously
// called the puppet-fire / combat-target path are also tagged
// BUILD64_DISABLED. Search the working tree for that marker before
// re-enabling any of them.
//
// WHAT TO BUILD NEXT:
//   Open problem. Cross-peer aggro path TBD.
//   Death sync + container sync round out MVP-A polish.
//   Do NOT re-enable any of the BUILD64_DISABLED hooks without a new
//   architecture document explaining why this time will be different.
// ============================================================================

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
#include "ghost_ai_action_execute.h"      // B6.6w5 Build 18 — bail BGSActionData::Execute on duplicate target
#include "ghost_is_attachable.h"          // B6.6w5 Build 28f — TLS-gated IsAttachable bypass for proxy spawn
#include "ghost_hostility_guard.h"        // B6.6w5 Build 30 Fix 2 — baseForm guard on sub_140C8DFF0
#include "ghost_hostility_guard_layer1.h" // Build 50 Strada A — layer-1 IsHostile gateway hook on sub_140C7AD40
#include "ghost_vt197_guard.h"            // Build 55e — Actor vt[197] IsHostileTo bail-on-ghost (prevents +0x418→+0x80 AV)
#include "ghost_global_walker_guards.h"   // Build 57 — comprehensive walker guards (7 hooks) — kills 0xE98860 AV class + Agent A/B/C/D/E/F predicted crash surfaces
#include "ghost_ai_hit_applier.h"         // B6.6w0 (hit applier BAIL): sub_140CD2780 — anti-crash on damage to frozen NPC
#include "ghost_ai_combat_orchestrator.h" // B6.6w0 NUKE (top-level combat orchestrator BAIL): sub_140CCFDF0 = Actor::vt[255]
#include "cross_cell_gate.h"              // Build 38: sub_140CF6100 detour — transient ghost+0xB8 swap to defeat PC.cell==target.cell gate
#include "ghost_combat_force.h"           // Build 40: 4-hook surgical decision override for combat AI
#include "event_dispatch_guard.h"         // Build 44: sub_140DEF780 vtable-validity guard against use-after-free EXEC fault
#include "puppet_update_perframe.h"       // B6.6w0 puppet Update_PerFrame replacement (KEEP-ALWAYS subset)
#include "../render/scene_render_hook.h" // B6.5w4 r4: late-frame NPC override
#include "equip_cycle.h"     // B8: post-LoadGame BipedAnim normalize
#include "equip_hook.h"      // M9 wedge 1: equipment-event sender hook
#include "engine_tracer.h"
#include "subrefload_hook.h" // M9 closure: live capture of sub_1404580C0 args
#include "bsmodelproc_hook.h" // M9 closure: live capture of BSModelProcessor post-hook

#include "../log.h"
#include "../diag/crash_veh.h"          // B6.6w5 Build 22: VEH for AV diagnostics
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

    // B6.6w5 Build 22 — install crash VEH FIRST so AVs from any later
    // hook install (or hot-path detour) get RIP/fault_addr logged.
    fw::diag::install_crash_veh(module_base);

    // B6.6w0 — resolve the 10 engine fn pointers used by the puppet
    // replacement body BEFORE any hook installs. npc_ai_suppress's
    // detour calls puppet_update_perframe(), which requires these
    // pointers to be live. Idempotent; safe to call once at boot.
    puppet_init(module_base);

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
    // ========================================================================
    // B6.6w4 PHASE A (2026-05-12 night, post-swarm-RE) — minimal re-enable.
    //
    // Only ONE hook restored: npc_ai_suppress in NO-BAIL discovery +
    // freeze mode. Per swarm-RE findings (re/B6.6w4_audit_*.md):
    //   - Bailing Update_PerFrame breaks the combat mirror chain
    //     (sub_140C5CCE0 mirror → sub_14087A8E0 → CombatController+0x98)
    //     by starving the perception/sensed-list update path → bit
    //     0x4000 at Actor+0x2D0 decays → compass white → "FRIENDLY".
    //     So this detour now NEVER bails — vanilla AI runs every frame.
    //   - Position freeze for tracked raiders is done via engine-native
    //     sub_140DC80B0 setter on MovementController+0x1A1 byte. When
    //     set to 1, Actor::TickMovementController bails ITSELF (no hook
    //     needed). Engine vanilla uses this path at scene-start/dialog
    //     so combat/perception/anim tolerate it natively.
    //   - The 4-hook freeze cascade (movement / pos_belt / actor_setpos
    //     / havok_step) is OBSOLETE under this design. Stays disabled.
    //   - Combat hooks (set_combat_target, fire, hit_applier) stay
    //     disabled for Phase A. Vanilla AI handles combat per-client;
    //     no cross-peer combat sync yet.
    //
    // Expected Phase A behavior: raiders attack with vanilla AI on
    // both clients. As soon as a raider engages combat (vanilla sets
    // InCombat bit 0x4000), npc_ai_suppress observes → calls
    // disable_actor_movement → raider freezes in place. NPC_DISCOVER
    // sent to server → server registers + starts broadcasting
    // movement_override=1 → other peer's npc_ai_suppress detour
    // observes cache.movement_override → also calls
    // disable_actor_movement → both clients see frozen raider.
    // ========================================================================
    // B6.6w4 PHASE A v3 (2026-05-12 late night):
    // Empirical test — restore the 3 pos-bail hooks that the user
    // reported as working ("ieri correvano sul posto e attaccavano")
    // BEFORE the puppet body / InCombat-triple-write regressions.
    //
    // Hooks installed:
    //   - ghost_ai_movement       (TickMovementController BAIL)
    //   - ghost_ai_pos_belt       (SetPosition_NiPoint3 BAIL)
    //   - ghost_ai_actor_setpos   (vt[202] SetPosition BAIL)
    //
    // Predicate `should_freeze_actor` now checks ONLY server cache
    // `movement_override` (per the rebuilt npc_ai_suppress.cpp).
    // Local-only InCombat auto-track removed → vanilla AI keeps running
    // for non-server-tracked actors.
    //
    // npc_ai_suppress NOW INSTALLED (B6.6w5 PHASE A v5) but in
    // PURE PASSTHROUGH MODE (constexpr bool bail_this_actor = false).
    // Reasons:
    //   a) Populates aiproc→fid reverse map used by
    //      ghost_ai_set_combat_target to identify owner Actor.
    //   b) Sends NPC_DISCOVER one-shot per fid on InCombat observation.
    //   c) The disable_actor_movement call (broken state-toggle) was
    //      REMOVED — detour is now safe.
    // Update_PerFrame still runs for every actor (no bail), so vanilla
    // AI combat/aim/fire/hostility persists.
    // Build 64 (2026-05-25) — AI-CONTROL HOOKS DISABLED.
    //
    // User decision after 13 failed builds (62.x → 63): the cumulative
    // interaction between puppet-fire era hooks and native combat tier is
    // intractable. Roll back to "vanilla engine + crash-prevention only".
    //
    // KEEP: npc_ai_suppress (provides aiproc→fid map needed elsewhere;
    // its bail logic is gated by movement_override=1 from server cache).
    // KEEP: ghost_global_walker_guards (pure crash prevention, no AI control).
    //
    // DISABLE: everything else that touches AI/combat decisions.
    s.npc_ai_suppress_ok       = install_npc_ai_suppress(module_base);
    s.ghost_ai_movement_ok     = false;  // BUILD64_DISABLED — install_ghost_ai_movement
    // Build 65.c.17 — re-enabled for owner-driven completeness. Predicate
    // flip from 65.c.3 already gates these: owner forces should_bail=false
    // (vanilla physics runs), non-owner forces should_bail=true (suppress
    // all engine pos writers so apply_npc_pos from owner is the sole
    // source on the receiver's actor). Without these, the engine's
    // SetPosition_NiPoint3 / vt[202] paths still write at 60Hz on the
    // non-owner client and produce the visible ghost-flicker.
    s.ghost_ai_pos_belt_ok     = install_ghost_ai_pos_belt(module_base);
    s.ghost_ai_actor_setpos_ok = install_ghost_ai_actor_setpos(module_base);
    // B6.6w5 — AGGRO SYNC (B.2): rdx-swap on AIProcess::SetCombatTarget.
    // Verified file:line:
    //   - signature `(AIProcess* a1, Actor* a2)` at funcs_0240.md:5872
    //   - writes `*(a1+0x6C) = a2->form_id` at funcs_0240.md:5986
    // Detour reads owner_fid via get_fid_for_aiproc (populated by
    // npc_ai_suppress above), looks up server's
    // cache.combat_target_form_id, resolves Actor* via
    // lookup_by_form_id, substitutes rdx (new_target arg).
    //
    // Build 29 — DISABLED for A/B test with engine-native Fixed selector
    // path (see engine_calls::install_fixed_selector_on_raider). The two
    // strategies CONFLICT: the Fixed selector makes the engine's own
    // promoter (sub_14087B080) write the correct combat target to
    // aiproc+0x6C every frame. If this detour also fires, it overwrites
    // the engine's write with our cache lookup — same target most of the
    // time, but the BYPASS-FROM-DUP cleanup-skip path (Build 26) would
    // leave the engine's broadcaster/cleanup chain in inconsistent state.
    // Cleaner A/B: install ONE of the two paths at a time.
    // Re-enable by uncommenting if Build 29 live test fails.
    // BUILD64_DISABLED — (void)install_ghost_ai_set_combat_target(module_base);
    //
    // ============================================================
    // Build 45 (2026-05-17 evening) — RE-ENABLED with role change.
    //
    // D agent (re/puppet_fire_phase1/D_AGENT_enter_combat.md §8) found:
    // after EnterCombat allocates HighProcess + registers ghost in
    // controller.known_targets[], engine's natural promoter
    // (sub_14087B080) writes aiproc+0x6C = ghost_handle every frame.
    // THAT write goes through sub_14087AB30 which:
    //   - 1st transition (old=NULL/something, new=ghost): SAFE — no
    //     cleanup-on-old triggered for ghost.
    //   - 2nd+ transition (old=ghost, new=anything): WALKS GHOST'S
    //     COMBAT-GROUP CLEANUP CHAIN → AVs at sub_14079C234
    //     broadcaster walker reading ghost.+0x28 as vtable (Build
    //     25/26 crash class).
    //
    // The existing detour body already has Build 25/26 BYPASS-FROM-DUP
    // logic: when old aiproc+0x6C == ghost_handle, skip orig (no
    // engine cleanup chain). This is EXACTLY the protection we need
    // for the 2nd-transition case.
    //
    // Re-enabling now. The detour also substitutes new_target →
    // duplicate when server pushes (substitution branch), which is
    // BENIGN in current flow (apply_npc_combat_target already writes
    // ghost_handle directly to +0x6C in Build 15). Substitution
    // becomes a no-op (same target).
    //
    // CONFLICT NOTE (Build 29 concern): the substitution overwrite
    // of engine's natural write. Verified safe because both paths
    // converge on the same ghost_handle when server says target=ghost.
    // For target=0x14 (vanilla local), substitution doesn't fire
    // (owner not known in our map for raiders aggro'd naturally).
    // ------------------------------------------------------------
    // Build 46 (2026-05-17 night) — RE-DISABLED. Build 45 live test
    // showed substitution writes aiproc+0x6C = ghost_handle every
    // tick the server says cross-peer, which CREATES A CHURN:
    //   - Engine SetCombatTarget(aiproc, player_A) — natural aggro
    //   - Our hook substitutes → writes ghost_handle to +0x6C, skips orig
    //   - Engine's combat brain reads +0x6C next tick → tries to
    //     engage ghost
    //   - But ghost has no CombatAimController registered in
    //     HighProcess+0x98 BSTArray for the raider's slot
    //     (Worker B verified — sub_14087D190 returns 0 for ghost)
    //   - Aim solver fails → no fire → engine sees "no progress"
    //   - Engine RE-RUNS target selection → SetCombatTarget(aiproc, player_A)
    //   - We substitute again → infinite churn
    //
    // VISIBLE OUTCOME: raiders LOSE natural aggro on player_A AND
    // never engage ghost. Compass shows green "RAIDER" + "TALK" prompt.
    // User's 20:48 screenshot pair confirms this.
    //
    // Re-disabling restores natural aggro on player_A. Cross-peer
    // ghost-targeting will not work until we manually allocate a
    // CombatAimController for raider's slot (separate RE work) —
    // but at least no regression vs vanilla.
    // ============================================================
    // BUILD64_DISABLED — (void)install_ghost_ai_set_combat_target(module_base);

    // B6.6w5 Build 18 — Bail BGSActionData::Execute on duplicate target.
    //
    // Per re/B6.6w5_build16_forensic.md the crash chain when combat_target
    // = our duplicate is:
    //   sub_14086DC80 → sub_140E6F830(duplicate, action_id, slot) →
    //   sub_140CE9280 → sub_140CEC490 → sub_140D0CF70(real_player.AIProcess, ...)
    //   → InterlockedInc/Dec on real_player's heap → crash.
    //
    // Hooking sub_140E6F830 and bailing when target == duplicate
    // preempts the entire downstream chain. Aim resolution (upstream)
    // and projectile launch (separate sub_140DFF6B0 path) are
    // unaffected — only the action-execute bookkeeping is skipped.
    // BUILD64_DISABLED — (void)install_ghost_ai_action_execute(module_base);

    // B6.6w5 Build 28f — IsAttachable bypass hook. TLS-gated: only
    // affects our spawn thread when the flag is set in
    // spawn_ghost_proxy. Allows PlaceAtMe → dispatcher to take the
    // "non-attached actor" init path without crashing on the player's
    // transient cell-context fields.
    (void)install_ghost_is_attachable(module_base);

    // Build 30 Fix 2 — Hostility-rank baseForm guard.
    // Hooks sub_140C8DFF0 (RVA 0xC8DFF0) to validate baseForm sanity
    // before the engine's factions BSTArray walk. Prevents the AV at
    // RVA 0x308AE7 (sub_140308AA0) when AddTarget's validator iterates
    // a raider's controller+32 known_targets[] containing stale handles.
    // Verified Build 29.2 live test 2026-05-16 08:11:48: crash inside
    // sub_140C8DFF0 reading *(*(known_tgt+0xE0)+0xB8) — bypass returns 0
    // (no hostility) for invalid actor pointers, preserves vanilla
    // behaviour for valid pointers.
    // BUILD64_DISABLED — (void)install_ghost_hostility_guard(module_base);

    // Build 65.c.29 — DIRECT collector guard on sub_140308AA0. This is the
    // anti-crash net for the AV at RVA 0x308AE7 (faction-list walk on a
    // freed/garbage array). The old sub_140C8DFF0 guard above (BUILD64_
    // DISABLED) covered only 1 of 15 callers; this one guards the collector
    // itself = ALL callers. Re-confirmed live-crashing in Build 65.c.28.1
    // (coc cell teardown: source count read as 0x1C87A4 garbage → AV).
    // Installed UNCONDITIONALLY — it is pure defensive validation (count
    // sanity + SEH), no AI-control behaviour, so the Build 64 "AI hooks
    // disabled" rationale does not apply.
    (void)install_ghost_faction_collect_guard(module_base);

    // Build 65.c.30 — player-death cell-teardown crash guard on sub_1404CAE90.
    // Prevents the AV at RVA 0x4CAF43 (read of *([2131]+0x50) where the
    // player-target singleton global[2131] (RVA 0x30E0210) is NULL during the
    // FO4 death-cam → "load last save" cell-unload window, ~8s after the local
    // player dies). Disasm/xref proven in re/crash_0x4CAF43_death_AGENT.md:
    // caller chain = TESObjectCELL::~TESObjectCELL → sub_140D4CE10 (music-changer
    // ref-clear) → sub_1404CAE90. Guard returns 0 (= the function's own "no
    // target" path) when [2131] is null; both callers act benignly on 0.
    // Installed UNCONDITIONALLY — pure defensive null-check + SEH, cold path.
    (void)install_ghost_target_resolve_guard(module_base);

    // ============================================================
    // Build 50 Strada A (2026-05-22) — Layer-1 IsHostile gateway hook.
    //
    // Hooks sub_140C7AD40 (RVA 0xC7AD40) to force-return 1 (hostile)
    // when ghost is either operand. Sits structurally ABOVE the existing
    // hostility_guard layer-3 hook on sub_140C8DFF0 — catches the engine's
    // cached, in-combat, has-owner, and has-rank-record short-circuit
    // paths that bypass C8DFF0 entirely (which is exactly why the
    // layer-3 FORCE-HOSTILE branch counter stayed at 0 across Builds
    // 40-49 despite ghost being in cell with raiders).
    //
    // Verified by re/strada_A_ishostile_master/:
    //   - A_AGENT_body_decomp.md     (92% conf, GREEN)
    //   - B_AGENT_caller_xref.md     (85% conf, GREEN; ~95% coverage)
    //   - C_AGENT_side_effects.md    (60% conf, YELLOW-GREEN;
    //                                 downstream gates B+C unproven)
    //   - SUPERVISOR_SYNTHESIS.md    (60% aggregate, GREEN to ship)
    //
    // Aggregate confidence:
    //   95% safe-to-ship (SEH cage + atomic-load + self-check).
    //   95% unblocks gate A (hostility).
    //   80% unblocks gate D (alive count via EnterCombat).
    //   45-55% raiders visibly fire at ghost without puppet-fire fallback.
    //
    // Stop-loss criteria in SUPERVISOR_SYNTHESIS.md §10. Pivot to
    // Strada B (manual CombatAimController allocation via sub_140E653D0)
    // only if FORCE-1 count > 100 but raiders rotate without firing.
    // BUILD64_DISABLED — (void)install_ghost_hostility_guard_layer1(module_base);

    // Build 55e (2026-05-23) — Actor vt[197] IsHostileTo guard.
    //
    // Bails on ghost-involving queries to prevent the +0x418→+0x80 NULL+8
    // vtable AV documented in re/crash_0xCA8624/AGENT_ca8624_analysis.md.
    // Root cause: Build 35.1's s_buf_418 (zero buffer at ghost+0x418)
    // satisfies sub_1408800C0's null-check-free read at +0x1C8 but NOT
    // sub_140CA85C0's secondary-override path which walks +0x80 as a
    // vtable pointer — our zero buffer dereffed there as NULL → AV at
    // addr=0x8 (= vtable[1] slot).
    //
    // Trigger live-observed Build 55d 16:42:44.746 (Client B): player_B
    // died, engine death-event fan-out called Actor vt[197] on ghost,
    // crash within 159ms of cell-sync making ghost enumerable.
    //
    // Returning 0 (= not hostile) from this dispatcher is architecturally
    // safe: our cross-peer aggro uses apply_npc_combat_target's direct
    // aiproc+0x6C write, not engine IsHostileTo perception calls. Engine
    // takes a benign path when ghost is "not hostile" from vt[197].
    (void)install_ghost_vt197_guard(module_base);

    // ========================================================================
    // Build 57 (2026-05-23) — Global Walker Guards (7 hooks).
    //
    // Source: 6-agent RE arena 2026-05-23 (re/walker_inventory/AGENT_A..F).
    // The arena enumerated every engine global walker that dispatches a
    // virtual call on collection entries — form table, cell ref_lists,
    // combat controller arrays, death/cleanup walkers, perception/hostility,
    // global per-frame thunks. Identified the ACTUAL root cause of the
    // 0xE98860 crash that defeated Builds 55f/55h/56:
    //
    //   The crash is NOT a vtable dispatch. It's a scalar `cmp [r8+rdx], ecx`
    //   inside `sub_140E98820` (CombatController::FindEntryByFormID) when
    //   `*(controller+0x08) == 0xFFFFFFFFFFFFFFFF` (poisoned entries-base).
    //   Single hook on sub_140E98820 that pre-checks the entries-base and
    //   returns 0 ("not found") kills the entire 27-caller AV class.
    //
    // 6 additional hooks installed for defense-in-depth + Agent-predicted
    // next-crash surfaces:
    //   Hook 2: sub_140E918C0 ProcessTick — skip when ctrl poisoned/ghost
    //   Hook 3: sub_140E988A0 Housekeeping — skip when ctrl poisoned/ghost
    //   Hook 4: sub_140E91D70 AddKnownTarget — bail when entries-base poisoned
    //   Hook 5: sub_140C06AC0 FormRehydrator — skip while ghost active
    //   Hook 6: sub_140C80D70 DeathBroadcast — skip when dying == ghost
    //   Hook 7: sub_140DA28A0 LOSSightCone — skip while ghost active (predictive)
    //
    // Replaces Build 56 Option C (deregister) which failed with SEH inside
    // lock+erase at sub_141659060.
    (void)install_ghost_global_walker_guards(module_base);

    // ========================================================================
    // B6.6w5 Build 20 (2026-05-13 evening) — RE-ENABLE DIAGNOSTIC HOOKS.
    //
    // Live test Build 19 showed:
    //   - ghost_ai_set_combat_target: 600+ SUBSTITUTE entries (server target
    //     0x14 forced into aiproc+0x6C via direct write).
    //   - ghost_ai_action_execute: 10 fires, 0 BAIL (= raiders never fire
    //     ON the duplicate; targets are real actors 1D4A9F.../1D4A26...).
    //   - duplicate ptr = 000001D4AB110150 (fid 0xFF000001), confirmed
    //     never seen by action_execute.
    //
    // Conclusion: between SetCombatTarget (writes duplicate handle) and
    // BGSActionData::Execute, SOMETHING in the engine validates / rewrites
    // the target. Re-enable the 4 disabled diagnostic hooks (package,
    // combat_target [Sync mirror], aim, fire-decide, dispatch-attack)
    // in pure passthrough mode to observe what the engine actually does
    // with the substituted target across each pipeline stage:
    //
    //   1. ghost_ai_package      → which packages evaluate hostile/attack?
    //   2. ghost_ai_combat_target → SyncCombatTargetFromAIProcess mirrors
    //                               aiproc+0x6C → actor+0x380; log values.
    //   3. ghost_ai_aim          → what target_pos (x,y,z) is the raider
    //                               actually aiming at?
    //   4. ghost_ai_dispatch     → universal attack funnel; what target
    //                               flag/action_id come through?
    //   5. ghost_ai_fire         → DecideAndFire decision per AI tick.
    //
    // All 5 are PASSTHROUGH-safe in the current scenario:
    //   - ghost_ai_package: only substitutes when server.package_form_id!=0
    //     (not used in Phase A → always passthrough).
    //   - ghost_ai_combat_target: mirror substitution DISABLED in source
    //     (per B6.5w13 root analysis); pure log+passthrough.
    //   - ghost_ai_aim: pure passthrough + DIAG first 5 fires.
    //   - ghost_ai_dispatch / fire: BAIL only when should_silence_combat()
    //     returns true (= server registered + combat_target_form_id==0).
    //     During an active aggro test server sends 0x14 continuously, so
    //     predicate returns false → passthrough.
    // STILL DISABLED (too invasive for diag pass):
    //   - ghost_ai_havok_step       (havok physics interfering risk)
    //   - ghost_ai_hit_applier      (damage path bail, irrelevant for diag)
    //   - ghost_ai_combat_orchestrator (top-level NUKE, too invasive)
    //   - ghost_ai_process_movement  (pending review)
    // ========================================================================
    s.ghost_ai_package_ok       = false;  // BUILD64_DISABLED — install_ghost_ai_package
    s.ghost_ai_combat_target_ok = false;  // BUILD64_DISABLED — install_ghost_ai_combat_target
    s.ghost_ai_aim_ok           = false;  // BUILD64_DISABLED — install_ghost_ai_aim
    // Build 65.c.16 — RE-ENABLED for owner-driven fire detection.
    // The detour now: (1) runs vanilla engine GunFire DecideAndFire,
    // (2) if the engine actually fired AND `is_owner_of(fid)` is true,
    // emits NPC_FIRE_FROM_OWNER over the wire so server can relay to
    // non-owner peers. Non-owner peers then replay the shot via
    // engine::fire_actor_weapon (projectile + muzzle flash + audio).
    s.ghost_ai_fire_ok          = install_ghost_ai_fire(module_base);
    // BUILD64_DISABLED — (void)install_ghost_ai_dispatch_attack(module_base);

    // Build 47 (2026-05-17 night) — all hooks RE-ENABLED per user directive.
    // Build 65.c.10 (2026-05-26) — RE-ENABLED for owner-driven sync. The
    // predicate-flip block at the top of the detour (see
    // ghost_ai_havok_step.cpp Build 65 block) bails the physics step ONLY
    // when `is_non_owner_tracked(fid)` is true — i.e. some other peer owns
    // this NPC. For owners and untracked actors, the original Build 64
    // gate (`should_freeze_actor` + native_combat_fid_exists) runs
    // unchanged. Without this hook the engine's 60 Hz physics integrator
    // fights our 10 Hz `apply_npc_pos` writes on non-owner clients →
    // visible vibration (user feedback after Build 65.c.10 test).
    s.ghost_ai_havok_step_ok    = install_ghost_ai_havok_step(module_base);
    //
    // Build 52 (2026-05-23) — DISABLED ghost_ai_hit_applier.
    //
    // Live test Build 51 (logs 03:53-03:56) showed:
    //   - synthesize_combat_extension_for_ghost_target succeeded 7x for
    //     Concord raiders (HighProcess + 2 AimController allocated)
    //   - [combat-force] alive-boost FIRED for first time in 50+ builds
    //   - [combat-force] post-pick OVERRIDE sustained (no decay)
    //   - BUT [ghost_ai_hit] BAIL count = 27235 — every damage attempt on
    //     a server-tracked raider was suppressed → raiders IMMORTAL
    //   - User observation: HUD "raider" bar flickering hostile/neutral
    //     rapidly — the engine tries to sustain combat but damage
    //     feedback is missing so it can't validate engagement
    //
    // Root cause of damage suppression: ghost_ai_hit_applier BAIL
    // predicate is `should_freeze_actor(target_fid)` which returns true
    // for ANY actor with cache.movement_override != 0. Server marks all
    // tracked raiders with movement_override=1. So:
    //   - Player_A shoots raider → engine calls sub_140CD2780
    //     (central hit applier) with target=raider
    //   - Hook intercepts, sees raider is "tracked", BAILS → no HP write,
    //     no hit-react, no ragdoll
    //
    // The original purpose was "anti-crash on damage to frozen NPC" but
    // current architecture isn't using puppet-mode (raiders run vanilla
    // AI with our cross-peer aggro setup, NOT controlled by server). So
    // the bail is harmful, not protective.
    //
    // Disabling. Vanilla damage flow restored. Raiders mortal.
    // Side effect: may also unblock the "no-progress-in-combat" decay
    // that causes the flicker (gate D's alive-boost forces +0x110=1
    // but if hit count not incrementing, engine may still demote).
    //
    // c.39b — RE-ENABLED as OBSERVE-ONLY. The Build 52 disable was because the
    // hook BAILED damage (harmful). The c.39b rewrite never bails: it only reads
    // (victim, damage) and reports the local player's damage so the threat table
    // makes ownership/aggro follow the real fighter. All hits pass through.
    (void)install_ghost_ai_hit_applier(module_base);
    // BUILD64_DISABLED — (void)install_ghost_ai_combat_orchestrator(module_base);
    // Build 65.c.17 — re-enabled. Same rationale as pos_belt / actor_setpos
    // above: predicate flip (65.c.3) ensures owner runs vanilla and
    // non-owner bails, eliminating the dual-writer race that produces
    // ghost flicker on the receiver client.
    (void)install_ghost_ai_process_movement(module_base);

    // BUILD64_DISABLED — (void)install_ghost_combat_force(module_base);
    // BUILD64_DISABLED — (void)install_event_dispatch_guard(module_base);
    // BUILD64_DISABLED — (void)install_cross_cell_gate(module_base);
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
    (void)install_engine_tracer(module_base);

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
      const bool subload_ok = install_subload_hook(module_base);
      if (!subload_ok) {
          FW_WRN("hooks: subrefload install FAILED");
      }

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
      const bool bsmp_ok = install_bsmodelproc_hook(module_base);
      if (!bsmp_ok) {
          FW_WRN("hooks: bsmodelproc install FAILED");
      }

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
