cmake_minimum_required(VERSION 3.25)
project(fw_native LANGUAGES CXX)

# Fallout 4 next-gen is /arch:AVX2 only, and we share its process space.
# Sticking to the same instruction set avoids ABI surprises.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MinHook — vendored in deps/MinHook/ (git submodule or clone). Static
# build as part of our DLL; no redistribution concern.
add_subdirectory(deps/MinHook EXCLUDE_FROM_ALL)

# Proxy DLL. The Windows loader picks up `dxgi.dll` in the game root
# BEFORE hitting C:\Windows\System32, so our file name must match exactly.
add_library(fw_native SHARED
    src/dll_main.cpp
    src/proxy_exports.cpp
    src/log.cpp
    src/version.cpp
    src/hook_manager.cpp
    src/main_thread_dispatch.cpp
    src/ref_identity.cpp
    src/hooks/install_all.cpp
    src/hooks/kill_hook.cpp
    src/hooks/container_hook.cpp
    src/hooks/put_hook.cpp
    src/hooks/pickup_hook.cpp
    src/hooks/player_pos_hook.cpp
    src/hooks/main_menu_hook.cpp
    src/hooks/worldstate_hook.cpp
    src/hooks/door_hook.cpp         # B6.0: Activate worker for door open/close
    src/hooks/lock_hook.cpp         # B6.3: ForceUnlock + ForceLock detours
    src/hooks/npc_ai_suppress.cpp   # B6.5w4: Actor::Update_PerFrame suppression for tracked NPCs
    src/hooks/ownership_manager.cpp # Build 65: DLL-side mirror of server NPC ownership registry (Solver 2)
    src/hooks/puppet_update_perframe.cpp # B6.6w0: KEEP-ALWAYS replacement body invoked by npc_ai_suppress bail path
    src/steam/steam_id.cpp          # B6.6w5: local Steam ID reader (real Steam + Goldberg)
    src/hooks/ghost_ai_package.cpp  # B6.5w12 hook #1: TESPackage::EvaluateConditions (server picks active package)
    src/hooks/ghost_ai_combat_target.cpp  # B6.5w12 hook #2: SyncCombatTargetFromAIProcess (server picks combat target)
    src/hooks/ghost_ai_aim.cpp            # B6.5w12 hook #3: CombatAimController::SetAimTarget (server picks aim vector)
    src/hooks/ghost_ai_movement.cpp       # B6.5w12 hook #4: Actor::TickMovementController (server BAILs movement when override set)
    src/hooks/ghost_ai_pos_belt.cpp       # B6.5w13 hook #5: SetPosition_NiPoint3 (belt-and-braces for AIPackage warp paths)
    src/hooks/ghost_ai_actor_setpos.cpp   # B6.5w14 hook #6: vt[202] Actor::SetPosition full (catches NIF+0x60 bypass per agent 1A)
    src/hooks/ghost_ai_havok_step.cpp     # B6.5w15 hook #7: bhkCharRigidBodyController FinishPhysicsStep DIAGNOSTIC (per agent 5A)
    src/hooks/ghost_ai_fire.cpp           # B6.6w0 hook #3 (fire decision): CombatBehaviorGunFire::DecideAndFire (Phase B bail tracked, single-shot only)
    src/hooks/ghost_ai_dispatch_attack.cpp    # B6.6w0 (dispatch attack) — universal attack action funnel per C1
    src/hooks/ghost_ai_process_movement.cpp   # B6.6w0 (movement intent) — AIProcess::ProcessPackages_Movement per B1
    src/hooks/ghost_ai_set_combat_target.cpp  # B6.6w0 (combat target writer DIAG) — AIProcess::SetCombatTarget per A1+A2
    src/hooks/ghost_ai_action_execute.cpp     # B6.6w5 Build 18 — bail BGSActionData::Execute on duplicate target
    src/hooks/ghost_ai_hit_applier.cpp        # B6.6w0 (hit applier orchestrator BAIL) — sub_140CD2780 per D2 — prevents crash on damage to frozen
    src/hooks/npc_hp_probe.cpp                # N3 step 1: READ-ONLY HP-funnel probe (sub_140CC9650) — validates RE before capture+clamp
    src/hooks/hp_bar_hook.cpp                 # v18: shared-pool HP override on the enemy bar (HUDEnemyHealthMeter Invoke)
    src/hooks/ghost_ai_combat_orchestrator.cpp # B6.6w0 NUKE (top-level combat orchestrator BAIL) — sub_140CCFDF0 = Actor::vt[255] per A1
    src/hooks/cross_cell_gate.cpp   # Build 38: sub_140CF6100 detour — transient ghost+0xB8 swap to defeat PC.cell==target.cell gate at funcs_0309:9926
    src/hooks/ghost_combat_force.cpp # Build 40: 4-hook surgical decision override (hostility, alive-count, cell-loaded, post-pick) — dossier-driven
    src/hooks/event_dispatch_guard.cpp # Build 44: sub_140DEF780 vtable-validity guard — blocks EXEC fault on stale event sinks
    src/hooks/equip_cycle.cpp       # B8  : post-LoadGame BipedAnim normalize (DISABLED 2026-05-08, see equip_announce.h)
    src/hooks/equip_announce.cpp    # B8 successor (NON TESTATO): apparel bootstrap broadcast — Option B scaffold
    src/hooks/equip_hook.cpp        # M9 w1: equipment-event sender hook
    src/hooks/engine_tracer.cpp     # M6.3: native NIF-load path observation
    src/hooks/subrefload_hook.cpp   # M9 closure: live capture of sub_1404580C0 args
    src/hooks/bsmodelproc_hook.cpp  # M9 closure: live capture of BSModelProcessor post-hook
    src/net/udp_socket.cpp
    src/net/reliable.cpp
    src/net/client.cpp
    src/config.cpp
    src/engine/engine_calls.cpp
    src/render/present_hook.cpp
    src/render/triangle_render.cpp
    src/render/body_render.cpp      # Path A archived, compiled but not invoked
    src/render/dsv_capture.cpp      # Path A archived, compiled but not invoked
    src/render/scene_render_hook.cpp  # β.6: hook 3D scene walker (reserved)
    src/render/vp_capture.cpp         # β.6: capture real scene VP (sub_1421DC480)
    src/render/head_placeholder.cpp   # β.6: procedural sphere head until real mesh
    src/assets/fwn_loader.cpp       # Path A archived, compiled but not invoked
    src/ghost/actor_hijack.cpp      # Path B ghost pipeline
    src/native/scene_inject.cpp     # Strada B M1: native scene graph injection
    src/native/scene_walker.cpp     # Strada B M2.1: diagnostic scene graph walker
    src/native/skin_rebind.cpp      # M8P3 step 1: BSSkin::Instance diagnostic walker
    src/native/nif_path_cache.cpp   # M9 w4 witness pattern step 1: NiAVObject*→path cache
    src/native/weapon_witness.cpp   # M9 w4 witness pattern step 2: walker for player BipedAnim weapon subtree
    src/native/bsgeo_input_cache.cpp # M9 w4 Path B-alt-1: factory input cache (BSTriShape* → vertex/index)
    src/native/ni_alloc_tracker.cpp  # M9 w4 Path B-alt-2: pool allocator caller RIP capture
    src/native/clone_factory_tracker.cpp # M9 w4: BSTriShape clone factory hook + hex dump
    src/native/weapon_capture.cpp        # M9.w4 PROPER (v0.4.2+): clone-factory-driven mesh capture
    src/native/spai_prewarm.cpp          # SPAI Tier 1: force-prewarm of weapon NIF resmgr
    src/native/synthetic_refr.cpp        # M9 closure (2026-05-07): synthetic TESObjectREFR weapon assembly
    src/diag/crash_veh.cpp               # B6.6w5 Build 22: VEH for AV diagnostics on duplicate-deref crashes
    src/hooks/ghost_is_attachable.cpp    # B6.6w5 Build 28f: TLS-gated bypass for IsAttachable during proxy spawn
    src/hooks/ghost_hostility_guard.cpp  # B6.6w5 Build 30 Fix 2: baseForm guard on sub_140C8DFF0
    src/hooks/ghost_hostility_guard_layer1.cpp  # Build 50 Strada A: layer-1 IsHostile gateway hook on sub_140C7AD40
    src/hooks/ghost_vt197_guard.cpp             # Build 55e: Actor vt[197] IsHostileTo bail-on-ghost
    src/hooks/ghost_global_walker_guards.cpp    # Build 57: 7 walker guards (kills 0xE98860 AV class)
)

target_link_libraries(fw_native PRIVATE minhook)

set_target_properties(fw_native PROPERTIES
    OUTPUT_NAME "dxgi"
    PREFIX ""
    SUFFIX ".dll"
)

# Export only the 3 real dxgi factory entry points via the .def file.
# No __declspec(dllexport) in the source — the .def is the single source of
# truth for what we advertise, so there's no chance of name mangling surprises.
target_link_options(fw_native PRIVATE
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/dxgi.def"
)

target_compile_options(fw_native PRIVATE
    /arch:AVX2        # match FO4 NG instruction set
    /W4
    /permissive-
    /EHsc
    /Zc:__cplusplus
    /utf-8
    # Release-only guards; CMake's Release config already adds /O2 /DNDEBUG
)

target_compile_definitions(fw_native PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

# Explicit system imports — WIN32_LEAN_AND_MEAN trims some.
# d3d11 added for B5 Step 1 (Present hook via kiero-style vtable capture).
# d3dcompiler added for B5 Step 2 (runtime HLSL compile via D3DCompile).
# NOT linking dxgi.lib: our output is dxgi.dll so MSVC emits dxgi.lib as
# import library, which would collide at link time with the system
# dxgi.lib (LNK1149). We don't actually need dxgi.lib because all
# IDXGI* usage in present_hook.cpp is via COM vtable (vtable[8]
# extraction) — no static symbols from the dxgi import library are
# referenced. D3D11CreateDeviceAndSwapChain is in d3d11.lib.
target_link_libraries(fw_native PRIVATE kernel32 user32 version d3d11 d3dcompiler)

# Visible build summary
add_custom_command(TARGET fw_native POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "[fw_native] built: $<TARGET_FILE:fw_native>"
    COMMAND ${CMAKE_COMMAND} -E echo "[fw_native] deploy with: deploy.bat"
)
