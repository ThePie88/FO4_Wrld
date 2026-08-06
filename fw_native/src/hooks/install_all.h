// Single entry point for installing the active hook set:
//   - Kill engine (sub_140C612E0)          — B0
//   - Container vt[0x7A] AddObjectToContainer — B0 + B1 pre-mutation block
//   - Player pos poll (not a hook, a polling thread) — B0
//   - Main menu registrar (sub_140B01290)  — B3.b auto-Continue
//
// Called exactly once from dll_main::init_thread, after the version gate
// has confirmed 1.11.191 and MinHook is up. Each individual hook module
// logs its own success/failure; install_all returns how many succeeded
// so the caller can decide whether to abort or run partially.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::hooks {

struct InstallSummary {
    bool kill_ok        = false;
    bool container_ok   = false;
    bool put_ok         = false;    // B1.k: ContainerMenu::TransferItem
    bool pickup_ok      = false;    // B1.n: PlayerCharacter::vt[0xEC] world pickup
    bool player_pos_ok  = false;
    bool main_menu_ok   = false;
    bool worldstate_ok  = false;
    bool door_ok        = false;    // B6.0: Activate worker (door open/close)
    bool equip_ok       = false;    // M9 w1: ActorEquipManager Equip+Unequip detours
    bool lock_ok        = false;    // B6.3 v0.5.3: ForceUnlock + ForceLock detours
    bool npc_ai_suppress_ok = false; // B6.5w4: Actor::Update_PerFrame detour (per-NPC AI skip)
    bool first_person_graph_ok = false; // Ghost 1P: extra tick for graphs[0] (3P) in first person
    bool ghost_ai_package_ok = false; // B6.5w12 hook #1: TESPackage::EvaluateConditions
    bool ghost_ai_combat_target_ok = false; // B6.5w12 hook #2: SyncCombatTargetFromAIProcess
    bool ghost_ai_aim_ok = false; // B6.5w12 hook #3: CombatAimController::SetAimTarget
    bool ghost_ai_movement_ok = false; // B6.5w12 hook #4: Actor::TickMovementController
    bool ghost_ai_pos_belt_ok = false; // B6.5w13 hook #5: SetPosition_NiPoint3 (belt-and-braces)
    bool ghost_ai_actor_setpos_ok = false; // B6.5w14 hook #6: vt[202] Actor::SetPosition (catches NIF+0x60 bypass)
    bool ghost_ai_havok_step_ok = false;   // B6.5w15 hook #7: bhkCharRigidBodyController::FinishPhysicsStep (DIAGNOSTIC ONLY)
    bool ghost_ai_fire_ok = false;         // B6.6w0 hook #3: CombatBehaviorGunFire::DecideAndFire (DIAGNOSTIC in Phase A)

    [[nodiscard]] std::size_t success_count() const noexcept {
        return (kill_ok ? 1u : 0u)
             + (container_ok ? 1u : 0u)
             + (put_ok ? 1u : 0u)
             + (pickup_ok ? 1u : 0u)
             + (player_pos_ok ? 1u : 0u)
             + (main_menu_ok ? 1u : 0u)
             + (worldstate_ok ? 1u : 0u)
             + (door_ok ? 1u : 0u)
             + (equip_ok ? 1u : 0u)
             + (lock_ok ? 1u : 0u)
             + (npc_ai_suppress_ok ? 1u : 0u)
             + (first_person_graph_ok ? 1u : 0u)
             + (ghost_ai_package_ok ? 1u : 0u)
             + (ghost_ai_combat_target_ok ? 1u : 0u)
             + (ghost_ai_aim_ok ? 1u : 0u)
             + (ghost_ai_movement_ok ? 1u : 0u)
             + (ghost_ai_pos_belt_ok ? 1u : 0u)
             + (ghost_ai_actor_setpos_ok ? 1u : 0u)
             + (ghost_ai_havok_step_ok ? 1u : 0u)
             + (ghost_ai_fire_ok ? 1u : 0u);
    }
};

// `module_base` is the address of Fallout4.exe in this process (from
// GetModuleHandleW). Each hook adds its own RVA to resolve the real
// target function. `cfg` is needed for the main-menu auto-Continue
// toggle + delay.
InstallSummary install_all(std::uintptr_t module_base,
                           const fw::config::Settings& cfg);

// Cleanup counterpart. Safe to call even if install partially failed.
void stop_all();

} // namespace fw::hooks
