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
    bool door_ok        = false;    // B6.1: SetOpenState mutator (phase 1 OBSERVE)

    [[nodiscard]] std::size_t success_count() const noexcept {
        return (kill_ok ? 1u : 0u)
             + (container_ok ? 1u : 0u)
             + (put_ok ? 1u : 0u)
             + (pickup_ok ? 1u : 0u)
             + (player_pos_ok ? 1u : 0u)
             + (main_menu_ok ? 1u : 0u)
             + (worldstate_ok ? 1u : 0u)
             + (door_ok ? 1u : 0u);
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
