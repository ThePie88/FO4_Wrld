// ============================================================================
// HP-bar sync (Build A — VALUE override). The enemy-health bar value comes from
// the crosshair/auto-aim target's LOCAL Health AV, which N3 CLAMPS to 1 → the
// vanilla bar reads ~empty for a tracked raider. We hook the meter's value-latch
// (HUDEnemyHealthMeter sink Invoke, sub_1409C28A0) and substitute the SHARED
// SERVER POOL fraction (broadcast via NPC_HP_POOL_BCAST → set_npc_pool_hp).
//
// Scope (Build A): override the value ONLY — works on whatever bar the engine
// already shows (i.e. the OWNER, whose raider is hostile). Forcing the bar to
// appear on the NON-OWNER (neutral mirror) is Build B (re/hpbar_visibility_AGENT).
//
// Zero AI/combat structures touched (pure HUD-value write) → off the entire
// crash rap-sheet. All engine reads SEH-caged; the detour is __try-free.
// RE: re/hpbar_widget_AGENT.md.
// ============================================================================
#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the MinHook detour on HUDEnemyHealthMeter's value-latch Invoke.
bool install_npc_hp_bar(std::uintptr_t module_base);

// RX entry — the server pushed the shared pool HP for a tracked raider.
// Cached per fid; the detour reads it. Thread-safe.
void set_npc_pool_hp(std::uint32_t form_id, float hp_cur, float hp_max) noexcept;

// Diagnostics.
std::uint64_t get_hp_bar_overrides() noexcept;

} // namespace fw::hooks
