// Build 55e — Actor::IsHostileTo (vt[197]) guard for ghost.
//
// Hooks sub_140CA85C0 (RVA 0xCA85C0, Actor vtable slot 197) and returns 0
// (not hostile, safe) when ghost is either operand. Without this hook,
// the function dereferences ghost+0x418 (our static zero buffer s_buf_418
// installed in Build 35.1 to satisfy sub_1408800C0's null-check-free read
// at +0x1C8) and then walks the chain `*(s_buf_418 + 0x80) → NULL → +0x8`
// → AV addr=0x8 → CRASH.
//
// Trigger observed Build 55d 16:42:44.746 (Client B): player_B died,
// engine death-event fan-out called Actor vt[197] on ghost, first time
// the +0x418→+0x80 vtable path was taken on a ghost. Cell-sync had just
// written ghost+0xB8 to local PC.parent_cell at 16:42:44.587 (159ms
// earlier), making the ghost discoverable to cell-co-resident actors.
//
// Verified by re/crash_0xCA8624/AGENT_ca8624_analysis.md (HIGH confidence
// on root cause, vtable slot, signature).
//
// Fix strategy: identical pattern to ghost_hostility_guard.cpp (which
// guards sub_140C8DFF0 / HostilityCore layer-3). SEH cage + ghost
// equality check + return 0 = "not hostile". Polarity safe: returning
// "not hostile" for ghost-involving queries is always correct because
// our cross-peer aggro is driven by apply_npc_combat_target writing
// aiproc+0x6C directly, not by engine perception calling IsHostileTo.
#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the MinHook detour. Idempotent.
bool install_ghost_vt197_guard(std::uintptr_t module_base);

// Diagnostic counters.
std::uint64_t get_vt197_guard_force_count();
std::uint64_t get_vt197_guard_passthrough_count();
std::uint64_t get_vt197_guard_seh_count();

} // namespace fw::hooks
