// B6.6w5 Build 22 — Vectored Exception Handler for crash diagnostics.
//
// Goal: when the engine derefs a bad field of our duplicate (which
// contains memcpy'd pointers into real_player's owned heap), the AV
// happens in engine code — we need RIP + fault_addr to map back to the
// specific engine function and decomp line. Build 18's hook on
// `sub_140E6F830` only catches the action-dispatch crash variant; the
// real production crash (Build 20 SUBSTITUTE #1 @ 18:11:11.633) happens
// UPSTREAM and currently has no observability.
//
// VEH runs BEFORE SEH __try/__except handlers. Filter rules:
//   - Only EXCEPTION_ACCESS_VIOLATION (0xC0000005)
//   - Skip RIP inside our own DLL (= SEH-caged safe_read_X helpers)
//   - Cap at 30 logs (avoid spam if cascade-faulting)
// Returns EXCEPTION_CONTINUE_SEARCH so SEH and the game's own filter
// still run; we are purely diagnostic.
#pragma once

#include <cstdint>

namespace fw::diag {

void install_crash_veh(std::uintptr_t module_base);

} // namespace fw::diag
