// Build 44 (2026-05-17) — event-dispatch vtable-validity guard.
//
// Detours `sub_140DEF780` @ RVA `0xDEF780`. This is an internal engine
// event dispatch helper that, on entry, immediately calls
// `vt[3](a2, a1)` (= `(*(void(**)(a2,a1))((*a2)+0x18))(a2, a1)`)
// at disasm offset 0x1C..0x22:
//
//   0x140DEF78D  mov rax, [rdx]          ; rax = a2->vtable
//   0x140DEF79F  call qword ptr [rax+0x18]
//
// Build 43b live test (2026-05-17 08:20:09) crashed here with
//   rcx = 0x12A6DD8BA40       (the called function's "this" arg)
//   rip = 0x12A6DD8BAE8       (= rcx + 0xA8, the called fn entry)
//   fault = EXEC at 0x12A6DD8BAE8
//   in_game = 0  (NOT in module text range)
//
// The vtable slot `[a2.vt + 0x18]` contained a HEAP pointer
// (0x12A6_xxxxxxxx is far below the module's 0x7FF6_xxxxxxxx range)
// instead of a function pointer. Use-after-free on the event sink
// `a2`: the combat orchestrator scheduled an event on a sink that was
// already deallocated; the freed memory got reused as plain heap
// data, then we tried to call `vt[3]` on it → execute non-code.
//
// This bug ONLY exposes after Build 43b made cross-peer combat
// actually engage — previously the engine never reached this path
// for our tracked raiders. The vtable corruption is intrinsic to the
// engine's combat brain when events outlive their target objects in
// our cross-peer scenario.
//
// FIX: validate `*(*a2 + 0x18)` is a real function pointer (= within
// the game's module .text range) before letting the orig run. If
// invalid, bail with a safe return value (0 = "didn't dispatch").
// The event is silently dropped instead of crashing. Engine continues.
//
// Scope: ONLY guards the entry-time vt[3] dispatch. Other vt calls
// later in sub_140DEF780 (vt[2], vt[4], vt[1] on a1, etc.) are NOT
// guarded — if they also crash, additional checks needed.
//
// Each detour fire is SEH-caged. First 8 fires + every 200th heartbeat
// logged. BYPASS count tracked separately.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_event_dispatch_guard(std::uintptr_t module_base);

std::uint64_t get_event_dispatch_fires();
std::uint64_t get_event_dispatch_bypasses();
std::uint64_t get_event_dispatch_seh_failures();

} // namespace fw::hooks
