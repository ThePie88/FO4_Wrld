// Thin wrapper over MinHook. Owns the lifecycle (init/uninit) of the
// hooking library and exposes a typed install primitive we'll use from
// the per-hook modules in B0.3 (kill, container, pos tick, ...).
//
// Not a singleton class on purpose — the library is effectively a
// singleton already (`MH_Initialize()` is process-global), so wrapping it
// in a static namespace API is simpler and less OOP ceremony.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Initialize MinHook. Idempotent-ish: safe to call twice, second call is
// a no-op but logs a warning. Returns true on success.
bool init();

// Remove all hooks and tear down MinHook. Call at DLL_PROCESS_DETACH.
void shutdown();

// Install a detour: replaces the function at `target` so it jumps to
// `detour`, and writes the original-call trampoline address to `*original`.
// The original pointer lets the detour call through to vanilla behavior.
//
// Returns true on success. On failure, logs the MH_STATUS at ERR level.
// Caller retains ownership of the trampoline pointer for its lifetime
// (it's managed by MinHook internally).
//
// After install, hooks are ENABLED immediately via MH_EnableHook. If you
// need deferred enable, don't use this helper — call MinHook directly.
bool install(void* target, void* detour, void** original);

} // namespace fw::hooks
