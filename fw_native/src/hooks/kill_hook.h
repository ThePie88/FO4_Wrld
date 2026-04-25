// Hook on the converged Actor::Kill entry point (sub_140C612E0).
// Signature: (Actor* victim, Actor* killer, ?, u8 silent, int)
//
// Previously in the Frida era this was `Interceptor.attach(KILL_ENGINE_RVA)`
// with an onEnter that read (victim, killer) identity and shipped an
// `actor_killed` send() up to Python. Here we install a MinHook detour
// that does the same work in-process — in B0.3 we only log; the network
// send lands in B0.4 once the C++ protocol port is ready.
//
// The detour MUST call through to the original Kill to preserve vanilla
// gameplay. The game expects the function to run; if we silently swallow
// the call, we desync actor death state and break the whole engine.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Installs and enables the kill hook. Returns true on success, false if
// MinHook rejected the target (bad address, already hooked, etc).
bool install_kill_hook(std::uintptr_t module_base);

} // namespace fw::hooks
