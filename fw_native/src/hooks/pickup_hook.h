// B1.n: hook on PlayerCharacter::vt[0xEC] = sub_140D62930 @ RVA 0xD62930.
//
// Captures the "player presses E on a world REFR (stimpak on table, ammo
// on floor, weapon leaning on a wall)" → picks up to inventory path.
//
// Live test 2026-04-21 confirmed this path does NOT fire vt[0x7A]
// (the container_hook target), so without this second hook world-placed
// items get duplicated across peers: A picks up a stimpak, B still sees
// it and can pick it up again (inventory drift, game loop broken).
//
// Output of the hook (on match + filter): ACTOR_EVENT DISABLE fire-and-
// forget, piggybacking on the B0 ACTOR_EVENT pipeline. Server + receiver
// already know how to handle DISABLE. Receiver's set_disabled_validated
// will disable the corresponding REFR on their local engine, making the
// world item invisible/un-pickupable there too.
//
// Filter: we must NOT emit if this invocation is a ContainerMenu withdraw
// (also routes through vt[0xEC] via sub_14103D3E0) — vt[0x7A] already
// covers those. See pickup_hook.cpp for filter rules.
//
// MUST run after install_container_hook (shares the ApplyingRemoteGuard
// thread-local for feedback-loop protection).

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_pickup_hook(std::uintptr_t module_base);

} // namespace fw::hooks
