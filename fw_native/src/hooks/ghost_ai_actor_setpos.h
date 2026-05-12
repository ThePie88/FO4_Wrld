// B6.5w14 hook #6 — Actor::SetPosition (vt[202] complete body).
//
// Per re/B6.5w14_pair_AGENT_1A.md (95% conf): sub_140C60630 @ 0x00C60630
// calls SetPosition_NiPoint3 AND writes NIF+0x60 directly. Bailing the
// whole function blocks both paths. Without this, hook #5 alone fails
// because NIF+0x60 → UpdateWorldData → NIF+0xA0 → renderer sees translation.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_actor_setpos(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_actor_setpos_fires();
std::uint64_t get_ghost_ai_actor_setpos_bails();
std::uint64_t get_ghost_ai_actor_setpos_seh_failures();

} // namespace fw::hooks
