// B4.d: capture Papyrus worldstate mutations to broadcast to peers.
//
// Hooks the GlobalVariable.SetValue Papyrus native (sub_1411459E0). When
// a script fires the native we read the TESGlobal formID + new value and
// enqueue a GLOBAL_VAR_SET to the server (which broadcasts to other
// peers). Apply path (peer receives BCAST) lives in net/client dispatch
// and uses engine::apply_global_var for a direct memory write.
//
// Quest.SetCurrentStageID is RE'd (offsets::PAPYRUS_QUEST_SETSTAGE_RVA)
// but not hooked in this MVP — apply-side needs a main-thread dispatcher
// because the engine workers TLS-use. Future: reuse the main_menu WndProc
// subclass infrastructure for that path.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Installs the GlobalVariable.SetValue hook. Returns true on success.
bool install_worldstate_hooks(std::uintptr_t module_base);

} // namespace fw::hooks
