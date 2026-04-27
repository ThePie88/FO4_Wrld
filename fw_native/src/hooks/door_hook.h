// B6 wedge 1: door open/close observation hook.
//
// Hooks the engine's inner SetOpenState mutator (sub_140305760, RVA
// 0x305760). All door open/close paths converge here:
//   - live player Activate (E key)
//   - BSAutoCloseController timer
//   - Papyrus Door.SetOpen native
//   - save-load propagator (vt[0x99] sub_140510CE0)
//
// Discovery: dual-agent RE 2026-04-27, see
//   re/B6_doors_AGENT_A_dossier.txt — vtable-enumeration approach
//   re/B6_doors_AGENT_B_dossier.txt — string-xref approach
//
// PHASE 1 (this file, OBSERVE-only): the detour reads refr identity +
// the new_state/notify args and FW_LOGs. Pass-through to g_orig
// unconditionally — zero behavioral change to the engine.
//
// Goal of phase 1: count fires per keypress to validate the model.
// Expected: 1 fire per E-press on a closed/open door. If the count is
// inflated by BSAutoCloseController timer fires or animation re-evals,
// we'll need a delta filter before promoting to phase 2.
//
// PHASE 2 (deferred to next session): broadcast DOOR_OP, server fanout,
// receiver apply via direct call to sub_140305760 with feedback-loop
// guard (TLS flag, same pattern as container_hook tls_applying_remote).

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_door_hook(std::uintptr_t module_base);

} // namespace fw::hooks
