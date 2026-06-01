// B6.6w5 Build 28g — IsAttachable / AttachREFR root-level bypass.
//
// **Build 28f** (return 0 = non-attached path) didn't reach engine's
// full per-cell init: dispatcher's non-attached branch only sets flag
// bits (sub_140CA3A50/CA3AB0/C92EF0), never calls vt[191](actor, cell)
// which is THE function that populates `actor+0x48` (and friends).
// Result: post-spawn crash at sub_1404C4DF0 reading proxy+0x48 = NULL.
//
// **Build 28g pivot** (user directive "tocchiamo le radici"):
// hook BOTH cell-attach root functions with TLS bypass:
//   - sub_1403095C0 IsAttachable → return **1** (TRUE) during spawn
//   - sub_1403097E0 AttachREFR  → **no-op** (return success) during spawn
//
// With IsAttachable=TRUE, the engine takes the ATTACHED path:
//   - PlaceAtMe line 1941: `AttachREFR(cell, actor)` → our no-op hook
//   - Dispatcher line 6849-6864 attached branch:
//       `vt[191](actor, cell)` ← populates actor+0x48, +0x418, etc.
//       `AttachREFR(cell, actor)` ← our no-op
//       `vt[191](actor, 0)`     ← cleanup
//
// Net result: engine BELIEVES the actor was attached to the cell and
// runs its full per-cell init pipeline. The actual heavy AttachREFR
// (physics, render bind, audio) is skipped via our no-op so no
// expensive side-effects and no AV on transient cell state.
//
// TLS scope: flag is set ONLY during our `spawn_ghost_actor` call on
// the main thread. Other threads/callers see flag=false → passthrough
// orig.
#pragma once

#include <cstdint>

namespace fw::hooks {

// Sets/clears the TLS bypass flag. Set BEFORE calling PlaceAtMe;
// clear AFTER. Same flag drives BOTH IsAttachable=TRUE override AND
// AttachREFR no-op override.
//
// (Function name kept for source-compat with Build 28f; semantic
// changed: it no longer "forces not attachable", it "forces engine to
// believe attach succeeded".)
void set_force_not_attachable(bool v);

// Install the MinHook detours. Idempotent. Installs BOTH IsAttachable
// and AttachREFR (Build 28g).
bool install_ghost_is_attachable(std::uintptr_t module_base);

// Counter accessors for diagnostics.
std::uint64_t get_is_attachable_bypass_count();
std::uint64_t get_is_attachable_passthrough_count();
std::uint64_t get_attach_refr_bypass_count();
std::uint64_t get_attach_refr_passthrough_count();

} // namespace fw::hooks
