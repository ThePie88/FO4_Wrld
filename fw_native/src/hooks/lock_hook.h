// B6.3 v0.5.3 — lock state sync hook.
//
// Hooks the engine's two ExtraLock mutators on TESObjectREFR:
//   - ForceUnlock (sub_140563320, RVA 0x563320)
//   - ForceLock   (sub_140563360, RVA 0x563360)
// Signature for both: void(__fastcall)(TESObjectREFR* refr).
//
// Coverage of these two narrow funnels (RE'd 2026-05-08 across the full
// decomp xrefs):
//   - lockpick minigame success (sub_14106BE80) → ForceUnlock
//   - terminal hack success                     → ForceUnlock
//   - AI lock/unlock package (sub_140CEE8F0/9C0) → ForceLock/Unlock
//   - perk auto-unlock effect (sub_140B92A10)   → ForceUnlock
//   - savefile load                              → ForceUnlock
// MISSES (uncommon paths, accept the gap for v0.5.3):
//   - Papyrus ObjectReference.Lock/Unlock (calls sub_141158640 directly)
//   - magic LockEffect (sub_140B81EB0, creates new lock; not "flip")
//
// On fire, the detour reads the post-state from LockData (sub_140563170
// returns LockData* or null; flag bit 0 at +0x10 = LOCKED) and broadcasts
// (form_id, base_id, cell_id, locked) as LOCK_OP. Receiver looks up the
// REFR and applies via the Papyrus binding sub_141158640 with
// ai_notify=0 — bypasses the lockpicking minigame and key consumption.
//
// Feedback-loop guard: receiver-side apply (sub_141158640) recurses into
// ForceUnlock/ForceLock. The drain that calls the apply sets the shared
// `tls_applying_remote` flag (same one container_hook + door_hook use)
// so the recursive hook fire is filtered before broadcast.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_lock_hook(std::uintptr_t module_base);

} // namespace fw::hooks
