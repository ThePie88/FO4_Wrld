// Stable identity read from a TESObjectREFR pointer.
//
// Matches the `readRefIdentity()` helper used in the previous Frida-era JS
// bridge (Option B): we read form_id, base_id (via REFR+0xE0 → TESForm+0x14),
// and cell_id (via REFR+0xB8 → TESObjectCELL+0x14). Together they are the
// stable persistence key that survives process restarts and cross-process
// runtime-refid aliasing.
//
// All reads are guarded: if any pointer chase hits a null or invalid address,
// the corresponding field is left at 0. A structurally-exceptional read does
// NOT throw — we catch SEH at the hook boundary (not here) so a partial
// identity still returns useful data.

#pragma once

#include <cstdint>

namespace fw {

struct RefIdentity {
    std::uint32_t form_id = 0;   // REFR's own TESForm.formID
    std::uint32_t base_id = 0;   // TESForm.formID of REFR::baseForm
    std::uint32_t cell_id = 0;   // TESForm.formID of REFR::parentCell
};

// Read all three identity fields from the given REFR pointer. Returns
// zero-filled identity if `ref` is null.
RefIdentity read_ref_identity(void* ref) noexcept;

// Convenience: true iff `ref` has PlayerCharacter's hardcoded formID 0x14.
// Used by the container hook to detect which side of the transfer is the
// player. Safe to call with null (returns false).
bool is_player(void* ref) noexcept;

} // namespace fw
