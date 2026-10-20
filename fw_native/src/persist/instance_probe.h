// L5 stage 4a (2026-10-02) — the measurements stage 4 is designed on.
//
// The replay of stage 4 keys every weapon, armour piece and core on an id
// the server mints, bound on each client to the engine's own per-container
// id (ExtraUniqueID, 0x9F); the world-side writers of stage 4b move stacks
// by an instance fingerprint. Both rest on facts the decomp suggests and
// nobody has measured (RESEARCH_L5_digest.md, sections REPLAY and
// world-writers-instances): the uid is reassigned at every crossing and
// survives an in-place mod, a rename, a split and a save/load; the OIE's
// u16 at +0x20 is the same on two clients for the same instance; which
// bases carry the uid flag; which stack the engine's base-only writers
// really take. This module only looks:
//   - every uid move the engine announces (sub_14052EB10, an observe-only
//     detour), with the core that made it, the thread and whether a load
//     is running;
//   - the stacks of a container and of the player around a menu transfer,
//     a remote apply, a rollback and a realignment that changes something;
//   - the capture's per-stack lines at info, in the same format.
// One switch, instance_probe in fw_config.ini; off = no detour, no line.

#pragma once

#include <cstdint>

namespace fw::config { struct Settings; }
namespace fw::persist::inventory { struct StackRecord; }

namespace fw::persist::probe {

// Reads the switch once, at install time.
void configure(const fw::config::Settings& cfg);
bool enabled() noexcept;

// Installs the uid detour when the switch is on. Returns 1 when it went in.
int install(std::uintptr_t module_base);

// Every stack of `refr` (only `base` when non-zero) as [probe] lines under
// `tag`, after a header naming the REFR. Main thread; nothing when off.
void dump(void* refr, std::uint32_t base, const char* tag);

// One stack as a [probe] line. `chain` < 0 = not known (the capture keeps
// its records in canonical order, not the engine's).
void log_stack(const char* tag, const fw::persist::inventory::StackRecord& r, int chain,
               bool transient, std::uint32_t base_flags);

} // namespace fw::persist::probe
