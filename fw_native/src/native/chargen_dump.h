// Character-creation asset dump (2026-08-06).
//
// PURPOSE
//   One clean vanilla session with the character-creation menu open, cycling
//   every preset and slider, while this records everything the engine touches.
//   The output is the catalogue the whole character-customisation epic is
//   built on: which meshes exist per category, which morph sets back which
//   slider, which textures and materials dress them.
//
//   Deliberately dumb and exhaustive. Volume does not matter; sorting happens
//   afterwards, offline. Nothing here interprets or filters — a line per event,
//   append-only, so a capture can never be lost to a clever filter that turned
//   out to be wrong.
//
// OUTPUT
//   fw_chargen_dump.log next to the game executable. Truncated once per
//   process so each capture session stands alone.
//   Format: one record per line, tab-separated, first field is the kind:
//       <ms since start>  <kind>  <field>=<value>  <field>=<value> ...
//   Kinds are free-form strings so new capture points can be added without
//   touching readers.
//
// COST WHEN OFF
//   A single relaxed atomic read per call site. The dump is opt-in through
//   the `chargen_dump` config key and is off in normal play.

#pragma once

#include <cstdint>
#include <string>

namespace fw::native::chargen_dump {

// Open the dump file. Called from install_all when the config key is set.
// `dir` is the game directory. Idempotent.
void init(const std::wstring& dir, bool enabled);

// True while a capture session is active. Call sites should check this before
// doing any work beyond passing values they already hold.
bool enabled() noexcept;

// Record one event. `kind` labels the capture point ("nif", "tri", "texture",
// "material", "headpart", "morph", ...); `detail` is a pre-formatted
// tab-separated field list. Thread-safe; safe to call from any thread and from
// inside an engine detour.
void note(const char* kind, const char* detail) noexcept;

// Convenience for the common "a resource path was requested" case.
void note_resource(const char* kind, const char* path) noexcept;

// Line count written so far, for the summary line at shutdown.
std::uint64_t records() noexcept;

// Install the capture detours (resource loaders, the LooksMenu callback
// dispatcher, and the morph writer). No-op when the dump is disabled.
bool install(std::uintptr_t module_base);

// Walk TESDataHandler's per-type form arrays and write the FULL catalogue —
// every head part in the game with its mesh, type, editor id and morph files,
// plus races and colour forms. Independent of what the session happens to
// load, so the catalogue does not depend on the player remembering to click
// every entry. Called repeatedly from the main-thread tick; dumps once, when
// the data handler first has content, then disarms itself.
void maybe_dump_catalogue(std::uintptr_t module_base) noexcept;

}  // namespace fw::native::chargen_dump
