// Which Fallout4.exe build we are running inside, and per-build RVAs.
//
// Every RVA in this tree was reverse-engineered on 1.11.191. Builds that the
// project has been ported to are listed here; an address that moved is
// written FW_RVA(rva_191, rva_240) and resolves to the value for the running
// build. tools/rva_port/ generates the second column by matching the two
// executables (see tools/rva_port/README.md) — never edit it by hand without
// re-verifying against the binary.
//
// Detection reads the PE header of the main module (TimeDateStamp +
// SizeOfImage), which is safe from static initialisers running under the
// loader lock, unlike GetFileVersionInfo.

#pragma once

#include <cstdint>

namespace fw::build {

enum class Id : int {
    Unknown   = -1,
    V1_11_191 = 0,   // December 2025 next-gen build (the RE baseline)
    V1_11_240 = 1,   // August 2026 update
};

// Cached after the first call.
Id current();

// "1.11.191.0" etc., or "unknown".
const char* name(Id id);

// True for builds that have a full RVA column.
inline bool supported(Id id) { return id != Id::Unknown; }

inline std::uintptr_t rva(std::uintptr_t rva_191, std::uintptr_t rva_240) {
    return current() == Id::V1_11_240 ? rva_240 : rva_191;
}

} // namespace fw::build

#define FW_RVA(rva_191, rva_240) (::fw::build::rva((rva_191), (rva_240)))
