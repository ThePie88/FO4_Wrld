// Version fingerprint check for Fallout4.exe.
//
// All our reverse-engineered RVAs (kill hook, container vt[0x7A], pos
// offsets, etc.) were validated against Fallout 4 version 1.11.191.0.
// If the game binary is anything else — older pre-NG, newer Bethesda
// patch, a Creation Club update that relinks — those RVAs are junk and
// installing hooks on them crashes the game reliably.
//
// This module is the gate: DllMain's init thread calls `check()` and
// refuses to proceed to hook installation unless the check returns
// `Match`. On mismatch we stay inert (log + forward-only) so FO4 still
// boots and the user can diagnose.

#pragma once

#include <string>

namespace fw::version {

// Expected binary version. Bump if we revalidate against a new build.
constexpr const char* EXPECTED = "1.11.191.0";

enum class Result {
    Match,        // exact expected version
    Mismatch,     // resolvable version, but different from EXPECTED
    Unresolvable, // couldn't read VERSIONINFO — treat as Mismatch
};

// Reads the VERSIONINFO resource of the currently-loaded Fallout4.exe
// and compares against EXPECTED. `actual_out` (if non-null) is set to
// the resolved "MAJOR.MINOR.PATCH.BUILD" string (empty on Unresolvable).
Result check(std::string* actual_out = nullptr);

} // namespace fw::version
