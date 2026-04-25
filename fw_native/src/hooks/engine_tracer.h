// M6.2 — engine tracer hooks.
//
// Purpose: observe how vanilla FO4 loads character textures, so we can
// replicate the correct sequence for our injected body.
//
// The differential diag (2026-04-24) proved our body's shader/material
// classes are DIFFERENT from vanilla (0x28F9FF8 vs 0x290CC80 shader;
// 0x290A190 vs 0x290B640 material). POSTPROC flag did not resolve this.
// Instead of more guessing, hook the key texture/NIF/material APIs and
// log every call during vanilla gameplay. When we see a character body
// get loaded properly, we see the EXACT sequence — and can replay it.
//
// Hooks installed:
//   - sub_1417B3E90  NIF loader (path + out + opts)
//   - sub_14217A910  texture load (DDS path → NiSourceTexture*)
//   - sub_1421627B0  BSShaderTextureSet::SetTexturePath
//   - sub_1421C6870  material ← texset bind
//   - sub_142171050  BSLightingShaderProperty alloc
//   - sub_1421C5CE0  BSLightingShaderMaterial ctor
//
// Each detour:
//   1. Captures args + thread id
//   2. Logs ONE line (path strings if relevant)
//   3. Calls through to original
//   4. Logs return pointer / rc
//
// Rate limit: none initially — these functions fire ~dozens/cell, not
// per-frame. If tracing slows the game, add per-function counter.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Install all engine tracer hooks. Returns true if all 6 hooks installed.
// Log spam starts immediately — filter by "[trace]" prefix in fw_native.log.
bool install_engine_tracer(std::uintptr_t module_base);

} // namespace fw::hooks
