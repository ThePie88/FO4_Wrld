// β.6 scene-VP capture. THE REAL ONE.
//
// Previous attempts (NiCamera+0x120, self-built VP from actor pose) all
// produced shake or wrong geometry because they read/built the wrong
// matrix. The IDA RE pass 2026-04-22 definitively located the scene VP:
//
//   PRODUCER:  sub_1421DC480 @ RVA 0x21DC480 — composes ViewProj from a
//              camera context (a1) and writes 4 __m128 rows to a
//              BSShaderAccumulator (a2) at a2+0x17C..+0x1BC.
//   CONSUMER:  sub_14221E6A0 @ RVA 0x21E6A0 — reads those 64 bytes,
//              transposes col-major→row-major, uploads to the GPU
//              constant buffer used by BSDFPrePassShaderVertexConstants.
//
// STORAGE: column-major — each of the four __m128's is ONE COLUMN of
// the 4x4 matrix (16 floats, 64 bytes total).
//
// By hooking the PRODUCER at its trailing edge we capture the exact VP
// matrix the engine will shortly upload to GPU and use for scene draws.
// Using this matrix in our own body shader eliminates shake because we
// share the engine's frame-perfect VP byte-for-byte.

#pragma once

#include <cstdint>

namespace fw::render {

// Install the MinHook detour on sub_1421DC480. Idempotent. Returns
// false on MinHook failure — caller should fall back to self-built VP.
bool install_vp_capture(std::uintptr_t module_base);

// Read the last captured scene VP (64 bytes, column-major 4x4).
// Returns false if no matrix has been captured yet (first frames or
// menu / load screen).
//
// Thread safety: the matrix is written atomically (INTERLOCKED flag +
// memcpy under flag). Callers read synchronously.
bool read_captured_scene_vp(float out_vp_col_major[16]);

// Diagnostic: how many times has the detour fired since install?
std::uint64_t vp_capture_hit_count();

} // namespace fw::render
