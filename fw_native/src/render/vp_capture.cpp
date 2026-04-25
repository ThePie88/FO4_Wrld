#include "vp_capture.h"

#include <windows.h>
#include <atomic>
#include <cmath>
#include <cstring>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::render {

namespace {

// β.6 v2 — CONSUMER hook (RE agent #2 corrected the target 2026-04-22):
//
//   sub_14221E6A0 @ RVA 0x221E6A0. vtable slot [8] of 0x14290D158.
//   Called 100-2000 times per frame (one per BSLightingShader-per-geometry
//   draw). At PROLOGUE we read the matrix via:
//
//     void* acc = *(void**)((char*)a2 + 0x18);  // BSShaderAccumulator*
//     memcpy(vp, (char*)acc + 0x17C, 64);        // col-major 4x __m128
//
// The PRODUCER (sub_1421DC480) was the wrong target — it has a vtable
// gate at entry (slot 64) that short-circuits for most accumulators,
// and only derived accumulators actually run the write path. Hooking
// the CONSUMER catches every actual VP usage.
//
// First 5 bytes at RVA 0x221E6A0 should be: 48 8B C4 48 89 (MinHook-safe).
using ConsumeVPFn = __int64 (__fastcall*)(void* a1, void* a2);

constexpr std::uintptr_t CONSUMER_RVA          = 0x221E6A0;
constexpr std::size_t    ACCUM_PTR_OFFSET      = 0x18;   // a2 + 0x18 = BSShaderAccum*
// Live memory dump (2026-04-22): matrix at +0x17C is garbage, actual
// identity-looking 4x4 matrix lives at +0x1A0 (cols 0..3 at +0x1A0,
// +0x1B0, +0x1C0, +0x1D0). Agent report had wrong struct layout for
// this binary version.
constexpr std::size_t    VP_MATRIX_OFFSET      = 0x1A0;  // CORRECTED
constexpr std::size_t    VP_MATRIX_SIZE        = 64;     // 4x4 floats

// Expected prologue bytes for sanity check at install time.
constexpr std::uint8_t EXPECTED_PROLOGUE[5] = { 0x48, 0x8B, 0xC4, 0x48, 0x89 };

ConsumeVPFn g_orig_compose_vp = nullptr;

// Captured matrix. Written inside the detour, read by body_render.
// We store the raw 64 bytes exactly as the engine wrote them (column
// major per agent's RE). Write is guarded by an atomic "captured" flag
// so readers see either "not ready" or a full matrix, never a tear.
std::atomic<bool>          g_vp_captured{false};
float                      g_vp_matrix[16]{};  // col-major, 16 floats
std::atomic<std::uint64_t> g_hit_count{0};
std::atomic<bool>          g_hooked{false};

__int64 __fastcall detour_consume_vp(void* a1, void* a2) {
    // PROLOGUE detour: read matrix BEFORE the consumer runs (matrix is
    // already populated by a previous producer call). This avoids any
    // possibility of the consumer modifying it.
    const auto n = g_hit_count.fetch_add(1, std::memory_order_relaxed);
    if (n < 3) {
        FW_LOG("[vp_capture] detour hit #%llu: a1=%p a2=%p",
               n, a1, a2);
    } else if ((n % 3600) == 0) {
        FW_DBG("[vp_capture] heartbeat: hit #%llu", n);
    }

    if (a2) {
        __try {
            // Memory dump at select hit numbers to see how the matrix
            // at +0x1A0 evolves during gameplay (hit 0 was at scene
            // init with identity, later hits during actual render
            // should show real VP values).
            const bool do_dump = (n == 0) || (n == 1000) || (n == 50000) ||
                                 (n == 200000) || (n == 1000000);
            if (do_dump) {
                const auto* bytes = reinterpret_cast<const std::uint8_t*>(a2);
                const auto inner = *reinterpret_cast<void* const*>(bytes + 0x18);
                FW_LOG("[vp_capture] === DUMP hit #%llu "
                       "*(a2+0x18)=%p ===", n, inner);
                if (inner) {
                    const auto* ib = reinterpret_cast<const std::uint8_t*>(inner);
                    // Cover a wider range this time so if matrix moved
                    // to another offset we catch it.
                    for (std::size_t off = 0x100; off < 0x280; off += 0x10) {
                        const auto* f = reinterpret_cast<const float*>(ib + off);
                        FW_LOG("[vp_capture]   +0x%03zX = (%9.3f %9.3f %9.3f %9.3f)",
                               off, f[0], f[1], f[2], f[3]);
                    }
                }
                FW_LOG("[vp_capture] === END DUMP ===");
            }

            // Read the matrix at *(a2+0x18)+0x1A0 (the real location
            // per live dump). This is col-major 4x4.
            void* acc = *reinterpret_cast<void* const*>(
                reinterpret_cast<const std::uint8_t*>(a2) + ACCUM_PTR_OFFSET);
            if (!acc) {
                if (n < 3) FW_DBG("[vp_capture] hit #%llu: a2+0x18=null", n);
                return g_orig_compose_vp(a1, a2);
            }

            const auto* src = reinterpret_cast<const float*>(
                reinterpret_cast<const std::uint8_t*>(acc) + VP_MATRIX_OFFSET);

            // Sanity: reject if matrix is too close to all-zeros or
            // pure identity (uninit). A real VP has f/a scales (~1-3)
            // mixed with translation values (thousands).
            float max_abs = 0.0f;
            int non_zero_count = 0;
            for (int i = 0; i < 16; ++i) {
                const float v = std::fabs(src[i]);
                if (v > max_abs) max_abs = v;
                if (v > 0.01f) ++non_zero_count;
            }

            // Good VP has: max magnitude >= 0.5 (FOV scale presence),
            // lots of non-zero entries (>= 6 — rotation + translation
            // columns shouldn't be mostly zero).
            bool accept = (max_abs >= 0.5f) && (non_zero_count >= 6);
            if (accept) {
                std::memcpy(g_vp_matrix, src, VP_MATRIX_SIZE);
                g_vp_captured.store(true, std::memory_order_release);
            }

            if (n < 3 || do_dump) {
                FW_LOG("[vp_capture] hit #%llu matrix @ *(a2+0x18)+0x%zX: "
                       "col0=(%.3f %.3f %.3f %.3f) "
                       "col3=(%.3f %.3f %.3f %.3f) "
                       "max_abs=%.3f nonzero=%d %s",
                       n, VP_MATRIX_OFFSET,
                       src[0], src[1], src[2], src[3],
                       src[12], src[13], src[14], src[15],
                       max_abs, non_zero_count,
                       accept ? "\u2192 accepted" : "\u2192 rejected (uninit?)");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (n < 3) FW_WRN("[vp_capture] SEH reading matrix at hit #%llu", n);
        }
    }

    // Pass through to the original consumer.
    return g_orig_compose_vp(a1, a2);
}

} // namespace

bool install_vp_capture(std::uintptr_t module_base) {
    if (g_hooked.load(std::memory_order_acquire)) return true;
    if (!module_base) return false;

    void* target = reinterpret_cast<void*>(module_base + CONSUMER_RVA);

    // Sanity check: verify expected prologue bytes before hooking —
    // catches wrong-RVA / wrong-binary-version bugs up front.
    __try {
        const auto* prologue = reinterpret_cast<const std::uint8_t*>(target);
        bool prologue_match = true;
        for (std::size_t i = 0; i < sizeof(EXPECTED_PROLOGUE); ++i) {
            if (prologue[i] != EXPECTED_PROLOGUE[i]) {
                prologue_match = false;
                break;
            }
        }
        FW_LOG("[vp_capture] target prologue bytes: "
               "%02X %02X %02X %02X %02X (expected 48 8B C4 48 89) %s",
               prologue[0], prologue[1], prologue[2], prologue[3], prologue[4],
               prologue_match ? "\u2713 MATCH" : "\u2717 MISMATCH (wrong RVA?)");
        if (!prologue_match) {
            FW_ERR("[vp_capture] ABORT install: prologue byte mismatch — "
                   "RVA 0x%llX may be wrong for this binary version",
                   static_cast<unsigned long long>(CONSUMER_RVA));
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[vp_capture] SEH reading prologue at %p — address invalid",
               target);
        return false;
    }

    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_consume_vp),
        reinterpret_cast<void**>(&g_orig_compose_vp));
    if (!ok) {
        FW_ERR("[vp_capture] MinHook install FAILED at %p (RVA 0x%llX)",
               target,
               static_cast<unsigned long long>(CONSUMER_RVA));
        return false;
    }

    g_hooked.store(true, std::memory_order_release);
    FW_LOG("[vp_capture] installed at %p (RVA 0x%llX) CONSUMER \u2014 will "
           "read VP at *(a2+0x%zX)+0x%zX each call (100-2000x/frame)",
           target,
           static_cast<unsigned long long>(CONSUMER_RVA),
           ACCUM_PTR_OFFSET, VP_MATRIX_OFFSET);
    return true;
}

bool read_captured_scene_vp(float out_vp_col_major[16]) {
    if (!g_vp_captured.load(std::memory_order_acquire)) return false;
    std::memcpy(out_vp_col_major, g_vp_matrix, VP_MATRIX_SIZE);
    return true;
}

std::uint64_t vp_capture_hit_count() {
    return g_hit_count.load(std::memory_order_relaxed);
}

} // namespace fw::render
