// Modded weapon assembly via direct NIF loader.
//
// See synthetic_refr.h for the architectural rationale. Iteration #2
// of this file: the synthetic REFR + vt[170] approach was refuted
// (vt[170] is a flag-setter, not a loader — see
// re/COLLAB_FOLLOWUP_vt170.md). Pivot to direct synchronous call to
// `sub_1404580C0` (DELTA §8 path) with a fabricated BGSObjectInstanceExtra
// passed as the 4th arg `modelExtraData`.
//
// PIPELINE
// ========
//   1. Resolve weapon TESForm* via lookup_form (or pass-through if
//      caller already has it — currently we look up).
//   2. Read its TESModel.modelPath (BSFixedString at known offset).
//   3. Fabricate a BGSObjectInstanceExtra carrying every OMOD form_id
//      as an 8-byte record. Recipe per
//      re/COLLAB_FOLLOWUP_oie_construction.md (Path B):
//         a. alloc 0x28-byte shell, write 6 ctor fields
//         b. for each OMOD: lookup → verify formType==0x90 → AddRecord
//      Pure mutation — no engine state pull-in.
//   4. Call `sub_1404580C0(modelPath, &out_node, opts, &modelExtraData)`.
//      Opts byte includes bit 0x08 → BSModelProcessor post-hook fires
//      → OMODs from our fabricated OIE get applied IN-PLACE on the
//      cached BSFadeNode → returned tree carries them.
//   5. Free the OIE shell + inner buffer (sub_1404580C0 either copies
//      what it needs or holds its own ref; if we leak the shell, it's
//      40 bytes — acceptable for the prototype).
//   6. Return the BSFadeNode* with refcount = 1.
//
// CURRENT STATUS (2026-05-07)
// ===========================
// `sub_1404580C0` signature + `modelExtraData` shape are STILL UNDER
// RE. Two parallel investigations:
//   (a) static decomp agent — running in background, see
//       re/COLLAB_FOLLOWUP_sub1404580C0.md (in flight)
//   (b) live capture via subrefload_hook — captures real args at
//       run-time when Pipboy hovers a weapon
//
// Until those land, this file's `assemble_modded_weapon` body is a
// SAFE NO-OP that returns nullptr + kErrInternal. The OIE machinery
// is fully implemented and tested via unit-style isolation.

#include "synthetic_refr.h"

#include <windows.h>
#include <atomic>
#include <cstring>
#include <mutex>

#include "../log.h"
#include "../offsets.h"

namespace fw::native::synthetic_refr {

namespace {

// ============================================================================
// Engine RVAs
// ============================================================================

// Pool allocator (same one scene_inject.cpp uses for NiNode).
constexpr std::uintptr_t POOL_ALLOC_RVA      = 0x016579C0;
constexpr std::uintptr_t POOL_DESC_RVA       = 0x03E5E0F0;
constexpr std::uintptr_t POOL_FREE_RVA       = 0x01657E20;
constexpr std::uintptr_t POOL_INIT_RVA       = 0x01657F90;
constexpr std::uintptr_t POOL_INIT_FLAG_RVA  = 0x03E5F2D0;

// Form lookup.
constexpr std::uintptr_t LOOKUP_FORM_RVA     = fw::offsets::LOOKUP_BY_FORMID_RVA;

// BGSObjectInstanceExtra fabrication (path B per
// re/COLLAB_FOLLOWUP_oie_construction.md).
constexpr std::uintptr_t OIE_VTABLE_RVA      = 0x02462298;
constexpr std::uintptr_t OIE_ADD_RECORD_RVA  = 0x002480F0;

// The DIRECT NIF loader candidate (DELTA §8). Signature TBD — current
// hypothesis from DELTA notes: `sub_1404580C0(path, &out_node, opts, modelExtraData)`.
constexpr std::uintptr_t SUBLOAD_RVA         = 0x004580C0;

// OIE layout (40 bytes total).
constexpr std::size_t OIE_SIZE              = 0x28;
constexpr std::size_t OIE_VTABLE_OFF        = 0x00;
constexpr std::size_t OIE_TYPE_BYTE_OFF     = 0x12;  // = 0x35
constexpr std::size_t OIE_ARMA_SENTINEL_OFF = 0x20;  // u16 = 0xFFFF

// Form layout (per offsets.h).
constexpr std::size_t FORM_TYPE_OFF = 0x1A;          // formType byte
constexpr std::uint8_t FORMTYPE_OMOD = 0x90;         // BGSMod::Attachment::Mod

// ============================================================================
// Function pointer typedefs
// ============================================================================

using PoolAllocFn    = void* (*)(void* pool, std::size_t size,
                                  std::uint32_t align, std::uint32_t flags);
using PoolFreeFn     = void  (*)(void* pool, void* ptr, std::uint32_t flags);
using PoolInitFn     = void  (*)(void* pool, std::uint32_t* init_flag);
using LookupFormFn   = void* (*)(std::uint32_t form_id);
using OieAddRecordFn = std::int64_t (*)(void* extra, void* omod_form,
                                         char attach_idx, char rank,
                                         char purge_existing);

// sub_1404580C0 — placeholder signature. Will be refined when subrefload_hook
// captures live args. 4 register args + return — the most likely shape.
using SubLoadFn = std::uint64_t (*)(std::uint64_t a0, std::uint64_t a1,
                                     std::uint64_t a2, std::uint64_t a3);

struct Resolved {
    std::uintptr_t  base             = 0;
    void*           pool             = nullptr;
    std::uint32_t*  pool_init_flag   = nullptr;
    PoolAllocFn     pool_alloc       = nullptr;
    PoolFreeFn      pool_free        = nullptr;
    PoolInitFn      pool_init        = nullptr;
    LookupFormFn    lookup_form      = nullptr;
    OieAddRecordFn  oie_add_record   = nullptr;
    SubLoadFn       sub_load         = nullptr;
    std::uintptr_t  oie_vtable_addr  = 0;
};

std::atomic<bool> g_resolved{false};
Resolved          g_r{};

bool resolve_once() {
    if (g_resolved.load(std::memory_order_acquire)) return true;
    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (!game) {
        FW_ERR("[modload] Fallout4.exe not loaded");
        return false;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(game);

    g_r.base            = base;
    g_r.pool            = reinterpret_cast<void*>(base + POOL_DESC_RVA);
    g_r.pool_init_flag  = reinterpret_cast<std::uint32_t*>(base + POOL_INIT_FLAG_RVA);
    g_r.pool_alloc      = reinterpret_cast<PoolAllocFn>(base + POOL_ALLOC_RVA);
    g_r.pool_free       = reinterpret_cast<PoolFreeFn>(base + POOL_FREE_RVA);
    g_r.pool_init       = reinterpret_cast<PoolInitFn>(base + POOL_INIT_RVA);
    g_r.lookup_form     = reinterpret_cast<LookupFormFn>(base + LOOKUP_FORM_RVA);
    g_r.oie_add_record  = reinterpret_cast<OieAddRecordFn>(base + OIE_ADD_RECORD_RVA);
    g_r.sub_load        = reinterpret_cast<SubLoadFn>(base + SUBLOAD_RVA);
    g_r.oie_vtable_addr = base + OIE_VTABLE_RVA;

    g_resolved.store(true, std::memory_order_release);
    FW_LOG("[modload] resolved engine refs (base=0x%llX)",
           static_cast<unsigned long long>(base));
    return true;
}

// ============================================================================
// SEH primitives + OIE fabrication
// ============================================================================

void ensure_pool_init() {
    if (!g_r.pool_init_flag || !g_r.pool_init || !g_r.pool) return;
    if (*g_r.pool_init_flag != 2) {
        __try { g_r.pool_init(g_r.pool, g_r.pool_init_flag); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

void* seh_lookup_form(std::uint32_t form_id) {
    if (!g_r.lookup_form) return nullptr;
    __try { return g_r.lookup_form(form_id); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

bool seh_is_omod_form(void* form) {
    if (!form) return false;
    __try {
        return *(static_cast<std::uint8_t*>(form) + FORM_TYPE_OFF) ==
                FORMTYPE_OMOD;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void* oie_alloc_init() {
    ensure_pool_init();
    void* extra = nullptr;
    __try { extra = g_r.pool_alloc(g_r.pool, OIE_SIZE, 0, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!extra) return nullptr;
    __try {
        char* p = static_cast<char*>(extra);
        std::memset(p, 0, OIE_SIZE);
        *reinterpret_cast<std::uintptr_t*>(p + OIE_VTABLE_OFF) =
            g_r.oie_vtable_addr;
        p[OIE_TYPE_BYTE_OFF] = 0x35;
        *reinterpret_cast<std::uint16_t*>(p + OIE_ARMA_SENTINEL_OFF) = 0xFFFF;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        __try { g_r.pool_free(g_r.pool, extra, 0); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return nullptr;
    }
    return extra;
}

bool oie_add_record(void* extra, void* omod_form,
                     std::uint8_t attach_idx, std::uint8_t rank) {
    if (!extra || !omod_form || !g_r.oie_add_record) return false;
    __try {
        g_r.oie_add_record(extra, omod_form,
                            static_cast<char>(attach_idx),
                            static_cast<char>(rank),
                            /*purge_existing=*/1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void oie_free(void* extra) {
    if (!extra) return;
    __try { g_r.pool_free(g_r.pool, extra, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Build an OIE carrying every valid OMOD form_id from the input list.
// Returns nullptr on alloc failure or 0 valid records.
void* build_omod_oie(const std::uint32_t* omod_form_ids,
                     std::size_t          num_omods) {
    if (!omod_form_ids || num_omods == 0) return nullptr;

    void* extra = oie_alloc_init();
    if (!extra) return nullptr;

    int records = 0;
    for (std::size_t i = 0; i < num_omods; ++i) {
        std::uint32_t fid = omod_form_ids[i];
        if (fid == 0) continue;
        void* omod_form = seh_lookup_form(fid);
        if (!omod_form) continue;
        if (!seh_is_omod_form(omod_form)) continue;
        if (oie_add_record(extra, omod_form, 0, 0)) ++records;
    }

    if (records == 0) {
        oie_free(extra);
        return nullptr;
    }
    FW_DBG("[modload] OIE built: %p with %d records", extra, records);
    return extra;
}

}  // anon namespace

// ============================================================================
// Public API
// ============================================================================

void* assemble_modded_weapon(
    std::uint32_t        weapon_form_id,
    const std::uint32_t* omod_form_ids,
    std::size_t          num_omods,
    const char**         out_err)
{
    if (out_err) *out_err = nullptr;
    if (weapon_form_id == 0) {
        if (out_err) *out_err = kErrFormNotResolved;
        return nullptr;
    }
    if (!resolve_once()) {
        if (out_err) *out_err = kErrInternal;
        return nullptr;
    }
    if (num_omods > 32) num_omods = 32;

    // Resolve form (sanity — also lets caller pass a stale id).
    void* weapon_form = seh_lookup_form(weapon_form_id);
    if (!weapon_form) {
        if (out_err) *out_err = kErrFormNotResolved;
        return nullptr;
    }

    // Fabricate the OMOD-bearing extra (NULL if no mods or all invalid).
    void* oie = build_omod_oie(omod_form_ids, num_omods);
    // oie may be nullptr — that's fine for stock weapons; the load
    // below should still succeed and return a stock mesh.

    // === STUB: sub_1404580C0 invocation pending RE finalization. ===
    //
    // Two parallel investigations are nailing the exact signature:
    //   (a) background static-decomp agent — see
    //       re/COLLAB_FOLLOWUP_sub1404580C0.md (in flight)
    //   (b) live-capture via subrefload_hook — captures real args
    //       at run-time when Pipboy hovers a weapon
    //
    // Once we know:
    //   • which arg is the modelPath (BSFixedString or const char*?)
    //   • which arg is the out-node pointer (void**)
    //   • the opts encoding (DELTA: byte 0x2D includes bit 0x08)
    //   • the modelExtraData layout (direct OIE* or wrapper struct?)
    // we replace this stub with the actual call.
    //
    // For now: free our OIE and return failure with a recognizable
    // error code so the caller's fallback (legacy ghost_set_weapon)
    // kicks in cleanly.
    if (oie) oie_free(oie);
    FW_DBG("[modload] sub_1404580C0 not yet wired — returning kErrInternal "
           "(form=0x%X, num_omods=%zu)", weapon_form_id, num_omods);
    if (out_err) *out_err = kErrInternal;
    return nullptr;
}

void shutdown() {
    // No persistent state currently. Reserved for future caching layer.
}

}  // namespace fw::native::synthetic_refr
