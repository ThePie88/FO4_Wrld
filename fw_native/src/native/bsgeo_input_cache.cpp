// M9 wedge 4 — Path B-alt-1 — BSGeometry factory input cache.
// See bsgeo_input_cache.h for design.

#include "bsgeo_input_cache.h"

#include <windows.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "../hook_manager.h"
#include "../log.h"
#include "ni_offsets.h"

namespace fw::native::bsgeo_input_cache {

namespace {

// Factory signature from M2 dossier (re/stradaB_M2_geometry_dossier.txt §2):
//   void* sub_14182FFD0(
//       int      tri_count,         // a1 — rcx
//       void*    indices_u16,       // a2 — rdx
//       unsigned vert_count,        // a3 — r8
//       void*    positions_vec3,    // a4 — r9 (12 bytes per vert)
//       void*    uvs_vec2,          // a5 — stack
//       void*    tangents_vec4,     // a6 — stack
//       void*    pos_alt,           // a7
//       void*    normals_vec3,      // a8
//       void*    colors_vec4f,      // a9
//       void*    skin_weights,      // a10
//       void*    skin_indices,      // a11
//       void*    tan_ex,            // a12
//       void*    eye_data,          // a13
//       void*    normals_alt,       // a14
//       void*    remap_u16,         // a15
//       char     build_mesh_extra); // a16
using GeoBuilderFn = void* (__fastcall*)(
    int, void*, unsigned, void*,
    void*, void*, void*, void*,
    void*, void*, void*, void*,
    void*, void*, void*, char);

GeoBuilderFn g_orig = nullptr;

std::shared_mutex                                       g_mtx;
std::unordered_map<const void*, CapturedMeshInput>      g_cache;
std::atomic<std::uint64_t>                              g_invocations{0};
std::atomic<std::uint64_t>                              g_evictions{0};

constexpr std::size_t MAX_ENTRIES = 8192;

// SEH-safe memcpy from engine pointer.
bool seh_memcpy_safe(void* dst, const void* src, std::size_t nbytes) {
    if (!dst || !src || nbytes == 0) return false;
    __try {
        std::memcpy(dst, src, nbytes);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Detour. Chain through, capture inputs by deep-copying into our cache,
// keyed by the returned BSTriShape pointer.
void* __fastcall detour_geo_builder(
    int       tri_count,
    void*     indices_u16,
    unsigned  vert_count,
    void*     positions_vec3,
    void*     uvs_vec2,
    void*     tangents_vec4,
    void*     pos_alt,
    void*     normals_vec3,
    void*     colors_vec4f,
    void*     skin_weights,
    void*     skin_indices,
    void*     tan_ex,
    void*     eye_data,
    void*     normals_alt,
    void*     remap_u16,
    char      build_mesh_extra)
{
    // Chain to original first — must NOT introduce side effects before the
    // factory runs. We capture inputs (which the factory only reads, not
    // mutates) AFTER the call returns the new BSTriShape*.
    void* result = g_orig(tri_count, indices_u16, vert_count, positions_vec3,
                           uvs_vec2, tangents_vec4, pos_alt, normals_vec3,
                           colors_vec4f, skin_weights, skin_indices, tan_ex,
                           eye_data, normals_alt, remap_u16, build_mesh_extra);

    const std::uint64_t n =
        g_invocations.fetch_add(1, std::memory_order_relaxed) + 1;

    // Sanity: don't capture if anything looks broken.
    if (!result || tri_count <= 0 || vert_count == 0
        || tri_count > 0x100000 || vert_count > 0x10000
        || !positions_vec3 || !indices_u16) {
        // Brief log for the first few invocations so we see when the
        // factory fires with absent positions/indices (e.g. for cube
        // engine usage that takes other input combinations).
        if (n <= 50) {
            FW_DBG("[bsgeo-cache] #%llu skip: result=%p tc=%d vc=%u "
                   "pos=%p idx=%p",
                   static_cast<unsigned long long>(n), result, tri_count,
                   vert_count, positions_vec3, indices_u16);
        }
        return result;
    }

    // Deep-copy positions (12 bytes per vert) and indices (6 bytes per tri).
    CapturedMeshInput cap;
    cap.vert_count = static_cast<std::uint16_t>(vert_count);
    cap.tri_count  = static_cast<std::uint32_t>(tri_count);

    cap.positions.resize(static_cast<std::size_t>(3) * vert_count);
    if (!seh_memcpy_safe(cap.positions.data(), positions_vec3,
                          12u * vert_count)) {
        FW_DBG("[bsgeo-cache] #%llu SEH copying positions vc=%u (skip)",
               static_cast<unsigned long long>(n), vert_count);
        return result;
    }

    cap.indices.resize(static_cast<std::size_t>(3) * tri_count);
    if (!seh_memcpy_safe(cap.indices.data(), indices_u16,
                          6u * tri_count)) {
        FW_DBG("[bsgeo-cache] #%llu SEH copying indices tc=%d (skip)",
               static_cast<unsigned long long>(n), tri_count);
        return result;
    }

    // Insert into cache.
    {
        std::unique_lock<std::shared_mutex> lk(g_mtx);
        if (g_cache.size() >= MAX_ENTRIES) {
            const std::size_t before = g_cache.size();
            g_cache.clear();
            g_evictions.fetch_add(before, std::memory_order_relaxed);
            FW_WRN("[bsgeo-cache] reached cap %zu — cleared", before);
        }
        g_cache[result] = std::move(cap);
    }

    // Verbose log for the first 50 invocations — lets us see if weapon
    // NIFs trigger this factory and what counts they have.
    if (n <= 50) {
        FW_LOG("[bsgeo-cache] #%llu trishape=%p tc=%d vc=%u pos=%p idx=%p",
               static_cast<unsigned long long>(n), result, tri_count,
               vert_count, positions_vec3, indices_u16);
    } else if ((n % 256) == 0) {
        FW_DBG("[bsgeo-cache] #%llu trishape=%p tc=%d vc=%u (heartbeat)",
               static_cast<unsigned long long>(n), result, tri_count,
               vert_count);
    }
    return result;
}

std::atomic<bool> g_installed{false};

} // namespace

bool install(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) return true;
    if (!module_base) {
        FW_ERR("[bsgeo-cache] install: module_base=0");
        return false;
    }
    void* target = reinterpret_cast<void*>(module_base + GEO_BUILDER_FN_RVA);
    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_geo_builder),
        reinterpret_cast<void**>(&g_orig));
    if (!ok) {
        FW_ERR("[bsgeo-cache] hook install FAILED on target=%p RVA=0x%llX",
               target,
               static_cast<unsigned long long>(GEO_BUILDER_FN_RVA));
        return false;
    }
    g_installed.store(true, std::memory_order_release);
    FW_LOG("[bsgeo-cache] installed: detour on GEO_BUILDER "
           "(target=%p RVA=0x%llX sub_14182FFD0) cap=%zu",
           target,
           static_cast<unsigned long long>(GEO_BUILDER_FN_RVA),
           MAX_ENTRIES);
    return true;
}

const CapturedMeshInput* lookup(const void* trishape) {
    if (!trishape) return nullptr;
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    auto it = g_cache.find(trishape);
    if (it == g_cache.end()) return nullptr;
    return &it->second;
}

std::uint64_t total_invocations() {
    return g_invocations.load(std::memory_order_relaxed);
}
std::size_t entry_count() {
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    return g_cache.size();
}
std::uint64_t total_evictions() {
    return g_evictions.load(std::memory_order_relaxed);
}

} // namespace fw::native::bsgeo_input_cache
