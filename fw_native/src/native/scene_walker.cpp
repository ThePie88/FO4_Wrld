#include "scene_walker.h"
#include "ni_offsets.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../log.h"

namespace fw::native {

namespace {

// Module-level slot for the first BSTriShape observed during the most
// recent walk. Reset to null at the start of each walk, written once
// when we hit the first vt_rva == BSTRISHAPE_VTABLE_RVA node.
//
// We use atomic for publish ordering — walker writes, M2.3 reads, both
// on main thread but atomics make the cross-function contract explicit.
std::atomic<void*> g_first_bstri_shape{nullptr};

// Module-level slot for the ShadowSceneNode pointer observed during
// the walk. vt_rva == 0x2908F40 = ShadowSceneNode. Like above, reset
// per-walk.
std::atomic<void*> g_shadow_scene_node{nullptr};

// Table of known vtable RVAs → friendly class names. Makes the dump
// readable ("BSTriShape" vs just "vt_rva=0x267E948"). Covered classes
// are from dossier § 2 + a few common Scaleform/camera/TESCamera we
// might bump into higher in the tree.
struct VTableName {
    std::uintptr_t rva;
    const char*    name;
};
constexpr VTableName kKnownVTables[] = {
    { 0x0267C888, "NiNode"            },
    { 0x0267D0C0, "NiAVObject"        },
    { 0x0267DD50, "NiCamera"          },
    { 0x02462F88, "NiRefObject"       },
    { 0x0267E0B8, "BSGeometry"        },
    { 0x0267E948, "BSTriShape"        },
    { 0x0267F948, "BSDynamicTriShape" },
    { 0x028FA3E8, "BSFadeNode"        },
    { 0x02908F40, "ShadowSceneNode"   },
    { 0x0255E180, "SceneGraph"        },
    { 0x0255E188, "SceneGraph(adj+8)" },
    { 0x0255E190, "SceneGraph(adj+10)"},
    { 0x0255E198, "SceneGraph(adj+18)"},
    { 0x0255DB08, "MainCullingCamera" },
    { 0x028F9FF8, "BSLightingShaderProperty" },
    { 0x02474400, "NiAlphaProperty"   },
    // Observed in live walk 2026-04-23 — classes TBC but harmless to label:
    { 0x026986C0, "NiNode-derived?(0x26986C0)"  }, // 10+ occurrences w/ children
    { 0x02696D8F, "BSLODTriShape?(0x2696D8F)"   }, // placeholder
    { 0x02696D68, "BSLeaf/Geom?(0x2696D68)"     }, // 30+ occurrences, geometry-like
    { 0x024D3230, "unknown(0x24D3230)"          },
    { 0x0290E070, "unknown(0x290E070)"          },
    { 0x026980D8, "unknown(0x26980D8)"          },
};

const char* classify_vtable(std::uintptr_t vt_rva) {
    for (const auto& e : kKnownVTables) {
        if (e.rva == vt_rva) return e.name;
    }
    return "UNKNOWN";
}

// Read an ASCII string from a NiFixedString handle.
//
// Live-test 2026-04-23 showed single-indirection (treating handle as
// char*) returned "(non-ascii)" for nodes we know have real names
// (e.g. our own "fw_debug_cube"). The actual NiFixedString layout in
// F4 seems to be { char* data_ptr } at the handle location — i.e.
// double indirection: deref handle to get data_ptr, then deref that.
//
// We try BOTH: first double-deref, then single-deref as fallback,
// then hex dump as last resort for forensic analysis.
const char* safe_read_fixed_string(std::uint64_t handle, char* buf, std::size_t buflen) {
    if (!handle) {
        std::strncpy(buf, "(null)", buflen - 1);
        buf[buflen - 1] = '\0';
        return buf;
    }
    // Helper: check if all chars in [start, end) are printable ASCII.
    auto try_decode = [&](const char* s) -> bool {
        __try {
            for (std::size_t i = 0; i < buflen - 1; ++i) {
                char c = s[i];
                if (c == '\0') {
                    buf[i] = '\0';
                    return i > 0;   // empty string = treat as failure
                }
                if (c < 0x20 || c > 0x7E) return false;
                buf[i] = c;
            }
            buf[buflen - 1] = '\0';
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    };

    // Attempt 1: double-deref (handle points to struct with char* at +0).
    __try {
        const char* inner = *reinterpret_cast<const char* const*>(handle);
        if (inner && try_decode(inner)) return buf;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // fall through
    }
    // Attempt 2: single-deref (handle IS char*).
    if (try_decode(reinterpret_cast<const char*>(handle))) return buf;

    // Both failed — dump first 16 bytes as hex for forensic inspection.
    __try {
        const auto* raw = reinterpret_cast<const std::uint8_t*>(handle);
        int w = std::snprintf(buf, buflen, "(raw16:");
        for (int i = 0; i < 16 && w < (int)buflen - 4; ++i) {
            w += std::snprintf(buf + w, buflen - w, "%02X", raw[i]);
        }
        std::snprintf(buf + w, buflen - w, ")");
        return buf;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::strncpy(buf, "(fault)", buflen - 1);
        buf[buflen - 1] = '\0';
        return buf;
    }
}

// Uint to module base delta — helps pattern-match pointers that are
// in the game's image range (RVA under ~0x4000000).
std::uintptr_t to_rva(void* p, std::uintptr_t base) {
    const auto v = reinterpret_cast<std::uintptr_t>(p);
    if (v < base) return 0;
    return v - base;
}

void walk_one(void* node, int depth, int max_depth, std::uintptr_t base) {
    if (!node || depth > max_depth) return;

    __try {
        auto* bytes = reinterpret_cast<char*>(node);

        void** vt = *reinterpret_cast<void***>(bytes);
        const auto vt_rva = to_rva(vt, base);
        const char* cls = classify_vtable(vt_rva);

        // Name: NiObjectNET stores NiFixedString at +0x10 as a raw u64
        // (which IS a char* after intern).
        const std::uint64_t name_handle =
            *reinterpret_cast<std::uint64_t*>(bytes + NIAV_NAME_OFF);
        char name_buf[128];
        const char* name = safe_read_fixed_string(name_handle, name_buf, sizeof(name_buf));

        // Local translation.
        const float* trans = reinterpret_cast<float*>(bytes + NIAV_LOCAL_TRANSLATE_OFF);

        // Children — only valid for NiNode-derived. We read anyway and
        // use heuristics to decide if the values are plausible.
        const std::uint16_t cap = *reinterpret_cast<std::uint16_t*>(
            bytes + NINODE_CHILDREN_CAP_OFF);
        const std::uint16_t cnt = *reinterpret_cast<std::uint16_t*>(
            bytes + NINODE_CHILDREN_CNT_OFF);
        void** children = *reinterpret_cast<void***>(
            bytes + NINODE_CHILDREN_PTR_OFF);

        // Indent for tree visualization.
        const char* indent = "                        ";  // 24 spaces
        const int pad = depth * 2;
        const char* ind = indent + (24 - (pad > 24 ? 24 : pad));

        FW_LOG("[walk]%s%p vt_rva=0x%llX [%s] name='%s' pos=(%.0f,%.0f,%.0f) "
               "chld=%u/%u ptr=%p",
               ind, node,
               static_cast<unsigned long long>(vt_rva), cls, name,
               trans[0], trans[1], trans[2],
               cnt, cap, static_cast<void*>(children));

        // Capture first BSTriShape encountered — M2.3 will clone its
        // shader+alpha. Only take the FIRST one (atomic CAS from null)
        // to avoid oscillating between different shaders across the walk.
        //
        // FIX #3 (2026-04-23 render diagnosis): prefer UNSKINNED shapes.
        // A skinned source has bit 52 set in the packed BSVertexDesc at
        // +0x150. If we clone a skinned shader onto our unskinned cube,
        // the shader tries to sample bone matrices from a null skin
        // instance → garbage transforms → invisible. Skip skinned.
        if (vt_rva == BSTRISHAPE_VTABLE_RVA) {
            const auto vdesc = *reinterpret_cast<std::uint64_t*>(
                bytes + 0x150);
            constexpr std::uint64_t kSkinnedBit = 1ull << 52;
            if (vdesc & kSkinnedBit) {
                // Skinned — skip for clone purposes (but let the log
                // see it for forensic value).
                FW_DBG("[walk]%s  .. BSTriShape %p is SKINNED (vdesc=0x%llX "
                       "bit52 set) — skip for first_bstri_shape capture",
                       ind, node,
                       static_cast<unsigned long long>(vdesc));
            } else {
                void* expected = nullptr;
                if (g_first_bstri_shape.compare_exchange_strong(
                        expected, node, std::memory_order_acq_rel)) {
                    FW_LOG("[walk]%s  ^^ captured as first_bstri_shape "
                           "(vdesc=0x%llX, unskinned)",
                           ind, static_cast<unsigned long long>(vdesc));
                }
            }
        }

        // Capture ShadowSceneNode (vt_rva 0x2908F40) — the REAL render
        // root. Both M1 dossier hypotheses (qword_143E47A10 singleton
        // and SceneGraph+0x140 shortcut) were wrong; they point to a
        // NiCamera. Walking the tree and vtable-matching is the only
        // reliable way we have. There should be exactly one SSN in the
        // scene — take the first one and lock it in.
        constexpr std::uintptr_t kSSNVtRVA = 0x02908F40;
        if (vt_rva == kSSNVtRVA) {
            void* expected = nullptr;
            if (g_shadow_scene_node.compare_exchange_strong(
                    expected, node, std::memory_order_acq_rel)) {
                FW_LOG("[walk]%s  ^^ captured as ShadowSceneNode for M2 attach", ind);
            }
        }

        // If this looks like a BSGeometry/BSTriShape/BSDynamicTriShape,
        // dump bytes +0x120..+0x180 in hex — that region holds the
        // shaderProperty ptr + alphaProperty + vertex buffer pointers
        // we'll need for M2.3. Harmless on other classes too but we
        // only bother for the geometry-probable ones.
        const bool is_geometry_probable =
            vt_rva == 0x0267E0B8 || // BSGeometry
            vt_rva == 0x0267E948 || // BSTriShape
            vt_rva == 0x0267F948 || // BSDynamicTriShape
            vt_rva == 0x02696D68;   // observed unknown — geometry-like
        if (is_geometry_probable) {
            char hex[256];
            int w = std::snprintf(hex, sizeof(hex), "[walk]%s  +0x120..180: ", ind);
            for (int i = 0x120; i < 0x180 && w < (int)sizeof(hex) - 4; i += 8) {
                std::uint64_t v = *reinterpret_cast<std::uint64_t*>(bytes + i);
                w += std::snprintf(hex + w, sizeof(hex) - w, "%016llX ",
                                   static_cast<unsigned long long>(v));
            }
            FW_LOG("%s", hex);
        }

        // Heuristic-based recursion (vtable classification isn't reliable
        // for unknown classes, but layout offsets +0x128/+0x130/+0x132
        // are shared across all NiNode-derived types — if values are
        // sane, safe to recurse; if junk, SEH-cage will catch it):
        if (cnt == 0 || cnt > 256)      return;
        if (!children)                  return;
        if (depth + 1 > max_depth)      return;

        // Cheap sanity: children ptr should live in heap userspace
        // (0x00000001'00000000..0x00007FFF'FFFFFFFF). If it's way
        // outside that, almost certainly we mis-read offsets.
        const auto cptr = reinterpret_cast<std::uintptr_t>(children);
        if (cptr < 0x00010000ull || cptr > 0x00007FFF'FFFFFFFFull) return;

        for (std::uint16_t i = 0; i < cnt; ++i) {
            void* child = children[i];
            if (!child) continue;
            walk_one(child, depth + 1, max_depth, base);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[walk] SEH at depth=%d node=%p — skipping subtree",
               depth, node);
    }
}

} // namespace

void walk_and_dump_scene(void* root, int max_depth) {
    if (!root) {
        FW_WRN("[walk] null root — nothing to dump");
        return;
    }
    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    const auto base = reinterpret_cast<std::uintptr_t>(game);

    // Reset the per-walk slots so each walk starts fresh. If the engine
    // tore down and rebuilt the scene between walks, previous ptrs are
    // stale.
    g_first_bstri_shape.store(nullptr, std::memory_order_release);
    g_shadow_scene_node.store(nullptr, std::memory_order_release);

    FW_LOG("[walk] ===== BEGIN scene dump (root=%p, max_depth=%d) =====",
           root, max_depth);
    walk_one(root, 0, max_depth, base);
    FW_LOG("[walk] ===== END scene dump =====");

    void* first = g_first_bstri_shape.load(std::memory_order_acquire);
    void* ssn   = g_shadow_scene_node.load(std::memory_order_acquire);
    FW_LOG("[walk] first_bstri_shape captured: %p%s",
           first, first ? "" : "  (NONE FOUND — M2.3 clone will skip)");
    FW_LOG("[walk] shadow_scene_node captured: %p%s",
           ssn, ssn ? "" : "  (NONE FOUND — M2.5 attach will skip)");
}

void* get_first_bstri_shape() {
    return g_first_bstri_shape.load(std::memory_order_acquire);
}

void* get_shadow_scene_node() {
    return g_shadow_scene_node.load(std::memory_order_acquire);
}

} // namespace fw::native
