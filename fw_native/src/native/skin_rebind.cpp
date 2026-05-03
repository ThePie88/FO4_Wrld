// Skin instance rebind — Step 1: DIAGNOSTIC ONLY (no mutation).
// =====================================================================
//
// Walks a body NIF subtree, finds every BSGeometry, reads its
// BSSkin::Instance pointer at +0x140, and dumps the names of every entry
// in the bones_primary array (skin+0x28). Tags entries whose name ends
// in "_skin" as STUB.
//
// This validates that our offsets are correct BEFORE we mutate anything.
// Run once per ghost body load and inspect fw_native.log.
//
// Layout source: re/M8P3_skin_instance_dossier.txt
//   BSGeometry+0x140 = NiPointer<BSSkin::Instance>
//   BSSkin::Instance+0x28 = bones_primary head (NiAVObject**)
//   BSSkin::Instance+0x38 = bones_primary count (u32)
//   BSSkin::Instance+0x10 = bones_fallback head
//   BSSkin::Instance+0x20 = bones_fallback count
//   BSSkin::Instance+0x48 = skel_root NiAVObject*
//
// Vtable source: re/stradaB_scene_root.txt + re/stradaB_M1_dossier.txt

#include "skin_rebind.h"

#include <windows.h>
#include <atomic>
#include <array>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../log.h"
#include "../hook_manager.h"

namespace fw::native::skin_rebind {

namespace {

// ------------------------------------------------------------------
// vtable RVAs (image-base relative, ImageBase 0x140000000)
// ------------------------------------------------------------------
constexpr std::uintptr_t kNiNodeVtRva            = 0x0267C888;
constexpr std::uintptr_t kBSFadeNodeVtRva        = 0x028FA3E8;
constexpr std::uintptr_t kBSLeafAnimNodeVtRva    = 0x028FA690;
constexpr std::uintptr_t kShadowSceneNodeVtRva   = 0x02908F40;

constexpr std::uintptr_t kBSGeometryVtRva        = 0x0267E0B8;
constexpr std::uintptr_t kBSTriShapeVtRva        = 0x0267E948;
constexpr std::uintptr_t kBSDynamicTriShapeVtRvaA = 0x0267F758;
constexpr std::uintptr_t kBSDynamicTriShapeVtRvaB = 0x0267F948;
constexpr std::uintptr_t kBSSubIndexTriShapeVtRva = 0x02697D40;

constexpr std::uintptr_t kBSSkinInstanceVtRva    = 0x0267E5C8;

// ------------------------------------------------------------------
// Struct offsets
// ------------------------------------------------------------------
constexpr std::size_t kNiObjectNetNameOff        = 0x10;  // BSFixedString
constexpr std::size_t kNiNodeChildrenPtrOff      = 0x128; // NiPointer<NiAVObject>*
constexpr std::size_t kNiNodeChildrenCountOff    = 0x132; // u16

constexpr std::size_t kBSGeometrySkinInstanceOff       = 0x140;
constexpr std::size_t kSkinInstanceBonesPrimaryHeadOff  = 0x28;
constexpr std::size_t kSkinInstanceBonesPrimaryCountOff = 0x38;
constexpr std::size_t kSkinInstanceBonesFallbackHeadOff = 0x10;
constexpr std::size_t kSkinInstanceBonesFallbackCountOff = 0x20;
constexpr std::size_t kSkinInstanceSkelRootOff          = 0x48;

// ------------------------------------------------------------------
// Module base
// ------------------------------------------------------------------
std::uintptr_t g_module_base = 0;

void ensure_base() {
    if (g_module_base == 0) {
        g_module_base = reinterpret_cast<std::uintptr_t>(
            GetModuleHandleW(L"Fallout4.exe"));
    }
}

// ------------------------------------------------------------------
// Helpers (all SEH-protected)
// ------------------------------------------------------------------
std::uintptr_t read_vt_rva(void* obj) {
    if (!obj || !g_module_base) return 0;
    __try {
        auto vt = *reinterpret_cast<std::uintptr_t*>(obj);
        if (vt < g_module_base) return 0;
        return vt - g_module_base;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool is_node_with_children(std::uintptr_t vt_rva) {
    return vt_rva == kNiNodeVtRva
        || vt_rva == kBSFadeNodeVtRva
        || vt_rva == kBSLeafAnimNodeVtRva
        || vt_rva == kShadowSceneNodeVtRva;
}

bool is_geometry(std::uintptr_t vt_rva) {
    return vt_rva == kBSGeometryVtRva
        || vt_rva == kBSTriShapeVtRva
        || vt_rva == kBSDynamicTriShapeVtRvaA
        || vt_rva == kBSDynamicTriShapeVtRvaB
        || vt_rva == kBSSubIndexTriShapeVtRva;
}

// Bounded copy of a NiObjectNET name (at obj+0x10, BSFixedString) into
// `out`. Returns the length copied (excluding null) or -1 on AV.
//
// Tries pool_entry+0x18 first (FO4 next-gen pool layout per Frida script).
// All memory access is SEH-protected. Bounded to out_cap-1 bytes to avoid
// strlen on potentially-bogus pointers.
//
// out is always null-terminated on return (even on failure -> empty).
int try_read_ni_name(void* obj, char* out, int out_cap) {
    if (out_cap < 1) return -1;
    out[0] = 0;
    if (!obj) return -1;
    __try {
        auto bsfs_slot = reinterpret_cast<char**>(
            reinterpret_cast<char*>(obj) + kNiObjectNetNameOff);
        char* pool_entry = *bsfs_slot;
        if (!pool_entry) return 0;
        // Pool layout: pool_entry has 0x18-byte header, c_str follows.
        char* src = pool_entry + 0x18;
        int n;
        for (n = 0; n < out_cap - 1; ++n) {
            char c = src[n];
            out[n] = c;
            if (c == 0) break;
        }
        out[n] = 0;
        return n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        return -1;
    }
}

// Detect "_skin" suffix on a (small, bounded) name buffer.
bool name_is_skin_stub(const char* name, int len) {
    if (!name || len < 5) return false;
    return std::memcmp(name + len - 5, "_skin", 5) == 0;
}

// ------------------------------------------------------------------
// Per-geometry diagnostic
// ------------------------------------------------------------------
struct DiagAccum {
    int geometries_seen      = 0;
    int geometries_skinned   = 0;
    int total_bones          = 0;
    int total_stubs          = 0;
};

void diagnose_geometry(void* geom, DiagAccum& acc) {
    acc.geometries_seen++;

    auto geom_bytes = reinterpret_cast<char*>(geom);
    void* skin = nullptr;
    __try {
        skin = *reinterpret_cast<void**>(geom_bytes + kBSGeometrySkinInstanceOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] diag: SEH reading skin@geom+0x140 (geom=%p)", geom);
        return;
    }

    char gname[96];
    int gname_len = try_read_ni_name(geom, gname, sizeof(gname));
    if (gname_len <= 0) std::strncpy(gname, "<noname>", sizeof(gname) - 1);

    if (!skin) {
        FW_LOG("[skin] diag: geom=%p name='%s' NO_SKIN_INSTANCE",
               geom, gname);
        return;
    }

    acc.geometries_skinned++;

    auto skin_vt_rva = read_vt_rva(skin);
    auto skin_bytes = reinterpret_cast<char*>(skin);

    void**       bones_pri_head  = nullptr;
    std::uint32_t bones_pri_count = 0;
    void**       bones_fb_head   = nullptr;
    std::uint32_t bones_fb_count  = 0;
    void*        skel_root        = nullptr;

    __try {
        bones_pri_head  = *reinterpret_cast<void***>(
            skin_bytes + kSkinInstanceBonesPrimaryHeadOff);
        bones_pri_count = *reinterpret_cast<std::uint32_t*>(
            skin_bytes + kSkinInstanceBonesPrimaryCountOff);
        bones_fb_head   = *reinterpret_cast<void***>(
            skin_bytes + kSkinInstanceBonesFallbackHeadOff);
        bones_fb_count  = *reinterpret_cast<std::uint32_t*>(
            skin_bytes + kSkinInstanceBonesFallbackCountOff);
        skel_root       = *reinterpret_cast<void**>(
            skin_bytes + kSkinInstanceSkelRootOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] diag: SEH reading skin fields (skin=%p)", skin);
        return;
    }

    FW_LOG("[skin] diag: geom=%p name='%s' skin=%p skin_vt_rva=0x%llX",
           geom, gname, skin,
           static_cast<unsigned long long>(skin_vt_rva));
    FW_LOG("[skin] diag:   bones_primary  head=%p count=%u",
           static_cast<void*>(bones_pri_head), bones_pri_count);
    FW_LOG("[skin] diag:   bones_fallback head=%p count=%u",
           static_cast<void*>(bones_fb_head), bones_fb_count);
    FW_LOG("[skin] diag:   skel_root=%p (vt_rva=0x%llX)",
           skel_root,
           static_cast<unsigned long long>(read_vt_rva(skel_root)));

    if (skin_vt_rva != kBSSkinInstanceVtRva) {
        FW_WRN("[skin] diag:   !! skin vtable mismatch — expected "
               "0x%llX (BSSkin::Instance), got 0x%llX",
               static_cast<unsigned long long>(kBSSkinInstanceVtRva),
               static_cast<unsigned long long>(skin_vt_rva));
    }

    // DEBUG: hex-dump skin instance + first entry of BOTH arrays.
    // Goal: figure out which array contains NiAVObject* with names.
    auto hex_dump_block = [](const char* label, const void* addr, int rows) {
        for (int line = 0; line < rows; ++line) {
            auto p = reinterpret_cast<const std::uint8_t*>(addr) + line * 16;
            FW_LOG("[skin] diag:     %s+0x%02X: "
                   "%02X %02X %02X %02X %02X %02X %02X %02X "
                   "%02X %02X %02X %02X %02X %02X %02X %02X "
                   "  '%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c'",
                   label, line * 16,
                   p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                   p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
                   p[0]  >= 0x20 && p[0]  < 0x7F ? p[0]  : '.',
                   p[1]  >= 0x20 && p[1]  < 0x7F ? p[1]  : '.',
                   p[2]  >= 0x20 && p[2]  < 0x7F ? p[2]  : '.',
                   p[3]  >= 0x20 && p[3]  < 0x7F ? p[3]  : '.',
                   p[4]  >= 0x20 && p[4]  < 0x7F ? p[4]  : '.',
                   p[5]  >= 0x20 && p[5]  < 0x7F ? p[5]  : '.',
                   p[6]  >= 0x20 && p[6]  < 0x7F ? p[6]  : '.',
                   p[7]  >= 0x20 && p[7]  < 0x7F ? p[7]  : '.',
                   p[8]  >= 0x20 && p[8]  < 0x7F ? p[8]  : '.',
                   p[9]  >= 0x20 && p[9]  < 0x7F ? p[9]  : '.',
                   p[10] >= 0x20 && p[10] < 0x7F ? p[10] : '.',
                   p[11] >= 0x20 && p[11] < 0x7F ? p[11] : '.',
                   p[12] >= 0x20 && p[12] < 0x7F ? p[12] : '.',
                   p[13] >= 0x20 && p[13] < 0x7F ? p[13] : '.',
                   p[14] >= 0x20 && p[14] < 0x7F ? p[14] : '.',
                   p[15] >= 0x20 && p[15] < 0x7F ? p[15] : '.');
        }
    };

    __try {
        FW_LOG("[skin] diag:   DEBUG skin instance %p hex (192 bytes):", skin);
        hex_dump_block("skin", skin, 12);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] diag:   DEBUG SEH during skin hex dump");
    }

    if (bones_pri_head && bones_pri_count > 0) {
        __try {
            void* bone_pri0 = bones_pri_head[0];
            FW_LOG("[skin] diag:   DEBUG bones_pri[0]=%p (head=%p)",
                   bone_pri0, static_cast<void*>(bones_pri_head));
            if (bone_pri0) hex_dump_block("pri0", bone_pri0, 4);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[skin] diag:   DEBUG SEH during bones_pri[0] dump");
        }
    }

    if (bones_fb_head && bones_fb_count > 0) {
        __try {
            void* bone_fb0 = bones_fb_head[0];
            FW_LOG("[skin] diag:   DEBUG bones_fb[0]=%p (head=%p)",
                   bone_fb0, static_cast<void*>(bones_fb_head));
            if (bone_fb0) hex_dump_block("fb0 ", bone_fb0, 4);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[skin] diag:   DEBUG SEH during bones_fb[0] dump");
        }
    }

    // Also dump skin+0x40 deref (the BoneData container)
    __try {
        void* boneData = *reinterpret_cast<void**>(
            reinterpret_cast<char*>(skin) + 0x40);
        FW_LOG("[skin] diag:   DEBUG boneData (skin+0x40 deref) = %p", boneData);
        if (boneData) hex_dump_block("bd  ", boneData, 4);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] diag:   DEBUG SEH during boneData dump");
    }

    // FIX: Walk bones_FALLBACK (skin+0x10) — that's the NiNode array
    // with names. The dossier's "bones_primary" at +0x28 is actually
    // the inverse-bind matrix array (no names). Confirmed via hex dump:
    // skin+0x10 entries have NiNode vtable @ +0x00, BSFixedString @ +0x10.
    if (bones_fb_head && bones_fb_count > 0 && bones_fb_count < 256) {
        int stub_in_geom = 0;
        for (std::uint32_t i = 0; i < bones_fb_count; ++i) {
            void* bone = nullptr;
            char  bname[96];
            int   bname_len = -1;

            __try {
                bone = bones_fb_head[i];
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_ERR("[skin] diag:     SEH reading bones_fb[%u] head=%p",
                       i, static_cast<void*>(bones_fb_head));
                break;
            }

            if (!bone) {
                FW_LOG("[skin] diag:     bones_fb[%u] = NULL", i);
                continue;
            }

            // Read NiNode name at bone+0x10 (BSFixedString -> pool_entry+0x18)
            bname_len = try_read_ni_name(bone, bname, sizeof(bname));
            if (bname_len < 0) {
                FW_LOG("[skin] diag:     bones_fb[%u] = %p (name AV)", i, bone);
                continue;
            }
            const auto vt_rva = read_vt_rva(bone);
            const bool stub = name_is_skin_stub(bname, bname_len);
            FW_LOG("[skin] diag:     bones_fb[%u] = %p vt=0x%llX name='%s'%s",
                   i, bone,
                   static_cast<unsigned long long>(vt_rva),
                   bname, stub ? " [STUB]" : "");
            if (stub) stub_in_geom++;
            acc.total_bones++;
        }
        acc.total_stubs += stub_in_geom;
        FW_LOG("[skin] diag:   geom STUB count = %d / %u",
               stub_in_geom, bones_fb_count);
    } else if (bones_fb_count >= 256) {
        FW_WRN("[skin] diag:   !! bones_fb_count=%u >= 256, capping",
               bones_fb_count);
    }
}

// ------------------------------------------------------------------
// Recursive subtree walker — visit every BSGeometry under root
// ------------------------------------------------------------------
void walk_for_geometries(void* node, int depth, DiagAccum& acc) {
    if (!node || depth > 32) return;

    auto vt_rva = read_vt_rva(node);

    if (is_geometry(vt_rva)) {
        diagnose_geometry(node, acc);
        return;
    }

    if (!is_node_with_children(vt_rva)) {
        // Unknown type — don't recurse, log so we can extend whitelist
        char nname[96];
        if (try_read_ni_name(node, nname, sizeof(nname)) <= 0) {
            std::strncpy(nname, "<?>", sizeof(nname) - 1);
        }
        FW_DBG("[skin] diag: skip unknown vt_rva=0x%llX node=%p name='%s'",
               static_cast<unsigned long long>(vt_rva), node, nname);
        return;
    }

    // Recurse into children
    void** children_ptr = nullptr;
    std::uint16_t count = 0;
    __try {
        auto bytes = reinterpret_cast<char*>(node);
        children_ptr = *reinterpret_cast<void***>(bytes + kNiNodeChildrenPtrOff);
        count = *reinterpret_cast<std::uint16_t*>(bytes + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] diag: SEH reading children of node=%p", node);
        return;
    }

    if (!children_ptr || count == 0) return;
    if (count > 256) {
        FW_WRN("[skin] diag: node=%p has count=%u children, capping at 256",
               node, count);
        count = 256;
    }

    for (std::uint16_t i = 0; i < count; ++i) {
        void* child = nullptr;
        __try {
            child = children_ptr[i];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[skin] diag: SEH reading child[%u] of node=%p",
                   i, node);
            break;
        }
        walk_for_geometries(child, depth + 1, acc);
    }
}

} // namespace

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------
int diagnose_skin_stubs(void* body_root) {
    ensure_base();
    if (!body_root) {
        FW_ERR("[skin] diagnose_skin_stubs: NULL body_root");
        return -1;
    }
    if (!g_module_base) {
        FW_ERR("[skin] diagnose_skin_stubs: NULL module base");
        return -1;
    }

    auto root_vt_rva = read_vt_rva(body_root);
    char root_name[128];
    if (try_read_ni_name(body_root, root_name, sizeof(root_name)) <= 0) {
        std::strncpy(root_name, "<?>", sizeof(root_name) - 1);
    }
    FW_LOG("[skin] diag START body_root=%p vt_rva=0x%llX name='%s'",
           body_root,
           static_cast<unsigned long long>(root_vt_rva),
           root_name);

    DiagAccum acc{};
    walk_for_geometries(body_root, 0, acc);

    FW_LOG("[skin] diag END  geometries_seen=%d skinned=%d "
           "total_bones=%d total_stubs=%d",
           acc.geometries_seen, acc.geometries_skinned,
           acc.total_bones, acc.total_stubs);

    return acc.total_stubs;
}

// ====================================================================
// Step 3 — Refcount-safe NiPointer manipulation + bone swap
// ====================================================================

namespace {

constexpr std::size_t kRefcountOff = 0x08;

// Refcount-safe release. If refcount drops to 0, calls vtable[1] dtor.
void niptr_release(void* obj) {
    if (!obj) return;
    __try {
        auto* refc = reinterpret_cast<volatile long*>(
            reinterpret_cast<char*>(obj) + kRefcountOff);
        const long prev = _InterlockedExchangeAdd(refc, -1);
        if (prev == 1) {
            using DtorFn = void(__fastcall*)(void*);
            auto vt = *reinterpret_cast<void***>(obj);
            auto dtor = reinterpret_cast<DtorFn>(vt[1]);
            dtor(obj);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] niptr_release SEH obj=%p", obj);
    }
}

// INCREMENT-ONLY slot mutation. Increments new_val, atomically writes
// to *slot, LEAKS old refcount (does NOT decrement). Avoids
// use-after-free risk where the old bone may be referenced from
// somewhere we haven't audited (children list, BSGeometry skin data
// caches, etc.). Memory cost: ~58 NiNodes leaked per ghost body load
// (≈12 KB). Trivial for our use case.
//
// (Pure refcount-safe variant kept in git history for the day we have
//  full audit of what holds refs to the old stubs.)
void niptr_swap(void** slot, void* new_val) {
    __try {
        void* old_val = *slot;
        if (old_val == new_val) return;
        if (new_val) {
            auto* refc = reinterpret_cast<volatile long*>(
                reinterpret_cast<char*>(new_val) + kRefcountOff);
            _InterlockedIncrement(refc);
        }
        *slot = new_val;
        // Deliberately NOT decrementing old_val. See block comment.
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skin] niptr_swap SEH slot=%p new=%p",
               static_cast<void*>(slot), new_val);
    }
}

// Recursive subtree walker that finds the first node whose name matches
// `target_name` (case-sensitive strcmp). Returns nullptr if not found.
void* find_node_by_name(void* root, const char* target_name,
                        int depth, int& visited, int max_visit) {
    if (!root || !target_name || depth > 32 || visited >= max_visit)
        return nullptr;
    visited++;

    char nname[96];
    const int n = try_read_ni_name(root, nname, sizeof(nname));
    if (n > 0 && std::strcmp(nname, target_name) == 0) return root;

    const auto vt_rva = read_vt_rva(root);
    if (!is_node_with_children(vt_rva)) return nullptr;

    void** children_ptr = nullptr;
    std::uint16_t count = 0;
    __try {
        auto bytes = reinterpret_cast<char*>(root);
        children_ptr = *reinterpret_cast<void***>(
            bytes + kNiNodeChildrenPtrOff);
        count = *reinterpret_cast<std::uint16_t*>(
            bytes + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    if (!children_ptr || count == 0) return nullptr;
    if (count > 256) count = 256;

    for (std::uint16_t i = 0; i < count && visited < max_visit; ++i) {
        void* child = nullptr;
        __try { child = children_ptr[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        void* found = find_node_by_name(child, target_name,
                                         depth + 1, visited, max_visit);
        if (found) return found;
    }
    return nullptr;
}

// Per-call thread-local toggle: when true, FW_LOG calls inside
// swap_for_geometry / walk_for_swap and helpers are suppressed.
// Used by the periodic re-apply in on_bone_tick_message to avoid log flood
// (would be ~20 lines × N bones × 20Hz = thousands/sec otherwise).
thread_local bool tls_skin_swap_silent = false;

// Per-geometry swap: walk skin->bones_fb, rebind each entry to the
// matching named NiNode in skel_root tree. Then rebind skin->skel_root.
void swap_for_geometry(void* geom, void* skel_root,
                       int& swapped, int& failed, int& already) {
    auto geom_bytes = reinterpret_cast<char*>(geom);
    void* skin = nullptr;
    __try {
        skin = *reinterpret_cast<void**>(
            geom_bytes + kBSGeometrySkinInstanceOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!skin) return;

    void**       bones_fb_head  = nullptr;
    std::uint32_t bones_fb_count = 0;
    __try {
        auto sb = reinterpret_cast<char*>(skin);
        bones_fb_head  = *reinterpret_cast<void***>(
            sb + kSkinInstanceBonesFallbackHeadOff);
        bones_fb_count = *reinterpret_cast<std::uint32_t*>(
            sb + kSkinInstanceBonesFallbackCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    if (!bones_fb_head || bones_fb_count == 0 || bones_fb_count > 256)
        return;

    char gname[96];
    if (try_read_ni_name(geom, gname, sizeof(gname)) <= 0)
        std::strncpy(gname, "<?>", sizeof(gname) - 1);
    if (!tls_skin_swap_silent) {
        FW_LOG("[skin] swap: geom=%p name='%s' bones=%u",
               geom, gname, bones_fb_count);
    }

    for (std::uint32_t i = 0; i < bones_fb_count; ++i) {
        void* current = nullptr;
        char bname[96];
        __try { current = bones_fb_head[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (!current) continue;

        const int n = try_read_ni_name(current, bname, sizeof(bname));
        if (n <= 0) continue;

        int visited = 0;
        void* match = find_node_by_name(skel_root, bname, 0, visited, 1000);
        if (!match) {
            if (!tls_skin_swap_silent) {
                FW_LOG("[skin] swap:   [%u] '%s' NO MATCH in skel "
                       "(visited=%d)", i, bname, visited);
            }
            failed++;
            continue;
        }
        if (match == current) {
            already++;
            continue;
        }

        niptr_swap(&bones_fb_head[i], match);
        if (!tls_skin_swap_silent) {
            FW_LOG("[skin] swap:   [%u] '%s' %p -> %p OK",
                   i, bname, current, match);
        }
        swapped++;
    }

    // CRITICAL — re-cache bones_pri[i] to point at the (new) skel
    // bone's m_kWorld slot. Empirical finding (M8P3 diag dump):
    //   bones_pri[i] = bones_fb[i] + 0x70   (NOT a NiAVObject* — it's
    //                                         a direct pointer to the
    //                                         bone's world matrix).
    // GPU reads bones_pri[i] via SRV at draw time and slurps 64 bytes
    // of matrix from there. The cache was populated at NIF load
    // pointing at the ORIGINAL stub bones' matrices, and our
    // bones_fb swap above does NOT update it. Without this update,
    // GPU keeps drawing the stub bind-pose matrices regardless of
    // what we do to the skel bones — that's why every bone-write
    // experiment until M8P3.10 deformed nothing.
    void**       bones_pri_head  = nullptr;
    std::uint32_t bones_pri_count = 0;
    __try {
        auto sb = reinterpret_cast<char*>(skin);
        bones_pri_head  = *reinterpret_cast<void***>(
            sb + kSkinInstanceBonesPrimaryHeadOff);
        bones_pri_count = *reinterpret_cast<std::uint32_t*>(
            sb + kSkinInstanceBonesPrimaryCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bones_pri_head = nullptr;
        bones_pri_count = 0;
    }

    if (bones_pri_head && bones_pri_count == bones_fb_count) {
        int pri_updated = 0;
        for (std::uint32_t i = 0; i < bones_fb_count; ++i) {
            void* fb = nullptr;
            __try { fb = bones_fb_head[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            if (!fb) continue;
            void* world_slot = reinterpret_cast<char*>(fb) + 0x70;
            __try { bones_pri_head[i] = world_slot; }
            __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            pri_updated++;
        }
        if (!tls_skin_swap_silent) {
            FW_LOG("[skin] swap: bones_pri re-cache %d/%u entries (point at "
                   "post-swap fb[i]+0x70)", pri_updated, bones_fb_count);
        }
    } else if (bones_pri_head) {
        FW_WRN("[skin] swap: bones_pri count mismatch (pri=%u fb=%u) — "
               "skip re-cache", bones_pri_count, bones_fb_count);
    } else {
        FW_WRN("[skin] swap: bones_pri head NULL — skip re-cache");
    }

    // Rebind skin->skel_root (skin+0x48) → our skel_root
    void** skel_slot = reinterpret_cast<void**>(
        reinterpret_cast<char*>(skin) + kSkinInstanceSkelRootOff);
    void* old_skel = nullptr;
    __try { old_skel = *skel_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (old_skel != skel_root) {
        niptr_swap(skel_slot, skel_root);
        if (!tls_skin_swap_silent) {
            FW_LOG("[skin] swap: skin=%p skel_root rebind %p -> %p",
                   skin, old_skel, skel_root);
        }
    }
}

void walk_for_swap(void* node, int depth, void* skel_root,
                   int& swapped, int& failed, int& already) {
    if (!node || depth > 32) return;
    const auto vt_rva = read_vt_rva(node);

    if (is_geometry(vt_rva)) {
        swap_for_geometry(node, skel_root, swapped, failed, already);
        return;
    }
    if (!is_node_with_children(vt_rva)) return;

    void** children_ptr = nullptr;
    std::uint16_t count = 0;
    __try {
        auto bytes = reinterpret_cast<char*>(node);
        children_ptr = *reinterpret_cast<void***>(
            bytes + kNiNodeChildrenPtrOff);
        count = *reinterpret_cast<std::uint16_t*>(
            bytes + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!children_ptr || count == 0) return;
    if (count > 256) count = 256;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* child = nullptr;
        __try { child = children_ptr[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        walk_for_swap(child, depth + 1, skel_root,
                      swapped, failed, already);
    }
}

// Global skeleton cache (singleton across session).
std::atomic<void*> g_skel_root_cached{nullptr};

} // namespace

void cache_or_release_skeleton(void* skel_root) {
    if (!skel_root) return;
    void* expected = nullptr;
    if (g_skel_root_cached.compare_exchange_strong(expected, skel_root)) {
        FW_LOG("[skin] cache_skeleton: cached %p (took ownership of "
               "caller's refcount)", skel_root);
    } else {
        FW_LOG("[skin] cache_skeleton: race-loss, releasing local %p "
               "(cached is %p)", skel_root, expected);
        niptr_release(skel_root);
    }
}

void* get_cached_skeleton() {
    return g_skel_root_cached.load(std::memory_order_acquire);
}

int swap_skin_bones_to_skeleton(void* body_root, void* skel_root, bool silent) {
    ensure_base();
    if (!body_root || !skel_root) {
        FW_ERR("[skin] swap: NULL input body=%p skel=%p", body_root, skel_root);
        return -1;
    }
    const bool prev_silent = tls_skin_swap_silent;
    tls_skin_swap_silent = silent;
    if (!silent) {
        FW_LOG("[skin] swap START body=%p skel=%p", body_root, skel_root);
    }
    int swapped = 0, failed = 0, already = 0;
    walk_for_swap(body_root, 0, skel_root, swapped, failed, already);
    if (!silent) {
        FW_LOG("[skin] swap END  swapped=%d failed=%d already_correct=%d",
               swapped, failed, already);
    }
    tls_skin_swap_silent = prev_silent;
    return swapped;
}

// =====================================================================
// M9 wedge 2 — vault-suit-cycle regression fix (2026-05-01)
// =====================================================================
//
// See header doc for design. Below is the implementation.
//
// Snapshot store keyed on the body_root (== armor_node from
// ghost_attach_armor's call site). Each snapshot records, per skin
// instance found in the subtree:
//   - the skin pointer itself (so on restore we re-walk and match)
//   - the original bones_fb[] head pointer + a DEEP COPY of the
//     contents (each bones_fb[i] before swap)
//   - the original bones_pri[] head pointer + a DEEP COPY
//   - the original skel_root pointer
//
// At restore: walk skin instances, look up snapshot by skin pointer,
// memcpy back the bones_fb[] / bones_pri[] / skel_root contents.
// Refcount-neutral on the slots (we're putting back exactly what was
// there before; the swap that displaced these did NOT decrement
// refcount — see niptr_swap leak philosophy at line 464).
//
// What "leaks": the skel_root bones we displaced via niptr_swap during
// the original swap_skin_bones_to_skeleton call. Those bones got their
// refcount bumped by niptr_swap; we never decrement. After restore,
// they're no longer referenced by bones_fb[i] but their refcount stays
// elevated. ~12KB per attach/detach cycle. Trivial.

namespace {

struct SkinSnapshot {
    void*               skin_ptr   = nullptr;
    void**              fb_head    = nullptr;   // address of skin+0x10 deref target
    std::vector<void*>  fb_orig;                // deep copy
    void**              pri_head   = nullptr;
    std::vector<void*>  pri_orig;
    void*               skel_root  = nullptr;
};

struct ArmorSnapshot {
    std::vector<SkinSnapshot> skins;
};

std::mutex                                g_armor_snap_mtx;
std::unordered_map<void*, ArmorSnapshot>  g_armor_snapshots;

// Walk a subtree and call cb(skin_instance, skin_offset_inside_geom) for
// every BSGeometry encountered. cb MUST be SEH-internal-safe.
template <typename Cb>
void for_each_skin_instance(void* node, int depth, Cb&& cb) {
    if (!node || depth > 32) return;
    const auto vt_rva = read_vt_rva(node);
    if (is_geometry(vt_rva)) {
        void* skin = nullptr;
        __try {
            skin = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(node) + kBSGeometrySkinInstanceOff);
        } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
        if (skin) cb(skin);
        return;
    }
    if (!is_node_with_children(vt_rva)) return;

    void** kids = nullptr;
    std::uint16_t cnt = 0;
    __try {
        auto bytes = reinterpret_cast<char*>(node);
        kids = *reinterpret_cast<void***>(bytes + kNiNodeChildrenPtrOff);
        cnt  = *reinterpret_cast<std::uint16_t*>(bytes + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!kids || cnt == 0 || cnt > 256) return;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = nullptr;
        __try { child = kids[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        for_each_skin_instance(child, depth + 1, cb);
    }
}

// Read fb_head, fb_count, pri_head, pri_count, skel_root from a skin
// instance. POD-only (callable from within __try of a non-POD function).
struct SkinSlots {
    void**          fb_head    = nullptr;
    std::uint32_t   fb_count   = 0;
    void**          pri_head   = nullptr;
    std::uint32_t   pri_count  = 0;
    void*           skel_root  = nullptr;
    bool            ok         = false;
};

SkinSlots read_skin_slots(void* skin) {
    SkinSlots s{};
    if (!skin) return s;
    __try {
        auto sb = reinterpret_cast<char*>(skin);
        s.fb_head   = *reinterpret_cast<void***>(
            sb + kSkinInstanceBonesFallbackHeadOff);
        s.fb_count  = *reinterpret_cast<std::uint32_t*>(
            sb + kSkinInstanceBonesFallbackCountOff);
        s.pri_head  = *reinterpret_cast<void***>(
            sb + kSkinInstanceBonesPrimaryHeadOff);
        s.pri_count = *reinterpret_cast<std::uint32_t*>(
            sb + kSkinInstanceBonesPrimaryCountOff);
        s.skel_root = *reinterpret_cast<void**>(
            sb + kSkinInstanceSkelRootOff);
        s.ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return s;
}

// Snapshot the contents (deep copy) of a head[] array of size count.
// SEH-protected. Returns whether the read succeeded; on failure `out`
// is left empty.
bool seh_snapshot_array(void** head, std::uint32_t count,
                        std::vector<void*>& out) {
    out.clear();
    if (!head || count == 0 || count > 1024) return false;
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        void* v = nullptr;
        __try { v = head[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        out.push_back(v);
    }
    return true;
}

// Write back contents from `src` into head[]. SEH-protected. Refcount-
// neutral — the slot held this pointer before (or its replacement that
// was leaked during niptr_swap), so writing it back does not require
// any new refcount manipulation.
void seh_restore_array(void** head, const std::vector<void*>& src) {
    if (!head || src.empty()) return;
    for (std::size_t i = 0; i < src.size(); ++i) {
        __try { head[i] = src[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    }
}

void seh_write_skel_root(void* skin, void* val) {
    if (!skin) return;
    __try {
        auto sb = reinterpret_cast<char*>(skin);
        *reinterpret_cast<void**>(sb + kSkinInstanceSkelRootOff) = val;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

} // namespace

int take_skin_snapshot(void* body_root) {
    ensure_base();
    if (!body_root) {
        FW_ERR("[skin] take_snapshot: null body_root");
        return -1;
    }

    ArmorSnapshot snap;
    for_each_skin_instance(body_root, 0, [&](void* skin) {
        SkinSlots slots = read_skin_slots(skin);
        if (!slots.ok) {
            FW_WRN("[skin] take_snapshot: SEH reading skin=%p slots — skip",
                   skin);
            return;
        }
        SkinSnapshot ss{};
        ss.skin_ptr  = skin;
        ss.fb_head   = slots.fb_head;
        ss.pri_head  = slots.pri_head;
        ss.skel_root = slots.skel_root;
        if (!seh_snapshot_array(slots.fb_head, slots.fb_count, ss.fb_orig)) {
            FW_WRN("[skin] take_snapshot: skin=%p fb head read failed (count=%u)",
                   skin, slots.fb_count);
        }
        if (!seh_snapshot_array(slots.pri_head, slots.pri_count, ss.pri_orig)) {
            FW_WRN("[skin] take_snapshot: skin=%p pri head read failed (count=%u)",
                   skin, slots.pri_count);
        }
        FW_DBG("[skin] take_snapshot: skin=%p fb=%zu pri=%zu skel=%p",
               skin, ss.fb_orig.size(), ss.pri_orig.size(), ss.skel_root);
        snap.skins.push_back(std::move(ss));
    });

    if (snap.skins.empty()) {
        FW_DBG("[skin] take_snapshot: body=%p has no skin instances — no-op",
               body_root);
        return -1;
    }

    {
        std::lock_guard lk(g_armor_snap_mtx);
        g_armor_snapshots[body_root] = std::move(snap);
    }
    FW_LOG("[skin] take_snapshot: body=%p stored snapshot for %zu skin "
           "instances", body_root,
           g_armor_snapshots[body_root].skins.size());
    return 0;
}

int restore_skin_from_snapshot(void* body_root) {
    ensure_base();
    if (!body_root) {
        FW_ERR("[skin] restore: null body_root");
        return -1;
    }

    ArmorSnapshot snap;
    {
        std::lock_guard lk(g_armor_snap_mtx);
        auto it = g_armor_snapshots.find(body_root);
        if (it == g_armor_snapshots.end()) {
            FW_DBG("[skin] restore: body=%p no snapshot — idempotent no-op",
                   body_root);
            return 1;
        }
        snap = std::move(it->second);
        g_armor_snapshots.erase(it);
    }

    int restored_skins = 0;
    for (const auto& ss : snap.skins) {
        // Defensive: re-read the skin's current slot pointers. If the
        // engine relocated the bones array between attach and detach,
        // our cached fb_head / pri_head pointers would be stale.
        SkinSlots cur = read_skin_slots(ss.skin_ptr);
        if (!cur.ok) {
            FW_WRN("[skin] restore: skin=%p SEH on read — skip", ss.skin_ptr);
            continue;
        }
        // If the array head moved or count changed, log + skip — restore
        // is unsafe. The skin was rebuilt by the engine; whatever state
        // it's in now we leave alone.
        if (cur.fb_head != ss.fb_head ||
            cur.pri_head != ss.pri_head ||
            cur.fb_count != ss.fb_orig.size() ||
            cur.pri_count != ss.pri_orig.size())
        {
            FW_WRN("[skin] restore: skin=%p layout changed since attach "
                   "(fb_head %p->%p, pri_head %p->%p, fb_cnt %zu->%u, "
                   "pri_cnt %zu->%u) — skip",
                   ss.skin_ptr,
                   ss.fb_head,  cur.fb_head,
                   ss.pri_head, cur.pri_head,
                   ss.fb_orig.size(),  cur.fb_count,
                   ss.pri_orig.size(), cur.pri_count);
            continue;
        }
        seh_restore_array(cur.fb_head,  ss.fb_orig);
        seh_restore_array(cur.pri_head, ss.pri_orig);
        seh_write_skel_root(ss.skin_ptr, ss.skel_root);
        ++restored_skins;
        FW_DBG("[skin] restore: skin=%p restored %zu fb + %zu pri + skel=%p",
               ss.skin_ptr, ss.fb_orig.size(), ss.pri_orig.size(),
               ss.skel_root);
    }

    FW_LOG("[skin] restore: body=%p restored %d/%zu skin instances",
           body_root, restored_skins, snap.skins.size());
    return 0;
}

void* get_bone_by_name(const char* name) {
    if (!name) return nullptr;
    void* skel = g_skel_root_cached.load(std::memory_order_acquire);
    if (!skel) return nullptr;
    int visited = 0;
    return find_node_by_name(skel, name, 0, visited, 1000);
}

// Iterate skin->bones_fb[] (skin+0x10 head, skin+0x20 count) and find
// the first entry whose NiAVObject* has matching name.
//
// IMPORTANT — DO NOT iterate bones_pri (skin+0x28). Empirical M8P3
// finding: bones_pri is NOT a NiAVObject** array; it's a cache of
// pointers DIRECTLY to bone world matrices (each entry =
// bones_fb[i]+0x70). Reading them as NiAVObject* gets garbage.
//
// Post-swap, bones_fb contains skel bones with their original
// (non-"_skin"-suffixed) NIF names like "LArm_ForeArm1". So lookup
// with the NORMAL bone name returns the bone whose world matrix is
// what the GPU reads (after the swap also re-caches bones_pri).
//
// Returns the NiAVObject* to register in the UpdateWorldData hook.
void* find_bone_in_bones_pri(void* skin, const char* name) {
    if (!skin || !name) return nullptr;
    void**       head  = nullptr;
    std::uint32_t count = 0;
    __try {
        auto sb = reinterpret_cast<char*>(skin);
        head  = *reinterpret_cast<void***>(
            sb + kSkinInstanceBonesFallbackHeadOff);
        count = *reinterpret_cast<std::uint32_t*>(
            sb + kSkinInstanceBonesFallbackCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!head || count == 0 || count > 256) return nullptr;
    for (std::uint32_t i = 0; i < count; ++i) {
        void* bone = nullptr;
        __try { bone = head[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!bone) continue;
        char bname[96];
        const int n = try_read_ni_name(bone, bname, sizeof(bname));
        if (n > 0 && std::strcmp(bname, name) == 0) {
            return bone;
        }
    }
    return nullptr;
}

namespace {

void* walk_for_first_skinned_geom(void* node, int depth) {
    if (!node || depth > 24) return nullptr;
    auto vt = read_vt_rva(node);
    if (is_geometry(vt)) {
        __try {
            void* skin = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(node) + kBSGeometrySkinInstanceOff);
            if (skin) return skin;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        return nullptr;
    }
    if (!is_node_with_children(vt)) return nullptr;
    void** kids = nullptr;
    std::uint16_t cnt = 0;
    __try {
        auto b = reinterpret_cast<char*>(node);
        kids = *reinterpret_cast<void***>(b + kNiNodeChildrenPtrOff);
        cnt = *reinterpret_cast<std::uint16_t*>(b + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!kids || cnt == 0 || cnt > 256) return nullptr;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* c = nullptr;
        __try { c = kids[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        void* found = walk_for_first_skinned_geom(c, depth + 1);
        if (found) return found;
    }
    return nullptr;
}

} // namespace

void* find_body_skin_instance(void* body_root) {
    ensure_base();
    if (!body_root) return nullptr;
    return walk_for_first_skinned_geom(body_root, 0);
}

namespace {

void walk_collect_skins(void* node, int depth, void** out, int max, int& count) {
    if (!node || depth > 24 || count >= max) return;
    auto vt = read_vt_rva(node);
    if (is_geometry(vt)) {
        __try {
            void* skin = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(node) + kBSGeometrySkinInstanceOff);
            if (skin && count < max) out[count++] = skin;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        return;
    }
    if (!is_node_with_children(vt)) return;
    void** kids = nullptr;
    std::uint16_t cnt = 0;
    __try {
        auto b = reinterpret_cast<char*>(node);
        kids = *reinterpret_cast<void***>(b + kNiNodeChildrenPtrOff);
        cnt = *reinterpret_cast<std::uint16_t*>(b + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!kids || cnt == 0 || cnt > 256) return;
    for (std::uint16_t i = 0; i < cnt && count < max; ++i) {
        void* c = nullptr;
        __try { c = kids[i]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        walk_collect_skins(c, depth + 1, out, max, count);
    }
}

} // namespace

int find_all_skin_instances(void* root, void** out_array, int max_count) {
    ensure_base();
    if (!root || !out_array || max_count <= 0) return 0;
    int count = 0;
    walk_collect_skins(root, 0, out_array, max_count, count);
    return count;
}

// ====================================================================
// M8P3.7 — UpdateWorldData hook (engine race winner)
// ====================================================================

namespace {

constexpr std::uintptr_t kUpdateWorldDataRva = 0x16C85A0;
constexpr std::size_t kWorldMatrixOff = 0x70;
constexpr std::size_t kWorldMatrixSize = 64;  // 4x4 col-major = 16 floats

// Globals — accessed from hook (game/render thread) + register/set
// (WndProc / net thread). Mutex on every UpdateWorldData hit (~30k/s)
// is acceptable: uncontended std::mutex ~20ns, total ~600us/sec.
std::mutex g_ghost_mutex;
std::unordered_set<void*> g_ghost_bones;
std::unordered_map<void*, std::array<float, 16>> g_bone_overrides;

using UpdateWorldDataFn = std::int64_t (__fastcall*)(void*, void*);
UpdateWorldDataFn g_orig_update_world_data = nullptr;
std::atomic<bool> g_hook_installed{false};

// Diagnostic counters
std::atomic<std::uint64_t> g_hook_total_calls{0};
std::atomic<std::uint64_t> g_hook_override_hits{0};

// Hot-path lookup, isolated from __try so MSVC doesn't choke on
// lock_guard (RAII) + SEH coexistence (C2712).
bool lookup_override(void* a1, std::array<float, 16>& out) {
    std::lock_guard<std::mutex> lk(g_ghost_mutex);
    if (g_ghost_bones.count(a1) == 0) return false;
    auto it = g_bone_overrides.find(a1);
    if (it == g_bone_overrides.end()) return false;
    out = it->second;
    return true;
}

// Apply override as a 3x3 ROTATION DELTA pre-multiplied against the
// engine's just-computed bone world matrix.
//
// CRITICAL semantics change (M8P3.13 → M8P3.14):
//   The override mat16's 3x3 part (mat[0..2], mat[4..6], mat[8..10]) is
//   treated as a *delta* rotation. The hook reads the engine's
//   freshly-written m_kWorld at bone+0x70, extracts its 3x3 (the bind-
//   pose world rotation, possibly already including parent-driven body
//   movement), pre-multiplies by the delta, and writes back. The
//   translation row of the override (mat[12..14]) is IGNORED — engine's
//   translation is preserved.
//
// Why: writing a self-contained 4x4 caused a feedback loop. The tick
// handler read bone+0xA0 to compute translation, but bone+0xA0 had
// just been overwritten by our previous override → translation
// permanently frozen at first-tick value → forearm pinned at spawn
// position while body translates with peer movement → mesh stretched.
//
// With this change, the body root translates → engine recomputes
// bone.world.translation each frame → hook keeps that translation,
// only spins the 3x3 → forearm follows body cleanly.
void apply_override_safe(void* a1, const float* mat16) {
    __try {
        float* engine = reinterpret_cast<float*>(
            reinterpret_cast<char*>(a1) + kWorldMatrixOff);
        // Engine's bind-pose 3x3 (rows 0-2, cols 0-2).
        const float b00 = engine[0],  b01 = engine[1],  b02 = engine[2];
        const float b10 = engine[4],  b11 = engine[5],  b12 = engine[6];
        const float b20 = engine[8],  b21 = engine[9],  b22 = engine[10];
        // Override 3x3 (delta rotation).
        const float o00 = mat16[0],   o01 = mat16[1],   o02 = mat16[2];
        const float o10 = mat16[4],   o11 = mat16[5],   o12 = mat16[6];
        const float o20 = mat16[8],   o21 = mat16[9],   o22 = mat16[10];
        // new_3x3 = override * bind  (row-major matmul).
        engine[0]  = o00*b00 + o01*b10 + o02*b20;
        engine[1]  = o00*b01 + o01*b11 + o02*b21;
        engine[2]  = o00*b02 + o01*b12 + o02*b22;
        engine[4]  = o10*b00 + o11*b10 + o12*b20;
        engine[5]  = o10*b01 + o11*b11 + o12*b21;
        engine[6]  = o10*b02 + o11*b12 + o12*b22;
        engine[8]  = o20*b00 + o21*b10 + o22*b20;
        engine[9]  = o20*b01 + o21*b11 + o22*b21;
        engine[10] = o20*b02 + o21*b12 + o22*b22;
        // engine[12..14] (translation) intentionally NOT touched —
        // engine's value follows body root movement.
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Hot path. Call orig first. Then if a1 is a registered ghost bone,
// override its world matrix.
std::int64_t __fastcall hook_update_world_data(void* a1, void* a2) {
    g_hook_total_calls.fetch_add(1, std::memory_order_relaxed);

    const auto result = g_orig_update_world_data
        ? g_orig_update_world_data(a1, a2) : 0;
    if (!a1) return result;

    std::array<float, 16> mat;
    if (!lookup_override(a1, mat)) return result;

    g_hook_override_hits.fetch_add(1, std::memory_order_relaxed);
    apply_override_safe(a1, mat.data());
    return result;
}

} // namespace

bool install_world_update_hook(std::uintptr_t module_base) {
    bool expected = false;
    if (!g_hook_installed.compare_exchange_strong(expected, true)) {
        FW_DBG("[skin] world-update hook already installed");
        return true;
    }
    auto target = reinterpret_cast<void*>(module_base + kUpdateWorldDataRva);
    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&hook_update_world_data),
        reinterpret_cast<void**>(&g_orig_update_world_data));
    if (!ok) {
        FW_ERR("[skin] install_world_update_hook FAILED at %p", target);
        g_hook_installed.store(false);
        return false;
    }
    FW_LOG("[skin] world-update hook installed @ %p (RVA 0x%llX)",
           target, static_cast<unsigned long long>(kUpdateWorldDataRva));
    return true;
}

void register_ghost_bone(void* bone) {
    if (!bone) return;
    std::lock_guard<std::mutex> lk(g_ghost_mutex);
    g_ghost_bones.insert(bone);
}

void set_bone_world(void* bone, const float* mat16) {
    if (!bone || !mat16) return;
    std::array<float, 16> copy;
    std::memcpy(copy.data(), mat16, kWorldMatrixSize);
    std::lock_guard<std::mutex> lk(g_ghost_mutex);
    g_bone_overrides[bone] = copy;
}

void clear_ghost_bones() {
    std::lock_guard<std::mutex> lk(g_ghost_mutex);
    g_ghost_bones.clear();
    g_bone_overrides.clear();
}

void get_and_reset_hook_stats(std::uint64_t& total, std::uint64_t& overrides) {
    total = g_hook_total_calls.exchange(0, std::memory_order_relaxed);
    overrides = g_hook_override_hits.exchange(0, std::memory_order_relaxed);
}

int write_bones_pri_translation(void* skin, int idx, int write_offset,
                                float x, float y, float z) {
    if (!skin || idx < 0 || idx >= 256) return -1;
    __try {
        auto sb = reinterpret_cast<char*>(skin);
        void** bones_pri_head = *reinterpret_cast<void***>(
            sb + kSkinInstanceBonesPrimaryHeadOff);
        std::uint32_t count = *reinterpret_cast<std::uint32_t*>(
            sb + kSkinInstanceBonesPrimaryCountOff);
        if (!bones_pri_head || static_cast<std::uint32_t>(idx) >= count) return -1;
        void* entry = bones_pri_head[idx];
        if (!entry) return -1;
        float* tr = reinterpret_cast<float*>(
            reinterpret_cast<char*>(entry) + write_offset);
        tr[0] = x; tr[1] = y; tr[2] = z;
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// ------------------------------------------------------------------
// Step 2 — recursive walker that logs every node in a skeleton tree
// ------------------------------------------------------------------
namespace {

void walk_skel_dump(void* node, int depth, int& visited, int max_visit) {
    if (!node || depth > 32 || visited >= max_visit) return;
    visited++;

    auto vt_rva = read_vt_rva(node);

    char nname[96];
    int n = try_read_ni_name(node, nname, sizeof(nname));
    if (n < 0) std::strncpy(nname, "<AV>", sizeof(nname) - 1);

    FW_LOG("[skel] %*s%p vt=0x%llX name='%s'",
           depth * 2, "", node,
           static_cast<unsigned long long>(vt_rva), nname);

    if (!is_node_with_children(vt_rva)) return;

    void** children_ptr = nullptr;
    std::uint16_t count = 0;
    __try {
        auto bytes = reinterpret_cast<char*>(node);
        children_ptr = *reinterpret_cast<void***>(
            bytes + kNiNodeChildrenPtrOff);
        count = *reinterpret_cast<std::uint16_t*>(
            bytes + kNiNodeChildrenCountOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[skel] SEH reading children of node=%p", node);
        return;
    }

    if (!children_ptr || count == 0) return;
    if (count > 256) {
        FW_WRN("[skel] node=%p has count=%u children, capping at 256",
               node, count);
        count = 256;
    }

    for (std::uint16_t i = 0; i < count && visited < max_visit; ++i) {
        void* child = nullptr;
        __try {
            child = children_ptr[i];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[skel] SEH reading child[%u] of node=%p", i, node);
            break;
        }
        walk_skel_dump(child, depth + 1, visited, max_visit);
    }
}

} // namespace

int dump_skeleton_bones(void* skel_root) {
    ensure_base();
    if (!skel_root) {
        FW_ERR("[skel] dump_skeleton_bones: NULL skel_root");
        return -1;
    }

    char root_name[96];
    if (try_read_ni_name(skel_root, root_name, sizeof(root_name)) <= 0) {
        std::strncpy(root_name, "<?>", sizeof(root_name) - 1);
    }
    auto root_vt_rva = read_vt_rva(skel_root);

    FW_LOG("[skel] dump START root=%p vt=0x%llX name='%s'",
           skel_root,
           static_cast<unsigned long long>(root_vt_rva),
           root_name);

    int visited = 0;
    walk_skel_dump(skel_root, 0, visited, 1000);

    FW_LOG("[skel] dump END  visited=%d nodes", visited);
    return visited;
}

} // namespace fw::native::skin_rebind
