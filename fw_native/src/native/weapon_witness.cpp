// M9 wedge 4 (witness pattern, step 2) — weapon witness walker.
// See weapon_witness.h for the design rationale.

#include "weapon_witness.h"

#include <windows.h>
#include <cstring>
#include <algorithm>
#include <utility>

#include "../log.h"
#include "../offsets.h"     // PLAYER_SINGLETON_RVA shared with engine path
#include "ni_offsets.h"     // NIAV_*, NINODE_*, REFR_LOADED_3D_OFF
#include "nif_path_cache.h" // lookup for cache hits
#include "bsgeo_input_cache.h" // M9 w4 Path B-alt-1: factory input lookup
#include "ni_alloc_tracker.h"  // M9 w4 Path B-alt-2: alloc caller-RIP lookup

namespace fw::native::weapon_witness {

namespace {

// ----------------------------------------------------------------------------
// SEH-safe primitive readers (no C++ objects → __try is legal)
// ----------------------------------------------------------------------------

// Read m_name (NiObjectNET +0x10) using the BSFixedString pool layout
// proven by scene_inject::safe_bone_name (which yields 98 named nodes
// from the local player's path_a — "Root, COM, Pelvis, ..., LArm_Hand,
// RArm_Hand, ..." — visible in pose-tx-diag's player_map dump).
//
// FO4 1.11.191 layout:
//   node + 0x10 → m_name field, an 8-byte BSFixedString handle that
//                 is a POINTER to a pool_entry struct
//   pool_entry + 0x18 → the inline ASCII string bytes (null-terminated)
//
// The previous implementation used the scene_walker double-deref pattern
// (interpret pool_entry as char*) which fails on FO4 NG — pool_entry+0x00
// is refcount/hash/length header, not the string itself. That bug made
// the walker see ALL nodes as anonymous "raw16" garbage, so it never
// matched "WEAPON" / "Weapon" / "RArm_Hand" / etc. Hence empty snapshot.
//
// Writes up to bufsz-1 chars + null. Returns true on success (name had
// at least one printable ASCII character).
bool seh_read_node_name(void* node, char* buf, std::size_t bufsz) {
    if (!node || bufsz < 2) {
        if (bufsz) buf[0] = 0;
        return false;
    }
    // 1. Read pool_entry from node+0x10 (single deref).
    const char* pool_entry = nullptr;
    __try {
        pool_entry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(node) + NIAV_NAME_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        buf[0] = 0;
        return false;
    }
    if (!pool_entry) { buf[0] = 0; return false; }

    // 2. ASCII string starts at pool_entry+0x18 (inline, null-terminated).
    __try {
        const char* s = pool_entry + 0x18;
        std::size_t i = 0;
        for (; i < bufsz - 1 && s[i]; ++i) {
            const char c = s[i];
            if (c < 0x20 || c > 0x7E) {
                // Non-printable: stop here. If we got at least one
                // printable char, treat as success (truncated read).
                buf[i] = 0;
                return i > 0;
            }
            buf[i] = c;
        }
        buf[i] = 0;
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        buf[0] = 0;
        return false;
    }
}

// Read parent NiAVObject* (NiAVObject +0x28). Returns nullptr on AV / null.
void* seh_read_parent(void* node) {
    if (!node) return nullptr;
    __try {
        return *reinterpret_cast<void**>(
            reinterpret_cast<char*>(node) + NIAV_PARENT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Read local NiTransform (16 floats: 0x40 bytes from node+0x30 to node+0x70).
// Returns true on success.
bool seh_read_local_transform(void* node, float out[16]) {
    if (!node) return false;
    __try {
        const char* base = reinterpret_cast<const char*>(node)
                         + NIAV_LOCAL_ROTATE_OFF;
        std::memcpy(out, base, sizeof(float) * 16);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Read children pointer + count from a NiNode-derived object. Returns
// false on AV. Both outputs valid on success; either may still be null/0
// for leaf shapes (BSGeometry, BSTriShape) which inherit the layout but
// don't use it.
bool seh_read_children(void* node, void**& kids, std::uint16_t& count) {
    kids = nullptr;
    count = 0;
    if (!node) return false;
    __try {
        char* nb = reinterpret_cast<char*>(node);
        kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        kids = nullptr;
        count = 0;
        return false;
    }
}

// SEH-cage indirect read of kids[i]. Pure POD signature (no C++ unwind
// requirements) so callers that hold std::vector / std::string can
// invoke this inside C++ control flow without tripping C2712.
void* seh_index_child(void** kids, std::uint16_t i) {
    if (!kids) return nullptr;
    __try {
        return kids[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// === BSGeometry mesh-data read helpers ===================================
// All POD signatures so they coexist with std::vector callers.

struct BSGeoHeader {
    void*         pos_data;       // BSPositionData* @ +0x148
    std::uint32_t tri_count;      // @ +0x160
    std::uint16_t vert_count;     // @ +0x164
    void*         shader_prop;    // BSLightingShaderProperty* @ +0x138
    bool          ok;
};

bool seh_read_bsgeo_header(void* geom, BSGeoHeader& out) {
    out = {};
    if (!geom) return false;
    __try {
        char* gb = reinterpret_cast<char*>(geom);
        out.pos_data    = *reinterpret_cast<void**>(gb + BSGEOM_POSITION_DATA_OFF);
        out.tri_count   = *reinterpret_cast<std::uint32_t*>(gb + BSGEOM_TRI_COUNT_OFF);
        out.vert_count  = *reinterpret_cast<std::uint16_t*>(gb + BSGEOM_VERT_COUNT_OFF);
        out.shader_prop = *reinterpret_cast<void**>(gb + BSGEOM_SHADERPROP_OFF);
        out.ok = true;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out.ok = false;
        return false;
    }
}

struct BSPosDataHeader {
    void*         packed_buffer;     // u16* @ +0x18
    void*         full_prec_pos;     // float* @ +0x20 (may be null)
    std::uint32_t packed_size_u16;   // @ +0x28 (size in u16 units)
    std::uint32_t flag;              // @ +0x30
    bool          ok;
};

bool seh_read_pos_data_header(void* pd, BSPosDataHeader& out) {
    out = {};
    if (!pd) return false;
    __try {
        char* pb = reinterpret_cast<char*>(pd);
        out.packed_buffer    = *reinterpret_cast<void**>(pb + BSPOSDATA_PACKED_BUFFER_OFF);
        out.full_prec_pos    = *reinterpret_cast<void**>(pb + BSPOSDATA_FULL_PREC_OFF);
        out.packed_size_u16  = *reinterpret_cast<std::uint32_t*>(pb + BSPOSDATA_PACKED_SIZE_OFF);
        out.flag             = *reinterpret_cast<std::uint32_t*>(pb + BSPOSDATA_FLAG_OFF);
        out.ok = true;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out.ok = false;
        return false;
    }
}

// Memcpy out raw bytes from a (possibly invalid) source pointer.
// Returns true if all `nbytes` were copied without AV.
bool seh_memcpy_from_engine(void* dst, const void* src, std::size_t nbytes) {
    if (!dst || !src || nbytes == 0) return false;
    __try {
        std::memcpy(dst, src, nbytes);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Read a node's vtable as an RVA (relative to Fallout4.exe image base).
// Returns 0 on AV / null. Used to discriminate BSTriShape (sizeof 0x170,
// has BSGeometry layout) from plain NiNode (sizeof 0x140, where +0x148 is
// past-the-end heap garbage that mimics a "geometry" with bogus vc/tc).
std::uintptr_t seh_read_vtable_rva(void* node, std::uintptr_t module_base) {
    if (!node || !module_base) return 0;
    __try {
        void* vt = *reinterpret_cast<void**>(node);
        if (!vt) return 0;
        const std::uintptr_t v = reinterpret_cast<std::uintptr_t>(vt);
        if (v < module_base) return 0;
        return v - module_base;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// True if `node`'s vtable is one of the BSGeometry-derived classes whose
// memory layout includes the +0x148 BSPositionData* / +0x160 tri_count /
// +0x164 vert_count fields. NiNode (0x140 bytes) does NOT — its +0x148
// reads past-the-end heap garbage.
bool is_bsgeometry_derived(std::uintptr_t vt_rva) {
    return vt_rva == BSGEOMETRY_VTABLE_RVA
        || vt_rva == BSTRISHAPE_VTABLE_RVA
        || vt_rva == BSDYNAMICTRISHAPE_VTABLE_RVA;
}

// === iter12 helper-struct readers (POD-only, no C++ unwind in scope) ====
// SEH-cage the qword reads from BSGeometryStreamHelper at clone+0x148
// and the inner BSStreamDesc structs. Caller passes outputs by ref so
// the helper has no C++ object to unwind on AV.

bool seh_read_helper_struct(const void* helper,
                             std::uint64_t& out_vd,
                             void*& out_vstream,
                             void*& out_istream)
{
    out_vd = 0; out_vstream = nullptr; out_istream = nullptr;
    if (!helper) return false;
    __try {
        const char* h = reinterpret_cast<const char*>(helper);
        out_vd      = *reinterpret_cast<const std::uint64_t*>(
            h + BSGEOSTREAMH_VERTEX_DESC_OFF);
        out_vstream = *reinterpret_cast<void* const*>(
            h + BSGEOSTREAMH_VSTREAM_OFF);
        out_istream = *reinterpret_cast<void* const*>(
            h + BSGEOSTREAMH_ISTREAM_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool seh_read_stream_desc(const void* desc,
                           void*& out_buf,
                           std::uint32_t& out_size)
{
    out_buf = nullptr; out_size = 0;
    if (!desc) return false;
    __try {
        const char* d = reinterpret_cast<const char*>(desc);
        out_buf  = *reinterpret_cast<void* const*>(
            d + BSSTREAMDESC_RAW_BUF_OFF);
        out_size = *reinterpret_cast<const std::uint32_t*>(
            d + BSSTREAMDESC_SIZE_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-cage byte read for hex dump diagnostic.
bool seh_read_byte(const void* p, std::uint8_t& out) {
    if (!p) { out = 0; return false; }
    __try {
        out = *reinterpret_cast<const std::uint8_t*>(p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out = 0xCC;
        return false;
    }
}

// Half-precision (IEEE 754 binary16) → single-precision conversion.
// Bit layout of half: sign[15] exp[14:10] mantissa[9:0]; bias 15.
// Used when the BSGeometry has no full-prec position buffer (pd->+0x20 null).
float half_to_float(std::uint16_t h) {
    const std::uint32_t sign = (h >> 15) & 0x1u;
    const std::uint32_t exp  = (h >> 10) & 0x1Fu;
    const std::uint32_t mant = h & 0x3FFu;
    std::uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            // signed zero
            f = sign << 31;
        } else {
            // subnormal: normalize
            int e = -1;
            std::uint32_t m = mant;
            do { e++; m <<= 1; } while ((m & 0x400u) == 0);
            const std::uint32_t f_exp  = (127 - 15 - e) << 23;
            const std::uint32_t f_mant = (m & 0x3FFu) << 13;
            f = (sign << 31) | f_exp | f_mant;
        }
    } else if (exp == 0x1F) {
        // inf/NaN
        f = (sign << 31) | (0xFFu << 23) | (mant << 13);
    } else {
        // normal
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float out;
    std::memcpy(&out, &f, sizeof(out));
    return out;
}

// Read player's primary 3D root for BipedAnim weapon walk. There are two
// candidate slots on Actor:
//
//   path_a = *(*(player + 0xF0) + 8)        ← preferred ("template 3D")
//   path_b = *(player + 0xB78)              ← REFR.loaded3D
//
// In practice (FO4 1.11.191 next-gen), path_b is empty for the local
// PlayerCharacter — the populated body subtree (98 nodes including
// "Weapon" attach point) lives at path_a. The pose-tx walker
// (scene_inject.cpp::seh_read_player_3d_paths) has been logging
//   "path A=98 nodes, path B=0 nodes (using A)"
// for weeks. We mirror that behaviour: try path_a first, fall back to
// path_b if path_a is unavailable (very rare on the local player).
//
// Both reads SEH-cage in case any pointer in the chain is invalid.
void* seh_read_player_loaded3d(std::uintptr_t module_base) {
    void* player = nullptr;
    __try {
        player = *reinterpret_cast<void**>(
            module_base + fw::offsets::PLAYER_SINGLETON_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    if (!player) return nullptr;

    // path_a: *(*(player + 0xF0) + 8). This is the slot the engine fills
    // for the player's BipedAnim weapon-tree-bearing 3D.
    void* path_a = nullptr;
    __try {
        char* pb = reinterpret_cast<char*>(player);
        void* f0 = *reinterpret_cast<void**>(pb + 0xF0);
        if (f0) {
            path_a = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(f0) + 8);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        path_a = nullptr;
    }
    if (path_a) return path_a;

    // path_b fallback: *(player + 0xB78) = REFR.loaded3D. Used by
    // ghost_attach_weapon for ghost player layouts. Empty for local
    // PlayerCharacter in practice but try it anyway as a safety net.
    __try {
        return *reinterpret_cast<void**>(
            reinterpret_cast<char*>(player) + REFR_LOADED_3D_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// ----------------------------------------------------------------------------
// Tree helpers
// ----------------------------------------------------------------------------

// Find the first descendant of `root` whose name matches one of the
// candidate strings. Depth-first, max_depth bound, SEH-safe per-node.
// Returns nullptr if none found.
//
// Telemetry counters (passed by reference so caller can log a single
// summary instead of spammy per-node log inside the walk).
struct WalkStats {
    std::size_t visited = 0;
    std::size_t named = 0;
    std::size_t max_depth_seen = 0;
    char first_few_names[256]{};  // null-terminated, ", "-joined
};
void append_telemetry_name(WalkStats& s, const char* name) {
    if (!name || !name[0]) return;
    if (s.named >= 10) return; // only first 10 to bound log size
    const std::size_t cur = std::strlen(s.first_few_names);
    const std::size_t need = std::strlen(name) + 2; // ", " + name
    if (cur + need >= sizeof(s.first_few_names)) return;
    if (cur > 0) {
        std::strcat(s.first_few_names, ", ");
    }
    std::strcat(s.first_few_names, name);
}

void* find_node_by_candidate_names(void* root,
                                   const char* const* candidates,
                                   std::size_t n_candidates,
                                   WalkStats& stats,
                                   int depth = 0,
                                   int max_depth = 32) {
    if (!root || depth > max_depth) return nullptr;
    ++stats.visited;
    if (static_cast<std::size_t>(depth) > stats.max_depth_seen) {
        stats.max_depth_seen = static_cast<std::size_t>(depth);
    }

    char name[128];
    if (seh_read_node_name(root, name, sizeof(name)) && name[0]) {
        ++stats.named;
        append_telemetry_name(stats, name);
        for (std::size_t i = 0; i < n_candidates; ++i) {
            if (std::strcmp(name, candidates[i]) == 0) {
                return root;
            }
        }
    }

    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children(root, kids, count)) return nullptr;
    if (!kids || count == 0 || count > 256) return nullptr;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_index_child(kids, i);
        if (!k) continue;
        void* hit = find_node_by_candidate_names(
            k, candidates, n_candidates, stats, depth + 1, max_depth);
        if (hit) return hit;
    }
    return nullptr;
}

// Walk `subtree`, populating `mods` with every cache-hit found at depth
// >= 1 (i.e. excluding `subtree` itself). For each cache hit we record
// path + parent name + local transform. Cap on mods to MAX_MODS to bound
// pathological growth.
constexpr std::size_t MAX_MODS = 32;

void walk_collect_mods(void* node,
                       int depth,
                       int max_depth,
                       std::vector<ModDescriptor>& mods) {
    if (!node || depth > max_depth) return;
    if (mods.size() >= MAX_MODS) return;

    // Diagnostic dump: log every visited node's name + cache status so we
    // can see the full weapon subtree shape. Cap at 50 lines per snapshot
    // by checking mods.size() (gross approximation, fine for diag).
    if (depth >= 1) {
        char dbg_name[128] = "";
        const bool dbg_named = seh_read_node_name(node, dbg_name,
                                                    sizeof(dbg_name));
        const std::string dbg_cache = nif_path_cache::lookup(node);
        FW_DBG("[witness]   walk d=%d node=%p name='%s' cache='%s'",
               depth, node,
               dbg_named ? dbg_name : "<unnamed>",
               dbg_cache.empty() ? "" : dbg_cache.c_str());
    }

    // Identify a "mod" candidate. Two strategies:
    //   (A) Cache hit on nif_path_cache — best, gives us real .nif path.
    //   (B) Named NiNode/BSFadeNode that isn't the root and isn't a
    //       skeleton bone — engine-attached mod NIFs typically retain
    //       their file basename as m_name. Bone names follow strict
    //       conventions (Pelvis, SPINE1, ..., RArm_Hand). Anything else
    //       is a candidate mod attachment.
    // Strategy (B) is a fallback for when the cache misses (pre-loaded
    // NIFs that didn't go through sub_1417B3E90).
    if (depth >= 1) {
        const std::string path = nif_path_cache::lookup(node);
        char node_name[128] = "";
        const bool is_named = seh_read_node_name(node, node_name,
                                                   sizeof(node_name));
        const bool has_path = !path.empty();
        const bool name_looks_like_modroot =
            is_named && node_name[0] && !path.empty();

        // Skip nodes that are clearly skeleton bones (start with common
        // bone prefixes). This prevents our walk from emitting bone
        // entries when we're actually walking through the player skel.
        bool is_likely_bone = false;
        if (is_named && node_name[0]) {
            // FO4 bone naming: prefixes Bip01_*, *_skin, SPINE*, COM*,
            // *Arm*, *Leg*, RArm_*, LArm_*, RLeg_*, LLeg_*, Pelvis,
            // Chest*, Neck*, Head*, Pipboy*. These never represent
            // mod attachments.
            static const char* kBonePrefixes[] = {
                "Bip01", "SPINE", "COM", "Pelvis", "Chest",
                "Neck", "Head", "RArm_", "LArm_", "RLeg_", "LLeg_",
                "Pipboy", "WeaponExtra", "WeaponBolt", "P-Barrel",
                "10mmTrigger", "AnimObj", "Root", "skeleton",
                "Camera", "Hair", "Eye"
            };
            for (const char* pref : kBonePrefixes) {
                const std::size_t plen = std::strlen(pref);
                if (std::strncmp(node_name, pref, plen) == 0) {
                    is_likely_bone = true;
                    break;
                }
            }
            // Anything ending in "_skin" is a skin anchor, not a mod
            const std::size_t nlen = std::strlen(node_name);
            if (nlen >= 5 &&
                std::strcmp(node_name + nlen - 5, "_skin") == 0) {
                is_likely_bone = true;
            }
        }

        if ((has_path || name_looks_like_modroot) && !is_likely_bone) {
            ModDescriptor d{};
            // Use cache path if we have it, otherwise use the node's
            // own name. Receiver-side resolves base via form_id, so
            // anything we emit here is meant for mod-NIF attachment.
            d.nif_path = has_path ? path : std::string(node_name);

            // Parent name from node->parent->m_name. The scene graph
            // wires this during attach_child_direct.
            void* parent = seh_read_parent(node);
            if (parent) {
                char pname[128];
                if (seh_read_node_name(parent, pname, sizeof(pname))) {
                    d.parent_node_name.assign(pname);
                }
            }

            // Local transform (16 floats from node+0x30).
            float xf[16];
            if (seh_read_local_transform(node, xf)) {
                std::memcpy(d.local_transform, xf, sizeof(d.local_transform));
            } else {
                // Identity rotation, zero translate, scale=1 fallback.
                std::memset(d.local_transform, 0, sizeof(d.local_transform));
                d.local_transform[0]  = 1.0f; // rot[0][0]
                d.local_transform[5]  = 1.0f; // rot[1][1]
                d.local_transform[10] = 1.0f; // rot[2][2]
                d.local_transform[15] = 1.0f; // scale (last float of NiTransform)
            }

            mods.emplace_back(std::move(d));
            if (mods.size() >= MAX_MODS) {
                FW_WRN("[witness] reached MAX_MODS=%zu — truncating walk",
                       MAX_MODS);
                return;
            }
        }
    }

    // Recurse into children regardless of cache-hit status (mods can
    // attach deep — e.g. a scope on a barrel mod).
    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children(node, kids, count)) return;
    if (!kids || count == 0 || count > 256) return;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_index_child(kids, i);
        if (!k) continue;
        walk_collect_mods(k, depth + 1, max_depth, mods);
    }
}

} // namespace

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

Snapshot snapshot_local_player_weapon() {
    Snapshot snap;

    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (!game) {
        FW_DBG("[witness] no Fallout4.exe handle — empty snapshot");
        return snap;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(game);

    void* loaded3d = seh_read_player_loaded3d(base);
    if (!loaded3d) {
        FW_DBG("[witness] player loaded3D null — empty snapshot");
        return snap;
    }

    // Find the weapon attach node. Same priority as scene_inject's
    // find_weapon_attach_node, but we walk the LOCAL PLAYER's tree (not
    // the cached ghost skel).
    static const char* kCandidates[] = {
        "WEAPON", "Weapon", "WeaponBone", "RArm_Hand"
    };
    WalkStats stats;
    void* attach_node = find_node_by_candidate_names(
        loaded3d, kCandidates,
        sizeof(kCandidates) / sizeof(kCandidates[0]), stats);
    if (!attach_node) {
        FW_LOG("[witness] no WEAPON/Weapon/WeaponBone/RArm_Hand under "
               "player loaded3D=%p — empty snapshot "
               "(visited=%zu named=%zu max_depth=%zu first_names=[%s])",
               loaded3d, stats.visited, stats.named, stats.max_depth_seen,
               stats.first_few_names);
        return snap;
    }
    FW_LOG("[witness] found attach_node=%p (visited=%zu named=%zu "
           "max_depth=%zu)",
           attach_node, stats.visited, stats.named, stats.max_depth_seen);

    // Identify the BASE weapon node: it's the FIRST cache-hit found among
    // attach_node's children. (Mods can ALSO be cache hits, but they are
    // descendants of the base, never direct children of the attach bone.)
    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children(attach_node, kids, count)) {
        FW_DBG("[witness] attach_node=%p children read failed — empty snapshot",
               attach_node);
        return snap;
    }
    if (!kids || count == 0) {
        FW_DBG("[witness] attach_node=%p has 0 children — no weapon equipped",
               attach_node);
        return snap;
    }

    // Dump all attach_node children with names + cache status to diagnose
    // what the engine actually attached. Useful especially when the cache
    // misses (engine preloads many NIFs via BSResource without going
    // through sub_1417B3E90 — e.g. weapons loaded as part of cell init
    // are never seen by the detour). The NIF root NiNode usually carries
    // the source file name as its m_name (BSFadeNode wraps it during
    // load), so reading the name directly is a reliable fallback.
    void* base_weapon_root = nullptr;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_index_child(kids, i);
        if (!k) continue;

        char child_name[128];
        const bool has_name = seh_read_node_name(k, child_name,
                                                  sizeof(child_name));
        const std::string cache_path = nif_path_cache::lookup(k);
        FW_LOG("[witness]   attach_node child[%u]=%p name='%s' "
               "cache_path='%s'",
               static_cast<unsigned>(i), k,
               has_name ? child_name : "<unnamed>",
               cache_path.empty() ? "<NOT IN CACHE>" : cache_path.c_str());

        // Prefer cache hit; fall back to anything with a meaningful name
        // (the first non-empty named child is almost always the weapon).
        if (!cache_path.empty()) {
            base_weapon_root = k;
            snap.base_nif_path = cache_path;
            break;
        }
        if (!base_weapon_root && has_name && child_name[0]) {
            base_weapon_root = k;
            // Name-as-path: store the bare name since we don't have a
            // real file path. Receiver will fall back to form_id resolve
            // for the base; the witness extraction still works for mods.
            snap.base_nif_path = child_name;
        }
    }

    if (!base_weapon_root) {
        // No usable child at all — no weapon equipped or attach point
        // empty. Bail with empty snapshot.
        FW_LOG("[witness] no usable child under attach_node=%p "
               "(child[0..%u] all unnamed and not in cache) — empty snapshot",
               attach_node, static_cast<unsigned>(count));
        return snap;
    }

    // Record where the base hangs off (parent name).
    char base_parent_name[128];
    if (seh_read_node_name(attach_node, base_parent_name,
                           sizeof(base_parent_name))) {
        snap.base_parent_name.assign(base_parent_name);
    }

    // Walk descendants of the base weapon root, collecting mods.
    walk_collect_mods(base_weapon_root, /*depth=*/0,
                      /*max_depth=*/16, snap.mods);

    return snap;
}

void log_snapshot(const Snapshot& s, const char* tag) {
    if (s.base_nif_path.empty()) {
        FW_LOG("%s snapshot EMPTY (no base weapon found)", tag);
        return;
    }
    FW_LOG("%s base='%s' parent='%s' mods=%zu",
           tag,
           s.base_nif_path.c_str(),
           s.base_parent_name.c_str(),
           s.mods.size());
    for (std::size_t i = 0; i < s.mods.size(); ++i) {
        const auto& m = s.mods[i];
        // Show translate (last 4 floats of m_kLocal: indices 12..14
        // are the translate vec3 inside NiTransform; index 15 is scale).
        FW_LOG("%s   mod[%zu] parent='%s' path='%s' "
               "trans=(%.2f,%.2f,%.2f) scale=%.3f",
               tag, i,
               m.parent_node_name.c_str(),
               m.nif_path.c_str(),
               m.local_transform[12],
               m.local_transform[13],
               m.local_transform[14],
               m.local_transform[15]);
    }
}

// ============================================================================
// PATH B — raw mesh extraction (M9.w4 step 2)
// ============================================================================
//
// For each BSGeometry (BSTriShape) leaf the walker discovers under the
// weapon root, extract:
//   - m_name             (e.g. "10mmHeavyPortedBarrel002:0")
//   - parent placeholder name  (the immediate parent NiNode name)
//   - bgsm material path (from BSLightingShaderProperty +0x10)
//   - vert_count, tri_count
//   - per-vertex positions (3 floats each, full precision)
//   - per-triangle indices (3 u16 each)
//   - local_transform (16 floats from node+0x30)
//
// All copied into heap-owned arrays so the engine's buffers are not
// touched after the call. SEH-protected per-leaf so a single corrupt
// shape doesn't poison the whole snapshot.

namespace {

// === LEGACY decoder (kept for reference; new path below) ===
//
// Decode the BSPositionData packed buffer's vertex/index streams into
// the ExtractedMesh's heap-owned arrays. Returns true on full success.
//
// Layout (from iter 11 dossier — verified by direct decomp):
//   packed[0          .. 6*vc)              packed half-prec POSITIONS
//   packed[6*vc       .. 12*vc)             packed half-prec NORMALS
//   packed[12*vc      .. 12*vc + 2*ic)      u16 INDICES
// where vc = vert_count, ic = idx_count = 3 * tri_count.
bool decode_packed_to_mesh(const BSGeoHeader& geo,
                            const BSPosDataHeader& pd,
                            ExtractedMesh& m) {
    const std::uint16_t vc = geo.vert_count;
    const std::uint32_t tc = geo.tri_count;
    const std::uint32_t ic = 3u * tc;
    if (vc == 0 || tc == 0) return false;

    m.vert_count = vc;
    m.tri_count  = tc;

    // -- Indices -------------------------------------------------------
    // Always read from packed_buffer at byte offset 12*vc.
    if (!pd.packed_buffer) return false;
    const std::size_t idx_byte_off  = static_cast<std::size_t>(12) * vc;
    const std::size_t idx_byte_size = static_cast<std::size_t>(2) * ic;
    // Sanity: packed_size_u16 must accommodate this region.
    const std::size_t packed_total_bytes =
        static_cast<std::size_t>(pd.packed_size_u16) * 2u;
    if (idx_byte_off + idx_byte_size > packed_total_bytes) {
        FW_WRN("[mesh-witness] packed buffer too small: need %zuB at "
               "offset %zu but only %zuB total (vc=%u tc=%u)",
               idx_byte_size, idx_byte_off, packed_total_bytes,
               static_cast<unsigned>(vc), tc);
        return false;
    }

    m.indices.resize(ic);
    const std::uint8_t* indices_src =
        reinterpret_cast<const std::uint8_t*>(pd.packed_buffer)
        + idx_byte_off;

    // Diagnostic: dump pos_data header values + try a 1-byte probe at
    // both packed_buffer[0] and packed_buffer[idx_byte_off-1] before the
    // big memcpy. If the probe AVs at offset 0 → packed_buffer ptr itself
    // is invalid. If probe at idx_byte_off-1 AVs but [0] works → buffer
    // is shorter than expected.
    std::uint8_t probe_first = 0xAA, probe_idx_minus1 = 0xAA;
    bool ok_first = seh_memcpy_from_engine(
        &probe_first, pd.packed_buffer, 1);
    bool ok_idx = false;
    if (ok_first && idx_byte_off > 0) {
        ok_idx = seh_memcpy_from_engine(
            &probe_idx_minus1,
            reinterpret_cast<const std::uint8_t*>(pd.packed_buffer)
                + (idx_byte_off - 1),
            1);
    }

    if (!seh_memcpy_from_engine(m.indices.data(), indices_src,
                                  idx_byte_size)) {
        FW_WRN("[mesh-witness] SEH copying indices vc=%u tc=%u "
               "pos_data=%p packed=%p packed_size_u16=%u flag=%u "
               "full_prec=%p probe_first(ok=%d val=0x%02X) "
               "probe_idx-1(ok=%d val=0x%02X) idx_off=%zu idx_size=%zu",
               static_cast<unsigned>(vc), tc,
               geo.pos_data, pd.packed_buffer,
               pd.packed_size_u16, pd.flag, pd.full_prec_pos,
               int(ok_first), unsigned(probe_first),
               int(ok_idx), unsigned(probe_idx_minus1),
               idx_byte_off, idx_byte_size);
        m.indices.clear();
        return false;
    }

    // -- Positions -----------------------------------------------------
    // Prefer the engine's full-precision positions (12*vc bytes) if
    // available. Otherwise, decode the half-prec stream from packed[0].
    m.positions.resize(static_cast<std::size_t>(3) * vc);
    if (pd.full_prec_pos) {
        const std::size_t fp_size = static_cast<std::size_t>(12) * vc;
        if (!seh_memcpy_from_engine(m.positions.data(), pd.full_prec_pos,
                                      fp_size)) {
            FW_WRN("[mesh-witness] SEH copying full-prec positions; "
                   "falling back to half-prec decode");
            // Fall through to half-prec path below.
        } else {
            return true; // full-prec path complete
        }
    }

    // Half-prec fallback: read 6*vc bytes from packed[0] and decode each
    // half float into m.positions.
    const std::size_t hp_size = static_cast<std::size_t>(6) * vc;
    std::vector<std::uint16_t> half_buf(static_cast<std::size_t>(3) * vc);
    if (!seh_memcpy_from_engine(half_buf.data(), pd.packed_buffer, hp_size)) {
        FW_WRN("[mesh-witness] SEH copying half-prec positions vc=%u",
               static_cast<unsigned>(vc));
        m.positions.clear();
        return false;
    }
    for (std::size_t i = 0; i < half_buf.size(); ++i) {
        m.positions[i] = half_to_float(half_buf[i]);
    }
    return true;
}

// Try to extract one BSGeometry leaf into the given ExtractedMesh.
// Returns true on success, false if any read fails (caller should skip
// this leaf).
//
// M9.w4 ITER 12 LAYOUT — 3-level indirection from clone+0x148:
//
//   clone+0x148  → BSGeometryStreamHelper (32 bytes from
//                  TLockingUserPool<32, BSGraphics::ResourceCacheAllocator>)
//     +0x00  u64 BSVertexDesc
//     +0x08  vstream_desc* (~80 byte BSStreamDesc)
//             +0x08  void*  raw_vertex_buffer
//             +0x30  u32    vbuf_size_bytes
//     +0x10  istream_desc* (~80 byte BSStreamDesc)
//             +0x08  u16*   raw_index_buffer
//             +0x30  u32    ibuf_size_bytes
//     +0x18  u32 refcount (1 source + N clones)
//
// On extraction, we deep-copy:
//   - tri_count (clone+0x160), vert_count (clone+0x164)
//   - raw vertex buffer (size = vbuf_size_bytes; format = packed per
//     BSVertexDesc — needs decode for positions)
//   - raw index buffer (u16 array, length = 3*tri_count)
//
// For initial deployment we extract RAW vertex bytes verbatim (no
// decode); a later iteration will decode positions using BSVertexDesc
// stream-offset nibbles. The receiver gets enough info to call the
// factory once the format mapping is settled.
bool extract_one_mesh(void* geom, ExtractedMesh& m) {
    if (!geom) return false;

    BSGeoHeader gh;
    if (!seh_read_bsgeo_header(geom, gh) || !gh.ok) return false;
    if (!gh.pos_data) return false;
    if (gh.vert_count == 0 || gh.tri_count == 0) return false;

    m.vert_count = gh.vert_count;
    m.tri_count  = gh.tri_count;
    const std::uint32_t idx_count = 3u * gh.tri_count;

    // Read the BSGeometryStreamHelper header at clone+0x148 via POD helper.
    void*         vstream_desc = nullptr;
    void*         istream_desc = nullptr;
    std::uint64_t vertex_desc  = 0;
    if (!seh_read_helper_struct(gh.pos_data, vertex_desc,
                                  vstream_desc, istream_desc)) {
        FW_DBG("[mesh-witness] SEH reading helper struct at %p",
               gh.pos_data);
        return false;
    }

    if (!vstream_desc || !istream_desc) {
        FW_DBG("[mesh-witness] helper has null vstream(%p) or istream(%p)",
               vstream_desc, istream_desc);
        return false;
    }

    // Read each BSStreamDesc via POD helper.
    void*         vbuf  = nullptr;
    void*         ibuf  = nullptr;
    std::uint32_t vsize = 0, isize = 0;
    if (!seh_read_stream_desc(vstream_desc, vbuf, vsize)) {
        FW_DBG("[mesh-witness] SEH reading vstream_desc");
        return false;
    }
    if (!seh_read_stream_desc(istream_desc, ibuf, isize)) {
        FW_DBG("[mesh-witness] SEH reading istream_desc");
        return false;
    }

    // Diagnostic: dump first 32 bytes of vbuf + ibuf via POD byte reader.
    auto hex32 = [](char* dst, std::size_t cap, const void* p) -> int {
        if (!p) { return std::snprintf(dst, cap, "<null>"); }
        int w = 0;
        for (int k = 0; k < 32 && w < (int)cap - 4; ++k) {
            std::uint8_t byte = 0;
            seh_read_byte(reinterpret_cast<const std::uint8_t*>(p) + k, byte);
            w += std::snprintf(dst + w, cap - w, "%02X ", byte);
        }
        return w;
    };
    char vhex[256], ihex[256];
    hex32(vhex, sizeof(vhex), vbuf);
    hex32(ihex, sizeof(ihex), ibuf);
    FW_LOG("[mesh-witness] helper=%p vstream=%p ibuf=%p "
           "vd=0x%016llX vsize=%u isize=%u "
           "vc=%u tc=%u",
           gh.pos_data, vstream_desc, ibuf,
           static_cast<unsigned long long>(vertex_desc),
           vsize, isize,
           static_cast<unsigned>(gh.vert_count), gh.tri_count);
    FW_LOG("[mesh-witness]   vbuf[0..32]: %s", vhex);
    FW_LOG("[mesh-witness]   ibuf[0..32]: %s", ihex);

    // Sanity: index buffer size must accommodate 3 * tri_count u16s,
    // padded to multiple of 4 bytes.
    const std::uint32_t expected_isize_aligned =
        ((idx_count * 2u) + 3u) & 0xFFFFFFFCu;
    if (isize < expected_isize_aligned) {
        FW_WRN("[mesh-witness] index buffer too small: have %u need %u",
               isize, expected_isize_aligned);
        return false;
    }

    // Copy raw indices.
    m.indices.resize(idx_count);
    if (!seh_memcpy_from_engine(m.indices.data(), ibuf,
                                  std::size_t(idx_count) * 2u)) {
        FW_WRN("[mesh-witness] SEH copying indices ic=%u from %p",
               idx_count, ibuf);
        m.indices.clear();
        return false;
    }

    // Decode positions from packed vertex stream.
    //
    // BSVertexDesc nibble encoding (from sub_14182DFC0 packer disasm,
    // iter11 log lines 660-700):
    //   bits 0..3   = stride / 4   (the low nibble of the desc)
    //   bits 4..9   = stream-1 offset / 4 (UV typically, set via v99<<6)
    //   bits 10..13 = stream-2 offset / 4
    //   ...
    //   bits 32..47 = flag bitmap (stream presence)
    //
    // Live evidence: vd=0x0001B00000430205 has low nibble 5 → stride 20.
    // Observed vsize/vc ≈ 20 bytes/vertex confirms.
    //
    // POSITIONS are at offset 0 of each vertex, encoded as 3 half-floats
    // (3 × 2 = 6 bytes). The remaining (stride − 6) bytes per vertex are
    // packed normals, UVs, etc. — we ignore them for the witness pattern
    // (receiver can rebuild defaults via the factory).
    if (vsize == 0 || !vbuf) {
        FW_WRN("[mesh-witness] vbuf null or zero-size (vbuf=%p vsize=%u)",
               vbuf, vsize);
        m.indices.clear();
        return false;
    }

    const std::uint32_t stride =
        static_cast<std::uint32_t>(vertex_desc & 0xFu) * 4u;
    if (stride == 0 || stride > 64) {
        FW_WRN("[mesh-witness] implausible stride %u from vd=0x%016llX",
               stride,
               static_cast<unsigned long long>(vertex_desc));
        m.indices.clear();
        return false;
    }
    if (static_cast<std::size_t>(stride) * gh.vert_count > vsize) {
        FW_WRN("[mesh-witness] stride*vc > vsize: %u*%u=%u > %u",
               stride, gh.vert_count,
               stride * gh.vert_count, vsize);
        m.indices.clear();
        return false;
    }

    // Copy the raw vertex bytes once, then decode positions from the
    // local copy (avoids per-vertex SEH overhead).
    std::vector<std::uint8_t> vbytes(stride * gh.vert_count);
    if (!seh_memcpy_from_engine(vbytes.data(), vbuf, vbytes.size())) {
        FW_WRN("[mesh-witness] SEH copying vbuf %zuB from %p",
               vbytes.size(), vbuf);
        m.indices.clear();
        return false;
    }

    // Decode 3 half-floats per vertex at offset 0 → m.positions[3i, 3i+1, 3i+2]
    m.positions.resize(static_cast<std::size_t>(3) * gh.vert_count);
    for (std::uint16_t i = 0; i < gh.vert_count; ++i) {
        const std::uint8_t* v = vbytes.data() + i * stride;
        std::uint16_t hx, hy, hz;
        std::memcpy(&hx, v + 0, 2);
        std::memcpy(&hy, v + 2, 2);
        std::memcpy(&hz, v + 4, 2);
        m.positions[3*i + 0] = half_to_float(hx);
        m.positions[3*i + 1] = half_to_float(hy);
        m.positions[3*i + 2] = half_to_float(hz);
    }

    // Local transform (16 floats from node +0x30).
    float xf[16];
    if (seh_read_local_transform(geom, xf)) {
        std::memcpy(m.local_transform, xf, sizeof(m.local_transform));
    } else {
        // Identity fallback.
        std::memset(m.local_transform, 0, sizeof(m.local_transform));
        m.local_transform[0]  = 1.0f;
        m.local_transform[5]  = 1.0f;
        m.local_transform[10] = 1.0f;
        m.local_transform[15] = 1.0f;
    }

    // m_name from the geometry leaf (e.g. "10mmHeavyPortedBarrel002:0").
    char buf[128];
    if (seh_read_node_name(geom, buf, sizeof(buf))) {
        m.m_name.assign(buf);
    }

    // Parent placeholder name (NiAVObject +0x28 → parent NiNode → m_name).
    void* parent = seh_read_parent(geom);
    if (parent) {
        if (seh_read_node_name(parent, buf, sizeof(buf))) {
            m.parent_placeholder.assign(buf);
        }
    }

    // bgsm path from BSLightingShaderProperty +0x10 (same NiObjectNET
    // pool layout). The pink-body solution dossier confirms this offset
    // for body materials; iter 11 confirmed weapons use the same layout.
    if (gh.shader_prop) {
        if (seh_read_node_name(gh.shader_prop, buf, sizeof(buf))) {
            m.bgsm_path.assign(buf);
        }
    }

    return true;
}

// Recursive walk: for each BSGeometry-derived leaf, extract its mesh
// data and append to `out`. Critical: we MUST filter by vtable RVA
// before reading +0x148/+0x160/+0x164 — NiNode is only 0x140 bytes, so
// reading at +0x148 on a NiNode yields heap garbage (in iter 11 first
// run we observed bogus "tc=1835626049" from this exact mistake).
constexpr std::size_t MESH_HARD_CAP = 64;
constexpr int         MESH_MAX_DEPTH = 16;

void walk_collect_meshes(void* node,
                         int depth,
                         std::uintptr_t module_base,
                         std::vector<ExtractedMesh>& out) {
    if (!node || depth > MESH_MAX_DEPTH) return;
    if (out.size() >= MESH_HARD_CAP) return;

    const std::uintptr_t vt_rva = seh_read_vtable_rva(node, module_base);

    // Only attempt extraction if vtable is BSGeometry-derived. NiNode and
    // other base-class instances DO NOT have the +0x148 layout; reading
    // there gives heap garbage.
    if (is_bsgeometry_derived(vt_rva)) {
        BSGeoHeader gh;
        if (seh_read_bsgeo_header(node, gh) && gh.ok && gh.pos_data
            && gh.vert_count > 0 && gh.tri_count > 0
            && gh.tri_count < 0x100000u) { // sanity ceiling: 1M tris

            // === Path B-alt-2 diag: log allocator caller RIP for this leaf.
            // If the BSTriShape was allocated via sub_1416579C0 with size
            // 0x170/0x190, we have the RIP of whoever invoked the
            // allocator → that's the parser/factory that built this shape.
            const auto* atrace = ni_alloc_tracker::lookup(node);
            const std::uintptr_t caller_rva =
                atrace ? ni_alloc_tracker::caller_rva(atrace) : 0;
            FW_LOG("[alloc-trace] geom=%p vt_rva=0x%llX vc=%u tc=%u "
                   "alloc_size=0x%zX caller_rva=0x%llX",
                   node,
                   static_cast<unsigned long long>(vt_rva),
                   static_cast<unsigned>(gh.vert_count),
                   gh.tri_count,
                   atrace ? atrace->size : 0,
                   static_cast<unsigned long long>(caller_rva));

            ExtractedMesh m;
            if (extract_one_mesh(node, m)) {
                out.emplace_back(std::move(m));
                if (out.size() >= MESH_HARD_CAP) {
                    FW_WRN("[mesh-witness] reached cap %zu — truncating walk",
                           MESH_HARD_CAP);
                    return;
                }
            }
        }
        // BSGeometry leaves typically have no children. They INHERIT
        // the NiNode children fields layout-wise but the count/ptr
        // are usually zero/null. We still recurse to be safe — it's
        // O(0) work in the common case.
    }

    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children(node, kids, count)) return;
    if (!kids || count == 0 || count > 256) return;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_index_child(kids, i);
        if (!k) continue;
        walk_collect_meshes(k, depth + 1, module_base, out);
    }
}

// Compute simple position-bbox + indices XOR checksum for diagnostic logging.
// Doesn't modify mesh; const reference + local accumulators.
void mesh_stats(const ExtractedMesh& m,
                float bbox_min[3], float bbox_max[3],
                std::uint32_t& idx_xor) {
    bbox_min[0] = bbox_min[1] = bbox_min[2] =  1e30f;
    bbox_max[0] = bbox_max[1] = bbox_max[2] = -1e30f;
    for (std::uint16_t i = 0; i < m.vert_count; ++i) {
        const float x = m.positions[3*i + 0];
        const float y = m.positions[3*i + 1];
        const float z = m.positions[3*i + 2];
        if (x < bbox_min[0]) bbox_min[0] = x;
        if (y < bbox_min[1]) bbox_min[1] = y;
        if (z < bbox_min[2]) bbox_min[2] = z;
        if (x > bbox_max[0]) bbox_max[0] = x;
        if (y > bbox_max[1]) bbox_max[1] = y;
        if (z > bbox_max[2]) bbox_max[2] = z;
    }
    idx_xor = 0;
    for (auto v : m.indices) idx_xor ^= static_cast<std::uint32_t>(v);
}

} // namespace

MeshSnapshot snapshot_player_weapon_meshes() {
    MeshSnapshot snap;

    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (!game) {
        FW_DBG("[mesh-witness] no Fallout4.exe handle");
        return snap;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(game);

    void* loaded3d = seh_read_player_loaded3d(base);
    if (!loaded3d) {
        FW_DBG("[mesh-witness] player loaded3D null");
        return snap;
    }

    static const char* kCandidates[] = {
        "WEAPON", "Weapon", "WeaponBone", "RArm_Hand"
    };
    WalkStats stats;
    void* attach_node = find_node_by_candidate_names(
        loaded3d, kCandidates,
        sizeof(kCandidates) / sizeof(kCandidates[0]), stats);
    if (!attach_node) {
        FW_LOG("[mesh-witness] no WEAPON/Weapon/WeaponBone/RArm_Hand under "
               "loaded3D=%p (visited=%zu named=%zu first=[%s])",
               loaded3d, stats.visited, stats.named, stats.first_few_names);
        return snap;
    }

    // Bone name where the weapon attaches.
    char bone_name[128];
    if (seh_read_node_name(attach_node, bone_name, sizeof(bone_name))) {
        snap.attach_bone_name.assign(bone_name);
    }

    // Find the weapon root (first child of attach_node that has a name —
    // typically the BSFadeNode wrapper named "Weapon  (00004822)" or
    // similar). We don't strictly need its name for extraction, but we
    // capture it for diagnostic identification.
    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children(attach_node, kids, count)) {
        FW_DBG("[mesh-witness] attach_node has no children");
        return snap;
    }
    void* weapon_root = nullptr;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_index_child(kids, i);
        if (!k) continue;
        char wname[128];
        if (seh_read_node_name(k, wname, sizeof(wname)) && wname[0]) {
            weapon_root = k;
            snap.weapon_root_name.assign(wname);
            break;
        }
    }
    if (!weapon_root) {
        FW_DBG("[mesh-witness] no named child under attach_node");
        return snap;
    }

    // Recurse the weapon subtree, collecting every BSGeometry leaf.
    walk_collect_meshes(weapon_root, /*depth=*/0, base, snap.meshes);
    return snap;
}

void log_mesh_snapshot(const MeshSnapshot& s, const char* tag) {
    if (s.meshes.empty()) {
        FW_LOG("%s EMPTY (no meshes captured) weapon='%s' bone='%s'",
               tag, s.weapon_root_name.c_str(),
               s.attach_bone_name.c_str());
        return;
    }
    FW_LOG("%s weapon='%s' bone='%s' meshes=%zu",
           tag, s.weapon_root_name.c_str(),
           s.attach_bone_name.c_str(), s.meshes.size());
    for (std::size_t i = 0; i < s.meshes.size(); ++i) {
        const auto& m = s.meshes[i];
        float bmin[3], bmax[3]; std::uint32_t xor_idx = 0;
        mesh_stats(m, bmin, bmax, xor_idx);
        FW_LOG("%s   [%zu] '%s' parent='%s' bgsm='%s' vc=%u tc=%u "
               "bbox=(%.1f,%.1f,%.1f)..(%.1f,%.1f,%.1f) idx_xor=0x%X",
               tag, i,
               m.m_name.c_str(),
               m.parent_placeholder.c_str(),
               m.bgsm_path.c_str(),
               static_cast<unsigned>(m.vert_count),
               m.tri_count,
               bmin[0], bmin[1], bmin[2],
               bmax[0], bmax[1], bmax[2],
               xor_idx);
    }
}

} // namespace fw::native::weapon_witness
