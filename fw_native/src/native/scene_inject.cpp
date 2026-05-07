// Strada B — M1 scene graph injection implementation.
//
// Flow (dossier §11):
//   1. Resolve base + function pointers from RVAs
//   2. Verify SSN singleton non-null (skip if loading screen)
//   3. Ensure memory pool initialized
//   4. Alloc NiNode (0x140 bytes, 16-aligned) via engine allocator
//   5. In-place ctor (sub_1416BDFE0)
//   6. Set name "fw_debug_cube" via NiFixedString API
//   7. Write local.translate at +0x54
//   8. OR kIsMovable (0x800) into flags at +0x108
//   9. Increment our refcount BEFORE attach (prevents free-before-attach;
//      AttachChild does its own +1 then undoes both temp refs)
//  10. Call SSN->AttachChild(cube, reuseFirstEmpty=true) via vtable[58]
//
// Everything wrapped in SEH __try/__except — first live call is high-risk
// (unknown interactions with engine state), we log and bail on AV rather
// than taking the whole process down.

#include "scene_inject.h"
#include "ni_offsets.h"
#include "scene_walker.h"
#include "skin_rebind.h"
#include "weapon_witness.h"  // read_parent_pub for detach-via-parent helper
#include "synthetic_refr.h"  // M9 closure (2026-05-07): synthetic REFR weapon assembly

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <string>
#include <thread>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../net/client.h"
#include "../offsets.h"   // M9 wedge 2: TESObjectARMO/ARMA + lookup_by_form_id RVAs

namespace fw::native {

// Forward declaration: bone_copy ns is defined later in this TU but
// populate_canonical_from_skel_native (below) needs to call its walker.
namespace bone_copy {
    static void walk_player_nested(void* node, int depth,
                                   std::unordered_map<std::string, void*>& out);
}

// M8P3.15 — canonical JOINT list cached at ghost-body inject. Both
// sender (on_bone_tick_message) and receiver (on_pose_apply_message)
// reference this list. Populated from the GHOST skel.nif tree, with
// "_skin"-suffixed nodes (skin anchors) excluded — only true joints
// are replicated. Engine UpdateWorldData propagates joint rotations
// down to skin anchors via parent-chain hierarchy.
//
// Defined at fw::native:: scope (NOT anon ns) so inject_body_nif
// (first anon ns) and the pose handlers (later anon ns) can both
// reference the same symbols.
static std::mutex                g_canonical_mutex;
static std::vector<std::string>  g_canonical_names;   // size == joint count
static std::vector<void*>        g_ghost_bone_ptrs;   // parallel: skel joint[i]

// SEH-safe helpers (no C++ objects → no C2712 conflict). Each
// function isolates the __try block so callers can mix C++ objects
// freely.
static bool seh_read_bones_fb_meta(void* skin, void**& head, std::uint32_t& count) {
    head = nullptr; count = 0;
    if (!skin) return false;
    __try {
        char* sb = reinterpret_cast<char*>(skin);
        head  = *reinterpret_cast<void***>(sb + 0x10);
        count = *reinterpret_cast<std::uint32_t*>(sb + 0x20);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void* seh_read_bones_fb_entry(void** head, std::uint32_t i) {
    if (!head) return nullptr;
    __try { return head[i]; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static const char* seh_read_bone_name(void* node) {
    if (!node) return "";
    __try {
        const char* pool_entry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(node) + 0x10);
        if (!pool_entry) return "";
        return pool_entry + 0x18;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return ""; }
}

// Resolve both candidate player_3d paths (+0xF0+0x08 and +0xB78). NO C++
// objects in this function so __try is safe (C2712 avoidance).
// Returns true if PlayerSingleton was readable. path_a / path_b may
// individually be null (sparse/1P scenarios).
static bool seh_read_player_3d_paths(std::uintptr_t base,
                                     void*& path_a, void*& path_b) {
    path_a = nullptr; path_b = nullptr;
    void* player = nullptr;
    __try {
        player = *reinterpret_cast<void**>(base + PLAYER_SINGLETON_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!player) return false;
    __try {
        char* pb = reinterpret_cast<char*>(player);
        void* f0 = *reinterpret_cast<void**>(pb + 0xF0);
        if (f0) path_a = *reinterpret_cast<void**>(
            reinterpret_cast<char*>(f0) + 8);
        path_b = *reinterpret_cast<void**>(pb + REFR_LOADED_3D_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { /* one or both null */ }
    return true;
}

// Helper: name ends with "_skin" suffix?
static bool ends_with_skin(const char* s) {
    if (!s) return false;
    const std::size_t n = std::strlen(s);
    return n >= 5 && std::strcmp(s + n - 5, "_skin") == 0;
}
static bool ends_with_skin_str(const std::string& s) {
    return s.size() >= 5
        && s.compare(s.size() - 5, 5, "_skin") == 0;
}

// Cache canonical JOINT list from the GHOST skel.nif tree (NOT the
// body's bones_fb, which contains both joints AND skin anchors but is
// missing many intermediate joints). The skel.nif has every joint
// in its hierarchy (LArm_ForeArm1, LLeg_Thigh, etc.) so walking it
// gives the COMPLETE set of joints to animate.
//
// Architecture:
//   - We replicate JOINT m_kLocal rotations only.
//   - Engine UpdateWorldData propagates joint rotations to descendants
//     (including the body's _skin anchors which inherit via parent
//     chain in skel.nif).
//   - This avoids the "twisted mesh" bug where writing a joint's
//     parent-relative rotation directly to a skin anchor mismatches
//     the anchor's bind orientation.
static void populate_canonical_from_skel_native(void* skel_root) {
    if (!skel_root) {
        FW_WRN("[pose] populate_canonical: skel_root is null — skipped");
        return;
    }
    std::unordered_map<std::string, void*> all_nodes;
    bone_copy::walk_player_nested(skel_root, 0, all_nodes);

    // Filter: keep joints only (names not ending in "_skin"); skip empty.
    std::vector<std::pair<std::string, void*>> joints;
    joints.reserve(all_nodes.size());
    for (auto& kv : all_nodes) {
        const std::string& nm = kv.first;
        if (nm.empty()) continue;
        if (ends_with_skin_str(nm)) continue;
        joints.emplace_back(nm, kv.second);
    }
    std::sort(joints.begin(), joints.end(),
              [](const auto& a, const auto& b){ return a.first < b.first; });

    std::vector<std::string> nms; nms.reserve(joints.size());
    std::vector<void*>       ptrs; ptrs.reserve(joints.size());
    for (auto& jp : joints) {
        nms.push_back(jp.first);
        ptrs.push_back(jp.second);
    }
    const std::size_t kept = nms.size();
    {
        std::lock_guard<std::mutex> lk(g_canonical_mutex);
        g_canonical_names.swap(nms);
        g_ghost_bone_ptrs.swap(ptrs);
    }
    FW_LOG("[pose] canonical JOINT list cached from skel: %zu joints "
           "(skel total nodes=%zu, _skin anchors excluded)",
           kept, all_nodes.size());
}

// M9.5 — Forward declaration for clone_nif_subtree. Definition lives much
// further down (~line 2960) outside any anonymous namespace, so it can be
// called both from try_inject_body_nif and ghost_attach_armor without
// scope-shadow ambiguity.
void* clone_nif_subtree(void* source);

// 2026-05-06 LATE evening (M9 closure, PLAN B — NiStream serialization) —
// engine-native serialize/deserialize of any NiObject subtree to/from a
// byte buffer. Format = byte-identical to a .nif file on disk. RVAs +
// recipe verified by re/nistream_memory_serialize_AGENT.md (HIGH conf).
//
// SENDER:  init NiStream → AddTopLevelObject(root) → SaveToMemory(&buf, &size)
//          → ship buf over wire → free buf via BSScrapHeap.
// RECEIVER: init NiStream → LoadFromMemory(buf, size) → read root from
//          stream+864 → bump refcount → destroy stream → attach root.
//
// Returns true/non-null on success.
struct SerializedNif {
    void*       buf;   // BSScrapHeap-allocated. Caller must free via nistream_free.
    std::size_t size;
};
bool nistream_serialize_subtree(void* root, SerializedNif* out);
void* nistream_deserialize_subtree(const void* buf, std::size_t size);
void nistream_free(void* buf);

namespace {

// Function pointer types (all __fastcall on x64 Windows).
using AllocateFn       = void* (*)(void* pool, std::size_t size,
                                   std::uint32_t align, bool aligned_fb);
using PoolInitFn       = void  (*)(void* pool, std::uint32_t* flag);
using NiNodeCtorFn     = void* (*)(void* self, std::uint16_t capacity);
using BSDynamicCtorFn  = void* (*)(void* self);
using FixedStrCreateFn = void* (*)(std::uint64_t* out_handle, const char* s);
using FixedStrReleaseFn= void  (*)(std::uint64_t* handle);
using SetNameFn        = void  (*)(void* node, void* fixed_str);
using AttachChildFn    = void  (*)(void* parent, void* child,
                                   char reuseFirstEmpty);
using DetachChildFn    = void  (*)(void* parent, void* child, void** removed);
using SetAlphaPropFn   = void  (*)(void* geom, void* alpha_prop);  // M2.3
// UpdateDownwardPass — forces world transform recomputation from local
// transforms. Arg is pointer to a NiUpdateData struct (zeros OK).
using UpdateDownwardFn = void  (*)(void* node, void* update_data);

// M2.5 own-shader constructors (replace clone).
using BSEffectShaderCtorFn  = void* (*)(void* self);       // sub_14216F9C0
using BSEffectShaderSetupFn = void  (*)(void* self,
                                        void* arg2,
                                        std::uint32_t arg3);  // sub_142161B10
using NiAlphaPropInitFn     = void  (*)(void* self);       // sub_1416BD6F0
// Generic "attach/install geometry" for vt[42] of BSEffectShaderProperty.
using ShaderAttachGeomFn    = void  (*)(void* shader, void* geom);

// M3.3 BSLightingShaderProperty + texture DDS path.
using BSLSPNewFn        = void* (*)();                      // sub_142171050
using TexSetCtorFn      = void* (*)(void* self);            // sub_14216ED10
using TexSetSetPathFn   = void* (*)(void* self,
                                    int slot,
                                    const std::uint8_t* path); // sub_1421627B0
using BindMatTexSetFn   = void* (*)(void* material,
                                    void* shader_arg2,
                                    void* textureSet);      // sub_1421C6870
using MaterialCtorFn    = void* (*)(void* self);            // sub_1421C5CE0
// Texture load API — sub_14217A910 per dossier texture.
using TexLoadFn = void* (*)(const char* path,
                            char blocking,
                            void** out_handle,
                            char force_special_default,
                            char emissive_or_normal,
                            char tls_sampler_flag);

// M7 fix v17 — manual bgsm load + bind for skinned meshes.
// The vanilla apply_materials walker (sub_140255BA0) skips per_geom_apply
// for skinned BSGeometry (confirmed via Frida trace 2026-04-25). For
// vanilla NPCs the body bgsm is loaded by Actor::Load3D / TESNPC pipeline
// which we don't have access to. So we manually replicate the inner
// per_geom apply for each BSTriShape:
//   1. Read bgsm path from shader+0x10 (BSFixedString)
//   2. Strip leading "Materials\\" if present (loader prepends)
//   3. sub_1417A9620(path, &mat, 0) → load bgsm
//   4. sub_142169AD0(mat, geom, 1) → bind material to geometry
//
// RVAs from re/_bgsm_loader.log + re/_bone_drive_correct.log dossiers.
using BgsmLoadFn   = std::uint32_t (*)(const char* path,
                                       void** out_mat,
                                       char force_reload);
using MatBindFn    = void* (*)(void* mat, void* geom, char flag);

// M5 — NIF loader (public API sub_1417B3E90).
//   a1 = ANSI path, no "Meshes\\" prefix (loader prepends internally)
//   a2 = NiAVObject** out — receives BSFadeNode* with refcount already bumped
//   a3 = POINTER to 16-byte NifLoadOpts struct (NOT a scalar flag)
// Returns u32: 0 = success, non-zero = fail.
//
// V1 (sub_14026E1C0) hung — wrong arg layout. V2 (sub_1417B3E90
// with arg3=0) AV'd at 0x8 — arg3 is NOT a scalar, it's an opts
// struct pointer. The inner loader deref'd NULL+8 to read flags.
// V3 (this typedef): arg3 is a pointer to a 16-byte zero-init'd
// struct with flags byte at +0x8. See ni_offsets.h §12.
using NifLoadByPathFn = std::uint32_t (*)(const char* path,
                                          void**      out_node,
                                          void*       opts);

// Worker NIF loader (sub_1417B3480). 5-arg form. Used for ghost geometry
// to BYPASS the cache resolver (sub_1416A6D00) and get a FRESH tree per
// call — avoids cache-share with the local player's NIF instances which
// caused state corruption on equip/unequip cycles. Per dossier
// stradaB_nif_loader_api.txt §11 OPEN-E: "Two NPCs sharing MaleBody.nif
// get the same BSFadeNode... If bugs: use Path-B (direct sub_1417B3480,
// fresh tree, no sharing)."
//
// Returns a TLS scratch DWORD* that the caller ignores; real output is
// *out_node (refcount already incremented). user_ctx is passed to the
// BSModelProcessor callback if opts.flag_0x08 is set.
using NifLoadWorkerFn = std::uint32_t* (*)(std::int64_t      stream_ctx,
                                            const char*       path_cstr,
                                            void*             opts,
                                            void**            out_node,
                                            std::int64_t      user_ctx);

// M9.w4 PROPER (v0.4.2+) — BSGeometry factory `sub_14182FFD0`. Builds a
// BSTriShape from raw vertex/index arrays. 16-arg __cdecl — the engine's
// own asset loader uses this same signature for weapon NIF assembly.
// See ni_offsets.h `WEAPON_GEO_FACTORY_RVA` block for full RE notes.
//
// Args 5-15 are stream pointers (UVs, normals, etc.). For our use case
// — captured weapon-mod meshes from the sender — we have positions +
// indices only; pass nullptr for all optional streams.
using WeaponGeoFactoryFn = void* (*)(
    int          tri_count,
    const void*  indices_u16,
    unsigned int vert_count,
    const void*  positions_vec3,
    const void*  uvs_vec2,
    const void*  tangents_vec4,
    const void*  pos_alt,
    const void*  normals_vec3,
    const void*  colors_vec4f,
    const void*  skin_weights,
    const void*  skin_indices_dw,
    const void*  tangent_ex,
    const void*  eye_data,
    const void*  normals_alt,
    const void*  remap_u16,
    char         build_mesh_extra);

// 16-byte opts struct. zero-init and write flags byte at +0x8.
// Keep plain aggregate — the loader touches only +0x4 (stream key
// dword) and +0x8 (flag byte); everything else is slack.
struct NifLoadOpts {
    std::uint64_t ignored_qword;  // +0x00 — overlaps stream_key in decomp view
    std::uint8_t  flags;          // +0x08
    std::uint8_t  pad[7];         // +0x09..+0x0F
};
static_assert(sizeof(NifLoadOpts) == 16, "NifLoadOpts must be 16B");
static_assert(offsetof(NifLoadOpts, flags) == 8,
              "flags must live at +0x08 for sub_1417B3480 to find it");

// M6.2 fix — tree-walker that resolves .bgsm material references on a
// BSFadeNode subtree. THE step that was missing: without this call,
// BSLSP.bgsm_path remains unresolved and material stays at default
// (pink fallback textures). Dossier: re/_bgsm_loader.log Q3.
//
// Vanilla Actor::Load3D calls it AFTER sub_1417B3E90 returns. We must
// do the same.
using ApplyMaterialsWalkerFn = void (*)(void* root,
                                        std::int64_t a2,
                                        std::int64_t a3,
                                        std::int64_t a4,
                                        std::int64_t a5);

// M2.4 factory — 16 args. Windows x64 fastcall; first 4 in registers.
using GeoBuilderFn = void* (*)(
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
    void*     skin_indices_u32,
    void*     tangent_ex,
    void*     eye_data,
    void*     normals_alt,
    void*     remap_u16,
    char      build_mesh_extra);

// Resolver state. Populated on first call; all subsequent calls short-
// circuit on g_resolved.
struct Resolved {
    uintptr_t base                = 0;
    void*     pool                = nullptr;
    std::uint32_t* pool_init_flag = nullptr;
    void**    ssn_slot            = nullptr;   // qword_143E47A10 — ???
    void**    world_sg_slot       = nullptr;   // qword_1432D2228 — World SceneGraph
    AllocateFn        allocate    = nullptr;
    PoolInitFn        pool_init   = nullptr;
    NiNodeCtorFn      ninode_ctor = nullptr;
    FixedStrCreateFn  fs_create   = nullptr;
    FixedStrReleaseFn fs_release  = nullptr;
    SetNameFn         set_name    = nullptr;
    DetachChildFn     detach_child = nullptr;
    AttachChildFn     attach_child_direct = nullptr;  // via RVA, not vtable
    BSDynamicCtorFn   bsdynamic_ctor = nullptr;      // M2.2
    SetAlphaPropFn    set_alpha_prop_direct = nullptr; // M2.3 (vt[42] = sub_1416D5930)
    GeoBuilderFn      geo_builder = nullptr;         // M2.4 factory sub_14182FFD0
    UpdateDownwardFn  update_downward = nullptr;    // M2.5 sub_1416C8050
    BSEffectShaderCtorFn  bseffect_ctor   = nullptr; // sub_14216F9C0
    BSEffectShaderSetupFn bseffect_setup  = nullptr; // sub_142161B10
    NiAlphaPropInitFn     nialpha_init    = nullptr; // sub_1416BD6F0
    void*                 effect_tex_handle = nullptr; // *(QWORD*)(base+0x34391A0)
    std::uint32_t*        effect_tex_int_slot = nullptr; // base+0x34391A8
    void*                 nialpha_vftable = nullptr;  // NiAlphaProperty::vftable

    // M3.3 texture via BSLightingShaderProperty.
    BSLSPNewFn       bslsp_new         = nullptr; // sub_142171050
    TexSetCtorFn     texset_ctor       = nullptr; // sub_14216ED10
    TexSetSetPathFn  texset_set_path   = nullptr; // sub_1421627B0
    BindMatTexSetFn  bind_mat_texset   = nullptr; // sub_1421C6870
    MaterialCtorFn   material_ctor     = nullptr; // sub_1421C5CE0 (fresh mat)
    TexLoadFn        tex_load          = nullptr; // sub_14217A910 (manual tex handles)

    // M5 NIF loader (public API sub_1417B3E90 — path + out slot + flags).
    NifLoadByPathFn  nif_load_by_path  = nullptr; // sub_1417B3E90
    // M9.5 cache-bypass loader (sub_1417B3480 — fresh tree per call).
    // Used by ghost_attach_armor + inject_body_nif to avoid cache-share
    // with local player's NIF instances. See dossier OPEN-E note.
    NifLoadWorkerFn  nif_load_worker   = nullptr; // sub_1417B3480
    void**           res_mgr_slot      = nullptr; // qword_1430DD618 — diagnostic only

    // M9.w4 PROPER (v0.4.2+) — BSGeometry factory for receiver-side mesh
    // reconstruction from captured weapon-mod data. See typedef block.
    WeaponGeoFactoryFn weapon_geo_factory = nullptr; // sub_14182FFD0

    // M6.2 apply-materials walker — fixes pink textures post-NIF-load.
    ApplyMaterialsWalkerFn apply_materials = nullptr; // sub_140255BA0

    // M7 v17 manual bgsm path: skip walker, do per-geom load+bind ourselves.
    BgsmLoadFn bgsm_load = nullptr;        // sub_1417A9620
    MatBindFn  mat_bind_to_geom = nullptr; // sub_142169AD0
};

std::atomic<bool> g_resolved{false};
Resolved          g_r{};

// The injected node. Written once on success, read on detach.
// Using atomic for publish ordering (main thread writes, main thread
// reads — single threaded in practice, but atomic makes the intent
// explicit and cheap).
std::atomic<void*>      g_injected_node{nullptr};
std::atomic<unsigned>   g_attach_count{0};

// M2.2: injected BSDynamicTriShape (the proto-cube). Separate from the
// NiNode canary so that a crash in the cube path doesn't take the
// canary down, and vice versa. Both are attached to World SceneGraph
// as siblings.
std::atomic<void*>      g_injected_cube{nullptr};

// M6.3 / v12: head is a separate BSFadeNode (BaseMaleHead.nif + rear
// as child). Attached as child of the body, but we store its ptr so
// pos_update can apply an INDEPENDENT rotation — body gets yaw only,
// head gets pitch only. Without this decoupling, remote looking up
// rotates the entire body like a tree trunk (user report).
std::atomic<void*>      g_injected_head{nullptr};

// M9 wedge 3 (2026-05-02 / refined 2026-05-03): cached LIST of ghost body
// BSSubIndexTriShape pointers — one per BSSITF found in the body NIF tree.
//
// Why a list: live diagnostic on May 3 revealed MaleBody.nif's loaded tree
// contains TWO BSSubIndexTriShape nodes (count=2 from `[body-tree-dump] DONE`),
// not one as initially assumed. Hiding only the FIRST (the previous behavior)
// left the second one visible, producing the "head + floating hands" effect
// after equip/unequip cycles — the second BSSITF (likely hands/face geometry
// that the body NIF carries internally) wasn't culled.
//
// Populated ONCE at body inject time (before any armor attaches) by walking
// the body NIF tree for ALL nodes whose vtable RVA == BSSUBINDEXTRISHAPE_VTABLE_RVA.
// Cleared at detach_debug_cube together with g_injected_cube.
//
// Protected by g_body_cull_mtx (declared just below) — same lock that already
// guards the body-cull contributor set. Not atomic because we read/write the
// whole vector together.
std::vector<void*>      g_ghost_body_geoms;

// M9 wedge 3 — body-cull contributor tracking ===============================
// Per-peer set of form_ids of currently-attached "slot 3 BODY" armors (Vault
// Suit, Power Armor, Synth Armor, etc.). When the set transitions empty→non-
// empty for a peer, we set NIAV_FLAG_APP_CULLED on that ghost's body BSSITF
// (the cached g_ghost_body_geom). Empty→non-empty triggers cull; non-empty→
// empty triggers restore. We use a SET rather than a refcount so re-attaching
// the SAME form (idempotent ghost_attach_armor on duplicate equip-cycle
// broadcasts) doesn't inflate count and leave body permanently hidden after
// detach.
//
// Lives at fw::native top-level (not in the armor helpers anon namespace at
// line ~2900) because detach_debug_cube needs to clear this set in lockstep
// with cube destruction — and detach_debug_cube lives ABOVE the armor helpers
// namespace block. Use static/anon-ns linkage by being defined in this TU only.
std::mutex g_body_cull_mtx;
std::unordered_map<std::string, std::unordered_set<std::uint32_t>>
    g_body_cull_contributors;

bool resolve_once() {
    if (g_resolved.load(std::memory_order_acquire)) return true;

    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (!game) {
        FW_ERR("[native] GetModuleHandle(Fallout4.exe) returned null");
        return false;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(game);

    g_r.base            = base;
    g_r.pool            = reinterpret_cast<void*>(base + MEM_POOL_RVA);
    g_r.pool_init_flag  = reinterpret_cast<std::uint32_t*>(base + POOL_INIT_FLAG_RVA);
    g_r.ssn_slot        = reinterpret_cast<void**>(base + SSN_SINGLETON_RVA);
    g_r.world_sg_slot   = reinterpret_cast<void**>(base + WORLD_SG_SINGLETON_RVA);
    g_r.allocate        = reinterpret_cast<AllocateFn>      (base + ALLOCATE_FN_RVA);
    g_r.pool_init       = reinterpret_cast<PoolInitFn>      (base + POOL_INIT_FN_RVA);
    g_r.ninode_ctor     = reinterpret_cast<NiNodeCtorFn>    (base + NINODE_CTOR_RVA);
    g_r.fs_create       = reinterpret_cast<FixedStrCreateFn>(base + FIXEDSTR_CREATE_RVA);
    g_r.fs_release      = reinterpret_cast<FixedStrReleaseFn>(base + FIXEDSTR_RELEASE_RVA);
    g_r.set_name        = reinterpret_cast<SetNameFn>       (base + NINODE_SETNAME_RVA);
    g_r.detach_child    = reinterpret_cast<DetachChildFn>   (base + NINODE_DETACH_CHILD_FN_RVA);
    g_r.attach_child_direct = reinterpret_cast<AttachChildFn>(base + NINODE_ATTACH_CHILD_FN_RVA);
    g_r.bsdynamic_ctor      = reinterpret_cast<BSDynamicCtorFn>(base + BSDYNAMICTRISHAPE_CTOR_RVA);
    g_r.set_alpha_prop_direct = reinterpret_cast<SetAlphaPropFn>(base + BSGEOM_SET_ALPHA_FN_RVA);
    g_r.geo_builder           = reinterpret_cast<GeoBuilderFn>  (base + GEO_BUILDER_FN_RVA);
    g_r.update_downward       = reinterpret_cast<UpdateDownwardFn>(base + UPDATE_DOWNWARD_PASS_RVA);
    g_r.bseffect_ctor         = reinterpret_cast<BSEffectShaderCtorFn>(base + BSEFFECT_SHADER_CTOR_RVA);
    g_r.bseffect_setup        = reinterpret_cast<BSEffectShaderSetupFn>(base + BSEFFECT_SHADER_SETUP_RVA);
    g_r.nialpha_init          = reinterpret_cast<NiAlphaPropInitFn>(base + NIALPHAPROP_INIT_RVA);
    // Texture handle is at *(QWORD*)(base + RVA) — i.e. the u64 value
    // at that address, not a pointer to it. We read the VALUE at cube
    // inject time because it may not be initialized at DLL load.
    g_r.effect_tex_handle     = *reinterpret_cast<void**>(base + BSEFFECT_SHADER_TEX_HANDLE_RVA);
    g_r.effect_tex_int_slot   = reinterpret_cast<std::uint32_t*>(base + BSEFFECT_SHADER_TEX_INT_RVA);
    g_r.nialpha_vftable       = reinterpret_cast<void*>(base + 0x02474400);  // NiAlphaProperty vtable RVA
    g_r.bslsp_new             = reinterpret_cast<BSLSPNewFn>    (base + BSLSP_NEW_RVA);
    g_r.texset_ctor           = reinterpret_cast<TexSetCtorFn>  (base + BSSHADERTEXSET_CTOR_RVA);
    g_r.texset_set_path       = reinterpret_cast<TexSetSetPathFn>(base + BSSHADERTEXSET_SETPATH_RVA);
    g_r.bind_mat_texset       = reinterpret_cast<BindMatTexSetFn>(base + BSLSP_BIND_MATERIAL_TEXSET_RVA);
    g_r.material_ctor         = reinterpret_cast<MaterialCtorFn> (base + BSLIGHTINGMAT_CTOR_RVA);
    g_r.tex_load              = reinterpret_cast<TexLoadFn>      (base + 0x0217A910);  // sub_14217A910

    // M5: public NIF loader API. 3-arg form (path, out-slot, flags).
    // sub_14026E1C0 (legacy wrapper) kept as constant for documentation
    // only — it hangs if called with a user-allocated NiNode holder.
    g_r.nif_load_by_path      = reinterpret_cast<NifLoadByPathFn> (base + NIF_LOAD_BY_PATH_RVA);
    // M9.5 cache-bypass: resolve worker (sub_1417B3480, NIF_LOAD_WORKER_RVA).
    // Used by ghost_attach_armor + inject_body_nif so ghosts get a FRESH
    // NIF tree per call instead of the cached instance shared with the
    // local player. Without this, attaching/detaching the ghost's armor
    // mutated the local player's armor state and vice-versa, causing
    // "ghost B unequips when local A equips" + cycle crash bugs.
    g_r.nif_load_worker       = reinterpret_cast<NifLoadWorkerFn> (base + NIF_LOAD_WORKER_RVA);
    g_r.res_mgr_slot          = reinterpret_cast<void**>          (base + NIF_LOAD_RESMGR_SLOT_RVA);
    g_r.weapon_geo_factory    = reinterpret_cast<WeaponGeoFactoryFn>(base + WEAPON_GEO_FACTORY_RVA);

    // M6.2: apply-materials walker — the missing post-NIF-load step.
    g_r.apply_materials       = reinterpret_cast<ApplyMaterialsWalkerFn>(base + APPLY_MATERIALS_WALKER_RVA);

    // M7 v17 manual per-geom bgsm load + bind.
    g_r.bgsm_load             = reinterpret_cast<BgsmLoadFn>     (base + BGSM_LOADER_RVA);
    g_r.mat_bind_to_geom      = reinterpret_cast<MatBindFn>      (base + MAT_BIND_TO_GEOM_RVA);

    FW_LOG("[native] resolved Strada B symbols:");
    FW_LOG("[native]   base=0x%llX", static_cast<unsigned long long>(base));
    FW_LOG("[native]   pool=%p  init_flag=%p (val=%u)",
           g_r.pool, g_r.pool_init_flag, *g_r.pool_init_flag);
    FW_LOG("[native]   ssn_slot=%p  ssn=%p",
           static_cast<void*>(g_r.ssn_slot), *g_r.ssn_slot);
    FW_LOG("[native]   world_sg_slot=%p  world_sg=%p",
           static_cast<void*>(g_r.world_sg_slot), *g_r.world_sg_slot);
    FW_LOG("[native]   alloc=%p  ninode_ctor=%p",
           reinterpret_cast<void*>(g_r.allocate),
           reinterpret_cast<void*>(g_r.ninode_ctor));
    FW_LOG("[native]   fs_create=%p  set_name=%p  detach=%p",
           reinterpret_cast<void*>(g_r.fs_create),
           reinterpret_cast<void*>(g_r.set_name),
           reinterpret_cast<void*>(g_r.detach_child));
    FW_LOG("[native]   bsdynamic_ctor=%p (M2.2)  set_alpha=%p (M2.3)",
           reinterpret_cast<void*>(g_r.bsdynamic_ctor),
           reinterpret_cast<void*>(g_r.set_alpha_prop_direct));
    FW_LOG("[native]   nif_load_by_path=%p (M5 sub_1417B3E90)  "
           "res_mgr_slot=%p  res_mgr=%p",
           reinterpret_cast<void*>(g_r.nif_load_by_path),
           static_cast<void*>(g_r.res_mgr_slot),
           g_r.res_mgr_slot ? *g_r.res_mgr_slot : nullptr);

    g_resolved.store(true, std::memory_order_release);
    return true;
}

// Thin SEH wrapper for the engine-side call sequence. Any AV/BP/OOB
// touch caught here is logged and the caller sees a clean false. We do
// NOT rethrow — the whole point of a guarded first test is to fail
// gracefully into the log rather than take the game down.
bool try_inject(float x, float y, float z, void** out_node) {
    *out_node = nullptr;

    __try {
        // 2. Pick an attach parent.
        //
        // Dossier said to use qword_143E47A10 (labeled "ShadowSceneNode"),
        // but live test 2026-04-23 revealed that slot holds a pointer to
        // an object whose vtable RVA == 0x267DD50 = NiCamera::vftable.
        // Attaching via NiNode::AttachChild to a NiCamera crashes because
        // NiCamera has no children-array member at +0x120. The dossier
        // misidentified that singleton — it's a camera slot, not a scene-
        // root slot.
        //
        // Fallback: qword_1432D2228 (World SceneGraph). Verified in the
        // same dossier to be a proper SceneGraph (inherits NiNode) whose
        // children are { SSN, Sky, Weather, LODRoot, ... }. Attaching as
        // its 8th child means our node gets walked every frame by the
        // main render pass (SceneGraph walks all its children, starting
        // with SSN).
        //
        // We still log both pointers + their vtable RVAs for forensic
        // clarity.
        void* ssn     = *g_r.ssn_slot;
        void* worldsg = *g_r.world_sg_slot;

        auto vt_rva = [&](void* obj) -> std::uintptr_t {
            if (!obj) return 0;
            void* vt = *reinterpret_cast<void**>(obj);
            return reinterpret_cast<std::uintptr_t>(vt) - g_r.base;
        };
        FW_LOG("[native] inject: candidates — ssn=%p (vt_rva=0x%llX), "
               "world_sg=%p (vt_rva=0x%llX)",
               ssn, static_cast<unsigned long long>(vt_rva(ssn)),
               worldsg, static_cast<unsigned long long>(vt_rva(worldsg)));

        // Use World SceneGraph as parent. Log which we picked + its vtable
        // RVA to make the choice auditable.
        void* parent = worldsg;
        if (!parent) {
            FW_WRN("[native] inject: World SceneGraph singleton is null "
                   "(very early boot / loading screen?)");
            return false;
        }

        // 3. Pool init if flag != 2.
        if (*g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
            FW_LOG("[native] inject: pool not ready (flag=%u), calling init",
                   *g_r.pool_init_flag);
            g_r.pool_init(g_r.pool, g_r.pool_init_flag);
            FW_LOG("[native] inject: pool init done (flag=%u)",
                   *g_r.pool_init_flag);
        }

        // 4. Alloc NiNode.
        void* node = g_r.allocate(g_r.pool, NINODE_SIZEOF, NINODE_ALIGN, true);
        if (!node) {
            FW_ERR("[native] inject: allocate returned null");
            return false;
        }
        FW_LOG("[native] inject: alloc OK node=%p", node);

        // 5. In-place ctor. Capacity 0 — empty children array; engine
        //    grows it on first AttachChild. After ctor returns:
        //      *(void**)node == &NiNode::vftable
        //      refcount @ node+8 == 0
        //      local/world transforms == identity
        g_r.ninode_ctor(node, /*capacity=*/0);

        // Verify vtable was wired (sanity — detects wrong RVA early).
        void* vt = *reinterpret_cast<void**>(node);
        void* expected_vt = reinterpret_cast<void*>(g_r.base + NINODE_VTABLE_RVA);
        if (vt != expected_vt) {
            FW_ERR("[native] inject: ctor wired wrong vtable got=%p expected=%p",
                   vt, expected_vt);
            // Don't free — we don't know the right deallocator path if
            // ctor didn't complete normally. Leak is safer than crash.
            return false;
        }
        FW_LOG("[native] inject: ctor OK vtable=%p refcount=%u",
               vt, *reinterpret_cast<std::uint32_t*>(
                        reinterpret_cast<char*>(node) + NIAV_REFCOUNT_OFF));

        // 6. Name.
        std::uint64_t name_handle = 0;
        g_r.fs_create(&name_handle, "fw_debug_cube");
        if (name_handle) {
            g_r.set_name(node, reinterpret_cast<void*>(name_handle));
            g_r.fs_release(&name_handle);
            FW_LOG("[native] inject: set_name OK");
        } else {
            FW_WRN("[native] inject: fs_create returned 0 handle (continuing)");
        }

        // 7. local.translate = (x, y, z). At NiAVObject+0x60 (NOT +0x54 —
        //    see ni_offsets.h for the SIMD-pad correction note).
        char* node_bytes = reinterpret_cast<char*>(node);
        float* trans = reinterpret_cast<float*>(node_bytes + NIAV_LOCAL_TRANSLATE_OFF);
        trans[0] = x;
        trans[1] = y;
        trans[2] = z;

        // 8. flags |= kIsMovable (0x800). Engine uses this bit to decide
        //    whether to recompute world transform from local each frame.
        auto* flags = reinterpret_cast<std::uint64_t*>(node_bytes + NIAV_FLAGS_OFF);
        *flags |= NIAV_FLAG_MOVABLE;

        // 9. Pre-bump refcount. AttachChild's Inc/Dec pair leaves the
        //    parent with +1 net — but if we don't hold our OWN +1 before
        //    the call, there's a micro-window where refcount drops to 0
        //    between the Inc and the Inc-inside-array-push. Bumping
        //    first is the canonical engine pattern (verified in SSN
        //    ctor writing its children).
        auto* refcount = reinterpret_cast<long*>(node_bytes + NIAV_REFCOUNT_OFF);
        _InterlockedIncrement(refcount);

        // 10. AttachChild — DIRECT CALL via function RVA, not vtable.
        //
        // First live test (2026-04-23) showed vtable[58] read yielded
        // 0x74656D6F6547694E ("NiGeomet" in LE ASCII) — a RTTI class-name
        // string in .rdata, NOT a function pointer. This means either:
        //   (a) ShadowSceneNode's vtable has fewer than 59 slots (its
        //       derived vtable layout differs from NiNode's AttachChild
        //       slot index)
        //   (b) the dossier's "slot 58" count was off-by-something
        //
        // Either way, calling sub_1416BE170 directly is safer: NiNode's
        // AttachChild is non-virtual in practice (no subclass we know of
        // overrides it — SSN inherits the base implementation), and we
        // have the verified RVA. The engine's own call sites do use the
        // vtable dispatch but they operate on SceneGraph (not SSN); the
        // layout may genuinely differ.
        //
        // Sanity-dump first 8 vtable slots + slot 58 of the CHOSEN parent
        // for forensic post-mortem. If AttachChild works via direct RVA
        // but vt[58] is junk, we know the vtable layout is more compact
        // than dossier claimed (info for M1.5 followup).
        void** parent_vtable = *reinterpret_cast<void***>(parent);
        FW_LOG("[native] inject: parent_vtable=%p — first 8 slots + slot 58:",
               static_cast<void*>(parent_vtable));
        for (int i = 0; i < 8; ++i) {
            FW_LOG("[native]   vt[%d] = %p", i, parent_vtable[i]);
        }
        FW_LOG("[native]   vt[58] = %p (expected: AttachChild fn ptr in 0x7FF7... range)",
               parent_vtable[VT_SLOT_ATTACH_CHILD]);

        FW_LOG("[native] inject: calling AttachChild (DIRECT RVA path) "
               "parent=%p (World SceneGraph) child=%p fn=%p",
               parent, node,
               reinterpret_cast<void*>(g_r.attach_child_direct));
        g_r.attach_child_direct(parent, node, /*reuseFirstEmpty=*/1);

        // Post-attach refcount — expect 2 (ours + SSN's). If it's 1 the
        // engine already decremented ours; if it's 0 the node has been
        // freed and we're about to UAF. Log either way so the first live
        // test surfaces the exact behavior.
        const long post = *refcount;
        FW_LOG("[native] inject: AttachChild returned; refcount=%ld "
               "(expect 2 = ours + parent)", post);

        *out_node = node;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[native] inject: SEH caught exception, inject aborted");
        return false;
    }
}

// --- M2.4 cube geometry (hardcoded, 70-unit-side ≈ 1m cube) ---------------
//
// 8 corner vertices. Cube is 70×70×70 world units ≈ 1m per side
// (FO4 unit scale: 1 unit ≈ 1.4 cm → 70 units ≈ 1m).
// Small enough to fit inside a humanoid actor body, making it a clean
// marker for M3 position-tracking tests: if the cube follows the remote
// correctly, it appears as a ~1m solid clipping into the character.
//
// UVs + normals are "smooth-shaded" approximations (each vertex shares
// its normal across 3 adjacent faces via the normalized corner vector).
// Good enough for an obvious colored cube; proper hard-edged shading
// would need 24 vertices.
//
// Indices: 12 triangles × 3 = 36 u16. Winding matches dossier §4 pseudo.
constexpr float kCubeHalfSize = 35.0f;  // 70-unit side ≈ 1m cube
constexpr float kCubeInvSqrt3 = 0.5773502692f;  // 1/sqrt(3)
constexpr float kCubePositions[8 * 3] = {
    -kCubeHalfSize, -kCubeHalfSize, -kCubeHalfSize,
     kCubeHalfSize, -kCubeHalfSize, -kCubeHalfSize,
     kCubeHalfSize,  kCubeHalfSize, -kCubeHalfSize,
    -kCubeHalfSize,  kCubeHalfSize, -kCubeHalfSize,
    -kCubeHalfSize, -kCubeHalfSize,  kCubeHalfSize,
     kCubeHalfSize, -kCubeHalfSize,  kCubeHalfSize,
     kCubeHalfSize,  kCubeHalfSize,  kCubeHalfSize,
    -kCubeHalfSize,  kCubeHalfSize,  kCubeHalfSize,
};
constexpr float kCubeUVs[8 * 2] = {
    0.0f, 0.0f,  1.0f, 0.0f,  1.0f, 1.0f,  0.0f, 1.0f,
    0.0f, 0.0f,  1.0f, 0.0f,  1.0f, 1.0f,  0.0f, 1.0f,
};
constexpr float kCubeNormals[8 * 3] = {
    -kCubeInvSqrt3, -kCubeInvSqrt3, -kCubeInvSqrt3,
     kCubeInvSqrt3, -kCubeInvSqrt3, -kCubeInvSqrt3,
     kCubeInvSqrt3,  kCubeInvSqrt3, -kCubeInvSqrt3,
    -kCubeInvSqrt3,  kCubeInvSqrt3, -kCubeInvSqrt3,
    -kCubeInvSqrt3, -kCubeInvSqrt3,  kCubeInvSqrt3,
     kCubeInvSqrt3, -kCubeInvSqrt3,  kCubeInvSqrt3,
     kCubeInvSqrt3,  kCubeInvSqrt3,  kCubeInvSqrt3,
    -kCubeInvSqrt3,  kCubeInvSqrt3,  kCubeInvSqrt3,
};
constexpr std::uint16_t kCubeIndices[12 * 3] = {
    0, 1, 2,   0, 2, 3,    // -Z face
    4, 6, 5,   4, 7, 6,    // +Z face
    0, 5, 1,   0, 4, 5,    // -Y face
    1, 6, 2,   1, 5, 6,    // +X face
    2, 7, 3,   2, 6, 7,    // +Y face
    3, 4, 0,   3, 7, 4,    // -X face
};

// FIX #2 (2026-04-23 render diagnosis): the shader we clone from a
// vanilla BSTriShape expects POS+UV+NRM+TANGENT+COLOR streams in the
// vertex buffer (bits 44,45,46,48,49 in its BSVertexDesc). If we only
// provide POS+UV+NRM, the D3D11 input assembler reads uninitialized
// memory for tangent/color → garbage → clip-space NaN → cube never
// reaches the rasterizer. So: pass dummy tangents + colors so the
// factory packs a VD that matches typical lit-shader layouts.
//
// Tangents: (1,0,0,1) per vertex — arbitrary but valid tangent basis.
// Colors:   (1,1,1,1) per vertex — solid white, full alpha.
constexpr float kCubeTangents[8 * 4] = {
    1.0f, 0.0f, 0.0f, 1.0f,   1.0f, 0.0f, 0.0f, 1.0f,
    1.0f, 0.0f, 0.0f, 1.0f,   1.0f, 0.0f, 0.0f, 1.0f,
    1.0f, 0.0f, 0.0f, 1.0f,   1.0f, 0.0f, 0.0f, 1.0f,
    1.0f, 0.0f, 0.0f, 1.0f,   1.0f, 0.0f, 0.0f, 1.0f,
};
constexpr float kCubeColors[8 * 4] = {
    1.0f, 1.0f, 1.0f, 1.0f,   1.0f, 1.0f, 1.0f, 1.0f,
    1.0f, 1.0f, 1.0f, 1.0f,   1.0f, 1.0f, 1.0f, 1.0f,
    1.0f, 1.0f, 1.0f, 1.0f,   1.0f, 1.0f, 1.0f, 1.0f,
    1.0f, 1.0f, 1.0f, 1.0f,   1.0f, 1.0f, 1.0f, 1.0f,
};

// M2.4 — build a BSTriShape via the engine's GEO BUILDER factory
// (sub_14182FFD0). This is the proven path used by 32 vanilla call sites;
// the factory handles vertex packing, BSVertexDesc computation, AABB
// bounds, BSPositionData allocation, counts. We just provide raw arrays
// and get back a fully-initialized BSTriShape.
//
// Replaces the previous BSDynamicTriShape approach which had ctor bugs
// (didn't call BSGeometry::ctor, leaving +0x120..+0x158 uninitialized).
//
// After the factory returns we still need to:
//   - Clone shader and alpha from a live vanilla BSTriShape (the walker
//     captured one in first_bstri_shape). Refcount bump + direct write.
//   - Set name, local translate, flags.
//   - Attach to the REAL ShadowSceneNode (from walker's capture, not any
//     of the M1 dossier shortcuts which both point to NiCamera).
//
// M5 status: NO LONGER CALLED from inject_debug_cube (replaced by
// try_inject_body_nif). Kept in source as a reference for the
// BSTriShape factory path — useful if we ever want to inject custom
// procedural geometry. [[maybe_unused]] so the compiler stops warning.
[[maybe_unused]] bool try_inject_cube(float x, float y, float z, void** out_cube) {
    *out_cube = nullptr;

    __try {
        // 1. Parent: the real SSN, captured during the walk. If the walk
        //    didn't run or didn't find SSN, we can't attach into a
        //    render-walked subtree — bail.
        void* parent = get_shadow_scene_node();
        if (!parent) {
            FW_WRN("[native] inject_cube: no SSN captured by walker yet "
                   "— cube would not be rendered; skipping");
            return false;
        }
        const auto ssn_vt_rva =
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(parent))
            - g_r.base;
        FW_LOG("[native] inject_cube: parent=SSN@%p (vt_rva=0x%llX, "
               "expected 0x2908F40)",
               parent, static_cast<unsigned long long>(ssn_vt_rva));

        // 2. Source shape for shader/alpha clone.
        void* src_shape = get_first_bstri_shape();
        if (!src_shape) {
            FW_WRN("[native] inject_cube: no first_bstri_shape captured "
                   "— cube will have no shader and be invisible");
        }

        // 3. Pool init (just in case — factory likely does this too).
        if (*g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
            g_r.pool_init(g_r.pool, g_r.pool_init_flag);
        }

        // 4. Call the factory. 16 args, most null (no tangents, no skin,
        //    no colors). We provide positions, UVs, normals, indices.
        //    build_mesh_extra=1 attaches the mesh-index helper struct —
        //    dossier §2 step (h) says the factory allocates a BSPositionData
        //    wrapper when this flag is set.
        FW_LOG("[native] inject_cube: calling GEO BUILDER factory "
               "(sub_14182FFD0, 8 verts, 12 tris)");
        void* cube = g_r.geo_builder(
            /*tri_count*/    12,
            /*indices*/      const_cast<std::uint16_t*>(kCubeIndices),
            /*vert_count*/   8,
            /*positions*/    const_cast<float*>(kCubePositions),
            /*uvs*/          const_cast<float*>(kCubeUVs),
            /*tangents*/     const_cast<float*>(kCubeTangents),  // FIX #2
            /*pos_alt*/      nullptr,
            /*normals*/      const_cast<float*>(kCubeNormals),
            /*colors*/       const_cast<float*>(kCubeColors),    // FIX #2
            /*skin_weights*/ nullptr,
            /*skin_indices*/ nullptr,
            /*tan_ex*/       nullptr,
            /*eye_data*/     nullptr,
            /*normals_alt*/  nullptr,
            /*remap_u16*/    nullptr,
            /*extra*/        1);
        if (!cube) {
            FW_ERR("[native] inject_cube: factory returned null");
            return false;
        }
        FW_LOG("[native] inject_cube: factory returned BSTriShape=%p", cube);

        // 5. Verify vtable. Factory should wire BSTriShape (0x267E948).
        char* cb = reinterpret_cast<char*>(cube);
        void* vt = *reinterpret_cast<void**>(cube);
        const auto vt_rva = reinterpret_cast<std::uintptr_t>(vt) - g_r.base;
        FW_LOG("[native] inject_cube: ctor vtable=%p (rva=0x%llX, "
               "expected 0x%llX BSTriShape)",
               vt, static_cast<unsigned long long>(vt_rva),
               static_cast<unsigned long long>(BSTRISHAPE_VTABLE_RVA));

        // 6. Dump the post-factory state for sanity checks.
        FW_LOG("[native] inject_cube: post-factory slot dump "
               "alpha@+0x130=%p shader@+0x138=%p skin@+0x140=%p "
               "posdata@+0x148=%p vdesc@+0x150=0x%llX idx_cnt@+0x160=%u "
               "vert_cnt@+0x164=%u refcount=%u",
               *reinterpret_cast<void**>(cb + BSGEOM_ALPHAPROP_OFF),
               *reinterpret_cast<void**>(cb + BSGEOM_SHADERPROP_OFF),
               *reinterpret_cast<void**>(cb + 0x140),
               *reinterpret_cast<void**>(cb + 0x148),
               static_cast<unsigned long long>(
                   *reinterpret_cast<std::uint64_t*>(cb + 0x150)),
               *reinterpret_cast<std::uint32_t*>(cb + 0x160),
               *reinterpret_cast<std::uint16_t*>(cb + 0x164),
               *reinterpret_cast<std::uint32_t*>(cb + NIAV_REFCOUNT_OFF));

        // 7. M3.3 — BSLightingShaderProperty with REAL texture from BA2.
        //
        // NOTE (2026-04-23): after ~10 iterations we have a cube that is
        // VISIBLE but stuck in env-map-reflection mode (material vtable
        // 0x2909CD0 is likely BSLightingShaderMaterialEnvmap). Rather
        // than push further on the abstract cube, the M5 pivot plan is
        // to load MaleBody.nif natively — the engine's NIF loader sets
        // up shader+material+textures correctly by itself. RE agent
        // running in background for the NIF load API.
        //
        // Previous approach used BSEffectShaderProperty + the FogOfWar
        // tint handle (`qword_1434391A0`), which the texture dossier
        // revealed is a COLOR tint, not a texture handle — that's why
        // the cube was flat white. The correct path:
        //
        //   1. Alloc BSLightingShaderProperty (0xE8) via sub_142171050
        //      (wraps allocator + ctor).
        //   2. Alloc BSShaderTextureSet (0x60) + init via sub_14216ED10.
        //   3. SetTexturePath(slot=0, diffuse) via sub_1421627B0.
        //   4. Bind via sub_1421C6870 — this iterates the 10 path slots
        //      and calls the texture-load API per slot, wiring the
        //      resulting NiSourceTexture* handles into the material's
        //      tex slots inside shader+88 (BSShaderMaterial).
        //   5. Direct-write the BSLSP to cube+0x138 with refcount++.
        //
        // NiAlphaProperty: we keep the fresh alloc path (worked fine).
        (void)src_shape;  // not cloning anymore
        __try {
            // --- BSLightingShaderProperty with DDS texture ---
            void* shader = g_r.bslsp_new();
            if (shader) {
                FW_LOG("[native] inject_cube: BSLSP alloc=%p (0x%zX B)",
                       shader, static_cast<std::size_t>(BSLSP_SIZEOF));

                // FIX #1c: BSLSP ctor does NOT zero-fill the 0xE8 block
                // and never writes +0x64. vt[43] SetupGeometry early-
                // rejects if *(float*)(shader+0x64) == 0. Force 1.0f.
                float* drawable_flt = reinterpret_cast<float*>(
                    reinterpret_cast<char*>(shader) + BSLSP_DRAWABLE_FLOAT_OFF);
                const float was_drawable = *drawable_flt;
                *drawable_flt = 1.0f;
                FW_LOG("[native] inject_cube: shader+0x64 was=%.3f now=1.0",
                       was_drawable);

                // Log shader +0x30/+0x38 for diagnostic (v9 confirmed
                // +0x30=0x180400000 is a cache hash, not BSShaderFlags —
                // NOT zeroing anymore since that was the wrong place).
                const std::uint64_t sflags_30 = *reinterpret_cast<std::uint64_t*>(
                    reinterpret_cast<char*>(shader) + 0x30);
                const std::uint64_t sflags_38 = *reinterpret_cast<std::uint64_t*>(
                    reinterpret_cast<char*>(shader) + 0x38);
                FW_LOG("[native] inject_cube: shader +0x30=0x%llX +0x38=0x%llX "
                       "(NOT zeroed — per v9 data these aren't flags)",
                       static_cast<unsigned long long>(sflags_30),
                       static_cast<unsigned long long>(sflags_38));

                // FIX #1a+b: swap the shared default material for a
                // fresh private one. BSLSP ctor installed the cache-dedup
                // default singleton (qword_143E488C8) at shader+0x58. If
                // we leave that there, sub_1421C6870 mutates the shared
                // object — cross-contaminates vanilla rendering AND may
                // be rejected by per-instance state that lives there.
                //
                // Allocate 0xC0 bytes, call raw material ctor, refcount-
                // safe swap.
                //
                // Size 0xC0 is INFERRED from ctor decomp (last write at
                // +0xB8). If the engine reads offsets beyond 0xBF we'll
                // crash or show garbage; revert to #2 path in that case.
                void** mat_slot = reinterpret_cast<void**>(
                    reinterpret_cast<char*>(shader) + BSLSP_MATERIAL_OFF);
                void* old_mat = *mat_slot;
                FW_LOG("[native] inject_cube: shared default material @+0x58=%p "
                       "— allocating fresh replacement (sizeof=0x%zX)",
                       old_mat, static_cast<std::size_t>(BSLIGHTINGMAT_SIZEOF));
                void* new_mat = g_r.allocate(g_r.pool,
                                             BSLIGHTINGMAT_SIZEOF,
                                             0, false);
                if (new_mat) {
                    // Zero-fill BEFORE ctor — allocator returns uninitialized
                    // memory and the ctor only writes offsets 0..0xB8. Any
                    // render-path reads beyond that hit heap garbage (likely
                    // 0 by luck, but sometimes non-0 → unpredictable). Zero
                    // is safer baseline: fields the render expects to be
                    // zero-or-ignored stay zero; ctor then overwrites the
                    // ones it cares about.
                    std::memset(new_mat, 0, BSLIGHTINGMAT_SIZEOF);
                    g_r.material_ctor(new_mat);
                    FW_LOG("[native] inject_cube: fresh material=%p "
                           "vt_rva=0x%llX",
                           new_mat,
                           static_cast<unsigned long long>(
                               reinterpret_cast<std::uintptr_t>(
                                   *reinterpret_cast<void**>(new_mat)) - g_r.base));
                    // Bump refcount on the new material BEFORE installing.
                    _InterlockedIncrement(reinterpret_cast<long*>(
                        reinterpret_cast<char*>(new_mat) + NIAV_REFCOUNT_OFF));
                    // Swap.
                    *mat_slot = new_mat;
                    // Release old — if refcount drops to 0 call vt[1] dtor.
                    // Shared default has refcount ≥ N (all BSLSP instances),
                    // so this decrement just brings it to N-1 — no actual
                    // dtor fire, which is what we want.
                    if (old_mat) {
                        long prev = _InterlockedExchangeAdd(
                            reinterpret_cast<long*>(
                                reinterpret_cast<char*>(old_mat) + NIAV_REFCOUNT_OFF),
                            -1);
                        FW_LOG("[native] inject_cube: old_mat refcount was %ld "
                               "(pre-decrement)", prev);
                        if (prev == 1) {
                            void** old_vt = *reinterpret_cast<void***>(old_mat);
                            using DtorFn = void (*)(void*);
                            auto dtor = reinterpret_cast<DtorFn>(old_vt[1]);
                            FW_WRN("[native] inject_cube: old_mat refcount hit 0 "
                                   "— calling dtor (unexpected for shared default)");
                            dtor(old_mat);
                        }
                    }
                } else {
                    FW_ERR("[native] inject_cube: fresh material alloc failed — "
                           "will fall back to shared default (cross-contaminate)");
                }

                // Alloc BSShaderTextureSet and set diffuse path.
                void* texset = g_r.allocate(g_r.pool,
                                            BSSHADERTEXSET_SIZEOF,
                                            0, false);
                if (texset) {
                    g_r.texset_ctor(texset);
                    // Populate slots 0 (diffuse), 1 (normal), 2 (specular).
                    // Leaving 1 and 2 null made the shader skip the draw.
                    g_r.texset_set_path(texset, 0,
                        reinterpret_cast<const std::uint8_t*>(
                            DEFAULT_CUBE_DIFFUSE_PATH));
                    g_r.texset_set_path(texset, 1,
                        reinterpret_cast<const std::uint8_t*>(
                            DEFAULT_CUBE_NORMAL_PATH));
                    g_r.texset_set_path(texset, 2,
                        reinterpret_cast<const std::uint8_t*>(
                            DEFAULT_CUBE_SPECULAR_PATH));
                    FW_LOG("[native] inject_cube: texset=%p slots: "
                           "0='%s' 1='%s' 2='%s'",
                           texset,
                           DEFAULT_CUBE_DIFFUSE_PATH,
                           DEFAULT_CUBE_NORMAL_PATH,
                           DEFAULT_CUBE_SPECULAR_PATH);

                    // Bind texset → material (resolves paths, loads
                    // NiSourceTexture* per slot, installs in material).
                    void* material = *reinterpret_cast<void**>(
                        reinterpret_cast<char*>(shader) + BSLSP_MATERIAL_OFF);
                    if (material) {
                        void* arg2 = reinterpret_cast<char*>(shader) + BSLSP_BIND_ARG2_OFF;

                        // FIX #2: force the killswitch byte to 1 around
                        // the bind call so the resolver loop actually
                        // runs and installs our NiSourceTexture handles
                        // at material+72/80/88. Save + restore to avoid
                        // side effects (the byte has no writers in the
                        // binary — default 0 — so restoring to 0 is
                        // semantically identical to how the game left it).
                        std::uint8_t* killswitch = reinterpret_cast<std::uint8_t*>(
                            g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
                        const std::uint8_t saved_ks = *killswitch;
                        *killswitch = 1;

                        FW_LOG("[native] inject_cube: binding material=%p "
                               "texset=%p (killswitch was=%u forced=1)",
                               material, texset, saved_ks);
                        g_r.bind_mat_texset(material, arg2, texset);
                        FW_LOG("[native] inject_cube: bind_mat_texset returned");

                        *killswitch = saved_ks;  // restore

                        // Dump material tex slots post-bind to confirm
                        // the resolver loop installed handles.
                        char* mb = reinterpret_cast<char*>(material);
                        FW_LOG("[native] inject_cube: post-bind material slots: "
                               "+72=%p +80=%p +88=%p +96=%p",
                               *reinterpret_cast<void**>(mb + 72),
                               *reinterpret_cast<void**>(mb + 80),
                               *reinterpret_cast<void**>(mb + 88),
                               *reinterpret_cast<void**>(mb + 96));

                        // --- Triton §10 belt-and-braces manual tex install ---
                        // The bind may have installed default-error handles
                        // at mat+0x48/0x50/0x58 (72/80/88) even with killswitch
                        // forced — or the slots may now contain refs the
                        // render path can't sample. Force-overwrite with
                        // fresh NiSourceTexture* handles from our DDS paths.
                        //
                        // Per tex load API (sub_14217A910): blocking=1 for
                        // synchronous queue, forceSpecialDefault=0, and
                        // emissiveOrNormal=(slot==1) so the normal-map slot
                        // gets normal-map fallback on error instead of
                        // diffuse fallback.
                        const char* tex_paths[3] = {
                            DEFAULT_CUBE_DIFFUSE_PATH,
                            DEFAULT_CUBE_NORMAL_PATH,
                            DEFAULT_CUBE_SPECULAR_PATH,
                        };
                        for (int i = 0; i < 3; ++i) {
                            void* h = nullptr;
                            g_r.tex_load(tex_paths[i], /*blocking*/1,
                                         &h, /*forceSpecialDefault*/0,
                                         /*emissiveOrNormal*/(i == 1 ? 1 : 0),
                                         /*tlsSamplerFlag*/0);
                            FW_LOG("[native] inject_cube: tex_load slot=%d "
                                   "path='%s' handle=%p",
                                   i, tex_paths[i], h);
                            if (!h) continue;

                            void** slot = reinterpret_cast<void**>(mb + 0x48 + 8 * i);
                            // Refcount bump on the new handle (we own 1 ref).
                            _InterlockedIncrement(reinterpret_cast<long*>(
                                reinterpret_cast<char*>(h) + NIAV_REFCOUNT_OFF));
                            // Swap slot; release old if refcount hits 0.
                            void* prev = *slot;
                            *slot = h;
                            if (prev) {
                                long prev_rc = _InterlockedExchangeAdd(
                                    reinterpret_cast<long*>(
                                        reinterpret_cast<char*>(prev) + NIAV_REFCOUNT_OFF),
                                    -1);
                                if (prev_rc == 1) {
                                    void** prev_vt = *reinterpret_cast<void***>(prev);
                                    using DtorFn = void (*)(void*);
                                    auto dtor = reinterpret_cast<DtorFn>(prev_vt[1]);
                                    dtor(prev);
                                }
                            }
                        }
                        FW_LOG("[native] inject_cube: manual tex install done. "
                               "Final slots: +0x48=%p +0x50=%p +0x58=%p",
                               *reinterpret_cast<void**>(mb + 0x48),
                               *reinterpret_cast<void**>(mb + 0x50),
                               *reinterpret_cast<void**>(mb + 0x58));

                        // --- Disable env-map (Skyrim-analog layout) ---
                        //
                        // Web-research 2026-04-23: material vtable 0x2909CD0
                        // is likely BSLightingShaderMaterialEnvmap — its
                        // GetFeature() returns kEnvironmentMap and the render
                        // path engages env sampling from its own dedicated
                        // fields (not shader flags).
                        //
                        // CommonLibSSE layout (Skyrim SE analog):
                        //   mat+0xA0  NiPointer<NiSourceTexture> envTexture
                        //   mat+0xA8  NiPointer<NiSourceTexture> envMaskTexture
                        //   mat+0xB0  float envMapScale
                        //   mat+0xB4  pad
                        //
                        // FO4 may differ slightly but our 0xC0-byte mat has
                        // ctor writes up to +0xB8 (per Triton dossier), so
                        // these fields fit. Zero them — shader can't render
                        // env reflection without env texture or scale.
                        //
                        // Also null slot +0x60 (the 4th tex slot bind may
                        // have set) — independent belt-and-braces.
                        {
                            void** env_slot    = reinterpret_cast<void**>(mb + 0x60);
                            void** env_tex     = reinterpret_cast<void**>(mb + 0xA0);
                            void** env_mask    = reinterpret_cast<void**>(mb + 0xA8);
                            float* env_scale   = reinterpret_cast<float*>(mb + 0xB0);

                            FW_LOG("[native] inject_cube: pre-zero env fields: "
                                   "mat+0x60=%p +0xA0=%p +0xA8=%p +0xB0=%.3f",
                                   *env_slot, *env_tex, *env_mask, *env_scale);

                            // Refcount-safe release at +0x60 (known texture handle).
                            void* prev60 = *env_slot;
                            *env_slot = nullptr;
                            if (prev60) {
                                long prev_rc = _InterlockedExchangeAdd(
                                    reinterpret_cast<long*>(
                                        reinterpret_cast<char*>(prev60) + NIAV_REFCOUNT_OFF),
                                    -1);
                                if (prev_rc == 1) {
                                    void** vt = *reinterpret_cast<void***>(prev60);
                                    using DtorFn = void (*)(void*);
                                    auto dtor = reinterpret_cast<DtorFn>(vt[1]);
                                    dtor(prev60);
                                }
                            }

                            // +0xA0 and +0xA8 may or may not be NiPointers;
                            // the ctor likely leaves them null or with garbage
                            // default-env texture ptrs. Null them straight —
                            // if they were valid handles, we leak 1 refcount
                            // per (trivial for a one-shot cube).
                            *env_tex  = nullptr;
                            *env_mask = nullptr;
                            *env_scale = 0.0f;

                            FW_LOG("[native] inject_cube: env fields zeroed "
                                   "(Skyrim-analog layout)");
                        }
                    } else {
                        FW_WRN("[native] inject_cube: material (shader+0x58) "
                               "is null, skipping bind");
                    }
                    // texset refcount should now be held by the material;
                    // our local ref can be dropped, but for safety we
                    // leave it — a tiny leak, no UAF. Can refine later.
                } else {
                    FW_ERR("[native] inject_cube: BSShaderTextureSet alloc failed");
                }

                // Install shader into cube+0x138. Direct write + bump refcount.
                _InterlockedIncrement(reinterpret_cast<long*>(
                    reinterpret_cast<char*>(shader) + NIAV_REFCOUNT_OFF));
                *reinterpret_cast<void**>(cb + BSGEOM_SHADERPROP_OFF) = shader;
                FW_LOG("[native] inject_cube: shader installed at +0x138=%p "
                       "refcount=%ld",
                       *reinterpret_cast<void**>(cb + BSGEOM_SHADERPROP_OFF),
                       *reinterpret_cast<long*>(
                           reinterpret_cast<char*>(shader) + NIAV_REFCOUNT_OFF));
            } else {
                FW_ERR("[native] inject_cube: BSLSP alloc failed");
            }

            // --- NiAlphaProperty DISABLED for diagnostic (2026-04-23) ---
            //
            // Suspicion: our alpha install writes *(u32*)(alpha+80) = 236
            // but sizeof(NiAlphaProperty) is 0x30 (48 bytes), so offset 80
            // is OUT OF BOUNDS of the allocation — we're corrupting heap
            // padding and the REAL alphaFlags field (at +0x18 per
            // CommonLibF4) stays at whatever sub_1416BD6F0 default sets,
            // which might be 0x6D (blending enabled SRC_ALPHA/ONE_MINUS_
            // SRC_ALPHA) — if pixel alpha evaluates to 0, cube renders
            // fully transparent regardless of diffuse texture.
            //
            // Test: skip alpha install entirely. Cube with NO alpha property
            // should render OPAQUE (engine's default when no alpha prop
            // is attached). If cube becomes VISIBLE → alpha was the bug.
            // If still invisible → alpha wasn't the issue.
            FW_LOG("[native] inject_cube: NiAlphaProperty install DISABLED "
                   "for visibility-vs-alpha diagnostic");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[native] inject_cube: SEH in BSLSP+texture path");
        }

        // 8. Name.
        std::uint64_t name_handle = 0;
        g_r.fs_create(&name_handle, "fw_cube");
        if (name_handle) {
            g_r.set_name(cube, reinterpret_cast<void*>(name_handle));
            g_r.fs_release(&name_handle);
        }

        // 9. Local translate + flags. The offset is +0x60 (NOT +0x54 —
        //    was a long-standing bug: NiMatrix3 is SIMD-padded to 0x30
        //    bytes, so translate follows at +0x30+0x30=+0x60).
        float* trans = reinterpret_cast<float*>(cb + NIAV_LOCAL_TRANSLATE_OFF);
        trans[0] = x;
        trans[1] = y;
        trans[2] = z;
        FW_LOG("[native] inject_cube: local.translate SET at +0x%zX to "
               "(%.1f, %.1f, %.1f)  read-back=(%.1f, %.1f, %.1f)",
               NIAV_LOCAL_TRANSLATE_OFF, x, y, z,
               trans[0], trans[1], trans[2]);
        auto* flags = reinterpret_cast<std::uint64_t*>(cb + NIAV_FLAGS_OFF);
        *flags |= NIAV_FLAG_MOVABLE;

        // 10. Refcount++ then AttachChild to SSN.
        auto* refcount = reinterpret_cast<long*>(cb + NIAV_REFCOUNT_OFF);
        _InterlockedIncrement(refcount);
        FW_LOG("[native] inject_cube: calling AttachChild parent=SSN@%p child=%p",
               parent, cube);
        // FIX #1 (2026-04-23 render diagnosis): reuseFirstEmpty=0 forces
        // the clean APPEND path — engine bumps +0x132 count to 11 and
        // our cube is guaranteed visible to walkers that iterate
        // children[0..count). reuseFirstEmpty=1 was ambiguous: the
        // engine bumps +0x134 (a DIFFERENT counter) and the cube may
        // end up in a slot the render walker never visits.
        g_r.attach_child_direct(parent, cube, /*reuseFirstEmpty=*/0);
        FW_LOG("[native] inject_cube: AttachChild returned; refcount=%ld",
               *refcount);

        // 11. Force world-transform update. The MOVABLE flag tells the
        //     engine to recompute world from local each frame, but on
        //     the FIRST frame after attach, world.translate may still be
        //     (0,0,0) (identity from ctor). We call UpdateDownwardPass
        //     on the parent SSN with a zeroed NiUpdateData to trigger
        //     an immediate recomputation.
        std::uint64_t update_data[4] = { 0, 0, 0, 0 };  // NiUpdateData stub
        FW_LOG("[native] inject_cube: calling UpdateDownwardPass on SSN "
               "to force world transform recomputation");
        g_r.update_downward(parent, update_data);

        // 12. Post-update diagnostics: where is the cube REALLY in worldspace?
        //     If world.translate is still (0,0,0), the renderer places the
        //     cube at worldspace origin and we'd never see it.
        const float* wt = reinterpret_cast<const float*>(cb + NIAV_WORLD_TRANSLATE_OFF);
        const float  ws = *reinterpret_cast<const float*>(cb + NIAV_WORLD_SCALE_OFF);
        const float* lt = reinterpret_cast<const float*>(cb + NIAV_LOCAL_TRANSLATE_OFF);
        // BSGeometry bound is a vec3 center + float radius at +0x120..+0x12C.
        const float* bc = reinterpret_cast<const float*>(cb + 0x120);
        FW_LOG("[native] inject_cube: POST-UPDATE diagnostics:");
        FW_LOG("[native]   local.translate=(%.1f, %.1f, %.1f)",
               lt[0], lt[1], lt[2]);
        FW_LOG("[native]   world.translate=(%.1f, %.1f, %.1f) world.scale=%.3f",
               wt[0], wt[1], wt[2], ws);
        FW_LOG("[native]   bound center=(%.1f, %.1f, %.1f) radius=%.1f",
               bc[0], bc[1], bc[2], bc[3]);

        // Also check SSN child array count to verify the cube is actually
        // in there (AttachChild should have bumped count).
        const auto ssn_child_cnt = *reinterpret_cast<const std::uint16_t*>(
            reinterpret_cast<const char*>(parent) + NINODE_CHILDREN_CNT_OFF);
        const auto ssn_child_cap = *reinterpret_cast<const std::uint16_t*>(
            reinterpret_cast<const char*>(parent) + NINODE_CHILDREN_CAP_OFF);
        FW_LOG("[native]   SSN children: count=%u capacity=%u (cube should be "
               "among these, increment from pre-attach value)",
               ssn_child_cnt, ssn_child_cap);

        *out_cube = cube;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[native] inject_cube: SEH caught exception");
        return false;
    }
}

// ============================================================================
// M6.1 — Material/texture diagnostic dump for the loaded body.
// ============================================================================
//
// After the NIF loader returns, we need to know EXACTLY what state the
// body's BSTriShape materials/textures are in. "Pink" could mean any of:
//   (a) No shaderProperty installed (NIF loader skipped it)
//   (b) Shader installed but material vtable wrong (not a LightingMaterial)
//   (c) Material OK but texture slots all null (paths never bound)
//   (d) Texture slots non-null but pointing at error-default handles
//   (e) Texture slots valid but resources not mounted → default texture
//
// Each case needs a different fix. This walker reads the loaded tree,
// finds BSTriShape/BSDynamicTriShape nodes (vt_rva matches known
// geometry vtables), and for each dumps:
//   - shader pointer + vtable RVA
//   - material pointer + vtable RVA (tells us Base vs Envmap vs Skin vs ...)
//   - 4 texture slot pointers at material +0x48/+0x50/+0x58/+0x60
//   - For each non-null tex handle: NiObjectNET name at +0x10
//     (BSFixedString, deref *(char**)(handle+0x10) gives the c_str)
//
// SEH-caged: if any read hits garbage, we log "<?>" and move on rather
// than crashing the dump.

static constexpr std::uintptr_t kBSTriShapeVt       = 0x0267E948;
static constexpr std::uintptr_t kBSDynamicTriVtA    = 0x0267F758;
static constexpr std::uintptr_t kBSDynamicTriVtB    = 0x0267F948;
// BSSubIndexTriShape — FO4 character bodies use THIS (multi-material
// single-mesh geometry). First live diag v3.2 saw vt_rva=0x2697D40 on
// the lone non-bone child of the BSFadeNode; string "BSSubIndexTriShape"
// exists in .rdata at binary offset 86148. The 58 sibling NiNodes are
// the skeleton bones, and the 59th-slot BSSIT is the actual body mesh.
// BSSIT inherits from BSGeometry so shader/alpha offsets (+0x130/+0x138)
// match what dump_trishape_materials already reads.
static constexpr std::uintptr_t kBSSubIndexTriVt    = 0x02697D40;

static bool is_geometry_vtable_rva(std::uintptr_t vt_rva) {
    return vt_rva == kBSTriShapeVt
        || vt_rva == kBSDynamicTriVtA
        || vt_rva == kBSDynamicTriVtB
        || vt_rva == kBSSubIndexTriVt;
}

// Read a NiObjectNET's name (BSFixedString).
//
// FO4 BSFixedString pool layout (discovered via M7.a skeleton dump
// 2026-04-24, see re/skel_bones.md):
//
//   obj + 0x10         → u64 handle (pointer into BSFixedString pool)
//   pool_entry + 0x00  → u64 next-in-pool ptr (linked list)
//   pool_entry + 0x08  → u64 hash/id
//   pool_entry + 0x10  → u32 length
//   pool_entry + 0x14  → u32 padding/flags
//   pool_entry + 0x18  → char[]   ← c_str starts here
//
// Earlier versions of this reader dereferenced pool_entry directly as
// c_str (returned 8 bytes of the next-in-pool pointer as "garbage
// characters"). Fixed to +0x18.
static const char* try_read_ni_name(void* obj) {
    __try {
        if (!obj) return "<null>";
        const char* pool_entry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(obj) + NIAV_NAME_OFF);
        if (!pool_entry) return "<null>";
        const char* cstr = pool_entry + 0x18;
        return cstr[0] ? cstr : "<empty>";
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return "<AV>";
    }
}

// Hex+ASCII dump of N bytes starting at obj, 32 bytes per line. Used
// to locate embedded path strings / pointers / flags that my typed
// field walkers might be missing (wrong offsets / unknown subclass).
// SEH-caged — truncates on AV rather than crashing.
static void dump_hex_block(void* obj, std::size_t n, int depth,
                           const char* label) {
    if (!obj) {
        FW_LOG("[diag] %*shex[%s] = <null>", depth * 2, "", label);
        return;
    }
    __try {
        const auto* p = reinterpret_cast<const std::uint8_t*>(obj);
        for (std::size_t off = 0; off < n; off += 32) {
            // Build a 32-byte hex + ascii line.
            char line[256];
            int pos = 0;
            // 16 hex pairs
            for (std::size_t i = 0; i < 32 && off + i < n; ++i) {
                pos += std::snprintf(line + pos, sizeof(line) - pos,
                                     "%02X ", p[off + i]);
            }
            // ASCII repr
            pos += std::snprintf(line + pos, sizeof(line) - pos, " |");
            for (std::size_t i = 0; i < 32 && off + i < n; ++i) {
                const std::uint8_t b = p[off + i];
                line[pos++] = (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
            }
            line[pos++] = '|';
            line[pos] = 0;
            FW_LOG("[diag] %*shex[%s+0x%02zX] %s",
                   depth * 2, "", label, off, line);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[diag] %*shex[%s]: SEH on obj=%p",
               depth * 2, "", label, obj);
    }
}

// Dump one BSTriShape's material+texture state. Depth param is for
// indenting the log output so we can see tree structure.
static void dump_trishape_materials(void* tri, int depth) {
    __try {
        char* tb = reinterpret_cast<char*>(tri);
        const char* name = try_read_ni_name(tri);

        void* shader = *reinterpret_cast<void**>(tb + BSGEOM_SHADERPROP_OFF);
        void* alpha  = *reinterpret_cast<void**>(tb + BSGEOM_ALPHAPROP_OFF);
        const auto shader_vt_rva = shader
            ? (reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(shader))
               - g_r.base)
            : 0ull;

        FW_LOG("[diag] %*sBSTriShape=%p name='%s' shader=%p "
               "(vt_rva=0x%llX) alpha=%p",
               depth * 2, "", tri, name, shader,
               static_cast<unsigned long long>(shader_vt_rva), alpha);

        if (!shader) {
            FW_WRN("[diag] %*s  !! NO SHADER installed — NIF parser "
                   "didn't wire one (geom will render with fallback)",
                   depth * 2, "");
            return;
        }

        // v16.2 — read shader+0x10 (BSFixedString) = bgsm material path.
        // From RE dossier: NIF parser stores the .bgsm path here from
        // the BSLightingShaderProperty NIF block. apply_materials walker
        // reads this to load the bgsm. We log it to verify: (a) is the
        // path actually populated? (b) is it a sensible vanilla path?
        // If empty/null, NIF didn't have a material ref → can't resolve.
        // If valid path, apply_materials should have loaded it.
        __try {
            const char* poolEntry = *reinterpret_cast<const char* const*>(
                reinterpret_cast<const char*>(shader) + 0x10);
            const char* bgsmPath = "<null>";
            if (poolEntry) {
                // BSFixedString pool entry: c_str at +0x18 per FO4 layout
                bgsmPath = poolEntry + 0x18;
            }
            FW_LOG("[diag] %*s  shader+0x10 bgsm='%s'",
                   depth * 2, "", bgsmPath);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_LOG("[diag] %*s  shader+0x10 read AV", depth * 2, "");
        }
        if (false) {  // keep below code reachable structurally
            return;
        }

        // Shader vtable telling us which subclass:
        //   BSLightingShaderProperty   vt_rva 0x2909148 (typical)
        //   BSEffectShaderProperty     vt_rva ~0x290xxxx
        //   other variants...
        char* sb = reinterpret_cast<char*>(shader);
        void* material = *reinterpret_cast<void**>(sb + BSLSP_MATERIAL_OFF);
        const auto mat_vt_rva = material
            ? (reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(material))
               - g_r.base)
            : 0ull;

        FW_LOG("[diag] %*s  material@shader+0x58=%p (vt_rva=0x%llX)",
               depth * 2, "", material,
               static_cast<unsigned long long>(mat_vt_rva));

        if (!material) {
            FW_WRN("[diag] %*s    !! NO MATERIAL — shader has null "
                   "material slot (unusable)", depth * 2, "");
            return;
        }

        // Known material vtables (from prior investigation):
        //   0x2909CD0 = BSLightingShaderMaterialEnvmap (the one we
        //               fought in M3.3 — has env-reflection hardcoded)
        //   0x2909xxx = other variants (Base, Skin, ParallaxOcc, etc.)
        // Log the RVA so we know which subclass we got.

        // Texture slots at material +0x48/+0x50/+0x58/+0x60 (per
        // CommonLibSSE-analog layout for BSLightingShaderMaterialBase).
        char* mb = reinterpret_cast<char*>(material);
        for (int i = 0; i < 4; ++i) {
            void* tex = *reinterpret_cast<void**>(mb + 0x48 + 8 * i);
            if (!tex) {
                FW_LOG("[diag] %*s    tex[%d]@+0x%X = null",
                       depth * 2, "", i, 0x48 + 8 * i);
                continue;
            }
            // NiSourceTexture vtable + name (path)
            const auto tex_vt_rva =
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(tex))
                - g_r.base;
            const char* tex_name = try_read_ni_name(tex);
            FW_LOG("[diag] %*s    tex[%d]@+0x%X = %p (vt_rva=0x%llX) name='%s'",
                   depth * 2, "", i, 0x48 + 8 * i, tex,
                   static_cast<unsigned long long>(tex_vt_rva), tex_name);
        }

        // Hex dump of the material's first 0xC0 bytes — if there's a
        // bgsm path or DDS path embedded anywhere in material memory
        // we'll see it as ASCII in the right column. Also dumps the
        // FIRST tex handle's first 0x80 bytes — if NiSourceTexture
        // stores its source DDS path in a field past +0x10, we'll
        // see it.
        FW_LOG("[diag] %*s  material hex dump (0xC0 bytes):",
               depth * 2, "");
        dump_hex_block(material, 0xC0, depth + 1, "mat");

        void* tex0 = *reinterpret_cast<void**>(mb + 0x48);
        if (tex0) {
            FW_LOG("[diag] %*s  tex[0] hex dump (0x80 bytes):",
                   depth * 2, "");
            dump_hex_block(tex0, 0x80, depth + 1, "tex0");
        }

        // Also dump the shader — might hold a reference to the
        // BSShaderTextureSet or a bgsm path at some offset.
        FW_LOG("[diag] %*s  shader hex dump (0xE8 bytes):",
               depth * 2, "");
        dump_hex_block(shader, 0xE8, depth + 1, "shdr");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[diag] %*sdump_trishape_materials: SEH on tri=%p",
               depth * 2, "", tri);
    }
}

// v17 — manual per-geom bgsm load + bind.
// For each BSTriShape we walk to: read shader+0x10 bgsm path, strip
// "Materials\\" prefix if present, call bgsm_load + mat_bind. This
// replicates what apply_materials walker SHOULD do for skinned meshes
// but doesn't (confirmed via Frida trace).
static void manual_bgsm_apply_one(void* tri, int depth) {
    __try {
        char* tb = reinterpret_cast<char*>(tri);
        const char* tri_name = try_read_ni_name(tri);
        void* shader = *reinterpret_cast<void**>(tb + BSGEOM_SHADERPROP_OFF);
        if (!shader) {
            FW_LOG("[bgsm-apply] %*s%s no shader, skip",
                   depth * 2, "", tri_name);
            return;
        }
        const char* poolEntry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(shader) + 0x10);
        if (!poolEntry) {
            FW_LOG("[bgsm-apply] %*s%s no bgsm path (null pool entry)",
                   depth * 2, "", tri_name);
            return;
        }
        // BSFixedString: c_str at pool_entry + 0x18 per FO4 layout.
        const char* full_path = poolEntry + 0x18;
        if (!full_path[0]) {
            FW_LOG("[bgsm-apply] %*s%s empty bgsm path",
                   depth * 2, "", tri_name);
            return;
        }
        // Strip leading "Materials\\" or "materials\\" (loader prepends).
        const char* trimmed = full_path;
        const char* mat_prefixes[] = { "Materials\\", "materials\\" };
        for (const char* pfx : mat_prefixes) {
            std::size_t plen = std::strlen(pfx);
            if (std::strncmp(trimmed, pfx, plen) == 0) {
                trimmed += plen;
                break;
            }
        }

        FW_LOG("[bgsm-apply] %*s%s → bgsm_load('%s')",
               depth * 2, "", tri_name, trimmed);

        void* mat = nullptr;
        const std::uint32_t rc = g_r.bgsm_load(trimmed, &mat, 0);
        if (rc != 0 || !mat) {
            FW_WRN("[bgsm-apply] %*s  bgsm_load FAILED rc=%u mat=%p",
                   depth * 2, "", rc, mat);
            return;
        }
        FW_LOG("[bgsm-apply] %*s  bgsm_load OK mat=%p (skipping mat_bind, "
               "doing refcount-safe direct write to shader+0x58)",
               depth * 2, "", mat);

        // v17.1: bypass mat_bind_to_geom (sub_142169AD0) which AV'd
        // because the 10-slot DDS resolve was skipped. Direct write
        // the loaded material to shader+0x58 (BSLSP material slot).
        // Refcount-safe pattern from M3.3 cube path: bump new, swap,
        // release old.
        void** matSlot = reinterpret_cast<void**>(
            reinterpret_cast<char*>(shader) + BSLSP_MATERIAL_OFF);
        void* old_mat = *matSlot;

        // Bump new mat refcount BEFORE installing.
        _InterlockedIncrement(reinterpret_cast<long*>(
            reinterpret_cast<char*>(mat) + NIAV_REFCOUNT_OFF));
        *matSlot = mat;

        // Release old mat (the placeholder vt 0x290A190).
        if (old_mat) {
            const long prev = _InterlockedExchangeAdd(
                reinterpret_cast<long*>(
                    reinterpret_cast<char*>(old_mat) + NIAV_REFCOUNT_OFF),
                -1);
            if (prev == 1) {
                // Actually was last ref — call vt[1] dtor
                void** old_vt = *reinterpret_cast<void***>(old_mat);
                using DtorFn = void (*)(void*);
                auto dtor = reinterpret_cast<DtorFn>(old_vt[1]);
                FW_LOG("[bgsm-apply] %*s  old_mat refcount hit 0, calling dtor",
                       depth * 2, "");
                dtor(old_mat);
            }
        }
        FW_LOG("[bgsm-apply] %*s  shader+0x58 swap done old=%p new=%p",
               depth * 2, "", old_mat, mat);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[bgsm-apply] SEH on tri=%p", tri);
    }
}

static void manual_bgsm_apply_subtree(void* node, int depth, int max_depth) {
    if (!node || depth > max_depth) return;
    __try {
        const auto vt_rva =
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(node))
            - g_r.base;
        if (is_geometry_vtable_rva(vt_rva)) {
            manual_bgsm_apply_one(node, depth);
            return;
        }
        char* nb = reinterpret_cast<char*>(node);
        void** kids = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        std::uint16_t count = *reinterpret_cast<std::uint16_t*>(
            nb + NINODE_CHILDREN_CNT_OFF);
        if (!kids || count == 0 || count > 256) return;
        for (std::uint16_t i = 0; i < count; ++i) {
            if (kids[i]) manual_bgsm_apply_subtree(kids[i], depth + 1, max_depth);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[bgsm-apply] SEH at depth=%d node=%p", depth, node);
    }
}

// Recursive walk starting from a BSFadeNode/NiNode root. Dives into
// children array at +0x128 (ptr) / +0x132 (count), up to max_depth.
// Calls dump_trishape_materials on each geometry leaf found.
static void dump_body_tree(void* node, int depth, int max_depth) {
    if (!node || depth > max_depth) return;
    __try {
        const auto vt_rva =
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(node))
            - g_r.base;
        const char* name = try_read_ni_name(node);

        if (is_geometry_vtable_rva(vt_rva)) {
            // Leaf-ish: dump material state.
            dump_trishape_materials(node, depth);
            return;
        }

        // NiNode-like: log + recurse into children.
        FW_LOG("[diag] %*sNode=%p vt_rva=0x%llX name='%s'",
               depth * 2, "", node,
               static_cast<unsigned long long>(vt_rva), name);

        char* nb = reinterpret_cast<char*>(node);

        // M7.a DIAG — dump +0x10 (BSFixedString pointer) + deref to see
        // if the c_str is directly at that pointer or behind a header.
        // Then dump +0x60 local.translate (so we can sort bones by Z
        // position: head ~120, chest ~90, pelvis ~60, feet ~0 in FO4
        // skeleton T-pose relative to body root).
        __try {
            void* fs_ptr = *reinterpret_cast<void**>(nb + 0x10);
            const float* t = reinterpret_cast<const float*>(
                nb + NIAV_LOCAL_TRANSLATE_OFF);
            FW_LOG("[diag] %*s  +0x10=%p  local.t=(%.1f, %.1f, %.1f)",
                   depth * 2, "", fs_ptr, t[0], t[1], t[2]);
            if (fs_ptr) {
                // Dump 32 bytes AT fs_ptr — to see BSFixedString pool
                // content. If it's c_str direct: ASCII readable. If it's
                // header + c_str: first bytes are refcount/hash then ASCII.
                dump_hex_block(fs_ptr, 32, depth + 1, "fs_deref");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_LOG("[diag] %*s  fs_deref SEH", depth * 2, "");
        }

        void** children_ptr = *reinterpret_cast<void***>(
            nb + NINODE_CHILDREN_PTR_OFF);
        std::uint16_t count = *reinterpret_cast<std::uint16_t*>(
            nb + NINODE_CHILDREN_CNT_OFF);
        std::uint16_t cap = *reinterpret_cast<std::uint16_t*>(
            nb + NINODE_CHILDREN_CAP_OFF);
        FW_LOG("[diag] %*s  children=%u/%u ptr=%p",
               depth * 2, "", count, cap, static_cast<void*>(children_ptr));

        if (!children_ptr || count == 0) return;

        // Cap iteration defensively — some node types share the
        // +0x128/+0x132 offsets with DIFFERENT semantics (e.g.
        // skinInstance-owning shapes). If count looks absurd, skip.
        if (count > 256) {
            FW_WRN("[diag] %*s  children count=%u looks bogus — skipping",
                   depth * 2, "", count);
            return;
        }

        for (std::uint16_t i = 0; i < count; ++i) {
            void* child = children_ptr[i];
            dump_body_tree(child, depth + 1, max_depth);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[diag] %*sdump_body_tree: SEH at node=%p depth=%d",
               depth * 2, "", node, depth);
    }
}

// ============================================================================
// M5 — NIF-loaded body (MaleBody.nif via public API sub_1417B3E90).
// ============================================================================
//
// Replaces the M2/M3.3 cube-with-hand-built-BSLSP path. After 10+ iterations
// the cube kept rendering with an env-map reflection effect (material vtable
// 0x2909CD0 = BSLightingShaderMaterialEnvmap per web-research), which we
// couldn't disable without deeper RE of the lighting-shader state machine.
//
// Pragmatic pivot: load the actual MaleBody.nif from the engine's own BA2.
// The NIF loader's block-factory path builds BSTriShape + BSLSP + material
// + BSShaderTextureSet + fully-resolved NiSourceTexture handles for every
// mesh in the NIF — no manual wiring, no env-map bullshit. What you get
// back is a BSFadeNode* ready to attach to SSN and track.
//
// V1 ATTEMPT (sub_14026E1C0 "TESModel wrapper") HUNG MAIN THREAD 60s.
// Dossier mis-described that function's args: it expects modelDB (which
// is ResourceManager + 256, NOT ResourceManager directly) and a real
// BSResource::EntryDB::Entry* (NOT a user-allocated NiNode). Wrong args
// put +12 padding into cache-state spin-machine → Sleep(0..1) loop
// forever. See ni_offsets.h §12 for the post-mortem.
//
// V2 FIX: sub_1417B3E90 is the ACTUAL public "load NIF by path" entry.
// Takes 3 args — a path string, an out-slot pointer, and flags. No
// holder allocation, no surrogate struct, no ResourceManager-math. This
// is the "BSModelDB::Demand"-equivalent entry point every vanilla
// caller funnels through for simple async-free loads.
//
//   uint32_t __fastcall sub_1417B3E90(
//       const char*    path,     // ANSI, no "Meshes\\" prefix
//       NiAVObject**   out,      // BYREF, populated on success
//       int64_t        flags);   // 0 = safe default
//
// On success (return 0), *out is a BSFadeNode* with refcount = 1
// (caller owns the reference). On failure (non-zero return OR *out
// null), the NIF parse failed — missing BA2, wrong path, corrupted
// mesh, etc.
//
// Tracking (M3.1/M3.2): pos_update_seh and rotation code operate on
// NiAVObject offsets (+0x60 translate, +0x30 rotate) which BSFadeNode
// inherits. No changes to tracking code required.
bool try_inject_body_nif(float x, float y, float z, void** out_body) {
    *out_body = nullptr;

    __try {
        // 1. Parent — the real SSN captured by the walker.
        void* parent_ssn = get_shadow_scene_node();
        if (!parent_ssn) {
            FW_WRN("[native] inject_body_nif: no SSN captured by walker yet "
                   "— body would not be rendered; skipping");
            return false;
        }
        const auto ssn_vt_rva =
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void**>(parent_ssn))
            - g_r.base;
        FW_LOG("[native] inject_body_nif: parent=SSN@%p (vt_rva=0x%llX)",
               parent_ssn, static_cast<unsigned long long>(ssn_vt_rva));

        // 2. Pool init guard (loader allocates BSFadeNode internally).
        if (*g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
            FW_LOG("[native] inject_body_nif: pool not ready, initializing");
            g_r.pool_init(g_r.pool, g_r.pool_init_flag);
        }

        // 3. Call the loader. ~2-10ms for a body-sized NIF.
        //    Path is relative to Data\, no "Meshes\\" prefix (loader
        //    prepends it internally).
        //
        //    arg3 is a POINTER to a 16-byte opts struct — zero-init
        //    plus flag byte at +0x8. 0x10 = wrap result as BSFadeNode.
        //    We AVOID 0x02 (D3D lock, render-thread-only) and 0x08
        //    (BSModelProcessor post-hook for material swaps — we
        //    want the raw NIF as-authored).
        //
        // v16 ARCHITECTURE: load skeleton.nif FIRST, then attach body+
        // head+hands as children. This matches what vanilla Actor::Load3D
        // does (RE dossier `re/_bone_drive_correct.log` Q4-Q5).
        // Without this, MaleBody.nif's parser creates "_skin" bind-pose
        // STUBS (Pelvis_skin, Belly_skin, etc.) instead of using real
        // skeleton bones. Result: ghost bone names diverged from the
        // player's animated skeleton (only ~14 of 61 matched), which
        // is why every previous attempt at bone-copy produced garbage
        // poses.
        //
        // Loading skeleton.nif first means the body's BSDismemberSkinInstance
        // resolver (sub_1403F85E0) finds REAL "Pelvis", "SPINE1", etc.
        // in the parent skeleton — no _skin fallback. The ghost tree
        // ends up structurally identical to the player's, so bone copy
        // becomes a 1:1 name-keyed memcpy of local rotation+translate.
        // v16: load_nif_and_apply lambda — defined here so we can use
        // it for the skeleton load BEFORE the body load.
        //
        // v16.1 FIX: wrap apply_materials with the texture-resolver
        // KILLSWITCH byte (byte_143E488C0). Default 0, gates the 10-slot
        // texture-resolution loop inside sub_1421C6870. Without this
        // forced ON, .bgsm paths get loaded but DDS resolution skips —
        // resulting in placeholder materials (vt 0x290A190 instead of
        // resolved vt 0x290B640) → pink/purple body. Discovered in M6.1
        // saga, accidentally dropped in v16 lambda refactor. Also use
        // POSTPROC flag (0x18 = FADE_WRAP|POSTPROC) like the original
        // v3 body load.
        std::uint8_t* killswitch_byte = reinterpret_cast<std::uint8_t*>(
            g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
        auto load_nif_and_apply =
            [&](const char* path, const char* label) -> void* {
            void* node = nullptr;
            NifLoadOpts sub_opts{};
            sub_opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;
            FW_LOG("[native] %s: nif_load_by_path path='%s' opts=0x%02X ...",
                   label, path,
                   static_cast<unsigned>(sub_opts.flags));

            const std::uint8_t saved_ks = *killswitch_byte;
            *killswitch_byte = 1;

            const std::uint32_t sub_rc = g_r.nif_load_by_path(
                path, &node, &sub_opts);

            *killswitch_byte = saved_ks;

            if (sub_rc != 0 || !node) {
                FW_WRN("[native] %s: nif_load_by_path FAILED rc=%u node=%p",
                       label, sub_rc, node);
                return nullptr;
            }
            __try {
                const std::uint8_t saved_ks2 = *killswitch_byte;
                *killswitch_byte = 1;
                g_r.apply_materials(node, 0, 0, 0, 0);
                *killswitch_byte = saved_ks2;
                FW_LOG("[native] %s: apply_materials OK node=%p", label, node);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_ERR("[native] %s: apply_materials SEH", label);
            }
            return node;
        };

        // v18 REVERT to v14 architecture (working state):
        // - Body is the root (no skeleton.nif loaded)
        // - Head + hands attached as children of body
        // - apply_materials called via lambda per NIF (textures resolved)
        // - T-pose accepted (animation = M8 future work)
        // The skel_root experiment (v16+) broke textures and didn't fix
        // the underlying skin-binding issue. Reverting.
        // skel_root references below are aliased to body for back-compat
        // with bone_copy code that was using skel_root as ghost root.
        void* skel_root = nullptr;  // set to body after body load

        constexpr const char* kBodyPath =
            "Actors\\Character\\CharacterAssets\\MaleBody.nif";
        void* body = nullptr;
        NifLoadOpts opts{};
        // v4: add POSTPROC (0x08). Diag v3.3 confirmed shader+material
        // are wired by the loader but the 4 texture slots hold "default"
        // empty-name handles — the engine's fallback NiSourceTexture
        // singletons used when texture resolution hasn't run yet. FO4
        // character bodies reference .bgsm (BGSMaterial) files instead
        // of embedding direct DDS paths. The bgsm → DDS resolution is
        // done by BSModelProcessor (qword_1430E0290) when the loader
        // is called with flag 0x08. Previously skipped because we
        // wanted "the raw NIF as-authored"; turns out the raw NIF is
        // intentionally incomplete for bodies — bgsm IS the authored
        // material spec. Flag combo 0x18 = 0x10 FADE_WRAP | 0x08 POSTPROC.
        //
        // If BSModelProcessor is null at our call time, postproc is a
        // no-op and we'll still see pink — in that case we'd need to
        // manually load the bgsm ourselves (RE agent is researching
        // the bgsm loader API in background).
        opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;  // 0x18

        // Log BSModelProcessor state so we can diagnose if POSTPROC
        // is a no-op (null processor) vs actually running.
        void** bsmp_slot = reinterpret_cast<void**>(g_r.base + 0x030E0290);
        void* bsmp = *bsmp_slot;
        FW_LOG("[native] inject_body_nif: BSModelProcessor slot @%p = %p "
               "(POSTPROC flag 0x08 is %s)",
               static_cast<void*>(bsmp_slot), bsmp,
               bsmp ? "ACTIVE" : "NO-OP (null processor)");

        // Force texture-resolver killswitch ON during the load. In
        // the M3.3 cube saga we discovered byte_143E488C0 gates the
        // 10-slot texture-resolution loop inside sub_1421C6870
        // (which the NIF loader's block factories call per-shape for
        // BSLightingShaderProperty + BSShaderTextureSet bind). Default
        // is 0 → skip resolution → pink-checker fallback. First live
        // test of v3 body render confirmed pink body (no textures).
        // Save + restore across the load so we don't leave global
        // state mutated.
        std::uint8_t* killswitch = reinterpret_cast<std::uint8_t*>(
            g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
        const std::uint8_t saved_ks = *killswitch;
        *killswitch = 1;

        // M9.5 — Load via public API (which goes through the cache and may
        // return a BSFadeNode shared with the local player's MaleBody.nif),
        // then DEEP-CLONE the subtree so the ghost owns an independent body.
        // Without the clone the body BSSITF is shared: our skin_swap on the
        // ghost mutates local A's body bones, our body-cull writes APP_CULLED
        // visible to local A, and engine cleanup of either side breaks the
        // other. Same fix-pattern as ghost_attach_armor.
        //
        // ROLLBACK NOTE (2026-05-04 PM): tried `nif_load_worker` direct call
        // for "fresh tree" — failed because the worker requires streamCtx
        // populated by cache resolver sub_1416A6D00 (per dossier line 531:
        // "cache miss → caller calls sub_1417B3480 with `handle`"). Calling
        // worker with streamCtx=0 → AV. Reverted to shared+clone path.
        FW_LOG("[native] inject_body_nif: calling nif_load_by_path "
               "path='%s' out=%p opts=%p opts.flags=0x%02X "
               "(killswitch was=%u forced=1, will deep-clone)",
               kBodyPath, static_cast<void*>(&body),
               static_cast<void*>(&opts),
               static_cast<unsigned>(opts.flags),
               saved_ks);
        void* shared_body = nullptr;
        const std::uint32_t rc = g_r.nif_load_by_path(
            kBodyPath, &shared_body, &opts);
        FW_LOG("[native] inject_body_nif: loader returned rc=%u shared_body=%p",
               rc, shared_body);

        // Restore killswitch — never leave the byte mutated across
        // the call (avoids side-effects on vanilla texture loads
        // happening concurrently on the render thread).
        *killswitch = saved_ks;

        if (rc != 0 || !shared_body) {
            FW_ERR("[native] inject_body_nif: load failed — missing BA2, "
                   "wrong path, or corrupted mesh. rc=%u shared_body=%p",
                   rc, shared_body);
            return false;
        }

        // Deep-clone the body subtree so it's independent from local player's
        // body. The walker handles NiNode/BSFadeNode/BSTriShape/BSSITF +
        // BSSkin::Instance with a manual deep copy (engine's copy ctor AV'd).
        body = clone_nif_subtree(shared_body);
        if (body == shared_body) {
            FW_WRN("[native] inject_body_nif: deep-clone returned shared "
                   "instance (root vt unknown?) — falling back to shared "
                   "body, cache-share bug may re-manifest for body");
        } else {
            FW_LOG("[native] inject_body_nif: deep-cloned body: shared=%p "
                   "clone=%p — independent skin instance, won't mutate "
                   "local player's body NIF", shared_body, body);
            // Drop our +1 ref on the shared instance — engine cache still
            // owns its slot ref so the shared node stays alive for the
            // local player to use.
            __try {
                auto* rcp = reinterpret_cast<long*>(
                    reinterpret_cast<char*>(shared_body) + NIAV_REFCOUNT_OFF);
                _InterlockedDecrement(rcp);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // 4. Sanity check vtable.
        void* body_vt = *reinterpret_cast<void**>(body);
        const auto body_vt_rva =
            reinterpret_cast<std::uintptr_t>(body_vt) - g_r.base;
        FW_LOG("[native] inject_body_nif: body=%p vt_rva=0x%llX "
               "(BSFadeNode expected 0x28FA3E8; NiNode fallback 0x267C888; "
               "BSLeafAnimNode 0x28FA690)",
               body, static_cast<unsigned long long>(body_vt_rva));
        FW_LOG("[native] inject_body_nif: body refcount pre-own-bump=%u",
               *reinterpret_cast<std::uint32_t*>(
                    reinterpret_cast<char*>(body) + NIAV_REFCOUNT_OFF));

        // v18 REVERT: skel_root IS body (no separate skeleton root).
        skel_root = body;
        FW_LOG("[native] inject_body_nif: v18 — skel_root aliased to body@%p",
               body);

        // v18.2 RESTORE: M6.1 apply_materials walker on the BODY.
        // In v6-v14 this was the call that turned the body from pink
        // to textured ("tatuata in fire" solution). In v16.2 I mistakenly
        // removed it thinking it was the redundant "second" call —
        // actually it was the ONLY apply_materials for the body since
        // body uses INLINE load (not lambda). Head/hands worked because
        // their lambda calls apply_materials.
        FW_LOG("[native] inject_body_nif: calling apply_materials on body "
               "(M6.1 fix — restored from v18.2)");
        __try {
            const std::uint8_t saved_ks_body = *killswitch;
            *killswitch = 1;
            g_r.apply_materials(body, 0, 0, 0, 0);
            *killswitch = saved_ks_body;
            FW_LOG("[native] inject_body_nif: apply_materials on body OK");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[native] inject_body_nif: apply_materials body SEH");
        }

        // M8P3 Step 1 — DIAGNOSTIC ONLY. SEH-wrapped at call site so a
        // walker bug doesn't abort the whole body injection (the diag is
        // best-effort; v18.2 baseline must continue regardless).
        FW_LOG("[native] inject_body_nif: M8P3 Step 1 skin diagnostic START");
        int stub_count = -2;
        __try {
            stub_count = fw::native::skin_rebind::diagnose_skin_stubs(body);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[native] inject_body_nif: SEH escaped from skin diag — "
                   "continuing body injection (diag aborted)");
        }
        FW_LOG("[native] inject_body_nif: M8P3 Step 1 skin diagnostic END "
               "(returned %d total _skin stubs)", stub_count);

        // M8P3 Step 2+3 — load skeleton.nif (singleton cache) + swap
        // body skin instance bones with skeleton's named NiNodes.
        // After swap, skin->bones_fb[i] points at REAL skeleton bones
        // (not "_skin" stubs), and skin->skel_root = skeleton root.
        // Driving skel bone transforms now drives the body mesh.
        FW_LOG("[native] inject_body_nif: M8P3 Step 2+3 skel cache + swap START");
        {
            void* skel = fw::native::skin_rebind::get_cached_skeleton();
            if (!skel) {
                constexpr const char* kSkelPath =
                    "Actors\\Character\\CharacterAssets\\skeleton.nif";
                NifLoadOpts skel_opts{};
                skel_opts.flags = NIF_OPT_FADE_WRAP;
                void* fresh_skel = nullptr;
                std::uint32_t skel_rc = 0xDEADBEEF;
                __try {
                    const std::uint8_t saved_ks_skel = *killswitch;
                    *killswitch = 1;
                    skel_rc = g_r.nif_load_by_path(
                        kSkelPath, &fresh_skel, &skel_opts);
                    *killswitch = saved_ks_skel;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    FW_ERR("[native] inject_body_nif: SEH loading skeleton.nif");
                }
                FW_LOG("[native] inject_body_nif: skel load rc=%u fresh=%p",
                       skel_rc, fresh_skel);
                if (skel_rc == 0 && fresh_skel) {
                    __try {
                        fw::native::skin_rebind::dump_skeleton_bones(fresh_skel);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        FW_ERR("[native] inject_body_nif: SEH in skel dump");
                    }
                    fw::native::skin_rebind::cache_or_release_skeleton(fresh_skel);
                    skel = fw::native::skin_rebind::get_cached_skeleton();
                }
            } else {
                FW_LOG("[native] inject_body_nif: skel cache hit %p", skel);
            }

            if (skel) {
                int swapped = -2;
                __try {
                    swapped = fw::native::skin_rebind::swap_skin_bones_to_skeleton(
                        body, skel);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    FW_ERR("[native] inject_body_nif: SEH in skin swap");
                }
                FW_LOG("[native] inject_body_nif: skin swap returned %d",
                       swapped);

                // M8P3.7 — install UpdateWorldData hook + register the
                // test bone.
                //
                // Pipeline (post-M8P3.11 TTD-verified fix):
                //   1. swap_for_geometry replaces bones_fb[i] entries
                //      from body's stubs to matching skel bones.
                //   2. swap_for_geometry ALSO re-caches bones_pri[i]
                //      to point at skel_bone[i]+0x70 (the matrix slot
                //      GPU reads via SRV). [TTD verified working]
                //   3. We register the skel bone so when engine calls
                //      UpdateWorldData(skel_bone) the hook overrides
                //      skel_bone+0x70 = the exact memory bones_pri[i]
                //      points at = what GPU reads.
                //
                // CRITICAL: skel bones in post-swap bones_fb are still
                // named WITH "_skin" suffix (verified via TTD trace —
                // both body NIF and skeleton.nif use _skin suffix on
                // skinning anchor bones). Lookup name = stub name.
                fw::native::skin_rebind::install_world_update_hook(g_r.base);
                void* body_skin = fw::native::skin_rebind::find_body_skin_instance(body);
                void* test_bone = nullptr;
                if (body_skin) {
                    test_bone = fw::native::skin_rebind::find_bone_in_bones_pri(
                        body_skin, "LArm_ForeArm1_skin");
                }
                if (test_bone) {
                    fw::native::skin_rebind::register_ghost_bone(test_bone);
                    FW_LOG("[native] inject_body_nif: registered ghost bone "
                           "LArm_ForeArm1_skin=%p (post-swap skel bone in "
                           "bones_fb[] of skin=%p; bones_pri[i] points at "
                           "this+0x70 = GPU read site verified by TTD)",
                           test_bone, body_skin);
                } else {
                    FW_ERR("[native] inject_body_nif: test_bone LOOKUP FAILED — "
                           "'LArm_ForeArm1_skin' not in body's bones_fb[] "
                           "(skin=%p). Registry empty, hook is no-op.", body_skin);
                }

                // M8P3.15 — populate canonical JOINT list from skel.nif.
                // We use skel (not bones_fb) because skel has the FULL
                // joint hierarchy (LArm_ForeArm1, LLeg_Thigh, etc.) that
                // bones_fb is missing. Engine propagates to skin anchors.
                // This MUST happen post-swap and post-attach so skel
                // hierarchy is stable.
                populate_canonical_from_skel_native(skel);

                // CRITICAL: attach skel as child of body. Without this,
                // skel is a free-floating tree — its bones' world
                // transforms never get updated, so when the engine's
                // skin shader reads bone.world for vertex deform, it
                // gets garbage/origin and the mesh renders far from
                // body (effectively invisible).
                //
                // Attaching skel as body's child means update_downward
                // on body propagates to skel root → skel bones get
                // their world.transform = body.world * skel.local *
                // bone.local. Now skin draws at body position with
                // skel pose driving deformation.
                __try {
                    _InterlockedIncrement(reinterpret_cast<long*>(
                        reinterpret_cast<char*>(skel) + NIAV_REFCOUNT_OFF));
                    g_r.attach_child_direct(body, skel, /*reuseFirstEmpty=*/0);
                    FW_LOG("[native] inject_body_nif: attached skel=%p as "
                           "child of body=%p (propagates world updates)",
                           skel, body);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    FW_ERR("[native] inject_body_nif: SEH attaching skel "
                           "to body");
                }
            } else {
                FW_WRN("[native] inject_body_nif: no skeleton - "
                       "swap skipped, body stays in T-pose");
            }
        }
        FW_LOG("[native] inject_body_nif: M8P3 Step 2+3 END");

        // 4c. M6.3 — Load MaleHead.nif and attach it to the body as a
        //     child NiNode. The body NIF does NOT include a head mesh
        //     (only torso + arms + legs); the head is a separate NIF
        //     that vanilla Actor::Load3D attaches at the HEAD bone of
        //     the skeleton. For a ghost marker we use a fixed local
        //     offset above the body root (neck ≈ +120 FO4 units above
        //     feet origin). Generic "base male" facegen — no per-player
        //     customization yet (M8 TBD).
        //
        // Same recipe as body:
        //   1. nif_load_by_path → BSFadeNode for head
        //   2. apply_materials  → resolve .bgsm (skin, eyes, teeth)
        //   3. set local.translate on head = neck offset
        //   4. attach head as child of body BSFadeNode
        //
        // If any step fails we continue — body+no-head is acceptable
        // degradation compared to no body at all.
        // v9: engine_tracer captured vanilla NIF loads during Museum of
        // Freedom gameplay (Preston, raiders). The REAL head NIF paths are:
        //   Actors\Character\CharacterAssets\BaseMaleHead.nif
        //   Actors\Character\CharacterAssets\FaceParts\MaleHeadRear.nif
        //   Actors\Character\CharacterAssets\BaseMaleHead_faceBones.nif
        //
        // Try BaseMaleHead.nif first — this is the main head mesh
        // (face, eyes, mouth). Load MaleHeadRear.nif as a SECOND child
        // for the back of the skull (hair/skull cap area).
        // BaseMaleHead_faceBones.nif is only needed for facegen morphs
        // (MFG/lip sync) — skip for now, M8 facegen milestone.
        //
        // Note vanilla flags observed in trace: 0xAA (POSTPROC + DYNAMIC
        // + D3D lock + bit 0x80). We stick with 0x10 (FADE_WRAP) as for
        // the body — simpler, proved to work. If render issues appear
        // (head not visible / culled / bound wrong), escalate to 0x2A.
        const char* kHeadPaths[] = {
            "Actors\\Character\\CharacterAssets\\BaseMaleHead.nif",
        };
        constexpr float kNeckOffsetZ = 120.0f;  // FO4 units, empirical

        void* head = nullptr;
        for (const char* hp : kHeadPaths) {
            head = load_nif_and_apply(hp, "inject_head");
            if (head) {
                FW_LOG("[native] inject_head: loaded from path='%s'", hp);
                break;
            }
            FW_LOG("[native] inject_head: path='%s' missed, trying next", hp);
        }
        if (head) {
            __try {
                char* hb = reinterpret_cast<char*>(head);

                // v10 POSITIONING FIX: head NIF vertices are authored
                // in worldspace relative to the HEAD bone's T-pose
                // position (~z+120 above the skeleton root). If we add
                // +120 local.translate here, total = 240 → head floats
                // 2m above body (v9 "palo quasi gol" screenshot).
                //
                // Fix: leave local.translate at whatever the NIF's own
                // root-transform is (don't touch it). The embedded
                // geometry + NIF's root-translate should place the head
                // correctly.
                //
                // IF v10 still misaligned, read back the current head
                // transform post-load and log it — we'll either (a) see
                // the NIF-baked offset and subtract/adjust, or (b) need
                // to do proper skeleton bone attachment.
                float* h_trans = reinterpret_cast<float*>(
                    hb + NIAV_LOCAL_TRANSLATE_OFF);
                FW_LOG("[native] inject_head: NIF-baked local.translate="
                       "(%.1f, %.1f, %.1f) — leaving unchanged (kNeckOffsetZ=%.1f "
                       "was v9 attempt, caused 2m floating head)",
                       h_trans[0], h_trans[1], h_trans[2], kNeckOffsetZ);
                (void)kNeckOffsetZ;  // keep constant around for reference

                // Head flags — MOVABLE not needed (moves with parent),
                // but harmless. We skip it here for minimal changes.
                //
                // Name for forensic.
                std::uint64_t head_name = 0;
                g_r.fs_create(&head_name, "fw_ghost_head");
                if (head_name) {
                    g_r.set_name(head, reinterpret_cast<void*>(head_name));
                    g_r.fs_release(&head_name);
                }

                // v11: Load MaleHeadRear.nif as secondary component of
                // the head. In FO4, BaseMaleHead.nif = FACE (front), and
                // MaleHeadRear.nif = back-of-skull. Both captured in
                // Museum trace. They render together as a complete head.
                //
                // Hair (multiple NIFs per hairstyle, user-selected at
                // character creation) is OMITTED for now — ghost will be
                // bald. Hair customization tracked as M8 milestone.
                //
                // Attach rear as child of HEAD (not body) so it follows
                // head rotation/position cascading. Leave its
                // local.translate untouched (NIF-baked worldspace offset
                // matches the face NIF, so rear should align naturally).
                void* head_rear = load_nif_and_apply(
                    "Actors\\Character\\CharacterAssets\\FaceParts\\"
                    "MaleHeadRear.nif",
                    "inject_headrear");
                if (head_rear) {
                    char* rb = reinterpret_cast<char*>(head_rear);
                    std::uint64_t rear_name = 0;
                    g_r.fs_create(&rear_name, "fw_ghost_headrear");
                    if (rear_name) {
                        g_r.set_name(head_rear,
                                     reinterpret_cast<void*>(rear_name));
                        g_r.fs_release(&rear_name);
                    }
                    _InterlockedIncrement(reinterpret_cast<long*>(
                        rb + NIAV_REFCOUNT_OFF));
                    FW_LOG("[native] inject_headrear: AttachChild parent=head@%p "
                           "rear=%p", head, head_rear);
                    g_r.attach_child_direct(head, head_rear,
                                            /*reuseFirstEmpty=*/0);
                }

                // M8P3.23 — apply skin swap on the head NIF too.
                // Without this the head's BSGeometry skin instance still
                // binds to the head NIF's internal _skin stubs (frozen
                // bind pose). With swap, head bones_fb is rebound to
                // the cached skel.nif's joints (which our pose-rx
                // pipeline writes via canonical). bones_pri re-cache
                // happens inside swap_for_geometry.
                {
                    void* skel_for_head =
                        fw::native::skin_rebind::get_cached_skeleton();
                    if (skel_for_head) {
                        int head_swapped = -2;
                        __try {
                            head_swapped = fw::native::skin_rebind::
                                swap_skin_bones_to_skeleton(head, skel_for_head);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            FW_ERR("[native] inject_head: SEH in skin swap");
                        }
                        FW_LOG("[native] inject_head: skin swap returned %d",
                               head_swapped);
                    }
                }

                // v18 REVERT: head attached to BODY (which now IS skel_root
                // alias). v14 architecture.
                _InterlockedIncrement(reinterpret_cast<long*>(
                    hb + NIAV_REFCOUNT_OFF));
                FW_LOG("[native] inject_head: AttachChild parent=body@%p "
                       "head=%p (+rear if loaded)",
                       body, head);
                g_r.attach_child_direct(body, head, /*reuseFirstEmpty=*/0);
                FW_LOG("[native] inject_head: attached; head refcount=%ld",
                       *reinterpret_cast<long*>(hb + NIAV_REFCOUNT_OFF));

                // v12: publish head ptr so pos_update_seh can apply
                // independent pitch rotation (instead of applying full
                // yaw+pitch+roll to body root which rotates the whole
                // subtree as a rigid tronco).
                g_injected_head.store(head, std::memory_order_release);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_ERR("[native] inject_head: SEH during positioning / "
                       "attach — head may be dangling");
            }
        } else {
            FW_WRN("[native] inject_head: head load returned null — "
                   "body will render headless (neck stump)");
        }

        // 4d. M6.3 — Load MaleHands NIF. In FO4 hands are a SEPARATE
        //     NIF (not part of the body mesh) so that armor/outfits
        //     can cover/replace them independently. For unclothed
        //     body we must load + attach hands ourselves.
        //
        //     Two common paths observed in Archive2:
        //       - MaleHands.nif          (clean base variant)
        //       - DirtyMaleHand.nif      (dirty raider/ghoul variant)
        //     Try clean first, fall back to dirty if the first misses.
        //
        //     Positioning: the hand NIFs are authored with their
        //     transforms relative to the WRIST BONE in the skeleton.
        //     If we attach them as direct children of the body root,
        //     they'll appear at the body origin (feet) — wrong.
        //     Proper fix: walk the skeleton, find LArm_Hand and
        //     RArm_Hand bones, attach per-hand to each bone.
        //     For now: attach at (0, 0, 0) and accept the positioning
        //     defect — live test will show if the NIF's internal
        //     transform puts them at the right place anyway (some
        //     character NIFs bake bone offsets in). If broken, follow
        //     up with bone walker.
        const char* kHandPaths[] = {
            "Actors\\Character\\CharacterAssets\\MaleHands.nif",
            "Actors\\Character\\CharacterAssets\\DirtyMaleHand.nif",
        };
        void* hands = nullptr;
        for (const char* hp : kHandPaths) {
            hands = load_nif_and_apply(hp, "inject_hands");
            if (hands) {
                FW_LOG("[native] inject_hands: loaded from path='%s'", hp);
                break;
            }
            FW_LOG("[native] inject_hands: path='%s' missed, trying next", hp);
        }

        if (hands) {
            __try {
                char* hb = reinterpret_cast<char*>(hands);

                std::uint64_t hands_name = 0;
                g_r.fs_create(&hands_name, "fw_ghost_hands");
                if (hands_name) {
                    g_r.set_name(hands, reinterpret_cast<void*>(hands_name));
                    g_r.fs_release(&hands_name);
                }

                // M8P3.23 — apply skin swap on the hands NIF too.
                // Same rationale as head (see above): rebind hands'
                // bones_fb from internal _skin stubs to the cached
                // skel joints so our pose-rx pipeline drives them.
                {
                    void* skel_for_hands =
                        fw::native::skin_rebind::get_cached_skeleton();
                    if (skel_for_hands) {
                        int hands_swapped = -2;
                        __try {
                            hands_swapped = fw::native::skin_rebind::
                                swap_skin_bones_to_skeleton(hands, skel_for_hands);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            FW_ERR("[native] inject_hands: SEH in skin swap");
                        }
                        FW_LOG("[native] inject_hands: skin swap returned %d",
                               hands_swapped);
                    }
                }

                // v18 REVERT: hands attached to BODY (v14 arch).
                _InterlockedIncrement(reinterpret_cast<long*>(
                    hb + NIAV_REFCOUNT_OFF));
                FW_LOG("[native] inject_hands: AttachChild parent=body@%p "
                       "hands=%p (local offset identity)",
                       body, hands);
                g_r.attach_child_direct(body, hands, /*reuseFirstEmpty=*/0);
                FW_LOG("[native] inject_hands: attached; refcount=%ld",
                       *reinterpret_cast<long*>(hb + NIAV_REFCOUNT_OFF));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_ERR("[native] inject_hands: SEH during attach");
            }
        } else {
            FW_WRN("[native] inject_hands: all hand NIF paths missed — "
                   "body will render handless (wrist stumps)");
        }

        // v16: skel_root is now the published root (its tree contains
        // body + head + hands as children, AND the kinematic skeleton
        // bones — Pelvis, SPINE1, etc. — that the player anim graph
        // drives). bb refers to skel for translate/rotate/SSN-attach.
        char* bb = reinterpret_cast<char*>(skel_root);

        // 5. local.translate + flags on skel_root.
        float* trans = reinterpret_cast<float*>(bb + NIAV_LOCAL_TRANSLATE_OFF);
        trans[0] = x;
        trans[1] = y;
        trans[2] = z;
        auto* flags = reinterpret_cast<std::uint64_t*>(bb + NIAV_FLAGS_OFF);
        *flags |= NIAV_FLAG_MOVABLE;
        FW_LOG("[native] inject_body_nif: skel_root local.translate="
               "(%.1f, %.1f, %.1f) flags|=MOVABLE", x, y, z);

        // 6. Name for forensic (doesn't affect render).
        std::uint64_t name_handle = 0;
        g_r.fs_create(&name_handle, "fw_ghost_skel");
        if (name_handle) {
            g_r.set_name(skel_root, reinterpret_cast<void*>(name_handle));
            g_r.fs_release(&name_handle);
        }

        // 7. AttachChild SSN ← skel_root (whole subtree gets in scene).
        _InterlockedIncrement(reinterpret_cast<long*>(bb + NIAV_REFCOUNT_OFF));
        FW_LOG("[native] inject_body_nif: AttachChild parent=SSN@%p skel=%p",
               parent_ssn, skel_root);
        g_r.attach_child_direct(parent_ssn, skel_root, /*reuseFirstEmpty=*/0);
        FW_LOG("[native] inject_body_nif: attached; skel refcount=%ld",
               *reinterpret_cast<long*>(bb + NIAV_REFCOUNT_OFF));

        // 8. Force world-transform update on the whole subtree.
        std::uint64_t update_data[4] = { 0, 0, 0, 0 };
        g_r.update_downward(skel_root, update_data);

        // 9. Diagnostics.
        const float* wt = reinterpret_cast<const float*>(bb + NIAV_WORLD_TRANSLATE_OFF);
        const float  ws = *reinterpret_cast<const float*>(bb + NIAV_WORLD_SCALE_OFF);
        const auto ssn_child_cnt = *reinterpret_cast<const std::uint16_t*>(
            reinterpret_cast<const char*>(parent_ssn) + NINODE_CHILDREN_CNT_OFF);
        FW_LOG("[native] inject_body_nif: POST-UPDATE local=(%.1f, %.1f, %.1f) "
               "world=(%.1f, %.1f, %.1f) scale=%.3f  SSN.child_count=%u",
               x, y, z, wt[0], wt[1], wt[2], ws, ssn_child_cnt);

        // v16: out_body = skel_root (the tracked node).
        *out_body = skel_root;
        FW_LOG("[native] inject_body_nif: SUCCESS — skeleton.nif (with body+"
               "head+hands as children) attached to SSN. M7 bone-copy "
               "from local player should now match 1:1 by name.");

        // v18 REVERT: removed v17 manual bgsm apply (was AVing on
        // mat_bind_to_geom and then on direct shader+0x58 swap). The
        // per-NIF lambda already applied materials successfully in v14.
        // No more material manipulation here.

        // M6.1 DIAGNOSTIC — walk the loaded tree
        // and dump material+texture state for each geometry leaf.
        // Run AFTER manual bgsm apply so we see post-apply material vtables.
        FW_LOG("[diag] ===== BEGIN body material/texture dump =====");
        dump_body_tree(skel_root, /*depth=*/0, /*max_depth=*/8);
        FW_LOG("[diag] ===== END body material/texture dump =====");

        // v4 DIFFERENTIAL DIAGNOSTIC — compare against a VANILLA
        // BSTriShape from the scene. If it has the same material vtable
        // + empty tex names, then our body is in the right state and
        // pink comes from elsewhere (e.g. a shader flag). If different,
        // we see exactly what's missing.
        //
        // scene_walker captures first_bstri_shape during each walk (it's
        // some random vanilla geometry — rock, terrain, prop). Vanilla
        // renders fine, so its material is PROPERLY textured. Dump it
        // with the same walker to get a known-good reference state.
        void* vanilla = get_first_bstri_shape();
        FW_LOG("[diag] ===== BEGIN VANILLA BSTriShape reference dump =====");
        if (vanilla) {
            FW_LOG("[diag] Comparing against vanilla first_bstri_shape=%p",
                   vanilla);
            dump_trishape_materials(vanilla, /*depth=*/0);
        } else {
            FW_WRN("[diag] No vanilla BSTriShape captured by walker — "
                   "cannot do differential comparison");
        }
        FW_LOG("[diag] ===== END VANILLA dump =====");

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[native] inject_body_nif: SEH caught exception");
        return false;
    }
}

bool try_detach(void* node) {
    if (!node) return true;
    __try {
        // Parents we might have attached to:
        //   - M1 NiNode canary → World SceneGraph
        //   - M2 cube          → real SSN (captured by walker)
        // DetachChild scans the children array by pointer match and is a
        // no-op if the node isn't there, so we can safely try both.
        void* world_sg = *g_r.world_sg_slot;
        void* ssn      = get_shadow_scene_node();

        if (!world_sg && !ssn) {
            FW_WRN("[native] detach: no parent available (shutdown race) "
                   "— skipping");
            return false;
        }
        auto detach = g_r.detach_child;
        void* removed = nullptr;
        // Try SSN first (the M2 cube parent).
        if (ssn) {
            detach(ssn, node, &removed);
            if (removed) {
                FW_LOG("[native] detach: removed=%p from SSN", removed);
                goto do_refcount;
            }
        }
        // Fallback: World SG (the M1 NiNode canary parent).
        if (world_sg) {
            detach(world_sg, node, &removed);
            FW_LOG("[native] detach: removed=%p from World SG (fallback)",
                   removed);
        }
    do_refcount:;

        // Drop our +1 ref. If this was the last, engine frees via vtable[0].
        char* node_bytes = reinterpret_cast<char*>(node);
        auto* refcount = reinterpret_cast<long*>(node_bytes + NIAV_REFCOUNT_OFF);
        const long after = _InterlockedDecrement(refcount);
        FW_LOG("[native] detach: refcount after decrement=%ld "
               "(0 = freed by engine)", after);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[native] detach: SEH caught exception");
        return false;
    }
}

} // namespace

bool inject_debug_node(float x, float y, float z) {
    if (!resolve_once()) return false;

    if (g_injected_node.load(std::memory_order_acquire)) {
        FW_LOG("[native] inject: already injected — skipping");
        return true;
    }

    void* node = nullptr;
    const bool ok = try_inject(x, y, z, &node);
    if (ok && node) {
        g_injected_node.store(node, std::memory_order_release);
        const unsigned n = g_attach_count.fetch_add(1, std::memory_order_relaxed) + 1;
        FW_LOG("[native] inject: SUCCESS node=%p pos=(%.1f, %.1f, %.1f) "
               "attach_count=%u", node, x, y, z, n);
    }
    return ok;
}

void detach_debug_node() {
    void* node = g_injected_node.exchange(nullptr, std::memory_order_acq_rel);
    if (!node) return;
    if (!g_resolved.load(std::memory_order_acquire)) return;
    try_detach(node);
}

void* get_debug_node() {
    return g_injected_node.load(std::memory_order_acquire);
}

unsigned int get_attach_count() {
    return g_attach_count.load(std::memory_order_relaxed);
}

// --- M9 wedge 3 — body geom cache populator ------------------------------
// Self-contained name reader (the seh_read_node_name_w4 helper lives later
// in the file in the weapon-helpers anon ns). Reads NIAV_NAME_OFF=+0x10
// BSFixedString handle, double-derefs to the c_str. Returns true with
// printable ASCII in `buf` on success.
static bool seh_read_name_diag(void* node, char* buf, std::size_t bufsz) {
    if (!node || !buf || bufsz < 2) return false;
    buf[0] = 0;
    std::uint64_t handle = 0;
    __try {
        handle = *reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<char*>(node) + NIAV_NAME_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!handle) return false;
    // Try double-deref first (BSFixedString stores ptr-to-string in slot).
    __try {
        const char* inner = *reinterpret_cast<const char* const*>(handle);
        if (inner) {
            std::size_t i = 0;
            for (; i < bufsz - 1 && inner[i]; ++i) {
                const char c = inner[i];
                if (c < 0x20 || c > 0x7E) { i = 0; break; }
                buf[i] = c;
            }
            buf[i] = 0;
            if (i > 0) return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    // Fallback to single-deref (some FixedStrings are inlined).
    __try {
        const char* s = reinterpret_cast<const char*>(handle);
        std::size_t i = 0;
        for (; i < bufsz - 1 && s[i]; ++i) {
            const char c = s[i];
            if (c < 0x20 || c > 0x7E) { i = 0; break; }
            buf[i] = c;
        }
        buf[i] = 0;
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Recursive walker: returns the FIRST BSSubIndexTriShape (vtable RVA ==
// BSSUBINDEXTRISHAPE_VTABLE_RVA = 0x2697D40) found in `root`'s subtree.
// Self-contained (own SEH cages) so it doesn't depend on the seh_read_*_w4
// helpers defined later in the file (forward-reference would prevent it
// from being callable from inject_debug_cube here at line 2503+).
//
// Used at body inject time (BEFORE any armor attaches, so the tree only
// contains the body NIF). At that moment the first BSSubIndexTriShape is
// unambiguously the body's "BaseMaleBody:0" geometry. The result is
// cached in g_ghost_body_geom; ghost_attach_armor / ghost_detach_armor
// read it via find_ghost_body_geom() to flip NIAV_FLAG_APP_CULLED on.
//
// Why vtable instead of name match: a first iteration (May 2 2026) tried
// `find_node_by_name_w4(root, "BaseMaleBody:0")` and consistently returned
// nullptr in production logs (`body=0000000000000000 set-flag failed`).
// Vtable check at NiAVObject+0 is invariant across runtime — every
// BSSubIndexTriShape shares the same vptr regardless of its name. Settled
// by 2 IDA agents (M9w3_ssitf_vtable_AGENT_A.md / _B.md, HIGH×HIGH).
//
// Diagnostic mode (May 3 2026): now also logs the NAME of every BSSITF
// encountered during the walk. Goal: confirm the cached pointer is actually
// "BaseMaleBody:0" and not some unrelated sub-mesh that happens to share
// the BSSITF vtable. If we find multiple BSSITFs, we still return the
// first hit (preserves old behavior) but log all names so we can adjust
// the heuristic if needed.
static void* find_first_bssitf(void* root, int depth = 0, int max_depth = 32) {
    if (!root || depth > max_depth || g_r.base == 0) return nullptr;

    // Vtable check on this node first.
    std::uintptr_t vt_addr = 0;
    __try {
        vt_addr = *reinterpret_cast<std::uintptr_t*>(root);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }

    if (vt_addr >= g_r.base) {
        const std::uintptr_t vt_rva = vt_addr - g_r.base;
        if (vt_rva == BSSUBINDEXTRISHAPE_VTABLE_RVA) {
            // Diagnostic: log the name of this BSSITF so we know which
            // node we're caching. Helps debug "body cull hides wrong node"
            // suspicions when the visible result looks off.
            char nm[96] = {0};
            (void)seh_read_name_diag(root, nm, sizeof(nm));
            FW_LOG("[body-cache] BSSITF found node=%p depth=%d name='%s'",
                   root, depth, nm);
            return root;
        }
    }

    // Recurse into children. Only valid for NiNode-derived nodes; for
    // BSGeometry leaves the +0x128 / +0x132 reads return garbage which is
    // either filtered by the count<=256 cap or yields a recursive walk
    // that bottoms out via SEH on bad pointers. Either way we tolerate it.
    void** kids = nullptr;
    std::uint16_t count = 0;
    __try {
        char* nb = reinterpret_cast<char*>(root);
        kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        count = *reinterpret_cast<std::uint16_t*>(
            nb + NINODE_CHILDREN_CNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }

    if (!kids || count == 0 || count > 256) return nullptr;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = nullptr;
        __try { k = kids[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!k) continue;
        void* hit = find_first_bssitf(k, depth + 1, max_depth);
        if (hit) return hit;
    }
    return nullptr;
}

// Walk entire body NIF tree and PUSH every BSSubIndexTriShape found into
// `out` (also logs name+addr+depth for each). Used at body inject time to
// build the cache list `g_ghost_body_geoms`. Empirically MaleBody.nif's
// tree contains 2 BSSITFs (May 3 2026 diagnostic dump), and we hide all
// of them when a slot-3 BODY armor is equipped.
//
// Returns total count pushed (caller can also read out->size()).
static int collect_all_bssitf_recursive(void* root, std::vector<void*>* out,
                                         int depth = 0, int max_depth = 32) {
    if (!root || depth > max_depth || g_r.base == 0 || !out) return 0;

    std::uintptr_t vt_addr = 0;
    __try {
        vt_addr = *reinterpret_cast<std::uintptr_t*>(root);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    if (vt_addr >= g_r.base) {
        const std::uintptr_t vt_rva = vt_addr - g_r.base;
        if (vt_rva == BSSUBINDEXTRISHAPE_VTABLE_RVA) {
            char nm[96] = {0};
            (void)seh_read_name_diag(root, nm, sizeof(nm));
            FW_LOG("[body-tree-dump]   BSSITF #%zu node=%p depth=%d name='%s'",
                   out->size(), root, depth, nm);
            out->push_back(root);
            // Don't recurse INTO BSSITF (it's a leaf geometry, no NiNode children).
            return 1;
        }
    }

    void** kids = nullptr;
    std::uint16_t count = 0;
    __try {
        char* nb = reinterpret_cast<char*>(root);
        kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        count = *reinterpret_cast<std::uint16_t*>(
            nb + NINODE_CHILDREN_CNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    if (!kids || count == 0 || count > 256) return 0;

    int total = 0;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = nullptr;
        __try { k = kids[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!k) continue;
        total += collect_all_bssitf_recursive(k, out, depth + 1, max_depth);
    }
    return total;
}

// =====================================================================
// M9.5 — Deep clone of a loaded NIF subtree (cache-share break)
// =====================================================================
//
// PROBLEM: g_r.nif_load_by_path goes through sub_1416A6D00 (cache resolver).
// On a hit, the engine returns the SAME BSFadeNode pointer that the local
// player is using. Sharing means:
//   - skin_swap on the ghost mutates local player's skin too
//   - engine post-equip skin re-bind on local mutates ghost's skin
//   - either side's NIF cleanup may invalidate the other's references
// User-visible effects (procedure tested 2026-05-03):
//   - Local body invisible after local unequip
//   - Ghost armor "detaches" when local equips/unequips
//   - Cycle crash from accumulated state corruption
//
// SOLUTION: after load, walk the tree and produce a deep clone. The clone:
//   - allocates fresh NiNode/BSFadeNode/BSGeometry instances (engine pool)
//   - copies state via memcpy (vtable, transforms, flags, name handle)
//   - resets refcount to 1, parent to NULL
//   - recursively clones children
//   - clones the BSSkin::Instance (via engine's copy ctor sub_1416D7B30)
//     and replaces *(geom + 0x140) so the clone has its own bone bindings
//   - SHARES read-only resources (shaders, materials, textures, vertex
//     buffers in BSGeometry+0x148 — d3d-mapped, expensive to clone).
//
// WHY SHARED RESOURCES ARE OK: shaders/materials/textures are stateless
// from a per-actor perspective. They get bound at draw time but don't
// change between actors. Only the SKIN (bones[] arrays + skel_root)
// gets mutated per-actor; that's what we clone.
//
// LIMITATIONS:
//   - Unknown NiAVObject derivatives are SHARED (logged as warning).
//     If MaleBody.nif contains exotic types, those bones won't be
//     independent — fallback to shared behavior for that subtree.
//   - BSDynamicTriShape / BSEffectShape / etc. fall through to shared.
//   - We don't clone NiTimeController chains (animation controllers);
//     ghost reads pose via direct bone matrix writes, not controllers.
//
// External linkage on clone_nif_subtree is intentional — it's also called
// from try_inject_body_nif (much earlier in this TU); a forward decl in
// the fw::native namespace points at the definitions below.

// Allocate a NiAVObject-pool block of `size` bytes via the engine's
// resolved allocator. Returns nullptr if alloc fails or g_r isn't ready.
static void* engine_pool_alloc(std::size_t size) {
    if (!g_r.allocate || !g_r.pool) return nullptr;
    return g_r.allocate(g_r.pool, size, NINODE_ALIGN, true);
}

// Manual deep clone of a BSSkin::Instance. Layout from M8P3_skin_instance_dossier.txt:
//   +0x00  vtable                                         (share)
//   +0x08  refcount                                       (set to 1)
//   +0x10  bones_fb head ptr (BSTArray)                   (deep clone array)
//   +0x18  bones_fb capacity                              (copy)
//   +0x20  bones_fb count                                 (copy)
//   +0x28  bones_pri head ptr                             (deep clone array)
//   +0x30  bones_pri capacity                             (copy)
//   +0x38  bones_pri count                                (copy)
//   +0x40  boneData ptr (NiPointer<BSSkin::BoneData>)     (share + refbump)
//   +0x48  skel_root ptr (NiPointer<NiAVObject>)          (share + refbump)
//   +0x50..+0xBF  remaining state                         (raw memcpy)
//
// Why MANUAL not engine's copy ctor (sub_1416D7B30): live test 2026-05-03
// showed the engine's copy ctor SEH-AVs in our context — likely because it
// expects the destination to be in a default-initialized state (post default
// ctor sub_1416D7640) and we're handing it raw allocation memory. The manual
// path gives us deterministic control without depending on engine internal
// initialization invariants.
//
// REFCOUNT POLICY: bones_fb / bones_pri entries are NiPointer-style strong
// refs in the engine's intent. We bump each bone's refcount when copying so
// the clone owns its own +1 ref. boneData and skel_root similarly bumped.
// Vertex/index buffers are NOT in the skin instance — they're on BSGeometry,
// shared and OK to keep shared.
void* clone_skin_instance(void* source) {
    if (!source || !g_r.base) return nullptr;
    void* clone = engine_pool_alloc(BSSKIN_INSTANCE_SIZEOF);
    if (!clone) {
        FW_WRN("[clone-skin] alloc 0x%zX failed", BSSKIN_INSTANCE_SIZEOF);
        return nullptr;
    }

    // Step 1: byte-copy the whole struct (vtable + transform matrix +
    // unknown trailing slots). Most fields are POD or vtable pointers
    // that are safe to share/duplicate-point-at.
    __try {
        std::memcpy(clone, source, BSSKIN_INSTANCE_SIZEOF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[clone-skin] memcpy SEH source=%p clone=%p", source, clone);
        return nullptr;
    }

    // Step 2: refcount = 1 (this is OUR exclusive reference).
    __try {
        *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<char*>(clone) + 0x08) = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Step 3: deep-copy bones_fallback array (+0x10 head, +0x20 count).
    // Each entry is a NiAVObject* (the bone the skin reads world matrix
    // from). With shared array, our skin_swap mutations would propagate
    // to source — independence requires a fresh array.
    {
        void**        src_head  = nullptr;
        std::uint32_t src_count = 0;
        __try {
            src_head  = *reinterpret_cast<void***>(
                reinterpret_cast<char*>(source) + 0x10);
            src_count = *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<char*>(source) + 0x20);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (src_head && src_count > 0 && src_count < 1024) {
            void** new_arr = reinterpret_cast<void**>(
                engine_pool_alloc(static_cast<std::size_t>(src_count) * 8));
            if (new_arr) {
                __try {
                    for (std::uint32_t i = 0; i < src_count; ++i) {
                        void* bone = src_head[i];
                        new_arr[i] = bone;
                        if (bone) {
                            // Refcount-bump: the clone holds a strong ref.
                            _InterlockedIncrement(reinterpret_cast<long*>(
                                reinterpret_cast<char*>(bone) + 0x08));
                        }
                    }
                    *reinterpret_cast<void***>(
                        reinterpret_cast<char*>(clone) + 0x10) = new_arr;
                    // Update BSTArray capacity field at +0x18 to match our
                    // allocation. memcpy left this as source's capacity (which
                    // was for source's larger / differently-sized array). If
                    // the engine reads capacity for any operation it'd walk
                    // off the end of our alloc.
                    *reinterpret_cast<std::uint64_t*>(
                        reinterpret_cast<char*>(clone) + 0x18) = src_count;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
    }

    // Step 4: deep-copy bones_primary array (+0x28 head, +0x38 count).
    // Per M8P3 §1: bones_pri[i] holds a pointer DIRECTLY to bone+0x70
    // (the world matrix slot), NOT to the bone NiAVObject itself. So we
    // do NOT refcount-bump these (they're not strong refs in our sense
    // either; they're cached read-points that the GPU consumes). But we
    // DO need a private array so our skin_swap rebinds don't cross over.
    {
        void**        src_head  = nullptr;
        std::uint32_t src_count = 0;
        __try {
            src_head  = *reinterpret_cast<void***>(
                reinterpret_cast<char*>(source) + 0x28);
            src_count = *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<char*>(source) + 0x38);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (src_head && src_count > 0 && src_count < 1024) {
            void** new_arr = reinterpret_cast<void**>(
                engine_pool_alloc(static_cast<std::size_t>(src_count) * 8));
            if (new_arr) {
                __try {
                    for (std::uint32_t i = 0; i < src_count; ++i) {
                        new_arr[i] = src_head[i];  // raw copy, no refbump
                    }
                    *reinterpret_cast<void***>(
                        reinterpret_cast<char*>(clone) + 0x28) = new_arr;
                    // Update BSTArray capacity at +0x30 (parallel to the +0x18
                    // for bones_fallback; sister field for bones_primary).
                    *reinterpret_cast<std::uint64_t*>(
                        reinterpret_cast<char*>(clone) + 0x30) = src_count;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
    }

    // Step 5: refbump shared-pointer slots (+0x40 boneData, +0x48 skel_root).
    // memcpy already duplicated the pointer values; we must add to refcount
    // so the engine doesn't free them when source's owner releases.
    for (std::size_t off : { static_cast<std::size_t>(0x40),
                             static_cast<std::size_t>(0x48) }) {
        __try {
            void* sp = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(clone) + off);
            if (sp) {
                _InterlockedIncrement(reinterpret_cast<long*>(
                    reinterpret_cast<char*>(sp) + 0x08));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    return clone;
}

// Recursively deep-clone a NIF subtree starting at `source`. Returns the
// clone of source, or `source` itself for unknown vtables (shared
// fallback). Children, geometry skin instances are also cloned.
//
// Refcount semantics:
//   - Clone's refcount initialized to 1 (caller owns the ref).
//   - Children: clone's children list points to OUR clones, each refcount 1.
//   - Skin instance: cloned via copy ctor (handles inner refcount bumps).
//   - Shared fields (vtable ptr, name BSFixedString handle, m_kLocal,
//     m_kWorld, etc.) are byte-identical copies — these are POD or
//     interned, so sharing is safe.
//
// max_depth guards against infinite recursion (cyclic graphs shouldn't
// exist in NIF trees but defense-in-depth). Default 32 is generous.
void* clone_nif_subtree_recursive(void* source, int depth, int max_depth);

// 2026-05-06 PM — REPLACED with engine vt[26] dispatch.
//
// Per six independent RE agents (B/C/E/F all converged + D for wrapper
// alloc and A confirming bypass impossible) the NetImmerse Clone slot
// at vtable offset +0xD0 = slot 26 is what FO4's own engine uses
// every time it needs a per-instance copy of a loaded NIF (e.g.
// `sub_140359870` biped rebuilder calls `sub_1416BA8E0(cached, ctx)`
// on the result of `nif_load_by_path` for every actor that equips a
// weapon). Each subclass implements its own clone:
//   - NiNode::CreateClone     = sub_1416BDA20 (alloc 0x140, recurse children)
//   - BSFadeNode::CreateClone = sub_142174C80 (alloc 0x1C0, recurse via sub_1416BDB90)
//   - BSTriShape::CreateClone = sub_1416D99E0 (alloc 0x170, AddRef GPU buffer
//                                              via MEMORY[0x1434380A8] vt[6])
//
// Polymorphic dispatch via vt[26] handles the per-class behaviour
// (including the GPU buffer AddRef on BSTriShape that our previous
// hand-rolled memcpy clone was missing — the symptom we documented as
// "clone walker breaks for BSTriShape — combat armor renders invisible
// when cloned" in the codebase comments was caused by NOT going through
// vt[26]).
//
// The OLD implementation (`clone_nif_subtree_recursive`) is kept as
// dead code below for reference — do not call it any more, it has
// known issues with BSTriShape D3D refs.
//
// Returns the cloned root with refcount=1 (we own one reference).
// On failure (null source / vtable AV / Clone fn null) returns the
// source unchanged — caller MUST be ready for that and not refbump
// blindly. Caller-side: after `nif_load_by_path`'s bumped ref,
// `clone == source` only happens on failure → just keep using source
// 2026-05-06 evening (M9 closure, ATTEMPT #5) — global tracker for every
// base clone we've ever produced. The per-call cleanup paths
// (release_weapon_node, ghost_clear_weapon, ghost_set_weapon Phase 3)
// ALL had the broken `detach_child(known_parent, child)` pattern that
// silently no-op'd when the actual parent ptr had drifted (e.g., engine
// re-parented the clone, or weapon attach point changed). Logs showed
// "detached" successfully but visual accumulation persisted across
// equips — there were stale clones still attached SOMEWHERE in the
// scene graph that our cleanup missed.
//
// Brutal solution: global g_owned_clones set, populated by
// clone_nif_subtree on every successful clone, swept aggressively on
// every set/clear-weapon. The sweep reads each clone's actual parent
// via +0x28 and detaches from there (the only thing that's
// authoritative). Anything not in slot.nif_node gets nuked.
namespace {

std::mutex                     g_owned_clones_mtx;
std::unordered_set<void*>      g_owned_clones;

void track_owned_clone(void* clone) {
    if (!clone) return;
    std::lock_guard lk(g_owned_clones_mtx);
    g_owned_clones.insert(clone);
}

// Remove a clone from the global tracker. Call this BEFORE the per-call
// path refdecs the node, so the tracker doesn't end up with a dangling
// pointer that the next purge would crash on.
void untrack_owned_clone(void* clone) {
    if (!clone) return;
    std::lock_guard lk(g_owned_clones_mtx);
    g_owned_clones.erase(clone);
}

}  // anon namespace

// Forward declarations — definitions are LATER in the file, after
// seh_refcount_dec_armor (~line 3686) and g_ghost_weapon_slot_mtx
// (~line 6519) are available. Calls happen later still
// (release_weapon_node, ghost_set_weapon, ghost_clear_weapon).
void purge_orphan_weapon_clones();

// 2026-05-06 LATE evening (M9 closure, PLAN B) — NiStream serialization
// implementations. See forward declarations + comment block near top of
// file. Recipe from re/nistream_memory_serialize_AGENT.md.

bool nistream_serialize_subtree(void* root, SerializedNif* out) {
    if (!root || !out || g_r.base == 0) return false;
    out->buf = nullptr;
    out->size = 0;

    using ctorFn = void (__fastcall*)(void*);
    using addFn  = void (__fastcall*)(void*, void*);
    using saveFn = bool (__fastcall*)(void*, void**, std::size_t*);
    using dtorFn = void (__fastcall*)(void*);

    constexpr std::uintptr_t NISTREAM_CTOR_RVA = 0x016DCB50;
    constexpr std::uintptr_t NISTREAM_ADD_RVA  = 0x016DCEB0;
    constexpr std::uintptr_t NISTREAM_SAVE_RVA = 0x016DD3B0;
    constexpr std::uintptr_t NISTREAM_DTOR_RVA = 0x016DCD80;
    // Bump from dossier's 1644 to 4096 for safety margin (alignment +
    // any version drift). NiStream can't realistically be larger.
    constexpr std::size_t    NISTREAM_SIZE     = 4096;

    auto NiStream_ctor = reinterpret_cast<ctorFn>(g_r.base + NISTREAM_CTOR_RVA);
    auto NiStream_add  = reinterpret_cast<addFn>(g_r.base + NISTREAM_ADD_RVA);
    auto NiStream_save = reinterpret_cast<saveFn>(g_r.base + NISTREAM_SAVE_RVA);
    auto NiStream_dtor = reinterpret_cast<dtorFn>(g_r.base + NISTREAM_DTOR_RVA);

    alignas(16) std::uint8_t storage[NISTREAM_SIZE];
    std::memset(storage, 0, NISTREAM_SIZE);  // zero-init: ctor may not touch all fields

    FW_DBG("[nistream] entry root=%p storage=%p size=%zu",
           root, static_cast<void*>(storage), NISTREAM_SIZE);

    void*       buf  = nullptr;
    std::size_t size = 0;
    bool ok = false;

    // Granular SEH per step — narrow down which engine call faults.
    bool ctor_ok = false;
    __try {
        NiStream_ctor(storage);
        // 2026-05-06 NIGHT (M9 closure, PLAN B v3) — SWAP vtable to
        // DeepCopyStream after ctor. The agent dossier said "do NOT
        // swap" — that was wrong: engine's own deep-clone helper
        // sub_1416BAA10 SWAPS via `v7[0] = DeepCopyStream::vftable`
        // (verified in funcs_0480.md line 8196 + raw bytes 48 8D 05 81
        // 1A FC 00 at 0x1416BAA30 → vtable RVA 0x02C7C4B8). Without
        // the swap, base NiStream's Load returns 0 (live test confirmed:
        // sender saves OK 185025 B, receiver Load returned ok=0).
        constexpr std::uintptr_t DEEPCOPY_VTABLE_RVA = 0x0267C4B8;
        *reinterpret_cast<void**>(storage) =
            reinterpret_cast<void*>(g_r.base + DEEPCOPY_VTABLE_RVA);
        ctor_ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_ctor / vtable swap");
    }
    if (!ctor_ok) return false;
    FW_DBG("[nistream] ctor + DeepCopyStream vtable swap OK");

    bool add_ok = false;
    __try {
        NiStream_add(storage, root);
        add_ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_add root=%p", root);
    }
    if (!add_ok) {
        __try { NiStream_dtor(storage); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        return false;
    }
    FW_DBG("[nistream] add OK");

    __try {
        ok = NiStream_save(storage, &buf, &size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_save");
        ok = false;
    }
    FW_DBG("[nistream] save returned ok=%d buf=%p size=%zu",
           ok ? 1 : 0, buf, size);

    __try {
        NiStream_dtor(storage);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_dtor");
    }
    FW_DBG("[nistream] dtor OK");

    if (!ok || !buf || size == 0) {
        return false;
    }
    out->buf  = buf;
    out->size = size;
    return true;
}

void* nistream_deserialize_subtree(const void* buf, std::size_t size) {
    if (!buf || size == 0 || g_r.base == 0) return nullptr;

    using ctorFn = void (__fastcall*)(void*);
    using loadFn = bool (__fastcall*)(void*, const void*, std::size_t);
    using dtorFn = void (__fastcall*)(void*);

    constexpr std::uintptr_t NISTREAM_CTOR_RVA = 0x016DCB50;
    constexpr std::uintptr_t NISTREAM_LOAD_RVA = 0x016DD370;
    constexpr std::uintptr_t NISTREAM_DTOR_RVA = 0x016DCD80;
    constexpr std::size_t    NISTREAM_SIZE     = 4096;
    constexpr std::size_t    ROOTS_DATA_OFF    = 864;
    constexpr std::size_t    ROOTS_COUNT_OFF   = 876;

    auto NiStream_ctor = reinterpret_cast<ctorFn>(g_r.base + NISTREAM_CTOR_RVA);
    auto NiStream_load = reinterpret_cast<loadFn>(g_r.base + NISTREAM_LOAD_RVA);
    auto NiStream_dtor = reinterpret_cast<dtorFn>(g_r.base + NISTREAM_DTOR_RVA);

    alignas(16) std::uint8_t storage[NISTREAM_SIZE];
    std::memset(storage, 0, NISTREAM_SIZE);  // zero-init

    FW_DBG("[nistream] deserialize entry buf=%p size=%zu storage=%p",
           buf, size, static_cast<void*>(storage));

    bool ctor_ok = false;
    __try {
        NiStream_ctor(storage);
        // PLAN B v3 — swap vtable to DeepCopyStream (see serialize side
        // for rationale).
        constexpr std::uintptr_t DEEPCOPY_VTABLE_RVA = 0x0267C4B8;
        *reinterpret_cast<void**>(storage) =
            reinterpret_cast<void*>(g_r.base + DEEPCOPY_VTABLE_RVA);
        ctor_ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_ctor / vtable swap (deserialize)");
    }
    if (!ctor_ok) return nullptr;
    FW_DBG("[nistream] deserialize ctor + DeepCopyStream vtable swap OK");

    bool load_ok = false;
    __try {
        load_ok = NiStream_load(storage, buf, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_load buf=%p size=%zu", buf, size);
        load_ok = false;
    }
    FW_DBG("[nistream] deserialize load returned ok=%d", load_ok ? 1 : 0);

    void* root = nullptr;
    if (load_ok) {
        __try {
            void** roots_data = *reinterpret_cast<void***>(storage + ROOTS_DATA_OFF);
            std::uint32_t count = *reinterpret_cast<std::uint32_t*>(storage + ROOTS_COUNT_OFF);
            FW_DBG("[nistream] deserialize roots_data=%p count=%u",
                   static_cast<void*>(roots_data), count);
            if (count > 0 && roots_data && roots_data[0]) {
                root = roots_data[0];
                _InterlockedIncrement(reinterpret_cast<volatile LONG*>(
                    reinterpret_cast<char*>(root) + 8));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_WRN("[nistream] SEH reading roots from stream");
            root = nullptr;
        }
    }
    FW_DBG("[nistream] deserialize root=%p", root);

    __try {
        NiStream_dtor(storage);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH in NiStream_dtor (deserialize)");
    }
    FW_DBG("[nistream] deserialize dtor OK");
    return root;
}

void nistream_free(void* buf) {
    if (!buf || g_r.base == 0) return;
    using freeFn = void (__fastcall*)(void*);
    auto bsScrapFree = reinterpret_cast<freeFn>(g_r.base + 0x01677D20);
    __try {
        bsScrapFree(buf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[nistream] SEH freeing buf=%p", buf);
    }
}

void* clone_nif_subtree(void* source) {
    if (!source || g_r.base == 0) return source;
    // 2026-05-06 evening — THIRD attempt. Triple-agent cross-confirmation
    // (re/vt26_crash_AGENT_A.md + re/niCloneProcess_AGENT_C.md +
    // re/unequip_cleanup_AGENT_B.md). Prior fixes failed because:
    //
    // ATTEMPT #1 (manual memcpy): broke BSTriShape D3D refs.
    // ATTEMPT #2 (vt[26] one-arg): RDX undefined → garbage forwarded
    //   into recursion → deep deref crash.
    // ATTEMPT #3 (vt[26] two-arg `(this, nullptr)`): STILL crashed,
    //   because ctx IS dereferenced at depth 6 (NiTPointerMap::Insert
    //   sub_1416BABF0 reads `*(ctx+8+0x20)` = `*(0x28)` → AV). My prior
    //   "ctx is just forwarded never deref'd" claim was a hallucination
    //   I propagated from incomplete agent input.
    //
    // ROOT CAUSE: vt[26] requires a valid 116-byte (0x74) NiCloneProcess
    // ctx with two embedded NiTPointerHashMap structs (src→clone dedup
    // for shared sub-objects, name dedup) that get LAZILY ALLOCATED
    // during clone — but the function reads ctx fields immediately at
    // entry (e.g., sub_1416BC860 line 9962 reads *(ctx+0x60)).
    //
    // FIX: call the engine helper sub_1416BA800 (RVA 0x16BA800) — a
    // single-arg `(NiObject** ppSrc)` "DeepClone" front-end the engine
    // uses in ~30 places (e.g., sub_14024B610, sub_140453F70). It:
    //   1. Allocates NiCloneProcess on its own stack with engine defaults
    //      (sentinels at +0x18/+0x48, name_mode=-1, suffix='$',
    //       scale=(1,1,1)).
    //   2. Calls vt[26](this, &ctx) → produces clone, refcount +1.
    //   3. Calls vt[32](this, &ctx) → post-clone callback chain
    //      (controller fix-ups, child→parent backlinks via the maps).
    //   4. Calls sub_14033E670 + sub_14033E5C0 → frees the bucket arrays
    //      that the maps allocated during recursion (≈12 KiB per clone
    //      otherwise leaks).
    //   5. Returns the clone, refcount=1, caller owns one ref.
    //
    // 2026-05-06 evening, ATTEMPT #4 — agents A & C BOTH had the
    // calling convention wrong. They claimed `sub_1416BA800` takes
    // `NiObject**` (pointer-to-pointer), but the decomp at
    // funcs_0480.md:8113-8117 reads:
    //     v2 = *a1;                                    // *a1 = vtable
    //     v3 = (*(...)(v2 + 208))(a1, v5);             // call vt[26]
    // For `*a1` to BE the vtable (so `v2+208` points at vt[26]), `a1`
    // must be `NiObject*` directly. The vtable lives at offset 0 of
    // every NiObject. Hex-Rays types `a1` as `__int64*` because of the
    // dereference — but semantically it's `NiObject*`.
    // Confirmed by caller at funcs_0123.md:7462 (`sub_1416BA800(v3)`
    // where v3 is an object pointer, not its address). Live test #3
    // crashed with `&src` because `*(source + 208)` was reading 8 bytes
    // INSIDE the NiObject (at offset 0xD0, which is just data fields),
    // interpreting as a function pointer → wild call → AV.
    using DeepCloneFn = void* (__fastcall*)(void* self);
    constexpr std::uintptr_t SUB_DEEPCLONE_RVA = 0x016BA800ULL;

    DeepCloneFn fn = reinterpret_cast<DeepCloneFn>(g_r.base + SUB_DEEPCLONE_RVA);
    void* clone = nullptr;
    __try {
        clone = fn(source);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[clone-deep] SEH cloning source=%p — falling back to share",
               source);
        return source;
    }
    if (!clone) {
        FW_WRN("[clone-vt26] vt[26] returned null for source=%p — share",
               source);
        return source;
    }
    if (clone == source) {
        // Defensive: shouldn't happen but if vt[26] returned the same
        // pointer (some "shared template" override?), don't pretend
        // we got an independent instance.
        return source;
    }
    FW_DBG("[clone-vt26] source=%p -> clone=%p (engine deep-clone)",
           source, clone);
    // 2026-05-06 LATE evening — DO NOT auto-track here. clone_nif_subtree
    // is called from MANY paths beyond ghost weapons (body, armor, etc.).
    // Auto-tracking caused the purge to nuke ghost body + armor whenever
    // a weapon equip event fired — both clients lost their ghost entirely
    // ("entrambi i ghost scompaiono nel nulla"). Tracking is now opt-in
    // by weapon-specific callers via explicit track_owned_clone(clone).
    return clone;
}

// M9.5 — Detect whether a NIF subtree contains any BSSubIndexTriShape (BSSITF)
// geometry. Used to route armor between CLONE path (VS-style, BSSITF) and
// SHARED+snapshot/restore path (combat / regular armor, BSTriShape only).
//
// Why BSSITF as the discriminator: empirically the deep clone walker
// (memcpy + manual skin clone) works for BSSITF geom (VS attaches and
// renders correctly when cloned), but breaks for BSTriShape geom (combat
// armor renders invisible when cloned — likely the +0x148 NiSkinPartition
// / D3D resource ref needs engine's clone factory sub_1416D5600 which we
// don't replicate). The split keeps each armor type on its working path.
//
// SEH-caged. Returns true on first BSSITF found.
bool tree_has_bssitf(void* root, int depth = 0, int max_depth = 32) {
    if (!root || depth > max_depth || g_r.base == 0) return false;

    std::uintptr_t vt_addr = 0;
    __try {
        vt_addr = *reinterpret_cast<std::uintptr_t*>(root);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    if (vt_addr >= g_r.base) {
        const std::uintptr_t vt_rva = vt_addr - g_r.base;
        if (vt_rva == BSSUBINDEXTRISHAPE_VTABLE_RVA) {
            return true;
        }
    }

    // Recurse into children (NiNode-derived only; geometry leaves don't have).
    void** kids = nullptr;
    std::uint16_t count = 0;
    __try {
        char* nb = reinterpret_cast<char*>(root);
        kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    if (!kids || count == 0 || count > 256) return false;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = nullptr;
        __try { k = kids[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!k) continue;
        if (tree_has_bssitf(k, depth + 1, max_depth)) return true;
    }
    return false;
}

// Legacy detector — kept for reference, not used in current routing logic
// (BSDynamicTriShape detection wasn't reliable for combat armor — it uses
// BSTriShape, not BSDynamicTriShape).
bool tree_has_bsdynamictrishape(void* root, int depth = 0, int max_depth = 32) {
    (void)root; (void)depth; (void)max_depth;
    return false;
}

// M9.5 (2026-05-04 PM) — Detect ANY non-cloneable geometry in subtree:
// BSTriShape, BSDynamicTriShape (both alt vtables). These vtables fall
// through to the walker's "share" branch (clone_nif_subtree_recursive line
// 3079+) because their +0x148 NiSkinPartition / D3D resource reference
// requires engine clone factory sub_1416D5600 to set up correctly — plain
// memcpy duplicates the pointer but engine D3D bindings stay tied to source.
//
// COMBAT ARMOR is the discovered case: contains BSSITF (would route to
// CLONE path via tree_has_bssitf) PLUS BSTriShape decals/sub-pieces
// (which fall through to share inside the walker → invisible render).
// VAULT SUIT is homogeneous BSSITF — no BSTriShape — so clone path is safe.
//
// SEH-caged. Returns true on first non-cloneable geom found.
bool tree_has_bstrishape(void* root, int depth = 0, int max_depth = 32) {
    if (!root || depth > max_depth || g_r.base == 0) return false;

    std::uintptr_t vt_addr = 0;
    __try {
        vt_addr = *reinterpret_cast<std::uintptr_t*>(root);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    if (vt_addr >= g_r.base) {
        const std::uintptr_t vt_rva = vt_addr - g_r.base;
        if (vt_rva == BSTRISHAPE_VTABLE_RVA           ||
            vt_rva == BSDYNAMICTRISHAPE_VTABLE_RVA    ||
            vt_rva == BSDYNAMICTRISHAPE_VTABLE_ALT_RVA)
        {
            return true;
        }
    }

    // Recurse into children.
    void** kids = nullptr;
    std::uint16_t count = 0;
    __try {
        char* nb = reinterpret_cast<char*>(root);
        kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    if (!kids || count == 0 || count > 256) return false;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = nullptr;
        __try { k = kids[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!k) continue;
        if (tree_has_bstrishape(k, depth + 1, max_depth)) return true;
    }
    return false;
}

void* clone_nif_subtree_recursive(void* source, int depth, int max_depth) {
    if (!source || depth > max_depth || !g_r.base) return source;

    // Read source vtable to identify class.
    std::uintptr_t vt = 0;
    __try {
        vt = *reinterpret_cast<std::uintptr_t*>(source);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return source; }
    if (vt < g_r.base) return source;
    const std::uintptr_t vt_rva = vt - g_r.base;

    std::size_t alloc_size = 0;
    bool is_node = false;
    bool is_geom = false;
    switch (vt_rva) {
        case BSFADENODE_VTABLE_RVA:
            alloc_size = BSFADENODE_SIZEOF; is_node = true; break;
        case BSLEAFANIMNODE_VTABLE_RVA:
            alloc_size = BSFADENODE_SIZEOF; is_node = true; break;
        case NINODE_VTABLE_RVA:
            alloc_size = NINODE_SIZEOF;     is_node = true; break;
        // BSTriShape NOT cloned — its +0x148 NiSkinPartition / D3D
        // resource ref is set up by engine's clone factory
        // sub_1416D99E0 via sub_1416D5600 which we don't replicate.
        // Plain memcpy duplicates the pointer but engine-side D3D
        // bindings stay tied to source → cloned BSTriShape renders
        // invisible. Falling through to "share" lets the engine
        // continue managing source's BSTriShape via NiNode parent
        // clone's children list. The periodic re-apply in
        // on_bone_tick_message forces ghost-skel binding on the
        // shared skin every ~250ms — covers combat armor / weapon
        // mods / hairstyles / atomic armor pieces.
        // case BSTRISHAPE_VTABLE_RVA:
        //     alloc_size = BSTRISHAPE_SIZEOF; is_geom = true; break;
        case BSSUBINDEXTRISHAPE_VTABLE_RVA:
            alloc_size = BSSUBINDEXTRISHAPE_SIZEOF;
            is_geom = true; break;
        // BSDynamicTriShape intentionally NOT in switch. Cloning it via
        // raw memcpy duplicates pointer to dynamic vertex CPU/GPU buffer
        // — engine writes per-frame skinned vertices to that buffer, so
        // sharing it would mean the ghost armor renders local-actor's
        // skinning data instead of its own. The hybrid path in
        // ghost_attach_armor detects BSDynamicTriShape via
        // tree_has_bsdynamictrishape() and routes to shared+snapshot
        // (M9.w2 path) instead of clone. If walker reaches a stray
        // BSDynamicTriShape during recursion (shouldn't happen if the
        // detector worked at root, but defensive), it'll fall through
        // to "share" below — the parent NiNode is cloned and points
        // at the source's BSDynamicTriShape, which is acceptable
        // because the M9.w2 snapshot/restore on the parent armor root
        // protects it.
        default:
            // Unknown vtable — share. Logs at DBG to avoid spam.
            FW_DBG("[clone] depth=%d unknown vt_rva=0x%llX node=%p — share",
                   depth,
                   static_cast<unsigned long long>(vt_rva), source);
            return source;
    }

    // Allocate clone block.
    void* clone = engine_pool_alloc(alloc_size);
    if (!clone) {
        FW_WRN("[clone] depth=%d alloc 0x%zX failed for vt_rva=0x%llX",
               depth, alloc_size,
               static_cast<unsigned long long>(vt_rva));
        return source;
    }

    // Byte-copy (SEH in case the source has unmapped pages — unlikely but
    // defensive). All fields including vtable, refcount, name, transforms,
    // flags are copied as-is. We override refcount + parent below.
    __try {
        std::memcpy(clone, source, alloc_size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[clone] memcpy SEH source=%p clone=%p size=0x%zX",
               source, clone, alloc_size);
        return source;
    }

    // Reset refcount to 1 (we own this ref).
    __try {
        *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<char*>(clone) + NIAV_REFCOUNT_OFF) = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Clear parent — the caller (e.g. attach_child) will set this when
    // attaching the clone tree to its new parent (ghost root or sub-NiNode).
    __try {
        *reinterpret_cast<void**>(
            reinterpret_cast<char*>(clone) + NIAV_PARENT_OFF) = nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (is_node) {
        // Read source's children array head + count.
        void** src_kids = nullptr;
        std::uint16_t count = 0;
        __try {
            src_kids = *reinterpret_cast<void***>(
                reinterpret_cast<char*>(source) + NINODE_CHILDREN_PTR_OFF);
            count = *reinterpret_cast<std::uint16_t*>(
                reinterpret_cast<char*>(source) + NINODE_CHILDREN_CNT_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (src_kids && count > 0 && count <= 256) {
            // Engine subsequently calls attach_child to add MORE children
            // (skeleton root, head, hands etc. attached after body load).
            // Each attach grows the array if capacity is exceeded. To avoid
            // buffer overflow on grow, allocate with HEADROOM and set the
            // capacity field at +0x130 to match. 16 extra slots covers
            // every observed attach pattern (max 5-6 extra in practice).
            const std::uint16_t cap_with_headroom =
                static_cast<std::uint16_t>(count + 16);
            void** new_kids = reinterpret_cast<void**>(
                engine_pool_alloc(static_cast<std::size_t>(cap_with_headroom)
                                  * 8));
            if (new_kids) {
                // Zero out the trailing slots so engine's count-based
                // iteration doesn't wander off the end if it ever does
                // capacity-bound walks (unlikely but defensive).
                for (std::uint16_t i = count; i < cap_with_headroom; ++i) {
                    new_kids[i] = nullptr;
                }
                for (std::uint16_t i = 0; i < count; ++i) {
                    void* src_child = nullptr;
                    __try { src_child = src_kids[i]; }
                    __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

                    void* cloned_child =
                        clone_nif_subtree_recursive(src_child,
                                                     depth + 1, max_depth);
                    new_kids[i] = cloned_child;

                    if (cloned_child && cloned_child != src_child) {
                        // Set clone-child's parent to OUR clone.
                        __try {
                            *reinterpret_cast<void**>(
                                reinterpret_cast<char*>(cloned_child)
                                + NIAV_PARENT_OFF) = clone;
                        } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
                // Replace clone's children pointer with our array AND
                // update the capacity field. Without the capacity update,
                // engine's attach_child writes past the end of our smaller
                // array (we observed this as `[ERR] inject_body_nif: SEH
                // attaching skel to body` on cloned body).
                __try {
                    *reinterpret_cast<void***>(
                        reinterpret_cast<char*>(clone)
                        + NINODE_CHILDREN_PTR_OFF) = new_kids;
                    *reinterpret_cast<std::uint16_t*>(
                        reinterpret_cast<char*>(clone)
                        + NINODE_CHILDREN_CAP_OFF) = cap_with_headroom;
                    // count stays as `count` (already memcpy'd from source
                    // earlier; we don't want to change live count here).
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
    }

    if (is_geom) {
        // Clone the BSSkin::Instance so this geometry has independent
        // bone bindings. Without this, modifying clone's bones[] would
        // also modify source's bones[] (skin instance is the cache-shared
        // mutable state per the bug analysis).
        void* src_skin = nullptr;
        __try {
            src_skin = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(source)
                + BSGEOMETRY_SKIN_INSTANCE_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (src_skin) {
            void* skin_clone = clone_skin_instance(src_skin);
            if (skin_clone) {
                __try {
                    *reinterpret_cast<void**>(
                        reinterpret_cast<char*>(clone)
                        + BSGEOMETRY_SKIN_INSTANCE_OFF) = skin_clone;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
            // If skin_clone failed, the geom clone keeps the source's skin
            // pointer (shared) — degraded but not broken.
        }
    }

    return clone;
}

// --- M2.2 API --------------------------------------------------------------

bool inject_debug_cube(float x, float y, float z) {
    if (!resolve_once()) return false;

    if (g_injected_cube.load(std::memory_order_acquire)) {
        FW_LOG("[native] inject_cube: already injected — skipping");
        return true;
    }

    // M5 pivot: instead of the hand-built BSTriShape cube that kept
    // showing env-map reflections (M3.3 saga), load MaleBody.nif
    // natively. Dossier: re/stradaB_nif_loader_api.txt §9 Path-A.
    //
    // g_injected_cube now stores the BSFadeNode* root of the body
    // subtree. The name is a historical artifact — the tracking /
    // rotation / detach code all operate on NiAVObject base offsets
    // which BSFadeNode inherits, so nothing downstream cares.
    //
    // (void)try_inject_cube; // kept in source for fallback during bring-up;
    //                        // flip this comment + the call site to revert.
    void* body = nullptr;
    const bool ok = try_inject_body_nif(x, y, z, &body);
    if (ok && body) {
        g_injected_cube.store(body, std::memory_order_release);
        FW_LOG("[native] inject_cube (M5 body): SUCCESS body=%p "
               "pos=(%.1f, %.1f, %.1f)", body, x, y, z);

        // M9 wedge 3 (2026-05-02): populate the body geometry cache HERE,
        // BEFORE flush_pending_armor_ops below. Reason: the flush replays
        // queued equip events which call ghost_attach_armor → body_cull_*
        // → find_ghost_body_geom (cache reader). If the cache isn't ready
        // when the first replayed equip arrives, body cull silently no-ops
        // (we logged this as `body=0000000000000000 set-flag failed` in
        // the May 2 first run). The walk is on the body NIF tree at the
        // moment NO armor is attached → first BSSubIndexTriShape hit is
        // unambiguously the body geom.
        // M9 wedge 3 (May 3 2026): walk the body tree and CACHE EVERY
        // BSSubIndexTriShape found. Live diagnostic showed MaleBody.nif's
        // loaded form contains 2 BSSITFs (presumably body + hands or
        // body + face). Caching all of them ensures the body cull set
        // hides them ALL when a slot-3 BODY armor is equipped — without
        // this, the unhidden second BSSITF was rendering as floating
        // hand/face geometry under the suit (visible artifacts post-cycle).
        FW_LOG("[body-tree-dump] enumerate ALL BSSITF in body tree:");
        std::vector<void*> body_geoms;
        body_geoms.reserve(8);
        const int total_bssitf = collect_all_bssitf_recursive(body, &body_geoms);
        FW_LOG("[body-tree-dump] DONE — total BSSITF in tree: %d", total_bssitf);

        {
            std::lock_guard lk(g_body_cull_mtx);
            g_ghost_body_geoms = std::move(body_geoms);
        }
        if (total_bssitf == 0) {
            FW_WRN("[native] inject_cube: NO BSSubIndexTriShape found in body "
                   "tree — M9.w3 body cull will no-op (verify "
                   "BSSUBINDEXTRISHAPE_VTABLE_RVA=0x%llX still matches binary)",
                   static_cast<unsigned long long>(BSSUBINDEXTRISHAPE_VTABLE_RVA));
        } else {
            FW_LOG("[native] inject_cube: cached %d body geom(s) for cull "
                   "(vt_rva=0x%llX)", total_bssitf,
                   static_cast<unsigned long long>(BSSUBINDEXTRISHAPE_VTABLE_RVA));
        }

        // M9 wedge 2: drain any equip events that arrived while the
        // ghost wasn't yet ready (boot-time race with peer's B8
        // force-equip-cycle). With g_injected_cube now non-null, the
        // replayed ghost_attach_armor / ghost_attach_weapon calls will
        // succeed. Both flushes are independent; armor flush handles
        // ARMO forms, weapon flush handles WEAP forms (boot-race may
        // queue the same form to BOTH queues — see ghost_attach_weapon
        // header — which self-corrects: wrong-type flush silently fails,
        // right-type flush succeeds).
        flush_pending_armor_ops();
        flush_pending_weapon_ops();
    } else {
        FW_WRN("[native] inject_cube (M5 body): failed — see preceding log");
    }
    return ok;
}

void detach_debug_cube() {
    void* cube = g_injected_cube.exchange(nullptr, std::memory_order_acq_rel);
    // M9 wedge 3: invalidate body geom cache + contributor set in lockstep
    // with cube destruction. The next inject_debug_cube will repopulate the
    // body geoms list from the fresh body NIF tree; contributor set must
    // start empty so the first replayed BODY-armor attach correctly
    // transitions empty→non-empty and applies the cull flag.
    {
        std::lock_guard lk(g_body_cull_mtx);
        g_ghost_body_geoms.clear();
        g_body_cull_contributors.clear();
    }
    if (!cube) return;
    if (!g_resolved.load(std::memory_order_acquire)) return;
    try_detach(cube);
}

// === M9 wedge 2 — armor visual sync on the ghost body =====================
//
// Pipeline summary (full rationale in scene_inject.h "M9 wedge 2" comment
// block + offsets.h "M9 wedge 2" RVA + struct documentation):
//
//   Receiver gets EQUIP_BCAST(peer_id, item_form_id, kind) → enqueues
//   PendingEquipOp → posts FW_MSG_EQUIP_APPLY → main thread WndProc
//   drains queue → calls ghost_attach_armor / ghost_detach_armor here.
//
//   ghost_attach_armor:
//     1. lookup_by_form_id(item_form_id) → TESObjectARMO*
//     2. Walk armor.addons[0].arma → TESModel(male 3rd) → BSFixedString → c_str
//     3. nif_load_by_path(path) → NiNode* armor_root
//     4. apply_materials(armor_root) — texture/material resolve via BSModelProcessor
//     5. attach_child_direct(g_injected_cube, armor_root)
//     6. Track in g_attached_armor[peer_id][form_id] = armor_root for later detach
//
//   ghost_detach_armor:
//     1. Look up armor_root in tracking map
//     2. detach_child(g_injected_cube, armor_root)
//     3. Drop refcount (engine bumped on load; we own the +1)
//     4. Remove from tracking map
// MSVC C2712 workaround: __try cannot live in a function with C++ unwind
// objects (std::lock_guard, std::unordered_map ops). These POD-only
// wrappers isolate the SEH calls so the higher-level ghost_attach_armor
// / ghost_detach_armor (which use std:: types) can drive them safely.
namespace {
std::uint32_t seh_nif_load_armor(NifLoadByPathFn fn,
                                  const char* path,
                                  void** out_node,
                                  NifLoadOpts* opts) {
    __try {
        return fn(path, out_node, opts);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xDEADBEEFu;
    }
}
// M9.5 — Cache-bypass NIF load via worker (sub_1417B3480). Returns
// true if the call completed without AV (whether *out_node is non-null
// is up to caller to check). Worker returns DWORD* TLS scratch that we
// ignore; the actual result lives in *out_node with refcount already
// incremented. Per stradaB_nif_loader_api.txt §10 worker signature.
bool seh_nif_load_worker_fresh(NifLoadWorkerFn fn,
                                const char*     path,
                                NifLoadOpts*    opts,
                                void**          out_node) {
    *out_node = nullptr;
    __try {
        (void)fn(/*stream_ctx*/ 0, path, opts, out_node, /*user_ctx*/ 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
void seh_apply_materials_armor(ApplyMaterialsWalkerFn fn, void* node) {
    __try { fn(node, 0, 0, 0, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
bool seh_attach_child_armor(AttachChildFn fn, void* parent, void* child) {
    __try { fn(parent, child, 0); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_detach_child_armor(DetachChildFn fn, void* parent, void* child,
                             void** out_removed) {
    __try { fn(parent, child, out_removed); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
long seh_refcount_dec_armor(void* node) {
    __try {
        auto* rc = reinterpret_cast<long*>(
            reinterpret_cast<char*>(node) + NIAV_REFCOUNT_OFF);
        return _InterlockedDecrement(rc);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -999; }
}
// SEH-protected lookup_by_form_id call (POD: takes a fn ptr + u32, returns ptr).
void* seh_lookup_form(void* (__fastcall* fn)(std::uint32_t),
                       std::uint32_t form_id) {
    __try { return fn(form_id); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
// SEH-protected struct walk for ARMO addon array meta.
// Returns true if read succeeded; out args populated.
bool seh_read_armo_addons(void* tes_form, void*** out_array,
                           std::uint32_t* out_count) {
    __try {
        auto bytes = reinterpret_cast<char*>(tes_form);
        *out_array = *reinterpret_cast<void***>(
            bytes + offsets::TESOBJECTARMO_ADDON_ARR_OFF);
        *out_count = *reinterpret_cast<std::uint32_t*>(
            bytes + offsets::TESOBJECTARMO_ADDON_COUNT_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out_array = nullptr;
        *out_count = 0;
        return false;
    }
}
// SEH-protected ARMA[i] entry → ARMA pointer extraction.
void* seh_read_arma_at(void** addon_array, std::uint32_t index) {
    __try {
        auto entry = reinterpret_cast<char*>(addon_array) +
                     index * offsets::TESOBJECTARMO_ADDON_ENTRY_STRIDE;
        return *reinterpret_cast<void**>(
            entry + offsets::TESOBJECTARMO_ADDON_ARMA_PTR_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
// SEH-protected ARMO biped-slot bitmask read (M9.w3 — 2026-05-02).
// ARMO+0x1E8 = uint32 bipedObjectSlots, see offsets.h §M9 wedge 3 for
// evidence chain (HIGH×HIGH consensus from 2 independent IDA agents).
// Returns true on success with mask in *out_mask. False if the form is
// not ARMO / pointer is bad — caller treats as "no slot info, skip hide".
bool seh_read_armo_biped_slots(void* tes_form, std::uint32_t* out_mask) {
    __try {
        *out_mask = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<char*>(tes_form) +
            offsets::TESOBJECTARMO_BIPED_SLOTS_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out_mask = 0;
        return false;
    }
}
// SEH-protected ARMO default priority read (M9.w2 PROPER, May 3 2026).
// ARMO+0x2A6 = uint16 default priority. The engine uses this when no
// OMOD-modified InstanceData is attached. See offsets.h §"M9 wedge 2
// PROPER — ARMA priority selection" for evidence chain.
bool seh_read_armo_default_priority(void* tes_form, std::uint16_t* out_prio) {
    __try {
        *out_prio = *reinterpret_cast<std::uint16_t*>(
            reinterpret_cast<char*>(tes_form) +
            offsets::TESOBJECTARMO_DEFAULT_PRIORITY_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out_prio = 0;
        return false;
    }
}
// SEH-protected per-addon-entry priority read (uint16 at addon_entry+0).
// addon_array points at ARMO+0x2A8; each entry is 16 bytes; index `i` is
// at addon_array + i*0x10. Priority is the WORD at start of each entry,
// ARMA* is at +8 within the entry.
bool seh_read_addon_entry_priority(void** addon_array, std::uint32_t index,
                                    std::uint16_t* out_prio) {
    __try {
        auto entry = reinterpret_cast<char*>(addon_array) +
                     index * offsets::TESOBJECTARMO_ADDON_ENTRY_STRIDE;
        *out_prio = *reinterpret_cast<std::uint16_t*>(
            entry + offsets::TESOBJECTARMO_ADDON_ENTRY_PRIORITY_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out_prio = 0;
        return false;
    }
}
// SEH-protected TESModel.path BSFixedString handle read at given offset.
// Generic: caller probes multiple candidate offsets to find which one
// holds the actual male 3rd-person model. Initial guess (0xD0) was
// wrong — the live ARMA struct in 1.11.191 next-gen has different
// layout; this generic helper lets us iterate at runtime.
void* seh_read_arma_path_handle_at(void* arma, std::size_t component_off) {
    __try {
        auto model_obj = reinterpret_cast<char*>(arma) + component_off;
        return *reinterpret_cast<void**>(
            model_obj + offsets::TESMODEL_PATH_BSFIXEDSTR_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
// Diagnostic: dump 8 bytes (qword) at arma+offset for layout RE.
std::uint64_t seh_read_arma_qword_at(void* arma, std::size_t off) {
    __try {
        return *reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<char*>(arma) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
// SEH-protected BSFixedString c_str pointer compute.
const char* seh_bsfs_cstr(void* bsfs_handle) {
    __try {
        return reinterpret_cast<const char*>(bsfs_handle) +
               offsets::BSFIXEDSTRING_CSTR_OFF;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
// SEH-protected strnlen (the result of seh_bsfs_cstr might point at an
// arbitrary memory region — we cannot trust regular strlen because the
// string may not be null-terminated within page bounds).
std::size_t seh_strnlen_armor(const char* s, std::size_t maxlen) {
    if (!s) return 0;
    __try {
        std::size_t n = 0;
        while (n < maxlen && s[n]) ++n;
        return n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
// Case-insensitive substring search (POD-only, no std::string).
// Used to filter "Female" / "_F." patterns in armor NIF paths so we
// can prefer male variants (the M8P3 ghost uses MaleBody.nif → male
// armor bones align, female don't → female armor renders T-pose).
bool seh_path_contains_ci(const char* hay, std::size_t hay_len, const char* needle) {
    if (!hay || !needle) return false;
    std::size_t nlen = 0;
    while (needle[nlen]) ++nlen;
    if (nlen == 0 || nlen > hay_len) return false;
    auto tolower_ascii = [](char c) -> char {
        return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
    };
    for (std::size_t i = 0; i + nlen <= hay_len; ++i) {
        std::size_t j = 0;
        for (; j < nlen; ++j) {
            if (tolower_ascii(hay[i + j]) != tolower_ascii(needle[j])) break;
        }
        if (j == nlen) return true;
    }
    return false;
}
// Find the LAST path-separator ('\' or '/') and return the index of the
// first byte AFTER it (= start of the basename). Returns 0 if no
// separator found. Doesn't read past `len`.
std::size_t basename_index(const char* path, std::size_t len) {
    if (!path) return 0;
    std::size_t last = 0;
    for (std::size_t i = 0; i < len; ++i) {
        if (path[i] == '\\' || path[i] == '/') last = i + 1;
    }
    return last;
}

// Returns true if `path` looks like a FEMALE armor NIF path. Three patterns:
//   1. Substring "female" anywhere (case-insensitive)
//   2. Suffix "_f.nif" / "_f.tri" (case-insensitive)
//   3. BASENAME prefix `F<UpperCase>` — Bethesda's `F<Part>` naming for
//      female-mesh variants (e.g. `FToroso_Heavy_1.nif`, `FArm_Mid.nif`,
//      `FLeg_Heavy.nif`). The capital letter after `F` distinguishes from
//      neutral names like `Foliage.nif` or `FlipBook.nif`.
//
// Note for #3: this also matches things like `FistMesh.nif` (FNeutralWord)
// theoretically, but in practice no FO4 vanilla armor has such a name —
// the convention is well-followed (`FArm`, `FLeg`, `FTorso`, `FHelmet`,
// `FPelvis`, etc.). False positives ship as fallbacks (still valid path,
// just deprioritized).
bool path_is_female_variant(const char* path, std::size_t len) {
    if (!path || len == 0) return false;
    if (seh_path_contains_ci(path, len, "female")) return true;
    if (seh_path_contains_ci(path, len, "_f.nif")) return true;
    if (seh_path_contains_ci(path, len, "_f.tri")) return true;

    // Pattern 3: basename starts with 'F' followed by:
    //  - another UPPERCASE letter (FArm, FLeg, FTorso) — old convention
    //  - or an underscore (F_Torso, F_Helmet, F_Torso_Lite) — new convention
    //
    // This used to require 2nd-char uppercase only, which missed ALL the
    // newer Combat Armor / DLC mesh names like `F_Torso_Lite.nif` →
    // resolver picked them over `M_Torso_*` of equal score → ghost rendered
    // a female mesh on a male skeleton → wild deformation. Discovered May 3
    // 2026 from Combat Armor (form 0x11D3C3) live test where the 6
    // candidates (F/M × Lite/Mid/Heavy) all scored 0 and the FIRST one
    // (F_Torso_Lite) won by enumeration order.
    //
    // The `F_` extension is safe: no FO4 vanilla armor mesh starts with
    // `F_` and is intended for males. The convention is well-followed.
    const std::size_t bi = basename_index(path, len);
    if (bi + 1 < len) {
        const char c0 = path[bi];
        const char c1 = path[bi + 1];
        if ((c0 == 'F' || c0 == 'f') &&
            ((c1 >= 'A' && c1 <= 'Z') || c1 == '_')) {
            return true;
        }
    }
    return false;
}
// Returns true if `path` is a 1st-person variant — those are arms-only
// meshes used for FPS view, NOT the full body NIF we want for the
// 3rd-person ghost. Common naming: "1stPerson", "_1st", "_1stperson".
bool path_is_first_person(const char* path, std::size_t len) {
    if (!path || len == 0) return false;
    return seh_path_contains_ci(path, len, "1stperson") ||
           seh_path_contains_ci(path, len, "1st_person") ||
           seh_path_contains_ci(path, len, "_1st.");
}
// Returns true if `path` is the "_faceBones" variant — these meshes use
// the FACE/HEAD bone hierarchy (eyebrow, lip, eyelid, jaw, etc.) which
// our M8P3 ghost's skel.nif does NOT contain (body skel only, ~80 joints).
// Loading these results in `swap_skin` failed=50+ → vertices stuck at
// bind pose → mesh renders distorted / out-of-place.
//
// Vanilla armor with face anim (gas masks, glasses) typically also ships
// a SIMPLER variant without face bones (e.g. `MGasMask.nif` vs
// `MGasMask_faceBones.nif`). We deprioritize the face-bones variant so
// the simpler one is picked.
bool path_is_face_bones(const char* path, std::size_t len) {
    if (!path || len == 0) return false;
    return seh_path_contains_ci(path, len, "facebones") ||
           seh_path_contains_ci(path, len, "_faceBones");  // exact case
}
// Compute selection score for an armor NIF path. Higher = better.
//   MALE 3rd-person                → +0   (ideal — what we want)
//   MALE 1st-person                → -5   (arms-only mesh)
//   _faceBones variant             → -8   (needs face skel we don't have)
//   FEMALE 3rd-person              → -10  (wrong gender bones)
//   FEMALE 3rd-person + faceBones  → -18  (worst of both)
//   FEMALE 1st-person              → -15
int armor_path_score(const char* path, std::size_t len) {
    int score = 0;
    if (path_is_female_variant(path, len)) score -= 10;
    if (path_is_first_person(path, len))   score -= 5;
    if (path_is_face_bones(path, len))     score -= 8;
    return score;
}
} // anon namespace (SEH POD wrappers)

namespace {

// Tracking map: peer_id (str) → form_id → loaded NiNode*
//
// Per-peer scoping is for forward-compat with multi-peer ghost wedge.
// Today we only have ONE g_injected_cube ghost, so the per-peer key is
// informational — physically the armor goes onto that single ghost
// regardless of peer_id. When the multi-peer ghost lands, this map's
// outer key naturally maps to per-peer ghost selection.
std::mutex g_armor_map_mtx;
std::unordered_map<std::string,
                    std::unordered_map<std::uint32_t, void*>>
    g_attached_armor;

// M9.5 — per-armor-node flag: was this attached via deep-clone (true) or
// SHARED + snapshot/restore path (false). Detach-side reads to skip
// restore_skin_from_snapshot for clone-path armors (clone is destroyed on
// dec_refcount; restore would write to dying memory).
std::unordered_map<void*, bool> g_armor_was_cloned;

// (M9 wedge 3 body-cull state machine moved to top of file alongside
//  g_ghost_body_geom — needs to be visible to detach_debug_cube which
//  lives ABOVE this anon namespace.)

// Pending equip ops accumulated while the ghost wasn't yet spawned.
// At boot time peer A's B8 force-equip-cycle broadcasts UNEQUIP+EQUIP
// for the Vault Suit before peer B's ghost is injected. Without a
// pending queue, B never sees A's outfit because A doesn't re-broadcast
// later. Drained on inject_debug_cube success via flush_pending_armor_ops.
//
// Order matters: queued FIFO per peer. A natural UNEQUIP→EQUIP cycle
// drains correctly (UNEQUIP is no-op since nothing's attached, then
// EQUIP attaches). Reverse would also work via the idempotent skip
// in ghost_attach_armor.
struct PendingArmorOp {
    std::uint32_t form_id;
    std::uint8_t  kind;   // EquipOpKind: 1=EQUIP, 2=UNEQUIP
};
std::mutex g_pending_armor_mtx;
std::unordered_map<std::string, std::deque<PendingArmorOp>>
    g_pending_armor_ops;

// Walk TESObjectARMO → TESObjectARMA[i] → TESModel(male3rd) → BSFixedString
// → c_str. Returns the first valid path found in the armor's addon list,
// or nullptr if the form is not an armor / has no usable addons.
//
// We pick the FIRST addon's path because:
//   - Most armor only has 1 addon (single mesh covers all races we use)
//   - Multi-race armor (e.g., rare pre-gen ones) has separate ARMAs per
//     race — the engine picks one based on actor race; we don't have an
//     actor here, so we just pick [0] and accept potential mismatch
//   - For the wedge 2 test scope (Vault Suit + raider chest), [0] is
//     the right one (vanilla human male)
//
// Path is returned WITHOUT "Meshes\\" prefix — nif_load_by_path prepends
// it internally.
//
// All struct dereferences go through the seh_* POD wrappers above,
// avoiding MSVC C2712 (FW_LOG / FW_WRN expand to code with C++ unwind
// objects, so we cannot use __try in this function directly).
const char* resolve_armor_nif_path(std::uint32_t item_form_id,
                                     std::uint16_t effective_priority) {
    if (item_form_id == 0 || g_r.base == 0) return nullptr;

    // 1. lookup_by_form_id — same RVA used by container_hook for REFR resolve.
    using LookupFn = void* (__fastcall*)(std::uint32_t);
    auto lookup = reinterpret_cast<LookupFn>(
        g_r.base + offsets::LOOKUP_BY_FORMID_RVA);

    void* tes_form = seh_lookup_form(lookup, item_form_id);
    if (!tes_form) {
        FW_WRN("[armor-resolve] lookup_by_form_id(0x%X) returned null / faulted "
               "(form not loaded? wrong plugin?)", item_form_id);
        return nullptr;
    }

    // 2. Read ARMO addon array base + count.
    // Offsets per re/M9_w2_armo_layout.log §H (sub_140462370 =
    // ARMO::FinalizeAfterLoad iterates `*(armo+0x2A8)+i*16+8`).
    void** addon_array = nullptr;
    std::uint32_t addon_count = 0;
    if (!seh_read_armo_addons(tes_form, &addon_array, &addon_count)) {
        FW_ERR("[armor-resolve] SEH reading ARMO addon array (form=0x%X "
               "may not be ARMO)", item_form_id);
        return nullptr;
    }
    if (!addon_array || addon_count == 0) {
        FW_WRN("[armor-resolve] form=0x%X: empty addon array (count=%u "
               "base=%p)", item_form_id, addon_count, addon_array);
        return nullptr;
    }
    if (addon_count > 16) {
        FW_WRN("[armor-resolve] form=0x%X claims %u addons (suspicious "
               "— clamp to 16)", item_form_id, addon_count);
        addon_count = 16;
    }

    // 2.5. M9.w2 PROPER (May 3 2026 v10): apply the engine's PrioritySelect
    // filter to the addon array. The receiver gets the OMOD-effective priority
    // from the wire (sender extracted it via sub_140436820 from the equipped
    // item's InstanceData+0x56, or fell back to ARMO+0x2A6). When the wire
    // value is 0 (sender skipped extraction or non-ARMO form), we read
    // ARMO+0x2A6 ourselves for back-compat.
    //
    // Selection rules (from sub_1404626A0 RE, HIGH×HIGH agent consensus):
    //   * priority == 0       → always invoke ("always-on" parts)
    //   * priority == reqPrio → invoke (exact match)
    //   * else                → invoke highest priority value still ≤ reqPrio
    //   * pass 3 fallback     → if pass 1+2 both empty, accept ALL addons
    //                           (degraded mode — better than rendering nothing)
    std::uint16_t req_prio = effective_priority;
    if (req_prio == 0) {
        // Wire didn't carry priority (pre-v10 sender, or non-ARMO form).
        // Fall back to reading ARMO+0x2A6 default ourselves.
        (void)seh_read_armo_default_priority(tes_form, &req_prio);
        FW_DBG("[armor-resolve] form=0x%X reqPrio=%u (ARMO+0x2A6 default; "
               "wire priority was 0)", item_form_id, req_prio);
    } else {
        FW_DBG("[armor-resolve] form=0x%X reqPrio=%u (from wire — "
               "OMOD-effective priority extracted by sender)",
               item_form_id, req_prio);
    }

    // Pre-pass: compute per-addon priority + decide pass-1 vs pass-2 fallback.
    // Pass 1 includes: priority==0 OR priority==reqPrio
    // Pass 2 fallback: highest priority value still ≤ reqPrio (used iff pass 1
    // matches NOTHING usable — gives us a graceful "fallback to closest tier"
    // rather than empty result).
    std::uint16_t addon_prios[16] = {0};
    bool          has_pass1[16]   = {false};
    std::uint16_t pass2_best      = 0;     // highest entryPrio s.t. entryPrio ≤ reqPrio
    bool          any_pass1_match = false;
    for (std::uint32_t i = 0; i < addon_count; ++i) {
        std::uint16_t ep = 0;
        if (seh_read_addon_entry_priority(addon_array, i, &ep)) {
            addon_prios[i] = ep;
            // Pass-1 rule: priority 0 (always-on) or exact match.
            if (ep == 0 || ep == req_prio) {
                has_pass1[i] = true;
                any_pass1_match = true;
            }
            // Pass-2 best tracker: highest entryPrio still ≤ reqPrio
            if (ep <= req_prio && ep > pass2_best) pass2_best = ep;
        }
    }
    // PASS 3 fallback (May 3 2026 v6): if neither pass-1 nor pass-2 found
    // anything, the engine would render nothing (Combat Armor with reqPrio=0
    // and addon priorities 1/2/3 produces empty result — the engine relies on
    // OMOD InstanceData+0x56 to override reqPrio to 1/2/3). To avoid the
    // ghost showing NOTHING at all on the receiver (since we don't have OMOD
    // priority yet — phase 3b), we fall through to "include all addons" so
    // existing path scoring picks the best M3rd path. This is a degraded
    // state ("render the form-default tier instead of the OMOD-modified one")
    // but better than rendering nothing.
    const bool priority_filter_disabled =
        !any_pass1_match && pass2_best == 0;
    FW_DBG("[armor-resolve] form=0x%X addon priorities: pass1_any=%d "
           "pass2_best=%u filter_disabled=%d",
           item_form_id, any_pass1_match ? 1 : 0, pass2_best,
           priority_filter_disabled ? 1 : 0);

    // 3. Walk addons. For each ARMA, probe multiple candidate offsets
    // for the TESModel(male 3rd) — the exact layout in FO4 1.11.191
    // next-gen wasn't pinned by the dossier (initial guess 0xD0 was
    // wrong per live test 2026-04-29). Probe in order of likelihood
    // based on TESObjectARMA component layout patterns.
    //
    // M9.w2 PROPER: addons NOT matching the priority filter are skipped.
    // For Combat Armor 0x11D3C3 (3 ARMAs: Lite/Mid/Heavy with priorities
    // 1/2/3), only the priority-matching addon's path candidates are
    // probed and scored. Saves work + isolates the right tier.
    static const std::size_t kCandidateModelOffsets[] = {
        0xD0, 0x90, 0x110, 0x150, 0x50, 0x190,  // model 3rd-person candidates
        0x80, 0xC0, 0x100, 0x140, 0x180,         // alt offsets if the
                                                  // 64-byte component grid
                                                  // is shifted
    };
    constexpr std::size_t kNumCandidates =
        sizeof(kCandidateModelOffsets) / sizeof(kCandidateModelOffsets[0]);

    // Collect ALL valid candidates first, then pick the highest-scoring
    // by armor_path_score. Score deprioritizes female-NIF (wrong gender
    // bones for our MaleBody ghost) and 1st-person variants (arms-only
    // meshes intended for FPS view). Empirical layout (RE 2026-04-29):
    //   +0x50  = TESModel male 3rd-person  ← target (score 0)
    //   +0x90  = TESModel female 3rd       (score -10)
    //   +0x150 = TESModel male 1st-person  (score -5, arms only)
    //   +0x190 = TESModel female 1st       (score -15)
    struct PathCandidate {
        std::size_t offset;
        const char* path;
        std::size_t len;
        int         score;
    };
    PathCandidate found[16];
    std::size_t found_count = 0;

    for (std::uint32_t i = 0; i < addon_count; ++i) {
        void* arma = seh_read_arma_at(addon_array, i);
        if (!arma) continue;

        // M9.w2 PROPER priority filter (May 3 2026):
        // Skip addons that don't match the PrioritySelect rules. Pass 1
        // accepts (prio==0 OR prio==reqPrio); pass 2 fallback uses prio==best
        // (highest ≤ reqPrio); pass 3 fallback (priority_filter_disabled)
        // accepts EVERYTHING when neither pass 1 nor pass 2 found anything —
        // typically Combat Armor with reqPrio=0 and addon priorities 1/2/3.
        const std::uint16_t this_prio = addon_prios[i];
        const bool include_pass1 = has_pass1[i];
        const bool include_pass2 = !any_pass1_match
                                && this_prio == pass2_best
                                && pass2_best != 0;
        const bool include_pass3 = priority_filter_disabled;
        if (!include_pass1 && !include_pass2 && !include_pass3) {
            FW_DBG("[armor-resolve] form=0x%X addon[%u] prio=%u skipped "
                   "(reqPrio=%u, pass1=%d pass2_best=%u)",
                   item_form_id, i, this_prio, req_prio,
                   any_pass1_match ? 1 : 0, pass2_best);
            continue;
        }

        for (std::size_t ci = 0; ci < kNumCandidates; ++ci) {
            if (found_count >= sizeof(found)/sizeof(found[0])) break;
            const std::size_t cand_off = kCandidateModelOffsets[ci];
            void* bsfs_handle = seh_read_arma_path_handle_at(arma, cand_off);
            if (!bsfs_handle) continue;

            const char* path = seh_bsfs_cstr(bsfs_handle);
            if (!path) continue;

            const std::size_t len = seh_strnlen_armor(path, 256);
            if (len < 5 || len > 200) continue;
            const char c0 = path[0];
            const bool looks_path = ((c0 >= 'A' && c0 <= 'Z') ||
                                     (c0 >= 'a' && c0 <= 'z'));
            if (!looks_path) continue;

            // Deduplicate — same BSFixedString handle reused across
            // multiple offsets (engine commonly stores the same path
            // pointer for related slots) shouldn't appear twice.
            bool dup = false;
            for (std::size_t k = 0; k < found_count; ++k) {
                if (found[k].path == path) { dup = true; break; }
            }
            if (dup) continue;

            const int sc = armor_path_score(path, len);
            FW_DBG("[armor-resolve] form=0x%X addon[%u] arma=%p "
                   "model@+0x%zX path='%s' (len=%zu, score=%d)",
                   item_form_id, i, arma, cand_off, path, len, sc);
            found[found_count++] = PathCandidate{cand_off, path, len, sc};
        }
    }

    if (found_count == 0) {
        FW_WRN("[armor-resolve] form=0x%X: no valid path across %u addons "
               "and %zu offset candidates",
               item_form_id, addon_count, kNumCandidates);
        return nullptr;
    }

    // Pick highest-scoring path. Score 0 = ideal male 3rd-person.
    // Negative scores = female / 1st-person / both (fallbacks).
    std::size_t best = 0;
    for (std::size_t k = 1; k < found_count; ++k) {
        if (found[k].score > found[best].score) best = k;
    }
    FW_LOG("[armor-resolve] form=0x%X SELECTED model@+0x%zX path='%s' "
           "(score=%d, %zu candidates total)",
           item_form_id, found[best].offset, found[best].path,
           found[best].score, found_count);
    return found[best].path;
}

} // anon namespace (armor helpers)

// === M9 wedge 7 — weapon helpers (anon namespace) ==========================
// Mirror of armor helpers above for TESObjectWEAP forms. Simpler than armor
// because:
//   - Single 3rd-person model per weapon (no addon array, no scoring)
//   - Rigid mesh (no skinning, no skin_rebind)
//   - Attach to a SINGLE bone (the "WEAPON" node) — not the ghost root
//
// See scene_inject.h "M9 wedge 7" block for design rationale and the
// limitations we accept (no BGSMod attachments, no holstered render,
// finger curl missing on grip).
namespace {

// Returns true if `path` looks like a vanilla/DLC/mod weapon NIF — checks
// for "weapons\\" prefix anywhere in the path (case-insensitive). Most
// weapon NIFs in FO4 live under "Weapons\\..." (Weapons\\Laser\\Pistol.nif,
// Weapons\\1HMelee\\Baton.nif, ...). Some power-armor / fusion-core
// integrated weapons may be under different roots — those won't match
// here and will fall through (acceptable, not common in survival
// gameplay).
bool path_looks_like_weapon(const char* path, std::size_t len) {
    if (!path || len < 8) return false;
    return seh_path_contains_ci(path, len, "weapons\\") ||
           seh_path_contains_ci(path, len, "weapons/");
}

// Walk TESObjectWEAP → embedded TESModel → BSFixedString → c_str. Returns
// the first valid path found at any candidate offset that ALSO matches
// the "weapons\\" path heuristic. Returns nullptr if the form isn't a
// weapon (or isn't loaded, or layout differs from our probe set).
//
// Mirror of resolve_armor_nif_path but simpler — no addon array walk,
// no male/female/1P scoring (single 3rd-person model per weapon).
const char* resolve_weapon_nif_path(std::uint32_t item_form_id) {
    if (item_form_id == 0 || g_r.base == 0) return nullptr;

    using LookupFn = void* (__fastcall*)(std::uint32_t);
    auto lookup = reinterpret_cast<LookupFn>(
        g_r.base + offsets::LOOKUP_BY_FORMID_RVA);

    void* tes_form = seh_lookup_form(lookup, item_form_id);
    if (!tes_form) {
        FW_DBG("[weapon-resolve] lookup_by_form_id(0x%X) returned null/SEH "
               "(form not loaded?)", item_form_id);
        return nullptr;
    }

    // TESObjectWEAP TESModel offset — uncertain on FO4 1.11.191 next-gen.
    // Extended probe range (2026-05-01 21:55) — old set [0x60..0xC0]
    // matched 10mmPistol's "RecieverDummy.nif" placeholder at +0x78
    // before reaching the proper "10mmPistol.nif" offset.
    //
    // Strategy:
    //   1. Scan ALL candidates, collect every "Weapons\\..." path found.
    //   2. PREFER paths that don't look like placeholder/dummy NIFs.
    //      Filters out: "RecieverDummy", "_Dummy", "Dummy_". Keeps real
    //      weapon NIFs like "10mmPistol.nif", "Baton_1.nif", etc.
    //   3. Fall back to first dummy match if no proper match found.
    //
    // We probe in 8-byte steps from 0x60 to 0x180 to cover the full
    // TESObjectWEAP struct layout. False positives (paths bleeding through
    // adjacent fields) are filtered by path_looks_like_weapon (must
    // contain "Weapons\\").
    auto path_is_placeholder = [](const char* p, std::size_t len) -> bool {
        // Case-insensitive substring match for known placeholder fragments.
        // Catches: RecieverDummy.nif (10mm pistol), DummyReciever.nif
        // (shotgun, reverse-typo), DummyAmmo.nif, _Dummy_, and generic
        // "Dummy" anywhere. False positives only if a real weapon NIF
        // contains "Dummy" in its name — rare in vanilla FO4.
        auto contains_ci = [](const char* hay, std::size_t hlen,
                              const char* needle) -> bool {
            const std::size_t nlen = std::strlen(needle);
            if (nlen > hlen) return false;
            for (std::size_t i = 0; i + nlen <= hlen; ++i) {
                bool match = true;
                for (std::size_t j = 0; j < nlen; ++j) {
                    char a = hay[i + j];
                    char b = needle[j];
                    if (a >= 'A' && a <= 'Z') a = a - 'A' + 'a';
                    if (b >= 'A' && b <= 'Z') b = b - 'A' + 'a';
                    if (a != b) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        };
        // Generic "Dummy" check covers all variants:
        //   RecieverDummy.nif (typo'd 10mm pistol)
        //   DummyReciever.nif (shotgun)
        //   *Dummy*.nif anywhere in path
        return contains_ci(p, len, "Dummy");
    };

    const char* best_path = nullptr;       // non-placeholder match
    const char* fallback_path = nullptr;   // first placeholder match

    for (std::size_t off = 0x60; off <= 0x180; off += 8) {
        void* bsfs = seh_read_arma_path_handle_at(tes_form, off);
        if (!bsfs) continue;

        const char* path = seh_bsfs_cstr(bsfs);
        if (!path) continue;

        const std::size_t len = seh_strnlen_armor(path, 256);
        if (len < 5 || len > 200) continue;

        const char c0 = path[0];
        const bool looks_path = ((c0 >= 'A' && c0 <= 'Z') ||
                                 (c0 >= 'a' && c0 <= 'z'));
        if (!looks_path) continue;

        if (!path_looks_like_weapon(path, len)) continue;

        if (path_is_placeholder(path, len)) {
            if (!fallback_path) {
                fallback_path = path;
                FW_DBG("[weapon-resolve] form=0x%X off=+0x%zX path='%s' "
                       "PLACEHOLDER (kept as fallback)",
                       item_form_id, off, path);
            }
            continue;
        }

        // Proper weapon NIF — return immediately.
        FW_LOG("[weapon-resolve] form=0x%X SELECTED model@+0x%zX path='%s' "
               "(non-placeholder)",
               item_form_id, off, path);
        return path;
    }

    if (fallback_path) {
        FW_LOG("[weapon-resolve] form=0x%X SELECTED placeholder='%s' "
               "(no non-placeholder path found in extended probe)",
               item_form_id, fallback_path);
        return fallback_path;
    }

    FW_DBG("[weapon-resolve] form=0x%X: no weapon path in extended probe "
           "[0x60..0x180]",
           item_form_id);
    return nullptr;
}

// (is_weapon_form public API moved out of this anon namespace; see
//  definition after the weapon-helpers anon namespace closes.)

// Tracking map: peer_id → form_id → loaded weapon NIF NiNode*
// Per-peer scoping mirrors armor for forward-compat with multi-peer ghost.
std::mutex g_weapon_map_mtx;
std::unordered_map<std::string,
                    std::unordered_map<std::uint32_t, void*>>
    g_attached_weapons;

// Pending weapon equip ops accumulated while ghost wasn't ready. Mirror
// of g_pending_armor_ops — both queues coexist; the dispatcher tries
// both attach paths so a duplicate queue entry on boot race is harmless
// (one fails silently, the other succeeds).
struct PendingWeaponOp {
    std::uint32_t form_id;
    std::uint8_t  kind;   // 1=EQUIP, 2=UNEQUIP (matches armor)
};
std::mutex g_pending_weapon_mtx;
std::unordered_map<std::string, std::deque<PendingWeaponOp>>
    g_pending_weapon_ops;

// Find the weapon attach node in the cached ghost skel. Priority list:
//   1. "WEAPON"     — vanilla FO4 standard (NiNode parented under RArm_Hand)
//   2. "Weapon"     — case variant some custom skels use
//   3. "WeaponBone" — alt naming
//   4. "RArm_Hand"  — fallback: attach directly to the right hand bone
// Returns nullptr only if NONE of the candidates exist in the cached skel.
//
// We try multiple names because the cached skeleton.nif is the one we
// loaded as a child of the ghost body — its exact bone names depend on
// the specific NIF file Bethesda shipped, which can vary between builds
// or come from CharacterAssets vs Skeleton.nif files.
void* find_weapon_attach_node() {
    static const char* kCandidates[] = {
        "WEAPON",
        "Weapon",
        "WeaponBone",
        "RArm_Hand",
    };
    for (const char* name : kCandidates) {
        void* node = fw::native::skin_rebind::get_bone_by_name(name);
        if (node) {
            FW_DBG("[weapon-attach] found attach node '%s' = %p", name, node);
            return node;
        }
    }
    return nullptr;
}

// === M9 w4 v8 — witness mod-attach helpers =================================
// All __try-only helpers (POD args, POD returns) so they can be called from
// inside C++ control flow that holds std::string / std::vector — keeps
// MSVC C2712 (mixed C++ unwind + SEH) happy.

// SEH-safe read of m_name (NiObjectNET +0x10 → BSFixedString handle).
// Writes up to bufsz-1 chars + null. Returns true on success.
static bool seh_read_node_name_w4(void* node, char* buf, std::size_t bufsz) {
    if (!node || bufsz < 2) {
        if (bufsz) buf[0] = 0;
        return false;
    }
    // 2026-05-06 FIX — was reading at *(pool_entry + 0x00) which is the
    // pool entry's first qword (refcount / inline metadata), NOT the
    // c-string. FO4 NG inline BSFixedString layout has the c-string at
    // pool_entry + 0x18 (matches the existing seh_read_node_name_ptr
    // helper at scene_inject.cpp:6602). The wrong offset caused EVERY
    // node to read as unnamed, which silently broke find_node_by_name_w4
    // for placeholder lookups and produced the "slot 'X' not found"
    // FALLBACKs we've been seeing for every mod attach since 2026-05-05.
    const char* cstr = nullptr;
    __try {
        const char* pool_entry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(node) + NIAV_NAME_OFF);
        if (!pool_entry) { buf[0] = 0; return false; }
        cstr = pool_entry + 0x18;
    } __except (EXCEPTION_EXECUTE_HANDLER) { buf[0] = 0; return false; }
    if (!cstr) { buf[0] = 0; return false; }
    __try {
        std::size_t i = 0;
        for (; i < bufsz - 1 && cstr[i]; ++i) {
            const char c = cstr[i];
            if (c < 0x20 || c > 0x7E) { i = 0; break; }
            buf[i] = c;
        }
        buf[i] = 0;
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        buf[0] = 0;
        return false;
    }
}

// SEH-safe NiNode children read.
static bool seh_read_children_w4(void* node, void**& kids, std::uint16_t& count) {
    kids = nullptr;
    count = 0;
    if (!node) return false;
    __try {
        char* nb = reinterpret_cast<char*>(node);
        kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        kids = nullptr; count = 0;
        return false;
    }
}

// SEH-safe array index (kids[i]).
static void* seh_kid_at_w4(void** kids, std::uint16_t i) {
    if (!kids) return nullptr;
    __try { return kids[i]; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// SEH-safe write of 16 floats (NiTransform) into node+0x30..+0x70.
static bool seh_write_local_transform(void* node, const float xf[16]) {
    if (!node) return false;
    __try {
        char* base = reinterpret_cast<char*>(node) + NIAV_LOCAL_ROTATE_OFF;
        std::memcpy(base, xf, sizeof(float) * 16);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Recursive find by name, depth-first. Returns first match or nullptr.
// max_depth bounded; SEH per-node so a corrupt subtree caps the search
// without taking down the caller.
static void* find_node_by_name_w4(void* root, const char* target,
                                   int depth = 0, int max_depth = 16) {
    if (!root || !target || depth > max_depth) return nullptr;
    char nm[128];
    if (seh_read_node_name_w4(root, nm, sizeof(nm)) && nm[0]
        && std::strcmp(nm, target) == 0) {
        return root;
    }
    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children_w4(root, kids, count)) return nullptr;
    if (!kids || count == 0 || count > 256) return nullptr;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_kid_at_w4(kids, i);
        if (!k) continue;
        void* hit = find_node_by_name_w4(k, target, depth + 1, max_depth);
        if (hit) return hit;
    }
    return nullptr;
}

// 2026-05-06 (M9 closure, ATTEMPT #8) — case-insensitive substring search
// for a placeholder node. `needle` is matched as a contiguous substring
// of each node's m_name. Used as Tier-2 fallback when exact-name lookup
// (find_node_by_name_w4) misses.
static bool ci_contains(const char* haystack, const char* needle) {
    if (!haystack || !needle || !needle[0]) return false;
    auto tolow = [](char c) -> char {
        if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
        return c;
    };
    const std::size_t hlen = std::strlen(haystack);
    const std::size_t nlen = std::strlen(needle);
    if (nlen == 0 || nlen > hlen) return false;
    for (std::size_t i = 0; i + nlen <= hlen; ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < nlen; ++j) {
            if (tolow(haystack[i + j]) != tolow(needle[j])) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}

static void* find_node_by_substring_w4(void* root, const char* needle,
                                         int depth = 0, int max_depth = 16) {
    if (!root || !needle || !needle[0] || depth > max_depth) return nullptr;
    char nm[128];
    if (seh_read_node_name_w4(root, nm, sizeof(nm)) && nm[0]
        && ci_contains(nm, needle)) {
        return root;
    }
    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children_w4(root, kids, count)) return nullptr;
    if (!kids || count == 0 || count > 256) return nullptr;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_kid_at_w4(kids, i);
        if (!k) continue;
        void* hit = find_node_by_substring_w4(k, needle, depth + 1, max_depth);
        if (hit) return hit;
    }
    return nullptr;
}

// 2026-05-06 evening (M9 closure, ATTEMPT #8) — multi-tier placeholder
// resolver. Replaces direct `find_node_by_name_w4` for slot_name lookup
// in mod-attach paths. Handles three classes of slot_name failures
// observed in live tests:
//
//   1. `P-*` mod-internal wrapper names (P-Barrel, P-Receiver, P-Mag,
//      P-Sight, etc.) — mod authors named NiNodes inside their .nif
//      assets following a "Placeholder anchor" convention. These are
//      not engine constants and have no corresponding base placeholder.
//      → strip the "P-" prefix, alias by category to a known base
//        placeholder substring (e.g. "P-Barrel" → look for "Receiver"
//        in pistols since pistols don't have a barrel placeholder).
//
//   2. `Weapon (form_id)` engine-runtime names — sender's walk-up went
//      too far and hit the WEAPON bone whose runtime m_name includes
//      the form id. → treat as catch-all, route to first placeholder
//      whose name contains "Receiver".
//
//   3. Sender-captured slot from non-pistol weapon families — substring
//      search handles "Mag" → "WeaponMagazine", "Sight" → "Optics", etc.
//
// Returns the matched node or `nullptr` (caller falls back to base_root).
// `slot_name_out` (optional) gets the final matched name for logging.
void* resolve_placeholder_for_slot(void* base_root,
                                     const char* slot_name,
                                     const char** match_kind_out) {
    if (match_kind_out) *match_kind_out = "miss";
    if (!base_root) return nullptr;
    if (!slot_name || !slot_name[0]) return nullptr;

    // Tier 0: exact match.
    if (void* hit = find_node_by_name_w4(base_root, slot_name)) {
        if (match_kind_out) *match_kind_out = "exact";
        return hit;
    }

    // Tier 1: alias map for "P-*" prefixes.
    // Each entry maps a known "P-*" name to a substring to search for
    // in base placeholder names. First match wins.
    struct Alias { const char* pattern; const char* substring; };
    static constexpr Alias kAliases[] = {
        // Receiver-class (catch-all for pistol body parts).
        { "P-Receiver",  "Receiver"  },
        { "P-Barrel",    "Receiver"  },  // pistols have no Barrel slot
        { "P-Muzzle",    "Receiver"  },
        { "P-Grip",      "Receiver"  },
        { "P-Stock",     "Receiver"  },
        // Magazine.
        { "P-Mag",       "Magazine"  },
        { "P-Magazine",  "Magazine"  },
        // Sights / scopes — try Optics first (pistol uses WeaponOptics1/2).
        { "P-Sight",     "Optics"    },
        { "P-Scope",     "Optics"    },
    };
    for (const auto& a : kAliases) {
        if (std::strcmp(slot_name, a.pattern) == 0) {
            if (void* hit = find_node_by_substring_w4(base_root, a.substring)) {
                if (match_kind_out) *match_kind_out = "alias";
                return hit;
            }
            break;  // alias matched but no node found in base; skip to fallback
        }
    }

    // Tier 2: strip "P-" prefix and try as substring directly.
    if (slot_name[0] == 'P' && slot_name[1] == '-' && slot_name[2]) {
        const char* needle = slot_name + 2;
        if (void* hit = find_node_by_substring_w4(base_root, needle)) {
            if (match_kind_out) *match_kind_out = "stripped-substring";
            return hit;
        }
    }

    // Tier 3: catch-all for "Weapon (form_id)" pattern (sender walked
    // past the placeholder and hit the WEAPON bone).
    if (std::strncmp(slot_name, "Weapon (", 8) == 0
        || std::strncmp(slot_name, "Weapon  (", 9) == 0) {
        if (void* hit = find_node_by_substring_w4(base_root, "Receiver")) {
            if (match_kind_out) *match_kind_out = "weapon-formid-catchall";
            return hit;
        }
    }

    // Tier 4: try slot_name as a direct substring (covers cases like
    // sender shipping "Mag" or "Optics" without "P-" prefix).
    if (void* hit = find_node_by_substring_w4(base_root, slot_name)) {
        if (match_kind_out) *match_kind_out = "raw-substring";
        return hit;
    }

    return nullptr;  // miss — caller falls back to base_root.
}

// === M9 wedge 3 — body cull helpers (slot-3 BODY armor → hide body NIF) =====
// SEH-cage NiAVObject m_uiFlags toggle. Sets or clears `mask` bits at
// node+NIAV_FLAGS_OFF (=0x108). Returns true if the write succeeded.
// Used to flip NIAV_FLAG_APP_CULLED on the ghost's BaseMaleBody:0
// BSSubIndexTriShape when peer equips a slot-3 BODY armor.
static bool seh_niav_set_flag(void* node, std::uint64_t mask, bool set) {
    if (!node) return false;
    __try {
        auto* flags = reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<char*>(node) + NIAV_FLAGS_OFF);
        if (set) *flags |= mask;
        else     *flags &= ~mask;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Apply / clear NIAV_FLAG_APP_CULLED on the FIRST cached ghost body
// BSSubIndexTriShape (slot 0 of `g_ghost_body_geoms`).
//
// Slot 0 (depth=1) is the body proper "BaseMaleBody:0".
// Slot 1 (depth=2) is hands "BaseMaleHands3rd:0" (loaded from MaleHands.nif
// and attached as child of body) — verified by cross-referencing the
// body-tree-dump address against the existing skin-rebind log:
//   [skin] swap: geom=000001D9DFB73130 name='BaseMaleHands3rd:0'  ← hands!
//   [body-tree-dump]   BSSITF #1 node=000001D9DFB73130 depth=2   ← same addr
// Hiding slot 1 in v4 broke hands rendering everywhere (including under
// armor that should cover them) — apparently the hands BSSITF is referenced
// by armor ARMA NIFs too, so we leave it alone.
//
// === DRY RUN MODE (v6 May 3 2026) ===
// User reports player's own body disappears on equip/unequip cycle, even
// though body cull is per-peer-ghost only. Hypothesis: the engine's NIF
// cache shares NiAVObject pointers between successive MaleBody.nif loads,
// so the BSSITF cached for the GHOST aliases with the PLAYER's body BSSITF.
// Setting NIAV_FLAG_APP_CULLED would then propagate.
//
// To verify: BODY_CULL_DRY_RUN=true causes apply_body_cull to LOG the
// intended action but NOT flip the flag. If the player-body-disappears
// symptom persists with dry-run on, our code is innocent (different bug).
// If symptom goes away with dry-run, NIF cache sharing is confirmed and
// we need a different visibility mechanism.
//
// FLIP TO false TO RE-ENABLE body cull (after diagnosis is complete).
//
// 2026-05-03 UPDATE: TTD investigation (37GB trace) confirmed STALE CACHE bug:
// `g_ghost_body_geoms[0]` becomes invalid within seconds of caching (engine
// destroys the body BSSITF when armor partition replaces it; memory pool
// reuses the address for unrelated BSSITF named "obj"). All apply_body_cull
// writes go to FREED memory.
//
// HOWEVER user testing with DRY_RUN=true showed the visible bugs (local body
// invisible, ghost mismatch, cycle crash) PERSIST — so stale cache is NOT
// the SOLE root cause. The cache-share bug needed deep-clone (M9.5).
//
// Now that BOTH body and armor are deep-cloned in inject_body_nif and
// ghost_attach_armor, the cache `g_ghost_body_geoms` points at our OWN
// cloned body BSSITF. That clone is owned by us, never touched by engine,
// and stays alive across the ghost's lifetime — so the cached pointer is
// VALID and writes go to OUR body, not random pool memory. Re-enabling
// the actual flag flip so the ghost body is hidden under armor (otherwise
// we get the user-reported "body compenetra con vault suit").
constexpr bool BODY_CULL_DRY_RUN = false;

static int apply_body_cull(bool culled) {
    void* primary = nullptr;
    {
        std::lock_guard lk(g_body_cull_mtx);
        if (!g_ghost_body_geoms.empty()) primary = g_ghost_body_geoms[0];
    }
    if (!primary) return 0;
    if constexpr (BODY_CULL_DRY_RUN) {
        FW_LOG("[body-cull-dryrun] WOULD %s NIAV_FLAG_APP_CULLED on body=%p "
               "(NIF-cache-sharing diagnosis — flag NOT actually flipped)",
               culled ? "set" : "clear", primary);
        return 1;  // pretend success so call-site logs ACQUIRED/RELEASED
    } else {
        return seh_niav_set_flag(primary, NIAV_FLAG_APP_CULLED, culled) ? 1 : 0;
    }
}

// Register a slot-3 BODY armor as a body-cull contributor for `peer_id`.
// Returns true ONLY if this is the FIRST contributor for the peer (i.e.
// the set transitioned empty→non-empty, so caller should now apply the
// NIAV_FLAG_APP_CULLED flag on the body geometry). Idempotent: re-adding
// the same form_id leaves the set unchanged and returns false.
static bool body_cull_register(const char* peer_id, std::uint32_t form_id) {
    if (!peer_id || form_id == 0) return false;
    std::lock_guard lk(g_body_cull_mtx);
    auto& set = g_body_cull_contributors[peer_id];
    const bool was_empty = set.empty();
    auto [_it, inserted] = set.insert(form_id);
    return was_empty && inserted;
}

// Unregister a body-cull contributor. Returns true ONLY if this was the
// LAST contributor for the peer (set transitioned non-empty→empty, so
// caller should clear NIAV_FLAG_APP_CULLED). Idempotent: removing a
// form_id not in the set returns false.
static bool body_cull_unregister(const char* peer_id, std::uint32_t form_id) {
    if (!peer_id || form_id == 0) return false;
    std::lock_guard lk(g_body_cull_mtx);
    auto it = g_body_cull_contributors.find(peer_id);
    if (it == g_body_cull_contributors.end()) return false;
    if (it->second.erase(form_id) == 0) return false;  // wasn't a contributor
    return it->second.empty();
}

// Apply one witness NIF descriptor to an already-loaded weapon root.
//   weapon_root: the loaded base weapon NIF (root of the receiver-side
//                assembled weapon, attached to the WEAPON bone).
//   path:        mod NIF path (e.g. "Weapons\10mmPistol\Mods\Barrel_Long.nif")
//   parent_name: name of the NiNode INSIDE weapon_root where the mod
//                should be attached (e.g. "BarrelAttachNode").
//   xform:       16 floats from sender's NiAVObject local transform.
// Returns true if the mod NIF was loaded AND attached successfully.
//
// Threading: main-thread only (calls nif_load_by_path + attach_child_direct
// + writes scene-graph transform). Called from ghost_attach_weapon which
// is itself main-thread only.
static bool attach_witness_mod(void* weapon_root,
                                const char* path,
                                const char* parent_name,
                                const float xform[16],
                                std::uint8_t* killswitch_byte)
{
    if (!weapon_root || !path || !parent_name || !xform) return false;
    if (!path[0]) return false;

    // Locate the parent node by name inside the loaded weapon tree.
    // If the engine's NIF loader didn't include this attach node (e.g.
    // base weapon variant doesn't have a "BarrelAttachNode"), we can't
    // place the mod — log + skip.
    void* parent = find_node_by_name_w4(weapon_root, parent_name);
    if (!parent) {
        FW_WRN("[weapon-attach][witness-mod] parent '%s' not found in "
               "weapon_root=%p — cannot attach mod NIF '%s'",
               parent_name, weapon_root, path);
        return false;
    }

    // Load the mod NIF. Same opts as base weapon (FADE_WRAP | POSTPROC).
    void* mod_node = nullptr;
    NifLoadOpts opts{};
    opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;
    const std::uint8_t saved_ks = killswitch_byte ? *killswitch_byte : 0;
    if (killswitch_byte) *killswitch_byte = 1;
    const std::uint32_t rc = seh_nif_load_armor(g_r.nif_load_by_path,
                                                  path, &mod_node, &opts);
    if (rc == 0xDEADBEEFu) {
        if (killswitch_byte) *killswitch_byte = saved_ks;
        FW_ERR("[weapon-attach][witness-mod] SEH in nif_load_by_path('%s')",
               path);
        return false;
    }
    if (rc != 0 || !mod_node) {
        if (killswitch_byte) *killswitch_byte = saved_ks;
        FW_WRN("[weapon-attach][witness-mod] nif_load_by_path('%s') failed "
               "rc=%u node=%p", path, rc, mod_node);
        return false;
    }

    // apply_materials walker — texture/shader bind for the loaded subtree.
    seh_apply_materials_armor(g_r.apply_materials, mod_node);
    if (killswitch_byte) *killswitch_byte = saved_ks;

    // Apply the local transform the sender captured. The engine wrote
    // these 16 floats into the corresponding NiAVObject after running
    // its mod-attach pipeline; we replicate identically on the receiver.
    if (!seh_write_local_transform(mod_node, xform)) {
        FW_WRN("[weapon-attach][witness-mod] SEH writing local transform "
               "to mod_node=%p — proceeding with default identity", mod_node);
    }

    // Attach as child of the named parent inside weapon_root.
    if (!seh_attach_child_armor(g_r.attach_child_direct, parent, mod_node)) {
        FW_ERR("[weapon-attach][witness-mod] SEH in attach_child_direct"
               "(parent=%p, mod=%p, path='%s')", parent, mod_node, path);
        return false;
    }

    FW_LOG("[weapon-attach][witness-mod] attached '%s' to parent='%s'(%p) "
           "mod_node=%p trans=(%.2f,%.2f,%.2f) scale=%.3f",
           path, parent_name, parent, mod_node,
           xform[12], xform[13], xform[14], xform[15]);
    return true;
}

} // anon namespace (weapon helpers)

// === M9 closure (Phase 1, 2026-05-06) — OMOD form → NIF path resolver ====
//
// Per re/OMOD_assembly_AGENT_A.md (deep RE done 2026-05-06):
//
//   - OMOD form is `BGSMod::Attachment::Mod` (form-type 0x6E / 110).
//   - Form-tag byte at form +0x1A is 0x90 for OMOD records (filter key
//     used by the engine itself in sub_140248F40).
//   - TESModel sub-object lives at form +0x48 (vtable bank 3).
//   - TESModel.modelPath BSFixedString handle is at form +0x50.
//
// We use the SAME helpers (seh_lookup_form, seh_read_arma_path_handle_at,
// seh_bsfs_cstr) that resolve_weapon_nif_path / resolve_armor_nif_path
// already use — TESModel layout is uniform across form types.
//
// On a fresh ghost equip, the receiver gets the omod_form_id list from
// the EQUIP_BCAST wire tail (already decoded at client.cpp:~L1063).
// For each, we resolve here to the actual NIF file path. This replaces
// the bgsm-derive heuristic + 18-pattern fallback that produced the
// "10mmReflexDot vs 10mmReflexSight.nif" mismatches.
const char* resolve_omod_model_path(std::uint32_t omod_form_id) {
    if (omod_form_id == 0 || g_r.base == 0) return nullptr;

    using LookupFn = void* (__fastcall*)(std::uint32_t);
    auto lookup = reinterpret_cast<LookupFn>(
        g_r.base + offsets::LOOKUP_BY_FORMID_RVA);

    void* form = seh_lookup_form(lookup, omod_form_id);
    if (!form) {
        FW_DBG("[omod-resolve] lookup_by_form_id(0x%X) returned null/SEH",
               omod_form_id);
        return nullptr;
    }

    // Confirm this is actually an OMOD via the form-tag byte. Without
    // this we'd happily pull a "modelPath" out of any form whose +0x50
    // bytes happen to look like a BSFixedString — bad path collisions.
    std::uint8_t tag = 0;
    __try {
        tag = *(reinterpret_cast<const std::uint8_t*>(form) + 0x1A);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_DBG("[omod-resolve] SEH reading form-tag byte for 0x%X",
               omod_form_id);
        return nullptr;
    }
    if (tag != 0x90) {
        FW_DBG("[omod-resolve] form 0x%X tag=0x%X != 0x90 — not an OMOD, "
               "skipping",
               omod_form_id, static_cast<unsigned>(tag));
        return nullptr;
    }

    // 2026-05-06 v2 — the dossier's +0x50 inference was wrong. Live
    // probe shows reading at +0x50 yields garbage ending in "dds"
    // (probably part of the MODT texture swap blob). Scan a range of
    // 8-byte offsets within the OMOD form and pick the FIRST handle
    // whose dereferenced C-string looks like a NIF path:
    //   - case-insensitive ".nif" suffix
    //   - non-empty, < 240 chars
    //   - first byte is an ASCII letter (ruling out garbage)
    // We do NOT require "Weapons\\" prefix because OMOD NIFs can also
    // live under "DLC04\\Weapons\\..." or other folders.
    auto path_looks_like_nif = [](const char* p, std::size_t len) -> bool {
        if (len < 5 || len > 240) return false;
        const char c0 = p[0];
        if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z')))
            return false;
        // Case-insensitive ".nif" suffix.
        if (len < 4) return false;
        const char a = p[len-4], b = p[len-3], c = p[len-2], d = p[len-1];
        auto lo = [](char x) -> char {
            return (x >= 'A' && x <= 'Z') ? (char)(x - 'A' + 'a') : x;
        };
        return lo(a) == '.' && lo(b) == 'n' && lo(c) == 'i' && lo(d) == 'f';
    };

    // 2026-05-06 v3 — constrain scan to OMOD sizeof (0xC8 = 200 bytes
    // per the dossier). Reading past 0xC0 would leak into adjacent
    // heap allocations and produce wildly wrong results — observed
    // live: OMOD 0x1601D6 returned 'Weapons\JunkJet\ShortBarrel.nif'
    // at offset +0x110 (= adjacent form's data). The result was a
    // valid-looking NIF path that crashed the receiver when attached
    // to a 10mm pistol base (ref=mod cycle in scene graph).
    //
    // The stride here is +0x08 because every BSFixedString slot is
    // qword-aligned. Reading via seh_read_arma_path_handle_at(form,
    // off) actually accesses form+off+0x08 because the helper adds
    // TESMODEL_PATH_BSFIXEDSTR_OFF (=0x08) internally — so off=0x48
    // means we're reading at form+0x50 (= TESModel.modelPath per
    // dossier section 2). Range 0x40..0xC0 covers the sub-object
    // banks without bleeding past the form.
    for (std::size_t off = 0x40; off <= 0xC0; off += 8) {
        void* bsfs = seh_read_arma_path_handle_at(form, off);
        if (!bsfs) continue;
        const char* path = seh_bsfs_cstr(bsfs);
        if (!path) continue;
        const std::size_t len = seh_strnlen_armor(path, 256);
        if (path_looks_like_nif(path, len)) {
            FW_DBG("[omod-resolve] OMOD 0x%X path='%s' (offset +0x%zX)",
                   omod_form_id, path, off);
            return path;
        }
    }

    FW_DBG("[omod-resolve] OMOD 0x%X — no valid NIF path found in scan range",
           omod_form_id);
    return nullptr;
}

// === Per-peer OMOD form-id stash (M9 Phase 1) =============================
//
// Populated from net-thread EQUIP_BCAST decode (where the OMOD list is
// already parsed and printed via [equip-rx] mod[N] log lines). Consumed
// from main-thread drain_mesh_blob_apply_queue when we're choosing
// which mod NIFs to attach to the ghost weapon.
//
// Storage is bounded (MAX_PEERS × MAX_EQUIP_MODS) — at most ~32 forms
// per peer, ~16 peers max in any realistic FoM session. Mutex
// protects against the inevitable net-thread vs main-thread races.

namespace {
constexpr std::size_t kMaxOmodFormsPerPeer = 32;

struct PeerOmodList {
    std::uint32_t forms[kMaxOmodFormsPerPeer] = {};
    std::uint8_t  count = 0;
};

std::mutex g_peer_omod_mtx;
std::unordered_map<std::string, PeerOmodList> g_peer_omod;
}  // namespace

void set_peer_omod_forms(const char* peer_id,
                          const std::uint32_t* forms,
                          std::uint8_t form_count) {
    if (!peer_id) return;
    if (form_count > kMaxOmodFormsPerPeer) {
        form_count = static_cast<std::uint8_t>(kMaxOmodFormsPerPeer);
    }

    std::lock_guard lk(g_peer_omod_mtx);
    auto& slot = g_peer_omod[peer_id];
    slot.count = form_count;
    if (form_count > 0 && forms) {
        std::memcpy(slot.forms, forms,
                    sizeof(std::uint32_t) * form_count);
    }
    FW_DBG("[omod-stash] peer=%s set %u forms",
           peer_id, static_cast<unsigned>(form_count));
}

std::uint8_t snapshot_peer_omod_forms_public(const char* peer_id,
                                              std::uint32_t* out_buf,
                                              std::size_t out_cap) {
    if (!peer_id || !out_buf || out_cap == 0) return 0;
    std::lock_guard lk(g_peer_omod_mtx);
    auto it = g_peer_omod.find(peer_id);
    if (it == g_peer_omod.end()) return 0;
    const std::uint8_t n = it->second.count;
    const std::size_t copy_n = (n < out_cap) ? n : out_cap;
    std::memcpy(out_buf, it->second.forms,
                sizeof(std::uint32_t) * copy_n);
    return static_cast<std::uint8_t>(copy_n);
}

// === M9 wedge 4 v9 — form-type probe (public API) =========================
//
// Reuses resolve_weapon_nif_path's logic (engine lookup + TESModel walk +
// "Weapons\\" path heuristic). For the equip_hook mesh-tx gate we only
// need a yes/no answer; rejecting forms with no weapon path catches all
// non-WEAP cases (armor, ammo, food, misc) including the Vault-Suit-with-
// OMOD case that broke the channel pre-fix.
bool is_weapon_form(std::uint32_t item_form_id) {
    return resolve_weapon_nif_path(item_form_id) != nullptr;
}

bool ghost_attach_armor(const char* peer_id, std::uint32_t item_form_id,
                        std::uint16_t effective_priority) {
    if (!peer_id || item_form_id == 0) return false;

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        // Ghost not yet spawned — queue for replay on next ghost spawn.
        // This is the boot-time race: peer's B8 force-equip-cycle fires
        // before our ghost is injected; without queue we'd permanently
        // miss the initial equipment state of that peer.
        std::size_t qsize;
        {
            std::lock_guard lk(g_pending_armor_mtx);
            g_pending_armor_ops[peer_id].push_back(
                PendingArmorOp{item_form_id, /*EQUIP=*/1});
            qsize = g_pending_armor_ops[peer_id].size();
        }
        FW_LOG("[armor-attach] no ghost yet (peer=%s form=0x%X) — queued "
               "EQUIP for replay on ghost spawn (pending size=%zu)",
               peer_id, item_form_id, qsize);
        return false;
    }
    if (!g_resolved.load(std::memory_order_acquire) ||
        !g_r.nif_load_by_path || !g_r.attach_child_direct) {
        FW_WRN("[armor-attach] engine refs not resolved yet — skip");
        return false;
    }

    // Idempotent: if same peer+form already attached, skip silently.
    // Happens when the B8 force-equip-cycle on each client re-broadcasts
    // an EQUIP for the Vault Suit while it's already on, or when peer
    // double-clicks an item.
    {
        std::lock_guard lk(g_armor_map_mtx);
        auto& peer_map = g_attached_armor[peer_id];
        auto it = peer_map.find(item_form_id);
        if (it != peer_map.end()) {
            FW_DBG("[armor-attach] peer=%s form=0x%X already attached "
                   "(node=%p) — idempotent skip", peer_id, item_form_id,
                   it->second);
            return true;
        }
    }

    const char* path = resolve_armor_nif_path(item_form_id, effective_priority);
    if (!path) return false;  // resolve_armor_nif_path already logged the issue

    // Pool init guard — same as inject_body_nif. The NIF loader allocates
    // BSFadeNode internally and needs the pool ready.
    if (g_r.pool_init_flag &&
        *g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
        FW_DBG("[armor-attach] pool not ready, initializing");
        g_r.pool_init(g_r.pool, g_r.pool_init_flag);
    }

    // Load the NIF. Same opts as body load: FADE_WRAP | POSTPROC (0x18).
    // POSTPROC triggers BSModelProcessor → resolves .bgsm → DDS textures
    // (without it, materials render pink/purple as we discovered in M6.1).
    NifLoadOpts opts{};
    opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;

    // M6.1 killswitch dance — same as body load. byte_143E488C0 gates
    // the texture-resolution loop inside BSLightingShaderProperty bind.
    // Default 0 = skip resolution (pink). We force ON during our load
    // and restore after.
    std::uint8_t* killswitch_byte = reinterpret_cast<std::uint8_t*>(
        g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
    const std::uint8_t saved_ks = *killswitch_byte;
    *killswitch_byte = 1;

    // M9.5 (2026-05-04) — TYPE-ROUTED armor path:
    //   * If armor NIF tree contains BSSITF (= VS-style armor): DEEP CLONE.
    //     Independent skin instance prevents shared-instance ping-pong
    //     between local player and ghost (the "VS appears on ghost B too"
    //     bug). Clone walker handles BSSITF correctly.
    //   * Otherwise (BSTriShape geom, e.g. combat armor / regular pieces):
    //     SHARED + yesterday's M9.w2 snapshot/restore. BSTriShape clone via
    //     memcpy doesn't replicate engine's +0x148 D3D resource binding
    //     (sub_1416D5600), causing invisible-armor; sharing lets the engine
    //     manage rendering, with periodic re-apply (4Hz in on_bone_tick_*)
    //     forcing ghost-skel binding to neutralize engine's local-actor
    //     re-bind during equip cycles.
    //
    // ROLLBACK NOTE (2026-05-04 PM): tried `nif_load_worker` direct call
    // for "fresh tree per armor" — same AV as the body inject (worker
    // requires streamCtx from cache resolver, can't be called standalone
    // with streamCtx=0). Reverted to type-routed clone vs shared.
    void* shared_armor = nullptr;
    const std::uint32_t rc = seh_nif_load_armor(g_r.nif_load_by_path,
                                                  path, &shared_armor, &opts);
    if (rc == 0xDEADBEEFu) {
        *killswitch_byte = saved_ks;
        FW_ERR("[armor-attach] SEH in nif_load_by_path('%s')", path);
        return false;
    }
    if (rc != 0 || !shared_armor) {
        *killswitch_byte = saved_ks;
        FW_ERR("[armor-attach] nif_load_by_path('%s') failed rc=%u node=%p",
               path, rc, shared_armor);
        return false;
    }

    // Decide path based on PATH WHITELIST.
    //
    // M9.5 (2026-05-04 PM, FINAL) — PATH-BASED ROUTING:
    // Empirically the manual deep-clone walker produces a RENDERABLE clone
    // ONLY for the Vault111Suit family. Combat heavy and RusticUnderArmor
    // (winter coat) are also "homogeneous BSSITF" by detector but their
    // clones render invisible — the +0x148 NiSkinPartition / D3D-resource
    // setup the engine performs in its clone factory sub_1416D5600 isn't
    // replicated by our memcpy walker, and only VS happens to survive the
    // missing setup (likely due to its specific vertex layout).
    //
    // Conservative routing: ONLY the Vault Suit path goes through CLONE.
    // Everything else uses yesterday's M9.w2 SHARED pipeline (commit
    // dd7910c, which had universal armor rendering). This unifies:
    //   - today's fix for VS cycle bugs (#1 SEH, #2 body invisible,
    //     #3 ghost armor disappears, #4 T-pose) — via clone
    //   - yesterday's universal armor render fix — via shared path
    //     for combat / winter coat / Atom Cats / any future armor
    //
    // To extend the whitelist for future custom armors that need clone
    // behavior, add a strstr() match below. Diagnostic detectors
    // (tree_has_bssitf / tree_has_bstrishape) kept as logged metadata.
    void* armor_node = nullptr;
    bool was_cloned = false;
    const bool has_bssitf     = tree_has_bssitf(shared_armor);
    const bool has_bstrishape = tree_has_bstrishape(shared_armor);
    const bool is_vault_suit_path = path && (
        std::strstr(path, "Vault111Suit") != nullptr ||
        std::strstr(path, "vault111suit") != nullptr);
    if (is_vault_suit_path) {
        // CLONE path — only for Vault Suit family.
        armor_node = clone_nif_subtree(shared_armor);
        if (armor_node != shared_armor) {
            was_cloned = true;
            FW_LOG("[armor-attach] CLONE path (VS whitelist): shared=%p "
                   "clone=%p (form=0x%X path='%s') — independent skin "
                   "instance, fixes VS cycle bugs #1-#4",
                   shared_armor, armor_node, item_form_id, path);
            // Drop our +1 caller-owned ref on shared; engine cache keeps it.
            const long after = seh_refcount_dec_armor(shared_armor);
            if (after == -999) {
                FW_WRN("[armor-attach] SEH dec on shared (benign)");
            }
        } else {
            FW_WRN("[armor-attach] VS clone walker returned shared for "
                   "form=0x%X — degrading to SHARED path", item_form_id);
            armor_node = shared_armor;  // already loaded with +1 ref, keep
        }
    } else {
        // SHARED path = yesterday's commit dd7910c pipeline (universal armor
        // render: combat, winter coat, Atom Cats, etc. all renderable).
        armor_node = shared_armor;
        FW_LOG("[armor-attach] SHARED path (yesterday's M9.w2): node=%p "
               "(form=0x%X path='%s') has_bssitf=%d has_bstrishape=%d "
               "— snapshot/restore + periodic re-apply",
               armor_node, item_form_id, path,
               static_cast<int>(has_bssitf),
               static_cast<int>(has_bstrishape));
    }
    {
        std::lock_guard<std::mutex> lk(g_armor_map_mtx);
        g_armor_was_cloned[armor_node] = was_cloned;
    }

    // apply_materials — runs BSModelProcessor's texture+shader bind so
    // the loaded NIF has its full PBR rendering set up. Without it the
    // armor would render with placeholder pink-squared materials.
    seh_apply_materials_armor(g_r.apply_materials, armor_node);
    *killswitch_byte = saved_ks;

    // Attach as child of the ghost root. attach_child_direct bumps engine
    // refcount internally for the slot. nif_load_by_path also bumped
    // (caller-owned ref); the +1 from attach is the engine's slot ref.
    // On detach we drop ours, engine drops its slot ref, total 0 → free.
    if (!seh_attach_child_armor(g_r.attach_child_direct, ghost, armor_node)) {
        FW_ERR("[armor-attach] SEH in attach_child_direct(ghost=%p, "
               "armor=%p, path='%s')", ghost, armor_node, path);
        return false;
    }

    // === M9 wedge 2 ANIMATION FIX (2026-04-29) ===
    // The armor NIF we just loaded has its OWN skin_instance.bones_fb[]
    // array pointing at internal stub bones (Pelvis, SPINE1, ...) that
    // the NIF parser created at load time. Those stub bones are INERT —
    // they sit in the armor's subtree at bind pose forever. Result: the
    // armor renders in T-pose regardless of what the underlying body
    // is doing.
    //
    // Fix: re-bind the armor's bones_fb[] to the GHOST's CACHED skel
    // (the skeleton.nif we loaded as a child of the body at inject
    // time, which IS receiving live pose data via on_pose_apply_message).
    // Same skin_rebind::swap_skin_bones_to_skeleton call we do for the
    // BODY at inject time — just applied to each armor NIF too.
    //
    // After swap, armor.bones_fb[i] points at the skel.nif joint with
    // matching name, and bones_pri[i] = bones_fb[i]+0x70 → the same
    // animated joint world matrices the body skin reads from. Armor
    // skinning becomes synchronized with body animation automatically.
    void* cached_skel = fw::native::skin_rebind::get_cached_skeleton();
    if (cached_skel) {
        // M9.w2 snapshot/restore — only for SHARED path. Clone has its
        // own skin instance (independent of engine cache) so snapshotting
        // the clone's pre-swap state and restoring on detach is pointless
        // (clone is destroyed on dec_refcount anyway, restore writes to
        // dying memory). Conditional here keeps clone path "lean" and
        // shared path protected.
        if (!was_cloned) {
            fw::native::skin_rebind::take_skin_snapshot(armor_node);
        }

        const int swapped = fw::native::skin_rebind::swap_skin_bones_to_skeleton(
            armor_node, cached_skel);
        FW_LOG("[armor-attach] skin rebind: armor=%p skel=%p swapped=%d "
               "bones (now reads ghost-anim joints)",
               armor_node, cached_skel, swapped);
    } else {
        FW_WRN("[armor-attach] no cached skeleton — armor will render in "
               "T-pose (body anim won't propagate to armor skinning)");
    }

    // Track for later detach.
    {
        std::lock_guard lk(g_armor_map_mtx);
        g_attached_armor[peer_id][item_form_id] = armor_node;
    }

    // === M9 wedge 3 — body cull on slot-3 BODY armor (2026-05-02) ============
    // If this armor has bit 3 (slot "33 - BODY") set in its bipedObjectSlots
    // mask, it's a full-body replacement (Vault Suit, Power Armor, Synth
    // Armor, etc.). Set NIAV_FLAG_APP_CULLED on the ghost's BaseMaleBody:0
    // BSSubIndexTriShape to hide the underlying body geometry — prevents the
    // body skin from poking through / z-fighting under the armor mesh.
    //
    // We register the form_id as a body-cull contributor for this peer; only
    // the FIRST contributor triggers the actual flag flip (cheap idempotency
    // for the rare case of two BODY armors arriving in racy order before
    // the unequip of the prior). Detach-side mirror clears the flag when
    // the last contributor is removed.
    //
    // Order: cull AFTER successful armor attach so we never have a frame
    // where both body AND armor are absent (briefly invisible ghost). One
    // frame of body+armor overlap (z-fight) is preferable to one frame of
    // nothing visible.
    {
        using LookupFn = void* (__fastcall*)(std::uint32_t);
        auto lookup = reinterpret_cast<LookupFn>(
            g_r.base + offsets::LOOKUP_BY_FORMID_RVA);
        void* tes_form = seh_lookup_form(lookup, item_form_id);
        std::uint32_t mask = 0;
        if (tes_form && seh_read_armo_biped_slots(tes_form, &mask)
            && (mask & offsets::BIPED_SLOT_BODY_MASK) != 0)
        {
            if (body_cull_register(peer_id, item_form_id)) {
                const int n = apply_body_cull(true);
                if (n > 0) {
                    FW_LOG("[body-cull] peer=%s form=0x%X mask=0x%08X ACQUIRED "
                           "— %d body geom(s) hidden under BODY-slot armor",
                           peer_id, item_form_id, mask, n);
                } else {
                    FW_WRN("[body-cull] peer=%s form=0x%X: register OK but "
                           "0 body geoms flipped (cache empty? all SEH-faulted?) "
                           "— z-fight may persist",
                           peer_id, item_form_id);
                }
            } else {
                FW_DBG("[body-cull] peer=%s form=0x%X mask=0x%08X: not first "
                       "BODY contributor (set non-empty) — flag already set",
                       peer_id, item_form_id, mask);
            }
        }
    }

    FW_LOG("[armor-attach] peer=%s form=0x%X path='%s' node=%p ghost=%p OK",
           peer_id, item_form_id, path, armor_node, ghost);
    return true;
}

bool ghost_detach_armor(const char* peer_id, std::uint32_t item_form_id) {
    if (!peer_id || item_form_id == 0) return false;

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        // Ghost not yet spawned (boot race) OR destroyed (cell change).
        // Queue UNEQUIP for replay too: when ghost spawns and pending
        // queue drains, we want to honor the cancellation. Order is
        // FIFO so EQUIP→UNEQUIP queued in that order resolves to "no
        // armor" cleanly. Also clean up tracking map (if there's a
        // racy stale entry).
        {
            std::lock_guard lk(g_pending_armor_mtx);
            g_pending_armor_ops[peer_id].push_back(
                PendingArmorOp{item_form_id, /*UNEQUIP=*/2});
        }
        {
            std::lock_guard lk(g_armor_map_mtx);
            auto pit = g_attached_armor.find(peer_id);
            if (pit != g_attached_armor.end()) pit->second.erase(item_form_id);
        }
        FW_DBG("[armor-detach] no ghost yet (peer=%s form=0x%X) — queued "
               "UNEQUIP for replay", peer_id, item_form_id);
        return false;
    }
    if (!g_resolved.load(std::memory_order_acquire) || !g_r.detach_child) {
        FW_WRN("[armor-detach] engine refs not resolved — skip");
        return false;
    }

    // Look up + remove from tracking map.
    void* armor_node = nullptr;
    {
        std::lock_guard lk(g_armor_map_mtx);
        auto pit = g_attached_armor.find(peer_id);
        if (pit == g_attached_armor.end()) {
            FW_DBG("[armor-detach] peer=%s has no attached armor map — "
                   "no-op", peer_id);
            return false;
        }
        auto fit = pit->second.find(item_form_id);
        if (fit == pit->second.end()) {
            FW_DBG("[armor-detach] peer=%s form=0x%X not in map — was "
                   "probably never attached (resolve failed?)",
                   peer_id, item_form_id);
            return false;
        }
        armor_node = fit->second;
        pit->second.erase(fit);
    }
    if (!armor_node) return false;

    // M9 wedge 2 + M9.5 — restore_skin_from_snapshot is necessary for
    // SHARED-path armor (yesterday's mechanism keeps cache pristine across
    // cycles). For CLONE-path armor (today's), the clone owns its skin
    // and is destroyed on dec_refcount, so restoring is pointless and
    // potentially writes to dying memory. Look up the routing flag to
    // decide.
    bool was_cloned = false;
    {
        std::lock_guard<std::mutex> lk(g_armor_map_mtx);
        auto it = g_armor_was_cloned.find(armor_node);
        if (it != g_armor_was_cloned.end()) {
            was_cloned = it->second;
            g_armor_was_cloned.erase(it);
        }
    }
    if (!was_cloned) {
        fw::native::skin_rebind::restore_skin_from_snapshot(armor_node);
    }

    // Remove from ghost subtree. detach_child returns the pointer in
    // `removed` (which is just armor_node — sanity check); we're holding
    // the +1 ref from nif_load_by_path so the object stays alive until
    // we drop it below.
    void* removed = nullptr;
    if (!seh_detach_child_armor(g_r.detach_child, ghost, armor_node, &removed)) {
        FW_ERR("[armor-detach] SEH in detach_child(ghost=%p, armor=%p)",
               ghost, armor_node);
        return false;
    }

    // Drop our +1 ref → engine destroys via vtable[0] when refcount hits 0.
    const long after = seh_refcount_dec_armor(armor_node);
    if (after == -999) {
        FW_WRN("[armor-detach] SEH in refcount decrement (already freed? "
               "memory corruption?)");
    } else {
        FW_DBG("[armor-detach] refcount after dec = %ld (0 means freed by engine)",
               after);
    }

    // === M9 wedge 3 — body cull release ====================================
    // Mirror of attach-side: if THIS form was a slot-3 BODY contributor for
    // this peer, unregister it. If it was the LAST contributor (set went
    // non-empty→empty), clear NIAV_FLAG_APP_CULLED on the body geometry so
    // the ghost's body becomes visible again. Idempotent for non-BODY forms
    // (helmets, [A] Torso pieces, weapons): unregister returns false, this
    // block is a no-op.
    //
    // Order: clear cull AFTER engine detach so we never have a frame with
    // armor still attached but body restored (z-fight). One frame of "armor
    // gone, body still hidden" is preferable to one frame of overlap.
    if (body_cull_unregister(peer_id, item_form_id)) {
        const int n = apply_body_cull(false);
        if (n > 0) {
            FW_LOG("[body-cull] peer=%s form=0x%X RELEASED — %d body geom(s) "
                   "visible again (last BODY contributor removed)",
                   peer_id, item_form_id, n);
        } else {
            FW_DBG("[body-cull] peer=%s form=0x%X: unregister OK but 0 body "
                   "geoms flipped (cache empty after cell change?) — state "
                   "cleared anyway", peer_id, item_form_id);
        }
    }

    FW_LOG("[armor-detach] peer=%s form=0x%X armor=%p ghost=%p OK",
           peer_id, item_form_id, armor_node, ghost);
    return true;
}

// Drain pending equip ops accumulated while ghost wasn't ready.
// Call after inject_debug_cube success. Idempotent (no-op if queue empty).
//
// Strategy: swap the queue under lock to a local copy, then iterate
// without holding the lock (so the called ghost_attach_armor /
// ghost_detach_armor can take their own locks freely). This also
// prevents re-queueing if those calls race somehow back to "no ghost".
void flush_pending_armor_ops() {
    std::unordered_map<std::string, std::deque<PendingArmorOp>> local;
    {
        std::lock_guard lk(g_pending_armor_mtx);
        local.swap(g_pending_armor_ops);
    }
    if (local.empty()) {
        FW_DBG("[armor-pending] flush: queue empty — no-op");
        return;
    }

    std::size_t total = 0;
    std::size_t ok = 0;
    for (auto& kv : local) {
        const std::string& peer = kv.first;
        for (const auto& op : kv.second) {
            ++total;
            const bool success = (op.kind == 1)
                ? ghost_attach_armor(peer.c_str(), op.form_id)
                : ghost_detach_armor(peer.c_str(), op.form_id);
            if (success) ++ok;
        }
    }
    FW_LOG("[armor-pending] flush: replayed %zu/%zu ops across %zu peers",
           ok, total, local.size());
}

// M9.5 — re-apply skin swap on every currently-attached ghost armor.
// Called from equip_hook AFTER chaining through g_orig_equip /
// g_orig_unequip so the engine's post-equip skin re-bind on the SHARED
// NIF instance (cache-share with our ghost armor) gets reversed back
// to the ghost skel for ghost rendering.
//
// Implementation:
//  - Snapshot g_attached_armor under mutex (so we don't hold the lock
//    while doing skin work which can SEH and is potentially slow).
//  - Get cached ghost skel.
//  - For each (peer, form, armor_node), call swap_skin_bones_to_skeleton
//    which is idempotent (niptr_swap is idempotent on identical writes).
//
// Logging: one summary line at INF, per-armor at DBG.
//
// Threading: MAIN THREAD only (engine calls our equip-tx hook from main).
void reapply_ghost_skin_swaps(const char* trigger_label) {
    if (!trigger_label) trigger_label = "<unknown>";

    // Snapshot the map so we don't hold the mutex during skin work.
    std::vector<std::pair<std::string, void*>> snapshot;
    {
        std::lock_guard<std::mutex> lk(g_armor_map_mtx);
        for (const auto& peer_kv : g_attached_armor) {
            for (const auto& form_kv : peer_kv.second) {
                if (form_kv.second) {
                    snapshot.emplace_back(peer_kv.first, form_kv.second);
                }
            }
        }
    }
    if (snapshot.empty()) {
        FW_DBG("[skin-reapply] trigger=%s: no ghost armors attached — "
               "no-op", trigger_label);
        return;
    }

    void* cached_skel = fw::native::skin_rebind::get_cached_skeleton();
    if (!cached_skel) {
        FW_WRN("[skin-reapply] trigger=%s: no cached skel — skipping "
               "%zu ghost armor(s)", trigger_label, snapshot.size());
        return;
    }

    std::size_t reapplied = 0;
    int total_swapped = 0;
    for (const auto& kv : snapshot) {
        const int swapped =
            fw::native::skin_rebind::swap_skin_bones_to_skeleton(
                kv.second, cached_skel);
        if (swapped >= 0) {
            ++reapplied;
            total_swapped += swapped;
            FW_DBG("[skin-reapply]   peer=%s armor=%p swapped=%d bones",
                   kv.first.c_str(), kv.second, swapped);
        }
    }
    FW_LOG("[skin-reapply] trigger=%s: re-bound %zu/%zu ghost armor(s) "
           "(%d total bone slots restored to ghost skel) — counters engine "
           "EquipObject post-attach skin re-bind on shared NIF instances",
           trigger_label, reapplied, snapshot.size(), total_swapped);
}

// === M9 wedge 7 — public weapon attach/detach/flush ========================
// Mirror of armor public functions. See scene_inject.h "M9 wedge 7" block
// for limitations. Threading: MAIN-THREAD-ONLY (called from
// drain_equip_apply_queue).

bool ghost_attach_weapon(const char* peer_id, std::uint32_t item_form_id,
                          const void*  nif_descs_v,
                          std::uint8_t nif_count,
                          const char*  nif_path_override) {
    if (!peer_id || item_form_id == 0) return false;

    // The dispatcher passes a pointer to the PendingEquipOp's nif_descs
    // array; cast back to typed view here.
    const auto* nif_descs =
        reinterpret_cast<const fw::net::NifDescriptor*>(nif_descs_v);
    if (!nif_descs) nif_count = 0;
    if (nif_count > fw::net::MAX_NIF_DESCRIPTORS) {
        nif_count = fw::net::MAX_NIF_DESCRIPTORS;
    }

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        // Boot race: ghost not yet spawned. Queue for replay on next ghost
        // spawn (mirror armor). Note that the dispatcher tries armor first —
        // if armor's path also queued for the SAME form, that's fine: on
        // flush, armor's resolve fails (form is WEAP) and weapon's resolve
        // succeeds. Cost: 2x queue size, harmless.
        //
        // NOTE: pending replay drops the nif_descs (witness data). When the
        // ghost spawns and we replay, the receiver attaches the BASE NIF
        // only, not the mods. Acceptable because the sender will broadcast
        // the next equip-cycle (B8 force-equip-cycle on every game start)
        // with the witness data again. The boot-race window is small.
        std::size_t qsize;
        {
            std::lock_guard lk(g_pending_weapon_mtx);
            g_pending_weapon_ops[peer_id].push_back(
                PendingWeaponOp{item_form_id, /*EQUIP=*/1});
            qsize = g_pending_weapon_ops[peer_id].size();
        }
        FW_LOG("[weapon-attach] no ghost yet (peer=%s form=0x%X) — queued "
               "EQUIP for replay (pending size=%zu, witness mods=%u dropped)",
               peer_id, item_form_id, qsize,
               static_cast<unsigned>(nif_count));
        return false;
    }
    if (!g_resolved.load(std::memory_order_acquire) ||
        !g_r.nif_load_by_path || !g_r.attach_child_direct) {
        FW_WRN("[weapon-attach] engine refs not resolved yet — skip");
        return false;
    }

    // Idempotent: if same peer+form already attached, normally skip.
    // EXCEPTION (M9 w4 v8 stage-2 delta): if the broadcast carries
    // nif_descs and the weapon is already attached, apply just the
    // witness mod loop on the existing weapon node. This is how the
    // two-stage broadcast pattern works:
    //   - Stage 1 (no nif_descs) fires before sender's g_orig_equip and
    //     does the base NIF attach here.
    //   - Stage 2 (with nif_descs) fires after sender's chain returned
    //     and the engine assembled the modded subtree. We get here a
    //     second time with the SAME form_id and nif_count > 0.
    void* existing_weapon_node = nullptr;
    {
        std::lock_guard lk(g_weapon_map_mtx);
        auto& peer_map = g_attached_weapons[peer_id];
        auto it = peer_map.find(item_form_id);
        if (it != peer_map.end()) {
            existing_weapon_node = it->second;
        }
    }
    if (existing_weapon_node) {
        if (nif_count > 0 && nif_descs) {
            // STAGE 2 delta: apply mods on the existing base.
            std::uint8_t* mod_killswitch = reinterpret_cast<std::uint8_t*>(
                g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
            std::size_t attached_ok = 0, attach_failed = 0;
            for (std::uint8_t i = 0; i < nif_count; ++i) {
                const auto& d = nif_descs[i];
                const bool ok = attach_witness_mod(existing_weapon_node,
                                                    d.nif_path,
                                                    d.parent_name,
                                                    d.local_transform,
                                                    mod_killswitch);
                if (ok) ++attached_ok; else ++attach_failed;
            }
            FW_LOG("[weapon-attach] peer=%s form=0x%X STAGE-2 witness-mods: "
                   "%zu ok / %zu failed (out of %u descriptors) on existing "
                   "weapon=%p",
                   peer_id, item_form_id, attached_ok, attach_failed,
                   static_cast<unsigned>(nif_count), existing_weapon_node);
            return true;
        }
        // No nif_descs → plain re-broadcast / double-EQUIP race / peer-join
        // push. Idempotent skip.
        FW_DBG("[weapon-attach] peer=%s form=0x%X already attached "
               "(node=%p) — idempotent skip",
               peer_id, item_form_id, existing_weapon_node);
        return true;
    }

    // Resolve weapon NIF path. Override has priority — caller from
    // mesh-blob path supplies a bgsm-derived path (e.g. "Weapons\10mmPistol\
    // 10mmPistol.nif") that's more accurate than the TESModel offset probe
    // (which often returns "10mmRecieverDummy.nif" placeholder for the
    // pistol). Override is null for the legacy EQUIP_BCAST path → falls
    // back to the original probe.
    const char* path = nif_path_override
        ? nif_path_override
        : resolve_weapon_nif_path(item_form_id);
    if (!path) return false;

    // Find the WEAPON attach node in the cached ghost skel. If none found,
    // we cannot place the weapon — abort (logged).
    void* attach_node = find_weapon_attach_node();
    if (!attach_node) {
        FW_ERR("[weapon-attach] no WEAPON / Weapon / WeaponBone / RArm_Hand "
               "node in cached ghost skel — cannot attach (peer=%s form=0x%X "
               "path='%s')", peer_id, item_form_id, path);
        return false;
    }

    // Pool init guard (same as body/armor load).
    if (g_r.pool_init_flag &&
        *g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
        FW_DBG("[weapon-attach] pool not ready, initializing");
        g_r.pool_init(g_r.pool, g_r.pool_init_flag);
    }

    // Load the NIF with FADE_WRAP | POSTPROC for material/texture resolution
    // (POSTPROC triggers BSModelProcessor → resolves .bgsm → DDS textures).
    void* weapon_node = nullptr;
    NifLoadOpts opts{};
    opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;

    // M6.1 killswitch dance — same as armor/body load.
    std::uint8_t* killswitch_byte = reinterpret_cast<std::uint8_t*>(
        g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
    const std::uint8_t saved_ks = *killswitch_byte;
    *killswitch_byte = 1;

    // Reuse the armor SEH wrapper (function signature is identical for any
    // NIF load — wrapper doesn't care about the asset type).
    const std::uint32_t rc = seh_nif_load_armor(g_r.nif_load_by_path,
                                                  path, &weapon_node, &opts);
    if (rc == 0xDEADBEEFu) {
        *killswitch_byte = saved_ks;
        FW_ERR("[weapon-attach] SEH in nif_load_by_path('%s')", path);
        return false;
    }
    if (rc != 0 || !weapon_node) {
        *killswitch_byte = saved_ks;
        FW_ERR("[weapon-attach] nif_load_by_path('%s') failed rc=%u node=%p",
               path, rc, weapon_node);
        return false;
    }

    // apply_materials walker — texture+shader bind.
    seh_apply_materials_armor(g_r.apply_materials, weapon_node);
    *killswitch_byte = saved_ks;

    // Attach as child of the WEAPON bone (NOT the ghost root). The bone's
    // world transform is driven by the synced peer pose (POSE_BROADCAST →
    // skel.nif joint matrices), so the weapon inherits the correct
    // position/rotation automatically. No skin_rebind needed — weapon NIF
    // is rigid (single-bone or no-bone mesh).
    if (!seh_attach_child_armor(g_r.attach_child_direct, attach_node, weapon_node)) {
        FW_ERR("[weapon-attach] SEH in attach_child_direct(parent=%p, "
               "weapon=%p, path='%s')", attach_node, weapon_node, path);
        return false;
    }

    // Track for later detach.
    {
        std::lock_guard lk(g_weapon_map_mtx);
        g_attached_weapons[peer_id][item_form_id] = weapon_node;
    }

    FW_LOG("[weapon-attach] peer=%s form=0x%X path='%s' node=%p "
           "attach_parent=%p OK",
           peer_id, item_form_id, path, weapon_node, attach_node);

    // === M9 w4 v8 — witness mod-attach loop ===
    // For each NIF descriptor the sender captured (by walking its own
    // BipedAnim post-equip), load the mod NIF, find the named parent
    // inside our just-loaded weapon_node tree, apply the captured local
    // transform, attach as child. This replicates the engine's mod
    // assembly result on our ghost weapon WITHOUT invoking the engine's
    // mod pipeline (which is fused with REFR vt[119]/vt[136] Reset3D
    // and cannot run on a non-Actor receiver — proven across 4 IDA iters).
    if (nif_count > 0) {
        // Re-acquire killswitch byte for the mod loads (each load needs
        // it set so BSLightingShaderProperty bind resolves DDS textures
        // properly — same dance as the base load above).
        std::uint8_t* mod_killswitch = reinterpret_cast<std::uint8_t*>(
            g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
        std::size_t attached_ok = 0, attach_failed = 0;
        for (std::uint8_t i = 0; i < nif_count; ++i) {
            const auto& d = nif_descs[i];
            const bool ok = attach_witness_mod(weapon_node,
                                                d.nif_path,
                                                d.parent_name,
                                                d.local_transform,
                                                mod_killswitch);
            if (ok) ++attached_ok; else ++attach_failed;
        }
        FW_LOG("[weapon-attach] peer=%s form=0x%X witness-mods: "
               "%zu ok / %zu failed (out of %u descriptors)",
               peer_id, item_form_id, attached_ok, attach_failed,
               static_cast<unsigned>(nif_count));
    }
    return true;
}

bool ghost_detach_weapon(const char* peer_id, std::uint32_t item_form_id) {
    if (!peer_id || item_form_id == 0) return false;

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        // Queue UNEQUIP for replay too (mirror armor — preserves cancellation
        // ordering when a peer rapidly EQUIP→UNEQUIP before our ghost spawns).
        {
            std::lock_guard lk(g_pending_weapon_mtx);
            g_pending_weapon_ops[peer_id].push_back(
                PendingWeaponOp{item_form_id, /*UNEQUIP=*/2});
        }
        {
            std::lock_guard lk(g_weapon_map_mtx);
            auto pit = g_attached_weapons.find(peer_id);
            if (pit != g_attached_weapons.end()) pit->second.erase(item_form_id);
        }
        FW_DBG("[weapon-detach] no ghost yet (peer=%s form=0x%X) — queued "
               "UNEQUIP for replay", peer_id, item_form_id);
        return false;
    }
    if (!g_resolved.load(std::memory_order_acquire) || !g_r.detach_child) {
        FW_WRN("[weapon-detach] engine refs not resolved — skip");
        return false;
    }

    // Look up weapon node in tracking map.
    void* weapon_node = nullptr;
    {
        std::lock_guard lk(g_weapon_map_mtx);
        auto pit = g_attached_weapons.find(peer_id);
        if (pit == g_attached_weapons.end()) {
            FW_DBG("[weapon-detach] peer=%s has no attached weapons map — "
                   "no-op", peer_id);
            return false;
        }
        auto fit = pit->second.find(item_form_id);
        if (fit == pit->second.end()) {
            FW_DBG("[weapon-detach] peer=%s form=0x%X not in map — was "
                   "probably never attached (resolve failed at attach time?)",
                   peer_id, item_form_id);
            return false;
        }
        weapon_node = fit->second;
        pit->second.erase(fit);
    }
    if (!weapon_node) return false;

    // Re-find attach parent (we don't store it per-form to keep the map
    // small; refind is cheap — a tree walk in cached skel). Same priority
    // list as attach.
    void* attach_node = find_weapon_attach_node();
    if (!attach_node) {
        FW_WRN("[weapon-detach] attach parent no longer exists in cached skel "
               "(peer=%s form=0x%X) — weapon already orphaned, skip detach to "
               "avoid AV", peer_id, item_form_id);
        return false;
    }

    void* removed = nullptr;
    if (!seh_detach_child_armor(g_r.detach_child, attach_node, weapon_node, &removed)) {
        FW_ERR("[weapon-detach] SEH in detach_child(parent=%p, weapon=%p)",
               attach_node, weapon_node);
        return false;
    }

    // Drop our +1 ref → engine destroys via vtable[0] when refcount hits 0.
    const long after = seh_refcount_dec_armor(weapon_node);
    if (after == -999) {
        FW_WRN("[weapon-detach] SEH in refcount decrement");
    } else {
        FW_DBG("[weapon-detach] refcount after dec = %ld (0 means freed)",
               after);
    }

    FW_LOG("[weapon-detach] peer=%s form=0x%X weapon=%p OK",
           peer_id, item_form_id, weapon_node);
    return true;
}

// === M9 wedge 4 v9 — raw mesh weapon attach (REPLACEMENT semantics) =======
//
// Receives decoded mesh records (deserialized from MESH_BLOB_BCAST chunks)
// and rebuilds geometry on the matching ghost via the engine's factory
// sub_14182FFD0 (g_r.geo_builder).
//
// Storage: per-peer weapon_root NiNode. On each attach we DESTROY any
// previous weapon_root (cascade-frees its child meshes via refcount) and
// build a fresh one. This is the "replacement" strategy chosen 2026-05-01:
// the receiver does NOT load the base weapon NIF; it relies on the wire
// blob to carry the entire weapon geometry. Trade-off: ~50-200 ms ghost
// hand-empty between EQUIP_BCAST arrival and last MESH_BLOB chunk landing.
// Acceptable.
namespace {

// peer_id → weapon root NiNode* (the parent we attach all meshes under).
std::mutex g_ghost_weapon_root_mtx;
std::unordered_map<std::string, void*> g_ghost_weapon_root;

// SEH-safe refcount increment (POD helper to avoid C2712 in callers
// holding std::vector / std::string).
void seh_refcount_inc_local(void* node) {
    if (!node) return;
    __try {
        auto* rc = reinterpret_cast<long*>(
            reinterpret_cast<char*>(node) + NIAV_REFCOUNT_OFF);
        _InterlockedIncrement(rc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// SEH-safe vtable read (POD).
void* seh_read_vt(void* obj) {
    if (!obj) return nullptr;
    __try {
        return *reinterpret_cast<void**>(obj);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// SEH-safe set MOVABLE flag (NIAV+0x108 |= 0x800).
// Without this flag the engine doesn't recompute world from local each
// frame — meshes get stuck at the first frame's world transform regardless
// of whether the parent (RArm_Hand bone) moves.
void seh_set_movable_flag(void* node) {
    if (!node) return;
    __try {
        auto* flags = reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<char*>(node) + NIAV_FLAGS_OFF);
        *flags |= NIAV_FLAG_MOVABLE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// SEH-safe update_downward call (POD wrapper).
void seh_update_downward(UpdateDownwardFn fn, void* node) {
    if (!fn || !node) return;
    std::uint64_t update_data[4] = { 0, 0, 0, 0 };  // NiUpdateData stub
    __try {
        fn(node, update_data);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// SEH-safe DFS for first BSGeometry-derived child under `root` (POD).
// Returns a BSGeometry* if found, nullptr otherwise. Used by donor pattern
// to harvest a working shader from a vanilla NIF.
void* seh_find_first_geom_dfs(void* root, int depth = 0) {
    if (!root || depth > 24) return nullptr;
    std::uintptr_t vt_rva = 0;
    __try {
        void* vt = *reinterpret_cast<void**>(root);
        // Read base from a global to avoid passing it explicitly.
        vt_rva = reinterpret_cast<std::uintptr_t>(vt) - g_r.base;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (is_geometry_vtable_rva(vt_rva)) return root;

    void** kids = nullptr;
    std::uint16_t cnt = 0;
    __try {
        char* nb = reinterpret_cast<char*>(root);
        kids = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        cnt  = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!kids || cnt == 0 || cnt > 256) return nullptr;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* k = nullptr;
        __try { k = kids[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (!k) continue;
        void* g = seh_find_first_geom_dfs(k, depth + 1);
        if (g) return g;
    }
    return nullptr;
}

// SEH-safe pointer read at offset.
void* seh_read_ptr_at(void* obj, std::size_t off) {
    if (!obj) return nullptr;
    __try {
        return *reinterpret_cast<void**>(reinterpret_cast<char*>(obj) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// SEH-safe pointer write at offset.
void seh_write_ptr_at(void* obj, std::size_t off, void* val) {
    if (!obj) return;
    __try {
        *reinterpret_cast<void**>(reinterpret_cast<char*>(obj) + off) = val;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// SEH-safe BSTriShape state dump for diagnostic. Dumps fields critical for
// rendering: vtable, refcount, flags, alpha, shader, skin, posdata, vert/idx
// counts, bbox, world transform. POD-only so callers with std::vector are
// safe.
struct BsTriDiagState {
    std::uint64_t vt_rva;       // vtable RVA (or -1)
    std::uint32_t refcount;
    std::uint64_t flags;
    void*         alpha_prop;   // +0x130
    void*         shader_prop;  // +0x138
    void*         skin_inst;    // +0x140
    void*         pos_data;     // +0x148 (BSGeometryStreamHelper)
    std::uint64_t vertex_desc;  // +0x150
    std::uint16_t vert_count;   // +0x164
    std::uint32_t idx_count;    // +0x160 (3 * tri_count)
    float         bound_x, bound_y, bound_z, bound_r;  // +0x120..+0x12C
    float         world_tx, world_ty, world_tz;        // +0xA0 (NIAV_WORLD_TRANSLATE_OFF)
};
void seh_dump_bstri_state(void* bs, std::uintptr_t base, BsTriDiagState* out) {
    if (!bs || !out) return;
    std::memset(out, 0, sizeof(*out));
    out->vt_rva = 0xFFFFFFFFFFFFFFFFull;
    __try {
        auto cb = reinterpret_cast<char*>(bs);
        void* vt = *reinterpret_cast<void**>(bs);
        if (vt) {
            out->vt_rva = reinterpret_cast<std::uintptr_t>(vt) - base;
        }
        out->refcount    = *reinterpret_cast<std::uint32_t*>(cb + NIAV_REFCOUNT_OFF);
        out->flags       = *reinterpret_cast<std::uint64_t*>(cb + NIAV_FLAGS_OFF);
        out->alpha_prop  = *reinterpret_cast<void**>(cb + BSGEOM_ALPHAPROP_OFF);
        out->shader_prop = *reinterpret_cast<void**>(cb + BSGEOM_SHADERPROP_OFF);
        out->skin_inst   = *reinterpret_cast<void**>(cb + 0x140);
        out->pos_data    = *reinterpret_cast<void**>(cb + 0x148);
        out->vertex_desc = *reinterpret_cast<std::uint64_t*>(cb + 0x150);
        out->idx_count   = *reinterpret_cast<std::uint32_t*>(cb + 0x160);
        out->vert_count  = *reinterpret_cast<std::uint16_t*>(cb + 0x164);
        const float* bc = reinterpret_cast<const float*>(cb + 0x120);
        out->bound_x = bc[0]; out->bound_y = bc[1]; out->bound_z = bc[2]; out->bound_r = bc[3];
        const float* wt = reinterpret_cast<const float*>(cb + NIAV_WORLD_TRANSLATE_OFF);
        out->world_tx = wt[0]; out->world_ty = wt[1]; out->world_tz = wt[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// === Opzione A — manual shader+material setup for wire-built BSTriShape ===
//
// Diagnosis 2026-05-01 15:56: factory output has shader=NULL post-call.
// The previous `bgsm_load + mat_bind_to_geom` attempt returned "OK" but
// shader stayed NULL — mat_bind_to_geom presumably requires an existing
// shader to bind into. We replicate the cube path's manual BSLSP setup,
// substituting bgsm_load for texset+bind_mat_texset:
//
//   1. bslsp_new() → fresh BSLightingShaderProperty (refcount=0)
//   2. shader+0x64 = 1.0f (drawable flag — vt[43] SetupGeometry early-rejects
//      if zero, per cube comment line ~843)
//   3. bgsm_load(trimmed_path, &mat, 0) → loads .bgsm file → material
//   4. Refcount-safe swap shader+0x58: shared default → loaded material
//   5. fs_create(bgsm_path) → BSFixedString handle, write to shader+0x10
//      (so apply_materials_walker can read it back for re-resolve)
//   6. Write shader to bs+0x138 with refcount bump (geom takes ownership)
//
// DDS texture resolution: we DON'T call mat_bind_to_geom or bind_mat_texset
// here — those need a texset or AV'd in past attempts. Instead we rely on
// apply_materials_walker called on weapon_root POST-attach to walk the
// subtree and resolve textures from the bgsm paths we just wired.
//
// Returns the BSLSP shader pointer on success (caller's responsibility:
// keep it pointed-to via bs+0x138, or release if abandoning). Returns
// nullptr on any sub-step failure; caller continues with mesh sans shader.
void* seh_setup_weapon_shader(
    BSLSPNewFn bslsp_new,
    BgsmLoadFn bgsm_load,
    FixedStrCreateFn fs_create,
    std::uint8_t* killswitch_byte,
    void* bs,
    const char* bgsm_path)
{
    if (!bslsp_new || !bgsm_load || !bs || !bgsm_path || !bgsm_path[0]) {
        return nullptr;
    }

    // 1. Allocate fresh BSLSP shader.
    void* shader = nullptr;
    __try { shader = bslsp_new(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!shader) return nullptr;

    // 2. Drawable flag.
    __try {
        float* drawable = reinterpret_cast<float*>(
            reinterpret_cast<char*>(shader) + BSLSP_DRAWABLE_FLOAT_OFF);
        *drawable = 1.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 3. Strip "Materials\\" prefix and load bgsm.
    const char* trimmed = bgsm_path;
    {
        const char* prefixes[] = { "Materials\\", "materials\\" };
        for (const char* pfx : prefixes) {
            const std::size_t plen = std::strlen(pfx);
            if (std::strncmp(trimmed, pfx, plen) == 0) { trimmed += plen; break; }
        }
    }
    void* mat = nullptr;
    std::uint32_t rc = 0xFFFFFFFFu;
    const std::uint8_t saved_ks = killswitch_byte ? *killswitch_byte : 0;
    if (killswitch_byte) *killswitch_byte = 1;
    __try { rc = bgsm_load(trimmed, &mat, 0); }
    __except (EXCEPTION_EXECUTE_HANDLER) { rc = 0xDEADBEEFu; mat = nullptr; }
    if (killswitch_byte) *killswitch_byte = saved_ks;
    if (rc != 0 || !mat) {
        // Leak shader — refcount=0 means it'll get GC'd (or just stays
        // detached, harmless tiny leak). Returning nullptr signals failure.
        return nullptr;
    }

    // 4. Refcount-safe swap shader+0x58: shared default → loaded material.
    __try {
        void** mat_slot = reinterpret_cast<void**>(
            reinterpret_cast<char*>(shader) + BSLSP_MATERIAL_OFF);
        void* old_mat = *mat_slot;
        // Bump new material refcount BEFORE installing.
        _InterlockedIncrement(reinterpret_cast<long*>(
            reinterpret_cast<char*>(mat) + NIAV_REFCOUNT_OFF));
        *mat_slot = mat;
        // Release old (likely shared default at high refcount).
        if (old_mat) {
            const long prev = _InterlockedExchangeAdd(
                reinterpret_cast<long*>(
                    reinterpret_cast<char*>(old_mat) + NIAV_REFCOUNT_OFF), -1);
            if (prev == 1) {
                void** old_vt = *reinterpret_cast<void***>(old_mat);
                using DtorFn = void(*)(void*);
                auto dtor = reinterpret_cast<DtorFn>(old_vt[1]);
                dtor(old_mat);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 5. (DISABLED 2026-05-01 16:15 — SUSPECTED CRASH CAUSE)
    //    Original step 5 wrote bgsm path to shader+0x10 via fs_create,
    //    intended so apply_materials_walker could re-resolve textures.
    //    Test 16:09:18 crashed in render walk after this setup; possible
    //    causes: BSFixedString refcount mismanagement, walker AVing on
    //    handle format, or both. Skip both fs_create AND apply_materials_
    //    walker for now — see commented-out call at the end of
    //    ghost_attach_mesh_blob. If mesh now renders pink/garbage but
    //    doesn't crash → confirmed this path was the culprit; can re-add
    //    once the format is right.
    (void)fs_create;
    (void)bgsm_path;

    // 6. Write shader to BSGeometry+0x138 with refcount bump.
    __try {
        _InterlockedIncrement(reinterpret_cast<long*>(
            reinterpret_cast<char*>(shader) + NIAV_REFCOUNT_OFF));
        *reinterpret_cast<void**>(
            reinterpret_cast<char*>(bs) + BSGEOM_SHADERPROP_OFF) = shader;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }

    return shader;
}

// SEH-protected factory call. Returns nullptr on AV / NULL result.
//
// build_mesh_extra=1 (matches inject_debug_cube): the factory allocates
// a BSPositionData wrapper for the geometry — required for GPU upload.
//
// Test 21:10 confirmed: passing positions-only (rest NULL) generates a
// minimal vd (0x100000000002, stride 8). Donor shader expects full-
// attribute layout → render walk AVs. Fix: pass dummy UVs/normals/
// tangents/colors so factory generates a full vd matching what shaders
// expect (matches cube path).
void* seh_geo_builder(GeoBuilderFn fn,
                      int tri_count, void* indices_u16, unsigned vert_count,
                      void* positions_vec3, void* uvs_vec2,
                      void* tangents_vec4, void* normals_vec3,
                      void* colors_vec4) {
    __try {
        return fn(tri_count, indices_u16, vert_count, positions_vec3,
                  /*uvs*/        uvs_vec2,
                  /*tangents*/   tangents_vec4,
                  /*pos_alt*/    nullptr,
                  /*normals*/    normals_vec3,
                  /*colors*/     colors_vec4,
                  /*sk_w*/       nullptr,
                  /*sk_idx*/     nullptr,
                  /*tan_ex*/     nullptr,
                  /*eye_data*/   nullptr,
                  /*norm_alt*/   nullptr,
                  /*remap*/      nullptr,
                  /*build_extra*/1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

} // namespace

int ghost_attach_mesh_blob(const char* peer_id, std::uint32_t item_form_id,
                            std::uint32_t equip_seq,
                            const void*  meshes_blob_ptr) {
    if (!peer_id || !meshes_blob_ptr) return -1;
    const auto* meshes =
        reinterpret_cast<const std::vector<fw::dispatch::PendingMeshRecord>*>(
            meshes_blob_ptr);
    if (meshes->empty()) {
        FW_DBG("[mesh-attach] peer=%s form=0x%X equip_seq=%u empty mesh list — no-op",
               peer_id, item_form_id, equip_seq);
        return 0;
    }

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        FW_WRN("[mesh-attach] peer=%s no ghost spawned yet — drop blob "
               "(equip_seq=%u, %zu meshes)",
               peer_id, equip_seq, meshes->size());
        return -1;
    }
    if (!g_resolved.load(std::memory_order_acquire) ||
        !g_r.geo_builder ||
        !g_r.attach_child_direct ||
        !g_r.detach_child ||
        !g_r.allocate ||
        !g_r.ninode_ctor)
    {
        FW_WRN("[mesh-attach] engine refs not resolved — skip");
        return -1;
    }

    // ---- 1. Find attach parent (RArm_Hand etc.) ------------------------
    void* attach_node = find_weapon_attach_node();
    if (!attach_node) {
        FW_ERR("[mesh-attach] no WEAPON / RArm_Hand attach node in cached "
               "ghost skel (peer=%s) — cannot attach", peer_id);
        return -1;
    }

    // ---- 2. REPLACEMENT — destroy any previous weapon root for this peer
    void* old_root = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_root_mtx);
        auto it = g_ghost_weapon_root.find(peer_id);
        if (it != g_ghost_weapon_root.end()) {
            old_root = it->second;
            g_ghost_weapon_root.erase(it);
        }
    }
    if (old_root) {
        void* removed = nullptr;
        if (!seh_detach_child_armor(g_r.detach_child, attach_node,
                                     old_root, &removed)) {
            FW_WRN("[mesh-attach] SEH detaching old weapon root peer=%s old=%p "
                   "(continuing — replacement)", peer_id, old_root);
        }
        const long after = seh_refcount_dec_armor(old_root);
        FW_DBG("[mesh-attach] dropped old weapon root peer=%s old=%p "
               "refcount_after=%ld", peer_id, old_root, after);
    }

    // ---- 3. Pool init guard --------------------------------------------
    if (g_r.pool_init_flag &&
        *g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
        FW_DBG("[mesh-attach] pool not ready, initializing");
        g_r.pool_init(g_r.pool, g_r.pool_init_flag);
    }

    // ---- 4. Allocate fresh weapon root NiNode --------------------------
    void* weapon_root = g_r.allocate(g_r.pool, NINODE_SIZEOF, NINODE_ALIGN, true);
    if (!weapon_root) {
        FW_ERR("[mesh-attach] alloc(NiNode) returned null (peer=%s)", peer_id);
        return -1;
    }
    g_r.ninode_ctor(weapon_root, /*capacity=*/0);
    {
        // Sanity: vt should match NiNode's vftable.
        void* vt = seh_read_vt(weapon_root);
        const void* expected_vt = reinterpret_cast<void*>(
            g_r.base + NINODE_VTABLE_RVA);
        if (vt != expected_vt) {
            FW_ERR("[mesh-attach] ninode_ctor produced wrong vtable "
                   "got=%p expected=%p — leak alloc, abort",
                   vt, expected_vt);
            return -1;
        }
    }
    // Optional: name the root so it shows in scene dumps.
    {
        char name_buf[64];
        std::snprintf(name_buf, sizeof(name_buf), "WeaponRoot_%s", peer_id);
        std::uint64_t name_handle = 0;
        g_r.fs_create(&name_handle, name_buf);
        if (name_handle) {
            g_r.set_name(weapon_root, reinterpret_cast<void*>(name_handle));
            g_r.fs_release(&name_handle);
        }
    }

    // Mark weapon_root MOVABLE — required so the engine recomputes its
    // world transform each frame as the parent bone (RArm_Hand) moves
    // with the body anim. Without this, the weapon stays glued to the
    // first frame's RArm_Hand world pose and clips through the body
    // when the peer walks/turns.
    seh_set_movable_flag(weapon_root);

    // Pre-bump our +1 ref. attach_child_direct will Inc once for the slot.
    seh_refcount_inc_local(weapon_root);

    // Attach the weapon root to the bone.
    if (!seh_attach_child_armor(g_r.attach_child_direct, attach_node, weapon_root)) {
        FW_ERR("[mesh-attach] SEH attaching weapon root to bone (peer=%s)",
               peer_id);
        // weapon_root ref leaks — safer than free path
        return -1;
    }

    // ---- 4.5. DONOR PATTERN — load base weapon NIF, harvest shader+alpha
    //
    // Bisect 20:54 + 21:03 confirmed: manual shader setup (bslsp_new +
    // bgsm_load + swap) crashes the render walk; apply_materials_walker
    // does NOT auto-allocate shader for shader=NULL geoms.
    //
    // Donor pattern: load the base weapon NIF (e.g. 10mmPistol.nif) via
    // nif_load_by_path. The engine builds a complete BSFadeNode tree with
    // proper BSLightingShaderProperty + material + texture chain on each
    // BSTriShape (apply_materials in POSTPROC resolves DDS). We harvest
    // the FIRST BSGeometry's shader+alpha pointers, refcount-bump them,
    // and write the same pointers into our factory-built BSTriShapes.
    //
    // Result: our factory shapes share a working shader chain. All 8
    // meshes will render with the FIRST donor shape's material — for a
    // 10mm pistol that's typically the receiver bgsm. Suboptimal (per-
    // mesh material variation lost) but VISIBLE, which is the PoC goal.
    // Per-mesh material match-by-name is a follow-up refinement.
    void* donor_root = nullptr;
    void* donor_shader = nullptr;
    void* donor_alpha = nullptr;
    {
        // Derive donor NIF path. Strategy:
        //   1. PRIMARY: derive from first mesh's bgsm_path
        //      (e.g. "Materials\Weapons\10mmPistol\10mmPistol.BGSM"
        //       → "Weapons\10mmPistol\10mmPistol.nif")
        //      Direct mapping, always returns the actual base weapon NIF.
        //   2. FALLBACK: resolve_weapon_nif_path's TESModel offset probe.
        //      Often returns wrong slot (e.g. "10mmRecieverDummy.nif"
        //      placeholder for the 10mm pistol — empty NIF, no BSGeometry).
        std::string nif_from_bgsm;
        if (!meshes->empty()) {
            const std::string& bgsm = (*meshes)[0].bgsm_path;
            if (!bgsm.empty()) {
                std::string trimmed = bgsm;
                static const char kPrefix[] = "Materials\\";
                static const char kPrefixLow[] = "materials\\";
                const std::size_t plen = sizeof(kPrefix) - 1;
                if (trimmed.size() >= plen &&
                    (std::strncmp(trimmed.c_str(), kPrefix, plen) == 0 ||
                     std::strncmp(trimmed.c_str(), kPrefixLow, plen) == 0))
                {
                    trimmed = trimmed.substr(plen);
                }
                // Replace last extension (.BGSM/.bgsm) with .nif
                const std::size_t dot = trimmed.find_last_of('.');
                if (dot != std::string::npos) {
                    trimmed.replace(dot, std::string::npos, ".nif");
                }
                nif_from_bgsm = std::move(trimmed);
            }
        }
        const char* base_nif_path = nif_from_bgsm.empty()
            ? resolve_weapon_nif_path(item_form_id)
            : nif_from_bgsm.c_str();
        if (base_nif_path && g_r.nif_load_by_path) {
            NifLoadOpts opts{};
            opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;
            std::uint8_t* ks = (g_r.base != 0)
                ? reinterpret_cast<std::uint8_t*>(g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA)
                : nullptr;
            const std::uint8_t saved = ks ? *ks : 0;
            if (ks) *ks = 1;
            const std::uint32_t rc = seh_nif_load_armor(
                g_r.nif_load_by_path, base_nif_path, &donor_root, &opts);
            if (rc == 0 && donor_root && g_r.apply_materials) {
                seh_apply_materials_armor(g_r.apply_materials, donor_root);
            }
            if (ks) *ks = saved;

            if (rc != 0 || !donor_root) {
                FW_WRN("[mesh-attach] donor: nif_load_by_path('%s') rc=%u "
                       "donor=%p — proceeding without donor (meshes will "
                       "be invisible)",
                       base_nif_path, rc, donor_root);
                donor_root = nullptr;
            } else {
                void* donor_geom = seh_find_first_geom_dfs(donor_root);
                if (donor_geom) {
                    donor_shader = seh_read_ptr_at(donor_geom,
                        BSGEOM_SHADERPROP_OFF);
                    donor_alpha = seh_read_ptr_at(donor_geom,
                        BSGEOM_ALPHAPROP_OFF);
                    FW_LOG("[mesh-attach] donor: base='%s' geom=%p "
                           "shader=%p alpha=%p (will be shared across all "
                           "%zu factory meshes)",
                           base_nif_path, donor_geom, donor_shader,
                           donor_alpha, meshes->size());

                    // DIAGNOSTIC: dump donor BSGeometry state — compare
                    // against our factory output to identify mismatches.
                    BsTriDiagState ds{};
                    seh_dump_bstri_state(donor_geom, g_r.base, &ds);
                    FW_LOG("[mesh-attach][DIAG] DONOR geom=%p vt_rva=0x%llX "
                           "rc=%u flags=0x%llX skin=%p posdata=%p vd=0x%llX "
                           "idx=%u vert=%u bound_r=%.2f",
                           donor_geom,
                           static_cast<unsigned long long>(ds.vt_rva),
                           ds.refcount,
                           static_cast<unsigned long long>(ds.flags),
                           ds.skin_inst, ds.pos_data,
                           static_cast<unsigned long long>(ds.vertex_desc),
                           ds.idx_count, ds.vert_count, ds.bound_r);
                } else {
                    FW_WRN("[mesh-attach] donor: no BSGeometry under "
                           "donor_root=%p — release donor + skip",
                           donor_root);
                }
            }
        }
    }

    // ---- 5. Per mesh: factory → donor share → transform → attach ------
    int attached_meshes = 0;
    int failed_meshes = 0;
    int bound_materials = 0;  // count of donor-shared shaders
    std::uint8_t* mesh_killswitch = nullptr;
    if (g_r.base) {
        mesh_killswitch = reinterpret_cast<std::uint8_t*>(
            g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
    }
    for (std::size_t i = 0; i < meshes->size(); ++i) {
        const auto& m = (*meshes)[i];
        if (m.vert_count == 0 || m.tri_count == 0
            || m.positions.empty() || m.indices.empty())
        {
            FW_DBG("[mesh-attach] mesh[%zu] '%s' empty (vc=%u tc=%u) — skip",
                   i, m.m_name.c_str(), m.vert_count, m.tri_count);
            continue;
        }

        // Defensive cast: factory wants non-const pointers (it doesn't
        // mutate, but old C signature). const_cast is safe here.
        void* idx_ptr = const_cast<std::uint16_t*>(m.indices.data());
        void* pos_ptr = const_cast<float*>(m.positions.data());

        // Dummy UVs/normals/tangents — match donor's vd (stride 20 = 5*4).
        // Diag 21:38 confirmed donor vd=0x1B00000430205 (low nibble 0x5 →
        // stride 20). Adding colors → stride 24 (low nibble 0x6) → vd
        // mismatch with donor shader → render AV. So skip colors.
        std::vector<float> dummy_uvs(static_cast<std::size_t>(m.vert_count) * 2, 0.0f);
        std::vector<float> dummy_normals(static_cast<std::size_t>(m.vert_count) * 3);
        std::vector<float> dummy_tangents(static_cast<std::size_t>(m.vert_count) * 4);
        for (std::uint16_t v = 0; v < m.vert_count; ++v) {
            dummy_normals[v*3+0] = 0.0f;
            dummy_normals[v*3+1] = 0.0f;
            dummy_normals[v*3+2] = 1.0f;  // up
            dummy_tangents[v*4+0] = 1.0f;
            dummy_tangents[v*4+1] = 0.0f;
            dummy_tangents[v*4+2] = 0.0f;
            dummy_tangents[v*4+3] = 1.0f;
        }

        void* bs = seh_geo_builder(
            g_r.geo_builder,
            static_cast<int>(m.tri_count),
            idx_ptr,
            static_cast<unsigned>(m.vert_count),
            pos_ptr,
            dummy_uvs.data(),
            dummy_tangents.data(),
            dummy_normals.data(),
            nullptr /* no colors → stride 20 to match donor */);
        if (!bs) {
            FW_WRN("[mesh-attach] mesh[%zu] '%s' factory returned null / SEH "
                   "(vc=%u tc=%u)", i, m.m_name.c_str(), m.vert_count, m.tri_count);
            ++failed_meshes;
            continue;
        }
        FW_DBG("[mesh-attach] mesh[%zu] '%s' factory OK bs=%p (vc=%u tc=%u)",
               i, m.m_name.c_str(), bs, m.vert_count, m.tri_count);

        // DIAGNOSTIC: dump BSTriShape state immediately post-factory (only
        // for first 2 meshes per blob to avoid log spam).
        if (i < 2) {
            BsTriDiagState st{};
            seh_dump_bstri_state(bs, g_r.base, &st);
            FW_LOG("[mesh-attach][DIAG] mesh[%zu] '%s' POST-FACTORY: "
                   "vt_rva=0x%llX rc=%u flags=0x%llX alpha=%p shader=%p "
                   "skin=%p posdata=%p vd=0x%llX idx=%u vert=%u",
                   i, m.m_name.c_str(),
                   static_cast<unsigned long long>(st.vt_rva),
                   st.refcount,
                   static_cast<unsigned long long>(st.flags),
                   st.alpha_prop, st.shader_prop, st.skin_inst, st.pos_data,
                   static_cast<unsigned long long>(st.vertex_desc),
                   st.idx_count, st.vert_count);
            FW_LOG("[mesh-attach][DIAG] mesh[%zu] bound=(%.2f,%.2f,%.2f) r=%.2f "
                   "world.t=(%.2f,%.2f,%.2f)",
                   i, st.bound_x, st.bound_y, st.bound_z, st.bound_r,
                   st.world_tx, st.world_ty, st.world_tz);
        }

        // B-2 DONOR SHARE — RE-ENABLED 2026-05-01 21:42
        // Bisect 21:38 confirmed: shader share previously crashed because
        // factory output vd (0x...3206 stride 24) didn't match donor's vd
        // (0x...0205 stride 20). Now factory call uses 4 attributes (no
        // colors) → stride 20 → matches donor → shader vertex compatible.
        if (donor_shader) {
            seh_refcount_inc_local(donor_shader);
            seh_write_ptr_at(bs, BSGEOM_SHADERPROP_OFF, donor_shader);
            ++bound_materials;
        }
        if (donor_alpha) {
            seh_refcount_inc_local(donor_alpha);
            seh_write_ptr_at(bs, BSGEOM_ALPHAPROP_OFF, donor_alpha);
        }

        // Write local_transform (16 floats = NiTransform: rot 3x4 + trans + scale)
        if (!seh_write_local_transform(bs, m.local_transform)) {
            FW_WRN("[mesh-attach] mesh[%zu] '%s' SEH writing local_transform "
                   "— continuing without xform", i, m.m_name.c_str());
        }

        // DIAGNOSTIC: dump state after bgsm bind + transform write.
        if (i < 2) {
            BsTriDiagState st{};
            seh_dump_bstri_state(bs, g_r.base, &st);
            FW_LOG("[mesh-attach][DIAG] mesh[%zu] POST-BGSM+XFORM: "
                   "shader=%p flags=0x%llX bound_r=%.2f world.t=(%.2f,%.2f,%.2f)",
                   i, st.shader_prop,
                   static_cast<unsigned long long>(st.flags),
                   st.bound_r,
                   st.world_tx, st.world_ty, st.world_tz);
        }

        // Mark BSTriShape MOVABLE — the geometry inherits world from
        // weapon_root, but the engine still needs the per-node movable
        // bit to walk the update propagation through it.
        seh_set_movable_flag(bs);

        // Pre-bump our +1 ref before attach (matches engine pattern).
        seh_refcount_inc_local(bs);
        if (!seh_attach_child_armor(g_r.attach_child_direct, weapon_root, bs)) {
            FW_WRN("[mesh-attach] mesh[%zu] '%s' SEH on attach_child — drop",
                   i, m.m_name.c_str());
            ++failed_meshes;
            continue;
        }
        ++attached_meshes;
    }

    // ---- 6. Force world-transform recomputation ------------------------
    // Without this, each freshly-attached BSTriShape's world.translate
    // stays at (0,0,0) (identity from ctor) until the next frame's
    // engine update walks it. UpdateDownwardPass walks the subtree
    // immediately and recomputes world from local. Identical pattern
    // to inject_debug_cube post-attach (line ~1188-1197).
    // ---- 6.5. apply_materials_walker — DISABLED 2026-05-01 21:35 ------
    // Test 21:31 with donor-shared shader + leak STILL crashed in render
    // walk. Hypothesis: walker traverses our 8 BSTriShapes (all sharing
    // the SAME donor shader), calls bgsm_load + swap material on shader
    // multiple times — possibly corrupting shader's internal state. The
    // donor was already loaded with POSTPROC + apply_materials at load
    // time, so its shader+material+textures are already wired and don't
    // need re-walk. Skip for diagnostic — if no crash → walker is culprit.
    if (false /* g_r.apply_materials */) {
        const std::uint8_t saved_ks = mesh_killswitch ? *mesh_killswitch : 0;
        if (mesh_killswitch) *mesh_killswitch = 1;
        seh_apply_materials_armor(g_r.apply_materials, weapon_root);
        if (mesh_killswitch) *mesh_killswitch = saved_ks;
        FW_DBG("[mesh-attach] apply_materials_walker(weapon_root=%p) called",
               weapon_root);

        // Diagnostic: dump first 2 meshes' state POST-WALKER. If walker
        // populated shader/alpha, those slots will be non-null.
        for (std::size_t i = 0; i < std::min<std::size_t>(2, meshes->size()); ++i) {
            void** kids = nullptr;
            std::uint16_t cnt = 0;
            if (seh_read_children_w4(weapon_root, kids, cnt) && kids
                && i < cnt)
            {
                void* bs_i = seh_kid_at_w4(kids, static_cast<std::uint16_t>(i));
                if (bs_i) {
                    BsTriDiagState st{};
                    seh_dump_bstri_state(bs_i, g_r.base, &st);
                    FW_LOG("[mesh-attach][DIAG] mesh[%zu] POST-WALKER: "
                           "shader=%p alpha=%p flags=0x%llX",
                           i, st.shader_prop, st.alpha_prop,
                           static_cast<unsigned long long>(st.flags));
                }
            }
        }
    }

    if (g_r.update_downward) {
        seh_update_downward(g_r.update_downward, weapon_root);
        FW_DBG("[mesh-attach] update_downward(weapon_root=%p) called",
               weapon_root);

        // DIAGNOSTIC: dump first 2 meshes' state POST-UPDATE-DOWNWARD.
        // If world.t is now non-zero (close to RArm_Hand world position),
        // the transform pipeline works. If still (0,0,0), the mesh is
        // rendered at world origin — nowhere near the player.
        for (std::size_t i = 0; i < std::min<std::size_t>(2, meshes->size()); ++i) {
            // Find the i-th attached BSTriShape via weapon_root children.
            void** kids = nullptr;
            std::uint16_t cnt = 0;
            if (seh_read_children_w4(weapon_root, kids, cnt) && kids
                && i < cnt)
            {
                void* bs_i = seh_kid_at_w4(kids, static_cast<std::uint16_t>(i));
                if (bs_i) {
                    BsTriDiagState st{};
                    seh_dump_bstri_state(bs_i, g_r.base, &st);
                    FW_LOG("[mesh-attach][DIAG] mesh[%zu] POST-UPDATE-DOWNWARD: "
                           "world.t=(%.2f,%.2f,%.2f) bound_r=%.2f flags=0x%llX",
                           i,
                           st.world_tx, st.world_ty, st.world_tz,
                           st.bound_r,
                           static_cast<unsigned long long>(st.flags));
                }
            }
        }
    }

    // ---- 7. Cache new weapon root --------------------------------------
    {
        std::lock_guard lk(g_ghost_weapon_root_mtx);
        g_ghost_weapon_root[peer_id] = weapon_root;
    }

    // ---- 8. Donor LEAK (deliberate, 2026-05-01 21:25) -----------------
    // PROBLEM: releasing donor here drops its BSTriShape's +1 ref to the
    // shared shader+material+textures. While we refcount-bumped the
    // shader (each mesh has +1 on shader), the SHADER->material->texture
    // chain has its OWN refcounts and we only have one level of ref.
    // When donor's BSTriShape destructs, it dec's material refs, and
    // possibly the texture handles inside material lose their last ref →
    // freed → render walk dereferences freed texture → AV.
    //
    // Temp fix: leak the donor BSFadeNode (don't refcount-dec). Memory
    // cost ~70 KB per equip event. Acceptable for PoC. Proper fix is
    // to walk the donor BSGeometry → shader → material → texture slots
    // and refcount-bump the textures explicitly before donor release.
    if (donor_root) {
        FW_DBG("[mesh-attach] donor LEAKED (root=%p) — refcount intact, "
               "shared textures stay alive (proper fix: deep refcount-bump)",
               donor_root);
    }

    FW_LOG("[mesh-attach] peer=%s form=0x%X equip_seq=%u weapon_root=%p "
           "attach_node=%p attached=%d/%zu (failed=%d, donor_shared=%d)",
           peer_id, item_form_id, equip_seq, weapon_root, attach_node,
           attached_meshes, meshes->size(), failed_meshes, bound_materials);
    return attached_meshes;
}

bool ghost_detach_mesh_blob(const char* peer_id) {
    if (!peer_id) return false;

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        FW_DBG("[mesh-detach] peer=%s no ghost — no-op", peer_id);
        return true;  // idempotent
    }
    if (!g_resolved.load(std::memory_order_acquire) || !g_r.detach_child) {
        FW_WRN("[mesh-detach] engine refs not resolved — skip");
        return false;
    }

    void* weapon_root = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_root_mtx);
        auto it = g_ghost_weapon_root.find(peer_id);
        if (it == g_ghost_weapon_root.end()) {
            FW_DBG("[mesh-detach] peer=%s no weapon root cached — no-op",
                   peer_id);
            return true;
        }
        weapon_root = it->second;
        g_ghost_weapon_root.erase(it);
    }
    if (!weapon_root) return true;

    void* attach_node = find_weapon_attach_node();
    if (!attach_node) {
        FW_WRN("[mesh-detach] peer=%s attach parent gone — orphaned weapon "
               "root leaked at %p", peer_id, weapon_root);
        return false;
    }

    void* removed = nullptr;
    if (!seh_detach_child_armor(g_r.detach_child, attach_node,
                                 weapon_root, &removed)) {
        FW_ERR("[mesh-detach] SEH in detach_child(parent=%p, root=%p)",
               attach_node, weapon_root);
        return false;
    }

    const long after = seh_refcount_dec_armor(weapon_root);
    FW_LOG("[mesh-detach] peer=%s weapon_root=%p refcount_after=%ld OK",
           peer_id, weapon_root, after);
    return true;
}

// === M9 wedge 4 v9.1 — UNIFIED ghost weapon state machine =================
//
// See header doc for design. Implementation notes:
//
// State: g_ghost_weapon_slot[peer_id] = {form_id, nif_node, nif_path}
// Mutex: g_ghost_weapon_slot_mtx (per-process; per-peer would be overkill
// since we're main-thread-only).
//
// Path resolution:
//   1. Try each caller-provided candidate. First load that succeeds wins.
//   2. If all fail, try resolve_weapon_nif_path (legacy probe).
//   3. If everything fails, return false. Existing slot untouched.
//
// Atomic transitions:
//   - On success: detach old (if any), attach new, update slot
//   - Idempotent: same form_id + same path → no engine work
//   - Downgrade rejected: new placeholder vs current proper → no-op
namespace {

struct GhostWeaponSlot {
    std::uint32_t form_id   = 0;
    void*         nif_node  = nullptr;
    std::string   nif_path;
    // 2026-05-05 — list of cached mod nodes we've attached to this base
    // via attach_extra_node_to_ghost_weapon. Tracked so the next equip
    // can detach + refdec all of them BEFORE attaching new ones —
    // otherwise the cached BSFadeNode (shared across equip cycles via
    // the resmgr) accumulates child references and their geometry
    // shows up duplicated / floating on the ghost.
    //
    // Stored as opaque void* (NiAVObject*); refbump is balanced 1-to-1
    // with attach (we refbump pre-attach, refdec on detach below).
    std::vector<void*> extra_mods;
    // Whether we've already run cull_geometry_leaves on this base node.
    // The cull walker recurses into all BSGeometry-derived leaves in
    // the subtree — if we ran it on every equip, after the first one
    // the walker would also descend into our `extra_mods` and cull
    // their geometry too (the cached base persists with the mods we
    // attached on the previous equip). Once-per-base is sufficient
    // because the stock leaves stay culled.
    bool          base_culled = false;
};

std::mutex g_ghost_weapon_slot_mtx;
std::unordered_map<std::string, GhostWeaponSlot> g_ghost_weapon_slot;

}  // close enclosing anon namespace temporarily so the orphan-sweep
   // helpers below can reference g_ghost_weapon_slot{,_mtx} (which were
   // declared inside it) without nested anon-namespace gymnastics.

// 2026-05-06 evening (M9 closure, ATTEMPT #5) — orphan clone sweep
// implementation. Forward-declared near clone_nif_subtree. See the big
// comment block there for rationale. This lives down here because it
// references both seh_refcount_dec_armor (~line 3686) and the slot
// map (declared just above this block).
namespace {

// SEH-only helper — pure POD args, no C++ object destruction, so MSVC
// allows __try here. Returns true iff engine reported `removed != null`.
bool seh_purge_detach(void* parent, void* child) {
    if (!parent || !child || !g_r.detach_child) return false;
    void* removed = nullptr;
    __try {
        g_r.detach_child(parent, child, &removed);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return removed != nullptr;
}

// Detach + refdec every tracked clone EXCEPT those in `keep_set`.
// Returns count of clones swept (detached or already-orphaned).
int purge_owned_clones_except(const std::unordered_set<void*>& keep_set) {
    std::vector<void*> to_check;
    {
        std::lock_guard lk(g_owned_clones_mtx);
        to_check.reserve(g_owned_clones.size());
        for (void* c : g_owned_clones) {
            if (keep_set.count(c) == 0) {
                to_check.push_back(c);
            }
        }
        // Remove non-keep entries from the global set NOW so we don't
        // re-sweep them on a later call (refdec below may free them).
        for (void* c : to_check) {
            g_owned_clones.erase(c);
        }
    }

    int detached = 0;
    int orphaned = 0;
    for (void* c : to_check) {
        if (!c) continue;
        void* parent = weapon_witness::read_parent_pub(c);
        if (parent) {
            if (seh_purge_detach(parent, c)) ++detached;
        } else {
            ++orphaned;
        }
        // Drop our +1 refbump regardless.
        seh_refcount_dec_armor(c);
    }
    if (!to_check.empty()) {
        std::size_t remaining = 0;
        {
            std::lock_guard lk(g_owned_clones_mtx);
            remaining = g_owned_clones.size();
        }
        FW_LOG("[orphan-purge] swept=%zu detached=%d orphaned=%d "
               "(remaining_tracked=%zu)",
               to_check.size(), detached, orphaned, remaining);
    }
    return static_cast<int>(to_check.size());
}

}  // anon namespace

// Public — see forward decl. Builds the keep-set from the live slot map.
void purge_orphan_weapon_clones() {
    std::unordered_set<void*> keep;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        for (auto& [pid, slot] : g_ghost_weapon_slot) {
            (void)pid;
            if (slot.nif_node) keep.insert(slot.nif_node);
            for (void* m : slot.extra_mods) {
                if (m) keep.insert(m);
            }
        }
    }
    purge_owned_clones_except(keep);
}

// Re-open the original anon namespace so subsequent helpers
// (is_placeholder_nif_path, load_one_weapon_nif, etc.) compile as before.
namespace {

// Returns true iff the given path looks like a placeholder/dummy NIF.
// Mirrors the filter in resolve_weapon_nif_path. Used here for downgrade
// protection — we never replace a proper NIF with a placeholder.
bool is_placeholder_nif_path(const std::string& path) {
    if (path.empty()) return true;
    // Generic case-insensitive "Dummy" substring match.
    for (std::size_t i = 0; i + 5 <= path.size(); ++i) {
        char a = path[i+0]; if (a >= 'A' && a <= 'Z') a = a - 'A' + 'a';
        char b = path[i+1]; if (b >= 'A' && b <= 'Z') b = b - 'A' + 'a';
        char c = path[i+2]; if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        char d = path[i+3]; if (d >= 'A' && d <= 'Z') d = d - 'A' + 'a';
        char e = path[i+4]; if (e >= 'A' && e <= 'Z') e = e - 'A' + 'a';
        if (a=='d' && b=='u' && c=='m' && d=='m' && e=='y') return true;
    }
    return false;
}

// Try to load + apply_materials a single NIF path. Returns the loaded
// node on success (refcount=1, owned by caller). Returns nullptr on any
// failure. SEH-wrapped via existing helpers.
void* load_one_weapon_nif(const char* path) {
    if (!path || !path[0]) return nullptr;
    if (!g_resolved.load(std::memory_order_acquire)) return nullptr;
    if (!g_r.nif_load_by_path) return nullptr;

    // Pool init guard.
    if (g_r.pool_init_flag &&
        *g_r.pool_init_flag != POOL_INIT_FLAG_READY) {
        g_r.pool_init(g_r.pool, g_r.pool_init_flag);
    }

    NifLoadOpts opts{};
    opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;

    std::uint8_t* killswitch_byte = reinterpret_cast<std::uint8_t*>(
        g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
    const std::uint8_t saved_ks = *killswitch_byte;
    *killswitch_byte = 1;

    void* node = nullptr;
    const std::uint32_t rc = seh_nif_load_armor(
        g_r.nif_load_by_path, path, &node, &opts);
    if (rc == 0xDEADBEEFu || rc != 0 || !node) {
        *killswitch_byte = saved_ks;
        return nullptr;
    }
    seh_apply_materials_armor(g_r.apply_materials, node);
    *killswitch_byte = saved_ks;
    return node;
}

// Detach a weapon NIF from its actual scene-graph parent and drop our +1
// ref. SEH-wrapped.
//
// 2026-05-06 evening — was: `detach_child(find_weapon_attach_node(), node)`
// which silently no-op'd when `node`'s actual parent wasn't the live
// WEAPON pointer (e.g., engine swapped BipedAnim → WEAPON ptr changed,
// clone's +0x28 still points at the OLD WEAPON which is no longer
// returned by find_weapon_attach_node). Symptom: pistols accumulated
// on the local PC's hand across ghost-peer equips because every "old"
// clone failed to detach. Fix: read clone's actual parent via +0x28
// (NiAVObject::m_pkParent) and detach from THERE — same primitive as
// Agent D's clear_ghost_extra_mods fix.
void release_weapon_node(void* node) {
    if (!node) return;
    if (!g_r.detach_child) {
        seh_refcount_dec_armor(node);
        return;
    }

    void* parent = weapon_witness::read_parent_pub(node);
    if (parent) {
        void* removed = nullptr;
        __try {
            g_r.detach_child(parent, node, &removed);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_WRN("[release-weapon] SEH detach node=%p parent=%p", node,
                   parent);
        }
        FW_DBG("[release-weapon] node=%p detached from parent=%p (removed=%p)",
               node, parent, removed);
    } else {
        FW_DBG("[release-weapon] node=%p has no parent (already orphaned)",
               node);
    }
    // Remove from the global clone tracker BEFORE the refdec so the
    // next purge_orphan_weapon_clones doesn't see a dangling pointer
    // (the refdec below may free `node` if refcount hits 0).
    untrack_owned_clone(node);
    seh_refcount_dec_armor(node);
}

} // namespace

bool ghost_set_weapon(const char* peer_id,
                       std::uint32_t item_form_id,
                       const char* const* candidate_paths,
                       std::size_t num_candidates) {
    if (!peer_id || item_form_id == 0) return false;

    // 2026-05-06 evening (M9 closure) — UNCONDITIONALLY clear any
    // tracked extra mods from the PREVIOUS equip cycle BEFORE any
    // other work. Was: extras only cleared inside the lock when the
    // base node pointer changed (`old_node != new_node`). With cache-
    // share (clone failure path), old_node == new_node, so extras
    // never got cleared, and the IDEMPOTENT branch (same form_id +
    // same path) didn't clear them either. Result: each equip
    // accumulated mods on top of previous equip's mods. User
    // reported: "cambio arma senza silenziatore ma il silenziatore
    // ora permane".
    //
    // clear_ghost_extra_mods now does proper detach-via-parent-ptr
    // (Agent D fix) so the cached BSFadeNode actually loses our mod
    // children — not just our refbump.
    clear_ghost_extra_mods(peer_id);

    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) {
        FW_DBG("[set-weapon] peer=%s no ghost yet — skip", peer_id);
        return false;
    }
    if (!g_resolved.load(std::memory_order_acquire)) {
        FW_DBG("[set-weapon] peer=%s engine refs not resolved — skip", peer_id);
        return false;
    }

    void* attach_node = find_weapon_attach_node();
    if (!attach_node) {
        FW_WRN("[set-weapon] peer=%s no WEAPON attach node — skip", peer_id);
        return false;
    }

    // ---- Phase 1: try caller candidates, fall back to legacy resolve.
    //
    // 2026-05-06 PM (M9 closure) — load returns a cached BSFadeNode shared
    // across every actor that ever loaded the same path (incl. the local
    // PC and every other ghost). Mutating it (apply_materials, attach
    // child mods, write transforms) corrupts every other consumer.
    // Six independent RE agents on the full FO4 decomp converged on
    // vt[26] (NetImmerse Clone slot) as the engine's own per-actor
    // instance mechanism — `sub_140359870` (biped rebuilder) calls
    // `sub_1416BA8E0` which dispatches to vt[26] for every equip on
    // every actor. We replicate that here: load → clone → release source.
    std::string winning_path;
    void* new_node = nullptr;
    for (std::size_t i = 0; i < num_candidates && !new_node; ++i) {
        const char* p = candidate_paths[i];
        if (!p || !p[0]) continue;
        FW_DBG("[set-weapon] peer=%s form=0x%X try candidate[%zu]='%s'",
               peer_id, item_form_id, i, p);
        void* source = load_one_weapon_nif(p);
        if (source) {
            void* clone = clone_nif_subtree(source);
            if (clone && clone != source) {
                // Engine deep-clone succeeded — release the cached source
                // ref we held. The clone is ours alone, refcount=1.
                seh_refcount_dec_armor(source);
                new_node = clone;
                winning_path = p;
                // Track for the orphan-purge sweep (weapon clones only).
                track_owned_clone(clone);
                FW_LOG("[set-weapon] peer=%s form=0x%X loaded candidate[%zu]='%s' "
                       "source=%p clone=%p (engine deep-clone)",
                       peer_id, item_form_id, i, p, source, clone);
            } else {
                // Clone failed — fall back to using the cached source.
                // Worst case: cache-share contamination across peers
                // (= prior behaviour). Better than no weapon.
                FW_WRN("[set-weapon] peer=%s clone failed for '%s' source=%p — "
                       "using cached source (cache-share fallback)",
                       peer_id, p, source);
                new_node = source;
                winning_path = p;
            }
        }
    }
    if (!new_node) {
        const char* legacy = resolve_weapon_nif_path(item_form_id);
        if (legacy) {
            FW_DBG("[set-weapon] peer=%s form=0x%X try legacy='%s'",
                   peer_id, item_form_id, legacy);
            void* source = load_one_weapon_nif(legacy);
            if (source) {
                void* clone = clone_nif_subtree(source);
                if (clone && clone != source) {
                    seh_refcount_dec_armor(source);
                    new_node = clone;
                    winning_path = legacy;
                    track_owned_clone(clone);
                    FW_LOG("[set-weapon] peer=%s form=0x%X loaded legacy='%s' "
                           "source=%p clone=%p (engine deep-clone)",
                           peer_id, item_form_id, legacy, source, clone);
                } else {
                    FW_WRN("[set-weapon] peer=%s clone failed for legacy='%s' "
                           "source=%p — using cached source",
                           peer_id, legacy, source);
                    new_node = source;
                    winning_path = legacy;
                }
            }
        }
    }
    if (!new_node) {
        FW_WRN("[set-weapon] peer=%s form=0x%X all paths failed — slot untouched",
               peer_id, item_form_id);
        return false;
    }

    // ---- Phase 2: examine current slot. Wrapped in a scope so the
    // lock releases before we call purge_orphan_weapon_clones (which
    // re-acquires the slot mutex internally to build its keep-set).
    {
    std::lock_guard lk(g_ghost_weapon_slot_mtx);
    auto& slot = g_ghost_weapon_slot[peer_id];

    // Idempotent: same form + same path → release new (we don't need it),
    // keep current.
    if (slot.form_id == item_form_id && slot.nif_path == winning_path
        && slot.nif_node)
    {
        FW_DBG("[set-weapon] peer=%s form=0x%X path='%s' idempotent — release new",
               peer_id, item_form_id, winning_path.c_str());
        release_weapon_node(new_node);
        return true;
    }

    // Downgrade protection: same form_id, current is proper, new is
    // placeholder → reject.
    if (slot.form_id == item_form_id && slot.nif_node
        && !is_placeholder_nif_path(slot.nif_path)
        && is_placeholder_nif_path(winning_path))
    {
        FW_LOG("[set-weapon] peer=%s form=0x%X DOWNGRADE refused — "
               "current='%s' (proper) vs new='%s' (placeholder)",
               peer_id, item_form_id, slot.nif_path.c_str(),
               winning_path.c_str());
        release_weapon_node(new_node);
        return true;
    }

    // ---- Phase 3: detach old, attach new, update slot.
    void* old_node = slot.nif_node;
    const std::uint32_t old_form = slot.form_id;

    if (!seh_attach_child_armor(g_r.attach_child_direct, attach_node, new_node))
    {
        FW_ERR("[set-weapon] peer=%s form=0x%X SEH attaching new node — "
               "release new, keep old",
               peer_id, item_form_id);
        release_weapon_node(new_node);
        return false;
    }

    if (old_node) {
        FW_DBG("[set-weapon] peer=%s detaching old form=0x%X path='%s' node=%p",
               peer_id, old_form, slot.nif_path.c_str(), old_node);
        release_weapon_node(old_node);
    }

    slot.form_id = item_form_id;
    slot.nif_node = new_node;
    slot.nif_path = std::move(winning_path);
    // 2026-05-05 — base node may be the SAME cached BSFadeNode as before
    // (engine resmgr returns shared instance for repeated path loads).
    // If the node pointer changed, treat as a fresh base: reset
    // base_culled flag so the new base's stock leaves get culled, and
    // clear any stale extra_mods pointers (they belonged to the OLD
    // base; the engine's release detached them as part of teardown).
    if (old_node != new_node) {
        slot.base_culled = false;
        // 2026-05-06 evening — extra_mods detach + refdec already done
        // at function entry by clear_ghost_extra_mods(peer_id), which
        // detaches via each mod's actual parent ptr (+0x28) — not just
        // refdec. slot.extra_mods is already empty here.
    }
    FW_LOG("[set-weapon] peer=%s SLOT UPDATED form=0x%X path='%s' node=%p "
           "(was form=0x%X, base_culled=%d, extras=%zu)",
           peer_id, item_form_id, slot.nif_path.c_str(), new_node, old_form,
           slot.base_culled ? 1 : 0, slot.extra_mods.size());
    }  // end Phase 2 lock scope

    // 2026-05-06 evening (M9 closure, ATTEMPT #5) — global orphan sweep.
    // Force-detach + refdec every previously-tracked clone that's NOT
    // referenced by any live slot (slot.nif_node + slot.extra_mods).
    // Defends against accumulation when the per-call cleanup paths fail
    // silently (which they did for 4 prior fix attempts).
    purge_orphan_weapon_clones();

    // ATTEMPT #6 diagnostic — dump complete WEAPON attach state so we
    // can diff "what we attached" vs "what the engine actually sees".
    dump_weapon_attach_state("post-set-weapon");
    return true;
}

bool ghost_clear_weapon(const char* peer_id,
                         std::uint32_t expected_form_id) {
    if (!peer_id) return false;

    // Phase 1 (no lock): pre-validate that the slot exists and matches
    // the expected form_id. If it doesn't match, bail without doing the
    // heavy detach work below.
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end()) {
            FW_DBG("[clear-weapon] peer=%s no slot — no-op", peer_id);
            return true;
        }
        if (expected_form_id != 0 &&
            it->second.form_id != expected_form_id) {
            FW_DBG("[clear-weapon] peer=%s expected form=0x%X but slot has "
                   "form=0x%X — no-op (peer already switched)",
                   peer_id, expected_form_id, it->second.form_id);
            return true;
        }
    }

    // Phase 2 (no lock): detach+refdec all tracked extra mods via their
    // ACTUAL parent pointers (not base_root), so the cached BSFadeNode
    // doesn't carry our mods forward to the next equip cycle.
    // 2026-05-06 evening — was: just refdec'd extras. Bug: cached
    // BSFadeNode kept all attached mod children, so next equip of same
    // path (engine resmgr returns the same cached instance) re-rendered
    // last equip's mods on top of new equip's mods. User reported:
    // "cambio arma senza silenziatore ma il silenziatore ora permane".
    clear_ghost_extra_mods(peer_id);

    // Phase 3 (lock again): release base node + erase slot. We re-find
    // the iterator since the previous lock was dropped.
    {
    std::lock_guard lk(g_ghost_weapon_slot_mtx);
    auto it = g_ghost_weapon_slot.find(peer_id);
    if (it == g_ghost_weapon_slot.end()) {
        // Lost a race with another clear — already gone.
        return true;
    }
    if (it->second.nif_node) {
        release_weapon_node(it->second.nif_node);
    }
    FW_LOG("[clear-weapon] peer=%s cleared form=0x%X path='%s'",
           peer_id, it->second.form_id, it->second.nif_path.c_str());
    g_ghost_weapon_slot.erase(it);
    }  // end Phase 3 lock scope

    // ATTEMPT #5 — global orphan sweep after the slot is gone. Same
    // rationale as ghost_set_weapon's tail call.
    purge_orphan_weapon_clones();

    // ATTEMPT #6 diagnostic — see ghost_set_weapon tail.
    dump_weapon_attach_state("post-clear-weapon");
    return true;
}

// === M9.w4 PROPER (v0.4.2+) — captured-mesh reconstruction =================
//
// Receiver-side: build BSTriShape from sender's captured raw vertex/index
// data and attach to placeholder NiNodes inside the loaded base weapon NIF.
//
// All helpers SEH-caged. Per-mesh failures don't poison the whole batch —
// we keep going and return final count of successes.

namespace {

// SEH-safe BSGeometry factory call. Returns the freshly-allocated
// BSTriShape* or nullptr on AV. Caller owns +1 ref bump if attaching.
void* seh_call_weapon_geo_factory(WeaponGeoFactoryFn fn,
                                    int          tri_count,
                                    const void*  indices_u16,
                                    unsigned int vert_count,
                                    const void*  positions_vec3,
                                    char         build_mesh_extra) {
    if (!fn) return nullptr;
    __try {
        // 11 nullptr stream pointers — we only have positions + indices.
        return fn(tri_count, indices_u16, vert_count, positions_vec3,
                   nullptr, nullptr, nullptr, nullptr, nullptr,
                   nullptr, nullptr, nullptr, nullptr, nullptr,
                   nullptr,
                   build_mesh_extra);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// (seh_write_local_transform lives at scene_inject.cpp:~4255 already —
// reuse rather than redefine. Same signature: bool(void*, const float[16]).)

// SEH-safe write of 16-float local transform into BSGeometry +0x30..+0x6F.
// Local helper (different name) for our reconstruction path so we don't
// collide with the existing one.
bool seh_write_local_transform_geom(void* geom, const float xf[16]) {
    if (!geom || !xf) return false;
    __try {
        std::memcpy(reinterpret_cast<char*>(geom) + 0x30, xf, 64);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-safe read of NiObjectNET name pool entry at node+0x10 (BSFixedString
// handle). Returns char* into pool storage (read-only, do not modify).
//
// FO4 NEXT-GEN LAYOUT (verified via weapon_witness::seh_read_node_name
// which has worked across M5/M6/M9): pool_entry's INLINE ASCII string
// starts at pool_entry+0x18, NOT at *pool_entry. Earlier versions of
// this helper used *pool_entry (first qword as char*) which produces
// garbage on FO4 NG — that bug silently broke find_node_by_name_dfs
// lookups (placeholder bones never matched). Fixed 2026-05-04 PM.
const char* seh_read_node_name_ptr(void* node) {
    if (!node) return nullptr;
    __try {
        const char* pool_entry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(node) + 0x10);
        if (!pool_entry) return nullptr;
        // ASCII string starts at pool_entry+0x18 (FO4 NG inline layout).
        return pool_entry + 0x18;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Compare a node's name against a target string. SEH-safe.
bool seh_node_name_eq(void* node, const char* target) {
    if (!node || !target || !target[0]) return false;
    const char* name = seh_read_node_name_ptr(node);
    if (!name) return false;
    __try {
        // Bounded strcmp.
        for (std::size_t i = 0; i < 256; ++i) {
            const char a = name[i];
            const char b = target[i];
            if (a != b) return false;
            if (a == 0) return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-safe attach_child_direct invocation. POD-only signature (no
// std:: types in the same scope) so it can use __try. Returns true on
// successful invocation, false on AV.
bool seh_attach_child_geom(AttachChildFn fn, void* parent, void* child) {
    if (!fn || !parent || !child) return false;
    __try {
        fn(parent, child, 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-safe refcount inc/dec on NiAVObject (refcount @ +0x08).
// POD-only so callers with std:: types can use them.
bool seh_node_refbump(void* node) {
    if (!node) return false;
    __try {
        auto* rcp = reinterpret_cast<long*>(
            reinterpret_cast<char*>(node) + NIAV_REFCOUNT_OFF);
        _InterlockedIncrement(rcp);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_node_refdec(void* node) {
    if (!node) return false;
    __try {
        auto* rcp = reinterpret_cast<long*>(
            reinterpret_cast<char*>(node) + NIAV_REFCOUNT_OFF);
        _InterlockedDecrement(rcp);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// SEH-safe read of vtable RVA (relative to image base). Returns 0 on AV
// or null vtable. Used to discriminate BSGeometry-derived (BSTriShape,
// BSSITF, BSDynamicTriShape — known to have valid +0x138 shader) from
// plain NiNode (where +0x138 is past size, heap garbage).
std::uintptr_t seh_read_vtable_rva_geom(void* node, std::uintptr_t base) {
    if (!node || !base) return 0;
    __try {
        void* vt = *reinterpret_cast<void**>(node);
        if (!vt) return 0;
        const auto vt_addr = reinterpret_cast<std::uintptr_t>(vt);
        if (vt_addr < base) return 0;
        return vt_addr - base;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// True iff the vtable RVA matches a known BSGeometry-derived class.
bool is_bsgeometry_vt_rva(std::uintptr_t rva) {
    return rva == BSTRISHAPE_VTABLE_RVA
        || rva == BSSUBINDEXTRISHAPE_VTABLE_RVA
        || rva == BSDYNAMICTRISHAPE_VTABLE_RVA
        || rva == BSDYNAMICTRISHAPE_VTABLE_ALT_RVA;
}

// SEH-safe read of two pointers: shader at geom+0x138 and alpha at +0x130.
// Both written through out params. Returns true if at least the shader
// was readable (alpha may be null even on success).
bool seh_read_shader_alpha(void* geom, void** out_shader, void** out_alpha) {
    if (!geom || !out_shader || !out_alpha) return false;
    *out_shader = nullptr;
    *out_alpha  = nullptr;
    __try {
        char* gb = reinterpret_cast<char*>(geom);
        *out_shader = *reinterpret_cast<void**>(gb + BSGEOM_SHADERPROP_OFF);
        *out_alpha  = *reinterpret_cast<void**>(gb + BSGEOM_ALPHAPROP_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// SEH-safe write of shader/alpha pointers + refcount-bump on each.
// Refcount lives at NIAV_REFCOUNT_OFF (0x08) for both
// BSLightingShaderProperty and NiAlphaProperty (NiRefObject base).
bool seh_write_shader_alpha_with_bump(void* geom,
                                       void* shader,
                                       void* alpha) {
    if (!geom) return false;
    __try {
        if (shader) {
            auto* rc = reinterpret_cast<long*>(
                reinterpret_cast<char*>(shader) + NIAV_REFCOUNT_OFF);
            _InterlockedIncrement(rc);
        }
        if (alpha) {
            auto* rc = reinterpret_cast<long*>(
                reinterpret_cast<char*>(alpha) + NIAV_REFCOUNT_OFF);
            _InterlockedIncrement(rc);
        }
        char* gb = reinterpret_cast<char*>(geom);
        *reinterpret_cast<void**>(gb + BSGEOM_SHADERPROP_OFF) = shader;
        *reinterpret_cast<void**>(gb + BSGEOM_ALPHAPROP_OFF)  = alpha;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// DFS walk: find first BSGeometry-derived leaf in `root`'s subtree that
// has a non-null shader pointer at +0x138. Used as donor for shader/alpha
// cloning when reconstructing captured weapon-mod meshes (Phase 3.1).
//
// Returns the donor BSGeometry node, or nullptr if none found.
// SEH-caged. Capped at 4096 visits.
void* find_donor_geometry_with_shader(void* root, std::uintptr_t base,
                                        int max_visits = 4096) {
    if (!root || !base) return nullptr;
    void* stack[64];
    int top = 0;
    stack[top++] = root;
    int visits = 0;
    while (top > 0 && visits < max_visits) {
        void* node = stack[--top];
        if (!node) continue;
        ++visits;

        // Only consider BSGeometry-derived nodes for shader cloning.
        const auto vt_rva = seh_read_vtable_rva_geom(node, base);
        if (is_bsgeometry_vt_rva(vt_rva)) {
            void* shader = nullptr;
            void* alpha  = nullptr;
            if (seh_read_shader_alpha(node, &shader, &alpha) && shader) {
                return node;
            }
        }

        // Recurse into children.
        void** kids = nullptr;
        std::uint16_t count = 0;
        __try {
            char* nb = reinterpret_cast<char*>(node);
            kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
            count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (!kids || count == 0 || count > 256) continue;
        for (std::uint16_t i = 0; i < count && top < 63; ++i) {
            void* k = nullptr;
            __try { k = kids[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (k) stack[top++] = k;
        }
    }
    return nullptr;
}

// DFS walk: find first node in tree whose name matches `target`.
// SEH-safe per-step. Capped at 4096 visits to bound runtime.
void* find_node_by_name_dfs(void* root, const char* target,
                              int max_visits = 4096) {
    if (!root || !target || !target[0]) return nullptr;
    void* stack[64];
    int top = 0;
    stack[top++] = root;
    int visits = 0;
    while (top > 0 && visits < max_visits) {
        void* node = stack[--top];
        if (!node) continue;
        ++visits;
        if (seh_node_name_eq(node, target)) return node;

        // Push children. NiNode children at NINODE_CHILDREN_PTR_OFF (0x128),
        // count u16 at NINODE_CHILDREN_CNT_OFF (0x132).
        void** kids = nullptr;
        std::uint16_t count = 0;
        __try {
            char* nb = reinterpret_cast<char*>(node);
            kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
            count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (!kids || count == 0 || count > 256) continue;
        for (std::uint16_t i = 0; i < count && top < 63; ++i) {
            void* k = nullptr;
            __try { k = kids[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (k) stack[top++] = k;
        }
    }
    return nullptr;
}

} // namespace

int attach_captured_meshes_to_ghost_weapon(
    const char*               peer_id,
    std::uint32_t             item_form_id,
    const CapturedMeshView*   meshes,
    std::size_t               mesh_count)
{
    if (!peer_id || !meshes || mesh_count == 0) return 0;

    if (!g_resolved.load(std::memory_order_acquire)) {
        FW_DBG("[mesh-rebuild] resolver not ready — skip");
        return -1;
    }
    if (!g_r.weapon_geo_factory) {
        FW_WRN("[mesh-rebuild] weapon_geo_factory not resolved — skip");
        return -1;
    }
    if (!g_r.attach_child_direct) {
        FW_WRN("[mesh-rebuild] attach_child_direct not resolved — skip");
        return -1;
    }

    // Look up the ghost's loaded base weapon NIF root (set by
    // ghost_set_weapon prior to this call).
    void* base_root = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) {
            FW_DBG("[mesh-rebuild] peer=%s no ghost weapon slot — skip "
                   "(MESH_BLOB arrived before EQUIP_BCAST set up base?)",
                   peer_id);
            return 0;
        }
        base_root = it->second.nif_node;
    }

    // Phase 3.1 (2026-05-04 PM): donor shader for visibility.
    // Without shader+alpha, factory-built BSTriShape renders invisible
    // (engine renderer skips it during the BSShader walk). Walk base_root
    // tree to find a BSGeometry leaf with a valid shader, clone its
    // shader+alpha pointers (refcount-bumped) into each newly-built geom.
    //
    // Material won't match perfectly (suppressor will use pistol body's
    // shader → metallic instead of matte black), but at least geometry
    // becomes visible. Per-mesh material binding via bgsm_path is a
    // future enhancement.
    void* donor_geom = find_donor_geometry_with_shader(base_root, g_r.base);
    void* donor_shader = nullptr;
    void* donor_alpha  = nullptr;
    if (donor_geom) {
        seh_read_shader_alpha(donor_geom, &donor_shader, &donor_alpha);
        FW_LOG("[mesh-rebuild] donor geom=%p shader=%p alpha=%p "
               "(cloned to all reconstructed meshes for visibility)",
               donor_geom, donor_shader, donor_alpha);
    } else {
        FW_WRN("[mesh-rebuild] no donor geometry with shader in base tree "
               "— reconstructed meshes will render invisible");
    }

    FW_LOG("[mesh-rebuild] peer=%s form=0x%X base_root=%p meshes=%zu",
           peer_id, item_form_id, base_root, mesh_count);

    // Dedup by m_name — engine clones some pieces twice (TTD 2026-05-04
    // showed each mesh appears 2x in burst 1; first occurrence wins).
    std::unordered_set<std::string> seen_names;
    seen_names.reserve(mesh_count);

    int attached = 0;
    int factory_fail = 0;
    int parent_missing = 0;
    int duped = 0;
    int shader_bound = 0;

    for (std::size_t i = 0; i < mesh_count; ++i) {
        const CapturedMeshView& m = meshes[i];
        if (!m.m_name || !m.m_name[0]) continue;
        if (m.vert_count == 0 || m.tri_count == 0) continue;
        if (!m.positions || !m.indices) continue;

        // Dedup.
        const std::string key(m.m_name);
        if (!seen_names.insert(key).second) {
            ++duped;
            continue;
        }

        // Build BSTriShape via factory. build_mesh_extra=1 attaches a
        // BSPositionData ExtraData entry — required for engine's bound
        // recompute / picking, harmless if unused.
        void* geom = seh_call_weapon_geo_factory(
            g_r.weapon_geo_factory,
            static_cast<int>(m.tri_count),
            m.indices,
            static_cast<unsigned int>(m.vert_count),
            m.positions,
            /*build_mesh_extra=*/1);
        if (!geom) {
            ++factory_fail;
            FW_WRN("[mesh-rebuild]   factory FAILED for '%s' "
                   "(vc=%u tc=%u)",
                   m.m_name,
                   static_cast<unsigned>(m.vert_count), m.tri_count);
            continue;
        }

        // Set local transform if provided (else factory's default identity).
        if (m.local_transform) {
            (void)seh_write_local_transform_geom(geom, m.local_transform);
        }

        // ROLLBACK 2026-05-04: Phase 3.1 donor shader binding caused
        // crash in render walk (next frame after attach). Same root
        // cause documented in CHANGELOG v0.4.0 §"Why this was extremely
        // hard" item 3 — donor's shader is compiled for the donor's
        // BSVertexDesc; our factory-built geom has a different vertex
        // format → GPU vertex shader reads attributes at wrong offsets
        // → AV in render. Disabled until proper bgsm-load per-geom is
        // implemented (Phase 3.2). Keep counters and donor lookup so
        // diagnostics still log what WOULD have been bound.
        (void)donor_shader; (void)donor_alpha;
        // if (donor_shader || donor_alpha) {
        //     if (seh_write_shader_alpha_with_bump(geom, donor_shader, donor_alpha)) {
        //         ++shader_bound;
        //     }
        // }

        // Find parent placeholder in the base NIF tree.
        void* parent = nullptr;
        if (m.parent_placeholder && m.parent_placeholder[0]) {
            parent = find_node_by_name_dfs(base_root, m.parent_placeholder);
        }
        if (!parent) {
            ++parent_missing;
            // Fallback: attach directly to base_root. The mesh will be at
            // the weapon's origin — visible but possibly mis-positioned.
            parent = base_root;
            FW_DBG("[mesh-rebuild]   '%s' parent='%s' NOT FOUND in base "
                   "tree — falling back to base_root",
                   m.m_name,
                   m.parent_placeholder ? m.parent_placeholder : "<null>");
        }

        // Attach. attach_child_direct internally does the refcount bump
        // for the parent's slot. We do not pre-bump.
        const bool ok =
            seh_attach_child_geom(g_r.attach_child_direct, parent, geom);
        if (!ok) {
            FW_WRN("[mesh-rebuild]   attach_child_direct SEH for '%s' "
                   "parent=%p geom=%p", m.m_name, parent, geom);
            // geom is leaked here — it has refcount=0 and no parent.
            // Engine GC won't free it. Acceptable for now (rare path).
            continue;
        }

        ++attached;
        FW_LOG("[mesh-rebuild]   [%zu] '%s' vc=%u tc=%u parent='%s' "
               "geom=%p ATTACHED",
               i, m.m_name,
               static_cast<unsigned>(m.vert_count), m.tri_count,
               m.parent_placeholder ? m.parent_placeholder : "",
               geom);
    }

    FW_LOG("[mesh-rebuild] peer=%s form=0x%X DONE attached=%d "
           "duped=%d factory_fail=%d parent_missing=%d shader_bound=%d",
           peer_id, item_form_id,
           attached, duped, factory_fail, parent_missing, shader_bound);

    return attached;
}

// === M9.w4 PROPER (v0.4.2+, Path Y) — disk-loaded mod NIFs =================
//
// See header for design. Implementation reuses load_one_weapon_nif (which
// runs nif_load_by_path + apply_materials) and attach_child_direct.

namespace {

// Walk a NiNode tree, append every BSGeometry leaf's m_name to `out`.
// Used to detect stock parts (already in base NIF).
void collect_geometry_names_dfs(void* root, std::uintptr_t base,
                                  std::unordered_set<std::string>& out,
                                  int max_visits = 4096) {
    if (!root || !base) return;
    void* stack[64];
    int top = 0;
    stack[top++] = root;
    int visits = 0;
    while (top > 0 && visits < max_visits) {
        void* node = stack[--top];
        if (!node) continue;
        ++visits;

        // If BSGeometry leaf, capture its m_name.
        const auto vt_rva = seh_read_vtable_rva_geom(node, base);
        if (is_bsgeometry_vt_rva(vt_rva)) {
            const char* nm = seh_read_node_name_ptr(node);
            if (nm && nm[0]) {
                out.emplace(nm);
            }
            continue;  // leaves don't have children to recurse into
        }

        // Recurse into children.
        void** kids = nullptr;
        std::uint16_t count = 0;
        __try {
            char* nb = reinterpret_cast<char*>(node);
            kids  = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
            count = *reinterpret_cast<std::uint16_t*>(nb + NINODE_CHILDREN_CNT_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!kids || count == 0 || count > 256) continue;
        for (std::uint16_t i = 0; i < count && top < 63; ++i) {
            void* k = nullptr;
            __try { k = kids[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (k) stack[top++] = k;
        }
    }
}

// Convert "Materials\Weapons\10mmPistol\10mmSuppressor.BGSM" →
// "Weapons\10mmPistol" (the parent folder of the .bgsm file, sans the
// "Materials\" prefix).
//
// Empty result on parse failure / empty input.
std::string base_folder_from_bgsm(const std::string& bgsm) {
    if (bgsm.empty()) return {};
    std::string s = bgsm;
    static const char kPrefix[]    = "Materials\\";
    static const char kPrefixLow[] = "materials\\";
    const std::size_t plen = sizeof(kPrefix) - 1;
    if (s.size() >= plen &&
        (std::strncmp(s.c_str(), kPrefix,    plen) == 0 ||
         std::strncmp(s.c_str(), kPrefixLow, plen) == 0)) {
        s = s.substr(plen);
    }
    const std::size_t bs = s.find_last_of('\\');
    if (bs == std::string::npos) return {};
    return s.substr(0, bs);
}

} // namespace

int attach_mod_nifs_via_disk(
    const char*               peer_id,
    std::uint32_t             item_form_id,
    const CapturedMeshView*   meshes,
    std::size_t               mesh_count)
{
    if (!peer_id || !meshes || mesh_count == 0) return 0;

    if (!g_resolved.load(std::memory_order_acquire)) {
        FW_DBG("[mod-nif] resolver not ready — skip");
        return -1;
    }
    if (!g_r.nif_load_by_path || !g_r.attach_child_direct) {
        FW_WRN("[mod-nif] engine refs not resolved — skip");
        return -1;
    }

    // Look up the ghost's loaded base weapon NIF root.
    void* base_root = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) {
            FW_DBG("[mod-nif] peer=%s no ghost weapon slot — skip", peer_id);
            return 0;
        }
        base_root = it->second.nif_node;
    }

    // Collect stock part names from base NIF tree (= names of BSGeometry
    // leaves already loaded as part of the base weapon). Captured meshes
    // whose m_name matches any of these are STOCK and shouldn't trigger
    // a mod-NIF load (would result in duplicate geometry).
    std::unordered_set<std::string> stock_names;
    collect_geometry_names_dfs(base_root, g_r.base, stock_names);

    FW_LOG("[mod-nif] peer=%s form=0x%X base_root=%p stock_parts=%zu "
           "captured_meshes=%zu",
           peer_id, item_form_id, base_root, stock_names.size(), mesh_count);

    // Group captured meshes by parent_placeholder (mod root name).
    // Each unique parent name corresponds to one mod sub-NIF on disk.
    struct ModGroup {
        std::vector<std::string> child_names;  // diagnostic only
    };
    std::unordered_map<std::string, ModGroup> mod_groups;
    std::size_t skipped_stock = 0;
    std::size_t skipped_no_parent = 0;
    for (std::size_t i = 0; i < mesh_count; ++i) {
        const CapturedMeshView& m = meshes[i];
        if (!m.m_name || !m.m_name[0]) continue;
        if (stock_names.count(m.m_name) > 0) {
            ++skipped_stock;
            continue;
        }
        if (!m.parent_placeholder || !m.parent_placeholder[0]) {
            ++skipped_no_parent;
            continue;
        }
        mod_groups[m.parent_placeholder].child_names.emplace_back(m.m_name);
    }

    FW_DBG("[mod-nif] groups=%zu skipped_stock=%zu skipped_no_parent=%zu",
           mod_groups.size(), skipped_stock, skipped_no_parent);

    // Use the ghost's loaded base nif_path to derive the base folder.
    // (Cleaner than threading bgsm through each captured mesh.)
    std::string base_folder;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it != g_ghost_weapon_slot.end()) {
            const std::string& base_path = it->second.nif_path;
            const std::size_t bs = base_path.find_last_of('\\');
            if (bs != std::string::npos) {
                base_folder = base_path.substr(0, bs);
            }
        }
    }
    if (base_folder.empty()) {
        FW_WRN("[mod-nif] could not derive base folder from slot path "
               "— skip");
        return 0;
    }

    FW_LOG("[mod-nif] base_folder='%s' mod_groups=%zu",
           base_folder.c_str(), mod_groups.size());

    int loaded = 0;
    int load_fail = 0;
    int attach_fail = 0;
    for (const auto& [placeholder, info] : mod_groups) {
        // Build candidate paths.
        const std::string c1 = base_folder + "\\" + placeholder + ".nif";
        const std::string c2 = base_folder + "\\Mods\\" + placeholder + ".nif";
        const std::string c3 = base_folder + "\\Mods\\Barrels\\" + placeholder + ".nif";
        const std::string c4 = base_folder + "\\Mods\\Sights\\" + placeholder + ".nif";
        const std::string c5 = base_folder + "\\Mods\\Grips\\" + placeholder + ".nif";
        const char* candidates[] = {
            c1.c_str(), c2.c_str(), c3.c_str(), c4.c_str(), c5.c_str(),
        };

        void* mod_root = nullptr;
        const char* winning_path = nullptr;
        for (const char* p : candidates) {
            void* n = load_one_weapon_nif(p);
            if (n) {
                mod_root = n;
                winning_path = p;
                break;
            }
        }
        if (!mod_root) {
            ++load_fail;
            FW_DBG("[mod-nif] '%s' no NIF loadable from %zu candidates "
                   "(child_count=%zu)",
                   placeholder.c_str(),
                   sizeof(candidates) / sizeof(candidates[0]),
                   info.child_names.size());
            continue;
        }

        // Attach to ghost's base weapon root. Positioning may be wrong
        // (mod NIF root's local_transform is identity; the engine
        // normally attaches to a placeholder bone with non-identity
        // transform). Phase 3.3 will resolve placeholder lookup.
        const bool ok = seh_attach_child_geom(g_r.attach_child_direct,
                                                base_root, mod_root);
        if (!ok) {
            ++attach_fail;
            seh_refcount_dec_armor(mod_root);  // drop our +1 ref
            FW_WRN("[mod-nif] attach SEH for '%s' path='%s'",
                   placeholder.c_str(), winning_path);
            continue;
        }

        ++loaded;
        FW_LOG("[mod-nif] LOADED+ATTACHED '%s' from '%s' (child_count=%zu) "
               "to base_root=%p",
               placeholder.c_str(), winning_path,
               info.child_names.size(), base_root);
    }

    FW_LOG("[mod-nif] peer=%s form=0x%X DONE loaded=%d load_fail=%d "
           "attach_fail=%d (groups=%zu skipped_stock=%zu skipped_no_parent=%zu)",
           peer_id, item_form_id,
           loaded, load_fail, attach_fail,
           mod_groups.size(), skipped_stock, skipped_no_parent);

    return loaded;
}

// === M9.w4 PROPER (v0.4.2+) — BSResource::EntryDB live probe ==============
//
// Dumps the first N non-null entries from the NIF resource manager singleton
// to fw_native.log. Used to settle the 4-agent disagreement on Entry layout
// (specifically: is +0x10 a BSFixedString path, a refcount, or something
// else?). See ni_offsets.h `BSRES_ENTRY_DB_*` block for the consensus
// layout claims.
//
// SEH-caged at every memory access so a torn read or unmapped page logs
// instead of crashing.

namespace {

// Read up to `n_qwords` qwords from `addr` into out. Returns count
// successfully read.
int seh_read_qwords(const void* addr, std::uint64_t* out, int n_qwords) {
    if (!addr || !out || n_qwords <= 0) return 0;
    int read = 0;
    for (int i = 0; i < n_qwords; ++i) {
        __try {
            out[i] = *reinterpret_cast<const std::uint64_t*>(
                reinterpret_cast<const char*>(addr) + i * 8);
            ++read;
        } __except (EXCEPTION_EXECUTE_HANDLER) { return read; }
    }
    return read;
}

// Try to read a C string (max len) from a candidate pointer.
// Returns true if at least 4 printable ASCII chars before null/AV.
// Used to test if a qword looks like a char* path pointer.
bool seh_looks_like_cstring(const void* addr, char* dst, std::size_t cap) {
    if (!addr || !dst || cap < 8) return false;
    int printable = 0;
    __try {
        for (std::size_t i = 0; i < cap - 1; ++i) {
            const char c =
                *(reinterpret_cast<const char*>(addr) + i);
            if (c == 0) {
                dst[i] = 0;
                return printable >= 4;
            }
            if ((c >= 0x20 && c < 0x7F) || c == '\\' || c == '/') {
                ++printable;
            } else {
                dst[i] = 0;
                return false;
            }
            dst[i] = c;
        }
        dst[cap - 1] = 0;
        return printable >= 4;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

void dump_resmgr_first_entries(int count_max) {
    if (!g_r.base) {
        FW_LOG("[resmgr-probe] g_r.base not resolved — skip");
        return;
    }

    // 1. Read singleton pointer from qword_1430DD618.
    void* singleton = nullptr;
    __try {
        void** slot = reinterpret_cast<void**>(
            g_r.base + NIF_LOAD_RESMGR_SLOT_RVA);
        singleton = *slot;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[resmgr-probe] SEH reading singleton slot");
        return;
    }
    if (!singleton) {
        FW_LOG("[resmgr-probe] singleton ptr null — engine not initialized");
        return;
    }

    // 2. Read vtable RVA (sanity check class identity).
    std::uintptr_t vt_rva = 0;
    __try {
        const auto vt_addr = *reinterpret_cast<std::uintptr_t*>(singleton);
        if (vt_addr >= g_r.base) vt_rva = vt_addr - g_r.base;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 3. Read bucket array head + capacity + count.
    void**        buckets = nullptr;
    std::uint32_t capacity = 0;
    std::uint32_t live_count = 0;
    __try {
        char* sb = reinterpret_cast<char*>(singleton);
        buckets = *reinterpret_cast<void***>(
            sb + BSRES_ENTRY_DB_BUCKETS_OFF);
        capacity = *reinterpret_cast<std::uint32_t*>(
            sb + BSRES_ENTRY_DB_CAPACITY_OFF);
        live_count = *reinterpret_cast<std::uint32_t*>(
            sb + BSRES_ENTRY_DB_COUNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[resmgr-probe] SEH reading bucket header from singleton=%p",
               singleton);
        return;
    }

    FW_LOG("[resmgr-probe] singleton=%p vtable_rva=0x%llX (expected "
           "0x%llX BSResource::EntryDB<BSModelDB>) buckets=%p cap=%u "
           "live=%u",
           singleton,
           static_cast<unsigned long long>(vt_rva),
           static_cast<unsigned long long>(BSRES_ENTRYDB_VTABLE_RVA),
           buckets, capacity, live_count);

    if (!buckets || capacity == 0 || capacity > 0x100000) {
        FW_WRN("[resmgr-probe] bucket array invalid — skip");
        return;
    }

    const void* tombstone = reinterpret_cast<const void*>(
        g_r.base + BSRES_ENTRY_DB_TOMBSTONE_RVA);

    // 4. Walk first N non-null/non-tombstone entries, dump 0x30 raw bytes
    // + per-field interpretation.
    int dumped = 0;
    for (std::uint32_t i = 0; i < capacity && dumped < count_max; ++i) {
        void* entry = nullptr;
        __try { entry = buckets[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!entry || entry == tombstone) continue;

        // Read 6 qwords (= 0x30 bytes = full Entry per A/C/D consensus).
        std::uint64_t q[6] = {0};
        const int n = seh_read_qwords(entry, q, 6);
        if (n == 0) continue;

        // Extract extension bytes at entry+0x04..+0x07 (per live data 2026-05-04
        // PM, ".nif" entries have these 4 bytes = 'n','i','f','\0').
        char ext[8] = {0};
        ext[0] = static_cast<char>((q[0] >> 32) & 0xFF);
        ext[1] = static_cast<char>((q[0] >> 40) & 0xFF);
        ext[2] = static_cast<char>((q[0] >> 48) & 0xFF);
        ext[3] = static_cast<char>((q[0] >> 56) & 0xFF);
        // Sanitize non-printables for log (replace with '.').
        for (int k = 0; k < 4; ++k) {
            if (ext[k] != 0 && (ext[k] < 0x20 || ext[k] >= 0x7F)) ext[k] = '.';
        }

        FW_LOG("[resmgr-probe] === Entry #%d (bucket[%u] @ %p) ext='%s' ===",
               dumped, i, entry, ext);
        FW_LOG("[resmgr-probe]   +0x00 = 0x%016llX (12B hash key candidate; "
               "low12: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X)",
               static_cast<unsigned long long>(q[0]),
               static_cast<unsigned>(q[0] & 0xFF),
               static_cast<unsigned>((q[0] >> 8) & 0xFF),
               static_cast<unsigned>((q[0] >> 16) & 0xFF),
               static_cast<unsigned>((q[0] >> 24) & 0xFF),
               static_cast<unsigned>((q[0] >> 32) & 0xFF),
               static_cast<unsigned>((q[0] >> 40) & 0xFF),
               static_cast<unsigned>((q[0] >> 48) & 0xFF),
               static_cast<unsigned>((q[0] >> 56) & 0xFF),
               static_cast<unsigned>(q[1] & 0xFF),
               static_cast<unsigned>((q[1] >> 8) & 0xFF),
               static_cast<unsigned>((q[1] >> 16) & 0xFF),
               static_cast<unsigned>((q[1] >> 24) & 0xFF));
        FW_LOG("[resmgr-probe]   +0x08 = 0x%016llX",
               static_cast<unsigned long long>(q[1]));
        FW_LOG("[resmgr-probe]   +0x10 = 0x%016llX (DISAGREEMENT POINT)",
               static_cast<unsigned long long>(q[2]));

        // Test if +0x10 is a BSFixedString-ish handle (ptr to ptr-to-cstring).
        // BSFixedString in FO4: handle is a ptr to a pool entry; the c-string
        // lives at handle[0] (or handle+0x18 in some layouts).
        if (q[2] != 0) {
            const void* p = reinterpret_cast<const void*>(q[2]);
            char buf[256] = {0};

            // Test 1: dereference once, see if THAT is a c-string ptr.
            std::uint64_t deref0 = 0;
            int n0 = seh_read_qwords(p, &deref0, 1);
            if (n0 == 1 && deref0 != 0) {
                const void* cs = reinterpret_cast<const void*>(deref0);
                if (seh_looks_like_cstring(cs, buf, sizeof(buf))) {
                    FW_LOG("[resmgr-probe]     → +0x10 deref → cstring "
                           "='%s' (BSFixedString-like 1-level)", buf);
                }
            }

            // Test 2: treat +0x10 itself as ptr-to-cstring directly.
            if (seh_looks_like_cstring(p, buf, sizeof(buf))) {
                FW_LOG("[resmgr-probe]     → +0x10 raw → cstring "
                       "='%s' (raw char* path)", buf);
            }

            // Test 3: BSFixedString FO4 layout — pool entry at handle,
            // c-string at handle+0x18.
            char buf18[256] = {0};
            const void* p18 = reinterpret_cast<const char*>(p) + 0x18;
            if (seh_looks_like_cstring(p18, buf18, sizeof(buf18))) {
                FW_LOG("[resmgr-probe]     → +0x10 + 0x18 → cstring "
                       "='%s' (BSFixedString +0x18 layout)", buf18);
            }
        }

        FW_LOG("[resmgr-probe]   +0x18 = 0x%016llX",
               static_cast<unsigned long long>(q[3]));
        FW_LOG("[resmgr-probe]   +0x20 = 0x%016llX (NODE candidate)",
               static_cast<unsigned long long>(q[4]));

        // Verify +0x20 is a NiAVObject by reading its vtable + m_name.
        if (q[4] != 0) {
            void* node = reinterpret_cast<void*>(q[4]);
            std::uint64_t node_vt = 0;
            int nn = seh_read_qwords(node, &node_vt, 1);
            if (nn == 1 && node_vt >= g_r.base) {
                const auto node_vt_rva = node_vt - g_r.base;
                FW_LOG("[resmgr-probe]     → +0x20 node vtable_rva=0x%llX "
                       "(BSFadeNode=0x28FA3E8, NiNode=0x267C888, "
                       "BSTriShape=0x267E948)",
                       static_cast<unsigned long long>(node_vt_rva));
            }
            // Read BSFadeNode->m_name (BSFixedString @ node+0x10).
            // For NIFs loaded from disk, m_name typically contains the
            // file basename or root NiNode name — ENOUGH for matching
            // captured parent_placeholder strings from sender.
            const char* nm = seh_read_node_name_ptr(node);
            if (nm) {
                // Bounded copy via string-test helper to avoid AV on garbage ptr.
                char nbuf[128] = {0};
                if (seh_looks_like_cstring(nm, nbuf, sizeof(nbuf))) {
                    FW_LOG("[resmgr-probe]     → +0x20 node m_name='%s' "
                           "(MATCHING KEY for sender's parent_placeholder)",
                           nbuf);
                }
            }
        }

        FW_LOG("[resmgr-probe]   +0x28 = 0x%016llX",
               static_cast<unsigned long long>(q[5]));

        ++dumped;
    }

    FW_LOG("[resmgr-probe] done — dumped %d / %d requested entries "
           "(scanned %u buckets)",
           dumped, count_max, capacity);
}

// Worker thread: sleeps `delay_ms` then dumps. Spawned from
// arm_injection_after_boot path so the engine has time to populate
// the resmgr with weapon NIFs (player needs to have walked into a cell,
// pickup pistol, equip it).
namespace {
void resmgr_probe_worker(unsigned int delay_ms) {
    Sleep(delay_ms);
    dump_resmgr_first_entries(32);
}
} // namespace

void arm_resmgr_probe(unsigned int delay_ms) {
    std::thread(&resmgr_probe_worker, delay_ms).detach();
    FW_LOG("[resmgr-probe] armed: will dump in %u ms", delay_ms);
}

// === M9.w4 PROPER (v0.4.2+, RESMGR-LOOKUP) — find cached NIF by name =====
//
// Walks the BSResource::EntryDB<BSModelDB> bucket array and returns the
// first BSFadeNode whose m_name matches `target_name`. Matches the
// captured `parent_placeholder` strings from sender (e.g. "10mmSuppressor",
// "10mmReflexCircle", "10mmWoodenGrip001", "Pistol10mmReceiver", etc.).
//
// The 4-agent RE + live probe v2 (2026-05-04) confirmed:
//   - Singleton @ *qword_1430DD618 with vtable RVA 0x2694C70
//   - Bucket array @ singleton+0x188, capacity @ +0x190
//   - Each entry's BSFadeNode at +0x20
//   - BSFadeNode m_name readable via pool_entry @ node+0x10 deref + 0x18
//   - Weapon mods ARE cached: live probe found `10mmWoodenGrip001` etc.
//
// Returns the BSFadeNode pointer (caller MUST refbump before attaching),
// or nullptr if no match found / engine not initialized.
//
// SEH-caged at every memory access. Linear scan of capacity-sized array
// — for capacity=2048, ~1167 live entries, this is ~microseconds.
//
// Threading: MAIN THREAD (caller's responsibility — internal mutex acquired
// by engine on map mutation, but read-only walk should be safe between
// frames).
void* find_loaded_nif_by_m_name(const char* target_name) {
    if (!target_name || !target_name[0]) return nullptr;
    if (!g_r.base) return nullptr;

    // 1. Read singleton ptr.
    void* singleton = nullptr;
    __try {
        void** slot = reinterpret_cast<void**>(
            g_r.base + NIF_LOAD_RESMGR_SLOT_RVA);
        singleton = *slot;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!singleton) return nullptr;

    // 2. Read bucket array head + capacity.
    void**        buckets = nullptr;
    std::uint32_t capacity = 0;
    __try {
        char* sb = reinterpret_cast<char*>(singleton);
        buckets = *reinterpret_cast<void***>(
            sb + BSRES_ENTRY_DB_BUCKETS_OFF);
        capacity = *reinterpret_cast<std::uint32_t*>(
            sb + BSRES_ENTRY_DB_CAPACITY_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!buckets || capacity == 0 || capacity > 0x100000) return nullptr;

    const void* tombstone = reinterpret_cast<const void*>(
        g_r.base + BSRES_ENTRY_DB_TOMBSTONE_RVA);

    // 3. Linear scan. Every non-null/non-tombstone bucket → read node →
    // read m_name → strcmp.
    int scanned = 0;
    int with_node = 0;
    for (std::uint32_t i = 0; i < capacity; ++i) {
        void* entry = nullptr;
        __try { entry = buckets[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!entry || entry == tombstone) continue;
        ++scanned;

        // Read node @ entry+0x20.
        void* node = nullptr;
        __try {
            node = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(entry) + BSRES_ENTRY_NODE_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!node) continue;
        ++with_node;

        // Read m_name (BSFixedString @ node+0x10 → pool_entry+0x18).
        const char* nm = seh_read_node_name_ptr(node);
        if (!nm) continue;

        // Bounded strcmp (256 chars max — m_name typically short).
        bool match = true;
        __try {
            for (std::size_t k = 0; k < 256; ++k) {
                const char a = nm[k];
                const char b = target_name[k];
                if (a != b) { match = false; break; }
                if (a == 0) break;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            match = false;
        }

        if (match) {
            FW_LOG("[resmgr-lookup] HIT '%s' → entry=%p node=%p "
                   "(scanned=%d/with_node=%d/%u buckets)",
                   target_name, entry, node, scanned, with_node, capacity);
            return node;
        }
    }

    FW_DBG("[resmgr-lookup] MISS '%s' (scanned=%d entries, with_node=%d, "
           "%u buckets)", target_name, scanned, with_node, capacity);
    return nullptr;
}

// Forward declaration — defined later in the file (anon namespace).
namespace {
int cull_geometry_leaves_w4(void* node, std::uintptr_t module_base,
                              int depth, int max_depth);
}

// Path NIF-CAPTURE — load `path` via the engine, attach to the ghost's
// loaded base weapon NIF. See header.
bool attach_extra_nif_to_ghost_weapon(const char* peer_id,
                                       const char* path,
                                       const char* slot_name) {
    if (!peer_id || !path || !path[0]) return false;
    if (!g_resolved.load(std::memory_order_acquire)) return false;
    if (!g_r.attach_child_direct) return false;

    // Look up ghost weapon slot's loaded base NIF root.
    void* base_root = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) {
            FW_DBG("[extra-nif] peer=%s no slot — skip path='%s'",
                   peer_id, path);
            return false;
        }
        base_root = it->second.nif_node;
    }

    // 2026-05-06 evening (ATTEMPT #8) — resolve placeholder via the
    // multi-tier resolver (same as resmgr-share path). If slot_name is
    // empty/nullptr or resolution fails, attach falls back to base_root
    // (legacy behaviour — visually wrong but stable).
    void* attach_parent = base_root;
    bool used_placeholder = false;
    const char* match_kind = "no-slot";
    if (slot_name && slot_name[0]) {
        void* hit = resolve_placeholder_for_slot(
            base_root, slot_name, &match_kind);
        if (hit && hit != base_root) {
            attach_parent = hit;
            used_placeholder = true;
        }
    }

    // Load via standard engine path (does apply_materials internally
    // via load_one_weapon_nif). Engine binds shader/material correctly
    // because it's a real NIF file — no vertex format mismatch issue.
    void* source = load_one_weapon_nif(path);
    if (!source) {
        FW_DBG("[extra-nif] nif_load FAILED path='%s'", path);
        return false;
    }

    // 2026-05-06 PM (M9 closure) — clone via vt[26] before attach. Same
    // rationale as ghost_set_weapon and attach_extra_node_to_ghost_weapon:
    // load_one_weapon_nif returns a cached BSFadeNode shared across all
    // actors. Attaching the cached pointer as a child of N different
    // bases mutates the same node's `+0x28 parent` field N times, last
    // writer wins, render walk corruption. Clone first → independent
    // instance per peer → cache stays clean.
    void* mod_node = clone_nif_subtree(source);
    if (mod_node && mod_node != source) {
        // Independent clone — release the cached source ref we held.
        seh_refcount_dec_armor(source);
        // Track for orphan-purge (weapon clones only, not body/armor).
        track_owned_clone(mod_node);
        FW_DBG("[extra-nif] cloned source=%p -> mod_node=%p path='%s'",
               source, mod_node, path);
    } else {
        // Clone failed — fall back to using the cached source. Same
        // tradeoff as ghost_set_weapon's fallback.
        FW_WRN("[extra-nif] clone failed for '%s' source=%p — using cached",
               path, source);
        mod_node = source;
    }

    // 2026-05-06 evening — cull placeholder's stock leaves before attach
    // (same as resmgr-share path). Only when we actually resolved to a
    // real placeholder, NOT when falling back to base_root (would kill
    // the body).
    if (used_placeholder) {
        const int culled = cull_geometry_leaves_w4(
            attach_parent, g_r.base, 0, 16);
        if (culled > 0) {
            FW_DBG("[extra-nif] CULLED %d default leaves inside "
                   "placeholder '%s'=%p before attaching '%s'",
                   culled, slot_name, attach_parent, path);
        }
    }

    // Attach to placeholder (or base_root fallback).
    const bool ok = seh_attach_child_geom(g_r.attach_child_direct,
                                            attach_parent, mod_node);
    if (!ok) {
        FW_WRN("[extra-nif] attach SEH path='%s' base=%p mod=%p",
               path, base_root, mod_node);
        // mod_node might be a clone (tracked) or the shared source
        // (untracked). untrack_owned_clone is a no-op if not present.
        untrack_owned_clone(mod_node);
        seh_refcount_dec_armor(mod_node);
        return false;
    }

    // 2026-05-06 (M9 closure) — also track this disk-loaded mod in
    // extra_mods so clear_ghost_extra_mods cleans it up on the next
    // equip cycle. The tracked node is the CLONE we own, not the
    // shared cached source.
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it != g_ghost_weapon_slot.end()) {
            it->second.extra_mods.push_back(mod_node);
        }
    }

    if (used_placeholder) {
        FW_LOG("[extra-nif] LOADED+ATTACHED '%s' → slot='%s' (match=%s) "
               "placeholder=%p (in base=%p, mod=%p)",
               path, slot_name, match_kind, attach_parent,
               base_root, mod_node);
    } else {
        FW_LOG("[extra-nif] LOADED+ATTACHED '%s' → base=%p (no/unresolved "
               "slot='%s', mod=%p)",
               path, base_root,
               (slot_name && slot_name[0]) ? slot_name : "<empty>",
               mod_node);
    }
    return true;
}

// 2026-05-05 — see header. Walks `base_root`'s subtree DFS and APP_CULLs
// every BSGeometry-derived leaf encountered. Implementation parallels
// find_node_by_name_w4 (same SEH-caged child reads); we just don't
// match by name and do the cull instead of returning the first hit.
//
// Bounded depth + child-count caps to avoid runaway loops if the engine
// ever hands us a corrupted subtree.
namespace {
int cull_geometry_leaves_w4(void* node,
                              std::uintptr_t module_base,
                              int depth = 0,
                              int max_depth = 16) {
    if (!node || depth > max_depth) return 0;

    int culled = 0;
    const std::uintptr_t vt_rva =
        seh_read_vtable_rva_geom(node, module_base);
    if (is_bsgeometry_vt_rva(vt_rva)) {
        if (seh_niav_set_flag(node, NIAV_FLAG_APP_CULLED, true)) {
            ++culled;
        }
        // BSGeometry-derived nodes are leaves — no children to recurse.
        return culled;
    }

    // 2026-05-06 PM — STOP at BSFadeNode (and BSLeafAnimNode) when not
    // at the root. These mark loaded-NIF subtrees — i.e. external mods
    // attached on top of the base by the engine's own assembly OR by
    // our resmgr-share path on prior equips. Their internal geometry
    // is "their business", not stock content of THIS base. Recursing
    // into them was the cause of the growing-cull-count bug:
    //   1st equip: cull 6  (stock leaves only)
    //   2nd equip: cull 14 (stock + mods from prior equip)
    //   3rd equip: cull 16, 4th: cull 28 etc.
    // → mods we attached for the previous equip got their geometry
    // APP_CULLED on the next equip, leaving the user with floating
    // partial weapons or invisible weapons. Limiting recursion to
    // PURE NiNode subtrees fixes this — placeholders inside the base
    // are NiNode (vt 0x267C888), mods are BSFadeNode (vt 0x28FA3E8).
    if (depth > 0 && (vt_rva == BSFADENODE_VTABLE_RVA ||
                       vt_rva == BSLEAFANIMNODE_VTABLE_RVA)) {
        return culled;
    }

    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children_w4(node, kids, count)) return culled;
    if (!kids || count == 0 || count > 256) return culled;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_kid_at_w4(kids, i);
        if (!k) continue;
        culled += cull_geometry_leaves_w4(k, module_base,
                                            depth + 1, max_depth);
    }
    return culled;
}
}  // anon namespace

// 2026-05-06 — diagnostic subtree dumper. Recursively walks a NiNode
// tree and logs each named child with depth + vtable RVA. SEH-caged
// (per-node, so a corrupt subtree caps the dump rather than killing
// us). Bounded by max_depth and a hard child-count guard.
namespace {
void dump_subtree_recursive(void* node, std::uintptr_t module_base,
                              int depth, int max_depth,
                              const char* tag) {
    if (!node || depth > max_depth) return;

    char nm[128] = {};
    const bool has_name = seh_read_node_name_w4(node, nm, sizeof(nm));
    const std::uintptr_t vt_rva =
        seh_read_vtable_rva_geom(node, module_base);

    // Indent with two-space stride.
    char indent[64] = {};
    int  ip = 0;
    for (int d = 0; d < depth && ip < 60; ++d) {
        indent[ip++] = ' ';
        indent[ip++] = ' ';
    }
    indent[ip] = 0;

    // Decode the most common vtable RVAs we know about.
    const char* vt_kind = "?";
    if      (vt_rva == BSFADENODE_VTABLE_RVA)             vt_kind = "BSFadeNode";
    else if (vt_rva == NINODE_VTABLE_RVA)                 vt_kind = "NiNode";
    else if (vt_rva == BSTRISHAPE_VTABLE_RVA)             vt_kind = "BSTriShape";
    else if (vt_rva == BSSUBINDEXTRISHAPE_VTABLE_RVA)     vt_kind = "BSSITF";
    else if (vt_rva == BSDYNAMICTRISHAPE_VTABLE_RVA)      vt_kind = "BSDynamicTriShape";
    else if (vt_rva == BSDYNAMICTRISHAPE_VTABLE_ALT_RVA)  vt_kind = "BSDynamicTriShape(alt)";
    else if (vt_rva == BSLEAFANIMNODE_VTABLE_RVA)         vt_kind = "BSLeafAnimNode";
    else if (vt_rva == BSGEOMETRY_VTABLE_RVA)             vt_kind = "BSGeometry";

    FW_LOG("%s%s'%s' vt_rva=0x%llX (%s) ptr=%p",
           tag, indent, has_name ? nm : "<unnamed>",
           static_cast<unsigned long long>(vt_rva), vt_kind, node);

    // Recurse into children unless we hit a geometry leaf (those
    // typically have no children but reading +0x100 is unsafe).
    if (is_bsgeometry_vt_rva(vt_rva)) return;

    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children_w4(node, kids, count)) return;
    if (!kids || count == 0 || count > 256) return;

    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_kid_at_w4(kids, i);
        if (!k) continue;
        dump_subtree_recursive(k, module_base, depth + 1, max_depth, tag);
    }
}
}  // anon namespace

// 2026-05-06 LATE evening — RICH diagnostic dumper. Per-node logs:
// vtable kind, m_name, ptr, +0x28 parent, NIAV_FLAG_APP_CULLED state,
// children count. SEH-caged per-node.
namespace {
void dump_node_rich(void* node, int depth, int max_depth, const char* tag) {
    if (!node || depth > max_depth) return;

    // Vtable + name
    char nm[128] = {};
    seh_read_node_name_w4(node, nm, sizeof(nm));
    const std::uintptr_t vt_rva =
        seh_read_vtable_rva_geom(node, g_r.base);

    // Parent ptr (+0x28).
    void* parent = weapon_witness::read_parent_pub(node);

    // APP_CULLED flag (NIAV +0x6C, mask NIAV_FLAG_APP_CULLED).
    bool app_culled = false;
    __try {
        const std::uint64_t flags = *reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<char*>(node) + NIAV_FLAGS_OFF);
        app_culled = (flags & NIAV_FLAG_APP_CULLED) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    const char* vt_kind = "?";
    if      (vt_rva == BSFADENODE_VTABLE_RVA)             vt_kind = "BSFadeNode";
    else if (vt_rva == NINODE_VTABLE_RVA)                 vt_kind = "NiNode";
    else if (vt_rva == BSTRISHAPE_VTABLE_RVA)             vt_kind = "BSTriShape";
    else if (vt_rva == BSSUBINDEXTRISHAPE_VTABLE_RVA)     vt_kind = "BSSITF";
    else if (vt_rva == BSDYNAMICTRISHAPE_VTABLE_RVA)      vt_kind = "BSDynamicTriShape";
    else if (vt_rva == BSDYNAMICTRISHAPE_VTABLE_ALT_RVA)  vt_kind = "BSDynamicTriShape(alt)";
    else if (vt_rva == BSLEAFANIMNODE_VTABLE_RVA)         vt_kind = "BSLeafAnimNode";
    else if (vt_rva == BSGEOMETRY_VTABLE_RVA)             vt_kind = "BSGeometry";

    char indent[64] = {};
    int  ip = 0;
    for (int d = 0; d < depth && ip < 60; ++d) {
        indent[ip++] = ' ';
        indent[ip++] = ' ';
    }
    indent[ip] = 0;

    // Children count (only meaningful for non-geom).
    std::uint16_t child_count = 0;
    if (!is_bsgeometry_vt_rva(vt_rva)) {
        void** kids = nullptr;
        seh_read_children_w4(node, kids, child_count);
    }

    FW_LOG("%s%sptr=%p name='%s' vt=%s(0x%llX) parent=%p culled=%d kids=%u",
           tag, indent, node, nm[0] ? nm : "<unnamed>",
           vt_kind, static_cast<unsigned long long>(vt_rva),
           parent, app_culled ? 1 : 0,
           static_cast<unsigned>(child_count));

    if (is_bsgeometry_vt_rva(vt_rva)) return;

    void** kids = nullptr;
    std::uint16_t count = 0;
    if (!seh_read_children_w4(node, kids, count)) return;
    if (!kids || count == 0 || count > 256) return;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_kid_at_w4(kids, i);
        if (!k) continue;
        dump_node_rich(k, depth + 1, max_depth, tag);
    }
}
}  // anon namespace

// Public diagnostic — call at strategic moments to dump the COMPLETE
// state of WEAPON's subtree + the parent chain from WEAPON up to scene
// root. This is the canonical "what does the engine actually see"
// snapshot. If the cleanup logs say `cleared 6/6 detached` but you still
// visually see 6 stale weapons, the discrepancy lives somewhere this
// dump will show.
void dump_weapon_attach_state(const char* event_tag) {
    if (!g_resolved.load(std::memory_order_acquire)) return;
    if (!event_tag) event_tag = "<no-tag>";

    void* weapon = find_weapon_attach_node();
    if (!weapon) {
        FW_LOG("[scene-dump] %s NO WEAPON ATTACH NODE", event_tag);
        return;
    }

    FW_LOG("[scene-dump] ============================================ "
           "tag='%s' WEAPON=%p ============================================",
           event_tag, weapon);

    // Parent chain UP from WEAPON.
    {
        FW_LOG("[scene-dump] %s parent-chain (WEAPON → scene root):",
               event_tag);
        void* cur = weapon;
        int depth = 0;
        std::uintptr_t prev_addr = reinterpret_cast<std::uintptr_t>(cur);
        while (cur && depth < 24) {
            char nm[128] = {};
            seh_read_node_name_w4(cur, nm, sizeof(nm));
            const std::uintptr_t vt_rva =
                seh_read_vtable_rva_geom(cur, g_r.base);
            FW_LOG("[scene-dump] %s   [%d] ptr=%p name='%s' vt_rva=0x%llX",
                   event_tag, depth, cur, nm[0] ? nm : "<unnamed>",
                   static_cast<unsigned long long>(vt_rva));
            void* parent = weapon_witness::read_parent_pub(cur);
            if (!parent) break;
            if (reinterpret_cast<std::uintptr_t>(parent) == prev_addr) {
                FW_LOG("[scene-dump] %s   [self-loop, stop]", event_tag);
                break;
            }
            prev_addr = reinterpret_cast<std::uintptr_t>(parent);
            cur = parent;
            ++depth;
        }
    }

    // Subtree DOWN from WEAPON.
    FW_LOG("[scene-dump] %s WEAPON subtree (DFS, max_depth=8):",
           event_tag);
    dump_node_rich(weapon, 0, 8, "[scene-dump]   ");

    // Tracker stats.
    {
        std::lock_guard lk(g_owned_clones_mtx);
        FW_LOG("[scene-dump] %s g_owned_clones tracker size=%zu",
               event_tag, g_owned_clones.size());
    }
    // Slot-map summary.
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        FW_LOG("[scene-dump] %s g_ghost_weapon_slot peers=%zu",
               event_tag, g_ghost_weapon_slot.size());
        for (auto& [pid, slot] : g_ghost_weapon_slot) {
            FW_LOG("[scene-dump] %s   peer='%s' form=0x%X path='%s' "
                   "nif_node=%p extras=%zu",
                   event_tag, pid.c_str(), slot.form_id,
                   slot.nif_path.c_str(), slot.nif_node,
                   slot.extra_mods.size());
        }
    }

    FW_LOG("[scene-dump] ============================================ "
           "tag='%s' END ============================================",
           event_tag);
}

void dump_ghost_weapon_subtree(const char* peer_id, int max_depth) {
    if (!peer_id) return;
    if (!g_resolved.load(std::memory_order_acquire)) return;
    if (max_depth < 1) max_depth = 1;
    if (max_depth > 12) max_depth = 12;

    void* base_root = nullptr;
    std::string base_path;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) {
            FW_DBG("[base-tree-dump] peer=%s no slot — skip", peer_id);
            return;
        }
        base_root = it->second.nif_node;
        base_path = it->second.nif_path;
    }

    FW_LOG("[base-tree-dump] === peer=%s base='%s' root=%p (max_depth=%d) ===",
           peer_id, base_path.c_str(), base_root, max_depth);
    dump_subtree_recursive(base_root, g_r.base, 0, max_depth,
                           "[base-tree-dump] ");
    FW_LOG("[base-tree-dump] === END peer=%s ===", peer_id);
}

int cull_base_geometry_for_modded_weapon(const char* peer_id) {
    if (!peer_id) return -1;
    if (!g_resolved.load(std::memory_order_acquire)) return -1;

    void* base_root = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) {
            return -1;
        }
        // Already culled this base — skip. The cached BSFadeNode is
        // shared across equip cycles, so the APP_CULLED bits we wrote
        // on the stock leaves persist between calls. Re-walking the
        // subtree on the next equip would also descend into our
        // attached mod nodes (children of base) and cull THEIR
        // geometry, making the mods invisible.
        if (it->second.base_culled) {
            return 0;
        }
        base_root = it->second.nif_node;
    }

    const int culled = cull_geometry_leaves_w4(base_root, g_r.base);

    // Mark slot as culled. Do this AFTER the walk so a partial AV
    // doesn't mark a half-culled base as "done".
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it != g_ghost_weapon_slot.end() &&
            it->second.nif_node == base_root) {
            it->second.base_culled = true;
        }
    }
    return culled;
}

// 2026-05-06 evening (Agent D RE finding, 99% confidence) — detach-via-
// parent helpers. Replaces the broken `detach_child(base_root, mod)`
// loop that silently no-op'd whenever `mod` wasn't a direct child of
// `base_root` (most of our mods are attached to placeholder NiNodes
// INSIDE base_root via `attach_extra_node_to_ghost_weapon`'s
// `find_node_by_name_w4` lookup, NOT to base_root directly). The
// engine's `sub_1416BE390` walks DIRECT children only and returns
// `removed = nullptr` (no SEH) when it doesn't find the child — our
// `seh_detach_child_armor` was reporting `ok=true` on these silent
// misses, so the cleanup looked successful but the cached BSFadeNode
// kept accumulating mod children across equips → "weapon shows old
// + new mods stacked" symptom.
//
// Fix: read child's actual parent via NiAVObject::m_pkParent (+0x28),
// detach from THAT parent. Triple-confirmed offset (per Agent D dossier
// `re/detach_primitives_AGENT_D.md`):
//   • SetParent (sub_1416C8B60)   writes *(child+0x28)=parent
//   • ClearParent (sub_1416C8CC0) writes *(child+0x28)=0
//   • Parent-chain walker (sub_1416C8C40) reads *(node+0x28)
namespace {

// DFS through subtree looking for the NiNode whose children array
// contains `target`. Returns first parent NiNode that owns target as a
// direct child, or nullptr. Bounded depth defends against pathological
// graphs (cycles shouldn't exist in NIF trees but seen in skeletons).
void* find_parent_in_subtree_w4(void* root, void* target,
                                  int depth = 0, int max_depth = 32) {
    if (!root || !target || depth > max_depth) return nullptr;

    void**         children = nullptr;
    std::uint16_t  count    = 0;
    __try {
        children = *reinterpret_cast<void***>(
            reinterpret_cast<char*>(root) + NINODE_CHILDREN_PTR_OFF);
        count    = *reinterpret_cast<std::uint16_t*>(
            reinterpret_cast<char*>(root) + NINODE_CHILDREN_CNT_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }

    if (!children || count == 0 || count > 4096) return nullptr;

    // Direct match?
    for (std::uint16_t i = 0; i < count; ++i) {
        void* c = nullptr;
        __try { c = children[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (c == target) return root;
    }
    // Recurse.
    for (std::uint16_t i = 0; i < count; ++i) {
        void* c = nullptr;
        __try { c = children[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (!c) continue;
        void* hit = find_parent_in_subtree_w4(c, target, depth + 1, max_depth);
        if (hit) return hit;
    }
    return nullptr;
}

struct DetachResult {
    bool  ok;       // engine call did not SEH AND removed != nullptr
    bool  seh;      // SEH fired
    void* parent;   // parent we detached from (may be != base_root)
};

DetachResult seh_detach_via_parent_ptr(void* child, void** removed_out) {
    DetachResult r{false, false, nullptr};
    if (!child || !g_r.detach_child) return r;

    void* parent = weapon_witness::read_parent_pub(child);
    if (!parent) {
        // Already orphaned — nothing to detach. Treat as success so
        // caller doesn't overcount failures.
        r.ok = true;
        return r;
    }
    r.parent = parent;

    void* removed = nullptr;
    __try {
        g_r.detach_child(parent, child, &removed);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r.seh = true;
        return r;
    }
    if (removed_out) *removed_out = removed;
    r.ok = (removed != nullptr);
    return r;
}

// Detach every mod in `mods` from its actual parent, with a
// subtree-search fallback if the parent ptr is stale. Returns count
// successfully detached. Does NOT touch refcounts — caller balances
// refbumps separately.
int seh_detach_mods_via_parent(void* base_root,
                                 const std::vector<void*>& mods) {
    int detached = 0;
    for (void* mod : mods) {
        if (!mod) continue;

        void* removed = nullptr;
        DetachResult r = seh_detach_via_parent_ptr(mod, &removed);

        if (r.ok && removed) {
            ++detached;
            FW_DBG("[detach-via-parent] mod=%p detached from parent=%p "
                   "(removed=%p)", mod, r.parent, removed);
            continue;
        }
        if (r.seh) {
            FW_WRN("[detach-via-parent] SEH for mod=%p parent=%p", mod,
                   r.parent);
            continue;
        }

        // Fallback: walk base_root recursively to find the actual parent.
        // Handles stale +0x28 ptrs (engine swapped parent under us).
        if (base_root) {
            void* fallback_parent = find_parent_in_subtree_w4(base_root, mod);
            if (fallback_parent) {
                __try {
                    g_r.detach_child(fallback_parent, mod, &removed);
                    if (removed) {
                        ++detached;
                        FW_DBG("[detach-via-parent] mod=%p FALLBACK "
                               "detached from parent=%p",
                               mod, fallback_parent);
                        continue;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        FW_WRN("[detach-via-parent] mod=%p NOT FOUND in scene graph "
               "(parent_ptr=%p, base_root=%p) — already detached or "
               "stale", mod, r.parent, base_root);
    }
    return detached;
}

}  // anon namespace

void clear_ghost_extra_mods(const char* peer_id) {
    if (!peer_id) return;
    if (!g_resolved.load(std::memory_order_acquire)) return;
    if (!g_r.detach_child) return;

    // Snapshot the (base_root, mod_nodes) tuple under the lock so the
    // detach loop below operates on stable values; then clear the
    // tracked vector. We DO NOT hold the slot mutex during the engine
    // detach call (engine takes its own scene-graph locks that we
    // don't want nested under our app mutex).
    void*               base_root = nullptr;
    std::vector<void*>  victims;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) return;
        base_root = it->second.nif_node;
        victims   = std::move(it->second.extra_mods);
        it->second.extra_mods.clear();
    }

    if (victims.empty()) return;

    // 2026-05-06 evening — was: detach_child(base_root, node) — silently
    // failed for mods attached to placeholder sub-nodes (the common
    // case). Now: read each mod's actual parent via +0x28 and detach
    // from THAT, with subtree-search fallback.
    const int detached = seh_detach_mods_via_parent(base_root, victims);
    const int detach_failed =
        static_cast<int>(victims.size()) - detached;

    // Drop our +1 refbump on every tracked node — even ones we
    // couldn't detach (engine's eventual NIF unload handles their final
    // destruction; we just balance our outstanding refbump). Untrack
    // from g_owned_clones first so the global purge sweep doesn't see
    // dangling pointers post-refdec.
    for (void* node : victims) {
        if (node) {
            untrack_owned_clone(node);
            seh_refcount_dec_armor(node);
        }
    }

    FW_LOG("[ghost-extras] peer=%s cleared %d mods (detached=%d "
           "detach_failed=%d) from base=%p",
           peer_id, static_cast<int>(victims.size()),
           detached, detach_failed, base_root);
}

// M9.w4 PROPER (v0.4.2+, RESMGR-SHARE) — see header.
//
// 2026-05-05 fix — placeholder-aware attach. Previous version attached
// every mod as a direct child of base_root; visually all mods stacked
// at the same point (transform inheritance from base) producing the
// "weapon-soup monster" that user reported. Real Bethesda behaviour:
// the base weapon NIF contains placeholder NiNodes (e.g. "PistolReceiver",
// "SightMount"); the engine attaches each loaded mod NIF as a child of
// the placeholder named in its OMOD INNT record. We replicate this by
// having the sender capture the slot placeholder name (= grand-parent
// of the BSGeometry leaf in its own assembled tree) and the receiver
// then walks the loaded base weapon for that exact name. We also write
// the sender's captured local_transform onto the mod node so it lands
// at the same offset within the placeholder that the sender had.
bool attach_extra_node_to_ghost_weapon(const char* peer_id,
                                        void* node,
                                        const char* display_name,
                                        const char* slot_name,
                                        const float local_transform[16]) {
    if (!peer_id || !node) return false;
    if (!g_resolved.load(std::memory_order_acquire)) return false;
    if (!g_r.attach_child_direct) return false;

    void* base_root = nullptr;
    GhostWeaponSlot* slot_ptr = nullptr;  // for tracking extra_mods (set under lock below)
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it == g_ghost_weapon_slot.end() || !it->second.nif_node) {
            FW_DBG("[resmgr-share] peer=%s no slot — skip '%s'",
                   peer_id, display_name ? display_name : "<null>");
            return false;
        }
        base_root = it->second.nif_node;
        slot_ptr  = &it->second;  // lifetime OK: map only mutated on main thread
    }

    // 2026-05-06 LATE evening (M9 closure, FLAT-REBUILD) — attach mods
    // DIRECTLY to the ghost's WEAPON bone (not to a placeholder inside
    // the base weapon NIF). The sender now ships local_transform as the
    // mod NIF root's rigid offset relative to the WEAPON bone (see
    // weapon_witness.cpp extract_one_mesh). When we set
    // mod_clone.m_local = received_relative, the engine recomputes
    // mod_clone.m_world = WEAPON.m_world * received_relative → mod
    // appears at the same offset from ghost's hand as on sender's
    // hand.
    //
    // This sidesteps ALL placeholder lookup machinery (exact match,
    // P-* alias, substring search, FALLBACK). slot_name is now unused
    // for placement (kept in signature for log clarity).
    //
    // The ghost's loaded base_root is kept attached to WEAPON as a
    // sibling of the mods. It provides body parts (receiver/slide/
    // frame) the user expects to see. Default content inside base
    // placeholders may overlap with mods — separate concern, can
    // address later via APP_CULL of base_root entirely if user
    // prefers "mods only" rendering.
    void* attach_parent = find_weapon_attach_node();
    bool used_placeholder = (attach_parent != nullptr
                              && attach_parent != base_root);
    const char* match_kind = "weapon-bone-direct";
    if (!attach_parent) {
        attach_parent = base_root;
        match_kind = "no-weapon-fallback";
        used_placeholder = false;
    }
    (void)slot_name;  // unused in flat-rebuild architecture

    // 2026-05-06 PM — CLONE via vt[26] BEFORE attach. Was: refbump the
    // shared cached node and attach. That made every peer's ghost
    // weapon mutate the SAME cached BSFadeNode (the cached `node`'s
    // `+0x28 parent` field was overwritten by whichever peer attached
    // last → first peer's children list pointed to a node whose parent
    // pointer no longer pointed back at it → render walk corruption →
    // user reported "le pistole sono tutte uguali e troppo moddate").
    // Six independent RE agents converged on the fix: invoke vt[26]
    // (NetImmerse Clone slot) on the cached node to get a per-peer
    // deep-clone with its own parent pointer + GPU buffer AddRef'd.
    // Cache stays clean.
    void* clone = clone_nif_subtree(node);
    if (!clone || clone == node) {
        FW_WRN("[resmgr-share] clone failed for '%s' node=%p — skip "
               "(would otherwise share-mutate cache)",
               display_name ? display_name : "<null>", node);
        return false;
    }
    // Track for orphan-purge (weapon clones only, not body/armor).
    track_owned_clone(clone);

    // 2026-05-06 LATE evening (FLAT-REBUILD) — selective cull DISABLED.
    // We're now attaching directly to WEAPON (not to a placeholder),
    // so there's no placeholder-default-content to hide on this path.
    // The default content inside base_root's placeholders will still
    // render alongside the mods — visual overlap is the cost of
    // bypassing the placeholder system entirely. If overlap is bad,
    // a follow-up can find each mod's matching base placeholder by
    // parent_placeholder name and cull its leaves separately.
    // The clone's refcount comes back as 1 (we own it). attach_child_direct
    // will bump to 2 when the parent slot takes its child reference.
    // No explicit refbump on the clone needed — that was for the SHARED
    // path; the clone is OURS exclusively.

    const bool ok = seh_attach_child_geom(g_r.attach_child_direct,
                                            attach_parent, clone);
    if (!ok) {
        // Drop our 1 ref so the clone deallocates instead of leaking.
        // Untrack from g_owned_clones first (clone is tracked from
        // clone_nif_subtree return).
        untrack_owned_clone(clone);
        seh_node_refdec(clone);
        FW_WRN("[resmgr-share] attach SEH for '%s' parent=%p clone=%p "
               "(source=%p)",
               display_name ? display_name : "<null>",
               attach_parent, clone, node);
        return false;
    }

    // Apply the sender's captured local_transform on the CLONE (not
    // the cached source — that would still be cache-share contamination).
    if (local_transform) {
        if (!seh_write_local_transform(clone, local_transform)) {
            FW_WRN("[resmgr-share] SEH writing local_transform for '%s' "
                   "clone=%p — proceeding (mod will use identity)",
                   display_name ? display_name : "<null>", clone);
        }
    }

    // Track the CLONE in extra_mods so next equip's clear pass detaches
    // it. Each peer has its own clones, no cross-peer contamination.
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it != g_ghost_weapon_slot.end()) {
            it->second.extra_mods.push_back(clone);
        }
    }

    // The 'node' arg is unused in the success path now — kept in signature
    // for log clarity (display_name comes from same call site). Avoid
    // unused-var warning by referencing it in the trace below.
    (void)node;

    if (used_placeholder) {
        FW_LOG("[resmgr-share] SHARED+ATTACHED '%s' node=%p → "
               "slot='%s' (match=%s) placeholder=%p (in base=%p, "
               "peer=%s, xf=%s)",
               display_name ? display_name : "<null>",
               node,
               slot_name ? slot_name : "",
               match_kind,
               attach_parent, base_root, peer_id,
               local_transform ? "yes" : "no");
    } else {
        FW_LOG("[resmgr-share] SHARED+ATTACHED '%s' node=%p → base=%p "
               "FALLBACK (slot '%s' not resolved, peer=%s, xf=%s)",
               display_name ? display_name : "<null>",
               node, base_root,
               (slot_name && slot_name[0]) ? slot_name : "<empty>",
               peer_id,
               local_transform ? "yes" : "no");
    }
    return true;
}

// === M9 closure (PLAN B — NiStream serialization) =========================

namespace {
// Get the first non-null child of a NiNode-derived `parent`. The
// "assembled weapon" tree on the local PC sits as a child of the
// WEAPON bone; this finds it.
void* first_child_w4(void* parent) {
    if (!parent) return nullptr;
    void**         kids = nullptr;
    std::uint16_t  count = 0;
    if (!seh_read_children_w4(parent, kids, count)) return nullptr;
    if (!kids || count == 0 || count > 256) return nullptr;
    for (std::uint16_t i = 0; i < count; ++i) {
        void* k = seh_kid_at_w4(kids, i);
        if (k) return k;
    }
    return nullptr;
}
}  // anon namespace

// 2026-05-06 NIGHT — diagnostic helper. Attempts a full
// serialize→deserialize round-trip in the SAME process. Returns
// true if both sides succeed and the deserialized root is non-null.
// If this fails, the engine NiStream Save/Load primitives don't
// roundtrip cleanly — the network layer can't be at fault. If this
// succeeds but cross-process Load fails, the wire layer is suspect.
static bool nistream_self_test(void* root) {
    if (!root) return false;
    SerializedNif blob{};
    if (!nistream_serialize_subtree(root, &blob)) {
        FW_WRN("[nistream-self] serialize FAILED (sender side)");
        return false;
    }
    FW_LOG("[nistream-self] serialized OK size=%zu — testing deserialize...",
           blob.size);
    // Dump first 32 bytes for visual inspection.
    {
        const std::uint8_t* p = static_cast<const std::uint8_t*>(blob.buf);
        char hex[100] = {0};
        int hp = 0;
        const std::size_t lim = blob.size < 32 ? blob.size : 32;
        for (std::size_t i = 0; i < lim && hp + 4 < (int)sizeof(hex); ++i) {
            hp += std::snprintf(hex + hp, sizeof(hex) - hp, "%02X ",
                                static_cast<unsigned>(p[i]));
        }
        FW_LOG("[nistream-self] buf head: %s", hex);
    }

    void* deser_root = nistream_deserialize_subtree(blob.buf, blob.size);
    nistream_free(blob.buf);
    if (!deser_root) {
        FW_WRN("[nistream-self] deserialize FAILED — engine roundtrip "
               "broken, NOT a network issue");
        return false;
    }
    FW_LOG("[nistream-self] deserialize OK root=%p — engine roundtrip "
           "works, dropping ref", deser_root);
    seh_refcount_dec_armor(deser_root);
    return true;
}

std::size_t serialize_and_ship_player_weapon(std::uint32_t item_form_id) {
    if (item_form_id == 0) return 0;
    if (!g_resolved.load(std::memory_order_acquire)) return 0;
    if (g_r.base == 0) return 0;

    // 2026-05-06 LATE evening — was: `find_weapon_attach_node()` which
    // walks `g_skel_root_cached` (= the GHOST's skeleton, populated by
    // inject_body_nif). On the SENDER, the ghost skeleton's WEAPON bone
    // has no children (we don't render the local PC as their own ghost).
    // The LOCAL player's actual assembled weapon lives under the engine's
    // own player loaded3D tree, NOT under the ghost. Use the witness
    // helper that walks player loaded3D → WEAPON bone → first named child.
    void* assembled_root =
        weapon_witness::find_player_assembled_weapon_root_pub();
    if (!assembled_root) {
        FW_DBG("[nistream-tx] no LOCAL player assembled weapon root "
               "(player not loaded? no equipped weapon?) — skip serialize");
        return 0;
    }

    // Self-test: serialize+deserialize in same process. If this fails,
    // the network is innocent — engine NiStream roundtrip is broken.
    nistream_self_test(assembled_root);

    SerializedNif blob{};
    if (!nistream_serialize_subtree(assembled_root, &blob)) {
        FW_WRN("[nistream-tx] serialize failed for root=%p (form=0x%X)",
               assembled_root, item_form_id);
        return 0;
    }

    FW_LOG("[nistream-tx] serialized assembled weapon root=%p form=0x%X "
           "into %zu bytes", assembled_root, item_form_id, blob.size);

    const std::size_t chunks = fw::net::client().enqueue_nif_blob_for_equip(
        item_form_id, blob.buf, blob.size);

    nistream_free(blob.buf);

    return chunks;
}

bool deserialize_and_attach_nif_blob(const char* peer_id,
                                       std::uint32_t item_form_id,
                                       const void* nif_buf,
                                       std::size_t nif_size) {
    if (!peer_id || !nif_buf || nif_size == 0) return false;
    if (!g_resolved.load(std::memory_order_acquire)) return false;
    if (g_r.base == 0) return false;
    if (!g_r.attach_child_direct) return false;

    void* weapon_bone = find_weapon_attach_node();
    if (!weapon_bone) {
        FW_WRN("[nistream-rx] no ghost WEAPON bone available — drop "
               "blob (peer=%s form=0x%X size=%zu)",
               peer_id, item_form_id, nif_size);
        return false;
    }

    void* root = nistream_deserialize_subtree(nif_buf, nif_size);
    if (!root) {
        FW_WRN("[nistream-rx] deserialize FAILED peer=%s form=0x%X "
               "size=%zu", peer_id, item_form_id, nif_size);
        return false;
    }

    // Track for the orphan-purge sweep so a subsequent equip auto-
    // releases this root if our explicit cleanup misses it.
    track_owned_clone(root);

    // Attach root as a child of WEAPON bone. Engine's attach_child_direct
    // takes its own +1 ref, so after this call: refcount = 2 (our +1
    // from deserialize + engine's +1 for parent slot).
    const bool ok = seh_attach_child_geom(g_r.attach_child_direct,
                                            weapon_bone, root);
    if (!ok) {
        FW_WRN("[nistream-rx] attach SEH peer=%s form=0x%X root=%p",
               peer_id, item_form_id, root);
        // Drop our +1 ref → engine destroys root.
        untrack_owned_clone(root);
        seh_refcount_dec_armor(root);
        return false;
    }

    // Track in slot.extra_mods so next ghost_set_weapon / clear_ghost_extra
    // detaches the deserialized tree.
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto& slot = g_ghost_weapon_slot[peer_id];
        slot.form_id = item_form_id;
        slot.extra_mods.push_back(root);
    }

    FW_LOG("[nistream-rx] ATTACHED nif_blob peer=%s form=0x%X root=%p "
           "(blob=%zu B) → WEAPON=%p",
           peer_id, item_form_id, root, nif_size, weapon_bone);
    return true;
}

// === M9 closure (2026-05-07) — name-match weapon assembly ==================
//
// LIVE TEST FINDING (06:18 session, see analysis in chat history):
// The engine's runtime weapon-mod assembly is dramatically simpler than
// any of the static decomp dossiers (ALPHA/GAMMA/DELTA + 4 follow-ups)
// suggested. There is NO BSModelProcessor OMOD-apply branch firing —
// the post-hook (sub_1402FC0E0) walks every weapon NIF parse but the
// `(v9 = sub_141730390(node))` lookup returns null because the loaded
// node carries no BGSObjectInstanceExtra. We confirmed this by dumping
// the extra-data chain of every loaded weapon NIF post-call: type
// bytes were always 0x00 (NiAVObject visit-state), never 0x35 (OIE).
//
// What ACTUALLY happens:
//   1. Engine loads base weapon NIF (e.g. 10mmPistol.nif).
//      Root m_name = "Weapon", sub-children include placeholder NiNodes
//      named like "10mmReceiverParentObject", "Magazine", "10mmGrip".
//   2. Engine separately loads each mod sub-NIF (e.g. 10mmReceiverDummy.nif).
//      The sub-NIF's NiHeader.RootNodeName is hardcoded by Bethesda to
//      MATCH the placeholder name in the base — e.g. the receiver mod
//      file 10mmReceiverDummy.nif loads with root m_name =
//      "10mmReceiverParentObject".
//   3. Engine calls find_child_by_name(base_root, sub_nif_root.m_name)
//      to locate the placeholder, then attaches the sub-NIF as child.
//
// That's it. No OIE, no synthetic REFR, no BSModelProcessor magic.
// Pure m_name string-match between the file's RootNodeName and the
// placeholder NiNode name in the base weapon.
//
// IMPLEMENTATION
// ==============
// 1. Resolve weapon TESForm → modelPath → load via nif_load_by_path.
// 2. Clone via vt[26] for per-peer instance independence.
// 3. For each omod_form_id:
//    a. Resolve TESForm → modelPath via resolve_omod_model_path.
//    b. nif_load_by_path → sub-NIF BSFadeNode.
//    c. Clone via vt[26].
//    d. Read clone root m_name.
//    e. find_node_by_name_w4(base_clone, m_name) → placeholder.
//    f. Attach clone as child of placeholder.
// 4. Attach base_clone under ghost WEAPON bone.
//
// Per-omod failure (load fail, m_name unreadable, no placeholder match)
// is NON-FATAL — we log and continue. Worst case the user sees the
// vanilla weapon with some mods missing.
namespace {

// SEH-safe lookup_form. POD-only so callers using C++ objects can use it
// without tripping C2712.
void* seh_lookup_form_local(std::uint32_t form_id) {
    if (form_id == 0 || g_r.base == 0) return nullptr;
    using LookupFn = void* (__fastcall*)(std::uint32_t);
    auto fn = reinterpret_cast<LookupFn>(
        g_r.base + offsets::LOOKUP_BY_FORMID_RVA);
    __try { return fn(form_id); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// SEH-safe formType byte read at form+0x1A.
std::uint8_t seh_read_form_type(void* form) {
    if (!form) return 0;
    __try {
        return *(static_cast<std::uint8_t*>(form) + 0x1A);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// SEH-safe call to sub_140434DA0 (engine OMOD attach via BSConnectPoint
// pairing). Returns engine rc or -1 on SEH. POD-only.
int seh_call_omod_attach(void* omod_form, void* base_node,
                          const char* placeholder, int flags) {
    if (g_r.base == 0 || !omod_form || !base_node) return -1;
    using OmodAttachFn = int (__fastcall*)(void*, void*, const char*, int);
    constexpr std::uintptr_t OMOD_ATTACH_RVA = 0x00434DA0;
    auto fn = reinterpret_cast<OmodAttachFn>(g_r.base + OMOD_ATTACH_RVA);
    __try {
        return fn(omod_form, base_node, placeholder, flags);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -2; }
}

// Verified by live test 06:18: all weapon-NIF parses use the same NIF
// loader the project already wraps via g_r.nif_load_by_path. The opts
// flag we want is the same combination armor/body uses (FADE_WRAP |
// POSTPROC = 0x18). The post-hook fires either way; we don't depend on
// it for OMOD apply (the runtime doesn't either — see header note).
void* seh_load_nif_path_local(const char* path) {
    if (!path || !*path || !g_r.nif_load_by_path) return nullptr;
    NifLoadOpts opts{};
    opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;
    void* node = nullptr;
    const std::uint32_t rc = seh_nif_load_armor(
        g_r.nif_load_by_path, path, &node, &opts);
    if (rc != 0 || !node) return nullptr;
    if (g_r.apply_materials) {
        seh_apply_materials_armor(g_r.apply_materials, node);
    }
    return node;
}

}  // anon namespace

bool ghost_attach_assembled_weapon(const char* peer_id,
                                     std::uint32_t weapon_form_id,
                                     const std::uint32_t* omod_form_ids,
                                     std::size_t num_omods) {
    if (!peer_id || weapon_form_id == 0) return false;
    if (!g_resolved.load(std::memory_order_acquire)) return false;
    if (!g_r.nif_load_by_path || !g_r.attach_child_direct) return false;

    // ----- 1. Resolve + load the BASE weapon NIF ---------------------------
    const char* probed_path = resolve_weapon_nif_path(weapon_form_id);
    if (!probed_path || !*probed_path) {
        FW_WRN("[name-match] peer=%s form=0x%X — could not resolve base "
               "modelPath", peer_id, weapon_form_id);
        return false;
    }

    // 2026-05-07 — Bethesda canonical fallback. resolve_weapon_nif_path
    // often returns a "*Dummy*" placeholder (e.g. 10mmRecieverDummy.nif)
    // because the form's TESModel field is set to the "stock receiver"
    // sub-NIF, NOT the base weapon. The convention is
    //   Weapons\<X>\<X>.nif
    // where <X> is the parent folder name. We try that first; if it
    // doesn't load, fall back to whatever the probe returned.
    auto build_canonical_path = [](const char* p) -> std::string {
        if (!p || !*p) return {};
        std::string s = p;
        const auto last_bs = s.find_last_of('\\');
        if (last_bs == std::string::npos) return {};
        const auto prev_bs = s.find_last_of('\\', last_bs - 1);
        const std::string folder = (prev_bs == std::string::npos)
            ? s.substr(0, last_bs)
            : s.substr(prev_bs + 1, last_bs - prev_bs - 1);
        if (folder.empty()) return {};
        return s.substr(0, last_bs + 1) + folder + ".nif";
    };

    std::string canonical = build_canonical_path(probed_path);
    std::string base_path_str;
    void* base_source = nullptr;
    if (!canonical.empty() && canonical != probed_path) {
        base_source = seh_load_nif_path_local(canonical.c_str());
        if (base_source) {
            base_path_str = std::move(canonical);
            FW_DBG("[name-match] peer=%s form=0x%X using canonical base "
                   "'%s' (probed='%s')",
                   peer_id, weapon_form_id,
                   base_path_str.c_str(), probed_path);
        }
    }
    if (!base_source) {
        base_source = seh_load_nif_path_local(probed_path);
        if (!base_source) {
            FW_WRN("[name-match] peer=%s form=0x%X base load FAILED "
                   "(canonical='%s', probed='%s')",
                   peer_id, weapon_form_id, canonical.c_str(), probed_path);
            return false;
        }
        base_path_str = probed_path;
    }
    const char* base_path = base_path_str.c_str();

    void* base_clone = clone_nif_subtree(base_source);
    if (!base_clone || base_clone == base_source) {
        FW_WRN("[name-match] peer=%s base CLONE FAILED — falling back to "
               "shared cached node (cache-share contamination risk)",
               peer_id);
        base_clone = base_source;
    } else {
        seh_refcount_dec_armor(base_source);
        track_owned_clone(base_clone);
    }

    // DIAGNOSTIC 2026-05-07 — dump the base clone subtree so we can SEE
    // which placeholder NiNodes actually exist. Live test showed every
    // OMOD's mod_root name failed to match — either the base is empty
    // (vt[26] clone shallow?) or names diverge (mod naming convention).
    {
        FW_LOG("[name-match][diag] === base subtree dump peer=%s "
               "form=0x%X path='%s' root=%p ===",
               peer_id, weapon_form_id, base_path, base_clone);
        dump_subtree_recursive(base_clone, g_r.base, 0, 6, "[name-match][diag]");
    }

    // ----- 2. Attach NEW base to WEAPON bone FIRST (so BSConnectPoint
    //          recursive walker resolves against an in-scene base) ---------
    void* attach_node = find_weapon_attach_node();
    if (!attach_node) {
        FW_WRN("[bsconnect] peer=%s no WEAPON bone — drop assembled base",
               peer_id);
        untrack_owned_clone(base_clone);
        seh_refcount_dec_armor(base_clone);
        return false;
    }

    clear_ghost_extra_mods(peer_id);
    void* old_node = nullptr;
    {
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto& slot = g_ghost_weapon_slot[peer_id];
        old_node          = slot.nif_node;
        slot.form_id      = weapon_form_id;
        slot.nif_node     = base_clone;
        slot.nif_path     = base_path;
        slot.base_culled  = false;
    }
    if (old_node) release_weapon_node(old_node);

    if (!seh_attach_child_armor(g_r.attach_child_direct,
                                  attach_node, base_clone)) {
        FW_ERR("[bsconnect] peer=%s form=0x%X SEH attaching base — "
               "rolling back slot", peer_id, weapon_form_id);
        std::lock_guard lk(g_ghost_weapon_slot_mtx);
        auto it = g_ghost_weapon_slot.find(peer_id);
        if (it != g_ghost_weapon_slot.end() &&
            it->second.nif_node == base_clone) {
            it->second.nif_node = nullptr;
        }
        untrack_owned_clone(base_clone);
        seh_refcount_dec_armor(base_clone);
        return false;
    }

    // ----- 3. NOW apply OMODs via engine BSConnectPoint pipeline -----------
    int mods_attached  = 0;
    int mods_resolve_fail = 0;
    int mods_type_fail = 0;
    int mods_seh = 0;

    for (std::size_t i = 0; i < num_omods; ++i) {
        const std::uint32_t omod_id = omod_form_ids[i];
        if (omod_id == 0) continue;

        void* omod_form = seh_lookup_form_local(omod_id);
        if (!omod_form) {
            ++mods_resolve_fail;
            FW_DBG("[bsconnect] peer=%s OMOD 0x%X lookup FAILED",
                   peer_id, omod_id);
            continue;
        }

        const std::uint8_t form_type = seh_read_form_type(omod_form);
        if (form_type != 0x90) {
            ++mods_type_fail;
            FW_DBG("[bsconnect] peer=%s OMOD 0x%X formType=0x%X (expected "
                   "0x90) — skip", peer_id, omod_id,
                   static_cast<unsigned>(form_type));
            continue;
        }

        const int rc = seh_call_omod_attach(omod_form, base_clone,
                                              /*placeholder=*/nullptr,
                                              /*flags=*/0);
        if (rc == -2) {
            ++mods_seh;
            FW_WRN("[bsconnect] peer=%s OMOD 0x%X SEH inside sub_140434DA0",
                   peer_id, omod_id);
            continue;
        }
        if (rc != 0) {
            FW_DBG("[bsconnect] peer=%s OMOD 0x%X sub_140434DA0 returned "
                   "rc=%d", peer_id, omod_id, rc);
        }
        ++mods_attached;
        FW_LOG("[bsconnect] peer=%s OMOD 0x%X attached via "
               "sub_140434DA0 (rc=%d)", peer_id, omod_id, rc);
    }

    purge_orphan_weapon_clones();

    FW_LOG("[bsconnect] peer=%s form=0x%X DONE base='%s' attached=%d/%zu "
           "(resolve_fail=%d type_fail=%d seh=%d)",
           peer_id, weapon_form_id, base_path, mods_attached, num_omods,
           mods_resolve_fail, mods_type_fail, mods_seh);
    return true;
}

// SPAI Tier 1 force-prewarm — see header. Composes the same load
// sequence as inject_body_nif's lambda but routed through the existing
// POD-only SEH helpers so we can call this from a function that uses
// no C++ destructors locally (avoids C2712 SEH-in-unwind).
//
// Note we silently DROP the loader's out-pointer ref. The engine's
// resmgr already holds 1 ref against the entry; the second ref the
// loader hands to us would just leak this NIF forever if we kept it
// (we never plan to release it from prewarm). Letting the local `node`
// var go out of scope without refdec is intentional — the engine's
// per-frame ref-equalization sweep is what trims this back to 1.
//
// (If empirical testing shows ref-leak symptoms — e.g. growing refcount
// each prewarm — we'd switch to seh_node_refdec(node) at the end.
// First-pass: keep it simple and observe.)
bool spai_force_load_path(const char* path) {
    if (!path || !*path) return false;
    if (!g_resolved.load(std::memory_order_acquire)) return false;
    if (!g_r.nif_load_by_path || !g_r.apply_materials) return false;

    NifLoadOpts opts{};
    opts.flags = NIF_OPT_FADE_WRAP | NIF_OPT_POSTPROC;  // 0x18 — same as body

    std::uint8_t* killswitch_byte = reinterpret_cast<std::uint8_t*>(
        g_r.base + BSLSP_BIND_KILLSWITCH_BYTE_RVA);
    const std::uint8_t saved_ks = *killswitch_byte;
    *killswitch_byte = 1;

    void* node = nullptr;
    const std::uint32_t rc = seh_nif_load_armor(g_r.nif_load_by_path,
                                                  path, &node, &opts);

    *killswitch_byte = saved_ks;

    if (rc == 0xDEADBEEFu) {
        FW_WRN("[spai] SEH in nif_load_by_path('%s')", path);
        return false;
    }
    if (rc != 0 || !node) {
        // Path doesn't exist on disk OR engine refused — both common in a
        // 1257-path catalog (some BA2 entries reference DLC-only assets
        // when only the base game DLCs are installed, etc.). Quiet log.
        FW_DBG("[spai] load FAIL rc=%u node=%p path='%s'", rc, node, path);
        return false;
    }

    // apply_materials walks the freshly-loaded subtree resolving .bgsm
    // → DDS so the cached entry has fully bound shaders/textures by the
    // time a later resmgr-lookup hands it back to attach_extra_node.
    const std::uint8_t saved_ks2 = *killswitch_byte;
    *killswitch_byte = 1;
    seh_apply_materials_armor(g_r.apply_materials, node);
    *killswitch_byte = saved_ks2;

    return true;
}

void flush_pending_weapon_ops() {
    std::unordered_map<std::string, std::deque<PendingWeaponOp>> local;
    {
        std::lock_guard lk(g_pending_weapon_mtx);
        local.swap(g_pending_weapon_ops);
    }
    if (local.empty()) {
        FW_DBG("[weapon-pending] flush: queue empty — no-op");
        return;
    }

    std::size_t total = 0;
    std::size_t ok = 0;
    for (auto& kv : local) {
        const std::string& peer = kv.first;
        for (const auto& op : kv.second) {
            ++total;
            const bool success = (op.kind == 1)
                ? ghost_attach_weapon(peer.c_str(), op.form_id)
                : ghost_detach_weapon(peer.c_str(), op.form_id);
            if (success) ++ok;
        }
    }
    FW_LOG("[weapon-pending] flush: replayed %zu/%zu ops across %zu peers",
           ok, total, local.size());
}

#if 0  // --- M2.3 clone_shader_into_cube (SUPERSEDED by M2.4 factory path) ---
// This was the pre-factory approach: alloc a BSDynamicTriShape separately
// and then hand-clone shader/alpha/vertex-data pointers. Replaced by the
// M2.4 factory-based flow which builds a proper BSTriShape from raw verts
// (with fresh BSPositionData, not shared from source). Kept here #if 0'd
// as historical reference for a few commits, will be deleted once M2
// proves stable.
bool clone_shader_into_cube_LEGACY() {
    if (!g_resolved.load(std::memory_order_acquire)) {
        FW_WRN("[native] clone_shader: not resolved yet — skipping");
        return false;
    }
    void* cube = g_injected_cube.load(std::memory_order_acquire);
    if (!cube) {
        FW_WRN("[native] clone_shader: no cube injected — skipping");
        return false;
    }
    void* src = get_first_bstri_shape();
    if (!src) {
        FW_WRN("[native] clone_shader: no first_bstri_shape captured — "
               "walker found no BSTriShape on this run; skipping");
        return false;
    }

    __try {
        char* cb  = reinterpret_cast<char*>(cube);
        char* sb  = reinterpret_cast<char*>(src);

        // Step 1: zero-init +0x130/+0x138 on the cube. The BSDynamicTriShape
        // ctor (sub_1416E4090) does NOT zero these slots (observed live:
        // they contained 0x3F800000_3F800000 = two 1.0f floats, garbage
        // from pool reuse). If we leave garbage in there, vt[42] will try
        // to release it as if it were a NiObject and AV on the deref.
        auto** p_alpha  = reinterpret_cast<void**>(cb + BSGEOM_ALPHAPROP_OFF);
        auto** p_shader = reinterpret_cast<void**>(cb + BSGEOM_SHADERPROP_OFF);
        FW_LOG("[native] clone_shader: pre-zero  alpha=%p shader=%p",
               *p_alpha, *p_shader);
        *p_alpha  = nullptr;
        *p_shader = nullptr;
        FW_LOG("[native] clone_shader: post-zero alpha=%p shader=%p",
               *p_alpha, *p_shader);

        // Step 2: read source properties from the vanilla BSTriShape.
        void* src_alpha  = *reinterpret_cast<void**>(sb + BSGEOM_ALPHAPROP_OFF);
        void* src_shader = *reinterpret_cast<void**>(sb + BSGEOM_SHADERPROP_OFF);
        FW_LOG("[native] clone_shader: src=%p  src_alpha=%p  src_shader=%p",
               src, src_alpha, src_shader);

        // Step 3: alpha via direct BSGeometry::SetAlphaProperty call.
        //         The function is refcount-safe: bumps new, direct-writes
        //         to +0x130, releases old. Old is now null (zeroed above)
        //         so release is a no-op. Safe.
        if (src_alpha) {
            g_r.set_alpha_prop_direct(cube, src_alpha);
            FW_LOG("[native] clone_shader: SetAlphaProperty called, "
                   "post-call alpha@+0x130=%p", *p_alpha);
        } else {
            FW_LOG("[native] clone_shader: src has no alpha property — "
                   "leaving cube alpha null");
        }

        // Step 4: shader via direct write + InterlockedIncrement.
        //         No public setter; the engine's installer sites in
        //         sub_140372CC0 / sub_1406B60C0 do this inline too.
        if (src_shader) {
            _InterlockedIncrement(reinterpret_cast<long*>(
                reinterpret_cast<char*>(src_shader) + NIAV_REFCOUNT_OFF));
            *p_shader = src_shader;
            FW_LOG("[native] clone_shader: shader installed via direct write, "
                   "src_shader refcount now=%ld",
                   *reinterpret_cast<long*>(
                       reinterpret_cast<char*>(src_shader) + NIAV_REFCOUNT_OFF));
        } else {
            FW_LOG("[native] clone_shader: src has no shader property — "
                   "leaving cube shader null");
        }

        // Step 5: also copy over the packed BSVertexDesc at +0x150 and
        //         material type at +0x158. The cube needs the same vertex
        //         format as the source so the renderer's stream setup
        //         works. Harmless copy — just 16 bytes. Not a refcount
        //         slot.
        std::uint64_t* cube_desc = reinterpret_cast<std::uint64_t*>(
            cb + 0x150);
        std::uint64_t* src_desc  = reinterpret_cast<std::uint64_t*>(
            sb + 0x150);
        cube_desc[0] = src_desc[0];  // packed vertex desc
        cube_desc[1] = src_desc[1];  // material type word + padding
        FW_LOG("[native] clone_shader: copied vertex desc "
               "+0x150=0x%llX +0x158=0x%llX",
               static_cast<unsigned long long>(cube_desc[0]),
               static_cast<unsigned long long>(cube_desc[1]));

        // ------------------------------------------------------------------
        // M2.4 (A-path — clone full geometry from source).
        //
        // Instead of building a vertex/index buffer ourselves (which would
        // require decoding BSVertexDesc packing — deferred to M2.4 B-path
        // via the RE agent running in background), we CLONE the pointers
        // +0x148 (vertex/geometry data) and +0x160/+0x168 (packed counts)
        // directly from the source BSTriShape.
        //
        // Effect: our cube renders the SAME mesh as the source. In a normal
        // outdoor scene, source is typically a random rock / terrain LOD
        // piece — so we'll see a copy of that floating at cube position
        // (50,50,50). Not literally a cube, but proof that the end-to-end
        // render path works.
        //
        // Safety caveats:
        //   - +0x148 probably contains a pointer to a struct with raw GPU
        //     buffer ptrs. We do NOT refcount-bump (not known if the field
        //     holds a NiObject-derived type; the BSGeometry ctor zero-inits
        //     it but does NOT refcount-release like it does for +0x130/
        //     +0x138 — suggests it's not a standard NiPointer). Raw copy
        //     means we share the buffer without a ref. If the source is
        //     freed, we UAF. For M2 test purposes (single session), low
        //     probability — vanilla scene geometry is engine-owned and
        //     sticky.
        //   - +0x140 (possibly BSSkinInstance) left null. If source is
        //     non-skinned (most world geometry isn't), this is correct.
        //     If source IS skinned, cube renders un-skinned version —
        //     may look warped but shouldn't crash.
        //
        // Log values before + after so we can diff against the live hex
        // dump the walker already produces.
        auto** p_geom148 = reinterpret_cast<void**>(cb + 0x148);
        std::uint64_t* p_count160 = reinterpret_cast<std::uint64_t*>(cb + 0x160);

        FW_LOG("[native] clone_geom: pre-clone +0x148=%p +0x160=0x%llX",
               *p_geom148,
               static_cast<unsigned long long>(*p_count160));

        void* src_geom148 = *reinterpret_cast<void**>(sb + 0x148);
        std::uint64_t src_count160 = *reinterpret_cast<std::uint64_t*>(sb + 0x160);

        FW_LOG("[native] clone_geom: src +0x148=%p +0x160=0x%llX",
               src_geom148,
               static_cast<unsigned long long>(src_count160));

        *p_geom148  = src_geom148;
        *p_count160 = src_count160;

        FW_LOG("[native] clone_geom: post-clone +0x148=%p +0x160=0x%llX "
               "(low32=%u verts, hi32=%u indices per dossier convention)",
               *p_geom148,
               static_cast<unsigned long long>(*p_count160),
               static_cast<unsigned int>(src_count160 & 0xFFFFFFFFu),
               static_cast<unsigned int>(src_count160 >> 32));

        FW_LOG("[native] M2.3+M2.4 CLONE: SUCCESS — cube has shader+alpha"
               " + geometry pointer clone from source. If the render walk"
               " dispatches the draw, you'll see a copy of source mesh at"
               " cube position. If you see nothing, check player pos and"
               " teleport near (50,50,50). Watch for crash first.");
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[native] clone_shader: SEH caught exception");
        return false;
    }
}
#endif  // --- end legacy M2.3 clone_shader_into_cube ---

// ---------------------------------------------------------------- dispatch

// Forward decl for arm_worker (in anon ns) to find the bone-tick starter
// (defined after bone_copy namespace far below). Must live at fw::native
// namespace scope so both the anon-ns caller and the out-of-anon definition
// link to the same symbol (anonymous-namespace functions get unique internal
// mangling, breaking cross-scope refs).
void start_bone_tick_worker_once();

namespace {

// Fixed test position for M1. Empty NiNode has no bounding / no geometry
// so the engine won't try to render anything regardless — we just need
// it walked + Update'd. (0,0,0) is the worldspace origin; fine as any
// other coord for an invisible canary.
constexpr float kTestPosX = 0.0f;
constexpr float kTestPosY = 0.0f;
constexpr float kTestPosZ = 0.0f;

std::thread       g_arm_thread;
std::atomic<bool> g_arm_stop{false};
std::atomic<bool> g_armed{false};

// Cooperative sleep: wakes every 100ms to check g_arm_stop. Returns
// true if slept the full duration, false if stop was requested.
bool cooperative_sleep(unsigned int ms) {
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (g_arm_stop.load(std::memory_order_acquire)) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return true;
}

// Check if the local player is TRULY in-world post-LoadGame completion.
//
// Multi-condition check (learned the hard way 2026-04-23 after a crash):
//
//   1. Player singleton non-null.
//   2. Player->parentCell (+0xB8) non-null. This is THE most reliable
//      "save completed" indicator — the cell pointer is only populated
//      after LoadGame finishes placing the player in a loaded cell.
//   3. Player pos NOT the pre-load default (2048, 2048, 0). That's
//      where the freshly-allocated singleton sits before the save
//      teleports the player — if we inject then, the scene graph is
//      about to be torn down by LoadGame and our refcounts UAF on
//      the old SSN.
//
// The crash on the last test happened because we passed all three
// checks from an older version (singleton + pos!=0,0,0) before the
// save actually loaded — injected a cube into a soon-to-be-destroyed
// scene graph.
bool local_player_in_world() {
    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (!game) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(game);
    __try {
        void** player_slot = reinterpret_cast<void**>(base + 0x032D2260);
        void* player = *player_slot;
        if (!player) return false;

        // parentCell at +0xB8 (from src/offsets.h PARENT_CELL_OFF).
        void* parent_cell = *reinterpret_cast<void**>(
            reinterpret_cast<char*>(player) + 0xB8);
        if (!parent_cell) return false;  // save not fully loaded yet

        // pos at +0xD0. Reject (0,0,0) AND the (2048, 2048, *) default.
        const float* pos = reinterpret_cast<const float*>(
            reinterpret_cast<char*>(player) + 0xD0);
        const bool is_zero =
            pos[0] == 0.0f && pos[1] == 0.0f && pos[2] == 0.0f;
        const bool is_pre_load_default =
            pos[0] == 2048.0f && pos[1] == 2048.0f;
        if (is_zero || is_pre_load_default) return false;

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void arm_worker(unsigned int grace_delay_ms) {
    // RETURN TO T+30s GRACE — the aggressive polling approach (2026-04-23
    // earlier this day) caused crashes because we'd inject between
    // game-auto-load and our DLL's auto_load_save second LoadGame. The
    // game's own save-load flow triggers multiple LoadGame events in
    // sequence; detecting "player is in-world" passes cleanly between
    // them, but the SSN is torn down each time. Injecting during that
    // transient window = UAF during scene graph rebuild.
    //
    // Static 30s grace is conservative but proven safe across 5+ prior
    // tests with cube allocation/attach (the pre-factory days). By T+30s
    // all auto-loads have completed, the SSN is stable.
    //
    // After grace, brief remote-snapshot poll (60s max, tick 2s) in
    // case Client B comes online late. If no snapshot, fall back to
    // local player (still visible from our own POV).
    FW_LOG("[native] arm_worker: grace sleep %u ms (wait for all LoadGame "
           "events to settle)", grace_delay_ms);
    if (!cooperative_sleep(grace_delay_ms)) {
        FW_LOG("[native] arm_worker: stop during grace — exit");
        return;
    }

    // v15.5: reduced from 60s → 8s. With 60s, solo testing (no peer)
    // had to wait T+30s grace + 60s poll = 90s before fallback inject
    // fired. Now T+30s + 8s = 38s. Negligible UX cost when peer IS
    // present (8s polling completes near-instantly when first remote
    // packet arrives).
    constexpr unsigned int poll_timeout_ms = 8000;
    constexpr unsigned int poll_tick_ms    = 1000;
    FW_LOG("[native] arm_worker: grace over, polling for remote snapshot "
           "(max %ums, tick %ums)", poll_timeout_ms, poll_tick_ms);

    const auto poll_deadline = std::chrono::steady_clock::now()
                             + std::chrono::milliseconds(poll_timeout_ms);
    bool got_snapshot = false;
    while (std::chrono::steady_clock::now() < poll_deadline) {
        if (g_arm_stop.load(std::memory_order_acquire)) {
            FW_LOG("[native] arm_worker: stop during remote poll — exit");
            return;
        }
        if (fw::net::client().get_remote_snapshot().has_state) {
            got_snapshot = true;
            FW_LOG("[native] arm_worker: remote snapshot acquired — "
                   "breaking poll early");
            break;
        }
        if (!cooperative_sleep(poll_tick_ms)) return;
    }
    if (!got_snapshot) {
        FW_WRN("[native] arm_worker: no remote snapshot after polling — "
               "posting inject anyway (cube will spawn above local player)");
    }

    const HWND h = fw::dispatch::get_target_hwnd();
    if (!h) {
        FW_ERR("[native] arm_worker: HWND never arrived — cannot post inject");
        return;
    }
    if (!PostMessageW(h, FW_MSG_STRADAB_INJECT, 0, 0)) {
        FW_ERR("[native] arm_worker: PostMessage(FW_MSG_STRADAB_INJECT) "
               "failed (err=%lu)", GetLastError());
        return;
    }
    FW_LOG("[native] arm_worker: FW_MSG_STRADAB_INJECT posted to hwnd=%p",
           h);
    // M3.1: tracking is now event-driven. The net thread calls
    // fw::native::notify_remote_pos_changed() each time a POS_BROADCAST
    // arrives — that posts WM_APP+0x46 directly. No polling needed.
    // This worker's job is done.
    //
    // M7.b (v15.4): start the bone-tick timer worker too. That worker
    // posts WM_APP+0x47 at 20Hz once the ghost is injected, so bone
    // copy runs regardless of peer activity / network state.
    FW_LOG("[native] arm_worker: starting bone-tick worker");
    start_bone_tick_worker_once();
    FW_LOG("[native] arm_worker: exiting (M3.1 event-driven tracking "
           "handles subsequent cube position updates)");
}

} // namespace

void arm_injection_after_boot(unsigned int delay_ms) {
    bool expected = false;
    if (!g_armed.compare_exchange_strong(expected, true)) {
        FW_DBG("[native] arm_injection_after_boot: already armed — ignoring");
        return;
    }
    g_arm_thread = std::thread(arm_worker, delay_ms);

    // M9.w4 PROPER (v0.4.2+) — live probe on resmgr to settle 4-agent
    // disagreement on Entry+0x10. Fire 90s post-DLL-init: gives player
    // time to (a) finish all auto-loads, (b) walk into a cell with
    // weapons, (c) equip something so the resmgr has weapon entries
    // worth inspecting.
    arm_resmgr_probe(/*delay_ms=*/ 90000);
}

// M3: per-frame positioning update handler. Runs on the main thread
// (WndProc dispatch). Reads the fresh remote snapshot and writes the
// new position into cube.local.translate. The engine's MOVABLE flag
// causes world transform to recompute on next frame walk — no need
// to call UpdateDownwardPass each tick (that would cost us CPU).
//
// Z-offset +1500 units (same as inject) keeps the cube floating above
// the remote player's head as they move.
// Internal helper: SEH-cage the cube memory write + update-pass call.
// Writing local.translate/rotate alone does NOT trigger world-transform
// recompute — that requires UpdateDownwardPass to mark the node dirty.
// We call it on the cube itself (not the parent SSN) so the cascade
// only touches our subtree (no children → cheap).
//
// Rotation: 3x3 matrix composed from euler angles (rx=pitch, ry=roll,
// rz=yaw) using R = Rz(yaw) * Ry(roll) * Rx(pitch) convention — the
// standard "yaw then pitch then roll" order used by most Bethesda-lineage
// engines (confirmed empirically with body_render in Strada A).
//
// ============================================================================
// M7.b — PLAYER BONE COPY  (re/_player_copy_m7.log)
// ============================================================================
//
// Instead of attaching an anim graph to our standalone BSFadeNode (proven
// impossible — all layers hard-bound to Actor, see re/_anim_graph_m7.log),
// we copy the LOCAL player's per-frame animated bone transforms onto our
// ghost body's matching bones. The engine already computes walk/run/idle/
// aim poses on the player every frame via vanilla animation graph; we
// just mirror those to the ghost. "Steal what's already computed."
//
// Key findings from the RE dossier:
//   - Player loaded3D at PlayerChar + 0xB78 (direct BSFadeNode*, no
//     loadedData indirection).
//   - Player skeleton = NESTED tree (Pelvis → SPINE1 → SPINE2 → Chest
//     → Neck1_sk → HEAD, arms branching at Chest). Recursive walk.
//   - Ghost skeleton (from standalone MaleBody.nif) = FLAT siblings of
//     BSFadeNode root. Single-loop walk. Bone NAMES match 1:1.
//   - CRITICAL: copy player.bone.WORLD → ghost.bone.LOCAL. NOT local→local
//     (tree shape mismatch = wrong semantics). Ghost bones' parent is
//     the body root, so their "local" is effectively worldspace relative
//     to body root, which matches the player's absolute worldspace pose.
//   - After copying: call UpdateDownwardPass(ghost_body) to recompute
//     world transforms for render submit.
//
// Limitation (M7.b shared-pose): all ghosts mirror THE LOCAL PLAYER's
// pose. If you walk, every ghost walks. If you aim, every ghost aims.
// M7.c protocol extension will sync remote peers' bone transforms over
// UDP and swap the source of bone copy per ghost.

namespace bone_copy {

// Read a NiObjectNET name (BSFixedString at +0x10 → pool_entry → c_str
// at +0x18 of the pool entry, per FO4 BSFixedString layout). Returns
// empty string on AV or null. Thread-local-ish static buffer for ASCII
// copy safety. Same semantics as try_read_ni_name but returns raw
// pointer (no quoting).
static const char* safe_bone_name(void* node) {
    __try {
        if (!node) return "";
        const char* pool_entry = *reinterpret_cast<const char* const*>(
            reinterpret_cast<const char*>(node) + NIAV_NAME_OFF);
        if (!pool_entry) return "";
        const char* c = pool_entry + 0x18;
        return c;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return ""; }
}

// Ghost bones: flat siblings. Build name → NiNode* map in one loop.
static void walk_ghost_flat(void* root,
                            std::unordered_map<std::string, void*>& out) {
    __try {
        char* rb = reinterpret_cast<char*>(root);
        void** kids = *reinterpret_cast<void***>(rb + NINODE_CHILDREN_PTR_OFF);
        std::uint16_t count = *reinterpret_cast<std::uint16_t*>(
            rb + NINODE_CHILDREN_CNT_OFF);
        if (!kids || count == 0 || count > 256) return;
        for (std::uint16_t i = 0; i < count; ++i) {
            void* c = kids[i];
            if (!c) continue;
            const char* name = safe_bone_name(c);
            if (name[0]) out.emplace(name, c);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Player bones: NESTED tree. Recursive walk, collect all named nodes.
// Bound depth to avoid runaway (real skeleton depth ≤ 12).
//
// v15-DIAG: log every visited node to understand tree shape. First
// live test showed player_bones=19 (way too few) and matched=4.
// Expected 50+ bones — something is off with the tree walk.
static bool g_verbose_player_walk = true;  // flip off after first diag cycle

static void walk_player_nested(void* node, int depth,
                               std::unordered_map<std::string, void*>& out) {
    if (!node || depth > 16) return;
    __try {
        const char* name = safe_bone_name(node);
        char* nb = reinterpret_cast<char*>(node);

        // Read vtable RVA for identification
        std::uintptr_t vt_rva = 0;
        void* vt = *reinterpret_cast<void**>(nb);
        if (vt) {
            const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
            if (game) {
                const auto base =
                    reinterpret_cast<std::uintptr_t>(game);
                vt_rva = reinterpret_cast<std::uintptr_t>(vt) - base;
            }
        }

        void** kids = *reinterpret_cast<void***>(nb + NINODE_CHILDREN_PTR_OFF);
        std::uint16_t count = *reinterpret_cast<std::uint16_t*>(
            nb + NINODE_CHILDREN_CNT_OFF);

        if (g_verbose_player_walk) {
            FW_LOG("[player_walk] %*snode=%p vt_rva=0x%llX name='%s' "
                   "kids=%p count=%u",
                   depth * 2, "", node,
                   static_cast<unsigned long long>(vt_rva),
                   name[0] ? name : "<anon>",
                   static_cast<void*>(kids),
                   static_cast<unsigned>(count));
        }

        if (name[0]) {
            out.emplace(name, node);
        }

        if (!kids || count == 0 || count > 256) return;
        for (std::uint16_t i = 0; i < count; ++i) {
            if (kids[i]) {
                walk_player_nested(kids[i], depth + 1, out);
            } else if (g_verbose_player_walk) {
                // Log null children — if COM count=2 but only visits
                // child[0], we want to know if child[1] is truly null
                // or if there's a bug in our offset reading.
                FW_LOG("[player_walk] %*s  (child[%u]=NULL)",
                       depth * 2, "", static_cast<unsigned>(i));
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Cached pair map + source pointers for invalidation detection.
// Thread-accessed from main thread (on_pos_update_message WM_APP dispatch).
struct Pair { void* p_bone; void* g_bone; };
static std::vector<Pair> g_bone_pairs;
static void* g_cached_player_3d = nullptr;
static void* g_cached_ghost_body = nullptr;
static std::atomic<std::uint64_t> g_copy_count{0};
static std::uint64_t g_last_rebuild_tick = 0;

// Follow Actor+0xF0 "template 3D" chain. Per the dossier, vt[139]
// Get3D(bool) returns sub_14050D990 on the else branch, which reads
// *(*(this+0xF0)+8). That might be a separate 3D handle (template /
// alternate 3D). Log its vtable if valid.
static void probe_actor_alt_3d_chain(void* player) {
    __try {
        char* pb = reinterpret_cast<char*>(player);
        void* f0_ptr = *reinterpret_cast<void**>(pb + 0xF0);
        if (!f0_ptr) {
            FW_LOG("[scan_actor] Actor+0xF0 = NULL");
            return;
        }
        FW_LOG("[scan_actor] Actor+0xF0 = %p (struct ptr)", f0_ptr);
        // Read struct+0x08
        void* alt_3d = *reinterpret_cast<void**>(
            reinterpret_cast<char*>(f0_ptr) + 8);
        if (!alt_3d) {
            FW_LOG("[scan_actor] Actor+0xF0->+0x08 = NULL");
            return;
        }
        const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
        if (!game) return;
        const auto base = reinterpret_cast<std::uintptr_t>(game);
        void* vt = *reinterpret_cast<void**>(alt_3d);
        auto vt_rva = reinterpret_cast<std::uintptr_t>(vt) - base;
        const char* name = safe_bone_name(alt_3d);
        std::uint16_t cnt = *reinterpret_cast<std::uint16_t*>(
            reinterpret_cast<char*>(alt_3d) + NINODE_CHILDREN_CNT_OFF);
        FW_LOG("[scan_actor] Actor+0xF0->+0x08 = %p vt_rva=0x%llX "
               "name='%s' children=%u",
               alt_3d, static_cast<unsigned long long>(vt_rva),
               name[0] ? name : "<anon>", cnt);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[scan_actor] probe_actor_alt_3d_chain SEH");
    }
}

// Scanner: find every pointer in Actor[0..0x1000] that looks like a
// BSFadeNode (vt_rva=0x28FA3E8) or NiNode (0x267C888). Logs all hits
// with their offset and first child name. This tells us if there are
// OTHER loaded3D-like fields beyond +0xB78 (e.g. 3rd person body).
static void scan_actor_for_3d_pointers(void* player) {
    __try {
        const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
        if (!game) return;
        const auto base = reinterpret_cast<std::uintptr_t>(game);
        const std::uintptr_t BSFADENODE_VT = base + 0x28FA3E8;
        const std::uintptr_t NINODE_VT     = base + 0x267C888;

        char* pb = reinterpret_cast<char*>(player);
        FW_LOG("[scan_actor] looking for BSFadeNode/NiNode ptrs in Actor "
               "first 0x1000 bytes");
        for (std::size_t off = 0x08; off < 0x1000; off += 8) {
            void* candidate = *reinterpret_cast<void**>(pb + off);
            if (!candidate) continue;
            // Pointers usually look like 0x00000XXXXXXXXXXX — filter obvious non-pointers
            auto p = reinterpret_cast<std::uintptr_t>(candidate);
            if (p < 0x10000 || p > 0xFFFFFFFFFFFF) continue;
            __try {
                void* vt = *reinterpret_cast<void**>(candidate);
                auto vt_addr = reinterpret_cast<std::uintptr_t>(vt);
                if (vt_addr == BSFADENODE_VT || vt_addr == NINODE_VT) {
                    const char* tag = (vt_addr == BSFADENODE_VT)
                        ? "BSFadeNode" : "NiNode";
                    const char* name = safe_bone_name(candidate);
                    // Also read child count to see if it's an interesting tree
                    std::uint16_t cnt = *reinterpret_cast<std::uint16_t*>(
                        reinterpret_cast<char*>(candidate)
                        + NINODE_CHILDREN_CNT_OFF);
                    FW_LOG("[scan_actor]   +0x%03zX = %p [%s] name='%s' "
                           "children=%u",
                           off, candidate, tag,
                           name[0] ? name : "<anon>", cnt);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        FW_LOG("[scan_actor] scan done");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[scan_actor] SEH");
    }
}

// Build (or rebuild on cache miss) the name-matched bone pair list.
static void rebuild_pairs(void* player_3d, void* ghost_body) {
    g_bone_pairs.clear();

    // v15-DIAG: dump player+ghost all 3 loaded pointers to see if
    // 0xB78 (what we use) is the right one or if 0xB80 / 0xB88 is
    // the actual animated skeleton.
    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    const auto base = reinterpret_cast<std::uintptr_t>(game);
    void* player = *reinterpret_cast<void**>(base + PLAYER_SINGLETON_RVA);
    if (player) {
        char* pb = reinterpret_cast<char*>(player);
        void* p_B78 = *reinterpret_cast<void**>(pb + 0xB78);
        void* p_B80 = *reinterpret_cast<void**>(pb + 0xB80);
        void* p_B88 = *reinterpret_cast<void**>(pb + 0xB88);
        auto vt_rva = [&](void* o) -> std::uintptr_t {
            if (!o) return 0;
            __try {
                void* vt = *reinterpret_cast<void**>(o);
                return reinterpret_cast<std::uintptr_t>(vt) - base;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0xDEAD; }
        };
        FW_LOG("[bonecopy] player pointers: "
               "+0xB78=%p(vt=0x%llX) +0xB80=%p(vt=0x%llX) +0xB88=%p(vt=0x%llX)",
               p_B78, static_cast<unsigned long long>(vt_rva(p_B78)),
               p_B80, static_cast<unsigned long long>(vt_rva(p_B80)),
               p_B88, static_cast<unsigned long long>(vt_rva(p_B88)));

        // v15.2 — scan first 4KB of Actor for ANY BSFadeNode/NiNode ptr.
        // If there's a separate 3D pointer for the 3rd-person body (what
        // the user is actually SEEING on screen with hair+clothes+skin),
        // it'll show here. We're currently reading +0xB78 which turned
        // out to be the 1st-person model ("BaseMaleBody_fitted1stPerson",
        // PipboyBone visible — unmistakable 1P signature).
        scan_actor_for_3d_pointers(player);
    }

    std::unordered_map<std::string, void*> p_map, g_map;
    FW_LOG("[bonecopy] === walking PLAYER tree (verbose) ===");
    walk_player_nested(player_3d, 0, p_map);
    g_verbose_player_walk = false;  // only first cycle
    FW_LOG("[bonecopy] === end PLAYER walk ===");
    walk_ghost_flat(ghost_body, g_map);

    for (auto& [name, g_bone] : g_map) {
        auto it = p_map.find(name);
        if (it != p_map.end()) {
            g_bone_pairs.push_back({ it->second, g_bone });
        }
    }
    FW_LOG("[bonecopy] pair rebuild: player_bones=%zu ghost_bones=%zu "
           "matched=%zu", p_map.size(), g_map.size(), g_bone_pairs.size());

    // Log first 10 ghost names NOT found in player map (for diag)
    int missed = 0;
    for (auto& [name, g_bone] : g_map) {
        if (p_map.find(name) == p_map.end() && missed < 15) {
            FW_LOG("[bonecopy] ghost-only bone: '%s'", name.c_str());
            missed++;
        }
    }

    g_cached_player_3d = player_3d;
    g_cached_ghost_body = ghost_body;
}

// Scratch maps for the bone copy logic — must be declared before
// dump_transform_diag uses them and before copy_bones_once does.
static std::unordered_map<std::string, void*> g_ghost_map_cached;
static std::unordered_map<std::string, void*> g_player_map_scratch;
static std::size_t g_last_pair_count = 0;

// One-time diagnostic dump of player_3d's transforms + sample bone +
// actor.pos, to learn the alt tree's coordinate space. Separate from
// copy_bones_once because the .find() iterator return type triggers
// MSVC C2712 (no STL with destructors inside __try).
static void dump_transform_diag(void* player_3d, void* player) {
    char* p3d = reinterpret_cast<char*>(player_3d);
    const float* lt = reinterpret_cast<const float*>(
        p3d + NIAV_LOCAL_TRANSLATE_OFF);
    const float* lr = reinterpret_cast<const float*>(
        p3d + NIAV_LOCAL_ROTATE_OFF);
    const float* wt = reinterpret_cast<const float*>(
        p3d + NIAV_WORLD_TRANSLATE_OFF);
    const float* wr = reinterpret_cast<const float*>(
        p3d + NIAV_WORLD_ROTATE_OFF);
    FW_LOG("[bonecopy-diag] player_3d=%p (alt_root)", player_3d);
    FW_LOG("[bonecopy-diag]   local.translate=(%.1f, %.1f, %.1f)",
           lt[0], lt[1], lt[2]);
    FW_LOG("[bonecopy-diag]   local.rot row0=(%.3f,%.3f,%.3f) "
           "row1=(%.3f,%.3f,%.3f) row2=(%.3f,%.3f,%.3f)",
           lr[0], lr[1], lr[2],
           lr[4], lr[5], lr[6],
           lr[8], lr[9], lr[10]);
    FW_LOG("[bonecopy-diag]   world.translate=(%.1f, %.1f, %.1f)",
           wt[0], wt[1], wt[2]);
    FW_LOG("[bonecopy-diag]   world.rot row0=(%.3f,%.3f,%.3f) "
           "row1=(%.3f,%.3f,%.3f) row2=(%.3f,%.3f,%.3f)",
           wr[0], wr[1], wr[2],
           wr[4], wr[5], wr[6],
           wr[8], wr[9], wr[10]);

    // Player actor.pos at +0xD0
    const float* ap = reinterpret_cast<const float*>(
        reinterpret_cast<char*>(player) + 0xD0);
    FW_LOG("[bonecopy-diag] player.actor.pos +0xD0=(%.1f, %.1f, %.1f)",
           ap[0], ap[1], ap[2]);

    // Sample bones: SPINE2, Chest, HEAD — what their world looks like
    // tells us if alt tree's WORLD is in worldspace or body-local.
    const char* sample_names[] = {"SPINE2", "Chest", "Head", "Pelvis"};
    for (const char* name : sample_names) {
        auto it = g_player_map_scratch.find(name);
        if (it == g_player_map_scratch.end()) continue;
        char* bn = reinterpret_cast<char*>(it->second);
        const float* swt = reinterpret_cast<const float*>(
            bn + NIAV_WORLD_TRANSLATE_OFF);
        const float* slt = reinterpret_cast<const float*>(
            bn + NIAV_LOCAL_TRANSLATE_OFF);
        FW_LOG("[bonecopy-diag] %s local=(%.1f,%.1f,%.1f) world=(%.1f,%.1f,%.1f)",
               name,
               slt[0], slt[1], slt[2],
               swt[0], swt[1], swt[2]);
    }
}

// Per-frame copy. Runs on main thread. SEH-caged.
// Call AFTER pos_update_seh (which sets body.local.translate + yaw).
//
// v16 ARCHITECTURE: ghost loaded as skeleton.nif (root) + MaleBody/
// Head/Hands as children. Bones now NESTED tree matching player's.
// Source = `Actor+0xF0->+0x08` (full 3P skeleton tree per RE dossier).
// Bone copy is a 1:1 name-keyed memcpy of LOCAL transforms (no body-
// relative math needed — local IS already in body-relative frame in
// a nested tree). Math reduced to: ghost.bone.local = player.bone.local.
// (g_ghost_map_cached / g_player_map_scratch / g_last_pair_count are
// declared above before dump_transform_diag.)

static void copy_bones_once(void* ghost_body) {
    if (!ghost_body) return;
    __try {
        // Find player 3D.
        const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
        if (!game) return;
        const auto base = reinterpret_cast<std::uintptr_t>(game);
        void* player = *reinterpret_cast<void**>(base + PLAYER_SINGLETON_RVA);
        if (!player) return;

        // v15.8: prefer Actor+0xF0->+0x08 (real 3rd-person skeleton tree
        // with full bones + face + hair). Fall back to +0xB78 only if
        // unavailable. The +0xB78 tree was a 1P stub with Pelvis=NULL.
        void* player_3d = nullptr;
        char* pb_for_alt = reinterpret_cast<char*>(player);
        void* f0_ptr = *reinterpret_cast<void**>(pb_for_alt + 0xF0);
        if (f0_ptr) {
            void* alt_3d = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(f0_ptr) + 8);
            if (alt_3d) player_3d = alt_3d;
        }
        if (!player_3d) {
            player_3d = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(player) + REFR_LOADED_3D_OFF);
        }
        if (!player_3d) return;  // loading screen

        // First-time bookkeeping: cache ghost map + run diag scan.
        const bool first_tick = (g_cached_player_3d == nullptr);
        if (first_tick) {
            g_ghost_map_cached.clear();
            // v16: ghost is now nested (skeleton.nif → bones), use the
            // recursive walker. Bones in our ghost tree have the SAME
            // names as the player's animated tree (skeleton.nif RE).
            walk_player_nested(ghost_body, 0, g_ghost_map_cached);
            FW_LOG("[bonecopy] ghost map built: %zu bones",
                   g_ghost_map_cached.size());
            scan_actor_for_3d_pointers(player);
            probe_actor_alt_3d_chain(player);  // Actor+0xF0->+0x08 probe

            // v15.8 DIAG — populate map first so dump can find SPINE2 etc.
            g_player_map_scratch.clear();
            walk_player_nested(player_3d, 0, g_player_map_scratch);
            dump_transform_diag(player_3d, player);
            g_player_map_scratch.clear();  // re-walked below

            g_cached_player_3d = player_3d;
            g_cached_ghost_body = ghost_body;
        }
        // Rebuild ghost map if ghost was re-injected
        if (ghost_body != g_cached_ghost_body) {
            g_ghost_map_cached.clear();
            walk_player_nested(ghost_body, 0, g_ghost_map_cached);
            g_cached_ghost_body = ghost_body;
        }

        // Walk PLAYER tree fresh every tick (picks up 1P↔3P mesh swaps).
        // Verbose enabled when: (a) first tick, OR (b) just after pair
        // count changed — catches content swap when user toggles view.
        // NEXT-tick-verbose flag: set by the "pair count changed"
        // branch below, processed THIS tick, then cleared.
        static bool request_verbose_next = false;
        g_verbose_player_walk = first_tick || request_verbose_next;
        request_verbose_next = false;  // consume
        g_player_map_scratch.clear();
        if (g_verbose_player_walk) FW_LOG("[bonecopy] === walking PLAYER tree #1 (+0xB78) verbose ===");
        walk_player_nested(player_3d, 0, g_player_map_scratch);

        // v15.6 REVERTED: dual-tree merge (also walking
        // Actor+0xF0->+0x08) caused body to render stretched + auto-
        // despawn — the alt tree's bone transforms have a different
        // coordinate space (or contain pre-bind/T-pose static values)
        // that, when blended into the +0xB78 named bones, give nan
        // or wildly off-axis poses. The BSFadeNode appears to cull
        // itself out on transform corruption.
        //
        // Kept: the diagnostic probe (probe_actor_alt_3d_chain) at
        // first-tick which logs the alt 3D's existence + child count.
        // We know it's THERE (a SEPARATE skeleton.nif BSFadeNode with
        // children=5), but we don't yet understand its pose semantics.
        // M7 follow-up: if we want to drive ghost from the alt tree,
        // first dump its full nested tree to understand bone naming
        // conventions and transform space, THEN compose properly.
        if (g_verbose_player_walk) FW_LOG("[bonecopy] === end PLAYER walk ===");

        // Build pair list for this tick — exact name match only.
        // Fuzzy/suffix-strip was a guess (rejected by user); proper
        // approach is RE'ing how vanilla drives bones, not pattern-
        // matching names speculatively.
        g_bone_pairs.clear();
        for (auto& [name, g_bone] : g_ghost_map_cached) {
            auto it = g_player_map_scratch.find(name);
            if (it != g_player_map_scratch.end()) {
                g_bone_pairs.push_back({ it->second, g_bone });
            }
        }

        // Log only when pair count CHANGES (indicates 1P↔3P swap
        // or new meshes loaded). Catches the "user just switched to
        // 3rd person" event. Also: request verbose walk NEXT tick so
        // we dump the new tree shape.
        if (g_bone_pairs.size() != g_last_pair_count) {
            FW_LOG("[bonecopy] pair count: %zu → %zu "
                   "(player_tree=%zu, ghost=%zu)",
                   g_last_pair_count, g_bone_pairs.size(),
                   g_player_map_scratch.size(), g_ghost_map_cached.size());
            g_last_pair_count = g_bone_pairs.size();
            request_verbose_next = true;  // force next walk to be verbose
        }

        if (g_bone_pairs.empty()) return;

        // v16 SIMPLE LOCAL→LOCAL COPY.
        // Both ghost and player have nested skeleton.nif trees with
        // identical hierarchy + bone names. Each bone's `local`
        // transform is parent-relative — the SAME semantic meaning
        // in both trees. So we just memcpy local rot+translate.
        // Per RE dossier Q1: anim writes BOTH rotation AND translate
        // (hkQsTransform = quat rot + vec4 trans + vec4 scale). So
        // copy both 0x30 (rot, NiMatrix3 SIMD-padded) and 0x0C
        // (translate, vec3).
        for (const Pair& pr : g_bone_pairs) {
            char* pb = reinterpret_cast<char*>(pr.p_bone);
            char* gb = reinterpret_cast<char*>(pr.g_bone);

            // Local rotation: 0x30 bytes (3 rows × NiPoint4).
            std::memcpy(gb + NIAV_LOCAL_ROTATE_OFF,
                        pb + NIAV_LOCAL_ROTATE_OFF, 0x30);

            // Local translate: 0x0C bytes (vec3).
            std::memcpy(gb + NIAV_LOCAL_TRANSLATE_OFF,
                        pb + NIAV_LOCAL_TRANSLATE_OFF, 0x0C);

            // Mark dirty so renderer recomputes world.
            std::uint64_t* flags = reinterpret_cast<std::uint64_t*>(
                gb + NIAV_FLAGS_OFF);
            *flags |= 0x2;  // world-cache-invalid
        }

        // Trigger world-transform recompute on the whole ghost subtree.
        // Param block 0x40 bytes, bit 0x1 at +0x10 = recurse-children.
        std::uint8_t param[0x40] = {};
        *reinterpret_cast<std::uint32_t*>(param + 0x10) = 1;
        g_r.update_downward(ghost_body, param);

        const auto n = g_copy_count.fetch_add(1, std::memory_order_relaxed);
        if ((n % 100) == 0) {
            FW_DBG("[bonecopy] tick #%llu pairs=%zu",
                   static_cast<unsigned long long>(n), g_bone_pairs.size());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[bonecopy] SEH during copy — ghost=%p", ghost_body);
    }
}

} // namespace bone_copy

// NiMatrix3 layout at +0x30: 3 rows × NiPoint4 (SIMD-padded to 16B each).
// Row i stored at offset +0x30 + 16*i, only the first 3 floats meaningful.
//
// v12 split: body and head now receive DIFFERENT rotations.
//   body.local.rotate = Rz(yaw)        — ghost faces remote's direction,
//                                         torso stays upright
//   head.local.rotate = Rx(pitch)       — head tilts up/down independently,
//                                         inherited body yaw cascades down
// Roll (ry) is IGNORED — a standing player doesn't lean sideways in
// vanilla movement. Add back if we ever see death animations that use it.
//
// This is NOT full skeletal animation (M7): body is still a rigid
// "tronco" with no spine bend, no arm sway, no walk cycle. But
// decoupling head from body pitch alone visually eliminates the worst
// "tree rotating" artifact per user report 2026-04-24.
static void pos_update_seh(void* body, void* head,
                           float x, float y, float z,
                           float rx /*pitch*/,
                           float ry /*roll, ignored*/,
                           float rz /*yaw*/) {
    (void)ry;  // explicitly unused — see comment above
    __try {
        char* bb = reinterpret_cast<char*>(body);

        // --- body.local.translate — worldspace remote pos ---
        float* b_trans = reinterpret_cast<float*>(bb + NIAV_LOCAL_TRANSLATE_OFF);
        b_trans[0] = x;
        b_trans[1] = y;
        b_trans[2] = z;

        // --- body.local.rotate = Rz(yaw) only ---
        // Standard rotation-around-Z matrix. Z is up in FO4's worldspace,
        // so yaw rotates the character around the vertical axis — the
        // orientation direction (facing angle).
        const float cz = std::cos(rz), sz = std::sin(rz);
        float* b_rot = reinterpret_cast<float*>(bb + NIAV_LOCAL_ROTATE_OFF);
        // Row 0: [ cz, -sz, 0 ]
        b_rot[0] = cz;   b_rot[1] = -sz;  b_rot[2]  = 0.0f;
        // Row 1: [ sz,  cz, 0 ]
        b_rot[4] = sz;   b_rot[5] = cz;   b_rot[6]  = 0.0f;
        // Row 2: [  0,   0, 1 ]
        b_rot[8] = 0.0f; b_rot[9] = 0.0f; b_rot[10] = 1.0f;

        // v14: head pitch DISABLED.
        //
        // Reason: v12 tried to pitch the head BSFadeNode to get Rust-style
        // look-up/down on the ghost. But head.local.rotate = Rx(pitch)
        // rotates the head around ITS OWN origin (which is inside/behind
        // the head, not at the neck), so the head flies off behind the
        // body as pitch increases. Classic "wrong pivot" artifact.
        //
        // M7.a live diag (bone skeleton dump) revealed the 58 body bones
        // are FLAT SIBLINGS under the body BSFadeNode — no nested scene-
        // graph hierarchy. The parent/child bone relationships are
        // managed by the Havok animation graph, not the scene graph.
        // This means any manual per-bone rotation only affects verts
        // skinned to THAT specific bone — you can't "cascade" rotation
        // down a chain manually. Rust-style upper-body aim-twist needs
        // the kinematic chain computed by the anim graph.
        //
        // Proper fix = M7.b: attach a BSAnimationGraphManager to our
        // body BSFadeNode and drive it via engine variables
        // (AimPitchCurrent, SpeedSampled, IsMoving, ...). That's the
        // engine's native path and gets us correct bend automatically.
        //
        // Until M7.b ships, we fall back to yaw-only on body — head
        // stays rigidly attached to body root (inherits yaw), no
        // independent pitch. T-pose looks static but facing direction
        // is correct and there's no flying-head bug.
        //
        // rx (pitch) is ignored here. Kept in the signature for when
        // M7.b wires the anim graph.
        (void)head;
        (void)rx;

        // UpdateDownwardPass on body — cascades to children (head,
        // hands, rear) so they get their world transforms recomputed
        // from our just-written local transforms.
        std::uint64_t update_data[4] = { 0, 0, 0, 0 };
        g_r.update_downward(body, update_data);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[native] pos_update_seh: caught — body/head may be freed");
    }
}

void on_pos_update_message() {
    void* body = g_injected_cube.load(std::memory_order_acquire);
    if (!body) return;
    void* head = g_injected_head.load(std::memory_order_acquire);
    const auto snap = fw::net::client().get_remote_snapshot();
    if (!snap.has_state) return;
    // M5: body origin = feet, so no Z offset. v12: body gets yaw only,
    // head gets pitch only — no more tree-trunk rotation when remote
    // looks up/down.
    pos_update_seh(body, head,
                   snap.pos[0], snap.pos[1], snap.pos[2],
                   snap.rot[0], snap.rot[1], snap.rot[2]);

    // v18: bone_copy disabled. Causes _skin stub corruption + body
    // distortion. Ghost stays in NIF-baked T-pose. M7 animation will
    // be unblocked by M8 full pipeline RE later.
}

// M3.1 event-driven. Called on the NET THREAD from client.cpp right
// after the remote snapshot has been updated with a fresh POS_BROADCAST.
// We just post the main-thread message. The main handler will re-read
// the snapshot — so we don't need to pack pos into the message.
//
// Cost: one PostMessageW per incoming POS_BROADCAST (~20/sec with
// default server settings). Negligible.
//
// Deliberately NO threshold filter here: the net thread has just spent
// resources decoding a packet; dropping the update based on distance
// saves nothing. The main thread writes 3 floats — also cheap. Skipping
// updates adds visual stutter; applying them all gives smooth motion.
void notify_remote_pos_changed() {
    if (!g_injected_cube.load(std::memory_order_acquire)) return;  // no cube yet
    const HWND h = fw::dispatch::get_target_hwnd();
    if (!h) return;  // WndProc not yet subclassed
    PostMessageW(h, FW_MSG_STRADAB_POS_UPDATE, 0, 0);
}

// M7.b bone-tick handler. Called from WndProc when a FW_MSG_STRADAB_BONE_TICK
// arrives. Mirrors bone_copy::copy_bones_once onto the ghost body.
//
// M8P3.15 — runs at 20Hz on main thread:
//   1. Reads local PC body bones m_kLocal 3x3, converts each to
//      quaternion, broadcasts via fw::net::Client::enqueue_pose_state.
//      Receiving peers apply this pose to their ghost-of-us body.
//   2. (legacy) test cycle drives one ghost bone via sin() override —
//      kept as visual fallback to confirm the hook still works.

// ---- M8P3.15 quaternion math (anonymous, file-local) -----------------
namespace {

// Read a 3x3 rotation from NiAVObject.m_kLocal (offset 0x30) into mat3.
// Layout in memory: 3 rows × NiPoint4 (16 bytes each, last 4 bytes pad).
//   row 0 @ +0x30..+0x3C, row 1 @ +0x40..+0x4C, row 2 @ +0x50..+0x5C
// Pad bytes (last 4 of each row) are ignored.
// mat3[0..2]=row0, [3..5]=row1, [6..8]=row2 (row-major).
bool read_local_3x3(void* bone, float mat3[9]) {
    if (!bone) return false;
    __try {
        const float* p = reinterpret_cast<const float*>(
            reinterpret_cast<char*>(bone) + 0x30);
        mat3[0] = p[0];  mat3[1] = p[1];  mat3[2] = p[2];   // row 0
        mat3[3] = p[4];  mat3[4] = p[5];  mat3[5] = p[6];   // row 1
        mat3[6] = p[8];  mat3[7] = p[9];  mat3[8] = p[10];  // row 2
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Write a 3x3 rotation to NiAVObject.m_kLocal (offset 0x30).
// Same SIMD-padded layout as read above.
bool write_local_3x3(void* bone, const float mat3[9]) {
    if (!bone) return false;
    __try {
        float* p = reinterpret_cast<float*>(
            reinterpret_cast<char*>(bone) + 0x30);
        p[0]  = mat3[0]; p[1]  = mat3[1]; p[2]  = mat3[2]; p[3]  = 0;
        p[4]  = mat3[3]; p[5]  = mat3[4]; p[6]  = mat3[5]; p[7]  = 0;
        p[8]  = mat3[6]; p[9]  = mat3[7]; p[10] = mat3[8]; p[11] = 0;
        // Mark dirty so engine's UpdateDownwardPass recomputes m_kWorld.
        std::uint64_t* flags = reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<char*>(bone) + NIAV_FLAGS_OFF);
        *flags |= 0x2;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Shepperd's method: row-major 3x3 → quaternion (qx, qy, qz, qw).
void mat3_to_quat(const float m[9], float q[4]) {
    const float trace = m[0] + m[4] + m[8];
    float qw, qx, qy, qz;
    if (trace > 0) {
        const float s = 0.5f / std::sqrt(trace + 1.0f);
        qw = 0.25f / s;
        qx = (m[7] - m[5]) * s;
        qy = (m[2] - m[6]) * s;
        qz = (m[3] - m[1]) * s;
    } else if (m[0] > m[4] && m[0] > m[8]) {
        const float s = 2.0f * std::sqrt(1.0f + m[0] - m[4] - m[8]);
        qw = (m[7] - m[5]) / s;
        qx = 0.25f * s;
        qy = (m[1] + m[3]) / s;
        qz = (m[2] + m[6]) / s;
    } else if (m[4] > m[8]) {
        const float s = 2.0f * std::sqrt(1.0f + m[4] - m[0] - m[8]);
        qw = (m[2] - m[6]) / s;
        qx = (m[1] + m[3]) / s;
        qy = 0.25f * s;
        qz = (m[5] + m[7]) / s;
    } else {
        const float s = 2.0f * std::sqrt(1.0f + m[8] - m[0] - m[4]);
        qw = (m[3] - m[1]) / s;
        qx = (m[2] + m[6]) / s;
        qy = (m[5] + m[7]) / s;
        qz = 0.25f * s;
    }
    q[0] = qx; q[1] = qy; q[2] = qz; q[3] = qw;
}

// Quaternion (qx, qy, qz, qw) → row-major 3x3 rotation.
void quat_to_mat3(const float q[4], float m[9]) {
    const float qx = q[0], qy = q[1], qz = q[2], qw = q[3];
    const float xx = qx*qx, yy = qy*qy, zz = qz*qz;
    const float xy = qx*qy, xz = qx*qz, yz = qy*qz;
    const float wx = qw*qx, wy = qw*qy, wz = qw*qz;
    m[0] = 1.0f - 2.0f*(yy + zz);
    m[1] = 2.0f*(xy - wz);
    m[2] = 2.0f*(xz + wy);
    m[3] = 2.0f*(xy + wz);
    m[4] = 1.0f - 2.0f*(xx + zz);
    m[5] = 2.0f*(yz - wx);
    m[6] = 2.0f*(xz - wy);
    m[7] = 2.0f*(yz + wx);
    m[8] = 1.0f - 2.0f*(xx + yy);
}

// ---- M8P3.15 net thread → main thread pose handoff -----------------
struct RemotePoseSlot {
    bool                         has_data = false;
    std::uint64_t                ts_ms = 0;
    std::uint16_t                bone_count = 0;
    fw::net::PoseBoneEntry       quats[fw::net::MAX_POSE_BONES] = {};
};
std::mutex      g_remote_pose_mutex;
RemotePoseSlot  g_remote_pose;

// Canonical bone list globals are defined at file scope (above) so
// inject_body_nif (different anon ns) can populate them.

// Strip "_skin" suffix in-place (returns reference into orig storage).
// Returns true if a suffix was stripped, false if no change.
bool strip_skin_suffix(std::string& s) {
    static const std::string SFX = "_skin";
    if (s.size() >= SFX.size()
        && s.compare(s.size() - SFX.size(), SFX.size(), SFX) == 0) {
        s.resize(s.size() - SFX.size());
        return true;
    }
    return false;
}

// SEH-safe helper for engine call. C++ objects forbidden by C2712.
void update_downward_safe(void* root) {
    std::uint8_t param[0x40] = {};
    *reinterpret_cast<std::uint32_t*>(param + 0x10) = 1;
    __try { g_r.update_downward(root, param); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// (Note: populate_canonical_from_ghost_skin_native lives at fw::native:: scope
//  — see top of file. inject_body_nif calls it post-swap.)

// Find the local player's 3D body (rendered character we control).
//
// M8P3.20 — multi-path lookup for 1P/3P agnostic operation.
//   path A: PlayerSingleton +0xF0 +0x08 (alt-tree 3rd-person body — has
//           full anim'd skeleton when in 3P; may be null in 1P)
//   path B: PlayerSingleton +0xB78 (REFR_LOADED_3D — 1P stub or fallback)
//   path C: walk both, pick the one with the most named non-_skin nodes
//           (the animated skeleton has the most body joints visible)
//
// We try A first; if it has < 30 named joints (likely a 1P stub), try B
// and use whichever has more. Simple heuristic, no view-mode detection.
void* find_local_player_3d(std::uintptr_t base) {
    void* player = nullptr;
    __try {
        player = *reinterpret_cast<void**>(base + PLAYER_SINGLETON_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (!player) return nullptr;

    void* path_a = nullptr;  // +0xF0 +0x08
    void* path_b = nullptr;  // +0xB78
    __try {
        char* pb = reinterpret_cast<char*>(player);
        void* f0 = *reinterpret_cast<void**>(pb + 0xF0);
        if (f0) {
            path_a = *reinterpret_cast<void**>(
                reinterpret_cast<char*>(f0) + 8);
        }
        path_b = *reinterpret_cast<void**>(pb + REFR_LOADED_3D_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { /* fall through */ }

    // Quick prefer A (the proven 3P tree). Only fall back to B if A is
    // null or visibly empty. We don't want to walk both every tick.
    if (path_a) return path_a;
    return path_b;
}

}  // anonymous namespace
// ----- end M8P3.15 helpers --------------------------------------------

void on_bone_tick_message() {
    // Force-disable the legacy diag log path. Without this, walk_player_nested
    // dumps ~500 lines per call × 20Hz = 10k lines/sec on FILE I/O. That
    // starves the FO4 main thread and freezes both clients.
    bone_copy::g_verbose_player_walk = false;

    static int s_decim = 0;
    const bool log_now = (++s_decim >= 60);  // ~3-second log decimation
    if (log_now) s_decim = 0;

    // M8P3.20 — broadcast every tick (20Hz). At 80 bones × 16B = 1280B
    // payload + 12B frame header = 1292B per packet × 20Hz = 25.8 KB/s
    // upload per peer. With 9 peers max = 232 KB/s downstream per
    // client. Acceptable for LAN; for internet may want adaptive rate.
    const bool broadcast_now = true;

    void* body = g_injected_cube.load(std::memory_order_acquire);
    if (!body) {
        if (log_now) FW_LOG("[bone-test] no ghost body");
        return;
    }

    // M9.5 — periodic ghost armor skin re-bind. The engine's per-frame
    // pipeline rewrites BSGeometry skin GPU palette state from the skin
    // instance's bones[] array. For SHARED-mesh armors (combat armor,
    // weapon mods, hairstyles, atomic armor pieces ...) the local actor's
    // engine-side binding overwrites bones[] back to the local skel each
    // time the local actor renders, so the ghost armor loses its ghost-
    // skel binding between attach and the next render → ghost armor
    // renders bound to the local skel, off-position, effectively invisible
    // at the ghost's location.
    //
    // Universal fix: every N ticks, walk our attached-armor map and re-
    // run swap_skin_bones_to_skeleton on each. niptr_swap is idempotent
    // (skips writes that would be no-ops), so this is cheap when nothing
    // changed. Decimated to ~4Hz to balance correctness with cost; engine's
    // bind operations happen on equip events (not every frame), so 4Hz
    // catches them with minimal worst-case latency. Silent flag suppresses
    // the otherwise-flooding per-bone FW_LOG.
    //
    // For CLONE-path armors (VS today), the skin is independent — the re-
    // apply is an idempotent no-op every tick. Same code path covers both.
    // Future weapon mods / hairstyles / atomic armor get this protection
    // for free as long as they go through ghost_attach_armor's tracking.
    {
        static int s_armor_decim = 0;
        if (++s_armor_decim >= 5) {
            s_armor_decim = 0;
            void* skel = fw::native::skin_rebind::get_cached_skeleton();
            if (skel) {
                std::vector<void*> armors_snapshot;
                {
                    std::lock_guard<std::mutex> lk(g_armor_map_mtx);
                    for (const auto& peer_kv : g_attached_armor) {
                        for (const auto& form_kv : peer_kv.second) {
                            if (form_kv.second) {
                                armors_snapshot.push_back(form_kv.second);
                            }
                        }
                    }
                }
                for (void* armor : armors_snapshot) {
                    (void)fw::native::skin_rebind::swap_skin_bones_to_skeleton(
                        armor, skel, /*silent=*/true);
                }
            }
        }
    }

    // === LEGACY test cycle (DISABLED in M8P3.15 — replaced by net pose) ==
    // The sin oscillation on LArm_ForeArm1_skin used the world-override
    // hook. With M8P3.15 we drive ALL bones from the remote peer's
    // m_kLocal via direct write (engine recomputes m_kWorld). The two
    // mechanisms would fight on this single bone. Re-enable only if
    // diagnosing the world-override hook in isolation.
    //
    // {
    //     void* body_skin_for_test = fw::native::skin_rebind::find_body_skin_instance(body);
    //     void* test_bone = body_skin_for_test
    //         ? fw::native::skin_rebind::find_bone_in_bones_pri(body_skin_for_test,
    //                                                           "LArm_ForeArm1_skin")
    //         : nullptr;
    //     if (test_bone) {
    //         static const ULONGLONG t0 = GetTickCount64();
    //         const float t = static_cast<float>(GetTickCount64() - t0) * 0.001f;
    //         const float ay = std::sin(t * 2.0f) * 0.5f;
    //         const float cy = std::cos(ay), sy = std::sin(ay);
    //         float mat[16] = {
    //             cy, 0, sy, 0,  0, 1, 0, 0,  -sy, 0, cy, 0,  0, 0, 0, 1
    //         };
    //         fw::native::skin_rebind::set_bone_world(test_bone, mat);
    //     }
    // }

    // === M8P3.15 broadcast LOCAL PC bones to peers =======================
    if (!broadcast_now) return;  // skip 3 of every 4 ticks → ~5Hz

    // Snapshot canonical bone list (populated at body inject).
    std::vector<std::string> canonical;
    {
        std::lock_guard<std::mutex> lk(g_canonical_mutex);
        canonical = g_canonical_names;
    }
    if (canonical.empty()) {
        if (log_now) FW_DBG("[pose-tx] canonical list not yet populated");
        return;
    }

    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (!game) return;
    const auto base = reinterpret_cast<std::uintptr_t>(game);

    // Try TWO paths to the local PC's 3D body — in 1st-person view
    // the +0xF0+0x08 path may return the 1P hand-stub tree (few bones);
    // +0xB78 (REFR_LOADED_3D) is the alternate. Pick whichever yields
    // the better match against canonical (the more populated joint tree).
    void* path_a = nullptr;
    void* path_b = nullptr;
    if (!seh_read_player_3d_paths(base, path_a, path_b)) {
        if (log_now) FW_DBG("[pose-tx] PlayerSingleton or paths null");
        return;
    }

    using BoneMap = std::unordered_map<std::string, void*>;
    BoneMap player_map_a, player_map_b;
    if (path_a) bone_copy::walk_player_nested(path_a, 0, player_map_a);
    // Probe path B only if A is empty or sparse (< 30 nodes likely
    // means 1P stub). Avoids per-tick double-walk in normal 3P case.
    if (path_b && (path_a == nullptr || player_map_a.size() < 30)) {
        bone_copy::walk_player_nested(path_b, 0, player_map_b);
    }

    // Pick whichever has more named entries (the richer tree).
    BoneMap& player_map =
        (player_map_b.size() > player_map_a.size()) ? player_map_b
                                                    : player_map_a;
    if (player_map.empty()) {
        if (log_now) FW_DBG("[pose-tx] both player trees empty (paths "
                            "A=%p B=%p)", path_a, path_b);
        return;
    }
    static int s_path_log_decim = 0;
    if (++s_path_log_decim >= 100) {
        s_path_log_decim = 0;
        FW_DBG("[pose-tx] path A=%zu nodes, path B=%zu nodes (using %s)",
               player_map_a.size(), player_map_b.size(),
               (&player_map == &player_map_a) ? "A" : "B");
    }

    // M8P3.22 KNOWN LIMITATION: in 1st-person view the alt-tree's
    // bones are animated by the engine to V-pose (idle) or T-pose
    // (moving) stub anims because the body is invisible. Both
    // hash-based and bone-canary heuristics failed to discriminate
    // (bones DO get rotated, just to stub poses).
    //
    // Proper fix requires reading the engine's PlayerCamera singleton
    // state field for 1stPerson/3rdPerson — RE pending. Until then,
    // remote ghost displays 1P sender's V/T-pose stub. Workaround:
    // user keeps sender in 3P while observed.

    // For each canonical JOINT name, look up exactly in local PC tree.
    // Joint names match identically (skel.nif schema is the same on
    // both clients). No _skin suffix-stripping needed: canonical only
    // has joint names (those entries were filtered out at populate).
    const std::size_t n = std::min<std::size_t>(
        canonical.size(),
        static_cast<std::size_t>(fw::net::MAX_POSE_BONES));

    // M8P3.23 — for joints NOT found in local PC tree (e.g. fingers,
    // which exist in skel.nif but NOT in the render-scene tree we
    // walk), mark with a SENTINEL quaternion (qw=2.0, invalid for any
    // unit quat). Receiver detects sentinel and SKIPS that bone, so
    // engine keeps its natural bind pose (slightly curled fingers,
    // not extended T-pose). Identity (0,0,0,1) would force extended
    // pose which looks worse than bind.
    constexpr float kSentinelQw = 2.0f;

    fw::net::PoseBoneEntry quats[fw::net::MAX_POSE_BONES] = {};
    int hits = 0, missing = 0;
    static bool s_diag_dumped = false;
    std::string miss_sample;
    for (std::size_t i = 0; i < n; ++i) {
        auto it = player_map.find(canonical[i]);
        if (it == player_map.end()) {
            // Not found → send sentinel.
            quats[i].qx = 0; quats[i].qy = 0; quats[i].qz = 0;
            quats[i].qw = kSentinelQw;
            ++missing;
            if (!s_diag_dumped && miss_sample.size() < 800) {
                if (!miss_sample.empty()) miss_sample += ", ";
                miss_sample += canonical[i];
            }
            continue;
        }
        float m3[9];
        if (!read_local_3x3(it->second, m3)) {
            // Read failed → send sentinel (don't corrupt with identity).
            quats[i].qx = 0; quats[i].qy = 0; quats[i].qz = 0;
            quats[i].qw = kSentinelQw;
            continue;
        }
        float q[4];
        mat3_to_quat(m3, q);
        quats[i].qx = q[0]; quats[i].qy = q[1];
        quats[i].qz = q[2]; quats[i].qw = q[3];
        ++hits;
    }
    if (!s_diag_dumped && missing > 0) {
        s_diag_dumped = true;
        FW_LOG("[pose-tx-diag] FIRST RUN: %zu canonical, matched=%d, "
               "missing names: %s",
               n, hits, miss_sample.c_str());
        // Also dump first 30 player_map keys so we see what's actually there.
        std::string pm_sample;
        int dumped = 0;
        for (auto& kv : player_map) {
            if (dumped >= 30) break;
            if (!pm_sample.empty()) pm_sample += ", ";
            pm_sample += kv.first;
            ++dumped;
        }
        FW_LOG("[pose-tx-diag] player_map first 30 (of %zu): %s",
               player_map.size(), pm_sample.c_str());
    }

    using namespace std::chrono;
    const std::uint64_t now_ms = duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
    fw::net::client().enqueue_pose_state(now_ms, quats, n);

    if (log_now) {
        FW_LOG("[pose-tx] sent %zu joints (matched=%d missing=%d)",
               n, hits, missing);
    }
}

// ---- M8P3.15 net→main pose handoff impl ------------------------------

void store_remote_pose(std::uint64_t ts_ms,
                       const void* quats_buf,
                       std::size_t bone_count)
{
    if (!quats_buf) bone_count = 0;
    if (bone_count > fw::net::MAX_POSE_BONES) bone_count = fw::net::MAX_POSE_BONES;
    {
        std::lock_guard<std::mutex> lk(g_remote_pose_mutex);
        g_remote_pose.has_data   = true;
        g_remote_pose.ts_ms      = ts_ms;
        g_remote_pose.bone_count = static_cast<std::uint16_t>(bone_count);
        if (bone_count > 0) {
            std::memcpy(g_remote_pose.quats, quats_buf,
                        bone_count * sizeof(fw::net::PoseBoneEntry));
        }
    }
    // Wake main thread.
    const HWND h = fw::dispatch::get_target_hwnd();
    if (h) PostMessageW(h, FW_MSG_STRADAB_POSE_APPLY, 0, 0);
}

void on_pose_apply_message() {
    void* ghost = g_injected_cube.load(std::memory_order_acquire);
    if (!ghost) return;

    // Snapshot pose under lock.
    fw::net::PoseBoneEntry quats[fw::net::MAX_POSE_BONES];
    std::uint16_t n = 0;
    {
        std::lock_guard<std::mutex> lk(g_remote_pose_mutex);
        if (!g_remote_pose.has_data || g_remote_pose.bone_count == 0) return;
        n = g_remote_pose.bone_count;
        std::memcpy(quats, g_remote_pose.quats,
                    n * sizeof(fw::net::PoseBoneEntry));
    }

    // Snapshot ghost bone pointers (cached from skin instance at inject).
    // These are the SAME 58 entries the GPU reads via bones_pri after
    // our re-cache. Index i in received quats[] aligns directly with
    // index i in g_ghost_bone_ptrs[] because both sides built the
    // canonical list from a body-NIF skin instance with identical layout.
    std::vector<void*> ptrs;
    {
        std::lock_guard<std::mutex> lk(g_canonical_mutex);
        ptrs = g_ghost_bone_ptrs;
    }
    if (ptrs.empty()) return;

    const std::size_t apply_n = std::min<std::size_t>(n, ptrs.size());
    int wrote = 0, skipped_sentinel = 0;
    for (std::size_t i = 0; i < apply_n; ++i) {
        void* bone = ptrs[i];
        if (!bone) continue;
        const float qx = quats[i].qx, qy = quats[i].qy,
                    qz = quats[i].qz, qw = quats[i].qw;
        // M8P3.23 sentinel: sender marks "not found in local PC" with
        // qw=2.0. We skip → engine keeps the bone's bind pose.
        if (qw > 1.5f) { ++skipped_sentinel; continue; }
        // Defensive: skip degenerate quaternions (near zero-length).
        const float ml = qx*qx + qy*qy + qz*qz + qw*qw;
        if (ml < 0.5f) continue;
        float q[4] = { qx, qy, qz, qw };
        float m3[9];
        quat_to_mat3(q, m3);
        if (write_local_3x3(bone, m3)) wrote++;
    }

    // Trigger world recompute on the ghost subtree (SEH-isolated).
    update_downward_safe(ghost);

    static int s_decim = 0;
    if (++s_decim >= 30) {
        s_decim = 0;
        FW_LOG("[pose-rx] applied %d/%zu bones (skipped %d sentinels) "
               "to ghost=%p",
               wrote, apply_n, skipped_sentinel, ghost);
    }
}


// Timer-thread worker: 20Hz posts of FW_MSG_STRADAB_BONE_TICK to the main
// window once the ghost body is injected. Joins on shutdown.
namespace {
std::thread       g_bone_tick_thread;
std::atomic<bool> g_bone_tick_stop{false};
std::atomic<bool> g_bone_tick_started{false};

void bone_tick_worker() {
    FW_LOG("[bonecopy] tick worker started (20Hz)");
    while (!g_bone_tick_stop.load(std::memory_order_acquire)) {
        // Sleep first, so we don't race with injection. 50ms = 20Hz.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));  // 20Hz idle
        if (g_bone_tick_stop.load(std::memory_order_acquire)) break;

        if (!g_injected_cube.load(std::memory_order_acquire)) continue;
        const HWND h = fw::dispatch::get_target_hwnd();
        if (!h) continue;
        PostMessageW(h, FW_MSG_STRADAB_BONE_TICK, 0, 0);
    }
    FW_LOG("[bonecopy] tick worker exiting");
}
} // namespace

// Call once during arm_injection_after_boot to start the bone tick worker.
// Idempotent. Called alongside the inject arm.
void start_bone_tick_worker_once() {
    bool expected = false;
    if (!g_bone_tick_started.compare_exchange_strong(expected, true)) return;
    g_bone_tick_thread = std::thread(bone_tick_worker);
}

void on_inject_message() {
    FW_LOG("[native] WM_APP+0x45 (STRADAB_INJECT) received on main thread — "
           "attempting inject at (%.1f, %.1f, %.1f)",
           kTestPosX, kTestPosY, kTestPosZ);
    const bool ok = inject_debug_node(kTestPosX, kTestPosY, kTestPosZ);
    if (ok) {
        FW_LOG("[native] M1 INJECT: success — node survives into scene graph.");
    } else {
        FW_WRN("[native] M1 INJECT: failed — see preceding log lines for cause");
    }

    // M2.1: dump the live scene graph so we can identify a BSTriShape
    // to clone a shaderProperty from. We walk starting from World
    // SceneGraph (the same singleton we attached to), depth=5 —
    // enough to descend through World → SSN → NiNode → BSFadeNode →
    // NiNode/subgroup → BSTriShape.
    //
    // First walk (depth=3) showed BSFadeNode at depth 3 — we need at
    // least 1-2 more levels to see its TriShape children. Depth=5
    // gives margin.
    //
    // Reading pointers into the scene is SEH-caged inside the walker;
    // worst case we log a subtree skip and move on. Safe.
    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    if (game) {
        const auto base = reinterpret_cast<std::uintptr_t>(game);
        void** world_sg_slot = reinterpret_cast<void**>(base + WORLD_SG_SINGLETON_RVA);
        void* world_sg = *world_sg_slot;
        if (world_sg) {
            walk_and_dump_scene(world_sg, /*max_depth=*/5);
        }
    }

    // M2.2: after the walk has captured a first_bstri_shape (for M2.3),
    // allocate + attach a BSDynamicTriShape with NO geometry. The object
    // will be walked by the render pass; empty vertex buffer means it
    // draws nothing.
    //
    // Position: read the latest REMOTE player snapshot (the other client,
    // pushed via POS_BROADCAST from the net thread) and spawn the cube
    // 500 units above THEIR head. The local player (Client A) running
    // this DLL will then see the cube floating above the remote (Client B).
    //
    // This is the end-to-end "ghost marker" test: if the cube renders
    // visibly tracking the remote's world position at the moment of
    // inject, Strada B is proven for the eventual full ghost body.
    //
    // Fallback order for cube position:
    //   1. Remote Client snapshot (preferred — proves network→scene flow)
    //   2. Local player pos (visible from our own POV for solo testing)
    //   3. Origin (last resort — cube invisible but at least injected)
    const auto snap = fw::net::client().get_remote_snapshot();
    float body_x = 0.0f, body_y = 0.0f, body_z = 0.0f;
    // M5: no Z offset — the NIF-loaded body spawns at the remote's
    // feet position directly (MaleBody.nif is modeled with its origin
    // at the feet, matching engine skeleton convention). The previous
    // +300 offset was a cube-specific hack to lift the visible marker
    // above the body so we could see it; now the ghost body IS the
    // body, so it goes exactly where the remote player is.
    constexpr float kBodyZOffset = 0.0f;

    if (snap.has_state) {
        body_x = snap.pos[0];
        body_y = snap.pos[1];
        body_z = snap.pos[2] + kBodyZOffset;
        FW_LOG("[native] body spawn pos from REMOTE snapshot (peer=%s): "
               "remote_pos=(%.1f,%.1f,%.1f)  body_pos=(%.1f,%.1f,%.1f)",
               snap.peer_id.c_str(),
               snap.pos[0], snap.pos[1], snap.pos[2],
               body_x, body_y, body_z);
    } else if (game) {
        const auto base = reinterpret_cast<std::uintptr_t>(game);
        void** player_slot = reinterpret_cast<void**>(base + 0x032D2260);
        void* player = *player_slot;
        if (player) {
            const float* player_pos =
                reinterpret_cast<const float*>(
                    reinterpret_cast<char*>(player) + 0xD0);
            body_x = player_pos[0];
            body_y = player_pos[1];
            body_z = player_pos[2] + kBodyZOffset;
            FW_LOG("[native] body spawn pos from LOCAL player (no remote snap yet): "
                   "local_pos=(%.1f,%.1f,%.1f) body_pos=(%.1f,%.1f,%.1f) — "
                   "ghost body will overlap local player (test mode)",
                   player_pos[0], player_pos[1], player_pos[2],
                   body_x, body_y, body_z);
        } else {
            FW_WRN("[native] player singleton null and no remote snap — "
                   "spawning body at origin as last-resort fallback");
        }
    } else {
        FW_WRN("[native] no Fallout4.exe module and no remote snap — "
               "spawning body at origin");
    }

    if (inject_debug_cube(body_x, body_y, body_z)) {
        FW_LOG("[native] M5 BODY via NIF loader: success — MaleBody.nif "
               "attached to SSN at remote player position. T-pose until "
               "M4 wires up animation driver.");
    } else {
        FW_WRN("[native] M5 BODY via NIF loader: failed");
    }
}

// Called from DLL_PROCESS_DETACH. Stops arm worker (no-op if not started
// or already fired), detaches all injected objects. Idempotent.
void shutdown() {
    g_arm_stop.store(true, std::memory_order_release);
    if (g_arm_thread.joinable()) {
        g_arm_thread.join();
    }
    // Stop bone-tick worker (M7.b).
    g_bone_tick_stop.store(true, std::memory_order_release);
    if (g_bone_tick_thread.joinable()) {
        g_bone_tick_thread.join();
    }
    // Cancel any in-flight synthetic-REFR assembly jobs (M9 closure).
    // Must precede detach_debug_cube — pending callbacks would try to
    // attach to the ghost which is about to be torn down.
    synthetic_refr::shutdown();
    detach_debug_cube();   // M2.2 — detach cube first (no dependencies)
    detach_debug_node();   // M1   — detach canary NiNode
}

} // namespace fw::native
