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
    void**           res_mgr_slot      = nullptr; // qword_1430DD618 — diagnostic only

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
    g_r.res_mgr_slot          = reinterpret_cast<void**>          (base + NIF_LOAD_RESMGR_SLOT_RVA);

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

        FW_LOG("[native] inject_body_nif: calling nif_load_by_path "
               "path='%s' out=%p opts=%p opts.flags=0x%02X "
               "(killswitch was=%u forced=1)",
               kBodyPath, static_cast<void*>(&body),
               static_cast<void*>(&opts),
               static_cast<unsigned>(opts.flags),
               saved_ks);
        const std::uint32_t rc = g_r.nif_load_by_path(
            kBodyPath, &body, &opts);
        FW_LOG("[native] inject_body_nif: loader returned rc=%u body=%p "
               "(rc=0 + body!=null = success)",
               rc, body);

        // Restore killswitch — never leave the byte mutated across
        // the call (avoids side-effects on vanilla texture loads
        // happening concurrently on the render thread).
        *killswitch = saved_ks;

        if (rc != 0 || !body) {
            FW_ERR("[native] inject_body_nif: load failed — missing BA2, "
                   "wrong path, or corrupted mesh. rc=%u body=%p", rc, body);
            return false;
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

        // M9 wedge 2: drain any equip events that arrived while the
        // ghost wasn't yet ready (boot-time race with peer's B8
        // force-equip-cycle). With g_injected_cube now non-null, the
        // replayed ghost_attach_armor calls will succeed.
        flush_pending_armor_ops();
    } else {
        FW_WRN("[native] inject_cube (M5 body): failed — see preceding log");
    }
    return ok;
}

void detach_debug_cube() {
    void* cube = g_injected_cube.exchange(nullptr, std::memory_order_acq_rel);
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
// Returns true if `path` looks like a FEMALE armor NIF path (e.g. ends
// in "_F.nif", contains "Female", contains "_f." mid-path). Used by
// resolve_armor_nif_path to deprioritize female variants.
bool path_is_female_variant(const char* path, std::size_t len) {
    if (!path || len == 0) return false;
    // Case-insensitive check against common female markers.
    return seh_path_contains_ci(path, len, "female") ||
           seh_path_contains_ci(path, len, "_f.nif") ||
           seh_path_contains_ci(path, len, "_f.tri");
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
// Compute selection score for an armor NIF path. Higher = better.
// We want: MALE 3rd-person → +0
//          MALE 1st-person → -5  (visible only as arms when attached
//                                  to a 3rd-person ghost body)
//          FEMALE 3rd-person → -10 (wrong gender bones, T-pose risk)
//          FEMALE 1st-person → -15 (worst of both)
int armor_path_score(const char* path, std::size_t len) {
    int score = 0;
    if (path_is_female_variant(path, len)) score -= 10;
    if (path_is_first_person(path, len))  score -= 5;
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
const char* resolve_armor_nif_path(std::uint32_t item_form_id) {
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

    // 3. Walk addons. For each ARMA, probe multiple candidate offsets
    // for the TESModel(male 3rd) — the exact layout in FO4 1.11.191
    // next-gen wasn't pinned by the dossier (initial guess 0xD0 was
    // wrong per live test 2026-04-29). Probe in order of likelihood
    // based on TESObjectARMA component layout patterns.
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

bool ghost_attach_armor(const char* peer_id, std::uint32_t item_form_id) {
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

    const char* path = resolve_armor_nif_path(item_form_id);
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
    void* armor_node = nullptr;
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

    const std::uint32_t rc = seh_nif_load_armor(g_r.nif_load_by_path,
                                                  path, &armor_node, &opts);
    if (rc == 0xDEADBEEFu) {
        *killswitch_byte = saved_ks;
        FW_ERR("[armor-attach] SEH in nif_load_by_path('%s')", path);
        return false;
    }
    if (rc != 0 || !armor_node) {
        *killswitch_byte = saved_ks;
        FW_ERR("[armor-attach] nif_load_by_path('%s') failed rc=%u node=%p",
               path, rc, armor_node);
        return false;
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
    detach_debug_cube();   // M2.2 — detach cube first (no dependencies)
    detach_debug_node();   // M1   — detach canary NiNode
}

} // namespace fw::native
