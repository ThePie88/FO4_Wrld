#include "anatomy_mirror.h"

#include "../render/present_hook.h"

#include <windows.h>
#include <d3d11.h>

#include <atomic>
#include <cstdio>
#include <cstring>

#include "../log.h"
#include "ni_offsets.h"

namespace fw::native::anatomy_mirror {

namespace {

std::atomic<bool> g_on{false};
std::atomic<bool> g_clone{false};
std::vector<Part> g_parts;

// Engine constants. Duplicated from chargen_dump on purpose: that module is
// a capture tool gated on its own config key and can disappear or change
// shape freely; this one is (aimed at) shipping. The values are the same
// 2026-08-06 RE pass either way.
constexpr std::uintptr_t DATAHANDLER_RVA     = 0x030DC000;
constexpr std::size_t    DH_ARRAYS_OFF       = 0x68;
constexpr std::size_t    DH_ARRAY_STRIDE     = 0x18;
constexpr std::uint8_t   FORMTYPE_HDPT       = 15;
constexpr std::size_t    FORM_ID_OFF         = 0x14;
constexpr std::size_t    HDPT_MODEL          = 0x38;
constexpr std::size_t    HDPT_PNAM           = 0x74;
constexpr std::size_t    HDPT_EDITORID       = 0x170;
constexpr std::uintptr_t BSFIXEDSTR_CSTR_RVA = 0x0167C070;
constexpr std::uintptr_t FACEGEN_NODE_VT_RVA = 0x024FF280;  // BSFaceGenNiNodeSkinned

using CStrFn = const char*(__fastcall*)(const void*);

// --- POD SEH helpers (no C++ objects in scope: C2712) ----------------------

void* seh_ptr(const void* addr) noexcept {
    if (!addr) return nullptr;
    __try { return *reinterpret_cast<void* const*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

std::uint32_t seh_u32(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint16_t seh_u16(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint16_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint64_t seh_u64(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint64_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

bool seh_copy_str(const char* src, char* dst, std::size_t n) noexcept {
    if (!src || !dst || n == 0) return false;
    __try {
        std::size_t i = 0;
        for (; i + 1 < n && src[i]; ++i) dst[i] = src[i];
        dst[i] = 0;
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { dst[0] = 0; return false; }
}

// NiObjectNET name: BSStringPool entry, chars at +0x18.
bool read_node_name(const void* node, char* dst, std::size_t n) noexcept {
    void* h = seh_ptr(reinterpret_cast<const std::uint8_t*>(node)
                      + NIAV_NAME_OFF);
    if (!h) { if (n) dst[0] = 0; return false; }
    return seh_copy_str(reinterpret_cast<const char*>(h) + 0x18, dst, n);
}

// BSFixedString field via the engine's own c_str (handles wide/narrow).
bool read_bsfixed(CStrFn cstr, const void* field, char* dst,
                  std::size_t n) noexcept {
    if (!cstr) return false;
    __try {
        if (!*reinterpret_cast<void* const*>(field)) {
            if (n) dst[0] = 0;
            return false;
        }
        return seh_copy_str(cstr(field), dst, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) { if (n) dst[0] = 0; return false; }
}

// The third-person tree — the ONLY one with a face. The probe measured this:
// REFR_LOADED_3D (+0xB78) is the first-person tree and carries no face node,
// so it is deliberately not used here.
void* player_3p_root(std::uintptr_t base) noexcept {
    void* player = seh_ptr(reinterpret_cast<void*>(base + PLAYER_SINGLETON_RVA));
    if (!player) return nullptr;
    void* f0 = seh_ptr(reinterpret_cast<std::uint8_t*>(player) + 0xF0);
    if (!f0) return nullptr;
    return seh_ptr(reinterpret_cast<std::uint8_t*>(f0) + 0x08);
}

// Find the facegen node among the root's direct children (probe: depth 1).
// One level of nesting is tolerated in case an outfit wraps it.
void* find_facegen_node(void* root, std::uintptr_t base, int depth) noexcept {
    if (!root || depth > 2) return nullptr;
    void* vt = seh_ptr(root);
    if (vt && reinterpret_cast<std::uintptr_t>(vt) > base &&
        reinterpret_cast<std::uintptr_t>(vt) - base == FACEGEN_NODE_VT_RVA) {
        return root;
    }
    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(root) + NINODE_CHILDREN_CNT_OFF);
    if (cnt == 0 || cnt > 256) return nullptr;
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(root) + NINODE_CHILDREN_PTR_OFF));
    if (!children) return nullptr;
    const auto cp = reinterpret_cast<std::uintptr_t>(children);
    if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return nullptr;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = seh_ptr(children + i);
        if (!child) continue;
        if (void* hit = find_facegen_node(child, base, depth + 1)) return hit;
    }
    return nullptr;
}

// Linear scan of the HDPT form array for an editor id. 420 forms; called a
// dozen times per collect. Case-insensitive because the catalogue showed the
// engine is not consistent about path casing and there is no reason to trust
// edid casing more.
void* find_hdpt_by_edid(std::uintptr_t base, CStrFn cstr,
                        const char* edid) noexcept {
    auto* dh = reinterpret_cast<std::uint8_t*>(
        seh_ptr(reinterpret_cast<void*>(base + DATAHANDLER_RVA)));
    if (!dh) return nullptr;
    auto* arr = dh + DH_ARRAYS_OFF + DH_ARRAY_STRIDE * FORMTYPE_HDPT;
    void** data = reinterpret_cast<void**>(seh_ptr(arr));
    const std::uint32_t size = seh_u32(arr + 0x10);
    if (!data || size == 0 || size > 200000) return nullptr;
    for (std::uint32_t i = 0; i < size; ++i) {
        void* form = seh_ptr(data + i);
        if (!form) continue;
        char fe[128];
        if (!read_bsfixed(cstr, reinterpret_cast<std::uint8_t*>(form)
                                    + HDPT_EDITORID, fe, sizeof(fe))) {
            continue;
        }
        if (_stricmp(fe, edid) == 0) return form;
    }
    return nullptr;
}

}  // namespace

void init(bool enabled_, bool clone_) {
    g_clone.store(clone_, std::memory_order_relaxed);
    // The clone supersedes the mirror: it produces the same parts PLUS the
    // morphs, the composited face texture and the real hair colour. Running
    // both would render two faces in the same place.
    g_on.store(enabled_ && !clone_, std::memory_order_relaxed);

    if (clone_) {
        FW_LOG("[face-clone] ARMED — the ghost gets a CLONE of the player's "
               "built BSFaceGenNiNodeSkinned subtree (morphs baked in the "
               "dynamic vertex buffers, composited texture and hair colour "
               "come along). Supersedes the mirror.");
        if (enabled_) {
            FW_WRN("[face-clone] anatomy_mirror was also set — ignoring it, "
                   "the two would render two faces on one head");
        }
    } else if (enabled_) {
        FW_LOG("[anatomy-mirror] ARMED — at ghost inject the head parts are "
               "read off the local player and mirrored (parts, not morphs)");
    }
}

bool enabled() noexcept {
    return g_on.load(std::memory_order_relaxed);
}

bool clone_enabled() noexcept {
    return g_clone.load(std::memory_order_relaxed);
}

void* find_facegen_node(std::uintptr_t module_base, void* player_root) noexcept {
    if (!module_base || !player_root) return nullptr;
    return find_facegen_node(player_root, module_base, 0);
}

void* player_face_node(std::uintptr_t module_base) noexcept {
    if (!module_base) return nullptr;
    void* root = player_3p_root(module_base);
    if (!root) return nullptr;
    return find_facegen_node(root, module_base, 0);
}

std::size_t collect(std::uintptr_t module_base) {
    g_parts.clear();
    if (!module_base) return 0;

    void* root = player_3p_root(module_base);
    if (!root) {
        FW_WRN("[anatomy-mirror] collect: player 3P root not readable — "
               "ghost keeps the default head");
        return 0;
    }
    void* facegen = find_facegen_node(root, module_base, 0);
    if (!facegen) {
        FW_WRN("[anatomy-mirror] collect: no BSFaceGenNiNodeSkinned under "
               "player 3P root %p — ghost keeps the default head", root);
        return 0;
    }

    const auto cstr = reinterpret_cast<CStrFn>(module_base
                                               + BSFIXEDSTR_CSTR_RVA);

    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(facegen) + NINODE_CHILDREN_CNT_OFF);
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(facegen) + NINODE_CHILDREN_PTR_OFF));
    if (!children || cnt == 0 || cnt > 64) {
        FW_WRN("[anatomy-mirror] collect: facegen node %p has no readable "
               "children (cnt=%u)", facegen, cnt);
        return 0;
    }

    int unresolved = 0;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = seh_ptr(children + i);
        if (!child) continue;
        char name[128];
        if (!read_node_name(child, name, sizeof(name)) || !name[0]) continue;

        // Hidden on the player -> not mirrored. First live test put a ring
        // of gore around the ghost's neck: MaleNeckGore, the decapitation
        // meatcap, present in every face. APP_CULLED on the player's node
        // turned out NOT to be how the engine hides it (the second run
        // proved the flag clear — logged below for the record), so the flag
        // is only advisory here; the meatcap class is excluded by TYPE in
        // the attach loop instead (pnam 7, data straight from the form).
        const std::uint64_t flags = seh_u64(
            reinterpret_cast<std::uint8_t*>(child) + NIAV_FLAGS_OFF);
        if (flags & NIAV_FLAG_APP_CULLED) {
            FW_LOG("[anatomy-mirror] collect: '%s' is APP_CULLED on the "
                   "player — skipped", name);
            continue;
        }

        void* form = find_hdpt_by_edid(module_base, cstr, name);
        if (!form) {
            // Not an error by itself — a mod part or decorative shape may
            // not be a head-part form. Count and report so a systematically
            // broken resolve is visible instead of a silently bald ghost.
            FW_LOG("[anatomy-mirror] collect: node '%s' matches no head-part "
                   "editor id — skipped", name);
            ++unresolved;
            continue;
        }
        auto* f = reinterpret_cast<std::uint8_t*>(form);
        char path[320];
        if (!read_bsfixed(cstr, f + HDPT_MODEL, path, sizeof(path)) ||
            !path[0]) {
            FW_LOG("[anatomy-mirror] collect: '%s' resolved but has no model "
                   "path — skipped", name);
            ++unresolved;
            continue;
        }
        Part p;
        p.edid     = name;
        p.path     = path;
        p.pnam     = seh_u32(f + HDPT_PNAM);
        p.form_id  = seh_u32(f + FORM_ID_OFF);
        p.src_node = child;   // the live shape — the tint pass reads its material
        g_parts.push_back(std::move(p));
    }

    FW_LOG("[anatomy-mirror] collect: %zu part(s) resolved off the player "
           "(%d node(s) unresolved) — facegen=%p", g_parts.size(),
           unresolved, facegen);
    for (const auto& p : g_parts) {
        FW_LOG("[anatomy-mirror]   pnam=%u id=0x%08X %s -> %s",
               p.pnam, p.form_id, p.edid.c_str(), p.path.c_str());
    }
    return g_parts.size();
}

const std::vector<Part>& parts() noexcept {
    return g_parts;
}

std::vector<Part>& parts_mut() noexcept {
    return g_parts;
}

// ===========================================================================
// The colour pass. Layouts in the header comment; every constant below was
// read out of the ctors, not guessed.
// ===========================================================================

namespace {

constexpr std::size_t    GEOM_SHADER_OFF   = 0x138;  // NiPointer<BSShaderProperty>
constexpr std::size_t    SHADER_MATERIAL_OFF = 0x58;
constexpr std::size_t    MAT_PAYLOAD_OFF   = 0xC0;
constexpr std::uintptr_t MAT_VT_SKIN_TINT  = 0x0290A190;
constexpr std::uintptr_t MAT_VT_HAIR_TINT  = 0x0290A228;
constexpr std::uintptr_t MAT_VT_FACE       = 0x0290A0F8;
constexpr std::uintptr_t MAT_VT_GLOWMAP    = 0x02909E98;  // the MAIN hair uses this

bool plausible(const void* p) noexcept {
    const auto v = reinterpret_cast<std::uintptr_t>(p);
    return v > 0x10000 && v < 0x00007FFFFFFFFFFFULL;
}

// geometry -> its shader material, or null.
void* geom_material(void* geom) noexcept {
    void* shader = seh_ptr(reinterpret_cast<std::uint8_t*>(geom)
                           + GEOM_SHADER_OFF);
    if (!plausible(shader)) return nullptr;
    void* mat = seh_ptr(reinterpret_cast<std::uint8_t*>(shader)
                        + SHADER_MATERIAL_OFF);
    return plausible(mat) ? mat : nullptr;
}

std::uintptr_t obj_vt_rva(std::uintptr_t base, void* obj) noexcept {
    void* vt = seh_ptr(obj);
    const auto v = reinterpret_cast<std::uintptr_t>(vt);
    return (v > base) ? v - base : 0;
}

bool seh_memcpy(void* dst, const void* src, std::size_t n) noexcept {
    __try { std::memcpy(dst, src, n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Copy one refcounted pointer slot (NiPointer<NiTexture> / texture set)
// from src material to dst material at the same offset. Increments the new
// object's refcount before publishing. The old pointer is deliberately NOT
// released — the defaults are process-lifetime singletons and one leaked
// reference on a per-session material is the safe side of a double-free.
bool seh_copy_ref_slot(void* dst_mat, const void* src_mat,
                       std::size_t off) noexcept {
    __try {
        void* obj = *reinterpret_cast<void* const*>(
            reinterpret_cast<const std::uint8_t*>(src_mat) + off);
        const auto v = reinterpret_cast<std::uintptr_t>(obj);
        if (v < 0x10000 || v > 0x00007FFFFFFFFFFFULL) return false;
        _InterlockedIncrement(reinterpret_cast<long*>(
            reinterpret_cast<std::uint8_t*>(obj) + 0x08));
        *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(dst_mat) + off) = obj;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Apply one source material's payload to one target material, classes
// already verified equal by the caller.
bool apply_payload(std::uintptr_t cls, void* src_mat, void* dst_mat) noexcept {
    auto* s = reinterpret_cast<std::uint8_t*>(src_mat) + MAT_PAYLOAD_OFF;
    auto* d = reinterpret_cast<std::uint8_t*>(dst_mat) + MAT_PAYLOAD_OFF;
    if (cls == MAT_VT_SKIN_TINT) return seh_memcpy(d, s, 16);
    if (cls == MAT_VT_HAIR_TINT) return seh_memcpy(d, s, 12);
    if (cls == MAT_VT_FACE || cls == MAT_VT_GLOWMAP) {
        // Both classes have the same shape: base material + one refcounted
        // texture pointer at +0xC0 (Face ctor 0x1421C9780, Glowmap ctor
        // 0x1421C8640 — identical lock-inc pattern).
        //
        // Face taught the lesson: copying only +0xC0 changed nothing,
        // because the RENDERED textures are the resolved NiTexture pointers
        // in the BASE material — four refcounted slots at +0x48/+0x50/
        // +0x58/+0x60 (ctor sub_1421C5CE0) plus the texture-set pointer at
        // +0x68. Sharing all of them gave the ghost the player's FaceGen
        // composited face, confirmed on screen. Glowmap (the main hair)
        // gets the same full-share treatment, plus the base colour at
        // +0x38 — the one field a hair colour can live in for a class
        // whose subclass payload is just a texture.
        int copied = 0;
        static constexpr std::size_t kRefSlots[] =
            { 0x48, 0x50, 0x58, 0x60, 0x68, MAT_PAYLOAD_OFF };
        for (const std::size_t off : kRefSlots) {
            if (seh_copy_ref_slot(dst_mat, src_mat, off)) ++copied;
        }
        if (cls == MAT_VT_GLOWMAP) {
            auto* sc = reinterpret_cast<std::uint8_t*>(src_mat) + 0x38;
            auto* dc = reinterpret_cast<std::uint8_t*>(dst_mat) + 0x38;
            if (seh_memcpy(dc, sc, 12)) ++copied;
        }
        return copied > 0;
    }
    return false;
}

// Recursive: apply `src_mat` (class `cls`) to every geometry under `node`
// whose material has the same class. Returns number patched.
int apply_to_subtree(std::uintptr_t base, void* node, std::uintptr_t cls,
                     void* src_mat, int depth) noexcept {
    if (!node || depth > 8) return 0;
    int patched = 0;

    void* mat = geom_material(node);
    if (mat && obj_vt_rva(base, mat) == cls &&
        apply_payload(cls, src_mat, mat)) {
        ++patched;
    }

    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_CNT_OFF);
    if (cnt == 0 || cnt > 256) return patched;
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_PTR_OFF));
    if (!children) return patched;
    const auto cp = reinterpret_cast<std::uintptr_t>(children);
    if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return patched;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = seh_ptr(children + i);
        if (child) patched += apply_to_subtree(base, child, cls, src_mat,
                                               depth + 1);
    }
    return patched;
}

// Forensic: log every material class in a subtree (budgeted). This replaces
// a broken first version that searched for "class 0" and always printed 0.
void log_material_classes(std::uintptr_t base, void* node, const char* tag,
                          int depth, int* budget) noexcept {
    if (!node || depth > 8 || *budget <= 0) return;
    void* mat = geom_material(node);
    if (mat) {
        FW_LOG("[anatomy-mirror] tints:   %s geom=%p mat_vt=0x%llX", tag,
               node, static_cast<unsigned long long>(obj_vt_rva(base, mat)));
        --(*budget);
    }
    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_CNT_OFF);
    if (cnt == 0 || cnt > 256) return;
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_PTR_OFF));
    if (!children) return;
    const auto cp = reinterpret_cast<std::uintptr_t>(children);
    if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return;
    for (std::uint16_t i = 0; i < cnt && *budget > 0; ++i) {
        void* child = seh_ptr(children + i);
        if (child) log_material_classes(base, child, tag, depth + 1, budget);
    }
}

// Copy the BASE-class colour (NiColor at +0x38, 12 bytes — present in every
// BSLightingShaderMaterialBase subclass; ctor sub_1421C5CE0 fills it from
// the same default constants as HairTint's own colour) onto every material
// in a subtree, regardless of subclass. Used for the main hair only: its
// player-side material is Glowmap, the ghost side is neither Glowmap nor
// HairTint, and this shared field is the one place a colour can cross that
// class gap.
constexpr std::size_t MAT_BASE_COLOR_OFF = 0x38;

int apply_base_color_to_subtree(std::uintptr_t base, void* node,
                                void* src_mat, int depth) noexcept {
    if (!node || depth > 8) return 0;
    int patched = 0;
    void* mat = geom_material(node);
    if (mat) {
        auto* s = reinterpret_cast<std::uint8_t*>(src_mat)
                  + MAT_BASE_COLOR_OFF;
        auto* d = reinterpret_cast<std::uint8_t*>(mat) + MAT_BASE_COLOR_OFF;
        if (seh_memcpy(d, s, 12)) ++patched;
    }
    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_CNT_OFF);
    if (cnt == 0 || cnt > 256) return patched;
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_PTR_OFF));
    if (!children) return patched;
    const auto cp = reinterpret_cast<std::uintptr_t>(children);
    if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return patched;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = seh_ptr(children + i);
        if (child) patched += apply_base_color_to_subtree(base, child,
                                                          src_mat, depth + 1);
    }
    return patched;
}

// Find the first material of class `cls` anywhere under `node`.
void* find_material_of_class(std::uintptr_t base, void* node,
                             std::uintptr_t cls, int depth) noexcept {
    if (!node || depth > 8) return nullptr;
    void* mat = geom_material(node);
    if (mat && obj_vt_rva(base, mat) == cls) return mat;

    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_CNT_OFF);
    if (cnt == 0 || cnt > 256) return nullptr;
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_PTR_OFF));
    if (!children) return nullptr;
    const auto cp = reinterpret_cast<std::uintptr_t>(children);
    if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return nullptr;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = seh_ptr(children + i);
        if (!child) continue;
        if (void* hit = find_material_of_class(base, child, cls, depth + 1)) {
            return hit;
        }
    }
    return nullptr;
}

}  // namespace

// ---------------------------------------------------------------- composites
//
// Offsets and function facts below are from the 2026-08-11 decomp sweep, every
// one cross-verified from an independent call site. See own_face_composite's
// header comment for the mechanism they add up to.
constexpr std::size_t MAT_TEX_SLOTS[] = { 0x48, 0x50, 0x60 };  // diffuse/normal/smooth
constexpr std::size_t NITEX_RENDERDATA = 0x38;   // NiTexture -> BSGraphics::Texture*
constexpr std::size_t BSTEX_SIZE       = 0x40;
constexpr std::size_t BSTEX_REFCOUNT   = 0x34;

// One SEH-guarded snapshot of an engine BSGraphics::Texture struct. POD in and
// out, so the COM work can live in a normal C++ function without C2712.
struct BsTexSnap {
    void*        srv = nullptr;
    std::uint8_t meta[BSTEX_SIZE] = {};
};

bool seh_snap_bstex(void* bt, BsTexSnap* out) noexcept {
    __try {
        std::memcpy(out->meta, bt, BSTEX_SIZE);
        out->srv = *reinterpret_cast<void* const*>(bt);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_store_ptr(void* at, void* v) noexcept {
    __try {
        *reinterpret_cast<void**>(at) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Duplicate the D3D texture behind one snapshot and wrap it in a BSGraphics::
// Texture-shaped struct WE own. The engine only ever reads it (the draw path
// walks +0x00 for the SRV, +0x3C for the degrade byte); its release path must
// never run on it, which is what the saturated refcount guarantees.
void* make_composite_snapshot(const BsTexSnap& snap) noexcept {
    const fw::render::GameD3D g = fw::render::game_d3d();
    if (!g.device || !g.context || !snap.srv) return nullptr;
    auto* dev = static_cast<ID3D11Device*>(g.device);
    auto* ctx = static_cast<ID3D11DeviceContext*>(g.context);
    auto* srv = static_cast<ID3D11ShaderResourceView*>(snap.srv);

    ID3D11Resource* res = nullptr;
    srv->GetResource(&res);
    if (!res) return nullptr;
    ID3D11Texture2D* tex = nullptr;
    res->QueryInterface(__uuidof(ID3D11Texture2D),
                        reinterpret_cast<void**>(&tex));
    res->Release();
    if (!tex) return nullptr;

    D3D11_TEXTURE2D_DESC d{};
    tex->GetDesc(&d);
    // The source is a render target; the copy only ever feeds a shader. Same
    // format and dimensions (CopyResource demands them), plainest possible use.
    d.Usage          = D3D11_USAGE_DEFAULT;
    d.BindFlags      = D3D11_BIND_SHADER_RESOURCE;
    d.CPUAccessFlags = 0;
    d.MiscFlags      = 0;

    ID3D11Texture2D* copy = nullptr;
    if (FAILED(dev->CreateTexture2D(&d, nullptr, &copy)) || !copy) {
        tex->Release();
        return nullptr;
    }
    ctx->CopyResource(copy, tex);
    tex->Release();

    // The view mirrors the source view, not a guess from the resource: pool
    // targets may be typeless with a typed view, and the view is what decides.
    D3D11_SHADER_RESOURCE_VIEW_DESC sd{};
    srv->GetDesc(&sd);
    ID3D11ShaderResourceView* csrv = nullptr;
    if (FAILED(dev->CreateShaderResourceView(copy, &sd, &csrv)) || !csrv) {
        copy->Release();
        return nullptr;
    }

    auto* bt = static_cast<std::uint8_t*>(std::calloc(1, BSTEX_SIZE));
    if (!bt) {
        csrv->Release();
        copy->Release();
        return nullptr;
    }
    std::memcpy(bt, snap.meta, BSTEX_SIZE);   // dims, format, sampler byte
    *reinterpret_cast<void**>(bt + 0x00) = csrv;
    *reinterpret_cast<void**>(bt + 0x08) = copy;
    *reinterpret_cast<void**>(bt + 0x10) = nullptr;   // no UAV on a snapshot
    // Saturated: the engine's Release decrements and destroys at zero, through
    // ITS pool allocator. This struct is from OUR heap, so that must never run.
    *reinterpret_cast<std::uint32_t*>(bt + BSTEX_REFCOUNT) = 0x40000000u;
    return bt;
}

int own_face_composite_walk(std::uintptr_t base, void* node, int depth,
                            void** seen, int* n_seen) noexcept {
    if (!node || depth > 8) return 0;
    int swapped = 0;

    void* mat = geom_material(node);
    if (mat && obj_vt_rva(base, mat) == MAT_VT_FACE) {
        for (const std::size_t off : MAT_TEX_SLOTS) {
            void* wrapper = seh_ptr(reinterpret_cast<std::uint8_t*>(mat) + off);
            if (!plausible(wrapper)) continue;
            bool dup = false;
            for (int i = 0; i < *n_seen; ++i) {
                if (seen[i] == wrapper) { dup = true; break; }
            }
            if (dup) continue;
            if (*n_seen < 16) seen[(*n_seen)++] = wrapper;

            auto* rd_at = reinterpret_cast<std::uint8_t*>(wrapper)
                        + NITEX_RENDERDATA;
            void* bstex = seh_ptr(rd_at);
            if (!plausible(bstex)) continue;

            BsTexSnap snap;
            if (!seh_snap_bstex(bstex, &snap)) continue;
            void* mine = make_composite_snapshot(snap);
            if (!mine) {
                FW_WRN("[face-own] slot +0x%02zX: snapshot failed (srv=%p) — "
                       "this wrapper keeps watching the shared canvas", off,
                       snap.srv);
                continue;
            }
            if (seh_store_ptr(rd_at, mine)) {
                ++swapped;
                FW_LOG("[face-own] slot +0x%02zX: wrapper %p rendererData "
                       "%p -> %p (private snapshot)", off, wrapper, bstex,
                       mine);
            }
        }
    }

    const std::uint16_t cnt = seh_u16(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_CNT_OFF);
    if (cnt == 0 || cnt > 256) return swapped;
    void** children = reinterpret_cast<void**>(seh_ptr(
        reinterpret_cast<std::uint8_t*>(node) + NINODE_CHILDREN_PTR_OFF));
    if (!children) return swapped;
    const auto cp = reinterpret_cast<std::uintptr_t>(children);
    if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return swapped;
    for (std::uint16_t i = 0; i < cnt; ++i) {
        void* child = seh_ptr(children + i);
        if (child) swapped += own_face_composite_walk(base, child, depth + 1,
                                                      seen, n_seen);
    }
    return swapped;
}

// Both engine halves, lifted from its update sites (sub_1406E00A0 and
// sub_1406E2EB0 use exactly this sequence):
//   float4 = 0; sub_1406555D0(npc, &float4, 0, 1); sub_1406EED30(root, &float4);
constexpr std::uintptr_t COMPUTE_SKIN_RVA = 0x006555D0;
constexpr std::uintptr_t PAINT_WALK_RVA   = 0x006EED30;
using ComputeSkinFn = void(__fastcall*)(void*, float*, int, int);
using PaintWalkFn   = void(__fastcall*)(void*, float*);

// The stashed peer skin. Main-thread only at both sites (the borrow tick and
// the inject dispatch), so plain storage with an atomic validity flag is enough.
float             g_ghost_skin[4] = {0.0f, 0.0f, 0.0f, 0.0f};
std::atomic<bool> g_ghost_skin_valid{false};

bool paint_skin(std::uintptr_t module_base, void* subtree_root,
                float col[4]) noexcept {
    if (!module_base || !subtree_root) return false;
    auto paint = reinterpret_cast<PaintWalkFn>(module_base + PAINT_WALK_RVA);
    __try {
        paint(subtree_root, col);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[skin-tone] engine skin PAINT faulted — the subtree keeps "
               "whatever colour it had");
        return false;
    }
}

bool compute_skin_from_npc(std::uintptr_t module_base, void* npc,
                           float out_col[4]) {
    if (!module_base || !npc || !out_col) return false;
    auto compute = reinterpret_cast<ComputeSkinFn>(module_base
                                                   + COMPUTE_SKIN_RVA);
    out_col[0] = out_col[1] = out_col[2] = out_col[3] = 0.0f;
    __try {
        compute(npc, out_col, 0, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[skin-tone] engine skin COMPUTE faulted");
        return false;
    }
}

bool paint_skin_from_npc(std::uintptr_t module_base, void* npc,
                         void* subtree_root) {
    float col[4];
    if (!compute_skin_from_npc(module_base, npc, col)) return false;
    if (!paint_skin(module_base, subtree_root, col)) return false;
    FW_LOG("[skin-tone] engine-computed skin (%.3f, %.3f, %.3f, %.3f) painted "
           "onto subtree %p", col[0], col[1], col[2], col[3], subtree_root);
    return true;
}

void stash_ghost_skin(const float col[4]) {
    std::memcpy(g_ghost_skin, col, sizeof(g_ghost_skin));
    g_ghost_skin_valid.store(true, std::memory_order_release);
    FW_LOG("[skin-tone] peer skin (%.3f, %.3f, %.3f, %.3f) stashed for "
           "whenever the ghost body exists", col[0], col[1], col[2], col[3]);
}

bool paint_stashed_ghost_skin(std::uintptr_t module_base, void* subtree_root) {
    if (!g_ghost_skin_valid.load(std::memory_order_acquire)) return false;
    if (!paint_skin(module_base, subtree_root, g_ghost_skin)) return false;
    FW_LOG("[skin-tone] stashed peer skin (%.3f, %.3f, %.3f, %.3f) painted "
           "onto the injected body %p — overrides the local copy",
           g_ghost_skin[0], g_ghost_skin[1], g_ghost_skin[2], g_ghost_skin[3],
           subtree_root);
    return true;
}

int own_face_composite(std::uintptr_t module_base, void* clone_root) {
    if (!module_base || !clone_root) return 0;
    void* seen[16] = {};
    int n_seen = 0;
    const int n = own_face_composite_walk(module_base, clone_root, 0,
                                          seen, &n_seen);
    if (n == 0) {
        FW_WRN("[face-own] no Face-material wrappers found under %p — the "
               "clone's complexion will follow the local player's rebuilds",
               clone_root);
    } else {
        FW_LOG("[face-own] %d composited texture(s) now privately owned by "
               "the clone at %p — local head rebuilds can no longer repaint "
               "it", n, clone_root);
    }
    return n;
}

int copy_skin_tone(std::uintptr_t module_base, void* ghost_body) {
    if (!module_base || !ghost_body) return 0;
    void* player_root = player_3p_root(module_base);
    if (!player_root) {
        FW_WRN("[skin-tone] player 3P root unreadable — ghost keeps the stock "
               "skin");
        return 0;
    }
    void* src = find_material_of_class(module_base, player_root,
                                       MAT_VT_SKIN_TINT, 0);
    if (!src) {
        FW_WRN("[skin-tone] no SkinTint material found on the player — skin "
               "tone not copied");
        return 0;
    }
    const int n = apply_to_subtree(module_base, ghost_body, MAT_VT_SKIN_TINT,
                                   src, 0);
    FW_LOG("[skin-tone] player SkinTint at %p -> %d ghost material(s) "
           "recoloured (body and hands)", src, n);
    return n;
}

void copy_tints(std::uintptr_t module_base, void* ghost_body,
                void* ghost_head) {
    if (!g_on.load(std::memory_order_relaxed) || !module_base) return;

    void* player_root = player_3p_root(module_base);
    if (!player_root) {
        FW_WRN("[anatomy-mirror] tints: player root unreadable — skipped");
        return;
    }

    // 1. Per-part copies: each mirrored part knows its live source shape.
    int part_hits = 0;
    for (const auto& p : g_parts) {
        if (!p.src_node || !p.dst_node) continue;
        void* src_mat = geom_material(p.src_node);
        if (!src_mat) {
            FW_LOG("[anatomy-mirror] tints: '%s' source has no material",
                   p.edid.c_str());
            continue;
        }
        const std::uintptr_t cls = obj_vt_rva(module_base, src_mat);
        const int n = apply_to_subtree(module_base, p.dst_node, cls,
                                       src_mat, 0);
        part_hits += n;
        FW_LOG("[anatomy-mirror] tints: '%s' src_mat_vt=0x%llX -> %d "
               "geometr%s patched", p.edid.c_str(),
               static_cast<unsigned long long>(cls), n, n == 1 ? "y" : "ies");
        if (n == 0) {
            // Class mismatch — enumerate what the ghost side actually
            // carries, so the log alone answers "why did this part stay
            // stock". (The first version of this diagnostic searched for
            // class 0 and always printed 0 — useless.)
            int budget = 4;
            log_material_classes(module_base, p.dst_node, p.edid.c_str(), 0,
                                 &budget);
        }
    }

    // 1b. Hair colour fill. Live measurement: the player's MAIN hair uses
    // the Glowmap material (vt 0x2909E98), not HairTint, so the strict
    // per-part copy above refuses it — correctly, the payloads differ. But
    // the hairline and beard are HairTint on BOTH sides and carry the same
    // chosen colour. Harvest one HairTint source from the player's parts
    // and pour it over every HairTint material under the ghost head, which
    // recolours the main hair when its loaded NIF resolved to HairTint.
    void* hair_src = nullptr;
    const char* hair_src_edid = "";
    for (const auto& p : g_parts) {
        if (!p.src_node) continue;
        void* m = geom_material(p.src_node);
        if (m && obj_vt_rva(module_base, m) == MAT_VT_HAIR_TINT) {
            hair_src = m;
            hair_src_edid = p.edid.c_str();
            break;
        }
    }
    if (hair_src && ghost_head) {
        const int n = apply_to_subtree(module_base, ghost_head,
                                       MAT_VT_HAIR_TINT, hair_src, 0);
        FW_LOG("[anatomy-mirror] tints: HairTint fill from '%s' -> %d "
               "geometr%s under the ghost head", hair_src_edid, n,
               n == 1 ? "y" : "ies");
    }

    // 1c. Main-hair last resort. If the per-part pass (now Glowmap-capable)
    // still patched nothing under the hair part, pour the hairline's
    // HairTint COLOUR into the base-class colour field (+0x38, present in
    // every material) of everything under the ghost hair node. Cross-class
    // by design: it is the only field a colour can cross that gap in.
    for (const auto& p : g_parts) {
        if (p.pnam != 3 || !p.src_node || !p.dst_node) continue;
        void* src_mat = geom_material(p.src_node);
        if (!src_mat) break;
        const std::uintptr_t cls = obj_vt_rva(module_base, src_mat);
        // Only when the exact copy cannot have run: count what it would hit.
        if (apply_to_subtree(module_base, p.dst_node, cls, src_mat, 0) == 0
            && hair_src) {
            const int n = apply_base_color_to_subtree(module_base,
                                                      p.dst_node, hair_src, 0);
            FW_LOG("[anatomy-mirror] tints: hair base-colour fallback from "
                   "'%s' -> %d material(s) under '%s'", hair_src_edid, n,
                   p.edid.c_str());
        }
        break;
    }

    // 2. Skin tone everywhere else. The player's face uses the Face
    // material; the visible SKIN colour of body and hands is SkinTint.
    // Harvest it once from the player and pour it over every SkinTint
    // material the ghost has (body, hands, and any part the per-part pass
    // left untouched because its source was a different class).
    void* skin_src = find_material_of_class(module_base, player_root,
                                            MAT_VT_SKIN_TINT, 0);
    int skin_hits = 0;
    if (skin_src) {
        if (ghost_body) {
            skin_hits += apply_to_subtree(module_base, ghost_body,
                                          MAT_VT_SKIN_TINT, skin_src, 0);
        }
        // ghost_head is a child of ghost_body in the v14 architecture, but
        // both are passed in case that ever changes; apply_to_subtree on the
        // body already covered the head subtree, so only run it separately
        // when the head is NOT under the body.
        (void)ghost_head;
        FW_LOG("[anatomy-mirror] tints: player SkinTint harvested at %p -> "
               "%d ghost geometr%s recoloured", skin_src, skin_hits,
               skin_hits == 1 ? "y" : "ies");
    } else {
        FW_WRN("[anatomy-mirror] tints: no SkinTint material found on the "
               "player — skin tone not copied");
    }

    FW_LOG("[anatomy-mirror] tints: done — %d per-part patch(es), %d skin "
           "patch(es)", part_hits, skin_hits);
}

}  // namespace fw::native::anatomy_mirror
