#include "engine_tracer.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::hooks {

namespace {

// ===== Function pointer typedefs =====
// Must match the arg layouts we already resolved in RE dossiers and
// ni_offsets.h. Each detour uses the same signature.

// sub_1417B3E90 — NIF loader. See re/_check_highlevel.log lines 309-394.
using NifLoadByPathFn = std::uint32_t (__fastcall*)(
    const char* path, void** out_node, void* opts);

// sub_14217A910 — texture load. Signature from M3.3 cube saga
// (texture API dossier). 6 args.
using TexLoadFn = void* (__fastcall*)(
    const char* path,
    char blocking,
    void** out_handle,
    char force_special_default,
    char emissive_or_normal,
    char tls_sampler_flag);

// sub_1421627B0 — BSShaderTextureSet::SetTexturePath (self, slot, path)
// where path is u8* (ANSI). M3.3 cube code used this directly.
using TexSetSetPathFn = void* (__fastcall*)(
    void* self, int slot, const std::uint8_t* path);

// sub_1421C6870 — bind material → texset. 3 args (material, shader_arg2,
// textureSet). Returns void*.
using BindMatTexSetFn = void* (__fastcall*)(
    void* material, void* shader_arg2, void* textureSet);

// sub_142171050 — BSLightingShaderProperty alloc+ctor wrapper. No args.
using BSLSPNewFn = void* (__fastcall*)();

// sub_1421C5CE0 — BSLightingShaderMaterial ctor. 1 arg (self).
using MaterialCtorFn = void* (__fastcall*)(void* self);

// ===== Trampolines (populated by MinHook on install) =====
NifLoadByPathFn    g_orig_nif_load      = nullptr;
TexLoadFn          g_orig_tex_load      = nullptr;
TexSetSetPathFn    g_orig_texset_path   = nullptr;
BindMatTexSetFn    g_orig_bind_mat      = nullptr;
BSLSPNewFn         g_orig_bslsp_new     = nullptr;
MaterialCtorFn     g_orig_material_ctor = nullptr;

uintptr_t g_base = 0;

// ===== Call counters (for post-mortem spam analysis) =====
std::atomic<std::uint64_t> g_nif_calls      {0};
std::atomic<std::uint64_t> g_tex_load_calls {0};
std::atomic<std::uint64_t> g_texset_calls   {0};
std::atomic<std::uint64_t> g_bind_calls     {0};
std::atomic<std::uint64_t> g_bslsp_calls    {0};
std::atomic<std::uint64_t> g_material_calls {0};

// Safe string read — truncates at 255 chars or first null, AV-caged.
// Returns "<null>" or "<AV>" on failure.
static const char* safe_cstr(const char* s, char* buf, std::size_t bufsz) {
    if (!s) return "<null>";
    __try {
        std::size_t i = 0;
        for (; i < bufsz - 1 && s[i]; ++i) buf[i] = s[i];
        buf[i] = 0;
        return buf;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return "<AV>";
    }
}

// ===== Detours =====

std::uint32_t __fastcall detour_nif_load(
    const char* path, void** out_node, void* opts)
{
    const auto tid = GetCurrentThreadId();
    const auto n = g_nif_calls.fetch_add(1, std::memory_order_relaxed) + 1;

    char pbuf[260];
    const char* ps = safe_cstr(path, pbuf, sizeof(pbuf));

    // Log opts flags byte at +0x8 if opts non-null.
    std::uint8_t flags = 0xFF;
    __try {
        if (opts) flags = reinterpret_cast<std::uint8_t*>(opts)[8];
    } __except (EXCEPTION_EXECUTE_HANDLER) { flags = 0xFE; }

    FW_LOG("[trace] nif_load #%llu tid=%lu path='%s' opts=%p flags=0x%02X",
           static_cast<unsigned long long>(n), tid, ps, opts, flags);

    const std::uint32_t rc = g_orig_nif_load(path, out_node, opts);

    // Log result — out pointer + its vtable RVA if valid.
    void* result = out_node ? *out_node : nullptr;
    std::uintptr_t vt_rva = 0;
    __try {
        if (result) {
            void* vt = *reinterpret_cast<void**>(result);
            vt_rva = reinterpret_cast<std::uintptr_t>(vt) - g_base;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { vt_rva = 0xDEAD; }

    FW_LOG("[trace] nif_load #%llu RET rc=%u result=%p vt_rva=0x%llX",
           static_cast<unsigned long long>(n), rc, result,
           static_cast<unsigned long long>(vt_rva));
    return rc;
}

void* __fastcall detour_tex_load(
    const char* path, char blocking, void** out_handle,
    char force_special_default, char emissive_or_normal,
    char tls_sampler_flag)
{
    const auto tid = GetCurrentThreadId();
    const auto n = g_tex_load_calls.fetch_add(1, std::memory_order_relaxed) + 1;

    char pbuf[260];
    const char* ps = safe_cstr(path, pbuf, sizeof(pbuf));

    FW_LOG("[trace] tex_load #%llu tid=%lu path='%s' blocking=%d "
           "force_def=%d emisNrm=%d tlsSmp=%d",
           static_cast<unsigned long long>(n), tid, ps,
           int(blocking), int(force_special_default),
           int(emissive_or_normal), int(tls_sampler_flag));

    void* ret = g_orig_tex_load(
        path, blocking, out_handle, force_special_default,
        emissive_or_normal, tls_sampler_flag);

    void* handle = out_handle ? *out_handle : nullptr;
    FW_LOG("[trace] tex_load #%llu RET ret=%p handle=%p",
           static_cast<unsigned long long>(n), ret, handle);
    return ret;
}

void* __fastcall detour_texset_set_path(
    void* self, int slot, const std::uint8_t* path)
{
    const auto tid = GetCurrentThreadId();
    const auto n = g_texset_calls.fetch_add(1, std::memory_order_relaxed) + 1;

    char pbuf[260];
    const char* ps = safe_cstr(
        reinterpret_cast<const char*>(path), pbuf, sizeof(pbuf));

    FW_LOG("[trace] texset_setPath #%llu tid=%lu self=%p slot=%d path='%s'",
           static_cast<unsigned long long>(n), tid, self, slot, ps);
    return g_orig_texset_path(self, slot, path);
}

void* __fastcall detour_bind_mat(
    void* material, void* shader_arg2, void* textureSet)
{
    const auto tid = GetCurrentThreadId();
    const auto n = g_bind_calls.fetch_add(1, std::memory_order_relaxed) + 1;

    std::uintptr_t mat_vt_rva = 0;
    __try {
        if (material) {
            void* vt = *reinterpret_cast<void**>(material);
            mat_vt_rva = reinterpret_cast<std::uintptr_t>(vt) - g_base;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { mat_vt_rva = 0xDEAD; }

    FW_LOG("[trace] bind_mat #%llu tid=%lu mat=%p (vt_rva=0x%llX) "
           "arg2=%p texset=%p",
           static_cast<unsigned long long>(n), tid, material,
           static_cast<unsigned long long>(mat_vt_rva),
           shader_arg2, textureSet);
    return g_orig_bind_mat(material, shader_arg2, textureSet);
}

void* __fastcall detour_bslsp_new() {
    const auto tid = GetCurrentThreadId();
    const auto n = g_bslsp_calls.fetch_add(1, std::memory_order_relaxed) + 1;

    void* ret = g_orig_bslsp_new();

    std::uintptr_t vt_rva = 0;
    __try {
        if (ret) {
            void* vt = *reinterpret_cast<void**>(ret);
            vt_rva = reinterpret_cast<std::uintptr_t>(vt) - g_base;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { vt_rva = 0xDEAD; }

    FW_LOG("[trace] bslsp_new #%llu tid=%lu RET=%p vt_rva=0x%llX",
           static_cast<unsigned long long>(n), tid, ret,
           static_cast<unsigned long long>(vt_rva));
    return ret;
}

void* __fastcall detour_material_ctor(void* self) {
    const auto tid = GetCurrentThreadId();
    const auto n = g_material_calls.fetch_add(1, std::memory_order_relaxed) + 1;

    void* ret = g_orig_material_ctor(self);

    std::uintptr_t vt_rva = 0;
    __try {
        if (self) {
            void* vt = *reinterpret_cast<void**>(self);
            vt_rva = reinterpret_cast<std::uintptr_t>(vt) - g_base;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { vt_rva = 0xDEAD; }

    FW_LOG("[trace] material_ctor #%llu tid=%lu self=%p vt_rva=0x%llX "
           "RET=%p",
           static_cast<unsigned long long>(n), tid, self,
           static_cast<unsigned long long>(vt_rva), ret);
    return ret;
}

// ===== RVA constants (match ni_offsets.h) =====
constexpr std::uintptr_t RVA_NIF_LOAD_BY_PATH   = 0x017B3E90;
constexpr std::uintptr_t RVA_TEX_LOAD           = 0x0217A910;
constexpr std::uintptr_t RVA_TEXSET_SETPATH     = 0x021627B0;
constexpr std::uintptr_t RVA_BIND_MAT_TEXSET    = 0x021C6870;
constexpr std::uintptr_t RVA_BSLSP_NEW          = 0x02171050;
constexpr std::uintptr_t RVA_MATERIAL_CTOR      = 0x021C5CE0;

template <typename OrigFn>
static bool install_one(
    const char* name, std::uintptr_t rva, std::uintptr_t base,
    void* detour, OrigFn* orig_slot)
{
    void* target = reinterpret_cast<void*>(base + rva);
    const bool ok = install(target, detour, reinterpret_cast<void**>(orig_slot));
    if (ok) {
        FW_LOG("[trace] hook installed: %s @ RVA 0x%lX (target=%p)",
               name, static_cast<unsigned long>(rva), target);
    } else {
        FW_ERR("[trace] hook install FAILED: %s @ RVA 0x%lX (target=%p)",
               name, static_cast<unsigned long>(rva), target);
    }
    return ok;
}

} // namespace

bool install_engine_tracer(std::uintptr_t module_base) {
    g_base = module_base;
    FW_LOG("[trace] installing engine tracer hooks (MINIMAL: nif_load only, "
           "base=0x%llX)", static_cast<unsigned long long>(module_base));

    // M6.3 use-case: observe what NIF paths the engine loads natively,
    // to discover the correct path for character heads (procedural in
    // FO4 — no static MaleHead.nif exists). When the user walks near
    // a vanilla NPC whose head is visible, the trace log will show
    // which .nif path the engine loads. Filter with:
    //   grep "nif_load" fw_native.log | grep -iE "head|face"
    //
    // Other 5 hooks from this module (tex_load, texset_set_path, etc)
    // are intentionally NOT installed — too noisy for this specific
    // investigation. Flip them back on if we need finer texture-layer
    // diagnostics later (e.g. for M7 animations or M8 facegen).
    bool all = true;
    all &= install_one("nif_load_by_path", RVA_NIF_LOAD_BY_PATH,
                       module_base,
                       reinterpret_cast<void*>(&detour_nif_load),
                       &g_orig_nif_load);
    // Keep the other function pointers unreachable but defined so the
    // detour helpers compile. Silence unused-warning hints:
    (void)&detour_tex_load; (void)&detour_texset_set_path;
    (void)&detour_bind_mat; (void)&detour_bslsp_new;
    (void)&detour_material_ctor;

    FW_LOG("[trace] engine tracer install %s (nif_load only)",
           all ? "OK" : "FAILED");
    return all;
}

} // namespace fw::hooks
