#include "pa_pipeline_trace.h"

#include <windows.h>

#include <atomic>
#include <cstdio>    // std::snprintf in the SetMaterial tracer
#include <cstring>   // std::strcmp in the material-swap tracer

#include "../hook_manager.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../log.h"

namespace fw::hooks {

namespace {

// Signatures — every arity here comes from a full read, not a guess
// (DEEP_140989A40: 3 args; pa_system_model §6.1: replay takes the actor;
// enter step 10 shows both reload calls with their exact arguments).
using PaEnterFn   = void*(__fastcall*)(void* actor, void* frame, char mode);
using PaExitReqFn = void*(__fastcall*)(void* actor, void* a2);
using PaReplayFn  = void*(__fastcall*)(void* actor);
using PaReloadAFn = void (__fastcall*)(void* proc, int code);
using PaReloadBFn = void (__fastcall*)(void* proc, void* actor, int flag);

PaEnterFn   g_orig_enter    = nullptr;
PaExitReqFn g_orig_exit_req = nullptr;
PaReplayFn  g_orig_replay   = nullptr;
PaReloadAFn g_orig_reload_a = nullptr;
PaReloadBFn g_orig_reload_b = nullptr;

// 2026-09-15 — material-swap tracer. The second player to enter a power
// armor loses its paint LOCALLY (PA-enter+2.5s dump: X1Body01_d.DDS where
// the first entrant shows X1bodyFlames_d.dds), reproducible, independent of
// how the ghost's own paint is applied. The engine applies an instance's
// swaps through sub_140255BA0(node, model_swap, swap, instance_data,
// prefetch) -> sub_140255D40 -> sub_140255F30 -> sub_140256070(ctx, geom).
// These two observe-only detours say, for every call that carries a swap
// or touches a power-armor node: did the walker get instance data, how
// many swaps it holds, and per geometry whether the leaf changed the
// bound material. Our own apply_materials calls pass through the same
// walker with instance_data == 0, which tells them apart.
constexpr std::uintptr_t kMatWalkerRva = 0x00255BA0;   // sub_140255BA0
constexpr std::uintptr_t kMatLeafRva   = 0x00256070;   // sub_140256070
using MatWalkerFn = void (__fastcall*)(void* node, void* model_swap, void* swap,
                                       void* inst, void* prefetch);
using MatLeafFn   = std::int64_t (__fastcall*)(void* ctx, void* geom);
MatWalkerFn g_orig_mat_walker = nullptr;
MatLeafFn   g_orig_mat_leaf   = nullptr;


// NiObjectNET name: BSFixedString entry at +0x10, characters at entry+0x18.
bool seh_ni_name(void* obj, char* out, std::size_t cap) noexcept {
    __try {
        out[0] = 0;
        if (!obj) return false;
        const char* entry = *reinterpret_cast<const char* const*>(
            static_cast<const char*>(obj) + 0x10);
        if (!entry) return false;
        const char* s = entry + 0x18;
        std::size_t n = 0;
        while (n + 1 < cap && s[n]) { out[n] = s[n]; ++n; }
        out[n] = 0;
        return n > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        return false;
    }
}

bool name_has_ci(const char* s, const char* needle) noexcept {
    std::size_t nl = 0;
    while (needle[nl]) ++nl;
    for (std::size_t i = 0; s[i]; ++i) {
        std::size_t k = 0;
        for (; k < nl; ++k) {
            char a = s[i + k];
            if (a == 0) return false;
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (a != needle[k]) break;
        }
        if (k == nl) return true;
    }
    return false;
}

// TBO_InstanceData vtable slot 10 = GetMaterialSwapArray (BSTArray: data,
// capacity, count at +16). -1 when unreadable, -2 when no array.
int seh_inst_swap_count(void* inst) noexcept {
    __try {
        if (!inst) return -1;
        using GetArrFn = void* (__fastcall*)(void*);
        void** vt = *reinterpret_cast<void***>(inst);
        auto fn = reinterpret_cast<GetArrFn>(vt[10]);
        void* arr = fn(inst);
        if (!arr) return -2;
        return static_cast<int>(*reinterpret_cast<std::uint32_t*>(
            static_cast<char*>(arr) + 16));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

void* seh_geom_material(void* geom) noexcept {
    __try {
        const char* prop = *reinterpret_cast<const char* const*>(
            static_cast<const char*>(geom) + 0x138);
        if (!prop) return nullptr;
        return *reinterpret_cast<void* const*>(prop + 0x58);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

bool seh_geom_prop_name(void* geom, char* out, std::size_t cap) noexcept {
    __try {
        out[0] = 0;
        void* prop = *reinterpret_cast<void* const*>(
            static_cast<const char*>(geom) + 0x138);
        return seh_ni_name(prop, out, cap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        return false;
    }
}

void __fastcall detour_mat_walker(void* node, void* model_swap, void* swap,
                                  void* inst, void* prefetch) {
    char nm[96];
    (void)seh_ni_name(node, nm, sizeof(nm));
    const bool pa = name_has_ci(nm, "pa_") || name_has_ci(nm, "powerarmor")
                 || name_has_ci(nm, "frame") || name_has_ci(nm, "armorpa");
    if (inst || swap || pa) {
        FW_LOG("[mat-trace] walker node=%p '%s' model_swap=%p swap=%p inst=%p "
               "(inst swaps=%d) prefetch=%p", node, nm, model_swap, swap, inst,
               seh_inst_swap_count(inst), prefetch);
    }
    g_orig_mat_walker(node, model_swap, swap, inst, prefetch);
}

std::int64_t __fastcall detour_mat_leaf(void* ctx, void* geom) {
    void* swap = nullptr;
    __try {
        void** pswap = *reinterpret_cast<void***>(static_cast<char*>(ctx) + 8);
        swap = pswap ? *pswap : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        swap = nullptr;
    }
    if (!swap) return g_orig_mat_leaf(ctx, geom);
    char gn[64], pn[160];
    (void)seh_ni_name(geom, gn, sizeof(gn));
    (void)seh_geom_prop_name(geom, pn, sizeof(pn));
    void* before = seh_geom_material(geom);
    const std::int64_t rc = g_orig_mat_leaf(ctx, geom);
    void* after = seh_geom_material(geom);
    char pn2[160];
    (void)seh_geom_prop_name(geom, pn2, sizeof(pn2));
    FW_LOG("[mat-trace] leaf geom=%p '%s' prop='%s' swap=%p material %p -> %p%s%s%s",
           geom, gn, pn, swap, before, after,
           (before != after) ? " CHANGED" : " unchanged",
           (std::strcmp(pn, pn2) != 0) ? " RENAMED->" : "",
           (std::strcmp(pn, pn2) != 0) ? pn2 : "");
    return rc;
}

// 2026-09-15 (evening) — the swap IS applied on the second entrant (leaf
// CHANGED the material), yet 2.5 s later the same geometry carries a NEW
// material object holding the default .bgsm, with nothing of ours in
// between. Every material replacement on a property goes through
// sub_142161B10(prop, material, unique) = BSShaderProperty::SetMaterial
// (acquires through the material manager at 0x1431E5320 and releases the
// old one). This detour names the caller: for PowerArmor properties it
// logs old/new material, the new material's .bgsm name and the first
// game-module return addresses of the call stack.
constexpr std::uintptr_t kSetMaterialRva = 0x02161B10;   // sub_142161B10
using SetMaterialFn = std::int64_t (__fastcall*)(void* prop, void* material, char unique);
SetMaterialFn g_orig_set_material = nullptr;

// BSShaderMaterial name: BSFixedString at material+0x58 (sub_142163B00
// copies it into prop+0xC0), characters at entry+0x18.
bool seh_material_name(void* mat, char* out, std::size_t cap) noexcept {
    __try {
        out[0] = 0;
        if (!mat) return false;
        const char* entry = *reinterpret_cast<const char* const*>(
            static_cast<const char*>(mat) + 0x58);
        if (!entry) return false;
        const char* s = entry + 0x18;
        std::size_t n = 0;
        while (n + 1 < cap && s[n]) { out[n] = s[n]; ++n; }
        out[n] = 0;
        return n > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        return false;
    }
}

void* seh_prop_material(void* prop) noexcept {
    __try {
        return *reinterpret_cast<void* const*>(static_cast<const char*>(prop) + 0x58);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

std::int64_t __fastcall detour_set_material(void* prop, void* material, char unique) {
    char pn[160];
    (void)seh_ni_name(prop, pn, sizeof(pn));
    if (!name_has_ci(pn, "powerarmor")) {
        return g_orig_set_material(prop, material, unique);
    }
    void* frames[10] = {};
    const USHORT n = RtlCaptureStackBackTrace(1, 10, frames, nullptr);
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    char chain[200];
    std::size_t pos = 0;
    for (USHORT i = 0; i < n && pos + 14 < sizeof(chain); ++i) {
        const auto a = reinterpret_cast<std::uintptr_t>(frames[i]);
        int w;
        if (base && a >= base && a < base + 0x10000000ull) {
            w = std::snprintf(chain + pos, sizeof(chain) - pos, " +%llX",
                              static_cast<unsigned long long>(a - base));
        } else {
            w = std::snprintf(chain + pos, sizeof(chain) - pos, " ext");
        }
        if (w <= 0) break;
        pos += static_cast<std::size_t>(w);
    }
    void* before = seh_prop_material(prop);
    char mn[160];
    (void)seh_material_name(material, mn, sizeof(mn));
    const std::int64_t rc = g_orig_set_material(prop, material, unique);
    void* after = seh_prop_material(prop);
    FW_LOG("[mat-trace] SetMaterial prop=%p '%s' unique=%d arg=%p ('%s') material %p -> %p"
           " | callers%s", prop, pn, int(unique), material, mn, before, after, chain);
    return rc;
}

std::atomic<std::uintptr_t> g_base{0};
std::atomic<std::uint64_t>  g_last_player_pa_ms{0};

// Build 70u — the player's AIProcess as the ENGINE passes it to the model
// reload pair, plus the player Actor* seen alongside it. Captured rather
// than derived: reading Actor+0x328 would be a second-hand guess, and this
// costs nothing because the engine runs the pair on every enter anyway.
std::atomic<void*> g_player_proc{nullptr};
std::atomic<void*> g_player_actor{nullptr};

// 2026-09-15 — RELOAD-B is a per-frame gate, not a rebuild (see the offset
// notes). Read the gate: the middle-high 3D-update flags and the
// "needs load" bool. Logged only when open, plus a 1 Hz summary.
using NeedsLoadFn = bool (__fastcall*)(void* proc);
std::uint64_t g_rb_window_ms  = 0;   // summary window start
std::uint32_t g_rb_calls      = 0;   // calls in the window
std::uint32_t g_rb_open       = 0;   // calls with the gate open
std::uint16_t g_rb_last_flags = 0;
std::uint32_t g_rb_open_logged_in_window = 0;

bool seh_read_update_gate(std::uintptr_t base, void* proc,
                          std::uint16_t* flags, bool* needs_load) noexcept {
    __try {
        auto* mh = *reinterpret_cast<std::uint8_t**>(
            static_cast<std::uint8_t*>(proc) + fw::offsets::AIPROCESS_MIDDLE_HIGH_OFF);
        *flags = mh ? *reinterpret_cast<std::uint16_t*>(
                          mh + fw::offsets::MIDDLEHIGH_3D_UPDATE_FLAGS_OFF)
                    : 0;
        auto fn = reinterpret_cast<NeedsLoadFn>(base + fw::offsets::AIPROCESS_NEEDS_3D_LOAD_RVA);
        *needs_load = fn(proc);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void mark_player_transition(void* actor) noexcept {
    const auto id = fw::read_ref_identity(actor);
    if (id.form_id == 0x14u) {
        g_last_player_pa_ms.store(GetTickCount64(),
                                  std::memory_order_relaxed);
    }
}

// ---- SEH POD readers (no unwindables in __try frames) ----------------------

void* seh_ptr(const void* p, std::size_t off) noexcept {
    if (!p) return nullptr;
    __try {
        return *reinterpret_cast<void* const*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

std::uint8_t seh_u8(const void* p, std::size_t off) noexcept {
    if (!p) return 0xEE;
    __try {
        return *reinterpret_cast<const std::uint8_t*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0xEE; }
}

std::uint32_t seh_u32(const void* p, std::size_t off) noexcept {
    if (!p) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// The extra-0xBB triple off an actor: state byte (+0x28), frame handle
// (+0x18), race ptr (+0x20). Uses the engine's LOCKED GetByType
// (sub_1402A0030(list, type) — the exact call sub_140290560's body makes).
struct PaExtra {
    bool          present = false;
    std::uint8_t  state   = 0xEE;   // 0xEE = unreadable
    std::uint32_t handle  = 0;
    void*         race    = nullptr;
};

PaExtra seh_read_pa_extra(std::uintptr_t base, void* actor) noexcept {
    PaExtra r{};
    if (!actor || !base) return r;
    void* list = seh_ptr(actor, 0x100);
    if (!list) return r;
    using GetByTypeFn = void*(__fastcall*)(void* list, std::uint32_t type);
    auto get_by_type = reinterpret_cast<GetByTypeFn>(
        base + fw::offsets::EXTRA_GET_BY_TYPE_RVA);
    void* extra = nullptr;
    __try {
        extra = get_by_type(list, 0xBBu);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return r; }
    if (!extra) return r;
    r.present = true;
    r.state   = seh_u8(extra, 0x28);
    r.handle  = seh_u32(extra, 0x18);
    r.race    = seh_ptr(extra, 0x20);
    return r;
}

void* seh_actor_3d(void* actor) noexcept {
    void* loaded = seh_ptr(actor, 0xF0);
    return loaded ? seh_ptr(loaded, 0x08) : nullptr;
}

void* seh_pa_race(std::uintptr_t base) noexcept {
    using RaceGetFn = void*(__fastcall*)();
    auto fn = reinterpret_cast<RaceGetFn>(
        base + fw::offsets::PA_RACE_GETTER_RVA);
    __try { return fn(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

void log_actor_pa_state(const char* tag, std::uintptr_t base, void* actor) {
    const auto id = fw::read_ref_identity(actor);
    const PaExtra x = seh_read_pa_extra(base, actor);
    void* race_global = seh_pa_race(base);
    FW_LOG("[pa-trace] %s actor=0x%08X extra0xBB=%s state=0x%02X "
           "frame_handle=0x%08X race=%p (PA race global=%p, match=%d) 3D=%p",
           tag, id.form_id, x.present ? "YES" : "no", x.state, x.handle,
           x.race, race_global,
           (x.race && x.race == race_global) ? 1 : 0,
           seh_actor_3d(actor));
}

// ---- E0 (PA pieces milestone) — [pa-inv] inventory dump --------------------
//
// Layout measured from sub_14051F050, the engine's own generic inventory
// walker (decomp 2026-08-16), not guessed:
//
//   REFR+0xF8 = BGSInventoryList*
//     +0x58  entries array, stride 0x10:
//              +0x00 TESBoundObject*  (+0x1A form-type byte, +0x14 form id)
//              +0x08 stack head
//     +0x68  entry count
//     +0x78  lock — NOT taken here: this dump runs on the main thread and
//            every inventory mutation path we know (AddItem delay functor,
//            the PA enter transfer) is main-thread too, so there is nothing
//            to race and the diagnostic stays dependency-free
//   stack:
//     +0x10  next stack
//     +0x20  count
//     +0x24  flags byte — THE MEASUREMENT TARGET: the engine's own filter
//            for "equipped/mounted" stacks is (flags & 7) != 0. The dump
//            prints the whole byte so a live frame with mounted pieces vs
//            a stored core names the exact bit values, and +0x00/+0x08/
//            +0x18 raw so the ExtraDataList slot identifies itself.
void dump_refr_inventory_impl(const char* tag, void* refr) {
    const auto rid = fw::read_ref_identity(refr);
    void* list = seh_ptr(refr, 0xF8);
    if (!list) {
        FW_LOG("[pa-inv] %s refr=0x%08X (base=0x%08X): NO inventory list "
               "(+0xF8 null)", tag, rid.form_id, rid.base_id);
        return;
    }
    const std::uint32_t count = seh_u32(list, 0x68);
    std::uint8_t* entries = static_cast<std::uint8_t*>(seh_ptr(list, 0x58));
    FW_LOG("[pa-inv] ===== %s refr=0x%08X (base=0x%08X): %u entries "
           "(list=%p) =====", tag, rid.form_id, rid.base_id, count, list);
    if (!entries || count > 64) return;
    for (std::uint32_t i = 0; i < count; ++i) {
        void* obj = seh_ptr(entries, i * 0x10);
        void* stack = seh_ptr(entries, i * 0x10 + 8);
        const std::uint32_t fid  = obj ? seh_u32(obj, 0x14) : 0;
        const std::uint8_t  type = obj ? seh_u8(obj, 0x1A) : 0xEE;
        int si = 0;
        for (void* s = stack; s && si < 8;
             s = seh_ptr(s, 0x10), ++si) {
            FW_LOG("[pa-inv]   [%2u] form=0x%08X type=0x%02X stack#%d "
                   "count=%u flags=0x%02X mounted(&7)=%u raw{+0=%p +8=%p "
                   "+18=%p}",
                   i, fid, type, si,
                   seh_u32(s, 0x20), seh_u8(s, 0x24),
                   seh_u8(s, 0x24) & 7u,
                   seh_ptr(s, 0x00), seh_ptr(s, 0x08), seh_ptr(s, 0x18));
        }
        if (si == 0) {
            FW_LOG("[pa-inv]   [%2u] form=0x%08X type=0x%02X NO stacks",
                   i, fid, type);
        }
    }
    FW_LOG("[pa-inv] ===== %s: end =====", tag);
}

// ---- detours ----------------------------------------------------------------

void* __fastcall detour_pa_enter(void* actor, void* frame, char mode) {
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    const auto aid = fw::read_ref_identity(actor);
    const auto fid = fw::read_ref_identity(frame);
    mark_player_transition(actor);
    FW_LOG("[pa-trace] ============ ENTER sub_140989A40(actor=0x%08X, "
           "frame=0x%08X base=0x%08X, mode=%d) ============",
           aid.form_id, fid.form_id, fid.base_id, int(mode));
    log_actor_pa_state("ENTER pre ", base, actor);
    // E0 — the standing frame's inventory IS the state we must replicate:
    // pre-enter shows the mounted set, post-enter shows what the native
    // transfer (DEEP step 15d) drained and what it left behind.
    dump_refr_inventory_impl("ENTER pre (frame)", frame);
    void* r = g_orig_enter(actor, frame, mode);
    log_actor_pa_state("ENTER post", base, actor);
    dump_refr_inventory_impl("ENTER post (frame)", frame);
    FW_LOG("[pa-trace] ENTER done — expected: extra=YES state=0x02 "
           "race match=1, frame 0x%08X now DISABLED via task 74",
           fid.form_id);
    return r;
}

void* __fastcall detour_pa_exit_req(void* actor, void* a2) {
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    const auto aid = fw::read_ref_identity(actor);
    mark_player_transition(actor);
    FW_LOG("[pa-trace] ============ EXIT REQUEST sub_14098BAF0(actor=0x%08X)"
           " ============", aid.form_id);
    log_actor_pa_state("EXIT pre  ", base, actor);
    void* r = g_orig_exit_req(actor, a2);
    log_actor_pa_state("EXIT post ", base, actor);
    return r;
}

void* __fastcall detour_pa_replay(void* actor) {
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    const auto aid = fw::read_ref_identity(actor);
    mark_player_transition(actor);
    FW_LOG("[pa-trace] ============ REPLAY sub_14098C9D0(actor=0x%08X) — "
           "save-load re-seat ============", aid.form_id);
    log_actor_pa_state("RPLY pre  ", base, actor);
    void* r = g_orig_replay(actor);
    log_actor_pa_state("RPLY post ", base, actor);
    return r;
}

void __fastcall detour_pa_reload_a(void* proc, int code) {
    // 1312 (0x520) is the PA model reload the enter/exit machine issues;
    // other codes are routine engine reloads — DBG only.
    if (code == 1312) {
        FW_LOG("[pa-trace] MODEL RELOAD A sub_140D35EA0(proc=%p, 1312) — "
               "the PA skeleton rebuild", proc);
    } else {
        FW_DBG("[pa-trace] reload A(proc=%p, code=%d)", proc, code);
    }
    g_orig_reload_a(proc, code);
}

void __fastcall detour_pa_reload_b(void* proc, void* actor, int flag) {
    // Measured 2026-08-15: this fires for EVERY loaded actor continuously
    // (mass reload waves re-queue ~20 actors for seconds at a time) — INF
    // flooded the log. Player-actor calls stay INF (the signal that the
    // local player's 3D is being rebuilt); the rest is DBG.
    const auto aid = fw::read_ref_identity(actor);
    if (aid.form_id == 0x14u) {
        // Build 70u — remember exactly what the engine used, so the forced
        // repeat is a replay and not an invention.
        g_player_proc.store(proc, std::memory_order_relaxed);
        g_player_actor.store(actor, std::memory_order_relaxed);
        // 2026-09-15 — the call is per-frame; only an OPEN gate means the
        // engine is about to touch the player's 3D. Log those (5 per
        // window at most) and a 1 Hz summary instead of the 73/s flood.
        std::uint16_t flags = 0;
        bool needs = false;
        const bool ok = seh_read_update_gate(
            g_base.load(std::memory_order_relaxed), proc, &flags, &needs);
        const bool open = ok && (needs || flags != 0);
        const std::uint64_t now = GetTickCount64();
        if (g_rb_window_ms == 0) g_rb_window_ms = now;
        ++g_rb_calls;
        if (open) {
            ++g_rb_open;
            g_rb_last_flags = flags;
            if (g_rb_open_logged_in_window < 5) {
                ++g_rb_open_logged_in_window;
                FW_DBG("[pa-trace] player 3D update gate OPEN: flags=0x%04X "
                       "needs_load=%d (sub_140D020E0 proc=%p, flag=%d)",
                       unsigned(flags), int(needs), proc, flag);
            }
        }
        if (now - g_rb_window_ms >= 1000) {
            FW_DBG("[pa-trace] player RELOAD-B gate: %u call(s)/s, %u open "
                   "(last flags=0x%04X)%s", g_rb_calls, g_rb_open,
                   unsigned(g_rb_last_flags), ok ? "" : " [gate unreadable]");
            g_rb_window_ms = now;
            g_rb_calls = 0;
            g_rb_open = 0;
            g_rb_open_logged_in_window = 0;
        }
    } else {
        FW_DBG("[pa-trace] reload B actor=0x%08X", aid.form_id);
    }
    g_orig_reload_b(proc, actor, flag);
}

}  // namespace

std::uint64_t last_local_pa_transition_ms() {
    return g_last_player_pa_ms.load(std::memory_order_relaxed);
}

bool force_local_pa_model_reload() {
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    void* proc  = g_player_proc.load(std::memory_order_relaxed);
    void* actor = g_player_actor.load(std::memory_order_relaxed);
    if (!base || !proc || !actor || !g_orig_reload_a || !g_orig_reload_b) {
        FW_DBG("[pa-refresh] not armed yet (base=%p proc=%p actor=%p)",
               reinterpret_cast<void*>(base), proc, actor);
        return false;
    }
    FW_LOG("[pa-refresh] replaying the engine's own model reload on the "
           "local player (proc=%p) — sub_140D35EA0(proc,1312) + "
           "sub_140D020E0(proc,actor,1)", proc);
    // Call the ORIGINALS: going through our own detours would re-log and,
    // worse, re-arm the deferred diagnostics from inside the repair.
    __try {
        g_orig_reload_a(proc, 1312);
        g_orig_reload_b(proc, actor, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[pa-refresh] SEH inside the forced reload — repair aborted, "
               "the engine's own next build still applies");
        return false;
    }
    return true;
}

bool install_pa_pipeline_trace(std::uintptr_t module_base) {
    if (!module_base) return false;
    g_base.store(module_base, std::memory_order_relaxed);

    // 2026-09-16 — the three material tracers (walker / leaf / SetMaterial
    // with caller chains) are DEBUG-ONLY. They found the skeleton loan, but
    // they log every swap application and capture a stack per PowerArmor
    // SetMaterial: hundreds of lines per power-armor entry. With the
    // default log level the engine's material path runs untouched.
    const bool debug_tracers =
        ::fw::log::get_level() >= ::fw::log::Level::Debug;

    struct HookDef {
        std::uintptr_t rva;
        void*          detour;
        void**         orig_slot;
        const char*    name;
        bool           debug_only;
    };
    const HookDef defs[] = {
        { fw::offsets::PA_ENTER_RVA,
          reinterpret_cast<void*>(&detour_pa_enter),
          reinterpret_cast<void**>(&g_orig_enter),    "ENTER 0x989A40",    false },
        { fw::offsets::PA_EXIT_REQUEST_RVA,
          reinterpret_cast<void*>(&detour_pa_exit_req),
          reinterpret_cast<void**>(&g_orig_exit_req), "EXIT-REQ 0x98BAF0", false },
        { fw::offsets::PA_REPLAY_RVA,
          reinterpret_cast<void*>(&detour_pa_replay),
          reinterpret_cast<void**>(&g_orig_replay),   "REPLAY 0x98C9D0",   false },
        { fw::offsets::PA_MODEL_RELOAD_A_RVA,
          reinterpret_cast<void*>(&detour_pa_reload_a),
          reinterpret_cast<void**>(&g_orig_reload_a), "RELOAD-A 0xD35EA0", false },
        { fw::offsets::PA_MODEL_RELOAD_B_RVA,
          reinterpret_cast<void*>(&detour_pa_reload_b),
          reinterpret_cast<void**>(&g_orig_reload_b), "RELOAD-B 0xD020E0", false },
        { kMatWalkerRva,
          reinterpret_cast<void*>(&detour_mat_walker),
          reinterpret_cast<void**>(&g_orig_mat_walker), "MAT-WALKER 0x255BA0", true },
        { kMatLeafRva,
          reinterpret_cast<void*>(&detour_mat_leaf),
          reinterpret_cast<void**>(&g_orig_mat_leaf),   "MAT-LEAF 0x256070",   true },
        { kSetMaterialRva,
          reinterpret_cast<void*>(&detour_set_material),
          reinterpret_cast<void**>(&g_orig_set_material), "SET-MATERIAL 0x2161B10", true },
    };

    int ok_count = 0;
    int wanted   = 0;
    for (const auto& d : defs) {
        if (d.debug_only && !debug_tracers) continue;
        ++wanted;
        void* target = reinterpret_cast<void*>(module_base + d.rva);
        const bool ok = fw::hooks::install(target, d.detour, d.orig_slot);
        if (ok) {
            ++ok_count;
        } else {
            FW_ERR("[pa-trace] hook FAILED: %s", d.name);
        }
    }
    FW_LOG("[pa-trace] PA pipeline tracer installed: %d/%d hooks (observe-"
           "only) — enter/exit/replay + both model reloads%s", ok_count,
           wanted, debug_tracers ? " + material swap walker/leaf + "
                                   "SetMaterial (debug level)" : "");
    return ok_count == wanted;
}

void dump_refr_inventory(const char* tag, void* refr) {
    dump_refr_inventory_impl(tag, refr);
}

}  // namespace fw::hooks
