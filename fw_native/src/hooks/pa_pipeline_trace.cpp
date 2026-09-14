#include "pa_pipeline_trace.h"

#include <windows.h>

#include <atomic>

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

std::atomic<std::uintptr_t> g_base{0};
std::atomic<std::uint64_t>  g_last_player_pa_ms{0};

// Build 70u — the player's AIProcess as the ENGINE passes it to the model
// reload pair, plus the player Actor* seen alongside it. Captured rather
// than derived: reading Actor+0x328 would be a second-hand guess, and this
// costs nothing because the engine runs the pair on every enter anyway.
std::atomic<void*> g_player_proc{nullptr};
std::atomic<void*> g_player_actor{nullptr};

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
        FW_LOG("[pa-trace] MODEL RELOAD B on THE PLAYER "
               "(sub_140D020E0 proc=%p) — 3D rebuilds from the CURRENT race",
               proc);
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

    struct HookDef {
        std::uintptr_t rva;
        void*          detour;
        void**         orig_slot;
        const char*    name;
    };
    const HookDef defs[] = {
        { fw::offsets::PA_ENTER_RVA,
          reinterpret_cast<void*>(&detour_pa_enter),
          reinterpret_cast<void**>(&g_orig_enter),    "ENTER 0x989A40" },
        { fw::offsets::PA_EXIT_REQUEST_RVA,
          reinterpret_cast<void*>(&detour_pa_exit_req),
          reinterpret_cast<void**>(&g_orig_exit_req), "EXIT-REQ 0x98BAF0" },
        { fw::offsets::PA_REPLAY_RVA,
          reinterpret_cast<void*>(&detour_pa_replay),
          reinterpret_cast<void**>(&g_orig_replay),   "REPLAY 0x98C9D0" },
        { fw::offsets::PA_MODEL_RELOAD_A_RVA,
          reinterpret_cast<void*>(&detour_pa_reload_a),
          reinterpret_cast<void**>(&g_orig_reload_a), "RELOAD-A 0xD35EA0" },
        { fw::offsets::PA_MODEL_RELOAD_B_RVA,
          reinterpret_cast<void*>(&detour_pa_reload_b),
          reinterpret_cast<void**>(&g_orig_reload_b), "RELOAD-B 0xD020E0" },
    };

    int ok_count = 0;
    for (const auto& d : defs) {
        void* target = reinterpret_cast<void*>(module_base + d.rva);
        const bool ok = fw::hooks::install(target, d.detour, d.orig_slot);
        if (ok) {
            ++ok_count;
        } else {
            FW_ERR("[pa-trace] hook FAILED: %s", d.name);
        }
    }
    FW_LOG("[pa-trace] PA pipeline tracer installed: %d/5 hooks (observe-"
           "only) — enter/exit/replay + both model reloads", ok_count);
    return ok_count == 5;
}

void dump_refr_inventory(const char* tag, void* refr) {
    dump_refr_inventory_impl(tag, refr);
}

}  // namespace fw::hooks
