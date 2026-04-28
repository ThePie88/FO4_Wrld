// B8 force-equip-cycle — implementation. See equip_cycle.h + offsets.h "B8"
// comment block for architectural rationale.

#include "equip_cycle.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"   // get_target_hwnd

namespace fw::hooks {

namespace {

// WM_APP message offsets — must NOT collide with anything else in the DLL.
// Current map (kept in sync with main_thread_dispatch.h, scene_inject.h,
// actor_hijack.h, container_hook.cpp, door_hook.cpp):
//   0x42 = FW_MSG_LOAD_GAME
//   0x43 = FW_MSG_CONTAINER_APPLY
//   0x44 = FW_MSG_SPAWN_GHOST
//   0x45 = FW_MSG_STRADAB_INJECT
//   0x46 = FW_MSG_STRADAB_POS_UPDATE
//   0x47 = FW_MSG_STRADAB_BONE_TICK
//   0x48 = FW_MSG_STRADAB_POSE_APPLY
//   0x49 = FW_MSG_DOOR_APPLY
//   0x4A = FW_MSG_FORCE_EQUIP_CYCLE_UNEQUIP   ← B8 (this module)
//   0x4B = FW_MSG_FORCE_EQUIP_CYCLE_EQUIP     ← B8 (this module)
constexpr UINT FW_MSG_FORCE_EQUIP_CYCLE_UNEQUIP = WM_APP + 0x4A;
constexpr UINT FW_MSG_FORCE_EQUIP_CYCLE_EQUIP   = WM_APP + 0x4B;

// State machine — single one-shot run per session.
enum class CycleState : int {
    IDLE        = 0,   // never armed, or shutdown
    ARMED       = 1,   // worker sleeping, will fire post-delay
    UNEQUIP_FIRED = 2, // we already posted unequip msg, awaiting equip
    DONE        = 3    // both posted; cycle complete
};
std::atomic<CycleState> g_state{CycleState::IDLE};

std::thread g_worker;
std::atomic<bool> g_worker_should_stop{false};

// Resolve all engine refs we need at the time of the cycle call (NOT at
// arm time — at arm time the player singleton might not yet be populated).
// Returns true if all refs resolved. Logs which one was missing on failure.
struct ResolvedRefs {
    void* manager     = nullptr;  // *(base + ACTOR_EQUIP_MGR_SINGLETON_RVA)
    void* player      = nullptr;  // *(base + PLAYER_SINGLETON_RVA)
    void* vault_suit  = nullptr;  // lookup_by_form_id(VAULT_SUIT_FORM_ID)
    std::uintptr_t base = 0;
    void* equip_fn    = nullptr;
    void* unequip_fn  = nullptr;
};

bool resolve_refs(ResolvedRefs* out) {
    HMODULE mod = GetModuleHandleW(L"Fallout4.exe");
    if (!mod) {
        FW_ERR("[equip-cycle] resolve: Fallout4.exe module not loaded");
        return false;
    }
    out->base = reinterpret_cast<std::uintptr_t>(mod);

    out->manager = *reinterpret_cast<void**>(
        out->base + offsets::ACTOR_EQUIP_MGR_SINGLETON_RVA);
    if (!out->manager) {
        FW_WRN("[equip-cycle] resolve: ActorEquipManager singleton is null "
               "(qword_1431E3328 not yet populated — game still booting?)");
        return false;
    }

    out->player = *reinterpret_cast<void**>(
        out->base + offsets::PLAYER_SINGLETON_RVA);
    if (!out->player) {
        FW_WRN("[equip-cycle] resolve: PlayerCharacter singleton is null "
               "(player not yet spawned — too early in load?)");
        return false;
    }

    // lookup_by_form_id(form_id) — same RVA used by ref_identity et al.
    using LookupFn = void* (__fastcall*)(std::uint32_t form_id);
    auto lookup = reinterpret_cast<LookupFn>(
        out->base + offsets::LOOKUP_BY_FORMID_RVA);
    out->vault_suit = lookup(offsets::VAULT_SUIT_FORM_ID);
    if (!out->vault_suit) {
        FW_WRN("[equip-cycle] resolve: VaultSuit form 0x%X not found — "
               "save-game probably doesn't include it; cycle will no-op",
               offsets::VAULT_SUIT_FORM_ID);
        return false;
    }

    out->equip_fn = reinterpret_cast<void*>(
        out->base + offsets::ENGINE_EQUIP_OBJECT_RVA);
    out->unequip_fn = reinterpret_cast<void*>(
        out->base + offsets::ENGINE_UNEQUIP_OBJECT_RVA);
    return true;
}

// Worker thread body: sleeps `delay_ms`, then posts UNEQUIP msg, sleeps
// 500ms, posts EQUIP msg. The 500ms gap gives the engine's BipedAnim
// rebuild path time to settle between the two operations — direct
// back-to-back call risks racing the rebuild and re-introducing the
// crash this whole exercise is trying to prevent.
void worker_main(unsigned int delay_ms) {
    FW_LOG("[equip-cycle] worker armed, will fire in %ums", delay_ms);

    // Wait the initial delay (with 50ms granularity for shutdown response).
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(delay_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (g_worker_should_stop.load()) {
            FW_LOG("[equip-cycle] worker shutdown requested — abort");
            g_state.store(CycleState::IDLE);
            return;
        }
        Sleep(50);
    }

    HWND hwnd = fw::dispatch::get_target_hwnd();
    if (!hwnd) {
        FW_ERR("[equip-cycle] worker: no target HWND — main_menu WndProc "
               "subclass not yet installed; cycle aborted");
        g_state.store(CycleState::IDLE);
        return;
    }

    // Phase 1: post unequip.
    g_state.store(CycleState::UNEQUIP_FIRED);
    if (!PostMessageW(hwnd, FW_MSG_FORCE_EQUIP_CYCLE_UNEQUIP, 0, 0)) {
        FW_ERR("[equip-cycle] worker: PostMessage UNEQUIP failed (err=%lu)",
               GetLastError());
        g_state.store(CycleState::IDLE);
        return;
    }
    FW_LOG("[equip-cycle] worker: UNEQUIP message posted (WM_APP+0x4A)");

    // 2000ms gap — let engine's biped rebuild settle BEFORE we re-equip.
    // 500ms was too short (live test 17:11-17:18 2026-04-28 showed
    // EQUIP SEH-crashed 3/3 times). The engine fires a deferred rebuild
    // task after Unequip; calling Equip during that rebuild hits the
    // half-allocated state and faults inside sub_140CE5900's allocator
    // path. 2s is conservative — rebuild typically settles in 100-300ms
    // but heavy save-load post-restore work can stretch it. Player sees
    // ~2s of "no Vault Suit" before it returns; acceptable trade.
    Sleep(2000);
    if (g_worker_should_stop.load()) {
        g_state.store(CycleState::IDLE);
        return;
    }

    // Phase 2: post equip.
    if (!PostMessageW(hwnd, FW_MSG_FORCE_EQUIP_CYCLE_EQUIP, 0, 0)) {
        FW_ERR("[equip-cycle] worker: PostMessage EQUIP failed (err=%lu)",
               GetLastError());
        // State stays UNEQUIP_FIRED; player keeps Vault Suit off. Bug.
        return;
    }
    FW_LOG("[equip-cycle] worker: EQUIP message posted (WM_APP+0x4B) — "
           "cycle dispatched");
    // Note: g_state moves to DONE inside the equip message handler, after
    // the engine call returns successfully.
}

} // anon namespace

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------
void arm_equip_cycle_after_loadgame(unsigned int delay_ms) {
    auto expected = CycleState::IDLE;
    if (!g_state.compare_exchange_strong(expected, CycleState::ARMED)) {
        FW_DBG("[equip-cycle] arm: already armed/in-progress (state=%d), no-op",
               static_cast<int>(expected));
        return;
    }

    g_worker_should_stop.store(false);
    g_worker = std::thread(&worker_main, delay_ms);
    g_worker.detach();   // we'll signal via g_worker_should_stop
}

void on_force_equip_cycle_unequip_message() {
    // We're on the main thread (WndProc dispatch). Safe to call engine.
    ResolvedRefs r;
    if (!resolve_refs(&r)) {
        // Don't change state — worker will still post EQUIP after 500ms,
        // which will also fail to resolve and log a warning. Cycle aborted
        // in practice but state machine stays consistent.
        return;
    }

    // Form pair as engine expects: {VMHandle (0 = no Papyrus context),
    // TESForm* (the item)}. Layout matches what callers pass per re log.
    // Form pair layout (RE'd 2026-04-28 from sub_140CE5900/5DA0 decomp):
    //   a3[0] = TESForm* (the item — what *a3 dereferences)
    //   a3[1] = "extra ref" / stack-tag — if 0, engine computes via
    //           sub_140505440(actor, form, count) for Equip path or
    //           sub_140CE6DF0(...) for Unequip.
    // Original guess "{VMHandle, form*}" was BACKWARDS — caused both
    // calls to early-exit on `if (!*a3) return ...` (log 17:11:18 showed
    // UNEQUIP returned 0 which is the early-exit code in sub_140CE5DA0
    // line 211: `if (!a2 || !*a3) return 0;`). Visually no effect.
    std::uint64_t form_pair[2] = {reinterpret_cast<std::uint64_t>(r.vault_suit), 0};

    // ActorEquipManager::UnequipObject(11 args).
    // Signature from re/B8_force_equip_cycle.log section B (sub_140CE5DA0).
    // Arg layout:
    //   a1 = manager singleton
    //   a2 = actor (player)
    //   a3 = form_pair {VMHandle, TESForm*}
    //   a4 = count                (1)
    //   a5 = slot                 (0 = let engine decide via biped data)
    //   a6 = stack_id             (0 = engine computes via sub_140CE6DF0)
    //   a7 = preventEquip flag    (0 = allow re-equip)
    //   a8..a10 = various char flags (silent, queued; 0 = defaults)
    //   a11 = TLS event override  (0 = use default sink)
    using UnequipFn = char (__fastcall*)(
        void*, void*, void*,
        int,            // a4 count
        std::int64_t,   // a5 slot
        int,            // a6 stack_id
        char, char, char, char,
        std::int64_t);

    auto unequip = reinterpret_cast<UnequipFn>(r.unequip_fn);

    FW_LOG("[equip-cycle] UNEQUIP firing: mgr=%p player=%p suit=%p form=0x%X",
           r.manager, r.player, r.vault_suit, offsets::VAULT_SUIT_FORM_ID);

    char ret = 0;
    __try {
        ret = unequip(
            r.manager,
            r.player,
            form_pair,
            /*count=*/      1,
            /*slot=*/       0,
            /*stack_id=*/   0,
            /*a7=*/         0,
            /*a8=*/         0,
            /*a9=*/         0,
            /*a10=*/        0,
            /*a11=*/        0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[equip-cycle] UNEQUIP: SEH caught — engine call faulted "
               "(player skel state probably even worse than expected)");
        return;
    }

    FW_LOG("[equip-cycle] UNEQUIP returned %d", static_cast<int>(ret));
    // engine call returns success/failure char; we don't gate equip on it
    // because even a "no-op unequip" (if suit wasn't worn) is fine.
}

void on_force_equip_cycle_equip_message() {
    ResolvedRefs r;
    if (!resolve_refs(&r)) {
        // If unequip succeeded but equip can't resolve, player is stuck
        // without Vault Suit. Log loud — user can manually re-equip.
        FW_ERR("[equip-cycle] EQUIP: resolve failed — player may be left "
               "without Vault Suit. Open PipBoy and re-equip manually.");
        g_state.store(CycleState::IDLE);
        return;
    }

    // Form pair layout (RE'd 2026-04-28 from sub_140CE5900/5DA0 decomp):
    //   a3[0] = TESForm* (the item — what *a3 dereferences)
    //   a3[1] = "extra ref" / stack-tag — if 0, engine computes via
    //           sub_140505440(actor, form, count) for Equip path or
    //           sub_140CE6DF0(...) for Unequip.
    // Original guess "{VMHandle, form*}" was BACKWARDS — caused both
    // calls to early-exit on `if (!*a3) return ...` (log 17:11:18 showed
    // UNEQUIP returned 0 which is the early-exit code in sub_140CE5DA0
    // line 211: `if (!a2 || !*a3) return 0;`). Visually no effect.
    std::uint64_t form_pair[2] = {reinterpret_cast<std::uint64_t>(r.vault_suit), 0};

    // ActorEquipManager::EquipObject(11 args).
    // Signature from re/B8_force_equip_cycle.log section A (sub_140CE5900).
    // Arg layout (NOTE: a4-a5-a6 ORDER differs from Unequip — see
    // offsets.h "B8" block):
    //   a1 = manager singleton
    //   a2 = actor (player)
    //   a3 = form_pair
    //   a4 = count                (1)
    //   a5 = stack_id             (0)
    //   a6 = slot                 (0 = let engine decide)
    //   a7..a11 = various flags (preventRemoval, silent, queued, ...)
    using EquipFn = char (__fastcall*)(
        void*, void*, void*,
        unsigned int,   // a4 count
        int,            // a5 stack_id
        std::int64_t,   // a6 slot
        char, char, char, char, char);

    auto equip = reinterpret_cast<EquipFn>(r.equip_fn);

    FW_LOG("[equip-cycle] EQUIP firing: mgr=%p player=%p suit=%p form=0x%X",
           r.manager, r.player, r.vault_suit, offsets::VAULT_SUIT_FORM_ID);

    char ret = 0;
    __try {
        // Args match the most common caller pattern observed at 4 sites in
        // Fallout4.exe (re/B8_force_equip_cycle.log §C):
        //   sub_140CE5900(mgr, actor, form_pair, count, 1, 0, 0, 0, 1, 0, 0)
        //                                                ↑           ↑
        //                                                a5=1        a9=1
        // 2026-04-28 first attempt with a5=0/a9=0 → SEH 3/3 times. The
        // a5=0 path forces engine to compute stack-id via sub_140505440
        // which faults when the form just had its stack torn down by the
        // preceding unequip. Passing literal 1 skips that path.
        // a9 is a bool flag (purpose unknown — probably "queue" or
        // "preventRemoval"); set to 1 to mirror the working callers.
        ret = equip(
            r.manager,
            r.player,
            form_pair,
            /*count=*/      1,
            /*stack_id=*/   1,   // was 0 → SEH; literal 1 matches callers
            /*slot=*/       0,
            /*a7=*/         0,
            /*a8=*/         0,
            /*a9=*/         1,   // was 0 → SEH; literal 1 matches callers
            /*a10=*/        0,
            /*a11=*/        0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[equip-cycle] EQUIP: SEH caught — engine call faulted");
        g_state.store(CycleState::IDLE);
        return;
    }

    FW_LOG("[equip-cycle] EQUIP returned %d — cycle COMPLETE, BipedAnim "
           "should now be in stable post-cycle state. Peer-connect can "
           "proceed safely.", static_cast<int>(ret));
    g_state.store(CycleState::DONE);
}

void shutdown_equip_cycle() {
    g_worker_should_stop.store(true);
    // Worker is detached; we just signal it. Process exit will reap it.
}

} // namespace fw::hooks
