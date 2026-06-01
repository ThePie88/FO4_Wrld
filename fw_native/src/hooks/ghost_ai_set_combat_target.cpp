// ============================================================================
// DISABLED in install_all (Build 29 A/B test, see install_all.cpp:160 comment).
// File compiled but install_ghost_ai_set_combat_target() is commented out:
//   // (void)install_ghost_ai_set_combat_target(module_base);
//
// REASON FOR DISABLE:
//   Builds 22-26 (RDX-swap substitution) accumulated 5 distinct crash
//   signatures because the duplicate handle write triggered engine cleanup
//   paths (broadcaster walker, faction map update, combat-state change
//   event) that deref the duplicate's PlayerNPC-inherited fields and AV.
//   The engine-native Fixed-selector path (engine_calls.cpp::
//   install_fixed_selector_on_raider) was chosen as the alternative — but
//   THAT is also dormant (see engine_calls.cpp banner).
//
//   So: neither RDX-swap (this file) NOR Fixed-selector (engine_calls.cpp)
//   actually drives cross-peer aggro in production. Both paths exist as
//   reference for future redesigns.
//
// LOG PROOF: Client A `fw_native.log` 17:29-17:39 has 0× `[ghost_ai_set_target]`
// lines. Hook never installed.
//
// KEEP-AS-IS RATIONALE:
//   This file documents 5 distinct crash chains (Builds 22-26 comments at
//   lines 130-300) and the Build 26 BYPASS-FROM-DUP workaround that solved
//   "transition AWAY from duplicate" AVs. That post-mortem is essential
//   reading if anyone ever revives the RDX-swap approach. Don't delete.
// ============================================================================

#include "ghost_ai_set_combat_target.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"   // get_cached_npc_state
#include "../engine/engine_calls.h"    // lookup_by_form_id
#include "npc_ai_suppress.h"           // get_fid_for_aiproc
#include <windows.h>                    // GetModuleHandleW for direct-write fallback

namespace fw::hooks {

namespace {

// `AIProcess::SetCombatTarget(AIProcess* rcx, Actor* rdx)`.
using SetCombatTargetFn = void (*)(void* aiproc, void* new_target);

SetCombatTargetFn g_orig_set_combat_target = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_substitutions{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

static std::uint32_t safe_read_form_id(const void* form_or_ref) noexcept {
    if (!form_or_ref) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(form_or_ref) +
            fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

// PHASE 2 (2026-05-12) — full substitution.
//
// Decision tree:
//   1. Read owner Actor's form_id via the aiproc→fid map.
//   2. If owner not mapped (unknown actor) → passthrough.
//   3. Query server cache for owner. If
//      `cache.combat_target_form_id != 0`:
//        a. `lookup_by_form_id(cache.combat_target_form_id)` → desired
//           target Actor*.
//        b. If lookup succeeded → swap `new_target` rdx → call orig
//           with our target → AIProcess+0x6C ends up holding the
//           server-chosen form_id → engine aim/fire pipeline uses
//           our target on this client.
//        c. If lookup failed (form_id 0x14 = local player on a client
//           with no PC loaded yet, unlikely but possible) → passthrough.
//   4. Otherwise (no server opinion) → passthrough.
void __fastcall detour_set_combat_target(void* aiproc, void* new_target) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        std::uint32_t owner_fid = 0xFFFFFFFFu;
        const bool owner_known =
            aiproc && fw::hooks::get_fid_for_aiproc(aiproc, &owner_fid);
        const std::uint32_t orig_target_fid = safe_read_form_id(new_target);

        // Server-cache substitution path.
        void* substituted = new_target;
        std::uint32_t srv_target = 0;
        bool did_sub = false;
        // Build 11 — only substitute when engine is SETTING a non-null
        // target. When engine clears combat_target (new_target == null,
        // e.g. after the previous target died), the SetCombatTarget body
        // at funcs_0240.md:5987 does `v5[224] = v28;` where v5 is the OLD
        // target and v28 is the new target's handle. If we substitute a
        // null → duplicate, v5 remains null (engine sees "no prior target
        // to update") → null deref → crash. Live test 2026-05-13 05:18:24
        // (Build 10 Side A): 3 consecutive substitutions of null → duplicate
        // immediately crashed the engine after Side B's player died.
        //
        // The trade-off: when the engine wants to CLEAR (raider has no
        // target now), we passthrough. The raider goes targetless for one
        // engine tick. On the next AI tick, the engine fires SetCombatTarget
        // with a fresh non-null target (the raider's new perception target)
        // — THAT'S when we substitute. Latency: 1 frame (~16ms).
        if (owner_known && new_target != nullptr) {
            fw::dispatch::CachedNPCState st{};
            if (fw::dispatch::get_cached_npc_state(owner_fid, &st)
                && st.combat_target_form_id != 0)
            {
                srv_target = st.combat_target_form_id;
                void* const resolved =
                    fw::engine::lookup_by_form_id(srv_target);
                if (resolved) {
                    substituted = resolved;
                    did_sub = true;
                    g_substitutions.fetch_add(
                        1, std::memory_order_relaxed);
                }
            }
        }

        if (n < 10) {
            FW_LOG("[ghost_ai_set_target] fire #%llu aiproc=%p "
                   "owner_fid=0x%08X owner_known=%d orig_target=%p "
                   "orig_target_fid=0x%08X srv_target_fid=0x%08X "
                   "did_substitute=%d",
                   static_cast<unsigned long long>(n), aiproc, owner_fid,
                   owner_known ? 1 : 0, new_target, orig_target_fid,
                   srv_target, did_sub ? 1 : 0);
        } else if (did_sub) {
            // Log each substitution at INFO at low rate; ~once / sec
            // when combat is hot.
            const auto subs = g_substitutions.load(
                std::memory_order_relaxed);
            if (subs <= 20 || (subs % 50) == 0) {
                FW_LOG("[ghost_ai_set_target] SUBSTITUTE #%llu "
                       "owner_fid=0x%08X srv_target=0x%08X "
                       "(orig_target_fid=0x%08X)",
                       static_cast<unsigned long long>(subs),
                       owner_fid, srv_target, orig_target_fid);
            }
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_set_target] fire #%llu (heartbeat, subs=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_substitutions.load(std::memory_order_relaxed)));
        }

        // ============================================================
        // Build 22 (2026-05-13 evening) — RESTORE the duplicate-handle
        // write, with crash VEH (src/diag/crash_veh.cpp) installed at
        // boot so when the AV fires we capture RIP/fault_addr.
        //
        // Build 21 confirmed the user's hypothesis: with the write
        // commented out, no crash but raiders never aggro on the ghost
        // (vanilla behavior — they attack real_player_A on its own
        // client). So the write IS the crash trigger; we now need the
        // crash to trigger AGAIN to capture diagnostic info.
        //
        // Flow per substitution (build 22):
        //   1. did_sub branch: alloc handle for duplicate via engine
        //      allocator, write to aiproc+0x6C (same as Build 20).
        //   2. Engine's next AI tick reads +0x6C → resolves → duplicate.
        //   3. Engine code derefs duplicate's memcpy'd field → AV.
        //   4. VEH catches the AV first, logs RIP+RVA+fault_addr+stack.
        //   5. EXCEPTION_CONTINUE_SEARCH → game's normal crash handler
        //      runs (typically Bethesda's CrashHandler or default OS).
        //
        // After crash we map RIP RVA to the engine function via decomp
        // (D:\falloutworld_decomp\out\10_decomp\) and identify which
        // field on duplicate was read. That field is then sanitized
        // (zeroed or repointed) in engine_calls.cpp::spawn_native_ghost.
        // ============================================================
        /* Build 21 kill-switch, kept for reference:
        if (g_orig_set_combat_target) {
            g_orig_set_combat_target(aiproc, new_target);
        }
        */

        // Build 23 (2026-05-13 late evening) — use the CACHED handle from
        // engine::spawn_ghost_player instead of re-calling the engine
        // handle allocator per substitution.
        //
        // Agent 8 of the 10-agent crash audit identified the recurring
        // s_alloc invocation as a heap-corruption / fast-fail vector:
        // the duplicate's `+0x28` carries real_player's memcpy'd refcount
        // bits, and the allocator's "is this actor already in the table?"
        // gate reads those bits → racy with real_player's own refcount
        // ops on another thread → undefined behavior → process killed
        // without exception dispatch (= why VEH didn't catch the Build 22
        // crash). Allocating ONCE at spawn — when no other thread is
        // racing the bits yet — was already safe (handle_value logged
        // in the spawn lines). Build 23 reuses that handle.
        //
        // Pass-through case (no substitution): engine call goes normally.
        if (did_sub) {
            const std::uint32_t target_handle =
                fw::engine::get_ghost_duplicate_handle();
            if (target_handle != 0) {
                __try {
                    *reinterpret_cast<std::uint32_t*>(
                        reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C) =
                        target_handle;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            } else {
                // Shouldn't happen: spawn always succeeds in allocating.
                // Log once for observability, then fall through to orig
                // so vanilla AI keeps running (raider attacks real_player_A).
                static std::atomic<bool> warned{false};
                bool expected = false;
                if (warned.compare_exchange_strong(expected, true)) {
                    FW_ERR("[ghost_ai_set_target] cached duplicate handle "
                           "is 0 — spawn didn't allocate? Falling back to "
                           "vanilla SetCombatTarget(orig_target).");
                }
                if (g_orig_set_combat_target) {
                    g_orig_set_combat_target(aiproc, new_target);
                }
            }
        } else {
            // Build 25 (2026-05-13 night) — bypass engine cleanup when the
            // raider is losing aggro AND the old combat_target was our
            // duplicate.
            //
            // Side B Build 24 live test: 1700+ substitutions ran fine
            // (Build 24's vtable expansion fixed slot 267 crash), then
            // 28s after last substitution the engine crashed at RVA
            // 0x79C234 inside sub_14079C1C0 (event broadcaster walker
            // called from sub_1407940A0). The walker iterates
            // qword_1430DBF78[257050]+88's subscriber list. For each
            // subscriber v7 it does:
            //   v8 = (v7 + 40);
            //   (*(_QWORD*)v8 + 8LL)(v8);   // vt[1] on the +0x28 sub-obj
            // The crash is `fault=READ addr=0x8` = deref of NULL+8 → the
            // subscriber's +0x28 contents (= our duplicate's
            // handle-bits/refcount qword, NOT a valid vtable ptr) → call
            // through NULL+8 → AV.
            //
            // Mechanism: when raider's perception clears combat_target,
            // the engine's SetCombatTarget body dispatches a "combat
            // state changed" event. The event broadcaster walks
            // registered subscribers. Our duplicate got registered when
            // we wrote its handle into aiproc+0x6C 1700 times; the
            // subscription list now has duplicate in it. Walker hits
            // duplicate → reads its +0x28 as vtable → AV.
            //
            // Workaround: when (new_target == NULL) AND (current
            // aiproc+0x6C == our duplicate's handle), write 0 directly
            // and SKIP orig. Engine sees "no transition needed" → no
            // event dispatch → no subscriber walk → no crash.
            //
            // Risk: duplicate stays in the subscription list — any
            // OTHER engine sweep that walks the list (cell unload,
            // CombatGroupManager periodic GC, etc.) will still crash.
            // Build 25 is a stop-gap; the real fix is to prevent
            // duplicate from being registered as a subscriber in the
            // first place (or to sanitize its +0x28 to look like a
            // valid vt-ptr structure). Tracked for Build 26.
            // Build 26 (2026-05-13 night, after Build 25 test) —
            // generalize the bypass: trigger on ANY transition AWAY from
            // duplicate (old aiproc+0x6C == cached duplicate handle),
            // not just transition-to-NULL.
            //
            // Build 25 only handled new_target=NULL. Live test showed
            // crashes also on new_target=real_actor (raider acquires
            // new visible target while old was our duplicate):
            //   Side A: AV @ RVA 0x7946D5 sub_140794650, addr=0x14
            //     (engine lookup `sub_1404A8D90` returned NULL; caller
            //     unconditionally dereffed v11[0]+0x14).
            //   Side B: AV @ RVA 0x4CAF43 sub_1404CAE90, addr=0x50
            //     (rcx=NULL, deref [rcx+0x50]).
            // Both faults happen INSIDE orig SetCombatTarget's cleanup
            // chain when the OLD target = duplicate. The cleanup walks
            // some indexed structure (combat group, faction map,
            // perception cache) keyed by duplicate's bad fields →
            // lookup returns NULL → caller unguarded → AV.
            //
            // Skipping orig entirely whenever old=duplicate. We write 0
            // to aiproc+0x6C; the engine's next-tick promoter
            // (sub_14087B080) recalculates target from the Standard
            // selector's known_targets[] cache without going through
            // the crashing cleanup chain.
            //
            // Trade-off: engine doesn't fire the "combat target changed"
            // event for duplicate→X transitions. Affected systems
            // (factions update, perception bookkeeping) are 1-frame
            // late catching up but aiproc+0x6C readers (aim, fire,
            // dispatch) read fresh each tick, so visual behavior
            // recovers immediately.
            std::uint32_t cur_handle = 0;
            __try {
                cur_handle = *reinterpret_cast<std::uint32_t*>(
                    reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            const std::uint32_t dup_handle =
                fw::engine::get_ghost_duplicate_handle();
            const bool old_is_duplicate =
                (cur_handle != 0 && dup_handle != 0 &&
                 cur_handle == dup_handle);

            bool bypassed = false;
            if (old_is_duplicate) {
                __try {
                    *reinterpret_cast<std::uint32_t*>(
                        reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C)
                        = 0;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                static std::atomic<std::uint64_t> bypass_count{0};
                const auto bc = bypass_count.fetch_add(
                    1, std::memory_order_relaxed);
                if (bc < 5 || (bc % 50) == 0) {
                    FW_LOG("[ghost_ai_set_target] BYPASS-FROM-DUP #%llu "
                           "aiproc=%p old=dup_handle=0x%08X "
                           "new_target=%p new_fid=0x%08X "
                           "— skipping orig (avoid cleanup-on-duplicate AV)",
                           static_cast<unsigned long long>(bc),
                           aiproc, dup_handle,
                           new_target, orig_target_fid);
                }
                bypassed = true;
            }
            if (!bypassed && g_orig_set_combat_target) {
                g_orig_set_combat_target(aiproc, substituted);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_set_target] SEH in detour (aiproc=%p)", aiproc);
    }
}

} // namespace

bool install_ghost_ai_set_combat_target(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_set_target] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::AIPROCESS_SET_COMBAT_TARGET_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_set_combat_target),
        reinterpret_cast<void**>(&g_orig_set_combat_target));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_set_target] AIProcess::SetCombatTarget hook "
               "installed at 0x%llX (RVA 0x%lX) — DIAGNOSTIC phase",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(
                   fw::offsets::AIPROCESS_SET_COMBAT_TARGET_RVA));
    } else {
        FW_ERR("[ghost_ai_set_target] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_set_combat_target_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_set_combat_target_substitutions() {
    return g_substitutions.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_set_combat_target_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
