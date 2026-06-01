#include "ghost_ai_movement.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "../engine/engine_calls.h"   // set_actor_anim_driven
#include "npc_ai_suppress.h"          // B6.5w17 v3: is_actor_bail_tracked()

namespace fw::hooks {

namespace {

// Engine signature (per B6.5w13 root analysis):
//   void __fastcall sub_140C65E20(_QWORD *actor, float dt);
// arg1 = Actor* directly. No bridge needed.
using MovementTickFn = void (*)(void* actor, float dt);

MovementTickFn g_orig_movement_tick = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static std::uint32_t safe_read_actor_fid(const void* actor) noexcept {
    if (!actor) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) + 0x14);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

// B6.5w13 hook #4 v3 — Actor::TickMovementController (wrapper) detour.
//
// Wrapper has Actor* as arg1 directly — no bridge needed. Covers all 3
// movement paths (Update_PerFrame inline, tier walker, CombatManager).
//
// Decision tree:
//   1. Read actor.form_id from arg1 (SEH-safe).
//   2. NEVER bail when actor is the local player (0x14).
//   3. For tracked NPCs with cache.movement_override != 0:
//      - Skip original (engine's MovementControllerNPC::Tick doesn't fire)
//      - Write bAnimationDriven=0 (kill anim root motion translation)
//   4. Otherwise: passthrough.
void __fastcall detour_movement_tick(void* actor, float dt) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t fid = safe_read_actor_fid(actor);

        if (n < 10) {
            FW_LOG("[ghost_ai_mov] fire #%llu actor=%p actor_fid=0x%08X dt=%.4f",
                   static_cast<unsigned long long>(n), actor, fid, dt);
        } else if ((n % 5000) == 0) {
            FW_DBG("[ghost_ai_mov] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        if (fid != PLAYER_FORM_ID && fid != 0 && fid != 0xFFFFFFFFu) {
            bool should_bail = false;
            fw::dispatch::CachedNPCState st{};
            if (fw::dispatch::get_cached_npc_state(fid, &st)
                && st.movement_override != 0)
            {
                should_bail = true;
            } else if (fw::hooks::is_actor_bail_tracked(fid)) {
                // B6.5w17 v3 — combat-detected actor not in server cache.
                should_bail = true;
            }

            // Build 62.9 — UNGATE for raiders in native combat tier.
            // See ghost_ai_havok_step for rationale.
            if (should_bail && fw::engine::native_combat_fid_exists(fid)) {
                should_bail = false;
            }

            if (should_bail) {
                // B6.5w14 cleanup: REMOVED set_actor_anim_driven(false) call.
                // Per re/B6.5w14_pair_AGENT_4B.md (95% conf), bAnimationDriven
                // has zero engine readers in native code — exactly 3 xrefs:
                // 1 string-interner init, 1 init-only writer at graph attach
                // (sub_140CA9520), 1 deinit. Readers only exist in Havok
                // .hkb/.hkx anim graph binary blobs. Our write was a dead
                // write. The real anim root-motion gating happens elsewhere
                // (sub_1403E5140 MovementHandlerAgentAnimationDriven::Update
                // accumulates displacement unconditionally — needs a separate
                // hook with owner-Actor RE).

                const auto bn = g_bails.fetch_add(
                    1, std::memory_order_relaxed);
                if (bn < 10) {
                    FW_LOG("[ghost_ai_mov] BAIL #%llu actor_fid=0x%08X "
                           "(skipping wrapper)",
                           static_cast<unsigned long long>(bn), fid);
                }
                return;  // ← BAIL: don't call original
            }
        }

        // Passthrough.
        if (g_orig_movement_tick) {
            g_orig_movement_tick(actor, dt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_mov] SEH in detour (actor=%p dt=%.4f)", actor, dt);
    }
}

} // namespace

bool install_ghost_ai_movement(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_mov] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::MOVEMENT_TICK_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_movement_tick),
        reinterpret_cast<void**>(&g_orig_movement_tick));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_mov] Actor::TickMovementController hook "
               "installed at 0x%llX (RVA 0x%lX) — bail when "
               "movement_override set",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::MOVEMENT_TICK_RVA));
    } else {
        FW_ERR("[ghost_ai_mov] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_movement_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_movement_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_movement_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
