#include "ghost_ai_havok_step.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "npc_ai_suppress.h"  // B6.5w17 v3: is_actor_bail_tracked()

namespace fw::hooks {

namespace {

// Engine signature (per pair 5A):
//   void __fastcall sub_1418B9790(bhkCharRigidBodyController* self);
using HavokFinishStepFn = void (*)(void* self);

HavokFinishStepFn g_orig_havok_step = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_tracked_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

static const void* safe_read_ptr_at(const void* base, std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

static std::uint32_t safe_read_u32_at(const void* base, std::size_t off) noexcept {
    if (!base) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

// B6.5w16: PRODUCTION decision logic. Per re/B6.5w16_pair_AGENT_{A,B}.md
// convergence (both 95% conf): owner Actor pointer on bhkCharRigidBodyController
// lives at +0x3E0 (= 992 decimal). Pair 5A round 14 said +32 — WRONG.
//
// Agent B chain: this function reads Havok body pos via vt[53], scales by
// 69.991249, then calls sub_1418B7D10(controller+48, &posVec) which
// dispatches HavokPositionUpdateEvent → per-Actor sinks write Actor pos.
// Bailing this function for tracked NPCs prevents the entire dispatch.
//
// Agent B also confirmed FO4 NPCs use this controller for BOTH alive and
// ragdoll states (differentiated by controller[+768] & 0x20000 flag).
// So one hook covers both.
constexpr std::size_t OWNER_ACTOR_OFF = 0x3E0;  // = 992 decimal
constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

void __fastcall detour_havok_step(void* self) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        // Read owner Actor at correct offset.
        const void* owner = safe_read_ptr_at(self, OWNER_ACTOR_OFF);
        const std::uint32_t fid = safe_read_u32_at(owner, 0x14);

        const bool fid_plausible =
            (fid != 0 && fid != 0xFFFFFFFFu &&
             ((fid & 0xFF000000u) == 0x00000000u ||
              (fid & 0xFF000000u) == 0xFF000000u));

        if (n < 10) {
            FW_LOG("[ghost_ai_havok] fire #%llu self=%p owner@+0x3E0=%p "
                   "fid_at_+14=0x%08X plausible=%d",
                   static_cast<unsigned long long>(n), self, owner, fid,
                   fid_plausible ? 1 : 0);
        } else if ((n % 5000) == 0) {
            FW_DBG("[ghost_ai_havok] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_tracked_fires.load(std::memory_order_relaxed)));
        }

        // Bail gate: tracked NPC + (server movement_override OR in shared
        // dynamic bail set), never player.
        //
        // B6.5w17 v3: the dynamic set is populated by npc_ai_suppress when an
        // actor enters combat (InCombat flag) and gets auto-tracked. Without
        // this OR-clause, Havok kept integrating motion for combat-detected
        // raiders that the server hadn't explicitly tracked — that's why
        // only server-tracked raiders visually froze.
        if (fid_plausible && fid != PLAYER_FORM_ID) {
            bool should_bail = false;
            fw::dispatch::CachedNPCState st{};
            if (fw::dispatch::get_cached_npc_state(fid, &st)
                && st.movement_override != 0)
            {
                should_bail = true;
            } else if (fw::hooks::is_actor_bail_tracked(fid)) {
                should_bail = true;
            }

            if (should_bail) {
                const auto bn = g_tracked_fires.fetch_add(
                    1, std::memory_order_relaxed);
                if (bn < 10) {
                    FW_LOG("[ghost_ai_havok] BAIL #%llu self=%p owner_fid=0x%08X "
                           "(skipping Havok pos sync — body stays put)",
                           static_cast<unsigned long long>(bn), self, fid);
                }
                return;  // ← BAIL: dispatch never fires, sinks never write pos
            }
        }

        if (g_orig_havok_step) {
            g_orig_havok_step(self);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_havok] SEH in detour (self=%p)", self);
    }
}

} // namespace

bool install_ghost_ai_havok_step(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_havok] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::BHK_CHAR_FINISH_STEP_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_havok_step),
        reinterpret_cast<void**>(&g_orig_havok_step));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_havok] bhkCharRigidBodyController::FinishPhysicsStep "
               "DIAGNOSTIC hook installed at 0x%llX (RVA 0x%lX)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::BHK_CHAR_FINISH_STEP_RVA));
    } else {
        FW_ERR("[ghost_ai_havok] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_havok_step_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_havok_step_tracked_fires() {
    return g_tracked_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_havok_step_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
