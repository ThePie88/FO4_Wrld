#include "ghost_ai_dispatch_attack.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // is_actor_bail_tracked

namespace fw::hooks {

namespace {

// `Actor::DispatchAttackAction` per C1 chain.
// Signature inferred from pseudo-C: `(__int64 actor, int action_id, int flags)`.
using DispatchAttackFn = std::int64_t (*)(void* actor, int action_id, int flags);

DispatchAttackFn g_orig_dispatch_attack = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static std::uint32_t safe_read_actor_fid(const void* actor) noexcept {
    if (!actor) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

// Defensive plausibility check.
//
// Bethesda placed form_ids are `0x00XXXXXX`; runtime spawns `0xFF______`.
// `0` is "no form" sentinel, 0xFFFFFFFF is our SEH sentinel. Anything
// else is suspicious — bail the bail-check (= don't bail, passthrough)
// so we never act on garbage.
static bool fid_looks_real(std::uint32_t fid) noexcept {
    if (fid == 0 || fid == 0xFFFFFFFFu) return false;
    const std::uint32_t hi = fid & 0xFF000000u;
    return hi == 0x00000000u || hi == 0xFF000000u;
}

std::int64_t __fastcall detour_dispatch_attack(void* actor, int action_id,
                                               int flags) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t fid = safe_read_actor_fid(actor);
        const bool plausible = fid_looks_real(fid);

        if (n < 10) {
            FW_LOG("[ghost_ai_dispatch] fire #%llu actor=%p fid=0x%08X "
                   "action_id=%d flags=%d plausible=%d",
                   static_cast<unsigned long long>(n), actor, fid,
                   action_id, flags, plausible ? 1 : 0);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_dispatch] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        // BAIL when server has NO active combat opinion. Server-driven
        // combat: when cache.combat_target_form_id != 0 the predicate
        // flips and the attack action passes through, letting the
        // engine fire the weapon.
        if (plausible && fid != PLAYER_FORM_ID
            && fw::hooks::should_silence_combat(fid))
        {
            const auto bn = g_bails.fetch_add(
                1, std::memory_order_relaxed);
            if (bn < 10) {
                FW_LOG("[ghost_ai_dispatch] BAIL #%llu fid=0x%08X "
                       "action=%d (skipping DispatchAttackAction — "
                       "no anim event, no fire, no melee)",
                       static_cast<unsigned long long>(bn), fid,
                       action_id);
            }
            return 0;
        }

        if (g_orig_dispatch_attack) {
            return g_orig_dispatch_attack(actor, action_id, flags);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_dispatch] SEH in detour (actor=%p)", actor);
        return 0;
    }
}

} // namespace

bool install_ghost_ai_dispatch_attack(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_dispatch] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::ACTOR_DISPATCH_ATTACK_ACTION_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_dispatch_attack),
        reinterpret_cast<void**>(&g_orig_dispatch_attack));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_dispatch] Actor::DispatchAttackAction hook "
               "installed at 0x%llX (RVA 0x%lX) — universal attack funnel; "
               "tracked NPCs will skip ALL fire+melee anim events",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(
                   fw::offsets::ACTOR_DISPATCH_ATTACK_ACTION_RVA));
    } else {
        FW_ERR("[ghost_ai_dispatch] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_dispatch_attack_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_dispatch_attack_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_dispatch_attack_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
