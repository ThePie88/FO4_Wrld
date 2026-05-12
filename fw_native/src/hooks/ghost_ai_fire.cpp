#include "ghost_ai_fire.h"

#include <windows.h>
#include <intrin.h>    // __readgsqword for TEB::ThreadLocalStoragePointer
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // is_actor_bail_tracked + get_fid_for_aiproc

namespace fw::hooks {

namespace {

// B6.6w0 hook #3 — `CombatBehaviorGunFire::DecideAndFire` @ 0x86FCA0.
//
// History:
//   - Phase A (diagnostic): TLS walk validated; first fire fid 0x46458
//     (Concord raider) identified via AIProcess→fid reverse map.
//   - Phase B (bail tracked): bails ~10 single-shot fires per 30s
//     correctly. Burst/suppressive variants bypass this leaf entirely
//     (C1 dossier open Q1) — only partial coverage.
//   - FireWeapon (sub_140479680) pivot ATTEMPTED 2026-05-12 evening:
//     turned out C1 misidentified that RVA. The function takes
//     `(stack_buf*, Actor*, ..., ...)` not `(Actor*, ...)`. Reverted.
//
// Current state: Phase B on 0x86FCA0. Catches GunFire single-shot only.
// Burst-fire raiders are caught by the SIBLING hook on
// `Actor::DispatchAttackAction @ 0xE6F830` (ghost_ai_dispatch_attack.cpp),
// which is the universal attack funnel.

using GunFireDecideFn = std::int64_t (*)(void);

GunFireDecideFn g_orig_gunfire_decide = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

std::uintptr_t g_module_base = 0;

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static const void* safe_read_ptr_at(const void* base, std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Walk TLS chain from sub_14086FCA0 prologue. Returns AIProcess* on
// success (NOT Actor — we map back to Actor via the npc_ai_suppress
// reverse map populated from Actor+0x328). Returns nullptr on any
// step fault / null. SEH-cased.
//
// Chain (verified live 2026-05-12):
//   tlsIdx = *(u32*)(module_base + 0x3E5C658)
//   tls_array = gs:[0x58]                       // TEB::TLS pointer
//   tls_block = tls_array[tlsIdx]
//   holder    = tls_block + 0x8F0
//   thread    = *holder
//   pr        = *(thread + 0x158)
//   aiproc    = *(pr + 0x68)
static const void* derive_aiproc_from_tls() noexcept {
    __try {
        if (!g_module_base) return nullptr;
        const std::uint32_t tls_idx =
            *reinterpret_cast<const std::uint32_t*>(
                g_module_base + fw::offsets::BEHAVIOR_THREAD_HOLDER_TLSIDX_RVA);
        if (tls_idx >= 1088u) return nullptr;
        void** const tls_array =
            reinterpret_cast<void**>(__readgsqword(0x58));
        if (!tls_array) return nullptr;
        void* const tls_block = tls_array[tls_idx];
        if (!tls_block) return nullptr;
        const void* const holder =
            reinterpret_cast<const std::uint8_t*>(tls_block) +
            fw::offsets::BEHAVIOR_HOLDER_OFFSET;
        const void* const thread = safe_read_ptr_at(holder, 0);
        if (!thread) return nullptr;
        const void* const pr = safe_read_ptr_at(
            thread, fw::offsets::BEHAVIOR_THREAD_PROCESS_OFFSET);
        if (!pr) return nullptr;
        return safe_read_ptr_at(
            pr, fw::offsets::BEHAVIOR_AIPROCESS_ACTOR_OFFSET);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

std::int64_t __fastcall detour_gunfire_decide(void) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        const void* const aiproc = derive_aiproc_from_tls();
        std::uint32_t fid = 0xFFFFFFFFu;
        bool fid_known = false;
        if (aiproc) {
            fid_known = fw::hooks::get_fid_for_aiproc(aiproc, &fid);
        }
        const bool fid_plausible = fid_known &&
            fid != 0 && fid != 0xFFFFFFFFu;

        if (n < 10) {
            FW_LOG("[ghost_ai_fire] fire #%llu aiproc=%p fid=0x%08X "
                   "known=%d plausible=%d",
                   static_cast<unsigned long long>(n), aiproc, fid,
                   fid_known ? 1 : 0, fid_plausible ? 1 : 0);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_fire] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        if (fid_plausible && fid != PLAYER_FORM_ID
            && fw::hooks::should_freeze_actor(fid))
        {
            const auto bn = g_bails.fetch_add(
                1, std::memory_order_relaxed);
            if (bn < 10) {
                FW_LOG("[ghost_ai_fire] BAIL #%llu fid=0x%08X "
                       "(skipping GunFire DecideAndFire)",
                       static_cast<unsigned long long>(bn), fid);
            }
            return 0;
        }

        if (g_orig_gunfire_decide) {
            return g_orig_gunfire_decide();
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_fire] SEH in detour");
        return 0;
    }
}

} // namespace

bool install_ghost_ai_fire(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_fire] already installed; skipping");
        return true;
    }
    g_module_base = module_base;
    const auto target_ea =
        module_base + fw::offsets::COMBAT_GUNFIRE_DECIDE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_gunfire_decide),
        reinterpret_cast<void**>(&g_orig_gunfire_decide));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_fire] CombatBehaviorGunFire::DecideAndFire hook "
               "installed at 0x%llX (RVA 0x%lX) — single-shot variant; "
               "burst/suppressive caught by dispatch_attack hook",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::COMBAT_GUNFIRE_DECIDE_RVA));
    } else {
        FW_ERR("[ghost_ai_fire] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_fire_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_fire_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_fire_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
