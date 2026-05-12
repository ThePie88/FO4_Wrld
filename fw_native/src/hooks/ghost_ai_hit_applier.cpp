#include "ghost_ai_hit_applier.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // should_freeze_actor

namespace fw::hooks {

namespace {

// `sub_140CD2780(__m128* hit_data, __m128* hit_pos_or_aux)`.
// We don't care about the struct internals — we only read the
// pointer at a1+0x300 (target Actor*) and pass through.
using HitApplierFn = std::int64_t (*)(void* hit_data, void* aux);

HitApplierFn g_orig_hit_applier = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static const void* safe_read_ptr_at(const void* base,
                                    std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

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

static bool fid_looks_real(std::uint32_t fid) noexcept {
    if (fid == 0 || fid == 0xFFFFFFFFu) return false;
    const std::uint32_t hi = fid & 0xFF000000u;
    return hi == 0x00000000u || hi == 0xFF000000u;
}

std::int64_t __fastcall detour_hit_applier(void* hit_data, void* aux) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        // Live test 2026-05-12 evening confirmed: `hit_data` (rcx, a1)
        // IS the target Actor itself, NOT a wrapper. Pseudo-C reads
        // `a1[13].m128_f32[0]` (= a1 + 0xD0) as a NiPoint3 world pos —
        // that's the canonical Actor.pos read. D2 dossier's "+0x300 =
        // target actor pointer" identification was incorrect; +0x300
        // is an internal sub-component (MiddleProcess?) used for the
        // bail check at function start.
        //
        // Correct: target Actor* = hit_data itself; form_id at +0x14.
        const void* const target_actor = hit_data;
        const std::uint32_t target_fid = safe_read_actor_fid(target_actor);
        const bool plausible = fid_looks_real(target_fid);

        // Diagnostic: also peek at +0x300 sub-component so we keep
        // sight of what D2 thought was the actor. First 10 fires log
        // both. If +0x14 yields a tracked raider fid, we're correct.
        const void* const subcomponent = safe_read_ptr_at(
            hit_data, fw::offsets::HIT_DATA_TARGET_ACTOR_OFFSET);

        if (n < 10) {
            FW_LOG("[ghost_ai_hit] fire #%llu target_actor=%p "
                   "target_fid=0x%08X plausible=%d aux=%p "
                   "(subcomponent_at+0x300=%p, kept for diag)",
                   static_cast<unsigned long long>(n), target_actor,
                   target_fid, plausible ? 1 : 0, aux, subcomponent);
        } else if ((n % 500) == 0) {
            FW_DBG("[ghost_ai_hit] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        // BAIL: target is tracked NPC. Skip orchestrator entirely.
        // No stagger, no hit-react, no HP decrement, no ragdoll.
        if (plausible && target_fid != PLAYER_FORM_ID
            && fw::hooks::should_freeze_actor(target_fid))
        {
            const auto bn = g_bails.fetch_add(
                1, std::memory_order_relaxed);
            if (bn < 10) {
                FW_LOG("[ghost_ai_hit] BAIL #%llu target_fid=0x%08X "
                       "(skipping hit orchestrator — no stagger, no "
                       "hit-react, no HP write, no ragdoll)",
                       static_cast<unsigned long long>(bn), target_fid);
            }
            return 0;
        }

        if (g_orig_hit_applier) {
            return g_orig_hit_applier(hit_data, aux);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_hit] SEH in detour (hit_data=%p)", hit_data);
        return 0;
    }
}

} // namespace

bool install_ghost_ai_hit_applier(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_hit] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::ACTOR_HIT_APPLIER_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_hit_applier),
        reinterpret_cast<void**>(&g_orig_hit_applier));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_hit] central hit applier hook installed at "
               "0x%llX (RVA 0x%lX) — bails ALL damage processing for "
               "frozen NPCs (prevents crash from anim graph desync)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::ACTOR_HIT_APPLIER_RVA));
    } else {
        FW_ERR("[ghost_ai_hit] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_hit_applier_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_hit_applier_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_hit_applier_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
