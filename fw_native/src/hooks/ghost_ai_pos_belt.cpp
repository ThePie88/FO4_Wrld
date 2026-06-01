#include "ghost_ai_pos_belt.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "npc_ai_suppress.h"  // B6.5w17 v3: is_actor_bail_tracked()
#include "ownership_manager.h"  // Build 65: owner-driven predicate
#include "container_hook.h"   // B6.6w5: tls_applying_remote for engine::apply_npc_pos bypass
#include "../engine/engine_calls.h"  // Build 62.9: native_combat_fid_exists

namespace fw::hooks {

namespace {

// Engine signature (per re/B6.5w13_root_AGENT_2.md):
//   void __fastcall sub_140513A80(TESObjectREFR* refr, float pos[3]);
using SetPositionFn = void (*)(void* refr, void* pos);

SetPositionFn g_orig_set_position = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static std::uint32_t safe_read_refr_fid(const void* refr) noexcept {
    if (!refr) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(refr) + 0x14);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

// Belt-and-braces bail: for tracked NPCs with movement_override, skip
// the pos write entirely. Engine's pos field stays at its last value.
void __fastcall detour_set_position(void* refr, void* pos) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t fid = safe_read_refr_fid(refr);

        if (n < 10) {
            // dump pos for diag
            float px = 0, py = 0, pz = 0;
            __try {
                px = *reinterpret_cast<const float*>(pos);
                py = *(reinterpret_cast<const float*>(pos) + 1);
                pz = *(reinterpret_cast<const float*>(pos) + 2);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            FW_LOG("[ghost_ai_pos] fire #%llu refr=%p fid=0x%08X "
                   "pos=(%.1f,%.1f,%.1f)",
                   static_cast<unsigned long long>(n), refr, fid, px, py, pz);
        } else if ((n % 5000) == 0) {
            FW_DBG("[ghost_ai_pos] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        if (fid != PLAYER_FORM_ID && fid != 0 && fid != 0xFFFFFFFFu) {
            // B6.6w5: receiver-side engine::apply_npc_pos sets this TLS
            // flag so OUR detour passthroughs and the write goes through.
            // Without this bypass, our hook would bail our own apply path.
            if (fw::hooks::tls_applying_remote) {
                if (g_orig_set_position) g_orig_set_position(refr, pos);
                return;
            }

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

            // Build 65 — owner-driven override (with fallback).
            if (fw::ownership::is_owner_of(fid)) {
                should_bail = false;
            } else if (fw::ownership::is_non_owner_tracked(fid)) {
                should_bail = true;
            }

            if (should_bail) {
                const auto bn = g_bails.fetch_add(
                    1, std::memory_order_relaxed);
                if (bn < 10) {
                    FW_LOG("[ghost_ai_pos] BAIL #%llu refr_fid=0x%08X "
                           "(skipping SetPosition_NiPoint3 — pos write blocked)",
                           static_cast<unsigned long long>(bn), fid);
                }
                return;  // ← BAIL
            }
        }

        if (g_orig_set_position) {
            g_orig_set_position(refr, pos);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_pos] SEH in detour (refr=%p)", refr);
    }
}

} // namespace

bool install_ghost_ai_pos_belt(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_pos] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::SETPOSITION_NIPOINT3_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_set_position),
        reinterpret_cast<void**>(&g_orig_set_position));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_pos] TESObjectREFR::SetPosition_NiPoint3 hook "
               "installed at 0x%llX (RVA 0x%lX) — belt-and-braces bail",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::SETPOSITION_NIPOINT3_RVA));
    } else {
        FW_ERR("[ghost_ai_pos] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_pos_belt_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_pos_belt_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_pos_belt_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
