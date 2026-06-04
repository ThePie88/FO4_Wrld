// ============================================================================
// NOT INSTALLED — 2026-05-17. install_all.cpp:246 has only `(void)install_ghost_ai_hit_applier;`
// for ODR; actual install call is commented out.
//
// LOG PROOF: `[ghost_ai_hit]` strings absent from both client logs.
//
// WHY DISABLED:
//   Hook detours central hit-applier `sub_140CD2780`. Bailing it for tracked
//   NPCs would prevent HP decrement, stagger, hit-react anim, and ragdoll.
//   Per the comment at line 137: "anti-crash on damage to frozen NPC" —
//   intended to prevent the engine from trying to apply damage to a tracked
//   NPC whose AI is bailed, which would crash because the anim graph state
//   is desynced.
//
//   In current architecture (raiders never engage ghost), the engine never
//   applies hits TO the ghost on this client (no projectile lands on ghost
//   because raider never fires at ghost). And player_A hitting raiders on
//   their own client goes through vanilla flow. So this hook has nothing
//   to bail in production.
//
// KEEP-AS-IS RATIONALE:
//   Becomes relevant when ANY hit might land on a tracked NPC during the
//   period that NPC's AI is suppressed. Puppet-fire pivot doesn't suppress
//   raider AI (raiders stay statically posed but their +0x328 might or
//   might not be populated), so the freeze-related anim desync may not
//   apply. Revisit during puppet-fire integration test if hit applies to
//   raider produce crashes.
// ============================================================================

#include "ghost_ai_hit_applier.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"     // c.39b: enqueue_npc_damage_claim
#include "npc_ai_suppress.h"   // should_freeze_actor

namespace fw::hooks {

namespace {

// c.39b — HitData (the rdx/`aux` arg) field offsets (Agent 2 RE, 1.11.191).
constexpr std::size_t HITDATA_DAMAGE_OFF = 0x90;  // float: incoming (pre-mitigation) damage

// c.39b — cached module base (set at install) for reading the player singleton.
std::atomic<std::uintptr_t> g_hit_module_base{0};
std::atomic<std::uint64_t>  g_dmg_reports{0};

// c.39b — the LOCAL player's combat-target form_id (PlayerCharacter+0x380).
static std::uint32_t read_local_player_combat_target_fid() noexcept {
    const std::uintptr_t base = g_hit_module_base.load(std::memory_order_relaxed);
    if (!base) return 0;
    __try {
        void* player = *reinterpret_cast<void* const*>(
            base + fw::offsets::PLAYER_SINGLETON_RVA);
        if (!player) return 0;
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(player) +
            fw::offsets::ACTOR_COMBAT_TARGET_FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static float safe_read_float_at(const void* base, std::size_t off) noexcept {
    if (!base) return 0.0f;
    __try {
        return *reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0.0f;
    }
}

// c.39b — precise "is the LOCAL player the attacker?" check (Agent 2 RE).
// HitData(rdx/aux)+0x40 = aggressor BSPointerHandle (u32). Decode via the
// engine's handle table (ptr at module_base+0x30DA390): entry = table[16*idx+8],
// Actor = entry-0x20. Compare to the player singleton. This is ground-truth and
// does NOT depend on the player's combat-target field (which is empty for the
// player, since that mirror is populated only for AI actors picking targets).
constexpr std::uintptr_t HANDLE_TABLE_PTR_RVA       = 0x30DA390;
constexpr std::size_t    HITDATA_AGGRESSOR_HANDLE_OFF = 0x40;

static bool hit_attacker_is_local_player(const void* aux) noexcept {
    const std::uintptr_t base = g_hit_module_base.load(std::memory_order_relaxed);
    if (!base || !aux) return false;
    __try {
        const std::uint32_t h = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(aux) + HITDATA_AGGRESSOR_HANDLE_OFF);
        if (h == 0 || h == 0xFFFFFFFFu) return false;
        const std::uint32_t idx = h & 0x1FFFFFu;
        const std::uintptr_t table = *reinterpret_cast<const std::uintptr_t*>(
            base + HANDLE_TABLE_PTR_RVA);
        if (!table) return false;
        void* entry = *reinterpret_cast<void* const*>(table + 16ull * idx + 8);
        if (!entry) return false;
        const void* attacker = reinterpret_cast<const std::uint8_t*>(entry) - 0x20;
        const void* player = *reinterpret_cast<void* const*>(
            base + fw::offsets::PLAYER_SINGLETON_RVA);
        return attacker != nullptr && attacker == player;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

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

// c.39b — OBSERVE-ONLY. We NEVER bail (bailing suppresses damage — proven by
// the old design). rcx/`hit_data` = victim Actor; rdx/`aux` = HitData (Agent 2).
// When the local player damages the NPC it is currently fighting, report the
// damage so the server's threat table makes ownership/aggro follow the real
// fighter. Then always call the original.
std::int64_t __fastcall detour_hit_applier(void* hit_data, void* aux) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        const std::uint32_t victim_fid = safe_read_actor_fid(hit_data);
        if (fid_looks_real(victim_fid) && victim_fid != PLAYER_FORM_ID) {
            const bool by_player = hit_attacker_is_local_player(aux);
            const float dmg = safe_read_float_at(aux, HITDATA_DAMAGE_OFF);

            // DIAGNOSTIC — first 30 fires + every 1000th: confirms the hook
            // fires, what the (suspected-empty) combat-target reads, and whether
            // the precise attacker decode works. Remove once validated.
            if (n < 30 || (n % 1000) == 0) {
                const std::uint32_t pct = read_local_player_combat_target_fid();
                FW_LOG("[c39b-diag] fire#%llu victim=0x%08X dmg=%.1f "
                       "by_player=%d player_combat_target=0x%08X",
                       static_cast<unsigned long long>(n), victim_fid, dmg,
                       by_player ? 1 : 0, pct);
            }

            if (by_player && dmg > 0.0f && dmg < 1.0e6f) {
                // N3 (2026-06-04) — the damage CLAIM moved to the HP funnel hook
                // (npc_hp_probe / sub_140CC9650). The funnel reports the FINAL
                // post-resist damage + the raider max HP for the shared pool and
                // catches fire/DoT/radiation too; this orchestrator path read
                // PRE-mitigation damage (HitData+0x90). Disabled here to avoid a
                // DOUBLE claim. Kept as a diagnostic only.
                // fw::net::client().enqueue_npc_damage_claim(victim_fid, dmg);
                const auto dn = g_dmg_reports.fetch_add(
                    1, std::memory_order_relaxed);
                if (dn < 20 || (dn % 500) == 0) {
                    FW_LOG("[c39b-diag] orchestrator saw player dmg %.1f to "
                           "fid=0x%08X (claim now via funnel) (#%llu)", dmg,
                           victim_fid, static_cast<unsigned long long>(dn));
                }
            }
        }

        // OBSERVE-ONLY: always pass through. Never suppress damage.
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
    g_hit_module_base.store(module_base, std::memory_order_release);  // c.39b
    const auto target_ea =
        module_base + fw::offsets::ACTOR_HIT_APPLIER_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_hit_applier),
        reinterpret_cast<void**>(&g_orig_hit_applier));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_hit] c.39b OBSERVE-ONLY hit hook installed at "
               "0x%llX (RVA 0x%lX) — reads (victim,damage), reports local "
               "player damage for threat; NEVER bails (passes all hits through)",
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
