// ============================================================================
// LIVE BAIL — 2026-05-17 log evidence: detour fires under natural raider
// combat (raiders aggro'd on player_A's NATURAL combat — NOT the ghost),
// bails when should_silence_combat returns true.
//
// LOG PROOF (Client A `fw_native.log` 17:32:06-17:32:18):
//   [ghost_ai_fire] BAIL #0 fid=0x00046459 (skipping GunFire DecideAndFire)
//   [ghost_ai_fire] BAIL #1 fid=0x00046459 ...
//   ...up to BAIL #9 fid=0x00046458...
//   (only 10 BAIL entries logged due to log-throttle; counter g_bails
//    likely much higher across the full session)
//
// WHEN BAIL FIRES:
//   - Raider naturally engages combat with player_A (engine sets +0x328,
//     EnterCombat runs)
//   - npc_ai_suppress observes InCombat → server gets NPC_DISCOVER →
//     server registers raider → movement_override=1 in BCAST
//   - Server says combat_target_form_id == 0 (between aggro-resolution
//     bursts) OR == 0x14 (vanilla local target)
//   - should_silence_combat: registered + target=0 → returns TRUE
//   - Detour bails → no GunFire decide → raider doesn't fire
//
// BUILD 43 STICKY BYPASS:
//   should_silence_combat first checks `is_ghost_engaged_raider_fid(fid)`.
//   That set is populated by install_fixed_selector_on_raider which is
//   DORMANT (see engine_calls.cpp banner). So the sticky bypass never
//   triggers → raider stays vulnerable to silence when server-cache
//   oscillates back to combat_target=0. Net effect: ghost-engaged-vibes
//   raider goes idle within ~2 seconds of any cache flicker.
//
// WHY KEEP RUNNING:
//   Single-shot raiders firing at player_A is fine (vanilla flow). Burst
//   variants are caught at ghost_ai_dispatch_attack.cpp (universal funnel).
//   This hook PREVENTS the raider from firing on the local player AFTER
//   server has decided cross-peer aggro switched away — fixing what would
//   otherwise be "raider keeps shooting peer A even though server says
//   target is peer B".
//
//   In current architecture (cross-peer aggro never actually engages
//   ghost on client), this means: server says "target=player_B" → raider
//   silenced → raider idle. That's bad UX but at least consistent across
//   clients.
//
//   THE FIX IS NOT IN THIS FILE. Fix is in the puppet-fire path
//   (re/AI_pipeline/section_08 §0): server emits NPC_FIRE events with
//   explicit (raider, target=ghost_pos) tuples, client executes the
//   3-call recipe (force weapon-state + write aim + WeaponFireHandler).
//   That bypass produces visible projectiles regardless of GunFire
//   DecideAndFire being bailed here.
// ============================================================================

#include "ghost_ai_fire.h"

#include <windows.h>
#include <intrin.h>    // __readgsqword for TEB::ThreadLocalStoragePointer
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // is_actor_bail_tracked + get_fid_for_aiproc
#include "../main_thread_dispatch.h"  // Build 55a: is_raider_currently_ghost_targeted
#include "../engine/engine_calls.h"   // Build 62.11: native_combat_fid_exists
#include "ownership_manager.h"        // Build 65.c.16: is_owner_of()
#include "../net/client.h"            // Build 65.c.16: enqueue_npc_fire_from_owner

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
std::atomic<std::uint64_t> g_emits{0};  // Build 65.c.16 — NPC_FIRE_FROM_OWNER emits
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

        // Build 65.c.16 — owner-driven fire detection.
        //
        // The legacy Build 55a / 62.11 BAIL paths (should_silence_combat,
        // ghost-target window) were tied to the server raider_brain which
        // is now silenced (65.c.13). In owner-driven mode the engine's
        // vanilla GunFire DecideAndFire is the authoritative decision for
        // every NPC the local peer owns: run it unconditionally, then if
        // we own this fid, propagate a NPC_FIRE_FROM_OWNER frame so
        // non-owner peers can replay the shot via
        // engine::fire_actor_weapon (projectile + muzzle flash + audio).
        //
        // Build 65.c.20 — NON-OWNER BAIL (L1 paired fix).
        //
        // Rationale: Build 65.c.20 reverts npc_ai_suppress non-owner
        // bail (Update_PerFrame now runs vanilla for non-owner raiders
        // so the behavior tree can advance and anim transitions fire).
        // That re-enables the engine's local fire path on non-owners
        // → projectile spawn / muzzle flash duplicated (owner client
        // also fires via NPC_FIRE_FROM_OWNER replay). We avoid the
        // duplication by gating fire DECISION here: if we're not the
        // authoritative owner, skip the engine's GunFire DecideAndFire
        // entirely. Receiver-side NPC_FIRE_FROM_OWNER (relayed from
        // owner) is the sole fire trigger on non-owner clients.
        //
        // Owners: original behavior preserved (orig runs + OWNER-EMIT).
        if (fid_plausible &&
            fid != PLAYER_FORM_ID &&
            fw::ownership::is_non_owner_tracked(fid))
        {
            const auto bn = g_bails.fetch_add(
                1, std::memory_order_relaxed);
            if (bn < 5 || (bn % 500) == 0) {
                FW_LOG("[ghost_ai_fire] NON-OWNER BAIL #%llu fid=0x%08X "
                       "(prevents dual-fire; receiver replays via "
                       "NPC_FIRE_FROM_OWNER)",
                       static_cast<unsigned long long>(bn), fid);
            }
            return 0;
        }

        // Owner path (or untracked NPCs — fallback to Build 64 behavior).
        std::int64_t ret = 0;
        if (g_orig_gunfire_decide) {
            ret = g_orig_gunfire_decide();
        }

        // Build 65.c.17 — relaxed gate: was `ret != 0` (treating engine
        // return as "fired this frame") but live test showed that
        // condition never fires: `ret` from the GunFire behavior is a
        // behavior-tree status (RUNNING/SUCCESS/FAILURE), not a fire
        // indicator. Result: zero NPC_FIRE_FROM_OWNER ever emitted.
        // New gate: emit per detour-tick for any NPC we own. Detour
        // fires ~2-4× per raider per second in active combat (visible
        // in fire #N rate from logs), tolerable bandwidth and the
        // receiver-side engine::fire_actor_weapon is idempotent (no-ops
        // when raider's weapon is mid-cooldown). Worst case = receiver
        // sees slightly more muzzle flashes than the owner; acceptable.
        if (fid_plausible &&
            fid != PLAYER_FORM_ID &&
            fw::ownership::is_owner_of(fid))
        {
            const auto en = g_emits.fetch_add(
                1, std::memory_order_relaxed);
            if (en < 10 || (en % 500) == 0) {
                FW_LOG("[ghost_ai_fire] OWNER-EMIT #%llu fid=0x%08X "
                       "ret=%lld",
                       static_cast<unsigned long long>(en), fid,
                       static_cast<long long>(ret));
            }
            // Minimal payload — receiver's engine::fire_actor_weapon
            // auto-acquires target and uses the raider's currently
            // equipped weapon, so target_fid/weapon_fid/aim hints can
            // stay zero in Phase A. ts_ms is wall-clock for receiver
            // lerp/log.
            fw::net::NPCFireFromOwnerPayload p{};
            p.form_id        = fid;
            p.target_form_id = 0;
            p.weapon_form_id = 0;
            p.aim_x          = 0.0f;
            p.aim_y          = 0.0f;
            p.aim_z          = 0.0f;
            p.ts_ms          = static_cast<std::uint64_t>(GetTickCount64());
            fw::net::client().enqueue_npc_fire_from_owner(p);

            // Build 65.c.24 — Signal 3 of the multi-signal anim_state
            // aggregation: stamp recent-fire timestamp so the npc_ai_
            // suppress owner-capture sees "in combat" via S3 even if
            // bit 0x4000 (S1) and CombatController+0x98 (S2) are both 0
            // in the capture frame (per-frame oscillation observed in
            // c.22/c.23 test). Sticky for RECENT_FIRE_WINDOW_MS = 1500.
            fw::dispatch::mark_owner_actor_fired(fid);
        }

        return ret;
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
