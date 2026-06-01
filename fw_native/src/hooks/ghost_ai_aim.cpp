// ============================================================================
// DIAGNOSTIC ONLY — 2026-05-17. Hook installed (install_all.cpp:239) but
// detour is pure passthrough. Detour logs the first 5 fires for owner-Actor
// offset discovery, then heartbeat every 1000 calls. NO substitution.
//
// LOG PROOF: Client A `fw_native.log` 17:29-17:39 has 0× `[ghost_ai_aim]` lines.
// That means CombatAimController::SetAimTarget (sub_140E65820) is NEVER called
// in current architecture — because:
//   - Engine calls SetAimTarget inside the combat orchestrator's aim-update
//     chain, which only runs when raider has a valid combat_target (aiproc+
//     0x6C resolves to a real Actor).
//   - For server-aggro'd raiders with target=ghost, aiproc+0x6C never gets
//     set to ghost_handle (Fixed selector dormant, RDX-swap disabled).
//   - For naturally-aggro'd raiders (target=player_A), the aim chain runs
//     vanilla and we observe NO log here either — suggesting the hook
//     installation may have failed silently (no `[ghost_ai_aim] hook
//     installed at` line in log).
//
// VERIFY: check install_all summary in log:
//   `hooks: install summary ... ghost_ai_aim=1 ...` — install reports OK.
//   But still 0 fires. Suggests sub_140E65820 isn't hit on these raiders.
//
// WHY IT MATTERS FOR THE PUPPET-FIRE STRATEGY:
//   re/AI_pipeline/section_08 §0 prescribes calling sub_140E65820 directly
//   from C++ to write aim before each NPC_FIRE event. To do that we need:
//     (a) the CombatAimController pointer for the raider — likely at
//         AIProcess+0xN (TBD, need RE pass);
//     (b) the function pointer for sub_140E65820 (RVA = 0x00E65820 per
//         re/AI_pipeline/section_06 §C, address fw::offsets::AIM_SET_TARGET_RVA
//         already defined).
//   This file's DIAG dump (first 5 fires) was DESIGNED to discover the
//   owner Actor offset chain. Since it never fires, we can't extract that
//   from runtime — must come from static RE.
//
// KEEP-AS-IS RATIONALE:
//   The instrumented detour is the right tool to discover offsets if/when
//   sub_140E65820 ever starts firing on tracked raiders. Counters + first-N
//   logging are zero-cost when fires=0.
// ============================================================================

#include "ghost_ai_aim.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"

namespace fw::hooks {

namespace {

// Engine signature (per agent 1):
//   void __fastcall sub_140E65820(CombatAimController* self,
//                                 NiPoint3* target_pos);
// target_pos: 3 floats packed (x, y, z) in world space.
using AimSetTargetFn = void (*)(void* self, void* target_pos);

AimSetTargetFn g_orig_aim_set_target = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

static std::uint64_t safe_read_u64_at(const void* base, std::size_t off) noexcept {
    if (!base) return 0xFFFFFFFFFFFFFFFFull;
    __try {
        return *reinterpret_cast<const std::uint64_t*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFFFFFFFFFull;
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

static float safe_read_f32_at(const void* base, std::size_t off) noexcept {
    if (!base) return 0.0f;
    __try {
        return *reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0.0f;
    }
}

// SKELETON detour. First 5 fires: dump candidate offsets on the
// CombatAimController + chain through self+16 (= CombatController per
// agent 1) trying to find the owner Actor via a form_id read.
//
// Heuristic: if a pointer's *(u32*)(ptr + 0x14) reads a plausible
// Bethesda form_id (0x00XXXXXX placed or 0xFFXXXXXX runtime spawn, NOT
// 0xFFFFFFFF SEH-sentinel and NOT 0), we mark it as a candidate owner.
//
// After collecting samples we'll know which offset chain to use for
// step B substitution.
void __fastcall detour_aim_set_target(void* self, void* target_pos) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        if (n < 5) {
            // Dump target_pos contents (3 floats).
            const float tgt_x = safe_read_f32_at(target_pos, 0);
            const float tgt_y = safe_read_f32_at(target_pos, 4);
            const float tgt_z = safe_read_f32_at(target_pos, 8);

            // Candidate chains to identify owner Actor:
            //   A. self + 0 / 8 / 16 / 24 / 32 / 48 / 64 / 96 / 104
            //      → try to read *(u32*)(candidate + 0x14) as form_id
            //   B. self + 16 (= CombatController per agent 1) → walk
            //      its offsets 0/8/16/24/32/48/96/104/128/136/376
            const void* p_self_8   = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x08));
            const void* p_self_10  = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x10));
            const void* p_self_18  = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x18));
            const void* p_self_20  = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x20));
            const void* p_self_40  = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x40));
            const void* p_self_60  = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x60));
            const void* p_self_68  = reinterpret_cast<const void*>(safe_read_u64_at(self, 0x68));

            // CombatController* (per agent 1) sits at self + 16. Walk its
            // children too — owner Actor likely accessible from here.
            const void* p_cc       = p_self_10;
            const void* p_cc_8     = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x08));
            const void* p_cc_10    = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x10));
            const void* p_cc_18    = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x18));
            const void* p_cc_20    = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x20));
            const void* p_cc_68    = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x68));   // +104
            const void* p_cc_80    = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x80));   // +128
            const void* p_cc_178   = reinterpret_cast<const void*>(safe_read_u64_at(p_cc, 0x178));  // +376

            FW_LOG("[ghost_ai_aim] DIAG #%llu self=%p target=(%.1f,%.1f,%.1f)",
                   static_cast<unsigned long long>(n), self, tgt_x, tgt_y, tgt_z);
            FW_LOG("    self deref candidates (form_ids at +0x14):");
            FW_LOG("      self+08=%p fid=0x%08X", p_self_8,  safe_read_u32_at(p_self_8,  0x14));
            FW_LOG("      self+10=%p fid=0x%08X (= CombatController* per agent 1)", p_self_10, safe_read_u32_at(p_self_10, 0x14));
            FW_LOG("      self+18=%p fid=0x%08X", p_self_18, safe_read_u32_at(p_self_18, 0x14));
            FW_LOG("      self+20=%p fid=0x%08X", p_self_20, safe_read_u32_at(p_self_20, 0x14));
            FW_LOG("      self+40=%p fid=0x%08X", p_self_40, safe_read_u32_at(p_self_40, 0x14));
            FW_LOG("      self+60=%p fid=0x%08X", p_self_60, safe_read_u32_at(p_self_60, 0x14));
            FW_LOG("      self+68=%p fid=0x%08X", p_self_68, safe_read_u32_at(p_self_68, 0x14));
            FW_LOG("    CombatController (self+16) deref candidates:");
            FW_LOG("      cc+08=%p fid=0x%08X",   p_cc_8,   safe_read_u32_at(p_cc_8,   0x14));
            FW_LOG("      cc+10=%p fid=0x%08X",   p_cc_10,  safe_read_u32_at(p_cc_10,  0x14));
            FW_LOG("      cc+18=%p fid=0x%08X",   p_cc_18,  safe_read_u32_at(p_cc_18,  0x14));
            FW_LOG("      cc+20=%p fid=0x%08X",   p_cc_20,  safe_read_u32_at(p_cc_20,  0x14));
            FW_LOG("      cc+68(+104)=%p fid=0x%08X (= 'target form-id handle' per agent 1)",
                   p_cc_68,  safe_read_u32_at(p_cc_68,  0x14));
            FW_LOG("      cc+80(+128)=%p fid=0x%08X (= 'best target ptr' per agent 1)",
                   p_cc_80,  safe_read_u32_at(p_cc_80,  0x14));
            FW_LOG("      cc+178(+376)=%p fid=0x%08X (= 'override target ptr' per agent 1)",
                   p_cc_178, safe_read_u32_at(p_cc_178, 0x14));
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_aim] fire #%llu (heartbeat)",
                   static_cast<unsigned long long>(n));
        }

        if (g_orig_aim_set_target) {
            g_orig_aim_set_target(self, target_pos);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_aim] SEH in detour (self=%p target=%p)",
               self, target_pos);
    }
}

} // namespace

bool install_ghost_ai_aim(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_aim] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::AIM_SET_TARGET_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_aim_set_target),
        reinterpret_cast<void**>(&g_orig_aim_set_target));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_aim] CombatAimController::SetAimTarget hook "
               "installed at 0x%llX (RVA 0x%lX) — SKELETON, owner-ptr diag",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::AIM_SET_TARGET_RVA));
    } else {
        FW_ERR("[ghost_ai_aim] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_aim_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_aim_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
