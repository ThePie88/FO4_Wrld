// ============================================================================
// DIAGNOSTIC ONLY — 2026-05-17. Installed at install_all.cpp:237. Detour
// passthrough; substitution branch only fires if
// `server.package_form_id != 0` for a tracked actor, which is NEVER set
// in current `raider_brain.py` (raider_brain emits combat_target_form_id
// + movement_override, not package_form_id).
//
// LOG PROOF: Client A `fw_native.log` has the DIAG5 dumps from the first
// 5 inner-predicate fires for offset discovery, then heartbeats. ZERO
// `[ghost_ai_pkg] SUBSTITUTE` lines. ZERO `[ghost_ai_pkg] TRACKED_FIRE`
// lines (= predicate fired with tls_actor_fid in tracked set AND a
// candidate package — but server.package_form_id stays 0, so no substitution
// is even attempted).
//
// WHY KEEP RUNNING:
//   The OUTER selector detour populates the tls_actor_fid bridge that's
//   used by ANY downstream package query inside the AI tick. Even though
//   inner substitution is dormant, the bridge has zero overhead and stays
//   useful as scaffolding for a future redesign that would use
//   server.package_form_id to force tracked NPCs to run server-chosen
//   AI packages (e.g., force a raider to run AI_CombatTakingCover.pkg
//   even if vanilla selection wouldn't pick it).
//
// KEEP-AS-IS RATIONALE:
//   Hook infrastructure is correct. Bridge atomic + inner detour pair
//   is the right mechanism for AI package overrides. Server side just
//   doesn't emit package_form_id today. When/if needed, a single line
//   change in raider_brain.py turns this on.
// ============================================================================

#include "ghost_ai_package.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"

namespace fw::hooks {

namespace {

// Engine signatures.
//
// Inner predicate (per agent 3 dossier — re/B6.5w12_round1_AGENT_3.md):
//   bool __fastcall sub_140768CC0(
//       __int64*** condition_list_head,   // = pkg + 0x60
//       void*      eval_ctx);             // 112-B struct from sub_140768260
//
// Outer selector (per agent 3):
//   bool __fastcall sub_140CEEC30(
//       AIProcess* aiproc,
//       Actor*     actor,
//       char       force_eval);
using PkgEvalConditionsFn = bool (*)(void* condition_list_head, void* eval_ctx);
using PkgSelectorFn       = bool (*)(void* aiproc, void* actor, char force_eval);

PkgEvalConditionsFn g_orig_pkg_eval_conditions = nullptr;
PkgSelectorFn       g_orig_pkg_selector        = nullptr;

// Counters. Hot path is ~1-100 calls/sec per loaded actor (AI ticks
// every ~3 s for full package re-eval, more for forced re-evals); not
// performance-critical to use relaxed.
std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<std::uint64_t> g_selector_fires{0};
std::atomic<std::uint64_t> g_substitutions{0};   // # times we overrode the predicate
std::atomic<std::uint64_t> g_tracked_predicate_fires{0};   // # times predicate fired for a tracked NPC
std::atomic<bool>          g_installed{false};

// (Bridge atomics moved to namespace scope below the anon block — they
// must be accessible from npc_ai_suppress.cpp.)

// SEH-caged primitive reads. noexcept so faults stay contained inside
// the helper — caller gets a sentinel back and the main detour __try
// is not entered. Used for the first-N diagnostic dumps to verify the
// offsets agent 3 dossier inferred (eval_ctx + 8 = Actor*, arg1 - 0x60
// = pkg) before we commit to them in Phase 2 step C decision logic.
[[maybe_unused]] static const void*
safe_read_ptr_at(const void* base, std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

[[maybe_unused]] static std::uint32_t
safe_read_u32_at(const void* base, std::size_t off) noexcept {
    if (!base) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

[[maybe_unused]] static std::uint64_t
safe_read_u64_at(const void* base, std::size_t off) noexcept {
    if (!base) return 0xFFFFFFFFFFFFFFFFull;
    __try {
        return *reinterpret_cast<const std::uint64_t*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFFFFFFFFFull;
    }
}

// Phase 2 step B SKELETON: the detour just calls original and bumps
// counters. No tracked-set lookup, no package_form_id substitution.
//
// What the production detour will do (Phase 4):
//   1. SEH-guarded read of pkg form_id via the offset trick
//        pkg_fid = *(u32*)((char*)arg1 - 0x4C)
//      (since arg1 = pkg + 0x60 and TESForm.formID = pkg + 0x14).
//   2. SEH-guarded read of Actor* via eval_ctx + 8 → Actor.formID at +0x14.
//   3. Cache lookup: if Actor.formID ∈ tracked_set AND server's
//      cache[actor_fid].package_form_id ≠ 0, return
//      (pkg_fid == server.package_form_id).
//   4. Else passthrough to original.
//
// For the skeleton we just want PROOF the detour fires under AI activity.
// First 10 fires + every 1000th get logged. SEH cage wraps the whole body
// so a malformed arg never propagates to the original (defensive).
bool __fastcall detour_pkg_eval_conditions(void* condition_list_head,
                                          void* eval_ctx)
{
    bool result = false;

    // ---- DIAGNOSTIC dump for first N fires --------------------------
    //
    // Before committing decision logic (Phase 2 step C) to agent 3's
    // INFERRED offsets, verify them at runtime. We expect:
    //   - eval_ctx + 8 dereferences to Actor* (the actor whose packages
    //     are being evaluated). Reading Actor + 0x14 should give a
    //     plausible Bethesda form_id (0x00XXXXXX for placed refs,
    //     0xFFXXXXXX for runtime spawns, 0x14 for the local player).
    //   - condition_list_head = pkg + 0x60. So pkg = arg1 - 0x60 and
    //     pkg.form_id = arg1 - 0x60 + 0x14 = arg1 - 0x4C. Reading
    //     should give a TESPackage form_id (mostly 0x000XXXXX since
    //     packages are baked into the ESM).
    //
    // If both reads return plausible values across 20+ samples, agent 3's
    // offsets are correct and we proceed. If either reads garbage / SEH-
    // faults consistently, we need a follow-up RE pass before step C.
    //
    // The reads use SEH-caged helpers that never propagate faults — bad
    // values become 0xFFFFFFFF sentinels, observed in log only.
    const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

    // Snapshot bridged actor state captured by the outer-selector detour.
    const void*         tls_actor_ptr = g_current_actor_ptr.load(
        std::memory_order_relaxed);
    const std::uint32_t tls_actor_fid = g_current_actor_fid.load(
        std::memory_order_relaxed);

    // Extra diagnostic: log first 5 inner fires where actor bridge is
    // non-null — proves the outer→inner bridge actually carries the
    // selector's actor through to the predicate.
    if (tls_actor_fid != 0) {
        static std::atomic<std::uint32_t> diag_nonnull{0};
        const auto dn = diag_nonnull.fetch_add(1, std::memory_order_relaxed);
        if (dn < 5) {
            FW_LOG("[ghost_ai_pkg] BRIDGE-OK #%u tls_actor_fid=0x%08X "
                   "(inner sees outer selector's actor)",
                   dn, tls_actor_fid);
        }
    }

    if (n < 5) {
        // DIAG round 2: full hex-dump of the 112-byte eval_ctx stack
        // buffer. Round 1 showed evalctx+8 = NULL on every sample, so
        // agent 3's inferred "Actor* at v71+8" was wrong. The ctor
        // sub_140768260(v71, Actor, alias, pkg) stores the args
        // somewhere in v71 — we dump 14 qwords (112 bytes) and look
        // for:
        //   - Actor* (heap pointer, looks like 0x000001EFXXXXXXXX
        //     based on prior cond_list values on Side A)
        //   - pkg* (we know it = cond_list - 0x60, e.g.
        //     0x0000021BA7C33450 in last round Side A DIAG #0)
        //   - alias* (heap pointer, unknown identity but distinct)
        //   - actor form_id (0x14 for player, 0x0001CA7D Codsworth,
        //     0x0001D162 Dogmeat, etc — small Bethesda values)
        //
        // 5 fires × 14 qwords = manageable log volume. Also dump the
        // pkg back-compute we trust + the actor-at-+8 attempt that
        // failed last round (for sanity confirmation across re-runs).
        // Round 2 showed evalctx+8 = NULL (agent 3's inference was wrong).
        // Round 2 also showed evalctx+0x28 is STABLE per actor and changes
        // with actor switch → strong candidate for Actor*.
        // Round 3 test: dereference +0x28 and check actor.form_id at +0x14.
        // Also still log the +8 read so we can confirm it stays NULL.
        const void* actor_ptr_at_8 = safe_read_ptr_at(eval_ctx, 8);
        const std::uint32_t actor_fid_at_8 = safe_read_u32_at(actor_ptr_at_8, 0x14);
        const void* actor_ptr_at_28 = safe_read_ptr_at(eval_ctx, 0x28);
        const std::uint32_t actor_fid_at_28 = safe_read_u32_at(actor_ptr_at_28, 0x14);
        const void* pkg_ptr = condition_list_head
            ? reinterpret_cast<const std::uint8_t*>(condition_list_head) - 0x60
            : nullptr;
        const std::uint32_t pkg_fid = safe_read_u32_at(pkg_ptr, 0x14);
        FW_LOG("[ghost_ai_pkg] DIAG5 #%llu cond_list=%p eval_ctx=%p "
               "TLS_actor=%p (fid=0x%08X) selector_fires=%llu "
               "actor@+8=%p (fid=0x%08X) actor@+28=%p (fid=0x%08X) "
               "pkg_ptr=%p pkg_fid=0x%08X",
               static_cast<unsigned long long>(n),
               condition_list_head, eval_ctx,
               tls_actor_ptr, tls_actor_fid,
               static_cast<unsigned long long>(
                   g_selector_fires.load(std::memory_order_relaxed)),
               actor_ptr_at_8, actor_fid_at_8,
               actor_ptr_at_28, actor_fid_at_28,
               pkg_ptr, pkg_fid);

        // Full hex-dump in 4-qword chunks.
        const std::uint64_t q00 = safe_read_u64_at(eval_ctx, 0x00);
        const std::uint64_t q08 = safe_read_u64_at(eval_ctx, 0x08);
        const std::uint64_t q10 = safe_read_u64_at(eval_ctx, 0x10);
        const std::uint64_t q18 = safe_read_u64_at(eval_ctx, 0x18);
        const std::uint64_t q20 = safe_read_u64_at(eval_ctx, 0x20);
        const std::uint64_t q28 = safe_read_u64_at(eval_ctx, 0x28);
        const std::uint64_t q30 = safe_read_u64_at(eval_ctx, 0x30);
        const std::uint64_t q38 = safe_read_u64_at(eval_ctx, 0x38);
        const std::uint64_t q40 = safe_read_u64_at(eval_ctx, 0x40);
        const std::uint64_t q48 = safe_read_u64_at(eval_ctx, 0x48);
        const std::uint64_t q50 = safe_read_u64_at(eval_ctx, 0x50);
        const std::uint64_t q58 = safe_read_u64_at(eval_ctx, 0x58);
        const std::uint64_t q60 = safe_read_u64_at(eval_ctx, 0x60);
        const std::uint64_t q68 = safe_read_u64_at(eval_ctx, 0x68);
        FW_LOG("    evalctx +00..+18: %016llX %016llX %016llX %016llX",
               q00, q08, q10, q18);
        FW_LOG("    evalctx +20..+38: %016llX %016llX %016llX %016llX",
               q20, q28, q30, q38);
        FW_LOG("    evalctx +40..+58: %016llX %016llX %016llX %016llX",
               q40, q48, q50, q58);
        FW_LOG("    evalctx +60..+68: %016llX %016llX",
               q60, q68);
    } else if ((n % 1000) == 0) {
        FW_DBG("[ghost_ai_pkg] fire #%llu (heartbeat, "
               "substitutions=%llu tracked_fires=%llu selector_fires=%llu)",
               static_cast<unsigned long long>(n),
               static_cast<unsigned long long>(
                   g_substitutions.load(std::memory_order_relaxed)),
               static_cast<unsigned long long>(
                   g_tracked_predicate_fires.load(std::memory_order_relaxed)),
               static_cast<unsigned long long>(
                   g_selector_fires.load(std::memory_order_relaxed)));
    }

    // ---- DECISION LOGIC (B6.5w12 Phase 2 step C) --------------------
    //
    // Three-step gate: any miss → passthrough to vanilla AI.
    //   1. TLS actor must be set (predicate fired inside the selector
    //      body — quest/dialog/scene callers see TLS=0 and passthrough).
    //   2. Actor must be in our tracked NPC cache (i.e., server's brain
    //      is authoritatively driving this NPC).
    //   3. Server must have a package_form_id opinion (non-zero).
    // When all three pass, we read the candidate package's form_id from
    // arg1 - 0x4C (DIAG2 confirmed this offset returns plausible TESPackage
    // form_ids like 0x000F39E4, 0x00003896, etc) and return
    //   (candidate_pkg_form_id == server.package_form_id).
    // The engine's selector loops candidates in priority order and picks
    // the first one returning TRUE — so our match wins the slot, vanilla
    // candidates above it lose, and the package executor runs natively.
    if (tls_actor_fid != 0) {
        fw::dispatch::CachedNPCState st{};
        if (fw::dispatch::get_cached_npc_state(tls_actor_fid, &st)) {
            const auto tn = g_tracked_predicate_fires.fetch_add(
                1, std::memory_order_relaxed);
            // Phase 3 diagnostic: log first 30 candidate pkgs seen for
            // tracked NPCs. Builds an empirical census so we know what
            // packages each tracked NPC actually has in its candidate
            // list — needed before we hardcode a server.package_form_id
            // that's guaranteed to win selection.
            if (tn < 30 && condition_list_head != nullptr) {
                const void* pkg_ptr_diag =
                    reinterpret_cast<const std::uint8_t*>(condition_list_head)
                    - 0x60;
                const std::uint32_t cand_pkg_fid_diag =
                    safe_read_u32_at(pkg_ptr_diag, 0x14);
                FW_LOG("[ghost_ai_pkg] TRACKED_FIRE #%llu actor=0x%08X "
                       "candidate_pkg=0x%08X server_pkg=0x%08X",
                       static_cast<unsigned long long>(tn),
                       tls_actor_fid, cand_pkg_fid_diag, st.package_form_id);
            }
            if (st.package_form_id != 0 && condition_list_head != nullptr) {
                // Decode candidate package's form_id (arg1 = pkg + 0x60).
                const void* pkg_ptr =
                    reinterpret_cast<const std::uint8_t*>(condition_list_head)
                    - 0x60;
                const std::uint32_t cand_pkg_fid =
                    safe_read_u32_at(pkg_ptr, 0x14);
                if (cand_pkg_fid != 0xFFFFFFFFu) {
                    const bool match = (cand_pkg_fid == st.package_form_id);
                    const auto sub_n = g_substitutions.fetch_add(
                        1, std::memory_order_relaxed);
                    if (sub_n < 10) {
                        FW_LOG("[ghost_ai_pkg] SUBSTITUTE #%llu actor=0x%08X "
                               "cand_pkg=0x%08X server_pkg=0x%08X -> %s",
                               static_cast<unsigned long long>(sub_n),
                               tls_actor_fid, cand_pkg_fid, st.package_form_id,
                               match ? "TRUE" : "FALSE");
                    }
                    return match;
                }
                // SEH read on pkg form_id failed — fall through to vanilla.
            }
        }
    }

    // ---- passthrough body -------------------------------------------
    __try {
        if (g_orig_pkg_eval_conditions) {
            result = g_orig_pkg_eval_conditions(condition_list_head, eval_ctx);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_pkg] SEH in detour (cond_list=%p eval_ctx=%p) — "
               "returning false to be safe",
               condition_list_head, eval_ctx);
        result = false;
    }
    return result;
}

// Outer-selector detour. Captures the Actor* arg2 in TLS at function
// entry, then calls original. Save/restore of prior TLS value supports
// recursive selector calls (SwapPackage chain → re-entry).
//
// Body of original is NOT touched (agent 3 warned mid-body bails risk
// the package-selection TLS lock — we only intercept ENTRY).
bool __fastcall detour_pkg_selector(void* aiproc, void* actor, char force_eval) {
    // Save and stash. Reading form_id with SEH cage so a bogus actor
    // never propagates a fault.
    const void*         prev_ptr = g_current_actor_ptr.load(
        std::memory_order_relaxed);
    const std::uint32_t prev_fid = g_current_actor_fid.load(
        std::memory_order_relaxed);
    g_current_actor_ptr.store(actor, std::memory_order_relaxed);
    g_current_actor_fid.store(safe_read_u32_at(actor, 0x14),
                              std::memory_order_relaxed);
    const auto sn = g_selector_fires.fetch_add(1, std::memory_order_relaxed);

    if (sn < 10) {
        FW_LOG("[ghost_ai_pkg] SELECTOR fire #%llu aiproc=%p actor=%p "
               "fid=0x%08X force=%d",
               static_cast<unsigned long long>(sn),
               aiproc, actor,
               g_current_actor_fid.load(std::memory_order_relaxed),
               static_cast<int>(force_eval));
    } else if ((sn % 100) == 0) {
        FW_DBG("[ghost_ai_pkg] SELECTOR fire #%llu (heartbeat)",
               static_cast<unsigned long long>(sn));
    }

    bool result = false;
    __try {
        if (g_orig_pkg_selector) {
            result = g_orig_pkg_selector(aiproc, actor, force_eval);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_pkg] selector SEH (aiproc=%p actor=%p force=%d)",
               aiproc, actor, static_cast<int>(force_eval));
    }

    // Restore for the caller's frame.
    g_current_actor_ptr.store(prev_ptr, std::memory_order_relaxed);
    g_current_actor_fid.store(prev_fid, std::memory_order_relaxed);
    return result;
}

} // namespace

// === Bridge atomics (namespace-scope so npc_ai_suppress can write) =====
//
// Live test 2026-05-11 revealed that the package selector sub_140CEEC30
// has an internal early-bail on vt[+0x2E0] truthy → for in-combat
// hostiles (every Concord raider in the MQ102 fight) the iteration never
// runs → inner predicate never fires from the selector body → bridging
// at sub_140CEEC30 entry fails to give the inner predicate any actor
// context. Switched bridge to Actor::Update_PerFrame (npc_ai_suppress)
// which is the universal per-actor AI tick funnel — fires for every
// loaded actor every frame regardless of combat state. Any inner
// predicate fire within Update_PerFrame's call tree (including quest/
// dialog evals that also use sub_140768CC0 with the same Actor in scope)
// reads the bridged actor from these atomics.
std::atomic<std::uint32_t>  g_current_actor_fid{0};
std::atomic<const void*>    g_current_actor_ptr{nullptr};

bool install_ghost_ai_package(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_pkg] already installed; skipping");
        return true;
    }
    // --- Inner predicate (EvaluateConditions) ---
    const auto inner_ea =
        module_base + fw::offsets::PKG_EVAL_CONDITIONS_RVA;
    const bool inner_ok = install(
        reinterpret_cast<void*>(inner_ea),
        reinterpret_cast<void*>(&detour_pkg_eval_conditions),
        reinterpret_cast<void**>(&g_orig_pkg_eval_conditions));
    if (inner_ok) {
        FW_LOG("[ghost_ai_pkg] inner (EvaluateConditions) hook installed "
               "at 0x%llX (RVA 0x%lX)",
               static_cast<unsigned long long>(inner_ea),
               static_cast<unsigned long>(fw::offsets::PKG_EVAL_CONDITIONS_RVA));
    } else {
        FW_ERR("[ghost_ai_pkg] inner hook FAILED at 0x%llX",
               static_cast<unsigned long long>(inner_ea));
    }

    // --- Outer selector (EvaluatePackages_And_Execute, ENTRY-only) ---
    const auto outer_ea =
        module_base + fw::offsets::PKG_SELECTOR_RVA;
    const bool outer_ok = install(
        reinterpret_cast<void*>(outer_ea),
        reinterpret_cast<void*>(&detour_pkg_selector),
        reinterpret_cast<void**>(&g_orig_pkg_selector));
    if (outer_ok) {
        FW_LOG("[ghost_ai_pkg] outer (selector) hook installed "
               "at 0x%llX (RVA 0x%lX) — TLS bridge to inner detour",
               static_cast<unsigned long long>(outer_ea),
               static_cast<unsigned long>(fw::offsets::PKG_SELECTOR_RVA));
    } else {
        FW_ERR("[ghost_ai_pkg] outer hook FAILED at 0x%llX — TLS Actor* "
               "bridge inactive; inner detour will see fid=0",
               static_cast<unsigned long long>(outer_ea));
    }

    const bool both = inner_ok && outer_ok;
    if (both) {
        g_installed.store(true, std::memory_order_release);
    }
    return both;
}

std::uint64_t get_ghost_ai_package_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_package_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
