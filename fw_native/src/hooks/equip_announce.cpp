// =============================================================================
// equip_announce — implementation. See equip_announce.h for the full
// architectural rationale, NON TESTATO banner, and wire-up instructions.
// =============================================================================
//
// !!! THIS CODE IS UNTESTED — NOT INVOKED AT RUNTIME (2026-05-08) !!!
//
// The skeleton (worker thread, message dispatch, arm-state machine) is
// complete and modeled on `equip_cycle.cpp`'s pattern (B8). The actual
// BipedAnim enumeration in `on_equip_announce_fire_message` is a TODO
// block — it needs RE work before this module can do real work.
// =============================================================================

#include "equip_announce.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

#include "../log.h"
#include "../main_thread_dispatch.h"   // get_target_hwnd

namespace fw::hooks {

namespace {

// WM_APP message offset for the announce trigger.
//
// Offset map snapshot at scaffold time (2026-05-08, see
// `main_thread_dispatch.h` for the canonical list — keep this comment in
// sync if you add more messages):
//   0x4F = FW_MSG_WEAPON_CAPTURE_FINALIZE      (taken)
//   0x50 = FW_MSG_SPAI_PREWARM (Tier 1)        (taken)
//   0x51 = FW_MSG_LOCK_APPLY (B6.3)            (taken)
//   0x52 = FW_MSG_EQUIP_ANNOUNCE_FIRE          ← NEW (this module)
constexpr UINT FW_MSG_EQUIP_ANNOUNCE_FIRE = WM_APP + 0x52;

// State machine — mirrors equip_cycle.cpp's CycleState. Same semantics:
// ARMED while worker is sleeping; FIRING while message dispatched (handler
// running on main thread); DONE after handler returns.
enum class AnnounceState : int {
    IDLE   = 0,
    ARMED  = 1,
    FIRING = 2,
    DONE   = 3,
};
std::atomic<AnnounceState> g_state{AnnounceState::IDLE};

std::thread g_worker;
std::atomic<bool> g_worker_should_stop{false};

// Worker thread body: sleeps `delay_ms`, posts the FIRE message. Mirror
// of equip_cycle.cpp's worker_main but single-shot (no two-phase like B8).
void worker_main(unsigned int delay_ms) {
    FW_LOG("[equip-announce] worker armed, will fire in %ums", delay_ms);

    // Wait the initial delay (50ms granularity for shutdown response).
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(delay_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (g_worker_should_stop.load()) {
            FW_LOG("[equip-announce] worker shutdown requested — abort");
            g_state.store(AnnounceState::IDLE);
            return;
        }
        Sleep(50);
    }

    HWND hwnd = fw::dispatch::get_target_hwnd();
    if (!hwnd) {
        FW_ERR("[equip-announce] worker: no target HWND — main_menu WndProc "
               "subclass not yet installed; announce aborted");
        g_state.store(AnnounceState::IDLE);
        return;
    }

    g_state.store(AnnounceState::FIRING);
    if (!PostMessageW(hwnd, FW_MSG_EQUIP_ANNOUNCE_FIRE, 0, 0)) {
        FW_ERR("[equip-announce] worker: PostMessage FIRE failed (err=%lu)",
               GetLastError());
        g_state.store(AnnounceState::IDLE);
        return;
    }
    FW_LOG("[equip-announce] worker: FIRE message posted (WM_APP+0x52)");
    // State moves to DONE inside the message handler after enumeration
    // completes (or back to IDLE on early-out so re-arm via peer-join is
    // possible).
}

} // anon namespace

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

void arm_equip_announce_after_loadgame(unsigned int delay_ms) {
    auto expected = AnnounceState::IDLE;
    if (!g_state.compare_exchange_strong(expected, AnnounceState::ARMED)) {
        FW_DBG("[equip-announce] arm: already armed/in-progress (state=%d), "
               "no-op", static_cast<int>(expected));
        return;
    }

    g_worker_should_stop.store(false);
    g_worker = std::thread(&worker_main, delay_ms);
    g_worker.detach();   // signal-via-flag; process exit reaps
}

void arm_equip_announce_for_peer_join(unsigned int delay_ms) {
    // Allowed transitions: IDLE → ARMED (first ever) OR DONE → ARMED
    // (re-arm after a previous announce completed). Reject transitions
    // from ARMED / FIRING (announce already in-flight; would race).
    auto current = g_state.load(std::memory_order_acquire);
    while (true) {
        if (current != AnnounceState::IDLE && current != AnnounceState::DONE) {
            FW_DBG("[equip-announce] peer-join arm: announce in-flight "
                   "(state=%d), skipping re-arm — current cycle's broadcast "
                   "will reach the new peer anyway",
                   static_cast<int>(current));
            return;
        }
        if (g_state.compare_exchange_weak(current, AnnounceState::ARMED,
                                           std::memory_order_acq_rel)) {
            break;
        }
        // CAS failed → current was reloaded; loop retries.
    }

    FW_LOG("[equip-announce] peer-join arm: re-firing announce in %ums to "
           "broadcast current apparel state to newly-joined peer", delay_ms);

    g_worker_should_stop.store(false);
    if (g_worker.joinable()) {
        g_worker.detach();
    }
    g_worker = std::thread(&worker_main, delay_ms);
    g_worker.detach();
}

void on_equip_announce_fire_message() {
    // ====================================================================
    //
    //   !!! NON TESTATO — UNTESTED CODE PATH — DO NOT TRUST !!!
    //
    //   This handler is the heart of the announce feature. The
    //   skeleton (state machine, log markers, return paths) is in
    //   place but the actual BipedAnim enumeration is a TODO that
    //   requires RE work to fill in.
    //
    // ====================================================================

    FW_WRN("[equip-announce] FIRE handler called — but enumeration is not "
           "implemented yet (NON TESTATO scaffold). No EQUIP_OPs will be "
           "broadcast. See `equip_announce.h` header banner + `equip_announce."
           "cpp` TODO block for what's needed.");

    // ====================================================================
    // TODO — RE WORK NEEDED BEFORE THIS HANDLER DOES ANYTHING USEFUL
    // ====================================================================
    //
    // 1. Find the offset of `BipedAnim*` on PlayerCharacter (or its Actor
    //    base). Decomp source:
    //      D:\falloutworld_decomp\out\10_decomp\
    //    Search hints:
    //      - grep for "BGSBipedObjectForm" — gives form-side layout.
    //        Existing notes in offsets.h (~line 733) document slot
    //        bitmask at +0x1E8 of TESObjectARMO. That's the FORM
    //        side (template), not the runtime per-actor table.
    //      - grep for "biped_anim" / "BipedAnim" in 10_decomp.
    //      - grep for callers of any function that takes Actor* and
    //        returns/uses the worn-equipment table.
    //      - re/M9_*_dossier.txt files may already document this:
    //        the witness pattern walks BipedAnim post-equip to extract
    //        NIF descriptors, so the offset is known there.
    //
    // 2. Determine the slot count and per-slot record layout. Likely
    //    structure (verify):
    //      struct BipedAnimSlot {
    //          TESForm* equipped_item;   // 0 = empty
    //          ... (NIF*, ARMA*, etc.)
    //      };
    //    Apparel slot indices to enumerate are documented in
    //    `re/biped_slots.md` and `offsets.h` "M9 wedge 3" block.
    //    Roughly: slot 0 (HAIR), 1 (BODY), 2 (HEAD), 3 (HEAD_GEAR),
    //    etc. Excluded: weapon slots and the special PIPBOY slot
    //    that's always present.
    //
    // 3. For each non-empty apparel slot:
    //      a. Read TESForm* equipped at slot N.
    //      b. SEH-protected (form pointer may be in flux during cell
    //         streaming; never AV without a __try wrapper).
    //      c. Read form_id at TESForm+0x14 (uint32).
    //      d. Filter out weapon-kind forms — TESForm.formType at
    //         offset 0x40 (1 byte, see offsets.h FORM_TYPE_OFF). Skip
    //         if formType == FORM_TYPE_WEAP (0x29 = 41 decimal).
    //      e. Skip the PIPBOY (it's always there, no need to broadcast).
    //      f. Build payload and enqueue:
    //
    //   const std::uint64_t now_ms =
    //       std::chrono::duration_cast<std::chrono::milliseconds>(
    //           std::chrono::system_clock::now().time_since_epoch()).count();
    //
    //   fw::net::client().enqueue_equip_op(
    //       /* item_form_id     */ form_id,
    //       /* kind             */ /* EQUIP = 1 */ 1,
    //       /* slot_form_id     */ 0,    // 0 = let receiver auto-resolve
    //                                     // via TESObjectARMO.equip_slot
    //       /* count            */ 1,
    //       /* timestamp_ms     */ now_ms,
    //       /* effective_priority */ 0,  // apparel = no OMOD priority
    //       /* mods             */ nullptr,
    //       /* mod_count        */ 0,
    //       /* nif_descs        */ nullptr,
    //       /* nif_count        */ 0
    //   );
    //
    // 4. Log a summary at INF level: how many slots were emitted, how
    //    many were empty/skipped, total time taken. This is the equivalent
    //    of B8's "cycle COMPLETE" log line but more informative since we
    //    don't depend on a 2-phase engine call.
    //
    // 5. Tag the resulting per-EQUIP_OP wire frames so the SERVER can
    //    later distinguish "boot announce" from "runtime equip event"
    //    if Option A persistence wants to dedup against a stored snapshot.
    //    Suggestion: a new optional `is_bootstrap` flag in EquipOpPayload
    //    (1 byte, default 0 = runtime; 1 = bootstrap). Wire-bump only
    //    needed when the server starts persisting.
    //
    // ====================================================================
    // RECEIVER SIDE — NO CHANGES EXPECTED
    // ====================================================================
    //
    // Receiver applies via existing `dispatch::drain_equip_apply_queue`
    // (M9 wedge 2 PROPER) which already handles `kind=EQUIP, slot=0,
    // mods/nif_descs empty` for vanilla apparel. No receiver-side code
    // needed if the payload format above matches what the runtime equip
    // hook emits today.
    //
    // ====================================================================
    // FAILURE / EDGE CASES TO TEST WHEN UNCOMMENTING
    // ====================================================================
    //
    // - PlayerCharacter not yet spawned at announce time → handler should
    //   no-op + log + leave state at IDLE so peer-join re-arm can fire.
    //   Match the resolve_refs pattern from equip_cycle.cpp.
    //
    // - PlayerCharacter::BipedAnim is null (rare; may happen if save load
    //   is mid-flight) → SEH wrap on the offset read. Same: no-op + log.
    //
    // - Modded apparel with custom NIF mods (very rare in vanilla, but
    //   conceivable with mods) → currently we send mod_count=0. If the
    //   apparel IS modded the receiver renders base-mesh only, identical
    //   to what M9 witness would produce on the first runtime re-equip.
    //   Acceptable for v1; can extract mod chain via memory walk later.
    //
    // - Receiver hasn't spawned its ghost yet (timing race with peer
    //   handshake) → existing M9 wedge 2 dispatch already buffers
    //   EQUIP_OPs awaiting ghost spawn, so this should be transparent.
    //   Verify via log: "[equip-apply] no ghost yet, deferred N ops".
    //
    // - Multiple peers join in rapid succession → each PEER_JOIN re-arms
    //   us. The state-machine collapses overlapping re-arms (only one
    //   announce in flight at a time) but the broadcast goes out to ALL
    //   peers via server fan-out, so the new peer always gets it on the
    //   next cycle.
    //
    // ====================================================================

    // For now, drop back to DONE so peer-join re-arm can transition us
    // back to ARMED. The skeleton is "logically complete" even though
    // it does no real work.
    g_state.store(AnnounceState::DONE);
}

void shutdown_equip_announce() {
    g_worker_should_stop.store(true);
    // Worker is detached; we just signal it. Process exit reaps.
}

} // namespace fw::hooks
