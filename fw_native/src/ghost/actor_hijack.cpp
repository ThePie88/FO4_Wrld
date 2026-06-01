#include "actor_hijack.h"

#include <windows.h>
#include <atomic>
#include <cmath>

#include "../engine/engine_calls.h"
#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../net/client.h"      // B6.6w5: enqueue_peer_ghost_register
#include "../offsets.h"

namespace fw::ghost {

namespace {

std::atomic<bool>  g_initialized{false};
std::uintptr_t     g_module_base = 0;

// Read the local player's position AND parent cell ptr with SEH guard.
// Returns false on null singleton or access fault. Used to gate spawn
// until LoadGame has FULLY placed the player into the world cell (pose
// + cell attach are both required — pose alone is populated from save
// metadata before the cell is actually loaded, which gives a false
// "in gameplay" reading during the LoadGame transition window).
//
// B6.6w5 live-test 2026-05-13: gating on pose alone allowed a spawn at
// 01:36:05, then the engine's LoadGame completed at 01:36:07 and
// crashed during the load sweep — the ghost was in ProcessLists at
// load-start with no valid parentCell, the engine touched its junk
// cell ptr during teardown. Adding the parentCell gate prevents this.
bool try_read_player_state(float out_pos[3], void** out_cell) {
    if (!g_module_base) return false;

    auto pc_slot = reinterpret_cast<void* const*>(
        g_module_base + offsets::PLAYER_SINGLETON_RVA);

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pc);
        out_pos[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        out_pos[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        out_pos[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
        *out_cell  = *reinterpret_cast<void* const*>(b + offsets::PARENT_CELL_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Are we in real gameplay (post-LoadGame, cell loaded)?
// Rejects:
//   - all-zero pose (pre-init singleton)
//   - MainMenu cell fingerprint (2048, 2048, 0)
//   - null parentCell (save metadata populated pose but cell not yet
//     attached — transient state during LoadGame)
bool is_in_gameplay(const float pos[3], const void* cell) {
    if (pos[0] == 0.0f && pos[1] == 0.0f && pos[2] == 0.0f) return false;
    if (std::fabs(pos[0] - 2048.0f) < 4.0f &&
        std::fabs(pos[1] - 2048.0f) < 4.0f &&
        std::fabs(pos[2])           < 4.0f) return false;
    if (!cell) return false;
    return true;
}

// Spawned ghost actor pointer. Written on the main thread (WndProc
// handler) exactly once, then read-only thereafter. std::atomic gives
// us the release/acquire fence we need for net-thread readers of
// get_ghost_actor().
std::atomic<void*> g_ghost_actor{nullptr};

// Guard for request_spawn: once a PostMessage has been issued we
// don't re-post on every POS_BROADCAST. Also prevents the main-thread
// handler from re-spawning if the message fires twice.
std::atomic<bool>  g_spawn_requested{false};

// Build 65.c.34 — PROXY-GHOST SPAWN KILL SWITCH (default: disabled).
// The proxy Actor (PlaceAtMe, fid 0xFF000001) is vestigial — all its
// combat/aggro consumers are dead (if(false)/BUILD64_DISABLED); its only live
// consumers are crash-guards that exist solely to stop the engine tripping
// over the proxy itself. It is the structural root of the death-reload crash
// family: on reload the engine frees it but it stays registered in the global
// form table (keyed by its engine-assigned fid, NOT 0xFF000001 — which is why
// the c.32/c.33 deregister was a no-op), so the form-table rehydrator
// dispatches vt[51] on the freed block (AV 0xC06BFC) and the block double-frees
// (AV 0x16632B9). NOT spawning it removes that whole class at the source.
// The VISUAL ghost (body NiNode g_injected_cube + pose-rx + equip relay) is
// fully independent — verified to write the NiNode, never the proxy — so the
// working cross-client sync (pos/yaw/anim/equip/hit-react) is unaffected.
// Cross-peer aggro will move server-side (proximity-ownership, c.35), not a
// local hostile proxy. Pre-flight audit: re/c34_preflight_safety_AGENT.md.
// Atomic (not constexpr) so the disabled spawn body stays compiled (no C4702)
// and the switch can be flipped at runtime if a future approach needs it.
std::atomic<bool>  g_proxy_spawn_disabled{true};

// B6.6w5 Build 28e — defer spawn after first valid request to let the
// cell-attach state stabilize. Build 28b crashed in IsAttachable
// (sub_1403095C0 RVA 0x309600 `mov rax, [rdx]` reading sentinel
// 0xFFFFFFFFFFFFFFFF) because the player's inline BSTArrays at
// +0x68-+0xAF were in flux during TP. Waiting ~3 seconds after first
// `is_in_gameplay` true means cell-load has completed cleanly.
//
// Implementation: record time of first request. POST the WM_APP only
// after kDeferMs has elapsed. Until then, return early and let the
// next POS_BROADCAST re-evaluate.
std::atomic<std::uint64_t> g_first_request_tick{0};
constexpr std::uint64_t kSpawnDeferMs = 3000;  // 3 seconds

} // namespace

bool init(std::uintptr_t module_base) {
    if (g_initialized.exchange(true)) return true;

    g_module_base = module_base;
    FW_LOG("[ghost] actor_hijack init: module_base=0x%llX "
           "(Z.2 wiring — awaiting first POS_BROADCAST to request spawn)",
           static_cast<unsigned long long>(module_base));
    return true;
}

void request_spawn() {
    // Cheap guard: don't spam PostMessage. First caller wins.
    bool expected = false;
    if (!g_spawn_requested.compare_exchange_strong(expected, true)) {
        return;
    }

    // Need main-thread hwnd. If WndProc subclass hasn't installed yet
    // (we're too early in boot), back out and allow a retry on next
    // POS_BROADCAST.
    HWND hwnd = fw::dispatch::get_target_hwnd();
    if (!hwnd) {
        FW_DBG("[ghost] request_spawn: hwnd not set yet, will retry");
        g_spawn_requested.store(false, std::memory_order_release);
        return;
    }

    // Crash-protection gate: don't post while LoadGame is still mid-
    // transition. Live tests:
    //   2026-04-22 — PlaceAtMe SEH from mid-LoadGame POS_BROADCAST
    //                (heap allocator corruption)
    //   2026-05-13 #1 — engine-native ctor OK but engine load-sweep
    //                crashed; root cause: spawn happened during the
    //                ~11-second LoadGame window (player singleton
    //                populated from save metadata pre-cell-attach)
    //   2026-05-13 #2 — parentCell gate fixed mid-load spawn but
    //                clients still crashed ~7s after LoadGame
    //                completed; suspected ProcessLists Update_PerFrame
    //                touching uninit ghost fields (separate defuse)
    //
    // Three required conditions for safe spawn:
    //   1. Player pose != menu cell, != all-zero
    //   2. Player parentCell (REFR+0xB8) != null
    //   3. Engine's `byte_1432D1FEA` (load_in_progress) == 0
    //
    // (3) is the strongest signal — it's flipped to 1 by our own
    // load_game_by_name BEFORE the engine's LoadGame call, and cleared
    // by the engine after the full load + cell-attach + autosave sweep
    // completes. Reading 0 proves the engine is back in steady-state
    // gameplay.
    float ppos[3]{};
    void* pcell = nullptr;
    if (!try_read_player_state(ppos, &pcell) ||
        !is_in_gameplay(ppos, pcell)) {
        FW_DBG("[ghost] request_spawn: player state not in real gameplay yet "
               "(pos=(%.0f, %.0f, %.0f), parentCell=%p) — will retry",
               ppos[0], ppos[1], ppos[2], pcell);
        g_spawn_requested.store(false, std::memory_order_release);
        return;
    }

    // Build 28e — defer spawn 3s after first time we see a valid gameplay
    // state. Build 28b live test confirmed: PlaceAtMe's IsAttachable
    // (sub_1403095C0) AVs during the TP transition window because the
    // player's cell-attach internal state (inline BSTArrays at +0x68-+0xAF)
    // is in flux. Waiting ~3s allows the engine to fully settle.
    const std::uint64_t now_ms = GetTickCount64();
    std::uint64_t first = g_first_request_tick.load(std::memory_order_acquire);
    if (first == 0) {
        g_first_request_tick.store(now_ms, std::memory_order_release);
        first = now_ms;
        FW_LOG("[ghost] request_spawn: first valid request observed at %llu ms, "
               "deferring spawn for %llums to let cell-attach state stabilize",
               static_cast<unsigned long long>(now_ms),
               static_cast<unsigned long long>(kSpawnDeferMs));
    }
    if (now_ms - first < kSpawnDeferMs) {
        const std::uint64_t remaining = kSpawnDeferMs - (now_ms - first);
        FW_DBG("[ghost] request_spawn: defer window active, %llums remaining",
               static_cast<unsigned long long>(remaining));
        g_spawn_requested.store(false, std::memory_order_release);
        return;
    }
    FW_LOG("[ghost] request_spawn: defer window elapsed (%llu ms since "
           "first request) — proceeding with spawn",
           static_cast<unsigned long long>(now_ms - first));

    // NOTE: B6.6w5 Build 2 added `is_load_in_progress()` here, but live test
    // showed the engine's `byte_1432D1FEA` flag gets stuck at 1 (it's set by
    // every save/load worker, and the engine's single clear path at
    // `funcs_0396.md:7261` is one-shot per load context). The gate ended up
    // blocking spawn forever. The parentCell != null check above is the more
    // reliable signal — parentCell is the last field set during cell-attach
    // (engine sequence: alloc actor → set fields → attach to cell → write
    // back-pointer at REFR+0xB8). If parentCell is non-null on the LOCAL
    // player singleton, the engine is past the dangerous early-load state.

    if (!PostMessageW(hwnd, FW_MSG_SPAWN_GHOST, 0, 0)) {
        FW_ERR("[ghost] request_spawn: PostMessage failed (err=%lu) — "
               "main-thread spawn will not happen",
               GetLastError());
        g_spawn_requested.store(false, std::memory_order_release);
        return;
    }

    FW_LOG("[ghost] request_spawn: WM_APP+0x44 posted to main-thread hwnd=%p "
           "(player at (%.0f, %.0f, %.0f), parentCell=%p)",
           static_cast<void*>(hwnd), ppos[0], ppos[1], ppos[2], pcell);
}

void on_spawn_message() {
    // Build 65.c.34 — proxy-ghost spawn disabled (see g_proxy_spawn_disabled
    // banner). The visual ghost is the body NiNode injected separately; this
    // only skips the vestigial, crash-rooting PlaceAtMe Actor.
    if (g_proxy_spawn_disabled.load(std::memory_order_relaxed)) {
        FW_LOG("[ghost] on_spawn_message: proxy-ghost spawn DISABLED (c.34) — "
               "vestigial + death-crash root (0xC06BFC/0x16632B9); visual ghost "
               "(NiNode) unaffected; aggro moves server-side (c.35)");
        return;
    }

    // We're on the main (WndProc) thread now — safe to run the
    // engine-native PlayerCharacter ctor.
    if (g_ghost_actor.load(std::memory_order_acquire)) {
        FW_DBG("[ghost] on_spawn_message: actor already spawned, no-op");
        return;
    }

    // B6.6w5 — engine-native PlayerCharacter spawn.
    //
    // Replaces the Z.2 PlaceAtMe path. PlaceAtMe is a console/Papyrus
    // shim that produces a generic Actor (engine AI keys on
    // PlayerCharacter identity, so a PlaceAtMe'd actor can never be a
    // "player target" for remote raiders). spawn_ghost_player runs the
    // engine's real `sub_140D52350` PlayerCharacter ctor and applies the
    // four mandatory post-ctor patches (see engine_calls.cpp for the
    // full audit trail and re/B6.6w5_player_ctor_audit.md for the proof).
    //
    // The ghost form-id is the multiplayer-stable identifier used by the
    // server to translate "raider combat-target = local-player on
    // sender's side" → "raider combat-target = ghost on receiver's side"
    // via project_for_peer. We hardcode GHOST_FORMID_BASE for the 2-peer
    // MVP; a 3+ peer scale-up will need per-peer unique fids.
    const std::uint32_t ghost_fid = offsets::GHOST_FORMID_BASE;

    // B6.6w5 Build 28 — switched from memcpy-duplicate `spawn_ghost_player`
    // to engine-native `spawn_ghost_proxy` per Path #1 of the 10-agent
    // TABULA RASA synthesis. Uses PlaceAtMe (verified RVA 0x1159C10) to
    // get a fully-constructed Actor with all engine subsystems initialized.
    // Zero aliasing with real_player's heap → eliminates the 27-build
    // crash matrix.
    //
    // Base form 0x0020593F = LCharWorkshopNPC (vanilla TESNPC, exists in
    // Fallout4.esm). Choice rationale per AGENT P1B: empty-faction, low
    // visual impact. A custom invisible-NPC ESL would be cleaner long-
    // term but this works for MVP.
    constexpr std::uint32_t kBaseFormId = 0x0020593F;
    void* actor = fw::engine::spawn_ghost_proxy(ghost_fid, kBaseFormId);
    if (!actor) {
        FW_ERR("[ghost] on_spawn_message: spawn_ghost_proxy failed — "
               "Build 28 engine-native spawn returned NULL. Check log for "
               "PlaceAtMe error path (anchor null? base not TESNPC?).");
        // Leave g_spawn_requested=true so we don't try again automatically.
        return;
    }

    g_ghost_actor.store(actor, std::memory_order_release);
    FW_LOG("[ghost] on_spawn_message: PlayerCharacter ghost pinned at %p "
           "fid=0x%08X (Z.3 pos sync next — currently static at spawn pose)",
           actor, ghost_fid);

    // Tell the server about the ghost form-id so it can route remote
    // raider combat-target broadcasts to it. The fid we send is exactly
    // what spawn_ghost_player wrote at ghost+0x14, so we can pass our
    // local constant directly — no defensive read-back needed (the write
    // path is local-memory only, no engine can mutate it).
    fw::net::client().enqueue_peer_ghost_register(ghost_fid);
    FW_LOG("[ghost] PEER_GHOST_REGISTER tx ghost_form_id=0x%08X (actor=%p)",
           ghost_fid, actor);
}

void* get_ghost_actor() {
    return g_ghost_actor.load(std::memory_order_acquire);
}

void tick_per_frame() {
    // Z.3 — reads net remote snapshot, writes to actor+0xD0 and +0xC0.
    // Z.2 leaves the actor frozen at its spawn pose (we can at least
    // visually confirm the spawn worked).
}

void shutdown() {
    if (!g_initialized.exchange(false)) return;

    // Z.6 — Disable+Delete on the actor. For Z.2 we leak the actor
    // on DLL unload (the TEMPORARY flag prevents save-bloat).
    void* actor = g_ghost_actor.exchange(nullptr, std::memory_order_acq_rel);
    FW_LOG("[ghost] shutdown: ghost_actor=%p (leaked; TEMPORARY flag "
           "prevents save persistence, Z.6 will do proper Disable)",
           actor);
}

// Build 65.c.32 — deregister + forget the proxy ghost on LOCAL-PLAYER DEATH,
// before the death-cam→"load last save" worldspace mass-free runs.
//
// CONFIRMED root (pointer match, not theory): the proxy-ghost Actor (fid
// 0xFF000001) is registered in the global form table by PlaceAtMe and was
// NEVER deregistered. On death→reload the engine frees its memory block but it
// stays in the form table, so the post-LoadGame form-table rehydrator
// (sub_140C06AC0) dispatches vt[51] on the freed block's −1 vtable → AV at
// 0xC06BFC → the crash-veh retries it forever → MAIN-THREAD FREEZE. The crash
// dump's rcx (0x26FE4CED400 on client B) is byte-identical to the proxy ptr
// this session logged at registration. `deregister_ghost_from_form_table`
// already exists (Build 56) for exactly this vt-cascade class but is never
// called — so call it here, at the kill of the local player (form 0x14), which
// the log shows fires ~14 s BEFORE the rehydrator runs (ample lead).
//
// We do NOT free/detach anything — the engine frees the proxy once during its
// own teardown; touching it would double-free. We only (1) remove it from the
// global form table so the rehydrator skips it, (2) drop our trackers so the
// next post-reload POS_BROADCAST re-spawns a fresh proxy. Main thread only
// (called from the kill detour). Idempotent (exchange→nullptr early-out).
void teardown_proxy_ghost_for_reload() {
    void* actor = g_ghost_actor.exchange(nullptr, std::memory_order_acq_rel);
    if (!actor) return;   // no proxy live / already torn down → idempotent

    // (1) Remove from the global form table FIRST, while g_ghost_duplicate_ptr
    //     still == actor (deregister re-registers it otherwise, see
    //     engine_calls.cpp:1322). Kills the 0xC06BFC vt[51]-on-freed dispatch.
    fw::engine::deregister_ghost_from_form_table(actor);

    // (2) Null the private lookup registry + re-arm the spawn gate so a fresh
    //     ghost re-spawns cleanly after the reload (the old block is the
    //     engine's to free now; we just forget it — NO detach, NO decrement).
    fw::engine::register_ghost_duplicate(0, nullptr);
    g_spawn_requested.store(false, std::memory_order_release);

    FW_LOG("[ghost] teardown_proxy_ghost_for_reload: deregistered+forgot proxy "
           "actor=%p on local-player death — prevents form-rehydrator vt[51] "
           "dispatch on freed proxy (0xC06BFC freeze); re-spawns post-reload",
           actor);
}

} // namespace fw::ghost
