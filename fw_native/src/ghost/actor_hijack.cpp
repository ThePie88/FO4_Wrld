#include "actor_hijack.h"

#include <windows.h>
#include <atomic>
#include <cmath>

#include "../engine/engine_calls.h"
#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../offsets.h"

namespace fw::ghost {

namespace {

std::atomic<bool>  g_initialized{false};
std::uintptr_t     g_module_base = 0;

// Read the local player's position with SEH guard. Returns false on
// null singleton or access fault. Used to gate spawn until LoadGame
// has actually placed the player into the world cell.
bool try_read_player_pos(float out[3]) {
    if (!g_module_base) return false;

    auto pc_slot = reinterpret_cast<void* const*>(
        g_module_base + offsets::PLAYER_SINGLETON_RVA);

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pc);
        out[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        out[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        out[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Are we in real gameplay (post-LoadGame, cell loaded)?
// Rejects:
//   - all-zero (pre-init singleton)
//   - MainMenu cell fingerprint (2048, 2048, 0)
bool is_in_gameplay(const float pos[3]) {
    if (pos[0] == 0.0f && pos[1] == 0.0f && pos[2] == 0.0f) return false;
    if (std::fabs(pos[0] - 2048.0f) < 4.0f &&
        std::fabs(pos[1] - 2048.0f) < 4.0f &&
        std::fabs(pos[2])           < 4.0f) return false;
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
    // transition. Live test 2026-04-22: POS_BROADCAST arriving during
    // LoadGame caused PlaceAtMe to SEH (allocator corruption). Wait
    // for a real gameplay pose before firing.
    float ppos[3]{};
    if (!try_read_player_pos(ppos) || !is_in_gameplay(ppos)) {
        FW_DBG("[ghost] request_spawn: player pose not in gameplay yet "
               "(pos=(%.0f, %.0f, %.0f)) — will retry",
               ppos[0], ppos[1], ppos[2]);
        g_spawn_requested.store(false, std::memory_order_release);
        return;
    }

    if (!PostMessageW(hwnd, FW_MSG_SPAWN_GHOST, 0, 0)) {
        FW_ERR("[ghost] request_spawn: PostMessage failed (err=%lu) — "
               "main-thread spawn will not happen",
               GetLastError());
        g_spawn_requested.store(false, std::memory_order_release);
        return;
    }

    FW_LOG("[ghost] request_spawn: WM_APP+0x44 posted to main-thread hwnd=%p "
           "(player at (%.0f, %.0f, %.0f))",
           static_cast<void*>(hwnd), ppos[0], ppos[1], ppos[2]);
}

void on_spawn_message() {
    // We're on the main (WndProc) thread now — safe to call PlaceAtMe.
    if (g_ghost_actor.load(std::memory_order_acquire)) {
        FW_DBG("[ghost] on_spawn_message: actor already spawned, no-op");
        return;
    }

    void* actor = fw::engine::spawn_ghost_actor(offsets::GHOST_TEMPLATE_FORM_ID);
    if (!actor) {
        FW_ERR("[ghost] on_spawn_message: spawn failed — will NOT retry "
               "(manual request_spawn needed)");
        // Leave g_spawn_requested=true so we don't try again automatically.
        // A reload-game / reconnect resets this.
        return;
    }

    g_ghost_actor.store(actor, std::memory_order_release);
    FW_LOG("[ghost] on_spawn_message: actor pinned at %p "
           "(Z.3 teleport next, currently static at spawn pose)",
           actor);
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

} // namespace fw::ghost
