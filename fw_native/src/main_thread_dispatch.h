// B1.l main-thread dispatch queue for remote engine calls.
//
// Problem this solves: CONTAINER_BCAST (and future similar events) must
// mutate the local engine's inventory state on the MAIN thread, not the
// net thread. Prior to B1.l we called engine::apply_container_op_to_engine
// directly from the net thread dispatch — which corrupted player B's
// inventory when B had a ContainerMenu open while peer A spammed takes
// (main thread paused in menu, net thread writing behind its back →
// ContainerMenu's cached iterator state got out of sync → user clicks
// in menu remove wrong items from player inventory).
//
// Fix: net thread enqueues a "pending container op" POD and PostMessage's
// a custom WM_APP to the FO4 main window. The WndProc subclass (installed
// by main_menu_hook for B3.b LoadGame; shared with us here) catches the
// message on the main thread and drains the queue, calling
// apply_container_op_to_engine from a thread the engine trusts.
//
// This mirrors the pattern used for B3.b LoadGame (FW_MSG_LOAD_GAME =
// WM_APP + 0x42). Our message uses WM_APP + 0x43.
//
// Thread safety: enqueue/drain use a shared std::mutex. HWND is set once
// after WndProc subclass installs (see main_menu_hook.cpp's
// install_wndproc_subclass) and read lock-free after that.

#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>

namespace fw::dispatch {

// WM_APP offsets (CORRECTED 2026-04-27 after collision bug):
//   0x42 = FW_MSG_LOAD_GAME (B3.b)         — main_menu_hook.cpp
//   0x43 = FW_MSG_CONTAINER_APPLY (B1.l)   — owned here
//   0x44 = FW_MSG_SPAWN_GHOST              — ghost/actor_hijack.h
//   0x45 = FW_MSG_STRADAB_INJECT           — native/scene_inject.h
//   0x46 = FW_MSG_STRADAB_POS_UPDATE       — native/scene_inject.h
//   0x47 = FW_MSG_STRADAB_BONE_TICK        — native/scene_inject.h
//   0x48 = FW_MSG_STRADAB_POSE_APPLY       — native/scene_inject.h
//   0x49 = FW_MSG_DOOR_APPLY (B6.1)        — owned here
//
// PRE-FIX BUG (commit landed 2026-04-27 evening): DOOR_APPLY was set
// to 0x47 in the initial Phase 2 ship, colliding with STRADAB_BONE_TICK.
// Result: 20Hz pose-tx never fired (bone tick worker posted 0x47, our
// WndProc dispatched it as DOOR_APPLY → empty drain → on_bone_tick_message
// never called → ghost body stuck in T-pose for receivers). Fixed by
// moving DOOR_APPLY to 0x49.
constexpr UINT FW_MSG_CONTAINER_APPLY = WM_APP + 0x43;
constexpr UINT FW_MSG_DOOR_APPLY      = WM_APP + 0x49;

struct PendingContainerOp {
    std::uint32_t kind;               // 1=TAKE, 2=PUT
    std::uint32_t container_form_id;  // sender's form_id (from v5 wire)
    std::uint32_t container_base_id;  // identity check component
    std::uint32_t container_cell_id;  // identity check component
    std::uint32_t item_base_id;       // what to add/remove
    std::int32_t  count;              // how many (>0)
};

struct PendingDoorOp {
    std::uint32_t door_form_id;   // sender's form_id (lookup_by_form_id)
    std::uint32_t door_base_id;   // identity check
    std::uint32_t door_cell_id;   // identity check
};

// Net thread → enqueues op and posts FW_MSG_CONTAINER_APPLY to the FO4
// main window. If the HWND isn't set yet (subclass not installed at
// boot), the op stays queued; main_menu_hook flushes once it subclasses
// via set_target_hwnd(). Safe at any time; no-ops if dispatch_ready()
// returns false AND no handler is configured.
void enqueue_container_apply(const PendingContainerOp& op);

// Main thread (WndProc dispatcher) only. Drains all pending ops in one
// shot and calls fw::engine::apply_container_op_to_engine on each,
// under an fw::hooks::ApplyingRemoteGuard to suppress feedback from any
// internal vt[0x7A] re-entry.
void drain_container_apply_queue();

// B6.1: door apply queue — same pattern as container.
void enqueue_door_apply(const PendingDoorOp& op);
void drain_door_apply_queue();

// Wires the HWND of the main FO4 window. Called exactly once from
// main_menu_hook after SetWindowLongPtr succeeds. Also flushes any ops
// that accumulated before the HWND was known (sends one PostMessage so
// the main thread drains).
void set_target_hwnd(HWND hwnd);

// Diagnostic: how many ops currently pending. Returned under the lock
// for a point-in-time snapshot; no atomicity guarantee vs concurrent
// enqueues.
std::size_t pending_count();

// Expose the main window handle to other modules (e.g. ghost actor
// hijack) that need to PostMessage onto the main thread. Returns
// nullptr if set_target_hwnd hasn't been called yet.
HWND get_target_hwnd();

} // namespace fw::dispatch
