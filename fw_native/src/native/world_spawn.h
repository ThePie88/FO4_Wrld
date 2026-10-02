// B6.14 — world-object spawn sync (2026-08-12), the receiving half.
//
// WHAT THIS IS. The foundation for "an object exists in one client's world and
// must exist in everyone's": console spawns today, power-armor frames next,
// settlement builds and dropped items later, transient effects whenever they
// are wanted. One client creates a REFR, the server assigns it a LOGICAL id
// (wid), persists it, and every client — present or joining later — places its
// own local copy and remembers the mapping.
//
// WHY A LOGICAL ID. PlaceAtMe mints a DIFFERENT form id on every client, so
// the sender's form id means nothing remotely. The server's wid is the shared
// name; each client keeps a wid <-> local-fid registry, exactly the mapping
// PEER_GHOST_REGISTER already proved for ghost actors. Every future operation
// on a spawned object (despawn, move, state) travels by wid.
//
// WHY THE LOCAL COPIES ARE TEMPORARY REFS. The server is authoritative and
// persistent; the save file is a vessel. Both the receiver's PlaceAtMe copy
// AND the spawner's original are flagged TEMPORARY, so no save ever
// accumulates them — every session starts clean and the join bootstrap
// replays the world from the server. Persisting them locally too would
// duplicate every object on its spawner's next join.
//
// THREADING. on_bcast is called from the network thread and only queues.
// tick() runs on the main thread (WndProc drain, next to the other native
// ticks) and does all engine work: base-form lookup, PlaceAtMe at the player
// anchor, teleport to the target, registry bind.

#pragma once

#include <cstdint>

#include "../net/protocol.h"

namespace fw::native::world_spawn {

struct SpawnEntry {
    std::uint32_t wid          = 0;
    std::uint32_t base_form_id = 0;
    // The spawner's own REFR id, only meaningful when is_self: the spawner
    // does not place a second copy, it binds the wid to what it already has.
    std::uint32_t spawner_fid  = 0;
    float         pos[3]       = {0.0f, 0.0f, 0.0f};
    float         rot[3]       = {0.0f, 0.0f, 0.0f};
    std::uint32_t cell_id      = 0;
    std::uint8_t  flags        = 0;   // bit0 = transient (never persisted)
    // v23/v24 — content of the object (PA frame pieces + core), each entry
    // with its OMOD list. Injected via the engine's own AddItem + mod
    // attach right after placement; travels with every spawn broadcast and
    // pieces update so a replica is never stocked from a hardcoded list
    // (that was E1) nor left to the engine's leveled roll (bare v23
    // AddItem — "same piece, different Mk" every time).
    std::uint8_t          piece_n = 0;
    fw::net::PaPieceEntry pieces[fw::net::kMaxPaPieces] = {};
};

// Network thread. is_self = this client is the spawner (bind, do not place).
void on_bcast(const SpawnEntry& e, bool is_self);

// MAIN THREAD ONLY. Drains the pending queue (place, position, bind), runs
// the once-per-second LIFECYCLE SWEEP over every bound object, and applies
// queued despawns. The sweep is the despawn SENDER: it polls each bound
// local fid and reports death by wid when the deleted flag appears, the
// disabled flag appears, or the form vanishes while its cell is the player's
// current cell. A poll instead of teardown hooks by design — the death-crash
// history says hooks on destruction paths bite.
void tick(std::uintptr_t module_base);

// Network thread: a WORLD_DESPAWN_BCAST arrived. Queued; the main tick
// unbinds and disables the local copy (the engine's own deferred disable,
// the same thing console `disable` does).
void on_despawn(std::uint32_t wid);

// The local form id bound to a wid, or 0. Any-thread safe.
std::uint32_t local_fid_for_wid(std::uint32_t wid);

// True if this local form id is currently bound to a wid — i.e. it is one of
// OUR replicas. Any-thread safe. The lifecycle tripwire uses it to clear the
// no-save flag on our refs the ENGINE destroys (Build 70c crash fix).
bool is_our_fid(std::uint32_t fid);

// v23 — the wid bound to a local form id, or 0. Any-thread safe. LOG USE
// ONLY since 2026-09-27: runtime form ids are handed out again while the
// previous holder lives (offsets.h: RUNTIME FORM IDS ARE NOT IDENTITIES),
// so a fid names our object only together with its pointer: see
// is_our_refr / wid_for_refr, which confirm through the handle.
std::uint32_t wid_for_fid(std::uint32_t fid);

// L5 stage 2 (2026-09-27) — identity by handle.
//
// True when `refr` IS one of our bound objects: the fid is a prefilter,
// the confirmation resolves the binding's handle and compares pointers.
// Any thread (the handle table is interlocked); `refr` must be alive at
// the call, which the destroy tripwire guarantees by asking BEFORE the
// original runs.
bool is_our_refr(void* refr, std::uint32_t fid);
std::uint32_t wid_for_refr(void* refr, std::uint32_t fid);

// The sender (hooks/world_spawn_hook.cpp) calls this right before it
// announces one of OUR objects, so the echo can bind the wid to the handle
// and not only to the fid. Entries expire on their own.
void note_self_object(std::uint32_t fid, std::uint32_t handle);

// The pickup hook, BEFORE the engine's own pickup runs: the local player
// is taking `refr` out of the world. If it is one of our bound objects the
// death is reported at once as reason 5 (no waiting for the sweep, whose
// "deleted" verdict cannot tell a pickup from a streaming loss). Any
// thread: it only marks and queues; the tick sends.
void on_local_pickup(void* refr);

// A REFR the local player just DROPPED (persist/inventory_tap.cpp resolves
// the remove core's out handle and hands it here through
// hooks::report_world_drop). Not announced yet: the object is watched
// until it rests (the drop falls from chest height; announcing the
// pre-fall pose made the drift watch despawn and rebirth every drop), then
// announced self-described with its instance read at that moment. Picked
// up again before it rests = nothing sent. MAIN THREAD (the drop runs on
// it), handle required.
void watch_local_drop(void* refr, std::uint32_t handle, std::int32_t count_hint);

// v23 — network thread: a WORLD_PA_PIECES_BCAST arrived. Queued; the main
// tick applies it by destroy-and-replace (the streaming-requeue idiom).
void on_pieces_update(std::uint32_t wid, const fw::net::PaPieceEntry* entries,
                      std::uint8_t n);

// v23 — MAIN THREAD, called by the container/put hooks after a manual
// take/put on a PA frame went through: rescan the frame's inventory and
// ship the full list for its wid (no-op if the fid is not one of ours or a
// PA transition is in flight — the enter drain is not a manual change).
void report_frame_pieces(void* frame_refr, std::uint32_t fid);

// v23/v24 — scan a frame's inventory (forms, counts, and each stack's
// OMOD list) into announce entries. Returns the entry count (0 for
// non-frames / unreadable). MAIN THREAD.
std::uint8_t capture_frame_pieces(void* refr, std::uint32_t base_id,
                                  fw::net::PaPieceEntry out[12]);

// L5 stage 3 (2026-09-28) — the saved copies.
//
// A checkpoint save carries every reference the engine had when it was
// written, our world objects included: the TEMPORARY flag stamped after
// placement protects nothing (the change record is written before the
// stamp), and a copy restored from the save comes back under the SAME
// runtime form id it had. Measured on 2026-09-28: A's replica of B's baton
// (fid 0xFF001188, placed 04:35:32, destroyed by the exit teardown at
// 04:35:44) was destroyed AGAIN by the teardown of the next session, flags
// 0x8, next to the fresh replica 0xFF001156 the bootstrap had placed: one
// duplicate per object per reboot, the pair overlapping in Havok.
//
// The remedy stays on our side of the line. Every checkpoint writes a world
// manifest next to itself (snapshot_world_objects: each bound object of
// ours, its fid, base and position), and when a checkpoint loads (the boot,
// a death reload) the lifecycle module hands that manifest back
// (purge_saved_copies). Once the world is back, BEFORE any placement, each
// stamped fid is looked up and the form that answers is destroyed only when
// it is a REFR of that base standing near the stamped spot and not a live
// binding of this session. The server's bootstrap then re-places what still
// exists, exactly once.
struct WorldObjectStamp {
    std::uint32_t fid;       // the runtime form id: the save restores the copy under it
    std::uint32_t base_id;   // form id of the base object
    std::uint32_t wid;       // the server's id at the time (log use only)
    float         pos[3];
};

// MAIN THREAD, at the save point: every bound object of ours that resolves
// in this world. Returns the count written to `out`.
std::size_t snapshot_world_objects(WorldObjectStamp* out, std::size_t cap);

// L5 stage 3c (2026-09-28) — the power armour frame the player climbs out
// of. A frame entered in this session is on the resurrection watch already
// (the sweep saw it disabled at the enter); a frame worn ACROSS a save
// (the checkpoint had the player inside it) is unknown here, and on the
// second live death its exit put a frame on the wearer's screen that no
// one else got. The PA exit hook hands the frame over: if it is not one
// of ours it goes on the watch, and the sweep announces it as a new
// object once the engine has enabled it. Any thread.
void watch_unknown_frame(void* frame_refr, std::uint32_t handle);

// Any thread: queues the manifest of the save being loaded; the tick
// applies it once the world is back, before any placement. n == 0 (a load
// without a manifest, the genesis save) clears whatever was queued.
void purge_saved_copies(const WorldObjectStamp* stamps, std::size_t n,
                        const char* save_name);

}  // namespace fw::native::world_spawn
