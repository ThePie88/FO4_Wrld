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

// v23 — the wid bound to a local form id, or 0. Any-thread safe.
std::uint32_t wid_for_fid(std::uint32_t fid);

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

}  // namespace fw::native::world_spawn
