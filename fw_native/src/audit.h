// Build 69m — MUTATION LEDGER.
//
// WHY THIS EXISTS. Five mitigations for the post-death AV have now failed, each
// built on a causal story that looked solid and was not. The last one died on a
// detail that should have been obvious: client A died TWICE in one session with
// near-identical mirror state (32 pins / 6 caches vs 35 pins / 7 caches) and
// only one of the two crashed. Same build, same scene, same respawn point,
// opposite outcome — so the discriminator is something we have never recorded.
//
// Everything we know about the fault points at reference/cell bookkeeping:
//   * the AV is always the vcall at sub_1404CC240+0x404, `call [cell_vtbl+0x148]`,
//     on a cell taken from refr+0xB8, whose vtable pointer is garbage
//   * it fires inside BGSSaveLoadGame::LoadGame (the death menu's Load button —
//     that is why death-to-crash varies 7.6 s to 15.2 s: human reaction time),
//     from the ClearFormReference / reconcile / load-form-buffer passes, which
//     walk EVERY form and call DetachReference(refr->parentCell, refr)
//   * the faulting branch is gated `!(flags & 0x4000) && !IsPersistent(refr)`
//     (disasm 0x1404CC611: `mov eax,[rsi+10h]; shr eax,0Eh; test al,1`, then
//     sub_1404FB8C0 = flags & 0x400), i.e. it only runs for ORDINARY PLACED
//     references — precisely the settlers and raiders we mirror
//   * apply_npc_pos moves a mirror's coordinates and re-hashes it into its
//     CURRENT parentCell's spatial grid, but nothing on that path ever writes
//     refr+0xB8; actor_teleport_handoff calls MoveTo with cell=NULL,
//     worldspace=NULL and skip_area_check=1, which disables the very guard that
//     would have read refr+0xB8
//
// So the hypothesis worth measuring is a COHERENCE one: we move actors large
// distances without ever updating which cell they believe they are in, and the
// save-load teardown then dereferences that belief.
//
// This ledger records, for every actor we mutate, WHAT we did to it — and at
// death it re-reads each one's live parentCell, coordinates and form flags and
// writes the whole table to fw_audit.log. Two deaths with opposite outcomes
// then differ in a file we can diff, instead of in a theory.
//
// Cost: one hash-map touch per mutation (already-rare operations, not per-frame
// hot paths), and one file write per death.

#pragma once

#include <cstdint>
#include <string>

namespace fw::audit {

// What we did to an actor. Bitmask — an actor usually accumulates several.
enum Kind : std::uint32_t {
    kBonesPinned       = 1u << 0,  // ni_incref on its skeleton bones
    kPosApplied        = 1u << 1,  // apply_npc_pos: vt[202], re-hashes the grid
    kPosAppliedRaw     = 1u << 2,  // apply_npc_pos_raw: writes +0xD0, no re-hash
    kTeleported        = 1u << 3,  // actor_teleport_handoff: MoveTo, cell=NULL
    kStopCombatBlocked = 1u << 4,  // we dropped its event-98 StopCombat request
    kSkipTickWritten   = 1u << 5,  // HighProcess+0x189 = 1
    kInCombatForced    = 1u << 6,  // Actor+0x2D0 |= 0x4000
    kHavokKeyframed    = 1u << 7,  // set_actor_motion_dynamic / freeze byte
};

// Record a mutation. `actor` may be null (we still record the kind).
// Cheap and thread-safe; safe to call from any thread.
void note(std::uint32_t form_id, std::uint32_t kind, void* actor) noexcept;

// Re-read every recorded actor's LIVE state and append the table to
// fw_audit.log. Main thread only — it dereferences engine objects (SEH-caged).
// `reason` labels the dump, e.g. "local-player-death".
void dump(const char* reason) noexcept;

// Called once at startup with the game directory so the audit file lands next
// to fw_native.log.
void init(const std::wstring& dir);

// ---------------------------------------------------------------------------
// Build 69o (2026-08-04) — WRITE RING.
//
// WHY. The 04:28:59 AV decoded to ExtraDataList::GetByType reading a presence-
// bitfield pointer of 0x8000000080000000 — two adjacent -0.0f floats where a
// pointer belongs. The earlier DetachReference crashes (garbage vtable READ -1,
// NULL vtable EXEC 0) are the same class: float/zero pairs smeared over engine
// objects whose heap blocks were freed and reallocated. A 29-agent sweep
// falsified every equip/weapon/mesh suspect against the session log; what
// remains is "some fw write through a stale pointer" with no way to name it.
// The mutation ledger above records WHICH ACTORS we touched; it cannot answer
// the only question that matters now: WHO wrote THESE 8 BYTES at THIS address.
//
// WHAT. Every fw store into engine-owned memory calls wnote() with the
// destination address, the source bytes and a site tag. Records land in a
// lock-free 2^19-entry ring (20 MB BSS, wait-free fetch_add slot claim). When
// the VEH catches the first AV it calls wring_dump_crash(), which
//   1. writes the raw ring to fw_writes.bin (header + 40 B records), and
//   2. scans the ring for records whose [dest, dest+len) overlaps any crash
//      register or the faulting address, and prints those hits to the log.
// One repro then names the guilty site — or proves no fw write touched the
// victim in the ring's window, which kills the whole stale-write theory.
//
// WINDOW. At the bone-drive flood rate (~25k writes/s with 5 mirrored NPCs)
// the ring holds ~20 s of history — it fully covers death -> load -> crash.
// A smear planted MINUTES earlier would scroll out; but the victim objects
// (extra lists, cells read by the load) are themselves allocated/read during
// the load, so the overlap we care about is in-window by construction.
//
// COST. 40 B write + one relaxed fetch_add per store. No locks, no allocation,
// safe from any thread, including inside __try blocks (wnote cannot fault:
// it only touches our own BSS and the caller's stack buffer).

// Where a write came from. u8 — extend freely, keep wsite_name() in sync.
enum class WSite : std::uint8_t {
    kNone       = 0,
    kBone3x3    = 1,   // write_local_3x3: 12 floats at bone+0x30 (mirror pose)
    kBoneTrans  = 2,   // write_local_translate: 3 floats at bone+0x60 (crouch)
    kNodeXform  = 3,   // seh_write_local_transform: 16 floats at node+0x30
    kGeomXform  = 4,   // seh_write_local_transform_geom: same, BSGeometry
    kSkinPtr    = 5,   // niptr_swap: 8-byte bone pointer into skin instance
    kGhostPos   = 6,   // apply_ghost_pos: 3 floats at ghost+0xD0
    kPosRaw     = 7,   // apply_npc_pos_raw: 3 floats at actor+0xD0
    kPosRawNif  = 8,   // apply_npc_pos_raw: 3 floats at nif+0x60 / +0xA0
    kGlobalVar  = 9,   // apply_global_var: 1 float at TESGlobal+0x30
    kHpFunnel   = 10,  // hp-pool funnel call: engine writes, dest=actor marker
    kRefInc     = 11,  // ni_incref: interlocked +1 at obj+refcount
    kRefDec     = 12,  // ni_decref: interlocked -1 at obj+refcount
    kNiFree     = 13,  // ni_decref hit 0 -> vt[1] DeleteThis: WE FREED obj
    kSkipTick   = 14,  // HighProcess+0x189 = 1 (AI skip-tick byte)
    kInCombat   = 15,  // Actor+0x2D0 |= 0x4000 (InCombat bit RMW)
    // Build 69p (2026-08-04) — ENGINE-MEDIATED mutations. The 69o ring proved
    // our RAW stores never touch the crash victims; what remains are the
    // engine calls that mutate cell/refr bookkeeping ON OUR BEHALF. dest =
    // the actor/refr handed to the engine (a marker, not a store address).
    kEngSetPos  = 16,  // vt[202] SetPosition / g_set_position_engine:
                       //   re-hashes the ref in its parentCell spatial grid
    kEngMoveTo  = 17,  // actor_teleport_handoff: MoveTo cell=NULL,
                       //   process+cell reattach, skip_area_check=1
    kEngKill    = 18,  // kill_actor: engine Actor::Kill on a mirror
    kEngMotion  = 19,  // set_actor_motion_dynamic/keyframed: Havok motion call
};

// Record one store into engine memory. `dest` = where it landed, `src` = the
// bytes written (first 16 captured), `len` = total bytes the store covered,
// `fid` = the actor/form involved if the caller knows it (0 = unknown; the
// thread-context fid set via wctx_fid() is used as fallback).
void wnote(WSite site, const void* dest, const void* src,
           std::uint32_t len, std::uint32_t fid = 0) noexcept;

// Set/clear the calling thread's "current form id" so leaf helpers that only
// see a bone pointer still attribute their writes. Set 0 to clear.
void wctx_fid(std::uint32_t fid) noexcept;

// Crash-time dump. `ctx` is the CONTEXT* from the exception record (passed as
// void* so this header stays windows.h-free), `fault_addr` the AV address.
// Idempotent (first caller wins). Writes fw_writes.bin + logs targeted hits.
void wring_dump_crash(const void* ctx, std::uintptr_t fault_addr) noexcept;

}  // namespace fw::audit
