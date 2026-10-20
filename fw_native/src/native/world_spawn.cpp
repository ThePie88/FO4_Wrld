#include "world_spawn.h"

#include <windows.h>

#include <atomic>
#include <cmath>   // v26: std::sqrt in the drift watch
#include <cstdio>  // L5 stage 2: the mod lists in the log
#include "../hooks/workbench_hook.h"   // v26: PowerArmorModMenu open/closed
#include <deque>
#include <mutex>
#include <unordered_map>
#include <unordered_set>   // 2026-10-04: the lone runtime frames said once

#include <vector>
#include <string>

#include "../engine/engine_calls.h"
#include "../engine/instance_writers.h"   // R1b: the undo of a refused op
#include "../hooks/equip_hook.h"        // v24: read_item_mod_forms (piece OMODs)
#include "../hooks/container_hook.h"    // 2026-09-29: ApplyingRemoteGuard around the in-place alignment
#include "../hooks/container_menu_hook.h" // 2026-09-29: refresh an open menu on the aligned frame
#include "../hooks/npc_ai_suppress.h"   // Build 70b: in_local_death_standdown gate
#include "../hooks/pa_pipeline_trace.h" // Build 70u: force_local_pa_model_reload
#include "../hooks/world_spawn_hook.h"  // L5 stage 2: announce_world_refr (a rested drop)
#include "../net/client.h"
#include "../offsets.h"
#include "../persist/inventory_capture.h" // L5 stage 2: read_refr_instance (drop rebirth)
#include "../persist/lifecycle.h"         // exiting(): no engine work during the teardown
#include "../ref_identity.h"
#include "../log.h"
#include "scene_inject.h"               // Build 70i: dump_local_player_tree

namespace fw::native::world_spawn {

namespace {

// Pending spawns from the network thread, drained on the main tick. A deque
// because the join bootstrap can deliver a burst (every persisted object at
// once) and order should be preserved — later ops referencing a wid must find
// it already placed.
std::mutex              g_mx;
std::deque<SpawnEntry>  g_pending;

// wid <-> local binding. Both directions, because the ops go both ways: a
// despawn arrives by wid and needs the local fid; the lifecycle sweep walks
// local fids and needs the wid to tell the server. `cell_id` is the spawn
// cell, kept to tell "vanished because consumed" (same cell, report) from
// "vanished because the cell unloaded" (benign, skip). `reported` stops a
// death from being reported more than once while the server round-trip is in
// flight.
struct Bound {
    std::uint32_t fid      = 0;
    std::uint32_t cell_id  = 0;   // refreshed to the ref's LIVE parent cell on
                                  // every sweep while it resolves: exteriors
                                  // are a grid, and a frame carried or exited
                                  // two squares over would otherwise compare
                                  // against its birth cell forever
    bool          reported = false;
    bool          null_seen = false;   // one-shot: said "went null" already
    // 2026-10-15 (D2's second live test): a crate re-placed right after a
    // death reload stood with no 3D on one client (its form id had just
    // been freed by the purge of a saved copy). Said once when the 3D is
    // missing for five seconds near the player, so the next test tells.
    std::uint64_t no3d_since_ms = 0;
    bool          no3d_said = false;
    DWORD         bound_at_ms = 0;     // birth of the binding, for the grace
    // Build 70b — the wire truth this binding replicates. Kept so a local
    // replica the ENGINE destroys (cell streaming, the PA janitor measured
    // live at +0x109DAA7) can be RE-QUEUED for placement on approach instead
    // of being reported as a world despawn. The server object is the truth;
    // a local death by streaming is not a world event.
    SpawnEntry    entry{};
    // v26 — set when WE announced this object (the echo bound it). Only an
    // owner may re-announce a moved object; a replica that drifts locally
    // is somebody else's truth.
    bool          ours = false;
    // v26 — drift watch: the position seen on the previous sweep while the
    // object stood away from entry.pos, and whether such a sweep happened.
    // Two consecutive sweeps at the same new spot = the move has settled.
    bool          move_seen = false;
    float         last_pos[3] = {0.0f, 0.0f, 0.0f};
    float         last_yaw = 0.0f;
    // L5 stage 2 (2026-09-27) — the engine handle: THE identity of the
    // object (offsets.h: RUNTIME FORM IDS ARE NOT IDENTITIES). 0 = legacy
    // binding by fid only (an object the engine gave no handle for).
    std::uint32_t handle = 0;
    // Dressing of a self-described replica, verified by re-reading the
    // instance after the engine had its turn: a placed REFR rolls its own
    // instance, and if that roll lands after our attach the replica shows
    // the roll, not the item. Then dress again, twice at most.
    DWORD         dress_verify_ms = 0;
    std::uint8_t  dress_attempts  = 0;
};
std::unordered_map<std::uint32_t, Bound>         g_wid_to_bound;
std::unordered_map<std::uint32_t, std::uint32_t> g_fid_to_wid;      // log and prefilter only
std::unordered_map<std::uint32_t, std::uint32_t> g_handle_to_wid;   // the identity

// Despawns from the network thread, applied on the main tick.
std::vector<std::uint32_t> g_pending_despawns;

// v23 — queued WORLD_PA_PIECES_BCAST payloads (net thread -> main tick).
struct PiecesUpdate {
    std::uint32_t wid = 0;
    std::uint8_t  n   = 0;
    fw::net::PaPieceEntry entries[12] = {};
};
std::vector<PiecesUpdate> g_pending_piece_updates;

// v23b — deferred manual-change reports (see report_frame_pieces for the
// measured take-timing bug this exists for). Deduped by fid; drained on
// the main tick once due.
constexpr DWORD kFrameReportDelayMs = 300;
struct DeferredReport { std::uint32_t fid; DWORD due_ms; };
std::vector<DeferredReport> g_deferred_reports;

// RESURRECTION WATCH — the exit half of the power-armor lifecycle, and it
// costs no new reverse engineering because the enter half measured the
// mechanism for us: entering a frame sets the DISABLED flag on the ref
// (reason=2 in three live despawns), and exiting CLEARS it on the very same
// fid. So when this client self-reports a death, the fid goes here instead
// of being forgotten; the sweep keeps polling it, and the moment the ref is
// alive again (resolvable, neither deleted nor disabled) it is re-announced
// to the server as a brand-new spawn at its live position. The server mints
// a new wid, everyone places, and the exit frame exists for every client.
// Entries expire so a frame that never comes back cannot leak forever.
// self_described: the wid was a dropped item (flags bit1); its rebirth
// re-reads the REFR's instance so the re-announce keeps count, condition
// and mods (a bare re-announce would replace every replica with a fresh
// roll of the base: the drift watch fires on the item's own fall).
struct Tombstone { std::uint32_t fid; DWORD since_ms; bool self_described; std::uint32_t handle; };
std::vector<Tombstone> g_tombstones;
constexpr DWORD       kTombstoneTtlMs = 15u * 60u * 1000u;
constexpr std::size_t kTombstoneCap   = 256;

// L5 stage 2 (2026-09-27) — objects of OURS announced and not yet echoed:
// fid -> handle, consumed by on_bcast(is_self) so the binding carries the
// handle from its first second. Entries expire on their own.
struct SelfObject { std::uint32_t fid; std::uint32_t handle; DWORD since_ms; };
std::vector<SelfObject> g_self_objects;
constexpr DWORD kSelfObjectTtlMs = 30000;

// Drops watched until they rest (watch_local_drop in the header). A drop
// leaves the hand at chest height and falls; announcing that pose made the
// drift watch despawn and rebirth every drop two seconds later.
struct PendingDrop {
    std::uint32_t handle, fid, base_id;
    std::int32_t  count_hint;
    DWORD         since_ms, stable_since_ms;
    float         last_pos[3];
    bool          rested;
    std::uint32_t op_id;      // R1b: the op of the record, handed out at the drop; 0 = legacy announce
};
std::vector<PendingDrop> g_pending_drops;
constexpr DWORD kDropSettleMs   = 1500;   // still for this long, model loaded = rested
constexpr DWORD kDropMaxWaitMs  = 6000;   // announce anyway after this
constexpr float kDropStillUnits = 1.0f;

// Deaths the pickup hook reported (any thread); the tick sends them.
struct PickupDeath { std::uint32_t wid; std::uint32_t fid; };
std::vector<PickupDeath> g_pickup_deaths;

// After a self-described replica is dressed, when to re-read it.
constexpr DWORD kDressVerifyMs = 2500;

// L5 stage 3 — the saved copies to purge (world_spawn.h, "the saved
// copies"): the manifest of the save being loaded, queued by the lifecycle
// module through purge_saved_copies, applied by the tick once the world is
// back. g_mx.
struct PurgeJob { std::vector<WorldObjectStamp> stamps; std::string save; };
PurgeJob g_purge;
bool     g_purge_armed = false;
// 2026-10-04 — see run_zombie_frame_sweep: due after every load (armed with
// the purge list, run once the purge is over). g_mx.
bool     g_zombie_sweep_due = false;
// 2026-10-04 — adopted copies disabled for their move, enabled again on a
// later tick (the adoption in tick). g_mx.
struct Reenable { std::uint32_t wid = 0, fid = 0, handle = 0; DWORD due_ms = 0; };
std::vector<Reenable> g_reenable;
constexpr DWORD kReenableDelayMs = 250;

// 2026-09-30 (live test #23) — the saved copy of a power armour frame is
// ADOPTED instead of purged when the server still has its wid (the wid is
// queued for placement once the world is back). The player's own record
// names the last frame they used (the tail of the player's change form),
// and destroying that object left the reference dead: after a respawn the
// player could not enter any frame again, the animation played and the
// engine's enter never ran, while the other client, with no load in
// between, entered the same frame. The copy is bound to its wid when the
// placement comes to it, its position and pieces aligned to the server's
// record; a despawn of the wid destroys it. g_mx.
struct Adoptable { std::uint32_t wid = 0, fid = 0, handle = 0; };
std::vector<Adoptable> g_adoptable;
constexpr float        kPurgeRadius   = 1024.0f;   // Havok may have rolled the copy since the save
constexpr std::uint8_t kFormTypeRefr  = 0x40;      // TESObjectREFR in this engine (ACHR is 0x41)

// Resolve a binding: by handle when it has one (the engine's own identity,
// never reused while the object lives), by fid otherwise.
static void* resolve_object(std::uint32_t handle, std::uint32_t fid) noexcept {
    if (handle != 0 && handle != 0xFFFFFFFFu) {
        std::uint32_t h = handle;
        return fw::engine::resolve_refhandle(&h);
    }
    return fid ? fw::engine::lookup_by_form_id(fid) : nullptr;
}

// The self handle noted for a fid, taken out of the list. g_mx held.
static std::uint32_t take_self_handle_locked(std::uint32_t fid) {
    const DWORD now = GetTickCount();
    std::uint32_t handle = 0;
    for (auto it = g_self_objects.begin(); it != g_self_objects.end();) {
        if (now - it->since_ms > kSelfObjectTtlMs) { it = g_self_objects.erase(it); continue; }
        if (it->fid == fid && handle == 0) { handle = it->handle; it = g_self_objects.erase(it); continue; }
        ++it;
    }
    return handle;
}

// v26 — absolute yaw difference, wrapped to [0, pi].
float yaw_delta(float a, float b) noexcept {
    float d = a - b;
    while (d >  3.14159265f) d -= 6.28318531f;
    while (d < -3.14159265f) d += 6.28318531f;
    return d < 0.0f ? -d : d;
}

bool seh_vec3_at(const void* at, float out[3]) noexcept {
    if (!at) return false;
    __try {
        const float* f = reinterpret_cast<const float*>(at);
        out[0] = f[0]; out[1] = f[1]; out[2] = f[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The lifecycle sweep cadence. One second is generous: a phantom that lives
// 900 ms less would impress nobody, and the sweep touches every bound object.
constexpr DWORD kSweepEveryMs = 1000;
DWORD g_next_sweep_ms = 0;

// PLACEMENT RANGE GATE + DEATH GRACE, both born from one measured failure:
// a client fresh from the join bootstrap placed a far object while still
// standing at spawn, the SetPosition leaf moved the position but not the
// parent cell (documented limit), and the engine DELETED the inconsistent
// temp ref within one second. The honest sweep reported the death, the
// server dropped the wid, and the other client's perfectly good copy was
// disabled — a false kill that read as "persistence is broken".
//
// The range gate keeps a pending spawn QUEUED until the player is within
// about one exterior cell of the target, so placement always happens into
// loaded, consistent space: distant objects appear as you approach, which is
// the correct semantics for a streamed world anyway. The grace keeps the
// sweep from ruling on freshly placed objects while the engine settles.
constexpr float kPlaceRadius   = 4096.0f;
constexpr DWORD kDeathGraceMs  = 5000;
// v26 — a bound object of ours standing this far (3D) from the position we
// announced has been MOVED by the engine: the power armor station docks the
// frame onto its platform after the wearer steps out (measured 2026-09-15:
// the exit rebirth carried the pre-dock spot, the peer's replica stood beside
// the station instead of on it). A moved object is re-announced through the
// same despawn + rebirth cycle the PA exit uses: despawn reason 4, the echo
// puts the fid on the resurrection watch, the next sweep finds it alive and
// announces it again at its live position with its pieces. Well above the
// ground-snap and floating-point noise of a static ref, well below any
// distance a player would call "the same place".
constexpr float kMoveThresholdUnits = 24.0f;
// The station also turns the frame to face out of the platform; a pure
// rotation is a move too (about 9 degrees).
constexpr float kMoveYawThresholdRad = 0.15f;

// v26 — station poll. While the PowerArmorModMenu is open (plus a tail
// after it closes, for the last edit) the tick compares every bound frame
// near the player with the ledger and reports the ones that differ. The
// menu is a local user action, so a client that touched nothing never
// polls: the echo safety the ledger design relies on is kept.
constexpr std::uint64_t kStationPollEveryMs = 500;
constexpr std::uint64_t kStationPollTailMs  = 3000;
constexpr float         kStationPollRange   = 1024.0f;
std::uint64_t g_next_station_poll_ms = 0;
// Measured 2026-09-15: the PowerArmorModMenu PREVIEWS the highlighted mod on
// the piece while the user browses, so a poll that ships every difference
// shipped every hover (A: a report every ~400 ms for the whole visit; B:
// a destroy-and-restock per report). A state must be seen unchanged for
// this many consecutive polls before it counts as an edit.
constexpr int kStationStablePolls = 3;   // 3 x 500 ms
struct StationSeen { std::uint64_t hash = 0; int repeats = 0; };
std::unordered_map<std::uint32_t, StationSeen> g_station_seen;   // by wid

// Order-insensitive content hash (same notion of equality as pieces_equal).
std::uint64_t pieces_hash(const fw::net::PaPieceEntry* live, std::uint8_t n) {
    std::uint64_t h = 1469598103934665603ull;
    auto mix = [&h](std::uint64_t v) {
        h ^= v; h *= 1099511628211ull;
    };
    // sort entries by form so the walk order does not matter
    std::uint8_t idx[12];
    for (std::uint8_t i = 0; i < n && i < 12; ++i) idx[i] = i;
    for (std::uint8_t i = 1; i < n && i < 12; ++i)
        for (std::uint8_t j = i; j > 0 && live[idx[j - 1]].form_id > live[idx[j]].form_id; --j) {
            const std::uint8_t t = idx[j]; idx[j] = idx[j - 1]; idx[j - 1] = t;
        }
    mix(n);
    for (std::uint8_t k = 0; k < n && k < 12; ++k) {
        const fw::net::PaPieceEntry& p = live[idx[k]];
        mix(p.form_id); mix(static_cast<std::uint64_t>(p.count)); mix(p.mod_n);
        std::uint32_t mods[fw::net::kMaxPieceMods] = {};
        for (std::uint8_t m = 0; m < p.mod_n && m < fw::net::kMaxPieceMods; ++m) mods[m] = p.mods[m];
        for (std::uint8_t m = 1; m < p.mod_n && m < fw::net::kMaxPieceMods; ++m)
            for (std::uint8_t l = m; l > 0 && mods[l - 1] > mods[l]; --l) { const auto t = mods[l]; mods[l] = mods[l - 1]; mods[l - 1] = t; }
        for (std::uint8_t m = 0; m < p.mod_n && m < fw::net::kMaxPieceMods; ++m) mix(mods[m]);
        mix(static_cast<std::uint64_t>(static_cast<std::int64_t>(p.health * 1000.0f)));
    }
    return h;
}

// Order-insensitive content comparison: pieces are matched by form (a
// frame never holds two stacks of the same piece), mod lists as sorted
// arrays, health within a hair. The ledger copy may have been captured by
// another client, whose walk order need not match ours.
bool pieces_equal(const SpawnEntry& e, const fw::net::PaPieceEntry* live,
                  std::uint8_t n) {
    if (e.piece_n != n) return false;
    for (std::uint8_t i = 0; i < n; ++i) {
        const fw::net::PaPieceEntry& a = live[i];
        const fw::net::PaPieceEntry* m = nullptr;
        for (std::uint8_t j = 0; j < e.piece_n; ++j) {
            if (e.pieces[j].form_id == a.form_id) { m = &e.pieces[j]; break; }
        }
        if (!m) return false;
        if (m->count != a.count || m->mod_n != a.mod_n) return false;
        std::uint32_t x[fw::net::kMaxPieceMods] = {}, y[fw::net::kMaxPieceMods] = {};
        for (std::uint8_t k = 0; k < a.mod_n && k < fw::net::kMaxPieceMods; ++k) {
            x[k] = a.mods[k];
            y[k] = m->mods[k];
        }
        // tiny insertion sorts (8 entries at most)
        for (std::uint8_t k = 1; k < a.mod_n && k < fw::net::kMaxPieceMods; ++k) {
            for (std::uint8_t l = k; l > 0 && x[l - 1] > x[l]; --l) { const auto t = x[l]; x[l] = x[l - 1]; x[l - 1] = t; }
            for (std::uint8_t l = k; l > 0 && y[l - 1] > y[l]; --l) { const auto t = y[l]; y[l] = y[l - 1]; y[l - 1] = t; }
        }
        for (std::uint8_t k = 0; k < a.mod_n && k < fw::net::kMaxPieceMods; ++k) {
            if (x[k] != y[k]) return false;
        }
        const float dh = m->health - a.health;
        if (dh > 0.002f || dh < -0.002f) return false;
    }
    return true;
}



// TESForm flag bits. DELETED is the standard kDeleted; DISABLED is the same
// bit the ghost machinery already documents at offsets.h FLAG_DISABLED.
constexpr std::uint32_t kFlagDeleted = 0x20;

std::uint32_t seh_u32_at(const void* at) noexcept {
    if (!at) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

void* seh_deref(std::uintptr_t at) noexcept {
    __try { return *reinterpret_cast<void* const*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

bool player_pos(std::uintptr_t base, float out[3]) noexcept {
    void* player = seh_deref(base + fw::offsets::PLAYER_SINGLETON_RVA);
    if (!player) return false;
    return seh_vec3_at(reinterpret_cast<std::uint8_t*>(player)
                       + fw::offsets::POS_OFF, out);
}

// The player's CURRENT cell form id, for the vanished-same-cell test.
std::uint32_t player_cell_id(std::uintptr_t base) noexcept {
    void* player = seh_deref(base + fw::offsets::PLAYER_SINGLETON_RVA);
    if (!player) return 0;
    void* cell = seh_deref(reinterpret_cast<std::uintptr_t>(player)
                           + fw::offsets::PARENT_CELL_OFF);
    if (!cell) return 0;
    return seh_u32_at(reinterpret_cast<std::uint8_t*>(cell)
                      + fw::offsets::FORMID_OFF);
}

// Build 70b — WORLD-INSTABILITY GATES, born from a measured freeze: B died,
// the death reload snapped the player position back near the armors, the
// range gate passed, and the tick placed two PA frames INTO THE LOADING
// SCREEN at 00:34:00 (log-timed 7s after the kill line) — the client froze
// there. Placement into a half-built world is exactly what the research
// warns about. Two gates:
//   1. the death stand-down (npc_ai_suppress owns it: opens on local death,
//      holds until the respawn teleport + 5s settle) pauses the WHOLE tick;
//   2. any player position jump > kJumpUnits in one tick (fast travel, coc,
//      load-in) pauses placement for kJumpSettleMs.
// On stand-down CLOSE every binding is re-queued: the reload's teardown
// destroyed all local replicas, so they must be re-placed from wire truth —
// and the old bindings would otherwise produce false reason=3 deaths.
bool  g_standdown_prev  = false;
// L5 stage 3c — the engine's load count when the death stand-down opened:
// unchanged at the close = the player respawned without a reload and every
// replica survived (nothing to re-queue).
std::uint64_t g_loads_at_standdown = 0;
bool  g_have_last_pos   = false;
float g_last_pos[3]     = {0.0f, 0.0f, 0.0f};
DWORD g_settle_until_ms = 0;
constexpr float kJumpUnits    = 2000.0f;
constexpr DWORD kJumpSettleMs = 5000;

// Build 70i — PA body-loss diagnostic. When the LOCAL player enters or
// exits a power-armor frame (base below), dump the local player's 3D
// subtree: once at detection and once 2.5s later, when the race-swap model
// reload has landed. Evidence for the "floating head" bug, zero writes.
constexpr std::uint32_t kPaFrameBase   = 0x0002079E;
constexpr DWORD         kPaDiag2ndMs   = 2500;
DWORD g_pa_diag_second_ms = 0;

// Build 70v — the healthy baseline, learned at runtime (see the verdict
// line below). 23 on this save; never hardcoded.
int g_pa_geoms_best = 0;
// The first sample cannot be judged (the healthy baseline is not known
// yet) — the 2026-08-16 log had one 20 reported as PRESENT for exactly
// that reason. The line now says so instead of lying.
int g_pa_samples    = 0;

// E1 — the Papyrus AddItem worker (offsets::PAPYRUS_ADDITEM_RVA, contract
// documented there). silent=1: no UI notification on the receiving client.
// SEH-caged POD call; main thread only (this file's dispatch already is).
std::uintptr_t g_module_base = 0;   // set on every tick() entry

static bool seh_papyrus_additem(void* refr, void* form, int count) {
    if (!refr || !form || count <= 0) return false;
    const std::uintptr_t base = g_module_base;
    if (!base) return false;
    using AddItemFn = void(__fastcall*)(void* refr, void* form, int count,
                                        std::uint8_t silent,
                                        std::int64_t a5, std::int64_t a6);
    const auto fn = reinterpret_cast<AddItemFn>(
        base + fw::offsets::PAPYRUS_ADDITEM_RVA);
    __try {
        fn(refr, form, count, /*silent=*/1, 0, 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// v26 — sub_140502280: how many of `item` the refr holds (see the offset
// note). -1 when the call faults.
static std::int64_t seh_refr_item_count(void* refr, void* item_form) {
    const std::uintptr_t base = g_module_base;
    if (!base || !refr || !item_form) return -1;
    using CountFn = std::int64_t(__fastcall*)(void* refr, void* item);
    const auto fn = reinterpret_cast<CountFn>(base + fw::offsets::REFR_ITEM_COUNT_RVA);
    __try {
        return fn(refr, item_form);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// v24 — the AttachModToInventoryItem worker (offsets::PAPYRUS_ATTACH_MOD_RVA,
// contract documented there). vm/stackId feed only the script error report,
// and with vm == nullptr that report FAULTS (SEH-caught, but inside the
// engine): the caller checks the worker's precondition (exactly one of the
// item in the refr) before coming here. Main thread only.
static bool seh_papyrus_attachmod(void* refr, void* item_form,
                                  void* mod_form) {
    if (!refr || !item_form || !mod_form) return false;
    const std::uintptr_t base = g_module_base;
    if (!base) return false;
    using AttachFn = std::uint8_t(__fastcall*)(
        void* vm, std::uint32_t stack_id, void* refr, void* item_form,
        void* mod_form, char attach);
    const auto fn = reinterpret_cast<AttachFn>(
        base + fw::offsets::PAPYRUS_ATTACH_MOD_RVA);
    __try {
        return fn(nullptr, 0, refr, item_form, mod_form, 1) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ---- v25: Health extra (0x25) on a frame's piece / core stack ---------------
//
// Layout and calls documented at offsets::EXTRA_ALLOC_RVA. All POD + SEH.
static void* seh_find_stack_extras(void* refr, std::uint32_t form_id) {
    if (!refr || form_id == 0) return nullptr;
    __try {
        auto* list = *reinterpret_cast<std::uint8_t**>(
            reinterpret_cast<std::uint8_t*>(refr) + fw::offsets::REFR_INV_LIST_OFF);
        if (!list) return nullptr;
        auto* entries = *reinterpret_cast<std::uint8_t**>(
            list + fw::offsets::INVLIST_ENTRIES_OFF);
        const std::uint32_t count = *reinterpret_cast<std::uint32_t*>(
            list + fw::offsets::INVLIST_COUNT_OFF);
        if (!entries || count > 4096) return nullptr;
        for (std::uint32_t i = 0; i < count; ++i) {
            auto* obj = *reinterpret_cast<std::uint8_t**>(entries + i * 0x10);
            if (!obj) continue;
            if (*reinterpret_cast<std::uint32_t*>(obj + fw::offsets::FORMID_OFF)
                != form_id) continue;
            auto* stack = *reinterpret_cast<std::uint8_t**>(entries + i * 0x10 + 8);
            if (!stack) return nullptr;
            return *reinterpret_cast<void**>(stack + fw::offsets::INV_STACK_EXTRAS_OFF);
        }
        return nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static float read_stack_health(void* refr, std::uint32_t form_id) {
    void* list = seh_find_stack_extras(refr, form_id);
    if (!list || !g_module_base) return -1.0f;
    using GetByTypeFn = void*(__fastcall*)(void* list, std::uint32_t type);
    const auto get = reinterpret_cast<GetByTypeFn>(
        g_module_base + fw::offsets::EXTRA_GET_BY_TYPE_RVA);
    __try {
        void* extra = get(list, fw::offsets::EXTRA_TYPE_HEALTH);
        if (!extra) return -1.0f;
        return *reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(extra) + fw::offsets::EXTRAHEALTH_VALUE_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1.0f; }
}

// The health writer on ANY ExtraDataList: a stack's (the PA pieces) or a
// world REFR's own (+0x100, a dropped item's condition).
static bool write_list_health(void* list, float value) {
    if (!list || !g_module_base) return false;
    const std::uintptr_t base = g_module_base;
    using GetByTypeFn = void*(__fastcall*)(void* list, std::uint32_t type);
    using AllocFn     = void*(__fastcall*)(std::size_t size);
    using CtorFn      = void*(__fastcall*)(void* mem, float value);
    using AddFn       = void*(__fastcall*)(void* head_slot, void* extra);
    using LockFn      = void (__fastcall*)(void* lock);
    const auto get    = reinterpret_cast<GetByTypeFn>(base + fw::offsets::EXTRA_GET_BY_TYPE_RVA);
    const auto alloc  = reinterpret_cast<AllocFn>(base + fw::offsets::EXTRA_ALLOC_RVA);
    const auto ctor   = reinterpret_cast<CtorFn>(base + fw::offsets::EXTRAHEALTH_CTOR_RVA);
    const auto add    = reinterpret_cast<AddFn>(base + fw::offsets::EXTRALIST_ADD_RVA);
    const auto wlock  = reinterpret_cast<LockFn>(base + fw::offsets::EXTRALIST_WLOCK_RVA);
    const auto wunlk  = reinterpret_cast<LockFn>(base + fw::offsets::EXTRALIST_WUNLOCK_RVA);
    __try {
        auto* lb = reinterpret_cast<std::uint8_t*>(list);
        void* extra = get(list, fw::offsets::EXTRA_TYPE_HEALTH);
        if (extra) {
            *reinterpret_cast<float*>(
                reinterpret_cast<std::uint8_t*>(extra) + fw::offsets::EXTRAHEALTH_VALUE_OFF) = value;
            return true;
        }
        void* mem = alloc(fw::offsets::EXTRAHEALTH_SIZE);
        if (!mem) return false;
        ctor(mem, value);
        wlock(lb + fw::offsets::EXTRALIST_LOCK_OFF);
        add(lb + fw::offsets::EXTRALIST_HEAD_OFF, mem);
        wunlk(lb + fw::offsets::EXTRALIST_LOCK_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool write_stack_health(void* refr, std::uint32_t form_id, float value) {
    return write_list_health(seh_find_stack_extras(refr, form_id), value);
}

static bool seh_refr_disabled(void* refr) {
    __try {
        return (*reinterpret_cast<const std::uint32_t*>(
                    static_cast<const std::uint8_t*>(refr) + fw::offsets::FLAGS_OFF) & 0x800u) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;   // unreadable: treat it as not a standing frame
    }
}

// v23/v24/v25/v26 — one piece onto a frame the way a replica is stocked:
// AddItem of ONE (the mod worker needs a singular stack), the source OMODs
// re-attached (a bare AddItem gets the engine's leveled roll), the
// condition or core charge, then the rest of the stack bare. True when the
// piece was added (its mods may still have failed: counted). Main thread.
static bool stock_one_piece(void* refr, const fw::net::PaPieceEntry& pe,
                            int* mods_applied, int* mods_failed) {
    void* form = fw::engine::lookup_by_form_id(pe.form_id);
    if (!form) {
        FW_WRN("[pa-pieces] entry 0x%08X: form lookup failed — skipped", pe.form_id);
        return false;
    }
    const int cnt = (pe.count > 0) ? pe.count : 1;
    if (!seh_papyrus_additem(refr, form, 1)) {
        FW_ERR("[pa-pieces] entry 0x%08X: AddItem SEH/call failed", pe.form_id);
        return false;
    }
    // v26: measured on B (2026-09-15) that one piece per re-stock round fails
    // every mod, i.e. the worker's count check refuses it; ask the same
    // question first and say what the answer was instead of letting the
    // worker fault in its error logger.
    const std::int64_t have = seh_refr_item_count(refr, form);
    if (have != 1) {
        *mods_failed += pe.mod_n;
        FW_WRN("[pa-pieces] piece 0x%08X: refr holds %lld of it after AddItem(%d) — %u mod(s) "
               "NOT attached (worker needs exactly one)", pe.form_id,
               static_cast<long long>(have), cnt, unsigned(pe.mod_n));
        if (pe.health >= 0.0f) {
            const bool hok = write_stack_health(refr, pe.form_id, pe.health);
            FW_LOG("[pa-pieces] piece 0x%08X: health %.3f %s", pe.form_id, pe.health,
                   hok ? "written" : "WRITE FAILED");
        }
        return true;
    }
    for (std::uint8_t m = 0; m < pe.mod_n && m < fw::net::kMaxPieceMods; ++m) {
        void* mod = fw::engine::lookup_by_form_id(pe.mods[m]);
        if (mod && seh_papyrus_attachmod(refr, form, mod)) {
            ++*mods_applied;
        } else {
            ++*mods_failed;
            FW_WRN("[pa-pieces] piece 0x%08X: mod 0x%08X %s", pe.form_id, pe.mods[m],
                   mod ? "attach failed" : "lookup failed");
        }
    }
    // v25 — condition / core charge: the Health extra on the stack, created
    // only when the original had one (an exact mirror).
    if (pe.health >= 0.0f) {
        const bool hok = write_stack_health(refr, pe.form_id, pe.health);
        FW_LOG("[pa-pieces] piece 0x%08X: health %.3f %s", pe.form_id, pe.health,
               hok ? "written" : "WRITE FAILED");
    }
    if (cnt > 1) {
        const bool rok = seh_papyrus_additem(refr, form, cnt - 1);
        FW_LOG("[pa-pieces] piece 0x%08X: %d more bare cop%s %s", pe.form_id, cnt - 1,
               (cnt - 1) == 1 ? "y" : "ies", rok ? "added" : "ADD FAILED");
    }
    return true;
}

static bool same_piece(const fw::net::PaPieceEntry& a, const fw::net::PaPieceEntry& b) {
    if (a.form_id != b.form_id || a.count != b.count || a.mod_n != b.mod_n) return false;
    if (std::fabs(a.health - b.health) > 0.001f) return false;
    for (std::uint8_t i = 0; i < a.mod_n && i < fw::net::kMaxPieceMods; ++i) {
        bool found = false;
        for (std::uint8_t j = 0; j < b.mod_n && j < fw::net::kMaxPieceMods; ++j) {
            if (a.mods[i] == b.mods[j]) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

// True when the frame holds exactly the wanted stacks of `form`: the same
// number of stacks, each matched once by count, mods and condition.
static bool same_stacks_of(std::uint32_t form, const fw::net::PaPieceEntry* have, std::uint8_t n_have,
                           const fw::net::PaPieceEntry* want, std::uint8_t n_want) {
    bool used[12] = {};
    int wanted = 0, had = 0;
    for (std::uint8_t j = 0; j < n_have; ++j) if (have[j].form_id == form) ++had;
    for (std::uint8_t i = 0; i < n_want; ++i) {
        if (want[i].form_id != form) continue;
        ++wanted;
        bool matched = false;
        for (std::uint8_t j = 0; j < n_have && j < 12; ++j) {
            if (!used[j] && same_piece(want[i], have[j])) { used[j] = true; matched = true; break; }
        }
        if (!matched) return false;
    }
    return wanted == had;
}

// 2026-09-29 — a peer changed this frame's pieces: the frame is aligned IN
// PLACE. It used to be destroyed and placed again (v23, "no remove-item
// primitive"), and on the client that had spawned the frame that destroyed
// its ORIGINAL: live test #12, wid 71, the console spawn of A, replaced
// twice by replicas that recycled its form id 0xFF00139F, one of which A
// then wore. Every destroyed copy also stays in the saves as a disabled
// zombie. Per form: when the frame already holds exactly the wanted stacks
// (count, mods, condition) nothing is touched; otherwise every unit of that
// form is removed and destroyed (never dropped) and the wanted stacks are
// stocked like a new replica's, and the frame redraws its pieces (the sync
// the engine runs after a menu transfer). Main thread, inside
// ApplyingRemoteGuard.
static void align_frame_pieces(void* refr, std::uint32_t fid, std::uint32_t wid,
                               const fw::net::PaPieceEntry* want, std::uint8_t n_want) {
    fw::net::PaPieceEntry have[12] = {};
    (void)fw::engine::force_materialize_inventory(refr);
    const std::uint8_t n_have = capture_frame_pieces(refr, kPaFrameBase, have);
    std::uint32_t forms[24] = {};
    int nf = 0;
    auto note_form = [&](std::uint32_t f) {
        for (int i = 0; i < nf; ++i) if (forms[i] == f) return;
        if (nf < 24) forms[nf++] = f;
    };
    for (std::uint8_t j = 0; j < n_have && j < 12; ++j) note_form(have[j].form_id);
    for (std::uint8_t i = 0; i < n_want && i < 12; ++i) note_form(want[i].form_id);

    int kept = 0, units_removed = 0, stacks_added = 0, mods_applied = 0, mods_failed = 0;
    for (int k = 0; k < nf; ++k) {
        const std::uint32_t f = forms[k];
        if (same_stacks_of(f, have, n_have, want, n_want)) { ++kept; continue; }
        int units = 0;
        for (std::uint8_t j = 0; j < n_have && j < 12; ++j) {
            if (have[j].form_id == f) units += (have[j].count > 0 ? have[j].count : 1);
        }
        if (units > 0) {
            void* form = fw::engine::lookup_by_form_id(f);
            if (form && fw::engine::remove_items_destroy(refr, form, units)) {
                units_removed += units;
            } else {
                FW_WRN("[pa-pieces] frame fid=0x%08X: removing %d x 0x%08X FAILED", fid, units, f);
            }
        }
        for (std::uint8_t i = 0; i < n_want && i < 12; ++i) {
            if (want[i].form_id == f && stock_one_piece(refr, want[i], &mods_applied, &mods_failed)) {
                ++stacks_added;
            }
        }
    }
    // Live test #17: the inventory alone does not redraw a frame whose 3D is
    // loaded (the data reached both clients, no piece moved on screen); the
    // engine's own post-transfer sync does.
    const bool changed = units_removed > 0 || stacks_added > 0;
    const bool redrawn = changed && fw::engine::sync_pa_frame_visuals(refr);
    FW_LOG("[pa-pieces] wid=%u content changed remotely -> frame fid=0x%08X aligned IN PLACE (not "
           "destroyed): %d form(s) kept, %d unit(s) removed, %d stack(s) added, %d mod(s) applied%s; "
           "visuals %s",
           wid, fid, kept, units_removed, stacks_added, mods_applied,
           mods_failed ? " (SOME MODS FAILED, see above)" : "",
           !changed ? "untouched" : redrawn ? "redrawn (task 106)" : "REDRAW FAILED");
    fw::hooks::dump_refr_inventory("post-align", refr);
    if (fw::hooks::refresh_container_menu(refr, true, false)) {
        FW_LOG("[pa-pieces] frame fid=0x%08X: the open container menu shows the new pieces", fid);
    }
}

// ---- L5 stage 2 (2026-09-27): a dropped item's world count and mods -------
//
// ExtraCount (0x24) on a world REFR's own list: what makes a placed base
// "Stimpak (5)" instead of one. Built the way the engine's own loader
// builds it (offsets::EXTRACOUNT_CTOR_RVA), added under the write lock
// like the health above; an existing node is updated in place.
static bool write_list_count(void* list, std::uint16_t count) {
    if (!list || !g_module_base || count == 0) return false;
    const std::uintptr_t base = g_module_base;
    using GetByTypeFn = void*(__fastcall*)(void* list, std::uint32_t type);
    using AllocFn     = void*(__fastcall*)(std::size_t size);
    using CtorFn      = void*(__fastcall*)(void* mem, std::int16_t count);
    using AddFn       = void*(__fastcall*)(void* head_slot, void* extra);
    using LockFn      = void (__fastcall*)(void* lock);
    const auto get    = reinterpret_cast<GetByTypeFn>(base + fw::offsets::EXTRA_GET_BY_TYPE_RVA);
    const auto alloc  = reinterpret_cast<AllocFn>(base + fw::offsets::EXTRA_ALLOC_RVA);
    const auto ctor   = reinterpret_cast<CtorFn>(base + fw::offsets::EXTRACOUNT_CTOR_RVA);
    const auto add    = reinterpret_cast<AddFn>(base + fw::offsets::EXTRALIST_ADD_RVA);
    const auto wlock  = reinterpret_cast<LockFn>(base + fw::offsets::EXTRALIST_WLOCK_RVA);
    const auto wunlk  = reinterpret_cast<LockFn>(base + fw::offsets::EXTRALIST_WUNLOCK_RVA);
    __try {
        auto* lb = reinterpret_cast<std::uint8_t*>(list);
        void* extra = get(list, fw::offsets::EXTRA_TYPE_COUNT);
        if (extra) {
            *reinterpret_cast<std::uint16_t*>(
                reinterpret_cast<std::uint8_t*>(extra) + fw::offsets::EXTRACOUNT_VALUE_OFF) = count;
            return true;
        }
        void* mem = alloc(fw::offsets::EXTRACOUNT_SIZE);
        if (!mem) return false;
        ctor(mem, static_cast<std::int16_t>(count));
        wlock(lb + fw::offsets::EXTRALIST_LOCK_OFF);
        add(lb + fw::offsets::EXTRALIST_HEAD_OFF, mem);
        wunlk(lb + fw::offsets::EXTRALIST_LOCK_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// TESObjectREFR::extraList (+0x100), a pointer the engine assumes non-null
// on every REFR; read under SEH all the same.
static void* seh_refr_extra_list(void* refr) {
    if (!refr) return nullptr;
    __try {
        return *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(refr) + fw::offsets::REFR_EXTRA_LIST_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// The engine's REFR-level mod attach (offsets::REFR_ATTACH_MOD_RVA, contract
// there): records the mod on the REFR's own instance extra and refreshes
// the 3D itself. rank 0 = the script default; the wire carries no ranks.
static bool seh_refr_attach_mod(void* refr, void* mod_form, std::uint8_t rank) {
    if (!refr || !mod_form || !g_module_base) return false;
    using AttachFn = std::uint64_t(__fastcall*)(void* refr, void* mod, std::uint8_t rank,
                                                std::uint8_t attach);
    const auto fn = reinterpret_cast<AttachFn>(g_module_base + fw::offsets::REFR_ATTACH_MOD_RVA);
    __try {
        return (fn(refr, mod_form, rank, 1) & 0xFF) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The mod list of a descriptor as "A,B,C" (hex), for the log.
static void format_mods(const fw::net::PaPieceEntry& pe, char* out, std::size_t n) {
    if (!out || n == 0) return;
    out[0] = '\0';
    std::size_t p = 0;
    for (std::uint8_t m = 0; m < pe.mod_n && m < fw::net::kMaxPieceMods && p + 12 < n; ++m) {
        p += static_cast<std::size_t>(std::snprintf(out + p, n - p, "%s%X", m ? "," : "", pe.mods[m]));
    }
}

// Whether the REFR has a loaded model right now (+0xF0), SEH-caged.
static bool seh_loaded_3d(void* refr) noexcept {
    if (!refr) return false;
    __try {
        return *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(refr) + fw::offsets::REFR_LOADED_3D_OFF) != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// A self-described spawn (flags bit1, a dropped item): pieces[0] is the
// object itself. Write its world count, condition and mods onto the placed
// REFR instead of stocking an inventory. Every step has its own fallback
// and its own word in the log; a descriptor that does not match the base
// leaves the object bare rather than dressing it as something else.
static void apply_self_descriptor(void* refr, std::uint32_t new_fid, const SpawnEntry& e) {
    if (e.piece_n < 1) {
        FW_WRN("[world-spawn] wid=%u is self-described but carries no descriptor: "
               "placed bare", e.wid);
        return;
    }
    const fw::net::PaPieceEntry& pe = e.pieces[0];
    if (pe.form_id != e.base_form_id) {
        FW_WRN("[world-spawn] wid=%u: descriptor base 0x%08X != object base 0x%08X: "
               "placed bare", e.wid, pe.form_id, e.base_form_id);
        return;
    }
    void* list = seh_refr_extra_list(refr);
    int mods_ok = 0, mods_failed = 0;
    for (std::uint8_t m = 0; m < pe.mod_n && m < fw::net::kMaxPieceMods; ++m) {
        void* mod = fw::engine::lookup_by_form_id(pe.mods[m]);
        if (mod && seh_refr_attach_mod(refr, mod, 0)) {
            ++mods_ok;
        } else {
            ++mods_failed;
            FW_WRN("[world-spawn] wid=%u: mod 0x%08X %s", e.wid, pe.mods[m],
                   mod ? "attach failed" : "lookup failed");
        }
    }
    bool hp_ok = true;
    if (pe.health >= 0.0f) hp_ok = write_list_health(list, pe.health);
    bool cnt_ok = true;
    if (pe.count > 1) {
        const std::uint16_t c = static_cast<std::uint16_t>(pe.count > 65535 ? 65535 : pe.count);
        cnt_ok = write_list_count(list, c);
    }
    char mods[fw::net::kMaxPieceMods * 9 + 4];
    format_mods(pe, mods, sizeof(mods));
    FW_LOG("[world-spawn] wid=%u fid=0x%08X dressed as the dropped item: count %d %s, "
           "condition %s, %d/%u mods%s [%s], 3D %s at dress time", e.wid, new_fid, pe.count,
           (pe.count > 1) ? (cnt_ok ? "written" : "WRITE FAILED (shows as one)") : "(single)",
           (pe.health >= 0.0f) ? (hp_ok ? "written" : "WRITE FAILED") : "none on the original",
           mods_ok, unsigned(pe.mod_n), mods_failed ? " (SOME MODS FAILED, see above)" : "",
           mods, seh_loaded_3d(refr) ? "loaded" : "not loaded");
}

// Placement retry bookkeeping. The head entry is retried, not dropped, when
// the world is not ready (player null during a load, teleport refused): the
// bootstrap arrives long before the save has finished loading, exactly like
// the appearance adoption did, and dropping would silently lose objects.
// The cap exists for the pathological case only.
constexpr int   kMaxAttempts   = 240;
constexpr DWORD kRetryDelayMs  = 250;
DWORD g_next_attempt_ms = 0;
int   g_attempts        = 0;

}  // namespace

void on_bcast(const SpawnEntry& e, bool is_self) {
    if (e.wid == 0 || e.base_form_id == 0) return;

    if (is_self) {
        // The spawner already owns the object; the broadcast's job here is
        // only to deliver the wid. Bind and done — placing a second copy is
        // exactly the duplication this design exists to prevent.
        std::lock_guard<std::mutex> lk(g_mx);
        Bound b{};
        b.fid         = e.spawner_fid;
        b.handle      = take_self_handle_locked(e.spawner_fid);
        b.cell_id     = e.cell_id;
        b.bound_at_ms = GetTickCount();
        b.entry       = e;
        b.ours        = true;
        g_wid_to_bound[e.wid]       = b;
        g_fid_to_wid[e.spawner_fid] = e.wid;
        if (b.handle) g_handle_to_wid[b.handle] = e.wid;
        FW_LOG("[world-spawn] wid=%u is OURS (base=0x%08X, local fid=0x%08X, "
               "handle=0x%08X%s) — bound, not re-placed", e.wid, e.base_form_id,
               e.spawner_fid, b.handle,
               b.handle ? "" : " NONE: fid-only binding, a reused id can fool the sweep");
        return;
    }

    {
        std::lock_guard<std::mutex> lk(g_mx);
        // A wid already bound is a replay (reconnect, duplicate reliable
        // delivery) — placing again would duplicate the object.
        if (g_wid_to_bound.count(e.wid)) {
            FW_LOG("[world-spawn] wid=%u already placed — replay ignored",
                   e.wid);
            return;
        }
        // Same for a wid already QUEUED (Build 70b: entries can re-enter the
        // queue via streaming requeue, and a replay landing on top of that
        // would place two copies on approach).
        for (const auto& p : g_pending) {
            if (p.wid == e.wid) {
                FW_LOG("[world-spawn] wid=%u already pending — replay "
                       "ignored", e.wid);
                return;
            }
        }
        g_pending.push_back(e);
    }
    FW_LOG("[world-spawn] wid=%u queued: base=0x%08X at (%.1f, %.1f, %.1f) "
           "cell=0x%08X%s%s", e.wid, e.base_form_id,
           e.pos[0], e.pos[1], e.pos[2], e.cell_id,
           (e.flags & 1) ? " [transient]" : "",
           (e.flags & fw::net::kWorldSpawnFlagSelfDescribed) ? " [item]" : "");
}

static void fire_due_frame_reports();   // v23b, defined with the API below

// L5 stage 2 — drops watched until they rest, then announced with the
// instance read at that moment. Main thread (tick).
static void tick_pending_drops() {
    std::vector<PendingDrop> ready;
    const DWORD now = GetTickCount();
    {
        std::lock_guard<std::mutex> lk(g_mx);
        for (auto it = g_pending_drops.begin(); it != g_pending_drops.end();) {
            PendingDrop& d = *it;
            std::uint32_t h = d.handle;
            void* refr = fw::engine::resolve_refhandle(&h);
            if (!refr) {
                FW_LOG("[world-spawn-tx] drop fid=0x%08X (base=0x%08X) is gone before it "
                       "rested (picked up again?): nothing announced", d.fid, d.base_id);
                if (d.op_id) fw::net::client().cancel_world_item_op(d.op_id);
                it = g_pending_drops.erase(it);
                continue;
            }
            // The stillness clock runs only once the model exists: havok
            // moves the object only then. Live (2026-09-27): every first
            // drop "rested" for a second at chest height, was announced
            // there, then fell 80 units and went through the drift watch's
            // despawn and rebirth.
            const bool loaded = seh_loaded_3d(refr);
            if (!loaded) d.stable_since_ms = now;
            float p[3];
            if (seh_vec3_at(reinterpret_cast<std::uint8_t*>(refr) + fw::offsets::POS_OFF, p)) {
                const float dx = p[0] - d.last_pos[0];
                const float dy = p[1] - d.last_pos[1];
                const float dz = p[2] - d.last_pos[2];
                if (dx * dx + dy * dy + dz * dz > kDropStillUnits * kDropStillUnits) {
                    d.last_pos[0] = p[0]; d.last_pos[1] = p[1]; d.last_pos[2] = p[2];
                    d.stable_since_ms = now;
                }
            }
            d.rested = loaded && (now - d.stable_since_ms) >= kDropSettleMs;
            const bool waited = (now - d.since_ms) >= kDropMaxWaitMs;
            if (d.rested || waited) {
                ready.push_back(d);
                it = g_pending_drops.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (const PendingDrop& d : ready) {
        std::uint32_t h = d.handle;
        void* refr = fw::engine::resolve_refhandle(&h);
        if (!refr) {
            if (d.op_id) fw::net::client().cancel_world_item_op(d.op_id);
            continue;
        }
        if (d.op_id != 0) {
            // R1b: the op of the record, with the line read now.
            char what[96];
            std::snprintf(what, sizeof(what), "Pip-Boy drop (%s after %u ms)",
                          d.rested ? "rested" : "still moving, announced anyway",
                          unsigned(now - d.since_ms));
            fw::hooks::announce_world_drop(refr, d.handle, d.op_id, d.count_hint, what);
            continue;
        }
        // The descriptor: what the item IS, read from the REFR the engine
        // built out of the stack (count, condition, mods). Unreadable =
        // bare, said out loud, never a half-read one presented as complete.
        fw::net::PaPieceEntry self{};
        const bool read_ok = fw::persist::inventory::read_refr_instance(g_module_base, refr, &self);
        if (!read_ok) {
            self.form_id = d.base_id;
            self.count   = d.count_hint > 0 ? d.count_hint : 1;
            self.mod_n   = 0;
            self.health  = -1.0f;
        } else if (self.form_id != d.base_id) {
            FW_WRN("[world-spawn-tx] drop: descriptor base 0x%08X != REFR base 0x%08X, "
                   "the REFR wins", self.form_id, d.base_id);
            self.form_id = d.base_id;
        }
        char mods[fw::net::kMaxPieceMods * 9 + 4];
        format_mods(self, mods, sizeof(mods));
        char what[320];
        std::snprintf(what, sizeof(what),
                      "Pip-Boy drop x%d hp=%.3f mods=%u[%s] (%s; %s after %u ms)",
                      self.count, self.health, unsigned(self.mod_n), mods,
                      read_ok ? "instance read" : "instance UNREAD, bare descriptor",
                      d.rested ? "rested" : "still moving, announced anyway",
                      unsigned(now - d.since_ms));
        fw::hooks::announce_world_refr(refr, d.handle,
                                       fw::net::kWorldSpawnFlagSelfDescribed,
                                       &self, 1, what);
    }
}

// L5 stage 2 — re-read every self-described replica a while after it was
// dressed: if the engine's own instance roll landed after our attach, the
// replica shows the roll and is dressed again (twice at most). Main thread.
static void tick_dress_verify(std::uintptr_t module_base) {
    const DWORD now = GetTickCount();
    struct Job { std::uint32_t wid, handle, fid; std::uint8_t attempts; SpawnEntry entry; };
    std::vector<Job> jobs;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        for (auto& [wid, b] : g_wid_to_bound) {
            if (b.dress_verify_ms == 0 || now < b.dress_verify_ms) continue;
            b.dress_verify_ms = 0;
            jobs.push_back({wid, b.handle, b.fid, b.dress_attempts, b.entry});
        }
    }
    for (const Job& j : jobs) {
        void* refr = resolve_object(j.handle, j.fid);
        if (!refr || j.entry.piece_n < 1) continue;   // gone already: nothing to verify
        const fw::net::PaPieceEntry& want = j.entry.pieces[0];
        fw::net::PaPieceEntry live{};
        const bool read_ok = fw::persist::inventory::read_refr_instance(module_base, refr, &live);
        unsigned missing = 0;
        for (std::uint8_t m = 0; m < want.mod_n && m < fw::net::kMaxPieceMods; ++m) {
            bool found = false;
            for (std::uint8_t k = 0; k < live.mod_n && k < fw::net::kMaxPieceMods; ++k) {
                if (live.mods[k] == want.mods[m]) { found = true; break; }
            }
            if (!found) ++missing;
        }
        char lm[fw::net::kMaxPieceMods * 9 + 4];
        format_mods(live, lm, sizeof(lm));
        const char* d3 = seh_loaded_3d(refr) ? "loaded" : "not loaded";
        // Where the replica stands NOW: a dropped item that fell through the
        // ground or flew off an overlapping copy is told apart from one that
        // was never looked at by this line alone.
        float lp[3] = {0.0f, 0.0f, 0.0f};
        (void)seh_vec3_at(reinterpret_cast<std::uint8_t*>(refr) + fw::offsets::POS_OFF, lp);
        if (!read_ok) {
            FW_WRN("[world-spawn] wid=%u dressing not verifiable: instance unreadable "
                   "(3D %s)", j.wid, d3);
            continue;
        }
        if (missing == 0) {
            FW_LOG("[world-spawn] wid=%u dressing verified after %u ms: %u/%u mods on the "
                   "replica, count %d, hp %.3f, live mods=[%s], 3D %s, now at (%.1f, %.1f, %.1f)",
                   j.wid, unsigned(kDressVerifyMs), unsigned(want.mod_n), unsigned(want.mod_n),
                   live.count, live.health, lm, d3, lp[0], lp[1], lp[2]);
            continue;
        }
        if (j.attempts < 2) {
            FW_WRN("[world-spawn] wid=%u dressing LOST %u/%u mods (the engine rolled its "
                   "own instance after ours: live=[%s], 3D %s) -> dressing again",
                   j.wid, missing, unsigned(want.mod_n), lm, d3);
            apply_self_descriptor(refr, j.fid, j.entry);
            std::lock_guard<std::mutex> lk(g_mx);
            auto it = g_wid_to_bound.find(j.wid);
            if (it != g_wid_to_bound.end()) {
                it->second.dress_verify_ms = now + kDressVerifyMs;
                it->second.dress_attempts  = static_cast<std::uint8_t>(j.attempts + 1);
            }
        } else {
            FW_ERR("[world-spawn] wid=%u dressing lost %u/%u mods twice: giving up "
                   "(live=[%s], 3D %s)", j.wid, missing, unsigned(want.mod_n), lm, d3);
        }
    }
}

// ============================================================================
// L5 stage 3 — the saved copies (world_spawn.h, "the saved copies").
// ============================================================================

std::uint8_t seh_u8_at(const void* at) noexcept {
    if (!at) return 0;
    __try { return *reinterpret_cast<const std::uint8_t*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::size_t snapshot_world_objects(WorldObjectStamp* out, std::size_t cap) {
    if (!out || cap == 0) return 0;
    std::size_t n = 0;
    std::lock_guard<std::mutex> lk(g_mx);
    for (const auto& [wid, b] : g_wid_to_bound) {
        if (n >= cap) break;
        void* refr = resolve_object(b.handle, b.fid);
        if (!refr) continue;   // not in this world: not in the save either
        const std::uint8_t* rb = reinterpret_cast<const std::uint8_t*>(refr);
        WorldObjectStamp s{};
        s.fid = seh_u32_at(rb + fw::offsets::FORMID_OFF);
        if (s.fid == 0) continue;
        void* base = seh_deref(reinterpret_cast<std::uintptr_t>(rb) + fw::offsets::BASE_FORM_OFF);
        s.base_id = base ? seh_u32_at(reinterpret_cast<const std::uint8_t*>(base)
                                      + fw::offsets::FORMID_OFF)
                         : b.entry.base_form_id;
        if (!seh_vec3_at(rb + fw::offsets::POS_OFF, s.pos)) {
            s.pos[0] = b.entry.pos[0]; s.pos[1] = b.entry.pos[1]; s.pos[2] = b.entry.pos[2];
        }
        s.wid = wid;
        out[n++] = s;
    }
    // 2026-10-05 (live test): the copies kept for adoption are saved objects
    // of ours too, unbound only until their wid comes within reach. Left out
    // of the manifest they outlived their wid outside every purge: the two
    // frames standing alone at Sanctuary were the copies kept for wids 108
    // and 110, never adopted (the player went elsewhere), the wids removed
    // on the server in between.
    for (const Adoptable& a : g_adoptable) {
        if (n >= cap) break;
        void* refr = resolve_object(a.handle, a.fid);
        if (!refr) continue;
        const std::uint8_t* rb = reinterpret_cast<const std::uint8_t*>(refr);
        WorldObjectStamp s{};
        s.fid = seh_u32_at(rb + fw::offsets::FORMID_OFF);
        if (s.fid == 0) continue;
        void* base = seh_deref(reinterpret_cast<std::uintptr_t>(rb) + fw::offsets::BASE_FORM_OFF);
        s.base_id = base ? seh_u32_at(reinterpret_cast<const std::uint8_t*>(base)
                                      + fw::offsets::FORMID_OFF)
                         : kPaFrameBase;
        if (!seh_vec3_at(rb + fw::offsets::POS_OFF, s.pos)) continue;
        s.wid = a.wid;
        out[n++] = s;
    }
    return n;
}

void watch_unknown_frame(void* frame_refr, std::uint32_t handle) {
    if (!frame_refr) return;
    const auto id = fw::read_ref_identity(frame_refr);
    if (id.form_id == 0 || id.base_id != kPaFrameBase) return;
    if (is_our_refr(frame_refr, id.form_id)) {
        FW_LOG("[world-spawn] PA exit: frame fid=0x%08X is bound already (the sweep announces "
               "its rebirth)", id.form_id);
        return;
    }
    std::lock_guard<std::mutex> lk(g_mx);
    for (const Tombstone& t : g_tombstones) {
        if (t.fid == id.form_id) return;   // on the watch already
    }
    if (g_tombstones.size() >= kTombstoneCap) return;
    g_tombstones.push_back({id.form_id, GetTickCount(), false, handle});
    FW_LOG("[world-spawn] PA exit: frame fid=0x%08X handle=0x%08X is not one of ours (worn "
           "across a save): on the watch, announced when the engine enables it",
           id.form_id, handle);
}

void purge_saved_copies(const WorldObjectStamp* stamps, std::size_t n, const char* save_name) {
    std::lock_guard<std::mutex> lk(g_mx);
    // L5 stage 3d (2026-09-29): every load comes through here, and a load
    // replaces the world: each fid on the resurrection watch names an object
    // of the old one. The runtime form ids start again from the save's
    // counter, so a watched fid can come back as another object, or as the
    // replica of the same frame placed again after a respawn, and be
    // announced as a rebirth. A frame worn out of a save is found at its
    // exit by watch_unknown_frame.
    if (!g_tombstones.empty()) {
        FW_LOG("[world-spawn] load: %zu fid(s) on the resurrection watch dropped (objects of "
               "the world before the load)", g_tombstones.size());
        g_tombstones.clear();
    }
    // The same for the saved copies kept for adoption: objects of the world
    // before this load.
    g_adoptable.clear();
    g_purge.stamps.clear();
    if (stamps && n) g_purge.stamps.assign(stamps, stamps + n);
    g_purge.save   = save_name ? save_name : "";
    g_purge_armed  = !g_purge.stamps.empty();
    g_zombie_sweep_due = true;
    if (g_purge_armed) {
        FW_LOG("[world-spawn] %zu saved cop(ies) of our objects listed for '%s': purged "
               "when the world is back, before any placement", g_purge.stamps.size(),
               g_purge.save.c_str());
    }
}

// The tick, once the world is back and before the queues: each stamped fid
// looked up, the form that answers destroyed only when it is the copy.
static bool run_saved_copy_purge() {
    PurgeJob job;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        if (!g_purge_armed) return false;
        g_purge_armed = false;
        job.stamps.swap(g_purge.stamps);
        job.save.swap(g_purge.save);
    }
    std::size_t purged = 0, absent = 0, kept = 0, adopted = 0;
    for (const WorldObjectStamp& s : job.stamps) {
        void* f = fw::engine::lookup_by_form_id(s.fid);
        if (!f) {
            ++absent;
            FW_DBG("[world-spawn] saved copy fid=0x%08X (wid %u then): not in this world",
                   s.fid, s.wid);
            continue;
        }
        if (is_our_refr(f, s.fid)) {
            ++kept;
            FW_LOG("[world-spawn] saved copy fid=0x%08X (wid %u then) is a live binding of "
                   "this session: kept", s.fid, s.wid);
            continue;
        }
        const std::uint8_t* rb = reinterpret_cast<const std::uint8_t*>(f);
        const std::uint8_t ft = seh_u8_at(rb + fw::offsets::FORMTYPE_OFF);
        void* base = seh_deref(reinterpret_cast<std::uintptr_t>(rb) + fw::offsets::BASE_FORM_OFF);
        const std::uint32_t base_id = base
            ? seh_u32_at(reinterpret_cast<const std::uint8_t*>(base) + fw::offsets::FORMID_OFF)
            : 0;
        float p[3] = {0.0f, 0.0f, 0.0f};
        const bool have_pos = seh_vec3_at(rb + fw::offsets::POS_OFF, p);
        const float dx = p[0] - s.pos[0], dy = p[1] - s.pos[1], dz = p[2] - s.pos[2];
        const float d2 = dx * dx + dy * dy + dz * dz;
        if (ft != kFormTypeRefr || base_id != s.base_id || !have_pos
                || d2 > kPurgeRadius * kPurgeRadius) {
            ++kept;
            FW_WRN("[world-spawn] saved copy fid=0x%08X (wid %u then, base 0x%08X): the form "
                   "here is not it (type 0x%02X, base 0x%08X, %.0f units from the stamp): kept",
                   s.fid, s.wid, s.base_id, unsigned(ft), base_id,
                   have_pos ? std::sqrt(d2) : -1.0f);
            continue;
        }
        if (s.base_id == kPaFrameBase) {
            // 2026-09-30 — see g_adoptable.
            const std::uint32_t h = fw::engine::refr_get_handle(f);
            bool pending = false;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                for (const SpawnEntry& pe : g_pending) {
                    if (pe.wid == s.wid) { pending = true; break; }
                }
                if (pending) g_adoptable.push_back(Adoptable{s.wid, s.fid, h});
            }
            if (pending) {
                ++adopted;
                FW_LOG("[world-spawn] saved copy fid=0x%08X handle=0x%08X (power armour frame, wid "
                       "%u) at (%.1f, %.1f, %.1f): KEPT for adoption, not purged: the player's "
                       "record may name it as their last power armour", s.fid, h, s.wid,
                       p[0], p[1], p[2]);
                continue;
            }
        }
        const bool gone = fw::engine::destroy_world_refr(f);
        if (gone) ++purged; else ++kept;
        FW_LOG("[world-spawn] saved copy fid=0x%08X base=0x%08X at (%.1f, %.1f, %.1f) from "
               "'%s' (wid %u then): %s", s.fid, s.base_id, p[0], p[1], p[2], job.save.c_str(),
               s.wid, gone ? "PURGED (unfile+destroy)" : "destroy FAILED - see preceding SEH line");
    }
    FW_LOG("[world-spawn] saved copies of '%s': %zu purged, %zu kept for adoption, %zu absent "
           "from this world, %zu kept", job.save.c_str(), purged, adopted, absent, kept);
    return purged > 0;
}

// 2026-10-04 — the zombie frames. A power armour frame this DLL places is a
// persistent reference (no temporary bit since stage 3d: a worn frame must
// save its cell), so a copy that lost its binding without being destroyed
// stays in the save for good, outside every manifest, and the purge never
// sees it. Live test of 2026-10-04: one such frame (0xFF001340, a core and
// nothing else) stood exactly where the adopted copy of wid 87 stood; the E
// key entered the zombie while the transfer had filled the other, the player
// climbed out of "a second frame", and its exit announced the zombie to the
// server twice. The sweep: every runtime power armour frame in the player's
// area that is neither bound, nor announced and awaiting its echo, nor kept
// for adoption, nor disabled (worn, or mid-transition), AND stands within
// kZombieTwinUnits of a frame of ours (bound, queued or kept for adoption)
// is a stale copy of that frame and goes. One standing alone is left and said
// once: it may be the game's own (a frame an NPC was thrown out of, a frame a
// script placed), and a lone stale copy only clutters. Once after the purge
// of a load, and once at each change of the player's cell, two seconds apart
// at least. Main thread.
constexpr float kZombieTwinUnits = 256.0f;

static void run_zombie_frame_sweep(const char* why) {
    static void* s_refs[4096];
    static std::unordered_set<std::uint32_t> s_alone_said;
    const std::size_t n = fw::engine::collect_player_area_refrs(s_refs, 4096);
    if (n == 0) return;
    // Where the frames of ours stand: the server's pose of the bound and the
    // queued ones, the live pose of the copies kept for adoption.
    struct Spot { float p[3]; std::uint32_t wid; };
    std::vector<Spot> ours;
    std::vector<Adoptable> adopt;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        for (const auto& [wid, b] : g_wid_to_bound) {
            if (b.entry.base_form_id == kPaFrameBase) {
                ours.push_back({{b.entry.pos[0], b.entry.pos[1], b.entry.pos[2]}, wid});
            }
        }
        for (const SpawnEntry& pe : g_pending) {
            if (pe.base_form_id == kPaFrameBase) ours.push_back({{pe.pos[0], pe.pos[1], pe.pos[2]}, pe.wid});
        }
        adopt = g_adoptable;
    }
    for (const Adoptable& a : adopt) {
        void* f = resolve_object(a.handle, a.fid);
        float p[3];
        if (f && seh_vec3_at(reinterpret_cast<const std::uint8_t*>(f) + fw::offsets::POS_OFF, p)) {
            ours.push_back({{p[0], p[1], p[2]}, a.wid});
        }
    }
    std::size_t frames = 0, zombies = 0, alone = 0;
    for (std::size_t i = 0; i < n; ++i) {
        void* r = s_refs[i];
        const auto* rb = reinterpret_cast<const std::uint8_t*>(r);
        if (seh_u8_at(rb + fw::offsets::FORMTYPE_OFF) != kFormTypeRefr) continue;
        void* base = seh_deref(reinterpret_cast<std::uintptr_t>(rb) + fw::offsets::BASE_FORM_OFF);
        if (!base || seh_u32_at(reinterpret_cast<const std::uint8_t*>(base)
                                + fw::offsets::FORMID_OFF) != kPaFrameBase) {
            continue;
        }
        const std::uint32_t fid = seh_u32_at(rb + fw::offsets::FORMID_OFF);
        if ((fid >> 24) != 0xFF) continue;   // a frame the game placed
        ++frames;
        const std::uint32_t flags = seh_u32_at(rb + fw::offsets::FLAGS_OFF);
        if (flags & (kFlagDeleted | fw::offsets::FLAG_DISABLED)) continue;   // worn, entering, going
        if (is_our_refr(r, fid)) continue;
        bool spoken_for = false;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            for (const Adoptable& a : g_adoptable) if (a.fid == fid) { spoken_for = true; break; }
            for (const SelfObject& s : g_self_objects) if (s.fid == fid) { spoken_for = true; break; }
            if (!spoken_for && g_purge_armed) {
                for (const WorldObjectStamp& s : g_purge.stamps) if (s.fid == fid) { spoken_for = true; break; }
            }
        }
        if (spoken_for) continue;
        float p[3] = {0.0f, 0.0f, 0.0f};
        const bool have_pos = seh_vec3_at(rb + fw::offsets::POS_OFF, p);
        std::uint32_t twin = 0;
        float best = kZombieTwinUnits * kZombieTwinUnits;
        if (have_pos) {
            for (const Spot& s : ours) {
                const float dx = p[0] - s.p[0], dy = p[1] - s.p[1], dz = p[2] - s.p[2];
                const float d2 = dx * dx + dy * dy + dz * dz;
                if (d2 <= best) { best = d2; twin = s.wid; }
            }
        }
        const std::uint32_t handle = fw::engine::refr_get_handle(r);
        if (twin == 0) {
            ++alone;
            if (s_alone_said.insert(fid).second) {
                FW_LOG("[world-spawn] runtime frame fid=0x%08X handle=0x%08X at (%.1f, %.1f, %.1f) "
                       "is nobody's (not bound, not announced, not kept for adoption) and stands "
                       "alone: left (the game's own, or a stale copy whose twin is elsewhere)",
                       fid, handle, p[0], p[1], p[2]);
            }
            continue;
        }
        const bool gone = fw::engine::destroy_world_refr(r);
        if (gone) ++zombies;
        FW_LOG("[world-spawn] zombie frame fid=0x%08X handle=0x%08X at (%.1f, %.1f, %.1f): a "
               "runtime power armour frame that is nobody's, %.0f units from our wid %u: %s (%s)",
               fid, handle, p[0], p[1], p[2], std::sqrt(best), twin,
               gone ? "DESTROYED" : "destroy FAILED - see preceding SEH line", why);
    }
    if (zombies || alone) {
        FW_LOG("[world-spawn] zombie sweep (%s): %zu reference(s) looked at, %zu runtime "
               "frame(s), %zu zombie(s) destroyed, %zu standing alone left", why, n, frames,
               zombies, alone);
    }
}

void tick(std::uintptr_t module_base) {
    if (!module_base) return;
    g_module_base = module_base;

    // 2026-09-28 — no engine work after the exit save request or while the
    // player has no parent cell (the exit teardown, a loading screen). The
    // shutdown nulls the handle table first and the resolver reads it:
    // measured at the end of live test #4 as a first-chance AV inside
    // sub_14021E230 at rcx = 0, SEH-caught, 40 ms before the process died
    // in the allocator. The queues keep what they hold; the next world
    // drains them.
    if (fw::persist::exiting()) return;
    if (fw::engine::get_pc_parent_cell() == nullptr) return;

    // ---- Build 70b: world-instability gates. NO engine work while the
    // world is being torn down or rebuilt (see the constants block).
    {
        const DWORD now0 = GetTickCount();
        const bool standdown = fw::hooks::in_local_death_standdown();
        if (standdown != g_standdown_prev) {
            g_standdown_prev = standdown;
            if (standdown) {
                g_loads_at_standdown = fw::persist::loads_requested();
                FW_LOG("[world-spawn] death stand-down OPEN — tick paused "
                       "(no placement, no sweep, no despawn apply)");
            } else if (fw::persist::loads_requested() == g_loads_at_standdown) {
                // L5 stage 3c — the stand-down ended in a respawn, not a
                // reload: the world and every replica survived, and
                // re-queuing them would place each object a second time.
                FW_LOG("[world-spawn] death stand-down CLOSED without a reload (the "
                       "respawn without a reload): the replicas survived, nothing re-queued");
            } else {
                // The death reload finished. Its teardown destroyed every
                // local replica, so all bindings are corpses: re-queue them
                // from wire truth (they re-place on approach) instead of
                // letting the sweep report false deaths.
                std::lock_guard<std::mutex> lk(g_mx);
                std::size_t requeued = 0;
                for (auto& [wid, b] : g_wid_to_bound) {
                    if (b.entry.flags & 1) continue;   // transient: gone is gone
                    g_pending.push_back(b.entry);
                    ++requeued;
                }
                g_wid_to_bound.clear();
                g_fid_to_wid.clear();
                g_handle_to_wid.clear();
                g_settle_until_ms = now0 + kJumpSettleMs;
                g_have_last_pos   = false;
                FW_LOG("[world-spawn] death stand-down CLOSED — %zu "
                       "binding(s) re-queued for re-placement on approach, "
                       "%ums settle", requeued, unsigned(kJumpSettleMs));
            }
        }
        if (standdown) return;
        float pp[3];
        if (player_pos(module_base, pp)) {
            if (g_have_last_pos) {
                const float dx = pp[0] - g_last_pos[0];
                const float dy = pp[1] - g_last_pos[1];
                const float dz = pp[2] - g_last_pos[2];
                if (dx * dx + dy * dy + dz * dz > kJumpUnits * kJumpUnits) {
                    g_settle_until_ms = now0 + kJumpSettleMs;
                    FW_LOG("[world-spawn] player position JUMPED (>%.0f "
                           "units: teleport/fast travel/load) — tick paused "
                           "%ums for the world to settle",
                           kJumpUnits, unsigned(kJumpSettleMs));
                }
            }
            g_last_pos[0] = pp[0];
            g_last_pos[1] = pp[1];
            g_last_pos[2] = pp[2];
            g_have_last_pos = true;
        }
        if (g_settle_until_ms != 0) {
            if (now0 < g_settle_until_ms) return;
            g_settle_until_ms = 0;
        }
    }

    // L5 stage 3 - the saved copies of the save that just loaded go first:
    // the bootstrap's placements are queued behind this line and would
    // otherwise stand next to their own copies. A tick passes after a
    // purge that destroyed anything: on live test #4 the copy's rigid body
    // and the fresh replica shared one tick and Havok kicked the replica
    // 27 units away.
    if (run_saved_copy_purge()) return;

    // 2026-10-04 — the adopted copies disabled for their move are enabled
    // again once the move is written: the engine rebuilds their 3D where
    // the reference now is.
    {
        std::vector<Reenable> due;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            const DWORD n1 = GetTickCount();
            for (auto it = g_reenable.begin(); it != g_reenable.end();) {
                if (static_cast<std::int32_t>(n1 - it->due_ms) >= 0) {
                    due.push_back(*it);
                    it = g_reenable.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const Reenable& r : due) {
            void* refr = resolve_object(r.handle, r.fid);
            if (!refr) {
                FW_WRN("[world-spawn] wid=%u: the adopted copy fid=0x%08X no longer resolves: "
                       "not enabled again", r.wid, r.fid);
                continue;
            }
            const bool was_disabled = seh_refr_disabled(refr);
            fw::engine::enable_ref(refr);
            FW_LOG("[world-spawn] wid=%u: the adopted copy fid=0x%08X enabled again at the "
                   "server's position (it read as %s before; %s now)", r.wid, r.fid,
                   was_disabled ? "disabled" : "enabled",
                   seh_refr_disabled(refr) ? "still disabled" : "enabled");
        }
    }

    // 2026-10-04 — the zombie frames: once the purge of a load is over, and
    // at each change of the player's cell.
    {
        static std::uint32_t s_zombie_cell = 0;
        static DWORD         s_zombie_ms   = 0;
        const std::uint32_t here = player_cell_id(module_base);
        const DWORD n2 = GetTickCount();
        bool load_due = false;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            load_due = !g_purge_armed && g_zombie_sweep_due;
        }
        const bool cell_due = here != 0 && here != s_zombie_cell;
        if ((load_due || cell_due) && n2 - s_zombie_ms >= 2000) {
            {
                std::lock_guard<std::mutex> lk(g_mx);
                if (load_due) g_zombie_sweep_due = false;
            }
            s_zombie_cell = here;
            s_zombie_ms   = n2;
            run_zombie_frame_sweep(load_due ? "after the load" : "the player changed cell");
        }
    }

    // Build 70i - deferred PA diagnostic dump (fires ~2.5s after the enter,
    // when the race-swap model reload has landed).
    if (g_pa_diag_second_ms != 0
        && GetTickCount() >= g_pa_diag_second_ms) {
        g_pa_diag_second_ms = 0;
        fw::native::dump_local_player_tree("PA-enter+2.5s");
        // Build 70t — THE MEASUREMENT. Geometry leaves under the local
        // player's own 3D once its PA build has settled. A healthy power
        // armour carries the frame's geometries; a poisoned build is
        // missing them. Read this against the [pa-bisect] mode of the last
        // attach: whichever mode stops the drop names the guilty step.
        // Build 70v — THE VERDICT LINE. Measured 2026-08-16: a healthy
        // power-armour build shows 23 geometry leaves, a poisoned one 20 —
        // exactly the 3 geometries of Frame.nif, missing. The best count
        // seen this session is the healthy baseline, so the line reads
        // itself with no hardcoded number.
        //
        // The forced model reload (Build 70u) is GONE: measured 20 -> 20 on
        // every poisoned build. sub_140D35EA0 + sub_140D020E0 do not rebuild
        // the biped body, so whatever makes the SECOND enter healthy is in
        // the rest of the enter pipeline, not in that pair. It only ever
        // "worked" on a build that was already healthy.
        const int geoms = fw::native::count_local_player_geometries();
        if (geoms > g_pa_geoms_best) g_pa_geoms_best = geoms;
        ++g_pa_samples;
        const int delta = geoms - g_pa_geoms_best;
        // Build 70w — the mode printed is the one that WILL run next; the
        // one that produced this verdict is the other. Spelled out because
        // the previous run's log needed hand-correlation by timestamp.
        const int next_mode = fw::native::pa_bisect_mode() & 1;
        const int ran_mode  = (next_mode + 1) & 1;
        FW_LOG("[pa-body] %d geometry leaves (best this session %d, delta "
               "%+d) => %s%s | verdict for attach mode %d = %s",
               geoms, g_pa_geoms_best, delta,
               (delta == 0) ? "BODY PRESENT" : "BODY MISSING",
               (g_pa_samples < 2) ? " [baseline still learning — ignore "
                                    "this first sample]" : "",
               ran_mode,
               (ran_mode == 0) ? "LOAD-ONLY(no clone at all)"
                               : "LOAD+CLONE(then release, attach nothing)");
        // Build 71 — ground truth for the ghost's power-armour subtree:
        // what a CORRECT power armour is made of on this very machine.
        // The skin-swap log names the ghost's side (PAFrame01:0 and
        // basesuit_reduced:0); this is the other half of the diff, and it
        // is what tells us which geometry the ghost is missing rather than
        // us guessing at feet and hands.
        fw::native::log_local_player_geometry_names("PA-enter+2.5s");
    }

    // ---- apply queued despawns first: unbind, then disable the local copy.
    {
        std::vector<std::uint32_t> dead;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            dead.swap(g_pending_despawns);
        }
        for (const std::uint32_t wid : dead) {
            std::uint32_t fid = 0;
            std::uint32_t handle = 0;
            bool self_reported = false;
            bool self_described = false;
            std::size_t purged = 0;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                auto it = g_wid_to_bound.find(wid);
                if (it != g_wid_to_bound.end()) {
                    fid           = it->second.fid;
                    handle        = it->second.handle;
                    self_reported = it->second.reported;
                    self_described = (it->second.entry.flags
                                      & fw::net::kWorldSpawnFlagSelfDescribed) != 0;
                    g_fid_to_wid.erase(fid);
                    if (handle) g_handle_to_wid.erase(handle);
                    g_wid_to_bound.erase(it);
                }
                // Build 70b — a despawned wid may still be QUEUED behind the
                // range gate (measured: wid=4 was despawned while pending on
                // the far client, then PLACED on approach anyway — a phantom
                // of an armor the wearer already occupied). Purge the queue.
                for (auto it2 = g_pending.begin(); it2 != g_pending.end();) {
                    if (it2->wid == wid) {
                        it2 = g_pending.erase(it2);
                        ++purged;
                    } else {
                        ++it2;
                    }
                }
            }
            if (purged) {
                FW_LOG("[world-spawn] despawn wid=%u: purged %zu queued "
                       "placement(s) waiting behind the range gate",
                       wid, purged);
            }
            {
                // 2026-09-30 — a saved copy kept for this wid dies with it.
                Adoptable ad{};
                bool have_ad = false;
                {
                    std::lock_guard<std::mutex> lk(g_mx);
                    for (auto it = g_adoptable.begin(); it != g_adoptable.end(); ++it) {
                        if (it->wid == wid) { ad = *it; have_ad = true; g_adoptable.erase(it); break; }
                    }
                }
                if (have_ad) {
                    void* old = resolve_object(ad.handle, ad.fid);
                    const bool gone = old && fw::engine::destroy_world_refr(old);
                    FW_LOG("[world-spawn] despawn wid=%u: the saved copy fid=0x%08X kept for "
                           "adoption %s", wid, ad.fid, gone ? "DESTROYED" : "was already gone");
                    ++purged;
                }
            }
            if (fid == 0) {
                if (!purged) {
                    FW_LOG("[world-spawn] despawn wid=%u: nothing bound here "
                           "(we reported it, or never placed it)", wid);
                }
                continue;
            }
            if (self_reported) {
                // OUR sweep saw this die — the engine did the killing (the PA
                // frame the player just climbed into). Disabling it again is
                // pointless, and forgetting it would lose the exit: keep the
                // fid on the resurrection watch instead.
                std::lock_guard<std::mutex> lk(g_mx);
                if (g_tombstones.size() < kTombstoneCap) {
                    g_tombstones.push_back({fid, GetTickCount(), self_described, handle});
                }
                FW_LOG("[world-spawn] despawn wid=%u confirmed for our own "
                       "report — fid=0x%08X on resurrection watch", wid, fid);
                continue;
            }
            void* refr = resolve_object(handle, fid);
            if (refr) {
                // Build 70 - REAL removal, not disable. The old
                // disable_ref(fade=true) parked the entry in the engine's
                // fade queue forever (the fade is never armed on that path):
                // the copy stayed VISIBLE, and the PA-exit resurrection then
                // placed a second one next to it - the measured duplicate.
                const bool gone = fw::engine::destroy_world_refr(refr);
                FW_LOG("[world-spawn] despawn wid=%u -> local fid=0x%08X "
                       "%s", wid, fid,
                       gone ? "DESTROYED (disable+unfile+destroy)"
                            : "destroy FAILED - see preceding SEH line");
            } else {
                FW_LOG("[world-spawn] despawn wid=%u -> local fid=0x%08X was "
                       "already gone", wid, fid);
            }
        }
    }

    // ---- v23 -> 2026-09-29: apply queued piece updates IN PLACE (see
    // align_frame_pieces). The v23 destroy-and-replace survives only for a
    // bound object that no longer resolves: then there is nothing to align
    // and a fresh placement with the new content is the right answer.
    {
        std::vector<PiecesUpdate> updates;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            updates.swap(g_pending_piece_updates);
        }
        for (const PiecesUpdate& u : updates) {
            SpawnEntry entry{};
            std::uint32_t fid = 0;
            std::uint32_t handle = 0;
            bool have = false;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                auto it = g_wid_to_bound.find(u.wid);
                if (it != g_wid_to_bound.end()) {
                    fid    = it->second.fid;
                    handle = it->second.handle;
                    entry  = it->second.entry;
                    have   = true;
                } else {
                    // Not placed yet — update the queued entry in place.
                    for (auto& p : g_pending) {
                        if (p.wid != u.wid) continue;
                        p.piece_n = u.n;
                        for (std::uint8_t i = 0; i < u.n; ++i) {
                            p.pieces[i] = u.entries[i];
                        }
                        FW_LOG("[pa-pieces] wid=%u still queued — updated "
                               "pending entry to %u entr%s", u.wid, u.n,
                               u.n == 1 ? "y" : "ies");
                        break;
                    }
                }
            }
            if (!have) continue;
            entry.piece_n = u.n;
            for (std::uint8_t i = 0; i < u.n; ++i) {
                entry.pieces[i] = u.entries[i];
            }
            void* refr = resolve_object(handle, fid);
            if (!refr) {
                std::lock_guard<std::mutex> lk(g_mx);
                auto it = g_wid_to_bound.find(u.wid);
                if (it != g_wid_to_bound.end() && it->second.fid == fid) {
                    g_fid_to_wid.erase(fid);
                    if (handle) g_handle_to_wid.erase(handle);
                    g_wid_to_bound.erase(it);
                }
                if (!(entry.flags & 1)) g_pending.push_back(entry);
                FW_LOG("[pa-pieces] wid=%u content changed remotely -> its frame fid=0x%08X no "
                       "longer resolves: placed again with %u entr%s", u.wid, fid, u.n,
                       u.n == 1 ? "y" : "ies");
                continue;
            }
            if (seh_refr_disabled(refr)) {
                FW_LOG("[pa-pieces] wid=%u content changed remotely -> frame fid=0x%08X is disabled "
                       "(worn or despawned): its inventory is left as it is, the new list is kept",
                       u.wid, fid);
            } else {
                fw::hooks::ApplyingRemoteGuard guard;
                align_frame_pieces(refr, fid, u.wid, u.entries, u.n);
            }
            {
                // The ledger copy follows what the frame now holds, so the
                // station poll stays quiet and no report echoes it back.
                std::lock_guard<std::mutex> lk(g_mx);
                auto it = g_wid_to_bound.find(u.wid);
                if (it != g_wid_to_bound.end()) {
                    it->second.entry.piece_n = entry.piece_n;
                    for (std::uint8_t i = 0; i < entry.piece_n && i < 12; ++i) {
                        it->second.entry.pieces[i] = entry.pieces[i];
                    }
                }
            }
        }
    }

    // ---- L5 stage 2: deaths the pickup hook reported (reason 5), the
    // drops that rested, the dressings to verify.
    {
        std::vector<PickupDeath> picked;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            picked.swap(g_pickup_deaths);
        }
        for (const PickupDeath& d : picked) {
            FW_LOG("[world-spawn] wid=%u (fid=0x%08X) picked up by the local player "
                   "-> WORLD_DESPAWN_OP sent (reason=5)", d.wid, d.fid);
            fw::net::client().enqueue_world_despawn_op(
                d.wid, 5, static_cast<std::uint64_t>(GetTickCount64()));
        }
    }
    tick_pending_drops();
    tick_dress_verify(module_base);

    // ---- v23b: fire deferred manual-change reports whose settle window
    // has elapsed (the take-timing fix — see report_frame_pieces).
    fire_due_frame_reports();

    // ---- v26: station poll (see kStationPollEveryMs). The PA station edits
    // pieces in place; nothing else reports that, so while its menu lives
    // the live content of every nearby bound frame is checked against the
    // ledger and a difference queues the usual deferred report.
    {
        const std::uint64_t now64  = static_cast<std::uint64_t>(GetTickCount64());
        const std::uint64_t closed = fw::hooks::pa_mod_menu_closed_ms();
        const bool active = fw::hooks::pa_mod_menu_open()
            || (closed != 0 && now64 - closed < kStationPollTailMs);
        if (active && now64 >= g_next_station_poll_ms) {
            g_next_station_poll_ms = now64 + kStationPollEveryMs;
            float pp[3];
            if (player_pos(module_base, pp)) {
                struct Cand { std::uint32_t wid, fid, handle; };
                std::vector<Cand> cands;
                {
                    std::lock_guard<std::mutex> lk(g_mx);
                    for (const auto& [wid, b] : g_wid_to_bound) {
                        if (b.reported) continue;
                        if (b.entry.base_form_id != kPaFrameBase) continue;
                        const float dx = b.entry.pos[0] - pp[0];
                        const float dy = b.entry.pos[1] - pp[1];
                        const float dz = b.entry.pos[2] - pp[2];
                        if (dx * dx + dy * dy + dz * dz
                            > kStationPollRange * kStationPollRange) continue;
                        cands.push_back({wid, b.fid, b.handle});
                    }
                }
                for (const Cand& c : cands) {
                    void* refr = resolve_object(c.handle, c.fid);
                    if (!refr) continue;
                    fw::net::PaPieceEntry live[12] = {};
                    const std::uint8_t n =
                        capture_frame_pieces(refr, kPaFrameBase, live);
                    bool same = true;
                    {
                        std::lock_guard<std::mutex> lk(g_mx);
                        auto it = g_wid_to_bound.find(c.wid);
                        if (it != g_wid_to_bound.end()) {
                            same = pieces_equal(it->second.entry, live, n);
                        }
                    }
                    // Stability gate (see kStationStablePolls): a preview
                    // changes on every hover, an edit stays.
                    const std::uint64_t hsh = pieces_hash(live, n);
                    StationSeen& seen = g_station_seen[c.wid];
                    if (seen.hash == hsh) {
                        if (seen.repeats < 1000) ++seen.repeats;
                    } else {
                        seen.hash = hsh;
                        seen.repeats = 1;
                    }
                    if (!same && seen.repeats >= kStationStablePolls) {
                        FW_LOG("[pa-pieces] station poll: frame fid=0x%08X (wid=%u) "
                               "content differs from the ledger and held for %d "
                               "polls (%u live entr%s) -> report queued", c.fid,
                               c.wid, kStationStablePolls, unsigned(n),
                               n == 1 ? "y" : "ies");
                        report_frame_pieces(refr, c.fid);
                    }
                }
            }
        }
    }

    // ---- lifecycle sweep: the despawn SENDER. Polls every bound object and
    // reports death by wid. A poll, not a teardown hook, on purpose.
    {
        const DWORD now_ms = GetTickCount();
        if (g_next_sweep_ms == 0 || now_ms >= g_next_sweep_ms) {
            g_next_sweep_ms = now_ms + kSweepEveryMs;
            struct Death { std::uint32_t wid; std::uint8_t reason; };
            std::vector<Death> deaths;
            std::vector<std::uint32_t> streaming_losses;
            bool pa_enter_diag = false;   // Build 70i
            {
                std::lock_guard<std::mutex> lk(g_mx);
                const std::uint32_t here = player_cell_id(module_base);
                for (auto& [wid, b] : g_wid_to_bound) {
                    if (b.reported) continue;
                    // Freshly placed objects get a settling window before any
                    // death verdict — the false kill that motivated this
                    // fired one second after placement.
                    if (now_ms - b.bound_at_ms < kDeathGraceMs) continue;
                    void* refr = resolve_object(b.handle, b.fid);
                    std::uint8_t reason = 0;
                    bool pc_alive = false;
                    if (refr) {
                        b.null_seen = false;
                        const std::uint32_t flags = seh_u32_at(
                            reinterpret_cast<std::uint8_t*>(refr)
                            + fw::offsets::FORMID_OFF - 4);
                        // FORMID_OFF-4 == FLAGS_OFF (0x10); spelled via the
                        // offset arithmetic so a future FLAGS_OFF move breaks
                        // the build instead of silently reading garbage.
                        static_assert(fw::offsets::FLAGS_OFF
                                      == fw::offsets::FORMID_OFF - 4,
                                      "flags/formid adjacency assumed here");
                        // Track the ref's LIVE cell while it is readable, so
                        // the vanish test below compares against where the
                        // object actually last stood.
                        void* pc = seh_deref(
                            reinterpret_cast<std::uintptr_t>(refr)
                            + fw::offsets::PARENT_CELL_OFF);
                        if (pc) {
                            pc_alive = true;
                            const std::uint32_t cid = seh_u32_at(
                                reinterpret_cast<std::uint8_t*>(pc)
                                + fw::offsets::FORMID_OFF);
                            if (cid) b.cell_id = cid;
                        }
                        // The 3D watch (the Bound's comment): said once.
                        if (!(flags & kFlagDeleted) && !(flags & fw::offsets::FLAG_DISABLED)) {
                            void* loaded = seh_deref(reinterpret_cast<std::uintptr_t>(refr)
                                                     + fw::offsets::REFR_LOADED_DATA_OFF);
                            if (loaded) {
                                b.no3d_since_ms = 0;
                                b.no3d_said = false;
                            } else if (b.no3d_since_ms == 0) {
                                b.no3d_since_ms = now_ms;
                            } else if (!b.no3d_said && now_ms - b.no3d_since_ms >= 5000) {
                                float op[3] = {0.0f, 0.0f, 0.0f}, pp[3] = {0.0f, 0.0f, 0.0f};
                                void* lp = fw::engine::get_local_player();
                                const bool have = seh_vec3_at(reinterpret_cast<std::uint8_t*>(refr)
                                                              + fw::offsets::POS_OFF, op)
                                    && lp && seh_vec3_at(static_cast<std::uint8_t*>(lp)
                                                         + fw::offsets::POS_OFF, pp);
                                const float dx = op[0] - pp[0], dy = op[1] - pp[1];
                                const float d = have ? std::sqrt(dx * dx + dy * dy) : -1.0f;
                                if (have && d < 6000.0f) {
                                    b.no3d_said = true;
                                    FW_LOG("[world-spawn] wid=%u (base 0x%08X, fid 0x%08X) has had NO 3D for "
                                           "%llu ms at (%.0f, %.0f, %.0f), %.0f units from the player: the "
                                           "engine never loaded its model", wid, b.entry.base_form_id, b.fid,
                                           static_cast<unsigned long long>(now_ms - b.no3d_since_ms),
                                           op[0], op[1], op[2], d);
                                }
                            }
                        }
                        if (flags & kFlagDeleted)                 reason = 1;
                        else if (flags & fw::offsets::FLAG_DISABLED) reason = 2;
                        else if (b.ours) {
                            // v26 — drift watch (see kMoveThresholdUnits).
                            float p[3], r[3];
                            auto* rb = reinterpret_cast<std::uint8_t*>(refr);
                            if (seh_vec3_at(rb + fw::offsets::POS_OFF, p)
                                && seh_vec3_at(rb + fw::offsets::ROT_OFF, r)) {
                                const float dx = p[0] - b.entry.pos[0];
                                const float dy = p[1] - b.entry.pos[1];
                                const float dz = p[2] - b.entry.pos[2];
                                const float d2 = dx * dx + dy * dy + dz * dz;
                                const float dyaw = yaw_delta(r[2], b.entry.rot[2]);
                                if (d2 > kMoveThresholdUnits * kMoveThresholdUnits
                                    || dyaw > kMoveYawThresholdRad) {
                                    const float sx = p[0] - b.last_pos[0];
                                    const float sy = p[1] - b.last_pos[1];
                                    const float sz = p[2] - b.last_pos[2];
                                    const bool settled = b.move_seen
                                        && (sx * sx + sy * sy + sz * sz) < 1.0f
                                        && yaw_delta(r[2], b.last_yaw) < 0.02f;
                                    if (settled) {
                                        FW_LOG("[world-spawn] wid=%u (ours) stands "
                                               "%.0f units / %.0f deg from its "
                                               "announced pose (%.1f, %.1f, %.1f) -> "
                                               "(%.1f, %.1f, %.1f): moved by the "
                                               "engine, re-announcing through "
                                               "despawn reason 4 + rebirth", wid,
                                               std::sqrt(d2), dyaw * 57.29578f,
                                               b.entry.pos[0], b.entry.pos[1],
                                               b.entry.pos[2], p[0], p[1], p[2]);
                                        reason = 4;
                                    } else {
                                        b.move_seen = true;
                                        b.last_pos[0] = p[0];
                                        b.last_pos[1] = p[1];
                                        b.last_pos[2] = p[2];
                                        b.last_yaw    = r[2];
                                    }
                                } else {
                                    b.move_seen = false;
                                }
                            }
                        }
                    } else if (b.entry.flags & fw::net::kWorldSpawnFlagContainer) {
                        // L5 realtime D1: the copy of a crate of the server's
                        // the engine freed (its cell went out of memory) is
                        // queued again at once (below: never reported), not
                        // when the player steps into that very cell: the
                        // next copy is placed on approach.
                        reason = 3;
                    } else if (here != 0 && b.cell_id == here) {
                        reason = 3;   // vanished while its cell is loaded
                    } else if (!b.null_seen) {
                        // The path that used to be SILENT, and silence cost a
                        // test cycle: say exactly what state blocked the call.
                        b.null_seen = true;
                        FW_LOG("[world-spawn] wid=%u: local fid=0x%08X no "
                               "longer resolves, but its last cell 0x%08X is "
                               "not the player's current cell 0x%08X — NOT "
                               "reported as dead (cell-unload is benign; if "
                               "this object was just consumed, this line is "
                               "the bug)", wid, b.fid, b.cell_id, here);
                    }
                    if (reason == 2
                        && b.entry.base_form_id == kPaFrameBase) {
                        // Build 70i - the LOCAL player just entered this
                        // frame (engine set DISABLED on it). Arm the tree
                        // dumps; fired outside this lock below.
                        pa_enter_diag       = true;
                        g_pa_diag_second_ms = now_ms + kPaDiag2ndMs;
                    }
                    // L5 stage 2 — an ITEM (self-described) marked deleted
                    // while its parent cell is alive was consumed (picked
                    // up by someone the pickup hook did not see, a script):
                    // a world event. The janitor case below has no live
                    // parent cell by definition.
                    const bool item = (b.entry.flags
                                       & fw::net::kWorldSpawnFlagSelfDescribed) != 0;
                    // L5 realtime D1: a container of the server's (the death
                    // crate) is never reported dead by a client: only the
                    // server ends it, when it is emptied; whatever happened
                    // to this copy, it is placed again on approach.
                    const bool server_container =
                        (b.entry.flags & fw::net::kWorldSpawnFlagContainer) != 0;
                    if (reason && server_container) {
                        streaming_losses.push_back(wid);
                    } else if (reason == 1 && !(item && pc_alive)) {
                        // Build 70b — DELETED by the engine is a LOCAL
                        // streaming event, not a world event. Measured live:
                        // the engine's PA janitor (caller +0x109DAA7)
                        // unpersists and destroys any frame whose parentCell
                        // died with the cell unload — B teleported away, the
                        // janitor ate B's replica, the old code reported it,
                        // and the server killed the wid A was standing next
                        // to. The server object is the truth: re-queue and
                        // re-place on approach instead.
                        streaming_losses.push_back(wid);
                    } else if (reason) {
                        b.reported = true;
                        deaths.push_back({wid, reason});
                    }
                }
                for (const std::uint32_t wid : streaming_losses) {
                    auto it = g_wid_to_bound.find(wid);
                    if (it == g_wid_to_bound.end()) continue;
                    FW_LOG("[world-spawn] wid=%u: local replica destroyed by "
                           "the engine (streaming/janitor) — NOT a world "
                           "event; re-queued for re-placement on approach",
                           wid);
                    if (!(it->second.entry.flags & 1)) {
                        g_pending.push_back(it->second.entry);
                    }
                    g_fid_to_wid.erase(it->second.fid);
                    if (it->second.handle) g_handle_to_wid.erase(it->second.handle);
                    g_wid_to_bound.erase(it);
                }
            }
            for (const auto& d : deaths) {
                FW_LOG("[world-spawn] wid=%u died locally (reason=%u: "
                       "1=deleted 2=disabled 3=vanished-same-cell 4=moved "
                       "5=picked up) -> WORLD_DESPAWN_OP sent", d.wid, d.reason);
                fw::net::client().enqueue_world_despawn_op(
                    d.wid, d.reason,
                    static_cast<std::uint64_t>(GetTickCount64()));
            }
            if (pa_enter_diag) {
                fw::native::dump_local_player_tree("PA-enter");
            }

            // ---- resurrection watch: a tombstoned fid whose ref is alive
            // again (exit from the power armor clears the disabled flag on
            // the same ref) is re-announced as a NEW spawn at its live
            // position. The server mints a fresh wid; the echo re-binds it.
            struct Rebirth {
                std::uint32_t fid, base_id, cell_id;
                float pos[3], rot[3];
                // v23/v24 — the frame's content at rebirth (the
                // post-exit truth: what the departing player left mounted,
                // with each piece's OMOD list).
                std::uint8_t          piece_n = 0;
                fw::net::PaPieceEntry pieces[12] = {};
                std::uint8_t          flags = 0;   // bit1 = self-described
                std::uint32_t         handle = 0;
            };
            std::vector<Rebirth> reborn;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                for (auto it = g_tombstones.begin();
                     it != g_tombstones.end();) {
                    if (now_ms - it->since_ms > kTombstoneTtlMs) {
                        it = g_tombstones.erase(it);
                        continue;
                    }
                    void* refr = resolve_object(it->handle, it->fid);
                    if (!refr) {
                        it = g_tombstones.erase(it);   // really gone
                        continue;
                    }
                    const std::uint32_t flags = seh_u32_at(
                        reinterpret_cast<std::uint8_t*>(refr)
                        + fw::offsets::FLAGS_OFF);
                    if (flags & (kFlagDeleted | fw::offsets::FLAG_DISABLED)) {
                        ++it;   // still dead — keep watching
                        continue;
                    }
                    const auto id = fw::read_ref_identity(refr);
                    Rebirth r{};
                    r.fid = it->fid;
                    r.handle = it->handle;
                    r.base_id = id.base_id;
                    r.cell_id = id.cell_id;
                    auto* rb = reinterpret_cast<std::uint8_t*>(refr);
                    (void)seh_vec3_at(rb + fw::offsets::POS_OFF, r.pos);
                    (void)seh_vec3_at(rb + fw::offsets::ROT_OFF, r.rot);
                    // E0 (pieces) — a reborn PA frame is the exit moment:
                    // the native transfer has just put the pieces back.
                    // THIS inventory is what a departing player leaves,
                    // i.e. exactly the state the replica model must carry —
                    // v23 captures it into the announce.
                    if (r.base_id == kPaFrameBase) {
                        fw::hooks::dump_refr_inventory(
                            "PA-exit reborn frame", refr);
                        r.piece_n = capture_frame_pieces(
                            refr, r.base_id, r.pieces);
                    } else if (it->self_described) {
                        // A dropped item that moved (its own fall, a
                        // nudge): re-announce WITH its descriptor, so the
                        // replicas keep count, condition and mods.
                        r.flags = fw::net::kWorldSpawnFlagSelfDescribed;
                        if (!fw::persist::inventory::read_refr_instance(
                                module_base, refr, &r.pieces[0])) {
                            FW_WRN("[world-spawn] fid=0x%08X: instance unread at "
                                   "rebirth, re-announced with a bare descriptor",
                                   r.fid);
                            r.pieces[0].form_id = r.base_id;
                        }
                        r.piece_n = 1;
                    }
                    if (r.base_id != 0) reborn.push_back(r);
                    it = g_tombstones.erase(it);
                }
            }
            for (const auto& r : reborn) {
                FW_LOG("[world-spawn] fid=0x%08X is ALIVE again (power-armor "
                       "exit or re-enable) at (%.1f, %.1f, %.1f) -> "
                       "re-announced as a new spawn", r.fid,
                       r.pos[0], r.pos[1], r.pos[2]);
                note_self_object(r.fid, r.handle);
                fw::net::client().enqueue_world_spawn_op(
                    r.base_id, r.fid, r.pos, r.rot, r.cell_id, r.flags,
                    static_cast<std::uint64_t>(GetTickCount64()),
                    r.piece_n ? r.pieces : nullptr, r.piece_n);
                if (r.base_id == kPaFrameBase) {
                    fw::native::dump_local_player_tree("PA-exit");
                }
            }
        }
    }

    SpawnEntry e;
    std::size_t pick = 0;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        if (g_pending.empty()) return;
        float pp[3];
        if (!player_pos(module_base, pp)) return;   // load screen — wait
        bool have = false;
        for (std::size_t i = 0; i < g_pending.size(); ++i) {
            const auto& c = g_pending[i];
            const float dx = c.pos[0] - pp[0];
            const float dy = c.pos[1] - pp[1];
            const float dz = c.pos[2] - pp[2];
            if (dx * dx + dy * dy + dz * dz
                    <= kPlaceRadius * kPlaceRadius) {
                // L5 realtime D1 (2026-10-04, every object of the server's: the
                // crates, the dropped items, the frames): an object goes only
                // into its own cell, or into the player's worldspace when it
                // stands outside. The range alone put an object of an interior
                // into any other interior with the same local coordinates
                // (most interiors are built around the origin) and into a
                // child worldspace over its parent. An entry without a cell
                // (never seen on the wire) keeps the range alone.
                if (c.cell_id != 0) {
                    const auto where = fw::engine::cell_place_for_player(c.cell_id, c.pos[0],
                                                                         c.pos[1]);
                    if (where != fw::engine::CellPlace::Here) {
                        static DWORD s_cell_log = 0;
                        const DWORD n1 = GetTickCount();
                        if (n1 - s_cell_log >= 10000) {
                            s_cell_log = n1;
                            FW_LOG("[world-spawn] wid=%u (base=0x%08X) is in range but its cell "
                                   "0x%08X is %s: placed when the player is there", c.wid,
                                   c.base_form_id, c.cell_id,
                                   where == fw::engine::CellPlace::Elsewhere
                                       ? "not here (an interior the player is not in, or "
                                         "another worldspace)"
                                       : where == fw::engine::CellPlace::NotLoaded
                                       ? "not loaded yet (an exterior the engine has not "
                                         "loaded in this session)"
                                       : "unreadable now");
                        }
                        continue;
                    }
                }
                e = c; pick = i; have = true;
                break;
            }
        }
        if (!have) {
            // Everything pending is far away. Say so occasionally — the
            // object appearing only on approach is by design, but a log line
            // separates by-design from stuck at a glance.
            static DWORD s_far_log = 0;
            const DWORD n2 = GetTickCount();
            if (n2 - s_far_log >= 10000) {
                s_far_log = n2;
                FW_LOG("[world-spawn] %zu spawn(s) pending, none within %.0f "
                       "units — they will be placed on approach",
                       g_pending.size(), kPlaceRadius);
            }
            return;
        }
    }

    const DWORD now = GetTickCount();
    if (g_next_attempt_ms != 0 && now < g_next_attempt_ms) return;
    g_next_attempt_ms = now + kRetryDelayMs;

    // Build 70d — liveness line. A candidate in range that repeatedly fails
    // to place must be VISIBLE: the post-respawn test window had B standing
    // 143 units from a pending armor with a mute log for 4 seconds.
    {
        static DWORD s_try_log_ms = 0;
        if (now - s_try_log_ms >= 2000) {
            s_try_log_ms = now;
            FW_LOG("[world-spawn] attempting wid=%u (base=0x%08X, in range, "
                   "attempt #%d)", e.wid, e.base_form_id, g_attempts + 1);
        }
    }

    // 2026-09-30 — a saved copy kept for this wid (see g_adoptable) is bound
    // instead of placing a new replica: the engine's references to it, the
    // player's last power armour among them, stay valid.
    {
        Adoptable ad{};
        bool have_ad = false;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            for (auto it = g_adoptable.begin(); it != g_adoptable.end(); ++it) {
                if (it->wid == e.wid) { ad = *it; have_ad = true; g_adoptable.erase(it); break; }
            }
        }
        void* old = have_ad ? resolve_object(ad.handle, ad.fid) : nullptr;
        if (have_ad && !old) {
            FW_WRN("[world-spawn] wid=%u: the saved copy fid=0x%08X kept for adoption no longer "
                   "resolves: placed anew", e.wid, ad.fid);
        }
        if (old) {
            {
                std::lock_guard<std::mutex> lk(g_mx);
                for (auto it = g_pending.begin(); it != g_pending.end(); ++it) {
                    if (it->wid == e.wid) { g_pending.erase(it); break; }
                }
                g_attempts = 0;
                Bound b{};
                b.fid         = ad.fid;
                b.handle      = ad.handle;
                b.cell_id     = e.cell_id;
                b.bound_at_ms = GetTickCount();
                b.entry       = e;
                g_wid_to_bound[e.wid] = b;
                g_fid_to_wid[ad.fid]  = e.wid;
                if (ad.handle) g_handle_to_wid[ad.handle] = e.wid;
            }
            // Disabled = worn: the local player climbed into it before this
            // ran. Left as it is; the sweep reports it entered, as for any
            // bound frame.
            const bool worn = seh_refr_disabled(old);
            float p[3] = {0.0f, 0.0f, 0.0f};
            bool moved = false;
            bool reenable = false;
            if (!worn && seh_vec3_at(static_cast<const std::uint8_t*>(old) + fw::offsets::POS_OFF, p)) {
                const float dx = p[0] - e.pos[0], dy = p[1] - e.pos[1], dz = p[2] - e.pos[2];
                if (dx * dx + dy * dy + dz * dz > kMoveThresholdUnits * kMoveThresholdUnits) {
                    // 2026-10-04 (live test): the position leaf and the re-file
                    // move the reference, not a 3D already loaded: the adopted
                    // copy of wid 87 was "moved onto the server's position" and
                    // stayed in sight where the save had it. A copy with its 3D
                    // loaded is disabled first and enabled again a few ticks
                    // later, once the move is written: the engine rebuilds its
                    // 3D where the reference now is (the console's disable and
                    // enable). The sweep's grace after a binding covers the
                    // moment it reads as disabled.
                    const bool loaded = seh_loaded_3d(old);
                    if (loaded) fw::engine::disable_ref(old, false);
                    moved = fw::engine::finalize_world_placement(
                        old, e.pos[0], e.pos[1], e.pos[2], e.rot[2], nullptr, true).moved;
                    if (loaded) {
                        std::lock_guard<std::mutex> lk(g_mx);
                        g_reenable.push_back(Reenable{e.wid, ad.fid, ad.handle,
                                                      GetTickCount() + kReenableDelayMs});
                        reenable = true;
                    }
                }
            }
            FW_LOG("[world-spawn] wid=%u ADOPTED: the saved copy fid=0x%08X handle=0x%08X is "
                   "bound instead of a new replica%s%s%s", e.wid, ad.fid, ad.handle,
                   worn ? " (worn by the local player already: left as it is)" : "",
                   moved ? ", moved onto the server's position" : "",
                   reenable ? " (its 3D was loaded: disabled for the move, enabled again on a "
                              "later tick)" : "");
            if (!worn && e.base_form_id == kPaFrameBase) {
                fw::hooks::ApplyingRemoteGuard guard;
                align_frame_pieces(old, ad.fid, e.wid, e.pieces, e.piece_n);
            }
            return;
        }
    }

    // All engine work happens here, on the main thread, mirroring the ghost
    // donor: resolve the base form, PlaceAtMe anchored at the player (the
    // engine call is wrapped in the internal-place scope so our own sender
    // detour does not re-broadcast it), then move it to the real target.
    std::uint32_t new_fid = 0;
    std::uint32_t new_handle = 0;
    void* refr = fw::engine::place_world_object(e.base_form_id, &new_fid, &new_handle);
    if (!refr) {
        if (++g_attempts >= kMaxAttempts) {
            FW_ERR("[world-spawn] wid=%u: placement failed %d times — giving "
                   "this object up (base=0x%08X)", e.wid, g_attempts,
                   e.base_form_id);
            std::lock_guard<std::mutex> lk(g_mx);
            if (pick < g_pending.size() && g_pending[pick].wid == e.wid) {
                g_pending.erase(g_pending.begin()
                                + static_cast<std::ptrdiff_t>(pick));
            }
            g_attempts = 0;
        }
        return;   // world not ready yet (load screen, player null) — retry
    }

    // Build 70f — the correct placement: upright, ground-snapped, re-filed.
    // L5 stage 3 — a dropped item keeps the pose and the height the sender
    // measured at rest instead (engine_calls.h, "the two poses"): the snap
    // planted its centre in the road and Havok pushed it through.
    const bool item = (e.flags & fw::net::kWorldSpawnFlagSelfDescribed) != 0;
    const auto fin = fw::engine::finalize_world_placement(
        refr, e.pos[0], e.pos[1], e.pos[2], e.rot[2], item ? e.rot : nullptr, !item);
    const bool moved = fin.moved;

    {
        std::lock_guard<std::mutex> lk(g_mx);
        if (pick < g_pending.size() && g_pending[pick].wid == e.wid) {
            g_pending.erase(g_pending.begin()
                            + static_cast<std::ptrdiff_t>(pick));
        }
        g_attempts = 0;
        Bound b{};
        b.fid         = new_fid;
        b.handle      = new_handle;
        b.cell_id     = e.cell_id;
        b.bound_at_ms = GetTickCount();
        b.entry       = e;
        if (e.flags & fw::net::kWorldSpawnFlagSelfDescribed) {
            b.dress_verify_ms = b.bound_at_ms + kDressVerifyMs;
            b.dress_attempts  = 1;
        }
        g_wid_to_bound[e.wid]  = b;
        g_fid_to_wid[new_fid]  = e.wid;
        if (new_handle) g_handle_to_wid[new_handle] = e.wid;
    }
    FW_LOG("[world-spawn] wid=%u PLACED: base=0x%08X -> local fid=0x%08X handle=0x%08X at "
           "(%.1f, %.1f, %.1f) teleport=%s ground=%s%+.1f pose=%s refile=%s",
           e.wid, e.base_form_id, new_fid, new_handle,
           e.pos[0], e.pos[1], e.pos[2],
           moved ? "ok" : "FAILED (left at the player)",
           fin.snapped ? "snapped" : "wire", fin.dz,
           item ? "rested" : "upright",
           fin.refiled ? "ok" : "SKIPPED (target cell not attached)");

    // ========================================================================
    // v23 — stock the replica with the object's REAL content, carried on the
    // wire (E1's hardcoded set is dead: its stale list is what duplicated
    // pieces the moment one client removed some by hand). E0/E1 facts this
    // rides on: an ARMO in a frame's inventory IS a mounted piece — no flag
    // to write — and the engine's own AddItem right after placement renders
    // on the standing frame and transfers on enter, both verified live.
    // ========================================================================
    if (e.flags & fw::net::kWorldSpawnFlagContainer) {
        // L5 realtime D1: a container of the server's (the death crate). Its
        // content is the container record keyed by the wid: aligned now that
        // the copy exists (the base's own inventory goes, the record's
        // instances are built). Without the record yet, the CONTAINER_STATE
        // that brings it, or the activation, aligns it.
        const bool queued =
            fw::net::client().reconverge_container(fw::net::wid_container_key(e.wid));
        FW_LOG("[world-spawn] wid=%u is a crate of the server's: content %s", e.wid,
               queued ? "aligned to its record"
                      : "not known yet (aligned when its record arrives, or at the activation)");
    } else if (e.flags & fw::net::kWorldSpawnFlagSelfDescribed) {
        // L5 stage 2 — a dropped item: pieces[0] is the object itself.
        apply_self_descriptor(refr, new_fid, e);
    } else if (e.piece_n > 0) {
        int injected = 0;
        int mods_applied = 0, mods_failed = 0;
        for (std::uint8_t i = 0; i < e.piece_n && i < 12; ++i) {
            // 2026-09-29: the same code the in-place alignment of a
            // remote change uses (stock_one_piece).
            if (stock_one_piece(refr, e.pieces[i], &mods_applied, &mods_failed)) ++injected;
        }
        FW_LOG("[pa-pieces] stocked replica fid=0x%08X (wid=%u) with %d/%u "
               "wire entries, %d mods applied%s", new_fid, e.wid, injected,
               e.piece_n, mods_applied,
               mods_failed ? " (SOME MODS FAILED, see above)" : "");
        fw::hooks::dump_refr_inventory("post-stock", refr);
    }
}

void on_despawn(std::uint32_t wid) {
    if (wid == 0) return;
    std::lock_guard<std::mutex> lk(g_mx);
    g_pending_despawns.push_back(wid);
}

void on_pieces_update(std::uint32_t wid, const fw::net::PaPieceEntry* entries,
                      std::uint8_t n) {
    if (wid == 0) return;
    PiecesUpdate u{};
    u.wid = wid;
    u.n   = (n > 12) ? 12 : n;
    for (std::uint8_t i = 0; i < u.n && entries; ++i) {
        u.entries[i] = entries[i];
    }
    std::lock_guard<std::mutex> lk(g_mx);
    g_pending_piece_updates.push_back(u);
}

std::uint32_t wid_for_fid(std::uint32_t fid) {
    if (fid == 0) return 0;
    std::lock_guard<std::mutex> lk(g_mx);
    auto it = g_fid_to_wid.find(fid);
    return it == g_fid_to_wid.end() ? 0u : it->second;
}

std::uint8_t capture_frame_pieces(void* refr, std::uint32_t base_id,
                                  fw::net::PaPieceEntry out[12]) {
    if (!refr || base_id != kPaFrameBase) return 0;
    std::uint32_t ids[12] = {0};
    std::int32_t  cnts[12] = {0};
    const std::size_t n =
        fw::engine::scan_container_inventory(refr, ids, cnts, 12);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = fw::net::PaPieceEntry{};
        out[i].form_id = ids[i];
        // v26 — measured 2026-09-15: while the PowerArmorModMenu works on a
        // piece the engine keeps a working copy in the same inventory entry
        // and the count reads 2. Shipping that made every replica AddItem(2)
        // and the mod worker refuse the stack ("holds 2 of it"): the piece
        // came back stock on the peer, and from persistence on everyone.
        // The copy is never inventory; while the menu is open one is one.
        std::int32_t cnt = cnts[i];
        if (cnt > 1 && fw::hooks::pa_mod_menu_open()) {
            FW_LOG("[pa-pieces] piece 0x%08X: count %d read while the PA "
                   "station menu is open -> shipped as 1 (workbench working "
                   "copy)", ids[i], cnt);
            cnt = 1;
        }
        out[i].count   = cnt;
        // v24 — the piece's identity is form + OMODs: the Mk level lives
        // in the mods, and without them the replica's AddItem rolls a
        // fresh leveled variant.
        out[i].mod_n = fw::hooks::read_item_mod_forms(
            refr, ids[i], out[i].mods, fw::net::kMaxPieceMods);
        // v25 — condition / core charge, -1 = no extra on the original.
        out[i].health = read_stack_health(refr, ids[i]);
    }
    return static_cast<std::uint8_t>(n);
}

void report_frame_pieces(void* frame_refr, std::uint32_t fid) {
    (void)frame_refr;   // resolved fresh at fire time — see below
    if (fid == 0) return;
    // TIMING FIX (measured 2026-08-16 20:02:59): our hook sits on the
    // player-side AddObject, and at post-orig time of a TAKE the FRAME-side
    // removal has not landed yet — an immediate rescan counted 6 pieces
    // after removing one, shipped the stale 6, and the removed piece
    // resurrected on the peer: the infinite-dupe loop the user reported.
    // So the rescan is DEFERRED, deduped by fid (a burst of transfers
    // collapses into one report of the settled state). Gates are evaluated
    // at fire time, when they are true.
    std::lock_guard<std::mutex> lk(g_mx);
    const DWORD due = GetTickCount() + kFrameReportDelayMs;
    for (auto& d : g_deferred_reports) {
        if (d.fid == fid) { d.due_ms = due; return; }
    }
    if (g_deferred_reports.size() < 16) {
        g_deferred_reports.push_back({fid, due});
    }
}

// The deferred half: runs from tick() on the main thread.
static void fire_due_frame_reports() {
    std::vector<DeferredReport> due;
    {
        const DWORD now = GetTickCount();
        std::lock_guard<std::mutex> lk(g_mx);
        for (auto it = g_deferred_reports.begin();
             it != g_deferred_reports.end();) {
            if (now >= it->due_ms) {
                due.push_back(*it);
                it = g_deferred_reports.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (const DeferredReport& d : due) {
        // The enter drain empties the frame through the same engine path a
        // manual take uses; it is NOT a manual change (the rebirth announce
        // carries the post-exit truth). The tracer marks every local PA
        // transition — a recent one means this mutation was the drain.
        const std::uint64_t last = fw::hooks::last_local_pa_transition_ms();
        if (last != 0 && GetTickCount64() - last < 3000) {
            FW_LOG("[pa-pieces] deferred report for fid=0x%08X suppressed — "
                   "inside a PA transition window (the drain, not a manual "
                   "change)", d.fid);
            continue;
        }
        const std::uint32_t wid = wid_for_fid(d.fid);
        if (wid == 0) {
            FW_LOG("[pa-pieces] deferred report for fid=0x%08X suppressed — "
                   "no wid bound (despawned meanwhile, or never announced)",
                   d.fid);
            continue;
        }
        void* refr = fw::engine::lookup_by_form_id(d.fid);
        if (!refr) {
            FW_LOG("[pa-pieces] deferred report for fid=0x%08X suppressed — "
                   "ref no longer resolves", d.fid);
            continue;
        }
        fw::net::PaPieceEntry pieces[12] = {};
        const auto rid = fw::read_ref_identity(refr);
        const std::uint8_t n =
            capture_frame_pieces(refr, rid.base_id, pieces);
        // v26 — the ledger copy follows what we ship (the server does not
        // echo our own pieces op), so the station poll compares against
        // the last shipped state and stays quiet until the next edit.
        {
            std::lock_guard<std::mutex> lk(g_mx);
            auto it = g_wid_to_bound.find(wid);
            if (it != g_wid_to_bound.end()) {
                it->second.entry.piece_n = n;
                for (std::uint8_t i = 0; i < n; ++i) {
                    it->second.entry.pieces[i] = pieces[i];
                }
            }
        }
        fw::net::client().enqueue_world_pa_pieces_op(
            wid, pieces, n,
            static_cast<std::uint64_t>(GetTickCount64()));
        FW_LOG("[pa-pieces] manual change on frame fid=0x%08X (wid=%u) -> "
               "settled state shipped: %u entr%s", d.fid, wid, unsigned(n),
               n == 1 ? "y" : "ies");
    }
}

std::uint32_t local_fid_for_wid(std::uint32_t wid) {
    std::lock_guard<std::mutex> lk(g_mx);
    auto it = g_wid_to_bound.find(wid);
    return it == g_wid_to_bound.end() ? 0u : it->second.fid;
}

bool is_our_fid(std::uint32_t fid) {
    if (fid == 0) return false;
    std::lock_guard<std::mutex> lk(g_mx);
    return g_fid_to_wid.count(fid) != 0;
}

std::uint32_t wid_for_refr(void* refr, std::uint32_t fid) {
    if (!refr || fid == 0) return 0;
    if (fw::persist::exiting()) return 0;   // the teardown destroys everything; nothing of ours to confirm
    std::uint32_t wid = 0, handle = 0;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        auto it = g_fid_to_wid.find(fid);
        if (it == g_fid_to_wid.end()) return 0;   // the prefilter: not one of ours
        auto bt = g_wid_to_bound.find(it->second);
        if (bt == g_wid_to_bound.end()) return 0;
        wid    = it->second;
        handle = bt->second.handle;
    }
    // Legacy fid-only binding: the fid is all there is to go by.
    if (handle == 0) return wid;
    std::uint32_t h = handle;
    if (fw::engine::resolve_refhandle(&h) == refr) return wid;
    // The fid map holds ONE wid per fid, and two live objects of ours can
    // share a fid (the engine hands ids out again): the full scan, only on
    // a prefilter hit that did not confirm.
    struct Cand { std::uint32_t wid, handle; };
    std::vector<Cand> cands;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        for (const auto& [w, b] : g_wid_to_bound) {
            if (b.fid == fid && b.handle != 0 && b.handle != handle) cands.push_back({w, b.handle});
        }
    }
    for (const Cand& c : cands) {
        std::uint32_t hh = c.handle;
        if (fw::engine::resolve_refhandle(&hh) == refr) return c.wid;
    }
    return 0;
}

bool is_our_refr(void* refr, std::uint32_t fid) {
    return wid_for_refr(refr, fid) != 0;
}

std::uint32_t container_key_for_refr(void* refr, std::uint32_t fid) {
    const std::uint32_t wid = wid_for_refr(refr, fid);
    if (wid == 0) return 0;
    std::lock_guard<std::mutex> lk(g_mx);
    auto it = g_wid_to_bound.find(wid);
    if (it == g_wid_to_bound.end()
            || !(it->second.entry.flags & fw::net::kWorldSpawnFlagContainer)) {
        return 0;
    }
    return fw::net::wid_container_key(wid);
}

bool saved_copy_awaiting_purge(std::uint32_t fid) {
    if (fid == 0 || (fid >> 24) != 0xFF) return false;
    std::lock_guard<std::mutex> lk(g_mx);
    if (!g_purge_armed) return false;
    for (const WorldObjectStamp& s : g_purge.stamps) {
        if (s.fid == fid) return true;
    }
    return false;
}

void* refr_for_container_key(std::uint32_t key) {
    if (!fw::net::is_wid_container_key(key)) return nullptr;
    std::uint32_t handle = 0, fid = 0;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        auto it = g_wid_to_bound.find(key & 0x00FFFFFFu);
        if (it == g_wid_to_bound.end()
                || !(it->second.entry.flags & fw::net::kWorldSpawnFlagContainer)) {
            return nullptr;
        }
        handle = it->second.handle;
        fid    = it->second.fid;
    }
    return resolve_object(handle, fid);
}

void note_self_object(std::uint32_t fid, std::uint32_t handle) {
    if (fid == 0) return;
    const DWORD now = GetTickCount();
    std::lock_guard<std::mutex> lk(g_mx);
    for (auto it = g_self_objects.begin(); it != g_self_objects.end();) {
        if (now - it->since_ms > kSelfObjectTtlMs || it->fid == fid) it = g_self_objects.erase(it);
        else ++it;
    }
    if (g_self_objects.size() < 64) g_self_objects.push_back({fid, handle, now});
}

void on_local_pickup(void* refr) {
    if (!refr) return;
    const auto id = fw::read_ref_identity(refr);
    if (id.form_id == 0) return;
    const std::uint32_t wid = wid_for_refr(refr, id.form_id);
    if (wid == 0) return;   // not one of ours: the ordinary pickup path handles it
    std::lock_guard<std::mutex> lk(g_mx);
    auto it = g_wid_to_bound.find(wid);
    if (it == g_wid_to_bound.end() || it->second.reported) return;
    it->second.reported = true;
    g_pickup_deaths.push_back({wid, id.form_id});
}

void watch_local_drop(void* refr, std::uint32_t handle, std::int32_t count_hint) {
    if (!refr || handle == 0 || handle == 0xFFFFFFFFu) return;
    const auto id = fw::read_ref_identity(refr);
    if (id.form_id == 0 || id.base_id == 0) return;
    PendingDrop d{};
    d.handle = handle;
    d.fid = id.form_id;
    d.base_id = id.base_id;
    d.count_hint = count_hint;
    d.since_ms = d.stable_since_ms = GetTickCount();
    (void)seh_vec3_at(reinterpret_cast<std::uint8_t*>(refr) + fw::offsets::POS_OFF, d.last_pos);
    d.rested = false;
    d.op_id = 0;
    std::lock_guard<std::mutex> lk(g_mx);
    for (const PendingDrop& p : g_pending_drops) {
        if (p.handle == handle) return;   // already watched
    }
    if (g_pending_drops.size() >= 64) {
        FW_WRN("[world-spawn-tx] 64 drops already watched: fid=0x%08X (base=0x%08X) not "
               "watched, not announced", id.form_id, id.base_id);
        return;
    }
    // R1b: the op id is handed out now, while the item has just left the
    // inventory, so no capture is taken over the drop before the server has
    // it; the op itself goes at rest, with the line read then. 0 (the client
    // is stopping) = the legacy announce, without the record side.
    d.op_id = fw::net::client().begin_world_item_op();
    g_pending_drops.push_back(d);
}

std::uint32_t note_local_pickup(void* refr) {
    if (!refr) return 0;
    const auto id = fw::read_ref_identity(refr);
    if (id.form_id == 0) return 0;
    const std::uint32_t wid = wid_for_refr(refr, id.form_id);
    if (wid == 0) return 0;
    std::lock_guard<std::mutex> lk(g_mx);
    auto it = g_wid_to_bound.find(wid);
    if (it != g_wid_to_bound.end()) it->second.reported = true;   // the op says it, not the sweep
    return wid;
}

bool cancel_pending_drop(void* refr) {
    if (!refr) return false;
    const std::uint32_t handle = fw::engine::refr_get_handle(refr);
    if (handle == 0 || handle == 0xFFFFFFFFu) return false;
    std::uint32_t op_id = 0;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        for (auto it = g_pending_drops.begin(); it != g_pending_drops.end(); ++it) {
            if (it->handle == handle) {
                op_id = it->op_id;
                g_pending_drops.erase(it);
                found = true;
                break;
            }
        }
    }
    if (found && op_id) fw::net::client().cancel_world_item_op(op_id);
    return found;
}

bool undo_local_drop(std::uint32_t fid, std::uint32_t handle, std::uint32_t base,
                     std::uint64_t fp, const fw::net::InstanceDesc* desc, std::int32_t count) {
    std::uint32_t h = handle;
    void* refr = (handle != 0 && handle != 0xFFFFFFFFu) ? fw::engine::resolve_refhandle(&h)
                                                        : nullptr;
    if (refr) {
        fw::engine::disable_ref(refr, false);
        FW_LOG("[world-spawn-tx] drop refused: REFR fid=0x%08X disabled (TEMPORARY since its "
               "announce, no save keeps it)", fid);
    } else {
        FW_WRN("[world-spawn-tx] drop refused: REFR fid=0x%08X handle=0x%08X not found, nothing "
               "to disable", fid, handle);
    }
    void* player = fw::engine::get_local_player();
    if (!player || base == 0 || count <= 0) return false;
    fw::net::InstanceDesc plain{};
    plain.tmpl = 0xFFFF;
    const bool named = desc != nullptr && fp != fw::net::kFpUnknown;
    const int added = fw::engine::instances::add_instance(player, base, named ? *desc : plain, count);
    FW_LOG("[world-spawn-tx] drop refused: %d of %d x 0x%08X back on the player %s", added, count,
           base, named ? "(the exact instance)" : "(a plain one: the instance was unread)");
    return added > 0;
}

bool undo_local_pickup(std::uint32_t base, std::uint64_t fp, std::int32_t count) {
    void* player = fw::engine::get_local_player();
    if (!player || base == 0 || count <= 0) return false;
    int removed = 0;
    if (fp != fw::net::kFpUnknown) {
        removed = fw::engine::instances::remove_instance(player, base, fp, count, nullptr);
    }
    if (removed < count) {
        void* form = fw::engine::lookup_by_form_id(base);
        if (form && fw::engine::remove_items_destroy(player, form, count - removed)) removed = count;
    }
    FW_LOG("[world-spawn] pickup refused: %d of %d x 0x%08X fp=%016llX destroyed on the player "
           "(someone else has the object)", removed, count, base,
           static_cast<unsigned long long>(fp));
    return removed > 0;
}

}  // namespace fw::native::world_spawn
