#include "world_spawn.h"

#include <windows.h>

#include <atomic>
#include <deque>
#include <mutex>
#include <unordered_map>

#include <vector>

#include "../engine/engine_calls.h"
#include "../hooks/equip_hook.h"        // v24: read_item_mod_forms (piece OMODs)
#include "../hooks/npc_ai_suppress.h"   // Build 70b: in_local_death_standdown gate
#include "../hooks/pa_pipeline_trace.h" // Build 70u: force_local_pa_model_reload
#include "../net/client.h"
#include "../offsets.h"
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
    DWORD         bound_at_ms = 0;     // birth of the binding, for the grace
    // Build 70b — the wire truth this binding replicates. Kept so a local
    // replica the ENGINE destroys (cell streaming, the PA janitor measured
    // live at +0x109DAA7) can be RE-QUEUED for placement on approach instead
    // of being reported as a world despawn. The server object is the truth;
    // a local death by streaming is not a world event.
    SpawnEntry    entry{};
};
std::unordered_map<std::uint32_t, Bound>         g_wid_to_bound;
std::unordered_map<std::uint32_t, std::uint32_t> g_fid_to_wid;

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
struct Tombstone { std::uint32_t fid; DWORD since_ms; };
std::vector<Tombstone> g_tombstones;
constexpr DWORD       kTombstoneTtlMs = 15u * 60u * 1000u;
constexpr std::size_t kTombstoneCap   = 256;

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

// v24 — the AttachModToInventoryItem worker (offsets::PAPYRUS_ATTACH_MOD_RVA,
// contract documented there). vm/stackId feed only the script error report:
// 0,0 is safe. Main thread only.
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

static bool write_stack_health(void* refr, std::uint32_t form_id, float value) {
    void* list = seh_find_stack_extras(refr, form_id);
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
        b.cell_id     = e.cell_id;
        b.bound_at_ms = GetTickCount();
        b.entry       = e;
        g_wid_to_bound[e.wid]       = b;
        g_fid_to_wid[e.spawner_fid] = e.wid;
        FW_LOG("[world-spawn] wid=%u is OURS (base=0x%08X, local fid=0x%08X) "
               "— bound, not re-placed", e.wid, e.base_form_id, e.spawner_fid);
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
           "cell=0x%08X%s", e.wid, e.base_form_id,
           e.pos[0], e.pos[1], e.pos[2], e.cell_id,
           (e.flags & 1) ? " [transient]" : "");
}

static void fire_due_frame_reports();   // v23b, defined with the API below

void tick(std::uintptr_t module_base) {
    if (!module_base) return;
    g_module_base = module_base;

    // ---- Build 70b: world-instability gates. NO engine work while the
    // world is being torn down or rebuilt (see the constants block).
    {
        const DWORD now0 = GetTickCount();
        const bool standdown = fw::hooks::in_local_death_standdown();
        if (standdown != g_standdown_prev) {
            g_standdown_prev = standdown;
            if (standdown) {
                FW_LOG("[world-spawn] death stand-down OPEN — tick paused "
                       "(no placement, no sweep, no despawn apply)");
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
            bool self_reported = false;
            std::size_t purged = 0;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                auto it = g_wid_to_bound.find(wid);
                if (it != g_wid_to_bound.end()) {
                    fid           = it->second.fid;
                    self_reported = it->second.reported;
                    g_fid_to_wid.erase(fid);
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
                    g_tombstones.push_back({fid, GetTickCount()});
                }
                FW_LOG("[world-spawn] despawn wid=%u confirmed for our own "
                       "report — fid=0x%08X on resurrection watch", wid, fid);
                continue;
            }
            void* refr = fw::engine::lookup_by_form_id(fid);
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

    // ---- v23: apply queued piece updates by DESTROY-AND-REPLACE — the
    // streaming-requeue idiom. A peer changed the frame's content by hand;
    // there is no remove-item primitive and no need for one: kill our
    // replica and let the placement path rebuild it with the new list.
    {
        std::vector<PiecesUpdate> updates;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            updates.swap(g_pending_piece_updates);
        }
        for (const PiecesUpdate& u : updates) {
            SpawnEntry entry{};
            std::uint32_t fid = 0;
            bool have = false;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                auto it = g_wid_to_bound.find(u.wid);
                if (it != g_wid_to_bound.end()) {
                    fid   = it->second.fid;
                    entry = it->second.entry;
                    have  = true;
                    g_fid_to_wid.erase(fid);
                    g_wid_to_bound.erase(it);
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
            void* refr = fw::engine::lookup_by_form_id(fid);
            const bool gone = refr ? fw::engine::destroy_world_refr(refr)
                                   : true;
            {
                std::lock_guard<std::mutex> lk(g_mx);
                if (!(entry.flags & 1)) g_pending.push_back(entry);
            }
            FW_LOG("[pa-pieces] wid=%u content changed remotely -> replica "
                   "fid=0x%08X %s, re-queued with %u entr%s", u.wid, fid,
                   gone ? "destroyed" : "destroy FAILED (re-queued anyway)",
                   u.n, u.n == 1 ? "y" : "ies");
        }
    }

    // ---- v23b: fire deferred manual-change reports whose settle window
    // has elapsed (the take-timing fix — see report_frame_pieces).
    fire_due_frame_reports();

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
                    void* refr = fw::engine::lookup_by_form_id(b.fid);
                    std::uint8_t reason = 0;
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
                            const std::uint32_t cid = seh_u32_at(
                                reinterpret_cast<std::uint8_t*>(pc)
                                + fw::offsets::FORMID_OFF);
                            if (cid) b.cell_id = cid;
                        }
                        if (flags & kFlagDeleted)                 reason = 1;
                        else if (flags & fw::offsets::FLAG_DISABLED) reason = 2;
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
                    if (reason == 1) {
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
                    g_wid_to_bound.erase(it);
                }
            }
            for (const auto& d : deaths) {
                FW_LOG("[world-spawn] wid=%u died locally (reason=%u: "
                       "1=deleted 2=disabled 3=vanished-same-cell) -> "
                       "WORLD_DESPAWN_OP sent", d.wid, d.reason);
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
                    void* refr = fw::engine::lookup_by_form_id(it->fid);
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
                fw::net::client().enqueue_world_spawn_op(
                    r.base_id, r.fid, r.pos, r.rot, r.cell_id, /*flags=*/0,
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

    // All engine work happens here, on the main thread, mirroring the ghost
    // donor: resolve the base form, PlaceAtMe anchored at the player (the
    // engine call is wrapped in the internal-place scope so our own sender
    // detour does not re-broadcast it), then move it to the real target.
    std::uint32_t new_fid = 0;
    void* refr = fw::engine::place_world_object(e.base_form_id, &new_fid);
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
    const auto fin = fw::engine::finalize_world_placement(
        refr, e.pos[0], e.pos[1], e.pos[2], e.rot[2]);
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
        b.cell_id     = e.cell_id;
        b.bound_at_ms = GetTickCount();
        b.entry       = e;
        g_wid_to_bound[e.wid]  = b;
        g_fid_to_wid[new_fid]  = e.wid;
    }
    FW_LOG("[world-spawn] wid=%u PLACED: base=0x%08X -> local fid=0x%08X at "
           "(%.1f, %.1f, %.1f) teleport=%s ground=%s%+.1f refile=%s",
           e.wid, e.base_form_id, new_fid,
           e.pos[0], e.pos[1], e.pos[2],
           moved ? "ok" : "FAILED (left at the player)",
           fin.snapped ? "snapped" : "wire", fin.dz,
           fin.refiled ? "ok" : "SKIPPED (target cell not attached)");

    // ========================================================================
    // v23 — stock the replica with the object's REAL content, carried on the
    // wire (E1's hardcoded set is dead: its stale list is what duplicated
    // pieces the moment one client removed some by hand). E0/E1 facts this
    // rides on: an ARMO in a frame's inventory IS a mounted piece — no flag
    // to write — and the engine's own AddItem right after placement renders
    // on the standing frame and transfers on enter, both verified live.
    // ========================================================================
    if (e.piece_n > 0) {
        int injected = 0;
        int mods_applied = 0, mods_failed = 0;
        for (std::uint8_t i = 0; i < e.piece_n && i < 12; ++i) {
            const fw::net::PaPieceEntry& pe = e.pieces[i];
            void* form = fw::engine::lookup_by_form_id(pe.form_id);
            if (!form) {
                FW_WRN("[pa-pieces] entry 0x%08X: form lookup failed — "
                       "skipped", pe.form_id);
                continue;
            }
            const int cnt = (pe.count > 0) ? pe.count : 1;
            if (!seh_papyrus_additem(refr, form, cnt)) {
                FW_ERR("[pa-pieces] entry 0x%08X: AddItem SEH/call failed",
                       pe.form_id);
                continue;
            }
            ++injected;
            // v24 — re-attach the source OMODs so the piece is the SAME
            // variant, not the engine leveled roll. The worker requires a
            // singular stack: pieces are count 1 and each form is added
            // exactly once, so the precondition holds.
            for (std::uint8_t m = 0; m < pe.mod_n
                                     && m < fw::net::kMaxPieceMods; ++m) {
                void* mod = fw::engine::lookup_by_form_id(pe.mods[m]);
                if (mod && seh_papyrus_attachmod(refr, form, mod)) {
                    ++mods_applied;
                } else {
                    ++mods_failed;
                    FW_WRN("[pa-pieces] piece 0x%08X: mod 0x%08X %s",
                           pe.form_id, pe.mods[m],
                           mod ? "attach failed" : "lookup failed");
                }
            }
            // v25 — condition / core charge: the Health extra on the stack,
            // created only when the original had one (an exact mirror).
            if (pe.health >= 0.0f) {
                const bool hok = write_stack_health(refr, pe.form_id, pe.health);
                FW_LOG("[pa-pieces] piece 0x%08X: health %.3f %s", pe.form_id,
                       pe.health, hok ? "written" : "WRITE FAILED");
            }
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
        out[i].count   = cnts[i];
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

}  // namespace fw::native::world_spawn
