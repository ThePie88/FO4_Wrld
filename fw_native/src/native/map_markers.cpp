#include "map_markers.h"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../config.h"
#include "../engine/engine_calls.h"
#include "../log.h"
#include "../net/client.h"
#include "../net/peer_names.h"
#include "../net/protocol.h"
#include "../offsets.h"
#include "scene_inject.h"   // ghost_head_anchors: the peers with a live ghost, and where

namespace fw::native::map_markers {

namespace {

// Signatures from the decomp (offsets.h, the map marker block; the
// experiment in map_marker.cpp proved every one of them live).
using AllocFn       = void* (__fastcall*)(std::uint64_t size);
using DataCtorFn    = void* (__fastcall*)(void* data);
using DataSetNameFn = void (__fastcall*)(void* data, const char* name);
using ListSetDataFn = void* (__fastcall*)(void* list, void* data);
using RefrGetDataFn = void* (__fastcall*)(void* refr, std::uint64_t unused);
using LockFn        = void (__fastcall*)(void* lock);
using PushIndexFn   = std::int32_t (__fastcall*)(std::uint32_t* size, void* functor,
                                                 std::uint32_t capacity, std::uint32_t elem_size);
using NotifyFn      = void (__fastcall*)(char changed);
using SourceFn      = void* (__fastcall*)();
using RefillFn      = void (__fastcall*)(void* player);
using RefrWsFn      = void* (__fastcall*)(void* refr);
using DataGetNameFn = const char* (__fastcall*)(void* data);

std::uintptr_t g_base        = 0;
bool           g_enabled     = true;
std::uint16_t  g_death_type  = 30;
std::uint16_t  g_player_type = 31;
std::uint32_t  g_rebuild_ms  = 3000;

template <typename F>
F fn_at(std::uintptr_t rva) { return reinterpret_cast<F>(g_base + rva); }

struct Marker {
    enum Kind : std::uint8_t { kCrate = 0, kPlayer = 1 };
    Kind          kind       = kCrate;
    std::uint32_t wid        = 0;        // a crate: the world spawn it marks
    std::uint32_t ordinal    = 0;        // a crate: which death made it
    std::string   peer;                  // a player: whose ghost it follows
    std::uint32_t faction_id = 0;        // TODO (the faction stub): nobody has one yet
    std::string   name;                  // what the map shows under the mouse
    std::uint16_t type       = 30;       // the icon
    float         target[3]  = {0.0f, 0.0f, 0.0f};   // where it should stand
    std::uint32_t cell_id    = 0;        // the cell of the target (the server's / the peer's)
    bool          wanted     = false;    // shown at all: the target is in the player's worldspace
    bool          on_compass = true;     // false = the map only (CORPSE #n)
    // The REFR carrying the data, 0 / nullptr while there is none.
    std::uint32_t fid        = 0;
    std::uint32_t handle     = 0;
    void*         data       = nullptr;
    bool          named      = false;    // the data carries `name`
    float         placed[3]  = {0.0f, 0.0f, 0.0f};   // where the REFR stands
    float         map_pos[3] = {0.0f, 0.0f, 0.0f};   // where the map last saw it (its last rebuild)
    // A REFR lost again and again (the engine throwing our markers away for
    // a reason not foreseen) is remade three times a minute at most, then
    // the marker rests for a minute: no REFR storm, and the log says it.
    std::uint8_t  remakes    = 0;
    std::uint64_t remake_window_ms = 0;
    std::uint64_t rest_until_ms    = 0;
    bool          verdict_said = false;   // the first "shown / not shown" is logged too
    // A spot: the mark of a death that left no crate (wid 0), for 15
    // minutes from the death (the server says its age, the clock is ours).
    bool          spot       = false;
    std::uint64_t expires_at_ms = 0;
};

std::vector<Marker> g_markers;   // MAIN THREAD only

// Network thread -> main thread: the last DEATH_CRATES, whole.
std::mutex                            g_inbox_mtx;
bool                                  g_inbox_new   = false;
std::uint32_t                         g_inbox_count = 0;
std::vector<fw::net::DeathCrateEntry> g_inbox;

std::uint64_t g_last_tick_ms    = 0;
std::uint64_t g_last_rebuild_ms = 0;
// The second live test (2026-10-15): the Pip-Boy data is down around a game
// load, a fire then reaches nobody, and its setup rebuilds the map from the
// array as it stands. A publish nobody heard leaves the map-only handles in
// the array and is made again once the sink is back; a map whose entries
// no longer match what the last publish left is published again.
bool          g_publish_pending   = false;
std::int32_t  g_map_entries_after = -1;
std::uint64_t g_last_engine_fix_ms = 0;
// The third live test (2026-10-15): the engine fills the array only while
// it is EMPTY (or on a worldspace change); a load empties it, and anything
// of ours pushed in first keeps the natives out. An array with no native
// marker in it is handed back: ours out, the engine's refill called, ours
// in after. A worldspace without native markers is remembered, or the
// hand-back would repeat every second.
void*         g_no_natives_ws     = nullptr;
std::uint64_t g_resync_said_ms    = 0;
std::string   g_membership;          // which of ours the array holds, as seen last
// R5 stays vanilla (the owner's decision, 2026-10-16), but a place
// discovered asks the server for a checkpoint, so a crash a minute later
// does not undo it. The watch: the visible bit of every native marker in
// the player's array, once a second; one visible now that was not before
// is a discovery (the engine's reveal on approach, a quest, AddToMap). The
// baseline is dropped on a refill (another set) and never fires at first
// sight.
std::unordered_map<std::uint32_t, bool> g_visible;   // native marker form id -> visible
bool          g_visible_valid     = false;
void*         g_last_worldspace = nullptr;
bool          g_worldspace_seen = false;
bool          g_direct_write_said = false;
bool          g_saving            = false;   // between suspend_for_save and resume_after_save
void*         g_last_player_cell  = nullptr; // the markers live in the player's cell: a change remakes them

const char* kind_name(const Marker& m) {
    return m.kind == Marker::kPlayer ? "player" : (m.spot ? "spot" : "crate");
}
constexpr std::uint64_t kSpotTtlMs = 15ull * 60ull * 1000ull;
void seh_refr_cell_info(void* refr, void* player, std::uint32_t* cell_fid, bool* persistent) noexcept;

// ---------------------------------------------------------------- SEH cages
// POD-only frames: no object with a destructor inside a __try.

void* seh_make_data(const char* name, std::uint16_t type) noexcept {
    __try {
        void* data = fn_at<AllocFn>(offsets::EXTRA_ALLOC_RVA)(offsets::MAPMARKERDATA_SIZE);
        if (!data) return nullptr;
        fn_at<DataCtorFn>(offsets::MAPMARKERDATA_CTOR_RVA)(data);
        fn_at<DataSetNameFn>(offsets::MAPMARKERDATA_SET_NAME_RVA)(data, name);
        auto* b = static_cast<std::uint8_t*>(data);
        // Visible, NO fast travel, not hidden (the owner's decision, 2026-10-15).
        *(b + offsets::MAPMARKERDATA_FLAGS_OFF) = offsets::MAPMARKER_FLAG_VISIBLE;
        *reinterpret_cast<std::uint16_t*>(b + offsets::MAPMARKERDATA_TYPE_OFF) = type;
        return data;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

bool seh_set_name(void* data, const char* name) noexcept {
    __try {
        fn_at<DataSetNameFn>(offsets::MAPMARKERDATA_SET_NAME_RVA)(data, name);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// TESObjectREFR::extraList (+0x100) is a POINTER to the list (the first
// live press of the experiment passed the field's address and faulted).
bool seh_set_data(void* refr, void* data) noexcept {
    __try {
        void* list = *reinterpret_cast<void**>(static_cast<std::uint8_t*>(refr)
                                               + offsets::REFR_EXTRA_LIST_OFF);
        if (!list) return false;
        fn_at<ListSetDataFn>(offsets::EXTRALIST_SET_MAPMARKER_RVA)(list, data);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void* seh_get_data(void* refr) noexcept {
    __try {
        return fn_at<RefrGetDataFn>(offsets::REFR_GET_MAPMARKER_DATA_RVA)(refr, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

std::uint32_t seh_refr_fid(void* refr) noexcept {
    __try {
        return *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(refr) + offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

std::uint32_t seh_refr_base_fid(void* refr) noexcept {
    __try {
        void* base = *reinterpret_cast<void**>(static_cast<std::uint8_t*>(refr) + offsets::BASE_FORM_OFF);
        if (!base) return 0;
        return *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(base) + offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool seh_refr_pos(void* refr, float out[3]) noexcept {
    __try {
        const float* p = reinterpret_cast<const float*>(static_cast<std::uint8_t*>(refr) + offsets::POS_OFF);
        out[0] = p[0]; out[1] = p[1]; out[2] = p[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The fallback of a move: the position triplet written directly. The map
// and the compass read nothing else of a REFR that has no 3D.
bool seh_write_pos(void* refr, const float p[3]) noexcept {
    __try {
        float* dst = reinterpret_cast<float*>(static_cast<std::uint8_t*>(refr) + offsets::POS_OFF);
        dst[0] = p[0]; dst[1] = p[1]; dst[2] = p[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The worldspace the player's marker array was filled for (the engine
// compares it with the player's on every cell change and refills on a
// difference): when it moves, the array was emptied and refilled without us.
void* seh_player_worldspace(void* player) noexcept {
    __try {
        return *reinterpret_cast<void**>(static_cast<std::uint8_t*>(player) + offsets::PLAYER_MAPMARKERS_WS_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// ---- the player's marker array, under the engine's global recursive lock
void lock_markers() noexcept {
    fn_at<LockFn>(offsets::SPINLOCK_LOCK_RVA)(reinterpret_cast<void*>(g_base + offsets::MAPMARKERS_LOCK_RVA));
}
// The engine's own unlock, inlined as sub_140D74690 does it.
void unlock_markers() noexcept {
    auto* lock = reinterpret_cast<volatile long*>(g_base + offsets::MAPMARKERS_LOCK_RVA);
    if (lock[1] == 1) {
        lock[0] = 0;
        _mm_mfence();
        InterlockedCompareExchange(lock + 1, 0, 1);
    } else {
        InterlockedDecrement(lock + 1);
    }
}

bool seh_array_contains(void* player, std::uint32_t handle) noexcept {
    __try {
        auto* arr = static_cast<std::uint8_t*>(player) + offsets::PLAYER_MAPMARKERS_ARR_OFF;
        auto* data = *reinterpret_cast<std::uint32_t**>(arr);
        const std::uint32_t size = *reinterpret_cast<std::uint32_t*>(arr + 16);
        for (std::uint32_t i = 0; data && i < size; ++i) {
            if (data[i] == handle) return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The slot index, -2 when already there, -1 on a fault or an array that
// could not grow.
std::int32_t seh_array_push(void* player, std::uint32_t handle) noexcept {
    __try {
        auto* arr = static_cast<std::uint8_t*>(player) + offsets::PLAYER_MAPMARKERS_ARR_OFF;
        auto* data = *reinterpret_cast<std::uint32_t**>(arr);
        const std::uint32_t capacity = *reinterpret_cast<std::uint32_t*>(arr + 8);
        auto* size = reinterpret_cast<std::uint32_t*>(arr + 16);
        for (std::uint32_t i = 0; data && i < *size; ++i) {
            if (data[i] == handle) return -2;
        }
        struct Functor { std::uintptr_t vtable; void* array; } functor{
            g_base + offsets::BSTARRAY_HEAP_FUNCTOR_VTABLE_RVA, arr};
        const std::int32_t idx = fn_at<PushIndexFn>(offsets::BSTARRAY_PUSH_INDEX_RVA)(
            size, &functor, capacity, 4u);
        if (idx < 0) return -1;
        data = *reinterpret_cast<std::uint32_t**>(arr);   // the push may have grown it
        if (!data) return -1;
        data[idx] = handle;
        return idx;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// The last entry moves into the slot. True when it was there.
bool seh_array_remove(void* player, std::uint32_t handle) noexcept {
    __try {
        auto* arr = static_cast<std::uint8_t*>(player) + offsets::PLAYER_MAPMARKERS_ARR_OFF;
        auto* data = *reinterpret_cast<std::uint32_t**>(arr);
        auto* size = reinterpret_cast<std::uint32_t*>(arr + 16);
        for (std::uint32_t i = 0; data && i < *size; ++i) {
            if (data[i] != handle) continue;
            data[i] = data[*size - 1];
            data[*size - 1] = 0;
            *size -= 1;
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The engine's "the marker list changed" event. TRUE: the map's sink
// empties its entries and rebuilds them from the array (with false it
// rebuilds only while still empty, which it never is by now).
bool seh_notify(bool changed) noexcept {
    __try {
        fn_at<NotifyFn>(offsets::MAPMARKERS_NOTIFY_RVA)(changed ? 1 : 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The map's sink count on the event source: 0 while the Pip-Boy data is
// down, when a fire reaches nobody.
std::uint32_t seh_sink_count() noexcept {
    __try {
        auto* src = static_cast<std::uint8_t*>(fn_at<SourceFn>(offsets::MAPMARKERS_EVENT_SOURCE_RVA)());
        if (!src) return 0;
        const std::uint32_t n = *reinterpret_cast<std::uint32_t*>(src + offsets::EVENT_SOURCE_SINK_COUNT_OFF);
        return n > 64 ? 0 : n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// The entries of the map data's marker map (capacity - free), reached
// through its sink; -1 when it cannot be reached (the data down, a fault).
std::int32_t seh_map_entries() noexcept {
    __try {
        auto* src = static_cast<std::uint8_t*>(fn_at<SourceFn>(offsets::MAPMARKERS_EVENT_SOURCE_RVA)());
        if (!src) return -1;
        const std::uint32_t n = *reinterpret_cast<std::uint32_t*>(src + offsets::EVENT_SOURCE_SINK_COUNT_OFF);
        if (n == 0 || n > 64) return -1;
        auto** sinks = *reinterpret_cast<std::uint8_t***>(src + offsets::EVENT_SOURCE_SINKS_OFF);
        if (!sinks || !sinks[0]) return -1;
        auto* md = sinks[0] - offsets::MAPDATA_SINK_OFF;
        const std::uint32_t cap = *reinterpret_cast<std::uint32_t*>(md + offsets::MAPDATA_MAP_CAPACITY_OFF);
        const std::uint32_t fre = *reinterpret_cast<std::uint32_t*>(md + offsets::MAPDATA_MAP_FREE_OFF);
        if (cap > 65536 || fre > cap) return -1;
        return static_cast<std::int32_t>(cap - fre);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// The array's handles, copied under the lock into `out` (at most `cap`).
std::uint32_t seh_array_snapshot(void* player, std::uint32_t* out, std::uint32_t cap) noexcept {
    __try {
        auto* arr = static_cast<std::uint8_t*>(player) + offsets::PLAYER_MAPMARKERS_ARR_OFF;
        auto* data = *reinterpret_cast<std::uint32_t**>(arr);
        std::uint32_t n = *reinterpret_cast<std::uint32_t*>(arr + 16);
        if (!data || n > 65536) return 0;
        if (n > cap) n = cap;
        for (std::uint32_t i = 0; i < n; ++i) out[i] = data[i];
        return n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

std::uint32_t seh_data_flags(void* data) noexcept {
    __try {
        return *(static_cast<const std::uint8_t*>(data) + offsets::MAPMARKERDATA_FLAGS_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

const char* seh_data_name(void* data) noexcept {
    __try {
        return fn_at<DataGetNameFn>(offsets::MAPMARKERDATA_GET_NAME_RVA)(data);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// ---------------------------------------------------------------- the REFRs

// The REFR the marker was given, or nullptr when the handle no longer
// resolves to it (a load threw the TEMPORARY REFR away, the engine purged
// it, the handle's slot was reused): form id, base and our data must match.
std::uint32_t seh_refr_flags(void* refr) noexcept {
    __try {
        return *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(refr) + offsets::FLAGS_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

constexpr std::uint32_t kFormFlagDeleted = 0x20;   // TESForm::flags bit 5

void* live_refr(const Marker& m) noexcept {
    if (!m.handle) return nullptr;
    std::uint32_t h = m.handle;
    void* refr = fw::engine::resolve_refhandle(&h);
    if (!refr) return nullptr;
    if (seh_refr_fid(refr) != m.fid) return nullptr;
    if (seh_refr_base_fid(refr) != offsets::MAPMARKER_BASE_FORMID) return nullptr;
    if (seh_get_data(refr) != m.data) return nullptr;
    // The fifth live test (2026-10-16): a REFR that lives through a
    // checkpoint load in a cell that stays attached comes out DISABLED
    // (the engine's treatment of a runtime REFR the save does not know,
    // the world-spawn sweep sees the same), and the map hides a disabled
    // marker (Visible = visible && !bit2 && !(flags & 0x800)): the corpses
    // vanished from the map while the spot, remade, showed. Disabled or
    // deleted = lost, remade.
    const std::uint32_t flags = seh_refr_flags(refr);
    if (flags & (offsets::FLAG_DISABLED | kFormFlagDeleted)) return nullptr;
    return refr;
}

float dist2(const float a[3], const float b[3]) {
    const float dx = a[0] - b[0], dy = a[1] - b[1], dz = a[2] - b[2];
    return dx * dx + dy * dy + dz * dz;
}

// The REFR to the marker's target. The SetPosition leaf first (the
// engine's own move of any REFR, same cell: the parent cell stays the one
// it was placed in, which is what the compass reads the worldspace from);
// the triplet written directly when the leaf refuses, said once.
bool move_refr(Marker& m, void* refr, bool force) {
    if (!force && dist2(m.target, m.placed) < 1.0f) return false;
    bool ok = fw::engine::move_world_refr(refr, m.target[0], m.target[1], m.target[2], 0.0f);
    if (!ok) {
        ok = seh_write_pos(refr, m.target);
        if (ok && !g_direct_write_said) {
            FW_WRN("[map-markers] the SetPosition leaf refused a marker REFR: the position "
                   "is written directly from now on (said once)");
            g_direct_write_said = true;
        }
    }
    if (ok) std::memcpy(m.placed, m.target, sizeof m.placed);
    return ok;
}

// A REFR of the MapMarker base at the player (TEMPORARY, the engine's own
// PlaceAtMe), our data on it, moved to the target. False and nothing left
// behind on any failure (the REFR disabled again).
bool place_refr(Marker& m) {
    std::uint32_t fid = 0, handle = 0;
    void* refr = fw::engine::place_world_object(offsets::MAPMARKER_BASE_FORMID, &fid, &handle);
    if (!refr) return false;
    if (!handle) {
        fw::engine::disable_ref(refr, false);
        return false;
    }
    void* data = seh_make_data(m.name.c_str(), m.type);
    if (!data || !seh_set_data(refr, data) || seh_get_data(refr) != data) {
        FW_WRN("[map-markers] %s '%s': the marker data could not be filed on REFR 0x%08X "
               "(data %p): the REFR is disabled again", kind_name(m), m.name.c_str(), fid, data);
        if (data) seh_set_data(refr, nullptr);
        fw::engine::disable_ref(refr, false);
        return false;
    }
    m.fid = fid;
    m.handle = handle;
    m.data = data;
    m.named = true;
    if (!seh_refr_pos(refr, m.placed)) std::memset(m.placed, 0, sizeof m.placed);
    move_refr(m, refr, true);
    return true;
}

// The REFR the marker was given, whatever its flags or data (for taking it
// out of the world): the handle must resolve to that form id and base.
void* ours_refr(const Marker& m) noexcept {
    if (!m.handle) return nullptr;
    std::uint32_t h = m.handle;
    void* refr = fw::engine::resolve_refhandle(&h);
    if (!refr) return nullptr;
    if (seh_refr_fid(refr) != m.fid) return nullptr;
    if (seh_refr_base_fid(refr) != offsets::MAPMARKER_BASE_FORMID) return nullptr;
    return refr;
}

// The marker's REFR gone: out of the array, data off (the engine frees it),
// then DESTROYED the engine's way (destroy_world_refr: the TEMPORARY bit
// cleared first so the dtor unregisters it, the immediate disable, out of
// its cell, DestroyByHandle). A disable alone left a REFR behind for the
// engine's save to choke on (2026-10-16 20:02). The marker keeps its wish
// and gets a new REFR when wanted again.
void drop_refr(Marker& m, void* player, const char* why) {
    void* refr = ours_refr(m);
    if (player && m.handle) {
        lock_markers();
        seh_array_remove(player, m.handle);
        unlock_markers();
    }
    if (refr) {
        seh_set_data(refr, nullptr);
        if (!fw::engine::destroy_world_refr(refr)) fw::engine::disable_ref(refr, false);
    }
    FW_LOG("[map-markers] %s '%s' (REFR 0x%08X): gone, %s", kind_name(m), m.name.c_str(), m.fid, why);
    m.fid = 0;
    m.handle = 0;
    m.data = nullptr;
    m.named = false;
}

Marker* find_crate(std::uint32_t wid) {
    for (auto& m : g_markers) if (m.kind == Marker::kCrate && !m.spot && m.wid == wid) return &m;
    return nullptr;
}

Marker* find_spot(std::uint32_t ordinal) {
    for (auto& m : g_markers) if (m.kind == Marker::kCrate && m.spot && m.ordinal == ordinal) return &m;
    return nullptr;
}

// The death marks (crates and spots) named by recency: the newest "LATEST
// DEATH" (map and compass), the ones before it "CORPSE #2", "#3"... (map
// only). The owner's decision of the fourth live test (2026-10-15): small
// numbers that say how many deaths ago, instead of the death count. True
// when a name or a compass wish moved.
bool rank_death_marks() {
    std::vector<Marker*> marks;
    for (auto& m : g_markers) if (m.kind == Marker::kCrate) marks.push_back(&m);
    std::sort(marks.begin(), marks.end(), [](const Marker* a, const Marker* b) {
        if (a->ordinal != b->ordinal) return a->ordinal > b->ordinal;
        return a->wid > b->wid;
    });
    bool dirty = false;
    for (std::size_t i = 0; i < marks.size(); ++i) {
        Marker& m = *marks[i];
        char name[32];
        if (i == 0) std::snprintf(name, sizeof(name), "LATEST DEATH");
        else std::snprintf(name, sizeof(name), "CORPSE #%zu", i + 1);
        if (m.name != name) {
            m.name = name;
            m.named = false;
            dirty = true;
        }
        const bool on_compass = (i == 0);
        if (m.on_compass != on_compass) {
            m.on_compass = on_compass;
            dirty = true;
        }
    }
    return dirty;
}

Marker* find_player(const std::string& peer) {
    for (auto& m : g_markers) if (m.kind == Marker::kPlayer && m.peer == peer) return &m;
    return nullptr;
}

// ---------------------------------------------------------------- the wishes

// The last DEATH_CRATES into the death marks (crates by wid, spots by the
// ordinal of their death): made, moved, dropped, then named by recency.
// True when the map has to be rebuilt.
bool drain_inbox(void* player, std::uint64_t now) {
    std::vector<fw::net::DeathCrateEntry> list;
    std::uint32_t count = 0;
    {
        std::lock_guard<std::mutex> g(g_inbox_mtx);
        if (!g_inbox_new) return false;
        g_inbox_new = false;
        list.swap(g_inbox);
        count = g_inbox_count;
    }
    bool dirty = false;
    int added = 0, moved = 0, removed = 0, spots = 0;
    std::unordered_set<std::uint64_t> seen;   // crates by wid, spots by ordinal | 1 << 32
    for (const auto& e : list) {
        Marker* m = nullptr;
        if (e.wid != 0) {
            seen.insert(e.wid);
            m = find_crate(e.wid);
        } else {
            seen.insert((1ull << 32) | e.ordinal);
            m = find_spot(e.ordinal);
            ++spots;
        }
        if (!m) {
            g_markers.push_back(Marker{});
            m = &g_markers.back();
            m->kind = Marker::kCrate;
            m->wid = e.wid;
            m->spot = (e.wid == 0);
            m->type = g_death_type;
            ++added;
            dirty = true;
        }
        m->ordinal = e.ordinal;
        if (m->spot) {
            const std::uint64_t left = e.age_ms < kSpotTtlMs ? kSpotTtlMs - e.age_ms : 0;
            m->expires_at_ms = now + left;
        }
        const float t[3] = {e.px, e.py, e.pz};
        if (std::memcmp(t, m->target, sizeof t) != 0 || m->cell_id != e.cell_id) {
            std::memcpy(m->target, t, sizeof t);
            m->cell_id = e.cell_id;
            ++moved;
            dirty = true;
        }
    }
    for (auto it = g_markers.begin(); it != g_markers.end();) {
        const bool mark = (it->kind == Marker::kCrate);
        const bool listed = !mark ? true
            : (it->spot ? seen.count((1ull << 32) | it->ordinal) != 0 : seen.count(it->wid) != 0);
        if (mark && !listed) {
            drop_refr(*it, player, "no longer in the server's list");
            it = g_markers.erase(it);
            ++removed;
            dirty = true;
        } else {
            ++it;
        }
    }
    if (rank_death_marks()) dirty = true;
    FW_LOG("[map-markers] death marks: %zu crate(s) and %d spot(s) standing, %u death(s) so far: "
           "%d added, %d moved, %d removed",
           list.size() - static_cast<std::size_t>(spots), spots, count, added, moved, removed);
    return dirty;
}

// The peers with a live ghost into the player markers: made, renamed,
// followed, dropped. True when the map has to be rebuilt (a move is not
// that: the map refreshes positions on its own cadence).
bool sync_players(void* player) {
    const auto anchors = fw::native::ghost_head_anchors();
    bool dirty = false;
    std::unordered_set<std::string> seen;
    for (const auto& a : anchors) {
        if (a.peer_id.empty() || !peer_visible_to_local(a.peer_id.c_str())) continue;
        seen.insert(a.peer_id);
        Marker* m = find_player(a.peer_id);
        if (!m) {
            g_markers.push_back(Marker{});
            m = &g_markers.back();
            m->kind = Marker::kPlayer;
            m->peer = a.peer_id;
            m->type = g_player_type;
            m->on_compass = true;
            dirty = true;
            FW_LOG("[map-markers] peer %s: a marker of their own", a.peer_id.c_str());
        }
        std::string name = fw::net::peer_names::display(a.peer_id);
        if (name.empty()) name = a.peer_id;
        if (m->name != name) {
            m->name = name;
            m->named = false;
            dirty = true;
        }
        const auto snap = fw::net::client().get_remote_snapshot(a.peer_id);
        m->cell_id = snap.has_state ? snap.cell_id : 0;
        std::memcpy(m->target, a.head, sizeof m->target);
    }
    for (auto it = g_markers.begin(); it != g_markers.end();) {
        if (it->kind == Marker::kPlayer && !seen.count(it->peer)) {
            drop_refr(*it, player, "the ghost is gone");
            it = g_markers.erase(it);
            dirty = true;
        } else {
            ++it;
        }
    }
    return dirty;
}

// Every marker's REFR as its wish says: wanted only when its target is in
// the player's worldspace (an interior, another worldspace: the
// coordinates would lie on this map), made when missing, remade when lost,
// renamed, moved. True when the map has to be rebuilt.
bool ensure_refrs(void* player, std::uint64_t now) {
    bool dirty = false;
    for (auto& m : g_markers) {
        // Where the target is. Here: shown. Elsewhere (an interior, another
        // worldspace): not shown. NotLoaded (an exterior cell the engine has
        // not loaded in this session; the first live test, 2026-10-15, kept
        // the crates off the map for 80 s until the player walked near):
        // shown, as an exterior of this worldspace (TODO: a world id on the
        // wire would tell for sure). Unknown (a fault): as it was.
        const auto place = fw::engine::cell_place_for_player(m.cell_id, m.target[0], m.target[1]);
        bool want = m.wanted;
        if (place == fw::engine::CellPlace::Here || place == fw::engine::CellPlace::NotLoaded) want = true;
        else if (place == fw::engine::CellPlace::Elsewhere) want = false;
        if (want != m.wanted || !m.verdict_said) {
            if (want != m.wanted) dirty = true;
            m.wanted = want;
            m.verdict_said = true;
            FW_LOG("[map-markers] %s '%s': %s (cell 0x%08X at (%.0f, %.0f) is %s)",
                   kind_name(m), m.name.c_str(), want ? "shown" : "not shown", m.cell_id,
                   m.target[0], m.target[1],
                   place == fw::engine::CellPlace::Here ? "here"
                   : place == fw::engine::CellPlace::NotLoaded ? "not loaded yet (taken as here)"
                   : place == fw::engine::CellPlace::Elsewhere ? "elsewhere" : "unknown");
        }
        if (!m.wanted) {
            if (m.handle) {
                drop_refr(m, player, "its target is not on this map");
                dirty = true;
            }
            continue;
        }
        void* refr = live_refr(m);
        if (!refr) {
            if (m.handle) {
                std::uint32_t h = m.handle;
                void* still = fw::engine::resolve_refhandle(&h);
                const std::uint32_t fl = still ? seh_refr_flags(still) : 0;
                FW_LOG("[map-markers] %s '%s': REFR 0x%08X (handle 0x%08X) is lost (%s): made again",
                       kind_name(m), m.name.c_str(), m.fid, m.handle,
                       !still ? "the handle no longer resolves: a load, a purge"
                       : (fl & offsets::FLAG_DISABLED) ? "DISABLED by the load"
                       : (fl & kFormFlagDeleted) ? "deleted" : "another object has its handle");
                m.fid = 0;
                m.handle = 0;
                m.data = nullptr;
                m.named = false;
                if (now - m.remake_window_ms > 60000) {
                    m.remake_window_ms = now;
                    m.remakes = 0;
                }
                if (++m.remakes > 3) {
                    m.rest_until_ms = now + 60000;
                    FW_WRN("[map-markers] %s '%s': lost %u times in a minute: it rests for a minute",
                           kind_name(m), m.name.c_str(), m.remakes);
                }
            }
            if (now < m.rest_until_ms) continue;
            if (!place_refr(m)) {
                FW_WRN("[map-markers] %s '%s': no REFR this tick (the world not ready?)",
                       kind_name(m), m.name.c_str());
                continue;
            }
            dirty = true;
            std::uint32_t cell_fid = 0;
            bool persistent = false;
            if (void* made = live_refr(m)) seh_refr_cell_info(made, player, &cell_fid, &persistent);
            FW_LOG("[map-markers] %s '%s': REFR 0x%08X handle 0x%08X type %u at (%.0f, %.0f, %.0f)%s, "
                   "parent cell 0x%08X%s",
                   kind_name(m), m.name.c_str(), m.fid, m.handle, m.type,
                   m.placed[0], m.placed[1], m.placed[2], m.on_compass ? "" : " (map only)",
                   cell_fid, persistent ? " (the PERSISTENT cell: the engine's refill collects it)" : "");
            continue;
        }
        if (!m.named) {
            if (seh_set_name(m.data, m.name.c_str())) {
                m.named = true;
                dirty = true;
                FW_LOG("[map-markers] %s REFR 0x%08X: named '%s'", kind_name(m), m.fid, m.name.c_str());
            } else {
                FW_WRN("[map-markers] %s REFR 0x%08X: the name '%s' could not be set (FAULTED)",
                       kind_name(m), m.fid, m.name.c_str());
            }
        }
        move_refr(m, refr, false);
    }
    return dirty;
}

// Every heartbeat (33 ms): the player markers' REFRs follow the ghosts'
// heads, so the compass moves with them (the first live test showed the
// one-second steps of the slow tick). Nothing at all when no player marker
// has a REFR; the rest of the module keeps its one-second cadence.
void follow_players() {
    bool any = false;
    for (const auto& m : g_markers) {
        if (m.kind == Marker::kPlayer && m.wanted && m.handle) { any = true; break; }
    }
    if (!any) return;
    if (fw::engine::loading_menu_open()) return;
    const auto anchors = fw::native::ghost_head_anchors();
    for (const auto& a : anchors) {
        Marker* m = find_player(a.peer_id);
        if (!m || !m->wanted || !m->handle) continue;
        std::memcpy(m->target, a.head, sizeof m->target);
        void* refr = live_refr(*m);
        if (refr) move_refr(*m, refr, false);
    }
}

// The discovery watch (g_visible). `reset`: the array was refilled or
// handed back this tick, the baseline is taken again without firing.
void discovery_watch(void* player, bool reset) {
    static std::uint32_t handles[2048];
    lock_markers();
    const std::uint32_t n = seh_array_snapshot(player, handles, 2048);
    unlock_markers();
    std::unordered_map<std::uint32_t, bool> now_visible;
    std::vector<std::pair<std::uint32_t, std::string>> found;
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t handle = handles[i];
        if (!handle) continue;
        bool ours = false;
        for (const auto& m : g_markers) if (m.handle == handle) { ours = true; break; }
        if (ours) continue;
        std::uint32_t h = handle;
        void* refr = fw::engine::resolve_refhandle(&h);
        if (!refr) continue;
        void* data = seh_get_data(refr);
        if (!data) continue;
        const std::uint32_t fid = seh_refr_fid(refr);
        if (!fid) continue;
        const bool visible = (seh_data_flags(data) & offsets::MAPMARKER_FLAG_VISIBLE) != 0;
        now_visible[fid] = visible;
        if (visible && g_visible_valid && !reset) {
            auto it = g_visible.find(fid);
            if (it != g_visible.end() && !it->second) {
                const char* name = seh_data_name(data);
                found.emplace_back(fid, name ? std::string(name) : std::string());
            }
        }
    }
    g_visible.swap(now_visible);
    g_visible_valid = !reset && n > 0;
    for (const auto& [fid, name] : found) {
        fw::net::LocationDiscoveredPayload p{};
        p.marker_form_id = fid;
        std::snprintf(p.name, sizeof(p.name), "%s", name.c_str());
        fw::net::client().enqueue_location_discovered(p);
        FW_LOG("[map-markers] place discovered: '%s' (0x%08X): a checkpoint asked of the server",
               name.c_str(), fid);
    }
}

// ---------------------------------------------------------------- the publish

// The engine refilled the array (a worldspace change) since the last look.
bool worldspace_changed(void* player) {
    void* ws = seh_player_worldspace(player);
    if (!g_worldspace_seen) {
        g_worldspace_seen = true;
        g_last_worldspace = ws;
        return false;
    }
    if (ws == g_last_worldspace) return false;
    g_last_worldspace = ws;
    return true;
}

// Every compass-visible marker of ours is still in the array.
bool compass_listed(void* player) {
    bool ok = true;
    lock_markers();
    for (const auto& m : g_markers) {
        if (m.wanted && m.on_compass && m.handle && !seh_array_contains(player, m.handle)) {
            ok = false;
            break;
        }
    }
    unlock_markers();
    return ok;
}

bool players_moved_since_rebuild() {
    for (const auto& m : g_markers) {
        if (m.kind == Marker::kPlayer && m.wanted && m.handle && dist2(m.placed, m.map_pos) > 64.0f * 64.0f) {
            return true;
        }
    }
    return false;
}

// Two phases: every wanted marker into the array, the event with TRUE (the
// map rebuilds its entries from the array, all of them), then the map-only
// markers out of the array again (the compass reads the array itself).
// How many handles the player's array holds, how many of them resolve and
// how many are ours (the natives = resolving - ours). Under the lock.
void array_stats(void* player, std::uint32_t* size, std::uint32_t* resolving,
                 std::uint32_t* ours) noexcept {
    *size = 0;
    *resolving = 0;
    *ours = 0;
    __try {
        auto* arr = static_cast<std::uint8_t*>(player) + offsets::PLAYER_MAPMARKERS_ARR_OFF;
        auto* data = *reinterpret_cast<std::uint32_t**>(arr);
        const std::uint32_t n = *reinterpret_cast<std::uint32_t*>(arr + 16);
        if (!data || n > 65536) return;
        *size = n;
        for (std::uint32_t i = 0; i < n; ++i) {
            std::uint32_t h = data[i];
            if (!h) continue;
            if (fw::engine::resolve_refhandle(&h)) ++*resolving;
            for (const auto& m : g_markers) {
                if (m.handle == data[i]) { ++*ours; break; }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// The engine's own refill of the array (offsets.h, MAPMARKERS_REFILL_RVA).
// NOT under our lock: it takes the lock itself (recursive, same thread,
// but it is the engine's call to make).
bool seh_refill(void* player) noexcept {
    __try {
        fn_at<RefillFn>(offsets::MAPMARKERS_REFILL_RVA)(player);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Diagnostics: the REFR's parent cell, and whether it is the persistent
// cell of the player's worldspace (then the engine's refill collects it
// on its own, which the design does not expect).
void seh_refr_cell_info(void* refr, void* player, std::uint32_t* cell_fid, bool* persistent) noexcept {
    *cell_fid = 0;
    *persistent = false;
    __try {
        void* cell = *reinterpret_cast<void**>(static_cast<std::uint8_t*>(refr) + offsets::PARENT_CELL_OFF);
        if (!cell) return;
        *cell_fid = *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(cell) + offsets::FORMID_OFF);
        void* ws = fn_at<RefrWsFn>(offsets::REFR_GET_WORLDSPACE_RVA)(player);
        if (!ws) return;
        void* pcell = *reinterpret_cast<void**>(static_cast<std::uint8_t*>(ws) + offsets::WORLDSPACE_PERSISTENT_CELL_OFF);
        *persistent = (pcell != nullptr && pcell == cell);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// Which of ours the array holds, as a string, for the membership watch.
std::string membership(void* player) {
    std::string s;
    lock_markers();
    for (const auto& m : g_markers) {
        if (!m.handle) continue;
        s += (m.kind == Marker::kCrate ? "crate " : "player ") + m.name
           + (seh_array_contains(player, m.handle) ? ":in " : ":OUT ");
    }
    unlock_markers();
    return s;
}

void publish(void* player, std::uint64_t now, const char* why) {
    int listed = 0, pushed = 0, hidden = 0, crates = 0, players = 0, failed = 0;
    const std::uint32_t sinks = seh_sink_count();
    const std::int32_t before = seh_map_entries();
    std::uint32_t arr_size = 0, arr_ok = 0, arr_ours = 0;
    lock_markers();
    for (auto& m : g_markers) {
        if (!m.wanted || !m.handle) continue;
        const std::int32_t idx = seh_array_push(player, m.handle);
        if (idx >= 0) ++pushed;
        if (idx >= 0 || idx == -2) ++listed; else ++failed;
    }
    array_stats(player, &arr_size, &arr_ok, &arr_ours);
    unlock_markers();
    LARGE_INTEGER f{}, t0{}, t1{};
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    const bool fired = seh_notify(true);
    QueryPerformanceCounter(&t1);
    const std::int32_t after = seh_map_entries();
    // Nobody listened (the Pip-Boy data is down, around a load): the
    // map-only handles stay in the array so the setup's own rebuild takes
    // them, and the publish is made again once the sink is back.
    const bool heard = sinks > 0;
    lock_markers();
    for (auto& m : g_markers) {
        if (!m.wanted || !m.handle) continue;
        if (m.kind == Marker::kCrate) ++crates; else ++players;
        if (heard && !m.on_compass && seh_array_remove(player, m.handle)) ++hidden;
        std::memcpy(m.map_pos, m.placed, sizeof m.map_pos);
    }
    unlock_markers();
    g_last_rebuild_ms = now;
    g_publish_pending = !heard;
    if (heard) g_map_entries_after = after;
    g_membership = membership(player);
    const double ms = f.QuadPart ? (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)f.QuadPart : 0.0;
    FW_LOG("[map-markers] published (%s): %d crate(s) and %d player(s) on the map, %d listed "
           "(%d pushed now, %d could not be), %d map-only; the rebuild %s in %.2f ms; "
           "sinks %u, array %u (%u resolve, %u ours), map entries %d -> %d%s",
           why, crates, players, listed, pushed, failed, hidden, fired ? "fired" : "FAULTED", ms,
           sinks, arr_size, arr_ok, arr_ours, before, after,
           heard ? "" : " (NOBODY LISTENED: the map-only handles stay listed, published again when the map is back)");
}

// An array with no native marker in it (a load emptied it, or ours alone
// went in before the engine's check): ours out, the engine's refill
// called, then a publish when the natives are there. A worldspace that
// has no native marker at all is remembered instead.
void resync(void* player, std::uint64_t now, std::uint32_t size, std::uint32_t resolving,
            std::uint32_t ours) {
    int removed = 0;
    lock_markers();
    for (auto& m : g_markers) {
        if (m.handle && seh_array_remove(player, m.handle)) ++removed;
    }
    unlock_markers();
    const bool refilled = seh_refill(player);
    std::uint32_t size2 = 0, ok2 = 0, ours2 = 0;
    lock_markers();
    array_stats(player, &size2, &ok2, &ours2);
    unlock_markers();
    const std::uint32_t natives = ok2 - (ours2 < ok2 ? ours2 : 0);
    g_visible_valid = false;   // the discovery watch takes its baseline again
    if (natives > 0) {
        FW_LOG("[map-markers] the array had no native marker (size %u, %u resolving, %u ours): "
               "%d of ours taken out, the engine's refill %s: now %u handles (%u resolving); ours go in",
               size, resolving, ours, removed, refilled ? "called" : "FAULTED", size2, ok2);
        g_no_natives_ws = nullptr;
        publish(player, now, "after the engine's refill");
        return;
    }
    // Still nothing native: the worldspace has none (or the engine would not
    // refill): remembered for this worldspace, ours go in anyway.
    g_no_natives_ws = seh_player_worldspace(player);
    if (now - g_resync_said_ms >= 10000) {
        g_resync_said_ms = now;
        FW_LOG("[map-markers] the array has no native marker even after the engine's refill (size %u -> %u, "
               "refill %s): this worldspace has none; ours go in", size, size2,
               refilled ? "called" : "FAULTED");
    }
    publish(player, now, "no native marker in this worldspace");
}

}  // namespace

// ---------------------------------------------------------------- the API

void init(std::uintptr_t module_base, const fw::config::Settings& cfg) {
    g_base = module_base;
    g_enabled = cfg.map_markers;
    g_death_type = static_cast<std::uint16_t>(cfg.map_marker_death_type);
    g_player_type = static_cast<std::uint16_t>(cfg.map_marker_player_type);
    g_rebuild_ms = cfg.map_marker_rebuild_ms;
    if (!g_enabled) {
        FW_LOG("[map-markers] off by config (map_markers = 0)");
        return;
    }
    FW_LOG("[map-markers] armed: death crates icon type %u, players icon type %u, the map's "
           "positions refreshed every %u ms while the Pip-Boy is open", g_death_type, g_player_type,
           g_rebuild_ms);
}

void on_death_crates(std::uint32_t death_count, const fw::net::DeathCrateEntry* entries,
                     std::size_t n) {
    std::lock_guard<std::mutex> g(g_inbox_mtx);
    g_inbox.assign(entries, entries + (entries ? n : 0));
    g_inbox_count = death_count;
    g_inbox_new = true;
    FW_LOG("[map-markers] DEATH_CRATES: %zu crate(s) in the world, %u made so far", n, death_count);
}

void suspend_for_save() {
    if (!g_enabled || !g_base) return;
    g_saving = true;
    void* player = fw::engine::get_local_player();
    int gone = 0;
    for (auto& m : g_markers) {
        if (!m.handle) continue;
        drop_refr(m, player, "a checkpoint is being written");
        ++gone;
    }
    if (gone) FW_LOG("[map-markers] %d marker REFR(s) taken out of the world for the save: remade after it", gone);
}

void resume_after_save() {
    g_saving = false;
}

void tick(std::uintptr_t) {
    if (!g_enabled || !g_base || g_saving) return;
    const std::uint64_t now = GetTickCount64();
    follow_players();
    if (now - g_last_tick_ms < 1000) return;
    g_last_tick_ms = now;
    if (fw::engine::loading_menu_open()) return;
    void* player = fw::engine::get_local_player();
    void* pcell = fw::engine::get_pc_parent_cell();
    if (!player || !pcell) return;
    bool inside = false;
    if (fw::engine::player_in_interior(&inside) && inside) return;   // the local map there: the markers wait
    // The marker REFRs are placed in the player's cell and only MOVED from
    // there (no re-file: the map and the compass read the position alone).
    // When the player leaves that cell, the engine would unload it and
    // destroy a TEMPORARY REFR without unregistering it (the stale entry a
    // later save or load trips over): the markers are taken out the clean
    // way first and remade in the new cell by the pass below.
    if (g_last_player_cell != nullptr && pcell != g_last_player_cell) {
        int moved = 0;
        for (auto& m : g_markers) {
            if (!m.handle) continue;
            drop_refr(m, player, "the player changed cell: remade in the new one");
            ++moved;
        }
        if (moved) FW_LOG("[map-markers] the player's cell changed: %d marker REFR(s) remade in it", moved);
    }
    g_last_player_cell = pcell;

    bool dirty = false;
    const char* why = nullptr;
    // The spots of the deaths without a crate expire (the owner's 15 minutes).
    {
        bool expired = false;
        for (auto it = g_markers.begin(); it != g_markers.end();) {
            if (it->spot && it->expires_at_ms != 0 && now >= it->expires_at_ms) {
                drop_refr(*it, player, "its 15 minutes are over");
                it = g_markers.erase(it);
                expired = true;
            } else {
                ++it;
            }
        }
        if (expired) {
            rank_death_marks();
            dirty = true;
            why = "a death spot expired";
        }
    }
    if (drain_inbox(player, now)) { dirty = true; if (!why) why = "the death marks changed"; }
    if (sync_players(player)) { dirty = true; if (!why) why = "the players changed"; }
    if (ensure_refrs(player, now)) { dirty = true; if (!why) why = "a marker was made, renamed or dropped"; }
    // The engine's natives first (the third live test, offsets.h: the refill).
    {
        std::uint32_t size = 0, ok = 0, ours = 0;
        lock_markers();
        array_stats(player, &size, &ok, &ours);
        unlock_markers();
        const std::uint32_t natives = ok - (ours < ok ? ours : 0);
        const bool known_empty_ws = (g_no_natives_ws != nullptr && g_no_natives_ws == seh_player_worldspace(player));
        if (natives == 0 && !known_empty_ws) {
            resync(player, now, size, ok, ours);
            return;
        }
        // The membership watch: which of ours the array holds, said when it
        // moves without a publish of ours (the engine's refill, a collector
        // that takes one of ours, a lost REFR).
        const std::string seen = membership(player);
        if (seen != g_membership) {
            FW_LOG("[map-markers] the array's membership moved without us: %s(array %u, %u resolving, %u ours)",
                   seen.c_str(), size, ok, ours);
            g_membership = seen;
        }
    }
    const bool ws_changed = worldspace_changed(player);
    discovery_watch(player, ws_changed);
    if (ws_changed) { dirty = true; why = "the engine refilled the array"; }
    if (!dirty && !compass_listed(player)) { dirty = true; why = "a marker was missing from the array"; }
    if (!dirty && g_publish_pending && seh_sink_count() > 0) { dirty = true; why = "the map is back (nobody listened before)"; }
    if (!dirty && !g_publish_pending && g_map_entries_after >= 0 && now - g_last_engine_fix_ms >= 2000) {
        const std::int32_t entries = seh_map_entries();
        if (entries >= 0 && entries != g_map_entries_after) {
            dirty = true;
            why = "the map was rebuilt by the engine";
            g_last_engine_fix_ms = now;
        }
    }
    if (!dirty && players_moved_since_rebuild() && now - g_last_rebuild_ms >= g_rebuild_ms &&
        fw::engine::ui_menu_open(offsets::PIPBOY_MENU_NAME_RVA)) {
        dirty = true;
        why = "the Pip-Boy is open and a player moved";
    }
    if (dirty) publish(player, now, why ? why : "?");
}

bool peer_visible_to_local(const char* peer_id) {
    // TODO (the faction stub, 2026-10-15): a member of another faction is not
    // shown; nobody has a faction yet, so everyone is.
    (void)peer_id;
    return true;
}

}  // namespace fw::native::map_markers
