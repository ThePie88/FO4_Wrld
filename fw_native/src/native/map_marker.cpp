#include "map_marker.h"

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "../config.h"
#include "../engine/engine_calls.h"
#include "../log.h"
#include "../offsets.h"
#include "../render/chat_overlay.h"

namespace fw::native::map_marker {

namespace {

// Signatures from the decomp (2026-10-15, RESEARCH_L5.md "D2 rivisto").
using AllocFn       = void* (__fastcall*)(std::uint64_t size);
using DataCtorFn    = void* (__fastcall*)(void* data);
using DataSetNameFn = void (__fastcall*)(void* data, const char* name);
using ListSetDataFn = void* (__fastcall*)(void* list, void* data);
using RefrGetDataFn = void* (__fastcall*)(void* refr, std::uint64_t unused);
using AddToMapFn    = std::uint64_t (__fastcall*)(std::uint64_t vm, std::uint32_t stack_id,
                                                  void* refr, char allow_travel);

std::uintptr_t g_base   = 0;
std::uint32_t  g_type   = 30;
int            g_state  = 0;        // 0 none, 1 placed (flags only), 2 added to the map
std::uint32_t  g_fid    = 0;
std::uint32_t  g_handle = 0;
void*          g_data   = nullptr;

template <typename F>
F fn_at(std::uintptr_t rva) { return reinterpret_cast<F>(g_base + rva); }

// POD-only frames: the SEH cage forbids objects with destructors here.
void* seh_make_data(const char* name, std::uint32_t type) noexcept {
    __try {
        void* data = fn_at<AllocFn>(offsets::EXTRA_ALLOC_RVA)(offsets::MAPMARKERDATA_SIZE);
        if (!data) return nullptr;
        fn_at<DataCtorFn>(offsets::MAPMARKERDATA_CTOR_RVA)(data);
        fn_at<DataSetNameFn>(offsets::MAPMARKERDATA_SET_NAME_RVA)(data, name);
        auto* b = static_cast<std::uint8_t*>(data);
        // Visible, NO fast travel (the owner's decision, 2026-10-15).
        *(b + offsets::MAPMARKERDATA_FLAGS_OFF) = offsets::MAPMARKER_FLAG_VISIBLE;
        *reinterpret_cast<std::uint16_t*>(b + offsets::MAPMARKERDATA_TYPE_OFF) =
            static_cast<std::uint16_t>(type);
        return data;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// TESObjectREFR::extraList (+0x100) is a POINTER to the list, which the
// engine assumes non-null on every REFR (world_spawn.cpp reads it the same
// way). The first live press (2026-10-15 17:50) passed the address of the
// field instead and faulted inside the engine's add.
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

std::uint32_t seh_flags(const void* data) noexcept {
    if (!data) return 0xFFFFFFFFu;
    __try {
        return *(static_cast<const std::uint8_t*>(data) + offsets::MAPMARKERDATA_FLAGS_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

bool seh_add_to_map(void* refr) noexcept {
    __try {
        // vm and stack id are read only on the error path ("is not a map
        // marker"), which the data attached first keeps closed.
        (void)fn_at<AddToMapFn>(offsets::PAPYRUS_ADD_TO_MAP_RVA)(0, 0, refr, 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ---- the player's map marker array (offsets.h, PLAYER_MAPMARKERS_ARR_OFF)
using LockFn      = void (__fastcall*)(void* lock);
using PushIndexFn = std::int32_t (__fastcall*)(std::uint32_t* size, void* functor,
                                               std::uint32_t capacity, std::uint32_t elem_size);

void lock_markers() noexcept {
    fn_at<LockFn>(offsets::SPINLOCK_LOCK_RVA)(reinterpret_cast<void*>(g_base + offsets::MAPMARKERS_LOCK_RVA));
}
// The engine's own unlock, inlined as sub_140D74690 does it: the last
// holder clears the owner and the count, a nested one just decrements.
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

// Pushes `handle` into the player's array unless it is there already.
// Returns the slot index, -2 when already present, -1 on a fault or a full
// array that could not grow. Main thread, POD frame.
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

// Takes `handle` out of the array (the last entry moves into its slot).
// True when it was there.
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

// Fires the engine's own "the marker list changed" event: the map's sink
// rebuilds its entries from the player's array (offsets.h, the notify).
// Always TRUE: with false (the engine's value on an ordinary cell change)
// the sink rebuilds only while its map is still empty, and ours never is
// by the time a marker is made at runtime (the fourth experiment showed
// nothing on the map). True empties the sink's entries and rebuilds.
using NotifyMarkersFn = void (__fastcall*)(char changed);

bool seh_notify_markers(bool worldspace_changed) noexcept {
    __try {
        fn_at<NotifyMarkersFn>(offsets::MAPMARKERS_NOTIFY_RVA)(worldspace_changed ? 1 : 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::uint32_t seh_array_size(void* player) noexcept {
    __try {
        return *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(player)
                                                 + offsets::PLAYER_MAPMARKERS_ARR_OFF + 16);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

void* current_refr() {
    if (g_handle == 0) return nullptr;
    std::uint32_t h = g_handle;
    return fw::engine::resolve_refhandle(&h);
}

void say(const char* msg) {
    FW_LOG("[map-marker] %s", msg);
    fw::render::chat::notice(std::string("(map marker test: ") + msg + ")");
}

void reset() {
    g_state = 0;
    g_fid = 0;
    g_handle = 0;
    g_data = nullptr;
}

}  // namespace

void init(std::uintptr_t module_base, const fw::config::Settings& cfg) {
    g_base = module_base;
    g_type = cfg.map_marker_test_type;
    if (cfg.map_marker_test_key == 0) {
        FW_LOG("[map-marker] experiment off (map_marker_test_key = 0; D2 closed 2026-10-16, the code stays)");
        return;
    }
    FW_LOG("[map-marker] experiment armed: key 0x%02X, icon type %u (press 1 = place, "
           "2 = AddToMap, 3 = remove)", cfg.map_marker_test_key, g_type);
}

void on_test_key() {
    if (!g_base) return;
    if (g_state == 0) {
        if (!fw::engine::get_pc_parent_cell()) {
            say("no world yet");
            return;
        }
        std::uint32_t fid = 0, handle = 0;
        void* refr = fw::engine::place_world_object(offsets::MAPMARKER_BASE_FORMID, &fid, &handle);
        if (!refr) {
            say("PlaceAtMe of the MapMarker base failed (the world not ready?)");
            return;
        }
        void* data = seh_make_data("FW TEST", g_type);
        if (!data) {
            say("the marker data could not be made: the REFR is disabled again");
            fw::engine::disable_ref(refr, false);
            return;
        }
        if (!seh_set_data(refr, data)) {
            say("SetMapMarkerData FAULTED (or the REFR has no extra list): the REFR is disabled again");
            fw::engine::disable_ref(refr, false);
            return;
        }
        void* got = seh_get_data(refr);
        // The second experiment (2026-10-15): the data alone showed nothing,
        // the engine collects markers from the persistent cell only; the
        // handle goes into the player's array by hand, under the lock.
        void* player = fw::engine::get_local_player();
        std::int32_t idx = -1;
        std::uint32_t before = 0xFFFFFFFFu, after = 0xFFFFFFFFu;
        if (player) {
            lock_markers();
            before = seh_array_size(player);
            idx = seh_array_push(player, handle);
            after = seh_array_size(player);
            unlock_markers();
        }
        // The third experiment (2026-10-15): the compass read the array, the
        // Pip-Boy map did not; the map rebuilds its entries only on the
        // event the engine's refill fires, so it is fired here by hand.
        const bool listed = (idx >= 0 || idx == -2);
        const bool notified = listed && seh_notify_markers(true);
        g_fid = fid;
        g_handle = handle;
        g_data = data;
        g_state = 1;
        char msg[360];
        std::snprintf(msg, sizeof(msg),
                      "A: marker fid=0x%08X handle=0x%08X data=%p (read back %p, flags 0x%X, "
                      "type %u); pushed into the player's marker array at %d (size %u -> %u); "
                      "marker-list event %s. Look at the compass and the Pip-Boy map, then "
                      "press again for AddToMap",
                      fid, handle, data, got, seh_flags(got), g_type, idx, before, after,
                      notified ? "fired" : (listed ? "FAULTED" : "not fired (not listed)"));
        say(msg);
        return;
    }
    void* refr = current_refr();
    if (!refr) {
        say("the marker is gone (a load?): state reset");
        reset();
        return;
    }
    if (g_state == 1) {
        const bool ok = seh_add_to_map(refr);
        void* got = seh_get_data(refr);
        char msg[160];
        std::snprintf(msg, sizeof(msg), "B: AddToMap %s (flags now 0x%X). Look again, then "
                      "press to remove", ok ? "ran" : "FAULTED", seh_flags(got));
        say(msg);
        if (ok) g_state = 2;
        return;
    }
    bool unlisted = false;
    if (void* player = fw::engine::get_local_player()) {
        lock_markers();
        unlisted = seh_array_remove(player, g_handle);
        unlock_markers();
    }
    // The map rebuilt without our handle BEFORE the data goes (the rebuild
    // resolves every handle in the array and reads its data).
    const bool notified = seh_notify_markers(true);
    const bool cleared = seh_set_data(refr, nullptr);   // the engine frees the extra and its data
    fw::engine::disable_ref(refr, false);
    char msg[200];
    std::snprintf(msg, sizeof(msg), "removed: %s the player's array, marker-list event %s, data %s, "
                  "REFR 0x%08X disabled",
                  unlisted ? "taken out of" : "was not in", notified ? "fired" : "FAULTED",
                  cleared ? "taken off" : "NOT taken off", g_fid);
    say(msg);
    reset();
}

}  // namespace fw::native::map_marker
