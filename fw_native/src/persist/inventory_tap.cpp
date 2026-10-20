#include "inventory_tap.h"

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <mutex>

#include "../config.h"
#include "../engine/engine_calls.h"   // get_local_player, resolve_refhandle
#include "../hook_manager.h"
#include "../hooks/world_spawn_hook.h" // report_world_drop
#include "../log.h"
#include "../offsets.h"
#include "lifecycle.h"                // load_in_flight

#pragma intrinsic(_ReturnAddress)

namespace fw::persist::tap {

namespace {

// Signatures from the decomp (2026-09-27); every integer argument is read
// by the callee at the width declared here.
using AddCoreFn = std::int64_t (__fastcall*)(void* refr, void* base, void** sp_extra,
                                             std::uint32_t count, void* old_container,
                                             void* level_info, void* world_ref);
using RemoveCoreFn = void* (__fastcall*)(void* refr, std::uint32_t* out_handle, void* data);
// The drop worker (offsets::INV_DROP_WORKER_RVA): 8 arguments, the last
// four on the stack; every integer passed through at the width received.
using DropWorkerFn = std::int32_t* (__fastcall*)(void* refr, std::uint32_t* out_handle,
                                                 void* obj, std::int64_t count, void* extra,
                                                 void* drop_at, void* rotation, void* refcounted);

AddCoreFn    g_orig_add    = nullptr;
RemoveCoreFn g_orig_remove = nullptr;
DropWorkerFn g_orig_drop   = nullptr;
std::atomic<bool> g_worker_hooked{false};   // the per-REFR path is armed
std::uintptr_t g_base = 0;
std::atomic<bool> g_enabled{false};
std::atomic<bool> g_observe{false};   // inventory_capture: record events for the census
std::atomic<bool> g_drops{false};     // world_spawn_sync: announce Pip-Boy drops

std::mutex g_ring_mtx;
Event g_ring[RING];
std::size_t g_ring_head = 0;   // next write
std::size_t g_ring_count = 0;
std::uint32_t g_dropped = 0;
std::atomic<std::uint64_t> g_adds{0};
std::atomic<std::uint64_t> g_removes{0};

std::uint64_t wall_ms() noexcept {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const std::uint64_t t = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ull) / 10000ull;
}

std::uint32_t seh_form_id(const void* form) noexcept {
    if (!form) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(static_cast<const std::uint8_t*>(form) + offsets::FORMID_OFF); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
std::uint32_t seh_u32(const void* p, std::size_t off) noexcept {
    if (!p) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(static_cast<const std::uint8_t*>(p) + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
void* seh_ptr(const void* p, std::size_t off) noexcept {
    if (!p) return nullptr;
    __try { return *reinterpret_cast<void* const*>(static_cast<const std::uint8_t*>(p) + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

void push(const Event& e) {
    std::lock_guard<std::mutex> lk(g_ring_mtx);
    if (g_ring_count == RING) {
        ++g_dropped;
        // The oldest goes: the census prefers the newest evidence.
        g_ring_count = RING - 1;
    }
    g_ring[g_ring_head] = e;
    g_ring_head = (g_ring_head + 1) % RING;
    ++g_ring_count;
}

bool is_player(void* refr) noexcept {
    return refr != nullptr && refr == fw::engine::get_local_player();
}

std::int64_t __fastcall detour_add(void* refr, void* base, void** sp_extra,
                                   std::uint32_t count, void* old_container,
                                   void* level_info, void* world_ref)
{
    const void* ret = _ReturnAddress();
    if (g_observe.load(std::memory_order_relaxed) && is_player(refr)) {
        g_adds.fetch_add(1, std::memory_order_relaxed);
        Event e{};
        e.wall_ms = wall_ms();
        e.base_id = seh_form_id(base);
        e.delta   = static_cast<std::int32_t>(count);
        const auto a = reinterpret_cast<std::uintptr_t>(ret);
        e.cause = (a >= g_base && a < g_base + 0x10000000ull)
                ? static_cast<std::uint32_t>(a - g_base) : 0xFFFFFFFFu;
        e.other = seh_form_id(old_container ? old_container : world_ref);
        e.during_load = fw::persist::load_in_flight() ? 1 : 0;
        e.tid = GetCurrentThreadId();
        push(e);
    }
    return g_orig_add ? g_orig_add(refr, base, sp_extra, count, old_container, level_info, world_ref) : 0;
}

// reason 3 of RemoveItemData: the item leaves the inventory for the world.
constexpr std::uint32_t kReasonDrop = 3;

// POD only in this frame (SEH-caged readers, no destructors): the detour
// body must stay unwind-free, the same rule as every other hook here.
void* __fastcall detour_remove(void* refr, std::uint32_t* out_handle, void* data) {
    const bool player = data != nullptr && is_player(refr);
    std::uint32_t reason = 0xFFFFFFFFu;
    std::uint32_t count  = 0;
    std::uint32_t base_id = 0;
    if (player) {
        reason  = seh_u32(data, offsets::REMOVE_ITEM_DATA_REASON_OFF) & 0xFFu;
        count   = seh_u32(data, offsets::REMOVE_ITEM_DATA_COUNT_OFF);
        base_id = seh_form_id(seh_ptr(data, offsets::REMOVE_ITEM_DATA_OBJECT_OFF));
        if (g_observe.load(std::memory_order_relaxed)) {
            g_removes.fetch_add(1, std::memory_order_relaxed);
            Event e{};
            e.wall_ms = wall_ms();
            e.base_id = base_id;
            e.delta   = -static_cast<std::int32_t>(count);
            e.cause   = 0x80000000u | reason;
            e.other   = seh_form_id(seh_ptr(data, offsets::REMOVE_ITEM_DATA_OTHER_OFF));
            e.during_load = fw::persist::load_in_flight() ? 1 : 0;
            e.tid = GetCurrentThreadId();
            push(e);
        }
    }
    void* ret = g_orig_remove ? g_orig_remove(refr, out_handle, data) : nullptr;
    // The drop branch wrote the new world REFR's handle into *out_handle:
    // the LAST one only, when the drop spanned several stacks (live: 5
    // stimpaks from three stacks = three REFRs, one handle). The drop
    // worker detour below sees every REFR; this path is the fallback for a
    // session where that detour did not install.
    if (player && reason == kReasonDrop && g_drops.load(std::memory_order_relaxed)
            && !g_worker_hooked.load(std::memory_order_relaxed)) {
        const std::uint32_t h = out_handle ? seh_u32(out_handle, 0) : 0;
        if (h != 0 && h != 0xFFFFFFFFu) {
            void* dropped = fw::engine::resolve_refhandle(out_handle);
            if (dropped) {
                fw::hooks::report_world_drop(dropped, h, static_cast<std::int32_t>(count));
            } else {
                FW_WRN("[inv-tap] drop of 0x%06X x%u: handle 0x%08X did not resolve, "
                       "nothing announced", base_id, count, h);
            }
        } else {
            FW_DBG("[inv-tap] drop of 0x%06X x%u: no handle came back (0x%08X), "
                   "nothing announced", base_id, count, h);
        }
    }
    return ret;
}

// One world REFR per source stack of a drop. After the original: the REFR
// exists, its handle is in *out_handle, its extras (count, instance) are
// final. Player only; every other owner (an NPC dropping its weapon on
// death) is the engine's business.
std::int32_t* __fastcall detour_drop_worker(void* refr, std::uint32_t* out_handle,
                                            void* obj, std::int64_t count, void* extra,
                                            void* drop_at, void* rotation, void* refcounted) {
    std::int32_t* ret = g_orig_drop
        ? g_orig_drop(refr, out_handle, obj, count, extra, drop_at, rotation, refcounted)
        : nullptr;
    if (g_drops.load(std::memory_order_relaxed) && is_player(refr)) {
        const std::uint32_t h = out_handle ? seh_u32(out_handle, 0) : 0;
        const std::uint32_t base_id = seh_form_id(obj);
        if (h != 0 && h != 0xFFFFFFFFu) {
            void* dropped = fw::engine::resolve_refhandle(out_handle);
            if (dropped) {
                fw::hooks::report_world_drop(dropped, h, static_cast<std::int32_t>(count));
            } else {
                FW_WRN("[inv-tap] drop worker: 0x%06X x%lld handle 0x%08X did not resolve, "
                       "nothing announced", base_id, static_cast<long long>(count), h);
            }
        } else {
            FW_DBG("[inv-tap] drop worker: 0x%06X x%lld gave no handle (0x%08X), "
                   "nothing announced", base_id, static_cast<long long>(count), h);
        }
    }
    return ret;
}

} // namespace

int install(std::uintptr_t module_base, const fw::config::Settings& cfg) {
    g_observe.store(cfg.inventory_capture, std::memory_order_relaxed);
    g_drops.store(cfg.world_spawn_sync, std::memory_order_relaxed);
    if (!cfg.inventory_capture && !cfg.world_spawn_sync) {
        FW_LOG("[inv-tap] off: inventory_capture=false and world_spawn_sync=false");
        return 0;
    }
    g_base = module_base;
    int n = 0;
    if (fw::hooks::install(reinterpret_cast<void*>(module_base + offsets::INV_ADD_CORE_RVA),
                           reinterpret_cast<void*>(&detour_add),
                           reinterpret_cast<void**>(&g_orig_add))) {
        ++n;
    } else {
        FW_ERR("[inv-tap] add core NOT hooked at RVA 0x%llX",
               static_cast<unsigned long long>(offsets::INV_ADD_CORE_RVA));
    }
    if (fw::hooks::install(reinterpret_cast<void*>(module_base + offsets::INV_REMOVE_CORE_RVA),
                           reinterpret_cast<void*>(&detour_remove),
                           reinterpret_cast<void**>(&g_orig_remove))) {
        ++n;
    } else {
        FW_ERR("[inv-tap] remove core NOT hooked at RVA 0x%llX",
               static_cast<unsigned long long>(offsets::INV_REMOVE_CORE_RVA));
    }
    if (cfg.world_spawn_sync) {
        if (fw::hooks::install(reinterpret_cast<void*>(module_base + offsets::INV_DROP_WORKER_RVA),
                               reinterpret_cast<void*>(&detour_drop_worker),
                               reinterpret_cast<void**>(&g_orig_drop))) {
            ++n;
            g_worker_hooked.store(true, std::memory_order_release);
        } else {
            FW_ERR("[inv-tap] drop worker NOT hooked at RVA 0x%llX: a drop spanning several "
                   "stacks announces only its last REFR",
                   static_cast<unsigned long long>(offsets::INV_DROP_WORKER_RVA));
        }
    }
    g_enabled.store(n > 0, std::memory_order_release);
    FW_LOG("[inv-tap] %d/%d detours on the inventory cores (player only; census %s, "
           "drop announce %s%s)", n, cfg.world_spawn_sync ? 3 : 2,
           cfg.inventory_capture ? "on" : "off", cfg.world_spawn_sync ? "on" : "off",
           g_worker_hooked.load(std::memory_order_relaxed) ? ", one announce per REFR" : "");
    return n;
}

std::size_t drain(Event* out, std::size_t max, std::uint32_t* dropped) {
    std::lock_guard<std::mutex> lk(g_ring_mtx);
    std::size_t n = 0;
    std::size_t idx = (g_ring_head + RING - g_ring_count) % RING;
    while (g_ring_count > 0 && n < max) {
        out[n++] = g_ring[idx];
        idx = (idx + 1) % RING;
        --g_ring_count;
    }
    if (dropped) { *dropped = g_dropped; g_dropped = 0; }
    return n;
}

const char* cause_name(std::uint32_t cause) {
    if (cause & 0x80000000u) {
        switch (cause & 0xFFu) {
        case 0: return "remove: consume";
        case 1: return "remove: steal";
        case 2: return "remove: barter";
        case 3: return "remove: drop";
        case 4: return "remove: to container";
        case 5: return "remove: to companion";
        default: return "remove: reason ?";
        }
    }
    // Callers of the add core, by the function they sit in (the return
    // address is a few bytes past the call).
    struct { std::uint32_t lo, hi; const char* name; } const table[] = {
        {0x5007B0, 0x5007B0 + 0xB4,  "add: Actor::AddObjectToContainer (transfer/pickup via vt[0x7A])"},
        {0x500430, 0x500430 + 0x376, "add: pickup from the world"},
        {0x522B00, 0x522B00 + 0x33A, "add: Papyrus AddItem worker"},
        {0x509250, 0x509250 + 0x308, "add: REFR::AddObjectToContainer"},
        {0x988080, 0x988080 + 0x2A8, "add: workbench (mod/craft)"},
        {0x989A40, 0x989A40 + 0xD77, "add: workbench (examine)"},
        {0xA57FC0, 0xA57FC0 + 0x237, "add: cooking/crafting result"},
        {0xA5EF20, 0xA5EF20 + 0x2C3, "add: workshop scrap"},
        {0xCACB80, 0xCACB80 + 0xDFE, "add: actor equip path"},
    };
    for (const auto& t : table) if (cause >= t.lo && cause < t.hi) return t.name;
    return nullptr;
}

std::uint64_t events_seen() noexcept {
    return g_adds.load(std::memory_order_relaxed) + g_removes.load(std::memory_order_relaxed);
}

} // namespace fw::persist::tap
