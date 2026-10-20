#include "instance_writers.h"

#include <windows.h>
#include <intrin.h>

#include <cstddef>
#include <cstdio>
#include <cstring>

#include "engine_calls.h"                   // lookup_by_form_id
#include "../log.h"
#include "../offsets.h"
#include "../net/protocol.h"                // InstanceDesc, kFp*
#include "../persist/instance_fp.h"
#include "../persist/inventory_capture.h"   // probe_stacks, base_flags_of

namespace fw::engine::instances {

namespace {

std::uintptr_t g_base = 0;

// Engine functions. Integer parameters are declared 64-bit (the project's
// rule); the values passed fit the narrower types the decomp shows.
using AllocFn      = void* (__fastcall*)(std::uint64_t size);
using FreeFn       = void  (__fastcall*)(void* p);
using ListCtorFn   = void* (__fastcall*)(void* list);
using ListDtorFn   = void  (__fastcall*)(void* list);
using LockFn       = void  (__fastcall*)(void* lock);
using AddExtraFn   = void* (__fastcall*)(void* head_slot, void* extra);
using HealthCtorFn = void* (__fastcall*)(void* mem, float value);
using AddRecordFn  = std::uint64_t (__fastcall*)(void* oie, void* mod, std::uint64_t attach,
                                                 std::uint64_t rank, std::uint64_t replace);
using RemoveFn     = void* (__fastcall*)(void* refr, std::uint32_t* out_handle, void* rid);
using AddObjectFn  = void  (__fastcall*)(void* refr, void* obj, void** sp, std::uint64_t count,
                                         void* src, std::uint64_t reason);
using CreateDataFn = void* (__fastcall*)(void* list, void* base, std::uint64_t generate_name);

// The engine's RemoveItemData, laid out as offsets.h documents it.
struct RemoveItemData {
    std::int32_t  header;      // sign bit: indices inline at +0x08
    std::uint32_t pad0;
    std::uint32_t idx[4];      // +0x08
    std::uint32_t idx_count;   // +0x18
    std::uint32_t pad1;
    void*         object;      // +0x20
    std::uint32_t count;       // +0x28
    std::uint32_t reason;      // +0x2C
    void*         dest;        // +0x30
    std::uint64_t drop_a;      // +0x38
    std::uint64_t drop_b;      // +0x40
};
static_assert(offsetof(RemoveItemData, idx) == 0x08, "RemoveItemData idx");
static_assert(offsetof(RemoveItemData, idx_count) == 0x18, "RemoveItemData idx_count");
static_assert(offsetof(RemoveItemData, object) == 0x20, "RemoveItemData object");
static_assert(offsetof(RemoveItemData, count) == 0x28, "RemoveItemData count");
static_assert(offsetof(RemoveItemData, reason) == 0x2C, "RemoveItemData reason");
static_assert(offsetof(RemoveItemData, dest) == 0x30, "RemoveItemData dest");
static_assert(sizeof(RemoveItemData) == 0x48, "RemoveItemData size");

constexpr std::uint32_t kReasonDestroy   = 0;
constexpr std::uint32_t kReasonContainer = 4;

// One scan buffer for every primitive: main thread only.
constexpr std::uint32_t kScanMax = 256;
fw::persist::inventory::ProbeStack g_scan[kScanMax];

template <class T> T fn_at(std::uintptr_t rva) { return reinterpret_cast<T>(g_base + rva); }

// ------------------------------------------------------------- SEH calls
void* seh_alloc(std::size_t size) noexcept {
    __try { return fn_at<AllocFn>(offsets::EXTRA_ALLOC_RVA)(size); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
bool seh_free(void* p) noexcept {
    __try { fn_at<FreeFn>(offsets::EXTRA_FREE_RVA)(p); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_list_ctor(void* list) noexcept {
    __try { fn_at<ListCtorFn>(offsets::EXTRALIST_CTOR_RVA)(list); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_list_dtor(void* list) noexcept {
    __try { fn_at<ListDtorFn>(offsets::EXTRALIST_DTOR_RVA)(list); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// Links `extra` into `list` under the list's write lock.
bool seh_list_add(void* list, void* extra) noexcept {
    auto* lb = static_cast<std::uint8_t*>(list);
    __try {
        fn_at<LockFn>(offsets::EXTRALIST_WLOCK_RVA)(lb + offsets::EXTRALIST_LOCK_OFF);
        fn_at<AddExtraFn>(offsets::EXTRALIST_ADD_RVA)(lb + offsets::EXTRALIST_HEAD_OFF, extra);
        fn_at<LockFn>(offsets::EXTRALIST_WUNLOCK_RVA)(lb + offsets::EXTRALIST_LOCK_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// One OMOD record appended to `oie`, under the list's write lock (as
// sub_140248F40 holds it around the same call).
bool seh_add_record(void* list, void* oie, void* mod, std::uint8_t attach, std::uint8_t rank) noexcept {
    auto* lb = static_cast<std::uint8_t*>(list);
    __try {
        fn_at<LockFn>(offsets::EXTRALIST_WLOCK_RVA)(lb + offsets::EXTRALIST_LOCK_OFF);
        fn_at<AddRecordFn>(offsets::OIE_ADD_RECORD_RVA)(oie, mod, attach, rank, /*replace=*/0);
        fn_at<LockFn>(offsets::EXTRALIST_WUNLOCK_RVA)(lb + offsets::EXTRALIST_LOCK_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
void* seh_health(float value) noexcept {
    __try {
        void* mem = fn_at<AllocFn>(offsets::EXTRA_ALLOC_RVA)(offsets::EXTRAHEALTH_SIZE);
        if (!mem) return nullptr;
        fn_at<HealthCtorFn>(offsets::EXTRAHEALTH_CTOR_RVA)(mem, value);
        return mem;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
bool seh_remove(void* refr, RemoveItemData* rid, std::uint32_t* handle) noexcept {
    __try {
        auto** vt = *reinterpret_cast<void***>(refr);
        reinterpret_cast<RemoveFn>(vt[offsets::REFR_VT_REMOVE_ITEM_SLOT])(refr, handle, rid);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
// The instance data and the generated name (offsets.h,
// XLIST_CREATE_INSTANCE_DATA_RVA). False = faulted: the list's state is
// unknown, its write lock possibly still held.
bool seh_create_data(void* list, void* form, void** data) noexcept {
    __try {
        *data = fn_at<CreateDataFn>(offsets::XLIST_CREATE_INSTANCE_DATA_RVA)(list, form, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_add_object(void* refr, void* form, void** sp, std::uint64_t count) noexcept {
    __try {
        auto** vt = *reinterpret_cast<void***>(refr);
        reinterpret_cast<AddObjectFn>(vt[offsets::REFR_VT_ADD_OBJECT_SLOT])(
            refr, form, sp, count, nullptr, 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
std::uint8_t seh_form_type(const void* form) noexcept {
    __try { return *(static_cast<const std::uint8_t*>(form) + offsets::FORMTYPE_OFF); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Our reference on a list we built. The last one destroys it the engine's
// way (the remove core's own idiom).
void release_list(void* list) noexcept {
    if (_InterlockedDecrement(static_cast<volatile long*>(list)) == 0) {
        seh_list_dtor(list);
        seh_free(list);
    }
}

// The ExtraDataList of one unit of the instance `d`, refcount 1 (ours).
// nullptr (and nothing left behind) when any step fails: a partial instance
// would be a different item than the one the server names.
void* build_list(const fw::net::InstanceDesc& d, char* why, std::size_t why_n) {
    void* list = seh_alloc(offsets::EXTRALIST_SIZE);
    if (!list) { std::snprintf(why, why_n, "list alloc"); return nullptr; }
    std::memset(list, 0, offsets::EXTRALIST_SIZE);
    if (!seh_list_ctor(list)) {
        seh_free(list);
        std::snprintf(why, why_n, "list ctor faulted");
        return nullptr;
    }
    _InterlockedIncrement(static_cast<volatile long*>(list));
    if (d.flags & fw::net::kInstanceFlagOie) {
        auto* oie = static_cast<std::uint8_t*>(seh_alloc(offsets::OIE_NODE_SIZE));
        if (!oie) { release_list(list); std::snprintf(why, why_n, "OIE alloc"); return nullptr; }
        std::memset(oie, 0, offsets::OIE_NODE_SIZE);
        *reinterpret_cast<std::uintptr_t*>(oie) = g_base + offsets::EXTRA_VT_OIE_RVA;
        oie[offsets::BSEXTRADATA_TYPE_BYTE_OFF] = offsets::EXTRA_TYPE_OIE;
        *reinterpret_cast<std::uint16_t*>(oie + offsets::OIE_TEMPLATE_INDEX_OFF) = d.tmpl;
        if (!seh_list_add(list, oie)) {
            // The link may have half happened: the node is left to the list.
            release_list(list);
            std::snprintf(why, why_n, "OIE link faulted");
            return nullptr;
        }
        for (std::uint8_t i = 0; i < d.mod_n && i < fw::net::kInstanceMaxMods; ++i) {
            void* mod = lookup_by_form_id(d.mods[i].form);
            if (!mod || seh_form_type(mod) != offsets::FORMTYPE_OMOD) {
                release_list(list);
                std::snprintf(why, why_n, "mod 0x%08X %s", d.mods[i].form,
                              mod ? "is not an OMOD" : "not found");
                return nullptr;
            }
            if (!seh_add_record(list, oie, mod, d.mods[i].attach, d.mods[i].rank)) {
                release_list(list);
                std::snprintf(why, why_n, "record of mod 0x%08X faulted", d.mods[i].form);
                return nullptr;
            }
        }
    }
    if (d.flags & fw::net::kInstanceFlagHealth) {
        void* h = seh_health(d.health);
        if (!h || !seh_list_add(list, h)) {
            release_list(list);
            std::snprintf(why, why_n, "health extra");
            return nullptr;
        }
    }
    return list;
}

// The units of (base, fp) `refr` holds, from one scan; -1 unreadable.
int units_of(void* refr, std::uint32_t base, std::uint64_t fp) {
    std::uint32_t reasons = 0;
    const std::uint32_t n = fw::persist::inventory::probe_stacks(g_base, refr, base, g_scan,
                                                                 kScanMax, &reasons);
    if (reasons & (fw::persist::inventory::REASON_WRITER_HELD |
                   fw::persist::inventory::REASON_NO_LIST)) return -1;
    int units = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
        if (g_scan[i].transient) continue;
        if (fw::persist::instance::fp_of_record(g_scan[i].r, nullptr) == fp) units += g_scan[i].r.count;
    }
    return units;
}

} // namespace

void init(std::uintptr_t module_base) { g_base = module_base; }

bool scan_lines(void* refr, std::uint32_t base, Line* out, std::size_t max, std::size_t* n_out,
                std::uint32_t* reasons_out) {
    if (n_out) *n_out = 0;
    if (reasons_out) *reasons_out = 0;
    if (!refr || !out || !g_base) return false;
    std::uint32_t reasons = 0;
    const std::uint32_t n = fw::persist::inventory::probe_stacks(g_base, refr, base, g_scan,
                                                                 kScanMax, &reasons);
    if (reasons_out) *reasons_out = reasons;
    if (reasons & (fw::persist::inventory::REASON_WRITER_HELD |
                   fw::persist::inventory::REASON_NO_LIST)) return false;
    std::size_t lines = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
        const auto& s = g_scan[i];
        if (s.transient || s.r.count <= 0) continue;
        const std::uint64_t fp = fw::persist::instance::fp_of_record(s.r, nullptr);
        std::size_t k = 0;
        for (; k < lines; ++k) if (out[k].base == s.r.base_id && out[k].fp == fp) break;
        if (k == lines) {
            if (lines >= max) break;
            out[lines++] = Line{s.r.base_id, fp, 0};
        }
        out[k].count += s.r.count;
    }
    if (n_out) *n_out = lines;
    return true;
}

int count_of(void* refr, std::uint32_t base, std::uint64_t fp) {
    if (!refr || !g_base) return -1;
    return units_of(refr, base, fp);
}

bool describe(void* refr, std::uint32_t base, std::uint64_t fp, fw::net::InstanceDesc* out) {
    if (!refr || !out || !g_base || fp == fw::net::kFpUnknown) return false;
    std::uint32_t reasons = 0;
    const std::uint32_t n = fw::persist::inventory::probe_stacks(g_base, refr, base, g_scan,
                                                                 kScanMax, &reasons);
    if (reasons & (fw::persist::inventory::REASON_WRITER_HELD |
                   fw::persist::inventory::REASON_NO_LIST)) return false;
    for (std::uint32_t i = 0; i < n; ++i) {
        if (g_scan[i].transient) continue;
        fw::net::InstanceDesc d{};
        if (fw::persist::instance::fp_of_record(g_scan[i].r, &d) == fp) {
            *out = d;
            return true;
        }
    }
    return false;
}

int remove_instance(void* refr, std::uint32_t base, std::uint64_t fp, int count, void* dest) {
    if (!refr || base == 0 || count <= 0 || !g_base) return 0;
    void* form = lookup_by_form_id(base);
    if (!form) return 0;
    int removed = 0;
    for (int round = 0; round < 32 && removed < count; ++round) {
        std::uint32_t reasons = 0;
        const std::uint32_t n = fw::persist::inventory::probe_stacks(g_base, refr, base, g_scan,
                                                                     kScanMax, &reasons);
        if (reasons & (fw::persist::inventory::REASON_WRITER_HELD |
                       fw::persist::inventory::REASON_NO_LIST)) break;
        int chain = -1, units = 0, before = 0;
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto& s = g_scan[i];
            if (s.transient) continue;
            if (fw::persist::instance::fp_of_record(s.r, nullptr) != fp) continue;
            before += s.r.count;
            if (chain < 0) { chain = s.chain; units = s.r.count; }
        }
        if (chain < 0 || units <= 0) break;
        RemoveItemData rid{};
        rid.header    = static_cast<std::int32_t>(0x80000004u);
        rid.idx[0]    = static_cast<std::uint32_t>(chain);
        rid.idx_count = 1;
        rid.object    = form;
        rid.count     = static_cast<std::uint32_t>(count - removed < units ? count - removed : units);
        rid.reason    = dest ? kReasonContainer : kReasonDestroy;
        rid.dest      = dest;
        std::uint32_t handle = 0;
        if (!seh_remove(refr, &rid, &handle)) {
            FW_ERR("[instance] remove of 0x%08X fp=%016llX (stack #%d, %u unit(s)) FAULTED in "
                   "the engine's RemoveItem", base, static_cast<unsigned long long>(fp), chain,
                   rid.count);
            break;
        }
        const int after = units_of(refr, base, fp);
        const int gone = (after >= 0) ? before - after : 0;
        if (gone <= 0) {
            FW_WRN("[instance] remove of 0x%08X fp=%016llX (stack #%d) moved nothing", base,
                   static_cast<unsigned long long>(fp), chain);
            break;
        }
        removed += gone;
    }
    return removed;
}

int add_instance(void* refr, std::uint32_t base, const fw::net::InstanceDesc& d, int count) {
    if (!refr || base == 0 || count <= 0 || !g_base) return 0;
    if (d.mod_n > fw::net::kInstanceMaxMods) return 0;
    void* form = lookup_by_form_id(base);
    if (!form) return 0;
    // A base with the unique-id flag gets one unit per pass from the add core
    // and the units after the first a copy without the OIE (rolled again): so
    // one unit per call, each with its own list.
    const bool one_by_one =
        (fw::persist::inventory::base_flags_of(base) & offsets::TESFORM_FLAG_UNIQUE_IDS) != 0;
    int added = 0;
    while (added < count) {
        const int n = one_by_one ? 1 : count - added;
        char why[96] = "";
        void* list = build_list(d, why, sizeof(why));
        if (!list) {
            FW_WRN("[instance] instance of 0x%08X not built: %s", base, why);
            break;
        }
        // What the engine's own creation adds after the OIE: the instance
        // data (the stats) and the name. Without it the instance is exact
        // but shows the base's name.
        if (d.flags & fw::net::kInstanceFlagOie) {
            void* data = nullptr;
            if (!seh_create_data(list, form, &data)) {
                // Neither freed nor handed on in an unknown state: leaked.
                FW_ERR("[instance] instance data of 0x%08X FAULTED; the list is leaked, "
                       "nothing added", base);
                break;
            }
            if (!data) {
                FW_DBG("[instance] no instance data for 0x%08X (tmpl 0x%04X, %u mods)",
                       base, unsigned(d.tmpl), unsigned(d.mod_n));
            }
        }
        // The callee consumes one reference: its own, added here.
        _InterlockedIncrement(static_cast<volatile long*>(list));
        void* sp = list;
        if (!seh_add_object(refr, form, &sp, static_cast<std::uint64_t>(n))) {
            // How far the engine got is unknown: neither reference is
            // dropped, the list is leaked rather than freed under it.
            FW_ERR("[instance] add of %d x 0x%08X FAULTED in the container's AddObject; "
                   "the list is left to the engine", n, base);
            break;
        }
        release_list(list);
        added += n;
    }
    return added;
}

} // namespace fw::engine::instances
