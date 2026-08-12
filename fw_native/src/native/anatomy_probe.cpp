#include "anatomy_probe.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "../log.h"
#include "ni_offsets.h"

namespace fw::native::anatomy_probe {

namespace {

std::atomic<bool> g_on{false};
std::atomic<bool> g_done{false};
std::mutex        g_mtx;
HANDLE            g_file  = INVALID_HANDLE_VALUE;
std::uint32_t     g_nodes = 0;
std::uint32_t     g_geom  = 0;

// Vtable RVAs are the only reliable way to name a node — NiObjectNET's own
// name is authored data and several important nodes carry none. This list is
// the M2.1 walker's, extended with nothing: unknown classes print their RVA
// so a new one shows up as a number rather than being silently mislabelled.
struct VtName { std::uintptr_t rva; const char* name; };
constexpr VtName kVtables[] = {
    { 0x0267C888, "NiNode"           },
    { 0x028FA3E8, "BSFadeNode"       },
    { 0x0267E948, "BSTriShape"       },
    { 0x0267F948, "BSDynamicTriShape"},
    { 0x0267E0B8, "BSGeometry"       },
    { 0x02696D68, "geometry-like"    },
    { 0x026986C0, "NiNode-derived?"  },
    { 0x02908F40, "ShadowSceneNode"  },
};

const char* classify(std::uintptr_t vt_rva) noexcept {
    for (const auto& e : kVtables) if (e.rva == vt_rva) return e.name;
    return "?";
}

bool is_geometry(std::uintptr_t vt_rva) noexcept {
    return vt_rva == 0x0267E0B8 || vt_rva == 0x0267E948 ||
           vt_rva == 0x0267F948 || vt_rva == 0x02696D68;
}

// NiObjectNET keeps a NiFixedString at +0x10. It is a BSStringPool::Entry*,
// and the characters live at entry+0x18 — not a char* despite the u64.
const char* read_name(std::uint64_t handle, char* buf, std::size_t n) noexcept {
    buf[0] = 0;
    if (!handle) return buf;
    __try {
        const char* s = reinterpret_cast<const char*>(handle) + 0x18;
        std::size_t i = 0;
        for (; i + 1 < n && s[i]; ++i) buf[i] = s[i];
        buf[i] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { buf[0] = 0; }
    return buf;
}

void write_line(const char* line, int len) noexcept {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_file == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(g_file, line, static_cast<DWORD>(len), &w, nullptr);
}

// One node. Everything here is a read; nothing in this function writes to
// engine memory. Recursion bounds and the children-pointer sanity check are
// copied from the M2.1 walker rather than reinvented.
void walk(void* node, int depth, int max_depth, std::uintptr_t base) noexcept {
    if (!node || depth > max_depth) return;

    __try {
        auto* b = reinterpret_cast<char*>(node);

        void** vt = *reinterpret_cast<void***>(b);
        const auto vt_rva =
            reinterpret_cast<std::uintptr_t>(vt) > base
                ? reinterpret_cast<std::uintptr_t>(vt) - base : 0;

        char name[128];
        read_name(*reinterpret_cast<std::uint64_t*>(b + NIAV_NAME_OFF),
                  name, sizeof(name));

        const float* t =
            reinterpret_cast<float*>(b + NIAV_LOCAL_TRANSLATE_OFF);
        const std::uint16_t cap =
            *reinterpret_cast<std::uint16_t*>(b + NINODE_CHILDREN_CAP_OFF);
        const std::uint16_t cnt =
            *reinterpret_cast<std::uint16_t*>(b + NINODE_CHILDREN_CNT_OFF);
        void** children =
            *reinterpret_cast<void***>(b + NINODE_CHILDREN_PTR_OFF);

        const bool geom = is_geometry(vt_rva);
        char line[512];
        const int n = std::snprintf(
            line, sizeof(line),
            "%d\t%p\t0x%llX\t%s\t%s\t%.1f,%.1f,%.1f\t%u/%u\t%s\r\n",
            depth, node, static_cast<unsigned long long>(vt_rva),
            classify(vt_rva), name, t[0], t[1], t[2], cnt, cap,
            geom ? "GEOM" : "");
        if (n > 0) write_line(line, n < static_cast<int>(sizeof(line))
                                        ? n : static_cast<int>(sizeof(line)) - 1);
        ++g_nodes;
        if (geom) ++g_geom;

        if (cnt == 0 || cnt > 256)  return;
        if (!children)              return;
        if (depth + 1 > max_depth)  return;
        const auto cp = reinterpret_cast<std::uintptr_t>(children);
        if (cp < 0x00010000ull || cp > 0x00007FFFFFFFFFFFull) return;

        for (std::uint16_t i = 0; i < cnt; ++i) {
            void* child = children[i];
            if (child) walk(child, depth + 1, max_depth, base);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        char line[128];
        const int n = std::snprintf(line, sizeof(line),
                                    "%d\t%p\tSEH\t-\t-\t-\t-\t-\r\n",
                                    depth, node);
        if (n > 0) write_line(line, n);
    }
}

// The player's 3D is reachable by two routes and neither is always live:
// +0xF0 then +0x08, and REFR_LOADED_3D_OFF. scene_inject resolves both for
// the same reason — in first person one of them can be null. No C++ objects
// in this function, so __try is legal (C2712).
bool read_player_3d(std::uintptr_t base, void*& a, void*& b) noexcept {
    a = nullptr; b = nullptr;
    void* player = nullptr;
    __try {
        player = *reinterpret_cast<void**>(base + PLAYER_SINGLETON_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!player) return false;
    __try {
        char* p = reinterpret_cast<char*>(player);
        void* f0 = *reinterpret_cast<void**>(p + 0xF0);
        if (f0) a = *reinterpret_cast<void**>(reinterpret_cast<char*>(f0) + 8);
        b = *reinterpret_cast<void**>(p + REFR_LOADED_3D_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return true;
}

}  // namespace

void init(const std::wstring& dir, bool enabled_) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!enabled_) { g_on.store(false, std::memory_order_relaxed); return; }

    const std::wstring path = dir + L"\\fw_anatomy.log";
    g_file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                         nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                         nullptr);
    if (g_file == INVALID_HANDLE_VALUE) {
        FW_ERR("[anatomy] could not open fw_anatomy.log — probe disabled");
        return;
    }
    const char* hdr =
        "# Local player anatomy — READ ONLY probe, nothing is modified.\r\n"
        "# depth\tptr\tvt_rva\tclass\tname\tpos\tchildren\tgeom\r\n";
    DWORD w = 0;
    WriteFile(g_file, hdr, static_cast<DWORD>(std::strlen(hdr)), &w, nullptr);
    g_on.store(true, std::memory_order_relaxed);
    FW_LOG("[anatomy] probe ARMED -> fw_anatomy.log. It walks the local "
           "player's 3D once, reads only, and disarms itself.");
}

bool enabled() noexcept {
    return g_on.load(std::memory_order_relaxed) &&
           !g_done.load(std::memory_order_relaxed);
}

void maybe_dump(std::uintptr_t module_base) noexcept {
    if (!enabled() || !module_base) return;

    void *a = nullptr, *b = nullptr;
    if (!read_player_3d(module_base, a, b)) return;
    if (!a && !b) return;   // player not loaded yet — try again next tick

    // Both routes get walked when they differ: in first person they point at
    // two different trees, and which one carries the head is exactly the kind
    // of thing this probe exists to answer rather than assume.
    void* roots[2] = { a, (b != a) ? b : nullptr };
    for (int i = 0; i < 2; ++i) {
        if (!roots[i]) continue;
        char hdr[160];
        const int n = std::snprintf(hdr, sizeof(hdr),
                                    "# --- root %d (%s) = %p ---\r\n",
                                    i, i == 0 ? "player+0xF0+0x08"
                                              : "REFR_LOADED_3D",
                                    roots[i]);
        if (n > 0) write_line(hdr, n);
        walk(roots[i], 0, 12, module_base);
    }

    g_done.store(true, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_file != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(g_file);
        }
    }
    FW_LOG("[anatomy] dumped %u nodes (%u carrying geometry) from the local "
           "player's 3D — probe disarmed", g_nodes, g_geom);
}

}  // namespace fw::native::anatomy_probe
