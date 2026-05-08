// ============================================================================
// DEAD-END / KEPT FOR MEMORY OF HOURS PASSED — M9.w4 RE phase, Apr-May 2026
// ============================================================================
//
// See subrefload_hook.h header for the full DEAD-END notice.
// Working M9.w4 path: scene_inject.cpp::ghost_attach_assembled_weapon
// (uses `sub_140434DA0` per-OMOD attach + BSConnectPoint pairing).
// Install call disabled in install_all.cpp.
// ============================================================================
//
// Diagnostic hook for sub_1404580C0 — capture run-time args.
// See subrefload_hook.h for rationale.

#include "subrefload_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::hooks {

namespace {

constexpr std::uintptr_t SUBLOAD_RVA = 0x004580C0;

// Don't yet know the true signature. We capture the 4 register args
// (RCX, RDX, R8, R9) PLUS the next 6 stack args (8 bytes each, starting
// at [rsp+0x28] after the 32-byte shadow space). The agent dossier
// suggests modelExtraData might NOT live in the 4 registers — declared
// via stack might explain why static decomp missed it.
using SubLoadFn = std::uint64_t (__fastcall*)(std::uint64_t a0,
                                              std::uint64_t a1,
                                              std::uint64_t a2,
                                              std::uint64_t a3,
                                              std::uint64_t a4,
                                              std::uint64_t a5,
                                              std::uint64_t a6,
                                              std::uint64_t a7,
                                              std::uint64_t a8,
                                              std::uint64_t a9);

SubLoadFn g_orig = nullptr;

constexpr int MAX_FIRES_LOGGED = 24;     // weapon-only fires
constexpr int MAX_FIRES_SCANNED = 50000; // hard runaway guard
std::atomic<int> g_fire_counter_total{0};
std::atomic<int> g_fire_counter_logged{0};
std::atomic<int> g_fire_counter_skipped_nonweapon{0};

// SEH-protected memory probe — returns true if `addr..addr+nbytes` is
// readable. Probes 1 byte every 16; conservative.
bool seh_is_readable(const void* addr, std::size_t nbytes) {
    if (!addr) return false;
    __try {
        const std::uint8_t* p = static_cast<const std::uint8_t*>(addr);
        for (std::size_t i = 0; i < nbytes; i += 16) {
            volatile std::uint8_t junk = p[i];
            (void)junk;
        }
        // and the last byte
        if (nbytes > 0) {
            volatile std::uint8_t junk = p[nbytes - 1];
            (void)junk;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Hex-dump up to `nbytes` from `addr` to a single log line per 16 bytes.
// Tag is included in every line for grep-ability.
void seh_hexdump(const char* tag, const char* arg_name, const void* addr,
                  std::size_t nbytes) {
    if (!addr) {
        FW_LOG("%s %s = nullptr", tag, arg_name);
        return;
    }
    if (!seh_is_readable(addr, nbytes)) {
        FW_LOG("%s %s = %p (NOT READABLE)", tag, arg_name, addr);
        return;
    }
    FW_LOG("%s %s = %p (hex):", tag, arg_name, addr);
    char line[200];
    const std::uint8_t* p = static_cast<const std::uint8_t*>(addr);
    for (std::size_t off = 0; off < nbytes; off += 16) {
        int w = std::snprintf(line, sizeof(line), "%s   +0x%02zX  ",
                               tag, off);
        for (std::size_t k = 0; k < 16 && off + k < nbytes; ++k) {
            std::uint8_t b = 0;
            __try { b = p[off + k]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { b = 0xFF; }
            w += std::snprintf(line + w, sizeof(line) - w, "%02X ", b);
        }
        // ASCII column
        w += std::snprintf(line + w, sizeof(line) - w, " | ");
        for (std::size_t k = 0; k < 16 && off + k < nbytes; ++k) {
            std::uint8_t b = 0;
            __try { b = p[off + k]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { b = 0; }
            char c = (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            w += std::snprintf(line + w, sizeof(line) - w, "%c", c);
        }
        FW_LOG("%s", line);
    }
}

// Read first qword as potential vtable pointer; if it points back into
// the engine module, log the RVA so we can identify the type.
void seh_classify_pointer(const char* tag, const char* arg_name,
                           std::uint64_t value,
                           std::uintptr_t module_base) {
    // Scalar-ish? (small integer like opts byte 0x2D, 0x08, count, etc.)
    if (value < 0x10000) {
        FW_LOG("%s %s = 0x%llX (likely scalar, e.g. opts/flags/count)",
               tag, arg_name,
               static_cast<unsigned long long>(value));
        return;
    }
    auto* ptr = reinterpret_cast<void*>(value);
    if (!seh_is_readable(ptr, 8)) {
        FW_LOG("%s %s = %p (looks like ptr but not readable)",
               tag, arg_name, ptr);
        return;
    }
    std::uint64_t first_qword = 0;
    __try {
        first_qword = *static_cast<std::uint64_t*>(ptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) { first_qword = 0; }

    // Does first qword look like a vtable in the engine module?
    if (module_base > 0 && first_qword >= module_base &&
        first_qword < module_base + 0x10000000ULL)
    {
        const std::uintptr_t vt_rva = first_qword - module_base;
        FW_LOG("%s %s = %p — first_qword=0x%llX (vtable RVA 0x%llX) "
               "→ likely an OBJECT",
               tag, arg_name, ptr,
               static_cast<unsigned long long>(first_qword),
               static_cast<unsigned long long>(vt_rva));
    } else {
        // Could be a c-string. Try ASCII probe.
        char preview[80] = {};
        bool looks_text = true;
        __try {
            const char* s = static_cast<const char*>(ptr);
            for (int i = 0; i < 64; ++i) {
                char c = s[i];
                if (c == 0) { preview[i] = 0; break; }
                if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7F) {
                    looks_text = false;
                    break;
                }
                preview[i] = c;
                preview[i + 1] = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { looks_text = false; }
        if (looks_text && preview[0]) {
            FW_LOG("%s %s = %p — string='%s'", tag, arg_name, ptr, preview);
        } else {
            FW_LOG("%s %s = %p — first_qword=0x%llX (no clear type)",
                   tag, arg_name, ptr,
                   static_cast<unsigned long long>(first_qword));
        }
    }
}

std::uintptr_t g_module_base = 0;

// Case-insensitive substring search. Returns true if `needle` is found
// anywhere in `hay` (treating both as lowercase). SEH-protected on hay.
bool seh_path_contains_ci(const char* hay, const char* needle) {
    if (!hay || !needle) return false;
    const std::size_t nlen = std::strlen(needle);
    if (nlen == 0) return false;
    __try {
        for (const char* p = hay; *p; ++p) {
            std::size_t i = 0;
            for (; i < nlen; ++i) {
                char a = p[i];
                char b = needle[i];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b || a == 0) break;
            }
            if (i == nlen) return true;
            // Also bail if we hit string terminator before matching
            if (!p[i]) return false;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Read up to 96 bytes of c-string from `addr` into `buf`. SEH-safe.
// Returns count read (excluding null terminator).
std::size_t seh_read_cstring(const void* addr, char* buf,
                              std::size_t bufsz) {
    if (!addr || !buf || bufsz == 0) {
        if (buf && bufsz > 0) buf[0] = 0;
        return 0;
    }
    __try {
        const char* s = static_cast<const char*>(addr);
        std::size_t i = 0;
        for (; i < bufsz - 1; ++i) {
            char c = s[i];
            if (c == 0) break;
            buf[i] = c;
        }
        buf[i] = 0;
        return i;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (bufsz > 0) buf[0] = 0;
        return 0;
    }
}

std::uint64_t __fastcall detour_subload(std::uint64_t a0, std::uint64_t a1,
                                         std::uint64_t a2, std::uint64_t a3,
                                         std::uint64_t a4, std::uint64_t a5,
                                         std::uint64_t a6, std::uint64_t a7,
                                         std::uint64_t a8, std::uint64_t a9)
{
    const int n_total = g_fire_counter_total.fetch_add(1, std::memory_order_relaxed);

    // Early-out runaway guard.
    if (n_total >= MAX_FIRES_SCANNED) {
        return g_orig(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    }

    // Filter by path (a4). Weapons live under "Weapons\\..." (or
    // similar case). All other paths (markers, statics, doors, etc.)
    // are skipped to keep the log focused.
    bool weapon_path = false;
    char path_preview[128] = {};
    if (a4 >= 0x10000) {
        seh_read_cstring(reinterpret_cast<const void*>(a4),
                          path_preview, sizeof(path_preview));
        if (path_preview[0] &&
            seh_path_contains_ci(path_preview, "weapons\\"))
        {
            weapon_path = true;
        }
    }

    if (!weapon_path) {
        g_fire_counter_skipped_nonweapon.fetch_add(1, std::memory_order_relaxed);
        return g_orig(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    }

    const int n = g_fire_counter_logged.fetch_add(1, std::memory_order_relaxed);
    bool log_this = (n < MAX_FIRES_LOGGED);

    if (log_this) {
        char tag[32];
        std::snprintf(tag, sizeof(tag), "[subload-hook][#%d]", n);
        FW_LOG("%s ENTRY regs a0=0x%llX a1=0x%llX a2=0x%llX a3=0x%llX",
               tag,
               static_cast<unsigned long long>(a0),
               static_cast<unsigned long long>(a1),
               static_cast<unsigned long long>(a2),
               static_cast<unsigned long long>(a3));
        FW_LOG("%s ENTRY stk  a4=0x%llX a5=0x%llX a6=0x%llX a7=0x%llX "
               "a8=0x%llX a9=0x%llX",
               tag,
               static_cast<unsigned long long>(a4),
               static_cast<unsigned long long>(a5),
               static_cast<unsigned long long>(a6),
               static_cast<unsigned long long>(a7),
               static_cast<unsigned long long>(a8),
               static_cast<unsigned long long>(a9));
        seh_classify_pointer(tag, "a0", a0, g_module_base);
        seh_classify_pointer(tag, "a1", a1, g_module_base);
        seh_classify_pointer(tag, "a2", a2, g_module_base);
        seh_classify_pointer(tag, "a3", a3, g_module_base);
        seh_classify_pointer(tag, "a4", a4, g_module_base);
        seh_classify_pointer(tag, "a5", a5, g_module_base);
        seh_classify_pointer(tag, "a6", a6, g_module_base);
        seh_classify_pointer(tag, "a7", a7, g_module_base);

        // Hex dumps of pointer-shaped args (skip scalars).
        const std::uint64_t args[] = {a0, a1, a2, a3, a4, a5, a6, a7};
        const char* names[]        = {"a0","a1","a2","a3","a4","a5","a6","a7"};
        for (int i = 0; i < 8; ++i) {
            if (args[i] >= 0x10000) {
                char label[24];
                std::snprintf(label, sizeof(label), "%s[0x40]", names[i]);
                seh_hexdump(tag, label,
                             reinterpret_cast<void*>(args[i]), 0x40);
            }
        }
    }

    std::uint64_t rc = 0;
    __try {
        rc = g_orig(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[subload-hook][#%d] SEH inside g_orig — returning 0", n);
        rc = 0;
    }

    if (log_this) {
        char tag[32];
        std::snprintf(tag, sizeof(tag), "[subload-hook][#%d]", n);
        FW_LOG("%s EXIT   rc=0x%llX", tag,
               static_cast<unsigned long long>(rc));
        // If any arg looks like an out-pointer slot, log what the engine
        // wrote post-call (it might have populated a void** with the
        // resulting BSFadeNode*).
        const std::uint64_t args[] = {a0, a1, a2, a3, a4, a5, a6, a7};
        const char* names[]        = {"a0","a1","a2","a3","a4","a5","a6","a7"};
        for (int i = 0; i < 8; ++i) {
            if (args[i] < 0x10000) continue;
            std::uint64_t out_val = 0;
            __try {
                out_val = *reinterpret_cast<std::uint64_t*>(args[i]);
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            // Only log if it's a plausible NiObject ptr post-call.
            if (out_val >= 0x10000) {
                char label[40];
                std::snprintf(label, sizeof(label), "*%s (post-call)", names[i]);
                seh_classify_pointer(tag, label, out_val, g_module_base);
            }
        }
    }

    return rc;
}

}  // anon namespace

bool install_subload_hook(std::uintptr_t module_base) {
    if (g_orig) {
        FW_LOG("[subload-hook] already installed — skip");
        return true;
    }
    g_module_base = module_base;

    void* target = reinterpret_cast<void*>(module_base + SUBLOAD_RVA);
    void* trampoline = nullptr;
    const bool ok = fw::hooks::install(
        target, reinterpret_cast<void*>(&detour_subload), &trampoline);
    if (!ok || !trampoline) {
        FW_ERR("[subload-hook] install FAILED at 0x%llX",
               reinterpret_cast<unsigned long long>(target));
        return false;
    }
    g_orig = reinterpret_cast<SubLoadFn>(trampoline);
    FW_LOG("[subload-hook] installed at 0x%llX (sub_1404580C0) — "
           "filtering for 'Weapons\\' paths only; first %d weapon fires "
           "will be logged",
           reinterpret_cast<unsigned long long>(target), MAX_FIRES_LOGGED);
    return true;
}

}  // namespace fw::hooks
