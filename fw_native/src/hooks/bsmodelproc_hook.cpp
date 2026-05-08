// ============================================================================
// DEAD-END / KEPT FOR MEMORY OF HOURS PASSED — M9.w4 RE phase, Apr-May 2026
// ============================================================================
//
// See bsmodelproc_hook.h header for the full DEAD-END notice.
// Working M9.w4 path: scene_inject.cpp::ghost_attach_assembled_weapon
// (uses `sub_140434DA0` per-OMOD attach + BSConnectPoint pairing).
// Install call disabled in install_all.cpp.
// ============================================================================
//
// Diagnostic hook for sub_1402FC0E0 — the BSModelProcessor post-hook
// where OMODs are applied to a freshly-parsed BSFadeNode tree.
// See bsmodelproc_hook.h for the design rationale.

#include "bsmodelproc_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::hooks {

namespace {

constexpr std::uintptr_t BSMODELPROC_RVA = 0x002FC0E0;

// 4 register args + 6 stack args (we don't know the true arity, so we
// over-capture). The fastcall ABI passes the first 4 in RCX/RDX/R8/R9
// and the rest at [rsp+0x28..]. Reading "extra" args when the real
// function has fewer is safe: we read garbage, never write.
using BsModProcFn = std::uint64_t (__fastcall*)(
    std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3,
    std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7);

BsModProcFn g_orig = nullptr;
std::uintptr_t g_module_base = 0;

constexpr int MAX_FIRES_LOGGED = 32;
std::atomic<int> g_fires_total{0};
std::atomic<int> g_fires_logged{0};

bool seh_is_readable(const void* addr, std::size_t nbytes) {
    if (!addr) return false;
    __try {
        const std::uint8_t* p = static_cast<const std::uint8_t*>(addr);
        for (std::size_t i = 0; i < nbytes; i += 16) {
            volatile std::uint8_t x = p[i]; (void)x;
        }
        if (nbytes > 0) {
            volatile std::uint8_t x = p[nbytes - 1]; (void)x;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

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
        int w = std::snprintf(line, sizeof(line), "%s   +0x%02zX  ", tag, off);
        for (std::size_t k = 0; k < 16 && off + k < nbytes; ++k) {
            std::uint8_t b = 0;
            __try { b = p[off + k]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { b = 0xFF; }
            w += std::snprintf(line + w, sizeof(line) - w, "%02X ", b);
        }
        w += std::snprintf(line + w, sizeof(line) - w, " | ");
        for (std::size_t k = 0; k < 16 && off + k < nbytes; ++k) {
            std::uint8_t b = 0;
            __try { b = p[off + k]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { b = 0; }
            char c = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            w += std::snprintf(line + w, sizeof(line) - w, "%c", c);
        }
        FW_LOG("%s", line);
    }
}

// Try to read m_name (NiObjectNET +0x10 → BSFixedString handle → +0x18
// = c-string). Returns count of chars copied (0 if fail).
std::size_t seh_read_node_name(void* node, char* buf, std::size_t bufsz) {
    if (!node || !buf || bufsz < 2) {
        if (buf && bufsz > 0) buf[0] = 0;
        return 0;
    }
    __try {
        const char* pool = *reinterpret_cast<const char* const*>(
            static_cast<char*>(node) + 0x10);
        if (!pool) { buf[0] = 0; return 0; }
        const char* s = pool + 0x18;
        std::size_t i = 0;
        for (; i < bufsz - 1; ++i) {
            char c = s[i];
            if (c == 0) break;
            if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7F) {
                buf[0] = 0; return 0;
            }
            buf[i] = c;
        }
        buf[i] = 0;
        return i;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (bufsz > 0) buf[0] = 0;
        return 0;
    }
}

// Walk the node's extra-data chain and dump each entry's vtable RVA + raw
// bytes. ALPHA: post-hook reads `*node + 0x18` to get the chain head;
// each entry is linked via +0x08 (BSExtraData::Next ptr). We dump the
// type byte at +0x12 and the first 0x40 of every entry to identify
// the OIE shape vs others.
void dump_extra_data_chain(const char* tag, void* node) {
    if (!node) return;
    if (!seh_is_readable(node, 0x40)) {
        FW_LOG("%s extra-chain: node %p not readable", tag, node);
        return;
    }

    char nm[128] = {};
    seh_read_node_name(node, nm, sizeof(nm));
    FW_LOG("%s node=%p name='%s' — walking extra-data chain at +0x18",
           tag, node, nm);

    // Read chain head pointer at node+0x18 (CHECK: per ALPHA dossier).
    void* head = nullptr;
    __try {
        head = *reinterpret_cast<void**>(static_cast<char*>(node) + 0x18);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_LOG("%s extra-chain: SEH reading node+0x18", tag);
        return;
    }
    if (!head) {
        FW_LOG("%s extra-chain: node+0x18 == NULL (no extras)", tag);
        return;
    }

    void* cur = head;
    int idx = 0;
    while (cur && idx < 16) {
        char etag[64];
        std::snprintf(etag, sizeof(etag), "%s.extra[%d]", tag, idx);

        if (!seh_is_readable(cur, 0x40)) {
            FW_LOG("%s @ %p NOT READABLE — stop", etag, cur);
            break;
        }

        std::uint64_t vt = 0;
        std::uint8_t  type_byte = 0;
        void*         next = nullptr;
        __try {
            vt        = *reinterpret_cast<std::uint64_t*>(cur);
            type_byte = *(static_cast<std::uint8_t*>(cur) + 0x12);
            next      = *reinterpret_cast<void**>(static_cast<char*>(cur) + 0x08);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_LOG("%s @ %p SEH header read — stop", etag, cur);
            break;
        }

        std::uintptr_t vt_rva = 0;
        if (g_module_base > 0 && vt >= g_module_base &&
            vt < g_module_base + 0x10000000ULL) {
            vt_rva = vt - g_module_base;
        }

        FW_LOG("%s @ %p vtable=0x%llX (RVA 0x%llX) type=0x%02X next=%p",
               etag, cur,
               static_cast<unsigned long long>(vt),
               static_cast<unsigned long long>(vt_rva),
               static_cast<unsigned>(type_byte), next);
        seh_hexdump(etag, "bytes", cur, 0x40);
        cur = next;
        ++idx;
    }
    if (cur && idx >= 16) {
        FW_LOG("%s extra-chain: stopped at %d entries (cap)", tag, idx);
    }
}

// Try to recover a c-string from a path-shaped pointer. Returns the
// preview into `buf`. SEH-safe.
void seh_read_cstring_preview(const void* addr, char* buf,
                               std::size_t bufsz) {
    if (!addr || !buf || bufsz < 2) {
        if (buf && bufsz > 0) buf[0] = 0;
        return;
    }
    __try {
        const char* s = static_cast<const char*>(addr);
        std::size_t i = 0;
        for (; i < bufsz - 1; ++i) {
            char c = s[i];
            if (c == 0) break;
            if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7F) {
                buf[0] = 0; return;
            }
            buf[i] = c;
        }
        buf[i] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (bufsz > 0) buf[0] = 0;
    }
}

std::uint64_t __fastcall detour_bsmodelproc(
    std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3,
    std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, std::uint64_t a7)
{
    g_fires_total.fetch_add(1, std::memory_order_relaxed);
    int n = g_fires_logged.load(std::memory_order_relaxed);

    // Try to derive a path string from the args BEFORE deciding to log.
    // Per ALPHA: signature is approximately
    //   sub_1402FC0E0(proc, opts, path, &node, ...)
    // i.e. one of the args is a c-string. We search a0..a4 for a
    // string starting with "Meshes\" or containing "Weapons\" or
    // "Armor\" — those are the files we care about.
    char path_preview[160] = {};
    bool has_path = false;
    bool is_weapon = false;
    bool is_armor  = false;
    const std::uint64_t args[5] = {a0, a1, a2, a3, a4};
    int path_arg_index = -1;
    for (int i = 0; i < 5; ++i) {
        if (args[i] < 0x10000) continue;
        char preview[160];
        seh_read_cstring_preview(reinterpret_cast<void*>(args[i]),
                                  preview, sizeof(preview));
        if (preview[0] && std::strlen(preview) >= 6) {
            // Is it a NIF/path-shaped string?
            const char* ext = std::strrchr(preview, '.');
            const bool has_dot = ext != nullptr;
            const bool has_slash = std::strchr(preview, '\\') != nullptr ||
                                    std::strchr(preview, '/') != nullptr;
            if (has_dot && has_slash) {
                std::strncpy(path_preview, preview, sizeof(path_preview) - 1);
                path_preview[sizeof(path_preview) - 1] = 0;
                has_path = true;
                path_arg_index = i;
                // Substring checks (case-insensitive).
                auto contains_ci = [](const char* hay, const char* needle) {
                    const std::size_t nl = std::strlen(needle);
                    for (const char* p = hay; *p; ++p) {
                        std::size_t k = 0;
                        for (; k < nl; ++k) {
                            char a = p[k]; char b = needle[k];
                            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                            if (a != b || a == 0) break;
                        }
                        if (k == nl) return true;
                        if (!p[k]) return false;
                    }
                    return false;
                };
                is_weapon = contains_ci(path_preview, "weapons\\");
                is_armor  = contains_ci(path_preview, "armor\\");
                break;
            }
        }
    }

    // Filter: log only weapon or armor parses. Everything else is
    // background (statics/clutter/etc).
    bool log_this = (is_weapon || is_armor) && (n < MAX_FIRES_LOGGED);
    if (log_this) {
        g_fires_logged.fetch_add(1, std::memory_order_relaxed);

        char tag[40];
        std::snprintf(tag, sizeof(tag), "[bsmodelproc][#%d]", n);
        FW_LOG("%s ENTRY %s path[a%d]='%s'",
               tag, is_weapon ? "WEAPON" : "ARMOR",
               path_arg_index, path_preview);
        FW_LOG("%s   regs a0=0x%llX a1=0x%llX a2=0x%llX a3=0x%llX",
               tag, (unsigned long long)a0, (unsigned long long)a1,
               (unsigned long long)a2, (unsigned long long)a3);
        FW_LOG("%s   stk  a4=0x%llX a5=0x%llX a6=0x%llX a7=0x%llX",
               tag, (unsigned long long)a4, (unsigned long long)a5,
               (unsigned long long)a6, (unsigned long long)a7);

        // Dump opts struct (a1) — flag at +0x08 should have bit 0x08
        // set (BSModelProcessor enable per ALPHA dossier).
        if (a1 >= 0x10000 && seh_is_readable((void*)a1, 0x20)) {
            seh_hexdump(tag, "opts(a1) first 0x20",
                         reinterpret_cast<void*>(a1), 0x20);
        }
    }

    std::uint64_t rc = 0;
    __try {
        rc = g_orig(a0, a1, a2, a3, a4, a5, a6, a7);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[bsmodelproc][#%d] SEH inside g_orig", n);
        rc = 0;
    }

    if (log_this) {
        char tag[40];
        std::snprintf(tag, sizeof(tag), "[bsmodelproc][#%d]", n);
        FW_LOG("%s EXIT  rc=0x%llX", tag, (unsigned long long)rc);

        // Per ALPHA dossier: the post-hook signature is approximately
        // `sub_1402FC0E0(this, opts, path, &node, ...)` where the 4th
        // arg `a3` is `void**` — the engine writes the loaded BSFadeNode*
        // into `*a3`. So POST-call we read *a3 to get the real node.
        //
        // The previous hook iteration wrongly walked extra-data on
        // `*a0` (which is the BSModelProcessor singleton, all garbage
        // when interpreted as NiObject). a3 is the right slot.
        for (int idx_check : {3, 4, 5, 6, 7}) {
            const std::uint64_t arg_val =
                (idx_check == 3) ? a3 :
                (idx_check == 4) ? a4 :
                (idx_check == 5) ? a5 :
                (idx_check == 6) ? a6 :
                                   a7;
            if (arg_val < 0x10000) continue;
            if (!seh_is_readable(reinterpret_cast<void*>(arg_val), 8))
                continue;

            std::uint64_t inner = 0;
            __try {
                inner = *reinterpret_cast<std::uint64_t*>(arg_val);
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (inner < 0x10000) continue;
            if (!seh_is_readable(reinterpret_cast<void*>(inner), 0x20))
                continue;

            // Try first qword as vtable RVA in module range.
            std::uint64_t first_qword = 0;
            __try {
                first_qword = *reinterpret_cast<std::uint64_t*>(inner);
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (first_qword < g_module_base ||
                first_qword > g_module_base + 0x10000000ULL) continue;

            // Looks like a NiObject. Walk extra-data chain at +0x18.
            const std::uintptr_t vt_rva = first_qword - g_module_base;
            char itag[60];
            std::snprintf(itag, sizeof(itag), "%s.POST.*a%d",
                           tag, idx_check);
            FW_LOG("%s a%d=%p → *a%d=%p (vtable RVA 0x%llX)",
                   tag, idx_check, (void*)arg_val, idx_check, (void*)inner,
                   (unsigned long long)vt_rva);
            dump_extra_data_chain(itag, reinterpret_cast<void*>(inner));

            // Also dump the FIRST 0x40 bytes of the NIF root for layout
            // discovery — useful for spotting non-standard fields.
            seh_hexdump(itag, "node first 0x40",
                         reinterpret_cast<void*>(inner), 0x40);
        }
    }
    return rc;
}

}  // anon namespace

bool install_bsmodelproc_hook(std::uintptr_t module_base) {
    if (g_orig) {
        FW_LOG("[bsmodelproc-hook] already installed — skip");
        return true;
    }
    g_module_base = module_base;
    void* target = reinterpret_cast<void*>(module_base + BSMODELPROC_RVA);
    void* trampoline = nullptr;
    const bool ok = fw::hooks::install(
        target, reinterpret_cast<void*>(&detour_bsmodelproc), &trampoline);
    if (!ok || !trampoline) {
        FW_ERR("[bsmodelproc-hook] install FAILED at 0x%llX",
               reinterpret_cast<unsigned long long>(target));
        return false;
    }
    g_orig = reinterpret_cast<BsModProcFn>(trampoline);
    FW_LOG("[bsmodelproc-hook] installed at 0x%llX (sub_1402FC0E0) — "
           "filtering for 'Weapons\\' / 'Armor\\' paths; first %d fires logged",
           reinterpret_cast<unsigned long long>(target), MAX_FIRES_LOGGED);
    return true;
}

}  // namespace fw::hooks
