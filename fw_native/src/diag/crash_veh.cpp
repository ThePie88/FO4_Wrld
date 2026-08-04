#include "crash_veh.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../audit.h"
#include "../log.h"

namespace fw::diag {

namespace {

std::atomic<std::uint64_t> g_av_count{0};
std::atomic<bool>          g_user_shutdown{false};   // Build 69r — ALT+F4 seen
std::uintptr_t g_game_base = 0;
std::uintptr_t g_game_end  = 0;
std::uintptr_t g_self_base = 0;
std::uintptr_t g_self_end  = 0;

// ---------------------------------------------------------------------------
// Build 69p (2026-08-04) — REFR-O-SCOPE.
//
// The 69o write ring proved no fw store touches the crash victims; the open
// question became WHO the victim is. The crash family is always
// TESObjectCELL::DetachReference(cell from refr+0xB8) on a cell with a
// garbage/NULL vtable — but the registers at the fault were never decoded, so
// the refr's identity (a mirrored raider? the dog? our synthetic ghost dup?)
// stayed anonymous. These probes SEH-read every crash register (and the top
// stack qwords) AS IF it were a TESForm/TESObjectREFR and print vtable RVA +
// form ID + flags + parentCell, so the next crash names its victim.
//
// TESForm layout used (FO4 1.11.191): +0x00 vtable, +0x10 form flags (u32),
// +0x14 formID (u32, = offsets::FORMID_OFF), +0x1A formType (u8),
// +0xB8 parentCell (TESObjectREFR only, = offsets::PARENT_CELL_OFF).

struct HeadProbe {
    std::uint64_t vt    = 0;
    std::uint32_t flags = 0;
    std::uint32_t fid   = 0;
    std::uint8_t  ftype = 0;
};

// Read the TESForm head fields. Returns 0 on any fault (partial data dropped).
int probe_form_head(std::uint64_t p, HeadProbe* out) noexcept {
    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(p);
        out->vt    = *reinterpret_cast<const std::uint64_t*>(b);
        out->flags = *reinterpret_cast<const std::uint32_t*>(b + 0x10);
        out->fid   = *reinterpret_cast<const std::uint32_t*>(b + 0x14);
        out->ftype = *(b + 0x1A);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

int probe_qword(std::uint64_t p, std::uint64_t* out) noexcept {
    __try {
        *out = *reinterpret_cast<const std::uint64_t*>(p);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

bool plausible_heap_ptr(std::uint64_t v) noexcept {
    return v >= 0x10000 && v < 0x0000800000000000ULL && (v & 7) == 0;
}

// Format a vtable pointer: game RVA if inside the image (this alone names the
// object's dynamic type via re/engine_rtti_catalog.md), raw value otherwise.
void fmt_vt(std::uint64_t vt, char* out, std::size_t n) noexcept {
    if (g_game_base && vt >= g_game_base && vt < g_game_end) {
        std::snprintf(out, n, "game+0x%llX",
                      static_cast<unsigned long long>(vt - g_game_base));
    } else {
        std::snprintf(out, n, "0x%llX", static_cast<unsigned long long>(vt));
    }
}

// Probe one value and, if it reads like an object, print a one-line dossier.
void refr_scope_one(const char* name, std::uint64_t v) noexcept {
    if (!plausible_heap_ptr(v)) return;
    HeadProbe h{};
    if (!probe_form_head(v, &h)) return;

    char vtb[48];
    fmt_vt(h.vt, vtb, sizeof(vtb));

    // parentCell leg — only meaningful for refr-like objects, but reading it
    // unconditionally costs nothing and a garbage value is itself a datum.
    std::uint64_t cell = 0;
    char cellinfo[96];
    if (probe_qword(v + 0xB8, &cell) && plausible_heap_ptr(cell)) {
        HeadProbe ch{};
        if (probe_form_head(cell, &ch)) {
            char cvtb[48];
            fmt_vt(ch.vt, cvtb, sizeof(cvtb));
            std::snprintf(cellinfo, sizeof(cellinfo),
                          "cell=0x%llX{vt=%s fid=0x%08X}",
                          static_cast<unsigned long long>(cell), cvtb, ch.fid);
        } else {
            std::snprintf(cellinfo, sizeof(cellinfo),
                          "cell=0x%llX{UNREADABLE}",
                          static_cast<unsigned long long>(cell));
        }
    } else {
        std::snprintf(cellinfo, sizeof(cellinfo), "cell=0x%llX",
                      static_cast<unsigned long long>(cell));
    }

    FW_ERR("[refr-scope] %s=0x%llX: vt=%s flags=0x%08X fid=0x%08X "
           "type=0x%02X %s",
           name, static_cast<unsigned long long>(v), vtb, h.flags, h.fid,
           h.ftype, cellinfo);
}

LONG WINAPI veh_handler(EXCEPTION_POINTERS* info) noexcept {
    if (!info || !info->ExceptionRecord || !info->ContextRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    // Only access violations — skip C++/SEH expected exceptions
    // (0xE06D7363 C++, 0x80000003 BP, etc).
    if (code != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto rip = static_cast<std::uintptr_t>(info->ContextRecord->Rip);

    // Skip faults inside our own DLL — those are the SEH-caged
    // safe_read_X helpers doing intentional unsafe-deref tests. Their
    // __try/__except handlers will catch them; we'd just spam the log.
    if (g_self_base != 0 && rip >= g_self_base && rip < g_self_end) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto n = g_av_count.fetch_add(1, std::memory_order_relaxed);
    if (n >= 30) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto rsp = static_cast<std::uintptr_t>(info->ContextRecord->Rsp);
    const auto rbp = static_cast<std::uintptr_t>(info->ContextRecord->Rbp);
    const auto rcx = static_cast<std::uintptr_t>(info->ContextRecord->Rcx);
    const auto rdx = static_cast<std::uintptr_t>(info->ContextRecord->Rdx);
    const auto r8  = static_cast<std::uintptr_t>(info->ContextRecord->R8);

    const auto fault_kind = info->ExceptionRecord->ExceptionInformation[0];
    const auto fault_addr = info->ExceptionRecord->ExceptionInformation[1];

    const bool rip_in_game =
        g_game_base != 0 && rip >= g_game_base && rip < g_game_end;
    const std::uintptr_t rva =
        rip_in_game ? (rip - g_game_base) : 0;

    FW_ERR("[crash-veh] AV #%llu%s rip=0x%llX RVA=0x%llX in_game=%d "
           "fault=%s addr=0x%llX rsp=0x%llX rbp=0x%llX "
           "rcx=0x%llX rdx=0x%llX r8=0x%llX",
           static_cast<unsigned long long>(n),
           // Build 69r — teardown stamp: this AV happened AFTER the user
           // closed the window (ALT+F4); it is shutdown fallout, not a
           // gameplay crash.
           g_user_shutdown.load(std::memory_order_relaxed)
               ? " (teardown=1 ALT+F4)" : "",
           static_cast<unsigned long long>(rip),
           static_cast<unsigned long long>(rva),
           rip_in_game ? 1 : 0,
           fault_kind == 0 ? "READ" : (fault_kind == 1 ? "WRITE" :
                                       (fault_kind == 8 ? "EXEC" : "?")),
           static_cast<unsigned long long>(fault_addr),
           static_cast<unsigned long long>(rsp),
           static_cast<unsigned long long>(rbp),
           static_cast<unsigned long long>(rcx),
           static_cast<unsigned long long>(rdx),
           static_cast<unsigned long long>(r8));

    // Try to grab 8 qwords above RSP — usually contains return addresses
    // that let us reconstruct the call stack via decomp lookup.
    __try {
        const std::uint64_t* sp =
            reinterpret_cast<const std::uint64_t*>(rsp);
        FW_ERR("[crash-veh]   stack: %016llX %016llX %016llX %016llX "
               "%016llX %016llX %016llX %016llX",
               sp[0], sp[1], sp[2], sp[3], sp[4], sp[5], sp[6], sp[7]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[crash-veh]   stack: <unreadable>");
    }

    // Build 69p (2026-08-04) — full register set (the first line only prints
    // rsp/rbp/rcx/rdx/r8; DetachReference keeps the REFR in rsi) + the
    // refr-o-scope over every register and the top stack qwords: the next
    // crash prints its victim's form ID and vtable RVA instead of an
    // anonymous pointer. Capped at the first 3 AVs to bound log noise.
    if (n < 3) {
        const CONTEXT* c = info->ContextRecord;
        FW_ERR("[crash-veh]   regs2: rax=0x%llX rbx=0x%llX rsi=0x%llX "
               "rdi=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX r12=0x%llX "
               "r13=0x%llX r14=0x%llX r15=0x%llX",
               static_cast<unsigned long long>(c->Rax),
               static_cast<unsigned long long>(c->Rbx),
               static_cast<unsigned long long>(c->Rsi),
               static_cast<unsigned long long>(c->Rdi),
               static_cast<unsigned long long>(c->R9),
               static_cast<unsigned long long>(c->R10),
               static_cast<unsigned long long>(c->R11),
               static_cast<unsigned long long>(c->R12),
               static_cast<unsigned long long>(c->R13),
               static_cast<unsigned long long>(c->R14),
               static_cast<unsigned long long>(c->R15));
        refr_scope_one("rax", c->Rax);  refr_scope_one("rbx", c->Rbx);
        refr_scope_one("rcx", c->Rcx);  refr_scope_one("rdx", c->Rdx);
        refr_scope_one("rsi", c->Rsi);  refr_scope_one("rdi", c->Rdi);
        refr_scope_one("rbp", c->Rbp);  refr_scope_one("r8",  c->R8);
        refr_scope_one("r9",  c->R9);   refr_scope_one("r10", c->R10);
        refr_scope_one("r11", c->R11);  refr_scope_one("r12", c->R12);
        refr_scope_one("r13", c->R13);  refr_scope_one("r14", c->R14);
        refr_scope_one("r15", c->R15);
        // Stack qwords often hold the object the faulting frame was working
        // on (this crash family spills the refr before the vcall).
        for (int i = 0; i < 8; ++i) {
            std::uint64_t sv = 0;
            if (!probe_qword(rsp + 8ull * i, &sv)) break;
            char nm[8];
            std::snprintf(nm, sizeof(nm), "st%d", i);
            refr_scope_one(nm, sv);
        }
    }

    // Build 69o (2026-08-04) — dump the write ring on the FIRST AV only.
    // Answers "did any fw store land near the registers this crash was
    // holding?" directly in the log, and drops the full ring to
    // fw_writes.bin for offline queries. Internally idempotent, so later
    // AVs in the 30-cap window cost nothing.
    if (n == 0) {
        fw::audit::wring_dump_crash(info->ContextRecord, fault_addr);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// B6.6w5 Build 23 — backup unhandled-exception filter. The VEH only
// catches exceptions that go through the OS exception dispatcher
// (AVs, divide-by-zero, etc). Heap corruption / fast-fail (e.g.,
// `RtlReportFatalFailure`, `__fastfail`, double-free detection by
// RtlpHeap*) calls `TerminateProcess` DIRECTLY — VEH never fires.
//
// Build 22 log showed VEH missed the SUBSTITUTE crash (28 unrelated
// AVs from `fire_actor_weapon` were caught, but the actual game
// crash @ 19:01:55.004 left no VEH entry → not a regular AV).
//
// `SetUnhandledExceptionFilter` runs as a last-resort for the regular
// exception path. It WON'T catch `__fastfail` either — Windows 10+
// fast-fail bypasses everything by design — but it's still useful for
// the cases where SEH __try/__except didn't catch something.
//
// For true `__fastfail` we'd need WerRegisterRuntimeExceptionModule or
// a debugger attached. Not implementing that here.
LONG WINAPI unhandled_filter(EXCEPTION_POINTERS* info) noexcept {
    if (!info || !info->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    const auto rip = info->ContextRecord
        ? static_cast<std::uintptr_t>(info->ContextRecord->Rip)
        : 0u;
    const std::uintptr_t rva =
        g_game_base != 0 && rip >= g_game_base && rip < g_game_end
            ? (rip - g_game_base)
            : 0;
    FW_ERR("[crash-veh] UNHANDLED code=0x%08X rip=0x%llX RVA=0x%llX",
           code,
           static_cast<unsigned long long>(rip),
           static_cast<unsigned long long>(rva));
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

void note_user_shutdown() noexcept {
    g_user_shutdown.store(true, std::memory_order_relaxed);
}

void install_crash_veh(std::uintptr_t module_base) {
    g_game_base = module_base;
    // Fallout4.exe is ~70MB; use 256MB upper bound. False positives only
    // if an allocation lands within that span, which is fine for our
    // "is RIP in game code?" filter purpose.
    g_game_end  = module_base + 0x10000000;

    // Resolve our own DLL base/size via a pointer inside this TU so we
    // can skip RIPs from our own SEH-caged helpers.
    HMODULE self = nullptr;
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&install_crash_veh),
            &self) && self) {
        g_self_base = reinterpret_cast<std::uintptr_t>(self);
        g_self_end  = g_self_base + 0x00400000;  // 4MB upper bound; our DLL is <2MB
    }

    AddVectoredExceptionHandler(/*first=*/1, veh_handler);

    // Backup: runs only if no SEH __try/__except caught the exception
    // AND the VEH chain didn't return EXCEPTION_CONTINUE_EXECUTION.
    // For AVs in engine code that nobody handles, this fires JUST
    // before the OS terminates the process.
    SetUnhandledExceptionFilter(unhandled_filter);

    FW_LOG("[crash-veh] installed (VEH priority=first + Unhandled filter) "
           "game=[0x%llX..0x%llX] self=[0x%llX..0x%llX]",
           static_cast<unsigned long long>(g_game_base),
           static_cast<unsigned long long>(g_game_end),
           static_cast<unsigned long long>(g_self_base),
           static_cast<unsigned long long>(g_self_end));
}

} // namespace fw::diag
