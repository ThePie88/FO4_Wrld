#include "crash_veh.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../log.h"

namespace fw::diag {

namespace {

std::atomic<std::uint64_t> g_av_count{0};
std::uintptr_t g_game_base = 0;
std::uintptr_t g_game_end  = 0;
std::uintptr_t g_self_base = 0;
std::uintptr_t g_self_end  = 0;

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

    FW_ERR("[crash-veh] AV #%llu rip=0x%llX RVA=0x%llX in_game=%d "
           "fault=%s addr=0x%llX rsp=0x%llX rbp=0x%llX "
           "rcx=0x%llX rdx=0x%llX r8=0x%llX",
           static_cast<unsigned long long>(n),
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
