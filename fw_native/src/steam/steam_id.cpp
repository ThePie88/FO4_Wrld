#include "steam_id.h"

#include <windows.h>
#include <atomic>

#include "../log.h"

namespace fw::steam {

namespace {

// Cached on first successful resolution. 0 = not yet resolved.
std::atomic<std::uint64_t> g_cached_steam_id{0};
// One-shot logger guard so we print the resolution exactly once.
std::atomic<bool> g_logged_once{false};

// Resolve ISteamUser* for either real Steam or Goldberg.
//
// Goldberg exports a convenience `SteamUser` accessor (returns the
// interface ptr directly). Real Steam's SDK keeps `SteamUser()` as an
// inline in the C++ header, so real `steam_api64.dll` does NOT export
// it. Real Steam exports the lower-level primitives:
//   - SteamAPI_GetHSteamUser()  → HSteamUser (int handle)
//   - SteamInternal_FindOrCreateUserInterface(hUser, "SteamUserNNN")
//     → ISteamUser*  (NNN is the interface version, e.g. "SteamUser023")
//
// We try Goldberg's path first (cheapest), fall back to real Steam's
// path with descending version probes.
void* resolve_isteamuser(HMODULE m) noexcept {
    using SteamUserFn      = void* (__cdecl*)();
    using GetHUserFn       = int    (__cdecl*)();
    using FindCreateUserFn = void* (__cdecl*)(int /*hUser*/, const char*);

    // Path A: Goldberg / Steam emulator direct accessor.
    if (auto* SteamUser = reinterpret_cast<SteamUserFn>(
            GetProcAddress(m, "SteamUser"))) {
        __try {
            void* p = SteamUser();
            if (p) return p;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // Path B: real Steam SDK versioned lookup.
    auto* GetHUser = reinterpret_cast<GetHUserFn>(
        GetProcAddress(m, "SteamAPI_GetHSteamUser"));
    auto* FindCreate = reinterpret_cast<FindCreateUserFn>(
        GetProcAddress(m, "SteamInternal_FindOrCreateUserInterface"));
    if (!GetHUser || !FindCreate) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true)) {
            FW_WRN("steam_id: missing all known ISteamUser accessors "
                   "(SteamUser=null, SteamAPI_GetHSteamUser=%p, "
                   "SteamInternal_FindOrCreateUserInterface=%p)",
                   reinterpret_cast<void*>(GetHUser),
                   reinterpret_cast<void*>(FindCreate));
        }
        return nullptr;
    }

    int hUser = 0;
    __try {
        hUser = GetHUser();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    if (hUser == 0) {
        // Steamworks::Init not run yet by the host.
        return nullptr;
    }

    // Probe newest → oldest. The exact version baked into FO4's SDK
    // depends on Bethesda's Steamworks integration vintage.
    static const char* const kVersions[] = {
        "SteamUser023", "SteamUser022", "SteamUser021",
        "SteamUser020", "SteamUser019", "SteamUser018",
        "SteamUser017", "SteamUser016",
    };
    for (const char* ver : kVersions) {
        void* p = nullptr;
        __try {
            p = FindCreate(hUser, ver);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
        if (p) {
            static std::atomic<bool> logged_ver{false};
            if (!logged_ver.exchange(true)) {
                FW_LOG("steam_id: ISteamUser resolved via real-Steam "
                       "path (FindOrCreate '%s' = %p, hUser=%d)",
                       ver, p, hUser);
            }
            return p;
        }
    }
    return nullptr;
}

// Try to read the Steam ID right now. Returns 0 on any failure.
std::uint64_t try_read_steam_id_now() noexcept {
    HMODULE m = GetModuleHandleW(L"steam_api64.dll");
    if (!m) {
        // Steam SDK not loaded yet.
        return 0;
    }

    using GetSteamIDFn = std::uint64_t (__cdecl*)(void*);
    auto* GetSteamID = reinterpret_cast<GetSteamIDFn>(
        GetProcAddress(m, "SteamAPI_ISteamUser_GetSteamID"));
    if (!GetSteamID) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true)) {
            FW_WRN("steam_id: SteamAPI_ISteamUser_GetSteamID export "
                   "missing from steam_api64.dll");
        }
        return 0;
    }

    void* user_iface = resolve_isteamuser(m);
    if (!user_iface) return 0;

    std::uint64_t sid = 0;
    __try {
        sid = GetSteamID(user_iface);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("steam_id: SEH in SteamAPI_ISteamUser_GetSteamID");
        return 0;
    }
    return sid;
}

}  // namespace

std::uint64_t get_local_steam_id() noexcept {
    // Fast path: already resolved.
    std::uint64_t cached =
        g_cached_steam_id.load(std::memory_order_acquire);
    if (cached) return cached;

    // Slow path: try to resolve.
    const std::uint64_t sid = try_read_steam_id_now();
    if (sid) {
        g_cached_steam_id.store(sid, std::memory_order_release);
        if (!g_logged_once.exchange(true)) {
            FW_LOG("steam_id: resolved local Steam ID = %llu (0x%llX)",
                   static_cast<unsigned long long>(sid),
                   static_cast<unsigned long long>(sid));
        }
    }
    return sid;
}

}  // namespace fw::steam
