#include "game_build.h"

#include <windows.h>

namespace fw::build {

namespace {

struct Fingerprint {
    Id            id;
    DWORD         time_date_stamp;
    DWORD         size_of_image;
    const char*   name;
};

constexpr Fingerprint kBuilds[] = {
    {Id::V1_11_191, 0x693A1A4C, 0x04243000, "1.11.191.0"},
    {Id::V1_11_240, 0x6A727FCC, 0x0425A000, "1.11.240.0"},
};

Id detect() {
    // The DLL is a dxgi proxy loaded into Fallout4.exe, so the main module
    // is the game. Fall back to the named module for safety.
    HMODULE h = GetModuleHandleW(L"Fallout4.exe");
    if (!h) h = GetModuleHandleW(nullptr);
    if (!h) return Id::Unknown;
    const auto* base = reinterpret_cast<const std::uint8_t*>(h);
    const auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return Id::Unknown;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return Id::Unknown;
    for (const auto& b : kBuilds) {
        if (nt->FileHeader.TimeDateStamp == b.time_date_stamp &&
            nt->OptionalHeader.SizeOfImage == b.size_of_image) {
            return b.id;
        }
    }
    return Id::Unknown;
}

} // namespace

Id current() {
    static const Id id = detect();
    return id;
}

const char* name(Id id) {
    for (const auto& b : kBuilds) {
        if (b.id == id) return b.name;
    }
    return "unknown";
}

} // namespace fw::build
