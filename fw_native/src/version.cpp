#include "version.h"

#include <windows.h>
#include <string>
#include <vector>

#pragma comment(lib, "version.lib")

namespace fw::version {

namespace {

// Returns the absolute path of Fallout4.exe (or empty on failure).
std::wstring fallout_path() {
    HMODULE h = GetModuleHandleW(L"Fallout4.exe");
    if (!h) return {};
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(h, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return {};
    return std::wstring(buf, n);
}

} // namespace

Result check(std::string* actual_out) {
    if (actual_out) actual_out->clear();

    const auto path = fallout_path();
    if (path.empty()) return Result::Unresolvable;

    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return Result::Unresolvable;

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) {
        return Result::Unresolvable;
    }

    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\",
                        reinterpret_cast<LPVOID*>(&fixed), &len)) {
        return Result::Unresolvable;
    }
    if (!fixed || len == 0) return Result::Unresolvable;

    const DWORD major = HIWORD(fixed->dwFileVersionMS);
    const DWORD minor = LOWORD(fixed->dwFileVersionMS);
    const DWORD patch = HIWORD(fixed->dwFileVersionLS);
    const DWORD build = LOWORD(fixed->dwFileVersionLS);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%lu.%lu.%lu.%lu", major, minor, patch, build);
    const std::string actual = buf;
    if (actual_out) *actual_out = actual;

    return (actual == EXPECTED) ? Result::Match : Result::Mismatch;
}

} // namespace fw::version
