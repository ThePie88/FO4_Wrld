// Proxy forwarding for dxgi.dll factory entry points.
//
// Windows's DLL search order picks OUR dxgi.dll (in the game root) before
// C:\Windows\System32\dxgi.dll. So when FO4 resolves its single import of
// CreateDXGIFactory, it finds us. We lazy-load the real system dxgi and
// forward the call verbatim.
//
// CRITICAL: we MUST load the real dxgi by ABSOLUTE path (System32). A naked
// LoadLibraryW(L"dxgi.dll") would re-enter us.
//
// Fallout 4 NG only statically imports CreateDXGIFactory (ordinal 3). We
// still export CreateDXGIFactory1 and CreateDXGIFactory2 because other
// modules in the process (D3D11 runtime, NVIDIA driver shims, Steam
// overlay) may resolve them dynamically via GetProcAddress and we don't
// want to break them if they try.
//
// Exports are declared in dxgi.def — DO NOT add __declspec(dllexport) here.

#include <windows.h>
#include <mutex>
#include <string>

#include "log.h"

// IID / factory types live in dxgi.h. We include the minimum to avoid a
// cascade of DirectX headers in this TU.
struct IDXGIFactory;   // opaque forward decl — we just pass through
typedef struct _GUID IID;

namespace {

std::mutex g_load_mutex;
HMODULE g_real = nullptr;

HMODULE get_real_dxgi() {
    // Double-checked lock: first call loads, every subsequent call is lock-free.
    HMODULE cached = g_real;
    if (cached) return cached;
    std::lock_guard lk(g_load_mutex);
    if (g_real) return g_real;

    wchar_t sysdir[MAX_PATH];
    const UINT n = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        FW_LOG("FATAL: GetSystemDirectoryW failed, err=%lu",
               static_cast<unsigned long>(GetLastError()));
        return nullptr;
    }
    std::wstring path = sysdir;
    path += L"\\dxgi.dll";

    HMODULE h = LoadLibraryW(path.c_str());
    if (!h) {
        FW_LOG("FATAL: LoadLibraryW(%ls) failed, err=%lu",
               path.c_str(),
               static_cast<unsigned long>(GetLastError()));
        return nullptr;
    }
    FW_LOG("real dxgi.dll loaded from %ls (handle=%p)", path.c_str(), h);
    g_real = h;
    return h;
}

template <typename Fn>
Fn resolve(const char* name) {
    HMODULE h = get_real_dxgi();
    if (!h) return nullptr;
    auto addr = reinterpret_cast<Fn>(GetProcAddress(h, name));
    if (!addr) {
        FW_LOG("WARN: real dxgi missing export %s", name);
    }
    return addr;
}

} // namespace

// ---------------------------------------------------------------- exports

extern "C" {

HRESULT WINAPI CreateDXGIFactory(REFIID riid, void** ppFactory) {
    using Fn = HRESULT(WINAPI*)(REFIID, void**);
    static Fn fn = resolve<Fn>("CreateDXGIFactory");
    if (!fn) return E_FAIL;
    return fn(riid, ppFactory);
}

HRESULT WINAPI CreateDXGIFactory1(REFIID riid, void** ppFactory) {
    using Fn = HRESULT(WINAPI*)(REFIID, void**);
    static Fn fn = resolve<Fn>("CreateDXGIFactory1");
    if (!fn) return E_FAIL;
    return fn(riid, ppFactory);
}

HRESULT WINAPI CreateDXGIFactory2(UINT Flags, REFIID riid, void** ppFactory) {
    using Fn = HRESULT(WINAPI*)(UINT, REFIID, void**);
    static Fn fn = resolve<Fn>("CreateDXGIFactory2");
    if (!fn) return E_FAIL;
    return fn(Flags, riid, ppFactory);
}

} // extern "C"
