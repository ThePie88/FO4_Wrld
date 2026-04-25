#include "present_hook.h"
#include "triangle_render.h"
#include "body_render.h"

#include "../engine/engine_calls.h"

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>

#include <atomic>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::render {

namespace {

// IDXGISwapChain::Present signature. __stdcall is the COM convention on
// Windows x64 (both __stdcall and the native x64 calling conv collapse
// to the same thing, but we keep __stdcall for intent clarity).
using PresentFn = HRESULT (STDMETHODCALLTYPE*)(
    IDXGISwapChain* self, UINT sync_interval, UINT flags);

PresentFn g_orig_present = nullptr;
std::atomic<unsigned long long> g_frame_count{0};
std::atomic<bool> g_hooked{false};

// Detour: log every Nth frame to avoid flooding, then passthrough.
HRESULT STDMETHODCALLTYPE detour_present(
    IDXGISwapChain* self, UINT sync_interval, UINT flags)
{
    const auto n = g_frame_count.fetch_add(1, std::memory_order_relaxed);

    // Log first 10 frames at INFO (high-signal for startup), then every
    // 600 frames (=10s at 60fps, 4s at 144fps) at DEBUG. The engine's
    // render thread fires this hundreds of times per second — noise at
    // full rate is useless.
    if (n < 10) {
        FW_LOG("[render] Present #%llu swapchain=%p sync=%u flags=0x%X",
               n, static_cast<void*>(self), sync_interval, flags);
    } else if ((n % 600) == 0) {
        FW_DBG("[render] Present #%llu tick (heartbeat)", n);
    }

    // B5 Step 2: draw our overlay BEFORE the game's Present call. The
    // swapchain's back buffer is the current frame; we draw on top of
    // whatever the game composited (world + UI). If the draw fails it
    // logs and returns silently — we never break the game's frame.
    __try {
        fw::render::draw_triangle(self);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A bug in our renderer must never crash the game's Present.
        // Log once via the renderer's own init-fail path next frame.
    }

    // Path A (custom D3D11 renderer) — REACTIVATED. Next fix: Agent 1's
    // PlayerCamera singleton read → correct view+proj → fixes wobble
    // AND depth range mismatch.
    __try {
        fw::render::draw_body(self);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    // B5 diagnostic: one-shot camera layout probes. Both are no-ops
    // after first successful scan. Run both to gather data on
    // PlayerCamera AND MainCullingCamera layouts.
    __try {
        fw::engine::probe_camera_layout_once();
        fw::engine::probe_main_culling_camera_once();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    if (!g_orig_present) {
        // Shouldn't happen — detour is only installed if original was
        // captured successfully. Defensive: pass-through via direct call
        // on the interface (this risks infinite recursion if the vtable
        // still points at us, but we'd have already crashed elsewhere).
        return S_OK;
    }
    return g_orig_present(self, sync_interval, flags);
}

// Create a minimal D3D11 device + dummy swapchain on a hidden window,
// extract the Present vtable pointer, release the temporary resources.
// Returns the captured Present fn pointer (nullptr on failure).
void* capture_present_vtable_ptr() {
    // Register a tiny ghost window. We use the built-in STATIC class to
    // avoid registering our own (one less failure mode). The window is
    // never shown; we just need an HWND for swapchain OutputWindow.
    HWND hwnd = CreateWindowExW(
        0, L"STATIC", L"fw_render_probe",
        WS_OVERLAPPEDWINDOW,
        0, 0, 100, 100,
        nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!hwnd) {
        FW_ERR("[render] capture: CreateWindowExW failed (err=%lu)",
               GetLastError());
        return nullptr;
    }

    DXGI_SWAP_CHAIN_DESC desc{};
    desc.BufferCount = 1;
    desc.BufferDesc.Width  = 100;
    desc.BufferDesc.Height = 100;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.SampleDesc.Count = 1;
    desc.OutputWindow = hwnd;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0 };
    D3D_FEATURE_LEVEL got_level = D3D_FEATURE_LEVEL_11_0;

    IDXGISwapChain*      swap_chain = nullptr;
    ID3D11Device*        device     = nullptr;
    ID3D11DeviceContext* context    = nullptr;

    const HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr,                    // pAdapter (default)
        D3D_DRIVER_TYPE_HARDWARE,   // driver type
        nullptr,                    // software module
        0,                          // flags (no DEBUG; we share process w/ game)
        levels, 1,                  // feature levels
        D3D11_SDK_VERSION,
        &desc, &swap_chain,
        &device, &got_level, &context);

    if (FAILED(hr) || !swap_chain) {
        FW_ERR("[render] capture: D3D11CreateDeviceAndSwapChain failed (hr=0x%08lX)",
               static_cast<unsigned long>(hr));
        if (hwnd) DestroyWindow(hwnd);
        return nullptr;
    }

    // Read vtable slot 8 (IDXGISwapChain::Present).
    // vtable layout (from dxgi.h, IUnknown + IDXGIObject + IDXGIDeviceSubObject + IDXGISwapChain):
    //   [0]  IUnknown::QueryInterface
    //   [1]  IUnknown::AddRef
    //   [2]  IUnknown::Release
    //   [3]  IDXGIObject::SetPrivateData
    //   [4]  IDXGIObject::SetPrivateDataInterface
    //   [5]  IDXGIObject::GetPrivateData
    //   [6]  IDXGIObject::GetParent
    //   [7]  IDXGIDeviceSubObject::GetDevice
    //   [8]  IDXGISwapChain::Present       <-- target
    void** vtable = *reinterpret_cast<void***>(swap_chain);
    void* present_ptr = vtable[8];
    FW_LOG("[render] capture: vtable=%p  Present@[8]=%p",
           static_cast<void*>(vtable), present_ptr);

    // Release temporary resources. Order per D3D11 convention: swapchain
    // first (depends on device), then context, then device.
    if (swap_chain) swap_chain->Release();
    if (context)    context->Release();
    if (device)     device->Release();
    if (hwnd)       DestroyWindow(hwnd);

    return present_ptr;
}

} // namespace

bool init_present_hook() {
    if (g_hooked.load(std::memory_order_acquire)) {
        FW_DBG("[render] init_present_hook: already hooked");
        return true;
    }

    void* present_ptr = capture_present_vtable_ptr();
    if (!present_ptr) {
        FW_ERR("[render] init_present_hook: vtable capture failed");
        return false;
    }

    const bool ok = fw::hooks::install(
        present_ptr,
        reinterpret_cast<void*>(&detour_present),
        reinterpret_cast<void**>(&g_orig_present));
    if (!ok) {
        FW_ERR("[render] init_present_hook: MinHook install failed target=%p",
               present_ptr);
        return false;
    }

    g_hooked.store(true, std::memory_order_release);
    FW_LOG("[render] Present hook installed at %p", present_ptr);
    return true;
}

unsigned long long frame_count() {
    return g_frame_count.load(std::memory_order_relaxed);
}

} // namespace fw::render
