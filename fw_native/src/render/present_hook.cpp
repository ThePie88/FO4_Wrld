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
#include "editor_overlay.h"
#include "../native/chargen_stage.h"
#include "../main_thread_dispatch.h"   // main_thread_id() — Present has 4 call
                                       // sites and one is a worker thread

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
// Off by default. The archived Strada A draws lazily initialise themselves, so
// without this gate simply installing the hook would put a triangle on screen.
std::atomic<bool> g_strada_a{false};
std::atomic<std::uintptr_t> g_base{0};
// Thread identity of the frames we see. See the detour for why this is tracked
// rather than assumed.
std::atomic<std::uint32_t> g_first_tid{0};
std::atomic<bool> g_offthread_warned{false};
std::atomic<bool> g_thread_reported{false};

// Renderer globals, from re/chargen_editor_data_AGENT.md's companion pass on
// the DXGI path (CHARGEN_PLAN §23). D is the renderer data block; a pointer to
// it is also parked at PTR_TO_D, which is what the game's own present wrapper
// dereferences, so it is the more faithful source of the two.
constexpr std::uintptr_t RENDERER_D_RVA = 0x03A0F410;
constexpr std::uintptr_t PTR_TO_D_RVA   = 0x038CAAA0;
constexpr std::size_t    D_DEVICE_OFF   = 0x48;
constexpr std::size_t    D_CONTEXT_OFF  = 0x50;
constexpr std::size_t    D_HWND_OFF     = 0x58;
constexpr std::size_t    D_SWAPCHAIN_OFF= 0x70;
constexpr std::size_t    D_BACKBUF_RTV  = 0x88;

// Every read of engine memory goes through a guarded helper — a rule this
// project adopted after three separate faults from unguarded reads.
void* seh_ptr(const void* at) noexcept {
    if (!at) return nullptr;
    __try {
        return *reinterpret_cast<void* const*>(at);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

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
        // The heartbeat carries the presenting thread, because a one-shot
        // report cannot answer the question that matters. During loading the
        // frames come from the JobListManager serving thread; only a periodic
        // sample shows the steady state once the game is in-world, and that is
        // what decides whether the overlay may touch the engine directly or has
        // to hand work to the main thread.
        const std::uint32_t mt = fw::dispatch::main_thread_id();
        const std::uint32_t me = GetCurrentThreadId();
        FW_LOG("[render] Present #%llu on tid=%lu (main=%lu) -> %s",
               n, static_cast<unsigned long>(me),
               static_cast<unsigned long>(mt),
               (mt == 0) ? "main thread not known yet"
                         : ((me == mt) ? "MAIN THREAD" : "off-thread"));
    }

    // WHICH THREAD ARE WE ON?
    //
    // Present is reached from four call sites in the game, and one of them —
    // the JobListManager serving thread that runs the animated loading screen —
    // is not the main thread. The overlay must not draw there, so this has to be
    // answered rather than assumed.
    //
    // It cannot be answered at frame #4: main_thread_id() is only known once the
    // WndProc subclass has seen a message, which happens long after the first
    // frames. So the report waits until the id is knowable, and separately warns
    // the first time a frame arrives on a different thread than the previous
    // ones — which is the actual event of interest.
    const std::uint32_t me = GetCurrentThreadId();
    {
        std::uint32_t expect = 0;
        if (!g_first_tid.compare_exchange_strong(expect, me,
                                                 std::memory_order_acq_rel)) {
            if (expect != me &&
                !g_offthread_warned.exchange(true, std::memory_order_acq_rel)) {
                FW_WRN("[render] Present arrived on tid=%lu, having previously "
                       "arrived on tid=%lu. One of Present's call sites is the "
                       "JobListManager serving thread (loading screens); the "
                       "overlay must not draw on it.",
                       static_cast<unsigned long>(me),
                       static_cast<unsigned long>(expect));
            }
        }
        const std::uint32_t mt = fw::dispatch::main_thread_id();
        if (mt != 0 &&
            !g_thread_reported.exchange(true, std::memory_order_acq_rel)) {
            FW_LOG("[render] frame #%llu on tid=%lu, main thread is %lu -> %s",
                   n, static_cast<unsigned long>(me),
                   static_cast<unsigned long>(mt),
                   (me == mt) ? "MAIN THREAD, the overlay may draw"
                              : "NOT the main thread");
        }
    }

    // ONE-SHOT SELF-CHECK. Resolve the game's own D3D objects from the fixed
    // globals and compare the swapchain we resolved against the `self` this
    // detour was handed. If those two pointers are equal, the hook and the
    // offsets have confirmed each other in a single line — and if the overlay
    // ever draws into the wrong surface, this is the line that says so.
    if (n == 4) {
        const GameD3D g = game_d3d();
        FW_LOG("[render] game D3D: device=%p context=%p swapchain=%p rtv=%p "
               "hwnd=%p", g.device, g.context, g.swap_chain, g.backbuf_rtv,
               g.hwnd);
        if (g.swap_chain == static_cast<void*>(self)) {
            FW_LOG("[render] swapchain from the globals MATCHES the one Present "
                   "was called on — hook and offsets confirm each other");
        } else {
            FW_ERR("[render] swapchain MISMATCH: globals say %p, Present was "
                   "called on %p. One of the two is wrong; do not draw until "
                   "this is resolved.", g.swap_chain, static_cast<void*>(self));
        }
    }

    // KEEPING THE STAGED PLAYER IN THE AIR, and why this call is HERE and not
    // in the WndProc with the rest of the per-tick work.
    //
    // While staged, collision has to be re-asserted continuously — something in
    // the engine turns it back on essentially every frame, and our write only
    // holds because it lands after the engine's. That re-assert used to live
    // solely in the WndProc subclass, which meant it ran only when a window
    // message arrived. So the moment the window lost focus, or the player simply
    // stopped moving the mouse, the message traffic stopped, the re-assert
    // stopped, gravity won, and the staged player began to sink: measured at
    // ~13.6 units/second, which took it from z=17830 down to z=10671 over about
    // nine minutes of an alt-tabbed session.
    //
    // Present is the right driver because it is what actually happens once per
    // frame whether or not anything is being typed or clicked, and — verified
    // over 27,000 frames — it is the main thread in-world. The work itself is
    // two field reads and, when it has flipped, one flag write plus five camera
    // floats: no allocation, no 3D rebuild, nothing that has any business being
    // unsafe mid-frame.
    //
    // The rest of the per-tick work deliberately stays in the WndProc.
    // face_borrow writes a whole recipe and calls Reset3D, and moving that
    // between the game's render prep and its present buys nothing and risks
    // something.
    {
        const std::uint32_t mt = fw::dispatch::main_thread_id();
        if (mt != 0 && me == mt) {
            __try {
                fw::native::chargen_stage::tick(
                    g_base.load(std::memory_order_relaxed));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }

    // THE EDITOR. Only on the main thread: one of Present's four call sites is
    // the JobListManager serving thread that runs the loading screen, and the
    // overlay must not draw there. A no-op when the editor is closed.
    {
        const std::uint32_t mt = fw::dispatch::main_thread_id();
        if (mt != 0 && me == mt) {
            __try {
                fw::render::editor::on_frame(
                    g_base.load(std::memory_order_relaxed));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // A bug in our panel must never take the game's frame with it.
                FW_ERR("[editor] SEH inside the overlay draw — the panel is "
                       "disabled for the rest of this session");
                fw::render::editor::shutdown();
            }
        }
    }

    // Archived Strada A renderer. OFF unless explicitly armed — draw_triangle
    // lazily initialises itself from the swapchain, so an ungated call here is
    // a triangle on screen.
    if (g_strada_a.load(std::memory_order_relaxed)) {
        // A bug in our renderer must never crash the game's Present.
        __try {
            fw::render::draw_triangle(self);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        __try {
            fw::render::draw_body(self);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        // One-shot camera layout probes; no-ops after the first scan.
        __try {
            fw::engine::probe_camera_layout_once();
            fw::engine::probe_main_culling_camera_once();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
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

void arm_strada_a(bool on) noexcept {
    g_strada_a.store(on, std::memory_order_relaxed);
}

GameD3D game_d3d() noexcept {
    GameD3D out;
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    if (!base) return out;

    // Prefer the pointer global: it is what the game's own present wrapper
    // dereferences, and there is a second store to it during renderer setup,
    // so it is the authority on where D actually is. Fall back to D's fixed
    // address if that pointer has not been written yet.
    void* d = seh_ptr(reinterpret_cast<const void*>(base + PTR_TO_D_RVA));
    if (!d) d = reinterpret_cast<void*>(base + RENDERER_D_RVA);

    auto* p = static_cast<std::uint8_t*>(d);
    out.device      = seh_ptr(p + D_DEVICE_OFF);
    out.context     = seh_ptr(p + D_CONTEXT_OFF);
    out.hwnd        = seh_ptr(p + D_HWND_OFF);
    out.swap_chain  = seh_ptr(p + D_SWAPCHAIN_OFF);
    out.backbuf_rtv = seh_ptr(p + D_BACKBUF_RTV);
    return out;
}

bool init_present_hook(std::uintptr_t module_base) {
    g_base.store(module_base, std::memory_order_relaxed);
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
