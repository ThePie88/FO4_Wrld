#include "dsv_capture.h"

#include <windows.h>
#include <d3d11.h>

#include <atomic>
#include <mutex>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::render {

namespace {

// ID3D11DeviceContext::OMSetRenderTargets — vtable slot 33.
// Slot layout (first 7 from IUnknown + ID3D11DeviceChild, then
// ID3D11DeviceContext methods in declaration order from d3d11.h):
//   7  VSSetConstantBuffers       20  DrawIndexedInstanced
//   8  PSSetShaderResources       21  DrawInstanced
//   9  PSSetShader                22  GSSetConstantBuffers
//  10  PSSetSamplers              23  GSSetShader
//  11  VSSetShader                24  IASetPrimitiveTopology
//  12  DrawIndexed                25  VSSetShaderResources
//  13  Draw                       26  VSSetSamplers
//  14  Map                        27  Begin
//  15  Unmap                      28  End
//  16  PSSetConstantBuffers       29  GetData
//  17  IASetInputLayout           30  SetPredication
//  18  IASetVertexBuffers         31  GSSetShaderResources
//  19  IASetIndexBuffer           32  GSSetSamplers
//                                 33  OMSetRenderTargets   <-- target
constexpr std::size_t kVtableSlotOMSetRenderTargets = 33;

using OMSetRenderTargets_fn = void (STDMETHODCALLTYPE*)(
    ID3D11DeviceContext*            self,
    UINT                            num_views,
    ID3D11RenderTargetView* const*  rtvs,
    ID3D11DepthStencilView*         dsv);

OMSetRenderTargets_fn g_orig_om_set = nullptr;

std::mutex                       g_dsv_mutex;
ID3D11DepthStencilView*          g_scene_dsv = nullptr;
std::atomic<bool>                g_installed{false};
std::atomic<std::uint64_t>       g_capture_count{0};
std::atomic<std::uint64_t>       g_reject_count{0};
std::atomic<UINT>                g_expected_w{0};
std::atomic<UINT>                g_expected_h{0};
std::atomic<bool>                g_first_accept_logged{false};

// Return dimensions + DXGI format + sample count of the DSV's
// underlying texture. Returns false on any COM error.
bool probe_dsv(ID3D11DepthStencilView* dsv,
               UINT& out_w, UINT& out_h, DXGI_FORMAT& out_fmt,
               UINT& out_samples)
{
    if (!dsv) return false;
    ID3D11Resource* res = nullptr;
    dsv->GetResource(&res);
    if (!res) return false;

    ID3D11Texture2D* tex = nullptr;
    const HRESULT hr = res->QueryInterface(
        __uuidof(ID3D11Texture2D),
        reinterpret_cast<void**>(&tex));
    res->Release();
    if (FAILED(hr) || !tex) return false;

    D3D11_TEXTURE2D_DESC td{};
    tex->GetDesc(&td);
    tex->Release();

    out_w       = td.Width;
    out_h       = td.Height;
    out_fmt     = td.Format;
    out_samples = td.SampleDesc.Count;
    return true;
}

// [Diagnostic code removed — would have been part of Strada A's depth
// fix path that we're deferring indefinitely. See
// docs/PIVOT_StradaA_to_StradaB.md for the "ReShade-style DSV tracking"
// plan if this needs to come back.]

// Update the cached scene DSV under lock. Filters: must match the
// expected backbuffer dimensions (set by the body renderer). Smaller
// DSVs (shadow maps) and differently-sized DSVs (half-res post
// effects) are skipped — they don't hold scene depth.
void set_scene_dsv(ID3D11DepthStencilView* dsv) {
    if (!dsv) return;

    const UINT expected_w = g_expected_w.load(std::memory_order_relaxed);
    const UINT expected_h = g_expected_h.load(std::memory_order_relaxed);
    if (expected_w == 0 || expected_h == 0) {
        // Body renderer hasn't published expected size yet — accept
        // nothing. Without this gate we'd cache the first DSV we see
        // (likely a shadow map early in the frame).
        return;
    }

    UINT w = 0, h = 0, samples = 0;
    DXGI_FORMAT fmt = DXGI_FORMAT_UNKNOWN;
    if (!probe_dsv(dsv, w, h, fmt, samples)) return;
    (void)samples;

    if (w != expected_w || h != expected_h) {
        g_reject_count.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    std::lock_guard lk(g_dsv_mutex);
    if (dsv == g_scene_dsv) return;

    dsv->AddRef();
    if (g_scene_dsv) g_scene_dsv->Release();
    g_scene_dsv = dsv;

    const auto n = g_capture_count.fetch_add(1, std::memory_order_relaxed);

    // Log the first accepted DSV with full metadata so we know what
    // format of depth buffer we're testing against.
    bool expected = false;
    if (g_first_accept_logged.compare_exchange_strong(expected, true)) {
        FW_LOG("[dsv] first scene DSV accepted: %p size=%ux%u format=0x%X "
               "(0x2D=D32_FLOAT, 0x2E=D32F_S8, 0x2D=D32F_S8X24, "
               "0x45=D24_UNORM_S8_UINT, 0x37=D16_UNORM)",
               static_cast<void*>(dsv), w, h, static_cast<unsigned>(fmt));
    }
    if ((n % 600) == 0) {
        FW_DBG("[dsv] scene capture #%llu dsv=%p (rejected since last log: %llu)",
               static_cast<unsigned long long>(n + 1),
               static_cast<void*>(dsv),
               static_cast<unsigned long long>(
                   g_reject_count.exchange(0, std::memory_order_relaxed)));
    }
}

// Detour: called on the game's render thread every time they bind
// render targets. Hot path — keep it minimal. Pass-through to the
// original, never throw.
void STDMETHODCALLTYPE detour_om_set_render_targets(
    ID3D11DeviceContext*            self,
    UINT                            num_views,
    ID3D11RenderTargetView* const*  rtvs,
    ID3D11DepthStencilView*         dsv)
{
    set_scene_dsv(dsv);
    if (g_orig_om_set) {
        g_orig_om_set(self, num_views, rtvs, dsv);
    }
}

} // namespace

bool install_dsv_capture(ID3D11DeviceContext* ctx) {
    if (g_installed.load(std::memory_order_acquire)) {
        return true;
    }
    if (!ctx) {
        FW_ERR("[dsv] install: null context");
        return false;
    }

    // Read the vtable pointer (first 8 bytes of every COM object on
    // x64) and extract slot 33.
    void** vtable = *reinterpret_cast<void***>(ctx);
    void* target  = vtable[kVtableSlotOMSetRenderTargets];
    FW_LOG("[dsv] vtable=%p  slot[%zu]=%p (OMSetRenderTargets target)",
           static_cast<void*>(vtable),
           kVtableSlotOMSetRenderTargets,
           target);

    if (!fw::hooks::install(
            target,
            reinterpret_cast<void*>(&detour_om_set_render_targets),
            reinterpret_cast<void**>(&g_orig_om_set))) {
        FW_ERR("[dsv] MinHook install failed target=%p", target);
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    FW_LOG("[dsv] OMSetRenderTargets hook installed at %p", target);
    return true;
}

ID3D11DepthStencilView* acquire_scene_dsv() {
    std::lock_guard lk(g_dsv_mutex);
    if (g_scene_dsv) g_scene_dsv->AddRef();
    return g_scene_dsv;
}

void release_cached_dsv() {
    std::lock_guard lk(g_dsv_mutex);
    if (g_scene_dsv) {
        g_scene_dsv->Release();
        g_scene_dsv = nullptr;
    }
}

void set_expected_dsv_size(unsigned int width, unsigned int height) {
    g_expected_w.store(width, std::memory_order_relaxed);
    g_expected_h.store(height, std::memory_order_relaxed);
}

} // namespace fw::render
