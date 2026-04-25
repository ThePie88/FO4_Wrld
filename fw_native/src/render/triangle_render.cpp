#include "triangle_render.h"

#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>

#include "../log.h"
#include "../offsets.h"

namespace fw::render {

namespace {

// ---------------------------------------------------------------- HLSL

// Vertex shader: transforms world-space position via view+proj matrices
// from the constant buffer. Passes color to the pixel stage.
//
// Matrix convention: HLSL defaults to column-major; we pass matrices
// already column-major from CPU so mul(M, v) works as expected.
constexpr const char* kVsSrc = R"HLSL(
cbuffer Matrices : register(b0)
{
    float4x4 model;   // triangle local → world (anchors to player)
    float4x4 view;    // world → view-space (camera)
    float4x4 proj;    // view → clip
};

struct VSIn {
    float3 pos   : POSITION;
    float3 color : COLOR;
};

struct VSOut {
    float4 pos   : SV_POSITION;
    float3 color : COLOR;
};

VSOut main(VSIn i)
{
    VSOut o;
    float4 local = float4(i.pos, 1.0);
    float4 world = mul(model, local);
    float4 view_space = mul(view, world);
    o.pos = mul(proj, view_space);
    o.color = i.color;
    return o;
}
)HLSL";

// Pixel shader: passthrough color with full alpha.
constexpr const char* kPsSrc = R"HLSL(
struct PSIn {
    float4 pos   : SV_POSITION;
    float3 color : COLOR;
};

float4 main(PSIn i) : SV_Target
{
    return float4(i.color, 1.0);
}
)HLSL";

// ---------------------------------------------------------------- data types

struct Vertex {
    float pos[3];
    float color[3];
};

struct MatricesCB {
    float model[16];  // column-major 4x4 — triangle local-space → world
    float view[16];   // column-major 4x4 — world → view-space
    float proj[16];   // column-major 4x4 — view → clip
};

// ---------------------------------------------------------------- state

struct Renderer {
    // D3D objects (all AddRef'd from swapchain, released at shutdown)
    ID3D11Device*           device    = nullptr;
    ID3D11DeviceContext*    context   = nullptr;

    // Our pipeline objects
    ID3D11VertexShader*     vs        = nullptr;
    ID3D11PixelShader*      ps        = nullptr;
    ID3D11InputLayout*      layout    = nullptr;
    ID3D11Buffer*           vb        = nullptr;   // vertex buffer
    ID3D11Buffer*           cb        = nullptr;   // constant buffer (matrices)

    // State objects: disable depth, disable culling, solid fill, opaque blend
    ID3D11DepthStencilState* dss      = nullptr;
    ID3D11RasterizerState*   rs       = nullptr;
    ID3D11BlendState*        bs       = nullptr;

    bool   initialized      = false;   // resources valid
    bool   permanent_fail   = false;   // something unrecoverable happened; log-once
    std::uint64_t frames_rendered = 0;
};

Renderer g_r;
std::atomic<std::uint64_t> g_init_log_once{0};

// ---------------------------------------------------------------- helpers

template <typename T>
void safe_release(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

// Identity 4x4 into column-major array.
void mat_identity(float* m) {
    std::memset(m, 0, 16 * sizeof(float));
    m[0] = m[5] = m[10] = m[15] = 1.0f;
}

// Translation matrix (column-major).
void mat_translation(float* m, float tx, float ty, float tz) {
    mat_identity(m);
    m[12] = tx;
    m[13] = ty;
    m[14] = tz;
}

// Build a right-handed perspective projection matrix (D3D11 clip space:
// x,y in [-1, 1], z in [0, 1]). Column-major layout. Matches standard
// HLSL mul(proj, view_space_pos) expectation.
void mat_perspective_rh(float* m, float fov_y_rad, float aspect,
                        float near_z, float far_z)
{
    const float f = 1.0f / std::tan(fov_y_rad * 0.5f);
    std::memset(m, 0, 16 * sizeof(float));
    m[0]  = f / aspect;
    m[5]  = f;
    m[10] = far_z / (near_z - far_z);
    m[11] = -1.0f;
    m[14] = (near_z * far_z) / (near_z - far_z);
}

// Build a right-handed view matrix looking from `eye` towards `at`, with
// `up` as reference up. Column-major output.
void mat_look_at_rh(float* m,
                    const float eye[3], const float at[3], const float up[3])
{
    // z = normalize(eye - at)
    float zx = eye[0] - at[0];
    float zy = eye[1] - at[1];
    float zz = eye[2] - at[2];
    float zl = std::sqrt(zx*zx + zy*zy + zz*zz);
    if (zl < 1e-6f) zl = 1.0f;
    zx /= zl; zy /= zl; zz /= zl;

    // x = normalize(cross(up, z))
    float xx = up[1]*zz - up[2]*zy;
    float xy = up[2]*zx - up[0]*zz;
    float xz = up[0]*zy - up[1]*zx;
    float xl = std::sqrt(xx*xx + xy*xy + xz*xz);
    if (xl < 1e-6f) xl = 1.0f;
    xx /= xl; xy /= xl; xz /= xl;

    // y = cross(z, x) (already orthonormal)
    float yx = zy*xz - zz*xy;
    float yy = zz*xx - zx*xz;
    float yz = zx*xy - zy*xx;

    std::memset(m, 0, 16 * sizeof(float));
    m[0] = xx;  m[4] = xy;  m[8]  = xz;   m[12] = -(xx*eye[0] + xy*eye[1] + xz*eye[2]);
    m[1] = yx;  m[5] = yy;  m[9]  = yz;   m[13] = -(yx*eye[0] + yy*eye[1] + yz*eye[2]);
    m[2] = zx;  m[6] = zy;  m[10] = zz;   m[14] = -(zx*eye[0] + zy*eye[1] + zz*eye[2]);
    m[15] = 1.0f;
}

// Read player (pos, euler-rot) from the engine singleton. Returns false
// on SEH / null. Rotation is (pitch_x, roll_y, yaw_z) in radians per our
// offsets.h notes.
bool read_player_pose(float pos_out[3], float rot_out[3]) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    // qword_1432D2260 stores the PlayerCharacter* singleton.
    auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_SINGLETON_RVA);

    void* pc = nullptr;
    __try {
        pc = *pc_slot;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if (!pc) return false;

    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pc);
        pos_out[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        pos_out[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        pos_out[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
        rot_out[0] = *reinterpret_cast<const float*>(b + offsets::ROT_OFF + 0);
        rot_out[1] = *reinterpret_cast<const float*>(b + offsets::ROT_OFF + 4);
        rot_out[2] = *reinterpret_cast<const float*>(b + offsets::ROT_OFF + 8);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Compile HLSL shader source. Returns a Blob* on success; logs and
// returns nullptr on failure with the full compiler error.
ID3DBlob* compile_shader(const char* src, const char* entry, const char* target) {
    ID3DBlob* blob = nullptr;
    ID3DBlob* err  = nullptr;
    const HRESULT hr = D3DCompile(
        src, std::strlen(src),
        "fw_triangle",          // file name for debug
        nullptr, nullptr,
        entry, target,
        D3DCOMPILE_OPTIMIZATION_LEVEL3, 0,
        &blob, &err);
    if (FAILED(hr)) {
        if (err) {
            FW_ERR("[render] shader compile FAILED entry=%s target=%s hr=0x%08lX msg=%s",
                   entry, target, static_cast<unsigned long>(hr),
                   static_cast<const char*>(err->GetBufferPointer()));
            err->Release();
        } else {
            FW_ERR("[render] shader compile FAILED entry=%s target=%s hr=0x%08lX (no blob)",
                   entry, target, static_cast<unsigned long>(hr));
        }
        if (blob) blob->Release();
        return nullptr;
    }
    if (err) err->Release();
    return blob;
}

// One-shot initialization from swapchain. Acquires device+context,
// compiles shaders, uploads VB/CB, creates state objects.
bool init_from_swapchain(IDXGISwapChain* swap) {
    if (g_r.initialized) return true;
    if (g_r.permanent_fail) return false;

    if (!swap) {
        FW_ERR("[render] init_from_swapchain: null swap");
        g_r.permanent_fail = true;
        return false;
    }

    // -- acquire device + immediate context --
    HRESULT hr = swap->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void**>(&g_r.device));
    if (FAILED(hr) || !g_r.device) {
        FW_ERR("[render] init: GetDevice failed hr=0x%08lX", static_cast<unsigned long>(hr));
        g_r.permanent_fail = true;
        return false;
    }
    g_r.device->GetImmediateContext(&g_r.context);
    if (!g_r.context) {
        FW_ERR("[render] init: GetImmediateContext returned null");
        g_r.permanent_fail = true;
        return false;
    }

    // -- compile shaders --
    ID3DBlob* vs_blob = compile_shader(kVsSrc, "main", "vs_5_0");
    ID3DBlob* ps_blob = compile_shader(kPsSrc, "main", "ps_5_0");
    if (!vs_blob || !ps_blob) {
        safe_release(vs_blob); safe_release(ps_blob);
        g_r.permanent_fail = true;
        return false;
    }

    hr = g_r.device->CreateVertexShader(
        vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(), nullptr, &g_r.vs);
    if (FAILED(hr)) {
        FW_ERR("[render] CreateVertexShader failed hr=0x%08lX", static_cast<unsigned long>(hr));
        safe_release(vs_blob); safe_release(ps_blob);
        g_r.permanent_fail = true;
        return false;
    }
    hr = g_r.device->CreatePixelShader(
        ps_blob->GetBufferPointer(), ps_blob->GetBufferSize(), nullptr, &g_r.ps);
    if (FAILED(hr)) {
        FW_ERR("[render] CreatePixelShader failed hr=0x%08lX", static_cast<unsigned long>(hr));
        safe_release(vs_blob); safe_release(ps_blob);
        g_r.permanent_fail = true;
        return false;
    }

    // -- input layout --
    const D3D11_INPUT_ELEMENT_DESC elems[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COLOR",    0, DXGI_FORMAT_R32G32B32_FLOAT, 0, sizeof(float) * 3,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    hr = g_r.device->CreateInputLayout(
        elems, 2,
        vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(),
        &g_r.layout);
    safe_release(vs_blob);
    safe_release(ps_blob);
    if (FAILED(hr)) {
        FW_ERR("[render] CreateInputLayout failed hr=0x%08lX", static_cast<unsigned long>(hr));
        g_r.permanent_fail = true;
        return false;
    }

    // -- vertex buffer: triangle in LOCAL space, centered on origin --
    // Each vertex is ~100 units from origin. The MODEL matrix (updated
    // per-frame in update_constant_buffer) translates this triangle to
    // player_pos + forward*500 + up*60 so it's always visible ahead.
    //
    // Triangle orientation: flat in XY plane, facing the camera along
    // +Z (but we disabled backface cull so orientation doesn't matter).
    // Colors: red/green/blue corners for visual verification of
    // vertex shading.
    const Vertex tri[3] = {
        { {   0.0f, 100.0f, 0.0f }, { 1.0f, 0.0f, 0.0f } },   // red top
        { { 100.0f,-100.0f, 0.0f }, { 0.0f, 1.0f, 0.0f } },   // green bottom-right
        { {-100.0f,-100.0f, 0.0f }, { 0.0f, 0.0f, 1.0f } },   // blue bottom-left
    };
    D3D11_BUFFER_DESC vb_desc{};
    vb_desc.Usage          = D3D11_USAGE_IMMUTABLE;
    vb_desc.ByteWidth      = sizeof(tri);
    vb_desc.BindFlags      = D3D11_BIND_VERTEX_BUFFER;
    D3D11_SUBRESOURCE_DATA vb_data{ tri, 0, 0 };
    hr = g_r.device->CreateBuffer(&vb_desc, &vb_data, &g_r.vb);
    if (FAILED(hr)) {
        FW_ERR("[render] CreateBuffer(VB) failed hr=0x%08lX", static_cast<unsigned long>(hr));
        g_r.permanent_fail = true;
        return false;
    }

    // -- constant buffer: updated every frame --
    D3D11_BUFFER_DESC cb_desc{};
    cb_desc.Usage          = D3D11_USAGE_DYNAMIC;
    cb_desc.ByteWidth      = sizeof(MatricesCB);
    cb_desc.BindFlags      = D3D11_BIND_CONSTANT_BUFFER;
    cb_desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    hr = g_r.device->CreateBuffer(&cb_desc, nullptr, &g_r.cb);
    if (FAILED(hr)) {
        FW_ERR("[render] CreateBuffer(CB) failed hr=0x%08lX", static_cast<unsigned long>(hr));
        g_r.permanent_fail = true;
        return false;
    }

    // -- state objects: no depth, no cull, solid, opaque --
    D3D11_DEPTH_STENCIL_DESC dss_desc{};
    dss_desc.DepthEnable    = FALSE;
    dss_desc.StencilEnable  = FALSE;
    hr = g_r.device->CreateDepthStencilState(&dss_desc, &g_r.dss);
    if (FAILED(hr)) { FW_ERR("[render] CreateDSS failed"); g_r.permanent_fail = true; return false; }

    D3D11_RASTERIZER_DESC rs_desc{};
    rs_desc.FillMode        = D3D11_FILL_SOLID;
    rs_desc.CullMode        = D3D11_CULL_NONE;   // see both sides
    rs_desc.DepthClipEnable = FALSE;             // no far-plane clip surprises
    hr = g_r.device->CreateRasterizerState(&rs_desc, &g_r.rs);
    if (FAILED(hr)) { FW_ERR("[render] CreateRS failed"); g_r.permanent_fail = true; return false; }

    D3D11_BLEND_DESC bs_desc{};
    bs_desc.RenderTarget[0].BlendEnable           = FALSE;
    bs_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    hr = g_r.device->CreateBlendState(&bs_desc, &g_r.bs);
    if (FAILED(hr)) { FW_ERR("[render] CreateBS failed"); g_r.permanent_fail = true; return false; }

    g_r.initialized = true;
    FW_LOG("[render] triangle renderer initialized (device=%p context=%p)",
           static_cast<void*>(g_r.device), static_cast<void*>(g_r.context));
    return true;
}

// Update the constant buffer with current view + proj matrices.
//
// Coordinate convention (FO4):
//   X = East, Y = North, Z = Up
//   Rotation: rot[0] = pitch (X axis), rot[1] = roll (Y axis), rot[2] = yaw (Z axis), radians
//
// Player "forward" on ground plane:
//   fwd.x = sin(yaw) * cos(pitch)
//   fwd.y = cos(yaw) * cos(pitch)
//   fwd.z = -sin(pitch)   (looking down = positive pitch in FO4 convention)
//
// We put the camera AT the player + eye offset, looking forward.
bool update_constant_buffer() {
    float ppos[3]{}, prot[3]{};
    if (!read_player_pose(ppos, prot)) {
        return false;
    }

    // Eye slightly above player root (FO4 eye ~120 units up)
    constexpr float EYE_HEIGHT = 120.0f;
    const float eye[3] = { ppos[0], ppos[1], ppos[2] + EYE_HEIGHT };

    // Forward vector from yaw (rot.z) + pitch (rot.x)
    const float yaw   = prot[2];
    const float pitch = prot[0];
    const float cp = std::cos(pitch);
    const float fwd[3] = {
        std::sin(yaw)   * cp,
        std::cos(yaw)   * cp,
       -std::sin(pitch),
    };

    // Look-at point 1000 units ahead of the eye along forward.
    const float at[3] = {
        eye[0] + fwd[0] * 1000.0f,
        eye[1] + fwd[1] * 1000.0f,
        eye[2] + fwd[2] * 1000.0f,
    };

    const float up[3] = { 0.0f, 0.0f, 1.0f };

    MatricesCB cb{};

    // B5 Step 2b: model matrix places the triangle 500 units ahead of
    // the player along their forward vector, +60 units above the eye
    // line for visibility (so it's not clipped by the ground). The
    // triangle's LOCAL-space vertices are centered around origin in
    // the VB; the model matrix translates them into WORLD space.
    const float anchor[3] = {
        eye[0] + fwd[0] * 500.0f,
        eye[1] + fwd[1] * 500.0f,
        eye[2] + fwd[2] * 500.0f + 60.0f,
    };
    mat_translation(cb.model, anchor[0], anchor[1], anchor[2]);

    mat_look_at_rh(cb.view, eye, at, up);

    // FOV 60 degrees, aspect 16:9 (approximation; we don't read the
    // swapchain resolution to compute true aspect yet — MVP).
    const float fov = 60.0f * 3.14159265f / 180.0f;
    mat_perspective_rh(cb.proj, fov, 16.0f / 9.0f, 1.0f, 100000.0f);

    D3D11_MAPPED_SUBRESOURCE mapped{};
    const HRESULT hr = g_r.context->Map(g_r.cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(hr)) {
        FW_DBG("[render] CB Map failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }
    std::memcpy(mapped.pData, &cb, sizeof(cb));
    g_r.context->Unmap(g_r.cb, 0);
    return true;
}

} // namespace

// ---------------------------------------------------------------- API

void release_triangle_resources() {
    safe_release(g_r.bs);
    safe_release(g_r.rs);
    safe_release(g_r.dss);
    safe_release(g_r.cb);
    safe_release(g_r.vb);
    safe_release(g_r.layout);
    safe_release(g_r.ps);
    safe_release(g_r.vs);
    safe_release(g_r.context);
    safe_release(g_r.device);
    g_r.initialized = false;
    FW_DBG("[render] triangle resources released");
}

void draw_triangle(IDXGISwapChain* swap) {
    if (g_r.permanent_fail) return;
    if (!g_r.initialized) {
        if (!init_from_swapchain(swap)) {
            // Log once to avoid spam; init_from_swapchain has already logged
            // the specific failure.
            if (g_init_log_once.exchange(1) == 0) {
                FW_WRN("[render] triangle init failed — overlay disabled");
            }
            return;
        }
    }

    if (!update_constant_buffer()) {
        // Can't read player or CB map failed this frame; skip.
        return;
    }

    // -- acquire back buffer + RTV for this frame --
    // Back buffer changes (swap cycle), RTV must be recreated.
    ID3D11Texture2D* back_buffer = nullptr;
    HRESULT hr = swap->GetBuffer(0, __uuidof(ID3D11Texture2D),
                                  reinterpret_cast<void**>(&back_buffer));
    if (FAILED(hr) || !back_buffer) {
        FW_DBG("[render] GetBuffer(0) failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return;
    }
    ID3D11RenderTargetView* rtv = nullptr;
    hr = g_r.device->CreateRenderTargetView(back_buffer, nullptr, &rtv);
    if (FAILED(hr) || !rtv) {
        FW_DBG("[render] CreateRTV failed hr=0x%08lX", static_cast<unsigned long>(hr));
        safe_release(back_buffer);
        return;
    }

    // -- query back buffer dimensions for viewport --
    D3D11_TEXTURE2D_DESC bb_desc{};
    back_buffer->GetDesc(&bb_desc);
    const UINT width  = bb_desc.Width;
    const UINT height = bb_desc.Height;

    // -- save the game's current render state (we'll restore at end) --
    // Bare minimum: targets, viewport, primitive topology, shaders, layout,
    // buffers, blend/depth/rasterizer. We save just enough that the game
    // doesn't glitch on the next frame.
    ID3D11RenderTargetView*   saved_rtvs[8]{};
    ID3D11DepthStencilView*   saved_dsv = nullptr;
    g_r.context->OMGetRenderTargets(8, saved_rtvs, &saved_dsv);

    UINT saved_vp_count = 1;
    D3D11_VIEWPORT saved_vps[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
    g_r.context->RSGetViewports(&saved_vp_count, saved_vps);

    D3D11_PRIMITIVE_TOPOLOGY saved_topo;
    g_r.context->IAGetPrimitiveTopology(&saved_topo);

    ID3D11InputLayout*   saved_layout = nullptr;
    g_r.context->IAGetInputLayout(&saved_layout);

    ID3D11VertexShader*  saved_vs = nullptr;
    g_r.context->VSGetShader(&saved_vs, nullptr, nullptr);
    ID3D11PixelShader*   saved_ps = nullptr;
    g_r.context->PSGetShader(&saved_ps, nullptr, nullptr);

    ID3D11Buffer*        saved_vb = nullptr;
    UINT saved_stride = 0, saved_offset = 0;
    g_r.context->IAGetVertexBuffers(0, 1, &saved_vb, &saved_stride, &saved_offset);

    ID3D11Buffer*        saved_cb = nullptr;
    g_r.context->VSGetConstantBuffers(0, 1, &saved_cb);

    ID3D11BlendState*         saved_bs = nullptr;
    float                     saved_bf[4];
    UINT                      saved_sm;
    g_r.context->OMGetBlendState(&saved_bs, saved_bf, &saved_sm);

    ID3D11DepthStencilState*  saved_dss = nullptr;
    UINT                      saved_sr;
    g_r.context->OMGetDepthStencilState(&saved_dss, &saved_sr);

    ID3D11RasterizerState*    saved_rs = nullptr;
    g_r.context->RSGetState(&saved_rs);

    // -- draw our triangle --
    D3D11_VIEWPORT vp{};
    vp.Width    = static_cast<float>(width);
    vp.Height   = static_cast<float>(height);
    vp.MaxDepth = 1.0f;
    g_r.context->RSSetViewports(1, &vp);
    g_r.context->RSSetState(g_r.rs);

    const float blend_factor[4] = { 0, 0, 0, 0 };
    g_r.context->OMSetBlendState(g_r.bs, blend_factor, 0xFFFFFFFFu);
    g_r.context->OMSetDepthStencilState(g_r.dss, 0);
    g_r.context->OMSetRenderTargets(1, &rtv, nullptr);

    g_r.context->IASetInputLayout(g_r.layout);
    g_r.context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    const UINT stride = sizeof(Vertex);
    const UINT offset = 0;
    g_r.context->IASetVertexBuffers(0, 1, &g_r.vb, &stride, &offset);

    g_r.context->VSSetShader(g_r.vs, nullptr, 0);
    g_r.context->VSSetConstantBuffers(0, 1, &g_r.cb);
    g_r.context->PSSetShader(g_r.ps, nullptr, 0);

    g_r.context->Draw(3, 0);

    // -- restore the game's state --
    g_r.context->OMSetRenderTargets(8, saved_rtvs, saved_dsv);
    for (auto*& t : saved_rtvs) safe_release(t);
    safe_release(saved_dsv);
    g_r.context->RSSetViewports(saved_vp_count, saved_vps);
    g_r.context->IASetPrimitiveTopology(saved_topo);
    g_r.context->IASetInputLayout(saved_layout);
    safe_release(saved_layout);
    g_r.context->VSSetShader(saved_vs, nullptr, 0);
    safe_release(saved_vs);
    g_r.context->PSSetShader(saved_ps, nullptr, 0);
    safe_release(saved_ps);
    g_r.context->IASetVertexBuffers(0, 1, &saved_vb, &saved_stride, &saved_offset);
    safe_release(saved_vb);
    g_r.context->VSSetConstantBuffers(0, 1, &saved_cb);
    safe_release(saved_cb);
    g_r.context->OMSetBlendState(saved_bs, saved_bf, saved_sm);
    safe_release(saved_bs);
    g_r.context->OMSetDepthStencilState(saved_dss, saved_sr);
    safe_release(saved_dss);
    g_r.context->RSSetState(saved_rs);
    safe_release(saved_rs);

    // -- release per-frame resources --
    safe_release(rtv);
    safe_release(back_buffer);

    ++g_r.frames_rendered;
    if (g_r.frames_rendered == 1 || (g_r.frames_rendered % 600) == 0) {
        FW_DBG("[render] triangle frame #%llu drawn %ux%u",
               static_cast<unsigned long long>(g_r.frames_rendered),
               width, height);
    }
}

} // namespace fw::render
