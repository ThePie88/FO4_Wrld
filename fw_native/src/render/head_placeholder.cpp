#include "head_placeholder.h"

#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../log.h"

namespace fw::render {

namespace {

// ----------------------------------------------------------------
// Sphere mesh generator. Standard lat/lon tessellation:
//   - stacks (horizontal rings), from top pole to bottom pole.
//   - slices (vertical wedges), around the equator.
// For a neck-sized head: radius ~8 units in FO4 game units
// (≈ 11cm). Real human head radius is ~9cm, so this is a rough
// match. Tuneable via HEAD_RADIUS.
// ----------------------------------------------------------------
constexpr float HEAD_RADIUS     = 8.0f;
constexpr std::uint32_t STACKS  = 12;   // min 2 (poles + equator)
constexpr std::uint32_t SLICES  = 18;   // min 3

// Head position computation.
//
// body_render passes anchor[2] = remote.pos.z + PELVIS_BIAS (= ground
// + 100 units). The mesh occupies z ∈ [anchor.z + mesh_z_min,
// anchor.z + mesh_z_max] = [anchor.z - 120, anchor.z - 5.7]. So the
// "top of body / neck" in world Z is anchor.z - 5.7.
//
// For the sphere head to sit just above the neck:
//   sphere_center_z ≈ (anchor.z - 5.7) + HEAD_RADIUS
//                   ≈ anchor.z + (HEAD_RADIUS - 5.7)
//                   ≈ anchor.z + 2.3  (with HEAD_RADIUS=8)
//
// Add a tiny gap so sphere doesn't intersect body. Total offset from
// anchor: ~5 units. Tuneable after live test.
constexpr float NECK_Z_WORLD_OFFSET = 5.0f;  // above body_pos.z+PELVIS_BIAS

struct SphereVertex {
    float pos[3];
    float normal[3];  // == normalized pos on unit sphere
};
static_assert(sizeof(SphereVertex) == 24, "SphereVertex unexpected size");

struct HeadCB {
    float model[16];     // 64 B — world placement (yaw + translate)
    float game_vp[16];   // 64 B — scene VP, passed from body_render
    float eye_world[3];  // 12 B — pre-subtract origin (0 if self-built)
    float pad0;          //  4 B
};
static_assert(sizeof(HeadCB) == 144, "HeadCB must be 144 B");

// ----------------------------------------------------------------
// HLSL — minimum shader for the head placeholder.
//
// Not skinned. Just model * VP * pos. Flat-ish shading via a fixed
// light direction dotted with the vertex normal.
// ----------------------------------------------------------------
constexpr const char* kHeadVsSrc = R"HLSL(
cbuffer HeadCB : register(b0)
{
    float4x4 model;
    float4x4 game_vp;
    float3   eye_world;
    float    _pad;
};

struct VSIn {
    float3 pos  : POSITION;
    float3 norm : NORMAL;
};

struct VSOut {
    float4 pos_clip : SV_POSITION;
    float3 norm_ws  : NORMAL;
};

VSOut main(VSIn v)
{
    float4 pos_world = mul(model, float4(v.pos, 1.0));
    float4 pos_rel   = float4(pos_world.xyz - eye_world, 1.0);
    float4 pos_clip  = mul(game_vp, pos_rel);

    VSOut o;
    o.pos_clip = pos_clip;
    o.norm_ws  = mul((float3x3)model, v.norm);
    return o;
}
)HLSL";

constexpr const char* kHeadPsSrc = R"HLSL(
struct PSIn {
    float4 pos_clip : SV_POSITION;
    float3 norm_ws  : NORMAL;
};

float4 main(PSIn i) : SV_Target
{
    float3 N = normalize(i.norm_ws);
    float3 L = normalize(float3(0.5, -0.3, 1.0));
    float lambert = saturate(dot(N, L));
    float ambient = 0.3;
    float shade = ambient + (1.0 - ambient) * lambert;
    float3 skin = float3(0.88, 0.72, 0.60);  // peach
    return float4(skin * shade, 1.0);
}
)HLSL";

struct HeadState {
    ID3D11Buffer*            vb       = nullptr;
    ID3D11Buffer*            ib       = nullptr;
    ID3D11Buffer*            cb       = nullptr;
    ID3D11InputLayout*       layout   = nullptr;
    ID3D11VertexShader*      vs       = nullptr;
    ID3D11PixelShader*       ps       = nullptr;
    ID3D11DepthStencilState* dss      = nullptr;
    ID3D11RasterizerState*   rs       = nullptr;
    ID3D11BlendState*        bs       = nullptr;
    std::uint32_t            index_count = 0;
    std::atomic<bool>        ready{false};
};

HeadState g_head;

template <typename T>
void safe_release(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

// ----------------------------------------------------------------
// Generate a UV-sphere: (STACKS-1) rings of SLICES vertices each,
// plus 2 poles. Triangles are built fan-style for the poles and
// strip-style for the middle.
// ----------------------------------------------------------------
void build_sphere_mesh(std::vector<SphereVertex>& verts,
                       std::vector<std::uint16_t>& idx)
{
    constexpr float PI_F = 3.14159265358979323846f;
    verts.clear();
    idx.clear();

    // Vertices: top pole, (STACKS-1) rings × SLICES vertices, bottom pole.
    verts.reserve(2 + (STACKS - 1) * SLICES);

    // Top pole (theta = 0)
    SphereVertex top{};
    top.pos[0] = 0; top.pos[1] = 0; top.pos[2] = HEAD_RADIUS;
    top.normal[0] = 0; top.normal[1] = 0; top.normal[2] = 1;
    verts.push_back(top);

    // Rings
    for (std::uint32_t s = 1; s < STACKS; ++s) {
        const float theta = PI_F * static_cast<float>(s) / static_cast<float>(STACKS);
        const float sin_t = std::sin(theta);
        const float cos_t = std::cos(theta);
        for (std::uint32_t k = 0; k < SLICES; ++k) {
            const float phi = 2.0f * PI_F * static_cast<float>(k) / static_cast<float>(SLICES);
            const float cos_p = std::cos(phi);
            const float sin_p = std::sin(phi);
            SphereVertex v{};
            v.pos[0] = HEAD_RADIUS * sin_t * cos_p;
            v.pos[1] = HEAD_RADIUS * sin_t * sin_p;
            v.pos[2] = HEAD_RADIUS * cos_t;
            v.normal[0] = sin_t * cos_p;
            v.normal[1] = sin_t * sin_p;
            v.normal[2] = cos_t;
            verts.push_back(v);
        }
    }

    // Bottom pole
    SphereVertex bot{};
    bot.pos[0] = 0; bot.pos[1] = 0; bot.pos[2] = -HEAD_RADIUS;
    bot.normal[0] = 0; bot.normal[1] = 0; bot.normal[2] = -1;
    verts.push_back(bot);

    const std::uint16_t top_idx    = 0;
    const std::uint16_t bot_idx    = static_cast<std::uint16_t>(verts.size() - 1);
    const std::uint16_t first_ring = 1;  // first ring starts at index 1

    // Top cap: triangles (top, ring0[k], ring0[k+1])
    for (std::uint32_t k = 0; k < SLICES; ++k) {
        const std::uint16_t a = static_cast<std::uint16_t>(first_ring + k);
        const std::uint16_t b = static_cast<std::uint16_t>(first_ring + ((k + 1) % SLICES));
        idx.push_back(top_idx);
        idx.push_back(a);
        idx.push_back(b);
    }
    // Middle rings: quad strips (split into 2 tris)
    for (std::uint32_t s = 0; s < STACKS - 2; ++s) {
        const std::uint16_t ring0 = static_cast<std::uint16_t>(first_ring + s * SLICES);
        const std::uint16_t ring1 = static_cast<std::uint16_t>(ring0 + SLICES);
        for (std::uint32_t k = 0; k < SLICES; ++k) {
            const std::uint16_t a = static_cast<std::uint16_t>(ring0 + k);
            const std::uint16_t b = static_cast<std::uint16_t>(ring0 + ((k + 1) % SLICES));
            const std::uint16_t c = static_cast<std::uint16_t>(ring1 + k);
            const std::uint16_t d = static_cast<std::uint16_t>(ring1 + ((k + 1) % SLICES));
            idx.push_back(a); idx.push_back(c); idx.push_back(b);
            idx.push_back(b); idx.push_back(c); idx.push_back(d);
        }
    }
    // Bottom cap: triangles (last_ring[k+1], last_ring[k], bottom)
    const std::uint16_t last_ring = static_cast<std::uint16_t>(
        first_ring + (STACKS - 2) * SLICES);
    for (std::uint32_t k = 0; k < SLICES; ++k) {
        const std::uint16_t a = static_cast<std::uint16_t>(last_ring + k);
        const std::uint16_t b = static_cast<std::uint16_t>(last_ring + ((k + 1) % SLICES));
        idx.push_back(b);
        idx.push_back(a);
        idx.push_back(bot_idx);
    }
}

ID3DBlob* compile_shader(const char* src, const char* entry, const char* target)
{
    ID3DBlob* blob = nullptr;
    ID3DBlob* err  = nullptr;
    const HRESULT hr = D3DCompile(
        src, std::strlen(src),
        "fw_head",
        nullptr, nullptr,
        entry, target,
        D3DCOMPILE_OPTIMIZATION_LEVEL3, 0,
        &blob, &err);
    if (FAILED(hr)) {
        if (err) {
            FW_ERR("[head] shader compile FAILED entry=%s target=%s hr=0x%08lX msg=%s",
                   entry, target, static_cast<unsigned long>(hr),
                   static_cast<const char*>(err->GetBufferPointer()));
            err->Release();
        }
        safe_release(blob);
        return nullptr;
    }
    if (err) err->Release();
    return blob;
}

// Build a col-major model matrix: Z-rotation by yaw + translation.
void mat_head_model(float* m, float tx, float ty, float tz, float yaw)
{
    const float c = std::cos(yaw);
    const float s = std::sin(yaw);
    m[ 0] =  c;    m[ 1] =  s;    m[ 2] = 0.0f;  m[ 3] = 0.0f;  // col 0
    m[ 4] = -s;    m[ 5] =  c;    m[ 6] = 0.0f;  m[ 7] = 0.0f;  // col 1
    m[ 8] = 0.0f;  m[ 9] = 0.0f;  m[10] = 1.0f;  m[11] = 0.0f;  // col 2
    m[12] = tx;    m[13] = ty;    m[14] = tz;    m[15] = 1.0f;  // col 3
}

} // namespace

bool init_head_placeholder(ID3D11Device* dev, ID3D11DeviceContext* ctx) {
    if (g_head.ready.load(std::memory_order_acquire)) return true;
    if (!dev || !ctx) return false;

    // --- Build mesh on CPU ---
    std::vector<SphereVertex>  verts;
    std::vector<std::uint16_t> idx;
    build_sphere_mesh(verts, idx);
    g_head.index_count = static_cast<std::uint32_t>(idx.size());
    FW_LOG("[head] sphere generated: %zu verts, %u indices (%u tris)",
           verts.size(), g_head.index_count, g_head.index_count / 3);

    // --- VB ---
    D3D11_BUFFER_DESC vb_desc{};
    vb_desc.Usage     = D3D11_USAGE_IMMUTABLE;
    vb_desc.ByteWidth = static_cast<UINT>(verts.size() * sizeof(SphereVertex));
    vb_desc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    D3D11_SUBRESOURCE_DATA vb_init{};
    vb_init.pSysMem = verts.data();
    HRESULT hr = dev->CreateBuffer(&vb_desc, &vb_init, &g_head.vb);
    if (FAILED(hr) || !g_head.vb) {
        FW_ERR("[head] CreateBuffer VB failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    // --- IB ---
    D3D11_BUFFER_DESC ib_desc{};
    ib_desc.Usage     = D3D11_USAGE_IMMUTABLE;
    ib_desc.ByteWidth = static_cast<UINT>(idx.size() * sizeof(std::uint16_t));
    ib_desc.BindFlags = D3D11_BIND_INDEX_BUFFER;
    D3D11_SUBRESOURCE_DATA ib_init{};
    ib_init.pSysMem = idx.data();
    hr = dev->CreateBuffer(&ib_desc, &ib_init, &g_head.ib);
    if (FAILED(hr) || !g_head.ib) {
        FW_ERR("[head] CreateBuffer IB failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    // --- CB ---
    D3D11_BUFFER_DESC cb_desc{};
    cb_desc.Usage          = D3D11_USAGE_DYNAMIC;
    cb_desc.ByteWidth      = sizeof(HeadCB);
    cb_desc.BindFlags      = D3D11_BIND_CONSTANT_BUFFER;
    cb_desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    hr = dev->CreateBuffer(&cb_desc, nullptr, &g_head.cb);
    if (FAILED(hr) || !g_head.cb) {
        FW_ERR("[head] CreateBuffer CB failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    // --- Shaders ---
    ID3DBlob* vs_blob = compile_shader(kHeadVsSrc, "main", "vs_5_0");
    if (!vs_blob) return false;
    ID3DBlob* ps_blob = compile_shader(kHeadPsSrc, "main", "ps_5_0");
    if (!ps_blob) { safe_release(vs_blob); return false; }

    hr = dev->CreateVertexShader(vs_blob->GetBufferPointer(),
                                  vs_blob->GetBufferSize(),
                                  nullptr, &g_head.vs);
    if (FAILED(hr)) {
        FW_ERR("[head] CreateVertexShader failed hr=0x%08lX", static_cast<unsigned long>(hr));
        safe_release(vs_blob); safe_release(ps_blob);
        return false;
    }

    hr = dev->CreatePixelShader(ps_blob->GetBufferPointer(),
                                 ps_blob->GetBufferSize(),
                                 nullptr, &g_head.ps);
    if (FAILED(hr)) {
        FW_ERR("[head] CreatePixelShader failed hr=0x%08lX", static_cast<unsigned long>(hr));
        safe_release(vs_blob); safe_release(ps_blob);
        return false;
    }

    // --- Input layout: POSITION float3 + NORMAL float3 ---
    const D3D11_INPUT_ELEMENT_DESC elems[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "NORMAL",   0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 12,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    hr = dev->CreateInputLayout(
        elems, static_cast<UINT>(sizeof(elems) / sizeof(elems[0])),
        vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(),
        &g_head.layout);
    safe_release(vs_blob);
    safe_release(ps_blob);

    if (FAILED(hr) || !g_head.layout) {
        FW_ERR("[head] CreateInputLayout failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    // --- State objects: same story as body (depth ALWAYS for now, no
    //     cull, no blend). ---
    // β.6b v4: reverse-Z GREATER_EQUAL (match body DSS).
    D3D11_DEPTH_STENCIL_DESC dss_desc{};
    dss_desc.DepthEnable    = TRUE;
    dss_desc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    dss_desc.DepthFunc      = D3D11_COMPARISON_GREATER_EQUAL;
    dss_desc.StencilEnable  = FALSE;
    hr = dev->CreateDepthStencilState(&dss_desc, &g_head.dss);
    if (FAILED(hr)) { FW_ERR("[head] dss failed"); return false; }

    D3D11_RASTERIZER_DESC rs_desc{};
    rs_desc.FillMode        = D3D11_FILL_SOLID;
    rs_desc.CullMode        = D3D11_CULL_NONE;
    rs_desc.DepthClipEnable = FALSE;
    hr = dev->CreateRasterizerState(&rs_desc, &g_head.rs);
    if (FAILED(hr)) { FW_ERR("[head] rs failed"); return false; }

    D3D11_BLEND_DESC bs_desc{};
    bs_desc.RenderTarget[0].BlendEnable           = FALSE;
    bs_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    hr = dev->CreateBlendState(&bs_desc, &g_head.bs);
    if (FAILED(hr)) { FW_ERR("[head] bs failed"); return false; }

    g_head.ready.store(true, std::memory_order_release);
    FW_LOG("[head] placeholder pipeline ready: sphere radius=%.1f units "
           "neck_offset=%.1f", HEAD_RADIUS, NECK_Z_WORLD_OFFSET);
    return true;
}

void draw_head(ID3D11DeviceContext* ctx,
               const float game_vp[16],
               const float eye_world[3],
               const float anchor[3],
               float yaw)
{
    if (!g_head.ready.load(std::memory_order_acquire) || !ctx) return;

    // --- Compose CB ---
    HeadCB cb{};
    // Head position: anchor + (0, 0, NECK_Z_WORLD_OFFSET)
    mat_head_model(cb.model,
                   anchor[0], anchor[1], anchor[2] + NECK_Z_WORLD_OFFSET,
                   -yaw);  // negate yaw to match body's convention
    std::memcpy(cb.game_vp,   game_vp,   sizeof(cb.game_vp));
    std::memcpy(cb.eye_world, eye_world, sizeof(cb.eye_world));

    D3D11_MAPPED_SUBRESOURCE mapped{};
    HRESULT hr = ctx->Map(g_head.cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(hr)) {
        return;
    }
    std::memcpy(mapped.pData, &cb, sizeof(cb));
    ctx->Unmap(g_head.cb, 0);

    // --- Save state we'll stomp (minimal — body_render already saved
    //     the big stuff. We save VB/IB/input-layout/VS/PS/b0 CB). ---
    ID3D11InputLayout*  saved_layout = nullptr;
    ctx->IAGetInputLayout(&saved_layout);
    ID3D11VertexShader* saved_vs     = nullptr;
    ctx->VSGetShader(&saved_vs, nullptr, nullptr);
    ID3D11PixelShader*  saved_ps     = nullptr;
    ctx->PSGetShader(&saved_ps, nullptr, nullptr);
    ID3D11Buffer*       saved_vb     = nullptr;
    UINT                saved_stride = 0, saved_offset = 0;
    ctx->IAGetVertexBuffers(0, 1, &saved_vb, &saved_stride, &saved_offset);
    ID3D11Buffer*       saved_ib     = nullptr;
    DXGI_FORMAT         saved_fmt    = DXGI_FORMAT_UNKNOWN;
    UINT                saved_ib_off = 0;
    ctx->IAGetIndexBuffer(&saved_ib, &saved_fmt, &saved_ib_off);
    ID3D11Buffer*       saved_cb0    = nullptr;
    ctx->VSGetConstantBuffers(0, 1, &saved_cb0);

    // --- Bind head pipeline ---
    ctx->IASetInputLayout(g_head.layout);
    ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    const UINT stride = sizeof(SphereVertex);
    const UINT offset = 0;
    ctx->IASetVertexBuffers(0, 1, &g_head.vb, &stride, &offset);
    ctx->IASetIndexBuffer(g_head.ib, DXGI_FORMAT_R16_UINT, 0);
    ctx->VSSetShader(g_head.vs, nullptr, 0);
    ctx->VSSetConstantBuffers(0, 1, &g_head.cb);
    ctx->PSSetShader(g_head.ps, nullptr, 0);
    // DSS/RS/BS were set by body — we use the body's state (same
    // conventions). If we set our own, we'd have to restore body's.
    // The body's DSS (ALWAYS) + RS (CULL_NONE) + BS (opaque) match
    // what we want.

    ctx->DrawIndexed(g_head.index_count, 0, 0);

    // --- Restore ---
    ctx->VSSetConstantBuffers(0, 1, &saved_cb0);
    safe_release(saved_cb0);
    ctx->IASetIndexBuffer(saved_ib, saved_fmt, saved_ib_off);
    safe_release(saved_ib);
    ctx->IASetVertexBuffers(0, 1, &saved_vb, &saved_stride, &saved_offset);
    safe_release(saved_vb);
    ctx->PSSetShader(saved_ps, nullptr, 0);
    safe_release(saved_ps);
    ctx->VSSetShader(saved_vs, nullptr, 0);
    safe_release(saved_vs);
    ctx->IASetInputLayout(saved_layout);
    safe_release(saved_layout);
}

void release_head_resources() {
    safe_release(g_head.bs);
    safe_release(g_head.rs);
    safe_release(g_head.dss);
    safe_release(g_head.layout);
    safe_release(g_head.ps);
    safe_release(g_head.vs);
    safe_release(g_head.cb);
    safe_release(g_head.ib);
    safe_release(g_head.vb);
    g_head.ready.store(false, std::memory_order_release);
}

} // namespace fw::render
