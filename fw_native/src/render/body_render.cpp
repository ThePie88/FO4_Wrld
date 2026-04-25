#include "body_render.h"
#include "dsv_capture.h"
#include "head_placeholder.h"
#include "scene_render_hook.h"
#include "vp_capture.h"

#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <optional>

#include "../assets/fwn_loader.h"
#include "../engine/engine_calls.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"

namespace fw::render {

namespace {

// Bone palette capacity in the CB. MaleBody uses 58; future armor/PA
// meshes may go higher. 64 is a comfortable ceiling — 64 * 64 B = 4 KB,
// which fits trivially in the 64 KB D3D11 CB limit. If we ever need
// more than 64 bones (unlikely for humanoid), bump here and in HLSL.
constexpr std::uint32_t kMaxBones = 64;

// -----------------------------------------------------------------------
// HLSL — skinned body pipeline.
//
// Vertex layout matches fw::assets::MeshVertex exactly (64 B AoS):
//   offset 0  : float3 position
//   offset 12 : float3 normal
//   offset 24 : float2 uv
//   offset 32 : uint4  bone_idx   (0xFFFFFFFF = unused slot)
//   offset 48 : float4 bone_weight
//
// Skinning: classic 4-bone LBS (linear blend skinning). The bone palette
// CB holds 64 row-major 4x4 transforms (ample for 58-bone MaleBody, room
// to grow). We mark them `row_major` because the writer emits row-major
// and HLSL's default is column-major — mismatch would silently produce
// garbage transforms.
//
// Camera matrices (model/view/proj) stay column-major to match the
// convention the triangle renderer already uses and the CPU-side math
// helpers produce.
//
// β.2 scope: compile these; NO draw yet (β.4). If the HLSL is broken,
// we find out here via D3DCompile's error message.
// -----------------------------------------------------------------------
constexpr const char* kBodyVsSrc = R"HLSL(
cbuffer Camera : register(b0)
{
    float4x4 model;           // body-world placement (col-major).
    float4x4 game_vp;         // Self-built proj*view (col-major, our
                              // own matrix). Shake known limit.
    float3   eye_world;       // (0,0,0) — self-built VP bakes view.
    float    _pad;
};

cbuffer BonePalette : register(b1)
{
    row_major float4x4 bones[64];
};

struct VSIn {
    float3 pos   : POSITION;
    float3 norm  : NORMAL;
    float2 uv    : TEXCOORD0;
    uint4  bidx  : BLENDINDICES;
    float4 bw    : BLENDWEIGHT;
};

struct VSOut {
    float4 pos_clip : SV_POSITION;
    float3 norm_ws  : NORMAL;
    float2 uv       : TEXCOORD0;
    float3 pos_ws   : TEXCOORD1;
};

VSOut main(VSIn v)
{
    uint4 idx;
    idx.x = v.bidx.x < 64 ? v.bidx.x : 0;
    idx.y = v.bidx.y < 64 ? v.bidx.y : 0;
    idx.z = v.bidx.z < 64 ? v.bidx.z : 0;
    idx.w = v.bidx.w < 64 ? v.bidx.w : 0;

    float wsum = v.bw.x + v.bw.y + v.bw.z + v.bw.w;
    float4x4 skin;
    if (wsum > 0.001)
    {
        skin = v.bw.x * bones[idx.x]
             + v.bw.y * bones[idx.y]
             + v.bw.z * bones[idx.z]
             + v.bw.w * bones[idx.w];
    }
    else
    {
        skin = float4x4(1, 0, 0, 0,
                        0, 1, 0, 0,
                        0, 0, 1, 0,
                        0, 0, 0, 1);
    }

    float4 pos_skinned  = mul(skin, float4(v.pos, 1.0));
    float3 norm_skinned = mul((float3x3)skin, v.norm);

    // Body-local -> world via our anchor model matrix.
    float4 pos_world = mul(model, pos_skinned);

    // Self-built VP: standard DX RH col-vec math. eye_world is (0,0,0)
    // from CPU, so pos_rel is just pos_world. VP bakes view translation.
    float4 pos_rel = float4(pos_world.xyz - eye_world, 1.0);
    float4 pos_clip = mul(game_vp, pos_rel);

    VSOut o;
    o.pos_clip = pos_clip;
    o.norm_ws  = mul((float3x3)model, norm_skinned);
    o.uv       = v.uv;
    o.pos_ws   = pos_world.xyz;
    return o;
}
)HLSL";

// CPU-side layout of the Camera CB (b0). `model` is column-major (our
// own math helpers produce that). `game_vp` is the raw memory copy of
// NiCamera+288 — marked `row_major` in HLSL so we don't accidentally
// transpose. `eye_world` is the player's eye position in world space,
// subtracted inside the shader before the game_vp multiply.
struct CameraCB {
    float model[16];          // 64 B
    float game_vp[16];        // 64 B
    float eye_world[3];       // 12 B
    float pad0;               //  4 B (CB 16-byte alignment)
};
static_assert(sizeof(CameraCB) == 144, "CameraCB must be 144 B");

// CPU-side layout of the BonePalette CB (b1). Row-major matrices to
// match the HLSL `row_major float4x4` annotation and the data produced
// by fwn_writer::mat_transform_to_44_rowmajor.
struct BonePaletteCB {
    float bones[kMaxBones][16];
};
static_assert(sizeof(BonePaletteCB) == kMaxBones * 64,
              "BonePaletteCB size mismatch");

// Pixel shader: flat-ish gray body with one-directional lambertian
// shading — enough to see 3D form on screen. No texture yet (β.5 brings
// diffuse DDS).
constexpr const char* kBodyPsSrc = R"HLSL(
struct PSIn {
    float4 pos_clip : SV_POSITION;
    float3 norm_ws  : NORMAL;
    float2 uv       : TEXCOORD0;
    float3 pos_ws   : TEXCOORD1;
};

float4 main(PSIn i) : SV_Target
{
    float3 N = normalize(i.norm_ws);
    // Sunlight from upper-right-front (world-space); pointing direction
    // is the light's source direction, normalized.
    float3 L = normalize(float3(0.5, -0.3, 1.0));
    float lambert = saturate(dot(N, L));
    float ambient = 0.25;
    float shade = ambient + (1.0 - ambient) * lambert;
    float3 base = float3(0.85, 0.75, 0.65);   // skin-ish placeholder
    return float4(base * shade, 1.0);
}
)HLSL";

// -----------------------------------------------------------------------
// State
//
// Single-instance body state. β.1 holds one mesh (MaleBody). When the
// ghost player feature matures (equipment submeshes, multiple bodies,
// remote players) this will grow into a per-entity registry — but for
// now the "ghost body" is just the local player's anchor, one asset.
// -----------------------------------------------------------------------
struct BodyState {
    // --- CPU-side (produced by init_body_asset) ---
    std::optional<fw::assets::MeshAsset> asset;

    // acquire/release fence for CPU→render-thread handoff. Render
    // thread reads asset only when this is true.
    std::atomic<bool> asset_ready{false};

    // --- GPU-side (produced by render-thread upload on first frame) ---
    ID3D11Device*        device        = nullptr;
    ID3D11DeviceContext* context       = nullptr;
    ID3D11Buffer*        vertex_buffer = nullptr;
    ID3D11Buffer*        index_buffer  = nullptr;

    // --- β.2: pipeline state (shaders + input layout) ---
    ID3D11VertexShader*  vs           = nullptr;
    ID3D11PixelShader*   ps           = nullptr;
    ID3D11InputLayout*   input_layout = nullptr;

    // --- β.3: per-frame constant buffers ---
    ID3D11Buffer*        camera_cb    = nullptr;   // register(b0), MatricesCB
    ID3D11Buffer*        bone_cb      = nullptr;   // register(b1), BonePaletteCB

    // --- β.4: fixed-function state objects (created once, reused) ---
    // β.4 MVP: no depth (draws on top of game pixels — still lets us see
    // a humanoid silhouette to validate the pipeline). β.6 adds proper
    // depth integration with the game's depth buffer.
    ID3D11DepthStencilState* dss      = nullptr;
    ID3D11RasterizerState*   rs       = nullptr;
    ID3D11BlendState*        bs       = nullptr;

    // Metadata cached at upload time for use in future draw calls
    // (β.2+). Kept here so draw_body doesn't need to re-read from the
    // (moved) MeshAsset every frame.
    std::uint32_t vertex_count = 0;
    std::uint32_t index_count  = 0;
    std::uint32_t bone_count   = 0;
    std::uint32_t flags        = 0;
    bool          uses_u32     = false;

    // --- Lifecycle flags (render-thread-only after init) ---
    bool          uploaded          = false;
    bool          pipeline_ready    = false;  // shaders + layout compiled+created
    bool          upload_failed     = false;  // log-once guard (applies to any
                                              // step of the init chain)
    bool          scene_hook_active = false;  // β.6: set when scene hook OK
                                              // → Present hook skips draw
    std::uint64_t frames_seen       = 0;

    // β.6: cached swapchain from first Present call. Used by
    // draw_body_at_scene_end() to get the backbuffer RTV when drawing
    // from the scene-render hook (which doesn't receive a swap ptr).
    IDXGISwapChain* cached_swapchain = nullptr;

    // β.6 head placeholder: cached values from update_camera_cb so
    // draw_head() (called after body's DrawIndexed) sees the SAME
    // VP/eye/anchor/yaw with zero timing drift.
    float           last_game_vp[16]{};
    float           last_eye_world[3]{};
    float           last_anchor[3]{};
    float           last_yaw    = 0.0f;
    bool            head_ready  = false;

    // --- β.4d: LIVE-follow placement (scrapped β.4c spawn pinning
    //     because Bethesda's MainMenu cell at (2048,2048,0) silently
    //     captured a bogus spawn before LoadGame completed).
    // The body now anchors to the live player foot pose every frame,
    // ground-aligned. Menu/load-screen frames are skipped via a pose
    // fingerprint check (see is_live_gameplay_pose).
    // When ε lands, this dynamic anchor gets swapped for per-remote
    // -player state driven by the network. ---
};

BodyState g_body;

template <typename T>
void safe_release(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

// -----------------------------------------------------------------------
// Matrix math helpers — column-major 4x4 (HLSL default). Duplicated
// from triangle_render.cpp for β.3/β.4 self-containment. TODO: factor
// into a shared render/math_utils.h in β.6 when we also share depth
// state management.
// -----------------------------------------------------------------------
void mat_identity(float* m) {
    std::memset(m, 0, 16 * sizeof(float));
    m[0] = m[5] = m[10] = m[15] = 1.0f;
}

void mat_translation(float* m, float tx, float ty, float tz) {
    mat_identity(m);
    m[12] = tx;
    m[13] = ty;
    m[14] = tz;
}

// Column-major 4x4: rotate around world Z (up) by `angle_z`, then translate.
// Z-rotation is right-hand CCW when looking DOWN the +Z axis (standard math
// convention). For FO4's Actor yaw (which increases CW from above = player
// turning right from N toward E), pass -yaw here to align body local +Y
// forward with the player's facing direction.
void mat_translation_rot_z(float* m,
                           float tx, float ty, float tz,
                           float angle_z)
{
    const float c = std::cos(angle_z);
    const float s = std::sin(angle_z);
    // Column 0: rotated local +X
    m[ 0] =  c;    m[ 1] =  s;    m[ 2] = 0.0f;  m[ 3] = 0.0f;
    // Column 1: rotated local +Y (= world forward when angle = -yaw)
    m[ 4] = -s;    m[ 5] =  c;    m[ 6] = 0.0f;  m[ 7] = 0.0f;
    // Column 2: local +Z unchanged (world up)
    m[ 8] = 0.0f;  m[ 9] = 0.0f;  m[10] = 1.0f;  m[11] = 0.0f;
    // Column 3: translation
    m[12] = tx;    m[13] = ty;    m[14] = tz;    m[15] = 1.0f;
}

// Column-major 4x4: M = T * R_z_yaw * R_x_root_correction
//
// β.6 body-orient fix: Bethesda MaleBody.nif stores vertex positions in
// a "shape local" frame whose axes differ from world when we apply
// IDENTITY bones (T-pose display). Empirically, the shape-local +Y axis
// corresponds to "head up" (natural +Y forward in NIF is actually up
// for the body in bind pose), so we need a +90° rotation around local
// X to bring local +Y → world +Z.
//
// This is a "root node correction" matrix — what the skeleton.nif's
// Bip01 root bone would normally apply. Since we don't load skeleton.nif
// and all bones are identity for now, we bake the correction into the
// model matrix.
//
// Composition order (column-major `mul`-friendly):
//   pos_world = (T · R_z · R_x) · pos_local
//   R_x is applied FIRST (closest to the vertex), so it's a BODY-local
//   X rotation. Then yaw Z around world-up. Then translation to anchor.
//
// pre_rot_x_rad: radians; try +PI/2 (90°) first. If body is wrong after
// that, try -PI/2 or 0.0 (bypass).
void mat_model_with_root_correction(float* m,
                                     float tx, float ty, float tz,
                                     float angle_z,
                                     float pre_rot_x_rad)
{
    const float cz = std::cos(angle_z);
    const float sz = std::sin(angle_z);
    const float cx = std::cos(pre_rot_x_rad);
    const float sx = std::sin(pre_rot_x_rad);

    // R_z * R_x (math / row-first view):
    //   [cz   -sz·cx   sz·sx   0]
    //   [sz    cz·cx  -cz·sx   0]
    //   [0     sx      cx      0]
    //   [0     0       0       1]
    //
    // We store column-major, so m[0..3] is column 0 of the above.
    m[ 0] =  cz;        m[ 1] =  sz;       m[ 2] = 0.0f;  m[ 3] = 0.0f;
    m[ 4] = -sz * cx;   m[ 5] =  cz * cx;  m[ 6] = sx;    m[ 7] = 0.0f;
    m[ 8] =  sz * sx;   m[ 9] = -cz * sx;  m[10] = cx;    m[11] = 0.0f;
    m[12] =  tx;        m[13] =  ty;       m[14] = tz;    m[15] = 1.0f;
}

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

// Reverse-Z infinite-far perspective matrix, RH (camera looks -Z).
// NDC.z = near / -view.z  → at near plane = 1.0, at infinity = 0.0.
// This matches FO4's scene depth convention (per IDA RE + Creation Engine
// consistency with Skyrim SE): DSV cleared to 0, DepthFunc=GREATER_EQUAL,
// D32_FLOAT format.
//
// Math (column-major, row-first view):
//   [f/a  0    0     0   ]
//   [0    f    0     0   ]
//   [0    0    0    near ]
//   [0    0   -1     0   ]
void mat_perspective_inf_reverse_rh(float* m, float fov_y_rad, float aspect,
                                     float near_z)
{
    const float f = 1.0f / std::tan(fov_y_rad * 0.5f);
    std::memset(m, 0, 16 * sizeof(float));
    // col 0
    m[0]  = f / aspect;
    // col 1
    m[5]  = f;
    // col 2 — (0, 0, 0, -1), so only row 3
    m[11] = -1.0f;
    // col 3 — (0, 0, near, 0), so only row 2
    m[14] = near_z;
}

void mat_look_at_rh(float* m,
                    const float eye[3], const float at[3], const float up[3])
{
    float zx = eye[0] - at[0];
    float zy = eye[1] - at[1];
    float zz = eye[2] - at[2];
    float zl = std::sqrt(zx*zx + zy*zy + zz*zz);
    if (zl < 1e-6f) zl = 1.0f;
    zx /= zl; zy /= zl; zz /= zl;

    float xx = up[1]*zz - up[2]*zy;
    float xy = up[2]*zx - up[0]*zz;
    float xz = up[0]*zy - up[1]*zx;
    float xl = std::sqrt(xx*xx + xy*xy + xz*xz);
    if (xl < 1e-6f) xl = 1.0f;
    xx /= xl; xy /= xl; xz /= xl;

    float yx = zy*xz - zz*xy;
    float yy = zz*xx - zx*xz;
    float yz = zx*xy - zy*xx;

    std::memset(m, 0, 16 * sizeof(float));
    m[0] = xx;  m[4] = xy;  m[8]  = xz;   m[12] = -(xx*eye[0] + xy*eye[1] + xz*eye[2]);
    m[1] = yx;  m[5] = yy;  m[9]  = yz;   m[13] = -(yx*eye[0] + yy*eye[1] + yz*eye[2]);
    m[2] = zx;  m[6] = zy;  m[10] = zz;   m[14] = -(zx*eye[0] + zy*eye[1] + zz*eye[2]);
    m[15] = 1.0f;
}

// Bethesda renders the MainMenu on an internal interior cell whose
// player pose is a fingerprintable constant. We must not render the
// body during menu frames (body would sit at whatever menu coord and
// then persist off-screen when LoadGame teleports the real player).
// Returns true only when the pose looks like real gameplay.
bool is_live_gameplay_pose(const float p[3]) {
    // Pre-init / torn-down singleton returns (0,0,0).
    if (p[0] == 0.0f && p[1] == 0.0f && p[2] == 0.0f) return false;

    // MainMenu interior cell: player sits at (2048, 2048, 0) — the
    // same fingerprint every Bethesda save shows during main menu.
    // Tolerance of a few units just in case the main-menu actor idles
    // with tiny drift.
    if (std::fabs(p[0] - 2048.0f) < 4.0f &&
        std::fabs(p[1] - 2048.0f) < 4.0f &&
        std::fabs(p[2])           < 4.0f) {
        return false;
    }
    return true;
}

// Read player (pos, euler-rot) from the engine singleton. SEH-guarded
// because the singleton slot may be torn down during load screens.
// Returns false on any access fault or null slot.
bool read_player_pose(float pos_out[3], float rot_out[3]) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

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

// -----------------------------------------------------------------------
// D3DCompile wrapper: compiles one HLSL TU. Returns a Blob* on success;
// logs the full compiler error + returns nullptr on failure. Caller is
// responsible for releasing the returned blob.
// -----------------------------------------------------------------------
ID3DBlob* compile_body_shader(const char* src, const char* entry, const char* target)
{
    ID3DBlob* blob = nullptr;
    ID3DBlob* err  = nullptr;
    const HRESULT hr = D3DCompile(
        src, std::strlen(src),
        "fw_body",                  // file name shown in error messages
        nullptr, nullptr,
        entry, target,
        D3DCOMPILE_OPTIMIZATION_LEVEL3, 0,
        &blob, &err);
    if (FAILED(hr)) {
        if (err) {
            FW_ERR("[body] shader compile FAILED entry=%s target=%s hr=0x%08lX msg=%s",
                   entry, target, static_cast<unsigned long>(hr),
                   static_cast<const char*>(err->GetBufferPointer()));
            err->Release();
        } else {
            FW_ERR("[body] shader compile FAILED entry=%s target=%s hr=0x%08lX (no blob)",
                   entry, target, static_cast<unsigned long>(hr));
        }
        safe_release(blob);
        return nullptr;
    }
    if (err) err->Release();   // warnings-only case
    return blob;
}

// -----------------------------------------------------------------------
// β.2 — compile VS/PS, create shader objects, build input layout.
//
// Input layout matches fw::assets::MeshVertex (64 B) exactly:
//   POSITION      float3  offset 0
//   NORMAL        float3  offset 12
//   TEXCOORD0     float2  offset 24
//   BLENDINDICES  uint4   offset 32
//   BLENDWEIGHT   float4  offset 48
//
// CreateInputLayout validates against the VS input signature — mismatch
// = immediate failure. That's exactly the test β.2 is designed to run.
// -----------------------------------------------------------------------
bool init_pipeline_state(ID3D11Device* dev)
{
    ID3DBlob* vs_blob = compile_body_shader(kBodyVsSrc, "main", "vs_5_0");
    if (!vs_blob) return false;

    ID3DBlob* ps_blob = compile_body_shader(kBodyPsSrc, "main", "ps_5_0");
    if (!ps_blob) {
        safe_release(vs_blob);
        return false;
    }

    HRESULT hr = dev->CreateVertexShader(
        vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(),
        nullptr, &g_body.vs);
    if (FAILED(hr) || !g_body.vs) {
        FW_ERR("[body] CreateVertexShader failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        safe_release(vs_blob); safe_release(ps_blob);
        return false;
    }

    hr = dev->CreatePixelShader(
        ps_blob->GetBufferPointer(), ps_blob->GetBufferSize(),
        nullptr, &g_body.ps);
    if (FAILED(hr) || !g_body.ps) {
        FW_ERR("[body] CreatePixelShader failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        safe_release(vs_blob); safe_release(ps_blob);
        return false;
    }

    // Input layout — one of the few places in D3D11 where a mismatch
    // silently *could* produce black/garbled geometry if signatures
    // differ but sizes still fit. D3D11 validates against the VS blob,
    // so any mismatch is caught here.
    const D3D11_INPUT_ELEMENT_DESC elems[] = {
        { "POSITION",     0, DXGI_FORMAT_R32G32B32_FLOAT,     0, 0,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "NORMAL",       0, DXGI_FORMAT_R32G32B32_FLOAT,     0, 12,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "TEXCOORD",     0, DXGI_FORMAT_R32G32_FLOAT,        0, 24,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "BLENDINDICES", 0, DXGI_FORMAT_R32G32B32A32_UINT,   0, 32,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "BLENDWEIGHT",  0, DXGI_FORMAT_R32G32B32A32_FLOAT,  0, 48,
          D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    hr = dev->CreateInputLayout(
        elems, static_cast<UINT>(sizeof(elems) / sizeof(elems[0])),
        vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(),
        &g_body.input_layout);

    // Blobs no longer needed after both shaders + layout built.
    safe_release(vs_blob);
    safe_release(ps_blob);

    if (FAILED(hr) || !g_body.input_layout) {
        FW_ERR("[body] CreateInputLayout failed hr=0x%08lX "
               "(vertex signature mismatch with HLSL VSIn?)",
               static_cast<unsigned long>(hr));
        return false;
    }

    FW_LOG("[body] pipeline compiled: vs=%p ps=%p layout=%p "
           "(5 elems = POS+NORM+UV+BIDX+BW, stride=64 B)",
           static_cast<void*>(g_body.vs),
           static_cast<void*>(g_body.ps),
           static_cast<void*>(g_body.input_layout));
    return true;
}

// -----------------------------------------------------------------------
// β.3/β.4 — create the dynamic constant buffers (camera + bone palette)
// and the fixed-function state objects (depth/raster/blend).
// -----------------------------------------------------------------------
bool init_state_and_cbs(ID3D11Device* dev)
{
    // --- Camera CB (register b0) ---
    D3D11_BUFFER_DESC cb_desc{};
    cb_desc.Usage          = D3D11_USAGE_DYNAMIC;
    cb_desc.ByteWidth      = sizeof(CameraCB);
    cb_desc.BindFlags      = D3D11_BIND_CONSTANT_BUFFER;
    cb_desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    HRESULT hr = dev->CreateBuffer(&cb_desc, nullptr, &g_body.camera_cb);
    if (FAILED(hr) || !g_body.camera_cb) {
        FW_ERR("[body] CreateBuffer(camera CB) failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        return false;
    }

    // --- Bone palette CB (register b1) ---
    cb_desc.ByteWidth = sizeof(BonePaletteCB);  // 4096 B
    hr = dev->CreateBuffer(&cb_desc, nullptr, &g_body.bone_cb);
    if (FAILED(hr) || !g_body.bone_cb) {
        FW_ERR("[body] CreateBuffer(bone CB) failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        return false;
    }

    // --- Depth/stencil state: β.6 diagnostic — DepthFunc=ALWAYS so
    //     every fragment passes regardless of depth comparison. This
    //     isolates "DSV bind works / body renders" from "depth math is
    //     correct". Once body is visible we'll iterate to LESS_EQUAL /
    //     GREATER_EQUAL / tuned near-far to get actual wall occlusion.
    //     DepthWriteMask ZERO ensures we don't corrupt the game's
    //     depth buffer even while not testing against it. ---
    // β.6b v4 depth fix: REVERSE-Z final.
    //
    // Iterations:
    //   v1 LESS_EQUAL + forward-Z proj:  body dome-only (DSV sky cleared
    //                                    to 0 in reverse-Z → body NDC.z
    //                                    ~0.999 fails LESS_EQUAL <= 0)
    //   v2 GREATER_EQUAL + forward-Z:    body visible but random occlusion
    //                                    (forward-Z NDC.z vs reverse-Z DSV
    //                                    = semantic mismatch)
    //   v3 LESS_EQUAL + forward-Z (w/ deploy fix): backwards occlusion
    //                                    (tree over body, etc.)
    //   v4 GREATER_EQUAL + REVERSE-Z proj: ← THIS. Semantic match.
    //
    // Per IDA RE: FO4 D32_FLOAT DSV cleared to 0, reverse-Z infinite
    // far. GREATER_EQUAL: body passes only if its NDC.z >= scene NDC.z,
    // which in reverse-Z means body is closer or equal → correct.
    D3D11_DEPTH_STENCIL_DESC dss_desc{};
    dss_desc.DepthEnable    = TRUE;
    dss_desc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    dss_desc.DepthFunc      = D3D11_COMPARISON_GREATER_EQUAL;
    dss_desc.StencilEnable  = FALSE;
    hr = dev->CreateDepthStencilState(&dss_desc, &g_body.dss);
    if (FAILED(hr)) {
        FW_ERR("[body] CreateDSS failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    // --- Rasterizer: CULL_NONE for MVP (we'll see both faces regardless
    //     of mesh winding convention). β.5/β.6 tightens. DepthClipEnable
    //     FALSE so the far plane doesn't eat vertices at large anchor
    //     distances. ---
    D3D11_RASTERIZER_DESC rs_desc{};
    rs_desc.FillMode        = D3D11_FILL_SOLID;
    rs_desc.CullMode        = D3D11_CULL_NONE;
    rs_desc.DepthClipEnable = FALSE;
    hr = dev->CreateRasterizerState(&rs_desc, &g_body.rs);
    if (FAILED(hr)) {
        FW_ERR("[body] CreateRS failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    // --- Blend: opaque ---
    D3D11_BLEND_DESC bs_desc{};
    bs_desc.RenderTarget[0].BlendEnable           = FALSE;
    bs_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    hr = dev->CreateBlendState(&bs_desc, &g_body.bs);
    if (FAILED(hr)) {
        FW_ERR("[body] CreateBS failed hr=0x%08lX", static_cast<unsigned long>(hr));
        return false;
    }

    FW_LOG("[body] state/CBs ready: "
           "cam_cb=%p bone_cb=%p dss=%p rs=%p bs=%p",
           static_cast<void*>(g_body.camera_cb),
           static_cast<void*>(g_body.bone_cb),
           static_cast<void*>(g_body.dss),
           static_cast<void*>(g_body.rs),
           static_cast<void*>(g_body.bs));
    return true;
}

// -----------------------------------------------------------------------
// Per-frame CB updates.
// -----------------------------------------------------------------------

// Map + fill the camera CB with model/view/proj derived from the current
// player pose. The body model-space origin is placed at
// (player_pos + forward * ANCHOR_DIST) — a few meters in front of the
// player at ground level. Returns false if the player pose can't be
// read this frame (the caller bails on the whole draw).
bool update_camera_cb(UINT viewport_w, UINT viewport_h)
{
    (void)viewport_w;  // game_vp bakes its own aspect — we don't reconstruct.
    (void)viewport_h;

    // --- REMOTE snapshot (body world pos/yaw) ---
    auto remote = fw::net::client().get_remote_snapshot();
    const bool remote_was_real = remote.has_state;  // before fallback overwrite

    std::uint64_t age_ms = 0;
    // DEV FALLBACK: if no remote connected (Side B not launched), fake
    // a remote at local_player + (300, 0, 0) so we can validate the
    // rendering pipeline with a single client. Delete once net-only
    // behavior needed.
    if (!remote.has_state) {
        float lp[3]{}, lr[3]{};
        if (!read_player_pose(lp, lr)) return false;
        if (!is_live_gameplay_pose(lp)) return false;
        remote.has_state      = true;
        remote.peer_id        = "dev_fallback";
        remote.pos[0]         = lp[0] + 300.0f;  // 300 units east of local
        remote.pos[1]         = lp[1];
        remote.pos[2]         = lp[2];
        remote.rot[0]         = 0;
        remote.rot[1]         = 0;
        remote.rot[2]         = lr[2];           // same yaw as local
        remote.received_at_ms = GetTickCount64();
    } else {
        constexpr std::uint64_t kStaleMs = 5000;
        const std::uint64_t now_ms = GetTickCount64();
        age_ms = now_ms - remote.received_at_ms;
        if (age_ms > kStaleMs) return false;
    }

    if (!is_live_gameplay_pose(remote.pos)) return false;

    // Log remote source (real vs fallback) every ~5s so we know what
    // position the body is being anchored to. If this says FALLBACK
    // during a multiplayer session, the net snapshot isn't landing here.
    if (g_body.frames_seen == 1 || (g_body.frames_seen % 300) == 0) {
        FW_DBG("[body] remote source = %s  peer='%s'  pos=(%.0f, %.0f, %.0f)  "
               "yaw=%.1f\u00b0",
               remote_was_real ? "REAL-NET" : "DEV-FALLBACK",
               remote.peer_id.c_str(),
               remote.pos[0], remote.pos[1], remote.pos[2],
               remote.rot[2] * 57.29578f);
    }


    CameraCB cb{};

    float lp_pos[3]{}, lp_rot[3]{};
    if (!read_player_pose(lp_pos, lp_rot)) return false;
    if (!is_live_gameplay_pose(lp_pos)) return false;

    // β.6 VP capture is disabled (see body_render draw_body comment).
    // Always use self-built VP. Body visible + synced + pitch correct,
    // with shake known limit.
    const bool got_captured_vp = false;

    // Eye (diagnostic + fallback computation only).
    constexpr float EYE_HEIGHT = 120.0f;
    float cam_eye[3]{};
    float cam_basis_unused[9]{};
    const bool got_cam_xform = fw::engine::read_camera_world_transform(
        cam_eye, cam_basis_unused);
    float eye[3];
    if (got_cam_xform) {
        eye[0] = cam_eye[0];  eye[1] = cam_eye[1];  eye[2] = cam_eye[2];
    } else {
        eye[0] = lp_pos[0];  eye[1] = lp_pos[1];  eye[2] = lp_pos[2] + EYE_HEIGHT;
    }

    const float yaw   = lp_rot[2];
    const float pitch = lp_rot[0];
    const float cp = std::cos(pitch);
    const float sp = std::sin(pitch);
    const float fwd[3] = {
        cp * std::sin(yaw),
        cp * std::cos(yaw),
        -sp,
    };

    if (!got_captured_vp) {
        // Fallback: self-built VP. Still better than nothing. Shake
        // present here. Only runs until the engine fires the VP
        // capture hook for the first time (usually first scene frame).
        const float at[3] = { eye[0]+fwd[0], eye[1]+fwd[1], eye[2]+fwd[2] };
        const float up[3] = { 0.0f, 0.0f, 1.0f };

        float view[16];
        mat_look_at_rh(view, eye, at, up);

        constexpr float PI_F = 3.14159265358979323846f;
        const float aspect = static_cast<float>(viewport_w) /
                             static_cast<float>(viewport_h > 0 ? viewport_h : 1u);
        const float fov_h_rad = 80.0f * PI_F / 180.0f;
        const float fov_v_rad = 2.0f * std::atan(std::tan(fov_h_rad * 0.5f) / aspect);

        // β.6b v5 depth fix: read game's ACTUAL near from NiFrustum
        // instead of guessing. Static RE found 2 candidates (near=10
        // main scene vs near=1 shadow), we picked the wrong one. Only
        // runtime read gives the truth.
        float game_near = 1.0f;
        float game_far  = 1.0e7f;
        const bool got_frustum =
            fw::engine::read_camera_frustum_near_far(game_near, game_far);
        if (!got_frustum) {
            // Fallback: use near=10 (second candidate from static RE).
            game_near = 10.0f;
        }
        if (g_body.frames_seen == 1 || (g_body.frames_seen % 300) == 0) {
            FW_DBG("[body] frustum near/far = %.2f / %.2f (from %s)",
                   game_near, game_far,
                   got_frustum ? "NiFrustum live" : "STATIC FALLBACK");
        }
        float proj[16];
        mat_perspective_inf_reverse_rh(proj, fov_v_rad, aspect, game_near);

        auto mat_mul4 = [](const float* A, const float* B, float* out) {
            for (int c = 0; c < 4; ++c)
              for (int r = 0; r < 4; ++r) {
                float s = 0.0f;
                for (int k = 0; k < 4; ++k) s += A[k*4+r] * B[c*4+k];
                out[c*4+r] = s;
              }
        };
        mat_mul4(proj, view, cb.game_vp);
    }

    // Both paths: pass pos_world raw (no pre-subtract). For self-built,
    // our mat_look_at_rh bakes eye. For captured, matrix already baked
    // view translation in the col-major 4x4.
    cb.eye_world[0] = 0.0f;
    cb.eye_world[1] = 0.0f;
    cb.eye_world[2] = 0.0f;

    // --- Model matrix: from remote snapshot ---
    // anchor = remote foot-level world pos. yaw = remote's facing.
    // No pitch on model (body doesn't lean on camera tilt).
    //
    // Z-bias: Bethesda MaleBody.nif has its local origin at the pelvis,
    // not the feet. Player pose at offset 0xD0 is foot-level, so we
    // Lift the model so feet land at ground. Mesh AABB z ∈ [-120, -5.7]
    // in local. For feet on ground we need anchor.z - 120 = remote.z
    // (the foot/ground level), so anchor.z = remote.z + 120 →
    // PELVIS_BIAS = 120 = |mesh_z_min|.
    //
    // β.6b fix (2026-04-23): was 100 which left feet 20u underground,
    // causing terrain to depth-occlude the entire body once LESS_EQUAL
    // was enabled. User observed only the sphere head (above ground)
    // as a "half dome". Correcting bias to 120 lifts body above ground.
    constexpr float PELVIS_BIAS = 120.0f;
    const float r_yaw = remote.rot[2];

    // β.6-orient: CommonLibF4 RE (2026-04-22) confirmed the mesh-local
    // AABB is +Z up standard (z span 114.6 >> x span 75.9, y span 21.0).
    // No root correction needed — my earlier +90°/-90° X rotations were
    // fighting a non-existent problem. The "Saddam Hussein lying"
    // appearance was actually UPSIDE-DOWN due to Bethesda's Y-flip in
    // the VP matrix (row1[2] = -f) combined with DX Y-up NDC convention.
    // Fix is a single clip.y negate in the VS, not a model-matrix rotation.
    mat_translation_rot_z(cb.model,
                          remote.pos[0], remote.pos[1],
                          remote.pos[2] + PELVIS_BIAS,
                          -r_yaw);

    // β.6 head placeholder: cache the values draw_head will need
    // (same VP + eye + anchor + yaw as body to ensure zero drift).
    std::memcpy(g_body.last_game_vp,   cb.game_vp,   sizeof(cb.game_vp));
    std::memcpy(g_body.last_eye_world, cb.eye_world, sizeof(cb.eye_world));
    g_body.last_anchor[0] = remote.pos[0];
    g_body.last_anchor[1] = remote.pos[1];
    g_body.last_anchor[2] = remote.pos[2] + PELVIS_BIAS;
    g_body.last_yaw       = r_yaw;

    // Diagnostic: dump captured matrix + remote anchor + PREDICTED NDC
    // for the body origin so we can verify where the body SHOULD render.
    if (g_body.frames_seen == 1 ||
        (g_body.frames_seen % 300) == 0)   // ~5s at 60fps
    {
        FW_DBG("[body] anchor=(%.0f, %.0f, %.0f) yaw=%.1f\u00b0 "
               "foot_origin=(%.0f, %.0f, %.0f) age=%llums",
               remote.pos[0], remote.pos[1], remote.pos[2] + PELVIS_BIAS,
               r_yaw * 57.29578f,
               cb.eye_world[0], cb.eye_world[1], cb.eye_world[2],
               static_cast<unsigned long long>(age_ms));
        FW_DBG("[body] VP=%s (capture hits=%llu)  eye=(%.0f, %.0f, %.0f) "
               "yaw=%.1f\u00b0 pitch=%.1f\u00b0",
               got_captured_vp ? "CAPTURED_SCENE_VP" : "self-built-fallback",
               static_cast<unsigned long long>(fw::render::vp_capture_hit_count()),
               eye[0], eye[1], eye[2],
               yaw * 57.29578f, pitch * 57.29578f);
        FW_DBG("[body] game_vp row0=[%7.3f %7.3f %7.3f %10.2f] "
               "row1=[%7.3f %7.3f %7.3f %10.2f]",
               cb.game_vp[0], cb.game_vp[1], cb.game_vp[2], cb.game_vp[3],
               cb.game_vp[4], cb.game_vp[5], cb.game_vp[6], cb.game_vp[7]);
        FW_DBG("[body] game_vp row2=[%7.3f %7.3f %7.3f %10.2f] "
               "row3=[%7.3f %7.3f %7.3f %10.2f]",
               cb.game_vp[8],  cb.game_vp[9],  cb.game_vp[10], cb.game_vp[11],
               cb.game_vp[12], cb.game_vp[13], cb.game_vp[14], cb.game_vp[15]);

        // Predict NDC for body origin — mirrors the shader (col-vec
        // math with our self-built column-major VP). cb.game_vp is
        // stored column-major so M[i][j] lives at mem[j*4+i].
        const float prx = remote.pos[0] - cb.eye_world[0];
        const float pry = remote.pos[1] - cb.eye_world[1];
        const float prz = (remote.pos[2] + PELVIS_BIAS) - cb.eye_world[2];
        auto row_dot = [&](int i) {
            return cb.game_vp[i]    * prx +
                   cb.game_vp[i+4]  * pry +
                   cb.game_vp[i+8]  * prz +
                   cb.game_vp[i+12] * 1.0f;
        };
        const float cx = row_dot(0);
        const float cy = row_dot(1);
        const float cz = row_dot(2);
        const float cw = row_dot(3);
        FW_DBG("[body] PREDICT pos_rel=(%.1f, %.1f, %.1f) clip=(%.1f, %.1f, %.1f, %.1f)",
               prx, pry, prz, cx, cy, cz, cw);
        if (std::fabs(cw) > 1e-3f) {
            const float ndx = cx / cw;
            const float ndy = cy / cw;
            const float ndz = cz / cw;
            FW_DBG("[body] PREDICT NDC=(%.3f, %.3f, %.3f)  %s",
                   ndx, ndy, ndz,
                   (std::fabs(ndx) <= 1.0f && std::fabs(ndy) <= 1.0f &&
                    ndz >= 0.0f && ndz <= 1.0f && cw > 0.0f)
                       ? "\u2192 ON-SCREEN VISIBLE"
                       : "\u2192 OFF-SCREEN / CLIPPED");
        } else {
            FW_DBG("[body] PREDICT NDC: w=0 (degenerate, likely at camera origin)");
        }
    }

    D3D11_MAPPED_SUBRESOURCE mapped{};
    const HRESULT hr = g_body.context->Map(
        g_body.camera_cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(hr)) {
        FW_DBG("[body] camera CB Map failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        return false;
    }
    std::memcpy(mapped.pData, &cb, sizeof(cb));
    g_body.context->Unmap(g_body.camera_cb, 0);
    return true;
}

// Map + fill the bone palette CB with 64 identity matrices (T-pose).
// β.4 MVP uses identity for every bone; γ will replace this with
// animated bone transforms from HKX clips. Returns false on Map fail.
bool update_bone_cb_identity()
{
    D3D11_MAPPED_SUBRESOURCE mapped{};
    const HRESULT hr = g_body.context->Map(
        g_body.bone_cb, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(hr)) {
        FW_DBG("[body] bone CB Map failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        return false;
    }
    auto* dst = static_cast<BonePaletteCB*>(mapped.pData);
    for (std::uint32_t i = 0; i < kMaxBones; ++i) {
        mat_identity(dst->bones[i]);
    }
    g_body.context->Unmap(g_body.bone_cb, 0);
    return true;
}

// -----------------------------------------------------------------------
// GPU upload: build D3D11_USAGE_IMMUTABLE VB + IB from the held asset.
//
// IMMUTABLE is the right choice: the mesh geometry is static (bind
// pose), never changes on CPU. Bones animate via a separate constant
// buffer (β.3) without touching the VB. Keeping the VB immutable lets
// the driver place it in optimal GPU memory.
//
// Returns true on full success (both buffers created, stats logged),
// false on any failure (partial cleanup done internally).
// -----------------------------------------------------------------------
bool upload_to_gpu(ID3D11Device* dev) {
    if (!dev) {
        FW_ERR("[body] upload: null device");
        return false;
    }
    if (!g_body.asset) {
        FW_ERR("[body] upload: no CPU asset to upload");
        return false;
    }

    const auto& a = *g_body.asset;
    g_body.vertex_count = static_cast<std::uint32_t>(a.vertices.size());
    g_body.index_count  = static_cast<std::uint32_t>(a.index_count());
    g_body.bone_count   = static_cast<std::uint32_t>(a.bones.size());
    g_body.flags        = a.flags;
    g_body.uses_u32     = a.uses_u32_indices();

    if (g_body.vertex_count == 0 || g_body.index_count == 0) {
        FW_ERR("[body] upload: empty mesh (v=%u i=%u) — cannot create buffers",
               g_body.vertex_count, g_body.index_count);
        return false;
    }

    // -- vertex buffer --
    const UINT vb_bytes = static_cast<UINT>(
        static_cast<std::uint64_t>(g_body.vertex_count) *
        sizeof(fw::assets::MeshVertex));

    D3D11_BUFFER_DESC vb_desc{};
    vb_desc.Usage     = D3D11_USAGE_IMMUTABLE;
    vb_desc.ByteWidth = vb_bytes;
    vb_desc.BindFlags = D3D11_BIND_VERTEX_BUFFER;

    D3D11_SUBRESOURCE_DATA vb_init{};
    vb_init.pSysMem = a.vertices.data();

    HRESULT hr = dev->CreateBuffer(&vb_desc, &vb_init, &g_body.vertex_buffer);
    if (FAILED(hr) || !g_body.vertex_buffer) {
        FW_ERR("[body] CreateBuffer(VB) failed hr=0x%08lX bytes=%u",
               static_cast<unsigned long>(hr), vb_bytes);
        return false;
    }

    // -- index buffer --
    const UINT ib_stride = g_body.uses_u32 ? 4u : 2u;
    const UINT ib_bytes  = static_cast<UINT>(
        static_cast<std::uint64_t>(g_body.index_count) * ib_stride);

    D3D11_BUFFER_DESC ib_desc{};
    ib_desc.Usage     = D3D11_USAGE_IMMUTABLE;
    ib_desc.ByteWidth = ib_bytes;
    ib_desc.BindFlags = D3D11_BIND_INDEX_BUFFER;

    D3D11_SUBRESOURCE_DATA ib_init{};
    ib_init.pSysMem = g_body.uses_u32
        ? static_cast<const void*>(a.indices_u32.data())
        : static_cast<const void*>(a.indices_u16.data());

    hr = dev->CreateBuffer(&ib_desc, &ib_init, &g_body.index_buffer);
    if (FAILED(hr) || !g_body.index_buffer) {
        FW_ERR("[body] CreateBuffer(IB) failed hr=0x%08lX bytes=%u stride=%u",
               static_cast<unsigned long>(hr), ib_bytes, ib_stride);
        safe_release(g_body.vertex_buffer);
        return false;
    }

    FW_LOG("[body] GPU upload OK: "
           "VB=%u B (%u verts x 64B), IB=%u B (%u idx x %uB, %s), "
           "bones=%u, submeshes=%zu, flags=0x%X "
           "(skinned=%d normals=%d uvs=%d)",
           vb_bytes, g_body.vertex_count,
           ib_bytes, g_body.index_count, ib_stride,
           g_body.uses_u32 ? "u32" : "u16",
           g_body.bone_count, a.submeshes.size(), g_body.flags,
           (g_body.flags & 0x1) ? 1 : 0,
           (g_body.flags & 0x2) ? 1 : 0,
           (g_body.flags & 0x4) ? 1 : 0);

    // β.6-orient diagnostic: scan the bind-pose vertex AABB so we can
    // reason about the mesh-local axis convention. Expected for a standing
    // humanoid in NIF default convention (+Z up, +Y forward):
    //   x: ~[-40, +40]     (shoulder span / arm extents in T-pose)
    //   y: ~[-20, +20]     (forward-depth, body thickness)
    //   z: ~[-60, +100]    (pelvis to head)
    // If instead y has the ~100 span and z is tiny, the body is rotated
    // ~90° around X — i.e., "laying face-up" in shape-local → needs
    // root correction to stand up.
    if (!a.vertices.empty()) {
        float x_min = a.vertices[0].position[0], x_max = x_min;
        float y_min = a.vertices[0].position[1], y_max = y_min;
        float z_min = a.vertices[0].position[2], z_max = z_min;
        for (const auto& v : a.vertices) {
            if (v.position[0] < x_min) x_min = v.position[0];
            if (v.position[0] > x_max) x_max = v.position[0];
            if (v.position[1] < y_min) y_min = v.position[1];
            if (v.position[1] > y_max) y_max = v.position[1];
            if (v.position[2] < z_min) z_min = v.position[2];
            if (v.position[2] > z_max) z_max = v.position[2];
        }
        const float x_span = x_max - x_min;
        const float y_span = y_max - y_min;
        const float z_span = z_max - z_min;
        FW_LOG("[body] mesh-local AABB: "
               "x=[%.1f, %.1f] span=%.1f  "
               "y=[%.1f, %.1f] span=%.1f  "
               "z=[%.1f, %.1f] span=%.1f",
               x_min, x_max, x_span,
               y_min, y_max, y_span,
               z_min, z_max, z_span);
        const char* likely_up_axis =
            (z_span >= x_span && z_span >= y_span) ? "+Z (standard NIF)" :
            (y_span >= x_span && y_span >= z_span) ? "+Y (needs +90\u00b0 X fix)" :
                                                      "+X (unusual)";
        FW_LOG("[body] likely \"height\" axis (longest span) = %s",
               likely_up_axis);

        // β.6 RESET: dump a few sample vertices so we can correlate
        // mesh-local coords to bone indices and weights. If the body
        // renders "laying flat" with identity bones, it's because the
        // vertex data assumes a specific root-bone transform; sampling
        // reveals WHICH vertex is which body part.
        const auto dump_v = [&](std::size_t idx, const char* tag) {
            if (idx >= a.vertices.size()) return;
            const auto& v = a.vertices[idx];
            FW_LOG("[body]   %s vtx[%zu]: pos=(%.2f, %.2f, %.2f) "
                   "bone_idx=(%u,%u,%u,%u) bone_w=(%.2f,%.2f,%.2f,%.2f)",
                   tag, idx,
                   v.position[0], v.position[1], v.position[2],
                   v.bone_idx[0], v.bone_idx[1], v.bone_idx[2], v.bone_idx[3],
                   v.bone_weights[0], v.bone_weights[1],
                   v.bone_weights[2], v.bone_weights[3]);
        };
        // First vertex, middle, last, plus whichever vertex has min/max z.
        dump_v(0, "first");
        dump_v(a.vertices.size() / 2, "middle");
        dump_v(a.vertices.size() - 1, "last");
        // Vertex with highest and lowest z (head-like and foot-like).
        std::size_t idx_zmax = 0, idx_zmin = 0;
        for (std::size_t i = 1; i < a.vertices.size(); ++i) {
            if (a.vertices[i].position[2] > a.vertices[idx_zmax].position[2])
                idx_zmax = i;
            if (a.vertices[i].position[2] < a.vertices[idx_zmin].position[2])
                idx_zmin = i;
        }
        dump_v(idx_zmax, "z_max  ");
        dump_v(idx_zmin, "z_min  ");
    }
    return true;
}

// -----------------------------------------------------------------------
// β.4 — draw the skinned body into the swapchain's back buffer.
//
// State save/restore protocol: we save a generous set of pipeline state
// objects, overwrite them with ours for the draw, then restore. Missing
// any one of these causes the game's next frame to glitch (wrong
// shader bound, missing RTV, etc.). Pattern mirrors draw_triangle's
// approach, extended for:
//   - two constant buffers (camera b0, bone palette b1)
//   - index buffer (IAGetIndexBuffer / IASetIndexBuffer)
//
// We do NOT save/restore compute/geometry/hull/domain shaders — the
// game's post-UI compositing pass doesn't use them at the Present
// boundary. If that changes we add more saves here.
// -----------------------------------------------------------------------
void draw_skinned_body(IDXGISwapChain* swap)
{
    // --- per-frame RTV for this swapchain's current back buffer ---
    ID3D11Texture2D* back_buffer = nullptr;
    HRESULT hr = swap->GetBuffer(0, __uuidof(ID3D11Texture2D),
                                  reinterpret_cast<void**>(&back_buffer));
    if (FAILED(hr) || !back_buffer) {
        FW_DBG("[body] GetBuffer(0) failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        return;
    }
    ID3D11RenderTargetView* rtv = nullptr;
    hr = g_body.device->CreateRenderTargetView(back_buffer, nullptr, &rtv);
    if (FAILED(hr) || !rtv) {
        FW_DBG("[body] CreateRTV failed hr=0x%08lX",
               static_cast<unsigned long>(hr));
        safe_release(back_buffer);
        return;
    }

    D3D11_TEXTURE2D_DESC bb_desc{};
    back_buffer->GetDesc(&bb_desc);
    const UINT width  = bb_desc.Width;
    const UINT height = bb_desc.Height;

    // β.6: tell the DSV capture module what "scene-sized" means, so it
    // can filter out shadow maps and half-res post DSVs from the
    // OMSetRenderTargets hook. Cheap — two atomic stores.
    set_expected_dsv_size(width, height);

    // --- fill CBs for this frame ---
    if (!update_camera_cb(width, height) || !update_bone_cb_identity()) {
        safe_release(rtv);
        safe_release(back_buffer);
        return;
    }

    auto* ctx = g_body.context;

    // --- save game state ---
    ID3D11RenderTargetView* saved_rtvs[8]{};
    ID3D11DepthStencilView* saved_dsv = nullptr;
    ctx->OMGetRenderTargets(8, saved_rtvs, &saved_dsv);

    UINT saved_vp_count = 1;
    D3D11_VIEWPORT saved_vps[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
    ctx->RSGetViewports(&saved_vp_count, saved_vps);

    D3D11_PRIMITIVE_TOPOLOGY saved_topo;
    ctx->IAGetPrimitiveTopology(&saved_topo);

    ID3D11InputLayout* saved_layout = nullptr;
    ctx->IAGetInputLayout(&saved_layout);

    ID3D11VertexShader* saved_vs = nullptr;
    ctx->VSGetShader(&saved_vs, nullptr, nullptr);
    ID3D11PixelShader* saved_ps = nullptr;
    ctx->PSGetShader(&saved_ps, nullptr, nullptr);

    ID3D11Buffer* saved_vb = nullptr;
    UINT saved_vb_stride = 0, saved_vb_offset = 0;
    ctx->IAGetVertexBuffers(0, 1, &saved_vb, &saved_vb_stride, &saved_vb_offset);

    ID3D11Buffer*  saved_ib = nullptr;
    DXGI_FORMAT    saved_ib_fmt = DXGI_FORMAT_UNKNOWN;
    UINT           saved_ib_offset = 0;
    ctx->IAGetIndexBuffer(&saved_ib, &saved_ib_fmt, &saved_ib_offset);

    ID3D11Buffer* saved_cbs[2] = { nullptr, nullptr };
    ctx->VSGetConstantBuffers(0, 2, saved_cbs);

    ID3D11BlendState* saved_bs = nullptr;
    float             saved_bf[4];
    UINT              saved_sm;
    ctx->OMGetBlendState(&saved_bs, saved_bf, &saved_sm);

    ID3D11DepthStencilState* saved_dss = nullptr;
    UINT                     saved_sr;
    ctx->OMGetDepthStencilState(&saved_dss, &saved_sr);

    ID3D11RasterizerState* saved_rs = nullptr;
    ctx->RSGetState(&saved_rs);

    // --- bind our pipeline ---
    D3D11_VIEWPORT vp{};
    vp.Width    = static_cast<float>(width);
    vp.Height   = static_cast<float>(height);
    vp.MaxDepth = 1.0f;
    ctx->RSSetViewports(1, &vp);
    ctx->RSSetState(g_body.rs);

    const float blend_factor[4] = { 0, 0, 0, 0 };
    ctx->OMSetBlendState(g_body.bs, blend_factor, 0xFFFFFFFFu);
    ctx->OMSetDepthStencilState(g_body.dss, 0);

    // β.6: pull the scene DSV captured by our OMSetRenderTargets detour
    // during the game's 3D pass. It arrives AddRef'd; we Release after
    // the draw. If the hook hasn't fired yet (very first Present, or
    // install failed) we fall back to no-depth rendering.
    ID3D11DepthStencilView* scene_dsv = acquire_scene_dsv();

    static bool dsv_probe_logged = false;
    if (!dsv_probe_logged && scene_dsv) {
        dsv_probe_logged = true;
        ID3D11Resource* res = nullptr;
        scene_dsv->GetResource(&res);
        UINT w = 0, h = 0;
        if (res) {
            ID3D11Texture2D* tex = nullptr;
            if (SUCCEEDED(res->QueryInterface(
                    __uuidof(ID3D11Texture2D),
                    reinterpret_cast<void**>(&tex))) && tex) {
                D3D11_TEXTURE2D_DESC td{};
                tex->GetDesc(&td);
                w = td.Width;
                h = td.Height;
                tex->Release();
            }
            res->Release();
        }
        FW_LOG("[body] \u03b2.6 scene DSV captured: %p size=%ux%u "
               "backbuffer=%ux%u \u2192 depth occlusion active",
               static_cast<void*>(scene_dsv), w, h, width, height);
    }

    ctx->OMSetRenderTargets(1, &rtv, scene_dsv);

    ctx->IASetInputLayout(g_body.input_layout);
    ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);

    const UINT stride = sizeof(fw::assets::MeshVertex);   // 64
    const UINT offset = 0;
    ctx->IASetVertexBuffers(0, 1, &g_body.vertex_buffer, &stride, &offset);

    const DXGI_FORMAT ib_fmt = g_body.uses_u32
        ? DXGI_FORMAT_R32_UINT
        : DXGI_FORMAT_R16_UINT;
    ctx->IASetIndexBuffer(g_body.index_buffer, ib_fmt, 0);

    ctx->VSSetShader(g_body.vs, nullptr, 0);
    ID3D11Buffer* cbs[2] = { g_body.camera_cb, g_body.bone_cb };
    ctx->VSSetConstantBuffers(0, 2, cbs);
    ctx->PSSetShader(g_body.ps, nullptr, 0);

    // --- draw body ---
    ctx->DrawIndexed(g_body.index_count, 0, 0);

    // --- β.6 draw head placeholder (sphere at neck) ---
    // Shares the current RTV/DSV/viewport. draw_head saves+restores
    // its own VS/PS/IA state so body state doesn't leak after us.
    if (g_body.head_ready) {
        fw::render::draw_head(ctx,
                              g_body.last_game_vp,
                              g_body.last_eye_world,
                              g_body.last_anchor,
                              g_body.last_yaw);
    }

    // --- restore game state (reverse of save) ---
    ctx->RSSetState(saved_rs);
    safe_release(saved_rs);
    ctx->OMSetDepthStencilState(saved_dss, saved_sr);
    safe_release(saved_dss);
    ctx->OMSetBlendState(saved_bs, saved_bf, saved_sm);
    safe_release(saved_bs);
    ctx->VSSetConstantBuffers(0, 2, saved_cbs);
    for (auto*& c : saved_cbs) safe_release(c);
    ctx->IASetIndexBuffer(saved_ib, saved_ib_fmt, saved_ib_offset);
    safe_release(saved_ib);
    ctx->IASetVertexBuffers(0, 1, &saved_vb, &saved_vb_stride, &saved_vb_offset);
    safe_release(saved_vb);
    ctx->PSSetShader(saved_ps, nullptr, 0);
    safe_release(saved_ps);
    ctx->VSSetShader(saved_vs, nullptr, 0);
    safe_release(saved_vs);
    ctx->IASetInputLayout(saved_layout);
    safe_release(saved_layout);
    ctx->IASetPrimitiveTopology(saved_topo);
    ctx->RSSetViewports(saved_vp_count, saved_vps);
    ctx->OMSetRenderTargets(8, saved_rtvs, saved_dsv);
    for (auto*& t : saved_rtvs) safe_release(t);
    safe_release(saved_dsv);

    // --- per-frame cleanup ---
    safe_release(rtv);
    safe_release(back_buffer);
    safe_release(scene_dsv);   // AddRef'd by acquire_scene_dsv
}

} // namespace

// =======================================================================
// Public API
// =======================================================================

bool init_body_asset(const std::filesystem::path& fwn_path) {
    if (g_body.asset_ready.load(std::memory_order_acquire)) {
        FW_WRN("[body] init_body_asset called twice — ignoring second call "
               "(first asset retained)");
        return true;
    }

    auto opt = fw::assets::load_fwn(fwn_path);
    if (!opt) {
        FW_ERR("[body] init_body_asset: load_fwn('%s') failed",
               fwn_path.string().c_str());
        return false;
    }

    // Move the parsed asset into the body state. MeshAsset holds
    // std::vector members — move is O(1) pointer swap, no copy.
    g_body.asset = std::move(*opt);

    // Publish: release fence so the render thread sees a fully
    // constructed std::optional<MeshAsset> with its vectors committed.
    g_body.asset_ready.store(true, std::memory_order_release);

    FW_LOG("[body] CPU asset retained (awaiting GPU upload on first frame): "
           "verts=%zu idx=%zu bones=%zu subm=%zu",
           g_body.asset->vertices.size(),
           g_body.asset->index_count(),
           g_body.asset->bones.size(),
           g_body.asset->submeshes.size());
    return true;
}

void draw_body(IDXGISwapChain* swap) {
    // Cheap early-outs (hot path: runs every frame).
    if (!g_body.asset_ready.load(std::memory_order_acquire)) return;
    if (g_body.upload_failed) return;

    ++g_body.frames_seen;

    // First-frame upload path — SEH-guarded because we touch COM
    // pointers whose lifetime is owned by the game.
    if (!g_body.uploaded) {
        if (!swap) return;

        ID3D11Device* dev = nullptr;
        HRESULT hr = S_OK;
        __try {
            hr = swap->GetDevice(
                __uuidof(ID3D11Device),
                reinterpret_cast<void**>(&dev));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[body] upload: SEH in swap->GetDevice");
            g_body.upload_failed = true;
            return;
        }
        if (FAILED(hr) || !dev) {
            FW_ERR("[body] upload: GetDevice failed hr=0x%08lX",
                   static_cast<unsigned long>(hr));
            g_body.upload_failed = true;
            return;
        }

        g_body.device = dev;    // retained (dev already AddRef'd by GetDevice)
        g_body.device->GetImmediateContext(&g_body.context);

        if (!upload_to_gpu(g_body.device)) {
            FW_ERR("[body] GPU upload failed — disabling body render");
            safe_release(g_body.index_buffer);
            safe_release(g_body.vertex_buffer);
            safe_release(g_body.context);
            safe_release(g_body.device);
            g_body.upload_failed = true;
            return;
        }
        g_body.uploaded = true;

        // β.2: compile shaders and build input layout.
        if (!init_pipeline_state(g_body.device)) {
            FW_ERR("[body] pipeline init failed — body draw disabled");
            release_body_resources();
            g_body.upload_failed = true;
            return;
        }

        // β.3+β.4: create dynamic CBs (camera @ b0, bones @ b1) and the
        // fixed-function state objects (depth/raster/blend). From here
        // on draw_skinned_body() is wired up for per-frame execution.
        if (!init_state_and_cbs(g_body.device)) {
            FW_ERR("[body] state/CBs init failed — body draw disabled");
            release_body_resources();
            g_body.upload_failed = true;
            return;
        }

        // β.6: install OMSetRenderTargets vtable hook so we can capture
        // the game's scene DSV during its 3D pass (it's unbound by the
        // time Present fires). Non-fatal: if install fails, body draws
        // without depth test = back to post-it mode.
        if (!install_dsv_capture(g_body.context)) {
            FW_WRN("[body] DSV capture hook install failed — body will "
                   "render without depth occlusion (pre-\u03b2.6 look)");
        }

        g_body.pipeline_ready = true;

        // β.6 head placeholder: build sphere mesh + shader now that
        // we have device/context. Non-fatal if it fails — body still
        // renders, just headless.
        if (fw::render::init_head_placeholder(g_body.device, g_body.context)) {
            g_body.head_ready = true;
            FW_LOG("[body] head placeholder ready (sphere, neck attach)");
        } else {
            FW_WRN("[body] head placeholder init failed \u2014 body will "
                   "render without head");
        }

        g_body.cached_swapchain = swap;
        const auto module_base = reinterpret_cast<std::uintptr_t>(
            GetModuleHandleW(L"Fallout4.exe"));

        // β.6 legacy hook (depth capture / scene integration reserved
        // for future use — body draw via it is no-op).
        (void)install_scene_render_hook(module_base);
        g_body.scene_hook_active = false;

        // β.6 VP capture DISABLED (2026-04-22). Three attempts exhausted:
        //   1. sub_1421DC480 producer: hook never fired (vtable gate).
        //   2. sub_14221E6A0 consumer @ +0x17C: garbage data.
        //   3. sub_14221E6A0 consumer @ +0x1A0 / +0x200: varies per
        //      accumulator, mostly shadow/cubemap cameras not scene VP.
        // Live memory dumps revealed BSShaderAccumulator struct layout
        // is NOT stable across accumulators — each call has different
        // offsets for the matrix. No reliable way to filter the "scene"
        // accumulator from shadow/reflection without deeper RE.
        //
        // Accepting shake as known limit for now. Body uses self-built
        // VP (visible + sync + pitch correct + shake when walking).
        // Will revisit once we have animation pipeline landed (γ) and
        // more rendering context.
        (void)module_base;  // would be used by install_vp_capture
        FW_LOG("[body] VP capture path DISABLED — using self-built VP "
               "(body visible with known shake limit)");

        FW_LOG("[body] first-frame init complete on frame #%llu — "
               "draw path ARMED (identity bones / T-pose)",
               static_cast<unsigned long long>(g_body.frames_seen));
        // Fall through: we also draw on this frame via the fallback
        // path below (scene hook hasn't fired yet for this frame).
    }

    // --- per-frame skinned draw ---
    if (!g_body.pipeline_ready) return;

    // β.6 gate: if the scene-render hook is active, the body draw
    // happens from sub_140C38F80's trailing edge (see
    // draw_body_at_scene_end). Skip the Present-time draw to avoid
    // drawing TWICE per frame.
    if (g_body.scene_hook_active) {
        // Periodic heartbeat so we know Present is still hooked/alive.
        if (g_body.frames_seen == 1 ||
            (g_body.frames_seen % 1800) == 0)
        {
            FW_DBG("[body] Present: scene hook active — delegating draw "
                   "to sub_140C38F80 detour (frame=%llu)",
                   static_cast<unsigned long long>(g_body.frames_seen));
        }
        return;
    }

    // Fallback path: scene hook install failed. Draw at Present anyway
    // so the body is at least visible (with shake).

    __try {
        draw_skinned_body(swap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Render-thread exception must not cascade into the game.
        // Disable body draw and log once — we'll need a manual restart
        // if this fires.
        if (!g_body.upload_failed) {
            FW_ERR("[body] SEH in draw_skinned_body — disabling body render");
            g_body.upload_failed = true;
        }
    }

    if (g_body.frames_seen == 1 ||
        (g_body.frames_seen % 1800) == 0)   // ~30 s at 60 fps
    {
        FW_DBG("[body] draw heartbeat frame=%llu idx=%u",
               static_cast<unsigned long long>(g_body.frames_seen),
               g_body.index_count);
    }
}

// -----------------------------------------------------------------------
// β.6 NEW — scene-render-time body draw. Invoked from the scene hook
// (sub_140C38F80 trailing edge). Gets into the game's render frame
// between "all scene actors drawn" and "UI composed" — the sweet spot
// where D3D state, VP matrix, and depth buffer are all frame-accurate.
// -----------------------------------------------------------------------
void draw_body_at_scene_end() {
    if (!g_body.asset_ready.load(std::memory_order_acquire)) return;
    if (g_body.upload_failed) return;
    if (!g_body.pipeline_ready) return;
    if (!g_body.scene_hook_active) return;
    if (!g_body.cached_swapchain) return;

    // Same draw as the Present-path fallback — just at a better point
    // in the frame. update_camera_cb() inside will (in the next step)
    // read NiCamera+0x120 directly for frame-accurate VP.
    __try {
        draw_skinned_body(g_body.cached_swapchain);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (!g_body.upload_failed) {
            FW_ERR("[body] SEH in draw_body_at_scene_end — disabling");
            g_body.upload_failed = true;
        }
    }
}

void release_body_resources() {
    // β.6: release head resources first (they share device with body).
    fw::render::release_head_resources();

    // β.6: release the cached scene DSV BEFORE we release the context
    // (cached DSV references objects created from the same device).
    release_cached_dsv();

    // Release order: draw state → CBs → pipeline state → buffers →
    // context → device. Reverse creation order.
    safe_release(g_body.bs);
    safe_release(g_body.rs);
    safe_release(g_body.dss);
    safe_release(g_body.bone_cb);
    safe_release(g_body.camera_cb);
    safe_release(g_body.input_layout);
    safe_release(g_body.ps);
    safe_release(g_body.vs);
    safe_release(g_body.index_buffer);
    safe_release(g_body.vertex_buffer);
    safe_release(g_body.context);
    safe_release(g_body.device);
    g_body.uploaded        = false;
    g_body.pipeline_ready  = false;
    g_body.upload_failed   = false;
    g_body.vertex_count = g_body.index_count = 0;
    g_body.bone_count = g_body.flags = 0;
    g_body.uses_u32 = false;
    // Flip the ready flag BEFORE dropping the optional so any in-flight
    // render-thread read either sees "not ready" (bails early) or the
    // valid optional (completes its read before we destroy).
    g_body.asset_ready.store(false, std::memory_order_release);
    g_body.asset.reset();
    FW_DBG("[body] resources released");
}

} // namespace fw::render
