// nametags — implementation. The why is in nametags.h.

#include "nametags.h"

#include <windows.h>

#include <cfloat>
#include <cmath>
#include <string>
#include <unordered_set>
#include <vector>

#include "imgui.h"

#include "overlay.h"
#include "../log.h"
#include "../offsets.h"
#include "../engine/engine_calls.h"
#include "../native/appearance_recipe.h"
#include "../native/ni_offsets.h"
#include "../native/scene_inject.h"
#include "../net/peer_names.h"

namespace fw::render::nametags {

namespace {

namespace off = fw::offsets;
namespace ni  = fw::native;

// Above the Head joint. The first guess was 31: about 10 units to the top of
// the skull plus 21 for the 30 cm the user asked for (1 unit is about
// 1.43 cm). Seen live on 2026-09-23 it sat a whole head too high, and the
// user asked for exactly half. Tuned by eye, which is the only instrument
// that counts for this number.
constexpr float kLiftUnits = 15.5f;
// Not drawn beyond 4200 units, about 60 m; the last 15% fades out.
constexpr float kMaxDistUnits = 4200.0f;
constexpr float kFadeFrom     = 0.85f;

// NiCamera::port, NiRect<float> {left, right, top, bottom}. After the frustum
// (+0x160, 0x1C bytes) come minNearPlaneDist (+0x17C) and maxFarNearRatio
// (+0x180) in CommonLibF4's layout, the same source offsets.h follows for the
// fields before it. Not otherwise proven, so it is only used when it holds a
// sane normalised rectangle; the full screen is the fallback, and the
// one-shot log prints what was read.
constexpr std::size_t kNiCameraPortOff = 0x184;

struct Camera {
    void* node     = nullptr;
    float eye[3]   = {};
    float fwd[3]   = {};   // row 0 of the world rotation: where the camera looks
    float up[3]    = {};   // row 1
    float right[3] = {};   // row 2
    float l = 0.0f, r = 0.0f, t = 0.0f, b = 0.0f, n = 0.0f;
    bool  ortho    = false;
    bool  port_ok  = false;
    float port[4]  = {0.0f, 1.0f, 1.0f, 0.0f};   // left, right, top, bottom
};

// This frame's heads, taken by wants_frame and drawn by draw.
std::vector<ni::GhostHeadAnchor> g_frame;
// Peers whose first tag has been logged, and the next periodic log.
std::unordered_set<std::string> g_logged;
bool      g_camera_logged = false;
bool      g_camera_failed_logged = false;
ULONGLONG g_next_dbg_ms = 0;

// POD-only, every engine read under SEH.
//
// THE AXES, from the engine's own code and not from Gamebryo's manual. The
// first build of this file took Gamebryo's convention — camera axes are the
// COLUMNS of the world rotation — and the tag moved with the camera: a
// transposed rotation is an error that rotates with the view, which is the
// symptom the user reported on 2026-09-23: the tag followed the player's view.
//
// NiCamera::WindowPointToRay in this binary (sub_1416D0CA0, RVA 0x16D0CA0)
// builds the ray through a pixel as
//
//     dir = row0 + fY * row1 + fX * row2
//
// where fX runs over the frustum's left..right and fY over bottom..top, and
// row i is the i-th 16-byte NiPoint4 of the world rotation at +0x70. And
// NiCamera::LookAt (sub_1416D0840) writes normalise(target - eye) into row 0
// of the local rotation, the up vector into row 1 and the right vector into
// row 2. So here the ROWS are the axes: row 0 forward, row 1 up, row 2 right.
bool read_camera(std::uintptr_t base, Camera& c) noexcept {
    __try {
        const auto* sg = *reinterpret_cast<std::uint8_t* const*>(
            base + ni::WORLD_SG_SINGLETON_RVA);
        if (!sg) return false;
        auto* cam = *reinterpret_cast<std::uint8_t* const*>(
            sg + ni::SCENEGRAPH_ROOT_CAMERA_OFF);
        if (!cam) return false;
        if (*reinterpret_cast<const std::uintptr_t*>(cam) !=
            base + off::NI_CAMERA_VTABLE_RVA) {
            return false;
        }
        c.node = cam;
        const float* rot =
            reinterpret_cast<const float*>(cam + ni::NIAV_WORLD_ROTATE_OFF);
        for (int j = 0; j < 3; ++j) {
            c.fwd[j]   = rot[0 * 4 + j];   // row 0
            c.up[j]    = rot[1 * 4 + j];   // row 1
            c.right[j] = rot[2 * 4 + j];   // row 2
        }
        const float* tr =
            reinterpret_cast<const float*>(cam + ni::NIAV_WORLD_TRANSLATE_OFF);
        c.eye[0] = tr[0]; c.eye[1] = tr[1]; c.eye[2] = tr[2];
        const float* fr =
            reinterpret_cast<const float*>(cam + off::NI_CAMERA_FRUSTUM_OFF);
        c.l = fr[0]; c.r = fr[1]; c.t = fr[2]; c.b = fr[3]; c.n = fr[4];
        c.ortho = cam[off::NI_CAMERA_FRUSTUM_OFF + off::NI_FRUSTUM_ORTHO_OFF] != 0;
        const float* pt = reinterpret_cast<const float*>(cam + kNiCameraPortOff);
        c.port_ok = pt[0] >= 0.0f && pt[1] <= 1.0f && pt[0] < pt[1] &&
                    pt[3] >= 0.0f && pt[2] <= 1.0f && pt[3] < pt[2];
        if (c.port_ok) {
            c.port[0] = pt[0]; c.port[1] = pt[1];
            c.port[2] = pt[2]; c.port[3] = pt[3];
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool read_vec3(const void* obj, std::size_t at, float out[3]) noexcept {
    if (!obj) return false;
    __try {
        const float* v = reinterpret_cast<const float*>(
            static_cast<const std::uint8_t*>(obj) + at);
        out[0] = v[0]; out[1] = v[1]; out[2] = v[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void* read_ptr(std::uintptr_t at) noexcept {
    __try { return *reinterpret_cast<void* const*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

float dot3(const float a[3], const float b[3]) {
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
}

// THE INDEPENDENT CHECK: the engine's own NiCamera::WindowPointToRay
// (sub_1416D0CA0), the function the axis convention above was read from.
// Given a pixel it returns the ray the engine would shoot through it: origin
// (the camera's world translate) and a unit direction. Pure arithmetic on the
// camera object — port, frustum, rotation, translation — no allocation, no
// lock. Returns 0 when the pixel lies outside the port.
//
// Used only for the log: the ray through the pixel where a tag is drawn must
// pass through the tag's anchor. If it does, this file's projection and the
// engine's agree, and a tag that still looks wrong is a wrong anchor, not a
// wrong camera.
constexpr std::uintptr_t NICAMERA_WINDOW_POINT_TO_RAY_RVA = 0x016D0CA0;
using WindowPointToRayFn = char(*)(void* cam, int px, int py, float* origin,
                                   float* dir, float width, float height);

bool engine_ray(std::uintptr_t base, void* cam, int px, int py, float W,
                float H, float origin[3], float dir[3]) noexcept {
    if (!base || !cam) return false;
    __try {
        auto fn = reinterpret_cast<WindowPointToRayFn>(
            base + NICAMERA_WINDOW_POINT_TO_RAY_RVA);
        return fn(cam, px, py, origin, dir, W, H) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Distance from a point to the engine's ray through a pixel, or -1 when the
// engine refused the pixel or the call faulted.
float ray_miss(std::uintptr_t base, const Camera& c, float sx, float sy,
               float W, float H, const float p[3]) {
    float o[3] = {}, d[3] = {};
    if (!engine_ray(base, c.node, static_cast<int>(sx + 0.5f),
                    static_cast<int>(sy + 0.5f), W, H, o, d)) {
        return -1.0f;
    }
    const float v[3] = {p[0] - o[0], p[1] - o[1], p[2] - o[2]};
    const float t = dot3(v, d);
    const float r[3] = {v[0] - t * d[0], v[1] - t * d[1], v[2] - t * d[2]};
    return std::sqrt(dot3(r, r));
}

// World point to screen pixels. False when the point is behind the camera
// (or inside its near plane) or the frustum is unusable.
bool project(const Camera& c, const float p[3], float W, float H,
             float& sx, float& sy, float& dist) {
    const float d[3] = {p[0] - c.eye[0], p[1] - c.eye[1], p[2] - c.eye[2]};
    dist = std::sqrt(dot3(d, d));
    if (c.ortho) return false;   // the world camera is never orthographic
    const float z = dot3(d, c.fwd);
    if (z <= 1.0f || z < c.n) return false;
    if (c.r == c.l || c.t == c.b) return false;
    const float x01 = (dot3(d, c.right) / z - c.l) / (c.r - c.l);
    const float y01 = (dot3(d, c.up) / z - c.b) / (c.t - c.b);
    const float nx = c.port[0] + x01 * (c.port[1] - c.port[0]);
    const float ny = c.port[3] + y01 * (c.port[2] - c.port[3]);
    sx = nx * W;
    sy = (1.0f - ny) * H;
    return true;
}

// Once: which camera, what it holds, and the proof that the axes are right.
// In third person the local player sits near the middle of the screen, so
// their head must project close to the centre and lie almost straight along
// the camera's forward axis. If the axes were wrong this line says so before
// anyone has to describe a tag floating in the wrong place.
void log_camera_once(std::uintptr_t base, const Camera& c, float W, float H) {
    if (g_camera_logged) return;
    g_camera_logged = true;
    const float len = std::sqrt(dot3(c.fwd, c.fwd));
    FW_LOG("[nametag] camera = WorldRoot Camera %p (World SceneGraph +0x140, "
           "vtable checked): eye=(%.1f, %.1f, %.1f) fwd=(%.3f, %.3f, %.3f) "
           "|fwd|=%.3f up=(%.3f, %.3f, %.3f) right=(%.3f, %.3f, %.3f) "
           "frustum l=%.3f r=%.3f t=%.3f b=%.3f near=%.2f ortho=%d "
           "port %s=(%.2f, %.2f, %.2f, %.2f) screen %.0fx%.0f",
           c.node, c.eye[0], c.eye[1], c.eye[2], c.fwd[0], c.fwd[1], c.fwd[2],
           len, c.up[0], c.up[1], c.up[2], c.right[0], c.right[1], c.right[2],
           c.l, c.r, c.t, c.b, c.n, c.ortho ? 1 : 0,
           c.port_ok ? "read" : "FALLBACK", c.port[0], c.port[1], c.port[2],
           c.port[3], W, H);

    // The engine's ray through the centre of the screen must be this file's
    // forward axis: cos = 1.000 or the rows are not the axes after all.
    {
        float o[3] = {}, d[3] = {};
        if (engine_ray(base, c.node, static_cast<int>(W * 0.5f),
                       static_cast<int>(H * 0.5f), W, H, o, d)) {
            FW_LOG("[nametag]   engine WindowPointToRay(centre): origin=(%.1f, "
                   "%.1f, %.1f) dir=(%.3f, %.3f, %.3f), cos(dir, fwd)=%.4f "
                   "(1.0000 = the axes are right)", o[0], o[1], o[2], d[0],
                   d[1], d[2], dot3(d, c.fwd));
        } else {
            FW_WRN("[nametag]   engine WindowPointToRay(centre) refused or "
                   "faulted — no independent check this session");
        }
    }

    // The April-validated render eye (PlayerCamera+0x188), for comparison.
    float buf_eye[3] = {};
    void* pcam = read_ptr(base + off::PLAYER_CAMERA_SINGLETON_RVA);
    if (read_vec3(pcam, off::PLAYER_CAMERA_BUF_POS_OFF, buf_eye)) {
        const float d[3] = {buf_eye[0] - c.eye[0], buf_eye[1] - c.eye[1],
                            buf_eye[2] - c.eye[2]};
        FW_LOG("[nametag]   PlayerCamera+0x188 eye=(%.1f, %.1f, %.1f), %.1f "
               "units from the WorldRoot Camera (0 in first person; the "
               "camera's offset in third)", buf_eye[0], buf_eye[1],
               buf_eye[2], std::sqrt(dot3(d, d)));
    }

    float me[3] = {};
    if (read_vec3(fw::engine::get_local_player(), off::POS_OFF, me)) {
        me[2] += 120.0f;   // roughly the head
        const float d[3] = {me[0] - c.eye[0], me[1] - c.eye[1],
                            me[2] - c.eye[2]};
        const float dl = std::sqrt(dot3(d, d));
        const float along = dl > 1.0f ? dot3(d, c.fwd) / dl : 0.0f;
        float sx = 0.0f, sy = 0.0f, dist = 0.0f;
        const bool on = project(c, me, W, H, sx, sy, dist);
        const float miss = on ? ray_miss(base, c, sx, sy, W, H, me) : -1.0f;
        FW_LOG("[nametag]   self-check: local player's head is %.0f units "
               "away, cos(angle to forward)=%.3f, projects %s (%.0f, %.0f) — "
               "expected in third person: close to 1 and near the centre "
               "(%.0f, %.0f); in first person the head is AT the camera and "
               "does not project. Engine ray through that pixel passes %.1f "
               "units from the head (under 2 = same projection as the engine; "
               "-1 = not checked)", dl, along, on ? "to" : "NOT, would be",
               sx, sy, W * 0.5f, H * 0.5f, miss);
    }
}

void draw_outlined(ImDrawList* dl, ImFont* font, float size, ImVec2 pos,
                   ImU32 fill, ImU32 edge, const char* s) {
    const float o = size >= 22.0f ? 2.0f : 1.0f;
    static constexpr float kDirs[8][2] = {{-1, 0}, {1, 0}, {0, -1}, {0, 1},
                                          {-1, -1}, {1, -1}, {-1, 1}, {1, 1}};
    for (const auto& d : kDirs) {
        dl->AddText(font, size, ImVec2(pos.x + d[0] * o, pos.y + d[1] * o),
                    edge, s);
    }
    dl->AddText(font, size, pos, fill, s);
}

}  // namespace

bool wants_frame(std::uintptr_t module_base) {
    g_frame.clear();
    if (fw::native::appearance::editing()) return false;
    if (!fw::native::ghost_scene_settled()) return false;
    if (fw::render::overlay::in_menu_mode(module_base)) return false;
    g_frame = fw::native::ghost_head_anchors();
    return !g_frame.empty();
}

void draw(std::uintptr_t module_base) {
    if (g_frame.empty()) return;

    Camera cam;
    if (!read_camera(module_base, cam)) {
        if (!g_camera_failed_logged) {
            g_camera_failed_logged = true;
            FW_WRN("[nametag] WorldRoot Camera not readable (null or not a "
                   "NiCamera) — no tags this frame; said once");
        }
        return;
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const float W = vp->Size.x;
    const float H = vp->Size.y;
    log_camera_once(module_base, cam, W, H);

    // 20 px at 1080p. Bold is what makes it readable over any background
    // together with the outline; size only shrinks a quarter with distance
    // so a far name stays legible without shouting when near.
    float base_px = H / 54.0f;
    if (base_px < 13.0f) base_px = 13.0f;
    if (base_px > 32.0f) base_px = 32.0f;

    ImFont* font = fw::render::overlay::tag_font();
    ImFont* measure = font ? font : ImGui::GetFont();
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    const ULONGLONG now = GetTickCount64();
    const bool periodic = now >= g_next_dbg_ms;
    if (periodic) g_next_dbg_ms = now + 30000;

    for (const auto& a : g_frame) {
        const float p[3] = {a.head[0], a.head[1], a.head[2] + kLiftUnits};
        float sx = 0.0f, sy = 0.0f, dist = 0.0f;
        const bool on = project(cam, p, W, H, sx, sy, dist);
        const std::string name = fw::net::peer_names::display(a.peer_id);

        const bool first = g_logged.insert(a.peer_id).second;
        if (first || periodic) {
            const float miss = on ? ray_miss(module_base, cam, sx, sy, W, H, p)
                                  : -1.0f;
            const char* fmt = "[nametag] peer=%s '%s': head (%.1f, %.1f, %.1f), "
                              "%.0f units away, tag %s (%.0f, %.0f); engine ray "
                              "through that pixel passes %.1f units from the "
                              "anchor (-1 = not checked)";
            if (first) {
                FW_LOG(fmt, a.peer_id.c_str(), name.c_str(), a.head[0],
                       a.head[1], a.head[2], dist,
                       on ? "at" : "off screen, would be at", sx, sy, miss);
            } else {
                FW_DBG(fmt, a.peer_id.c_str(), name.c_str(), a.head[0],
                       a.head[1], a.head[2], dist,
                       on ? "at" : "off screen, would be at", sx, sy, miss);
            }
        }
        if (!on || dist > kMaxDistUnits) continue;

        const float k = dist / kMaxDistUnits;
        const float px = base_px * (1.0f - 0.25f * k);
        const float alpha =
            k < kFadeFrom ? 1.0f : 1.0f - (k - kFadeFrom) / (1.0f - kFadeFrom);
        const ImVec2 ts = measure->CalcTextSizeA(px, FLT_MAX, 0.0f, name.c_str());
        // Whole pixels: a name sliding across sub-pixel positions shimmers.
        const ImVec2 pos(std::floor(sx - ts.x * 0.5f + 0.5f),
                         std::floor(sy - ts.y + 0.5f));
        if (pos.x + ts.x < 0.0f || pos.x > W || pos.y + ts.y < 0.0f || pos.y > H) {
            continue;
        }
        const int a8 = static_cast<int>(255.0f * alpha);
        draw_outlined(dl, font, px, pos, IM_COL32(255, 255, 255, a8),
                      IM_COL32(0, 0, 0, (a8 * 9) / 10), name.c_str());
    }
}

}  // namespace fw::render::nametags
