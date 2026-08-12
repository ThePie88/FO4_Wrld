#include "chargen_stage.h"

#include "appearance_recipe.h"

#include <windows.h>

#include <atomic>
#include <cmath>

#include "../engine/engine_calls.h"
#include "../log.h"
#include "../offsets.h"

namespace fw::native::chargen_stage {

namespace {

// ForceThirdPerson, located 2026-08-08 through the Papyrus registrar
// sub_141123910 using the Idiom A pattern this project already documented for
// GetPlayer: the native is written to [rbx+0x50] AFTER the sub_1420F9D00
// registration call.
//
//   0x141124371  lea  rdx, aForcethirdpers ; "ForceThirdPerson"
//   0x141124378  call sub_1420F9D00
//   0x14112438E  lea  rax, sub_1411299B0
//   0x141124395  mov  [rbx+50h], rax
//
// It is a thin wrapper: it DISCARDS a1 (the Papyrus StaticFunctionTag, unused)
// and calls sub_1410268A0(qword_1430DBD58, a2), which forces LOBYTE(a2) = 1
// before use. So (0, 0) is a safe call and the arity is read off the decomp
// rather than inferred — which matters, because two wrong arities crashed New
// Game earlier today.
//
// WATCH: the worker consults UI::IsMenuOpen before switching. Force the camera
// BEFORE any menu of ours is open, never after.
constexpr std::uintptr_t FORCE_THIRD_PERSON_RVA = 0x011299B0;
constexpr std::uintptr_t FORCE_FIRST_PERSON_RVA = 0x011299A0;
using ForcePovFn = char(__fastcall*)(void*, void*);

// COLLISION — the `tcl` console command's own get/set pair, which is what makes
// this whole thing simple. Found from the ToggleCollision command table entry at
// 0x142EEF830 (opcode 0x114), whose handler sub_1405E4440 does exactly:
//
//     v4 = sub_1404F4010(refr);        // read
//     sub_1404F3FD0(refr, v4 == 0);    // write the inverse
//
// And the setter is trivial: collision-off is a single flag bit on the 3D root.
//
//     v2 = *(_QWORD *)(refr + 240);                  // refr+0xF0 = 3D root
//     if (v2) { if (on) *(_WORD*)(v2+32) |=  0x800;  // NiAVObject flags
//               else    *(_WORD*)(v2+32) &= 0xF7FF; }
//
// Using the engine's setter rather than poking the bit ourselves because it
// handles the null-3D case, and using the GETTER means the restore puts back
// exactly what was there instead of blindly inverting.
//
// This replaced an earlier attempt that keyframed the Havok body. That failed
// live and the log measured it: the player fell 1950 units in two seconds. Two
// reasons, both instructive. The player is moved by a character controller, not
// by rigid-body integration, so keyframing the body does not touch it — and
// engine_calls.h says the NPC recipe needs BOTH the keyframe AND a bailed
// FinishPhysicsStep, of which I had applied only one. Actor::MoveTo also
// "atomically updates ... Havok body", so it very likely reset the motion type
// that had just been set.
constexpr std::uintptr_t SET_COLLISION_RVA = 0x004F3FD0;
constexpr std::uintptr_t GET_COLLISION_RVA = 0x004F4010;
using SetCollisionFn = void(__fastcall*)(void*, char);
using GetCollisionFn = char(__fastcall*)(void*);

// THE CAMERA, and why it is NOT the free camera.
//
// The first implementation used ToggleFreeCameraMode - the `tfc` console command,
// correctly identified: the handler sub_1405ED0C0 does call sub_1410273F0. It
// worked in the sense that every field behaved as documented. The camera went
// exactly where it was put, the engine consumed the yaw (a written 7.1469 came
// back as 0.8637, wrapped into [0, 2*pi) by sub_141022630), and the geometry
// checked out to within 0.04 units.
//
// It was still the wrong camera, and no amount of aiming would have fixed it:
// FREE CAMERA DOES NOT RENDER THE PLAYER. That was established by flying it
// around the map - no body anywhere, no third person available, and the Pip-Boy
// without its opening animation and unusable. `tfc` detaches the camera from the
// player rather than looking at them, so the character simply is not drawn. The
// blue Vault-suit arm visible in one screenshot was the FIRST-person model, which
// was the clue: first person is what the game still thought it was rendering.
// Four quarter turns all showing sky was not a bad angle. It was an empty scene.
//
// AUTO VANITY IS THE CAMERA THAT WORKS, and the evidence for it came from a
// nuisance: earlier in the same session the idle camera started orbiting the
// character 360 degrees, showing the face from every side. That is auto vanity,
// it is a third-person state, and it renders the body. So instead of disabling
// it, the ritual now uses it and stops it from moving.
//
// AutoVanityState::Update is sub_14101EFA0 and it is short enough to quote:
//
//     if ( !*(_BYTE *)(a1 + 36) ) return;           // gate byte at +0x24
//     ... compute the camera transform from the angle ...
//     v5 = *(float *)(a1 + 40) - fAutoVanityIncrement * dt;
//     *(float *)(a1 + 40) = v5;                     // advance, wrapped [0, 2pi)
//
// The orbit is ONE float at +0x28. The angle is read at the top of Update and
// advanced at the bottom, so writing it after the game's update - which is what
// the Present-driven tick does - pins the orbit exactly where it is wanted.
//
// The state's identity is verified rather than assumed. Its constructor stores it
// into PlayerCamera as a1[29], i.e. cam+0xE8, which is index 1 of the state array
// at cam+0xE0 - the same array whose index 0 ForceFirstPerson switches to and
// whose index 8 ForceThirdPerson switches to. The vtable is checked at runtime on
// top of that, so a wrong index is reported instead of scribbling on a stranger.
constexpr std::uintptr_t PLAYER_CAMERA_RVA   = 0x030DBD58;
constexpr std::size_t    CAM_CURRENT_STATE   = 0x28;
constexpr std::uintptr_t CAM_GET_STATE_RVA   = 0x0102B100;  // (cam, index)
constexpr std::uintptr_t SET_CAM_STATE_RVA   = 0x00827A80;  // (cam, state)

constexpr unsigned int   STATE_AUTOVANITY    = 1;
constexpr unsigned int   STATE_THIRDPERSON   = 8;
constexpr std::uintptr_t AUTOVANITY_VTBL_RVA = 0x025A2658;  // re/engine_rtti_catalog
constexpr std::size_t    AV_GATE             = 0x24;  // u8: Update returns if 0
constexpr std::size_t    AV_ANGLE            = 0x28;  // float: the orbit angle

// How far the orbit sits from the character. sub_14101F190 builds the camera
// position using the value of fDefaultAutoVanityZoom, so this is the dial that
// brings the face close. Restored on unstage - it is a global game setting, and
// leaving it changed would quietly alter the player's idle camera forever.
constexpr std::uintptr_t AUTOVANITY_ZOOM_RVA = 0x02F2DC60;

// The framing, settled by measurement.
//
// sub_14101F190 uses the setting as `*(float*)0x143437F54 - fDefaultAutoVanityZoom`
// and feeds the result into SSE basis maths, so which way a larger value moves the
// camera was not readable from the decompilation. It was settled from two data
// points instead: vanilla runs at 300 and frames the whole character, and a first
// attempt at 35 framed it from the nose down. So a SMALLER value is closer, and
// the head-and-shoulders framing wanted here sits at 65 -- chosen on screen, not
// derived.
//
// The vanilla value is saved on entry and restored on exit rather than assumed to
// be 300: it is a game setting the player may have edited, and leaving it changed
// would quietly alter their idle camera for the rest of the session.
constexpr float ZOOM_START = 65.0f;
constexpr float ZOOM_STEP  = 10.0f;
constexpr float ZOOM_MIN   = 5.0f;
constexpr float ZOOM_MAX   = 400.0f;

using CamGetStateFn = void*(__fastcall*)(void*, unsigned int);
using SetCamStateFn = void(__fastcall*)(void*, void*);

// The verified auto-vanity state while staged, null otherwise. Holding the
// pointer avoids re-fetching and re-validating it sixty times a second.
std::atomic<void*> g_av_state{nullptr};
std::atomic<float> g_saved_zoom{0.0f};

// THE POINT-OF-VIEW SETTLE WINDOW, and why the camera switch is deferred.
//
// Fallout spawns into first person, and in first person the body is not rendered
// at all -- so the character-creation camera framed an empty patch of sky. The
// obvious fix, calling ForceThirdPerson, was already there and did not work, and
// the log said why in a single millisecond:
//
//   18:39:15.813  re-forcing third person (ok=1)
//   18:39:15.813  the camera had been moved off auto vanity - put back, ok=1
//   18:39:15.813  auto-vanity pinned
//
// ForceThirdPerson makes the third-person state current, and camera_apply's own
// re-assert -- three lines further down the same function -- immediately took it
// away again. The third-person state never survived one frame, so whatever loads
// the third-person body never ran. Repeating the call more often could not
// possibly help: each repetition was undone by the same tick that made it.
//
// Closing and reopening the panel DID fix it, and that is the clue: between
// unstage and stage the camera sits in third person for real frames. So the fix
// is to reproduce that on purpose -- hold third person for a settle window, and
// only then take the camera for auto vanity.
//
// 600 ms is about thirty-six frames at 60 fps, which is generous for something
// that needs one or two, and short enough not to be seen as a pause. The window
// is measured from staging, but the tick that drives it only runs in-world (during
// the loading screen Present comes from the JobListManager thread), so in practice
// it starts counting when there is something to render.
std::atomic<DWORD> g_staged_at{0};
std::atomic<bool>  g_cam_announced{false};
constexpr DWORD    POV_SETTLE_MS = 600;
constexpr DWORD    RE_POV_MS     = 150;

std::atomic<float> g_z_offset{0.0f};
std::atomic<bool>  g_staged{false};
// The origin, written before anything is touched and read from the position-poll
// thread. Three separate atomics rather than a struct because the reader only
// ever wants a coherent-enough snapshot to report a standing position, and a
// lock on the poll path would buy nothing.
std::atomic<float> g_origin_x{0.0f};
std::atomic<float> g_origin_y{0.0f};
std::atomic<float> g_origin_z{0.0f};

void* seh_ptr_at(std::uintptr_t at) noexcept {
    if (!at) return nullptr;
    __try { return *reinterpret_cast<void* const*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

float seh_f32(const void* at) noexcept {
    if (!at) return 0.0f;
    __try { return *reinterpret_cast<const float*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0.0f; }
}

void* player_actor(std::uintptr_t base) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<void* const*>(base + offsets::PLAYER_SINGLETON_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

bool read_vec3(const void* at, float out[3]) noexcept {
    if (!at) return false;
    __try {
        const auto* f = reinterpret_cast<const float*>(at);
        out[0] = f[0]; out[1] = f[1]; out[2] = f[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    for (int i = 0; i < 3; ++i) {
        if (!std::isfinite(out[i])) return false;
    }
    return true;
}

bool force_third_person(std::uintptr_t base) noexcept {
    auto fn = reinterpret_cast<ForcePovFn>(base + FORCE_THIRD_PERSON_RVA);
    __try { fn(nullptr, nullptr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool get_collision_off(std::uintptr_t base, void* actor) noexcept {
    auto fn = reinterpret_cast<GetCollisionFn>(base + GET_COLLISION_RVA);
    __try { return fn(actor) != 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool set_collision_off(std::uintptr_t base, void* actor, bool off) noexcept {
    auto fn = reinterpret_cast<SetCollisionFn>(base + SET_COLLISION_RVA);
    __try { fn(actor, off ? 1 : 0); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Whether collision was already off before we touched it, so the restore puts
// back what was there rather than assuming it was on.
std::atomic<bool> g_had_collision_off{false};

// The altitude staging put the player at, so the drift correction in tick() has
// something to correct TOWARDS. Stored rather than recomputed because the origin
// is what gets reported to peers and must not be conflated with this.
std::atomic<float> g_target_z{0.0f};

// How far the player may sink before being put back. 60 units is a little under
// a metre — small enough that the face never leaves the frame (the camera is
// derived from the actor's position every frame, so it follows the drift), large
// enough that the correction fires every five to eight seconds rather than
// every frame.
constexpr float DRIFT_TOLERANCE = 60.0f;


// WHERE THE ORBIT IS PINNED.
//
// AutoVanityState carries one absolute orbit angle and the direction its zero
// faces is not documented anywhere in the decompilation. Rather than guess it, it
// was walked round in eighths on screen: zero puts the camera at a three-quarter
// view from the character's left, and the face comes front-on at 45 degrees.
//
// The turn keys stay, and not as leftovers. Looking at the model from another
// side while editing it is something a character creator should be able to do, so
// what began as a calibration aid is now the view control -- it just has a
// sensible default under it.
constexpr float ORBIT_START = 0.78539816f;   // 45 degrees, face-on
std::atomic<float> g_orbit_angle{ORBIT_START};
std::atomic<float> g_zoom{ZOOM_START};

void* player_camera(std::uintptr_t base) noexcept {
    return seh_ptr_at(base + PLAYER_CAMERA_RVA);
}

void* camera_state(std::uintptr_t base, unsigned int idx) noexcept {
    void* cam = player_camera(base);
    if (!cam) return nullptr;
    auto fn = reinterpret_cast<CamGetStateFn>(base + CAM_GET_STATE_RVA);
    __try { return fn(cam, idx); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// The auto-vanity state, but only if its vtable says that is what it is.
void* autovanity_state(std::uintptr_t base) noexcept {
    void* st = camera_state(base, STATE_AUTOVANITY);
    if (!st) return nullptr;
    const void* vt = seh_ptr_at(reinterpret_cast<std::uintptr_t>(st));
    const auto want = base + AUTOVANITY_VTBL_RVA;
    if (reinterpret_cast<std::uintptr_t>(vt) != want) {
        static std::atomic<bool> s_told{false};
        if (!s_told.exchange(true, std::memory_order_relaxed)) {
            FW_ERR("[chargen-stage] camera state 1 has vtable %p, expected %p "
                   "(AutoVanityState). Not touching it - the state array layout "
                   "is not what this was written against.",
                   vt, reinterpret_cast<void*>(want));
        }
        return nullptr;
    }
    return st;
}

bool set_camera_state(std::uintptr_t base, void* st) noexcept {
    void* cam = player_camera(base);
    if (!cam || !st) return false;
    auto fn = reinterpret_cast<SetCamStateFn>(base + SET_CAM_STATE_RVA);
    __try { fn(cam, st); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    void* cur = seh_ptr_at(
        reinterpret_cast<std::uintptr_t>(cam) + CAM_CURRENT_STATE);
    return cur == st;
}

// Pin the orbit. Called every frame from the Present-driven tick, because Update
// advances the angle on every one of its own frames and the last writer wins.
void camera_apply(std::uintptr_t base) noexcept {
    void* st = g_av_state.load(std::memory_order_relaxed);
    if (!st) return;
    auto* p = reinterpret_cast<std::uint8_t*>(st);

    // THE STATE ITSELF HAS TO BE RE-ASSERTED, not just the angle inside it.
    //
    // Pinning the orbit angle is pointless if auto vanity is no longer the
    // camera being read. That is exactly what happened when a stray click got
    // through: the game put the player into an aiming state, swapped the camera
    // with it, and from then on the angle was being written to a state nobody was
    // looking at -- the view showed a first-person arm and only closing and
    // reopening the panel fixed it, because reopening re-staged and set the state
    // again. Setting it here means the fix costs a frame instead of a keypress,
    // and it holds against anything else that reassigns the camera.
    // HOLD THIRD PERSON FIRST, TAKE THE CAMERA AFTER. Inside the settle window
    // the camera state is deliberately left alone: touching it is precisely what
    // broke this before.
    // THE CLOCK STARTS ON THE FIRST TICK THAT ACTUALLY RUNS, not at staging.
    //
    // Measuring from staging looked equivalent and was not: this tick is driven by
    // Present, and during the loading screen Present comes from the JobListManager
    // thread rather than the main one, so the tick is dormant for the whole load.
    // The first run measured 8691 ms since staging against a 600 ms window -- the
    // window had expired before a single frame of the world had been drawn, so
    // third person was held for exactly one tick, during the loading screen, where
    // holding it achieves nothing.
    //
    // Anchoring it here means the window covers the first 600 ms of RENDERED world,
    // which is what it was supposed to mean all along.
    DWORD started = g_staged_at.load(std::memory_order_relaxed);
    if (started == 0) {
        started = GetTickCount();
        if (started == 0) started = 1;   // 0 is the sentinel
        g_staged_at.store(started, std::memory_order_relaxed);
        force_third_person(base);
        FW_LOG("[chargen-stage] first in-world tick: holding third person for "
               "%ums so the body loads before the camera is taken",
               POV_SETTLE_MS);
        return;
    }
    const DWORD since = GetTickCount() - started;
    if (since < POV_SETTLE_MS) {
        static DWORD s_last_pov = 0;
        const DWORD now1 = GetTickCount();
        if (now1 - s_last_pov >= RE_POV_MS) {
            s_last_pov = now1;
            (void)force_third_person(base);
        }
        return;
    }
    if (!g_cam_announced.exchange(true, std::memory_order_relaxed)) {
        FW_LOG("[chargen-stage] settle window over -> AutoVanityState %p: it "
               "orbits the character and renders the body, which the free camera "
               "does not. Orbit pinned at %.0f degrees (F3/F4 turn it an eighth, "
               "F5/F6 move it in and out).",
               st, g_orbit_angle.load(std::memory_order_relaxed) * 57.2957795f);
    }

    void* cam = player_camera(base);
    if (cam) {
        void* cur = seh_ptr_at(
            reinterpret_cast<std::uintptr_t>(cam) + CAM_CURRENT_STATE);
        if (cur != st) {
            const bool ok = set_camera_state(base, st);
            static DWORD s_last = 0;
            const DWORD now = GetTickCount();
            if (now - s_last >= 2000) {
                s_last = now;
                FW_LOG("[chargen-stage] the camera had been moved off auto vanity "
                       "(state was %p, wanted %p) - put back, ok=%d (throttled "
                       "to 1/2s)", cur, st, ok ? 1 : 0);
            }
            if (!ok) return;
        }
    }

    const float want = g_orbit_angle.load(std::memory_order_relaxed);
    std::uint8_t gate = 0;
    __try {
        *reinterpret_cast<float*>(p + AV_ANGLE) = want;
        // The gate has to be 1 or Update returns before it moves the camera at
        // all, which would leave the view frozen wherever it happened to be.
        *(p + AV_GATE) = 1;
        gate = *(p + AV_GATE);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    // Re-assert the zoom: it is a game setting and other code may write it.
    const float want_zoom = g_zoom.load(std::memory_order_relaxed);
    float zoom_now = 0.0f;
    auto* zoom = reinterpret_cast<float*>(base + AUTOVANITY_ZOOM_RVA);
    __try {
        if (*zoom != want_zoom) *zoom = want_zoom;
        zoom_now = *zoom;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    static DWORD s_beat = 0;
    const DWORD now = GetTickCount();
    if (now - s_beat >= 2000) {
        s_beat = now;
        FW_LOG("[chargen-stage] auto-vanity pinned: angle=%.4f rad (%.0f deg) "
               "gate=%u zoom=%.1f", want, want * 57.2957795f,
               static_cast<unsigned>(gate), zoom_now);
    }
}

}  // namespace

void init(float z_offset) {
    g_z_offset.store(z_offset, std::memory_order_relaxed);
    if (z_offset > 0.0f) {
        FW_LOG("[chargen-stage] armed: creation happens %.0f units up. "
               "Collision is turned off while staged — the same flag the `tcl` "
               "console command flips — so the player floats instead of "
               "falling. There is no pause in this project to do it for us.",
               z_offset);
    }
}

bool armed() noexcept {
    return g_z_offset.load(std::memory_order_relaxed) > 0.0f;
}

bool staged() noexcept {
    return g_staged.load(std::memory_order_acquire);
}

void nudge_camera_yaw(bool backwards) noexcept {
    // An eighth of a turn, not a quarter. A quarter was too coarse to land on
    // the front: at angle 0 the camera sits at a three-quarter view from the
    // character's left, so the front is somewhere between one and two steps away
    // and a 90-degree step steps straight over it. Both directions are offered
    // because which way the angle runs is not established, and hunting outward
    // from the starting point beats walking seven eighths of the way round.
    constexpr float EIGHTH = 0.78539816f;
    constexpr float TWO_PI = 6.28318531f;
    float v = g_orbit_angle.load(std::memory_order_relaxed)
            + (backwards ? -EIGHTH : EIGHTH);
    // std::fmod rather than a single compare-and-subtract. The compare version
    // let 360 degrees through: eight eighths sum to 6.28318528, which is a hair
    // BELOW the 6.28318531 it was tested against, so the wrap never fired and the
    // log showed "orbit angle -> 360 degrees". Harmless as an angle and wrong as
    // arithmetic, and the same near-miss would bite any threshold written by hand.
    v = std::fmod(v, TWO_PI);
    if (v < 0.0f) v += TWO_PI;
    g_orbit_angle.store(v, std::memory_order_relaxed);
    FW_LOG("[chargen-stage] orbit angle -> %.4f rad (%.0f degrees). If the face "
           "is centred at this value, make it the default.",
           v, v * 57.2957795f);
}

void nudge_camera_zoom(bool further) noexcept {
    // `further` adds to the setting, because a larger value is further away.
    // The first version of this called the parameter `closer` and added on the
    // same branch, which was simply wrong: the direction had not been measured
    // yet. The behaviour was right and only the name lied, but a lying name is
    // how the next reader gets it backwards.
    float v = g_zoom.load(std::memory_order_relaxed)
            + (further ? ZOOM_STEP : -ZOOM_STEP);
    if (v < ZOOM_MIN) v = ZOOM_MIN;
    if (v > ZOOM_MAX) v = ZOOM_MAX;
    g_zoom.store(v, std::memory_order_relaxed);
    FW_LOG("[chargen-stage] fDefaultAutoVanityZoom -> %.1f (vanilla was %.1f, "
           "editor default %.1f)", v,
           g_saved_zoom.load(std::memory_order_relaxed), ZOOM_START);
}

bool report_pos(float out_xyz[3]) noexcept {
    if (!out_xyz || !g_staged.load(std::memory_order_acquire)) return false;
    out_xyz[0] = g_origin_x.load(std::memory_order_relaxed);
    out_xyz[1] = g_origin_y.load(std::memory_order_relaxed);
    out_xyz[2] = g_origin_z.load(std::memory_order_relaxed);
    return true;
}

void tick(std::uintptr_t module_base) {
    if (!g_staged.load(std::memory_order_acquire)) return;
    void* actor = player_actor(module_base);
    if (!actor) return;
    // THE REASON THIS EXISTS, corrected after measuring it.
    //
    // The first version of this comment blamed Reset3D for rebuilding the 3D root
    // and losing the flag. That was wrong, and the log said so: the selftest's
    // Reset3D fired thirteen seconds BEFORE staging, while the first re-assert
    // came 17 ms AFTER it, and 1581 more followed over eighty seconds.
    //
    // So something re-enables collision on essentially every frame, and this is
    // not a fix-up after a known event — it is a continuous fight that we win
    // because our write lands after the engine's. WHO clears it is NOT
    // identified. It is cheap to win (one word read, and a write only when it
    // has flipped) and it demonstrably holds the player up, so it stays; but it
    // is a standing fight and not a settled state, and anyone changing this
    // should know that before trusting it.
    // Keep the camera parked in front of the face. Same reasoning as the
    // collision flag below: the state is the engine's and re-asserting is
    // cheaper than finding every path that touches it.
    camera_apply(module_base);

    if (!get_collision_off(module_base, actor)) {
        set_collision_off(module_base, actor, true);
        // Throttled: this fires ~20 times a second, so an unthrottled line
        // buries the log. One line per second is enough to see it is alive.
        static DWORD s_last = 0;
        const DWORD now = GetTickCount();
        if (now - s_last >= 1000) {
            s_last = now;
            FW_DBG("[chargen-stage] collision keeps being re-enabled by the "
                   "engine — re-asserting (throttled to 1/s)");
        }
    }

    // THE SLOW SINK, and why collision-off does not stop it.
    //
    // Measured: the staged player descends at roughly 7 to 14 units per second.
    // The first theory was that the engine kept switching collision back on and
    // our re-assert was losing whenever the tick stopped running, and that WAS
    // happening — but with the re-assert now driven by Present it fires every
    // frame, the flag flips about twice a minute instead of 1581 times in eighty
    // seconds, and the player still sinks. So collision-off is not what holds an
    // actor up. Something integrates a small downward velocity regardless of it.
    //
    // 7 to 14 units per second is far too slow to be gravity — Fallout's gravity
    // would cover the ten thousand units to the ground in about four and a half
    // seconds, not twenty minutes. WHAT it actually is has not been identified,
    // and this does not pretend to fix it: it puts the player back whenever the
    // drift becomes visible, using the same teleport that staged them in the
    // first place. That is a correction, not a cure, and it is written down as
    // one so nobody later reads this as the sink being understood.
    const float target_z = g_target_z.load(std::memory_order_relaxed);
    if (target_z != 0.0f) {
        float pos[3] = {};
        auto* a = reinterpret_cast<std::uint8_t*>(actor);
        if (read_vec3(a + offsets::POS_OFF, pos) &&
            std::fabs(target_z - pos[2]) > DRIFT_TOLERANCE) {
            float rot[3] = {};
            (void)read_vec3(a + offsets::ROT_OFF, rot);
            const bool ok = fw::engine::actor_teleport_handoff(
                actor, pos[0], pos[1], target_z, rot[2]);
            // Collision does not survive a teleport; staging re-asserts it after
            // its own move for the same reason.
            set_collision_off(module_base, actor, true);
            static DWORD s_drift = 0;
            const DWORD now = GetTickCount();
            if (now - s_drift >= 5000) {
                s_drift = now;
                FW_DBG("[chargen-stage] drift correction: sank %.1f units to "
                       "z=%.1f, put back to %.1f (ok=%d, throttled to 1/5s)",
                       target_z - pos[2], pos[2], target_z, ok ? 1 : 0);
            }
        }
    }
}

void sync(std::uintptr_t module_base) {
    const bool want = ::fw::native::appearance::editing();
    const bool have = g_staged.load(std::memory_order_acquire);
    if (want == have) return;

    if (!want) {
        unstage(module_base);
        return;
    }
    if (!armed()) return;

    // RETRY, THROTTLED, because the first attempt usually cannot succeed.
    //
    // The editing flag goes up the moment the server's WELCOME says the ritual is
    // required, which is long before the save has finished loading: there is no
    // player actor to teleport and no cell to teleport within. stage() refuses
    // both cases and says so, so the job here is to keep asking until the world
    // is ready rather than to guess how long that takes. Half a second between
    // attempts keeps the refusal warnings readable.
    static DWORD s_last_try = 0;
    const DWORD now = GetTickCount();
    if (now - s_last_try < 500) return;
    s_last_try = now;
    if (stage(module_base)) return;

    static DWORD s_last_moan = 0;
    if (now - s_last_moan >= 5000) {
        s_last_moan = now;
        FW_LOG("[chargen-stage] the editor is open but staging has not taken yet "
               "- retrying twice a second (throttled to one line per 5s)");
    }
}

bool stage(std::uintptr_t module_base) {
    if (!armed() || g_staged.load(std::memory_order_acquire)) return false;

    void* actor = player_actor(module_base);
    if (!actor) {
        FW_WRN("[chargen-stage] no player actor — not staging");
        return false;
    }

    // The cell-grid spinlock this teleport touches is process-global, and the
    // documented c.25/c.27 freeze is what happens when the streaming thread is
    // holding it. recently_teleported() is this project's own gate for exactly
    // that window, so refuse rather than risk it; the caller can try again.
    if (fw::engine::recently_teleported()) {
        FW_WRN("[chargen-stage] a cell transition is still settling — refusing "
               "to teleport into the cell-grid lock. Try again shortly.");
        return false;
    }

    auto* a = reinterpret_cast<std::uint8_t*>(actor);
    float pos[3] = {}, rot[3] = {};
    if (!read_vec3(a + offsets::POS_OFF, pos) ||
        !read_vec3(a + offsets::ROT_OFF, rot)) {
        FW_WRN("[chargen-stage] could not read the player's position — not "
               "staging");
        return false;
    }

    // ORIGIN FIRST. Everything after this point can fail; nothing after this
    // point may run without a way back.
    g_origin_x.store(pos[0], std::memory_order_relaxed);
    g_origin_y.store(pos[1], std::memory_order_relaxed);
    g_origin_z.store(pos[2], std::memory_order_relaxed);

    // Camera BEFORE anything menu-shaped exists — the engine's own switch
    // consults UI::IsMenuOpen and may branch once a menu is up.
    if (!force_third_person(module_base)) {
        FW_WRN("[chargen-stage] ForceThirdPerson faulted — continuing, but the "
               "view may be first person and show nothing but sky");
    }

    // Collision off BEFORE the move, so there is never a frame of freefall.
    // Remember what it was, because a player who was already noclipping for
    // their own reasons should still be noclipping afterwards.
    g_had_collision_off.store(get_collision_off(module_base, actor),
                              std::memory_order_relaxed);
    const bool coll = set_collision_off(module_base, actor, true);

    const float target_z = pos[2] + g_z_offset.load(std::memory_order_relaxed);
    const bool moved = fw::engine::actor_teleport_handoff(
        actor, pos[0], pos[1], target_z, rot[2]);
    // Again after the move: MoveTo rebuilds enough of the actor that the flag
    // cannot be assumed to have survived, and the setter is idempotent.
    set_collision_off(module_base, actor, true);

    if (!moved) {
        FW_ERR("[chargen-stage] the teleport failed — restoring collision and "
               "staying on the ground rather than half-staged");
        set_collision_off(module_base, actor,
                          g_had_collision_off.load(std::memory_order_relaxed));
        return false;
    }

    g_target_z.store(target_z, std::memory_order_relaxed);
    g_staged_at.store(0, std::memory_order_relaxed);   // armed; the
                       // first in-world camera tick starts the clock

    // The camera last: it reads the player's position, so it wants the teleport
    // already done.
    void* av = autovanity_state(module_base);
    if (av) {
        auto* zoom = reinterpret_cast<float*>(module_base + AUTOVANITY_ZOOM_RVA);
        __try { g_saved_zoom.store(*zoom, std::memory_order_relaxed); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        // The vanilla number, logged because it is the reference point for
        // choosing a sensible default once the framing is settled.
        FW_LOG("[chargen-stage] fDefaultAutoVanityZoom was %.1f in this session; "
               "the editor uses %.1f while staged and puts it back on close. "
               "F5/F6 adjust it by %.0f.",
               g_saved_zoom.load(std::memory_order_relaxed),
               g_zoom.load(std::memory_order_relaxed), ZOOM_STEP);
        g_av_state.store(av, std::memory_order_relaxed);
        g_cam_announced.store(false, std::memory_order_relaxed);
        // Not switched here. The settle window in camera_apply holds third person
        // for a few frames first, because the body only loads while that state is
        // actually current, and then takes the camera.
        FW_LOG("[chargen-stage] auto-vanity target is %p; holding third person "
               "for %ums first so the body is loaded before the camera moves",
               av, POV_SETTLE_MS);
    }

    g_staged.store(true, std::memory_order_release);
    FW_LOG("[chargen-stage] STAGED. origin=(%.1f, %.1f, %.1f) -> z=%.1f "
           "collision_off=%d (was already off: %d). Peers are told the origin, "
           "not this, so their ghosts of us stay on the ground.",
           pos[0], pos[1], pos[2], target_z, coll ? 1 : 0,
           g_had_collision_off.load(std::memory_order_relaxed) ? 1 : 0);
    return true;
}

bool unstage(std::uintptr_t module_base) {
    if (!g_staged.load(std::memory_order_acquire)) return false;

    void* actor = player_actor(module_base);
    if (!actor) {
        // Nothing can be done about the position, but the flag must not stay
        // raised or the position reporter would lie about the origin forever.
        FW_ERR("[chargen-stage] no player actor while unstaging — clearing the "
               "staged flag so position reporting goes back to the truth");
        g_staged.store(false, std::memory_order_release);
        return true;
    }

    const float ox = g_origin_x.load(std::memory_order_relaxed);
    const float oy = g_origin_y.load(std::memory_order_relaxed);
    const float oz = g_origin_z.load(std::memory_order_relaxed);

    // TEMPORARY, and not a safety measure. The intended ending is to set the
    // motion type back to Dynamic and let the player fall, die, and be respawned
    // by the server at its spawn point — the fall being the transition. That
    // needs the server's spawn system, which does not exist yet, so until it does
    // the exit is a plain teleport back to where they were.
    float rot[3] = {};
    auto* a = reinterpret_cast<std::uint8_t*>(actor);
    (void)read_vec3(a + offsets::ROT_OFF, rot);
    const bool moved = fw::engine::actor_teleport_handoff(actor, ox, oy, oz,
                                                          rot[2]);
    g_target_z.store(0.0f, std::memory_order_relaxed);

    // Clear the staged flag BEFORE restoring collision: the per-frame re-assert
    // reads that flag, and if it still saw `staged` it would put collision
    // straight back off again on the very next frame.
    g_staged.store(false, std::memory_order_release);
    const bool restored = set_collision_off(
        module_base, actor,
        g_had_collision_off.load(std::memory_order_relaxed));
    if (g_av_state.exchange(nullptr, std::memory_order_relaxed)) {
        // Put the setting back before the state, so no frame of the ordinary
        // third-person camera renders with the chargen zoom.
        auto* zoom = reinterpret_cast<float*>(module_base + AUTOVANITY_ZOOM_RVA);
        const float saved = g_saved_zoom.load(std::memory_order_relaxed);
        __try { if (saved > 0.0f) *zoom = saved; }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        void* tp = camera_state(module_base, STATE_THIRDPERSON);
        if (tp) set_camera_state(module_base, tp);
    }

    if (!moved) {
        FW_ERR("[chargen-stage] UNSTAGE: the return teleport failed and "
               "collision is back on (restore ok=%d) — the player will fall "
               "from altitude rather than float there.", restored ? 1 : 0);
    } else {
        FW_LOG("[chargen-stage] unstaged -> (%.1f, %.1f, %.1f), collision "
               "restored=%d", ox, oy, oz, restored ? 1 : 0);
    }
    return true;
}

}  // namespace fw::native::chargen_stage
