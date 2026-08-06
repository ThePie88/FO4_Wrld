#include "first_person_graph.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"

namespace fw::hooks {

namespace {

// --- BSAnimationGraphManager layout (decomp-proven, see header) -------------
constexpr std::uintptr_t GRAPH_MGR_UPDATE_RVA   = 0x0130E240;  // sub_14130E240
constexpr std::uintptr_t GRAPH_UPDATE_RVA       = 0x01320530;  // sub_141320530
constexpr std::uintptr_t GRAPH_EVENT_FLUSH_RVA  = 0x01320EA0;  // sub_141320EA0
// 2026-08-05 RE pass 2 — the two pieces that were missing (see header).
constexpr std::uintptr_t GRAPH_ACTIVATE_RVA     = 0x01320430;  // sub_141320430
constexpr std::uintptr_t GRAPH_POSE_APPLY_RVA   = 0x01320C40;  // sub_141320C40

// BShkbAnimationGraph fields (decomp-proven, see header).
constexpr std::size_t GRAPH_HKB_WRAPPER_OFF = 0x378;  // hkbBehaviorGraph wrapper
constexpr std::size_t HKB_ACTIVE_BYTE_OFF   = 0x1AA;  // wrapper+0x1AA: graph is live
constexpr std::size_t GRAPH_MUTE_BYTE_OFF   = 0x3C3;  // engine's own "mute outputs"
// The bone-write gate (vtbl+0x98 = sub_141327D40, "pose is physics-driven"):
//   return graph+0x3B8 && sub_1413B90A0(graph+0x210) && vfunc+0x20(graph+0x210);
// When TRUE the pose is routed to the physics path, NOT the NiNode writer.
constexpr std::uintptr_t GRAPH_PHYS_PRED_RVA = 0x01327D40;  // sub_141327D40
constexpr std::size_t GRAPH_PHYS_WORLD_OFF   = 0x3B8;
constexpr std::size_t GRAPH_RAGDOLL_OBJ_OFF  = 0x210;

// Round 7 — the engine's own out-of-band drive sequence (its graph-bind path)
// refreshes the behavior graph's ACTIVE NODE LIST before updating it. Skipping
// that leaves hkbBehaviorGraph::update iterating a stale/empty list, so
// computeTimestepForActiveNodes hands the timestep to nobody: the clip clock
// stops while generate still emits a full 95-bone pose. Exactly our symptom.
// ============================================================================
// THE OVERWRITER (found 2026-08-05, round 7 — this is the actual defect)
//
// PlayerCharacter overrides slot 23 of IAnimationGraphManagerHolder — the
// POST-update hook, which runs immediately after BSAnimationGraphManager::
// Update inside sub_140818930. Its body (sub_140D7DE50):
//
//   if ((PC+3510 & 0x10) == 0) {                 // i.e. while in FIRST person
//       src = *(void**)(PC + 2864);              // the FIRST-person tree
//       dst = Actor::Get3D(false);               // the THIRD-person tree
//       for (i = 0; i < *(u32*)(PC + 3472); ++i) // index-pair map at PC+3456
//           copy rotation + translate + scale  src[srcIdx] -> dst[dstIdx];
//   }
//
// So in first person the engine COPIES THE FIRST-PERSON SKELETON ONTO THE
// THIRD-PERSON ONE every frame, for the bones in that map — the arms. That is
// why the peer's ghost shows first-person arms grafted onto a body whose legs
// never move, why the aim pose looks impossible, and why nothing we did to the
// third-person graph ever survived: we wrote the bones, and this ran one call
// later and overwrote them.
//
// Skipping it while we drive is visually free for the local player: the
// third-person body is APP_CULLED in first person, so nobody sees it. The
// copy exists to keep the two skeletons agreeing for shadows and for the
// bRenderFirstPersonInWorld case; our ghost stream needs the opposite.
constexpr std::uintptr_t PC_SKELETON_SYNC_RVA = 0x00D7DE50;  // sub_140D7DE50

// PlayerCharacter::PopulateGraphVariables (holder vtable slot +0x40 override).
// It recomputes and writes the actor's whole locomotion snapshot into ONE
// given graph — speed, iSyncIdleLocomotion, iSyncTurnState, iSyncForwardState,
// iSyncStrafeState, iSyncJumpState — plus the player flags. The engine uses it
// when priming graphs after a reset. Firing it at the camera transition is the
// "force an update" the ghost needs: without it the third-person graph carries
// stale locomotion values across the switch and picks the wrong state.
constexpr std::uintptr_t PC_POPULATE_VARS_RVA = 0x00D7DB10;  // sub_140D7DB10
constexpr std::size_t    ACTOR_HOLDER_OFF     = 0x48;

// BSFixedString(const char*) — the engine's own interning ctor, used by the
// static initialisers that build the graph-variable name table.
constexpr std::uintptr_t BSFIXEDSTRING_CTOR_RVA = 0x0167BDC0;  // sub_14167BDC0

// The wake-up events, read straight off the live mirror: logging the active-
// node count around every mirrored event showed which names actually move the
// parked state machine. 'g_archetypeBaseStateStartInstant' is the behavior's
// own "enter the base state, immediately" trigger; 'MoveStop' settles it into
// idle, which is the pose a standing player should be showing. Raising these
// two at wake-up replaces the manual action the player had to perform (drawing
// a weapon happened to work only because WeapEquip is another such trigger).
const char* const kWakeEvents[] = {
    "g_archetypeBaseStateStartInstant",
    "MoveStop",
};

// Per-graph float setter — writes ONE graph, unlike the holder-level setters
// which broadcast to all of them. Used for the locomotion scalars below so the
// first-person graph (and the player's own arms) is never touched.
constexpr std::uintptr_t GRAPH_SET_VAR_FLOAT_RVA = 0x01326590;  // sub_141326590

// The two scalars that make a walk cycle match the ground it covers.
// PopulateGraphVariables writes a variable called "speed", but the behavior
// scales its locomotion clips from SpeedSampled/Direction — the same pair this
// project already drives on mirrored NPCs. Nothing writes them into a parked
// graph, so its walk plays at a stale rate and ignores the strafe axis: the
// reported "slow walk that does not reflect the distance covered", and why a
// camera round-trip appeared to fix it for a moment.
const char* const kLocoVars[] = { "SpeedSampled", "Direction" };

constexpr std::uintptr_t HKB_CTX_CTOR_RVA     = 0x013A9A10;  // sub_1413A9A10
constexpr std::uintptr_t HKB_CTX_DTOR_RVA     = 0x013A9A90;  // sub_1413A9A90
constexpr std::uintptr_t HKB_UPD_ACTIVE_RVA   = 0x0148EB70;  // sub_14148EB70
constexpr std::uintptr_t HKB_UPD_SYNC_RVA     = 0x01480720;  // sub_141480720
constexpr std::size_t GRAPH_HKB_CHARACTER_OFF = 0x1C8;  // inline hkbCharacter
constexpr std::size_t HKB_ACTIVE_NODES_OFF    = 0xE0;   // m_activeNodes
constexpr std::size_t HKB_NODES_DIRTY_OFF     = 0x1AC;  // gate for the refresh

constexpr std::size_t MGR_ARRAY_FLAGS_OFF = 0x40;  // bit31 set => inline data
constexpr std::size_t MGR_ARRAY_DATA_OFF  = 0x48;
constexpr std::size_t MGR_ARRAY_SIZE_OFF  = 0x50;
constexpr std::size_t MGR_EVENT_ARRAY_OFF = 0x10;  // passed to the flush call
constexpr std::size_t MGR_LOCK_OWNER_OFF  = 0xC8;
constexpr std::size_t MGR_LOCK_COUNT_OFF  = 0xCC;
constexpr std::size_t MGR_ACTIVE_OFF      = 0xD8;

constexpr std::uint32_t THIRD_PERSON_GRAPH = 0;
constexpr std::uint32_t FIRST_PERSON_GRAPH = 1;

using GraphMgrUpdateFn  = void(__fastcall*)(void*, void*);
using GraphUpdateFn     = void(__fastcall*)(void*, void*);
using GraphEventFlushFn = void(__fastcall*)(void*, void*);
using GraphActivateFn   = void(__fastcall*)(void*);
using GraphPoseApplyFn  = void(__fastcall*)(void*, void*);

GraphMgrUpdateFn  g_orig_mgr_update = nullptr;
GraphUpdateFn     g_graph_update    = nullptr;
GraphEventFlushFn g_graph_flush     = nullptr;
GraphActivateFn   g_graph_activate  = nullptr;
GraphPoseApplyFn  g_graph_pose_apply = nullptr;

using GraphPhysPredFn = std::uint8_t(__fastcall*)(void*);
GraphPhysPredFn   g_graph_phys_pred = nullptr;   // vtbl+0x98 predicate

using HkbCtxCtorFn   = void*(__fastcall*)(void*, void*, void*, void*);
using HkbCtxDtorFn   = void(__fastcall*)(void*);
using HkbUpdActiveFn = void(__fastcall*)(void*, void*, std::uint8_t);
using HkbUpdSyncFn   = void(__fastcall*)(void*, void*);

using PcSkelSyncFn = void(__fastcall*)(void*);
PcSkelSyncFn   g_orig_skel_sync  = nullptr;
std::atomic<std::uint64_t> g_sync_suppressed{0};

// --- 2026-08-05 round 8: KEEP THE STATE MACHINE ALIVE -----------------------
// Live result of round 7: the ghost DOES animate now, but it starts in T-pose
// and only wakes when something raises an event (drawing a weapon, swinging).
// Going back to third person and returning re-freezes it into T-pose.
//
// Cause: hkbBehaviorGraph::activate re-activates the root generator and
// rebuilds the active-node list — it resets the state machine to its INITIAL
// state. So every trip into first person the engine deactivates the
// third-person graph, we resurrect it, and it is reborn with no idea that the
// player is mid-walk. T-pose is literally the newborn graph; a mirrored event
// is what finally transitions it somewhere real.
//
// Fix: stop letting it die. When the camera enters first person we suppress
// the engine's deactivate of the third-person graph, so it keeps running with
// the state it already had (walking stays walking). The reverse trip still
// deactivates it deliberately, so the engine's own re-activation runs in full
// (ragdoll bind + pending-flag clear) — that path goes through
// g_orig_graph_deactivate, which bypasses this detour.
// (spelled out rather than via the typedef, which is declared further down)
std::uint8_t(__fastcall* g_orig_graph_deactivate)(void*, void*) = nullptr;
// PlayerCharacter::PopulateGraphVariables(holder, BSTSmartPointer<graph>*)
void(__fastcall* g_pc_populate_vars)(void*, void**) = nullptr;
// BSFixedString ctor + the interned wake-up event names (built once at install)
void*(__fastcall* g_bsfixedstring_ctor)(void**, const char*) = nullptr;
void* g_wake_event_str[sizeof(kWakeEvents) / sizeof(kWakeEvents[0])] = {};
bool  g_wake_events_ready = false;
std::uint8_t(__fastcall* g_graph_set_var_float)(void*, void**, float) = nullptr;
void* g_loco_var_str[sizeof(kLocoVars) / sizeof(kLocoVars[0])] = {};
bool  g_loco_vars_ready = false;
void*             g_driven_graph          = nullptr;   // the 3P graph we drive
std::atomic<bool> g_allow_deactivate{false};           // set only by our undo
std::atomic<std::uint64_t> g_deact_suppressed{0};

HkbCtxCtorFn   g_hkb_ctx_ctor    = nullptr;
HkbCtxDtorFn   g_hkb_ctx_dtor    = nullptr;
HkbUpdActiveFn g_hkb_upd_active  = nullptr;
HkbUpdSyncFn   g_hkb_upd_sync    = nullptr;

// --- 2026-08-05 round 5: EVENT MIRRORING -----------------------------------
// Variables already reach both graphs (the holder-level setters loop over the
// whole graph array). EVENTS do not: BSAnimationGraphManager::NotifyAnimation-
// Graph delivers only to graphs[activeGraph]. That is why the revived
// third-person graph generates a real pose but always the SAME one — its hkb
// state machine never receives moveStart/SprintStart/turn/etc, so it loops
// whatever state it was parked in. Mirror the event to the parked graph.
constexpr std::uintptr_t MGR_NOTIFY_RVA       = 0x0130EAE0;  // sub_14130EAE0
constexpr std::uintptr_t GRAPH_SEND_EVENT_RVA = 0x01320FE0;  // sub_141320FE0
constexpr std::uintptr_t SET_ACTIVE_GRAPH_RVA = 0x0130EDF0;  // sub_14130EDF0
constexpr std::uintptr_t GRAPH_DEACTIVATE_RVA = 0x01326370;  // sub_141326370

using MgrNotifyFn      = std::uint8_t(__fastcall*)(void*, const void*);
using GraphSendEventFn = std::uint8_t(__fastcall*)(void*, const void*, void*);
using SetActiveGraphFn = std::uint8_t(__fastcall*)(void*, std::uint32_t);
using GraphDeactivateFn = std::uint8_t(__fastcall*)(void*, void*);

MgrNotifyFn       g_orig_mgr_notify   = nullptr;
GraphSendEventFn  g_graph_send_event  = nullptr;
SetActiveGraphFn  g_orig_set_active   = nullptr;
GraphDeactivateFn g_graph_deactivate  = nullptr;

std::atomic<std::uint64_t> g_events_mirrored{0};
// Set once we force-revive graphs[0]; consumed by the SetActiveGraph hook.
std::atomic<bool> g_forced_revive{false};

// Mute-byte custody, so the gag can be restored even if an engine call
// faults inside the SEH-caged worker (otherwise it leaks into third person
// and stops WASD movement — the regression from round 3).
std::uint8_t* g_mute_graph = nullptr;
std::uint8_t  g_mute_saved = 0;

std::atomic<bool>          g_enabled{true};
std::atomic<bool>          g_installed{false};
std::atomic<bool>          g_stream_in_1p{false};
std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_seh{0};

// The engine's own recursive spinlock idiom, transcribed from
// sub_14130E240 (funcs_0423.md:18465-18487 acquire, 18553-18563 release).
// Same thread re-entry bumps the count; otherwise CAS-spin with a Sleep(0)
// backoff that escalates to Sleep(1) after 0x2710 attempts.
void mgr_lock(std::uint8_t* mgr) noexcept {
    auto* owner = reinterpret_cast<volatile long*>(mgr + MGR_LOCK_OWNER_OFF);
    auto* count = reinterpret_cast<volatile long*>(mgr + MGR_LOCK_COUNT_OFF);
    const DWORD tid = GetCurrentThreadId();
    if (static_cast<DWORD>(*owner) == tid) {
        _InterlockedIncrement(count);
        return;
    }
    unsigned spins = 0;
    while (_InterlockedCompareExchange(count, 1, 0)) {
        Sleep(spins >= 0x2710 ? 1 : 0);
        if (spins < 0x2710) ++spins;
    }
    *owner = static_cast<long>(tid);
    MemoryBarrier();
}

void mgr_unlock(std::uint8_t* mgr) noexcept {
    auto* owner = reinterpret_cast<volatile long*>(mgr + MGR_LOCK_OWNER_OFF);
    auto* count = reinterpret_cast<volatile long*>(mgr + MGR_LOCK_COUNT_OFF);
    if (*count == 1) {
        *owner = 0;
        MemoryBarrier();
        _InterlockedCompareExchange(count, 0, 1);
    } else {
        _InterlockedDecrement(count);
    }
}

// Resolve graphs[idx] from the BSTSmallArray at +0x40/+0x48 exactly the way
// the engine does: `v = (mgr + 0x48); if ((int)flags >= 0) v = *v;`
void* graph_at(std::uint8_t* mgr, std::uint32_t idx) noexcept {
    const auto flags = *reinterpret_cast<const std::int32_t*>(
        mgr + MGR_ARRAY_FLAGS_OFF);
    auto** data = reinterpret_cast<void**>(mgr + MGR_ARRAY_DATA_OFF);
    if (flags >= 0) data = *reinterpret_cast<void***>(data);
    return data[idx];
}

// 2026-08-05 — READ-ONLY state probe of the parked third-person graph.
//
// Pairs with the symbolic execution of the pose-apply dispatcher: that run
// produces the checklist of field values required to reach the bone writer,
// this reads what the live parked graph actually holds. The diff names the
// gate. Strictly reads — no engine call, no store — so it is safe to run
// with the drive switched OFF, which is exactly how it is used: gather the
// evidence without risking another third-person regression.
void probe_parked_graph(std::uint8_t* mgr, std::uint8_t* g) noexcept {
    __try {
        void* hkb  = *reinterpret_cast<void**>(g + GRAPH_HKB_WRAPPER_OFF);
        void* chr  = *reinterpret_cast<void**>(g + 0x240);
        void* chr2 = chr ? *reinterpret_cast<void**>(
                        reinterpret_cast<std::uint8_t*>(chr) + 0x20) : nullptr;
        const std::uint8_t active = hkb
            ? *(reinterpret_cast<std::uint8_t*>(hkb) + HKB_ACTIVE_BYTE_OFF) : 0;
        // THE GATE: is the writer's vtbl+0x98 predicate true here? If it is,
        // the pose is diverted to the physics path and never reaches the
        // NiNodes — which would explain the frozen bones with a valid count.
        void* pw   = *reinterpret_cast<void**>(g + GRAPH_PHYS_WORLD_OFF);
        void* rdo  = *reinterpret_cast<void**>(g + GRAPH_RAGDOLL_OBJ_OFF);
        const std::uint8_t phys = g_graph_phys_pred
            ? g_graph_phys_pred(g) : 0xFF;
        const auto bones_u16 = *reinterpret_cast<std::uint16_t*>(g + 0x3C0);
        const auto arr_size  = *reinterpret_cast<std::uint32_t*>(g + 0x2B0);
        void* arr_data       = *reinterpret_cast<void**>(g + 0x2A0);
        void* pose_out       = *reinterpret_cast<void**>(g + 0x1F8);
        void* root_node      = *reinterpret_cast<void**>(g + 0x388);
        FW_LOG("[fp-probe] parked 3P graph=%p | hkb=%p m_isActive=%u | "
               "PHYS-PRED(vtbl+0x98)=%u physWorld(0x3B8)=%p rdObj(0x210)=%p | "
               "hkbChar=%p/%p | boneCount(0x3C0)=%u arrSize(0x2B0)=%u "
               "arrData(0x2A0)=%p | poseOut(0x1F8)=%p root(0x388)=%p | "
               "updateDue(0x3C5)=%u genDue(0x3C6)=%u mute(0x3C3)=%u "
               "ragdollPend(0x3CA)=%u",
               static_cast<void*>(g), hkb, active, phys, pw, rdo, chr, chr2,
               bones_u16, arr_size, arr_data, pose_out, root_node,
               *(g + 0x3C5), *(g + 0x3C6), *(g + GRAPH_MUTE_BYTE_OFF),
               *(g + 0x3CA));
        // Same fields on the ACTIVE (first-person) graph, as the control:
        // whatever differs between the two IS the gate.
        void* fp = graph_at(mgr, FIRST_PERSON_GRAPH);
        if (fp) {
            auto* f = reinterpret_cast<std::uint8_t*>(fp);
            void* fhkb = *reinterpret_cast<void**>(f + GRAPH_HKB_WRAPPER_OFF);
            FW_LOG("[fp-probe] active 1P graph=%p | hkb=%p m_isActive=%u | "
                   "PHYS-PRED(vtbl+0x98)=%u physWorld=%p | "
                   "boneCount=%u arrSize=%u arrData=%p | poseOut=%p root=%p "
                   "| updateDue=%u genDue=%u mute=%u ragdollPend=%u",
                   fp, fhkb,
                   fhkb ? *(reinterpret_cast<std::uint8_t*>(fhkb)
                            + HKB_ACTIVE_BYTE_OFF) : 0,
                   g_graph_phys_pred ? g_graph_phys_pred(f) : 0xFF,
                   *reinterpret_cast<void**>(f + GRAPH_PHYS_WORLD_OFF),
                   *reinterpret_cast<std::uint16_t*>(f + 0x3C0),
                   *reinterpret_cast<std::uint32_t*>(f + 0x2B0),
                   *reinterpret_cast<void**>(f + 0x2A0),
                   *reinterpret_cast<void**>(f + 0x1F8),
                   *reinterpret_cast<void**>(f + 0x388),
                   *(f + 0x3C5), *(f + 0x3C6), *(f + GRAPH_MUTE_BYTE_OFF),
                   *(f + 0x3CA));
        }
        // THE COMPARISON THAT SHOULD HAVE COME FIRST (2026-08-05).
        // Each graph writes its pose into ITS OWN node tree (bone array built
        // from graph+0x388). The pose capture, meanwhile, reads whatever
        // player+0xF0+0x08 hands it, and that choice was never checked
        // against the graph roots. If in first person that path yields the
        // FIRST-person tree, then the third-person graph could be animating
        // perfectly and we would still ship a frozen pose — we would simply
        // be reading the other skeleton. Print all four pointers on one line
        // and the question answers itself.
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"Fallout4.exe"));
        void* pa = nullptr;
        void* pb = nullptr;
        if (base) {
            void* player = *reinterpret_cast<void**>(
                base + fw::offsets::PLAYER_SINGLETON_RVA);
            if (player) {
                auto* pbytes = reinterpret_cast<std::uint8_t*>(player);
                void* lrd = *reinterpret_cast<void**>(
                    pbytes + fw::offsets::LOADED_REF_DATA_OFF);
                if (lrd) {
                    pa = *reinterpret_cast<void**>(
                        reinterpret_cast<std::uint8_t*>(lrd)
                        + fw::offsets::LOADED_REF_DATA_3D_OFF);
                }
                pb = *reinterpret_cast<void**>(pbytes + 0x0B78);  // REFR_LOADED_3D
            }
        }
        void* fp2 = graph_at(mgr, FIRST_PERSON_GRAPH);
        void* root1p = fp2 ? *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(fp2) + 0x388) : nullptr;
        const char* verdict =
            (pa && pa == root_node) ? "captureA == 3P-graph root (RIGHT tree)"
          : (pa && pa == root1p)    ? "captureA == 1P-graph root (WRONG tree!)"
          : "captureA matches NEITHER graph root";
        FW_LOG("[fp-probe] TREES: capturePathA=%p capturePathB=%p | "
               "root3P=%p root1P=%p  -> %s",
               pa, pb, root_node, root1p, verdict);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[fp-probe] SEH while reading graph state");
    }
}

// SEH-caged worker: everything that dereferences engine memory lives here so
// the detour body can keep its C++ locals (C2712).
bool drive_third_person_graph(void* mgr_v, void* update_data) noexcept {
    __try {
        auto* mgr = reinterpret_cast<std::uint8_t*>(mgr_v);

        // The engine's own "is this the player" test: exactly two graphs
        // (sub_140D79000 guards its toggle with size == 2). Everything else
        // in the game — every NPC — has one graph and is skipped here.
        const auto size = *reinterpret_cast<const std::uint32_t*>(
            mgr + MGR_ARRAY_SIZE_OFF);
        if (size != 2) return false;

        // Only when the engine has parked the 3P graph, i.e. first person.
        const auto active = *reinterpret_cast<const std::uint32_t*>(
            mgr + MGR_ACTIVE_OFF);
        if (active != FIRST_PERSON_GRAPH) return false;

        void* tp_graph = graph_at(mgr, THIRD_PERSON_GRAPH);
        if (!tp_graph) return false;
        auto* g = reinterpret_cast<std::uint8_t*>(tp_graph);
        g_forced_revive.store(true, std::memory_order_relaxed);
        g_driven_graph = tp_graph;   // identity for the deactivate guard

        // (1) REVIVE. SetActiveGraph deactivated this graph's Havok
        // behavior graph on the way into first person (hkb vtbl+0x50), and
        // EVERY call below early-outs on that byte — which is why the
        // first version of this hook "ran" 3600 times a minute and changed
        // nothing at all. Re-activating is idempotent: the engine's own
        // sub_141320430 no-ops when the graph is already live, and a later
        // SetActiveGraph(0) calls it again harmlessly.
        void* hkb = *reinterpret_cast<void**>(g + GRAPH_HKB_WRAPPER_OFF);
        if (!hkb) return false;
        auto* live = reinterpret_cast<std::uint8_t*>(hkb) + HKB_ACTIVE_BYTE_OFF;
        if (!*live) {
            if (!g_graph_activate) return false;
            g_graph_activate(tp_graph);
            if (!*live) return false;   // refused to wake — nothing to do

            // A freshly activated behavior sits in its INITIAL state, which
            // renders as T-pose, and only leaves it when an event moves the
            // state machine. In a session that starts in first person nothing
            // ever raises one while the player stands still, so both ghosts
            // spawned in T-pose until the player did something. Raise the
            // behavior's own base-state trigger, then settle it into idle.
            // (Names identified by logging the active-node count around every
            // mirrored event — these are the ones that actually move it.)
            if (g_wake_events_ready && g_graph_send_event) {
                mgr_lock(mgr);
                for (auto& s : g_wake_event_str) {
                    if (s) g_graph_send_event(tp_graph, &s, nullptr);
                }
                mgr_unlock(mgr);
                FW_LOG("[fp-graph] wake-up events raised on the freshly "
                       "revived third-person graph — no manual action needed "
                       "to leave T-pose");
            }
        }

        // (2) DO NOT MUTE. Round 7 verdict, and it was my own bug twice over.
        //
        // graph+0x3C3 looked like a safe "suppress this graph's outward
        // channels" flag. It is not: with it set, sub_14131DC40 becomes
        //     if (mute) { wipe the character event queue; return; }
        // so hkbBehaviorGraph::handleEvents NEVER runs and every event the
        // graph raises FOR ITSELF — clip triggers, annotations, state-machine
        // transition events — is thrown away each frame. A state machine
        // waiting on one of those stays in its state forever. That is the
        // frozen pose. (The same byte, left set, is what stopped third-person
        // WASD movement earlier.) The engine never sets it on this path.
        // Outward gameplay traffic stays suppressed by the a3 = NULL argument
        // to the pose-apply call instead, which is the engine's own idiom.
        g_mute_graph = nullptr;

        // (2b) REFRESH THE ACTIVE NODE LIST. The engine's out-of-band drive
        // (its graph-bind path) does this before Update whenever the dirty
        // byte is set; skipping it leaves the timestep being fanned out over
        // a stale or empty node list, which stops the clip clock while
        // generate still writes a full pose.
        if (*(reinterpret_cast<std::uint8_t*>(hkb) + HKB_NODES_DIRTY_OFF)
            && g_hkb_ctx_ctor && g_hkb_upd_active && g_hkb_upd_sync
            && g_hkb_ctx_dtor) {
            void* physh = *reinterpret_cast<void**>(g + GRAPH_PHYS_WORLD_OFF);
            void* world = physh ? *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(physh) + 0x30) : nullptr;
            std::uint8_t hctx[0x80] = {};
            g_hkb_ctx_ctor(hctx, g + GRAPH_HKB_CHARACTER_OFF, world, nullptr);
            g_hkb_upd_active(hkb, hctx, 0);
            g_hkb_upd_sync(hkb, hctx);
            g_hkb_ctx_dtor(hctx);
        }

        // (3) The engine's own three-step frame, under the manager lock
        // (recursive by thread id — every engine call site holds it):
        //     flush bound channel values -> generate pose -> APPLY to bones.
        // Step three was the other half of the bug: sub_141320530 only
        // fills the Havok pose buffers; the NiAVObject write lives behind
        // sub_141320C40, which the engine runs for the ACTIVE graph only.
        // NULL event array is engine-sanctioned (its own bind path passes
        // 0) and keeps the event queue out of gameplay.
        // (2d) STARTUP WAKE KICK — REMOVED (2026-08-05, measured).
        //
        // Cycling the graph (deactivate + activate) to shake it out of T-pose
        // did the opposite: the live counter went from 59 active nodes to 19,
        // i.e. straight back to the initial state. Activate REBUILDS the
        // active-node list from the root, which is the very reset the
        // deactivate guard exists to prevent — I reintroduced it by hand.
        // The graph does not need cycling; it needs the EVENT that moves its
        // state machine out of the initial state. Drawing a weapon supplies
        // one, which is why a manual action "fixes" it. The event names are
        // logged below so the right one can be raised at wake-up instead.
#if 0
        // (kept for the record; do not re-enable without new evidence)
        //
        // A graph that has never been active since load sits in its initial
        // state — which renders as T-pose — and only leaves it when something
        // makes it transition. In a session that begins in first person there
        // is no camera switch to re-prime it, so both ghosts spawn in T-pose
        // until the player happens to draw a weapon or swing. (This is a
        // SENDER-side problem: the peer's ghost is showing the pose we ship,
        // so no amount of server signalling would fix it on the receiver.)
        // Once, a few seconds after the drive first runs — late enough that
        // the world and the skeleton are settled — cycle the graph the way a
        // camera switch would and re-prime its locomotion. From then on the
        // mirrored events keep it moving.
        {
            static std::uint64_t s_kick_at_ms = 0;
            static bool s_kicked = false;
            const std::uint64_t now = GetTickCount64();
            if (s_kick_at_ms == 0) {
                s_kick_at_ms = now + 3000;      // arm on the first driven frame
            } else if (!s_kicked && now >= s_kick_at_ms) {
                s_kicked = true;
                if (g_orig_graph_deactivate && g_graph_activate) {
                    g_allow_deactivate.store(true, std::memory_order_relaxed);
                    g_orig_graph_deactivate(tp_graph, nullptr);
                    g_allow_deactivate.store(false, std::memory_order_relaxed);
                    g_graph_activate(tp_graph);
                }
                FW_LOG("[fp-graph] startup wake kick — cycled and re-primed "
                       "the third-person graph so the ghost leaves T-pose "
                       "without the player having to do anything");
            }
        }
#endif

        // (3) FORCED update context — this is what the previous attempt got
        // wrong. Reusing the engine's own update data means reusing the
        // camera pointer and LOD word it computed FOR THE FIRST-PERSON
        // GRAPH. sub_141320530 then runs its distance/LOD throttle against
        // the parked graph's root node, scaling the squared distance by
        // (80.0 / root.worldScale)^2, and on the skip branch it clears
        // "update due" / "generate due" and sets the per-frame bone count to
        // the LOD value. A hidden third-person body is exactly the case that
        // resolves to "generate nothing", so the pose-apply that followed had
        // zero bones to write — the writer ran and wrote nothing, which is
        // precisely what the frozen matrices showed.
        // The engine's own graph-bind path builds a FORCED context instead:
        // null camera pointer and the force byte set, which takes the
        // generate branch unconditionally and uses the full bone count.
        // Layout proven from the bind function's stack frame.
        // Layout per the engine's own per-frame driver (sub_140818870), NOT
        // its bind path — the bind path deliberately passes dt = 0 because it
        // wants a STATIC prime, and copying that was the trap.
        //
        // The delta time is the only time input in the whole pipeline, and it
        // does not travel inside the Havok context: the disassembly shows it
        // loaded from ud+0x00 into xmm9 and handed to hkbBehaviorGraph::update
        // as a third argument in xmm2 (IDA drops it from the pseudo-C, which
        // is why an earlier pass concluded the context carried no timestep).
        // From there computeTimestepForActiveNodes fans it out per node. With
        // dt == 0 every generator keeps its local clock, so generate runs,
        // all 95 bones are written, events still force transitions — and the
        // clip never advances. Exactly the observed symptom.
        std::uint8_t ctx[0x40] = {};
        const float dt = *reinterpret_cast<const float*>(update_data);
        *reinterpret_cast<float*>(ctx + 0x00) = dt;
        *reinterpret_cast<void**>(ctx + 0x08) = nullptr;  // no camera = force
        *reinterpret_cast<std::uint16_t*>(ctx + 0x18) = 0;   // no bone cap
        ctx[0x1A] = 1;   // force full LOD (skips the distance throttle)
        ctx[0x1B] = 1;
        ctx[0x1C] = 1;
        ctx[0x1D] = 1;   // allow the IK/foot block, as the engine does

        // Sentinel: Update's last statement inside the gated block is
        // `graph+0x3A8 = ud+0x00`. Poison it first; if it comes back holding
        // our dt, all four entry gates passed and the call really executed.
        // If it stays poisoned, nothing ran and every other measurement is
        // meaningless.
        *reinterpret_cast<float*>(g + 0x3A8) = -12345.0f;

        // (2c) REFRESH THE LOCOMOTION SNAPSHOT, EVERY FRAME.
        //
        // The engine recomputes speed, iSyncForwardState, iSyncStrafeState,
        // iSyncTurnState, iSyncIdleLocomotion and iSyncJumpState in
        // PopulateGraphVariables — and calls it for the ACTIVE graph only.
        // Priming the parked graph once at the camera switch (which is what
        // round 9 did) leaves it frozen on that instant's values: it never
        // learns that the player has since changed direction or started
        // sprinting. That is exactly the reported residue — no strafing
        // animation, and an occasional walk where a run belongs. Refresh it
        // on every driven frame instead.
        if (g_pc_populate_vars) {
            const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(L"Fallout4.exe"));
            void* player = base ? *reinterpret_cast<void**>(
                base + fw::offsets::PLAYER_SINGLETON_RVA) : nullptr;
            if (player) {
                void* holder = reinterpret_cast<std::uint8_t*>(player)
                             + ACTOR_HOLDER_OFF;
                void* gp = tp_graph;
                g_pc_populate_vars(holder, &gp);
            }
        }

        // (2e) LOCOMOTION SCALARS from the player's REAL motion.
        // NOTE ON ORDER: these are written AFTER the channel flush below, not
        // here. sub_141320EA0 copies the manager's cached channel values into
        // the target graph, so anything written before it that shares a name
        // with a bound channel is overwritten on the spot. Writing after the
        // flush and before the update is what makes the value survive to the
        // clip. Computed here, applied further down.
        float loco_speed = 0.0f;
        float loco_dir   = 0.0f;
        bool  loco_ready = false;
        //
        // SpeedSampled scales the walk/run clips; Direction picks the strafe
        // axis. Derived here from the actual per-frame displacement and the
        // body yaw — the same trick the owner side already uses for mirrored
        // NPCs — and written with the PER-GRAPH setter so the first-person
        // graph driving the player's own arms is never touched.
        if (g_loco_vars_ready && g_graph_set_var_float) {
            const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(L"Fallout4.exe"));
            void* player = base ? *reinterpret_cast<void**>(
                base + fw::offsets::PLAYER_SINGLETON_RVA) : nullptr;
            if (player && dt > 1e-4f) {
                auto* pb = reinterpret_cast<std::uint8_t*>(player);
                const float* p =
                    reinterpret_cast<const float*>(pb + fw::offsets::POS_OFF);
                const float yaw = *reinterpret_cast<const float*>(
                    pb + fw::offsets::ROT_OFF + 8);
                static float s_prev[3] = {0.0f, 0.0f, 0.0f};
                static bool  s_have    = false;
                if (s_have) {
                    const float dx = p[0] - s_prev[0];
                    const float dy = p[1] - s_prev[1];
                    const float dist = std::sqrt(dx * dx + dy * dy);
                    const float speed = dist / dt;      // game units per second
                    float dir = 0.0f;
                    if (dist > 0.05f) {
                        // Movement heading in math convention, minus the body
                        // forward (Bethesda yaw: 0 = +Y, clockwise), in
                        // degrees and wrapped to [-180, 180].
                        const float move = std::atan2(dy, dx);
                        const float fwd  = 1.57079633f - yaw;
                        dir = (move - fwd) * 57.2957795f;
                        while (dir >  180.0f) dir -= 360.0f;
                        while (dir < -180.0f) dir += 360.0f;
                    }
                    loco_speed = speed;
                    loco_dir   = dir;
                    loco_ready = true;
                }
                s_prev[0] = p[0]; s_prev[1] = p[1]; s_prev[2] = p[2];
                s_have = true;
            }
        }

        mgr_lock(mgr);
        if (g_graph_flush) g_graph_flush(tp_graph, mgr + MGR_EVENT_ARRAY_OFF);
        // AFTER the flush (see the note above), BEFORE the update: this is the
        // only window where the value reaches the clip generator intact.
        // 2026-08-06 — DISABLED. Deriving SpeedSampled/Direction from the
        // frame-to-frame displacement is unsound here: this drive does not run
        // on every frame (only while the camera is in first person), so the
        // displacement spans gaps the dt does not account for. Measured live:
        // client A reported 5953 where ~100-200 was expected, client B a
        // constant 0. It made the walk worse, not better. The clean source is
        // the engine's own movement speed rather than a positional delta —
        // left for whenever this is picked up again.
        (void)loco_speed; (void)loco_dir; (void)loco_ready;
        if (g_graph_update) g_graph_update(tp_graph, ctx);
        if (g_graph_pose_apply) g_graph_pose_apply(tp_graph, nullptr);
        mgr_unlock(mgr);

        // Post-call truth: did the generate branch actually run, and with how
        // many bones? These are the numbers that matter, read straight after
        // the call instead of from a stale parked graph.
        {
            static std::uint64_t s_next_ms = 0;
            const std::uint64_t now = GetTickCount64();
            if (now >= s_next_ms) {
                s_next_ms = now + 3000;
                // ragdollPend (0x3CA) is the next suspect: the per-graph
                // SendEvent (sub_141320FE0) refuses to run while it is set,
                // which would leave this graph's state machine frozen in
                // whatever state it was parked in — exactly the "generates,
                // but always the same idle pose" symptom. activate() only
                // clears it when graph+0x3A0 is non-null.
                // 2026-08-05 round 6 — TIME. Events now reach the parked
                // graph (a real organic pose appeared the instant one did),
                // but between events it regenerates the same frame forever.
                // Update decrements the graph's two frame timers (+0x350 /
                // +0x354) by the context's delta time and gates the generate
                // branch on them; a zero dt freezes the clip. Print what the
                // engine's own context actually holds in its first floats
                // next to the timers, instead of assuming offset 0 is dt.
                // Round 7 measurements, all decisive:
                //  * 0x3A8 — Update's last statement inside the gated block
                //    (`graph+0x3A8 = ud+0x00`). We poisoned it with -12345
                //    before the call: if it still reads -12345 the function
                //    never executed and every other number here is noise.
                //  * active node count — hkbBehaviorGraph::update fans the
                //    timestep out over m_activeNodes (hkb+0xE0, size at +8).
                //    An empty list means nothing to advance no matter how
                //    correct the timestep is.
                //  * the two timers, which decide the timestep: with
                //    0x350 = 0.0 / 0x354 = -FLT_MAX the disassembly's
                //    min(-timer, dt) resolves to dt and the clamp to zero is
                //    NOT taken.
                void* hkb2 = *reinterpret_cast<void**>(g + GRAPH_HKB_WRAPPER_OFF);
                void* act_nodes = hkb2 ? *reinterpret_cast<void**>(
                    reinterpret_cast<std::uint8_t*>(hkb2) + 0xE0) : nullptr;
                const std::int32_t act_count = act_nodes
                    ? *reinterpret_cast<std::int32_t*>(
                          reinterpret_cast<std::uint8_t*>(act_nodes) + 8)
                    : -1;
                FW_LOG("[fp-graph] post-drive: RAN=%s (0x3A8=%.5f vs dt=%.5f) "
                       "| activeNodes=%p count=%d | boneCount=%u "
                       "updateDue=%u genDue=%u | timers 0x350=%.5f "
                       "0x354=%.3e",
                       (*reinterpret_cast<float*>(g + 0x3A8) != -12345.0f)
                           ? "YES" : "NO-OP",
                       *reinterpret_cast<float*>(g + 0x3A8), dt,
                       act_nodes, act_count,
                       *reinterpret_cast<std::uint16_t*>(g + 0x3C0),
                       *(g + 0x3C5), *(g + 0x3C6),
                       *reinterpret_cast<float*>(g + 0x350),
                       static_cast<double>(
                           *reinterpret_cast<float*>(g + 0x354)));
            }
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
        // Restore the gag no matter how we got here: a leaked mute byte is
        // the exact regression that stopped third-person movement.
        if (g_mute_graph) {
            *(g_mute_graph + GRAPH_MUTE_BYTE_OFF) = g_mute_saved;
            g_mute_graph = nullptr;
        }
        return false;
    }
}

// Mirror one animation event onto the parked third-person graph.
// a3 = NULL is the entire safety story: sink notifications are collected only
// under `if (result && a3)`, and the collector itself bails on `!a3`. With
// NULL there is ZERO outward gameplay traffic from this graph — no duplicated
// footsteps, hit frames, weapon fire or script events. The engine uses this
// exact form in its own deferred-event path.
std::uint8_t __fastcall detour_mgr_notify(void* mgr_v, const void* ev) {
    const std::uint8_t r = g_orig_mgr_notify
        ? g_orig_mgr_notify(mgr_v, ev) : 0;   // engine first, answer untouched
    if (!g_enabled.load(std::memory_order_relaxed)) return r;
    if (!mgr_v || !ev || !g_graph_send_event) return r;
    __try {
        auto* mgr = reinterpret_cast<std::uint8_t*>(mgr_v);
        if (*reinterpret_cast<std::uint32_t*>(mgr + MGR_ARRAY_SIZE_OFF) != 2) {
            return r;                      // player-shaped manager only
        }
        if (*reinterpret_cast<std::uint32_t*>(mgr + MGR_ACTIVE_OFF)
                != FIRST_PERSON_GRAPH) {
            return r;                      // only while 3P is the parked one
        }
        void* g3p = graph_at(mgr, THIRD_PERSON_GRAPH);
        if (!g3p) return r;
        auto* g = reinterpret_cast<std::uint8_t*>(g3p);
        void* hkb = *reinterpret_cast<void**>(g + GRAPH_HKB_WRAPPER_OFF);
        if (!hkb) return r;
        if (!*(reinterpret_cast<std::uint8_t*>(hkb) + HKB_ACTIVE_BYTE_OFF)) {
            return r;                      // not revived yet — nothing to feed
        }
        if (*(g + 0x3CA)) return r;        // SendEvent refuses while pending
        // Read the active-node count around the send: the event that lifts the
        // graph out of its initial state is the one where this jumps (measured
        // 19 in the initial state, 59 once it is really animating). Logging
        // the NAME next to it identifies exactly which event to raise
        // ourselves at wake-up, instead of waiting for the player to draw a
        // weapon. BSFixedString: the qword is a pool entry whose inline ASCII
        // starts at +0x18 (same layout the node-name readers in this project
        // already rely on).
        void* an_before = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(hkb) + HKB_ACTIVE_NODES_OFF);
        const std::int32_t cnt_before = an_before
            ? *reinterpret_cast<std::int32_t*>(
                  reinterpret_cast<std::uint8_t*>(an_before) + 8) : -1;

        mgr_lock(mgr);
        g_graph_send_event(g3p, ev, nullptr);
        mgr_unlock(mgr);

        void* an_after = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(hkb) + HKB_ACTIVE_NODES_OFF);
        const std::int32_t cnt_after = an_after
            ? *reinterpret_cast<std::int32_t*>(
                  reinterpret_cast<std::uint8_t*>(an_after) + 8) : -1;
        if (cnt_after != cnt_before) {
            const char* nm = "?";
            __try {
                auto* pool = *reinterpret_cast<char* const*>(ev);
                if (pool) nm = pool + 0x18;
            } __except (EXCEPTION_EXECUTE_HANDLER) { nm = "<unreadable>"; }
            FW_LOG("[fp-graph] EVENT '%s' moved the parked graph: activeNodes "
                   "%d -> %d", nm, cnt_before, cnt_after);
        }

        const auto n = g_events_mirrored.fetch_add(1, std::memory_order_relaxed);
        if (n == 0) {
            FW_LOG("[fp-graph] event mirroring live — the parked 3P state "
                   "machine now receives the same animation events as the "
                   "active 1P one (a3=NULL: no outward gameplay traffic)");
        } else if ((n % 500) == 0) {
            FW_LOG("[fp-graph] %llu events mirrored to the parked graph",
                   static_cast<unsigned long long>(n));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh.fetch_add(1, std::memory_order_relaxed);
    }
    return r;
}

// Undo the "sticky revive" before the engine switches back to third person.
//
// sub_141320430 (Activate) early-outs when the graph is ALREADY active. Since
// this module leaves the parked third-person graph revived, the engine's own
// SetActiveGraph(0) on the way back to third person would hit that early-out
// and skip both the ragdoll-bind registration and the clear of the pending
// flag. Hand the graph back deactivated — the exact call the engine's own
// DeactivateAll makes — so its activation runs in full.
std::uint8_t __fastcall detour_set_active_graph(void* mgr_v,
                                                std::uint32_t new_idx) {
    if (g_forced_revive.load(std::memory_order_relaxed)
        && new_idx == THIRD_PERSON_GRAPH && mgr_v && g_graph_deactivate) {
        __try {
            auto* mgr = reinterpret_cast<std::uint8_t*>(mgr_v);
            if (*reinterpret_cast<std::uint32_t*>(mgr + MGR_ARRAY_SIZE_OFF)
                    == 2) {
                void* g3p = graph_at(mgr, THIRD_PERSON_GRAPH);
                if (g3p) {
                    // Bypass our own guard for this one deliberate call.
                    g_allow_deactivate.store(true, std::memory_order_relaxed);
                    if (g_orig_graph_deactivate) {
                        g_orig_graph_deactivate(g3p, nullptr);
                    }
                    g_allow_deactivate.store(false, std::memory_order_relaxed);
                    // Round 8 bug, fixed: this used to null g_driven_graph.
                    // The guard then failed to recognise the graph on the NEXT
                    // entry into first person, the engine's deactivate went
                    // through, and the ghost was reborn in T-pose again — the
                    // exact symptom the guard was written to prevent. The
                    // pointer stays; it is only ever compared, never
                    // dereferenced, so a stale value is harmless.
                    FW_LOG("[fp-graph] handing the 3P graph back DEACTIVATED "
                           "so the engine's own activation runs in full "
                           "(ragdoll bind + pending flag)");
                }
            }
            g_forced_revive.store(false, std::memory_order_relaxed);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_seh.fetch_add(1, std::memory_order_relaxed);
        }
    }
    const std::uint8_t r =
        g_orig_set_active ? g_orig_set_active(mgr_v, new_idx) : 0;

    // Entering FIRST person: re-prime the third-person graph's locomotion
    // variables from the actor's live state. This is the engine's own
    // "populate" call, the one it uses when priming a graph after a reset —
    // exactly the forced refresh the ghost was missing at the switch. Without
    // it the parked graph keeps whatever locomotion values it had and starts
    // in the wrong state, which is what left the body in T-pose until some
    // event (drawing a weapon, swinging) happened to wake it.
    if (g_enabled.load(std::memory_order_relaxed)
        && new_idx == FIRST_PERSON_GRAPH && mgr_v && g_pc_populate_vars) {
        __try {
            auto* mgr = reinterpret_cast<std::uint8_t*>(mgr_v);
            if (*reinterpret_cast<std::uint32_t*>(mgr + MGR_ARRAY_SIZE_OFF)
                    == 2) {
                void* g3p = graph_at(mgr, THIRD_PERSON_GRAPH);
                const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(
                    GetModuleHandleW(L"Fallout4.exe"));
                void* player = base ? *reinterpret_cast<void**>(
                    base + fw::offsets::PLAYER_SINGLETON_RVA) : nullptr;
                if (g3p && player) {
                    void* holder = reinterpret_cast<std::uint8_t*>(player)
                                 + ACTOR_HOLDER_OFF;
                    void* gp = g3p;          // BSTSmartPointer-shaped argument
                    g_pc_populate_vars(holder, &gp);
                    static std::atomic<std::uint64_t> s_n{0};
                    const auto k = s_n.fetch_add(1, std::memory_order_relaxed);
                    if (k == 0 || (k % 20) == 0) {
                        FW_LOG("[fp-graph] re-primed the third-person graph's "
                               "locomotion variables at the camera switch "
                               "(#%llu) — no more waiting for an event to "
                               "leave T-pose",
                               static_cast<unsigned long long>(k));
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_seh.fetch_add(1, std::memory_order_relaxed);
        }
    }
    return r;
}

// Keep the driven third-person graph from being deactivated on the way INTO
// first person: deactivate resets its state machine, and the re-activation we
// then perform gives it back as a newborn (T-pose) instead of a body that was
// already walking. Our own undo path calls the original directly, so the trip
// back to third person still hands the graph over properly deactivated.
std::uint8_t __fastcall detour_graph_deactivate(void* graph, void* scrap) {
    if (graph && graph == g_driven_graph
        && g_enabled.load(std::memory_order_relaxed)
        && !g_allow_deactivate.load(std::memory_order_relaxed)) {
        const auto n = g_deact_suppressed.fetch_add(
            1, std::memory_order_relaxed);
        if (n == 0) {
            FW_LOG("[fp-graph] keeping the third-person graph ALIVE across "
                   "the camera switch — deactivating it would reset its "
                   "state machine and the ghost would restart in T-pose "
                   "until some event woke it");
        }
        return 0;
    }
    return g_orig_graph_deactivate ? g_orig_graph_deactivate(graph, scrap) : 0;
}

// Suppress the first-person -> third-person skeleton copy while we are driving
// the third-person graph, so the pose we just generated survives to the pose
// capture. See the block comment on PC_SKELETON_SYNC_RVA.
void __fastcall detour_pc_skeleton_sync(void* pc) {
    if (g_enabled.load(std::memory_order_relaxed)
        && g_fires.load(std::memory_order_relaxed) > 0) {
        const auto n = g_sync_suppressed.fetch_add(1, std::memory_order_relaxed);
        if (n == 0) {
            FW_LOG("[fp-graph] suppressing the engine's first-person -> "
                   "third-person bone copy while driving: it ran one call "
                   "after our pose and overwrote it every frame (the body is "
                   "APP_CULLED locally, so nothing is lost on this screen)");
        } else if ((n % 3600) == 0) {
            FW_LOG("[fp-graph] %llu skeleton-sync copies suppressed",
                   static_cast<unsigned long long>(n));
        }
        return;                      // skip the overwrite entirely
    }
    if (g_orig_skel_sync) g_orig_skel_sync(pc);
}

void __fastcall detour_graph_mgr_update(void* mgr, void* update_data) {
    // Engine first, untouched: the active graph (1P while the player is in
    // first person) gets its normal frame, so the local player's own arms
    // and weapon keep animating.
    if (g_orig_mgr_update) g_orig_mgr_update(mgr, update_data);

    if (!mgr || !update_data) return;
    // Solo play costs nothing: without a peer there is no ghost to animate.
    if (!fw::net::client().is_connected()) return;

    // 2026-08-05 — read-only state probe, runs whether or not the drive is
    // enabled (see probe_parked_graph). Throttled to one pair of lines every
    // 5 s so a first-person session leaves a readable trace instead of a
    // flood.
    {
        static std::uint64_t s_next_probe_ms = 0;
        const std::uint64_t now = GetTickCount64();
        if (now >= s_next_probe_ms) {
            __try {
                auto* m = reinterpret_cast<std::uint8_t*>(mgr);
                const auto size = *reinterpret_cast<const std::uint32_t*>(
                    m + MGR_ARRAY_SIZE_OFF);
                const auto active = *reinterpret_cast<const std::uint32_t*>(
                    m + MGR_ACTIVE_OFF);
                if (size == 2 && active == FIRST_PERSON_GRAPH) {
                    s_next_probe_ms = now + 5000;
                    void* tp = graph_at(m, THIRD_PERSON_GRAPH);
                    if (tp) {
                        probe_parked_graph(
                            m, reinterpret_cast<std::uint8_t*>(tp));
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    if (!g_enabled.load(std::memory_order_relaxed)) return;

    if (drive_third_person_graph(mgr, update_data)) {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        if (n == 0) {
            FW_LOG("[fp-graph] driving the THIRD-person graph while the "
                   "camera is in first person: revived (hkb+0x1AA), muted "
                   "(0x3C3), then flush+generate+APPLY — the apply step "
                   "(sub_141320C40) is what actually writes the bones");
        } else if ((n % 3600) == 0) {
            FW_LOG("[fp-graph] heartbeat: %llu extra 3P graph updates "
                   "(seh=%llu)", static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_seh.load(std::memory_order_relaxed)));
        }
    }
}

}  // namespace

void set_first_person_graph_drive(bool enabled) noexcept {
    g_enabled.store(enabled, std::memory_order_relaxed);
    FW_LOG("[fp-graph] third-person graph drive in first person = %s",
           enabled ? "ON" : "OFF");
}

void set_stream_pose_in_first_person(bool enabled) noexcept {
    g_stream_in_1p.store(enabled, std::memory_order_relaxed);
    FW_LOG("[fp-graph] pose stream while in first person = %s",
           enabled ? "ON (experiment)" : "OFF (hold last 3P pose)");
}

bool stream_pose_in_first_person() noexcept {
    return g_stream_in_1p.load(std::memory_order_relaxed);
}

bool fp_graph_is_driving() noexcept {
    return g_installed.load(std::memory_order_relaxed)
        && g_enabled.load(std::memory_order_relaxed)
        && g_fires.load(std::memory_order_relaxed) > 0;
}

std::uint64_t get_fp_graph_fires() {
    return g_fires.load(std::memory_order_relaxed);
}

std::uint64_t get_fp_graph_seh() {
    return g_seh.load(std::memory_order_relaxed);
}

bool install_first_person_graph(std::uintptr_t module_base) {
    if (!module_base) return false;

    g_graph_update = reinterpret_cast<GraphUpdateFn>(
        module_base + GRAPH_UPDATE_RVA);
    g_graph_flush = reinterpret_cast<GraphEventFlushFn>(
        module_base + GRAPH_EVENT_FLUSH_RVA);
    g_graph_activate = reinterpret_cast<GraphActivateFn>(
        module_base + GRAPH_ACTIVATE_RVA);
    g_graph_pose_apply = reinterpret_cast<GraphPoseApplyFn>(
        module_base + GRAPH_POSE_APPLY_RVA);
    g_graph_phys_pred = reinterpret_cast<GraphPhysPredFn>(
        module_base + GRAPH_PHYS_PRED_RVA);
    g_graph_send_event = reinterpret_cast<GraphSendEventFn>(
        module_base + GRAPH_SEND_EVENT_RVA);
    g_graph_deactivate = reinterpret_cast<GraphDeactivateFn>(
        module_base + GRAPH_DEACTIVATE_RVA);
    g_hkb_ctx_ctor = reinterpret_cast<HkbCtxCtorFn>(
        module_base + HKB_CTX_CTOR_RVA);
    g_hkb_ctx_dtor = reinterpret_cast<HkbCtxDtorFn>(
        module_base + HKB_CTX_DTOR_RVA);
    g_hkb_upd_active = reinterpret_cast<HkbUpdActiveFn>(
        module_base + HKB_UPD_ACTIVE_RVA);
    g_hkb_upd_sync = reinterpret_cast<HkbUpdSyncFn>(
        module_base + HKB_UPD_SYNC_RVA);
    g_pc_populate_vars = reinterpret_cast<void(__fastcall*)(void*, void**)>(
        module_base + PC_POPULATE_VARS_RVA);
    g_bsfixedstring_ctor =
        reinterpret_cast<void*(__fastcall*)(void**, const char*)>(
            module_base + BSFIXEDSTRING_CTOR_RVA);
    g_graph_set_var_float =
        reinterpret_cast<std::uint8_t(__fastcall*)(void*, void**, float)>(
            module_base + GRAPH_SET_VAR_FLOAT_RVA);
    __try {
        for (std::size_t i = 0;
             i < sizeof(kWakeEvents) / sizeof(kWakeEvents[0]); ++i) {
            g_bsfixedstring_ctor(&g_wake_event_str[i], kWakeEvents[i]);
        }
        g_wake_events_ready = true;
        for (std::size_t i = 0;
             i < sizeof(kLocoVars) / sizeof(kLocoVars[0]); ++i) {
            g_bsfixedstring_ctor(&g_loco_var_str[i], kLocoVars[i]);
        }
        g_loco_vars_ready = true;
        FW_LOG("[fp-graph] interned wake-up events ('%s', '%s') and "
               "locomotion vars ('%s', '%s')",
               kWakeEvents[0], kWakeEvents[1],
               kLocoVars[0], kLocoVars[1]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_wake_events_ready = false;
        FW_WRN("[fp-graph] could not intern the wake-up event names — the "
               "ghost will need a manual action to leave T-pose at spawn");
    }

    // Round 8: keep the driven graph's state machine alive across the camera
    // switch (installed before the skeleton-sync hook so g_graph_deactivate
    // still points at the raw function when we take the trampoline).
    if (install(reinterpret_cast<void*>(module_base + GRAPH_DEACTIVATE_RVA),
                reinterpret_cast<void*>(&detour_graph_deactivate),
                reinterpret_cast<void**>(&g_orig_graph_deactivate))) {
        FW_LOG("[fp-graph] deactivate guard installed (RVA 0x%lX) — the "
               "third-person state machine survives the camera switch "
               "instead of being reborn in T-pose",
               static_cast<unsigned long>(GRAPH_DEACTIVATE_RVA));
    } else {
        FW_ERR("[fp-graph] FAILED to hook the graph deactivate — the ghost "
               "will restart in T-pose on every first-person entry");
    }

    // THE decisive hook: stop the engine overwriting the third-person bones
    // with the first-person ones right after we generate them.
    if (install(reinterpret_cast<void*>(module_base + PC_SKELETON_SYNC_RVA),
                reinterpret_cast<void*>(&detour_pc_skeleton_sync),
                reinterpret_cast<void**>(&g_orig_skel_sync))) {
        FW_LOG("[fp-graph] skeleton-sync hook installed (RVA 0x%lX) — the "
               "1P->3P bone copy is what erased every previous attempt",
               static_cast<unsigned long>(PC_SKELETON_SYNC_RVA));
    } else {
        FW_ERR("[fp-graph] FAILED to hook the 1P->3P skeleton copy — the "
               "driven pose will keep being overwritten each frame");
    }

    // Event mirroring + sticky-revive undo. Both are secondary to the main
    // update hook: if either fails to install the drive still runs, it just
    // keeps looping the parked state's clip.
    if (install(reinterpret_cast<void*>(module_base + MGR_NOTIFY_RVA),
                reinterpret_cast<void*>(&detour_mgr_notify),
                reinterpret_cast<void**>(&g_orig_mgr_notify))) {
        FW_LOG("[fp-graph] event mirror hook installed on "
               "BSAnimationGraphManager::NotifyAnimationGraph (RVA 0x%lX)",
               static_cast<unsigned long>(MGR_NOTIFY_RVA));
    } else {
        FW_ERR("[fp-graph] FAILED to hook NotifyAnimationGraph — the parked "
               "graph will keep looping its parked state");
    }
    if (install(reinterpret_cast<void*>(module_base + SET_ACTIVE_GRAPH_RVA),
                reinterpret_cast<void*>(&detour_set_active_graph),
                reinterpret_cast<void**>(&g_orig_set_active))) {
        FW_LOG("[fp-graph] SetActiveGraph hook installed (RVA 0x%lX) — undoes "
               "the sticky revive on the way back to third person",
               static_cast<unsigned long>(SET_ACTIVE_GRAPH_RVA));
    } else {
        FW_ERR("[fp-graph] FAILED to hook SetActiveGraph — third person may "
               "lose its ragdoll bind after a first-person session");
    }

    void* target = reinterpret_cast<void*>(module_base + GRAPH_MGR_UPDATE_RVA);
    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_graph_mgr_update),
        reinterpret_cast<void**>(&g_orig_mgr_update));
    g_installed.store(ok, std::memory_order_relaxed);
    if (ok) {
        FW_LOG("[fp-graph] hook installed on BSAnimationGraphManager::Update "
               "(RVA 0x%lX) — graphs[0] gets an extra tick whenever a "
               "two-graph manager sits on index 1",
               static_cast<unsigned long>(GRAPH_MGR_UPDATE_RVA));
    } else {
        FW_ERR("[fp-graph] FAILED to hook RVA 0x%lX — ghost keeps the last "
               "3P pose while the sender is in first person",
               static_cast<unsigned long>(GRAPH_MGR_UPDATE_RVA));
    }
    return ok;
}

}  // namespace fw::hooks
