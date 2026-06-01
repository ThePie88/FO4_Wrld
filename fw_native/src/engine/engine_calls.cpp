#include "engine_calls.h"

#include <windows.h>
#include <atomic>
#include <cmath>
#include <cstring>
#include <mutex>
#include <unordered_set>

#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../hooks/container_hook.h"   // ApplyingRemoteGuard for TLS bypass
#include "../native/scene_inject.h"    // B6.6w5 Build 8b: get_injected_body_ghost()
#include "../hooks/npc_ai_suppress.h"  // B6.6w5 Build 12 Fix 1 gate: get_fid_for_aiproc
#include "../hooks/ghost_is_attachable.h"  // B6.6w5 Build 28f: TLS bypass for IsAttachable during spawn
#include "../main_thread_dispatch.h"        // Build 55f: mark_raider_ghost_targeted_yaw

namespace fw::engine {

namespace {

// Function pointer types for the engine natives.
using LookupByFormIDFn = void* (*)(std::uint32_t form_id);
using DisableEnqueueFn = void (*)(void* ref, std::uint8_t fade_out);
using EnableCleanupFn  = void (*)(void* ref);
using EnableApplyFn    = void (*)(void* ref);
// B1.e: BGSInventoryList accessor — takes the BGSInventoryItem* (entry
// pointer inside the list), returns its int count.
using InvItemGetCountFn = int (*)(void* entry);
// B1.j.1: BGSInventoryList materializer + CONT component getter. Re-uses
// the engine's own lazy materialization (sub_140511F10 @ 0x511F10) that
// the engine would otherwise invoke the first time the player interacts
// with the container. Calling it ourselves pre-scan ensures REFR+0xF8
// holds the complete list.
using MaterializeInvListFn = void* (*)(void* refr, void* bgscont);
using GetComponentFn       = void* (*)(void* form, std::uint32_t sig);
// B1.g: engine's real AddItem / RemoveItem. Papyrus ObjectReference.AddItem
// / RemoveItem bottom out here after the functor dispatch. Signatures
// documented in offsets.h.
using EngineAddItemFn    = void (*)(
    void* container_refr, void* item_form, std::uint32_t count,
    std::uint8_t flag, std::uint32_t vm_id, void* vm_state);
using EngineRemoveItemFn = void (*)(
    void* container_refr, void* item_form, std::uint32_t count,
    std::uint8_t flag, void* dest_actor_refr, std::uint8_t flag2,
    std::uint32_t vm_id, void* vm_state);
// B1.k.2: sub_14021E230 — BGSObjectRefHandle → TESObjectREFR* resolver.
// Written as: (out_refr_ptr_ptr, in_handle_ptr) → writes to *out.
using RefHandleResolveFn = void (*)(void** out, void* handle_ptr);
// B1.k.3: sub_1403478E0 — ContainerMenu inventory-entry → TESForm*.
// Takes (form_cache_global_value, entry_ptr) → returns form ptr or null.
using InvEntryToFormFn = void* (*)(void* form_cache, void* entry_ptr);
// B3.b: the engine's LoadGame native. Signature decoded from the
// LoadGame console command (re/console_table_report.txt).
using LoadGameFn       = std::uint8_t (*)(
    void* save_load_mgr, const char* filename,
    int unk_neg1, std::uint32_t flags, int one, int zero);
// Precondition check: "is the save device / profile available?"
using LoadPreconditionFn = std::uint8_t (*)(void* save_dev, int a2, int a3);
// Prep call — opaque from the decomp, always called right before LoadGame.
using LoadPrepFn       = void (*)();

// Z.2: PlaceAtMe Papyrus native. Returns Actor*.
// See offsets.h PLACE_AT_ME_RVA for full arg semantics.
using PlaceAtMeFn = void* (*)(
    void* vm, std::uint32_t stack_id, void** form_pair,
    void* anchor_refr, std::uint32_t count, std::uint64_t persistent);

LookupByFormIDFn g_lookup  = nullptr;
DisableEnqueueFn g_disable = nullptr;
EnableCleanupFn  g_enable_cleanup = nullptr;
EnableApplyFn    g_enable_apply   = nullptr;
InvItemGetCountFn g_inv_item_count = nullptr;
MaterializeInvListFn g_materialize_inv = nullptr;
GetComponentFn       g_get_component  = nullptr;
EngineAddItemFn      g_engine_add_item    = nullptr;
EngineRemoveItemFn   g_engine_remove_item = nullptr;

// B6.1: Activate worker = sub_140514180. Reused for door open/close
// receive-side apply. 7-arg signature inferred from Papyrus SetOpen
// callsite (the args 5-7 we logged were stack noise — first 4 are real:
// refr, activator, ?, force).
using ActivateWorkerFn = char (*)(void* refr, void* activator,
                                  void* a3, void* a4,
                                  void* a5, void* a6, void* a7);
ActivateWorkerFn     g_engine_activate    = nullptr;

// B6.3 v0.5.3 — Papyrus ObjectReference.Lock/Unlock binding.
// Signature: void(_unused, _unused, REFR*, u8 locked, char ai_notify).
// With ai_notify=0: bypass minigame, no key consumption, no AI events.
using LockApplyPapyrusFn = void (*)(void* a1, void* a2, void* refr,
                                    std::uint8_t locked, char ai_notify);
LockApplyPapyrusFn   g_lock_apply_papyrus = nullptr;
RefHandleResolveFn   g_refhandle_resolve  = nullptr;
InvEntryToFormFn     g_inv_entry_to_form  = nullptr;
// B1.k.3: form-cache global slot. Value at this address is the "form cache"
// singleton pointer that sub_1403478E0 needs as its first arg.
void**               g_form_cache_slot    = nullptr;
LoadGameFn       g_load_game      = nullptr;
LoadPreconditionFn g_load_precond = nullptr;
LoadPrepFn       g_load_prep      = nullptr;
// Pointer to the TESSaveLoadManager singleton slot (qword_14329D508).
// We read its contents at call time — the slot is populated during engine
// init, so reading too early gives 0.
void**           g_save_load_mgr_slot = nullptr;
// Pointer to the "save device" singleton slot (qword_1431E5A90).
void**           g_save_dev_slot      = nullptr;
// Pointer to the "load in progress" flag byte (byte_1432D1FEA).
std::uint8_t*    g_load_in_progress   = nullptr;

// Z.2: PlaceAtMe native + player singleton slot.
PlaceAtMeFn      g_place_at_me         = nullptr;
void**           g_player_singleton_slot = nullptr;   // deref → Actor*

// B6.5w3.b — anim graph variable setters + BSFixedString minter.
// `BSFixedString` is internally an 8-byte struct holding a pointer to
// a refcount-managed pool entry. We pre-mint the names we care about
// (SpeedSampled, Direction) ONCE at init so the refcount stays at +1
// for the lifetime of the DLL; setter calls re-use the same cached
// pointer and don't leak per-call.
struct BSFixedString {
    void* pool_entry = nullptr;
};

using BSFixedStringMakeFn = void  (*)(BSFixedString* dest, const char* literal);
using SetGraphVarFloatFn  = bool  (*)(void* holder, const BSFixedString* name, float value);
using SetGraphVarBoolFn   = bool  (*)(void* holder, const BSFixedString* name, char value);
using SetGraphVarIntFn    = bool  (*)(void* holder, const BSFixedString* name, int value);

BSFixedStringMakeFn g_bsfs_make           = nullptr;
SetGraphVarFloatFn  g_set_graph_var_float = nullptr;
SetGraphVarBoolFn   g_set_graph_var_bool  = nullptr;
SetGraphVarIntFn    g_set_graph_var_int   = nullptr;

// B6.5w4 round 5 — Actor.EnableAI native.
using ActorEnableAIFn = char (*)(void* actor, char enable, char queue);
ActorEnableAIFn g_actor_enable_ai = nullptr;

// B6.5w4 round 7 — Actor::MoveTo atomic teleport + NiAVObject::SetMotionType.
using ActorMoveToFn = char (*)(
    void* actor, float pos[3], float yaw, float pitch,
    void* target_cell, void* target_marker,
    char ran_interior_change, char skip_player_check, char skip_area_check);
using NiAVSetMotionTypeFn = char (*)(
    void* root3d, int motion_type, char a3, char a4, std::uint8_t activate_on_land);

ActorMoveToFn       g_actor_atomic_teleport = nullptr;
NiAVSetMotionTypeFn g_niav_set_motion_type  = nullptr;

// Build 65.c.47 — WEDGE3 death-sync. Actor::Kill (sub_140C612E0). Same
// function kill_hook detours; called here to apply a relayed owner death to
// the non-owner's mirror. Signature per decomp funcs_0301.md:6338.
using ActorKillFn = void* (*)(
    void* victim, void* killer, float a3, char silent, char a5);
ActorKillFn g_kill_engine = nullptr;

// B6.6w4 — fire trigger via WeaponFireHandler.
// `sub_140DFF6B0(unused, Actor*, anim_event_arg)` — handles slot resolution
// + projectile-class validation + ammo bookkeeping internally.
using WeaponFireHandlerFn = char (*)(std::int64_t unused, void* actor,
                                     std::int64_t* anim_event_arg);
WeaponFireHandlerFn g_weapon_fire_handler = nullptr;

// ============================================================================
// PUPPET FIRE PHASE 1 (2026-05-17 — 3-worker + supervisor RE pass).
// See re/puppet_fire_phase1/SUPERVISOR_SYNTHESIS.md.
// ============================================================================
// Weapon-state class setter (sub_140CD1830). Sets slot_record[+56] = new_class
// (canonical state read by sub_140CD1770). For class 15/16/17 only the slot
// record write fires (3-bit Actor+0x130 field can't hold values 7+).
// Does NOT consult Actor+0x328 — safe on actors without HighProcess.
using WeaponStateClassSetterFn =
    char (*)(void* actor, std::uint32_t slot, int new_class);
WeaponStateClassSetterFn g_weapon_state_class_setter = nullptr;

// Slot resolver (sub_140CD0A60). Walks equipManager via primary AIProcess.
//   int* __fastcall(Actor*, int* out_slot, int64_t zero_pair[2])
// Sets *out_slot to slot id, or -1 sentinel if no weapon equipped.
using ActorResolveWeaponSlotFn =
    int* (*)(void* actor, int* out_slot, std::int64_t* zero_pair);
ActorResolveWeaponSlotFn g_resolve_weapon_slot = nullptr;

// Aim-target setter (sub_140E65820 — CombatAimController::SetAimTarget).
// 42-byte leaf, 6 stores: x/y/z @ +0x18/+0x1C/+0x20, +0x38 = g_game_time
// anchor, +0x3C = 0, +0x34 |= 1 (valid flag). No SEH, no lock, no vt.
using AimSetTargetFn = void (*)(void* aim_controller, const float* xyz);
AimSetTargetFn g_aim_set_target = nullptr;

// Cached absolute address of CombatAimController vtable (computed at init
// from module_base + COMBAT_AIM_CONTROLLER_VTBL_RVA). Used by
// resolve_actor_aim_controller_for_slot to filter BSTArray entries.
std::uintptr_t g_aim_ctrl_vtbl_addr = 0;

// Diagnostic counters for the new fire path.
std::atomic<std::uint64_t> g_puppet_fire_calls{0};
std::atomic<std::uint64_t> g_puppet_fire_aim_resolved{0};
std::atomic<std::uint64_t> g_puppet_fire_aim_missing{0};
std::atomic<std::uint64_t> g_puppet_fire_class_set_ok{0};
std::atomic<std::uint64_t> g_puppet_fire_class_set_fail{0};
std::atomic<std::uint64_t> g_puppet_fire_handler_ok{0};
std::atomic<std::uint64_t> g_puppet_fire_handler_fail{0};

// ============================================================================
// PUPPET FIRE PHASE 1.5 — EnterCombat direct primitive (D agent verified).
// Source dossier: re/puppet_fire_phase1/D_AGENT_enter_combat.md
// ============================================================================
using EnterCombatFn = char (*)(void* observer_actor, void* subject_actor,
                               void* descriptor_or_null);
EnterCombatFn g_enter_combat = nullptr;

// Build 63 (2026-05-25) — sub_140E929C0 = AddAlly(CombatController, Actor).
//
// Per re/walker_audit_v2/AGENT_C_pipeline_gaps.md + SUPERVISOR_SYNTHESIS.md:
// the fresh-alloc branch inside sub_140ED2390 (the path CCF810 hits when the
// raider has no prior HighProcess) calls AddTarget(ghost) but NEVER calls
// AddAlly(raider, raider's own controller). Result: controller+0x20 allies[]
// stays empty → sub_140E9E650 per-frame walker writes controller+0x110 = 0
// (alive counter) → engine treats combat as "no one engaged" → tears the
// combat group down within 2-3 frames. THIS is the exact "1-2 steps then
// idle" symptom user observed Build 62.9+.
//
// Note: we already hook this function as Hook 13 (detour_ensure_known) in
// ghost_global_walker_guards.cpp under the name "EnsureKnownTarget". The
// name was wrong; it's AddAlly. The hook's poison check returns false for
// fresh CC (count==0 path), so our direct call goes through to orig.
//
// Signature returns std::int64_t (matches Hook 13 typedef). Returns the
// allies array index of the inserted/found entry, or 0 on failure.
using AddAllyToCtrlFn = std::int64_t (__fastcall *)(void* ctrl, void* actor);
AddAllyToCtrlFn g_add_ally_to_ctrl = nullptr;

std::atomic<std::uint64_t> g_add_ally_calls{0};
std::atomic<std::uint64_t> g_add_ally_seh{0};

// ============================================================================
// STRADA B.2 (2026-05-22) — Manual HighProcess + AimController synthesis.
// Source: re/strada_B2_synthesize_highprocess/SUPERVISOR_SYNTHESIS.md
// ============================================================================
// sub_140ED2390 (Fresh-allocation orchestrator). Calling this DIRECTLY
// bypasses the combat-disable gate that refused 5/5 Concord raiders in
// Build 45. See offsets::COMBAT_PROMOTER_FRESH_RVA for body summary.
using CombatPromoterFreshFn = char (*)(void* combat_manager,
                                       void* observer_actor,
                                       void* target_actor);
CombatPromoterFreshFn g_combat_promoter_fresh = nullptr;

// sub_140E653D0 CombatAimController ctor. Self-registers to
// parent_HighProcess+0x98 BSTArray. Leaves +0x30/+0x34 zero — caller writes.
using AimCtrlCtorFn = void* (*)(void* self,
                                void* parent_highprocess,
                                int   type_tag);
AimCtrlCtorFn g_aim_ctrl_ctor = nullptr;

// Diagnostic counters.
std::atomic<std::uint64_t> g_synth_calls{0};
std::atomic<std::uint64_t> g_synth_success{0};
std::atomic<std::uint64_t> g_synth_refused_baseform{0};
std::atomic<std::uint64_t> g_synth_refused_aiproc{0};
std::atomic<std::uint64_t> g_synth_refused_frozen{0};
std::atomic<std::uint64_t> g_synth_already_in_combat{0};
std::atomic<std::uint64_t> g_synth_ed2390_failed{0};
std::atomic<std::uint64_t> g_synth_aim_alloc_failed{0};
std::atomic<std::uint64_t> g_synth_aim_ctor_seh{0};
std::atomic<std::uint64_t> g_synth_seh{0};

// Diagnostic counters for the EnterCombat wrapper.
std::atomic<std::uint64_t> g_enter_combat_calls{0};
std::atomic<std::uint64_t> g_enter_combat_success{0};
std::atomic<std::uint64_t> g_enter_combat_refused_gate{0};
std::atomic<std::uint64_t> g_enter_combat_refused_frozen{0};
std::atomic<std::uint64_t> g_enter_combat_refused_baseform{0};
std::atomic<std::uint64_t> g_enter_combat_refused_aiproc{0};
std::atomic<std::uint64_t> g_enter_combat_already_in_combat{0};
std::atomic<std::uint64_t> g_enter_combat_post_alloc_null{0};
std::atomic<std::uint64_t> g_enter_combat_seh{0};
// Build 62.4 (2026-05-24) — new counters for the dedup + distance safety nets.
std::atomic<std::uint64_t> g_enter_combat_refused_distance{0};
std::atomic<std::uint64_t> g_enter_combat_dedup_skip{0};

// Build 62.4 — per-(raider, ghost) dedup set.
// Server-authoritative pattern: server is supposed to send the perception
// trigger ONCE per acquisition (60s debounce). This set is the CLIENT-SIDE
// crash-prevention safety net for the case where server somehow re-emits:
// once enter_combat_raider_vs_ghost succeeds for a given pair, subsequent
// calls return true immediately without re-invoking CCF810 or
// install_fixed_selector_on_raider. Prevents known_targets[] duplicate
// inflation + the cell-unload freeze observed in Build 62.3 live test
// (Client A frozen mid-teleport-to-Concord at 21:03:56 after 13 re-triggers
// kept calling install_fixed_selector on already-engaged raiders).
//
// The set is NEVER cleared automatically — entries live until the DLL
// unloads. That is OK for the wedge: at scale we'd clear on raider death
// + ghost despawn, but for the MVP a few hundred (raider, ghost) pairs
// per session is fine. Worst case the set holds all (17 raiders × 2 ghosts)
// = 34 entries.
std::mutex g_engaged_pairs_mtx;
std::unordered_set<std::uint64_t> g_engaged_pairs;

inline std::uint64_t make_engaged_key(void* raider, void* ghost) noexcept {
    // Mix the two pointers to avoid XOR symmetry on swapped args.
    const auto r = reinterpret_cast<std::uint64_t>(raider);
    const auto g = reinterpret_cast<std::uint64_t>(ghost);
    return (r << 1) ^ (g >> 1) ^ (g << 32);
}

// Build 62.9 (2026-05-25) — NATIVE COMBAT FID SET.
//
// Parallel to g_engaged_pairs (which is keyed by raider*+ghost*), this
// set is keyed by raider FORM_ID. Populated when trigger_npc_perception
// SUCCESS path runs, alongside the dedup-pair insert. Queried by the
// LEGACY freeze hooks (ghost_ai_havok_step, ghost_ai_movement,
// ghost_ai_pos_belt, ghost_ai_actor_setpos) so they can SKIP THE BAIL
// when the raider is in native combat tier.
//
// Without this, those 4 motion-writer hooks observe cache.movement_override
// = 1 (puppet-fire era flag still set by raider_brain) and bail every
// Havok/SetPosition call → raider Havok body frozen at last vanilla pose
// → "raider stationary like a log even when in red-marker combat tier"
// (user feedback Build 62.8 test).
//
// Cleared like g_engaged_pairs: NEVER (DLL lifetime). MVP-scale acceptable.
std::mutex g_native_combat_fids_mtx;
std::unordered_set<std::uint32_t> g_native_combat_fids;

// MSVC C2712 workaround: __try cannot coexist with C++ objects needing
// destructors (std::lock_guard) in the same function frame. Wrap the
// lock-touching ops as free helpers — they have no __try, so they can
// own a lock_guard; the SEH-using wrapper only calls them.
bool engaged_pair_exists(std::uint64_t key) {
    std::lock_guard<std::mutex> lk(g_engaged_pairs_mtx);
    return g_engaged_pairs.count(key) != 0;
}

void engaged_pair_insert(std::uint64_t key) {
    std::lock_guard<std::mutex> lk(g_engaged_pairs_mtx);
    g_engaged_pairs.insert(key);
}

std::size_t engaged_pair_count() {
    std::lock_guard<std::mutex> lk(g_engaged_pairs_mtx);
    return g_engaged_pairs.size();
}

// Build 62.9 — native combat fid set helpers (same C2712 workaround
// pattern: free functions own the lock_guard, no __try here).
//
// IMPORTANT: native_combat_fid_exists must have EXTERNAL linkage so
// the 4 legacy motion-writer hooks (ghost_ai_havok_step,
// ghost_ai_movement, ghost_ai_pos_belt, ghost_ai_actor_setpos) can
// call it from their own TUs. Defined out-of-anonymous below; the
// anonymous-namespace insert helper stays internal-linkage (only
// our SUCCESS path uses it).
void native_combat_fid_insert(std::uint32_t fid) {
    if (fid == 0 || fid == 0xFFFFFFFFu) return;
    std::lock_guard<std::mutex> lk(g_native_combat_fids_mtx);
    g_native_combat_fids.insert(fid);
}

// B6.6w4 — engine-native movement disable.
// `sub_140DC80B0(MovementController*)` — sets *(mc+0x1A1) = 1, drives
// inner vt cleanup. DEFUNCT (live-test showed mirror-on-set bug).
using MovCtrlSetDisabledFn = void (*)(void* mc);
MovCtrlSetDisabledFn g_movctrl_set_disabled = nullptr;

// B6.6w5 — Actor::vt[202] = `sub_140C60630(actor, float pos[3], char a3)`.
// Full-teleport entry. Called with a3=0 from apply_npc_pos so only the
// minimal-side-effect path runs (Actor+0xD0 write + cell broadcast + NIF
// root pos write). a3=1 would identity-overwrite Havok rotation.
using ActorSetPosFullFn = void (*)(void* actor, float* pos, char a3);
ActorSetPosFullFn g_actor_setpos_vt202 = nullptr;

// B6.6w5 Build 6 — REFR::SetParentCell + REFR::SetPosition leaf writer.
// Used by Steps D & E of the ghost init sequence (audit
// re/B6.6w5_cell_attach_aiprocess_audit.md verdict).
using RefrSetParentCellFn   = void (*)(void* refr, void* cell);
using RefrSetPositionLeafFn = void (*)(void* refr, const float pos[3]);

// B6.6w5 — engine-native PlayerCharacter spawn.
// PlayerCharacter ctor: `sub_140D52350(void* zeroed_buffer) -> Actor*` returns
// the buffer as initialized PlayerCharacter. The ctor's a2=0 hidden gate
// skips ProcessLists registration, so we do it manually post-call.
using PlayerCtorFn          = void* (*)(void* buffer);
// Generic Bethesda MemoryManager allocator.
using MemMgrAllocFn         = void* (*)(void* mgr_instance, std::size_t size,
                                        unsigned align, char aligned_path);
// Lazy-init worker for the MemoryManager. The engine calls this guarded
// by `if (dword_143E5F2D0 != 2)` before every alloc against the global
// instance. We mirror the guard.
using MemMgrLazyInitFn      = void  (*)(void* mgr_instance, std::uint32_t* state);
// ProcessLists::AddActor.
using ProcessListsAddActorFn = void (*)(void* processlists, void* actor);

PlayerCtorFn           g_player_ctor             = nullptr;
MemMgrAllocFn          g_memmgr_alloc            = nullptr;
MemMgrLazyInitFn       g_memmgr_lazy_init        = nullptr;
ProcessListsAddActorFn g_processlists_add_actor  = nullptr;
RefrSetParentCellFn    g_refr_set_parent_cell    = nullptr;
RefrSetPositionLeafFn  g_refr_set_position_leaf  = nullptr;

// B6.6w5 Build 12 (Fix 1) — direct call to engine AIProcess::SetCombatTarget.
// Calling the engine's address goes through our MinHook detour (firing the
// substitution logic) — same as if the engine had called it itself.
using SetCombatTargetFn = void (*)(void* aiproc, void* new_target);
SetCombatTargetFn g_set_combat_target_engine = nullptr;

// B6.6w5 Build 12 (Fix 2) — engine handle allocator (BSPointerHandle binding).
// Signature: `DWORD* sub_14022C8B0(DWORD* out_handle, Actor* actor)`.
// See offsets.h HANDLE_GET_OR_ALLOC_RVA for full semantics.
using HandleGetOrAllocFn = std::uint32_t* (*)(std::uint32_t* out_handle, void* actor);
HandleGetOrAllocFn g_handle_get_or_alloc = nullptr;

// B6.6w5 Build 27 (2026-05-13 night) — duplicate sanitization per Agent 10
// recipe (re/B6.6w5_crash_AGENT_10_pc_field_map.md, Section 4A/4D).
//
// `sub_140CEEAB0` — AIProcess ctor. Takes aiproc buffer, zeroes + inits
// lock state. RVA 0xCEEAB0 per Agent 10's audit.
using AIProcessCtorFn   = void* (*)(void* aiproc_buf);
AIProcessCtorFn   g_aiprocess_ctor       = nullptr;

// `sub_140CFA450` — AIProcess sub-buffer populator. Takes (aiproc, actor)
// and allocates the 4 inner sub-buffers (sized 0x4C0, 0x5A0, 0x60, etc.)
// referenced by AIProcess+0/+8/+16. RVA 0xCFA450 per Agent 10.
using AIProcessPopulateFn = void* (*)(void* aiproc, void* actor);
AIProcessPopulateFn g_aiprocess_populate = nullptr;

// `sub_140272730` — BSHandleRefObject sub-buffer init for +0x100. Takes
// the 0x28-byte buffer and returns it after initializing. RVA 0x272730.
using HandleRefInitFn   = void* (*)(void* buf_0x28);
HandleRefInitFn   g_handleref_init       = nullptr;

// B6.6w5 Build 28 — engine-native proxy spawn primitives (verified RVAs
// from AGENT P1A+P1B audit, cross-checked manually against decomp).
//
// NOTE: PlaceAtMe typedef + g_place_at_me are ALREADY declared above at
// lines ~62 and ~109 (Z.2 path B). We reuse them. Build 28 adds the
// remaining four primitives for flag stacking and position/rotation
// after spawn.
//
// sub_140519410 SetDisabled — funcs_0175.md:12328
//   char __fastcall(_WORD* refr, char enable_flag)
//   Internally calls sub_140313230(refr, 1, enable_flag) which mutates
//   refr+24, then propagates to refr+16 bit 0x800 via vtable[13].
using SetDisabledFn     = char (*)(void* refr, char enabled);
SetDisabledFn     g_set_disabled         = nullptr;

// ============================================================================
// Build 56 (2026-05-23) — Option C: Global form-table deregister primitives.
//
// Source: re/option_C_deregister_ghost/AGENT_deregister_analysis.md.
//
// The ghost is created via PlaceAtMe (or CreateByTypeCode), which auto-
// registers it into the engine's GLOBAL FormID→Form hash table at
// qword_1430DBF78[2506] (= MEMORY[0x1430E0DC8]). After registration,
// every global walker (sub_140C06AC0 = vt[51] form walker, sub_140CA85C0
// = vt[197] IsHostileTo, save serialiser, debug dumpforms, cell-rehydrate
// scheduler, etc.) iterates the table and dispatches virtuals on EVERY
// entry — including the ghost. Because the ghost is a synthetic proxy
// with incomplete sub-objects (s_buf_418 zero buffer, non-canonical vt
// slot 51 per the death_vtable_cascade dossier), these virtual dispatches
// AV. Whack-a-mole per-RVA guards don't scale (25+ similar dispatch sites).
//
// Option C unhooks the ghost from the global form table at spawn time so
// no walker ever reaches it. Our private g_ghost_duplicate_ptr map keeps
// lookup_by_form_id(0xFF000001) working — all 8 callers of our wrapper
// resolve via the private map FIRST, falling back to engine g_lookup
// only on cache miss.
//
// Verified by RE agent:
//   - sub_140315740 is the ERASE function (NOT insert). Signature:
//     u8(table_base, *fid, **out_form). table_base = qword_1430DBF78[2506].
//   - sub_141659060 = BSReadWriteLock acquire-write (for the table lock at
//     qword_1430DBF78[2516] = MEMORY[0x1430E0E18]).
//   - sub_1416592C0 = same lock release-write.
//   - lookup_by_form_id wrapper at this file:1289 already handles ghost
//     via g_ghost_duplicate_ptr — no new resolver needed.
// ============================================================================
using EraseFormFn    = std::uint8_t (*)(std::uintptr_t table_base,
                                        const std::uint32_t* fid,
                                        void** out_form);
using AcquireWriteFn = void (*)(void* lock);
using ReleaseWriteFn = void (*)(void* lock);

EraseFormFn      g_form_erase           = nullptr;  // sub_140315740
AcquireWriteFn   g_form_lock_acquire_w  = nullptr;  // sub_141659060
ReleaseWriteFn   g_form_lock_release_w  = nullptr;  // sub_1416592C0
void*            g_form_table_base_addr = nullptr;  // &qword_1430DBF78[2506]
void*            g_form_table_lock_addr = nullptr;  // &qword_1430DBF78[2516]

// sub_140C5CE40 SetGhost — funcs_0301.md:2959
//   void __fastcall(_QWORD* actor, unsigned __int8 ghost)
//   Reads actor+0x300 (AIProcess), +0x58 sub-obj, sets bit 0x100000
//   at +44 of sub-obj (verified line 2997).
using SetGhostFn        = void (*)(void* actor, std::uint8_t ghost);
SetGhostFn        g_set_ghost            = nullptr;

// sub_140513A80 SetPosition — referenced from PlaceAtMe path (funcs_0401):
//   void __fastcall(void* refr, float* xyz)
using SetPositionEngineFn = void (*)(void* refr, float* xyz);
SetPositionEngineFn g_set_position_engine = nullptr;

// sub_140513790 SetRotation — funcs_0190.md:6512 usage pattern verified
//   void __fastcall(void* refr, float* rotxyz)
using SetRotationEngineFn = void (*)(void* refr, float* rotxyz);
SetRotationEngineFn g_set_rotation_engine = nullptr;

// B6.6w5 Build 28c — sub_1404F9E60 CreateByTypeCode (Agent P1A rank #1).
// Allocates 0x490 bytes + runs Actor ctor sub_140C57640 + registers in
// handle table (writes (slot<<11)|0x400 to actor+0x28). NO cell-attach.
// Verified body funcs_0173.md:18690-18772.
//   signature: unsigned int* __fastcall(unsigned int* out_handle,
//                                       char type_code,
//                                       unsigned __int8 ctor_flag)
//   type 'A' (65) → Actor; out_handle holds (slot|gen) on return.
using CreateByTypeCodeFn = std::uint32_t* (*)(std::uint32_t* out_handle,
                                              char type_code,
                                              std::uint8_t ctor_flag);
CreateByTypeCodeFn g_create_by_type_code = nullptr;

// sub_1402A0540 ObjectRefHandle::TryGetRef — funcs_0131.md:2893 (Agent P1A)
//   bool __fastcall(unsigned int* handle, void** out_refr)
//   Resolves a handle returned by CreateByTypeCode to the actual REFR/Actor ptr.
using HandleResolveFn = bool (*)(std::uint32_t* handle, void** out_refr);
HandleResolveFn g_handle_resolve = nullptr;

// ============================================================================
// B6.6w5 Build 29 — CombatTargetSelectorFixed engine primitives.
//
// See engine_calls.h::install_fixed_selector_on_raider for the architecture
// and the offsets.h block "Build 29" for verified RVAs + decomp citations.
// ============================================================================

// sub_140E91D70 CombatController::AddTarget — funcs_0337.md:1818
//   Inserts a 208-byte record into the controller's known_targets[] BSTArray
//   (base at controller+8, count at controller+0x30). Returns 1 on insert OR
//   if target was already in the list (sub_140E922D0 short-circuit).
using AddCombatTargetFn = char (*)(void* controller, void* target_actor);
AddCombatTargetFn g_add_combat_target = nullptr;

// sub_140EE9780 CombatTargetSelectorFixed::ctor — funcs_0346.md:6444
//   Constructs the Fixed selector in caller-provided 40-byte block. Stores
//   target's HANDLE (via sub_140C73280 → sub_14022C8B0) at block+0x18,
//   priority at block+0x1C, flag byte at block+0x20 (init = 1). Then calls
//   sub_14087B1F0(aiproc, block) which inserts the selector pointer into
//   aiproc+0x100 BSTArray (count at aiproc+0x110).
using FixedSelectorCtorFn = std::uint64_t (*)(void* block,
                                              void* aiproc,
                                              void* target_actor,
                                              int   priority);
FixedSelectorCtorFn g_fixed_selector_ctor = nullptr;

// sub_1416579C0 — engine NiHeap allocator. Used at the canonical vanilla
// Fixed-selector call site (funcs_0358.md:4906) with the static heap
// descriptor at &unk_143E5E0F0. Signature:
//   void* __fastcall(void* heap_desc, std::size_t size, int align, int flags)
// Returns the allocated block or nullptr on OOM.
using EngineHeapAllocFn = void* (*)(void* heap_desc,
                                    std::size_t size,
                                    int align,
                                    int flags);
EngineHeapAllocFn g_engine_heap_alloc = nullptr;

// Build 30 Fix 1 — BSReadWriteLock write-release. `sub_1416592C0`,
// funcs_0472.md:42, 26 bytes. Signature: `void(void* lock)`. Safe to call
// only when WE own the lock (lock+0x00 == GetCurrentThreadId()).
// Used to recover from AddTarget SEH where the lock at controller+0x120
// stayed acquired after the validator crashed mid-function.
using LockReleaseWriteFn = void (*)(void* lock);
LockReleaseWriteFn g_lock_release_write = nullptr;

// Build 30 Fix 3 — Handle table base for inline (no-refcount) resolution
// during purge_stale_known_targets. Resolved at init() from
// offsets::HANDLE_TABLE_BASE_RVA.
std::uint8_t* g_handle_table_base = nullptr;

// Address of the static heap descriptor `unk_143E5E0F0` used by the vanilla
// Fixed-selector caller. Resolved at init() from offsets::ENGINE_HEAP_DESC_RVA.
void* g_engine_heap_desc = nullptr;
// The MemoryManager instance itself (we pass its ADDRESS as the first arg
// of g_memmgr_alloc, exactly like the engine does — `&unk_143E5E0F0`).
void*                  g_memmgr_instance         = nullptr;
// Init-state guard (engine: dword_143E5F2D0). Value 2 = initialized.
std::uint32_t*         g_memmgr_init_guard       = nullptr;
// Secondary player-equality singleton slot at 0x1431E2D50. Ctor clobbers
// this; we restore immediately after ctor returns.
void**                 g_player_alt_singleton    = nullptr;
// Address of qword_1430DBF78 — array root. ProcessLists* lives at [41]
// (= +0x148). Read-then-use because the array entries can be lazy-init'd
// by other engine paths.
void**                 g_procmgr_bag             = nullptr;

BSFixedString g_bs_speed_sampled{};   // pre-minted at init for hot-path WALKING/RUNNING
BSFixedString g_bs_direction{};       // pre-minted at init
BSFixedString g_bs_anim_driven{};     // pre-minted at init for round 3 — kills root motion
// B6.5w4 round 8 — humanoid anim graph state suite. Written every frame
// for tracked NPCs to override vanilla AI's local decisions and sync
// anim state across clients.
BSFixedString g_bs_is_running{};
BSFixedString g_bs_is_sprinting{};
BSFixedString g_bs_is_attacking{};
BSFixedString g_bs_is_aiming_gun{};
BSFixedString g_bs_is_blocking{};
BSFixedString g_bs_is_sneaking{};
BSFixedString g_bs_is_dead{};

std::atomic<bool> g_ready{false};

// B6.6w5 Build 4 — no-op vtable to defuse the ghost's event sinks.
//
// The PlayerCharacter ctor at funcs_0314.md:6209-6213 unconditionally
// registers four sub-objects of the ghost as listeners on two global
// event-broadcasters:
//   - MEMORY[0x1430DD830] + 24 / + 112 ← ghost+1168 / +1176
//   - MEMORY[0x1430DD7B0]              ← ghost+1184 / +1192
//
// When the engine broadcasts an event it iterates the sink list and
// calls `sink->vftable->ProcessEvent(sink, event)`. The ghost's sinks
// have valid vftables (Actor base ctor at funcs_0300.md:5985-6043) but
// the rest of the ghost is uninitialized — ProcessEvent dispatches into
// PC code that dereferences AIProcess / parentCell / anim graph / etc.
// → crash.
//
// Build 3 live test (2026-05-13 01:57): spawn OK, ProcessLists skipped,
// game still crashed ~7s after spawn during the engine's LoadGame
// completion sweep. The remaining suspect is exactly these event sinks.
//
// Defuse: replace each ghost sub-object's vftable pointer (first qword
// at offset 0) with `g_noop_vtable[0]` — an array of 256 function
// pointers all set to `noop_sink_method`. Dispatcher calls noop, which
// returns 0 (= kContinue in BSEventNotifyControl) in rax. Zero side
// effects. Ghost stays alive but invisible to the event bus.
//
// 256 slots is overkill — BSTEventSink vtables are typically 2-4 slots.
// Belt-and-braces for any specialization we don't have RTTI for. 2 KB
// static cost.

void* noop_sink_method() noexcept {
    return nullptr;
}

void* g_noop_vtable[256] = {};   // filled at runtime in init()

// Sub-object offsets — verified via audit Q4b against funcs_0314.md:6209-6213.
constexpr std::size_t GHOST_EVENT_SINK_OFFSETS[] = {
    1168,   // MEMORY[0x1430DD830] + 24  sink — first event source
    1176,   // MEMORY[0x1430DD830] + 112 sink — second event source
    1184,   // MEMORY[0x1430DD7B0]       sink — BSInputEnableManager #1
    1192,   // MEMORY[0x1430DD7B0]       sink — BSInputEnableManager #2
};

// =====================================================================
// B6.6w5 Build 8b — custom vtable for the duplicate ghost (per-instance
// vtable swap, NOT a global MinHook).
//
// The duplicate inherits the real player's NIF pointer via memcpy
// (REFR+0xF0 → ThreeDHolder → +8 → actual NiAVObject*). If we leave
// vtable[140] (Get3D, sub_14050D990) pointing at the engine's original,
// raider AI calling `duplicate->Get3D()` for aim resolution would get
// the real player's NIF (at real player's pos). Aim mis-direction.
//
// Solution: per-instance vtable swap. Allocate a writable copy of the
// PlayerCharacter primary vtable (at module_base + 0x2564838), replace
// slot 140 with our hook, and write the new vtable address to
// `duplicate+0x00`. Only the duplicate uses this vtable; the real player
// is untouched. Other slots are pristine — engine still calls original
// methods on the duplicate (most of which are read-only of valid state).
//
// vtable RVA = 0x2564838 (TESOBJECTREFR_VTABLE_RVA in offsets.h — name
// is historical; this is the primary vtable shared by all REFR-derived
// classes including PlayerCharacter via the C++ object-model layout).
//
// Slot 140 = byte offset 140*8 = 1120. Get3D signature (verified at
// funcs_0175.md:3254-3268): `void* __fastcall(void* refr)`.

// B6.6w5 Build 24 (2026-05-13 late evening) — buffer expanded from 256 to
// 512 slots. Build 23 crash root cause: engine called slot 267 (byte
// offset 0x858) on duplicate via `call qword ptr [rax+858h]` at engine
// RVA 0x14061856C (inside sub_140618520). Slot 267 was PAST our 256-slot
// buffer end → engine read adjacent zero-init statics → `call NULL` →
// RIP=0 EXEC fault @ 20:25:47.766 (verified via VEH crash log Build 23).
//
// Real PC vtable (TESOBJECTREFR_VTABLE_RVA = 0x2564838 per
// reference_fo4_offsets.md) is followed by other vtables in .rdata —
// over-copying 4 KB is safe (we just read more pristine vtable bytes /
// neighboring static data; engine never reads slots above the real PC
// vtable's actual size). 512 slots = 4 KB covers any plausible
// Bethesda vtable depth and gives us 80+ slots of safety margin past
// the highest known callsite (slot 267).
alignas(8) void* g_duplicate_vtable[512] = {};   // 4 KB; was 256 (Build 23 crash)
std::atomic<bool>   g_duplicate_vtable_ready{false};
void*               g_duplicate_original_get3d = nullptr;  // saved for fallback (slot 140)
void*               g_duplicate_original_get3d_alt = nullptr;  // slot 139 fallback

// Hook function. Returns the body renderer ghost's BSFadeNode root.
// extern "C" + __fastcall to match the engine's calling convention.
extern "C" void* __fastcall duplicate_get3d_hook(void* this_) noexcept {
    // Per-instance vtable means this_ IS the duplicate (no need to compare).
    // The engine asks "where is your 3D?" — we point at the body renderer
    // ghost (positioned at peer's world pos via M3.1 event-driven tracking).
    void* body_ghost = nullptr;
    __try {
        body_ghost = fw::native::get_injected_body_ghost();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        body_ghost = nullptr;
    }
    if (body_ghost) {
        return body_ghost;
    }
    // Fallback: body ghost not yet injected (pre-T+30s grace). Call the
    // original Get3D on the duplicate (returns real player's NIF since
    // REFR+0xF0 was memcpy'd). Aim resolution would point at real player,
    // but that's the best we can do until the body is up. In practice
    // Build 5 onwards ties spawn to body inject success, so this fallback
    // is dead code — kept for defense in depth.
    if (g_duplicate_original_get3d) {
        using Get3DFn = void* (*)(void*);
        __try {
            return reinterpret_cast<Get3DFn>(g_duplicate_original_get3d)(this_);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
    }
    return nullptr;
}

// B6.6w5 Build 23 — vtable slot 139 thunk per Agent 9 of the 10-agent
// crash audit.
//
// Slot 139 is `sub_140D5BBB0` ("Get3DAlt" / 1P-NIF accessor). Its body
// reads `*(this + 0xB78)` which is real_player's 1P NIF root on a
// memcpy'd duplicate. Then sub_1417A0A30 walks that NIF looking for
// "WEAPON" / "MagicEffectsNode" / "FireNode" placeholder nodes; on a
// REAL real-player NIF those derefs walk into real_player's owned
// scene-graph subtree → cross-thread AV during HitApplier+ApplyHitReaction.
//
// We redirect slot 139 to return the SAME body ghost as slot 140 —
// the body ghost has empty NiNode children with those exact names
// attached per `scene_inject.cpp` Build 16 Fix 2 (verified in log lines
// 5170-5172 of Build 22). The walker finds the named placeholders and
// stops without crashing.
//
// Caller sites (per Agent 9): HitApplier sub_140CD2780:8131,
// ApplyHitReaction sub_???:20938. Both fire on damage to the duplicate.
extern "C" void* __fastcall duplicate_get3d_alt_hook(void* this_) noexcept {
    void* body_ghost = nullptr;
    __try {
        body_ghost = fw::native::get_injected_body_ghost();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        body_ghost = nullptr;
    }
    if (body_ghost) {
        return body_ghost;
    }
    if (g_duplicate_original_get3d_alt) {
        using Get3DAltFn = void* (*)(void*);
        __try {
            return reinterpret_cast<Get3DAltFn>(
                g_duplicate_original_get3d_alt)(this_);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
    }
    return nullptr;
}

// One-shot init: clone original PC vtable, replace slot 140. Called
// from engine::init() once module_base is known.
void init_duplicate_vtable(std::uintptr_t module_base) {
    if (g_duplicate_vtable_ready.load(std::memory_order_acquire)) return;

    void** orig_vtable = reinterpret_cast<void**>(
        module_base + offsets::TESOBJECTREFR_VTABLE_RVA);

    __try {
        // Build 24 — copy 512 slots (4 KB). Build 23's 256-slot copy
        // crashed at engine RVA 0x14061856C calling vt[267] (byte offset
        // 0x858 = 2136 > 2048 = our 256-slot buffer end). Safe over-read
        // since .rdata is contiguous; engine never reads above PC's real
        // vtable size, so the extra slots are never invoked.
        std::memcpy(g_duplicate_vtable, orig_vtable, sizeof(g_duplicate_vtable));
        // Save original Get3D for hook's fallback path.
        g_duplicate_original_get3d = g_duplicate_vtable[140];
        // Replace slot 140 (Get3D) with our hook.
        g_duplicate_vtable[140] = reinterpret_cast<void*>(&duplicate_get3d_hook);
        // Build 23 — slot 139 ("Get3DAlt" per Agent 9) → body ghost too,
        // so HitApplier's NIF walker doesn't deref real_player's 1P NIF.
        g_duplicate_original_get3d_alt = g_duplicate_vtable[139];
        g_duplicate_vtable[139] = reinterpret_cast<void*>(&duplicate_get3d_alt_hook);
        g_duplicate_vtable_ready.store(true, std::memory_order_release);
        FW_LOG("[ghost-native] duplicate vtable initialized: buf=%p "
               "(slot 140 Get3D: orig=%p, hook=%p; "
               "slot 139 Get3DAlt: orig=%p, hook=%p) — Build 23: both "
               "slots return body ghost (peer pos with placeholder children)",
               &g_duplicate_vtable[0], g_duplicate_original_get3d,
               reinterpret_cast<void*>(&duplicate_get3d_hook),
               g_duplicate_original_get3d_alt,
               reinterpret_cast<void*>(&duplicate_get3d_alt_hook));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-native] SEH initializing duplicate vtable from %p — "
               "Build 8b Get3D redirect will not work; spawn falls back to "
               "Build 7 memcpy-only behavior (shared real_player NIF)",
               orig_vtable);
    }
}

// SEH-safe pointer read at offset.
template <typename T>
T safe_read(const void* addr, T fallback) noexcept {
    if (!addr) return fallback;
    __try { return *reinterpret_cast<const T*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return fallback; }
}

// SEH-safe pointer write at offset.
template <typename T>
void safe_write(void* addr, T value) noexcept {
    if (!addr) return;
    __try { *reinterpret_cast<T*>(addr) = value; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Build 33 — F5: MagicTarget vt[4] immunity stub.
//
// Agent F5 BLUNT: "the cleanest immunity is MagicTarget vt[4] → return 1,
// which makes sub_140C62EE0 return 0 at line 7594 before it touches
// AIProcess, HighProcess, or AV chain."
//
// vt[4] of MagicTarget interface is the "is target immune to damage"
// predicate. Returning 1 (= immune) makes HP-delta path short-circuit
// before walking into the half-init ghost state. Engine signature:
//   char __fastcall MagicTarget::IsImmune(this)
//
// We install this stub at slot 4 of a SHIM vtable that replaces the
// real MagicTarget vftable at ghost+0x110. Other slots in the shim are
// copies of the real vftable, so engine calls to non-immunity methods
// hit real engine functions (which themselves null-check AIProcess and
// return safely on a sanitized ghost).
//
// Per-DLL-lifetime singleton (s_magic_target_shim_vtable below). The
// shim is built lazily on first ghost spawn from a snapshot of the
// real vftable read off the freshly-ctor'd ghost+0x110.
extern "C" char __fastcall magic_target_immune_stub(void* /*this*/) noexcept {
    return 1;   // "Yes, this target is immune to damage."
}

} // namespace

// Build 62.9 — out-of-anonymous so external TUs (the 4 legacy
// motion-writer hooks) can link this symbol. Storage stays anonymous.
bool native_combat_fid_exists(std::uint32_t fid) {
    if (fid == 0 || fid == 0xFFFFFFFFu) return false;
    std::lock_guard<std::mutex> lk(g_native_combat_fids_mtx);
    return g_native_combat_fids.count(fid) != 0;
}

bool init(std::uintptr_t module_base) {
    if (!module_base) {
        FW_ERR("engine: module_base=0 — cannot resolve calls");
        return false;
    }

    // RVAs from re/reference_fo4_offsets.md (validated via IDA).
    // (DisableEnqueue / EnableCleanup / EnableApply RVAs were already
    // used in the Frida JS era as constants — we're re-using them here.)
    constexpr std::uintptr_t DISABLE_ENQUEUE_RVA = 0x005B3EE0;
    constexpr std::uintptr_t ENABLE_CLEANUP_RVA  = 0x005B4430;
    constexpr std::uintptr_t ENABLE_APPLY_RVA    = 0x005B4140;

    g_lookup = reinterpret_cast<LookupByFormIDFn>(
        module_base + offsets::LOOKUP_BY_FORMID_RVA);
    g_disable = reinterpret_cast<DisableEnqueueFn>(
        module_base + DISABLE_ENQUEUE_RVA);
    g_enable_cleanup = reinterpret_cast<EnableCleanupFn>(
        module_base + ENABLE_CLEANUP_RVA);
    g_enable_apply = reinterpret_cast<EnableApplyFn>(
        module_base + ENABLE_APPLY_RVA);
    g_inv_item_count = reinterpret_cast<InvItemGetCountFn>(
        module_base + offsets::INVITEM_GET_COUNT_RVA);

    // B1.j.1: BGSInventoryList materializer + CONT component getter.
    g_materialize_inv = reinterpret_cast<MaterializeInvListFn>(
        module_base + offsets::BGS_INV_LIST_MATERIALIZE_RVA);
    g_get_component = reinterpret_cast<GetComponentFn>(
        module_base + offsets::TESFORM_GET_COMPONENT_RVA);

    // B1.g: engine's real AddItem / RemoveItem (called by the functor path).
    g_engine_add_item = reinterpret_cast<EngineAddItemFn>(
        module_base + offsets::ENGINE_ADD_ITEM_RVA);
    g_engine_remove_item = reinterpret_cast<EngineRemoveItemFn>(
        module_base + offsets::ENGINE_REMOVE_ITEM_RVA);

    // B6.1: Activate worker resolver (door open/close engine call).
    g_engine_activate = reinterpret_cast<ActivateWorkerFn>(
        module_base + offsets::ENGINE_ACTIVATE_WORKER_RVA);

    // B6.3 v0.5.3: Papyrus Lock/Unlock binding (sub_141158640) for the
    // receiver-side lock state apply. With ai_notify=0 it bypasses the
    // minigame and key-consumption side effects.
    g_lock_apply_papyrus = reinterpret_cast<LockApplyPapyrusFn>(
        module_base + offsets::ENGINE_LOCK_PAPYRUS_APPLY_RVA);

    // B6.5w3.b: anim graph variable setters + BSFixedString minter.
    g_bsfs_make = reinterpret_cast<BSFixedStringMakeFn>(
        module_base + offsets::BSFIXEDSTRING_MAKE_RVA);
    g_set_graph_var_float = reinterpret_cast<SetGraphVarFloatFn>(
        module_base + offsets::SET_GRAPH_VAR_FLOAT_RVA);
    g_set_graph_var_bool = reinterpret_cast<SetGraphVarBoolFn>(
        module_base + offsets::SET_GRAPH_VAR_BOOL_RVA);
    g_set_graph_var_int = reinterpret_cast<SetGraphVarIntFn>(
        module_base + offsets::SET_GRAPH_VAR_INT_RVA);

    // B6.5w4 round 5: Actor.EnableAI native — clears bit 2 of flags_720
    // (+0x2D0). Walker gate `(flags_720 & 2) != 0` becomes false →
    // Update_PerFrame skipped for the actor → AI fully silenced.
    g_actor_enable_ai = reinterpret_cast<ActorEnableAIFn>(
        module_base + offsets::ENGINE_ENABLE_AI_RVA);

    // B6.5w4 round 7: atomic teleport (Actor::MoveTo) + SetMotionType
    // worker. Identified by agent B as the silver bullet — atomic write
    // through all engine caches, bypassing the 6-round fight.
    g_actor_atomic_teleport = reinterpret_cast<ActorMoveToFn>(
        module_base + offsets::ACTOR_ATOMIC_TELEPORT_RVA);
    g_niav_set_motion_type = reinterpret_cast<NiAVSetMotionTypeFn>(
        module_base + offsets::NIAV_SET_MOTION_TYPE_RVA);

    // Build 65.c.47 — WEDGE3 death-sync. Actor::Kill worker (same RVA the
    // kill_hook detours). Used by kill_actor() to corpse a non-owner mirror.
    g_kill_engine = reinterpret_cast<ActorKillFn>(
        module_base + offsets::KILL_ENGINE_RVA);

    // B6.6w4 — fire trigger via WeaponFireHandler.
    g_weapon_fire_handler = reinterpret_cast<WeaponFireHandlerFn>(
        module_base + offsets::WEAPON_FIRE_HANDLER_RVA);
    // B6.6w4 — movement controller disable (defunct, never call).
    g_movctrl_set_disabled = reinterpret_cast<MovCtrlSetDisabledFn>(
        module_base + offsets::MOVCTRL_SET_DISABLED_RVA);

    // ============================================================
    // PUPPET FIRE PHASE 1 — Scenario A primitives (2026-05-17).
    // See re/puppet_fire_phase1/SUPERVISOR_SYNTHESIS.md §7.
    // ============================================================
    g_weapon_state_class_setter = reinterpret_cast<WeaponStateClassSetterFn>(
        module_base + offsets::WEAPON_STATE_CLASS_SETTER_RVA);
    g_resolve_weapon_slot = reinterpret_cast<ActorResolveWeaponSlotFn>(
        module_base + offsets::ACTOR_RESOLVE_WEAPON_SLOT_RVA);
    g_aim_set_target = reinterpret_cast<AimSetTargetFn>(
        module_base + offsets::AIM_SET_TARGET_RVA);
    g_aim_ctrl_vtbl_addr =
        module_base + offsets::COMBAT_AIM_CONTROLLER_VTBL_RVA;
    FW_LOG("engine: puppet-fire init  state_setter=%p slot_resolver=%p "
           "aim_setter=%p vtbl=0x%llX",
           reinterpret_cast<void*>(g_weapon_state_class_setter),
           reinterpret_cast<void*>(g_resolve_weapon_slot),
           reinterpret_cast<void*>(g_aim_set_target),
           static_cast<unsigned long long>(g_aim_ctrl_vtbl_addr));

    // ============================================================
    // PUPPET FIRE PHASE 1.5 — EnterCombat primitive (2026-05-17).
    // See re/puppet_fire_phase1/D_AGENT_enter_combat.md.
    // ============================================================
    g_enter_combat = reinterpret_cast<EnterCombatFn>(
        module_base + offsets::ENTER_COMBAT_RVA);
    FW_LOG("engine: enter_combat resolved at %p (RVA 0x%lX)",
           reinterpret_cast<void*>(g_enter_combat),
           static_cast<unsigned long>(offsets::ENTER_COMBAT_RVA));

    // Build 63 — AddAlly(CombatController, Actor). Same RVA we hook as
    // Hook 13 ("EnsureKnownTarget" — naming mistake; it's actually AddAlly
    // per Agent C's static analysis of funcs_0344.md:6557-6562).
    g_add_ally_to_ctrl = reinterpret_cast<AddAllyToCtrlFn>(
        module_base + offsets::COMBATCTRL_ENSURE_KNOWN_RVA);
    FW_LOG("engine: add_ally_to_ctrl resolved at %p (RVA 0x%lX)",
           reinterpret_cast<void*>(g_add_ally_to_ctrl),
           static_cast<unsigned long>(offsets::COMBATCTRL_ENSURE_KNOWN_RVA));

    // ============================================================
    // STRADA B.2 (2026-05-22) — Manual synthesis primitives.
    // re/strada_B2_synthesize_highprocess/SUPERVISOR_SYNTHESIS.md
    // ============================================================
    g_combat_promoter_fresh = reinterpret_cast<CombatPromoterFreshFn>(
        module_base + offsets::COMBAT_PROMOTER_FRESH_RVA);
    g_aim_ctrl_ctor = reinterpret_cast<AimCtrlCtorFn>(
        module_base + offsets::COMBAT_AIM_CONTROLLER_CTOR_RVA);
    FW_LOG("[strada-B2] resolved promoter_fresh=%p (RVA 0x%lX) "
           "aim_ctrl_ctor=%p (RVA 0x%lX) combat_mgr_bag_idx=%zu",
           reinterpret_cast<void*>(g_combat_promoter_fresh),
           static_cast<unsigned long>(offsets::COMBAT_PROMOTER_FRESH_RVA),
           reinterpret_cast<void*>(g_aim_ctrl_ctor),
           static_cast<unsigned long>(offsets::COMBAT_AIM_CONTROLLER_CTOR_RVA),
           offsets::COMBAT_MANAGER_BAG_INDEX);

    // B6.6w5 — Actor::vt[202] full-teleport for receiver-side pos apply.
    g_actor_setpos_vt202 = reinterpret_cast<ActorSetPosFullFn>(
        module_base + offsets::ACTOR_SETPOS_VT202_RVA);

    // B6.6w5 — engine-native PlayerCharacter spawn path.
    g_player_ctor = reinterpret_cast<PlayerCtorFn>(
        module_base + offsets::PLAYER_CTOR_RVA);
    g_memmgr_alloc = reinterpret_cast<MemMgrAllocFn>(
        module_base + offsets::MEMMGR_ALLOC_RVA);
    g_memmgr_lazy_init = reinterpret_cast<MemMgrLazyInitFn>(
        module_base + offsets::MEMMGR_LAZY_INIT_RVA);
    g_processlists_add_actor = reinterpret_cast<ProcessListsAddActorFn>(
        module_base + offsets::PROCESSLISTS_ADD_ACTOR_RVA);
    g_memmgr_instance = reinterpret_cast<void*>(
        module_base + offsets::MEMMGR_INSTANCE_RVA);
    g_memmgr_init_guard = reinterpret_cast<std::uint32_t*>(
        module_base + offsets::MEMMGR_INIT_GUARD_RVA);

    // B6.6w5 Build 27 — AIProcess + handle-sub-buffer constructors for
    // per-ghost re-allocation (Agent 10 recipe Section 4A + 4D).
    g_aiprocess_ctor = reinterpret_cast<AIProcessCtorFn>(
        module_base + 0xCEEAB0);
    g_aiprocess_populate = reinterpret_cast<AIProcessPopulateFn>(
        module_base + 0xCFA450);
    g_handleref_init = reinterpret_cast<HandleRefInitFn>(
        module_base + 0x272730);

    // B6.6w5 Build 28 — engine-native proxy spawn primitives. RVAs
    // manually verified against `D:\falloutworld_decomp\out\05_functions.csv`
    // and decomp file:line citations in AGENT P1A/P1B reports.
    // (g_place_at_me already resolved below at line ~720 from offsets::PLACE_AT_ME_RVA)
    g_set_disabled = reinterpret_cast<SetDisabledFn>(
        module_base + 0x0519410);            // SetDisabled sub_140519410

    // Build 56 (Option C) — global form-table deregister primitives.
    g_form_erase = reinterpret_cast<EraseFormFn>(
        module_base + 0x0315740);            // ERASE sub_140315740
    g_form_lock_acquire_w = reinterpret_cast<AcquireWriteFn>(
        module_base + 0x1659060);            // WriteLock acquire sub_141659060
    g_form_lock_release_w = reinterpret_cast<ReleaseWriteFn>(
        module_base + 0x16592C0);            // WriteLock release sub_1416592C0
    g_form_table_base_addr = reinterpret_cast<void*>(
        module_base + 0x030E0DC8);           // qword_1430DBF78[2506]
    g_form_table_lock_addr = reinterpret_cast<void*>(
        module_base + 0x030E0E18);           // qword_1430DBF78[2516]
    FW_LOG("[ghost-deregister] form-table primitives resolved: "
           "erase=%p lock_acq_w=%p lock_rel_w=%p table_base=%p table_lock=%p",
           reinterpret_cast<void*>(g_form_erase),
           reinterpret_cast<void*>(g_form_lock_acquire_w),
           reinterpret_cast<void*>(g_form_lock_release_w),
           g_form_table_base_addr,
           g_form_table_lock_addr);
    g_set_ghost = reinterpret_cast<SetGhostFn>(
        module_base + 0x0C5CE40);            // SetGhost sub_140C5CE40
    g_set_position_engine = reinterpret_cast<SetPositionEngineFn>(
        module_base + 0x0513A80);            // SetPosition sub_140513A80
    g_set_rotation_engine = reinterpret_cast<SetRotationEngineFn>(
        module_base + 0x0513790);            // SetRotation sub_140513790
    g_create_by_type_code = reinterpret_cast<CreateByTypeCodeFn>(
        module_base + 0x04F9E60);            // CreateByTypeCode sub_1404F9E60
    g_handle_resolve = reinterpret_cast<HandleResolveFn>(
        module_base + 0x02A0540);            // ObjHandle::TryGetRef sub_1402A0540

    g_player_alt_singleton = reinterpret_cast<void**>(
        module_base + offsets::PLAYER_ALT_SINGLETON_RVA);
    g_procmgr_bag = reinterpret_cast<void**>(
        module_base + offsets::PROCMGR_BAG_RVA);
    g_refr_set_parent_cell = reinterpret_cast<RefrSetParentCellFn>(
        module_base + offsets::REFR_SETPARENTCELL_RVA);
    g_refr_set_position_leaf = reinterpret_cast<RefrSetPositionLeafFn>(
        module_base + offsets::REFR_SETPOSITION_LEAF_RVA);
    g_set_combat_target_engine = reinterpret_cast<SetCombatTargetFn>(
        module_base + offsets::AIPROCESS_SET_COMBAT_TARGET_RVA);
    g_handle_get_or_alloc = reinterpret_cast<HandleGetOrAllocFn>(
        module_base + offsets::HANDLE_GET_OR_ALLOC_RVA);

    // B6.6w5 Build 29 — Fixed selector primitives. See engine_calls.h
    // ::install_fixed_selector_on_raider and offsets.h "Build 29" block.
    g_add_combat_target = reinterpret_cast<AddCombatTargetFn>(
        module_base + offsets::ADD_COMBAT_TARGET_RVA);
    g_fixed_selector_ctor = reinterpret_cast<FixedSelectorCtorFn>(
        module_base + offsets::FIXED_SELECTOR_CTOR_RVA);
    g_engine_heap_alloc = reinterpret_cast<EngineHeapAllocFn>(
        module_base + offsets::ENGINE_HEAP_ALLOC_RVA);
    g_engine_heap_desc = reinterpret_cast<void*>(
        module_base + offsets::ENGINE_HEAP_DESC_RVA);
    // Build 30 Fix 1 — spinlock write-release for AddTarget SEH recovery.
    g_lock_release_write = reinterpret_cast<LockReleaseWriteFn>(
        module_base + offsets::LOCK_RELEASE_WRITE_RVA);
    // Build 30 Fix 3 — handle table base for inline resolution during purge.
    g_handle_table_base = reinterpret_cast<std::uint8_t*>(
        module_base + offsets::HANDLE_TABLE_BASE_RVA);
    FW_LOG("[fixed-sel] resolved: add_combat_target=%p ctor=%p heap_alloc=%p "
           "heap_desc=%p lock_release=%p handle_tbl=%p",
           reinterpret_cast<void*>(g_add_combat_target),
           reinterpret_cast<void*>(g_fixed_selector_ctor),
           reinterpret_cast<void*>(g_engine_heap_alloc),
           g_engine_heap_desc,
           reinterpret_cast<void*>(g_lock_release_write),
           static_cast<void*>(g_handle_table_base));

    // B6.6w5 Build 4 — populate the no-op vtable used to defuse the ghost's
    // event sinks. Done in init() (not at static-init time) to avoid ODR
    // issues with function pointers in array initializers.
    for (auto& slot : g_noop_vtable) {
        slot = reinterpret_cast<void*>(&noop_sink_method);
    }

    // B6.6w5 Build 8b — clone PlayerCharacter vtable and patch slot 140
    // (Get3D) with our hook. Read-only after this point; spawn_ghost_player
    // installs the cloned vtable on the duplicate.
    init_duplicate_vtable(module_base);

    // Mint cached BSFixedStrings for the hot anim variables we drive in
    // w3.b. Wrapped in SEH because BSFixedString minter touches the pool
    // global allocator — pre-engine-init call would crash. By the time
    // engine::init() runs the player singleton is populated, so the pool
    // is alive; still defensive.
    __try {
        g_bsfs_make(&g_bs_speed_sampled, "SpeedSampled");
        g_bsfs_make(&g_bs_direction,     "Direction");
        g_bsfs_make(&g_bs_anim_driven,   "bAnimationDriven");
        // Build 62 (2026-05-24) — CANONICAL anim graph names.
        //
        // Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md §4 (Agent C-BETA
        // discovery, judge verified): the previous names `bIsRunning`,
        // `bIsSprinting`, `bIsAttacking`, `bIsAimingGun`, `bIsBlocking`,
        // `bIsSneaking`, `bIsDead` are HALLUCINATED — zero matches in
        // strings.csv. Every SetGraphVariableBool call against these names
        // was a silent no-op since Build 23. Canonical names verified
        // against decomp + pool registration sites:
        //   - iIsInSneak    INT, pool 2992       (funcs_0008.md:1478)
        //   - IsRunning     bool, HKX-loaded     (strings.csv 0x1424C38E8)
        //   - IsSprinting   bool, pool 282690    (funcs_0059.md:587)
        //   - IsBlocking    bool, pool 282691    (funcs_0059.md:588)
        //   - bAimActive    bool, pool 282710    (funcs_0059.md:607)
        //   - IsDead        bool, Papyrus-only   (strings.csv 0x1425B63AC)
        //
        // NOTE: `IsAttacking` has only data-section xrefs (no code-side
        // registration). Driving attack animations via SetGraphVariable
        // by name may NOT propagate to transitions. Reserved for future
        // research; for now we mint it but don't rely on its effect.
        //
        // CRITICAL: `iIsInSneak` is INT (0/1), use SetGraphVariableInt,
        // NOT SetGraphVariableBool. Callers must dispatch correctly.
        g_bsfs_make(&g_bs_is_running,    "IsRunning");
        g_bsfs_make(&g_bs_is_sprinting,  "IsSprinting");
        g_bsfs_make(&g_bs_is_attacking,  "IsAttacking");   // see NOTE above
        g_bsfs_make(&g_bs_is_aiming_gun, "bAimActive");    // canonical aim-active
        g_bsfs_make(&g_bs_is_blocking,   "IsBlocking");
        g_bsfs_make(&g_bs_is_sneaking,   "iIsInSneak");    // INT, NOT bool
        g_bsfs_make(&g_bs_is_dead,       "IsDead");
        FW_LOG("engine: BSFixedString cache minted (Build 62 canonical names): "
               "SpeedSampled=%p Direction=%p bAnimationDriven=%p "
               "IsRunning=%p IsAttacking=%p bAimActive=%p iIsInSneak=%p",
               g_bs_speed_sampled.pool_entry, g_bs_direction.pool_entry,
               g_bs_anim_driven.pool_entry, g_bs_is_running.pool_entry,
               g_bs_is_attacking.pool_entry, g_bs_is_aiming_gun.pool_entry,
               g_bs_is_sneaking.pool_entry);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: BSFixedString mint SEH-faulted — w3.b/w4 setter calls "
               "will short-circuit until next init");
        g_bs_speed_sampled.pool_entry = nullptr;
        g_bs_direction.pool_entry     = nullptr;
        g_bs_anim_driven.pool_entry   = nullptr;
        g_bs_is_running.pool_entry    = nullptr;
        g_bs_is_sprinting.pool_entry  = nullptr;
        g_bs_is_attacking.pool_entry  = nullptr;
        g_bs_is_aiming_gun.pool_entry = nullptr;
        g_bs_is_blocking.pool_entry   = nullptr;
        g_bs_is_sneaking.pool_entry   = nullptr;
        g_bs_is_dead.pool_entry       = nullptr;
    }

    // B1.k.2: BGSObjectRefHandle resolver — for ContainerMenu::TransferItem
    // we need to reach the container REFR from `this+1064` (a handle slot).
    g_refhandle_resolve = reinterpret_cast<RefHandleResolveFn>(
        module_base + offsets::REFHANDLE_RESOLVE_RVA);

    // B1.k.3: ContainerMenu inventory-entry → TESForm* decoder. The engine's
    // ContainerMenu keeps 32-byte-per-entry rows; decoding them requires
    // calling sub_1403478E0 with the form-cache global as context.
    g_inv_entry_to_form = reinterpret_cast<InvEntryToFormFn>(
        module_base + offsets::INV_ENTRY_TO_FORM_RVA);
    g_form_cache_slot = reinterpret_cast<void**>(
        module_base + offsets::FORM_CACHE_SINGLETON_RVA);

    // B3.b: LoadGame ingredients.
    g_load_game = reinterpret_cast<LoadGameFn>(
        module_base + offsets::LOAD_GAME_FN_RVA);
    g_load_precond = reinterpret_cast<LoadPreconditionFn>(
        module_base + offsets::LOAD_PRECOND_FN_RVA);
    g_load_prep = reinterpret_cast<LoadPrepFn>(
        module_base + offsets::LOAD_PREP_FN_RVA);
    g_save_load_mgr_slot = reinterpret_cast<void**>(
        module_base + offsets::SAVE_LOAD_MGR_SINGLETON_RVA);
    g_save_dev_slot = reinterpret_cast<void**>(
        module_base + offsets::SAVE_DEV_SINGLETON_RVA);
    g_load_in_progress = reinterpret_cast<std::uint8_t*>(
        module_base + offsets::LOAD_IN_PROGRESS_FLAG_RVA);

    // Z.2: PlaceAtMe native + player singleton slot (for anchor REFR).
    g_place_at_me = reinterpret_cast<PlaceAtMeFn>(
        module_base + offsets::PLACE_AT_ME_RVA);
    g_player_singleton_slot = reinterpret_cast<void**>(
        module_base + offsets::PLAYER_SINGLETON_RVA);

    g_ready.store(true, std::memory_order_release);
    FW_LOG("engine: calls resolved "
           "lookup=%p disable=%p enable_cleanup=%p enable_apply=%p "
           "inv_item_count=%p materialize_inv=%p get_component=%p "
           "add_item=%p remove_item=%p refhandle=%p "
           "inv_entry_to_form=%p form_cache_slot=%p "
           "load_game=%p precond=%p prep=%p "
           "mgr_slot=%p dev_slot=%p flag=%p",
           g_lookup, g_disable, g_enable_cleanup, g_enable_apply,
           g_inv_item_count, g_materialize_inv, g_get_component,
           g_engine_add_item, g_engine_remove_item, g_refhandle_resolve,
           g_inv_entry_to_form, g_form_cache_slot,
           g_load_game, g_load_precond, g_load_prep,
           g_save_load_mgr_slot, g_save_dev_slot, g_load_in_progress);
    return true;
}

// B6.6w5 Build 9 — ghost duplicate registry.
//
// The duplicate spawned via memcpy is intentionally NOT in the engine's
// global form table (we never called vt[65] SetFormID(fid, /*add=*/true)).
// So `g_lookup(0xFF000001)` returns NULL.
//
// But `ghost_ai_set_combat_target.cpp` relies on lookup_by_form_id to
// resolve the server-broadcast combat_target form_id → actor pointer.
// To make the substitution work when server says
// `combat_target = 0xFF000001` (= the ghost on this client representing
// the OTHER peer), we keep a tiny client-side registry: fid → ptr.
//
// lookup_by_form_id below first checks this registry; if hit, returns
// the duplicate ptr. Else falls back to engine lookup.
//
// 2-peer MVP: a single slot. Scaling beyond 2 peers requires per-peer
// fids (e.g. 0xFF000001, 0xFF000002, ...) and a map; out of scope here.
std::atomic<std::uint32_t> g_ghost_duplicate_fid{0};
std::atomic<void*>          g_ghost_duplicate_ptr{nullptr};
// B6.6w5 Build 23 — cached engine handle for the duplicate. Allocated
// once at spawn (in spawn_ghost_player). Reused by the set_combat_target
// hook to avoid re-entering the engine handle allocator on every
// substitution (each re-entry is a heap-corruption / fast-fail risk per
// agent 8 analysis of the duplicate's memcpy'd refcount slot).
std::atomic<std::uint32_t>  g_ghost_duplicate_handle{0};

// ============================================================================
// Build 35 (2026-05-16) — ONE-HOOK BASEFORM SWAP state.
//
// `g_safe_npc_base` is a SHARED engine TESNPC pointer (formType==0x2D,
// formID != 0x07). We observe it lazily by walking through any actor
// the per-frame hook sees and checking their baseForm. Once seeded, we
// never overwrite it (the cached pointer is a long-lived engine
// singleton; whichever NPC's baseForm we picked first is fine — it's a
// vanilla, fully-initialized TESForm record in the engine's master
// form-table).
//
// `g_ghost_baseform_swapped` tracks whether we've done the one-shot
// swap on the live ghost yet. Reset on ghost despawn / DLL reload.
// ============================================================================
std::atomic<void*>          g_safe_npc_base{nullptr};
std::atomic<std::uint32_t>  g_safe_npc_base_formid{0};
std::atomic<bool>           g_ghost_baseform_swapped{false};
std::atomic<std::uint64_t>  g_safe_npc_acquire_attempts{0};

void register_ghost_duplicate(std::uint32_t fid, void* ptr) noexcept {
    g_ghost_duplicate_ptr.store(ptr, std::memory_order_release);
    g_ghost_duplicate_fid.store(fid, std::memory_order_release);
    FW_LOG("[ghost-native] registered duplicate in client-side lookup "
           "registry: fid=0x%08X → ptr=%p (lookup_by_form_id will now "
           "return this for combat_target substitution)", fid, ptr);
}

// ============================================================================
// Build 56 (2026-05-23) — Option C: Deregister ghost from global form table.
//
// Source: re/option_C_deregister_ghost/AGENT_deregister_analysis.md (HIGH conf
// on table layout + ERASE function semantics; MED conf on residual untraced
// engine paths). Per-RVA vt-guards (vt[197] ghost_vt197_guard.cpp, vt[51]
// docs) don't scale — 25+ similar dispatch sites identified. This is the
// architecturally clean fix that eliminates the entire vt-cascade-on-ghost
// crash class in one operation.
//
// Pipeline: PlaceAtMe / CreateByTypeCode auto-registers ghost into
// qword_1430DBF78[2506] (= MEMORY[0x1430E0DC8], the engine's global
// FormID→Form hash table). After this call, sub_140C06AC0 / sub_140CA85C0 /
// sub_1402ED190 / etc. iterate the table and call vt[N] on EVERY entry.
// Because ghost is a synthetic proxy with incomplete sub-objects, those
// vt dispatches hit garbage and crash.
//
// Option C unhooks the ghost from this global table AFTER spawn completes.
// Engine walkers iterate the same buckets but find ghost.bucket->form*
// == NULL (the standard skip-empty path) and move on.
//
// Our internal paths (combat target apply, anim sync, ghost-pos write)
// continue working via lookup_by_form_id which checks g_ghost_duplicate_ptr
// FIRST before falling back to g_lookup. All 8 wrapper callers in this
// file route through that wrapper — no caller changes needed.
//
// MUST run AFTER register_ghost_duplicate (so the private-map fallback is
// hot before we yank the global entry). MAIN THREAD ONLY.
//
// Returns true if a bucket entry matching the ghost's FormID was found
// and unlinked. False if no such entry existed (ghost was never auto-
// registered — e.g., PlaceAtMe took a temp-ref shortcut).
bool deregister_ghost_from_form_table(void* ghost_actor) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!ghost_actor) return false;
    if (!g_form_erase || !g_form_lock_acquire_w ||
        !g_form_lock_release_w || !g_form_table_base_addr ||
        !g_form_table_lock_addr) {
        FW_ERR("[ghost-deregister] one or more form-table resolvers null "
               "(erase=%p acq=%p rel=%p base=%p lock=%p)",
               reinterpret_cast<void*>(g_form_erase),
               reinterpret_cast<void*>(g_form_lock_acquire_w),
               reinterpret_cast<void*>(g_form_lock_release_w),
               g_form_table_base_addr, g_form_table_lock_addr);
        return false;
    }

    // Read ghost's FormID (TESForm::formID at +0x14).
    std::uint32_t ghost_fid = 0;
    __try {
        ghost_fid = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(ghost_actor) +
            offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-deregister] SEH reading ghost+0x14 (fid)");
        return false;
    }
    if (ghost_fid == 0 || ghost_fid == 0xFFFFFFFFu) {
        FW_WRN("[ghost-deregister] ghost has invalid FID=0x%08X; "
               "nothing to remove", ghost_fid);
        return false;
    }

    // Sanity: ensure private-map lookup is hot for ghost_fid before
    // we remove the global entry. Idempotent — re-registers safely.
    if (g_ghost_duplicate_ptr.load(std::memory_order_acquire)
            != ghost_actor) {
        register_ghost_duplicate(ghost_fid, ghost_actor);
    }

    // WRITE-lock, erase, unlock. SEH-cage the whole sequence — if any
    // step AVs (e.g. relocation drift on table base), log + survive.
    std::uint8_t removed_flag = 0;
    void* out_form_ptr = nullptr;
    __try {
        g_form_lock_acquire_w(g_form_table_lock_addr);
        removed_flag = g_form_erase(
            reinterpret_cast<std::uintptr_t>(g_form_table_base_addr),
            &ghost_fid,
            &out_form_ptr);
        g_form_lock_release_w(g_form_table_lock_addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-deregister] SEH inside lock+erase for fid=0x%08X",
               ghost_fid);
        // Best-effort release in case we faulted between acquire and
        // release. Release is idempotent for write-held-by-us.
        __try { g_form_lock_release_w(g_form_table_lock_addr); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return false;
    }

    FW_LOG("[ghost-deregister] fid=0x%08X removed=%u out_form=%p "
           "(ghost is now invisible to global form-table walkers; "
           "private-registry lookup still resolves via "
           "g_ghost_duplicate_ptr)",
           ghost_fid, static_cast<unsigned>(removed_flag), out_form_ptr);

    return removed_flag != 0;
}

void* get_ghost_duplicate() noexcept {
    return g_ghost_duplicate_ptr.load(std::memory_order_acquire);
}

std::uint32_t get_ghost_duplicate_handle() noexcept {
    return g_ghost_duplicate_handle.load(std::memory_order_acquire);
}

// ============================================================================
// Build 35 (2026-05-16) — ONE-HOOK BASEFORM SWAP implementation.
//
// Strategy: when ANY non-ghost actor is visited by the per-frame walker,
// peek its baseForm pointer. If formType==0x2D (TESNPC) AND formID is
// NEITHER 0 NOR 0x07 (PlayerNPC), this is a safe vanilla NPC base we
// can point our ghost at. CAS-install it into the cache. Idempotent —
// once seeded, the early-out returns immediately.
//
// The swap itself is a single 8-byte qword write to ghost+0xE0
// (BASE_FORM_OFF). Atomic on x64. Engine readers do a single mov to
// pick up the new value; no torn read possible.
//
// What this kills:
//   - sub_140CC9150 (perception/relation walk reading baseForm+0x130)
//   - sub_140C7AD40 (IsHostile master predicate's player-fast-path)
//   - sub_140C7ABC0 (AddTarget validator's "is player target" check)
//   - All 155+ functions decompiled by Agent F3 with `if (baseForm ==
//     PlayerNPC) { ... player-only deref ... }` branches
//   - Damage modifier pipeline reads of baseForm-AttackData
//   - Faction list resolution on baseForm
//   - Race-data resolver chain (sub_141019DD0 and friends)
//   - AI orchestrator player-check pre-filter (sub_140CCFDF0)
//
// All these become "non-player NPC, take the generic path" which is
// the well-trodden path the engine runs on every vanilla raider already.
//
// Sub-object patches (F2 IAGMH vt, F5 MagicTarget vt[4] immune shim,
// F9 AIProcess zeros, isPlayer-bit clear at 0x2D0) remain in place as
// defense-in-depth — they're cheap, they harden the ghost against any
// stray code path that doesn't go via baseForm. But the baseForm swap
// is the ONE primary fix that removes the entire crash CLASS.
// ============================================================================

void try_acquire_safe_npc_base(void* candidate_actor) noexcept {
    if (!candidate_actor) return;
    // Fast path: already cached.
    if (g_safe_npc_base.load(std::memory_order_acquire) != nullptr) return;

    // Increment attempts counter once per call (diagnostic — tells us how
    // many actors the walker scanned before we got a hit).
    g_safe_npc_acquire_attempts.fetch_add(1, std::memory_order_relaxed);

    void* base = nullptr;
    std::uint8_t formtype = 0xFF;
    std::uint32_t base_fid = 0;
    __try {
        base = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(candidate_actor) +
            offsets::BASE_FORM_OFF);
        if (!base) return;
        formtype = *reinterpret_cast<std::uint8_t*>(
            reinterpret_cast<std::uint8_t*>(base) + offsets::FORMTYPE_OFF);
        base_fid = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(base) + offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    // Must be a TESNPC, non-null fid, NOT PlayerNPC, AND vanilla (formID
    // < 0xFF000000). The 0xFF range is reserved by FO4 for runtime-
    // allocated forms (light master / temp / SPAI-injected custom
    // forms). These can have partially-init sub-objects (race, anim
    // graph), exactly the kind of missing data that crashes the race
    // resolver chain. We need an ESM-loaded form with all sub-objects
    // populated.
    //
    // Build 35.2 (2026-05-16) — added vanilla-range filter after live
    // test of Build 35 cached fid=0xFF001115 (a runtime form) and the
    // engine race resolver sub_140CCD380 returned 0x400 garbage → AV
    // at rip=0x101C549.
    if (formtype != offsets::FORMTYPE_NPC) return;
    if (base_fid == 0 || base_fid == offsets::PLAYERNPC_FORMID) return;
    if (base_fid >= 0xFF000000u) return;  // skip runtime / custom forms

    // CAS-install. Lose the race? Someone else cached a different valid
    // TESNPC — that's also fine, any vanilla TESNPC is acceptable.
    void* expected = nullptr;
    if (g_safe_npc_base.compare_exchange_strong(
            expected, base,
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        g_safe_npc_base_formid.store(base_fid, std::memory_order_release);
        const auto attempts =
            g_safe_npc_acquire_attempts.load(std::memory_order_relaxed);
        FW_LOG("[basebrm-swap] CACHED safe vanilla TESNPC: ptr=%p "
               "formID=0x%08X formType=0x%02X (= TESNPC) after %llu walker "
               "scans — attempting immediate swap on registered ghost",
               base, base_fid, formtype,
               static_cast<unsigned long long>(attempts));

        // Zero-frame-latency swap: if a ghost is already registered,
        // perform the swap RIGHT NOW so subsequent engine reads in this
        // very tick (e.g., later in this frame's ProcessLists pass when
        // the engine visits the ghost from a different code path) see
        // the vanilla baseForm. Without this, the swap would wait until
        // the walker visits the ghost itself, which could be a frame
        // away — and that frame's worth of engine reads on the ghost
        // would still see PlayerNPC.
        //
        // get_ghost_duplicate is atomic-load (acquire), thread-safe.
        // try_swap_ghost_baseform internally early-outs if the swap
        // was already done.
        void* ghost = g_ghost_duplicate_ptr.load(std::memory_order_acquire);
        if (ghost) {
            try_swap_ghost_baseform(ghost);
        }
    }
}

void* get_safe_npc_base() noexcept {
    return g_safe_npc_base.load(std::memory_order_acquire);
}

bool try_swap_ghost_baseform(void* ghost_actor) noexcept {
    if (!ghost_actor) return false;
    // Already swapped? Bail.
    if (g_ghost_baseform_swapped.load(std::memory_order_acquire)) return false;

    void* safe_base = g_safe_npc_base.load(std::memory_order_acquire);
    if (!safe_base) return false;  // No cached vanilla NPC yet.

    void* current_base = nullptr;
    std::uint32_t current_base_fid = 0;
    std::uint8_t current_base_formtype = 0xFF;
    __try {
        current_base = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(ghost_actor) +
            offsets::BASE_FORM_OFF);
        if (current_base) {
            current_base_fid = *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(current_base) +
                offsets::FORMID_OFF);
            current_base_formtype = *reinterpret_cast<std::uint8_t*>(
                reinterpret_cast<std::uint8_t*>(current_base) +
                offsets::FORMTYPE_OFF);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[basebrm-swap] SEH reading ghost+0xE0 / current_base "
               "fields (ghost=%p)", ghost_actor);
        return false;
    }

    // Build 35.2 (2026-05-16) — fire the swap WHENEVER current_base
    // is not already what we want (i.e., != safe_base). Previous
    // gate was "only swap if base == PlayerNPC(0x07)" which bailed
    // out when live test showed ghost+0xE0 reading fid=0x14 (some
    // engine post-spawn fixup populated baseForm with a non-PlayerNPC,
    // non-vanilla pointer). We don't care WHAT the current pointer
    // is — if it's not our cached safe vanilla TESNPC, we override it.
    //
    // The diagnostic log captures the full triple (ptr / fid / formType)
    // so any future weird state is observable.
    if (current_base == safe_base) {
        // Already pointing where we want — mark done, suppress further checks.
        g_ghost_baseform_swapped.store(true, std::memory_order_release);
        return false;
    }

    // Perform the atomic 8-byte qword write. On x64 a single mov to an
    // 8-byte-aligned address is atomic (Intel SDM Vol.1 §17.2.1) — and
    // actor+0xE0 is 8-byte-aligned. Engine readers `mov rax,[actor+0xE0]`
    // observe either the OLD or the NEW pointer atomically, never a tear.
    bool swap_ok = false;
    std::uint32_t new_base_fid = 0;
    void* readback_base = nullptr;
    std::uint32_t readback_fid = 0;
    __try {
        *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(ghost_actor) +
            offsets::BASE_FORM_OFF) = safe_base;
        new_base_fid = g_safe_npc_base_formid.load(
            std::memory_order_acquire);
        // Read-back verification — if some engine code wrote ghost+0xE0
        // between our write and this read, we'll see the divergence.
        readback_base = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(ghost_actor) +
            offsets::BASE_FORM_OFF);
        if (readback_base) {
            readback_fid = *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(readback_base) +
                offsets::FORMID_OFF);
        }
        swap_ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[basebrm-swap] SEH writing/reading ghost+0xE0 = %p",
               safe_base);
        return false;
    }

    if (swap_ok) {
        g_ghost_baseform_swapped.store(true, std::memory_order_release);
        FW_LOG("[basebrm-swap] *** SWAP DONE *** ghost=%p +0xE0 was "
               "ptr=%p (fid=0x%08X formType=0x%02X) → wrote safe_base=%p "
               "(fid=0x%08X). readback ptr=%p fid=0x%08X. "
               "If readback matches safe_base, all engine baseForm "
               "reads from here on get a vanilla TESNPC.",
               ghost_actor, current_base, current_base_fid,
               current_base_formtype, safe_base, new_base_fid,
               readback_base, readback_fid);
    }
    return swap_ok;
}

// Build 38 (2026-05-16) — read PC's current parent_cell.
//
// Used by the `cross_cell_gate` hook (sub_140CF6100 detour) to satisfy
// the engine's PC.cell == target.cell predicate via TRANSIENT write
// to ghost+0xB8 for the duration of the hooked call, restored on
// return. See offsets.h `COMBAT_ENGAGE_GATE_RVA` block for full
// rationale.
//
// Safe to call from any thread: g_player_singleton_slot is an
// engine-managed const data pointer (set once in init()), and the
// player REFR itself is a long-lived singleton. We SEH-cage the
// derefs to guard against the brief window between game-load start
// and PC instantiation.
void* get_pc_parent_cell() noexcept {
    if (!g_player_singleton_slot) return nullptr;
    __try {
        void* pc = *g_player_singleton_slot;
        if (!pc) return nullptr;
        return *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(pc) +
            offsets::PARENT_CELL_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Build 62 — exposed accessor for local player Actor*. SEH-caged.
void* get_local_player() noexcept {
    if (!g_player_singleton_slot) return nullptr;
    __try {
        return *g_player_singleton_slot;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Build 65.c.28.1 — TELEPORT / CELL-TRANSITION detection.
//
// Replaces the BROKEN c.28 guard `is_load_in_progress()`, which read
// byte_1432D1FEA — a flag OUR OWN B3.b auto-load set to 1 at boot and that
// is never cleared in our bypass path. It stayed true for the whole
// session (52s+ observed) → every NPC sync write was suspended → total
// pos-sync regression. Wrong signal.
//
// Correct signal: watch the LOCAL PLAYER's parentCell pointer (Actor+0xB8).
// When it changes the player crossed a cell boundary (teleport / coc / door
// / exterior streaming) — exactly when the engine holds the cell-hash lock
// that apply_npc_pos (vt[202]) and puppet-fire would deadlock against (root
// cause of the c.25 + c.27 main-thread freezes). We suspend NPC engine
// writes for TELEPORT_SUSPEND_MS after any transition, and unconditionally
// while parentCell is null (mid-stream).
//
// Returns true = "suspend NPC engine writes now". During a stationary fight
// (no cell crossings) it always returns false → full-rate sync. Only a
// teleport/transition arms the brief window.
//
// Main-thread only (the 3 callers — npc_ai_suppress detour + the 2 WndProc
// drains — all run on the main thread). Statics need no mutex.
bool recently_teleported() noexcept {
    static void*         s_last_cell        = nullptr;
    static std::uint64_t s_suspend_until_ms = 0;
    constexpr std::uint64_t TELEPORT_SUSPEND_MS = 1500;

    void* const cur_cell = get_pc_parent_cell();   // SEH-caged read
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());

    if (cur_cell != s_last_cell) {
        // Arm the suspend window on a real transition. The first non-null
        // acquisition at boot (s_last_cell == null && cur_cell != null) is
        // NOT a teleport — don't arm for it. Any later change, or entering
        // a null-cell streaming window, arms.
        if (s_last_cell != nullptr || cur_cell == nullptr) {
            s_suspend_until_ms = now + TELEPORT_SUSPEND_MS;
        }
        s_last_cell = cur_cell;
    }

    // Null parentCell = mid-stream / no cell loaded → always unsafe to
    // touch NPC actors.
    if (cur_cell == nullptr) return true;

    return now < s_suspend_until_ms;
}

void* lookup_by_form_id(std::uint32_t form_id) {
    if (!g_ready.load(std::memory_order_acquire) || !g_lookup) return nullptr;
    // B6.6w5 Build 9: client-side override for the ghost duplicate fid.
    // Check BEFORE engine lookup — engine doesn't know about the duplicate
    // (intentional: we skipped vt[65] SetFormID add-to-table). If the
    // registered fid matches, return the duplicate ptr directly.
    const auto reg_fid = g_ghost_duplicate_fid.load(std::memory_order_acquire);
    if (reg_fid != 0 && reg_fid == form_id) {
        void* dup = g_ghost_duplicate_ptr.load(std::memory_order_acquire);
        if (dup) return dup;
    }
    void* result = nullptr;
    __try {
        result = g_lookup(form_id);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in lookup_by_form_id(0x%X)", form_id);
        result = nullptr;
    }
    return result;
}

// B6.6w5 Build 12 (Fix 1) — server-push combat target apply.
//
// Main-thread entry point that resolves `actor.AIProcess` (Actor+0x300)
// then calls the engine's `AIProcess::SetCombatTarget` directly with the
// looked-up target actor. The hook on SetCombatTarget will fire and do
// its substitution logic — which is fine, the substitution either
// confirms the target (no-op) or replaces with the registered duplicate.
//
// Threading: main thread only. SetCombatTarget reads TLS + global
// handle table, cross-thread races would corrupt state.
//
// ============================================================================
// DORMANT BEHAVIOR — 2026-05-17 log analysis. Function is CALLED but
// silently returns false on every call in production. Logs prove it:
//
//   Client A `fw_native.log`:
//     [17:29:39.650] dispatch: drained 13 npc entries
//                    (pos applied=8 missed=0,
//                     combat_target applied=0 missed=5)
//     [17:33:59.656] dispatch: drained 5 npc entries
//                    (pos applied=0 missed=0,
//                     combat_target applied=0 missed=5)
//   ↑ ALL 5 combat-target applies MISSED. Zero applied.
//
//   The function's first 20 log lines (`engine: apply_npc_combat_target #N`)
//   that would prove a successful write are ABSENT from both client logs.
//   The early-return-false paths are silent — no log line. So we infer
//   failure from the dispatch drain summary.
//
// WHICH EARLY-RETURN FIRES:
//   Most likely return at line `if (!aiproc) return false;` (combat
//   AIProcess slot at Actor+0x328 is NULL). The 5 raiders the server
//   aggroes (74E50/74E51/19E13C-E) are in Concord while player_A is in
//   Sanctuary. Engine never promotes them to combat tier with the ghost
//   because:
//     - Ghost.baseForm was swapped to safe vanilla TESNPC (no Raider
//       hostility) → HostilityCore returns 0
//     - No EnterCombat call → no AIProcess+0x328 allocation
//     - +0x328 stays NULL → this function bails at line ~1251
//
//   For raiders that DO enter natural combat (e.g. 0x46458/0x46459
//   when player_A walks near Concord at 17:32:06), the function might
//   reach the body, but the server says target=player_A=0x14 on this
//   client (vanilla local-target) and lookup_by_form_id returns the
//   real player actor. apply succeeds. We just don't see "combat_target
//   applied=>0" in the drain summary because Build 12 gate `(apply_flags
//   & 0x02)` is set only when server says combat_target != 0 AND the
//   dedup check passes.
//
// WHAT THIS MEANS FOR CROSS-PEER AGGRO:
//   The whole strategy of "client receives BCAST with target=ghost,
//   writes aiproc+0x6C=ghost_handle, engine combat brain runs against
//   ghost" is structurally blocked by the +0x328==NULL precondition.
//   Cannot fix from inside this function without first solving the
//   chicken-and-egg of "raider needs to be in combat tier with ghost
//   to be in combat tier with ghost".
//
//   The puppet-fire alternative (see re/AI_pipeline/section_08 §0)
//   does NOT call this function. Puppet fire writes weapon-state +
//   aim_target directly into the raider regardless of +0x328 state,
//   then invokes WeaponFireHandler to emit the visible projectile.
//   That bypass would make this function obsolete for combat sync —
//   but pos sync (apply_npc_pos) still needs the cache/drain pipeline.
//
// KEEP-AS-IS RATIONALE:
//   The function's full pipeline (gate→aiproc→lookup→handle→write
//   →inline install_fixed_selector) is sound and well-tested for the
//   IDEAL case (raider in combat, target lookup-able). It just never
//   gets to exercise that path in current architecture. Keep code for
//   the day a raider DOES end up in combat-tier vs ghost (e.g. via a
//   custom ESL with Raider-hostile factions on ghost.baseForm).
// ============================================================================
bool apply_npc_combat_target(void* actor, std::uint32_t target_form_id) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!g_set_combat_target_engine) {
        FW_WRN("engine: apply_npc_combat_target — fn pointer not resolved");
        return false;
    }
    if (!actor) return false;

    // Build 13 (Fix 1 hardening — macro gate). Skip until the body
    // renderer ghost is injected. The body inject path
    // (scene_inject.cpp:on_inject_message) runs only after the 30s
    // arm_worker grace + local_player_in_world() check (parentCell +
    // pos + singleton). When the body ghost exists, the engine has
    // fully completed LoadGame transition + cell-attach + autosave
    // sweep, and is in steady-state gameplay. SetCombatTarget calls
    // on raider aiprocs are safe at this point — engine subsystems
    // (faction, perception, combat) are all warmed up.
    //
    // Without this gate (Build 12 live test): first BCAST fired apply
    // at T+8s post-boot, raider aiprocs were in early-init "skeleton"
    // state, engine SetCombatTarget faulted on reads beyond 0xE8
    // AIProcess allocation → SEH caught + engine corruption → crash.
    //
    // Belt-and-suspenders: combined with the per-aiproc gate below,
    // this ensures BOTH global engine stability AND per-raider AI
    // tick has occurred at least once.
    if (!fw::native::get_injected_body_ghost()) {
        // Body not yet injected — engine still in early-load state.
        return false;
    }

    // ============================================================
    // Build 55h (2026-05-23) — GHOST-TARGET FAST PATH bypass.
    //
    // For target_form_id >= 0xFF000000 (cross-peer ghost target), skip
    // ALL the gates below (aiproc null check at line 1448, Build 13
    // tracked-aiproc gate at line 1466) and jump straight to the 3-tier
    // synth pipeline.
    //
    // RATIONALE: those gates exist to protect engine SetCombatTarget
    // from SEH'ing when called on partially-initialized AIProcess
    // (Build 12 crash class). But for ghost targets, we DON'T call
    // engine SetCombatTarget directly — we call:
    //   Tier 1: enter_combat_raider_vs_ghost (engine EnterCombat
    //           sub_140CCF810 which has its own internal preconditions)
    //   Tier 2: synthesize_combat_extension_for_ghost_target which
    //           CREATES Actor+0x328 via sub_140ED2390 if missing
    //
    // The Build 12-13 gates were CHICKEN-AND-EGG with our synth: we
    // refused to call synth because +0x328 was NULL, but synth EXISTS
    // to allocate +0x328. Build 55h breaks the cycle.
    //
    // SCENARIO: user reports raider with pistol firing at ground
    // (Build 55g live test, 19:08:33). 164 NPC_FIRE GHOST events
    // arrived, ZERO synth events fired, all puppet-fire calls hit
    // Scenario B (aim_ctrl=NULL). Root cause: vanilla AI never
    // engaged combat tier on raiders locally (user stayed in cover),
    // so Actor+0x328 stays NULL, this function returns false at
    // line 1452, 3-tier block at line 1585 never executes.
    //
    // Fix: ghost-target shortcut to Tier 1+2 directly. No gate needed.
    if (target_form_id >= 0xFF000000u) {
        void* target = lookup_by_form_id(target_form_id);
        if (!target) {
            // Ghost not registered in private lookup table yet — spawn
            // path probably not yet completed. Skip; next BCAST will retry.
            return false;
        }

        // Tier 1: enter_combat_raider_vs_ghost (vanilla EnterCombat path).
        const bool tier1_ok = enter_combat_raider_vs_ghost(actor, target);

        // Read ghost.pos for aim target.
        float aim_x = 0.f, aim_y = 0.f, aim_z = 0.f;
        __try {
            const auto* pos = reinterpret_cast<const float*>(
                reinterpret_cast<std::uint8_t*>(target) + offsets::POS_OFF);
            aim_x = pos[0];
            aim_y = pos[1];
            aim_z = pos[2];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            aim_x = aim_y = aim_z = 0.f;
        }

        // Tier 2: ALWAYS synth (Build 55c — adds AimControllers regardless
        // of Tier 1 outcome).
        const bool tier2_ok = synthesize_combat_extension_for_ghost_target(
            actor, target, aim_x, aim_y, aim_z);

        if (!tier1_ok && !tier2_ok) {
            // Tier 3 — last-resort install_fixed_selector.
            install_fixed_selector_on_raider(actor, target);
        }

        // Diagnostic counter / log.
        static std::atomic<std::uint64_t> s_fastpath_calls{0};
        const auto fpn = s_fastpath_calls.fetch_add(
            1, std::memory_order_relaxed);
        if (fpn < 20) {
            FW_LOG("engine: apply_npc_combat_target (Build 55h fast-path) "
                   "#%llu actor=%p target_fid=0x%08X target_ptr=%p "
                   "tier1_ok=%d tier2_ok=%d",
                   static_cast<unsigned long long>(fpn),
                   actor, target_form_id, target,
                   tier1_ok ? 1 : 0, tier2_ok ? 1 : 0);
        }
        return tier1_ok || tier2_ok;
    }
    // ============================================================

    // Read AIProcess pointer.
    //
    // Build 13b empirical fix: read from Actor+0x328 (NOT +0x300).
    //
    // Conflict between two sources:
    //   - Audit re/B6.6w5_cell_attach_aiprocess_audit.md Q1: alloc at +0x300
    //     (`*(QWORD*)(a1+768) = sub_140CEEAB0(...)` at funcs_0304.md:7592)
    //   - Engine disasm via npc_ai_suppress.cpp:74 + sub_140C5CCE0:
    //     `mov rcx, [rbx+328h]` reads the AIProcess from +0x328
    //
    // Empirical evidence from Build 9 logs: detour_set_combat_target sees
    // `owner_known=1` when `get_fid_for_aiproc(detour.aiproc_param)`
    // returns true. The hook's map keys are populated from `actor+0x328`
    // (suppress hook). The detour's aiproc PARAMETER is what the engine
    // passes when calling SetCombatTarget. Match → engine itself uses
    // +0x328 as the AIProcess pointer in combat context.
    //
    // Resolution: Actor has TWO AIProcess-related fields:
    //   - +0x300: "primary" AIProcess (allocated by InitDefaults, used
    //             internally for tier transitions / AIProcess lifecycle)
    //   - +0x328: "combat" AIProcess (set when active combat; this is
    //             the one passed to SetCombatTarget by the engine)
    //
    // For our combat_target apply to match the engine's SetCombatTarget
    // semantics — and to match the suppress hook's map keys — we MUST
    // read +0x328. Reading +0x300 here was the bug causing 0/5 misses.
    void* aiproc = nullptr;
    __try {
        aiproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x328);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: apply_npc_combat_target SEH reading AIProcess from "
               "actor=%p", actor);
        return false;
    }
    if (!aiproc) {
        // Actor's combat AIProcess slot at +0x328 is null. Either the
        // actor isn't in active combat (tier promotion hasn't happened),
        // or it's dormant. Either way: no combat target to set.
        return false;
    }

    // Build 13 — gate on aiproc being TRACKED by the suppress hook.
    //
    // Build 12 live test (2026-05-13 05:47) crashed at startup with 5
    // consecutive `SEH in detour (aiproc=...)` errors. All faulting
    // aiprocs had `owner_known=0` in the hook — meaning the suppress
    // hook had not yet seen them via Update_PerFrame. These raiders
    // were in early-load state with AIProcess partially-initialized;
    // calling engine SetCombatTarget on them faulted inside the engine
    // body (reads of aiproc+0x178 and other fields beyond the 0xE8
    // fresh-alloc footprint).
    //
    // Gate: only apply if `fw::hooks::get_fid_for_aiproc(aiproc, ...)`
    // returns true. That populates only when the suppress hook fires
    // for this actor — proves the engine has at least once driven an
    // AI tick on this raider locally. After that, the aiproc is "warm"
    // and SetCombatTarget is safe.
    //
    // Trade-off: raiders the engine NEVER ticks locally (e.g. ones
    // server-only-tracked in low/dormant cells) miss the substitution.
    // Acceptable — those raiders aren't on screen for the user anyway.
    std::uint32_t dummy_fid = 0;
    if (!fw::hooks::get_fid_for_aiproc(aiproc, &dummy_fid)) {
        // Raider not yet tracked. Engine state may not be ready for
        // SetCombatTarget — skip to avoid SEH inside engine.
        return false;
    }

    // Resolve target form_id. Our lookup_by_form_id override returns
    // the registered ghost duplicate for the peer-ghost fid (0xFF000001+).
    void* target = nullptr;
    if (target_form_id != 0) {
        target = lookup_by_form_id(target_form_id);
        if (!target) {
            // Target not in form table (e.g. 0x14 = real player on a
            // client with no PC loaded yet). Skip — engine retains
            // current target.
            return false;
        }
    }

    // Build 15 — BYPASS engine SetCombatTarget. Direct write to
    // aiprocess+0x6C (combat_target_handle) instead of calling
    // sub_14087AB30.
    //
    // Why: Build 14 live test (2026-05-13 06:06) showed engine
    // SetCombatTarget body SEHs at line 5982 `sub_140E93340(combat_ctrl,
    // OLD_target)` when OLD_target = real_player and NEW = duplicate.
    // Engine's cleanup-on-old-target path doesn't handle "stopped
    // attacking the player" gracefully. 5 SEHs accumulated → engine
    // corruption → crash.
    //
    // After our active applies wrote aiprocess+0x6C = duplicate's
    // handle (via the SEH'd engine call's PARTIAL completion), the
    // engine's subsequent natural SetCombatTarget(aiproc, real_player)
    // → hook substitutes to duplicate → engine sees a2 == v17 (old)
    // → noop → no SEH. So the SEH is specifically on the FIRST
    // transition real_player → duplicate.
    //
    // Direct write avoids the cleanup path entirely. Engine's per-frame
    // AI tick reads aiprocess+0x6C, resolves handle → duplicate, aim
    // path works (duplicate.pos = peer_pos via apply_ghost_pos sync).
    //
    // We use g_handle_get_or_alloc to compute the target's handle:
    //   - For duplicate (preallocated at spawn): returns existing handle
    //   - For real_player_A (engine-allocated): returns existing handle
    //   - For null target: handle stays 0 (= NULL_HANDLE, clears combat)
    static std::atomic<std::uint64_t> s_calls{0};
    static std::atomic<std::uint64_t> s_seh{0};

    std::uint32_t target_handle = 0;
    if (target && g_handle_get_or_alloc) {
        __try {
            g_handle_get_or_alloc(&target_handle, target);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            target_handle = 0;  // fall through to NULL_HANDLE
        }
    }

    bool wrote = false;
    __try {
        *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(aiproc) + 0x6C) = target_handle;
        wrote = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = s_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("engine: apply_npc_combat_target SEH writing "
                   "aiprocess+0x6C — actor=%p aiproc=%p target_fid=0x%08X",
                   actor, aiproc, target_form_id);
        }
    }

    if (wrote) {
        const auto cn = s_calls.fetch_add(1, std::memory_order_relaxed);
        if (cn < 20) {
            FW_LOG("engine: apply_npc_combat_target #%llu (Build 15 direct "
                   "write) actor=%p aiproc=%p target_fid=0x%08X target_ptr=%p "
                   "→ aiproc+0x6C = 0x%08X",
                   static_cast<unsigned long long>(cn),
                   actor, aiproc, target_form_id, target, target_handle);
        } else if ((cn % 200) == 0) {
            FW_DBG("engine: apply_npc_combat_target #%llu heartbeat seh=%llu",
                   static_cast<unsigned long long>(cn),
                   s_seh.load(std::memory_order_relaxed));
        }

        // Build 41 (2026-05-17) — INSTALL FIXED SELECTOR + AddTarget here.
        //
        // The cache-based install gate in npc_ai_suppress was reading
        // cache.combat_target_form_id == 0 even when apply_npc_combat_target
        // was firing with target_form_id == 0xFF000001 — temporal race
        // between NPC_STATE_BCAST updates (overwriting cache with later
        // 0-target broadcasts) and the install gate's tick frequency.
        // Result: ghost was written to aiproc+0x6C but never added to
        // controller.known_targets[] → alive_counter override never matched
        // → combat dispatch gate at sub_140E988A0:7135 skipped → idle.
        //
        // Fix: when target IS the ghost (fid in 0xFF000000+ runtime range),
        // install Fixed selector + call AddTarget RIGHT NOW. The dedup
        // set inside install_fixed_selector_on_raider makes repeated calls
        // cheap no-ops once installed on a given aiproc.
        //
        // We pass `target` as the ghost_proxy arg — which IS the ghost
        // pointer (resolved via lookup_by_form_id above).
        //
        // ============================================================
        // Build 45 (2026-05-17 evening) — call EnterCombat FIRST.
        //
        // D agent verified (re/puppet_fire_phase1/D_AGENT_enter_combat.md):
        //   - install_fixed_selector_on_raider returns NoAiproc when
        //     Actor+0x328 is NULL — exactly the production case for
        //     server-aggro'd raiders the user wants to redirect.
        //   - Chicken-and-egg: needs +0x328 populated to install fixed
        //     selector, but +0x328 only gets populated via natural
        //     EnterCombat which doesn't fire for cross-cell ghost.
        //   - Direct EnterCombat call breaks this. Allocates +0x328 +
        //     registers ghost in known_targets[] in ONE call.
        //
        // enter_combat_raider_vs_ghost ALSO calls install_fixed_selector
        // internally on success, so this single call replaces the old
        // 2-step (install_fixed_selector standalone). When the raider
        // already has +0x328, enter_combat_raider_vs_ghost routes
        // through install_fixed_selector instead (idempotent).
        //
        // 5 internal guards prevent crash on bad state. See dossier §5.
        // ============================================================
        // ------------------------------------------------------------
        // Build 46 (2026-05-17 night) — DISABLED.
        //
        // Build 45 live test (Client A log 20:46:06 onwards) confirmed:
        //   - enter_combat refused 5/5 by G5.4 combat-disable gate
        //     (Actor+0x208+0x1D8 & 2 SET on every Concord raider —
        //     D agent's MED-HIGH prediction proven correct)
        //   - Fallback install_fixed_selector succeeded 5/5 because
        //     those raiders ALREADY had HighProcess (natural aggro on
        //     player_A in same cell)
        //   - install_fixed_selector added ghost to known_targets[]
        //     with priority=10 (highest, dominates vanilla 1-3)
        //   - Engine promoter picked ghost as target → wrote
        //     aiproc+0x6C = ghost_handle naturally
        //   - But ghost has no CombatAimController in HighProcess+0x98
        //     BSTArray for raider's slot (Worker B verified gap)
        //   - sub_14087D190 returns 0 → aim solver fails → no fire
        //   - Engine "no progress" → combat state decays → raider
        //     loses aggro → goes friendly ("TALK" prompt visible in
        //     user's 20:48 screenshot)
        //
        // Net effect of Build 45: REGRESSION — natural aggro on
        // player_A broken, ghost aggro also broken.
        //
        // Build 46 reverts: do NOT auto-add ghost to known_targets[]
        // via apply_npc_combat_target. Natural aggro on player_A
        // restored. Cross-peer ghost aggro remains unimplemented;
        // requires manual CombatAimController allocation (Phase 2 RE).
        //
        // Code kept compiled and reachable for future re-enable after
        // the AimController allocation gap is solved.
        // ------------------------------------------------------------
        if (target_form_id >= 0xFF000000u && target) {
            __try {
                // ============================================================
                // Build 55c (2026-05-23) — REVISED 3-step pipeline.
                //
                // Discovered in Build 55b: my previous 3-tier "Tier 1 OR Tier 2"
                // was a regression. With the gate fix 0x208→0x418, Tier 1
                // (enter_combat_raider_vs_ghost) now succeeds, but that
                // SKIPPED Tier 2 (synth), which was the path that manually
                // allocates 2 CombatAimController instances in HighProcess+0x98
                // BSTArray. Without those, puppet-fire's resolve_aim_controller
                // returns NULL → Scenario B → no aim write → ghost not shot.
                //
                // Fix: Tier 1 AND Tier 2 ALWAYS, not OR.
                //
                // Step 1 (Tier 1): enter_combat_raider_vs_ghost. Allocates
                //   HighProcess via vanilla EnterCombat (sub_140CCF810). With
                //   Build 55b gate fix this should succeed for typical
                //   Concord raiders. If raider already has HighProcess (from
                //   prior natural perception), routes to install_fixed_selector
                //   via G5.10 idempotency.
                //
                // Step 2 (Tier 2): synthesize_combat_extension_for_ghost_target.
                //   STEP A skips if HighProcess already exists (set by Tier 1
                //   or vanilla AI). STEP B resolves weapon slot. STEP C
                //   ALWAYS allocates 2 CombatAimController instances
                //   (+0x30=slot, +0x30=slot|0x100) and writes ghost.pos as
                //   target. This is the load-bearing step for puppet-fire's
                //   resolve_aim_controller to find a valid target.
                //
                // Step 3 (Tier 3 — last-resort): if both above refuse for any
                //   reason, install_fixed_selector_on_raider — only useful
                //   when raider transiently has +0x328 from somewhere else.
                //   Harmless if not.
                //
                // No early-exit between Tier 1 and Tier 2. The "OR" was the
                // bug. Synth runs regardless of Tier 1 outcome.
                // ============================================================
                const bool tier1_ok =
                    enter_combat_raider_vs_ghost(actor, target);

                // Read target_pos from ghost (cell-sync keeps it updated).
                float aim_x = 0.f, aim_y = 0.f, aim_z = 0.f;
                __try {
                    const auto* pos = reinterpret_cast<const float*>(
                        reinterpret_cast<std::uint8_t*>(target) +
                        offsets::POS_OFF);
                    aim_x = pos[0];
                    aim_y = pos[1];
                    aim_z = pos[2];
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    aim_x = aim_y = aim_z = 0.f;
                }

                // Always run synth to ensure AimControllers exist for puppet-
                // fire to resolve. Synth's STEP A is idempotent (skips alloc
                // if HighProcess already exists from Tier 1 or vanilla AI).
                const bool tier2_ok =
                    synthesize_combat_extension_for_ghost_target(
                        actor, target, aim_x, aim_y, aim_z);

                if (!tier1_ok && !tier2_ok) {
                    // Tier 3 — last-resort. Both upstream failed.
                    install_fixed_selector_on_raider(actor, target);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_WRN("engine: apply_npc_combat_target SEH in Build 55c "
                       "pipeline actor=%p target=%p target_fid=0x%08X",
                       actor, target, target_form_id);
            }
        }
    }
    return wrote;
}

// B6.6w5 Build 9 — direct pos write on the ghost duplicate.
//
// Called from the POS_BROADCAST receive path (via main-thread dispatch)
// when a peer's pos updates. Writes Actor+0xD0 (POS_OFF) on the
// duplicate directly. No engine API calls — pure memory write, since:
//   - the duplicate is not in any engine subsystem that needs pos-change
//     notification (no ProcessLists, no cell list, no scene graph)
//   - the only consumer of duplicate.pos is the engine's raider AI when
//     reading combat_target.pos for aim — a simple field read
//
// SEH-caged. Returns true on write, false on missing duplicate / SEH.
bool apply_ghost_pos(float x, float y, float z) noexcept {
    void* dup = g_ghost_duplicate_ptr.load(std::memory_order_acquire);
    if (!dup) return false;

    // Always write the raw pos field first (proxy+0xD0). This is the
    // baseline guarantee — even if the engine native bails or faults,
    // any code path that reads pos directly (rare, but possible) gets
    // the up-to-date value.
    bool raw_ok = false;
    auto* p = reinterpret_cast<std::uint8_t*>(dup) + offsets::POS_OFF;
    __try {
        auto* coords = reinterpret_cast<float*>(p);
        coords[0] = x;
        coords[1] = y;
        coords[2] = z;
        raw_ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raw_ok = false;
    }

    // Build 36 (2026-05-16) — also drive the engine-native SetPosition.
    //
    // Pre-36 we only wrote `proxy+0xD0` (raw field), assuming the engine
    // would read that for combat-aim. Live test of Build 35.2 showed
    // raiders go IDLE after cross-peer aggro install: the raider's
    // combat brain on client A reads ghost.NIF.world.translate for
    // LOS / range queries, NOT the +0xD0 field. With NIF transform
    // still at the ghost's spawn pose (Sanctuary), raiders perceive
    // the ghost as ~26000ft away → out of engagement range → AI bails
    // combat → idle.
    //
    // The native `g_set_position_engine` is the engine's authoritative
    // SetPosition flow: writes +0xD0, NIF.local.translate, propagates to
    // NIF.world via UpdateWorldData, syncs Havok body, updates cell
    // attach. Calling this every PEER_POS broadcast keeps the ghost
    // visible to every spatial query the engine runs on it.
    //
    // Hook bypass: our `ghost_ai_pos` + `ghost_ai_setpos` hooks bail
    // SetPosition for tracked NPCs (movement_override / bail_tracked).
    // The ghost (fid 0xFF000001) is not in those sets, so passthrough
    // happens naturally — BUT we still set `tls_applying_remote` for
    // safety, since both hooks honor that flag as an unconditional
    // passthrough escape hatch (used by `apply_npc_pos`). This is
    // belt-and-braces.
    if (g_set_position_engine && raw_ok) {
        float xyz[3] = { x, y, z };
        const bool prev_remote_flag = fw::hooks::tls_applying_remote;
        fw::hooks::tls_applying_remote = true;
        __try {
            g_set_position_engine(dup, xyz);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            static std::atomic<std::uint64_t> seh_count{0};
            const auto n = seh_count.fetch_add(1, std::memory_order_relaxed);
            if (n < 5) {
                FW_ERR("[ghost-proxy] SEH in apply_ghost_pos native "
                       "SetPosition #%llu proxy=%p xyz=(%.1f,%.1f,%.1f)",
                       static_cast<unsigned long long>(n), dup, x, y, z);
            }
        }
        fw::hooks::tls_applying_remote = prev_remote_flag;
    }

    // Build 37 (2026-05-16) — DISABLED cell-sync direct write.
    //
    // Initial Build 37 attempted to satisfy the combat-engage cell-gate
    // at `sub_140CF6100:9926` (which checks `PC.parent_cell ==
    // target.parent_cell`) by directly writing `ghost+0xB8 = PC.parent_cell`
    // every PEER_POS tick. Live test crashed BOTH clients consistently:
    //
    //   - Tests 1+2: crash at RVA 0xCDFD9D (sub_140CDFD30 + 0x6D)
    //     IMMEDIATELY after cell-sync, BEFORE the basebrm-swap walker
    //     visit. Sequence: spawn OK → cell-sync #0 → crash (4ms gap).
    //     Disasm at the AV: `call [rax+0x338]` where rax was loaded
    //     from `[rbx]` (entry vtable). vt[103] held sentinel
    //     0xFFFFFFFFFFFFFFFF. Upstream walks
    //     `*(baseForm + 0xF0).entries[i].vt[103]()` — i.e. iterates
    //     a PlayerNPC sublist whose entries have unimplemented vt[103].
    //     With PlayerNPC still as baseForm (swap hadn't fired yet),
    //     the walker faulted on the very first entry that didn't
    //     implement that slot.
    //
    //   - Test 3 (swap completed before cell-sync): different downstream
    //     crash at RVA 0x16632B9 (sub_141663260) WRITE addr=0x8,
    //     61s post cell-sync. Confirms the cell-sync side-effect cascades
    //     into other engine paths that walk ghost as an in-cell actor.
    //
    // Root cause of the regression: writing `ghost+0xB8 = live cell`
    // activates engine walkers that process the ghost as "an actor in
    // PC's cell". Those walkers iterate sublists on the ghost's
    // baseForm (factions, packages, sa-list) and call virtual methods
    // we haven't shimmed. PlayerNPC special-cases hide those crashes
    // for the real player; our proxy doesn't get the special-case path.
    //
    // Correct fix path (post-rollback): detour `sub_140CF6100` itself
    // and force the cell comparison to succeed when `a2 == ghost`,
    // WITHOUT touching ghost+0xB8. Likely impl: hook the function,
    // detect ghost target, transient-write PC.cell to ghost+0xB8 ONLY
    // for the duration of the hooked call, restore on return. This keeps
    // the engine's other walkers seeing the original (stale) ghost.cell
    // and never activating the dangerous in-cell processing paths.
    //
    // For now: NO-OP. Raiders stay idle on cross-peer aggro install
    // (combat-engage gate fails) but the game doesn't crash. We're
    // back to Build 36 behavior + the harmless native SetPosition.
    //
    // ============================================================
    // Build 49 (2026-05-17 night) — RE-ENABLE cell-sync.
    //
    // Build 37's crash class (RVA 0xCDFD9D, vt[103] sentinel on
    // PlayerNPC sublist) was caused by walkers iterating
    // *(ghost.baseForm + 0xF0) when ghost.baseForm == PlayerNPC.
    // The 4ms gap between cell-sync write and the walker hit was
    // before any baseForm swap could happen.
    //
    // Build 48 (just deployed) does the baseForm swap SYNCHRONOUSLY
    // inside spawn_ghost_proxy, BEFORE register_ghost_duplicate
    // returns. By the time apply_ghost_pos is ever called (which
    // requires the duplicate to be registered for the cache lookup
    // to find it), the swap is GUARANTEED complete:
    //   spawn_ghost_proxy() {
    //     ... PlaceAtMe ...
    //     register_ghost_duplicate(fid, proxy)
    //     try_swap_ghost_baseform(proxy)  ← Build 48 sync
    //     return proxy
    //   }
    //
    // So ghost.baseForm is vanilla TESNPC (formID 0x00026F37 or
    // similar) for every cell-sync write. PlayerNPC sublist walker
    // can't trigger because the sublist no longer exists on this
    // baseForm. The Build 37 crash class is structurally eliminated.
    //
    // Goal of cell-sync: make ghost.parent_cell point to the LOCAL
    // PC's parent_cell so the engine's perception walkers (which
    // scope by cell) find ghost as a hostile target candidate. With
    // FORCE-HOSTILE hook intercepting HostilityCore(raider, ghost)
    // and returning rank=1, EnterCombat fires naturally → raider
    // engagement on ghost is sustained instead of decaying after
    // 1 second.
    //
    // Risk surface remaining:
    //   - Build 37 test 3 had a different crash at RVA 0x16632B9
    //     (sub_141663260) 61s post cell-sync. We can't pre-rule this
    //     out. If it fires, we'll see it in the crash-veh log and
    //     can decide whether to disable specific walker entries or
    //     accept the trade.
    //   - Engine may try to insert ghost into PC's cell's actor list.
    //     With ghost.parent_cell already pointing there, the insert
    //     might fail/double or trigger cell-attach machinery. Worth
    //     watching.
    //
    // Strategy: write conservatively. If PC.parent_cell is null
    // (PC in load screen, menu, etc.), skip the write. If write
    // SEHs, log + bail without retry.
    if (g_player_singleton_slot) {
        void* pc_cell = get_pc_parent_cell();
        if (pc_cell) {
            __try {
                auto* slot = reinterpret_cast<void**>(
                    reinterpret_cast<std::uint8_t*>(dup) +
                    offsets::PARENT_CELL_OFF);
                void* prev_ghost_cell = *slot;
                if (prev_ghost_cell != pc_cell) {
                    *slot = pc_cell;
                    static std::atomic<std::uint64_t> n_sync{0};
                    const auto nn = n_sync.fetch_add(
                        1, std::memory_order_relaxed);
                    if (nn < 8 || (nn % 500) == 0) {
                        FW_LOG("[ghost-cell-sync] #%llu ghost=%p +0xB8 was=%p "
                               "→ wrote=%p (= local PC.parent_cell). Engine "
                               "perception walkers in this cell can now find "
                               "ghost as candidate target.",
                               static_cast<unsigned long long>(nn),
                               dup, prev_ghost_cell, pc_cell);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                static std::atomic<std::uint64_t> n_seh{0};
                const auto nn = n_seh.fetch_add(
                    1, std::memory_order_relaxed);
                if (nn < 5) {
                    FW_ERR("[ghost-cell-sync] SEH #%llu writing ghost+0xB8 "
                           "(dup=%p pc_cell=%p) — bailing without retry",
                           static_cast<unsigned long long>(nn),
                           dup, pc_cell);
                }
            }
        }
    }
    // ============================================================

    return raw_ok;
}

std::uint32_t read_flags(void* ref) {
    if (!ref) return 0;
    const auto* base = reinterpret_cast<const std::uint8_t*>(ref);
    return safe_read<std::uint32_t>(base + offsets::FLAGS_OFF, 0u);
}

void disable_ref(void* ref, bool fade_out) {
    if (!g_ready.load(std::memory_order_acquire) || !g_disable || !ref) return;
    __try {
        g_disable(ref, fade_out ? 1 : 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in disable_ref(%p)", ref);
    }
}

void enable_ref(void* ref) {
    if (!g_ready.load(std::memory_order_acquire)) return;
    if (!g_enable_cleanup || !g_enable_apply || !ref) return;
    __try {
        g_enable_cleanup(ref);
        g_enable_apply(ref);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in enable_ref(%p)", ref);
    }
}

bool set_disabled_validated(
    std::uint32_t form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    bool disabled)
{
    // c.40a — latent vanish guard. The "disappear+reappear" can also be caused
    // by this DISABLE path firing on a LIVE raider: a stale world-snapshot
    // "alive:False" entry, or a relayed KILL, whose base+cell happen to match a
    // dynamic actor → SetDisabled = 3D detach = vanish. Refuse to DISABLE a
    // runtime/dynamic form (0xFF______) — those are the in-encounter raiders we
    // sync; hiding one makes it disappear. Enabling is always allowed, and
    // persisted base-game corpses use 0x00______ forms (still disable-able).
    if (disabled && (form_id & 0xFF000000u) == 0xFF000000u) {
        FW_DBG("engine: refuse-disable dynamic form=0x%X (c.40a vanish guard)",
               form_id);
        return false;
    }

    void* ref = lookup_by_form_id(form_id);
    if (!ref) {
        // Common at bootstrap: the form table isn't populated until after
        // the save loads, so WORLD_STATE apply often misses the first pass.
        // Kept at DBG to avoid log spam; retry-after-save-load is B-level.
        FW_DBG("engine: set_disabled_validated lookup_null form=0x%X", form_id);
        return false;
    }

    // Identity check — refuse to apply if the ref resolves to a different
    // logical actor. expected_* = 0 means skip check (degrade path for
    // legacy entries without identity, kept for compat).
    const auto id = fw::read_ref_identity(ref);
    const bool base_mismatch =
        (expected_base_id != 0) && (id.base_id != expected_base_id);
    const bool cell_mismatch =
        (expected_cell_id != 0) && (id.cell_id != expected_cell_id);
    if (base_mismatch || cell_mismatch) {
        FW_WRN("engine: identity mismatch form=0x%X "
               "got=(base=0x%X, cell=0x%X) expected=(base=0x%X, cell=0x%X)",
               form_id,
               id.base_id, id.cell_id,
               expected_base_id, expected_cell_id);
        return false;
    }

    const std::uint32_t flags = read_flags(ref);
    const bool currently_disabled = (flags & offsets::FLAG_DISABLED) != 0;
    if (disabled && !currently_disabled) {
        disable_ref(ref, /*fade_out=*/false);
        FW_LOG("engine: disable form=0x%X (base=0x%X cell=0x%X)",
               form_id, id.base_id, id.cell_id);
        return true;
    }
    if (!disabled && currently_disabled) {
        enable_ref(ref);
        FW_LOG("engine: enable form=0x%X (base=0x%X cell=0x%X)",
               form_id, id.base_id, id.cell_id);
        return true;
    }
    // No transition needed — already in the desired state.
    return false;
}

void write_ghost_pos_rot(
    std::uint32_t form_id,
    float x, float y, float z,
    float rx, float ry, float rz)
{
    if (!g_ready.load(std::memory_order_acquire)) return;
    void* ref = lookup_by_form_id(form_id);
    if (!ref) return;
    auto* base = reinterpret_cast<std::uint8_t*>(ref);
    safe_write<float>(base + offsets::POS_OFF,     x);
    safe_write<float>(base + offsets::POS_OFF + 4, y);
    safe_write<float>(base + offsets::POS_OFF + 8, z);
    safe_write<float>(base + offsets::ROT_OFF,     rx);
    safe_write<float>(base + offsets::ROT_OFF + 4, ry);
    safe_write<float>(base + offsets::ROT_OFF + 8, rz);
}

bool load_game_by_name(const char* save_name) {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_WRN("engine: load_game_by_name called before engine init");
        return false;
    }
    if (!save_name || !*save_name) {
        FW_WRN("engine: load_game_by_name called with empty save_name");
        return false;
    }
    if (!g_load_game || !g_load_precond || !g_load_prep ||
        !g_save_load_mgr_slot || !g_save_dev_slot || !g_load_in_progress)
    {
        FW_ERR("engine: load_game_by_name missing resolved pointers — "
               "engine::init didn't populate them");
        return false;
    }

    bool ok = false;
    __try {
        // 1) Precondition: save device available?
        void* save_dev = *g_save_dev_slot;
        if (!save_dev) {
            FW_ERR("engine: LoadGame aborted — save_dev singleton is null "
                   "(engine not fully initialized?)");
            return false;
        }
        const std::uint8_t precond = g_load_precond(save_dev, 0, 0);
        if (!precond) {
            FW_ERR("engine: LoadGame aborted — precondition returned 0 "
                   "(save device / profile not ready)");
            return false;
        }

        // 2) Resolve the TESSaveLoadManager singleton.
        void* mgr = *g_save_load_mgr_slot;
        if (!mgr) {
            FW_ERR("engine: LoadGame aborted — save_load_manager singleton "
                   "is null (engine not fully initialized?)");
            return false;
        }

        // 3) Replicate the exec_fn: prep call + flag + LoadGame.
        FW_LOG("engine: load_game_by_name('%s') → invoking prep + LoadGame",
               save_name);
        g_load_prep();
        *g_load_in_progress = 1;

        // flags=0: all four parsed-flag bits clear (default console behavior
        // when the user types "LoadGame <name>" with no extra switches).
        const std::uint8_t rc = g_load_game(
            mgr, save_name, /*unk_neg1=*/-1, /*flags=*/0,
            /*one=*/1, /*zero=*/0);

        if (rc == 0) {
            FW_ERR("engine: LoadGame returned 0 — savefile '%s' not found "
                   "or unreadable. Check the save name (no path, no .fos "
                   "extension).", save_name);
        } else {
            FW_LOG("engine: LoadGame accepted — engine transitioning to load "
                   "screen for '%s'", save_name);
            ok = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in load_game_by_name('%s')", save_name);
        ok = false;
    }
    return ok;
}

bool apply_global_var(std::uint32_t global_form_id, float value) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (global_form_id == 0) return false;

    void* form = lookup_by_form_id(global_form_id);
    if (!form) {
        FW_DBG("engine: apply_global_var lookup_null form=0x%X", global_form_id);
        return false;
    }

    auto* bytes = reinterpret_cast<std::uint8_t*>(form);
    bool ok = false;
    __try {
        const std::uint32_t flags = *reinterpret_cast<const std::uint32_t*>(
            bytes + offsets::FLAGS_OFF);
        if (flags & offsets::TESGLOBAL_FLAG_CONST) {
            FW_WRN("engine: apply_global_var refusing const global 0x%X",
                   global_form_id);
            return false;
        }
        *reinterpret_cast<float*>(bytes + offsets::TESGLOBAL_VALUE_OFF) = value;
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in apply_global_var(0x%X, %g)",
               global_form_id, value);
        ok = false;
    }
    if (ok) {
        FW_LOG("engine: apply_global_var 0x%X = %g", global_form_id, value);
    }
    return ok;
}

void* resolve_inventory_entry_form(void* entry_ptr) {
    if (!entry_ptr) return nullptr;
    if (!g_ready.load(std::memory_order_acquire)) return nullptr;
    if (!g_inv_entry_to_form || !g_form_cache_slot) {
        FW_WRN("engine: resolve_inventory_entry_form: resolver not ready");
        return nullptr;
    }
    void* result = nullptr;
    __try {
        void* form_cache = *g_form_cache_slot;
        if (!form_cache) {
            FW_DBG("engine: resolve_inventory_entry_form: form_cache global is null "
                   "(engine not fully initialized?)");
            return nullptr;
        }
        result = g_inv_entry_to_form(form_cache, entry_ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in resolve_inventory_entry_form(%p)", entry_ptr);
        result = nullptr;
    }
    return result;
}

void* resolve_refhandle(void* handle_ptr) {
    if (!handle_ptr) return nullptr;
    if (!g_ready.load(std::memory_order_acquire) || !g_refhandle_resolve) {
        FW_WRN("engine: resolve_refhandle: resolver not ready");
        return nullptr;
    }
    void* result = nullptr;
    __try {
        // sub_14021E230(out, handle_ptr) writes the resolved REFR* into *out
        // (or leaves it null if the handle is stale).
        g_refhandle_resolve(&result, handle_ptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in resolve_refhandle(%p)", handle_ptr);
        result = nullptr;
    }
    return result;
}

bool apply_container_op_to_engine(
    std::uint32_t kind,
    std::uint32_t container_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    std::uint32_t item_base_id,
    std::int32_t  count)
{
    // Sanity + readiness.
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (container_form_id == 0 || item_base_id == 0 || count <= 0) {
        FW_DBG("engine: apply_container_op: early-out zero fields "
               "(cfid=0x%X iid=0x%X cnt=%d)",
               container_form_id, item_base_id, count);
        return false;
    }
    if (!g_engine_add_item || !g_engine_remove_item) {
        FW_WRN("engine: apply_container_op: add/remove fn pointers not resolved");
        return false;
    }

    // Resolve the REFR for the container on OUR side.
    void* container_ref = lookup_by_form_id(container_form_id);
    if (!container_ref) {
        // Container not loaded in our engine (cell not streamed in, different
        // save state, etc.). Not a bug — just a no-op apply.
        FW_DBG("engine: apply_container_op: container form 0x%X not found locally",
               container_form_id);
        return false;
    }

    // Identity check — refuse if (base, cell) don't match what the sender saw.
    // Guards against plugin-order drift and the 0xFF______ aliasing bug.
    const auto id = read_ref_identity(container_ref);
    const bool base_mismatch =
        (expected_base_id != 0) && (id.base_id != expected_base_id);
    const bool cell_mismatch =
        (expected_cell_id != 0) && (id.cell_id != expected_cell_id);
    if (base_mismatch || cell_mismatch) {
        FW_WRN("engine: apply_container_op: identity mismatch cfid=0x%X "
               "got=(base=0x%X cell=0x%X) expected=(base=0x%X cell=0x%X)",
               container_form_id,
               id.base_id, id.cell_id,
               expected_base_id, expected_cell_id);
        return false;
    }

    // Resolve the item form (TESForm*). The engine's AddItem/RemoveItem
    // accept a TESForm* and internally call GetAsBoundObject (vtable[51])
    // to reach the actual TESBoundObject* for items like MISC/WEAP/ARMO.
    // So passing the bare TESForm* is sufficient.
    void* item_form = lookup_by_form_id(item_base_id);
    if (!item_form) {
        FW_WRN("engine: apply_container_op: item form 0x%X not found",
               item_base_id);
        return false;
    }

    // B1.j.1: make sure the container's runtime inventory list is
    // materialized BEFORE we add/remove. The engine's AddItem lazily
    // materializes, so an Add would work either way — but a RemoveItem
    // on a never-touched container with a null REFR+0xF8 might no-op
    // or crash. Best to materialize first.
    (void)force_materialize_inventory(container_ref);

    const char* op_tag = "?";
    bool ok = false;
    __try {
        if (kind == 2 /* PUT */) {
            op_tag = "PUT";
            g_engine_add_item(
                container_ref,
                item_form,
                static_cast<std::uint32_t>(count),
                /*flag=*/0,
                /*vm_id=*/0,
                /*vm_state=*/nullptr);
            ok = true;
        } else if (kind == 1 /* TAKE */) {
            op_tag = "TAKE";
            g_engine_remove_item(
                container_ref,
                item_form,
                static_cast<std::uint32_t>(count),
                /*flag=*/0,
                /*dest_actor_refr=*/nullptr,  // nullptr = drop on ground
                                               // (nobody ever sees it — receiver's
                                               //  local world; peer A already took
                                               //  it on their side)
                /*flag2=*/0,
                /*vm_id=*/0,
                /*vm_state=*/nullptr);
            ok = true;
        } else {
            FW_WRN("engine: apply_container_op: unknown kind=%u", kind);
            return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in apply_container_op_to_engine "
               "kind=%u cfid=0x%X iid=0x%X cnt=%d",
               kind, container_form_id, item_base_id, count);
        return false;
    }

    if (ok) {
        FW_LOG("engine: apply_container_op_to_engine %s cfid=0x%X "
               "(base=0x%X cell=0x%X) item=0x%X count=%d",
               op_tag, container_form_id,
               id.base_id, id.cell_id, item_base_id, count);
    }
    return ok;
}

bool apply_door_op_to_engine(
    std::uint32_t door_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id)
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (door_form_id == 0) {
        FW_DBG("engine: apply_door_op: zero form_id");
        return false;
    }
    if (!g_engine_activate) {
        FW_WRN("engine: apply_door_op: activate worker resolver not ready");
        return false;
    }

    void* door_ref = lookup_by_form_id(door_form_id);
    if (!door_ref) {
        // Door not loaded in our world (cell not streamed in, peer is in
        // a different area). Not a bug — silent no-op apply. The next
        // time the cell streams in, save-load propagator (vt[0x99] =
        // sub_140510CE0) will set the persisted state, which catches up
        // any drift.
        FW_DBG("engine: apply_door_op: door form 0x%X not found locally",
               door_form_id);
        return false;
    }

    // Identity check: refuse if (base, cell) don't match what the sender
    // saw. Same defensive pattern as apply_container_op_to_engine — guards
    // against plugin-load-order drift and the 0xFF______ aliasing bug.
    const auto id = read_ref_identity(door_ref);
    const bool base_mismatch =
        (expected_base_id != 0) && (id.base_id != expected_base_id);
    const bool cell_mismatch =
        (expected_cell_id != 0) && (id.cell_id != expected_cell_id);
    if (base_mismatch || cell_mismatch) {
        FW_WRN("engine: apply_door_op: identity mismatch dfid=0x%X "
               "got=(base=0x%X cell=0x%X) expected=(base=0x%X cell=0x%X)",
               door_form_id,
               id.base_id, id.cell_id,
               expected_base_id, expected_cell_id);
        return false;
    }

    // Invoke the engine's Activate worker. Args 2-7 from the phase-1.b
    // observation:
    //   args=(activator_refr, 0, 0x1, garbage, garbage, garbage)
    // The 4 in-register args (RCX/RDX/R8/R9) are: refr, activator, ?, force
    // For receive-side we pass:
    //   refr      = local door ref
    //   activator = nullptr (no in-game activator initiated the action)
    //   a3        = nullptr
    //   a4        = (void*)1 — observed "force" / "process_inactive" flag
    //   a5..a7    = nullptr (out of arg-count range; harmless)
    bool ok = false;
    __try {
        g_engine_activate(door_ref,
                          /*activator=*/nullptr,
                          /*a3=*/nullptr,
                          /*a4=*/reinterpret_cast<void*>(static_cast<std::uintptr_t>(1)),
                          /*a5=*/nullptr,
                          /*a6=*/nullptr,
                          /*a7=*/nullptr);
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in apply_door_op_to_engine "
               "dfid=0x%X (base=0x%X cell=0x%X)",
               door_form_id, expected_base_id, expected_cell_id);
        return false;
    }

    if (ok) {
        FW_LOG("engine: apply_door_op_to_engine dfid=0x%X "
               "(base=0x%X cell=0x%X)",
               door_form_id, id.base_id, id.cell_id);
    }
    return ok;
}

bool apply_lock_op_to_engine(
    std::uint32_t lock_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    bool          locked)
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (lock_form_id == 0) {
        FW_DBG("engine: apply_lock_op: zero form_id");
        return false;
    }
    if (!g_lock_apply_papyrus) {
        FW_WRN("engine: apply_lock_op: Papyrus binding not resolved");
        return false;
    }

    void* lock_ref = lookup_by_form_id(lock_form_id);
    if (!lock_ref) {
        // Cell not streamed in — silent no-op. Server keeps the
        // authoritative state; when the cell loads, the bootstrap
        // snapshot replays the latest state to this client.
        FW_DBG("engine: apply_lock_op: REFR 0x%X not loaded locally",
               lock_form_id);
        return false;
    }

    // Identity check — same defensive pattern as door / container apply.
    const auto id = read_ref_identity(lock_ref);
    const bool base_mismatch =
        (expected_base_id != 0) && (id.base_id != expected_base_id);
    const bool cell_mismatch =
        (expected_cell_id != 0) && (id.cell_id != expected_cell_id);
    if (base_mismatch || cell_mismatch) {
        FW_WRN("engine: apply_lock_op: identity mismatch fid=0x%X "
               "got=(base=0x%X cell=0x%X) expected=(base=0x%X cell=0x%X)",
               lock_form_id,
               id.base_id, id.cell_id,
               expected_base_id, expected_cell_id);
        return false;
    }

    bool ok = false;
    __try {
        // sub_141158640(_unused, _unused, REFR*, u8 locked, char ai_notify).
        // ai_notify=0 → no AI events / key consumption / minigame.
        g_lock_apply_papyrus(nullptr, nullptr, lock_ref,
                             locked ? std::uint8_t{1} : std::uint8_t{0},
                             /*ai_notify=*/0);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in apply_lock_op_to_engine "
               "fid=0x%X (base=0x%X cell=0x%X locked=%d)",
               lock_form_id, expected_base_id, expected_cell_id,
               locked ? 1 : 0);
        return false;
    }

    if (ok) {
        FW_LOG("engine: apply_lock_op_to_engine fid=0x%X "
               "(base=0x%X cell=0x%X locked=%d)",
               lock_form_id, id.base_id, id.cell_id, locked ? 1 : 0);
    }
    return ok;
}

bool force_materialize_inventory(void* container_ref) {
    if (!container_ref) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!g_materialize_inv || !g_get_component) {
        FW_WRN("engine: force_materialize_inventory: resolvers not ready");
        return false;
    }

    bool already_materialized = false;
    void* list_after = nullptr;

    __try {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(container_ref);

        // (1) Is the runtime list already populated?
        void* list_before = *reinterpret_cast<void* const*>(
            bytes + offsets::REFR_INV_LIST_OFF);
        if (list_before) {
            FW_DBG("engine: materialize skipped — list already present "
                   "ref=%p list=%p", container_ref, list_before);
            return true;
        }

        // (2) Get baseForm at REFR+0xE0. A null baseForm means the REFR
        //     is likely runtime-spawned without a template — nothing we
        //     can materialize from.
        void* base_form = *reinterpret_cast<void* const*>(
            bytes + offsets::BASE_FORM_OFF);
        if (!base_form) {
            FW_DBG("engine: materialize: no baseForm on ref=%p", container_ref);
            return false;
        }

        // (3) Is the baseForm a container? Ask for its CONT component.
        void* bgscont = g_get_component(base_form, offsets::TESFORM_SIG_CONT);
        if (!bgscont) {
            FW_DBG("engine: materialize: baseForm has no CONT component "
                   "(not a container) ref=%p base=%p", container_ref, base_form);
            return false;
        }

        // (4) Invoke the engine's own materializer. It allocates a
        //     0x80-byte BGSInventoryList, populates it from the CONT
        //     entries, and writes the ptr into REFR+0xF8.
        //     Return value is the post-init hook's output — we don't
        //     rely on it; we verify via memory read.
        (void)g_materialize_inv(container_ref, bgscont);

        list_after = *reinterpret_cast<void* const*>(
            bytes + offsets::REFR_INV_LIST_OFF);
        already_materialized = (list_after != nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: SEH in force_materialize_inventory(%p)", container_ref);
        return false;
    }

    if (!already_materialized) {
        FW_WRN("engine: materialize returned but REFR+0xF8 still null "
               "ref=%p", container_ref);
        return false;
    }
    FW_LOG("engine: materialized runtime inventory list ref=%p list=%p",
           container_ref, list_after);
    return true;
}

std::size_t scan_container_inventory(
    void* container_ref,
    std::uint32_t* out_item_ids,
    std::int32_t*  out_counts,
    std::size_t    max_items)
{
    if (!container_ref || !out_item_ids || !out_counts || max_items == 0) return 0;
    if (!g_ready.load(std::memory_order_acquire) || !g_inv_item_count) return 0;

    // Cache fields outside __try so we don't create C++ objects inside it.
    std::size_t n = 0;
    const auto* cref = reinterpret_cast<const std::uint8_t*>(container_ref);

    __try {
        // REFR + 0xF8 → BGSInventoryList*. Null = never materialized (fresh
        // cell, pristine static loot table — we skip the seed, server will
        // trust client on first TAKE as in B0).
        void* list = *reinterpret_cast<void* const*>(cref + offsets::REFR_INV_LIST_OFF);
        if (!list) return 0;

        const auto* lbase = reinterpret_cast<const std::uint8_t*>(list);
        void* entries_start = *reinterpret_cast<void* const*>(
            lbase + offsets::INVLIST_ENTRIES_OFF);
        const std::uint32_t entry_count = *reinterpret_cast<const std::uint32_t*>(
            lbase + offsets::INVLIST_COUNT_OFF);

        if (!entries_start || entry_count == 0) return 0;

        auto* entry = reinterpret_cast<std::uint8_t*>(entries_start);
        std::uint32_t skipped_null_obj  = 0;
        std::uint32_t skipped_null_form = 0;
        std::uint32_t skipped_zero_cnt  = 0;
        for (std::uint32_t i = 0; i < entry_count && n < max_items; ++i,
             entry += offsets::INVENTORY_ITEM_STRIDE)
        {
            // entry + 0x00 → TESBoundObject* (item template)
            void* obj = *reinterpret_cast<void* const*>(
                entry + offsets::INVENTORY_ITEM_OBJ_OFF);
            if (!obj) { ++skipped_null_obj; continue; }

            // NOTE: previous revision here filtered entries with
            // formType == 0x38 ("LVLI") — that was WRONG. Re-read of
            // sub_140507660 shows the game counts EVERY entry in the
            // runtime list (REFR+0xF8) regardless of formType; the
            // formType check only applies in the fallback branch where
            // the runtime list is null and we walk the baseForm CONT.
            // Dropping that filter here was the root cause of "scan
            // only saw 2/4 items → server state incomplete → subsequent
            // TAKEs REJ_INSUFFICIENT" observed 2026-04-20 live.
            const std::uint8_t ftype = *reinterpret_cast<const std::uint8_t*>(
                reinterpret_cast<const std::uint8_t*>(obj) + offsets::FORMTYPE_OFF);
            (void)ftype;  // kept for future diagnostic logging if needed

            const std::uint32_t item_id = *reinterpret_cast<const std::uint32_t*>(
                reinterpret_cast<const std::uint8_t*>(obj) + offsets::FORMID_OFF);
            if (item_id == 0) { ++skipped_null_form; continue; }

            // Engine accessor: returns int32 stack count for this entry.
            int cnt = 0;
            __try { cnt = g_inv_item_count(entry); }
            __except (EXCEPTION_EXECUTE_HANDLER) { cnt = 0; }
            if (cnt <= 0) { ++skipped_zero_cnt; continue; }

            out_item_ids[n] = item_id;
            out_counts[n]   = cnt;
            ++n;
        }

        // Summary log at DEBUG so we can spot future scan-miss bugs at a glance.
        // Mismatch between entry_count and (n + skipped_*) would indicate we're
        // iterating off a different count field than the engine uses.
        if (skipped_null_obj || skipped_null_form || skipped_zero_cnt) {
            FW_DBG("engine: scan_container_inventory ref=%p: entry_count=%u "
                   "produced=%zu skipped_null_obj=%u skipped_null_form=%u "
                   "skipped_zero_cnt=%u",
                   container_ref, entry_count, n,
                   skipped_null_obj, skipped_null_form, skipped_zero_cnt);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in scan_container_inventory(%p)", container_ref);
        return 0;
    }

    return n;
}

// -----------------------------------------------------------------------
// B5 scene view-proj capture (hot path — one call per frame).
//
// Chain (resolved 2026-04-22):
//   imgbase + PLAYER_CAMERA_SINGLETON_RVA -> PlayerCamera*
//   PlayerCamera + PLAYER_CAMERA_STATES_OFF -> states[0] = FirstPersonState*
//   FirstPersonState + TES_STATE_NICAM_OFF (0x50) -> NiCamera*
//   NiCamera + NI_CAMERA_VIEWPROJ_OFF (288) -> float[16] 4x4 matrix
//
// MATRIX SEMANTICS (cracked 2026-04-22, math verified against live capture):
// The matrix stored here is a row-major world-to-clip VP with FULL XYZ
// pre-subtract of player foot position baked into its design. The game
// expects input vectors as `pos_rel = (world - player_foot_pos)` with
// the camera eye sitting at (0, 0, 120) in this chunk coordinate system
// (= EYE_HEIGHT above the foot). Live capture values confirm:
//   row1[3] = 252.16 ≈ f · EYE_HEIGHT = 2.093 · 120 = 251.16  (Y-flip)
//   row2[3] = -1  → near plane N = 1
//   row3    = (forward, 0)  → no world-origin translation in perspective row
//
// Therefore: we return player's FOOT position in `out_eye_world` (NOT
// foot + EYE_HEIGHT). The shader does `pos_rel = world - foot_pos`.
// Prior code added +120 to z, which broke the math — caused the body to
// clip off-screen because the second eye-height subtraction shifted
// depth inconsistently.
//
// Returns false on any null / SEH. All reads SEH-caged; never crashes.
// -----------------------------------------------------------------------
bool read_scene_view_proj(float out_view_proj[16], float out_eye_world[3]) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);
        // states[0] = FirstPersonState* (always populated once in-game)
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return false;

        const auto* st_bytes = reinterpret_cast<const std::uint8_t*>(state);
        const auto nicam = *reinterpret_cast<void* const*>(
            st_bytes + offsets::TES_STATE_NICAM_OFF);
        if (!nicam) return false;

        // Sanity: first qword of nicam must be the NiCamera vtable.
        const auto nicam_vtbl = *reinterpret_cast<void* const*>(nicam);
        if (reinterpret_cast<std::uintptr_t>(nicam_vtbl) !=
            module_base + offsets::NI_CAMERA_VTABLE_RVA) {
            return false;
        }

        // Copy 64 bytes of cached matrix.
        const auto* mat_src = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(nicam) +
            offsets::NI_CAMERA_VIEWPROJ_OFF);
        std::memcpy(out_view_proj, mat_src, 64);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    // Chunk-subtraction origin = player FOOT position (NOT eye = foot+120).
    // The matrix already bakes EYE_HEIGHT=120 into its translation column;
    // adding 120 here would double-subtract and clip the body off-screen.
    // See the SEMANTICS block above for the math derivation.
    const auto pchar_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_SINGLETON_RVA);
    void* pchar = nullptr;
    __try { pchar = *pchar_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pchar) return false;

    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pchar);
        out_eye_world[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        out_eye_world[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        out_eye_world[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
// β.6 shake fix — read live render-frame eye (bob-aware).
//
// The attempt to read NiCamera::world.translate (+0xA0) FAILED: that
// field holds only the LOCAL eye offset (0, 0, 120) relative to the
// camera's parent, because PlayerCamera doesn't drive NiCamera through
// UpdateWorldData. Instead, PlayerCamera caches the current-frame world
// eye position at its OWN +0x188 (see offsets.h for proof).
//
// We keep the old signature `read_camera_world_transform(eye, basis)`
// for ABI continuity, but basis is no longer populated (caller ignored
// it anyway). If future work needs camera orientation, read it from the
// captured `worldToCam` matrix or from PC's own rotation quaternion.
// -----------------------------------------------------------------------
bool read_camera_world_transform(float out_eye_world[3],
                                  float out_basis_rows[9]) {
    if (out_basis_rows) {
        // Basis is not set by this function anymore — identity fallback
        // to avoid undefined reads in the caller.
        for (int i = 0; i < 9; ++i) out_basis_rows[i] = 0.0f;
        out_basis_rows[0] = 1.0f;  // row0.x
        out_basis_rows[4] = 1.0f;  // row1.y
        out_basis_rows[8] = 1.0f;  // row2.z
    }

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);

        // Validate the buffered-pos flag at +0x1A7. If 0, the value at
        // +0x188 hasn't been populated yet (e.g., first frames or
        // state transition) — treat as failure so caller can fall back.
        const auto valid = *reinterpret_cast<const std::uint8_t*>(
            pc_bytes + offsets::PLAYER_CAMERA_BUF_VAL_OFF);
        if (valid == 0) return false;

        const auto* eye_ptr = reinterpret_cast<const float*>(
            pc_bytes + offsets::PLAYER_CAMERA_BUF_POS_OFF);
        out_eye_world[0] = eye_ptr[0];
        out_eye_world[1] = eye_ptr[1];
        out_eye_world[2] = eye_ptr[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
// β.6b v5 — read live NiFrustum near/far from PlayerCamera's NiCamera.
// Layout per CommonLibF4: NiFrustum at NiCamera+0x160, fields are
// {left, right, top, bottom, near, far, ortho} — near @ +0x10, far @
// +0x14 into the frustum. Values are the current-frame scene camera's
// clip planes used to build VP.
// -----------------------------------------------------------------------
bool read_camera_frustum_near_far(float& out_near, float& out_far) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return false;

        const auto* st_bytes = reinterpret_cast<const std::uint8_t*>(state);
        const auto nicam = *reinterpret_cast<void* const*>(
            st_bytes + offsets::TES_STATE_NICAM_OFF);
        if (!nicam) return false;

        const auto nicam_vtbl = *reinterpret_cast<void* const*>(nicam);
        if (reinterpret_cast<std::uintptr_t>(nicam_vtbl) !=
            module_base + offsets::NI_CAMERA_VTABLE_RVA) {
            return false;
        }

        const auto* ni_bytes = reinterpret_cast<const std::uint8_t*>(nicam);
        const auto* frustum_base = ni_bytes + offsets::NI_CAMERA_FRUSTUM_OFF;
        out_near = *reinterpret_cast<const float*>(
            frustum_base + offsets::NI_FRUSTUM_NEAR_OFF);
        out_far = *reinterpret_cast<const float*>(
            frustum_base + offsets::NI_FRUSTUM_FAR_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    // Sanity: plausible values?
    if (out_near <= 0.0f || out_near > 1000.0f) return false;
    if (out_far  <= out_near || out_far > 1e10f) return false;
    return true;
}

// -----------------------------------------------------------------------
// β.6 shake fix v2 — extract forward direction from worldToCam row 3.
//
// In row-major VP matrix, row 3 is the perspective-divide row, which
// encodes the camera-forward unit vector (fx, fy, fz, 0). Reading this
// gives the game's actual frame-perfect camera orientation (smoothed,
// interpolated by the engine) — matches what the scene was rendered
// with, no angular jitter vs. actor rot[] raw input.
// -----------------------------------------------------------------------
bool read_camera_forward(float out_fwd[3]) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return false;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!pc) return false;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return false;

        const auto* st_bytes = reinterpret_cast<const std::uint8_t*>(state);
        const auto nicam = *reinterpret_cast<void* const*>(
            st_bytes + offsets::TES_STATE_NICAM_OFF);
        if (!nicam) return false;

        // Validate NiCamera vtable.
        const auto nicam_vtbl = *reinterpret_cast<void* const*>(nicam);
        if (reinterpret_cast<std::uintptr_t>(nicam_vtbl) !=
            module_base + offsets::NI_CAMERA_VTABLE_RVA) {
            return false;
        }

        // Row 3 of row-major 4x4 = mem[12..15].
        const auto* m = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(nicam) +
            offsets::NI_CAMERA_VIEWPROJ_OFF);
        const float fx = m[12];
        const float fy = m[13];
        const float fz = m[14];

        // Sanity: forward should be ~unit length.
        const float mag2 = fx*fx + fy*fy + fz*fz;
        if (mag2 < 0.9f || mag2 > 1.1f) {
            // Matrix is in a weird state (shadow/UI/post-process pass,
            // or mid-write). Fall back.
            return false;
        }

        const float inv_mag = 1.0f / std::sqrt(mag2);
        out_fwd[0] = fx * inv_mag;
        out_fwd[1] = fy * inv_mag;
        out_fwd[2] = fz * inv_mag;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------
// β.6 camera-eye probe — dump candidate offsets for frame-perfect eye.
//
// RE leads (2026-04-22 from CommonLibF4 + SSE cross-ref):
//   PlayerCamera+0x188 : bufferedCameraPos (NiPoint3)
//   PlayerCamera+0x1A7 : cameraPosBuffered (bool flag)
//   FirstPersonState+0x30 : lastPosition     (SSE analog)
//   FirstPersonState+0x3C : lastFrameSpringVelocity (SSE analog)
//   FirstPersonState+0x48 : dampeningOffset  (SSE analog, bob delta)
//   FirstPersonState+0x54 : ??? next NiPoint3 slot
//
// We also log actor foot pos for reference — whatever tracks it with a
// +120-ish z offset + oscillates during walking is the bob-aware eye.
// -----------------------------------------------------------------------
void probe_camera_eye_fields() {
    if (!g_ready.load(std::memory_order_acquire)) return;

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return;

    // Player actor foot pos (ground truth).
    const auto pchar_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_SINGLETON_RVA);
    void* pchar = nullptr;
    __try { pchar = *pchar_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!pchar) return;

    float foot[3]{};
    __try {
        const auto* b = reinterpret_cast<const std::uint8_t*>(pchar);
        foot[0] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 0);
        foot[1] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 4);
        foot[2] = *reinterpret_cast<const float*>(b + offsets::POS_OFF + 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!pc) return;

    __try {
        const auto* pc_bytes = reinterpret_cast<const std::uint8_t*>(pc);

        // PlayerCamera+0x188 = bufferedCameraPos
        const float* pc188 = reinterpret_cast<const float*>(pc_bytes + 0x188);
        const std::uint8_t* pc1a7 = pc_bytes + 0x1A7;
        FW_LOG("[eyeprobe] foot=(%.1f, %.1f, %.1f)  "
               "PC+0x188 bufferedCameraPos=(%.1f, %.1f, %.1f) "
               "PC+0x1A7 flag=%u",
               foot[0], foot[1], foot[2],
               pc188[0], pc188[1], pc188[2],
               *pc1a7);

        // states[0] = FirstPersonState
        const auto state = *reinterpret_cast<void* const*>(
            pc_bytes + offsets::PLAYER_CAMERA_STATES_OFF);
        if (!state) return;
        const auto* fs = reinterpret_cast<const std::uint8_t*>(state);

        // Scan FirstPersonState+0x28..0x90 as NiPoint3 (every 4 bytes,
        // look for 3-float clusters that have player-pos-scale values).
        FW_LOG("[eyeprobe] FirstPersonState candidate eye fields:");
        for (std::size_t off = 0x28; off <= 0x80; off += 4) {
            const float* f = reinterpret_cast<const float*>(fs + off);
            // Heuristic filter: only print if first float is in player
            // coord range (|f[0]| > 100) — otherwise it's noise.
            if (std::fabs(f[0]) > 100.0f && std::fabs(f[0]) < 1e6f) {
                FW_LOG("[eyeprobe]   FS+0x%02zX = (%10.1f, %10.1f, %10.1f)",
                       off, f[0], f[1], f[2]);
            }
        }

        // Specifically dump the "known SSE" offsets unconditionally.
        const float* fs30 = reinterpret_cast<const float*>(fs + 0x30);
        const float* fs3c = reinterpret_cast<const float*>(fs + 0x3C);
        const float* fs48 = reinterpret_cast<const float*>(fs + 0x48);
        const float* fs54 = reinterpret_cast<const float*>(fs + 0x54);
        FW_LOG("[eyeprobe]   FS+0x30 (sse=lastPosition)      = (%.1f, %.1f, %.1f)",
               fs30[0], fs30[1], fs30[2]);
        FW_LOG("[eyeprobe]   FS+0x3C (sse=lastSpringVelocity)= (%.1f, %.1f, %.1f)",
               fs3c[0], fs3c[1], fs3c[2]);
        FW_LOG("[eyeprobe]   FS+0x48 (sse=dampeningOffset)   = (%.1f, %.1f, %.1f)",
               fs48[0], fs48[1], fs48[2]);
        FW_LOG("[eyeprobe]   FS+0x54 (next NiPoint3 slot)    = (%.1f, %.1f, %.1f)",
               fs54[0], fs54[1], fs54[2]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[eyeprobe] SEH during probe");
    }
}

// -----------------------------------------------------------------------
// B5 diagnostic — PlayerCamera layout probe.
//
// We scan the singleton's first 0x200 bytes looking for qwords that
// dereference to the known NiCamera vtable VA. Each match is logged;
// stable matches across frames identify the "OFF_NICAM" we need to
// navigate PlayerCamera → NiCamera at runtime. One-shot.
// -----------------------------------------------------------------------
static std::atomic<bool> g_camera_probe_done{false};

// Parallel probe: scan MainCullingCamera (the scene-render culling
// camera) for an internal NiCamera*. MCC is a BSTSingletonSDM with
// its instance at a fixed RVA (not derived from PlayerCamera). Hits
// give us a second candidate for the "real" scene VP matrix.
void probe_main_culling_camera_once() {
    static std::atomic<bool> done{false};
    if (done.load(std::memory_order_acquire)) return;
    if (!g_ready.load(std::memory_order_acquire)) return;

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return;

    const auto ni_vtbl = module_base + offsets::NI_CAMERA_VTABLE_RVA;
    const auto mcc_vtbl = module_base + offsets::MAIN_CULLING_CAMERA_VTABLE_RVA;

    // Try both accessors: direct (instance at fixed RVA) and via ptr slot.
    const auto direct_instance = reinterpret_cast<const std::uint8_t*>(
        module_base + offsets::MAIN_CULLING_CAMERA_INSTANCE_RVA);
    void* via_slot = nullptr;
    __try {
        via_slot = *reinterpret_cast<void* const*>(
            module_base + offsets::MAIN_CULLING_CAMERA_PTR_SLOT_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    FW_LOG("[mccprobe] direct_instance=%p via_slot=%p  (should be same)",
           static_cast<const void*>(direct_instance),
           via_slot);

    // Use the via_slot if non-null else fall back to direct.
    const auto* mcc = via_slot
        ? reinterpret_cast<const std::uint8_t*>(via_slot)
        : direct_instance;

    // Verify vtable matches MainCullingCamera.
    __try {
        const auto vt = *reinterpret_cast<void* const*>(mcc);
        const auto vt_va = reinterpret_cast<std::uintptr_t>(vt);
        FW_LOG("[mccprobe] MCC[0] = vtable 0x%llX (expected MCC 0x%llX, "
               "match=%d)",
               static_cast<unsigned long long>(vt_va),
               static_cast<unsigned long long>(mcc_vtbl),
               vt_va == mcc_vtbl ? 1 : 0);
        if (vt_va != mcc_vtbl) {
            FW_WRN("[mccprobe] MCC vtable mismatch — instance not initialized yet?");
            return;  // retry next frame
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[mccprobe] SEH reading MCC vtable");
        return;
    }

    // MCC IS-A NiCamera (extends it), so its own vtable != NiCamera vtable.
    // The NiCamera-inherited fields live at SAME offsets within MCC as in
    // NiCamera. So the cached matrix at NiCamera+288 lives at MCC+288.
    (void)ni_vtbl;

    // Dump the 4x4 matrix at MCC+288 directly.
    __try {
        const float* m = reinterpret_cast<const float*>(
            mcc + offsets::NI_CAMERA_VIEWPROJ_OFF);
        FW_LOG("[mccprobe] MCC+288 matrix (inherited NiCamera viewproj):");
        FW_LOG("[mccprobe]   row0=[%8.3f %8.3f %8.3f %12.2f]",
               m[0], m[1], m[2], m[3]);
        FW_LOG("[mccprobe]   row1=[%8.3f %8.3f %8.3f %12.2f]",
               m[4], m[5], m[6], m[7]);
        FW_LOG("[mccprobe]   row2=[%8.3f %8.3f %8.3f %12.2f]",
               m[8], m[9], m[10], m[11]);
        FW_LOG("[mccprobe]   row3=[%8.3f %8.3f %8.3f %12.2f]",
               m[12], m[13], m[14], m[15]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[mccprobe] SEH reading MCC+288");
        return;
    }

    // Also dump a few other interesting offsets for MCC layout (the
    // cached world transform, eye position, frustum params).
    __try {
        const float* f160 = reinterpret_cast<const float*>(mcc + 160);
        FW_LOG("[mccprobe]   MCC+160 [%8.3f %8.3f %8.3f]",
               f160[0], f160[1], f160[2]);
        const float* f352 = reinterpret_cast<const float*>(mcc + 352);
        FW_LOG("[mccprobe]   MCC+352 (frustum L/R/T/B N/F) "
               "[%8.3f %8.3f %8.3f %8.3f %8.3f %8.3f]",
               f352[0], f352[1], f352[2], f352[3], f352[4], f352[5]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    FW_LOG("[mccprobe] MCC probe complete — matrix dumped.");
    done.store(true, std::memory_order_release);
}

void probe_camera_layout_once() {
    if (g_camera_probe_done.load(std::memory_order_acquire)) return;
    if (!g_ready.load(std::memory_order_acquire)) return;

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(L"Fallout4.exe"));
    if (!module_base) return;

    const auto pc_slot = reinterpret_cast<void* const*>(
        module_base + offsets::PLAYER_CAMERA_SINGLETON_RVA);
    const auto ni_camera_vtable_va =
        module_base + offsets::NI_CAMERA_VTABLE_RVA;

    void* pc = nullptr;
    __try { pc = *pc_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_DBG("[camprobe] SEH reading PlayerCamera singleton (not ready)");
        return;
    }
    if (!pc) {
        FW_DBG("[camprobe] PlayerCamera singleton null (not ready)");
        return;
    }

    FW_LOG("[camprobe] scanning PlayerCamera=%p for NiCamera vtable=0x%llX",
           pc, static_cast<unsigned long long>(ni_camera_vtable_va));

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(pc);
    int matches = 0;

    // Scan PlayerCamera[0..0x1B0] as qwords. For each non-null pointer,
    // deref and check if the first qword at that target equals the
    // NiCamera vtable VA.
    __try {
        for (std::size_t off = 0; off < 0x1C0; off += 8) {
            const auto candidate = *reinterpret_cast<void* const*>(bytes + off);
            if (!candidate) continue;

            // Heuristic: pointer must be within a sensible process
            // address range (x64 user-space, above 0x10000).
            const auto cva = reinterpret_cast<std::uintptr_t>(candidate);
            if (cva < 0x10000ull || cva > 0x7FFFFFFFFFFFull) continue;

            void* first_qword = nullptr;
            __try {
                first_qword = *reinterpret_cast<void* const*>(candidate);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
            const auto fva = reinterpret_cast<std::uintptr_t>(first_qword);

            // Exact NiCamera vtable match.
            if (fva == ni_camera_vtable_va) {
                FW_LOG("[camprobe] PlayerCamera+0x%zX -> NiCamera* %p "
                       "(vtable match)", off, candidate);
                ++matches;
                continue;
            }

            // Secondary: pointer-to-pointer (smart-ptr wrapper) —
            // deref twice.
            if (fva > 0x10000ull && fva < 0x7FFFFFFFFFFFull) {
                void* second_qword = nullptr;
                __try {
                    second_qword = *reinterpret_cast<void* const*>(first_qword);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
                const auto sva = reinterpret_cast<std::uintptr_t>(second_qword);
                if (sva == ni_camera_vtable_va) {
                    FW_LOG("[camprobe] PlayerCamera+0x%zX -> smart_ptr -> "
                           "NiCamera* %p (indirect vtable match)",
                           off, first_qword);
                    ++matches;
                }
            }
        }

        // Also scan each slot of the states array (+0xE0..+0x158) — each
        // is a TESCameraState*. For the ACTIVE state, look INSIDE it for
        // a NiCamera pointer.
        const auto active_idx = *reinterpret_cast<const std::int32_t*>(
            bytes + offsets::PLAYER_CAMERA_ACTIVE_OFF);
        FW_LOG("[camprobe] active_state_idx = %d (raw dword @ +0x1A0)",
               active_idx);

        // Dump likely "current state pointer" caches at +0x170 and +0x178.
        const auto ptr_170 = *reinterpret_cast<void* const*>(bytes + 0x170);
        const auto ptr_178 = *reinterpret_cast<void* const*>(bytes + 0x178);
        FW_LOG("[camprobe] cached-state candidates: "
               "PlayerCamera+0x170 = %p,  +0x178 = %p",
               ptr_170, ptr_178);

        for (int i = 0; i < 16; ++i) {
            const std::size_t slot_off = offsets::PLAYER_CAMERA_STATES_OFF + i * 8;
            if (slot_off >= 0x1C0) break;
            const auto state_ptr = *reinterpret_cast<void* const*>(
                bytes + slot_off);
            if (!state_ptr) continue;

            const auto sva = reinterpret_cast<std::uintptr_t>(state_ptr);
            if (sva < 0x10000ull || sva > 0x7FFFFFFFFFFFull) continue;

            // State object's first qword is its vtable.
            void* state_vt = nullptr;
            __try {
                state_vt = *reinterpret_cast<void* const*>(state_ptr);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
            const auto svt = reinterpret_cast<std::uintptr_t>(state_vt);
            const auto state_vt_rva = (svt > module_base) ? (svt - module_base) : 0;
            FW_LOG("[camprobe]   state[%d] @ +0x%zX = %p  vtable=0x%llX (RVA 0x%llX)",
                   i, slot_off, state_ptr,
                   static_cast<unsigned long long>(svt),
                   static_cast<unsigned long long>(state_vt_rva));

            // Scan first 0x100 bytes of the state object for NiCamera ptr.
            const auto* sbytes = reinterpret_cast<const std::uint8_t*>(state_ptr);
            for (std::size_t soff = 0; soff < 0x120; soff += 8) {
                void* cand = nullptr;
                __try {
                    cand = *reinterpret_cast<void* const*>(sbytes + soff);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
                const auto cva = reinterpret_cast<std::uintptr_t>(cand);
                if (cva < 0x10000ull || cva > 0x7FFFFFFFFFFFull) continue;

                void* fq = nullptr;
                __try { fq = *reinterpret_cast<void* const*>(cand); }
                __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                const auto fva = reinterpret_cast<std::uintptr_t>(fq);
                if (fva == ni_camera_vtable_va) {
                    FW_LOG("[camprobe]     state[%d]+0x%zX -> NiCamera* %p "
                           "(\u2705 vtable match)",
                           i, soff, cand);
                    ++matches;

                    // Bonus: dump the 4x4 float matrix at NiCamera+288
                    // (from IDA clone method — candidate view-proj).
                    const auto* ncam_bytes = reinterpret_cast<const std::uint8_t*>(cand);
                    __try {
                        const float* m = reinterpret_cast<const float*>(
                            ncam_bytes + offsets::NI_CAMERA_VIEWPROJ_OFF);
                        FW_LOG("[camprobe]       NiCamera+288 matrix 4x4:");
                        FW_LOG("[camprobe]         row0=[%10.3f %10.3f %10.3f %10.3f]",
                               m[0],  m[1],  m[2],  m[3]);
                        FW_LOG("[camprobe]         row1=[%10.3f %10.3f %10.3f %10.3f]",
                               m[4],  m[5],  m[6],  m[7]);
                        FW_LOG("[camprobe]         row2=[%10.3f %10.3f %10.3f %10.3f]",
                               m[8],  m[9],  m[10], m[11]);
                        FW_LOG("[camprobe]         row3=[%10.3f %10.3f %10.3f %10.3f]",
                               m[12], m[13], m[14], m[15]);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        FW_WRN("[camprobe]       SEH reading NiCamera+288 matrix");
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[camprobe] SEH during scan");
        return;
    }

    FW_LOG("[camprobe] scan complete: %d NiCamera pointer matches found", matches);
    if (matches > 0) {
        g_camera_probe_done.store(true, std::memory_order_release);
    }
    // Else: keep retrying next frame until PlayerCamera is populated.
}

// -----------------------------------------------------------------------
// Z.2 (Path B) — spawn a ghost Actor via PlaceAtMe native.
//
// MUST be called from the main (WndProc) thread. See
// re/placeatme_calling_convention.txt for the full signature decode.
// -----------------------------------------------------------------------
void* spawn_ghost_actor(std::uint32_t template_form_id) {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_ERR("[ghost] spawn: engine not ready");
        return nullptr;
    }
    if (!g_place_at_me || !g_lookup || !g_player_singleton_slot) {
        FW_ERR("[ghost] spawn: resolvers null "
               "(place=%p lookup=%p player_slot=%p)",
               g_place_at_me, g_lookup, g_player_singleton_slot);
        return nullptr;
    }

    // Resolve template form (e.g., LCharWorkshopNPC settler).
    void* template_form = nullptr;
    __try { template_form = g_lookup(template_form_id); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost] spawn: SEH in lookup(0x%X)", template_form_id);
        return nullptr;
    }
    if (!template_form) {
        FW_ERR("[ghost] spawn: lookup(0x%X) returned null — "
               "ESM not loaded? worldspace unavailable?", template_form_id);
        return nullptr;
    }

    // Resolve player REFR (the "at me" anchor). Read-then-use to avoid
    // holding a stale pointer across re-load.
    void* player = nullptr;
    __try { player = *g_player_singleton_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost] spawn: SEH reading player singleton");
        return nullptr;
    }
    if (!player) {
        FW_ERR("[ghost] spawn: player singleton null — not in game yet?");
        return nullptr;
    }

    // Form pair { VMHandle=null, TESForm*=template }. Decomp shows PlaceAtMe
    // reads *a3 first (handle path); NULL handle → falls back to a3[1]
    // direct TESForm*, which is what we want.
    void* form_pair[2] = { nullptr, template_form };

    void* actor = nullptr;
    __try {
        actor = g_place_at_me(
            /* vm         = */ nullptr,
            /* stack_id   = */ 0,
            /* form_pair  = */ form_pair,
            /* anchor     = */ player,
            /* count      = */ 1,
            /* persistent = */ 0);  // 0 = temp ref, skip MarkPersistent
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost] spawn: SEH in PlaceAtMe(template=0x%X)",
               template_form_id);
        return nullptr;
    }

    if (!actor) {
        FW_ERR("[ghost] spawn: PlaceAtMe returned null (template=0x%X)",
               template_form_id);
        return nullptr;
    }

    // OR in the TEMPORARY flag so this ref doesn't persist in the save.
    // PlaceAtMe hardcodes NEW_REFR_DATA.flags = 0x1000000 only; we patch
    // the resulting REFR's flags field post-return.
    auto* actor_bytes = reinterpret_cast<std::uint8_t*>(actor);
    __try {
        auto* flags_ptr = reinterpret_cast<std::uint32_t*>(
            actor_bytes + offsets::FLAGS_OFF);
        *flags_ptr |= offsets::REFR_FLAG_TEMPORARY;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost] spawn: SEH patching TEMPORARY flag on actor=%p",
               actor);
        // Non-fatal — worst case is save bloat, we still got an actor.
    }

    // Read back the resulting form_id for logging.
    std::uint32_t actor_form_id = 0;
    __try {
        actor_form_id = *reinterpret_cast<const std::uint32_t*>(
            actor_bytes + offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    FW_LOG("[ghost] spawn OK: template=0x%X \u2192 actor=%p form_id=0x%X "
           "(TEMPORARY patched)",
           template_form_id, actor, actor_form_id);
    return actor;
}

// =========================================================================
// B6.5w3.b \u2014 apply_npc_state_to_engine
// =========================================================================
//
// Called on the MAIN thread (via fw::dispatch::drain_npc_state_apply_queue)
// for each PendingNPCStateEntry in a drained batch.
//
// Pipeline:
//   1. lookup_by_form_id \u2192 Actor* (null if cell not loaded on this client)
//   2. SEH-caged write of pos (3 floats at Actor+0xD0) + yaw radians
//      (1 float at Actor+0xC0 + 8 \u2014 Z component of the rotation triplet).
//      Pitch (+0xC0+0) and roll (+0xC0+4) left untouched: body yaw is
//      the only axis the server drives in MVP.
//   3. Anim graph variable writes (#STATE MINIMAL for now):
//        IDLE     (0): no-op \u2014 let vanilla idles play
//        WALKING  (1): SpeedSampled = 100 + Direction = 0
//        RUNNING  (2): SpeedSampled = 200 + Direction = 0
//        others     : skipped (covered by B6.5w4 / B6.6)
//
// Yaw conversion:
//   The server brain (server/npc_brain.py) emits yaw in MATH convention
//   (atan2 of dy/dx, 0 = +X axis, CCW positive) as degrees.
//   Bethesda actors store yaw in radians with 0 = +Y axis (north),
//   CW positive. Conversion:
//
//       beth_yaw_rad = (pi/2) - yaw_deg_math * (pi/180)
//                    = (90 - yaw_deg_math) * pi / 180
//
// Returns true on lookup + at least pos write success; false on miss/SEH.
bool apply_npc_state_to_actor(
    void* actor,
    float pos_x, float pos_y, float pos_z,
    float yaw_deg_math,
    std::uint8_t anim_state,
    bool skip_anim_graph)
{
    if (!actor) return false;
    if (!g_ready.load(std::memory_order_acquire)) {
        return false;
    }

    auto* bytes = reinterpret_cast<std::uint8_t*>(actor);

    // Convert math-degrees \u2192 Bethesda-radians.
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kDegToRad = kPi / 180.0f;
    const float yaw_beth_rad = (90.0f - yaw_deg_math) * kDegToRad;

    // ---- Direct write of pos + yaw on the Actor struct ------------------
    // Pure memory writes \u2014 safe from any thread (no engine recursion).
    bool pos_ok = false;
    __try {
        *reinterpret_cast<float*>(bytes + offsets::POS_OFF + 0) = pos_x;
        *reinterpret_cast<float*>(bytes + offsets::POS_OFF + 4) = pos_y;
        *reinterpret_cast<float*>(bytes + offsets::POS_OFF + 8) = pos_z;
        // Only Z component of rotation (yaw). Pitch + roll left alone.
        *reinterpret_cast<float*>(bytes + offsets::ROT_OFF + 8) = yaw_beth_rad;
        pos_ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("npc_apply: SEH writing pos/yaw on actor=%p", actor);
        return false;
    }

    // ---- B6.5w4 round 3: direct NIF.world.translate write ----------------
    // Renderer reads world.translate from the actor's BSFadeNode (NIF root).
    // The engine's NIF sync inside Update_PerFrame uses AI's +0xD0 value,
    // so by the time we post-overwrite +0xD0, NIF still has AI's pos and
    // render shows AI's pos. Writing NIF directly here makes the renderer
    // see our pos this frame. Pointer chain:
    //   Actor + 0xF0  → LoadedRefData* (NULL if 3D not loaded yet)
    //   LoadedRefData + 0x08  → NiAVObject* (BSFadeNode root)
    //   NiAVObject + 0xA0  → world.translate (NiPoint3)
    __try {
        void* loaded_ref_data = *reinterpret_cast<void**>(
            bytes + offsets::LOADED_REF_DATA_OFF);
        if (loaded_ref_data) {
            void* nif = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(loaded_ref_data) +
                offsets::LOADED_REF_DATA_3D_OFF);
            if (nif) {
                auto* nbytes = reinterpret_cast<std::uint8_t*>(nif);
                // Write world.translate (renderer reads this).
                *reinterpret_cast<float*>(
                    nbytes + offsets::NI_AV_WORLD_TRANSLATE_OFF + 0) = pos_x;
                *reinterpret_cast<float*>(
                    nbytes + offsets::NI_AV_WORLD_TRANSLATE_OFF + 4) = pos_y;
                *reinterpret_cast<float*>(
                    nbytes + offsets::NI_AV_WORLD_TRANSLATE_OFF + 8) = pos_z;
                // Round 4: ALSO write local.translate. If the engine
                // recomputes world from local*parent during the frame,
                // our local write ensures world stays at our value.
                // For top-level BSFadeNode under cell root (identity
                // parent transform on exterior cells), local == world.
                *reinterpret_cast<float*>(
                    nbytes + offsets::NI_AV_LOCAL_TRANSLATE_OFF + 0) = pos_x;
                *reinterpret_cast<float*>(
                    nbytes + offsets::NI_AV_LOCAL_TRANSLATE_OFF + 4) = pos_y;
                *reinterpret_cast<float*>(
                    nbytes + offsets::NI_AV_LOCAL_TRANSLATE_OFF + 8) = pos_z;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 3D may not be loaded yet (cell streaming) — silently skip.
        // pos_ok stays true since the actor pos write succeeded.
    }

    // ---- Anim graph variable writes (#STATE MINIMAL for now) -----------
    // Setter takes the IAnimationGraphManagerHolder sub-object pointer
    // (Actor + 0x48) \u2014 NOT the Actor pointer. MAIN THREAD REQUIRED:
    // the setter recurses into smart-pointer fetch + dispatch, which
    // races with scene-graph mutations on the main thread. Caller must
    // pass skip_anim_graph=true when invoking from off-main-thread.
    if (!skip_anim_graph &&
        g_set_graph_var_float &&
        g_bs_speed_sampled.pool_entry &&
        g_bs_direction.pool_entry)
    {
        auto* holder = bytes + offsets::IANIMGRAPHHOLDER_OFF;
        float speed_target = -1.0f;
        switch (anim_state) {
            case 0: /* IDLE */    speed_target = 0.0f;   break;
            case 1: /* WALKING */ speed_target = 100.0f; break;
            case 2: /* RUNNING */ speed_target = 200.0f; break;
            // AIMING/FIRING/RELOADING/DEAD: layered in by B6.6 + B6.5w4.
            default:              speed_target = -1.0f;  break;
        }
        if (speed_target >= 0.0f) {
            __try {
                g_set_graph_var_float(holder, &g_bs_speed_sampled, speed_target);
                g_set_graph_var_float(holder, &g_bs_direction,     0.0f);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_WRN("npc_apply: SEH in SetGraphVariable* actor=%p anim=%u",
                       actor, static_cast<unsigned>(anim_state));
                // pos write already landed; treat as partial success.
            }
        }

        // Round 3: kill anim-driven root motion. When bAnimationDriven=1
        // the engine applies the anim's root-motion displacement to the
        // actor's pos each frame, fighting our writes. Setting to 0 makes
        // anim decorative (plays without translating the actor).
        // (B6.5w12: same logic also exposed via set_actor_anim_driven()
        //  for the movement-bail hook.)
        if (g_set_graph_var_bool && g_bs_anim_driven.pool_entry) {
            __try {
                g_set_graph_var_bool(holder, &g_bs_anim_driven,
                                     static_cast<char>(0));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_WRN("npc_apply: SEH setting bAnimationDriven=0 actor=%p",
                       actor);
            }
        }

        // Round 8: humanoid anim state suite. Force-write every bool
        // every frame so vanilla AI's between-frame writes (e.g. its
        // local decision "bIsAttacking=1 because saw an enemy nearby")
        // get overwritten back to our server-authoritative value next
        // frame. The fight is at 60 Hz on both sides — but our writes
        // are timestamp-stable across clients, AI's are not, so the
        // visible result converges to ours.
        if (g_set_graph_var_bool) {
            const char is_running    = (anim_state == 2) ? 1 : 0;  // RUNNING
            const char is_sprinting  = 0;
            const char is_attacking  = (anim_state == 4) ? 1 : 0;  // FIRING
            const char is_aiming_gun = (anim_state == 3 ||
                                         anim_state == 4) ? 1 : 0; // AIMING|FIRING
            const char is_blocking   = 0;
            const char is_sneaking   = 0;
            const char is_dead       = (anim_state == 6) ? 1 : 0;  // DEAD
            __try {
                if (g_bs_is_running.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_running, is_running);
                if (g_bs_is_sprinting.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_sprinting, is_sprinting);
                if (g_bs_is_attacking.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_attacking, is_attacking);
                if (g_bs_is_aiming_gun.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_aiming_gun, is_aiming_gun);
                if (g_bs_is_blocking.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_blocking, is_blocking);
                if (g_bs_is_sneaking.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_sneaking, is_sneaking);
                if (g_bs_is_dead.pool_entry)
                    g_set_graph_var_bool(holder, &g_bs_is_dead, is_dead);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                FW_WRN("npc_apply: SEH in humanoid bool suite actor=%p anim=%u",
                       actor, static_cast<unsigned>(anim_state));
            }
        }
    }

    return pos_ok;
}

bool apply_npc_state_to_engine(
    std::uint32_t form_id,
    float pos_x, float pos_y, float pos_z,
    float yaw_deg_math,
    std::uint8_t anim_state,
    bool skip_anim_graph)
{
    void* actor = lookup_by_form_id(form_id);
    if (!actor) return false;
    return apply_npc_state_to_actor(actor, pos_x, pos_y, pos_z,
                                    yaw_deg_math, anim_state, skip_anim_graph);
}

void set_actor_ai_enabled(void* actor, bool enabled) {
    if (!actor || !g_actor_enable_ai) return;
    if (!g_ready.load(std::memory_order_acquire)) return;
    __try {
        g_actor_enable_ai(actor,
                          static_cast<char>(enabled ? 1 : 0),
                          /*queueEquipChange=*/static_cast<char>(0));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in set_actor_ai_enabled actor=%p enabled=%d",
               actor, enabled ? 1 : 0);
    }
}

bool actor_atomic_teleport(void* actor,
                          float pos_x, float pos_y, float pos_z,
                          float yaw_rad) {
    if (!actor || !g_actor_atomic_teleport) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    bool ok = false;
    __try {
        float pos[3] = { pos_x, pos_y, pos_z };
        // Round 11 — high-frequency teleport flag set.
        //   doProcessUpdate=0 : skip AI-process reattachment (cell unchanged)
        //   skipPlayerCheck=1 : skip "is this the player" branch (we never are)
        //   skipAreaCheck=1   : skip "is target area loaded" gate
        // Combined → lightest path through sub_140C60BE0; minimizes the
        // anim-graph-flush + cell-reattach overhead per call, at the cost
        // of less safety on cell boundary crossings (acceptable: server
        // brain is single-cell for MVP).
        g_actor_atomic_teleport(
            actor, pos, yaw_rad, 0.0f /*pitch*/,
            nullptr /*target_cell*/, nullptr /*target_marker*/,
            /*do_process_update=*/static_cast<char>(0),
            /*skip_player_check=*/static_cast<char>(1),
            /*skip_area_check=*/static_cast<char>(1));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in actor_atomic_teleport actor=%p pos=(%.1f,%.1f,%.1f)",
               actor, pos_x, pos_y, pos_z);
    }
    return ok;
}

bool actor_teleport_handoff(void* actor,
                            float pos_x, float pos_y, float pos_z,
                            float yaw_rad) {
    if (!actor || !g_actor_atomic_teleport) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    bool ok = false;
    __try {
        float pos[3] = { pos_x, pos_y, pos_z };
        // c.44 — doProcessUpdate=1: REATTACH the AI-process + cell at the target
        // (vs actor_atomic_teleport's 0 = "cell unchanged" light path). The
        // reattach is the whole point here — it moves B's engine GROUND-TRUTH,
        // not just the display, so the raider doesn't re-snap to its diverged
        // default. Heavier, but one-shot per handoff. skip_player/area = 1: the
        // target IS the rendered/visible pos, so the area is loaded.
        g_actor_atomic_teleport(
            actor, pos, yaw_rad, 0.0f /*pitch*/,
            nullptr /*target_cell*/, nullptr /*target_marker*/,
            /*do_process_update=*/static_cast<char>(1),
            /*skip_player_check=*/static_cast<char>(1),
            /*skip_area_check=*/static_cast<char>(1));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in actor_teleport_handoff actor=%p pos=(%.1f,%.1f,%.1f)",
               actor, pos_x, pos_y, pos_z);
    }
    return ok;
}

bool set_actor_motion_keyframed(void* actor) {
    if (!actor || !g_niav_set_motion_type) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    // Fetch the actor's 3D root: Actor + 0xF0 → LoadedRefData* → +0x8 → NiAVObject*
    void* root3d = nullptr;
    __try {
        auto* bytes = reinterpret_cast<std::uint8_t*>(actor);
        void* loaded_ref_data = *reinterpret_cast<void**>(
            bytes + offsets::LOADED_REF_DATA_OFF);
        if (!loaded_ref_data) return false;
        root3d = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(loaded_ref_data) +
            offsets::LOADED_REF_DATA_3D_OFF);
        if (!root3d) return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    bool ok = false;
    __try {
        g_niav_set_motion_type(
            root3d,
            /*motion_type=*/2 /*Keyframed*/,
            /*a3=*/static_cast<char>(1),
            /*a4=*/static_cast<char>(0),
            /*activate_on_land=*/static_cast<std::uint8_t>(0));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in set_actor_motion_keyframed actor=%p root3d=%p",
               actor, root3d);
    }
    return ok;
}

// Build 62.8 (2026-05-25) — undo the Keyframed motion. Required for raiders
// that were keyframed in the cell-load era (movement_override=1) and have
// since entered native combat tier — without this, Havok body stays frozen
// so the engine can't path/move them even though combat AI wants to.
//
// c.41b BUGFIX — motion_type for Dynamic is 1, NOT 4. The engine's actor
// motion applier accepts ONLY {1=Dynamic, 2=Keyframed} (decomp-verified: the
// GameScript SetMotionTypeFunctor rejects `(a4-1) > 1` as "invalid motion
// type", and set_actor_motion_keyframed correctly passes 2). Passing 4 was a
// silent no-op → the body never returned to Dynamic, which would have frozen
// raider corpses (no ragdoll) and stuck the body Keyframed after a handoff.
bool set_actor_motion_dynamic(void* actor) {
    if (!actor || !g_niav_set_motion_type) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    void* root3d = nullptr;
    __try {
        auto* bytes = reinterpret_cast<std::uint8_t*>(actor);
        void* loaded_ref_data = *reinterpret_cast<void**>(
            bytes + offsets::LOADED_REF_DATA_OFF);
        if (!loaded_ref_data) return false;
        root3d = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(loaded_ref_data) +
            offsets::LOADED_REF_DATA_3D_OFF);
        if (!root3d) return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    bool ok = false;
    __try {
        g_niav_set_motion_type(
            root3d,
            /*motion_type=*/1 /*Dynamic — c.41b: was 4 (no-op); engine wants 1*/,
            /*a3=*/static_cast<char>(1),
            /*a4=*/static_cast<char>(0),
            /*activate_on_land=*/static_cast<std::uint8_t>(1));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in set_actor_motion_dynamic actor=%p root3d=%p",
               actor, root3d);
    }
    return ok;
}

// Build 65.c.47 — WEDGE3 death-sync. Invoke Actor::Kill on the mirror.
// killer=nullptr is intentional for the MINIMAL build (engine substitutes
// dword_1430DA180 default + still flops the body via sub_140C45EA0; no
// directional impulse). a3=0 (no impulse magnitude), silent=1 (suppress the
// kill HUD/log churn on the non-owner), a5=0. The caller (drain_npc_death_
// apply_queue) un-keyframes first and holds an ApplyingRemoteGuard so the
// detour_kill re-entry caused by this call does NOT re-report to the server.
bool kill_actor(void* victim, void* killer) noexcept {
    if (!victim || !g_kill_engine) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    bool ok = false;
    __try {
        g_kill_engine(victim, killer,
                      /*a3=*/0.0f,
                      /*silent=*/static_cast<char>(1),
                      /*a5=*/static_cast<char>(0));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in kill_actor victim=%p killer=%p", victim, killer);
    }
    return ok;
}

bool set_actor_anim_driven(void* actor, bool value) {
    if (!actor) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!g_set_graph_var_bool || !g_bs_anim_driven.pool_entry) return false;

    // Anim graph holder = Actor + 0x48 (IANIMGRAPHHOLDER_OFF).
    void* holder = reinterpret_cast<void*>(
        reinterpret_cast<std::uint8_t*>(actor) +
        offsets::IANIMGRAPHHOLDER_OFF);

    bool ok = false;
    __try {
        g_set_graph_var_bool(holder, &g_bs_anim_driven,
                             value ? static_cast<char>(1) : static_cast<char>(0));
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("engine: SEH in set_actor_anim_driven actor=%p value=%d",
               actor, int(value));
    }
    return ok;
}

// B6.6w4 — fire trigger via WeaponFireHandler (sub_140DFF6B0).
// Single-call invocation; the handler does slot resolution + projectile-
// class validation + ammo bookkeeping internally.
//
// Pass nullptr for anim_event_arg → vanilla slot resolver branch fires
// (`sub_140CD0A60` walks equipManager). First arg is unused inside the
// body (verified funcs_0325.md:9573 — never deref'd), pass 0.
//
// SEH-caged. First 10 fires + every 200 thereafter logged.
bool fire_actor_weapon(void* actor) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_WRN("engine: fire_actor_weapon called before init");
        return false;
    }
    if (!actor) return false;
    if (!g_weapon_fire_handler) {
        FW_ERR("engine: fire_actor_weapon — fn pointer not resolved");
        return false;
    }

    static std::atomic<std::uint64_t> s_fires{0};
    static std::atomic<std::uint64_t> s_seh{0};

    // B6.6w5 Build 23 — replace nullptr with `alignas(8) zero_arg[2]={0,0}`.
    //
    // Build 22 log showed 30 AVs at RVA 0x167C200 (= `sub_14167C200`, the
    // anim-event-arg parser). Audit B6.6w4_audit_fire_trigger_AGENT.md sec 4
    // explicitly prescribes passing a zero-pair so `sub_14167C200(a3)`
    // tests `a3+something == 0` and falls into the slot-resolve branch
    // (sub_140CD0A60 walks equipManager). Passing literal nullptr makes
    // the parser deref a3 = NULL → AV.
    alignas(8) std::int64_t zero_arg[2] = {0, 0};

    char rc = 0;
    __try {
        rc = g_weapon_fire_handler(0, actor, zero_arg);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = s_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("engine: fire_actor_weapon SEH #%llu actor=%p",
                   static_cast<unsigned long long>(sn), actor);
        }
        return false;
    }

    const auto fn = s_fires.fetch_add(1, std::memory_order_relaxed);
    if (fn < 10) {
        FW_LOG("engine: fire_actor_weapon #%llu actor=%p rc=%d",
               static_cast<unsigned long long>(fn), actor, int(rc));
    } else if ((fn % 200) == 0) {
        FW_DBG("engine: fire_actor_weapon #%llu (heartbeat, seh=%llu)",
               static_cast<unsigned long long>(fn),
               s_seh.load(std::memory_order_relaxed));
    }
    return rc != 0;
}

// ============================================================================
// PUPPET FIRE PHASE 1 — Scenario A orchestration (2026-05-17).
// Source: re/puppet_fire_phase1/SUPERVISOR_SYNTHESIS.md §7.2.
//
// Scenario A applies when the raider is already in combat tier (Actor+0x328
// non-null) and a Stage-1 combat behavior leaf has fired at least once for
// the firing slot (CombatAimController registered in HighProcess+0x98
// BSTArray). For those raiders, the 3-call recipe drives Stage-4 directly:
//
//   1. set_actor_weapon_state_class(actor, 15)  — gate B passes
//   2. aim_set_target(aim_ctrl, x, y, z)        — gate C passes
//   3. fire_actor_weapon(actor)                  — emits Stage-4 visuals
//
// Scenario B (raider WITHOUT HighProcess, the 5 ghost-aggro Concord raiders)
// is NOT covered by this code. Under verification by §8.6 background agent.
// ============================================================================

// Internal helper: SEH-safe pointer read at offset. Local to this block.
namespace {

template <typename T>
T puppet_safe_read(const void* base, std::size_t off, T sentinel = T{}) noexcept {
    if (!base) return sentinel;
    __try {
        return *reinterpret_cast<const T*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return sentinel;
    }
}

}  // namespace

// Resolve a raider's CombatAimController for the given slot.
//
// Walks: Actor+0x328 (HighProcess) → HighProcess+0x98 (BSTArray data ptr) →
// scan entries by vtable match (== g_aim_ctrl_vtbl_addr) AND entry+0x30 low
// byte == slot.
//
// Returns nullptr if:
//   - actor null
//   - g_aim_ctrl_vtbl_addr not initialized
//   - Actor+0x328 NULL (raider not in combat tier — Scenario B case)
//   - BSTArray empty or oversized (sanity bound 64 entries)
//   - no entry matches vtable + slot filter
//
// Fully SEH-caged. Caller must dispatch on main thread (HighProcess.dtor
// runs on main thread — serialization avoids races).
//
// Performance: BSTArray typically ≤4 entries; walk is O(N) with tiny
// constant. No caching.
void* resolve_actor_aim_controller_for_slot(void* actor,
                                            std::uint32_t slot) noexcept {
    if (!actor || !g_aim_ctrl_vtbl_addr) return nullptr;

    void* result = nullptr;
    __try {
        // 1) Actor + 0x328 → HighProcess*
        void* hp = puppet_safe_read<void*>(actor, offsets::ACTOR_AIPROCESS_OFF);
        if (!hp) return nullptr;  // Scenario B — handled separately

        // 2) BSTArray header at HighProcess + 0x98
        void** data = puppet_safe_read<void**>(
            hp, offsets::HIGHPROC_CHILDREN_BSTARRAY_DATA_OFF);
        std::uint32_t size = puppet_safe_read<std::uint32_t>(
            hp, offsets::HIGHPROC_CHILDREN_BSTARRAY_SIZE_OFF);
        if (!data || size == 0 || size > 64) return nullptr;

        // 3) Scan entries. Filter:
        //    (a) vtable matches CombatAimController class
        //    (b) entry+0x30 low byte matches slot
        const std::uint32_t slot_low = slot & 0xFFu;
        for (std::uint32_t i = 0; i < size; ++i) {
            void* entry = data[i];
            if (!entry) continue;

            // Vtable filter — distinguishes CombatAimController from other
            // CombatObjectBase derivatives registered in the same BSTArray.
            std::uintptr_t entry_vt =
                puppet_safe_read<std::uintptr_t>(entry, 0);
            if (entry_vt != g_aim_ctrl_vtbl_addr) continue;

            // Slot filter (low byte = slot id; high bits = wstate flags
            // varying per-tick — supervisor §8.2 noted this needs live
            // verification, so match low byte only).
            std::uint32_t entry_slot_filter = puppet_safe_read<std::uint32_t>(
                entry, offsets::AIM_CTRL_SLOT_FILTER_OFF);
            if ((entry_slot_filter & 0xFFu) != slot_low) continue;

            result = entry;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Unexpected — every read above is already __try-caged via
        // puppet_safe_read. This handles any straggler.
        return nullptr;
    }
    return result;
}

// Drive a raider's weapon-state class to `new_class` via sub_140CD1830.
// Resolves the slot internally via sub_140CD0A60 (the slot resolver).
//
// `new_class` typical values:
//   15 = ready-to-fire (puppet-fire entry value — handler advances to 16/17)
//   16 = fire-semi
//   17 = fire-auto
//
// Returns false on:
//   - engine not ready
//   - null actor
//   - fn pointer not resolved
//   - slot resolver SEH or -1 return (no weapon equipped)
//   - setter SEH
//
// Fully SEH-caged. Safe on actors WITHOUT HighProcess (Worker A verified —
// sub_140CD1830 only touches Actor+0x130 and Actor+0x300; Actor+0x328 is
// NOT read).
bool set_actor_weapon_state_class(void* actor, int new_class) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!actor || !g_weapon_state_class_setter || !g_resolve_weapon_slot) {
        return false;
    }

    alignas(8) std::int64_t zero_arg[2] = {0, 0};
    int resolved_slot = -1;

    __try {
        g_resolve_weapon_slot(actor, &resolved_slot, zero_arg);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_puppet_fire_class_set_fail.fetch_add(
            1, std::memory_order_relaxed);
        FW_ERR("engine: set_actor_weapon_state_class slot resolver SEH "
               "actor=%p", actor);
        return false;
    }
    if (resolved_slot == -1) {
        // No weapon equipped — not an error in puppet-fire context but
        // we can't proceed. Log at DEBUG; this is normal for
        // pre-combat actors.
        g_puppet_fire_class_set_fail.fetch_add(
            1, std::memory_order_relaxed);
        FW_DBG("engine: set_actor_weapon_state_class no weapon actor=%p",
               actor);
        return false;
    }

    __try {
        g_weapon_state_class_setter(
            actor, static_cast<std::uint32_t>(resolved_slot), new_class);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_puppet_fire_class_set_fail.fetch_add(
            1, std::memory_order_relaxed);
        FW_ERR("engine: set_actor_weapon_state_class SEH actor=%p slot=%d "
               "class=%d", actor, resolved_slot, new_class);
        return false;
    }

    const auto n = g_puppet_fire_class_set_ok.fetch_add(
        1, std::memory_order_relaxed);
    if (n < 10) {
        FW_LOG("engine: set_actor_weapon_state_class #%llu actor=%p slot=%d "
               "class=%d", static_cast<unsigned long long>(n), actor,
               resolved_slot, new_class);
    }
    return true;
}

// Write aim target on a resolved CombatAimController.
//
// Calls sub_140E65820(aim_controller, &xyz). The function writes:
//   aim_ctrl+0x18..0x20 = (x, y, z)
//   aim_ctrl+0x34      |= 0x1   (valid-aim flag)
//   aim_ctrl+0x38       = g_game_time (anchor)
//   aim_ctrl+0x3C       = 0     (reset)
//
// Returns false on null inputs or SEH.
bool aim_set_target(void* aim_controller,
                    float x, float y, float z) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!aim_controller || !g_aim_set_target) return false;

    alignas(4) float xyz[3] = { x, y, z };
    __try {
        g_aim_set_target(aim_controller, xyz);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("engine: aim_set_target SEH aim_ctrl=%p xyz=(%.1f,%.1f,%.1f)",
               aim_controller, x, y, z);
        return false;
    }
    return true;
}

// Top-level puppet-fire orchestrator — Scenario A recipe.
//
// Drives raider to emit a visible projectile aimed at target_xyz on this
// client. Server-driven: caller is the NPC_FIRE event handler that
// receives raider_form_id + target_xyz from the server.
//
// Flow:
//   1. Resolve weapon slot (idempotent — slot resolver is read-only).
//   2. set_actor_weapon_state_class(raider, 15) — handler will advance
//      to 16 or 17 internally based on weapon flags.
//   3. Resolve CombatAimController for that slot via HighProcess+0x98
//      BSTArray scan. If missing (Scenario B — HighProcess NULL or no
//      Stage-1 leaf has run yet for this slot), proceed without aim
//      write — Stage-4 will silent-no-op via sub_14087D190 returning 0.
//      Counter g_puppet_fire_aim_missing increments to signal this.
//   4. fire_actor_weapon(raider) — invokes WeaponFireHandler which runs
//      Stage-3 + Stage-4 (projectile spawn + muzzle flash + audio).
//
// Returns true if WeaponFireHandler returned non-zero (= projectile
// emitted, or at least handler claimed success — Stage-4 has its own
// internal silencers per re/AI_pipeline/section_08 §16).
//
// MUST run on main thread (HighProcess lifecycle, NIF scene graph
// mutations, anim graph notify — none of these are net-thread safe).
//
// SCENARIO B NOTE: when Actor+0x328 == NULL, step 3 returns nullptr,
// step 4 may still fire but produces no visible projectile because
// Stage-4's aim solver bails. This is the current ghost-aggro case.
// Verification of an alternate (primary-AIProcess) path is in progress
// per re/puppet_fire_phase1/B_AGENT_section_8_6_verify.md.
bool fire_actor_at_target(void* raider_actor,
                          float target_x, float target_y, float target_z) noexcept
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!raider_actor) return false;

    const auto call_n = g_puppet_fire_calls.fetch_add(
        1, std::memory_order_relaxed);

    // --- Step 1+2 fused: resolve slot once, use for both class set + aim resolve ---
    alignas(8) std::int64_t zero_arg[2] = {0, 0};
    int slot = -1;
    if (g_resolve_weapon_slot) {
        __try { g_resolve_weapon_slot(raider_actor, &slot, zero_arg); }
        __except (EXCEPTION_EXECUTE_HANDLER) { slot = -1; }
    }
    if (slot == -1) {
        FW_DBG("engine: fire_actor_at_target #%llu actor=%p slot=-1 "
               "(no weapon equipped) — skipping",
               static_cast<unsigned long long>(call_n), raider_actor);
        return false;
    }

    // --- Step 2: advance weapon-state class to firable (15) ---
    // Don't bail if this fails — class may already be 15/16/17 from a
    // prior natural fire. Worst case fire_actor_weapon below silent-no-ops
    // via WeaponFireHandler's `(class - 15) <= 2` gate.
    if (g_weapon_state_class_setter) {
        __try {
            g_weapon_state_class_setter(
                raider_actor, static_cast<std::uint32_t>(slot), 15);
            g_puppet_fire_class_set_ok.fetch_add(
                1, std::memory_order_relaxed);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_puppet_fire_class_set_fail.fetch_add(
                1, std::memory_order_relaxed);
        }
    }

    // --- Step 3: resolve CombatAimController + write aim target (Scenario A only) ---
    void* aim_ctrl = resolve_actor_aim_controller_for_slot(
        raider_actor, static_cast<std::uint32_t>(slot));
    if (aim_ctrl) {
        aim_set_target(aim_ctrl, target_x, target_y, target_z);
        g_puppet_fire_aim_resolved.fetch_add(1, std::memory_order_relaxed);
        if (call_n < 10) {
            FW_LOG("engine: fire_actor_at_target #%llu actor=%p slot=%d "
                   "aim_ctrl=%p target=(%.1f,%.1f,%.1f) [Scenario A]",
                   static_cast<unsigned long long>(call_n), raider_actor,
                   slot, aim_ctrl, target_x, target_y, target_z);
        }
    } else {
        // Build 60.1 fix #2 (2026-05-24) — Scenario B early-bail.
        //
        // Without an AimController, Stage-4 (sub_140479680 Projectile::Launch)
        // dereferences fields on the actor's combat extension that the synth
        // failed to populate for this raider. Observed live in Build 60:
        // 6 consecutive AV @ RVA 0x479F67 addr=0x260, all on the same
        // Scenario B raider, in ~4 seconds (puppet retries every 0.8s).
        // SEH-recovered by fire_actor_weapon's wrapper, but each AV corrupts
        // engine state cumulatively and contributes to downstream crashes
        // (vtable corruption → EXEC fault on event_dispatch_guard).
        //
        // Stage-4 silent-no-ops when aim is not set anyway (no projectile,
        // no muzzle, no audio). So we lose NOTHING by skipping the call,
        // and we eliminate the cumulative AV cascade.
        //
        // Future B-phase work: investigate why synth fails for these
        // raiders (only 3/5 succeed). Until then, Scenario B raiders
        // are silent on this client.
        g_puppet_fire_aim_missing.fetch_add(1, std::memory_order_relaxed);
        if (call_n < 10) {
            FW_DBG("engine: fire_actor_at_target #%llu actor=%p slot=%d "
                   "aim_ctrl=NULL — SKIPPING fire_actor_weapon to avoid "
                   "Stage-4 AV @ 0x479F67+0x260 cascade [Scenario B early-bail]",
                   static_cast<unsigned long long>(call_n),
                   raider_actor, slot);
        }
        return false;  // no fire, no crash
    }

    // --- Step 4: fire (WeaponFireHandler → Stage-3 → Stage-4) ---
    const bool fire_ok = fire_actor_weapon(raider_actor);
    if (fire_ok) {
        g_puppet_fire_handler_ok.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_puppet_fire_handler_fail.fetch_add(1, std::memory_order_relaxed);
    }

    // Heartbeat every 100 calls
    if ((call_n % 100) == 0 && call_n != 0) {
        FW_DBG("engine: puppet-fire heartbeat #%llu  aim_resolved=%llu "
               "aim_missing=%llu class_ok=%llu class_fail=%llu "
               "handler_ok=%llu handler_fail=%llu",
               static_cast<unsigned long long>(call_n),
               g_puppet_fire_aim_resolved.load(std::memory_order_relaxed),
               g_puppet_fire_aim_missing.load(std::memory_order_relaxed),
               g_puppet_fire_class_set_ok.load(std::memory_order_relaxed),
               g_puppet_fire_class_set_fail.load(std::memory_order_relaxed),
               g_puppet_fire_handler_ok.load(std::memory_order_relaxed),
               g_puppet_fire_handler_fail.load(std::memory_order_relaxed));
    }
    return fire_ok;
}

// ============================================================================
// End PUPPET FIRE PHASE 1
// ============================================================================

// ============================================================================
// PUPPET FIRE PHASE 1.5 — Direct EnterCombat call (2026-05-17).
// Source: re/puppet_fire_phase1/D_AGENT_enter_combat.md
//
// This breaks the chicken-and-egg of "raider needs HighProcess to engage
// ghost, but only enters combat tier via natural perception which doesn't
// see ghost across cells".
//
// We call sub_140CCF810(raider, ghost, NULL) directly. With descriptor=NULL
// the engine runs bilateral hostility (relies on our FORCE-HOSTILE hook in
// ghost_hostility_guard.cpp), then dispatches to one of:
//   - sub_140ED2390 (fresh allocation, cold path)
//   - sub_140ED2490 (alt/merge path)
// Both end at sub_140878640 (combat-extension ctor at Actor+0x328).
//
// Required prior-installed infrastructure (verified existing):
//   - ghost_hostility_guard FORCE-HOSTILE branch  ← present
//   - ghost_combat_force 3 surgical hooks         ← present (dormant — will fire)
//   - Build 35.2 baseForm swap on ghost           ← present
//   - install_fixed_selector_on_raider            ← present
//
// 5 guards required at call time (D agent §5):
//   G5.2 raider.+0x300 (primary aiproc) non-null
//   G5.3 + G5.6 raider+ghost baseForms valid (formType 0x2D or 0x2E, sane
//        faction count)
//   G5.4 combat-disable gate at raider+0x418→+0x1D8 bit 2 must be CLEAR (Build 55b: was 0x208, that was a phantom)
//   G5.5 raider not frozen (+0x2D0 & 0x800)
//   G5.7 distance-snap mitigation (write ghost.pos = raider.pos transient)
//
// Returns true if Actor+0x328 was populated post-call (= success).
// ============================================================================

namespace {

// Local baseform validator — mirrors the one further down at line ~5012 but
// inlined here to avoid a forward declaration. SEH-caged.
inline bool ec_actor_baseform_valid(void* actor) noexcept {
    if (!actor) return false;
    __try {
        const auto baseform = *reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<std::uint8_t*>(actor) + 0xE0);
        if (!baseform) return false;
        const std::uint8_t formType =
            *reinterpret_cast<std::uint8_t*>(baseform + 0x1A);
        if (formType != 0x2D && formType != 0x2E) return false;
        const std::uint32_t fcount =
            *reinterpret_cast<std::uint32_t*>(baseform + 0xB8 + 0x10);
        return fcount <= 4096;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool enter_combat_raider_vs_ghost(void* raider_actor,
                                  void* ghost_actor,
                                  bool is_player) noexcept
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!g_enter_combat) {
        FW_WRN("enter_combat: fn pointer not resolved");
        return false;
    }
    if (!raider_actor || !ghost_actor || raider_actor == ghost_actor) {
        return false;
    }

    // -----------------------------------------------------------
    // Build 62.4 — DEDUP pre-flight (crash prevention, safety net).
    //
    // Server is authoritative for the perception trigger emission policy
    // (sphere range, debounce window, cross-cell filter). This set merely
    // catches the case where server re-emits despite acquisition state —
    // returning true immediately so we don't call install_fixed_selector
    // again. Without this, the Build 62.3 test froze Client A after 13
    // re-trigger drains × 2 raiders = 26 redundant install_fixed_selector
    // calls inflated known_targets[] and choked the AI tick during a
    // teleport-induced cell load.
    // -----------------------------------------------------------
    const std::uint64_t engaged_key =
        make_engaged_key(raider_actor, ghost_actor);
    if (engaged_pair_exists(engaged_key)) {
        const auto dn = g_enter_combat_dedup_skip.fetch_add(
            1, std::memory_order_relaxed);
        if (dn < 5 || (dn % 100) == 0) {
            FW_DBG("enter_combat dedup-skip #%llu raider=%p ghost=%p "
                   "(pair already engaged)",
                   static_cast<unsigned long long>(dn),
                   raider_actor, ghost_actor);
        }
        return true;
    }

    // -----------------------------------------------------------
    // Build 62.4 — DISTANCE hard ceiling (crash prevention, safety net).
    //
    // Engine combat tier with a target across cells (Concord raider vs
    // Sanctuary peer at ~30000 units) caused the Build 62.3 freeze:
    // combat AI pathfinding to an unreachable target during cell
    // load/unload race. Server filters cross-cell pairs, this is the
    // client-side floor in case the server policy fails open.
    //
    // 4000 units ≈ 57m, which is roughly weapon engagement range for
    // raider rifles and well within line-of-sight feasibility. Anything
    // beyond is not a meaningful combat engagement anyway.
    // -----------------------------------------------------------
    {
        float rp[3] = {0, 0, 0}, gp[3] = {0, 0, 0};
        bool ok = false;
        __try {
            std::memcpy(rp,
                reinterpret_cast<std::uint8_t*>(raider_actor) + 0xD0,
                sizeof(rp));
            std::memcpy(gp,
                reinterpret_cast<std::uint8_t*>(ghost_actor) + 0xD0,
                sizeof(gp));
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
        }
        if (!ok) {
            g_enter_combat_refused_distance.fetch_add(
                1, std::memory_order_relaxed);
            return false;
        }
        const float dx = rp[0] - gp[0];
        const float dy = rp[1] - gp[1];
        const float dz = rp[2] - gp[2];
        const float dist_sq = dx * dx + dy * dy + dz * dz;
        constexpr float HARD_RANGE = 4000.0f;
        if (dist_sq > HARD_RANGE * HARD_RANGE) {
            const auto rn = g_enter_combat_refused_distance.fetch_add(
                1, std::memory_order_relaxed);
            if (rn < 5 || (rn % 100) == 0) {
                FW_DBG("enter_combat refused-distance #%llu raider=%p "
                       "ghost=%p dist=%.1f > HARD_RANGE=%.1f",
                       static_cast<unsigned long long>(rn),
                       raider_actor, ghost_actor,
                       std::sqrt(dist_sq), HARD_RANGE);
            }
            return false;
        }
    }

    const auto n = g_enter_combat_calls.fetch_add(
        1, std::memory_order_relaxed);

    // -----------------------------------------------------------
    // G5.3 + G5.6 — baseForm sanity on BOTH actors.
    // -----------------------------------------------------------
    if (!ec_actor_baseform_valid(raider_actor) ||
        !ec_actor_baseform_valid(ghost_actor))
    {
        g_enter_combat_refused_baseform.fetch_add(
            1, std::memory_order_relaxed);
        if (n < 10) {
            FW_DBG("enter_combat #%llu refused: bad baseform "
                   "raider=%p ghost=%p",
                   static_cast<unsigned long long>(n),
                   raider_actor, ghost_actor);
        }
        return false;
    }

    // -----------------------------------------------------------
    // G5.2 — raider primary aiproc (+0x300) must be allocated.
    // (HighProcess at +0x328 is what we're TRYING to allocate; the
    // PRIMARY aiproc at +0x300 must already exist — engine uses it
    // for the combat-disable read at +0x208 chain.)
    // -----------------------------------------------------------
    void* raider_aip = nullptr;
    __try {
        raider_aip = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x300);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_enter_combat_refused_aiproc.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }
    if (!raider_aip) {
        g_enter_combat_refused_aiproc.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    // -----------------------------------------------------------
    // G5.5 — raider not frozen (+0x2D0 bit 0x800).
    // -----------------------------------------------------------
    std::uint32_t flags_2D0 = 0;
    __try {
        flags_2D0 = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x2D0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if ((flags_2D0 & 0x800u) != 0) {
        g_enter_combat_refused_frozen.fetch_add(
            1, std::memory_order_relaxed);
        if (n < 5) {
            FW_DBG("enter_combat #%llu raider=%p frozen +0x2D0=0x%x",
                   static_cast<unsigned long long>(n), raider_actor,
                   flags_2D0);
        }
        return false;
    }

    // -----------------------------------------------------------
    // G5.4 — combat-disable gate. If `*(Actor+0x418)+0x1D8 & 2` is
    // SET, EnterCombat (sub_140CCF810) falls into sub_140D00D50
    // (animation archetype / fear behavior) which does NOT allocate
    // HighProcess.
    //
    // Build 55b (2026-05-23) — OFFSET FIX 0x208 → 0x418.
    //
    // Original D agent dossier (re/puppet_fire_phase1/D_AGENT_enter_combat.md)
    // mis-converted the IDA pseudo-C expression `a1[65].m128_u64[1]`
    // to byte offset 0x208. Correct math: a1 is __m128*, each element
    // is 16 bytes wide → a1[65] starts at 65×16 = 1040 = 0x410; the
    // `.m128_u64[1]` selects the second qword inside that 16-byte
    // block → +8. Net: **byte offset 1048 = 0x418**, NOT 0x208.
    //
    // Verified by re/strada_C_G54_gate/AGENT_g54_analysis.md:
    //   - sub_140CCF810:4549 (the gate) — IDA shows `a1[65].m128_u64[1]`
    //   - sub_140CCF810:10203 + sub_140CCFD40:6483 + sub_140C7A370:3965
    //     read the SAME field using raw decimal `+ 1048` (= 0x418)
    //   - Six independent FalloutWorld RE dossiers identify
    //     Actor+0x418 as `TESRace.MovementType` (race-shared) or its
    //     per-instance override (post-perk init).
    //   - Vanilla Concord raiders aggro player_A in singleplayer →
    //     bit-2 of (raider+0x418)+0x1D8 must be CLEAR for them.
    //   - Build 45 telemetry "5/5 refused" with our +0x208 read was
    //     reading RANDOM memory whose bit-2 happens to be set; engine
    //     was simultaneously taking the ALLOC branch via the correct
    //     +0x418 field (confirmed by "fixed-sel succeeded 5/5 because
    //     raiders ALREADY had HighProcess").
    //
    // Consequence: Strada B.2 synthesize_combat_extension_for_ghost_target
    // was built to bypass a gate that wasn't actually blocking us. The
    // synth still works (calls sub_140ED2390 internally — same thing
    // vanilla EnterCombat would have done), so keep as belt-and-braces
    // Tier 2 fallback in the 3-tier pipeline at apply_npc_combat_target.
    // With this offset fix, Tier 1 (this function) should succeed for
    // typical Concord raiders and Tier 2 will rarely fire.
    //
    // Polarity verified correct: bit CLEAR → engine ALLOC branch →
    // we set gate_ok=true and call EnterCombat. bit SET → engine ALT
    // path (no alloc) → we set gate_ok=false and refuse.
    // -----------------------------------------------------------
    bool gate_ok = false;
    __try {
        std::uintptr_t race_movement = *reinterpret_cast<std::uintptr_t*>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x418);
        if (race_movement) {
            std::uint32_t f = *reinterpret_cast<std::uint32_t*>(
                race_movement + 0x1D8);
            gate_ok = ((f & 2u) == 0);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        gate_ok = false;
    }
    if (!gate_ok) {
        const auto rn = g_enter_combat_refused_gate.fetch_add(
            1, std::memory_order_relaxed);
        if (rn < 5 || (rn % 100) == 0) {
            FW_WRN("enter_combat: combat-disable gate fails for raider=%p "
                   "(Actor+0x418→+0x1D8 & 2 set, Build 55b corrected offset) "
                   "— refusing call #%llu",
                   raider_actor,
                   static_cast<unsigned long long>(rn));
        }
        return false;
    }

    // -----------------------------------------------------------
    // G5.10 — re-entry idempotency. If raider already has +0x328,
    // route to the AddCombatTarget primitive instead of re-calling
    // EnterCombat (which on existing-target would trigger the
    // sub_14087A320 destructive rewire).
    // -----------------------------------------------------------
    void* existing_highproc = nullptr;
    __try {
        existing_highproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x328);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (existing_highproc) {
        // c.45 FIX 1a — for the REAL player we do NOT install the ghost-specific
        // fixed-selector/combat-force machinery (the vanilla AI keeps a real
        // player as target on its own). Raider already in combat → done.
        if (is_player) return true;
        g_enter_combat_already_in_combat.fetch_add(
            1, std::memory_order_relaxed);
        if (n < 10) {
            FW_DBG("enter_combat #%llu raider=%p already in combat "
                   "(+0x328=%p) — routing to install_fixed_selector",
                   static_cast<unsigned long long>(n), raider_actor,
                   existing_highproc);
        }
        const bool fs_ok =
            install_fixed_selector_on_raider(raider_actor, ghost_actor);
        // Build 62.4 — mark pair engaged on FIRST already-in-combat hit so
        // future re-triggers short-circuit at the dedup pre-flight above.
        if (fs_ok) {
            engaged_pair_insert(engaged_key);
            // Build 62.9 — also register fid in native-combat set so the
            // 4 legacy motion-writer hooks skip their bail for this raider.
            // Also un-keyframe the Havok body so engine can move it.
            std::uint32_t fid_ico = 0;
            __try {
                fid_ico = *reinterpret_cast<std::uint32_t*>(
                    reinterpret_cast<std::uint8_t*>(raider_actor) + 0x14);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (fid_ico != 0 && fid_ico != 0xFFFFFFFFu) {
                native_combat_fid_insert(fid_ico);
            }
            set_actor_motion_dynamic(raider_actor);
        }
        return fs_ok;
    }

    // -----------------------------------------------------------
    // G5.7 — distance pre-snap. Read raider.pos, save ghost.pos,
    // write ghost.pos = raider.pos to satisfy the perception-
    // radius gate inside EnterCombat. Restored on return.
    // -----------------------------------------------------------
    float raider_pos[3] = {0, 0, 0};
    float saved_ghost_pos[3] = {0, 0, 0};
    bool ghost_pos_snapped = false;
    // c.45 FIX 1a — SKIP the pre-snap for the REAL player: we must NOT move the
    // player to the raider's pos. The raider was just MoveTo'd beside the player
    // by the c.44 handoff, so the distance/perception gate passes anyway.
    if (!is_player)
    __try {
        std::memcpy(raider_pos,
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0xD0,
            sizeof(raider_pos));
        std::memcpy(saved_ghost_pos,
            reinterpret_cast<std::uint8_t*>(ghost_actor) + 0xD0,
            sizeof(saved_ghost_pos));
        std::memcpy(
            reinterpret_cast<std::uint8_t*>(ghost_actor) + 0xD0,
            raider_pos, sizeof(raider_pos));
        ghost_pos_snapped = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Fall through — try EnterCombat anyway. If distance gate
        // rejects, we'll know via post-alloc check.
    }

    // -----------------------------------------------------------
    // THE CALL.
    // -----------------------------------------------------------
    char rc = 0;
    __try {
        rc = g_enter_combat(raider_actor, ghost_actor, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = g_enter_combat_seh.fetch_add(
            1, std::memory_order_relaxed);
        FW_ERR("enter_combat SEH #%llu raider=%p ghost=%p",
               static_cast<unsigned long long>(sn), raider_actor,
               ghost_actor);
        rc = 0;
    }

    // Restore ghost.pos regardless of rc — caller can re-write to peer pos.
    if (ghost_pos_snapped) {
        __try {
            std::memcpy(
                reinterpret_cast<std::uint8_t*>(ghost_actor) + 0xD0,
                saved_ghost_pos, sizeof(saved_ghost_pos));
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // -----------------------------------------------------------
    // Post-call verification: Actor+0x328 MUST be non-null on success.
    // If rc != 0 but +0x328 stays NULL, EnterCombat took the
    // sub_140D00D50 alt-path which doesn't allocate. Same outcome
    // for us as a hard fail.
    // -----------------------------------------------------------
    void* new_highproc = nullptr;
    __try {
        new_highproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x328);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!new_highproc) {
        g_enter_combat_post_alloc_null.fetch_add(
            1, std::memory_order_relaxed);
        if (n < 10) {
            FW_WRN("enter_combat #%llu rc=%d but raider.+0x328 stayed NULL "
                   "(raider=%p ghost=%p) — fell into sub_140D00D50 alt-path "
                   "or alloc failed",
                   static_cast<unsigned long long>(n), static_cast<int>(rc),
                   raider_actor, ghost_actor);
        }
        return false;
    }

    // c.45 FIX 1a — for the REAL player, EnterCombat has allocated HighProcess +
    // set the player as combat target; the vanilla combat group forms naturally
    // around a real target (no teardown risk → no AddAlly/fixed-selector needed —
    // that is the ghost-specific machinery with the c.25/c.33 crash history).
    if (is_player) return true;

    // -----------------------------------------------------------
    // SUCCESS. Register the controller in our combat-force sets so
    // alive-counter / post-pick / cell-loaded overrides start
    // firing immediately on the next per-frame tick.
    //
    // install_fixed_selector_on_raider handles dedup (per-aiproc set)
    // and also calls AddCombatTarget which is now guaranteed to
    // succeed because controller+aiproc both exist.
    // -----------------------------------------------------------
    void* controller = nullptr;
    __try {
        controller = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(new_highproc) +
            offsets::AIPROCESS_CONTROLLER_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (controller) {
        // ============================================================
        // Build 63 (2026-05-25) — ADD ALLY (THE actual fix).
        //
        // Per re/walker_audit_v2/SUPERVISOR_SYNTHESIS.md + Agent C
        // (funcs_0344.md:6557-6562): the fresh-alloc branch of
        // sub_140ED2390 (the path CCF810 takes when raider has no prior
        // HighProcess) calls AddTarget(ghost) but NEVER calls AddAlly.
        // Without this, controller+0x20 allies[] stays empty,
        // sub_140E9E650 alive-counter writes controller+0x110=0 every
        // frame, engine tears combat group down within 2-3 frames.
        //
        // This is the SINGLE missing function call that explains the
        // entire "raider red marker + 1-2 step + idle" symptom user
        // reported Build 62.9 / 62.12.
        //
        // Judge confidence: 65% this alone fixes engagement; 88% with
        // CombatAimController synthesis if rotation/aim still broken.
        // ============================================================
        if (g_add_ally_to_ctrl) {
            const auto n = g_add_ally_calls.fetch_add(
                1, std::memory_order_relaxed);
            std::int64_t ally_rc = 0;
            __try {
                ally_rc = g_add_ally_to_ctrl(controller, raider_actor);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                g_add_ally_seh.fetch_add(1, std::memory_order_relaxed);
                FW_ERR("enter_combat: SEH in AddAlly(ctrl=%p raider=%p)",
                       controller, raider_actor);
                ally_rc = 0;
            }
            FW_LOG("enter_combat #%llu AddAlly(ctrl=%p raider=%p) rc=%lld "
                   "(Build 63 — allies[] populated so engine doesn't "
                   "tear down combat group on alive-counter=0)",
                   static_cast<unsigned long long>(n),
                   controller, raider_actor,
                   static_cast<long long>(ally_rc));
        } else {
            FW_WRN("enter_combat: g_add_ally_to_ctrl unresolved at "
                   "SUCCESS path — Build 63 fix won't fire, raider "
                   "will collapse to idle in 2-3 frames");
        }

        // This populates g_ghost_combat_controllers + g_ghost_engaged_raider_fids.
        // After this returns, the ghost_combat_force surgical hooks become live.
        install_fixed_selector_on_raider(raider_actor, ghost_actor);
    }

    // Build 62.8 (2026-05-25) — UN-keyframe the raider's Havok body.
    //
    // npc_ai_suppress keyframes every raider at cell-load when
    // movement_override=1 (puppet-fire era assumption: server pos sync,
    // no engine combat tier). Now that natural CCF810 succeeded, the
    // engine WILL try to path/move this raider; the keyframed Havok
    // body would block its motion → "raider stationary like a log".
    // Setting motion back to Dynamic unlocks movement. SEH-caged inside
    // the function. Counter-free (cheap, fires once per raider on the
    // initial dedup-passing SUCCESS path).
    set_actor_motion_dynamic(raider_actor);

    // Build 62.9 (2026-05-25) — REGISTER fid in native-combat set.
    //
    // Required so the 4 legacy motion-writer hooks
    // (ghost_ai_havok_step, ghost_ai_movement, ghost_ai_pos_belt,
    // ghost_ai_actor_setpos) can SKIP THEIR BAIL when this raider
    // is in native combat. Without this, they continue to see
    // cache.movement_override=1 (puppet-fire flag from raider_brain)
    // and freeze the Havok body at every tick → raider stationary
    // even after Build 62.8 un-keyframed it (the Dynamic motion gets
    // re-locked by these motion-writer bails per frame).
    std::uint32_t raider_fid_for_set = 0;
    __try {
        raider_fid_for_set = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x14);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (raider_fid_for_set != 0 && raider_fid_for_set != 0xFFFFFFFFu) {
        native_combat_fid_insert(raider_fid_for_set);
    }

    // Build 62.4 — mark pair engaged so future re-triggers short-circuit
    // at the dedup pre-flight. Critical: insert ONLY after CCF810 +
    // install_fixed_selector have both run, so re-call doesn't skip a
    // pipeline that wasn't completed.
    engaged_pair_insert(engaged_key);

    const auto sn = g_enter_combat_success.fetch_add(
        1, std::memory_order_relaxed);
    FW_LOG("enter_combat #%llu SUCCESS raider=%p ghost=%p highproc=%p "
           "controller=%p rc=%d (engaged_pairs now=%zu)",
           static_cast<unsigned long long>(sn), raider_actor, ghost_actor,
           new_highproc, controller, static_cast<int>(rc),
           engaged_pair_count());
    return true;
}

// ============================================================================
// End PUPPET FIRE PHASE 1.5
// ============================================================================

// ============================================================================
// STRADA B.2 — Manual HighProcess + CombatAimController synthesis (Build 51).
// Source: re/strada_B2_synthesize_highprocess/SUPERVISOR_SYNTHESIS.md
// 4-agent RE arena 2026-05-22, aggregate confidence 85% YELLOW.
//
// Why this exists:
//   Builds 45/47/50 live tests proved sub_140CCF810 (EnterCombat) refuses
//   5/5 Concord raiders via the combat-disable gate at line 4549
//   (Actor+0x208+0x1D8 & 2 == 1). Gate lives in EnterCombat preamble, NOT
//   in the underlying allocation orchestrator sub_140ED2390.
//
// Strategy: call sub_140ED2390 DIRECTLY. That function runs:
//   1. TLS frame counter (recursion guard).
//   2. If actor+0x328 != NULL → AddTarget on existing controller; return.
//   3. sub_140C7ABC0 bilateral hostility predicate. Our FORCE-HOSTILE hook
//      on sub_140C8DFF0 intercepts the inner sub_140C7AD40 call.
//   4. sub_140ED44F0(CombatManager) — alloc fresh CombatController (0x128 B).
//   5. AddAlly(observer) + AddTarget(target). On fail → destroy group; return 0.
//   6. Engine heap alloc 0x190 bytes for HighProcess buffer.
//   7. sub_140878640(buf, observer, ctrl) — HighProcess ctor. Allocates 4
//      mandatory sub-objects (0x50+0xC0+0x1F8+0x78 = 896 B) + Standard
//      selector at +0x118, registers owner handle at +0x68, 2 event-bus
//      sinks via sub_140975030.
//   8. *(observer + 0x328) = result.
//
// After HighProcess is wired, we ALSO synthesize 2 CombatAimController
// instances at HighProcess+0x98 BSTArray via sub_140E653D0. The ctor
// self-registers via sub_14087CFA0 but leaves +0x30 (slot_filter) and
// +0x34 (flags) zero — we set them post-ctor so the scanner sub_14087D190
// predicate matches. Two variants cover wstate_flag=0 (slot only) and
// wstate_flag=1 (slot | 0x100) cases.
//
// Returns true when (a) Actor+0x328 non-null post-call AND (b) at least
// one CombatAimController constructed for the raider's weapon slot.
//
// Cost per call: ~880 bytes engine heap.
// Thread safety: MAIN THREAD ONLY. Caller responsible for dispatch.
// ============================================================================

// ============================================================================
// Build 62 (2026-05-24) — `trigger_npc_perception` thin wrapper.
//
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md (P-ALPHA wins, S-BETA
// confirms): sub_140CCF810 IS the canonical EnterCombat. Calling it
// with (observer, target, NULL) makes engine allocate HighProcess +
// CombatController + AddTarget in 1 frame.
//
// This wrapper renames the (raider, ghost) parameter pair to the more
// general (observer, target) — semantically reflects the new design
// where server's proximity sphere triggers any NPC to perceive any
// peer's ghost, not just "raiders vs the ghost duplicate". The
// underlying implementation is the same as enter_combat_raider_vs_ghost.
//
// Used by main_thread_dispatch::handle_npc_perception_trigger to apply
// server-pushed MSG_NPC_PERCEPTION_TRIGGER events.
//
// MAIN THREAD ONLY (same constraint as enter_combat_raider_vs_ghost).
// ============================================================================
bool trigger_npc_perception(void* observer_actor,
                            void* target_actor) noexcept
{
    return enter_combat_raider_vs_ghost(observer_actor, target_actor);
}

// ============================================================================
// Build 62 — posture detection helpers.
//
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md §3 (C-ALPHA wins,
// C-BETA concedes): Actor + 0x134 high nibble bits 11-13 encode
// movement state. Mask 0x3800, sneak value 0x800. Triple-verified:
//   1. Papyrus Actor.IsSneaking native body reads exactly this mask
//   2. Combat orchestrator reads same field for ally posture gating
//   3. Actor::SetSneaking writer flips bits 11-13 as final commit
//
// Lock-free, 2 instructions, frame-perfect. No anim graph lookup
// needed (anim graph variable iIsInSneak is DOWNSTREAM replica of
// this flag — flag is master, set BEFORE anim graph var per
// sub_140CA6220).
// ============================================================================
namespace {
inline constexpr std::size_t   ACTOR_MOVEMENT_STATE_OFF = 0x134;
inline constexpr std::uint32_t MOVEMENT_STATE_MASK      = 0x3800;
inline constexpr std::uint32_t MOVEMENT_STATE_STAND     = 0x0000;
inline constexpr std::uint32_t MOVEMENT_STATE_SNEAK     = 0x0800;
inline constexpr std::uint32_t MOVEMENT_STATE_WALK      = 0x1000;
inline constexpr std::uint32_t MOVEMENT_STATE_RUN       = 0x1800;
inline constexpr std::uint32_t MOVEMENT_STATE_SPRINT    = 0x2000;
} // namespace

bool is_actor_sneaking(const void* actor) noexcept {
    if (!actor) return false;
    std::uint32_t bits = 0;
    __try {
        bits = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            ACTOR_MOVEMENT_STATE_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return (bits & MOVEMENT_STATE_MASK) == MOVEMENT_STATE_SNEAK;
}

std::uint8_t read_actor_posture_byte(const void* actor) noexcept {
    if (!actor) return 0;
    std::uint32_t bits = 0;
    __try {
        bits = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            ACTOR_MOVEMENT_STATE_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    switch (bits & MOVEMENT_STATE_MASK) {
        case MOVEMENT_STATE_SNEAK:  return 1;
        case MOVEMENT_STATE_WALK:   return 2;
        case MOVEMENT_STATE_RUN:    return 3;
        case MOVEMENT_STATE_SPRINT: return 4;
        default:                    return 0;  // Stand
    }
}

bool synthesize_combat_extension_for_ghost_target(
    void* raider_actor,
    void* ghost_actor,
    float target_x, float target_y, float target_z) noexcept
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!raider_actor || !ghost_actor || raider_actor == ghost_actor) {
        return false;
    }

    const auto n = g_synth_calls.fetch_add(1, std::memory_order_relaxed);

    // ---- PRECONDITION 1 — fn pointers resolved ----
    if (!g_combat_promoter_fresh || !g_aim_ctrl_ctor ||
        !g_engine_heap_alloc || !g_engine_heap_desc ||
        !g_procmgr_bag || !g_aim_set_target) {
        FW_WRN("synth #%llu: fn pointers not resolved "
               "(prom=%p ctor=%p alloc=%p desc=%p bag=%p aimset=%p)",
               static_cast<unsigned long long>(n),
               reinterpret_cast<void*>(g_combat_promoter_fresh),
               reinterpret_cast<void*>(g_aim_ctrl_ctor),
               reinterpret_cast<void*>(g_engine_heap_alloc),
               g_engine_heap_desc,
               static_cast<void*>(g_procmgr_bag),
               reinterpret_cast<void*>(g_aim_set_target));
        return false;
    }

    // ---- PRECONDITION 2 — baseForm sanity (reuse 5-guard pattern) ----
    if (!ec_actor_baseform_valid(raider_actor) ||
        !ec_actor_baseform_valid(ghost_actor))
    {
        g_synth_refused_baseform.fetch_add(1, std::memory_order_relaxed);
        if (n < 10) {
            FW_DBG("synth #%llu refused: bad baseform raider=%p ghost=%p",
                   static_cast<unsigned long long>(n),
                   raider_actor, ghost_actor);
        }
        return false;
    }

    // ---- PRECONDITION 3 — primary aiproc (+0x300) must exist ----
    // sub_140878640's Phase E.6 reads `a2+0x300+0xE1` — NULL deref AVs.
    void* raider_aip = nullptr;
    __try {
        raider_aip = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x300);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_synth_refused_aiproc.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (!raider_aip) {
        g_synth_refused_aiproc.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // ---- PRECONDITION 4 — raider not frozen ----
    std::uint32_t flags_2D0 = 0;
    __try {
        flags_2D0 = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x2D0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if ((flags_2D0 & 0x800u) != 0) {
        g_synth_refused_frozen.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // ---- PRECONDITION 5 — re-entry idempotency ----
    void* existing_highproc = nullptr;
    __try {
        existing_highproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(raider_actor) + 0x328);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    bool synthesized_highproc = false;

    if (!existing_highproc) {
        // ----------------------------------------------------------
        // STEP A — call sub_140ED2390 to allocate HighProcess + wire.
        //
        // CombatManager singleton @ qword_1430DBF78[135939].
        // ----------------------------------------------------------
        void* combat_manager = nullptr;
        __try {
            combat_manager = g_procmgr_bag[offsets::COMBAT_MANAGER_BAG_INDEX];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("synth #%llu SEH reading CombatManager from bag idx=%zu",
                   static_cast<unsigned long long>(n),
                   offsets::COMBAT_MANAGER_BAG_INDEX);
            return false;
        }
        if (!combat_manager) {
            FW_WRN("synth #%llu: CombatManager singleton is NULL — "
                   "engine combat subsystem not initialized?",
                   static_cast<unsigned long long>(n));
            return false;
        }

        char rc = 0;
        __try {
            rc = g_combat_promoter_fresh(combat_manager, raider_actor,
                                         ghost_actor);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const auto sn = g_synth_seh.fetch_add(
                1, std::memory_order_relaxed);
            FW_ERR("synth #%llu SEH in sub_140ED2390 raider=%p ghost=%p "
                   "(seh_total=%llu)",
                   static_cast<unsigned long long>(n),
                   raider_actor, ghost_actor,
                   static_cast<unsigned long long>(sn));
            return false;
        }

        // Verify allocation happened.
        void* new_highproc = nullptr;
        __try {
            new_highproc = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(raider_actor) + 0x328);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (!new_highproc) {
            g_synth_ed2390_failed.fetch_add(1, std::memory_order_relaxed);
            if (n < 10) {
                FW_WRN("synth #%llu: sub_140ED2390 rc=%d but +0x328 stayed "
                       "NULL — hostility predicate refused or alloc OOM",
                       static_cast<unsigned long long>(n),
                       static_cast<int>(rc));
            }
            return false;
        }
        existing_highproc = new_highproc;
        synthesized_highproc = true;

        // ------------------------------------------------------
        // Agent 1 §8.1 step 6 — sticky skip-tick flag at +0x189.
        // Makes the post-pick gate (sub_14087A900 family) short-
        // circuit BEFORE it dereferences potentially-stale fields
        // like +0x118 selector or +0x180 cached primary. Defense
        // in depth alongside ghost_combat_force post-pick hook.
        // ------------------------------------------------------
        __try {
            *reinterpret_cast<std::uint8_t*>(
                reinterpret_cast<std::uint8_t*>(new_highproc) +
                offsets::HIGHPROC_SKIP_TICK_FLAG_OFF) = 1;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        FW_LOG("synth #%llu STEP A OK: raider=%p ghost=%p +0x328=%p "
               "(rc=%d, skip-tick set at +0x189)",
               static_cast<unsigned long long>(n),
               raider_actor, ghost_actor, new_highproc,
               static_cast<int>(rc));
    } else {
        g_synth_already_in_combat.fetch_add(1, std::memory_order_relaxed);
        // Re-entry — still need ghost in known_targets[].
        install_fixed_selector_on_raider(raider_actor, ghost_actor);

        // Build 61.2 (2026-05-24) — REVERTED Build 61.1 early return.
        //
        // Build 61.1 added `return true` here to prevent Steps B/C from
        // re-allocating ctrl_main on defensive-synth re-entry. Live test
        // proved this BROKE the normal flow: apply_npc_combat_target
        // calls Tier 1 (enter_combat) which allocates HighProcess, THEN
        // Tier 2 (synth) which sees existing_highproc != null and took
        // this re-entry branch — early-returning BEFORE Steps B/C could
        // run. Result: NO ctrl_main allocated for ANY raider → all
        // Scenario B → no puppet fire → main thread freeze + B crash.
        //
        // Correct fix: keep this branch FALL-THROUGH to Steps B/C as in
        // Build 60.1. The defensive-synth idempotency is moved to the
        // CALLER side (npc_fire_with_ghost_aim) which checks the
        // is_ghost_engaged_raider_fid set BEFORE calling synth at all.
        // That way:
        //   - Normal flow (apply_npc_combat_target): enter_combat allocates
        //     HighProcess, synth fall-throughs to Steps B/C, ctrl_main
        //     allocated. ✓
        //   - Defensive flow (npc_fire_with_ghost_aim first time): caller
        //     sees raider NOT in ghost-engaged set yet → calls enter_combat
        //     + synth → Steps B/C run → ctrl_main allocated. ✓
        //   - Defensive flow (re-call for already-synth'd raider): caller
        //     sees raider IS in ghost-engaged set → SKIPS enter_combat +
        //     synth entirely → no duplicate ctrl_main. ✓
        //
        // No early return. Just diagnostic log.
        if (n < 10) {
            FW_LOG("synth #%llu: existing HighProcess (+0x328=%p) — "
                   "install_fixed_selector + falling through to Steps B/C "
                   "(Build 60.1 normal flow, Build 61.1 early-return REVERTED)",
                   static_cast<unsigned long long>(n), existing_highproc);
        }
    }

    // ---- STEP B — resolve weapon slot ----
    alignas(8) std::int64_t zero_arg[2] = {0, 0};
    int slot = -1;
    if (g_resolve_weapon_slot) {
        __try { g_resolve_weapon_slot(raider_actor, &slot, zero_arg); }
        __except (EXCEPTION_EXECUTE_HANDLER) { slot = -1; }
    }
    if (slot == -1) {
        FW_DBG("synth #%llu: no weapon slot resolved — HighProcess synth'd "
               "but aim controller skipped",
               static_cast<unsigned long long>(n));
        return synthesized_highproc;  // partial success
    }

    // ---- STEP C — synthesize 2 CombatAimController variants ----
    // The aim solver's slot_key formula is `slot | (wstate_flags << 8)`.
    // For idle wstate (=0) → slot_key = slot. For wstate=1 → slot|0x100.
    // Register both to cover the wstate transition window.
    auto synth_one_controller =
        [&](std::uint32_t slot_filter) -> void* {
        void* ctrl_buf = nullptr;
        __try {
            ctrl_buf = g_engine_heap_alloc(g_engine_heap_desc, 0x40, 0, 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
        if (!ctrl_buf) {
            g_synth_aim_alloc_failed.fetch_add(
                1, std::memory_order_relaxed);
            return nullptr;
        }

        __try {
            // Ctor: self, parent HighProcess, type_tag=1 (gun).
            g_aim_ctrl_ctor(ctrl_buf, existing_highproc, 1);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_synth_aim_ctor_seh.fetch_add(
                1, std::memory_order_relaxed);
            return nullptr;
        }

        // Bump refcount (NiRefObject convention; ctor leaves 0).
        __try {
            _InterlockedIncrement(
                reinterpret_cast<volatile long*>(
                    reinterpret_cast<std::uint8_t*>(ctrl_buf) +
                    offsets::AIM_CTRL_REFCOUNT_OFF));
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        // Write slot_filter at +0x30 and flag bit 0 at +0x34.
        // CRITICAL: ctor leaves these zero. Scanner sub_14087D190
        // predicate is `entry+0x30 == slot_key AND (entry+0x34 & 1)`.
        __try {
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(ctrl_buf) + 0x30) =
                slot_filter;
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(ctrl_buf) + 0x34) |= 1u;
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        // Write target_pos via engine setter (refreshes +0x38 timestamp
        // and re-OR's flag bit 0 — idempotent and safe).
        alignas(4) float xyz[3] = { target_x, target_y, target_z };
        __try {
            g_aim_set_target(ctrl_buf, xyz);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        return ctrl_buf;
    };

    // Build 60 fix B (2026-05-24) — REMOVED dual-controller registration.
    //
    // Per re/walker_inventory/AGENT_SYNTH_dissection.md §4 the previous
    // dual registration (ctrl_main with slot, ctrl_alt with slot|0x100)
    // caused a double-detach race: engine's CombatAimController cleanup
    // path (sub_14087D050) removes only the FIRST entry matching the
    // slot/wstate filter. The orphan entry persisted until eventually
    // freed by a different path → double-free of the heap buffer →
    // BSTSmallArrayHeapAllocator wrote its freelist marker (0x1) into
    // the now-freed slot's first 8 bytes. That slot happened to be the
    // CombatController.entries_base at +0x08 → all subsequent walkers
    // (sub_140E98820 family + sub_140E96490 + ...) AV'd at addr=0x1.
    //
    // Single-controller registration eliminates the orphan. The
    // wstate-flag variant (slot|0x100) was speculative coverage for
    // "weapon-state class 17" cases; in practice WeaponFireHandler
    // resolves the slot via sub_140CD0A60 internally and accepts the
    // single registered controller.
    void* ctrl_main = synth_one_controller(
        static_cast<std::uint32_t>(slot) & 0xFFu);
    void* ctrl_alt = nullptr;  // intentionally NOT registered (Build 60)

    if (!ctrl_main) {
        FW_WRN("synth #%llu: aim controller ctor failed — HighProcess "
               "synth'd but Stage-4 aim solver will still bail",
               static_cast<unsigned long long>(n));
        return false;
    }

    // ----------------------------------------------------------------
    // STEP D (Build 52) — Force weapon-state class to "firable" (15).
    //
    // NPCs.md §1078 documents Gate B: "sub_140479680 Stage 4 bails when
    // class ∉ {15,16,17}; transitioned by sub_140CD1830 from inside
    // combat orchestrator". Build 51 had synth + AimController + alive-
    // boost + post-pick OVERRIDE all working, but raiders STILL didn't
    // fire because the engine never reached the orchestrator's internal
    // class-transition path. Symptom: HUD "raider" bar flickered
    // hostile/neutral as engine tried to engage then demoted.
    //
    // Calling g_weapon_state_class_setter(raider, slot, 15) directly
    // advances slot_record[+0x38] = 15 (firable). After this, Stage-4
    // (sub_140479680) should pass the class check and emit projectile +
    // muzzle + audio.
    //
    // Same fn pointer used by fire_actor_at_target (puppet-fire path).
    // Idempotent — re-calling on already-class-15 is no-op.
    // ----------------------------------------------------------------
    if (g_weapon_state_class_setter) {
        __try {
            g_weapon_state_class_setter(
                raider_actor, static_cast<std::uint32_t>(slot), 15);
            g_puppet_fire_class_set_ok.fetch_add(
                1, std::memory_order_relaxed);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_puppet_fire_class_set_fail.fetch_add(
                1, std::memory_order_relaxed);
        }
    }

    g_synth_success.fetch_add(1, std::memory_order_relaxed);
    FW_LOG("synth #%llu COMPLETE raider=%p ghost=%p hp=%p slot=%d "
           "ctrl_main=%p ctrl_alt=%p target=(%.1f,%.1f,%.1f) class=15 (Build 52)",
           static_cast<unsigned long long>(n),
           raider_actor, ghost_actor, existing_highproc, slot,
           ctrl_main, ctrl_alt,
           target_x, target_y, target_z);

    // Register raider in combat-force sets so ghost_combat_force
    // overrides become live (dedup'd idempotent call).
    install_fixed_selector_on_raider(raider_actor, ghost_actor);

    return true;
}

std::uint64_t get_synth_calls() {
    return g_synth_calls.load(std::memory_order_relaxed);
}
std::uint64_t get_synth_success() {
    return g_synth_success.load(std::memory_order_relaxed);
}
std::uint64_t get_synth_seh() {
    return g_synth_seh.load(std::memory_order_relaxed);
}

// ============================================================================
// End STRADA B.2
// ============================================================================

// ============================================================================
// BUILD 54 (2026-05-23) — Visual aim alignment for puppet-fire.
//
// Build 53 added per-fire AimController target write via fire_actor_at_target,
// but live test showed:
//   - 98-99% of fires went [Scenario B] (aim_ctrl=NULL) because engine frees
//     synthesized CombatAimControllers when raider "demotes from combat".
//   - Even the 1-2% [Scenario A] fires emitted projectiles in raider's
//     CURRENT FACING direction (NOT toward target_pos).
//   - Reason: Stage-4 (sub_140479680) reads the WEAPON NODE's world
//     forward vector, which is inherited from the raider's upper body
//     rotation. Without anim graph driving the aim pose, weapon stays in
//     the raider's natural idle facing.
//
// Fix per NPC_FIRE event:
//   1. SetRotation(raider, [0, 0, yaw_to_target]) — rotates the actor
//      body so the weapon node inherits the correct forward direction.
//   2. SetGraphVariable(bIsAimingGun = 1) — keeps the upper-body aim
//      anim active so the weapon doesn't snap back to idle.
//   3. SetGraphVariable(bIsAttacking = 1) — drives the fire anim layer.
//
// Math: yaw = atan2(target.x - raider.x, target.y - raider.y).
// Bethesda convention: yaw 0 = facing +Y, positive = clockwise from above.
// atan2(dx, dy) gives the angle clockwise from +Y. CORRECT.
//
// Pitch not currently computed — vertical aim depends on weapon trajectory
// and is best left to the anim graph's aim-direction floats (future
// refinement). For horizontal targets (ghost at similar Z) yaw alone is
// sufficient.
//
// Thread safety: MAIN THREAD ONLY (SetGraphVariable* recurses into smart-
// pointer fetch).
// ============================================================================

bool aim_actor_at_target(void* raider_actor,
                         float target_x, float target_y, float target_z) noexcept
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!raider_actor) return false;
    if (!g_set_rotation_engine) return false;

    // Read raider position from Actor+0xD0.
    float rx = 0.f, ry = 0.f, rz = 0.f;
    __try {
        const auto* pos = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(raider_actor) +
            offsets::POS_OFF);
        rx = pos[0];
        ry = pos[1];
        rz = pos[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    (void)rz;
    (void)target_z;  // not used yet — pitch deferred

    // Compute horizontal vector raider -> target.
    const float dx = target_x - rx;
    const float dy = target_y - ry;
    // Avoid degenerate atan2 when raider is at target (no rotation needed).
    if (dx == 0.f && dy == 0.f) return false;

    // Bethesda yaw convention: 0 = +Y, positive = clockwise from above.
    // atan2(dx, dy) gives the angle clockwise from +Y. Result in radians.
    const float yaw_rad = std::atan2(dx, dy);

    // Apply rotation via engine setter. rot[0]=pitch, rot[1]=roll, rot[2]=yaw.
    float rot[3] = { 0.f, 0.f, yaw_rad };
    static std::atomic<std::uint64_t> s_rot_seh{0};
    __try {
        g_set_rotation_engine(raider_actor, rot);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = s_rot_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("aim_actor_at_target SEH in SetRotation raider=%p "
                   "yaw=%.3f (seh_total=%llu)",
                   raider_actor, yaw_rad,
                   static_cast<unsigned long long>(sn));
        }
        return false;
    }

    // Set anim graph variables to drive aim pose + fire layer.
    // Holder = Actor + 0x48 (IAnimationGraphManagerHolder sub-object).
    if (g_set_graph_var_bool && g_bs_is_aiming_gun.pool_entry) {
        auto* holder = reinterpret_cast<std::uint8_t*>(raider_actor) +
                       offsets::IANIMGRAPHHOLDER_OFF;
        __try {
            g_set_graph_var_bool(holder, &g_bs_is_aiming_gun,
                                 static_cast<char>(1));
            if (g_bs_is_attacking.pool_entry) {
                g_set_graph_var_bool(holder, &g_bs_is_attacking,
                                     static_cast<char>(1));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Anim graph write failure is non-fatal — rotation already
            // landed which is the dominant factor for weapon direction.
        }
    }

    // Build 55f — populate per-fid yaw map for 60Hz rotation re-apply
    // from npc_ai_suppress detour POST orig. This gives smooth visual
    // tracking instead of vanilla AI fighting our rotation at 2Hz.
    //
    // Read raider's form_id and stash the yaw with a 5s expiry. The
    // npc_ai_suppress hook reads this every tick to re-write Actor+0xC0
    // rotation AFTER vanilla AI's rotation pass — effectively making
    // ours the last word per frame.
    std::uint32_t raider_fid = 0;
    __try {
        raider_fid = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(raider_actor) +
            offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raider_fid = 0;
    }
    if (raider_fid != 0 && raider_fid != 0xFFFFFFFFu) {
        constexpr std::uint64_t kYawWindowMs = 5000;
        fw::dispatch::mark_raider_ghost_targeted_yaw(
            raider_fid, yaw_rad,
            static_cast<std::uint64_t>(GetTickCount64()) + kYawWindowMs);
    }

    // First 10 calls log; then heartbeat every 100.
    static std::atomic<std::uint64_t> s_calls{0};
    const auto cn = s_calls.fetch_add(1, std::memory_order_relaxed);
    if (cn < 10) {
        FW_LOG("aim_actor_at_target #%llu raider=%p rpos=(%.1f,%.1f,%.1f) "
               "target=(%.1f,%.1f,%.1f) yaw_rad=%.3f",
               static_cast<unsigned long long>(cn),
               raider_actor, rx, ry, rz,
               target_x, target_y, target_z, yaw_rad);
    } else if ((cn % 100) == 0) {
        FW_DBG("aim_actor_at_target heartbeat #%llu rot_seh=%llu",
               static_cast<unsigned long long>(cn),
               s_rot_seh.load(std::memory_order_relaxed));
    }
    return true;
}

// Build 55f — lightweight 60Hz rotation override.
//
// Designed for high-frequency calls from npc_ai_suppress POST orig.
// Skips anim graph writes (those are persistent from full aim_actor_at_target
// at each NPC_FIRE event). Only writes Actor+0xC0 rotation to override
// vanilla AI's per-tick rotation write toward local player.
bool aim_actor_at_target_rotation_only(void* raider_actor,
                                       float yaw_rad) noexcept
{
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!raider_actor) return false;
    if (!g_set_rotation_engine) return false;

    float rot[3] = { 0.f, 0.f, yaw_rad };
    __try {
        g_set_rotation_engine(raider_actor, rot);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// ============================================================================
// End BUILD 54
// ============================================================================

// B6.6w4 — engine-native movement-controller disable.
// 1. Read MovementController* at Actor + 0x318.
// 2. Call sub_140DC80B0(mc) → sets *(mc + 0x1A1) = 1 + vt-cleanup.
// 3. Flip Havok rigid body to KEYFRAMED via existing helper.
//
// Idempotent: subsequent calls on the same actor are harmless (the
// setter's `if (*(mc + 0x1A1) != 1)` guard skips the inner cleanup).
bool disable_actor_movement(void* actor) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_WRN("engine: disable_actor_movement called before init");
        return false;
    }
    if (!actor) return false;
    if (!g_movctrl_set_disabled) {
        FW_ERR("engine: disable_actor_movement — fn pointer not resolved");
        return false;
    }

    static std::atomic<std::uint64_t> s_calls{0};
    static std::atomic<std::uint64_t> s_seh{0};

    void* mc = nullptr;
    __try {
        mc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) +
            offsets::ACTOR_MOVCTRL_PTR_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = s_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("engine: disable_actor_movement SEH reading +0x318 "
                   "actor=%p", actor);
        }
        return false;
    }
    if (!mc) {
        FW_DBG("engine: disable_actor_movement — actor=%p has no "
               "MovementController (null at +0x318)", actor);
        return false;
    }

    __try {
        g_movctrl_set_disabled(mc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = s_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("engine: disable_actor_movement SEH in setter "
                   "actor=%p mc=%p", actor, mc);
        }
        return false;
    }

    // Also keyframe the Havok body — prevents impulse-on-frozen-body
    // ragdoll crashes (kept from the v5 fix).
    const bool kf_ok = set_actor_motion_keyframed(actor);

    const auto cn = s_calls.fetch_add(1, std::memory_order_relaxed);
    if (cn < 20) {
        FW_LOG("engine: disable_actor_movement #%llu actor=%p mc=%p "
               "keyframed=%d — TickMovementController will now bail "
               "self until byte cleared",
               static_cast<unsigned long long>(cn), actor, mc,
               kf_ok ? 1 : 0);
    }
    return true;
}

// B6.6w5 — receiver-side pos apply.
//
// Wraps Actor::vt[202] (sub_140C60630) call with TLS bypass so our own
// ghost_ai_pos_belt / ghost_ai_actor_setpos detours pass through and
// the engine actually writes the pos. a3=0 selected per
// re/B6.6w5_vt202_unknowns.md (avoids Havok rotation identity-overwrite).
//
// Threading: main thread only. Cell-hash mutation inside is unprotected
// in vanilla so caller must serialize against AI tick — we dispatch via
// WndProc message which is main-thread.
//
// SEH-caged. First 10 + every 100th logged.
bool apply_npc_pos(void* actor, float x, float y, float z) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_WRN("engine: apply_npc_pos called before init");
        return false;
    }
    if (!actor) return false;
    if (!g_actor_setpos_vt202) {
        FW_ERR("engine: apply_npc_pos — fn pointer not resolved");
        return false;
    }

    static std::atomic<std::uint64_t> s_calls{0};
    static std::atomic<std::uint64_t> s_seh{0};

    float pos[3] = {x, y, z};

    // TLS bypass: manual toggle (RAII guard has non-trivial dtor → MSVC
    // C2712 conflict with __try in same function). Pos hooks check this
    // and passthrough when true.
    const bool prev_tls = fw::hooks::tls_applying_remote;
    fw::hooks::tls_applying_remote = true;

    bool seh_failed = false;
    __try {
        g_actor_setpos_vt202(actor, pos, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        seh_failed = true;
    }

    fw::hooks::tls_applying_remote = prev_tls;

    if (seh_failed) {
        const auto sn = s_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("engine: apply_npc_pos SEH #%llu actor=%p pos=(%.1f,%.1f,%.1f)",
                   static_cast<unsigned long long>(sn), actor, x, y, z);
        }
        return false;
    }

    const auto cn = s_calls.fetch_add(1, std::memory_order_relaxed);
    if (cn < 10) {
        FW_LOG("engine: apply_npc_pos #%llu actor=%p pos=(%.1f,%.1f,%.1f) — "
               "vt[202] with a3=0 (Actor+0xD0 + NIF root, no Havok reset)",
               static_cast<unsigned long long>(cn), actor, x, y, z);
    } else if ((cn % 100) == 0) {
        FW_DBG("engine: apply_npc_pos #%llu (heartbeat, seh=%llu)",
               static_cast<unsigned long long>(cn),
               s_seh.load(std::memory_order_relaxed));
    }
    return true;
}

// Build 65.c.46 — deadlock-safe pos pin (see header for full rationale).
// Pure SEH-caged memory writes, NO engine call → cannot touch the global
// cell-grid spinlock that makes vt[202] deadlock during a cell-stream.
bool apply_npc_pos_raw(void* actor, float x, float y, float z) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!actor) return false;

    static std::atomic<std::uint64_t> s_calls{0};
    static std::atomic<std::uint64_t> s_seh{0};

    auto* bytes = reinterpret_cast<std::uint8_t*>(actor);

    bool wrote_logical = false;
    // (1) Actor+0xD0/D4/D8 — the logical pos vt[202] writes via sub_140513A80.
    __try {
        *reinterpret_cast<float*>(bytes + offsets::POS_OFF + 0) = x;
        *reinterpret_cast<float*>(bytes + offsets::POS_OFF + 4) = y;
        *reinterpret_cast<float*>(bytes + offsets::POS_OFF + 8) = z;
        wrote_logical = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        const auto sn = s_seh.fetch_add(1, std::memory_order_relaxed);
        if (sn < 5) {
            FW_ERR("engine: apply_npc_pos_raw SEH (logical) #%llu actor=%p",
                   static_cast<unsigned long long>(sn), actor);
        }
        return false;
    }

    // (2) NIF root local(+0x60) + world(+0xA0) translate. The renderer reads
    // world; UpdateWorldData re-derives child world from local. 3D may be
    // unloaded mid-stream (Actor+0xF0 null) — that's fine, the logical write
    // already landed and the next post-stream frame re-syncs the NIF.
    __try {
        void* lrd = *reinterpret_cast<void**>(
            bytes + offsets::LOADED_REF_DATA_OFF);
        if (lrd) {
            void* nif = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(lrd) +
                offsets::LOADED_REF_DATA_3D_OFF);
            if (nif) {
                auto* n = reinterpret_cast<std::uint8_t*>(nif);
                *reinterpret_cast<float*>(n + offsets::NI_AV_LOCAL_TRANSLATE_OFF + 0) = x;
                *reinterpret_cast<float*>(n + offsets::NI_AV_LOCAL_TRANSLATE_OFF + 4) = y;
                *reinterpret_cast<float*>(n + offsets::NI_AV_LOCAL_TRANSLATE_OFF + 8) = z;
                *reinterpret_cast<float*>(n + offsets::NI_AV_WORLD_TRANSLATE_OFF + 0) = x;
                *reinterpret_cast<float*>(n + offsets::NI_AV_WORLD_TRANSLATE_OFF + 4) = y;
                *reinterpret_cast<float*>(n + offsets::NI_AV_WORLD_TRANSLATE_OFF + 8) = z;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // NIF not loaded / torn down — logical write already succeeded.
    }

    const auto cn = s_calls.fetch_add(1, std::memory_order_relaxed);
    if (cn < 10) {
        FW_LOG("engine: apply_npc_pos_raw #%llu actor=%p pos=(%.1f,%.1f,%.1f) "
               "— RAW (Actor+0xD0 + NIF local/world, NO cell-grid lock)",
               static_cast<unsigned long long>(cn), actor, x, y, z);
    } else if ((cn % 100) == 0) {
        FW_DBG("engine: apply_npc_pos_raw #%llu (heartbeat, seh=%llu)",
               static_cast<unsigned long long>(cn),
               s_seh.load(std::memory_order_relaxed));
    }
    return wrote_logical;
}

// B6.6w5 — engine load-in-progress byte read.
bool is_load_in_progress() noexcept {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (!g_load_in_progress) return false;
    __try {
        return *g_load_in_progress != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================================
// B6.6w5 Build 7 — engine-native ghost via MEMCPY from local player.
//
// =================== APPROACH PIVOT (2026-05-13 user insight) ===================
//
// Builds 1-6 invoked the engine PC ctor `sub_140D52350(buffer)` on a fresh
// alloc. Every build crashed at a different audit-missed side-effect. After
// 6 builds + 2 deep audits we hit the wall: the ctor's 5383-byte body has
// side effects we cannot fully enumerate, AND the engine's 30+ "is this the
// player?" code paths assume singleton-only PC.
//
// The user's insight: instead of asking the engine to CONSTRUCT a fresh PC
// (and triggering the side-effect avalanche), MEMCPY the LOCAL PLAYER's
// existing 0xE10-byte struct into a fresh allocation. The local player has
// been fully initialized for minutes — every internal pointer is valid:
//   - AIProcess @+0x300 → real, populated, sub-buffers allocated
//   - MovementController @+0x318 → real, attached
//   - parentCell @+0xB8 → real, valid cell
//   - NIF root → real, scene-attached
//   - inventory list, anim graph holder, faction, equip cycle — all real
//
// The duplicate inherits VALID pointers (shared with real player). Patch
// only the few fields we want to differ: form_id (0xFF000001 instead of 0x14),
// flags (OR in TEMPORARY 0x4000).
//
// Same pattern as the existing M8P3 bone-copy and M9 equipment-clone systems:
// "copy from the real player's working state". Proven approach extended to
// the actor struct itself.
//
// =================== NO ENGINE-SIDE REGISTRATIONS ===================
//
// The duplicate is a "phantom" — known only to our code, invisible to engine
// subsystems:
//   - NO call to PlayerCharacter ctor → NO event-sink registration on
//     MEMORY[0x1430DD830] / MEMORY[0x1430DD7B0]. The duplicate's sub-objects
//     at +1168, +1176, +1184, +1192 are byte-identical to real_player's, but
//     the engine's sink lists contain pointers to REAL_PLAYER+1168 etc., not
//     DUPLICATE+1168. Engine never dispatches to the duplicate's sinks.
//   - NO ProcessLists registration. Per-frame walkers don't see the duplicate.
//   - NO cell-attach. Cell's atomic actor refcount is not bumped.
//   - NO secondary singleton write at MEMORY[0x1431E2D50] (we don't call the
//     ctor → no clobber → no restore needed).
//
// The duplicate exists in memory ONLY as a target pointer that our hooks
// pass to engine code. When a raider's combat_target is set to the duplicate
// (via our hook on AIProcess::SetCombatTarget), the engine's per-tick AI
// reads duplicate.{pos, parentCell, vtable, ...} which are all valid.
//
// =================== SHARED-POINTER CAVEATS (KNOWN, MANAGED) ===================
//
// The duplicate's internal pointers alias the real player's:
//   1. duplicate.Get3D() returns REAL_PLAYER's NIF root. Aim resolution on
//      duplicate would aim at REAL_PLAYER's pos, not peer's pos.
//      → MITIGATION (future patch): hook duplicate.vtable[140] (Get3D) to
//        return the body renderer ghost's NIF root (which IS at peer's pos).
//   2. duplicate.AIProcess is shared with real player. If engine writes to
//      duplicate.AIProcess (e.g., SetCombatTarget on duplicate), it writes
//      to REAL_PLAYER's AIProcess.
//      → MITIGATION: never call SetCombatTarget ON the duplicate. The
//        duplicate is only a TARGET, not an attacker. Raider's combat_target
//        points to duplicate, but engine never makes duplicate fight.
//   3. duplicate.inventory is shared. If raider's projectile.HandleHit
//      writes to duplicate.inventory, it writes to REAL_PLAYER's inventory.
//      → MITIGATION: damage routing is server-mediated (DAMAGE_SYNC B.3),
//        not engine-mediated. Raider's projectile hit is server-broadcast
//        and applied on the peer's client to peer's local player.
//
// All three caveats become hook problems, not crash problems. The MVP is:
//   "spawn duplicate without crashing the game" — this build.
//
// Threading: MAIN THREAD ONLY. memcpy of an actor's live state requires
// the actor not be mid-update. Caller is responsible for marshalling — we
// dispatch from FW_MSG_STRADAB_INJECT (after body inject success).
//
// Returns the duplicate Actor* on success, nullptr on any failure path.
void* spawn_ghost_player(std::uint32_t ghost_form_id) noexcept {
    if (!g_ready.load(std::memory_order_acquire)) {
        FW_ERR("[ghost-native] spawn: engine not ready");
        return nullptr;
    }
    if (!g_memmgr_alloc || !g_memmgr_lazy_init || !g_memmgr_instance ||
        !g_memmgr_init_guard || !g_player_singleton_slot) {
        FW_ERR("[ghost-native] spawn: resolver(s) null — init didn't run?");
        return nullptr;
    }

    // Step 1: read the real player pointer.
    void* real_player = nullptr;
    __try {
        real_player = *g_player_singleton_slot;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-native] spawn: SEH reading player singleton");
        return nullptr;
    }
    if (!real_player) {
        FW_ERR("[ghost-native] spawn: real player not yet in world "
               "(primary singleton null) — refusing to spawn ghost");
        return nullptr;
    }

    // Step 2: mirror the engine's lazy-init guard for the MemMgr.
    __try {
        if (*g_memmgr_init_guard != 2) {
            g_memmgr_lazy_init(g_memmgr_instance, g_memmgr_init_guard);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-native] spawn: SEH in MemMgr lazy-init");
        return nullptr;
    }

    // Step 3: allocate the raw buffer (0xE10 bytes, 0x10-aligned) — same
    // size + alignment the engine uses for a real PlayerCharacter.
    void* duplicate = nullptr;
    __try {
        duplicate = g_memmgr_alloc(g_memmgr_instance,
                                   offsets::PLAYER_INSTANCE_SIZE,
                                   offsets::PLAYER_INSTANCE_ALIGN,
                                   /*aligned_path=*/1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-native] spawn: SEH in MemMgr alloc(0xE10, 0x10)");
        return nullptr;
    }
    if (!duplicate) {
        FW_ERR("[ghost-native] spawn: alloc returned null");
        return nullptr;
    }

    // Step 4: THE KEY STEP — memcpy the real player's 0xE10 byte struct
    // into the duplicate. Every field (vtable, form_id, flags, parentCell,
    // pos, rot, AIProcess pointer, MovementController pointer, NIF root,
    // inventory list, anim graph holder, faction, equip cycle, the four
    // event-sink sub-objects at +1168/+1176/+1184/+1192, everything) is
    // byte-copied. The duplicate is a valid PlayerCharacter, sharing all
    // referenced engine state with the real player.
    //
    // SEH-caged for defense in depth (a normal memcpy on valid memory
    // should never fault, but mid-tick races or torn alignments could).
    __try {
        std::memcpy(duplicate, real_player, offsets::PLAYER_INSTANCE_SIZE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-native] spawn: SEH in memcpy(duplicate, real_player, "
               "0xE10) — duplicate is invalid, leaking buffer");
        return nullptr;
    }

    // Step 5: patch the fields that MUST differ between duplicate and real
    // player. Direct memory writes; no engine API calls.
    auto* dup_bytes = reinterpret_cast<std::uint8_t*>(duplicate);
    __try {
        // form_id: real player has 0x14 (hardcoded engine constant). The
        // duplicate must have a unique fid so our peer-routing code can
        // identify it. 0xFF000001 is in the engine's "transient mod-index"
        // space, won't collide with any loaded ESM/ESP form. We do NOT
        // call vt[65] SetFormID — that would also insert the duplicate
        // into the global form table, which we intentionally avoid.
        *reinterpret_cast<std::uint32_t*>(dup_bytes + offsets::FORMID_OFF)
            = ghost_form_id;

        // TESForm flags: OR in TEMPORARY (0x4000) so the save serializer
        // skips the duplicate if anything were to walk forms during save.
        // We also keep all other flags as-is (real player's flags include
        // kInitialized 0x400 and various engine state — preserving them
        // means the duplicate looks "fully-initialized" to every engine
        // gate that checks flags).
        *reinterpret_cast<std::uint32_t*>(dup_bytes + offsets::FLAGS_OFF)
            |= offsets::TESFORM_FLAG_TEMPORARY;

        // Build 12 (Fix 2) — set engine handle bits at +0x28 to TRIGGER
        // allocator path on next sub_14022C8B0 call.
        //
        // History:
        //   Build 10: zeroed +0x28 → engine resolver's else branch →
        //             returns NULL_HANDLE → aiprocess+0x6C=0 → AI can't
        //             find duplicate as target. RESULT: substitution
        //             "fired" but no visual change (raider re-perceives
        //             real_player from local AI tick).
        //   Build 11: passthrough on null new_target → no crash.
        //   Build 12: refcount=1, bit 0x400 cleared, slot bits zero.
        //
        // The allocator gate in sub_14022C8B0 (funcs_0120.md:9875) is:
        //   `(a2+40 & 0x3FF) != 0` → refcount != 0 enters if-branch
        //   Inside if: `v6 = 0` when bit 0x400 cleared
        //   Inside if: `v7 = (v6 == dword_1430DA180)` = (0 == 0) = TRUE
        //   `if (v7) ALLOCATE FRESH SLOT` — slot bound to duplicate.
        //
        // Agent A audit (re/B6.6w5_handle_resolver_audit.md) verified
        // dword_1430DA180 = 0 statically (never written in .text). NULL_HANDLE
        // sentinel = 0. With our pattern, gate triggers, allocator runs.
        //
        // After allocation:
        //   duplicate+0x28 = (slot_idx<<11) | 0x400 | refcount=2
        //   unk_1430DA390[slot_idx].data_ptr = duplicate+32 (smart-ptr-to-self)
        //   handle_value = slot_idx | generation_bits
        //
        // Engine's sub_14021E230 resolver (funcs_0119.md:3333) now resolves
        // the handle back to duplicate. AI tick + aim resolution work.
        *reinterpret_cast<std::uint32_t*>(dup_bytes + 0x28) = 1;

        // Build 16 Fix 1 (debate winner Pair A) — decouple from real_player's
        // BSAnimationGraphHolder by zeroing duplicate+0x720. Kept from
        // Build 16 (aligns with ctor init, doesn't hurt).
        *reinterpret_cast<std::uint64_t*>(dup_bytes + 0x720) = 0;

        // Build 17 zeros on +0x300..+0x328 were REVERTED in Build 18.
        //
        // Build 17 live test (2026-05-13 17:26): zeroing +0x300 (AIProcess
        // pointer) caused FASTER crash, not slower. The forensic agent's
        // 5% reservation was hit: "zeroing +0x300 might cascade-fault in
        // a different path... if so, add the sub_14086DC80 hook." We hit
        // exactly that — engine paths that read duplicate.AIProcess
        // without null-check segfault on the 0 ptr.
        //
        // Build 18 strategy: REVERT the +0x300 zero (keep memcpy'd from
        // real_player). Don't try to neutralize the field via zeroing —
        // instead, install a hook on `sub_140E6F830` (BGSActionData::
        // Execute entry, funcs_0334.md:7286) that BAILS when the target
        // arg matches our duplicate. This preempts the whole crash path
        // BEFORE it reaches the deref sites identified in the forensic.
        //
        // PAIR B's general thesis (memcpy'd ptrs → real_player heap)
        // remains correct, but the fix is engine-side gating, not field
        // zeroing. Zeroing trades a controlled-mutation race for a hard
        // null-deref, which the engine handles less gracefully.
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-native] spawn: SEH patching fid/flags/handle/anim on "
               "duplicate=%p", duplicate);
        return duplicate;  // still usable for some purposes
    }

    // ========================================================================
    // B6.6w5 Build 27 (2026-05-13 night) — FULL DUPLICATE SANITIZATION per
    // Agent 10 recipe (re/B6.6w5_crash_AGENT_10_pc_field_map.md, Section 4).
    //
    // Why: Build 24+25+26 hook-level workarounds fixed only the
    // SetCombatTarget cleanup path. Live test 21:02 showed crashes in
    // OTHER engine subsystems that also read the duplicate's poisoned
    // fields (Side B: Papyrus condition `GetLightLevel` at sub_140C98C40
    // RVA 0xC98CA1; Side A: sub_140798120 RVA 0x798180). Each subsystem
    // is its own whack-a-mole hole.
    //
    // Strategy: instead of hooking each subsystem, sanitize the duplicate
    // ITSELF so that any engine code reading its pointer fields gets
    // either (a) a fresh ghost-owned allocation [for AIProcess], or
    // (b) NULL [for fields where engine code null-checks before deref].
    //
    // Section 4 recipe applied:
    //   A. Fresh AIProcess at +0x300       — alloc 0xE8 via memmgr,
    //                                         ctor sub_140CEEAB0, populate
    //                                         sub_140CFA450(aip, dup)
    //   B. Zero HighProcess at +0x328     — engine null-checks
    //   C. Zero InventoryList at +0xF8    — engine lazy-materializes
    //   D. Re-alloc handle-buf at +0x100  — alloc 0x28, init sub_140272730
    //   E. Zero 23+ refcounted ptr fields — engine null-checks all
    //
    // Note: +0x300 zero (Build 17) caused immediate cascade-fault because
    // engine paths read AIProcess fields without null-check. Allocating
    // a FRESH AIProcess gives engine a valid empty one — its sub-buffers
    // are ghost-owned, no aliasing with real_player.
    //
    // The user's key insight: "agro client A e agro B non possono coesistere".
    // After sanitization, the engine can have both real_A and our duplicate
    // in known_targets[] simultaneously without crashing because all
    // duplicate field accesses now hit either fresh state or NULL-checked
    // branches.
    // ========================================================================
    bool ai_fresh_ok = false;
    if (g_memmgr_alloc && g_memmgr_instance && g_aiprocess_ctor
        && g_aiprocess_populate) {
        __try {
            // Allocate 0xE8 bytes for AIProcess.
            void* aip = g_memmgr_alloc(g_memmgr_instance, 0xE8, 0, 1);
            if (aip) {
                // Initialize: zeroes the buffer + sets up locks.
                g_aiprocess_ctor(aip);
                // Populate the 4 inner sub-buffers, bound to ghost actor.
                g_aiprocess_populate(aip, duplicate);
                // Install the fresh AIProcess.
                *reinterpret_cast<void**>(dup_bytes + 0x300) = aip;
                ai_fresh_ok = true;
                FW_LOG("[ghost-native] spawn: fresh AIProcess allocated at "
                       "%p, installed at duplicate+0x300", aip);
            } else {
                FW_WRN("[ghost-native] spawn: memmgr_alloc(0xE8) returned "
                       "NULL — AIProcess at +0x300 left as memcpy'd (HIGH "
                       "crash risk)");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[ghost-native] spawn: SEH allocating fresh AIProcess "
                   "for duplicate=%p — +0x300 left as memcpy'd", duplicate);
        }
    } else {
        FW_WRN("[ghost-native] spawn: AIProcess ctor/populate fn ptrs "
               "not resolved — +0x300 left as memcpy'd");
    }

    // Re-allocate the BSHandleRefObject sub-buffer at +0x100 so the
    // duplicate doesn't share refcount slot with real_player.
    bool handle_buf_ok = false;
    if (g_memmgr_alloc && g_memmgr_instance && g_handleref_init) {
        __try {
            void* hb = g_memmgr_alloc(g_memmgr_instance, 0x28, 0, 1);
            if (hb) {
                void* hb_init = g_handleref_init(hb);
                *reinterpret_cast<void**>(dup_bytes + 0x100) = hb_init;
                // Refbump per ctor pattern (funcs_0173.md:12017).
                if (hb_init) {
                    __try {
                        _InterlockedIncrement(reinterpret_cast<volatile long*>(
                            reinterpret_cast<std::uint8_t*>(hb_init) + 0x08));
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
                handle_buf_ok = true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[ghost-native] spawn: SEH re-allocating +0x100 handle "
                   "sub-buffer for duplicate=%p", duplicate);
        }
    }

    // Zero all the per-instance pointer fields listed in Agent 10 Section
    // 4E. The engine's per-frame walkers null-check each of these before
    // dereferencing, so NULL is safe; sharing them with real_player is
    // not. SEH-cage each batch.
    //
    // Skip +0x300 if we DID allocate a fresh one above (don't overwrite
    // our valid pointer). Same for +0x100.
    int zeroed_count = 0;
    int seh_count = 0;
    static constexpr std::size_t kZeroOffsets[] = {
        // High-priority (Section 2 top-ranked)
        0x328,   // HighProcess* — combat aim path
        0xF8,    // BGSInventoryList* — engine lazy-materializes
        0xD80,   // secondary REFR holder — engine null-checks
        0x318,   // MovementController* — engine lazy-allocs
        // Refcount-chain heap children (Section 4E)
        0x2F0, 0x2F8,         // Actor own-ptrs (HIGH)
        0x308, 0x310, 0x320, 0x330, 0x370, 0x37C, 0x39C,
        0x408, 0x410, 0x418, 0x420, 0x428,  // Active effects head etc.
        0x8A0, 0x8B0, 0x8E8, 0x8F0, 0x8F8,  // NiTMap bucket array + chain
        0x918, 0x920, 0x928, 0x948, 0x950, 0x958,
        0x978, 0x980, 0x988, 0x9C0, 0x9C8, 0x9F8,
        0xA20, 0xA28, 0xA38, 0xA40, 0xA50,  // refcounted misc
        0xB70, 0xB78, 0xB80, 0xB88, 0xB98,
        0xBA4, 0xBAC, 0xBB4, 0xBBC, 0xBC8,  // 7768/80-byte allocs
        0xBD8, 0xC00, 0xC10, 0xC18, 0xC20, 0xC28, 0xC40, 0xC48,
        0xC70, 0xC78,
        0xCC8, 0xCE8, 0xD00,
        0xD10, 0xD18, 0xD20, 0xD28, 0xD30, 0xD38, 0xD40, 0xD48, 0xD50,
        0xD98,                 // another 0x50 alloc
        0xDA0,
    };

    for (std::size_t off : kZeroOffsets) {
        // Don't overwrite freshly-allocated buffers.
        if (handle_buf_ok && off == 0x100) continue;
        __try {
            *reinterpret_cast<std::uint64_t*>(dup_bytes + off) = 0;
            zeroed_count++;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            seh_count++;
        }
    }
    FW_LOG("[ghost-native] spawn: sanitization zeroed %d/%zu pointer "
           "fields (SEH on %d) — Build 27 Agent 10 recipe",
           zeroed_count,
           sizeof(kZeroOffsets) / sizeof(kZeroOffsets[0]),
           seh_count);
    FW_LOG("[ghost-native] spawn: fresh_AIProcess=%d fresh_handle_buf=%d",
           ai_fresh_ok ? 1 : 0, handle_buf_ok ? 1 : 0);

    // Step 5b (B6.6w5 Build 12 Fix 2) — preallocate engine handle.
    //
    // We could rely on sub_14087AB30 (SetCombatTarget) to lazy-call the
    // allocator on first substitution. But to be deterministic — and to
    // log the allocated handle for diagnostic — explicitly call the
    // allocator now. Idempotent: if duplicate already has bit 0x400 set,
    // the allocator returns existing handle, no new slot allocated.
    std::uint32_t allocated_handle = 0;
    if (g_handle_get_or_alloc) {
        __try {
            g_handle_get_or_alloc(&allocated_handle, duplicate);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[ghost-native] spawn: SEH in handle allocator for "
                   "duplicate=%p — fallback: engine will lazy-allocate on "
                   "first SetCombatTarget(aiproc, duplicate)", duplicate);
        }
    }

    // Sanity-read duplicate+0x28 after allocator: should now have bit
    // 0x400 set and slot_idx in bits 11-20.
    std::uint32_t handle_field_after = 0;
    __try {
        handle_field_after = *reinterpret_cast<std::uint32_t*>(dup_bytes + 0x28);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    FW_LOG("[ghost-native] spawn: handle allocated for duplicate=%p — "
           "handle_value=0x%08X duplicate+0x28=0x%08X (bit 0x400 %s)",
           duplicate, allocated_handle, handle_field_after,
           (handle_field_after & 0x400) ? "SET" : "NOT SET");

    // B6.6w5 Build 23 — cache the handle for the set_combat_target hook
    // to reuse. Eliminates per-substitution s_alloc calls, which Agent 8
    // identified as the heap-corruption / fast-fail vector (the engine
    // handle allocator reads duplicate+0x28's memcpy'd refcount bits to
    // decide alloc vs reuse — racing with real_player's own refcount ops
    // → undefined behavior → process termination without VEH dispatch).
    if (allocated_handle != 0) {
        g_ghost_duplicate_handle.store(allocated_handle,
                                        std::memory_order_release);
    }

    // Step 6 (B6.6w5 Build 8b) — per-instance vtable swap. The duplicate
    // currently has the original PlayerCharacter vtable (memcpy'd from real
    // player). We replace its vtable pointer with our cloned vtable that
    // redirects slot 140 (Get3D) to return the body renderer ghost.
    //
    // After this step, any engine code calling `duplicate->Get3D()` (raider
    // AI aim resolution, scene-graph queries, distance checks) receives the
    // body renderer ghost at the peer's world position — NOT the real
    // player's NIF (which would point at the local user).
    //
    // All other vtable slots are pristine — engine still calls original PC
    // methods on the duplicate where needed. Most reads return valid state
    // (because the duplicate is byte-identical to a fully-initialized PC).
    bool vtable_swapped = false;
    if (g_duplicate_vtable_ready.load(std::memory_order_acquire)) {
        __try {
            *reinterpret_cast<void**>(dup_bytes) = &g_duplicate_vtable[0];
            vtable_swapped = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[ghost-native] spawn: SEH installing custom vtable on "
                   "duplicate=%p — Get3D redirect inactive, aim resolution "
                   "will point at real player NIF (shared via memcpy)",
                   duplicate);
        }
    } else {
        FW_WRN("[ghost-native] spawn: g_duplicate_vtable not ready (init "
               "didn't run?) — Get3D redirect inactive");
    }

    // Read back fid/flags + sanity-check vtable for the log line.
    std::uint32_t dup_fid = 0, dup_flags = 0;
    void* dup_vtable = nullptr;
    __try {
        dup_fid = *reinterpret_cast<std::uint32_t*>(dup_bytes + offsets::FORMID_OFF);
        dup_flags = *reinterpret_cast<std::uint32_t*>(dup_bytes + offsets::FLAGS_OFF);
        dup_vtable = *reinterpret_cast<void**>(dup_bytes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // already-logged
    }

    FW_LOG("[ghost-native] spawn OK (Build 8b memcpy+vt140): duplicate=%p "
           "fid=0x%08X flags=0x%08X vtable=%p (vt_swapped=%d) — "
           "memcpy'd from real_player=%p, Get3D %s redirected to body ghost",
           duplicate, dup_fid, dup_flags, dup_vtable, vtable_swapped ? 1 : 0,
           real_player, vtable_swapped ? "IS" : "is NOT");

    // Step 7 (B6.6w5 Build 9) — register duplicate in client-side fid
    // lookup registry. After this, lookup_by_form_id(ghost_form_id)
    // returns this duplicate ptr instead of NULL. The combat-target
    // substitution hook (ghost_ai_set_combat_target.cpp) uses this to
    // resolve the server-broadcast `combat_target_form_id` when server
    // says a raider should aggro the OTHER peer.
    register_ghost_duplicate(ghost_form_id, duplicate);

    // Build 48 — same synchronous swap as the PlaceAtMe path (see
    // spawn_ghost_proxy). Closes the +8-17ms post-spawn window during
    // which the duplicate's PlayerNPC baseForm would be walked by
    // engine post-spawn processing and AV on sentinel vt[103].
    try_swap_ghost_baseform(duplicate);

    // Build 60 (2026-05-24) — REMOVED Build 56 deregister call (same
    // reason as in spawn_ghost_proxy: it always returned result=0 because
    // the bucket lookup used the wrong fid hash). The memcpy path doesn't
    // insert the duplicate into the global form-table directly (memcpy
    // copies bytes but doesn't call SetFormID), so there's no bucket to
    // remove. Hook 5/6 walker guards cover any rare exposure.
    //
    // Note: spawn_ghost_player (memcpy path) is DEPRECATED in production —
    // spawn_ghost_proxy (PlaceAtMe) is the live path. Kept compilable for
    // historic reference but not invoked at runtime.

    return duplicate;
}

// ============================================================================
// B6.6w5 Build 28 (2026-05-13 late night) — engine-native proxy spawn.
//
// REPLACEMENT for spawn_ghost_player. Path #1 from the 10-agent TABULA
// RASA synthesis. Uses PlaceAtMe (sub_141159C10) to get a fully-
// constructed Actor with all engine subsystems initialized. Zero
// aliasing with real_player's heap → eliminates the 27-build crash
// matrix at its source.
//
// Verification (manual cross-check of AGENT P1A+P1B against decomp):
//   - PlaceAtMe RVA 0x1159C10 / size 0x393  funcs_0401.md:1809 [VERIFIED]
//     Signature confirmed: (vm, stack, form_pair, anchor_refr, count, persist)
//     Validates anchor_refr != NULL (errors at line 1854).
//     Internal: allocates 0x490 via memmgr → Actor ctor sub_140C57640 →
//     dispatches sub_1402E4DF0 (NEW_REFR_DATA full integration).
//   - SetDisabled RVA 0x519410 / size 0x41  funcs_0175.md:12328 [VERIFIED]
//     Calls sub_140313230(refr, 1, enabled) → mutates refr+24 bit, then
//     vtable[13] propagates to refr+16 bit 0x800. IsDisabled getter
//     (sub_141181060 funcs_0404.md:4021) reads refr+16 & 0x800 — matches.
//   - SetGhost RVA 0xC5CE40 / size 0xB6  funcs_0301.md:2959 [VERIFIED]
//     Reads actor+0x300 (AIProcess), AIProcess+0x58 (sub-obj), sets bit
//     0x100000 at +44 of that sub-obj (line 2997).
//
// Flags strategy for MVP: set Temporary (no save). LEAVE Disabled and
// Ghost cleared at first test — we WANT raiders to perceive and engage
// the proxy. If raider visibly attacks the proxy → MVP gate. If the
// proxy is rendered annoyingly (its own body) → add SetDisabled in a
// follow-up; the existing body-ghost renderer will continue painting
// the peer at the proxy's position.
// ============================================================================
void* spawn_ghost_proxy(std::uint32_t ghost_form_id,
                        std::uint32_t base_form_id) noexcept
{
    // Build 28b — fix: 0x0020593F (LCharWorkshopNPC) is a leveled-character
    // list (LCHAR), NOT a TESNPC. PlaceAtMe needs a TESNPC. Fall back to
    // the LOCAL PLAYER's base form (real_player+0xE0 = PlayerNPC, formType
    // 0x2D guaranteed). The base_form_id arg is kept for future use when
    // we author a custom invisible-NPC ESL.
    (void)base_form_id;
    if (!g_ready.load(std::memory_order_acquire) || !g_player_singleton_slot) {
        FW_ERR("[ghost-proxy] engine not ready or player_slot null");
        return nullptr;
    }

    // Read local player + their base form.
    void* player = nullptr;
    __try { player = *g_player_singleton_slot; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[ghost-proxy] SEH reading player singleton");
        return nullptr;
    }
    if (!player) {
        FW_ERR("[ghost-proxy] player singleton null (not in world yet?)");
        return nullptr;
    }
    void* player_base = nullptr;
    __try {
        player_base = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(player) + 0xE0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!player_base) {
        FW_ERR("[ghost-proxy] player+0xE0 (baseForm) is NULL — early init?");
        return nullptr;
    }
    std::uint8_t base_type = 0xFF;
    std::uint32_t base_fid_real = 0;
    __try {
        base_type     = *reinterpret_cast<std::uint8_t*>(
            reinterpret_cast<std::uint8_t*>(player_base) + 0x1A);
        base_fid_real = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(player_base) + 0x14);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (base_type != 0x2D) {
        FW_ERR("[ghost-proxy] player baseForm formType=0x%02X (expected 0x2D)",
               base_type);
        return nullptr;
    }
    FW_LOG("[ghost-proxy] using player.baseForm=%p fid=0x%08X formType=NPC "
           "as proxy template (was overriding requested base_form_id=0x%08X)",
           player_base, base_fid_real, base_form_id);

    // Build 28e (2026-05-13 late) — REVERT to full PlaceAtMe path.
    //
    // Build 28c/d (CreateByTypeCode + manual vt[] init) demonstrated
    // whack-a-mole: each missing field exposed by NULL deref required a
    // new manual write. After +0x418 (vt[191] populated) we hit +0x48
    // (NULL → lock acquire at 0x20). Engine assumes the FULL PlaceAtMe
    // init pathway ran; we can't replicate it field-by-field.
    //
    // The PlaceAtMe path crashes only during TP (Build 28b: AV inside
    // IsAttachable sub_1403095C0 RVA 0x309600 — reads anchor+0x68 area
    // sentinel value 0xFFFFFFFFFFFFFFFF). Solution: DEFER the spawn
    // call until player cell-attach state is stable. Caller
    // (actor_hijack.cpp) is responsible for the deferral; here we
    // simply trust them.
    //
    // Below uses `spawn_ghost_actor` (the Z.2 path B function that
    // wraps PlaceAtMe + Temp-flag patch). Same engine code that vanilla
    // PlaceAtMe console command goes through — guaranteed init
    // pathway runs.
    // Build 28f — set TLS bypass for IsAttachable BEFORE calling
    // PlaceAtMe. The hook (ghost_is_attachable.cpp) checks the TLS flag
    // and returns 0 for both call sites:
    //   - PlaceAtMe line 1940: outer IsAttachable check → skip AttachREFR
    //   - dispatcher line 6849: inner IsAttachable check → take
    //     "non-attached path" which runs sub_140CA3A50/CA3AB0/C92EF0
    //     proper AI init via flag bits (verified in funcs_0137.md:6849-6872)
    //     and CRITICALLY does NOT call vt[191] (which previously
    //     corrupted proxy+0x48 in Build 28d).
    //
    // Can't use RAII destructor in this function (C2712: __try in
    // functions requiring unwind). Manual set/clear: spawn_ghost_actor
    // is fully SEH-caged internally — on a fault it returns NULL
    // rather than propagating, so the clear after the call always runs.
    // Build 28m (2026-05-16) — TEMP injection of player_cell into
    // player_base+0xB8 to defeat the dispatcher's early-exit.
    //
    // The dispatcher (sub_1402E4DF0) takes early-exit at funcs_0137.md
    // line 6561 when NEW_REFR_DATA.parent_cell is NULL. PlaceAtMe builds
    // NEW_REFR_DATA by reading `*(base+0xB8)` (line 1942 v22 = base+184).
    // For PlayerNPC base (fid 0x07), base+0xB8 is NULL → NEW_REFR_DATA
    // parent_cell=NULL → dispatcher early-exits → skip the vt[191](actor,
    // cell) native call that properly populates actor+0x48 and +0x418
    // with valid heap pointers.
    //
    // Build 28i tried to manually call vt[191](proxy, cell) post-PlaceAtMe.
    // But vt[191] with cell arg writes a sentinel-shaped value at +0x418
    // (verified Build 28h log: `FF54545400000000`). Result Build 28l:
    // engine reads +0x418 → gets sentinel → derefs → AV at sub_140C73720
    // RVA 0xC73759.
    //
    // Real fix: make dispatcher run NATIVELY by injecting a valid cell
    // into base+0xB8 before PlaceAtMe. The dispatcher's vt[191] call
    // uses cell properly — populates +0x48 and +0x418 with valid heap
    // pointers (different code path than what we manually triggered).
    //
    // After PlaceAtMe returns, restore base+0xB8 to original value.
    // Player NPC base is shared singleton; modification is brief (only
    // during the synchronous PlaceAtMe call on main thread, no other
    // thread can interleave).
    // Build 28o — REVERT dual injection (28n broke PlaceAtMe internals
    // by triggering vt[191](actor, cell) NATIVE which writes sentinel at
    // proxy+0x418 just like the manual call did. The dispatcher's
    // attached path can't be "fixed" because AttachREFR (the function
    // that completes the +0x418 init) is no-op'd by our hook.
    //
    // Strategic combination: KEEP non-attached path (no dual injection,
    // no manual vt[191]) so PlaceAtMe completes cleanly. POST-spawn,
    // write SAFE values to the fields the engine derefs without null-
    // checking (+0x48 = static zero buffer pretending to be a lock
    // object, +0x418 = NULL so null-check readers short-circuit).
    fw::hooks::set_force_not_attachable(true);
    void* proxy = spawn_ghost_actor(base_fid_real);
    fw::hooks::set_force_not_attachable(false);

    // Build 28l (2026-05-16) — RESTORE handle alloc that was lost during
    // PlaceAtMe refactor. Without this, g_ghost_duplicate_handle stays at
    // 0 → ghost_ai_set_combat_target hook substitutes aiproc+0x6C with
    // 0 → engine sees no target AND BYPASS-FROM-DUP check (gated on
    // dup_handle != 0) never fires → orig SetCombatTarget runs and
    // crashes at sub_1404CAE90 (Build 28k Side A crash 00:49:04 RVA 0x4CAF43).
    //
    // PlaceAtMe internally allocates the handle via dispatcher (line 6571
    // sub_14021E3F0) but stores it in a stack buffer that's lost on
    // return. g_handle_get_or_alloc is idempotent — actor+0x28 bit 0x400
    // already set → returns existing handle from unk_1430DA390[slot].
    //
    // Run BEFORE SetDisabled to avoid any state interference (Disabled
    // might mark refr+0x10A=4 which is the engine's delete-pending
    // sentinel; handle alloc may bail on delete-pending actors).
    std::uint32_t alloc_handle = 0;
    if (g_handle_get_or_alloc && proxy) {
        __try {
            g_handle_get_or_alloc(&alloc_handle, proxy);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_WRN("[ghost-proxy] SEH in g_handle_get_or_alloc(proxy)");
            alloc_handle = 0;
        }
    }
    std::uint32_t handle_field_pre_disabled = 0;
    __try {
        handle_field_pre_disabled =
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(proxy) + 0x28);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    FW_LOG("[ghost-proxy] handle alloc (pre-SetDisabled): "
           "alloc_handle=0x%08X proxy+0x28=0x%08X (bit0x400=%s)",
           alloc_handle, handle_field_pre_disabled,
           (handle_field_pre_disabled & 0x400) ? "SET" : "CLEAR");
    if (alloc_handle != 0) {
        g_ghost_duplicate_handle.store(alloc_handle,
                                        std::memory_order_release);
    }

    // Build 28j set SetDisabled(proxy, 1) to make the per-frame walker
    // skip the proxy. Build 29 REVERSES that decision: the Disabled flag
    // (bit 0x800 at refr+0x10) trips the `(flags & 0x820) == 0` check
    // inside `sub_140E98250` — the IsInList gate called by the Fixed
    // selector's vt[5] refresh (funcs_0337.md:6724). Failing that check
    // sets selector flag bit 1 → promoter skips → ghost never gets
    // committed as combat_target. Disabled MUST be CLEAR for the engine-
    // native Fixed-selector path to work.
    //
    // Walker-skip role is now provided by:
    //   1. `npc_ai_suppress::detour_actor_update_perframe` GHOST-BAIL
    //      (fid == GHOST_FORMID_BASE early-return).
    //   2. `ghost_is_attachable` Build 28q lock-walker NULL safety.
    //   3. Post-spawn safe-init writes at proxy+0x48 / +0x418.
    // No need to set Disabled.
    if (proxy && g_set_disabled) {
        __try {
            // Build 29: arg=0 (NOT Disabled). Engine sees proxy as alive
            // → Fixed selector vt[5] IsInList check passes → promoter
            // installs ghost handle into aiproc+0x6C every frame natively.
            g_set_disabled(proxy, 0);
            FW_LOG("[ghost-proxy] SetDisabled(proxy, 0) — Build 29: ghost "
                   "must be NOT disabled so Fixed selector's vt[5] check "
                   "`(flags & 0x820) == 0` passes (sub_140E98250 gate).");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_WRN("[ghost-proxy] SEH in SetDisabled(proxy, 0)");
        }
    }

    // (already cleared above near line 3548)
    if (!proxy) {
        FW_ERR("[ghost-proxy] spawn_ghost_actor(PlaceAtMe) returned NULL "
               "even with IsAttachable bypass — bypass_count=%llu "
               "passthrough_count=%llu",
               static_cast<unsigned long long>(
                   fw::hooks::get_is_attachable_bypass_count()),
               static_cast<unsigned long long>(
                   fw::hooks::get_is_attachable_passthrough_count()));
        return nullptr;
    }

    auto* proxy_bytes = reinterpret_cast<std::uint8_t*>(proxy);
    std::uint32_t new_handle = 0;

    // Build 28o — SAFE BUFFER injection at proxy+0x48 and NULL at +0x418.
    //
    // sub_1404C4DF0 reads `v1 = *(actor+0x48)`, then passes `v1+32` to
    // sub_141658FE0 (lock acquire). Without init, v1=NULL → crash at
    // sub_141658FE0(0x20). With our safe buffer, v1=buffer → reads at
    // buffer+0/+4 (thread_id/lock_count) return 0 → lock "free" → engine
    // proceeds normally.
    //
    // sub_140CA85C0, sub_140C73720 read `*(actor+0x418)` and null-check
    // (`if (!v8) return`) → writing NULL there is safe.
    //
    // sub_140CBFBA0 reads `*(actor+0x418)` WITHOUT null-check → crashes
    // on NULL. But that function is on the per-frame walker path which
    // we already bail via npc_ai_suppress GHOST-BAIL.
    //
    // Build 33 (2026-05-16) — F2: REAL IAGMH vtable at proxy+0x48.
    //
    // History:
    //   28o → 31.5 wrote a 256-byte zero buffer (`s_lock_buf_48`) to
    //     proxy+0x48. Worked for lock-walker sub_1404C4DF0 (treated the
    //     buffer's first 8 bytes = vtable=0 as a lock obj that "happened"
    //     to be free), but broke vt[18] anim-graph dispatch
    //     (sub_140CD68CD line 9891) → null function pointer → AV at rip=0.
    //
    //   31.5 tried trusting ctor's value. Engine post-spawn overwrites
    //     it with 0x42C80000 (= IEEE float bit pattern from SSE math
    //     bleeding into the slot per F2 dossier) → invalid pointer →
    //     lock-walker crashes at 0x42C80020.
    //
    // Agent F2's BLUNT (verified against funcs_0173.md:11985 ctor +
    //   funcs_0300.md:6032 Actor ctor): +0x48 is an 8-byte
    //   IAnimationGraphManagerHolder inline sub-object whose ONLY field
    //   is the vtable pointer. Actor's ctor writes `&Actor::vftable[6]`
    //   = module_base + 0x2560CB0 (= 26-slot interface vtable, all
    //   slots null-check actor+0x300 AIProcess and fast-return false
    //   when ghost.AIProcess is null/sanitized). Writing this CANONICAL
    //   value defeats both crash classes:
    //     - lock-walker reads it as the vtable, +0x20 lands at
    //       vtable[4] which is a real function pointer in .rdata, NOT
    //       a faultable read.
    //     - vt[18] dispatch lands in a real engine function that
    //       returns false safely.
    //
    // Per-instance: each ghost is a distinct Actor; the inline sub-
    // object lives at proxy+0x48 inside that Actor's heap allocation.
    // We just write a STATIC vtable pointer to it.
    //
    // Build 35.1 (2026-05-16) — +0x418 is NOT safe as NULL.
    //
    // History: 28o wrote NULL at proxy+0x418 because the two callers
    // we'd identified at the time (sub_140CA85C0, sub_140C73720) null-
    // check it. Live test of Build 34 (cross-peer aggro install)
    // exposed a NEW caller, sub_1408800C0 line 10628:
    //     fmaxf(*(float *)(*(actor+0x418) + 0x1C8), <const>)
    // This caller derefs *(actor+0x418) WITHOUT a null-check and reads
    // a float at offset 0x1C8 inside the resulting struct (it's the
    // engine's combat-aim "view cone radius" reader). With +0x418=NULL,
    // *(NULL+0x1C8) = AV at 0x1C8 — exactly the 19:57:54 crash.
    //
    // Replacement: STATIC ZERO BUFFER at proxy+0x418, same pattern we
    // use for proxy+0x48 (s_lock_buf_48). 512 bytes covers offset
    // 0x1C8 (= 456 dec) with slack for any other sub-fields engine
    // callers might read inside the struct. Effect:
    //   * Callers that null-check +0x418 → see non-NULL → proceed
    //     with their normal logic. Sub-fields they read are 0 → falls
    //     into "no data, default behavior" branches.
    //   * sub_1408800C0 line 10628 → reads float 0.0f at +0x1C8 →
    //     fmaxf(0.0f, <const>) returns <const> → uses the hardcoded
    //     fallback angle → no crash, no garbage aim math.
    //   * Vtable-style readers (if any) of *(buf+0) = 0 would AV at
    //     rip=0 — we'd see a distinct crash signature if such a path
    //     exists. None observed yet.
    //
    // Per-DLL static lifetime (zero-init data section), shared across
    // all ghost instances. Read-only from engine's POV (engine never
    // writes through this pointer for the ghost — it's a "fake
    // initialized" sub-object that satisfies field reads).
    static std::uint8_t s_buf_418[512] = {};
    __try {
        const std::uintptr_t module_base =
            reinterpret_cast<std::uintptr_t>(g_engine_heap_alloc) -
            offsets::ENGINE_HEAP_ALLOC_RVA;
        const std::uintptr_t iagmh_vt =
            module_base + offsets::ACTOR_IAGMH_VTABLE_RVA;
        *reinterpret_cast<std::uintptr_t*>(proxy_bytes + 0x48) = iagmh_vt;
        *reinterpret_cast<void**>(proxy_bytes + 0x418) =
            static_cast<void*>(s_buf_418);
        FW_LOG("[ghost-proxy] F2: proxy+0x48 = 0x%llX "
               "(Actor IAGMH vtable @ module+0x%lX, 26 slots all "
               "AIProcess-gated); proxy+0x418 = %p (Build 35.1: "
               "static 512B zero buffer — sub_1408800C0 line 10628 "
               "reads float at +0x1C8 → 0.0f → fmaxf fallback safe)",
               static_cast<unsigned long long>(iagmh_vt),
               static_cast<unsigned long>(offsets::ACTOR_IAGMH_VTABLE_RVA),
               static_cast<void*>(s_buf_418));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] SEH writing IAGMH vtable / +0x418");
    }

    // Build 33 — F9: ghost field zero block.
    //
    // Agent F9 synthesis: post-PlaceAtMe, the ghost's AIProcess (at
    // actor+0x300) inherits whatever PlayerNPC ctor produced — including
    // residual handles at +0x68/+0x6C and a partially-init alive byte
    // at +0xDF. Zeroing these forces the engine into the "no current
    // target / not in active combat" fallback paths which are NULL-safe
    // (every reader checks the resolved Actor* != null before deref).
    //
    // Also clears actor+0xDFF bit 0x02 (is1P flag inherited from
    // PlayerNPC base) so vt[142]/vt[254] take the non-player branch
    // and don't deref player-only state on the ghost.
    //
    // Note: aiproc+0x68/+0x6C are ALREADY purged at install-time by
    // `purge_stale_aiproc_handles`, but doing it here too ensures the
    // initial state is clean even before any raider goes InCombat —
    // important for engine sweeps that touch ghost passively (e.g.,
    // perception pair-tests during cell-attach, Agent F6 step 13).
    __try {
        auto* aiproc = *reinterpret_cast<void**>(
            proxy_bytes + offsets::ACTOR_AIPROCESS_OFF);
        if (aiproc) {
            auto* aip_bytes = reinterpret_cast<std::uint8_t*>(aiproc);
            *reinterpret_cast<std::uint32_t*>(
                aip_bytes + offsets::AIPROCESS_TARGET_HANDLE_1_OFF) = 0;
            *reinterpret_cast<std::uint32_t*>(
                aip_bytes + offsets::AIPROCESS_TARGET_HANDLE_2_OFF) = 0;
            *reinterpret_cast<void**>(
                aip_bytes + offsets::AIPROCESS_CACHED_ATTACKER_OFF) = nullptr;
            *reinterpret_cast<void**>(
                aip_bytes + offsets::AIPROCESS_CACHED_TARGET_OFF) = nullptr;
            *reinterpret_cast<std::uint32_t*>(
                aip_bytes + offsets::AIPROCESS_LOCK_COUNTER_OFF) = 0;
            *(aip_bytes + offsets::AIPROCESS_ALIVE_BYTE_OFF) = 0;
            FW_LOG("[ghost-proxy] F9: AIProcess @ %p — zeroed handles "
                   "(+0x68/+0x6C), raw caches (+0x178/+0x180), lock "
                   "counter (+0x170), alive byte (+0xDF)",
                   aiproc);
        } else {
            FW_DBG("[ghost-proxy] F9: AIProcess at +0x328 is NULL "
                   "(combat tier not yet promoted); skipping AIProc "
                   "field zero pass");
        }
        // Clear is1P bit on actor flags
        auto* flag_byte = proxy_bytes + offsets::ACTOR_IS_1P_FLAGS_OFF;
        const std::uint8_t before_1p = *flag_byte;
        *flag_byte = before_1p & ~offsets::ACTOR_IS_1P_FLAGS_BIT;
        FW_LOG("[ghost-proxy] F9: actor+0x%lX is1P flag before=0x%02X "
               "after=0x%02X (cleared bit 0x%02X)",
               static_cast<unsigned long>(offsets::ACTOR_IS_1P_FLAGS_OFF),
               before_1p, *flag_byte,
               offsets::ACTOR_IS_1P_FLAGS_BIT);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] F9: SEH writing zero block / is1P");
    }

    // Build 33 — F5: install MagicTarget vt[4] immunity shim.
    //
    // ghost+0x110 = MagicTarget inline sub-object (per Agent F5 + F9).
    // Its first 8 bytes are the vtable pointer. We replace it with a
    // SHIM vtable: copy of the real vtable EXCEPT slot 4 (= byte offset
    // 0x20) which points to `magic_target_immune_stub`.
    //
    // Effect: when raider's hit path runs `sub_140C62EE0` line 7591:
    //   (*(actor+0x110)+0x20)(actor+0x110)
    // it dispatches our stub → returns 1 → HP-delta caller returns 0
    // at line 7594 → NO damage applied to ghost, NO AIProcess walk,
    // NO HighProcess walk, NO AV chain → entire combat-damage crash
    // class (RVA 0x101E9C9 GetRaceData and friends) eliminated.
    //
    // Other slots passthrough to the real engine vtable functions
    // (which all null-check AIProcess and fast-return safely on
    // sanitized ghost).
    //
    // Shim lifetime: per-DLL static. Built ONCE on first ghost spawn
    // from a snapshot of the real vftable read off the ghost's just-
    // ctor'd +0x110. All subsequent ghost spawns reuse the same shim.
    {
        static std::uint64_t s_magic_target_shim_vt[64] = {};
        static std::atomic<bool> s_shim_ready{false};
        __try {
            if (!s_shim_ready.load(std::memory_order_acquire)) {
                const std::uint64_t real_vt =
                    *reinterpret_cast<std::uint64_t*>(
                        proxy_bytes + offsets::ACTOR_MAGIC_TARGET_OFF);
                if (real_vt != 0) {
                    // Copy 64 slots (= 512 bytes) of the real vftable.
                    // MagicTarget interfaces typically have ≤32 slots
                    // but we over-copy to be safe; the extra slots are
                    // .rdata so the read is safe.
                    std::memcpy(s_magic_target_shim_vt,
                                reinterpret_cast<void*>(real_vt),
                                sizeof(s_magic_target_shim_vt));
                    // Override slot 4 with our immunity stub.
                    s_magic_target_shim_vt[
                        offsets::MAGIC_TARGET_VT_IMMUNITY_SLOT] =
                        reinterpret_cast<std::uint64_t>(
                            &magic_target_immune_stub);
                    s_shim_ready.store(true,
                                        std::memory_order_release);
                    FW_LOG("[ghost-proxy] F5: MagicTarget shim built "
                           "from real_vt=0x%llX; slot %zu overridden "
                           "with immune_stub @ %p",
                           static_cast<unsigned long long>(real_vt),
                           offsets::MAGIC_TARGET_VT_IMMUNITY_SLOT,
                           reinterpret_cast<void*>(
                               &magic_target_immune_stub));
                } else {
                    FW_WRN("[ghost-proxy] F5: real MagicTarget vtable "
                           "at proxy+0x110 is NULL; cannot build shim");
                }
            }
            if (s_shim_ready.load(std::memory_order_acquire)) {
                *reinterpret_cast<std::uint64_t*>(
                    proxy_bytes + offsets::ACTOR_MAGIC_TARGET_OFF) =
                    reinterpret_cast<std::uint64_t>(s_magic_target_shim_vt);
                FW_LOG("[ghost-proxy] F5: proxy+0x%lX = shim vtable %p "
                       "(damage immunity active)",
                       static_cast<unsigned long>(
                           offsets::ACTOR_MAGIC_TARGET_OFF),
                       static_cast<void*>(s_magic_target_shim_vt));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_WRN("[ghost-proxy] F5: SEH building/writing MagicTarget "
                   "shim at proxy+0x110");
        }
    }

    // Build 29 Fase 1 — Clear "isPlayer" bits at Actor+0x2D0 (actorFlags_720).
    //
    // Rationale (verified by Agent 3 dossier + funcs_0302.md:11312-11413):
    //   We spawn proxy via PlaceAtMe with baseForm = player.baseForm (PlayerNPC,
    //   form 0x07). The Actor ctor (sub_140C57640) inherits PlayerNPC's
    //   "player identity" flags and sets bit 0x4000000 (isPlayer) and bit
    //   0x40000000 (player-aux) on the new Actor at +0x2D0.
    //
    //   Every IsHostile / target-screener function in the engine BRANCHES on
    //   bit 0x4000000:
    //     - sub_140C7AD40 funcs_0302.md:11413 takes the player-singleton
    //       fast-path when bit set → derefs `qword_1430DBF78[257117]` (the
    //       real player singleton) treating ghost as if it were the PC.
    //     - sub_140C7ABC0 funcs_0302.md:11312 short-circuits returning 1
    //       when target has bit 0x4000000 → AddTarget's validator sees ghost
    //       as "always a valid existing player target" and skips the proper
    //       relation check.
    //
    //   Result without this fix: ghost is treated as "the player" by every
    //   AI subsystem, raiders never properly aggro ghost (they think they're
    //   already targeting "the player" via singleton), and downstream code
    //   that reads player-only state on the ghost derefs into stale/wrong
    //   memory → Build 29.1 crash at RVA 0x308AE7 was downstream of one such
    //   misidentification.
    //
    // Fix: clear bits 0x4000000 AND 0x40000000 immediately after spawn.
    // Defensive — covers BOTH the AI-decision drift AND the crash chain.
    // The proxy keeps PlayerNPC's other state (anim graph, body mesh, etc.)
    // which we WANT for the body-ghost renderer; only the "is the player"
    // identity bits get stripped.
    __try {
        auto* flags720 = reinterpret_cast<std::uint32_t*>(proxy_bytes + 0x2D0);
        const std::uint32_t before = *flags720;
        *flags720 &= ~0x4000000u;   // clear isPlayer
        *flags720 &= ~0x40000000u;  // clear player-aux
        const std::uint32_t after = *flags720;
        FW_LOG("[ghost-proxy] Fase 1: cleared isPlayer bits @ +0x2D0  "
               "before=0x%08X after=0x%08X (mask=0x44000000)",
               before, after);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] SEH clearing isPlayer bits at +0x2D0");
    }

    // Build 28e: spawn_ghost_actor (= PlaceAtMe full path) handles the
    // entire engine init internally — Actor ctor + vt[13] flag setter +
    // vt[191] AI init + vt[170] SetParentRef + NEW_REFR_DATA dispatcher.
    // Caller deferred the call until cell-attach state is stable so
    // PlaceAtMe internals don't crash on IsAttachable. No manual vt
    // calls or dummy buffers needed.

    // Copy position + rotation from anchor (local player) — proxy spawned
    // at player's location initially. Build 29 will add per-frame sync to
    // peer coords.
    __try {
        float* anchor_pos = reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(player) + 0xD0);
        *reinterpret_cast<float*>(proxy_bytes + 0xD0) = anchor_pos[0];
        *reinterpret_cast<float*>(proxy_bytes + 0xD4) = anchor_pos[1];
        *reinterpret_cast<float*>(proxy_bytes + 0xD8) = anchor_pos[2];
        float* anchor_rot = reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(player) + 0xC0);
        *reinterpret_cast<float*>(proxy_bytes + 0xC0) = anchor_rot[0];
        *reinterpret_cast<float*>(proxy_bytes + 0xC4) = anchor_rot[1];
        *reinterpret_cast<float*>(proxy_bytes + 0xC8) = anchor_rot[2];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] SEH writing pos/rot");
    }

    // Build 60 fix A (2026-05-24) — FormID change via vt[65] SetFormID.
    //
    // Per re/walker_inventory/AGENT_FORM_corruption.md the previous code
    // raw-wrote proxy+0x14 = ghost_form_id, which BROKE the invariant
    // `bucket_entry.fid == form_ptr->+0x14`. PlaceAtMe had inserted the
    // proxy into the global form-table at hash(engine_fid) — after our
    // raw write, the form's FID was 0xFF000001 but its bucket entry
    // still keyed on engine_fid. Engine rehash/compaction code paths
    // then mis-located the entry, eventually the slot was freed and the
    // BSFixedString allocator reused it, writing ASCII bytes from
    // ".rdata strings" over the bucket. Subsequent bucket walkers AV'd
    // (RVA 0x3157A2 with rcx containing ASCII fragments).
    //
    // Fix: use the engine's vt[65] SetFormID, which atomically:
    //   1. Erases the bucket at hash(old_fid) under the form-table
    //      write-lock.
    //   2. Writes form->+0x14 = new_fid.
    //   3. Reinserts under hash(new_fid).
    // Result: the invariant is preserved. No slot orphan, no reuse,
    // no ASCII corruption.
    //
    // vt[65] = byte offset 0x208 in TESForm vtable. Default body is
    // sub_1403132A0 (the engine erase-then-reinsert helper); some Actor
    // subclasses override, but the override still maintains the
    // invariant.
    std::uint32_t engine_fid_before = 0;
    std::uint32_t engine_flags_before = 0;
    std::uint32_t handle_field_before = 0;
    bool set_form_id_ok = false;
    __try {
        engine_fid_before   = *reinterpret_cast<std::uint32_t*>(proxy_bytes + offsets::FORMID_OFF);
        engine_flags_before = *reinterpret_cast<std::uint32_t*>(proxy_bytes + offsets::FLAGS_OFF);
        handle_field_before = *reinterpret_cast<std::uint32_t*>(proxy_bytes + 0x28);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] SEH reading pre-state fid/flags");
    }

    // Call vt[65] SetFormID. Signature: void(__fastcall*)(TESForm*, u32 new_fid).
    using SetFormIDViaVtFn = void (__fastcall *)(void* form, std::uint32_t new_fid);
    __try {
        void** vt = *reinterpret_cast<void***>(proxy);
        auto set_form_id_vt65 = reinterpret_cast<SetFormIDViaVtFn>(vt[65]);
        if (set_form_id_vt65) {
            set_form_id_vt65(proxy, ghost_form_id);
            set_form_id_ok = true;
            FW_LOG("[ghost-proxy] vt[65] SetFormID OK: engine_fid=0x%08X -> "
                   "ghost_form_id=0x%08X (atomic erase+reinsert under "
                   "form-table write-lock; bucket invariant preserved)",
                   engine_fid_before, ghost_form_id);
        } else {
            FW_WRN("[ghost-proxy] vt[65] is null — falling back to raw write "
                   "(known-broken; will cause form-table corruption)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] SEH inside vt[65] SetFormID — falling back to raw");
    }

    // Fallback raw write if vt[65] failed. KNOWN to break invariant; only
    // here as last-resort to avoid leaving the proxy with engine_fid in
    // our private registry.
    if (!set_form_id_ok) {
        __try {
            *reinterpret_cast<std::uint32_t*>(proxy_bytes +
                offsets::FORMID_OFF) = ghost_form_id;
            FW_WRN("[ghost-proxy] FALLBACK raw write proxy+0x14 = 0x%08X "
                   "(WILL cause form-table bucket invariant violation; "
                   "expect AV @ RVA 0x3157A2 later)", ghost_form_id);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[ghost-proxy] SEH in fallback raw write");
        }
    }

    // Mark TEMPORARY (always safe; same offset, doesn't touch hash bucket).
    __try {
        *reinterpret_cast<std::uint32_t*>(proxy_bytes +
            offsets::FLAGS_OFF) |= offsets::TESFORM_FLAG_TEMPORARY;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[ghost-proxy] SEH OR-ing TEMPORARY flag");
    }

    // Register proxy ptr under our ghost_form_id in client-side lookup.
    // The existing ghost_ai_set_combat_target hook resolves server-
    // broadcast 0xFF000001 → proxy_ptr via this map.
    register_ghost_duplicate(ghost_form_id, proxy);

    // Cache the handle from CreateByTypeCode for set_combat_target hook.
    if (new_handle != 0) {
        g_ghost_duplicate_handle.store(new_handle,
                                        std::memory_order_release);
    }

    // Build 60 (2026-05-24) — REMOVED the Build 56 deregister call.
    //
    // Build 56 deregister was based on the same broken assumption: it
    // tried to erase the bucket at hash(0xFF000001) but the entry was
    // actually keyed by engine_fid (= 0xFF001393 or similar). It always
    // returned result=0 (entry not found) → leftover orphan slot → ASCII
    // corruption (root cause of all 0x3157A2 AVs).
    //
    // With Fix A (vt[65] SetFormID) above, the proxy now lives properly
    // keyed by ghost_form_id (0xFF000001) in the global table. Walkers
    // can find it normally. Hook 5 (form-table rehydrator guard) and
    // Hook 6 (death broadcast guard) still protect against rare walker
    // crashes. NO deregister needed.

    // Build 48 (2026-05-17 night) — SYNCHRONOUS baseForm swap.
    //
    // Build 47 live test crashed at RVA 0xCDFD9D (Client B) and 0x16632B9
    // (Client A) — same class as Build 37 documented at line ~1693 of
    // this file. Both crashes walk ghost.baseForm.+0xF0 sublist, hit
    // sentinel vt[103] = 0xFFFFFFFFFFFFFFFF on PlayerNPC sublist entries.
    //
    // Root cause: between PlaceAtMe completion (T+0ms) and npc_ai_suppress
    // detour visit of ghost (T+17+ ms = first frame walk), engine has a
    // ~8-17ms window where it processes the freshly-spawned ghost
    // actor with ghost.baseForm = PlayerNPC (fid 0x07). Re-enabling
    // additional hooks in Build 47 (orchestrator, havok_step,
    // hit_applier, process_movement, set_combat_target) added engine
    // paths that touch ghost in that window. The baseForm walker
    // inside one of those paths AVs on PlayerNPC's special-case
    // sublist entries.
    //
    // Fix: synchronously swap ghost.baseForm BEFORE returning from
    // spawn_ghost_proxy. By the time we reach here, the per-frame
    // npc_ai_suppress walker has typically run dozens of times and
    // already cached a safe vanilla TESNPC pointer (the 19-second
    // session warmup before user spawns ghost is plenty). Build 47
    // log line 2048: `[basebrm-swap] CACHED safe vanilla TESNPC: ptr=
    // ... formID=0x00026F37` 19 seconds before spawn — confirmation.
    //
    // try_swap_ghost_baseform internally early-outs if safe_base isn't
    // cached yet (returns false, swap deferred to first walker visit
    // as before). It also early-outs on double-call (g_ghost_baseform_swapped
    // atomic flag).
    //
    // After the swap, every engine read of ghost.baseForm.+0xN gets
    // the vanilla TESNPC fields. PlayerNPC special-cases (155+ branches
    // per Agent F3 dossier) never fire on ghost. The whole crash CLASS
    // from Build 37 should be eliminated.
    try_swap_ghost_baseform(proxy);

    FW_LOG("[ghost-proxy] Build 28c spawn via CreateByTypeCode: "
           "proxy=%p engine_handle=0x%08X engine_fid_before=0x%08X "
           "engine_flags_before=0x%08X handle_field_before=0x%08X "
           "baseForm=%p ghost_fid=0x%08X (was base_form_id=0x%08X)",
           proxy, new_handle, engine_fid_before, engine_flags_before,
           handle_field_before, player_base, ghost_form_id, base_form_id);

    return proxy;
}

void update_ghost_proxy_position(void* proxy,
                                  float x, float y, float z) noexcept
{
    if (!proxy || !g_set_position_engine) return;
    float xyz[3] = { x, y, z };
    __try {
        g_set_position_engine(proxy, xyz);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        static std::atomic<std::uint64_t> seh_count{0};
        const auto n = seh_count.fetch_add(1, std::memory_order_relaxed);
        if (n < 5) {
            FW_ERR("[ghost-proxy] SEH in SetPosition #%llu proxy=%p "
                   "xyz=(%.1f,%.1f,%.1f)",
                   static_cast<unsigned long long>(n), proxy, x, y, z);
        }
    }
}

void update_ghost_proxy_rotation(void* proxy,
                                  float rx, float ry, float rz) noexcept
{
    if (!proxy || !g_set_rotation_engine) return;
    float rot[3] = { rx, ry, rz };
    __try {
        g_set_rotation_engine(proxy, rot);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        static std::atomic<std::uint64_t> seh_count{0};
        const auto n = seh_count.fetch_add(1, std::memory_order_relaxed);
        if (n < 5) {
            FW_ERR("[ghost-proxy] SEH in SetRotation #%llu proxy=%p",
                   static_cast<unsigned long long>(n), proxy);
        }
    }
}

// ============================================================================
// B6.6w5 Build 29 — CombatTargetSelectorFixed installation.
//
// Per-aiproc dedup: each raider's AIProcess is recorded once we install a
// Fixed selector on it. Re-install attempts return success without doing
// anything (the existing selector keeps winning the per-frame promoter pick
// at priority=3).
//
// Thread safety:
//   - The dedup set is guarded by a mutex.
//   - The actual install_fixed_selector_on_raider body MUST be called from
//     the main thread (engine's BSTArray at aiproc+0x100 is not lock-free).
//     The hook site (npc_ai_suppress::detour_actor_update_perframe) is
//     guaranteed main-thread by MinHook + the engine's per-frame walker.
// ============================================================================

namespace {

std::mutex                           g_fixed_sel_mu;
std::unordered_set<void*>            g_fixed_sel_installed_aiprocs;  // aiproc ptr set
std::unordered_set<void*>            g_ghost_combat_controllers;     // controller ptr set (Build 42)
std::unordered_set<std::uint32_t>    g_ghost_engaged_raider_fids;    // raider fid set (Build 43)
std::atomic<std::uint64_t>           g_fixed_sel_install_attempts{0};
std::atomic<std::uint64_t>           g_fixed_sel_install_successes{0};
std::atomic<std::uint64_t>           g_fixed_sel_install_failures{0};
std::atomic<std::uint64_t>           g_fixed_sel_install_dedup_hits{0};

// Build 30 Fix 3 — Inline handle resolver (no refcount mutation).
//
// Mirrors sub_14022CC20 (funcs_0120.md:10046) but skips the
// _InterlockedIncrement/Decrement on refcount slots. Safe for transient
// validation during purge: we're only READING ptr+flags from the global
// handle table, no ownership transfer.
//
// Returns the resolved Actor* or nullptr if:
//   - handle is 0
//   - handle table base is null
//   - entry's active bit (0x4000000) is clear
//   - entry's generation bits don't match the handle's
//   - actor's own generation (at actor+40 >> 11) doesn't match index
//   - any read faults (e.g., table entry crosses an unmapped page)
static void* resolve_handle_inline(std::uint32_t handle,
                                   std::uint8_t* htab_base) noexcept {
    if (!handle || !htab_base) return nullptr;
    __try {
        const std::uint32_t idx = handle & 0x1FFFFFu;
        const std::uint32_t gen = handle & 0x3E00000u;
        auto* entry = htab_base + 16ULL * idx;
        const std::uint64_t ptr = *reinterpret_cast<std::uint64_t*>(entry + 8);
        if (!ptr) return nullptr;
        const std::uint32_t flags = *reinterpret_cast<std::uint32_t*>(entry);
        if (!(flags & 0x4000000u) || (flags & 0x3E00000u) != gen) {
            return nullptr;  // stale: generation mismatch or freed slot
        }
        void* actor = reinterpret_cast<void*>(ptr - 32);
        // Cross-check: actor's stored generation/index must match handle's idx.
        // Engine uses this same check at sub_14022CC20 line 10086.
        const std::uint32_t actor_gen =
            *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(actor) + 40);
        if ((actor_gen >> 11) != idx) return nullptr;
        return actor;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Validates that an Actor* has a readable baseForm (TESActorBase) suitable
// for the engine's factions/relationship walks. Same logic as
// ghost_hostility_guard::is_actor_baseform_valid but inlined here for the
// purge hot path.
static bool actor_baseform_valid(void* actor) noexcept {
    if (!actor) return false;
    __try {
        const auto baseform = *reinterpret_cast<std::uint64_t*>(
            reinterpret_cast<std::uint8_t*>(actor) + 0xE0);
        if (!baseform) return false;
        const std::uint8_t formType =
            *reinterpret_cast<std::uint8_t*>(baseform + 0x1A);
        if (formType != 0x2D && formType != 0x2E) return false;
        const std::uint32_t fcount =
            *reinterpret_cast<std::uint32_t*>(baseform + 0xB8 + 0x10);
        return fcount <= 4096;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

// Build 30 Fix 3 — PURGE stale entries from `controller+32 known_targets[]`.
//
// Strategy: walk the 24-byte-stride array at controller+0x20 (count at
// controller+0x30). For each entry, read the handle at +0x00, inline-
// resolve it to Actor*, and validate the resulting baseForm. If invalid
// (= the handle resolves to freed memory or to an actor with a corrupt
// baseForm), zero the handle field at entry+0. The engine's resolve-or-
// skip pattern at sub_140E924A0:2229 (`!v53[0]`) then treats the entry
// as empty without faulting.
//
// Idempotent: zero-handle entries are skipped (no change). Thread-safe
// only when controller+0x120 spinlock is held by the caller, OR when no
// other thread is concurrently mutating the array. We call this from
// install_fixed_selector_seh's main-thread context BEFORE AddTarget,
// without explicitly holding the lock — AddTarget will acquire its own
// recursive write-lock; concurrent reader threads would tolerate a
// transient zero-handle (engine's resolve_handle returns null → skip).
//
// Returns true if walk completed (with or without purges), false on SEH.
bool purge_stale_known_targets(void* controller) noexcept {
    if (!controller || !g_handle_table_base) return false;

    std::uint32_t purged = 0;
    std::uint32_t total  = 0;

    __try {
        auto* ctrl_bytes = reinterpret_cast<std::uint8_t*>(controller);
        const std::uint32_t count =
            *reinterpret_cast<std::uint32_t*>(
                ctrl_bytes + offsets::CONTROLLER_KNOWN_TGT_COUNT_OFF);
        auto* array_base =
            *reinterpret_cast<std::uint8_t**>(
                ctrl_bytes + offsets::CONTROLLER_KNOWN_TGT_BASE_OFF);
        if (!array_base || count == 0) return true;
        if (count > 4096) {
            // Sanity bound: vanilla raiders have <16 known_targets typically.
            // >4096 means we're reading garbage from controller itself.
            FW_WRN("[purge] controller=%p count=%u suspiciously large; bail",
                   controller, count);
            return false;
        }
        total = count;
        for (std::uint32_t i = 0; i < count; ++i) {
            auto* entry =
                array_base + offsets::KNOWN_TGT_ENTRY_STRIDE * i;
            const std::uint32_t handle =
                *reinterpret_cast<std::uint32_t*>(entry);
            if (!handle) continue;   // already null/skipped

            void* actor =
                resolve_handle_inline(handle, g_handle_table_base);
            if (!actor || !actor_baseform_valid(actor)) {
                // Atomic write to avoid torn read by concurrent threads.
                InterlockedExchange(
                    reinterpret_cast<volatile LONG*>(entry), 0);
                ++purged;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[purge] SEH walking controller=%p known_targets[]",
               controller);
        return false;
    }

    if (purged > 0) {
        FW_LOG("[purge] controller=%p purged %u/%u stale entries "
               "from known_targets[] (zeroed handles → engine skip)",
               controller, purged, total);
    }
    return true;
}

// Build 42 (2026-05-17) — query for ghost_combat_force alive-counter
// detour. Returns true if `controller` was registered via
// install_fixed_selector_on_raider as engaged with the ghost.
bool is_ghost_combat_controller(void* controller) noexcept {
    if (!controller) return false;
    std::lock_guard<std::mutex> lk(g_fixed_sel_mu);
    return g_ghost_combat_controllers.count(controller) != 0;
}

bool is_ghost_engaged_raider_fid(std::uint32_t form_id) noexcept {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    std::lock_guard<std::mutex> lk(g_fixed_sel_mu);
    return g_ghost_engaged_raider_fids.count(form_id) != 0;
}

void reset_fixed_selector_tracking() noexcept {
    std::lock_guard<std::mutex> lk(g_fixed_sel_mu);
    const auto n = g_fixed_sel_installed_aiprocs.size();
    g_fixed_sel_installed_aiprocs.clear();
    g_ghost_combat_controllers.clear();   // Build 42
    g_ghost_engaged_raider_fids.clear();  // Build 43
    FW_LOG("[fixed-sel] tracking reset (cleared %zu aiproc entries)", n);

    // Build 35 (2026-05-16) — also reset the baseForm-swap state.
    //
    // On ghost despawn (e.g., peer disconnect, LoadGame, DLL unload), the
    // proxy actor is gone; the next ghost spawn gets a fresh actor with
    // a fresh PlayerNPC baseForm. We need to re-run the swap on the new
    // proxy, so clear the "already swapped" flag. The cached safe TESNPC
    // pointer itself is fine to keep — it's an engine singleton that
    // survives across game sessions (the underlying TESNPC record is
    // loaded into the form-table for the whole gameplay session).
    //
    // We DO clear `g_safe_npc_base` on full LoadGame to be safe, because
    // a save loaded from a different cell set could conceivably reshuffle
    // the form table (this is paranoid — TESNPCs are static records, not
    // dynamic — but cheap).
    const bool had_swap =
        g_ghost_baseform_swapped.exchange(false, std::memory_order_acq_rel);
    void* prev_safe_base = g_safe_npc_base.exchange(nullptr,
                                                    std::memory_order_acq_rel);
    g_safe_npc_base_formid.store(0, std::memory_order_release);
    g_safe_npc_acquire_attempts.store(0, std::memory_order_release);
    FW_LOG("[basebrm-swap] reset on selector teardown: had_swap=%d "
           "prev_safe_base=%p (will re-acquire on next walker pass)",
           had_swap ? 1 : 0, prev_safe_base);
}

// Build 31 Phase 1 — Extended purge of AIProcess stale-handle fields.
//
// Per Agent B2 + Agent D1 synthesis: the raider's combat AIProcess (at
// Actor+0x328) inherits multiple stale fields from save buffer that
// LoadGame never validates against the (never-reset) handle table.
// Beyond controller+0x20 (purged by purge_stale_known_targets) the
// vulnerable fields are:
//
//   aiproc+0x100  selectors BSTArray (heap ptrs to refcounted selectors)
//   aiproc+0x178  cached attacker raw Actor* (tick-lifetime, no refcount)
//   aiproc+0x180  cached target   raw Actor* (tick-lifetime, no refcount)
//
// Strategy (B2 §5):
//  - Selectors: walk count, drop entries whose ptr/refcount is invalid.
//    Engine's iterators tolerate null slots (resolve-or-skip pattern).
//  - Raw caches: zero unconditionally. Engine repopulates pre-tick from
//    +0x68/+0x6C handles via sub_14087F9D0 (funcs_0240.md:10156). One
//    frame of "no override" is safer than holding a stale raw Actor*.
//
// Thread safety: caller MUST be main thread. No locks acquired here —
// the engine's own selector list / raw caches are tick-scoped, so we
// run BEFORE the tick to clear them, and the engine repopulates DURING
// the tick. Concurrent reads from net thread would be unsafe; this is
// not called from net thread.
//
// Returns: true if walk completed (with or without purges), false on SEH.
static bool purge_stale_aiproc_handles(void* aiproc) noexcept {
    if (!aiproc) return false;
    auto* aiproc_bytes = reinterpret_cast<std::uint8_t*>(aiproc);

    // 1. Zero the two raw Actor* caches. Engine's pre-tick prologue
    //    (sub_14087F9D0) will re-resolve from +0x68/+0x6C handle fields
    //    using the live handle table. If those handles are themselves
    //    stale, the resolver returns null cleanly (it does its own
    //    generation check) — so we get a safe "no cached actor" state.
    __try {
        auto** cached_attacker = reinterpret_cast<void**>(
            aiproc_bytes + offsets::AIPROCESS_CACHED_ATTACKER_OFF);
        auto** cached_target = reinterpret_cast<void**>(
            aiproc_bytes + offsets::AIPROCESS_CACHED_TARGET_OFF);
        const void* prev_atk = *cached_attacker;
        const void* prev_tgt = *cached_target;
        *cached_attacker = nullptr;
        *cached_target   = nullptr;
        if (prev_atk || prev_tgt) {
            FW_DBG("[purge-aiproc] aiproc=%p zeroed cached actors "
                   "(attacker=%p target=%p → 0,0)",
                   aiproc, prev_atk, prev_tgt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[purge-aiproc] SEH zeroing cached caches on aiproc=%p",
               aiproc);
        return false;
    }

    // 1b. Build 31.4 — Substitute stale scalar handles with GHOST handle
    //     instead of zeroing them.
    //
    // Build 31.3 zeroed aiproc+0x68 and aiproc+0x6C when the handle
    // resolved to a freed actor. Live test 2026-05-16 18:06:10 showed:
    //   - 5 raiders ALL had stale +0x68/+0x6C — zeroed cleanly
    //   - But immediately crashed at RVA 0xCD9C3F (sub_140CD9C30) reading
    //     `*(actor + 0x300)` with actor = NULL → fault addr 0x300, rcx=0
    //   - sub_140CD9C30 was called with NULL actor because some upstream
    //     code resolved one of our zeroed handles to NULL and passed it
    //     in without null-check
    //
    // Replacing stale → ghost-handle is safer:
    //   - Resolved actor = our ghost proxy (a real, valid Actor with
    //     populated +0x300 primary AIProcess from PlaceAtMe)
    //   - Downstream readers get a non-null actor and proceed normally
    //   - Coincidentally aligns with MVP goal: raider's "target" handle
    //     points at the ghost (= what we WANT them to fight anyway)
    //
    // Fallback to zero if ghost_handle is unavailable (early init).
    __try {
        const std::uint32_t ghost_handle =
            g_ghost_duplicate_handle.load(std::memory_order_acquire);
        struct { std::size_t off; const char* name; } slots[] = {
            { offsets::AIPROCESS_TARGET_HANDLE_1_OFF, "+0x68" },
            { offsets::AIPROCESS_TARGET_HANDLE_2_OFF, "+0x6C" },
        };
        for (const auto& s : slots) {
            auto* handle_field =
                reinterpret_cast<std::uint32_t*>(aiproc_bytes + s.off);
            const std::uint32_t handle = *handle_field;
            if (!handle) continue;   // already null
            void* resolved =
                resolve_handle_inline(handle, g_handle_table_base);
            if (resolved && actor_baseform_valid(resolved)) {
                continue;  // looks alive — leave alone
            }
            // Stale. Substitute with ghost handle (valid actor whose
            // +0x300 primary AIProcess is populated by PlaceAtMe).
            // If ghost_handle is 0 (early init), fall back to zero.
            const LONG new_val =
                static_cast<LONG>(ghost_handle != 0 ? ghost_handle : 0u);
            InterlockedExchange(
                reinterpret_cast<volatile LONG*>(handle_field), new_val);
            FW_LOG("[purge-aiproc] aiproc=%p stale handle at %s "
                   "was=0x%08X resolved=%p invalid → wrote 0x%08X "
                   "(%s)",
                   aiproc, s.name, handle, resolved,
                   static_cast<unsigned>(new_val),
                   ghost_handle != 0 ? "GHOST" : "ZERO_FALLBACK");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[purge-aiproc] SEH validating scalar handles on aiproc=%p",
               aiproc);
        // Don't bail — selector walk below is still worth attempting.
    }

    // 2. Validate selectors[]. Each entry is a heap ptr to a refcounted
    //    CombatTargetSelector* (NiRefObject base, refcount DWORD at +0x08).
    //    A valid selector has non-null ptr AND refcount > 0. Drop entries
    //    that fail either check by writing null to the slot. The engine's
    //    promoter (sub_14087B080) iterates this BSTArray and the loop at
    //    funcs_0240.md:6196 calls a vtable function — null entries would
    //    crash there, so we drop them ONLY if the slot is non-null AND
    //    its refcount/vtable looks invalid (we never null an originally-
    //    null slot, which would be redundant).
    //
    //    Sanity bound: vanilla AIProcess rarely has >16 selectors.
    //    >256 means we're reading garbage from aiproc itself.
    std::uint32_t purged_selectors = 0;
    std::uint32_t total_selectors  = 0;
    __try {
        const std::uint32_t count = *reinterpret_cast<std::uint32_t*>(
            aiproc_bytes + offsets::AIPROCESS_SELECTORS_COUNT_OFF);
        auto** array_base = *reinterpret_cast<void***>(
            aiproc_bytes + offsets::AIPROCESS_SELECTORS_BASE_OFF);
        if (array_base && count > 0 && count <= 256) {
            total_selectors = count;
            for (std::uint32_t i = 0; i < count; ++i) {
                void* sel = array_base[i];
                if (!sel) continue;  // already null

                bool valid = false;
                __try {
                    const std::uint32_t refcount =
                        *reinterpret_cast<std::uint32_t*>(
                            reinterpret_cast<std::uint8_t*>(sel) +
                            offsets::NIREFOBJECT_REFCOUNT_OFF);
                    // vtable at selector+0 should be in game module
                    // (high address ~0x7FF...). If it's in low memory
                    // (< 0x10000_0000), it's almost certainly garbage.
                    const std::uintptr_t vtable =
                        *reinterpret_cast<std::uintptr_t*>(sel);
                    valid = (refcount > 0 && refcount < 0x10000u) &&
                            (vtable > 0x10000000000ULL);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    valid = false;
                }

                if (!valid) {
                    array_base[i] = nullptr;
                    ++purged_selectors;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[purge-aiproc] SEH walking selectors[] on aiproc=%p",
               aiproc);
        // Even if selector walk failed, the raw-cache zero above succeeded.
        return false;
    }

    if (purged_selectors > 0) {
        FW_LOG("[purge-aiproc] aiproc=%p selectors %u/%u nulled "
               "(refcount==0 or bad vtable)",
               aiproc, purged_selectors, total_selectors);
    }
    return true;
}

// Build 31 Phase 1 — Composite purge for a raider Actor.
//
// Orchestrates the full stale-state cleanup for one actor:
//   1. Resolve combat AIProcess at actor+0x328 (Build 13b verified offset)
//   2. Resolve CombatController at aiproc+0x40
//   3. Purge controller+0x20 known_targets[] (Fix 3, existing)
//   4. Purge aiproc selectors[] + zero raw Actor* caches (new)
//
// Returns true if at least one purge sub-step ran successfully.
// All sub-steps are SEH-caged; partial success is acceptable (better
// than nothing). Idempotent: re-running on an already-clean actor is
// a no-op walk.
bool purge_stale_actor_state(void* actor) noexcept {
    if (!actor) return false;

    void* aiproc      = nullptr;
    void* controller  = nullptr;
    __try {
        aiproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(actor) +
            offsets::ACTOR_AIPROCESS_OFF);
        if (aiproc) {
            controller = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(aiproc) +
                offsets::AIPROCESS_CONTROLLER_OFF);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_WRN("[purge-actor] SEH reading aiproc/controller on actor=%p",
               actor);
        return false;
    }

    if (!aiproc) {
        // Actor has no combat AIProcess yet — nothing to purge.
        return false;
    }

    bool any_ok = false;
    if (controller) {
        any_ok |= purge_stale_known_targets(controller);
    }
    any_ok |= purge_stale_aiproc_handles(aiproc);
    return any_ok;
}

namespace {

// Outcome enum returned by the SEH-only helper. Keeps __try blocks isolated
// from destructible C++ objects (mutex/lock_guard) in the outer function —
// MSVC C2712 forbids __try in functions requiring object unwinding.
enum class InstallSehOutcome : int {
    Ok            = 0,
    NullPrim      = 1,   // an engine primitive ptr was null
    SehReadActor  = 2,   // SEH while dereferencing actor+0x300 / aiproc+0x40
    NoAiproc      = 3,   // raider has no AIProcess yet (transient)
    SehAddTarget  = 4,   // SEH in g_add_combat_target
    AddRejected   = 5,   // AddTarget returned 0
    SehAlloc      = 6,   // SEH in g_engine_heap_alloc
    AllocNull     = 7,   // heap returned null
    SehCtor       = 8,   // SEH in g_fixed_selector_ctor (block leaked)
};

// Pure-SEH helper: no destructible C++ objects in scope. Returns the outcome
// + (on success) the resolved aiproc/controller/block ptrs for logging.
// Designed for noexcept main-thread callers; never throws.
static InstallSehOutcome install_fixed_selector_seh(
    void*  raider_actor,
    void*  ghost_proxy,
    void** out_aiproc,
    void** out_controller,
    void** out_block) noexcept
{
    *out_aiproc     = nullptr;
    *out_controller = nullptr;
    *out_block      = nullptr;

    if (!g_add_combat_target || !g_fixed_selector_ctor ||
        !g_engine_heap_alloc || !g_engine_heap_desc) {
        return InstallSehOutcome::NullPrim;
    }

    void* aiproc      = nullptr;
    void* controller  = nullptr;
    __try {
        aiproc = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(raider_actor) +
            offsets::ACTOR_AIPROCESS_OFF);
        if (aiproc) {
            controller = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(aiproc) +
                offsets::AIPROCESS_CONTROLLER_OFF);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return InstallSehOutcome::SehReadActor;
    }
    if (!aiproc || !controller) {
        return InstallSehOutcome::NoAiproc;
    }
    *out_aiproc     = aiproc;
    *out_controller = controller;

    // Build 30 Fix 3 + Build 31 Phase 1 — EXTENDED purge before AddTarget.
    //
    // AddTarget's validator (sub_140E924A0) and notify loop iterate
    // `controller+0x20 known_targets[]`. But ALSO downstream the engine
    // walks `aiproc+0x100` selectors AND derefs `aiproc+0x178/+0x180`
    // raw Actor* caches. All three vectors carry stale handles from
    // save-restore (D1 dossier: LoadGame restores from save buffer
    // without validating against the never-reset handle table).
    //
    // Build 30.1 (controller+0x20 only) live-test 2026-05-16 16:15:12:
    // PURGE 5/5 succeeded → AddTarget OK → but vt[9] crash at
    // HighProcess+0x68 (= aiproc+0x68/+0x6C area, B2 dossier).
    // Build 31 Phase 1: add aiproc-level purge here so ALL 3 stale
    // vectors get cleaned before the engine touches them in any chain.
    //
    // Order matters: clean aiproc FIRST (zeros +0x178/+0x180 raw caches),
    // then controller (zeros known_targets handles). AddTarget then walks
    // a doubly-clean controller+aiproc state.
    purge_stale_aiproc_handles(aiproc);
    purge_stale_known_targets(controller);

    char added = 0;
    __try {
        added = g_add_combat_target(controller, ghost_proxy);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Build 30 Fix 1 — LOCK RECOVERY.
        //
        // AddTarget (sub_140E91D70) acquires `controller + 0x120` spinlock
        // at funcs_0337.md:1877 BEFORE running the validator chain that
        // crashes on stale known_targets (Build 29.2 freeze, 2026-05-16
        // 08:11:48 log RVA 0x308AE7). Without recovery the lock stays
        // held → next thread acquiring the same controller spins forever →
        // main-thread freeze.
        //
        // Spinlock layout (funcs_0471.md:8136 + funcs_0472.md:42):
        //   +0x00: owner TID (write-lock)
        //   +0x04: count (= 0x80000001 single writer)
        // sub_1416592C0 safely releases when we own the lock.
        //
        // Nested SEH because reading +0x120 of a corrupted controller
        // could itself fault — if the controller's pointer was already
        // garbage, the AV happened upstream and we just bail.
        __try {
            if (g_lock_release_write) {
                auto* lock_obj =
                    reinterpret_cast<std::uint8_t*>(controller) +
                    offsets::CONTROLLER_SPINLOCK_OFF;
                const std::uint32_t owner_tid =
                    *reinterpret_cast<std::uint32_t*>(lock_obj);
                if (owner_tid == GetCurrentThreadId()) {
                    g_lock_release_write(lock_obj);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Nested SEH — lock_obj itself was invalid. Nothing to recover.
        }
        return InstallSehOutcome::SehAddTarget;
    }
    if (!added) {
        return InstallSehOutcome::AddRejected;
    }

    void* block = nullptr;
    __try {
        block = g_engine_heap_alloc(g_engine_heap_desc,
                                    offsets::FIXED_SELECTOR_BLOCK_SIZE,
                                    0, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return InstallSehOutcome::SehAlloc;
    }
    if (!block) {
        return InstallSehOutcome::AllocNull;
    }
    *out_block = block;

    __try {
        g_fixed_selector_ctor(block, aiproc, ghost_proxy,
                              offsets::FIXED_SELECTOR_PRIORITY);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // block is leaked here — caller cannot safely free it without
        // knowing what the ctor partially wrote. Acceptable trade-off:
        // SEH inside the ctor is a one-shot diagnostic, not a hot path.
        return InstallSehOutcome::SehCtor;
    }
    return InstallSehOutcome::Ok;
}

} // namespace

// ============================================================================
// DORMANT — 2026-05-17 log evidence: function is never invoked in production
// because BOTH call sites (npc_ai_suppress::detour_actor_update_perframe gate
// + apply_npc_combat_target's Build 41 inline call) fail their preconditions:
//
//   Site 1 (npc_ai_suppress): gate `in_combat == true` requires raider's
//   Actor+0x2D0 bit 0x4000 set. The 5 server-aggro'd raiders never enter
//   combat tier on the client where player_A is in Sanctuary (different
//   cell from Concord raiders).
//
//   Site 2 (apply_npc_combat_target Build 41): inline call only fires when
//   target_form_id >= 0xFF000000 AND the function reached the write-success
//   branch. But apply_npc_combat_target returns false at the AIProcess-null
//   check before getting there (raider not in combat tier ⇒ +0x328 NULL).
//
// PROOF: Client A `fw_native.log` 17:29-17:39 contains:
//   - 1× `[fixed-sel] resolved: add_combat_target=... ctor=... heap_alloc=...`
//     (init-time resolution OK)
//   - 0× `[fixed-sel] installed #N raider=...`
//   - 0× `[fixed-sel] SEH ...`
//   - 0× `[fixed-sel] AddTarget rejected ...`
//   `g_fixed_sel_install_successes` is 0. Same on Client B.
//
// The function body is correct (verified against funcs_0240.md:6180-6196
// + funcs_0346.md ctors). The Fixed selector ctor + AddTarget primitive
// resolution succeeded at boot (line 7 of log). All preconditions for a
// successful call EXIST in memory — they just never get triggered.
//
// KEEP-AS-IS RATIONALE:
//   This is the canonical engine-native bridge for "force raider X to
//   combat target = ghost". It's the right primitive for the day raider
//   actually enters combat tier vs ghost. Cost: zero (function never
//   called). Body: SEH-caged and lock-recovery-safe. Don't delete.
//
// ALTERNATIVE (puppet fire bypass per re/AI_pipeline/section_08):
//   For visible muzzle/projectile WITHOUT the engine accepting ghost as
//   a real combat target, bypass this entire path and just call
//   WeaponFireHandler directly after writing weapon-state + aim. The
//   raider remains visually static (no rotation, no aggro stance) but
//   emits the fire visual. See ghost_combat_force.cpp banner for the
//   full 4-gate analysis.
// ============================================================================
bool install_fixed_selector_on_raider(void* raider_actor,
                                       void* ghost_proxy) noexcept
{
    g_fixed_sel_install_attempts.fetch_add(1, std::memory_order_relaxed);

    if (!raider_actor || !ghost_proxy || raider_actor == ghost_proxy) {
        g_fixed_sel_install_failures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Cheap aiproc resolution mirrored from the SEH helper, so we can dedup
    // BEFORE invoking the engine primitives. Wrapped in its own SEH cage to
    // keep this outer function free of __try (C2712 with mutex below).
    void* aiproc_for_dedup = [&]() -> void* {
        // Lambda body is a separate function under MSVC — __try is OK here.
        void* p = nullptr;
        __try {
            p = *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(raider_actor) +
                offsets::ACTOR_AIPROCESS_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            p = nullptr;
        }
        return p;
    }();

    if (aiproc_for_dedup) {
        std::lock_guard<std::mutex> lk(g_fixed_sel_mu);
        if (g_fixed_sel_installed_aiprocs.count(aiproc_for_dedup)) {
            g_fixed_sel_install_dedup_hits.fetch_add(
                1, std::memory_order_relaxed);
            return true;
        }
    }

    void* aiproc     = nullptr;
    void* controller = nullptr;
    void* block      = nullptr;
    const InstallSehOutcome rc = install_fixed_selector_seh(
        raider_actor, ghost_proxy, &aiproc, &controller, &block);

    if (rc != InstallSehOutcome::Ok) {
        switch (rc) {
        case InstallSehOutcome::NullPrim:
            FW_ERR("[fixed-sel] engine primitives not resolved — "
                   "add=%p ctor=%p heap_alloc=%p heap_desc=%p",
                   reinterpret_cast<void*>(g_add_combat_target),
                   reinterpret_cast<void*>(g_fixed_selector_ctor),
                   reinterpret_cast<void*>(g_engine_heap_alloc),
                   g_engine_heap_desc);
            break;
        case InstallSehOutcome::SehReadActor:
            FW_WRN("[fixed-sel] SEH reading aiproc/controller raider=%p",
                   raider_actor);
            break;
        case InstallSehOutcome::NoAiproc:
            // Raider not in combat state yet — caller should retry on a
            // later frame. Not a hard failure; do NOT count as failure.
            return false;
        case InstallSehOutcome::SehAddTarget:
            FW_ERR("[fixed-sel] SEH in AddTarget(ctrl=%p ghost=%p)",
                   controller, ghost_proxy);
            break;
        case InstallSehOutcome::AddRejected:
            FW_WRN("[fixed-sel] AddTarget rejected raider=%p ghost=%p "
                   "(sub_140E924A0 validation — likely ghost.faction/state "
                   "doesn't qualify). Will retry next frame.",
                   raider_actor, ghost_proxy);
            break;
        case InstallSehOutcome::SehAlloc:
            FW_ERR("[fixed-sel] SEH in heap_alloc(%zu)",
                   offsets::FIXED_SELECTOR_BLOCK_SIZE);
            break;
        case InstallSehOutcome::AllocNull:
            FW_ERR("[fixed-sel] heap_alloc returned null for %zu bytes",
                   offsets::FIXED_SELECTOR_BLOCK_SIZE);
            break;
        case InstallSehOutcome::SehCtor:
            FW_ERR("[fixed-sel] SEH in selector_ctor(block=%p aiproc=%p "
                   "ghost=%p prio=%d) — block leaked",
                   block, aiproc, ghost_proxy,
                   offsets::FIXED_SELECTOR_PRIORITY);
            break;
        case InstallSehOutcome::Ok:
            break;  // unreachable
        }
        g_fixed_sel_install_failures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Build 43: read raider's form_id for the engaged-fid set.
    // Wrapped in lambda to keep __try out of this function's frame
    // (C2712: function uses lock_guard which requires object unwinding).
    const std::uint32_t raider_fid = [&]() -> std::uint32_t {
        std::uint32_t fid = 0;
        __try {
            fid = *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(raider_actor) + 0x14);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            fid = 0;
        }
        return fid;
    }();

    {
        std::lock_guard<std::mutex> lk(g_fixed_sel_mu);
        g_fixed_sel_installed_aiprocs.insert(aiproc);
        // Build 42: also track the controller so alive-counter detour
        // can force-boost +0x110 on subsequent ticks.
        if (controller) g_ghost_combat_controllers.insert(controller);
        // Build 43: track raider fid so should_silence_combat NEVER
        // bails fire/dispatch for cross-peer-engaged raiders, even
        // when cache.combat_target_form_id oscillates back to 0.
        if (raider_fid != 0 && raider_fid != 0xFFFFFFFFu) {
            g_ghost_engaged_raider_fids.insert(raider_fid);
        }
    }

    // Build 42: expose query for the ghost_combat_force alive-counter detour.
    (void)0;  // marker for diff readability
    const auto n = g_fixed_sel_install_successes.fetch_add(
        1, std::memory_order_relaxed);
    if (n < 20 || (n % 50) == 0) {
        FW_LOG("[fixed-sel] installed #%llu raider=%p ghost=%p ctrl=%p "
               "aiproc=%p block=%p prio=%d",
               static_cast<unsigned long long>(n),
               raider_actor, ghost_proxy, controller, aiproc, block,
               offsets::FIXED_SELECTOR_PRIORITY);
    }
    return true;
}

} // namespace fw::engine
