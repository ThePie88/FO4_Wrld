// Reverse-engineered offsets for Fallout 4 1.11.191 (next-gen).
// Source: re/reference_fo4_offsets.md + memory/reference_fo4_offsets.md.
// All values are RVAs relative to Fallout4.exe module base (which is fixed
// on NG — no ASLR — but we still resolve at runtime via GetModuleHandleW).

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::offsets {

// --- Module-relative RVAs ---

// Papyrus-level engine entry points (all take REFR* pointers as first args).
constexpr std::uintptr_t KILL_ENGINE_RVA       = 0x00C612E0; // sub_140C612E0
constexpr std::uintptr_t LOOKUP_BY_FORMID_RVA  = 0x00311850; // sub_140311850

// TESObjectREFR vtable. vt[0x7A] = AddObjectToContainer (converged entry
// for player-container transfers in both directions).
constexpr std::uintptr_t TESOBJECTREFR_VTABLE_RVA = 0x02564838;
constexpr std::size_t    VT_ADD_TO_CONTAINER_SLOT = 0x7A;

// Player singleton (points to the active PlayerCharacter Actor*).
constexpr std::uintptr_t PLAYER_SINGLETON_RVA  = 0x032D2260;

// --- TESForm / TESObjectREFR struct field offsets ---
// Layout for 1.11.191 confirmed via Hex-Rays decompile of GetPositionX,
// GetParentCell, GetBaseObject natives.

constexpr std::size_t FORMID_OFF      = 0x14;  // TESForm::formID      (u32)
constexpr std::size_t FLAGS_OFF       = 0x10;  // TESForm::flags       (u32)
constexpr std::uint32_t FLAG_DISABLED = 0x800;

constexpr std::size_t ROT_OFF         = 0xC0;  // AngleX/Y/Z, radians  (3x f32)
constexpr std::size_t POS_OFF         = 0xD0;  // X/Y/Z                (3x f32)
constexpr std::size_t PARENT_CELL_OFF = 0xB8;  // TESObjectCELL*
constexpr std::size_t BASE_FORM_OFF   = 0xE0;  // TESForm* (baseForm)

// --- Constants ---

constexpr std::uint32_t PLAYER_FORMID = 0x14;  // Bethesda-hardcoded on PlayerCharacter

// --- BGSInventoryList runtime layout (source: B1.c IDA RE pass) ---
// Confirmed by decompile of GetItemCount real impl sub_140507660:
//   v25 = *(a1 + 248)              // REFR + 0xF8 → runtime inventory list
//   sub_141658FE0(v25 + 120)       // lock mutex at +0x78
//   count = *(u32)(v25 + 104)      // +0x68  — u32 entry count
//   entries = *(v25 + 88)          // +0x58  — BGSInventoryItem*
//   for (i = 0; i < count; ++i) entries += 16  // stride 16
// Each entry: { TESBoundObject* obj(+0), void* data(+8) }.
// obj+0x1A is formType byte (skip if == 0x38 i.e. LVLI leveled item).
// Per-entry count obtained via sub_140349B30(entry).
constexpr std::size_t REFR_INV_LIST_OFF       = 0xF8;   // REFR → BGSInventoryList*
constexpr std::size_t INVLIST_ENTRIES_OFF     = 0x58;   // list → entries ptr
constexpr std::size_t INVLIST_COUNT_OFF       = 0x68;   // list → u32 count
constexpr std::size_t INVLIST_MUTEX_OFF       = 0x78;   // BSSimpleMutex-ish
constexpr std::size_t INVENTORY_ITEM_STRIDE   = 0x10;   // 16 bytes
constexpr std::size_t INVENTORY_ITEM_OBJ_OFF  = 0x00;   // entry → TESBoundObject*

// formType byte at TESForm+0x1A: 0x38 = kLVLI leveled item, filter out in seed.
constexpr std::uint8_t FORMTYPE_OFF           = 0x1A;
constexpr std::uint8_t FORMTYPE_LVLI          = 0x38;

// Engine helpers for inventory iteration.
constexpr std::uintptr_t INVLIST_MUTEX_LOCK_RVA   = 0x01658FE0; // lock(mtx*)
constexpr std::uintptr_t INVLIST_MUTEX_UNLOCK_RVA = 0x016592B0; // unlock(mtx*)
constexpr std::uintptr_t INVITEM_GET_COUNT_RVA    = 0x00349B30; // entry → int count

// --- B3.b main menu auto-load hook ---
// sub_140B01290 is the MainMenu Scaleform registrar: binds AS3 callbacks
// ("onContinuePress"=0, "ContinueGame"=2, "requestLoadGame"=13, etc.) to
// indexed C++ handlers via sub_141B1A340(menu_obj, name, idx). Called once
// on the main thread when the MainMenu is being constructed.
//
// Hook point: after g_orig_register returns (main thread, engine ready,
// save subsystem initialized) we directly call the engine's LoadGame
// native — bypassing the main menu entirely. Zero keystroke simulation.
constexpr std::uintptr_t MAIN_MENU_REGISTRAR_RVA  = 0x00B01290;

// --- B4 world-state sync (quest stages + global variables) ---
//
// From re/setstage_report.txt + re/stage_core_report.txt:
//
// GlobalVariable.SetValue Papyrus native (sub_1411459E0 @ RVA 0x11459E0):
//   Signature: uint8_t __fastcall(VM*, uint32_t, TESGlobal*, float)
//   Action:    *(float*)(TESGlobal + 0x30) = value
//   Gate:      refuses if TESGlobal.flags (at +0x10) & 0x40 (const)
//
// TESGlobal field offsets (class TESGlobal : TESForm):
//   +0x10  TESForm::flags (u32)
//   +0x14  TESForm::formID (u32)
//   +0x1A  TESForm::formType (u8) — kTESGlobal=0x?? (not critical)
//   +0x30  TESGlobal::value (f32) — the actual variable value
//
// Quest.SetCurrentStageID Papyrus native (sub_141185DD0 @ RVA 0x1185DD0):
//   Signature: char __fastcall(VM*, uint32_t vm_id, TESQuest*, uint32_t stage)
//   Calls into sub_1410D41D0 (inactive) or sub_1410D5FA0 (started) per
//   sub_14066B100's "quest started" check. Both engine workers TLS-use
//   (NtCurrentTeb + TlsIndex), so calling them cross-thread is unsafe.
//   For the receive-side apply we'll route through the main-thread
//   WndProc dispatcher (the same path B3.b v4 uses for LoadGame).
constexpr std::uintptr_t PAPYRUS_GLOBALVAR_SETVALUE_RVA = 0x011459E0;
constexpr std::uintptr_t PAPYRUS_QUEST_SETSTAGE_RVA     = 0x01185DD0;

constexpr std::size_t    TESGLOBAL_VALUE_OFF            = 0x30;
constexpr std::uint32_t  TESGLOBAL_FLAG_CONST           = 0x40;

// --- B1.j.1 BGSInventoryList materializer (fix scan-incompleteness) ---
//
// Live-test 2026-04-20 revealed: on a container that's never been touched
// at runtime, REFR+0xF8 is null or partially populated. Our scan saw 2/4
// items → incomplete SEED → subsequent TAKEs REJ_INSUFFICIENT.
//
// The engine already materializes the runtime list lazily inside
// sub_140502940 (AddObject worker) via vtable[167]. But that fires AFTER
// our pre-op hook observes. Fix: call the materializer ourselves BEFORE
// the scan so the runtime list has the full contents.
//
// Path found via angr (CFGFast + scan writes to [+0xF8]) + IDA decomp:
//   sub_140511F10(REFR*, BGSContainer*) @ RVA 0x511F10
//     - alloc 0x80 bytes (BGSInventoryList)
//     - sub_14034D320(list, BGSContainer, owner) to populate from CONT
//     - write to REFR+0xF8
//
//   sub_140313570(TESForm*, u32 'CONT') @ RVA 0x313570
//     - returns BGSContainer component from form, or null
//
//   'CONT' signature: 0x544E4F43 (little-endian 'C','O','N','T')
constexpr std::uintptr_t BGS_INV_LIST_MATERIALIZE_RVA  = 0x00511F10;
constexpr std::uintptr_t TESFORM_GET_COMPONENT_RVA     = 0x00313570;
constexpr std::uint32_t  TESFORM_SIG_CONT              = 0x544E4F43;  // 'CONT' LE

// --- B1.n world-item pickup (PlayerCharacter vt[0xEC]) ---
//
// When the player presses E on a world-placed REFR (stimpak on a table,
// ammo on the floor, weapon leaning on a wall), the engine routes the
// activation through PlayerCharacter's vt[0xEC] at RVA 0xD62930. This
// is a PC-specific virtual (TESObjectREFR::vt[0xEC] is nullsub_5593),
// so hooking the function pointer directly via MinHook is the cleanest
// approach — no need to patch a vtable slot.
//
// Call path (from RE 2026-04-21, re/world_pickup_report.txt):
//   HUD E-press → input dispatcher → sub_141033580
//     → qword_1432D2260->vt[0xEC](player, currentRefHandle, 1, 1)
//       → sub_140D62930
//         → ownership/theft arbitration
//         → sub_140500430(player, refr, count)  // real inv add
//           → sub_140502940 (AddObject workhorse)
//         → disable/destroy the world REFR
//         → fire OnItemAdded script event
//
// Why this does NOT fire vt[0x7A] AddObjectToContainer (already hooked):
// BFS depth 6 from sub_140D62930 over 1705 functions found zero paths
// to sub_140C7A500 (vt[0x7A]). The two virtuals share only the inner
// workhorse sub_140502940, which neither side hooks. No feedback loop.
//
// Signature:
//   char __fastcall sub_140D62930(
//       PlayerCharacter *this,      // rcx = qword_1432D2260 (player)
//       ObjectRefHandle *refHandle, // rdx = handle of the world REFR taken
//       unsigned int     count,     // r8d = # of instances (usually 1)
//       char             silent);   // r9b = 1=suppress HUD/log messages
//
// Filter inside the detour (to avoid double-firing on ContainerMenu
// withdraw, which ALSO uses vt[0xEC] via sub_14103D3E0):
//   - tls_applying_remote == false (not inside a remote-apply path)
//   - refr->parentCell != null (world item; container withdrawals see a
//     wrapper ref with null/different parentCell)
//   - resolve to valid (base_id, cell_id) identity tuple
//
// On match: emit ACTOR_EVENT DISABLE fire-and-forget via existing B0
// pipeline (server already knows how to track + broadcast). Always call
// g_orig so the player's local pickup completes normally (trust-client).
// B1.n attempt #1..#3 (2026-04-21) — all failed:
//   #1 hook PC::vt[0xEC] sub_140D62930 + resolve_refhandle: refHandle
//      unresolved (ContainerMenu-style resolver doesn't match layout).
//   #2 same hook + raw-u32 read from refHandle+0: constant 0x7B30CBC8
//      across different handles (offset 0 isn't the raw u32).
//   #3 same hook + read PC+0xD28 (CurrentActivateRef): always null at
//      detour entry (field isn't populated yet when PC::PickUp enters,
//      or offset is wrong in 1.11.191 next-gen).
//
// Pivot: hook the INVENTORY-ADD HELPER sub_140500430 instead. Signature
// is cleaner — it receives the world REFR* DIRECTLY as arg2, no handle
// resolution or field-read gymnastics:
//
//   void __fastcall sub_140500430(
//       TESObjectREFR *dstActor,    // rcx — player (or any actor)
//       TESObjectREFR *srcREFR,     // rdx — the world ref being absorbed
//       unsigned int   count);      // r8d — # instances
//
// This is "THE real inv-add" called internally by PC::PickUp and likely
// by a few other inventory-insert paths (sub-ref collection, etc.) per
// the RE agent summary. We accept that some non-pickup paths may fire
// and rely on filter (identity check + tls_applying_remote).
constexpr std::uintptr_t PLAYER_PICKUP_RVA = 0x00D62930;  // sub_140D62930 (kept for reference; NOT hooked)
constexpr std::uintptr_t INV_ADD_FROM_WORLD_RVA = 0x00500430;  // sub_140500430 — our NEW hook target

// --- B1.k.2 ContainerMenu::TransferItem (UI PUT entry point) ---
//
// Live test 2026-04-21 proved TWO separate problems on PUT:
//
//  1. vt[0x7A] AddObjectToContainer captures TAKE (dest=player,
//     source=container) but NEVER fires on PUT.
//  2. sub_14031C310 (the "generic move item between refs" function we
//     first suspected) ALSO doesn't fire when the user deposits items
//     through the two-column TRASFERISCI UI — zero [put] ENTRY events
//     across the whole live test with the hook installed.
//
// Second RE pass (re/containermenu_put_report.txt) traced the Scaleform
// callback chain: the AS3 string "transferItem" → registrar
// sub_140A548B0 (id=1) → dispatcher vt[1] of ContainerMenuBase
// (sub_140A54210, switch case 1LL) → virtual call
// (*(*this + 168))(this, invIdx, count, side) → ContainerMenu vtable
// slot[21] = sub_14103E950.
//
// Signature:
//   void sub_14103E950(
//       ContainerMenu* this,       // a1 — the UI menu instance
//       int            invIdx,     // a2 — index into menu's item array
//       unsigned int   count,      // a3 — count explicitly passed (yay!)
//       unsigned __int8 side);     // a4 — 1 = DEPOSIT (player→container)
//                                    //      0 = WITHDRAW (container→player)
//
// Menu struct layout (all fields identified by decompile):
//   this + 512 : WITHDRAW inventory array base (container items)
//   this + 528 : WITHDRAW entry count (u32)
//   this + 536 : WITHDRAW state flag (u8)
//   this + 640 : DEPOSIT inventory array base (player items)
//   this + 656 : DEPOSIT entry count (u32)
//   this + 664 : DEPOSIT state flag (u8)
//   this + 1040: menu type/kind (u32; 3=barter, 4=transfer, etc.)
//   this + 1064: BGSObjectRefHandle of the container REFR
//                (unconditionally resolved by sub_14021E230 in worker —
//                 see real_transfer_report.txt line 193)
//
// Each entry (stride 32 bytes) in the DEPOSIT/WITHDRAW array:
//   entry + 0x00: TESBoundObject* (the item template)
//   entry + 0x08: discriminator int (sign bit → union selector)
//   entry + 0x10: count (u16) OR ptr-to-stack (selected by +0x08 sign)
//   entry + 0x18: extra data / label
//
// To retrieve the container REFR*, call sub_14021E230(&out, this+1064).
// That helper takes a handle-slot pointer and writes the resolved
// TESObjectREFR* (or null if stale) into *out. We expose it as
// engine::resolve_refhandle().
constexpr std::uintptr_t CONTAINER_MENU_TRANSFER_ITEM_RVA = 0x0103E950;  // sub_14103E950
constexpr std::uintptr_t REFHANDLE_RESOLVE_RVA            = 0x0021E230;  // sub_14021E230

// B1.k.3 CORRECTED (live log 2026-04-21): side=1 is WITHDRAW, not DEPOSIT.
// Previous agent summary had these swapped. Proof from log: every side=1
// ENTRY is followed by vt[0x7A] with source=container dest=player — that's
// WITHDRAW semantics. So side=0 is DEPOSIT (player→container).
//
// Array layout (each array is at {+512, +640}, each entry is 32 bytes):
//   +512 array  = PLAYER inventory rows (clickable on DEPOSIT side)
//   +528 count  = u32 player-row count
//   +536 flag   = u8 state flag
//   +640 array  = CONTAINER inventory rows (clickable on WITHDRAW side)
//   +656 count  = u32 container-row count
//   +664 flag   = u8 state flag
//
// Decoding an entry to a TESForm*: the first qword is NOT a direct
// TESBoundObject pointer. It's an opaque handle that must be resolved
// via sub_1403478E0(*qword_1430E1370, entry) → TESForm*. See
// engine::resolve_inventory_entry_form.
constexpr std::size_t CMENU_PLAYER_ARRAY_OFF       = 512;   // DEPOSIT source
constexpr std::size_t CMENU_PLAYER_COUNT_OFF       = 528;
constexpr std::size_t CMENU_PLAYER_FLAG_OFF        = 536;
constexpr std::size_t CMENU_CONTAINER_ARRAY_OFF    = 640;   // WITHDRAW source
constexpr std::size_t CMENU_CONTAINER_COUNT_OFF    = 656;
constexpr std::size_t CMENU_CONTAINER_FLAG_OFF     = 664;
constexpr std::size_t CMENU_CONTAINER_HANDLE_OFF   = 1064;  // BGSObjectRefHandle
constexpr std::size_t CMENU_ENTRY_STRIDE           = 32;    // bytes per entry

constexpr std::uint8_t CMENU_SIDE_DEPOSIT  = 0;   // player→container (what we capture)
constexpr std::uint8_t CMENU_SIDE_WITHDRAW = 1;   // container→player (vt[0x7A] handles it)

// B1.k.3: decoder for ContainerMenu entry struct → TESForm*.
// sub_1403478E0(form_cache_global_value, entry_ptr) returns the TESForm* or
// equivalent that underlies the menu row. qword_1430E1370 is the slot that
// stores the "form cache" global — we read its current value at call time.
constexpr std::uintptr_t INV_ENTRY_TO_FORM_RVA     = 0x003478E0;   // sub_1403478E0
constexpr std::uintptr_t FORM_CACHE_SINGLETON_RVA  = 0x030E1370;   // qword_1430E1370

// --- B1.g container apply-to-engine (receiver-side) ---
//
// The receiver-side C++ mirror of what Papyrus's ObjectReference.AddItem /
// RemoveItem end up calling at the "real" engine level. Found via the
// functor vtable RE pass 2026-04-21 (re/put_candidate_report.txt):
//
//   AddItemFunctor vtable @ RVA 0x25C4598  slot[1] = sub_14114DD20
//     → eventually calls sub_1411735A0 (the "real" AddItem)
//   RemoveItemFunctor vtable @ RVA 0x25C45F8  slot[1] = sub_14114E440
//     → eventually calls sub_1411825A0 (the "real" RemoveItem)
//
// Signatures (from Hex-Rays, SEH-caged in apply_container_op_to_engine):
//
//   void sub_1411735A0(
//       void*    container_refr,   // dest — the container REFR to add into
//       void*    item_form,        // TESForm* of the item (lookup_by_form_id)
//       uint32_t count,
//       uint8_t  flag,             // "show message" flag — 0 = silent
//       uint32_t vm_id,            // Papyrus VM handle — 0 = no VM context
//       void*    vm_state);        // ScriptVirtualMachine* — nullptr OK
//                                  //   (only used for error logs; null =
//                                  //    errors go nowhere, no crash on
//                                  //    the hot happy-path)
//
//   void sub_1411825A0(
//       void*    container_refr,   // source — the container to remove from
//       void*    item_form,        // TESForm* of the item
//       uint32_t count,
//       uint8_t  flag,             // "show message" flag — 0 = silent
//       void*    dest_actor_refr,  // where items go; nullptr = drop in world
//       uint8_t  flag2,            // "silent" flag — 0 = normal
//       uint32_t vm_id,            // 0 = no VM context
//       void*    vm_state);        // nullptr OK
//
// For our receive-side apply we pass vm_id=0, vm_state=nullptr, flag=0,
// flag2=0, dest_actor_refr=nullptr. The item disappears from / appears in
// the local container, UI refreshes next time the ContainerMenu reads.
constexpr std::uintptr_t ENGINE_ADD_ITEM_RVA    = 0x011735A0;
constexpr std::uintptr_t ENGINE_REMOVE_ITEM_RVA = 0x011825A0;

// --- B6 wedge 1: door open/close ---
//
// PHASE 1 EMPIRICAL RESULT (2026-04-27 live test):
// sub_140305760 (RVA 0x305760) does NOT fire on live keypress E.
// 3527 fires logged, ALL within 6 sec of save-load, then ZERO during
// 75 sec of active gameplay including E-presses on doors. Conclusion:
// sub_140305760 is the SAVE-LOAD apply function (sets persisted state),
// not the live mutator. Useful for receiver-side apply (call it directly
// to set door state to match remote peer), NOT useful for sender-side
// detection of "player just opened a door".
constexpr std::uintptr_t ENGINE_SET_OPEN_STATE_RVA = 0x00305760;
//
// LIVE KEYPRESS TARGET (per Agent A dossier recommendation):
// sub_140514180 = "Activate worker" (non-virtual). Called by:
//   - Papyrus Door.SetOpen native (verified: SetOpen ends in
//       sub_140514180(refr, 0, 0, 1, 0, 0, 0); sub_1404F3E00(refr, "Open"|"Close"))
//   - Live player Activate path (sub_140467740, "door activate path
//       handles type 65 = TESObjectDOOR derived")
//   - BSAutoCloseController timer
//
// Signature (7 args inferred from Papyrus call site decomp; exact
// types unknown but layout matches x64 ABI: 4 in regs RCX/RDX/R8/R9,
// rest on stack). Return type is void or char; declare char (most
// Bethesda mutators return success/status; if actually void we waste
// 1 byte of AL — harmless).
//
//   char sub_140514180(
//       TESObjectREFR* refr,    // target REFR (door, container, activator, ...)
//       void*          a2,
//       void*          a3,
//       void*          a4,      // observed value 1 in Papyrus SetOpen
//       void*          a5,
//       void*          a6,
//       void*          a7);
//
// Phase 1.b validates: hook here OBSERVE-only, spam E on door, expect
// 1 fire per E press with refr being the door + identity_ok=1.
constexpr std::uintptr_t ENGINE_ACTIVATE_WORKER_RVA = 0x00514180;

// --- B3.b engine LoadGame ---
// Decoded from the `LoadGame` console command exec_fn (sub_1405EFAC0) via
// re/console_table_report.txt. Signature of the real loader:
//
//   uint8_t LoadGame(
//       void* save_load_mgr,     // TESSaveLoadManager singleton (qword_14329D508)
//       const char* filename,    // save name (no path, no .fos extension)
//       int         unk_neg1,    // always -1 from the exec_fn
//       uint32_t    flags,       // 4-bit combined from parse output (v9|v10<<1|v11<<2|v12<<3)
//       int         one,         // always 1 from the exec_fn
//       int         zero);       // always 0 from the exec_fn
//
// Returns non-zero on success, 0 on failure. Emits "ERR: Could not load
// savefile '%s'" to the game log on failure.
//
// Prerequisites the exec_fn performs before calling LoadGame:
//   1) sub_141084830(save_dev_ptr, 0, 0)  — precondition check (save
//      device / profile available). Returns 1 on PC in normal state.
//   2) sub_140C37200()                    — prep (unknown exact purpose;
//      possibly "save current session / flush writes / acquire lock").
//   3) byte_1432D1FEA = 1                 — set a "load in progress" flag.
//
// We replicate this sequence from our hook.
constexpr std::uintptr_t LOAD_GAME_FN_RVA          = 0x00BF93B0;   // sub_140BF93B0
constexpr std::uintptr_t SAVE_LOAD_MGR_SINGLETON_RVA = 0x0329D508; // qword_14329D508
constexpr std::uintptr_t LOAD_PRECOND_FN_RVA       = 0x01084830;   // sub_141084830
constexpr std::uintptr_t SAVE_DEV_SINGLETON_RVA    = 0x031E5A90;   // qword_1431E5A90
constexpr std::uintptr_t LOAD_PREP_FN_RVA          = 0x00C37200;   // sub_140C37200
constexpr std::uintptr_t LOAD_IN_PROGRESS_FLAG_RVA = 0x032D1FEA;   // byte_1432D1FEA

// --- β.6 scene render hook (Agent RE, 2026-04-22) ---
// sub_140C38F80 = 3D scene walker. Called ONCE per frame from
// RenderDispatch (sub_140C32D30) BEFORE Scaleform UI render
// (sub_140C37D20). At its trailing edge the game has finished all
// scene draws; NiCamera+0x120 holds the EXACT VP used for those draws
// (frame-accurate, no Present-time mismatch). Hooking here and reading
// that matrix eliminates shake because our body's VP matches the
// scene's VP byte-for-byte.
// Threading: 100% main thread (verified by RE).
constexpr std::uintptr_t SCENE_RENDER_RVA            = 0x00C38F80;

// --- B5 camera capture (Agent 1 RE, 2026-04-22) ---
constexpr std::uintptr_t PLAYER_CAMERA_SINGLETON_RVA = 0x030DBD58;
constexpr std::uintptr_t NI_CAMERA_VTABLE_RVA        = 0x0267DD50;
// NiCamera layout confirmed via CommonLibF4 (alandtse/master) 2026-04-22:
//   +0x120  worldToCam[4][4]   (VIEW matrix, row-major, world→camera)
//   +0x160  viewFrustum = { left, right, top, bottom, near, far, ortho }
//   sizeof(NiCamera) == 0x1A0
// Note: NiMatrix3.entry[i] = row i (NiPoint4) → float[4][4] is row-major C.
// NiAVObject world transform (inherited by NiCamera) — from CommonLibF4
// static_asserts verified 2026-04-22:
//   NiAVObject::world @ +0x70 (NiTransform = rotate[0x30] + translate[0xC] + scale[0x4])
//   => world.rotate @ +0x70  (NiMatrix3, 3 rows of NiPoint4, row-major)
//   => world.translate @ +0xA0  (NiPoint3 = 3 floats)
//   => world.scale @ +0xAC (float)
// These give the FRAME-PERFECT camera eye pos + orientation, including
// head-bob/smoothing/interpolation that the game applies internally.
// Reading these eliminates shake from using the raw actor pose.
constexpr std::size_t NI_AV_WORLD_ROTATE_OFF    = 0x70;   // NiMatrix3 (0x30 B)
constexpr std::size_t NI_AV_WORLD_TRANSLATE_OFF = 0xA0;   // NiPoint3  (0xC B)
constexpr std::size_t NI_AV_WORLD_SCALE_OFF     = 0xAC;   // float
// NiMatrix3.entry[i] = NiPoint4 row i: (m[i][0], m[i][1], m[i][2], _pad).
// Stride between rows = 16 bytes (sizeof NiPoint4).
constexpr std::size_t NI_MATRIX3_ROW_STRIDE     = 0x10;

constexpr std::size_t NI_CAMERA_WORLD_TO_CAM_OFF = 0x120;  // 288
constexpr std::size_t NI_CAMERA_FRUSTUM_OFF      = 0x160;  // 352
// Inside NiFrustum (all float except last):
constexpr std::size_t NI_FRUSTUM_LEFT_OFF    = 0x00;
constexpr std::size_t NI_FRUSTUM_RIGHT_OFF   = 0x04;
constexpr std::size_t NI_FRUSTUM_TOP_OFF     = 0x08;
constexpr std::size_t NI_FRUSTUM_BOTTOM_OFF  = 0x0C;
constexpr std::size_t NI_FRUSTUM_NEAR_OFF    = 0x10;
constexpr std::size_t NI_FRUSTUM_FAR_OFF     = 0x14;
constexpr std::size_t NI_FRUSTUM_ORTHO_OFF   = 0x18;
constexpr std::size_t NI_CAMERA_SIZE         = 0x1A0;

// MainCullingCamera (scene-render culling camera, TESCamera subclass).
// BSTSingletonSDMOpStaticBuffer — instance lives at 0x32D25D0, pointer
// slot at 0x32D2590. Confirmed via IDA xref to its vtable 0x255DB08
// from the ctor/binder at sub_140C31ED0 lines:
//   qword_1432D25D0 = vtable_MCC
//   qword_1432D2590 = &qword_1432D25D0
constexpr std::uintptr_t MAIN_CULLING_CAMERA_INSTANCE_RVA = 0x032D25D0;
constexpr std::uintptr_t MAIN_CULLING_CAMERA_PTR_SLOT_RVA = 0x032D2590;
constexpr std::uintptr_t MAIN_CULLING_CAMERA_VTABLE_RVA   = 0x0255DB08;
// PlayerCamera layout confirmed via IDA decomp of ctor @ 0x1024A50:
//   +0xE0..+0x158  states array (NiPointer<TESCameraState>[16], slot +0x148 is a gap)
//   +0x1A0         dword = active state index
//   other sub-vtables at +0x38/+0x48/+0x50/+0x58 (BSTEventSink MI)
constexpr std::size_t PLAYER_CAMERA_STATES_OFF  = 0xE0;
constexpr std::size_t PLAYER_CAMERA_ACTIVE_OFF  = 0x1A0;
// β.6 shake fix (validated via live eyeprobe 2026-04-22): PlayerCamera
// stores the current-frame "render eye" position — including head-bob
// and sway — as a NiPoint3 at +0x188. Gated by a valid-flag byte at
// +0x1A7 (must be non-zero before the value is trustworthy).
//
// Empirical proof (walking samples from live log):
//   foot.z=7827.9, PC+0x188.z=7948.9 → delta 121.0
//   foot.z=7828.1, PC+0x188.z=7948.8 → delta 120.7 (different frame, same pose)
//   foot.z=7829.8, PC+0x188.z=7950.4 → delta 120.6
// That 120.5..121.1 oscillation is the head-bob. Using this pos as our
// VP eye makes body's screen position track scenery byte-for-byte, no
// shake.
constexpr std::size_t PLAYER_CAMERA_BUF_POS_OFF = 0x188;  // NiPoint3 = 3 f32
constexpr std::size_t PLAYER_CAMERA_BUF_VAL_OFF = 0x1A7;  // u8 flag
// TESCameraState → NiCamera offset. Confirmed via runtime probe
// 2026-04-22 on FirstPersonState (state[0]). ThirdPerson may share the
// same NiCamera pointer (single shared object across states).
constexpr std::size_t TES_STATE_NICAM_OFF       = 0x50;
// NiCamera cached matrix at +288 (= 0x120 = NI_CAMERA_WORLD_TO_CAM_OFF).
// Confirmed VP for CHUNK-RELATIVE coords where chunk origin = player
// foot position (FULL XYZ subtract). EYE_HEIGHT=120 is pre-baked into
// the matrix translation column (row1[3] = f·120 ≈ 251 in live capture).
// Input vector: pos_rel = (world - player.pos); matrix does the rest.
// Kept as NI_CAMERA_VIEWPROJ_OFF alias for existing call sites; prefer
// NI_CAMERA_WORLD_TO_CAM_OFF in new code (matches CommonLibF4 naming).
constexpr std::size_t NI_CAMERA_VIEWPROJ_OFF    = 288;

// --- Z.2 (Path B) actor spawn via Papyrus PlaceAtMe native ---
//
// sub_141159C10 @ RVA 0x1159C10. Signature (from re/placeatme_calling_convention.txt):
//   void* __fastcall(
//       void*        vm,           // a1: BSScript::IVirtualMachine* — MVP 0
//       uint32_t     stack_id,     // a2: Papyrus stack id           — MVP 0
//       void**       form_pair,    // a3: &{VMHandle, TESForm*}      — pass [null, pForm]
//       void*        anchor_refr,  // a4: REFR* anchor (MUST be non-null)
//       uint32_t     count,        // a5: count                       — MVP 1
//       uint64_t     persistent);  // a6: persistent-flag             — MVP 0 (temp)
//
// Returns raw Actor* (0x490 B). NOT an ObjectRefHandle.
// THREAD-UNSAFE: reads NtCurrentTeb TLS + takes REFR cell-attach lock.
// Must be called from the engine's main thread (WndProc dispatch path).
constexpr std::uintptr_t PLACE_AT_ME_RVA = 0x01159C10;

// TEMPORARY flag bit in the Actor/REFR flags field at offset +0x10.
// PlaceAtMe hardcodes NEW_REFR_DATA flags to 0x1000000 only. To avoid
// save bloat we OR in 0x4000 post-return.
constexpr std::uint32_t REFR_FLAG_TEMPORARY = 0x00004000;

// --- B8 force-equip-cycle on game start (M9 architectural workaround) ---
//
// Background (2026-04-28):
//   The M8P3 ghost body's skin instance shares pointers (bones_fb,
//   bones_pri, skel_root) with the LOCAL player's skeleton. When the
//   player's BipedAnim is rebuilt by an equip change, the ghost's stale
//   pointers crash the engine's biped processor walk.
//
//   Two days of M9 attempts (B-MOD+E null skel_root, recursive cull-flags,
//   PipBoy SSN-detach gating) all failed because they don't address the
//   architectural root cause: the player's BipedAnim is in a SEMI-ALLOCATED
//   state immediately after save-load (some fields point at globally-pooled
//   data instead of heap-owned). The FIRST equip cycle through
//   ActorEquipManager normalizes this state. After that first cycle,
//   subsequent equip events don't leave dangling refs.
//
//   User empirically validated 2026-04-28:
//     - Unequip Vault Suit BEFORE peer joins → no crash, ghost spawns
//       cleanly afterwards, subsequent equip cycles never crash.
//     - Skip the pre-cycle → first equip after peer joins crashes.
//
// FIX: on game start, after LoadGame completes and player is in-world but
// BEFORE peer can connect, programmatically call:
//   ActorEquipManager::UnequipObject(player, VaultSuit, ...)
//   wait ~500ms for BipedAnim to settle
//   ActorEquipManager::EquipObject  (player, VaultSuit, ...)
// This exercises the BipedAnim through the normal engine pipeline,
// converting it from "post-load-pool-refs" to "fully-heap-owned". The
// ghost subsequently bound by M8P3 swap_for_geometry latches onto stable
// pointers; equip changes after peer-connect become safe.
//
// ENGINE FUNCTIONS (RE'd from re/B8_force_equip_cycle.log):
//
//   sub_140CE5DA0 = ActorEquipManager::UnequipObject(11 args):
//     a1 = ActorEquipManager*  (singleton, see ACTOR_EQUIP_MGR_SINGLETON_RVA)
//     a2 = Actor*              (target — the player)
//     a3 = _QWORD form_pair[2] = {VMHandle/0, TESForm* item}
//     a4 = int  count          (1 for single)
//     a5 = i64  slot           (0 = let engine decide from biped data)
//     a6 = int  stack_id       (1 or 0 — pass 0 makes engine compute via sub_140CE6DF0)
//     a7 = char (preventEquip flag, 0 = no)
//     a8 = char (silent / queued / ?)
//     a9 = char (?)
//     a10 = char (?)
//     a11 = i64 (TLS event sink override; 0 = use default)
//   Returns: char success
//
//   sub_140CE5900 = ActorEquipManager::EquipObject(11 args):
//     a1 = ActorEquipManager*
//     a2 = Actor*
//     a3 = form_pair
//     a4 = uint count
//     a5 = int  stack_id
//     a6 = i64  slot
//     a7..a11 = char flags (preventRemoval, silent, ...)
//   IMPORTANT: arg 4-5-6 ORDER differs from Unequip:
//     Equip:    a4=count, a5=stackID, a6=slot
//     Unequip:  a4=count, a5=slot,    a6=stackID
//   This was the M9 mistake yesterday — args swapped between the two.
//
// SINGLETON (qword_1431E3328) — confirmed by xref pass: 4+ callers all
// pass `qword_1431E3328` as a1 to sub_140CE5900. RVA 0x031E3328 in .data.
//
// VAULT SUIT form ID 0x0001EED7 — observed in our equip detour logs from
// the M9 attempts. It's the start-state armor in our world_base.fos save.
// If a future save doesn't have it equipped, the unequip is a no-op and
// the equip might error — currently acceptable; we ignore failure return.
constexpr std::uintptr_t ENGINE_EQUIP_OBJECT_RVA          = 0x00CE5900;
constexpr std::uintptr_t ENGINE_UNEQUIP_OBJECT_RVA        = 0x00CE5DA0;
constexpr std::uintptr_t ACTOR_EQUIP_MGR_SINGLETON_RVA    = 0x031E3328;
constexpr std::uint32_t  VAULT_SUIT_FORM_ID               = 0x0001EED7;

// --- M9 wedge 2 — armor visual sync via TESObjectARMO/ARMA struct walk ---
//
// Background (2026-04-28):
//   M9 wedge 1 already broadcasts EQUIP_OP / EQUIP_BCAST when local player
//   equips/unequips. Wedge 2 makes the receiver SHOW the armor visually
//   on the M8P3 ghost body of the originating peer.
//
// Approach (Option δ — TESObjectARMO struct walk):
//   We REJECTED several alternatives:
//     - actor hijack: permanently bocciato per user memory
//     - Inventory3DManager engine API: too menu-coupled (requires
//       Inventory3DSceneRoot wrapper class with vt[136], not a plain
//       NiNode — see re/M9_w2_inv3d_main.log)
//     - Hook deep engine attach (sub_140C45450): args are in-process
//       NiNode pointers, not file paths — can't replicate cross-client
//
//   Therefore: walk TESObjectARMO struct ourselves to resolve the
//   3rd-person NIF path, then load + attach to the ghost via primitives
//   we already have (g_r.nif_load_by_path + attach_child_direct).
//
// LAYOUT (RE'd 2026-04-28 from sub_140462370 = ARMO::FinalizeAfterLoad
// + sub_14045FD90 = ARMA::~TESObjectARMA — re/M9_w2_armo_layout.log):
//
//   TESObjectARMO struct:
//     +0x2A8  = ARMA addon array base (stride 16, addon[i] at +i*16)
//     +0x2B8  = u32 addon count
//     entries: { ??? @+0, TESObjectARMA* @+8 }  — 16-byte stride
//
//   TESObjectARMA struct (6 sub-component objects, ~64B each):
//     +0x50   = TESRaceForm
//     +0x90   = BGSBipedObjectForm
//     +0xD0   = TESModel male 3rd-person   ← what we read for ghost
//     +0x110  = TESModel female 3rd-person
//     +0x150  = TESModel male 1st-person
//     +0x190  = TESModel female 1st-person
//
//   TESModel struct:
//     +0x08   = BSFixedString model_path (pool handle, +0x18 = c_str)
//
// The ghost shares the LOCAL player's skel via M8P3 swap. When we attach
// an armor NIF as child of the ghost root, the engine's
// BSDismemberSkinInstance resolver looks up bone names ("Pelvis",
// "SPINE1", etc.) in the parent tree — which IS shared with the player
// skel — so resolution should succeed and the armor renders skinned to
// the same bones as the body. Tested initially with Vault Suit (form
// 0x1EED7) and any raider chest armor for live validation.
constexpr std::size_t TESOBJECTARMO_ADDON_ARR_OFF      = 0x2A8;
constexpr std::size_t TESOBJECTARMO_ADDON_COUNT_OFF    = 0x2B8;
constexpr std::size_t TESOBJECTARMO_ADDON_ENTRY_STRIDE = 0x10;
constexpr std::size_t TESOBJECTARMO_ADDON_ARMA_PTR_OFF = 0x08;

constexpr std::size_t TESOBJECTARMA_MODEL_M3RD_OFF     = 0xD0;
constexpr std::size_t TESOBJECTARMA_MODEL_F3RD_OFF     = 0x110;

constexpr std::size_t TESMODEL_PATH_BSFIXEDSTR_OFF     = 0x08;

// Pool layout for BSFixedString (RE'd in skin_rebind.cpp 2026-04-24):
//   pool_entry + 0x18 = c_str (preceded by 24-byte header containing
//   length, refcount, hash, etc).
constexpr std::size_t BSFIXEDSTRING_CSTR_OFF           = 0x18;

// Template form ID for ghost spawn. Agent 3 recommended 0x0020593F
// (LCharWorkshopNPC leveled list) but live test 2026-04-22 showed
// lookup_by_form_id returned null on that one — leveled lists aren't
// indexed in the form table or the FormID was hallucinated.
//
// Falling back to Codsworth (0x0001CA7D) which is verified-valid from
// the B1 ghost_map era. We'll get a Codsworth CLONE at spawn location;
// that's fine for pipeline validation. Z.8 replaces identity via
// SetRace+SetOutfit so the clone ultimately looks like the remote.
constexpr std::uint32_t GHOST_TEMPLATE_FORM_ID = 0x0001CA7D;

} // namespace fw::offsets
