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

// --- B6.3 lock state sync ---
//
// ForceUnlock (sub_140563320) and ForceLock (sub_140563360) are the
// canonical engine entry points that flip ExtraLock state on a REFR.
// Both signatures: void(__fastcall)(TESObjectREFR* refr).
//
// Coverage (RE'd 2026-05-08 across decomp xrefs):
//   - lockpick minigame success  → sub_14106BE80 → ForceUnlock
//   - terminal hack success      → ForceUnlock
//   - AI lock/unlock package     → sub_140CEE8F0/9C0 → ForceLock/Unlock
//   - perk auto-unlock effect    → sub_140B92A10 → ForceUnlock
//   - savefile load              → ForceUnlock (server dedups by state)
// MISSES: Papyrus ObjectReference.Lock/Unlock (uses sub_141158640
// directly), magic LockEffect (uses sub_140B81EB0). Cover the common
// gameplay (lockpick + terminal + AI); add the rest later if needed.
//
// Receiver-side apply: sub_141158640 — Papyrus binding for
// ObjectReference.Lock/Unlock.
//   signature: void(_unused, _unused, REFR*, u8 locked, char ai_notify)
//   call: sub_141158640(0, 0, refr, locked ? 1 : 0, 0);
// With ai_notify=0: no AI side-effects, no key consumption, no
// minigame trigger. Allocates ExtraLock if missing. Recurses into
// ForceUnlock/ForceLock — net thread sets tls_applying_remote so
// the recursive hook fire is filtered.
//
// LockData layout (read via sub_140563170(REFR) → LockData* or null):
//   +0x00  u8     base_lock_level (1..99)
//   +0x08  TESForm* required_key
//   +0x10  u8     flags  (bit 0 = LOCKED — the flag we care about)
//   +0x14  u32    partial_pick state (cleared on unlock)
constexpr std::uintptr_t ENGINE_FORCE_UNLOCK_RVA       = 0x00563320;
constexpr std::uintptr_t ENGINE_FORCE_LOCK_RVA         = 0x00563360;
constexpr std::uintptr_t ENGINE_LOCK_DATA_GET_RVA      = 0x00563170;
constexpr std::uintptr_t ENGINE_LOCK_PAPYRUS_APPLY_RVA = 0x01158640;

constexpr std::size_t  LOCK_DATA_FLAGS_OFF = 0x10;
constexpr std::uint8_t LOCK_FLAG_LOCKED    = 0x01;

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

// === M9 wedge 2 PROPER — ARMA priority selection (M9_arma_select dossier) ====
// Settled 2026-05-03 by 2 IDA agents (HIGH×HIGH consensus).
//
// Engine selects which ARMA to render via sub_1404626A0 (RVA 0x4626A0,
// "TESObjectARMO::ForEachAddonInstance"). Algorithm walks the addon
// array with a priority filter:
//   - reqPrio source: InstanceData+0x56 (OMOD-modified) OR ARMO+0x2A6 (default)
//   - per-addon priority: WORD at addon_entry+0 (within each 16-byte entry)
//   - selection rules:
//       * priority == 0       → always invoke ("always-on" parts)
//       * priority == reqPrio → invoke (exact match)
//       * else                → invoke highest priority value still ≤ reqPrio
// Combat Armor 0x11D3C3 has 3 addon entries (priorities 1/2/3 = Lite/Mid/Heavy).
// Heavy upgrade OMOD writes InstanceData+0x56 = 3 → engine renders Heavy.
//
// For ghost-side resolver: read ARMO+0x2A6 (default) for now; OMOD-modified
// priority requires sender-side extraction via engine helper sub_140436820
// + wire extension. (TODO: phase 3b).
constexpr std::size_t TESOBJECTARMO_DEFAULT_PRIORITY_OFF        = 0x2A6;  // u16
constexpr std::size_t TESOBJECTARMO_INSTANCEDATA_PRIORITY_OFF   = 0x56;   // u16 inside InstanceData
constexpr std::size_t TESOBJECTARMO_ADDON_ENTRY_PRIORITY_OFF    = 0x00;   // u16 at start of each 16-byte addon entry

// Engine helper that builds the [ARMO*, InstanceData*] holder pair given
// (out, ARMO*, OIE*). Refcounts the InstanceData ptr; caller must Release.
// See re/M9_arma_select_AGENT_A_r8_dec_140658DF0.txt for the canonical use
// pattern. This is the API to use on sender to extract OMOD-effective
// priority from the equipped item.
constexpr std::uintptr_t OBJINSTANCE_BUILD_HOLDER_RVA           = 0x436820;

// === ARMA TESModel offsets (CORRECTED 2026-05-03) ============================
// Live data + agent A confirm:
//   +0x50  = TESModel male   3rd-person  (worn) — what the ghost should render
//   +0x90  = TESModel female 3rd-person  (worn)
//   +0x150 = TESModel male   1st-person  (arms-only, FPS)
//   +0x190 = TESModel female 1st-person
// TESModel.path BSFixedString is at +0x08 within the TESModel struct.
//
// PREVIOUS (WRONG) values 0xD0 / 0x110 were inherited from an older dossier
// that confused 3rd-person with some other slot. Live test of Vault Suit
// 0x1EED7 shows `Vault111Suit.nif` at arma+0x50 (M3rd) and
// `FemaleVault111Suit.nif` at arma+0x90 (F3rd) — see existing armor-resolve
// log lines. Agent A also independently derived (isFemale<<6)+0x50 from
// sub_14045F320 disasm.
constexpr std::size_t TESOBJECTARMA_MODEL_M3RD_OFF     = 0x50;
constexpr std::size_t TESOBJECTARMA_MODEL_F3RD_OFF     = 0x90;
constexpr std::size_t TESOBJECTARMA_MODEL_M1ST_OFF     = 0x150;
constexpr std::size_t TESOBJECTARMA_MODEL_F1ST_OFF     = 0x190;

constexpr std::size_t TESMODEL_PATH_BSFIXEDSTR_OFF     = 0x08;

// === M9 wedge 3 — TESObjectARMO biped slot mask ============================
// Used for: hide ghost body when peer equips a slot-3 BODY armor (Vault Suit,
// Power Armor, Synth Armor, etc.) — these REPLACE the entire body geometry,
// so we set NIAV_FLAG_APP_CULLED on the ghost's BaseMaleBody:0 BSSubIndexTriShape
// to prevent z-fighting under the armor mesh.
//
// LAYOUT:
//   TESObjectARMO inherits BGSBipedObjectForm sub-component @ +0x1E0:
//     +0x1E0  vtable BGSBipedObjectForm
//     +0x1E8  uint32 bipedObjectSlots  (32-bit bitmask, slots 30..61 in xEdit
//                                       UI = bit 0..31 internal index)
//
// VERIFIED 2026-05-02 by 2 independent IDA agents (M9w3_armo_biped_AGENT_A.md
// and _B.md), HIGH × HIGH consensus. Evidence chains:
//   - sub_140462370 (FinalizeAfterLoad) calls sub_1402FC780(a1+480, src+480)
//     where sub_1402FC780 = BGSBipedObjectForm::CopyComponentFrom which reads
//     *(uint32*)(this+8). So biped slots offset = 480 + 8 = 488 = 0x1E8.
//   - MSVC RTTI ClassHierarchyDescriptor BCD[19] declares mdisp=0x1E0 for the
//     BGSBipedObjectForm subobject inside TESObjectARMO.
//   - sub_1405A4A10 (WornCoversBipedSlot worker) calls vt[7] (TestSlot) on
//     (armo_ptr + 480), confirming the subobject placement.
//
// SLOT MAPPING (xEdit UI label → internal bit index → typical attach):
//   slot  3 (mask 0x0008) = "33 - BODY"     ← FULL-BODY REPLACEMENT
//   slot  6 (mask 0x0040) = "36 - [U] Torso"  (underwear-type torso)
//   slot 11 (mask 0x0800) = "41 - [A] Torso"  (armor-type torso, additive)
//   slot 30 (mask 0x40000000) = "60 - Pipboy"
//   ... see M9_equipment_AGENT_B_dossier.txt §DELIVERABLE_2 for full table.
//
// For w3 we ONLY act on slot 3 BODY (mask 0x8). Other slots are handled by
// natural geometry occlusion (additive attach already works).
constexpr std::size_t   TESOBJECTARMO_BIPED_SLOTS_OFF = 0x1E8;  // u32 bitmask
constexpr std::uint32_t BIPED_SLOT_BODY_MASK         = 0x00000008;  // bit 3 = "33 - BODY"

// === M9 wedge 7 — TESObjectWEAP layout =====================================
// Weapons (pistols, melee, rifles) attach to a SINGLE bone (typically the
// "WEAPON" node parented under RArm_Hand) and use a single 3rd-person model.
// No biped slot bitmask, no addon array, no ARMA struct walk needed —
// simpler than ARMO.
//
// TESObjectWEAP inherits TESBoundAnimObject → TESBoundObject → TESForm. The
// embedded TESModel (3rd-person world model) lives somewhere in the ~0x60..
// 0xC0 region per CommonLibF4 layout, but the EXACT offset on FO4 1.11.191
// next-gen wasn't pinned by static decomp. We probe a candidate list at
// runtime (mirror of the ARMA approach in M9.w2) and pick the first offset
// yielding a valid path containing "Weapons\\" prefix.
//
// Candidate offsets (probed in order in resolve_weapon_nif_path):
//   0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0xA0, 0xB0, 0xC0
//
// Once empirically pinned by live test, replace the probing with a single
// constant TESOBJECTWEAP_MODEL_OFF. Until then the probe handles the
// uncertainty.
//
// Path heuristic: vanilla FO4 weapon NIFs live under "Weapons\\..." (e.g.
//   Weapons\\Laser\\Pistol.nif, Weapons\\1HMelee\\Baton.nif). We accept any
// path whose case-insensitive form contains the substring "weapons\\" —
// also catches DLC/mod weapons which follow the same convention.

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

// === M9 wedge 4 — BGSMod (Object Modification) sync =========================
// RE'd 2026-04-30 via dual-agent IDA analysis + tiebreaker. See
//   re/M9_w4_TIEBREAKER_analysis.md
//   re/M9_w4_AGENT_A_analysis.md
//   re/M9_w4_AGENT_B_analysis.md
//   re/M9_w4_ida4_comprehensive.log + ida5_tiebreaker.log + ida5b_followup.log
//
// Goal: when a peer equips a modded weapon (e.g. 10mm pistol w/ long barrel +
// reflex sight), peer's ghost on remote clients must render the SAME assembled
// NIF (base dummy + N mod NIFs). M9.w4 covers extraction (sender) + replay
// (receiver) of the OMOD list per equipped item.
//
// =========================================================================
// BGSMod::Attachment::Mod (sizeof = 0xC8 = 200 B, formType = 0x90)
// =========================================================================
// vtable @ IDA 0x142486630 (RVA 0x2486630). Allocated in ctor sub_140432740.
//
// Multi-inheritance layout (FROM dtor thunks `a1 - 32/-48/-72`):
//   +0x00  vtable_main      (TESForm-derived MAIN)
//   +0x20  vtable_base_0    (TESFullName / BaseFormComponent)
//   +0x30  vtable_base_1    (BGSKeywordForm-like)
//   +0x48  vtable_base_2    (BGSModelMaterialSwap-like)
//
// Per-mod data arrays (RE'd in tiebreaker via sub_140433870 DATA-record loader):
//   +0x88  void*  property records ptr        (16-B stride per record)
//   +0x90  u32    property records count
//   +0x98  inline BGSAttachParentArray sub-object
//          +0x00 vtable, +0x08 data ptr, +0x10 count u32 — i.e. abs offsets:
//          +0x98 vtable, +0xA0 data ptr, +0xA8 count u32
//   +0xB0  u16*   keyword-include array        (2-B stride per entry)
//   +0xB8  u32    keyword-include count
//   +0xC0  u32    sentinel (init 0xFFFF — TESForm-style "unbound rank/idx")
//   +0xC4  u16    counter (cleared in ctor)
//   +0xC6  u8     flag byte (low 2 bits = ApplyMode mask)
//
// IMPORTANT — for sender side (extracting peer's mods) we DO NOT walk these
// arrays. We walk Actor.inventory → BSExtraDataList → BGSObjectInstanceExtra
// instead. The fields above are needed for the RECEIVER side (deferred to
// iter 6) when assembling NIFs from individual mods.
constexpr std::size_t BGSMOD_ATTACHMENT_MOD_SIZE          = 0xC8;
constexpr std::uint8_t BGSMOD_ATTACHMENT_MOD_FORMTYPE     = 0x90;
constexpr std::size_t BGSMOD_PROPERTY_ARRAY_DATA_OFF      = 0x88;
constexpr std::size_t BGSMOD_PROPERTY_ARRAY_COUNT_OFF     = 0x90;
constexpr std::size_t BGSMOD_PROPERTY_RECORD_STRIDE       = 0x10;
constexpr std::size_t BGSMOD_ATTACH_PARENT_ARRAY_OFF      = 0x98;
constexpr std::size_t BGSMOD_ATTACH_PARENT_DATA_OFF       = 0xA0; // abs
constexpr std::size_t BGSMOD_ATTACH_PARENT_COUNT_OFF      = 0xA8; // abs
constexpr std::size_t BGSMOD_KEYWORD_LIST_DATA_OFF        = 0xB0;
constexpr std::size_t BGSMOD_KEYWORD_LIST_COUNT_OFF       = 0xB8;
constexpr std::size_t BGSMOD_KEYWORD_LIST_STRIDE          = 0x02;

// =========================================================================
// BGSObjectInstanceExtra (BSExtraData type carrying mods on an inventory item)
// sizeof = 40, type byte = 0x35 (53), vtable @ IDA 0x142462298
// =========================================================================
// Direct evidence in ctor sub_1402471A0:
//   *(_BYTE *)(a1 + 18) = 53;                  // type byte (= 0x35)
//   *(_QWORD *)(a1 + 24) = 0;                  // inner = nullptr
//   *(_WORD *)(a1 + 32) = -1;                  // u16 sentinel @ +0x20
//
// NOTE: the type byte value 0x35 contradicts CommonLibF4 (which says 0xA1 for
// kObjectInstance) — FO4 1.11.191 next-gen has remapped the BSExtraData type
// table. Trust the binary, NOT the public docs.
constexpr std::size_t BSEXTRADATA_NEXT_OFF                = 0x08;
constexpr std::size_t BSEXTRADATA_TYPE_BYTE_OFF           = 0x12;

constexpr std::uint8_t BGSOBJECTINSTANCEEXTRA_TYPE_BYTE   = 0x35;
constexpr std::size_t BGSOBJECTINSTANCEEXTRA_SIZE         = 40;
constexpr std::size_t BGSOBJECTINSTANCEEXTRA_INNER_OFF    = 0x18;
constexpr std::size_t BGSOBJECTINSTANCEEXTRA_VTABLE_RVA   = 0x2462298;

// =========================================================================
// BGSObjectInstanceExtra::Inner (16 B sub-struct at OIE + 0x18)
// =========================================================================
// Direct evidence in OIE dtor sub_14024BC20:
//   v3 = a1[3];                          // inner ptr at +0x18
//   v5 = *(void**)v3;                    // data @+0x00
//   *(_QWORD *)v3 = 0;                   // clear data ptr
//   *(_DWORD *)(v3 + 8) = 0;             // clear u32 at +0x08
//   sub_1422B6BC8(v3, 16);               // free 16 B sub-struct
//
// Inner.data is NOT a flat record array. It's a packed-bitstream HEADER
// followed by N×8B records. Walker pattern (verbatim 4× in binary):
//   while (1) {
//       v9 = *(_BYTE *)(v6 + 3);          // tag at byte +3 of DWORD
//       if (!v9) break;                   // end-of-header
//       if (v9 != -1) {                   // skip 0xFF padding
//           v10 = *(_DWORD *)v6 & 0xFFFFFF;   // 24-bit length
//           v6 += 4; v7 += v10;
//       } else {
//           v6 += 4;
//       }
//   }
//   v11 = data + v7;                          // start of records
//   v12 = (*(_DWORD *)v6 >> 3) & 0x1FFFFF;     // 21-bit record count
//
// See helpers in oie_walker.{h,cpp} (M9.w4 sender utilities).
constexpr std::size_t OIE_INNER_DATA_OFF                  = 0x00;
constexpr std::size_t OIE_INNER_DATA_BYTELEN_OFF          = 0x08;
constexpr std::size_t OIE_INNER_SIZE                      = 16;

// =========================================================================
// ObjectModifier — record inside OIE.Inner.data after header walk
// sizeof = 8 B per record. Three independent decomps confirm stride.
// =========================================================================
// Direct evidence (BGSObjectInstanceExtra::Init sub_1402480F0):
//   *(_DWORD *)(v45 + 8*i + 0) = *(_DWORD *)(a2 + 20);   // mod_form_id
//   *(_BYTE  *)(v45 + 8*i + 4) = a3;                     // attach_index
//   *(_BYTE  *)(v45 + 8*i + 5) = a4;                     // index2/rank
//   *(_BYTE  *)(v45 + 8*i + 6) = 0;                      // flag (=0 on insert)
constexpr std::size_t OBJMOD_RECORD_STRIDE                = 8;
constexpr std::size_t OBJMOD_FORM_ID_OFF                  = 0x00;
constexpr std::size_t OBJMOD_ATTACH_INDEX_OFF             = 0x04;
constexpr std::size_t OBJMOD_INDEX2_RANK_OFF              = 0x05;
constexpr std::size_t OBJMOD_FLAG_OFF                     = 0x06;

// =========================================================================
// BSExtraDataList (well-known FO4 layout, head pointer at +0x08)
// =========================================================================
constexpr std::size_t BSEXTRADATALIST_HEAD_OFF            = 0x08;

// =========================================================================
// BGSInventoryItem.data → Stack chain
//
// CORRECTED 2026-04-30 from runtime probe (iter 6 sender test):
// First attempt used +0x00=next, +0x08=extras (CommonLibF4 read of the
// struct skipping the vtable). That was wrong. Live test showed
//   *(stack + 0x00) = 0x7FF6.... — code-segment vtable, NOT a Stack*
//   *(stack + 0x08) = 0x1 — refcount value, not a pointer
// confirming Stack has its OWN vtable at +0x00 (RTTI exists for
// `Stack@BGSInventoryItem` per IDA query 4 line 1275 of dossier).
//
// Correct layout (vtable + BSIntrusiveRefCounted (4B + pad) + payload):
//   Stack {
//     +0x00 vtable*
//     +0x08 BSIntrusiveRefCounted::refCount (u32) + 4 B pad
//     +0x10 BSTSmartPointer<Stack> nextStack    ← this is the NEXT pointer
//     +0x18 BSExtraDataList* extra              ← this is the EXTRAS pointer
//     +0x20 i32 count
//     +0x24 u32 flags
//   }
constexpr std::size_t INV_STACK_NEXT_OFF                  = 0x10;
constexpr std::size_t INV_STACK_EXTRAS_OFF                = 0x18;

// =========================================================================
// B6.5w3 — NPC continuous-state apply (animation graph + pos write)
// =========================================================================
// Source: re/B6.5_npc_pipeline_AGENT_B.md (RE'd 2026-05-10).
//
// `IAnimationGraphManagerHolder` is a sub-object embedded in `Actor` at
// offset 0x48. The setter functions take a pointer to it (NOT a pointer
// to the Actor), a `BSFixedString*` name, and a value. The functions
// internally fetch the actual `BSAnimationGraphManager` smart-pointer
// from `MiddleProcess + 0x258` and dispatch to its impl.
//
// BSFixedString minter (`sub_14167BDC0`) interns an ad-hoc literal into
// the global string pool and writes the entry pointer into the caller-
// supplied 8-byte BSFixedString slot. Refcount is bumped on the pool
// entry; if we cache the minted BSFixedString globally we keep the
// refcount stable across many setter calls (no leak per apply).
//
// Threading: setter routes through the manager's smart-pointer fetch +
// dispatch — main-thread-only because the manager is rebuilt by
// scene-graph mutations (cell load, race change, weapon swap, etc).
constexpr std::size_t    IANIMGRAPHHOLDER_OFF       = 0x48;   // Actor → IAnimationGraphManagerHolder sub-object
constexpr std::uintptr_t SET_GRAPH_VAR_BOOL_RVA     = 0x00818D60;
constexpr std::uintptr_t SET_GRAPH_VAR_INT_RVA      = 0x00818D80;
constexpr std::uintptr_t SET_GRAPH_VAR_FLOAT_RVA    = 0x00818DA0;
constexpr std::uintptr_t BSFIXEDSTRING_MAKE_RVA     = 0x0167BDC0;

// =========================================================================
// B6.5w4 — Per-Actor AI tick (suppression target)
// =========================================================================
// Source: re/B6.5_npc_pipeline_AGENT_A.md (RE'd 2026-05-10).
//
// `Actor::Update_PerFrame` at RVA 0xC636A0 is the SINGLE funnel for all
// per-Actor AI work each frame. Called by all three ProcessLists tier
// walkers (Mid/Low/High) + 5 forced-tick sites — hooking this one
// function with MinHook covers every call path. Signature:
//
//   void __fastcall sub_140C636A0(Actor* this, float simTime);
//
// Detour reads form_id at Actor+0x14. If form_id ∈ tracked-NPC set
// (registered via fw::dispatch::register_tracked_npc_form_id), bail
// out — vanilla AI doesn't run for that NPC, and our server-authoritative
// pos/yaw/anim writes become uncontested. Otherwise call the original
// (normal AI tick).
//
// Threading: always called from the engine main thread (verified by RE).
// Our register/is_tracked uses a std::mutex but the critical section is
// tiny (set lookup over ~2-10 entries for MVP); contention is negligible.
//
// Side effects of suppression for tracked NPCs:
//   - No pathfinding (good — server is the authority)
//   - No anim graph update by AI (good — server's SetGraphVariable wins)
//   - No gravity/collision check (cosmetic: NPC may float if terrain Z
//     doesn't match server's waypoint Z; accept for MVP)
//   - No combat/dialogue logic (good — B6.6 will drive these via server)
constexpr std::uintptr_t ACTOR_UPDATE_PERFRAME_RVA = 0x00C636A0;

// =========================================================================
// B6.5w4 round 3 — Actor → 3D NIF direct write
// =========================================================================
// Source: re/B6.5w4_round3_AGENT.md (RE'd 2026-05-11).
//
// To bypass the renderer-vs-AI fight, we write the NIF.world.translate
// directly each frame. The renderer reads from there, so winning the
// last write to that field = render shows our pos regardless of what
// Actor+0xD0 (the "logical" pos) holds.
//
// Pointer chain (TESObjectREFR::Get3D at RVA 0x0050D9D0 disasm:
// `mov rax, [rcx+0F0h]; mov rax, [rax+8]; retn`):
//   Actor + 0xF0  → LoadedRefData* (refcounted, NULL until 3D loaded)
//   LoadedRefData + 0x08  → NiAVObject* (BSFadeNode root)
//   NiAVObject + 0xA0  → world.translate (NiPoint3 — the renderer reads HERE)
//
// `bAnimationDriven` graph variable index in the pre-interned BSFixedString
// pool: `qword_1430DBF78[2939]`. We mint our own BSFixedString at init
// (idempotent against pool dedup) and call SetGraphVariableBool to clear
// it — disables anim root motion so the actor doesn't displace from
// walk-cycle animations fighting our pos writes.
constexpr std::size_t LOADED_REF_DATA_OFF    = 0xF0;  // Actor → LoadedRefData*
constexpr std::size_t LOADED_REF_DATA_3D_OFF = 0x08;  // LoadedRefData → NiAVObject*
// (NI_AV_WORLD_TRANSLATE_OFF = 0xA0 already defined above in B5 section)
// Local NiTransform on NiAVObject: rotation at +0x30, translate at +0x60,
// scale at +0x6C. Per scene_inject.cpp comments + standard NetImmerse
// layout (sizeof NiTransform = 0x40, two of them stacked).
constexpr std::size_t NI_AV_LOCAL_TRANSLATE_OFF = 0x60;

// =========================================================================
// B6.5w4 round 5 — Actor.EnableAI native (final AI silencer)
// =========================================================================
// Source: re/B6.5w4_round3_AGENT.md §"EnableAI" (RE'd 2026-05-11).
//
// `Actor.EnableAI(bool enable, bool queueEquipChange)` toggles bit 2 of
// `actor->actorFlags_720` (at offset 0x2D0) — the SAME bit the
// ProcessLists tier walkers test in their gate:
//     `if ((actor.flags_720 & 2) != 0) call Update_PerFrame(actor)`
// So calling EnableAI(false) makes the walker SKIP this actor entirely —
// Update_PerFrame never fires, AI never decides, anim graph never
// transitions on its own. Our scene_render late-frame override
// remains the sole authority over pos/NIF.world.translate.
//
// Signature: char __fastcall(void* actor, char enable, char queue);
// Side effects: resets movement controller (zeros velocity), dispatches
// re-equip if Get3D() non-null. Call ONCE per NPC at registration time
// (not every frame) to avoid re-equip storm.
constexpr std::uintptr_t ENGINE_ENABLE_AI_RVA = 0x00C76590;

// =========================================================================
// B6.5w4 round 7 — Atomic teleport silver bullet (4-agent consensus)
// =========================================================================
// Source: re/B6.5w4_round7_AGENT_B.md (RE'd 2026-05-11) — agent B of the
// 4-agent arena identified the canonical engine teleport primitive.
// Cross-validated by agent D's finding that our current write target
// (BSFadeNode.world.translate) doesn't drive render, and agent A's
// skeleton-root chain.
//
// `Actor::MoveTo` at RVA 0x00C60BE0 is the Actor-specific atomic teleport
// that the engine itself uses when scripts call `ObjectReference.MoveTo`.
// It writes Actor+0xD0, syncs the full NIF world transform tree, syncs
// the Havok rigid body, syncs the anim graph, AND re-attaches to the
// cell. ATOMIC = all caches updated in one call. Bypasses the 6-round
// fight with vanilla AI / Havok / NIF cache.
//
// Signature:
//   char __fastcall sub_140C60BE0(
//       Actor* this,
//       float  pos[3],                  // world coords
//       float  yaw,                     // Bethesda radians (Z-axis)
//       float  pitch,                   // Bethesda radians (X-axis), 0 for upright
//       REFR*  target_cell_or_null,     // nullptr to stay in same cell
//       REFR*  target_marker_or_null,   // nullptr
//       char   ranInteriorChange,       // pass 1 ("real teleport")
//       char   skipPlayerCheck,         // pass 0 unless caller is player
//       char   skipAreaCheck);          // pass 1 to skip "is target area loaded"
//
// Estimated cost: ~1.4 µs same-cell. At 10 Hz × 2 NPCs = 28 µs/sec.
// Safe.
constexpr std::uintptr_t ACTOR_ATOMIC_TELEPORT_RVA = 0x00C60BE0;

// `NiAVObject::SetMotionType` at RVA 0x018763E0 is the NIF-3D-level
// worker that walks the NIF subtree finding Havok rigid bodies and
// calls `hkpRigidBody::setMotionType` on each via a deferred callback.
//
// Motion types: 1=Dynamic, 2=Keyframed.
//
// We call this with motion_type=2 (Keyframed) once per tracked NPC at
// first sight. After that, Havok physics treats the body as externally
// controlled — Havok stops pushing the body around, so our per-tick
// teleports stick without physics fighting us.
//
// Signature:
//   char __fastcall sub_1418763E0(
//       NiAVObject* root3d,             // Actor's Get3D() output
//       int         motionType,         // 1=Dynamic, 2=Keyframed
//       char        a3,                 // pass 1
//       char        a4,                 // pass 0
//       std::uint8_t activateOnLand);   // pass 0
constexpr std::uintptr_t NIAV_SET_MOTION_TYPE_RVA = 0x018763E0;

// =========================================================================
// B6.5w12 — Ghost AI decision-point hook RVAs
//
// 12 small functions inside Fallout4.exe that the AI brain calls each frame
// to decide what an Actor should do this frame. We MinHook them and, for
// form_ids in our tracked-NPC set, substitute the server's decision instead
// of letting local AI decide. The engine then runs animation, IK, physics,
// render natively with our value as input. See NPCs.md "Next direction —
// Ghost AI pattern" + re/B6.5w12_round1_AGENT_{1,2,3,4}.md for the 4-agent
// RE arena that produced these.
//
// Implementation phasing:
//   Phase 2 step B (now): skeleton hook on PKG_EVAL_CONDITIONS_RVA only,
//                         log+passthrough. Confirms the hook installs and
//                         fires under realistic AI activity.
//   Phase 4 (incremental): per-hook server-decision logic + ramp through
//                         all 12 RVAs, one at a time with live test
//                         between each.
//
// Each hook is small and clean (per agent dossiers — 0x2A to ~0x800 bytes,
// most ≤ 0x100). All sit inside a per-frame AI tick pipeline and have
// signatures observed in the decomp at D:\falloutworld_decomp\out\.

// HOOK #1 OUTER — AIProcess::EvaluatePackages_And_Execute (the SELECTOR).
//
// The selector iterates an Actor's candidate packages and calls
// TESPackage::EvaluateConditions for each. We hook ENTRY ONLY (read arg2
// = Actor*, stash form_id in thread_local, tail-call original — we do NOT
// touch the body to avoid the package-selection TLS lock that agent 3
// flagged as deadlock-risky for mid-body detours).
//
// The thread_local captured here is then read inside the inner
// EvaluateConditions detour to know which Actor's packages are being
// evaluated this frame. Cleaner than guessing offsets inside the
// stack-allocated eval_ctx buffer (round 1/2/3 of runtime probing failed
// to identify a stable Actor* offset within eval_ctx).
//
// Signature (per agent 3 dossier):
//   bool __fastcall sub_140CEEC30(
//       AIProcess* aiproc,
//       Actor*     actor,
//       char       force_eval);
constexpr std::uintptr_t PKG_SELECTOR_RVA = 0x00CEEC30;

// HOOK #1 — TESPackage::EvaluateConditions (the MVP "predicate" hook).
//
// Pure predicate: returns bool. Caller (AIProcess::EvaluatePackages_And_Execute
// at 0x00CEEC30) loops over candidate packages in priority order, calls
// this for each. First TRUE wins → engine installs that package + runs the
// procedure executor natively. The cleanest hook of the 12 because it has
// ZERO side effects in the engine path — we just return TRUE for the
// package the server chose, FALSE for the rest.
//
// Signature (per agent 3 dossier):
//   bool __fastcall sub_140768CC0(
//       __int64*** condition_list_head,   // = pkg + 96
//       void*      eval_ctx);             // 112-B struct from sub_140768260
//                                         //   eval_ctx + 8 = Actor* (inferred)
//
// Note: the FUNCTION sees the condition list head (pkg+96), not pkg directly.
// To know which package is being evaluated:
//   - Back-compute: pkg = (char*)arg1 - 96 = (char*)arg1 - 0x60
//   - pkg form_id = *(u32*)(pkg + 0x14) = *(u32*)((char*)arg1 - 0x4C)
//   This is an empirically derived offset; verify at runtime before relying.
//
// MVP detour pseudo-code (Phase 4):
//   actor    = *(Actor**)((char*)eval_ctx + 8);
//   actor_fid = *(u32*)((char*)actor + 0x14);
//   if (actor_fid ∈ tracked_set) {
//       pkg_fid = *(u32*)((char*)condition_list_head - 0x4C);
//       return pkg_fid == cache[actor_fid].package_form_id;
//   }
//   return g_orig(condition_list_head, eval_ctx);
constexpr std::uintptr_t PKG_EVAL_CONDITIONS_RVA = 0x00768CC0;

// HOOK #2 — Actor::SyncCombatTargetFromAIProcess (the combat-target SETTER).
//
// Per agent 1 dossier (re/B6.5w12_round1_AGENT_1.md): 0x74 bytes. Called
// per-actor per-frame from inside Actor::Update_PerFrame. Mirrors the
// combat target form_id from AIProcess+0x6C to Actor+0x380 and toggles
// the InCombat flag bit 0x4000 in Actor+0x2D0 based on a hostility
// predicate. This is THE field Papyrus reads via GetCombatTarget (per
// agent 1 cross-check with sub_1405CD830).
//
// Body sketch (annotated):
//   char sub_140C5CCE0(__int64 actor) {
//     char result = (*vt[+0x7F0])(actor);    // some gate predicate
//     if (result) {
//       v3 = *(QWORD*)(actor + 808);         // = AIProcess-linked controller
//       if (v3) {
//         *(DWORD*)(actor + 896) =           // = Actor + 0x380 = combat_target_form_id
//             *(DWORD*)(v3 + 108);           // AIProcess + 0x6C
//         result = sub_14087A8E0(v3);        // is hostile? → result
//         if (result) *(DWORD*)(actor+720) |= 0x4000;      // set InCombat
//         else        *(DWORD*)(actor+720) &= 0xFFFFBFFF;  // clear InCombat
//       }
//     } else {
//       *(DWORD*)(actor + 720) &= ~0x4000u;
//       *(DWORD*)(actor + 896) = 0;
//     }
//     return result;
//   }
//
// Ghost AI substitution (Phase 4 step B):
//   if (actor_fid ∈ tracked_set && cache[fid].combat_target_form_id != 0) {
//     *(DWORD*)(actor + 896) = cache[fid].combat_target_form_id;
//     *(DWORD*)(actor + 720) |= 0x4000;      // force InCombat
//     return 1;                              // skip original
//   }
//   else { call_original(); }
constexpr std::uintptr_t COMBAT_TARGET_SETTER_RVA = 0x00C5CCE0;

// Actor field offsets exposed by hook #2 substitution.
constexpr std::size_t    ACTOR_COMBAT_TARGET_FORMID_OFF = 0x380;   // u32 form_id
constexpr std::size_t    ACTOR_FLAGS_720_OFF            = 0x2D0;   // u32 flags, bit 0x4000 = InCombat

// HOOK #3 — CombatAimController::SetAimTarget (the aim-vector WRITER).
//
// Per agent 1 dossier (re/B6.5w12_round1_AGENT_1.md): tiny function (0x2A
// bytes) that writes the aim target world-space position (NiPoint3) into
// the CombatAimController at offsets +24/+28/+32 (3 floats), sets a flag
// bit at +52, and stamps +56 with the current time.
//
// Signature:
//   void __fastcall sub_140E65820(CombatAimController* self,
//                                 NiPoint3* target_pos);
//
// CHALLENGE: self is CombatAimController, NOT Actor directly. To filter
// by tracked NPC form_id we need to walk the chain: self → ?? → Actor.
// Agent 1 said `self + 16` = owning CombatController*, and noted
// CombatController+104 / +128 / +376 are TARGET pointers (not owner). The
// OWNER Actor offset on CombatController is not yet documented — Phase
// 4 hook #3 SKELETON will dump candidate offsets in the log so we can
// identify it empirically from live data.
//
// Ghost AI substitution (Phase 4 hook #3 step B, deferred until owner
// resolved):
//   if (owner_actor_fid ∈ tracked_set && cache.aim_xyz non-zero):
//     target_pos->x = cache.aim_x;
//     target_pos->y = cache.aim_y;
//     target_pos->z = cache.aim_z;
//   ... then call original so it writes our coords into self+24/28/32.
constexpr std::uintptr_t AIM_SET_TARGET_RVA = 0x00E65820;

// HOOK #4 — Actor::TickMovementController (per-actor wrapper).
//
// Tortuous history (in order):
//   v1 (2026-05-11 early): RVA 0x00C65E20 (this function). Live test
//   showed 0 fires. Concluded: Update_PerFrame body INLINES the wrapper
//   (lines 8169-8186 — confirmed in decomp), so this path isn't called
//   from per-frame ticks of most actors → wrong target.
//
//   v2 (2026-05-11 mid): switched to MovementControllerNPC::Tick
//   (vt[8]) @ RVA 0x1E44660. Used Update_PerFrame bridge atomic to
//   identify Actor. Live test: 110k fires, 870 bails. Looked OK but
//   wasn't — false positive (user was in TCL noclip → raiders not in
//   combat → wouldn't have moved anyway).
//
//   v3 (NOW, B6.5w13 root analysis): SWITCH BACK to wrapper 0x00C65E20.
//   Re-analysis (re/B6.5w13_root_AGENT_2.md): the wrapper IS called
//   from the OTHER two paths we missed before:
//     - Tier walker sub_140DA9B30 (PlayerCharacter::Update chain)
//     - CombatManager::Update sub_140ED1BB0 per combat participant
//   These are exactly the paths combat raiders use. Update_PerFrame's
//   inline copy is just one of three, and not even the dominant one
//   for combat actors. The wrapper covers all paths AND has Actor* as
//   arg1 directly — no bridge needed.
//
// Signature:
//   void __fastcall sub_140C65E20(_QWORD *actor, float dt);
//
// Ghost AI substitution:
//   If actor is tracked AND cache.movement_override != 0:
//     - BAIL (don't call original)
//     - Also write bAnimationDriven=0 on the anim graph so root motion
//       doesn't translate the actor via anim
//     - Engine's MovementControllerNPC::Tick (via vt[8]) doesn't fire
//   Otherwise: passthrough.
constexpr std::uintptr_t MOVEMENT_TICK_RVA = 0x00C65E20;

// HOOK #5 — TESObjectREFR::SetPosition_NiPoint3 (BELT-AND-BRACES).
//
// Per re/B6.5w13_root_AGENT_2.md: this is the SINGLE FUNNEL for all
// Actor+0xD0 writes. 82 distinct callers across the engine. Of note,
// AIPackage executor sub_140CEEC30 has 8 separate direct calls for
// warp/idle packages — these BYPASS MovementController entirely, so
// hook #4 alone wouldn't catch them.
//
// Signature:
//   void __fastcall sub_140513A80(TESObjectREFR* refr, float pos[3]);
//
// Ghost AI substitution: same gate as hook #4 — for tracked NPCs with
// movement_override, BAIL. The actor won't get pos-written via any
// engine path. Combined with hook #4 wrapper bail, this should yield
// full freeze for tracked combat raiders.
constexpr std::uintptr_t SETPOSITION_NIPOINT3_RVA = 0x00513A80;

// HOOK #6 — Actor::SetPosition full (vt[202], slot offset 0x650 from Actor
// vtable base). Per re/B6.5w14_pair_AGENT_1A.md (95% conf): this is the
// real choke point for "translate this actor". Body:
//   1. Calls sub_140513A80(actor, pos) — our HOOK #5 catches and bails this
//   2. CONTINUES past the call, fetches NIF root via vt[1120] Get3D
//   3. Writes NIF+0x60/+0x64/+0x68 (NIF.local.translate) DIRECTLY
//      (disasm citation: text_0137.asm:9052 `mov [rbx+60h], ecx`)
// Step 3 BYPASSES our SetPosition_NiPoint3 hook. Hook #5 alone doesn't
// freeze the actor because NIF.local gets written here, then UpdateWorldData
// propagates parent.world × local → NIF.world (+0xA0), then renderer
// reads NIF.world.
//
// Bailing this WHOLE function at entry prevents BOTH the SetPosition
// call AND the NIF+0x60 direct write. Per agent 1A: 4 per-frame call
// sites in sub_140D11AF0 (procedure executor), called for combat raider
// AIPackage path-step / warp / idle marker.
//
// Signature:
//   void __fastcall sub_140C60630(Actor* actor, float pos[3]);
constexpr std::uintptr_t ACTOR_SETPOS_VT202_RVA = 0x00C60630;

// HOOK #7 — bhkCharRigidBodyController FinishPhysicsStep (Havok per-frame).
//
// Per re/B6.5w14_pair_AGENT_5A.md (80% conf): this is the TRUE Havok→engine
// pos sync, fires per-controller per frame. Bypasses SetPosition_NiPoint3
// because it dispatches via BSTEventSource at controller+48 to the actor's
// vtable slot 1 (Havok-pos-event sink). NO call to sub_140513A80 in this
// chain. Reads Havok body world pos, scales by 69.991249 (hk-units →
// game-units), then dispatches the pos event.
//
// Profiler tag: "TtRB-FinishPhysicsStep". Called per-controller from
// sub_1418C1B70 (bhkCharRigidBodyManager-AfterWholePhysicsUpdate).
//
// Pair 5A finding: owner Actor accessible via *(controller+32) back-ptr.
//
// THIS STEP (B6.5w15 Phase A): DIAGNOSTIC-ONLY. Install hook, log first
// N fires with controller pointer + read of +32 + form_id at +0x14. NO
// bail, NO substitution. Goal: empirically verify (a) function actually
// fires per-frame at expected rate during combat, (b) +32 read returns
// plausible Actor*, (c) form_id matches a tracked raider when those
// raiders are running.
//
// Signature (per pair 5A):
//   void __fastcall sub_1418B9790(bhkCharRigidBodyController* self);
constexpr std::uintptr_t BHK_CHAR_FINISH_STEP_RVA = 0x018B9790;


// ============================================================================
// B6.6w0 RE Arena results (2026-05-12, 10-agent pair, 95% confidence) —
// Ghost AI substitution hooks for combat behavior.
//
// All hooks below are NEW post-MVP-freeze targets. Each is independently
// validated by a pair of RE agents working from opposite ends (downstream
// vs upstream). Dossier `re/B6.6w0_pair_AGENT_*.md` per pair.
// ============================================================================

// Hook #3 (fire) — REPLACED 2026-05-12 evening.
//
// First attempt: `CombatBehaviorGunFire::DecideAndFire` at RVA 0x86FCA0
// (kept as named constant for archaeology). Live test 2026-05-12
// confirmed C1 dossier's open question Q1: this is the leaf-decide
// function for SINGLE-SHOT `GunFire` ONLY. BurstFire / SuppressiveFire
// / SuppressiveBurstFire have their own leaf decides → bypass our
// hook. At Concord (Phase B test): only 10 fires logged in 30 sec for
// fid 0x46458 (a single-shot weapon raider); all bailed; raiders
// shooting auto weapons were untouched. Replaced by ACTOR_FIRE_WEAPON_RVA
// below (universal funnel).
constexpr std::uintptr_t COMBAT_GUNFIRE_DECIDE_RVA = 0x0086FCA0;

// Hook #3 v2 (fire weapon) — `Actor::FireWeapon` at RVA 0x479680.
//
// Per C1 §3 chain: ANY fire path (single-shot, burst, suppressive,
// suppressive-burst, even melee/spell projectiles) eventually funnels
// through this function. It's the universal projectile-spawn entry:
//
//   ConcreteFormFactory<BGSProjectile> → Projectile alloc
//   → Havok body Add → projectile in flight
//
// Critically: signature has `Actor* this` in rcx (first arg). NO TLS
// chain needed — we read formID from `Actor+0x14` directly. Confirmed
// in disasm at text_0047.asm:18406 (`mov r13, rcx`).
//
// Function signature (per disasm of first ~30 instructions):
//   void __fastcall sub_140479680(Actor* actor, void* arg2, int arg3, void* arg4);
//   - rcx = Actor* (the firing NPC, or PlayerCharacter for player input)
//   - rdx = some pointer (TESObjectREFR target? weapon ref?) — not used by us
//   - r8d = u32 (action ID? flags?) — not used by us
//   - r9 = pointer — not used by us
//
// SUBSTITUTION strategy: if Actor is tracked AND not player (form_id
// 0x14), bail before original runs → no projectile, no anim event
// secondaries, no ammo deduction. AI state "thinks it fired" but
// projectile never materialises. This causes AI-side desync (cooldown
// thinks shot happened) which is acceptable for MVP because the
// freeze still works.
//
// C1 marked this as "TOO LATE TO HOOK" because hooking here means
// projectile is already constructed if we DON'T bail. But we DO bail,
// so the construction is skipped entirely. The "AI thinks fired"
// concern is moot for our visual-sync MVP.
//
// Confidence: HIGH (signature verified in disasm; Actor* directly in
// rcx; called for every weapon fire by every actor including player).
constexpr std::uintptr_t ACTOR_FIRE_WEAPON_RVA = 0x00479680;

// ============================================================================
// B6.6w0 "all hooks" batch (2026-05-12 evening) — install everything from
// the 10-agent arena that has clear Actor* arg, debug from there.
// ============================================================================

// Hook #1 (combat target writer) — pair A1+A2 dossier.
// `AIProcess::SetCombatTarget(AIProcess* rcx, Actor* rdx)` — writes
// `*(AIProcess+0x6C) = target.formID`. Per A1 disasm at text_0093.asm:688-691:
//   mov ecx, [rcx+68h]       ; ECX = old target u32
//   mov r15, [rsi+178h]      ; r15 = override target ptr (AIProcess+0x178)
// Both A1 and A2 agree this is the canonical writer. Owner Actor of
// the AI process is NOT in args here — we resolve via aiproc→fid map
// (populated by npc_ai_suppress at Actor+0x328).
//
// Substitution strategy: replace rdx (new target Actor*) with server-
// chosen target. For Phase 1 we DIAGNOSTIC ONLY: log first N fires
// to confirm hook semantics + fid identification.
constexpr std::uintptr_t AIPROCESS_SET_COMBAT_TARGET_RVA = 0x0087AB30;

// Hook #2 v2 (movement intent decision funnel) — pair B1 dossier.
// `AIProcess::ProcessPackages_Movement(AIProcess* rcx, Actor* rdx, char a3)`
// — iterates AIPackages, switches on package type, calls
// `sub_140513A80(actor, target_pos)` to write Actor+0xD0/0xD4/0xD8.
// Size 0x844. NON-inlined (B1 caller chain confirmed).
//
// Owner Actor* is rdx (2nd arg) — direct read possible.
//
// BAIL strategy: if rdx-Actor is tracked, skip original → no movement
// decision processed for this actor this frame → pos stays put.
// Belt-and-braces with our existing pos_belt / actor_setpos hooks.
constexpr std::uintptr_t AIPROCESS_PROCESS_MOVEMENT_RVA = 0x00CEEC30;

// Hook #3 alternative (dispatch attack action) — C1 chain @ §3 line 286.
// `Actor::DispatchAttackAction(Actor* rcx, int action_id rdx, int a3 r8)`
// per pseudo-C `__int64 __fastcall sub_140E6F830(__int64 a1, int a2, int a3)`.
//
// Called AFTER any CBT leaf decides to fire, BEFORE the anim event
// dispatcher → before WeaponFireHandler → before projectile spawn.
// Constructs BGSActionData on stack and vfcalls vt+40 → "WeaponFire"
// anim event.
//
// This is the UNIVERSAL ATTACK FUNNEL — single-shot, burst, suppressive,
// melee, power attack all go through here. Bailing this with Actor*
// in rcx directly identifiable is the cleanest "stop attacks" hook.
//
// Common action IDs (per C1 dossier §3):
//   0x3D = ActionAttackSighted
//   0x3E = ActionAttackSightedPower
//   0x23 = ActionAttack
//   0x27 = ActionAttackPower
//   12, 14, 15, 16, 17, 18, 19, 20, 26, 36, 40 = various attacks
//
// BAIL strategy: if Actor* in rcx is tracked && not player, return 0.
// Caller treats as "action failed", retries next tick.
constexpr std::uintptr_t ACTOR_DISPATCH_ATTACK_ACTION_RVA = 0x00E6F830;

// Hook #5 (hit applier orchestrator) — `sub_140CD2780`. Per D2 dossier
// this is the CENTRAL FUNNEL for projectile + melee + explosion hit
// processing. Inside, it calls in order: stagger applier
// (sub_140C92350), hit-reaction animator (sub_140C88950), HP decrement
// (sub_140CC9650), and (if HP=0) ragdoll setup (sub_140CA7880).
//
// Signature per pseudo-C (funcs_0307.md:6911):
//   __int64 __fastcall sub_140CD2780(__m128 *a1, __m128 *a2);
//
// Args are IDA-typed as __m128* (packed-vector structs). a1 is a
// HIT-DATA / HIT-EVENT struct with:
//   a1[48].m128_u64[0]  (= a1+0x300) = TARGET ACTOR POINTER ← THE VICTIM
//
// Confirmed via disasm at text_0142.asm:7491-7492:
//   cmp [rcx+300h], r12     ; r12=0 → checking target_actor == null
//   jz  loc_140CD4B90       ; bail if null (early-exit branch)
//
// So *(rcx + 0x300) is the target Actor*. Read its form_id at +0x14.
//
// BAIL strategy: if target is tracked (frozen), bail this orchestrator
// entirely → no stagger anim applied to frozen anim graph, no hit
// reaction, no HP decrement, no ragdoll. Critical for crash prevention:
// the crash 2026-05-12 evening "user attacks friendly NPC → crash 3s
// later" matches exactly this code path — engine tries to apply
// stagger/hit anim to a frozen anim graph, leaves it in inconsistent
// state, subsequent access AVs.
//
// Confidence: HIGH on RVA + a1+0x300 = target Actor (disasm verified).
// MEDIUM-HIGH on bail behavior (cleanest place to short-circuit; the
// caller is the dispatcher case 14 path in sub_140C4CE00 which
// already handles "case did nothing" gracefully).
constexpr std::uintptr_t ACTOR_HIT_APPLIER_RVA = 0x00CD2780;

// Offset to target Actor within the hit-data struct passed as 1st arg.
constexpr std::size_t HIT_DATA_TARGET_ACTOR_OFFSET = 0x300;

// Hook #4 (HP writer) — still deferred. `sub_140CC9650` signature is
// `(_QWORD *AVO_view, int=2 for HP, __int64 healthForm, float delta,
// __int64 source)`. The victim Actor is reachable via AVO_view → owner
// chain but exact offset not yet RE'd. Bailing sub_140CD2780 above
// short-circuits BEFORE sub_140CC9650 is called for tracked NPCs, so
// HP authority can stay deferred for the MVP.


// ============================================================================
// B6.6w0 NUKE — per-actor combat orchestrator (the TOP-LEVEL hook).
//
// 2026-05-12 live test feedback: with 6 hooks installed (Update_PerFrame
// bail, havok step, pos belt, actor setpos, dispatch_attack BAIL, fire
// decide BAIL, hit_applier BAIL), NPCs are FROZEN + IMMORTAL + can't
// attack, BUT still visually "angry" — aim animation, head tracking,
// hostile barks. User: "stiamo sbagliando hooks".
//
// Root insight: we've been suppressing OUTPUTS one-by-one (fire decide,
// attack action, hit response, movement). The COMBAT PIPELINE still
// thinks every frame. The orchestrator decides every frame "what
// combat work should this actor do" and dispatches everything.
//
// Per A1 chain (re/B6.6w0_pair_AGENT_A1.md):
//   Main::TickFrame
//     → sub_140ED2280 (per-frame AI fan-out)
//       → sub_140ED4760(form_id) (task thunk)
//         → Actor::vt[255] = sub_140CCFDF0 (per-actor orchestrator) ← HERE
//           → sub_14087B080 (promoter) → sub_14087AB30 (combat target write)
//           → ... (every other combat decision)
//
// Bailing sub_140CCFDF0 for tracked actors prevents ALL combat work for
// that actor — no target promotion, no fire decide chain, no dispatch
// attack, no aim update. Anim graph stays in whatever pose it was at
// freeze time (still potentially "combat ready") but no NEW combat
// reasoning happens.
//
// Signature per pseudo-C (funcs_0307.md:4668):
//   char __fastcall sub_140CCFDF0(__int64 a1, __int64 a2);
//   - a1 = Actor* (rcx) — the actor being orchestrated
//   - a2 = ??? (rdx) — probably state/flag arg, we pass through
// Returns char (bool). Returning 0 ≡ "no combat work this frame".
//
// Confidence: HIGH on RVA + Actor* in rcx (disasm verified: rsi=actor
// saved at function start, then reads +0x10/0x300/0x100/0x43C etc.).
//
// THIS IS THE NUKE — combined with existing freeze + immortality hooks
// this should give us totally neutral, non-aggressive tracked NPCs.
constexpr std::uintptr_t ACTOR_COMBAT_ORCHESTRATOR_RVA = 0x00CCFDF0;

// .data slot holding the tlsIndex used by sub_14086FCA0 to find the
// per-thread CombatBehaviorThread. ABSOLUTE address per dossier:
// 0x143E5C658 → RVA 0x03E5C658.
//
// The slot contains a `u32 tlsIndex` (Windows TLS slot index). To read
// the per-thread CombatBehaviorThread pointer:
//   u32 idx  = *(u32*)(module_base + 0x03E5C658);
//   void* p  = ((void**)NtCurrentTeb()->ThreadLocalStoragePointer)[idx];
//   // p is the CombatBehaviorThread's TLS-resident process-block holder
constexpr std::uintptr_t BEHAVIOR_THREAD_HOLDER_TLSIDX_RVA = 0x03E5C658;

// Inner offsets in the TLS-walk chain (constants pulled from the
// pseudo-code at the head of sub_14086FCA0). Kept as named constants
// rather than magic numbers so the chain reads cleanly in the detour.
constexpr std::size_t BEHAVIOR_HOLDER_OFFSET            = 0x8F0;   // 2288
constexpr std::size_t BEHAVIOR_THREAD_PROCESS_OFFSET    = 0x158;   // 344
constexpr std::size_t BEHAVIOR_AIPROCESS_ACTOR_OFFSET   = 0x68;    // 104

} // namespace fw::offsets
