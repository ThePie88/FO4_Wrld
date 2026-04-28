# FO4_Wrld — Changelog

Full version history. README has the latest 3 entries summarized; everything
older lives here. Format: newest first, milestones / patches inline.

---

## B8 — force-equip-cycle on game start (2026-04-28) — ⚠️ TEMPORARY WORKAROUND

> **This is a band-aid, not a fix.** It papers over an M8P3 architectural
> bug (ghost body skin instance shares pointers with the local player
> skeleton) by exercising the player's `BipedAnim` through
> `ActorEquipManager` once on game start, before any remote peer can
> connect and bind a ghost. After that initial cycle, subsequent equip
> changes don't crash — but the underlying fragility remains: any save
> without `Vault Suit 111` (form `0x1EED7`) silently no-ops the cycle and
> the crash returns. Proper fix is **Option C** (load an independent
> `skeleton.nif` for the ghost via the canonical NIF loader so it has its
> own `BSFlattenedBoneTree` not shared with the player) — deferred,
> multi-day RE work.
>
> Tracking: `re/M9_y_post_bmod_crash_dossier.txt` documents the failed
> M9 attempts (B-MOD+E null `skel_root`, recursive cull-flag 0x2001,
> PipBoy SSN-detach gating — all 3 produced different crash signatures).
> Reopen and finish Option C when M9 (equipment sync between peers)
> becomes a milestone priority.

**Three days of crashes finally bypassed.** Player can now change clothes
freely with the M8P3 ghost body of remote peers active, no SEGV — as long
as the cycle ran on game start and the save has Vault Suit equipped.

### The problem

After save-load, the local player's `BipedAnim` is in a semi-allocated
state — some fields point at globally-pooled save-format data instead of
heap-owned. The M8P3 ghost body (representing remote peers visually) binds
its skin instance pointers (`bones_fb`, `bones_pri`, `skel_root` at
`skin+0x10/+0x28/+0x48`) to that semi-allocated skel. When the LOCAL player
then triggers an equip change (Vault Suit, armor, anything biped), the
engine's `BipedAnim` rebuild walker (`sub_1416C7510` →
`BSAttachReferenceProcess::Process`) iterates over the freed pool refs
holding stale `BSFlattenedBoneTree` joints → AV.

### Why M9 attempts failed (3 days, 3 different crashes)

| Approach | Crash signature |
|---|---|
| B-MOD+E null `skin->skel_root` | RIP=0x16D7A1E, AV @ 0xA0 (engine deref'd null skel_root) |
| Recursive cull-flag 0x2001 | Crash returned to FBT walker (different walker entirely) |
| PipBoy SSN-detach gating | `detach_child` itself SEH'd; walker never visits SSN anyway |

Common architectural error: all three tried to protect the ghost during
the equip event. But the engine reaches our skin via a "users-of-bone"
internal cache, NOT via SSN. The ghost can't hide from that walker no
matter where it sits in the scene tree.

### The fix — workaround, not architectural

User's empirical observation 2026-04-28: cycling Vault Suit
unequip+equip BEFORE peer connects normalizes the BipedAnim state.
After the cycle, M8P3 binds to fully-heap-owned data → equip changes
post-peer-connect no longer dangle.

Implementation (`fw_native/src/hooks/equip_cycle.{cpp,h}`):
1. `arm_equip_cycle_after_loadgame(10000)` armed in `main_menu_hook`'s
   `fw_wndproc` post-LoadGame callback (timing measured from LoadGame
   call, not DLL inject).
2. Worker thread sleeps 10s → posts `WM_APP+0x4A` (UNEQUIP).
3. Main thread WndProc receives → calls `ActorEquipManager::UnequipObject(
   mgr=qword_1431E3328, player, vault_suit_form_pair, count=1, slot=0,
   stack_id=0, flags=0)`.
4. Worker sleeps 2000ms (gap for biped rebuild settle — 500ms was too
   short, caused EQUIP SEH).
5. Worker posts `WM_APP+0x4B` (EQUIP). Main thread calls
   `ActorEquipManager::EquipObject(mgr, player, vault_suit, count=1,
   stack_id=1, slot=0, ...)` — args `a5=1, a9=1` literal, mirrors the
   common engine caller pattern (a5=0/a9=0 path goes through
   `sub_140505440` which faults on freshly-unequipped stack info).

Visually: ~2s flicker of "no Vault Suit" right after entering the world,
then automatic re-equip. After this, peer connection + ghost spawn +
manual equip changes work cleanly on both clients.

### Reverse engineering

Dossier: `re/B8_force_equip_cycle.log` (5331 lines). Identified:
- `ActorEquipManager` singleton at `qword_1431E3328` (RVA `0x031E3328`),
  confirmed via xref pass on 4 callers all passing it as a1.
- `sub_140CE5900` `EquipObject` 11-arg signature (a4=count, a5=stack_id,
  a6=slot, ...).
- `sub_140CE5DA0` `UnequipObject` 11-arg signature — args 4-5-6 are in
  DIFFERENT ORDER from Equip (a5=slot, a6=stack_id). Yesterday's M9 hook
  attempt got these swapped.
- Form pair layout: `{TESForm*, extra/0}`. Initial implementation had
  it backwards (`{0, TESForm*}`) which made both calls early-exit
  silently — fixed by swapping.

### Known limitations

1. EQUIP engine call still SEH's internally on completion (caught by
   our `__try`, game stays alive). The work has fully landed by the time
   the fault hits — Vault Suit re-equipped, BipedAnim normalized. Looks
   like cleanup-path bug in our arg combination; not blocking.
2. Hardcoded to Vault Suit form `0x1EED7` from our `world_base.fos`.
   A save without it would no-op the cycle and the M8P3 crash would
   re-emerge. Future polish: cycle whatever's currently equipped.
3. Architectural root cause (M8P3 sharing player skel pointers) is NOT
   fixed. Option C (independent skeleton.nif loaded for the ghost) is
   the proper fix, multi-day RE work — deferred.

### Failed M9 work archived

`re/M9_y_post_bmod_crash_dossier.txt` documents the post-B-MOD+E crash
analysis (2-loop bug in `NiNode::Update`, vt[51] of BSGeometry =
`UpdateLocalGeomBound`, why nullifying `skel_root` causes a NEW null
deref). Useful reference if Option C is ever tackled.

---

## B6 wedge 1 — door open/close sync between peers (2026-04-27)

[![Door sync demo on YouTube](https://img.youtube.com/vi/T8wLZmCqjxw/maxresdefault.jpg)](https://youtu.be/T8wLZmCqjxw)

▶ **[Watch the 30s door-sync clip on YouTube](https://youtu.be/T8wLZmCqjxw)**

First true end-to-end world-state replication beyond the player avatar +
inventory. Peer A presses E on a door → peer B sees the same door swing
open in real time (and vice versa). Symmetric for close. Spam-tested
A↔B for 5-10 cycles without desync.

### Pipeline

**Sender side**: hook engine `Activate worker` (`sub_140514180` @ RVA
`0x514180`).
- Detour entry: if `tls_applying_remote` flag set → passthrough (feedback-
  loop guard, shared with `container_hook` via `ApplyingRemoteGuard` RAII).
- Observe REFR identity: `form_id`, `base_id`, `cell_id`, `formType`.
- Filter on door-like form types: `0x1F` (TESObjectDOOR), `0x20`/`0x24`
  (TESObjectACTI activator-style — most Sanctuary house doors are these,
  not the cell-transition DOOR type), `0x29`.
- Enqueue `DOOR_OP` to server (reliable UDP), then chain to `g_orig` so
  vanilla engine animation fires locally.

**Server**: pure fan-out (`net/server/main.py::_handle_door_op`). No
validation — toggle is self-correcting.

**Receiver side**:
- Net thread: dispatch `DOOR_BCAST` → enqueue `PendingDoorOp` on the
  main-thread queue, post `FW_MSG_DOOR_APPLY` (= `WM_APP + 0x49`) to
  the FO4 main window.
- Main thread (`fw_wndproc` subclass): drain queue inside an
  `ApplyingRemoteGuard` scope so the local door hook detour treats
  this re-entry as remote-apply (skips broadcast).
- `apply_door_op_to_engine` resolves the local REFR via
  `lookup_by_form_id`, identity-checks `(base, cell)` against the
  broadcast values, and invokes `sub_140514180(refr, null, null, 1, …)`.
  The engine's animation graph fires automatically.

### Toggle semantics

`Activate worker` flips the open state on every call. Receiver
re-invoking it on its local REFR performs the same flip from whatever
local state was. Both clients converge as long as they started from
the same `world_base` save (the engine's save-load propagator
`sub_140510CE0` at `vt[0x99]` sets initial state on cell stream-in).
If they diverge briefly (rare missed BCAST), the next press resyncs
them. **No server-side state tracking needed.**

### Dual-agent RE methodology

Reused the M8P3 pattern: 2 independent agents with non-correlated
investigation strategies converge or diverge on the answer. Dossier:
[`re/B6_doors_AGENT_A_dossier.txt`](re/B6_doors_AGENT_A_dossier.txt) +
[`re/B6_doors_AGENT_B_dossier.txt`](re/B6_doors_AGENT_B_dossier.txt).

- **Agent A — vtable enumeration**: walked `TESObjectREFR` vtable from
  slot `0x70` to `0xA0`, decompiled each, found `vt[0x99] = sub_140510CE0`
  with door-form-type gate + `CHANGE_OBJECT_OPEN_STATE` bit + the inner
  `sub_140305760` setter call.
- **Agent B — string xref**: located the string `'CHANGE_OBJECT_OPEN_STATE'`
  (= changeflag bit `0x800000`), found 58 functions referencing this
  immediate, **exactly 1** lives in the `TESObjectREFR` vtable: slot `0x99`.

Both converged on `vt[0x99]` BUT both also flagged that this slot is
only the save-load propagator (2 callsites: `Load3D` worker + savegame
tree walker), NOT the live keypress handler. Agent A explicitly
recommended `sub_140514180` ("Activate worker") for live detection.

### Empirical phase progression

| Phase | Hook target | Fires at load | Fires on keypress | Verdict |
|-------|------------|---------------|-------------------|---------|
| 1.a | `sub_140305760` (SetOpenState mutator) | 3527 | **0** in 75s gameplay | ❌ save-load only |
| 1.b | `sub_140514180` (Activate worker) | 0 | **14** matching keypresses | ✅ correct target |
| 2 | same + protocol + receiver apply | (filtered) | 1 fire/keypress, broadcast OK | ✅ shipped |

The 3527 fires in phase 1.a were the bulk-apply pass: at game load,
the engine walks ALL state-trackable refs in streamed cells (doors,
lights, containers w/ lid, activators) and applies their persisted
open state. None of these are live keypress events.

### Bug squashed during phase 2 ship

`FW_MSG_DOOR_APPLY` was initially assigned `WM_APP + 0x47`, **colliding
with `FW_MSG_STRADAB_BONE_TICK`** (also `WM_APP + 0x47`, owned by
`scene_inject.h`). WndProc dispatch order checked DOOR_APPLY before
BONE_TICK → 20Hz pose-tx never fired → ghost body stuck in T-pose
for the OTHER peer.

User flagged "regressione gravissima animazioni rotte sul body".
Caught + fixed pre-commit: moved `DOOR_APPLY` to `WM_APP + 0x49`,
added an exhaustive offset table comment in `main_thread_dispatch.h`
to prevent recurrence. Lesson: `grep "WM_APP +"` across the project
before assigning a new offset.

### Code deliverables

- `fw_native/src/hooks/door_hook.{cpp,h}` — sender-side detour
- `fw_native/src/engine/engine_calls.cpp::apply_door_op_to_engine` —
  receiver-side engine call with SEH cage + identity check
- `fw_native/src/main_thread_dispatch.{cpp,h}` — door queue + drain
- `fw_native/src/hooks/main_menu_hook.cpp` — WndProc case
- `fw_native/src/net/{client,protocol}.{cpp,h}` — DOOR_OP/DOOR_BCAST
- `net/protocol.py` — Python codec mirror (byte-identical roundtrip)
- `net/server/main.py::_handle_door_op` — fan-out

### Known limits carried forward

- Form-type filter is liberal (4 types) — if non-door fires leak,
  tighten post-hoc from log evidence.
- Receiver-side `Activate worker` invoked with `activator=nullptr`.
  If door behavior depends on activator (NPC-only doors,
  activator-tracked locks), may need to pass local PC. Not observed.
- No interpolation: high-RTT peers see the door fire visibly later.
  Acceptable for v1 (broadcast is reliable, no drops).

Commit: `39b7090`, tagged `v0.2.0-pre-worldsync`.

---

## M8P3.23 — head/hands skin swap + sentinel quat (2026-04-27)

Fixes head and hands T-pose. Two changes:

1. **Apply skin swap to head + hands NIFs**, not just body.
   `BaseMaleHead.nif` and `MaleHands.nif` are loaded as separate NIFs
   attached as children of the body NIF. Each has its own BSGeometry +
   skin instance binding to its own internal `_skin` stubs. Without
   swap on these, the head/hand meshes keep reading FROZEN bind-pose
   matrices regardless of how we drive the skel joints — head and
   hands stay T-pose.

   With swap: head + hands `bones_fb` rebound to the SAME skel joints
   the body uses, and `bones_pri` pointer-cache (skin+0x28) re-pointed
   to `skel_joint+0x70`. All three meshes now read from the shared
   skel hierarchy → engine UpdateDownwardPass propagates joint
   rotations to all mesh anchors uniformly → head bobs with neck
   animation, hands curl with forearm chain.

2. **Sentinel quaternion (qw=2.0)** for joints not present in local
   PC's render-scene tree. Previously sender wrote identity (0,0,0,1)
   for missing names like fingers, AnimObjects, helpers — forcing the
   receiver to write extended bind = T-pose stick fingers. Now sender
   marks missing joints with qw=2.0 (invalid for unit quat). Receiver
   detects qw>1.5 and skips that bone, letting engine keep the natural
   bind pose (slightly curled fingers, looser wrists).

**Verified working end-to-end:** walk / run / idle / sneak / turn / jump /
breathing — all standard FO4 movement set replicates body-wide
including head bobbing and hand wrist articulation.

**Known limitations carried forward:**
- Fingers don't articulate (joints only in havok skeleton, not in
  render-scene walk path)
- Ghost body has no shadow (separate render flag, deferred)
- 1P sender → V/T-pose contagion (PlayerCamera singleton RE pending)

Commit: `a98eb35`

---

## M8P3.20+22 — 20Hz rate + 1P/3P path fallback (2026-04-27)

**Working:**
- Bumped pose broadcast rate from 5Hz → 20Hz (every bone-tick).
  Bandwidth: ~26 KB/s/peer at 80 bones × 16B/quat. Visual smoothness
  confirmed — running animation now fluid, not stepped.
- Dual-path lookup: `Player+0xF0+0x08` (alt-tree) primary,
  `Player+0xB78` (REFR_LOADED_3D) fallback. Walks both, picks richer.
  Future-proofs the case where +0xF0+0x08 is null/sparse.
- Cleaner sender code: SEH-isolated path resolution, no C++/SEH conflicts.

**Known limitation (1st-person sender):**
When the local PC is in 1P view, the engine animates alt-tree bones
to V-pose (idle) or T-pose (moving) STUB animations because the body
is invisible to the local camera. Broadcasting these makes the remote
ghost adopt those stub poses.

Tried two heuristics, both failed:
1. Pelvis-canary skip: alt-tree keeps all 57 named nodes in 1P, so
   Pelvis is always present.
2. Rotation-hash skip: bones DO get rotated in 1P (just to stub poses),
   so hash changes every tick.

Proper fix requires RE'ing the engine's `PlayerCamera` singleton to
read its 1stPerson/3rdPerson state field. Deferred.

**Workaround:** observed peer keeps 3rd-person view while watched.
Gracefully degrades when sender goes 1P (ghost shows V/T-pose) and
recovers immediately when sender returns 3P.

Commit: `d968a09`

---

## M8P3 — Pose replication over network (2026-04-26)

**First end-to-end animation replication.** Peer A's body movement
triggers peer B's ghost-of-A to mirror in real time.

### Pipeline (per frame, 5Hz network rate)

1. Sender (peer A) reads local PC's joint `m_kLocal` rotations.
2. 3x3 → quaternion → packed in `POSE_STATE` payload (~1KB).
3. Server fan-outs to other peers as `POSE_BROADCAST`.
4. Receiver (peer B) writes received quaternions into ghost skel
   joint `m_kLocal`.
5. Engine `UpdateDownwardPass` propagates rotations through the
   skeleton hierarchy → skin anchors inherit → GPU draws animated body.

### RE deliverables

- `re/M8P3_skin_instance_dossier.txt` — full BSSkin::Instance layout
- `re/M8P3_skin_walker_dossier.txt` — `NiAVObject::UpdateWorldData` chain
- `re/M8P3_skin_update_pass_AGENT_*.txt` — dual-agent investigation of
  the GPU upload pipeline (concluded: pull-based via SRV, no flat buffer)

### Code deliverables

- `fw_native/src/native/skin_rebind.{cpp,h}` — bones_fb swap +
  bones_pri re-cache (critical for GPU to read swapped matrices)
- `fw_native/src/native/scene_inject.cpp` — `on_bone_tick_message`
  (sender, 20Hz tick / 5Hz broadcast) + `on_pose_apply_message`
  (receiver, main-thread)
- `fw_native/src/net/protocol.h` + `net/protocol.py` —
  `MessageType::POSE_STATE` / `POSE_BROADCAST` (variable-length
  quaternion payloads, max 80 bones × 16B)
- `net/server/main.py` — `_handle_pose_state` fan-out

### Bugs squashed during M8P3 (chronological — for posterity)

1. `get_bone_by_name("LArm_ForeArm1_skin")` returned NULL because cached
   skel had only `_skin`-stripped names (false at the time, see #6).
2. Skel cache had duplicate name entries; `find_node_by_name` first-match
   diverged from the swap walker's match for the same name.
3. `swap_for_geometry` modified only `bones_fb`, not `bones_pri`. GPU
   reads `bones_pri` → kept reading stale stub matrices.
4. `bones_pri[i]` was assumed to be `NiAVObject*` array — it's actually
   a pointer-cache to bone+0x70 (matrix data). Confirmed via TTD.
5. Test cycle matrix translation formula was wrong (was
   `T(joint)·R·T(-joint)` for pure-rotate-around-joint, but the bone's
   m_kWorld translation should stay at joint position regardless).
6. Bind orientation was lost when overriding world matrix with pure
   `R_y` — replaced with `R_y(angle) × engine's_3x3` to preserve.
7. Translation feedback loop: tick handler read `bone+0xA0` to compose
   override translation, but our hook had just overwritten that field
   → translation frozen at first-tick value → forearm pinned at spawn
   while body translated. Solved by hook applying 3x3 delta only;
   translation always taken from engine's just-written m_kWorld.
8. Sender + receiver sorted bone trees alphabetically and indexed
   positionally — but the trees had **different content** (local PC
   render scene vs ghost skin). Fixed via canonical name list cached
   from skel.nif (joints only, `_skin` anchors filtered out).
9. `bones_fb` is missing intermediate joints (only `_skin` anchors for
   forearms etc.). Refactored canonical to walk skel.nif directly,
   filter `_skin`, keep all 80+ joints.

### Diagnostic tools added

- **TTD (Time Travel Debugging)** via WinDbg Preview — recorded a 10GB
  trace of FO4 to confirm `bones_pri[i]` layout via memory inspection.
  Setup at `ttd_attach.bat` (run as admin while game is alive).
- **7 Frida scripts** for runtime memory diff, pose probe, skin buffer
  hunt, etc. Under `frida/14_*.js`–`20_*.js`.

### Open work tracked at this point (status as of M8P3 commit)

- Step 4: replicate fingers (resolved: limitation documented, fingers
  not in render-scene tree)
- Step 5: bump network rate from 5Hz → 20Hz (✅ shipped in M8P3.20)
- Step 6: receiver-side interpolation for visual smoothness (open)
- Step 7: multi-peer ghost cache (registry per peer_id) (open)

Commit: `874c0ca`

---

## M6.final / v18.2 — Textured ghost body T-pose baseline (2026-04-25)

Pre-M8 baseline: ghost body visible + textured + position/yaw tracked.
T-pose static. Animation was the M8 milestone.

### Achievements

- **Single-instance bypass** (1-byte binary patch @ RVA `0xC2FB62`) —
  runs 2 FO4 instances simultaneously on same machine.
- **`apply_materials` walker** (`sub_140255BA0`) — `.bgsm` material
  resolution after standalone NIF load.
- **NIF loader public API** (`sub_1417B3E90`) — bypasses broken cache
  wrapper that hangs with naive args.
- **Scene graph integration** — depth occlusion, lighting, shadows
  via `BSFadeNode` attachment to `ShadowSceneNode`.

Commit: `d5f8e80`

---

## Earlier (B0–B4)

| Milestone | Status |
|-----------|--------|
| **B0** Networking + native client port | ✅ done — 196+ pytest, byte-identical protocol |
| **B1** Container pre-mutation block | ✅ done — concurrent TAKE dup race closed |
| **B2** Launcher (`FoM.exe`) | ✅ done — drop-in for `start_A.bat`/`start_B.bat` |
| **B3** Auto-load save (delayed LoadGame via WndProc subclass) | ✅ done |
| **B4** Worldstate sync | 🟡 GlobalVar shipped; QuestStage RE done, apply pending wire |
