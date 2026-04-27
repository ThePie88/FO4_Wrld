# FO4_Wrld — Changelog

Full version history. README has the latest 3 entries summarized; everything
older lives here. Format: newest first, milestones / patches inline.

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
