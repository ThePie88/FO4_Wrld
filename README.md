
This project uses unconventional approaches in several critical areas (scene graph injection, skin buffer manipulation, binary patches). External contributions could inadvertently break invariants that aren't documented at the line level. The license reflects this — the source is published for transparency and review, not for collaborative development at this stage. May reconsider after the architecture stabilizes and a CONTRIBUTING.md exists.

# FO4_Wrld

Fallout 4 1.11.191 next-gen — multiplayer mod (FoM-lite framework).
Solo-dev, evening project. Target: 10-player persistent-world survival MMO.

> **Status (2026-04-26):** ghost player body **animates** in real time —
> 31 of ~70 joints replicated over network at 5Hz. Walking / running pose
> visible end-to-end (peer A moves → peer B's ghost-of-A mirrors). Hands
> (fingers), helpers, AnimObjects pending Step 2.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Python Server (asyncio UDP)                   │
│  authoritative state · identity-keyed (base, cell) · validator    │
│  reliable channel (SACK + retransmit) · JSON snapshot persistence │
└─────────────────────────┬────────────────────────────────────────┘
                          │ binary protocol v4 (44B POS_BCAST)
            ┌─────────────┼─────────────┐
            │             │             │
       ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
       │ Client A │  │ Client B │  │   ...    │
       │  FO4 +   │  │  FO4 +   │  │  Up to   │
       │ dxgi.dll │  │ dxgi.dll │  │  10      │
       │  proxy   │  │  proxy   │  │  peers   │
       └──────────┘  └──────────┘  └──────────┘
       Each client:
       - 1 LOCAL player (vanilla FO4 controls, full anim)
       - N GHOST bodies (1 per remote peer, native scene graph)
```

## Repository layout

| Path | Purpose |
|------|---------|
| `fw_native/` | C++ native client (dxgi.dll proxy + MinHook + scene graph injection) |
| `fw_native/src/native/` | Strada B native injection (NIF loader, scene graph, ghost body) |
| `fw_native/src/hooks/` | MinHook detours (kill, container, pos poll, main_menu, worldstate) |
| `fw_native/src/net/` | C++ port of Python protocol (byte-identical via static_assert) |
| `fw_native/docs/` | Internal docs + tools list |
| `launcher/` | Python orchestrator (FO4 INI mgmt, side A/B startup, fw_config.ini) |
| `fw_launcher/` | C++ launcher wrapper (`FoM.exe`) |
| `net/` | Python server (asyncio UDP, validator, persistence, snapshot v3) |
| `frida/` | Frida JS scripts + Python attach helpers (RE / live tracing) |
| `re/` | Reverse-engineering dossiers + IDA Python scripts |

## Major milestones

| Milestone | Status |
|-----------|--------|
| **B0** Networking + native client port | ✅ done — 196+ pytest, byte-identical protocol |
| **B1** Container pre-mutation block | ✅ done — concurrent TAKE dup race closed |
| **B2** Launcher (`FoM.exe`) | ✅ done — drop-in for `start_A.bat`/`start_B.bat` |
| **B3** Auto-load save (delayed LoadGame via WndProc subclass) | ✅ done |
| **B4** Worldstate sync (GlobalVar + QuestStage) | 🟡 GlobalVar shipped; QuestStage RE done, apply pending wire |
| **M5–M6** Strada B ghost body (NIF native injection + textures) | ✅ done — body + head + hands textured, scene graph attached |
| **M7** Ghost animations (local memcpy from PC tree) | ✅ superseded by M8P3 |
| **M8P1** RE NiAVObject::Load3D | ✅ done — `sub_1417B3E90` public API |
| **M8P2** RE BSGeometry skin instance offsets | ✅ done — `+0x140` confirmed |
| **M8P3** Skin pipeline RE + per-bone pose replication | ✅ M8P3.18 — see changelog |
| **B5** D3D11 custom render | 🗿 not needed — Strada B native injection replaced |
| **B6** Sync expansion (cell cleared, workshop, faction rep) | ⏳ |
| **B7** Rust server port | ⏳ |

## Major RE achievements

- **Single-instance bypass** (1-byte binary patch @ RVA `0xC2FB62`) — runs 2 FO4
  instances simultaneously on same machine. Killer of Fallout Together + F4MP.
- **`apply_materials` walker discovery** (`sub_140255BA0`) — the missing step
  for `.bgsm` material resolution after standalone NIF load. Documented in
  `re/stradaB_pink_body_solution.txt`.
- **NIF loader public API** (`sub_1417B3E90`) — bypasses the broken cache
  wrapper that hangs with naive args.
- **Scene graph integration** — depth occlusion, lighting, shadows free via
  `BSFadeNode` attachment to `ShadowSceneNode`.
- **BSSkin::Instance layout fully RE'd** — `bones_fb` at `+0x10`,
  `bones_pri` at `+0x28`, `boneData` at `+0x40`, `skel_root` at `+0x48`.
  Critical empirical finding via TTD: `bones_pri[i]` is NOT a `NiAVObject**`
  but a **direct pointer-to-matrix cache** (= `bones_fb[i]+0x70`). The GPU
  reads matrices via SRV indirection through this cache. Documented in
  `re/M8P3_skin_instance_dossier.txt`.

## Changelog

### M8P3 — Pose replication over network (2026-04-26)

First end-to-end animation replication: peer A's body movement triggers
peer B's ghost-of-A to mirror in real time.

**Pipeline (per frame, 5Hz network rate):**
1. Sender (peer A) reads local PC's joint `m_kLocal` rotations.
2. 3x3 → quaternion → packed in `POSE_STATE` payload (~1KB).
3. Server fan-outs to other peers as `POSE_BROADCAST`.
4. Receiver (peer B) writes received quaternions into ghost skel
   joint `m_kLocal`.
5. Engine `UpdateDownwardPass` propagates rotations through the
   skeleton hierarchy → skin anchors inherit → GPU draws animated body.

**RE deliverables:**
- `re/M8P3_skin_instance_dossier.txt` — full BSSkin::Instance layout
- `re/M8P3_skin_walker_dossier.txt` — `NiAVObject::UpdateWorldData` chain
- `re/M8P3_skin_update_pass_AGENT_*.txt` — dual-agent investigation of
  the GPU upload pipeline (concluded: pull-based via SRV, no flat buffer)

**Code deliverables:**
- `fw_native/src/native/skin_rebind.{cpp,h}` — bones_fb swap +
  bones_pri re-cache (critical for GPU to read swapped matrices)
- `fw_native/src/native/scene_inject.cpp` — `on_bone_tick_message`
  (sender, 20Hz tick / 5Hz broadcast) + `on_pose_apply_message`
  (receiver, main-thread)
- `fw_native/src/net/protocol.h` + `net/protocol.py` —
  `MessageType::POSE_STATE` / `POSE_BROADCAST` (variable-length
  quaternion payloads, max 80 bones × 16B)
- `net/server/main.py` — `_handle_pose_state` fan-out

**Bugs squashed during M8P3 (in chronological order — for posterity):**
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

**Diagnostic tools added:**
- TTD (Time Travel Debugging via WinDbg Preview) — recorded a 10GB
  trace of FO4 to confirm `bones_pri[i]` layout via memory inspection.
  Setup at `ttd_attach.bat` (run as admin while game is alive).
- 7 Frida scripts for runtime memory diff, pose probe, skin buffer
  hunt, etc. Under `frida/14_*.js`–`20_*.js`.

**Open work (next milestones):**
- Step 4: replicate fingers (30 bones missing in current canonical
  because they live deeper in skel.nif than the local PC walk reaches).
- Step 5: bump network rate from 5Hz → 20Hz; add receiver-side
  interpolation for visual smoothness.
- Step 6: multi-peer ghost cache (registry per peer_id).

## How to build (developer notes)

Required:
- Visual Studio Build Tools 2022 (`E:\BuildTools\` assumed by `build.bat`)
- CMake ≥ 3.25
- Ninja (bundled with VS Build Tools)
- Python 3.12 (for launcher + server)
- Frida 17+ (for live RE traces)

Build native DLL:
```
cd fw_native
build.bat       # produces build/dxgi.dll
deploy.bat      # copies to Side A + Side B game dirs
```

Run multiplayer (after deploy):
```
launcher/start_A.bat
launcher/start_B.bat
```

## Reverse-engineering target

Fallout4.exe **1.11.191 next-gen** (December 2025).
ImageBase 0x140000000 (no ASLR in practice).
IDA Pro 9.3 used for static decomp; cached DB at `re/Fallout4.exe.i64` (NOT
committed — proprietary format + size). Regenerate locally from your own
copy of Fallout4.exe.

## License

Personal mod project. Not distributed. Requires owned copy of Fallout 4.
No Bethesda IP committed to this repo (no game binaries, no BA2 contents,
no decomp dumps — only our own analysis dossiers).

## Notes

- Brainstorm + design doc: `fallout_multiplayer_project_brainstorm.md`
- Solution dossiers: `re/stradaB_*.txt` (production-grade RE writeups)
- Tools list: `fw_native/docs/tools-da-usare.md`
