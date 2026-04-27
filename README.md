
This project uses unconventional approaches in several critical areas (scene graph injection, skin buffer manipulation, binary patches). External contributions could inadvertently break invariants that aren't documented at the line level. The license reflects this — the source is published for transparency and review, not for collaborative development at this stage. May reconsider after the architecture stabilizes and a CONTRIBUTING.md exists.

# FO4_Wrld

Fallout 4 1.11.191 next-gen — multiplayer mod (FoM-lite framework).
Solo-dev, evening project. Target: 10-player persistent-world survival MMO.

> **Status (2026-04-27):** ghost player body **animates** in real time —
> ~31 joints (full body chain incl. head + hands) replicated over network
> at 20Hz. Walking / running / idle / sneak / turn / jump pose visible
> end-to-end (peer A moves → peer B's ghost-of-A mirrors). Body+head+hands
> all skin-swapped to shared skel hierarchy. Fingers stay at natural
> rest pose (no joints in render-scene tree → sentinel-skip avoids
> T-pose contagion). 1P sender → V/T-pose stub on ghost (deferred).

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
| **M8P3** Skin pipeline RE + per-bone pose replication | ✅ M8P3.23 — body+head+hands animated, see [CHANGELOG.md](CHANGELOG.md) |
| **B5** D3D11 custom render | 🗿 not needed — Strada B native injection replaced |
| **B6** Sync expansion (cell cleared, workshop, faction rep) | ⏳ |
| **B7** Rust server port | ⏳ |

## Major RE achievements

- **Single-instance bypass** (1-byte binary patch @ RVA `0xC2FB62`) — runs 2 FO4
  instances simultaneously on the same machine. Required for local
  multi-client testing without spinning up a second physical PC. The
  patch flips a NOP-equivalent on the singleton-check branch.
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

Latest 3 patches summarized below. **Full version history in
[CHANGELOG.md](CHANGELOG.md).**

### M8P3.23 (2026-04-27) — head + hands animated

- Apply skin swap to head NIF (`BaseMaleHead.nif`) + hands NIF
  (`MaleHands.nif`), not only body. All three meshes now share the
  same skel joint hierarchy → engine UpdateDownwardPass propagates
  joint rotations uniformly → head bobs with neck, hands curl with
  forearm chain.
- Sentinel quaternion (qw=2.0) for joints absent from local PC's
  render-scene tree (fingers, AnimObjects, helpers). Receiver detects
  and skips → engine keeps natural bind pose instead of T-pose.
- Verified: walk / run / idle / sneak / turn / jump replicate body-wide.

### M8P3.20+22 (2026-04-27) — 20Hz rate + 1P limitation documented

- Network rate 5Hz → 20Hz (every bone-tick). Smoothness confirmed.
- Dual-path lookup `Player+0xF0+0x08` / `Player+0xB78` for 1P/3P
  agnosticism (path B currently always null but future-proofed).
- Two failed heuristics for 1P sender V/T-pose detection (Pelvis canary,
  rotation hash). Proper fix needs PlayerCamera singleton RE — deferred.

### M8P3 (2026-04-26) — pose replication network milestone

- First end-to-end body animation replication. ~31 of ~70 skel joints
  driven over network. Sender reads local PC `m_kLocal`, packs
  quaternions, broadcasts. Receiver writes to ghost skel and lets
  engine UpdateDownwardPass propagate.
- 9 chained bugs squashed (see CHANGELOG.md for full list).
- New modules: `skin_rebind.{cpp,h}`, POSE_STATE/POSE_BROADCAST
  protocol, server fan-out, TTD diagnostic infra.

## Why this exists

I've been waiting ~10 years for someone to ship Fallout 4 multiplayer.
Existing efforts I'm aware of:

- **Fallout Together** — abandoned 2020, never reached stable bone
  replication.
- **F4MP** — paused / no animation system in the public state I last saw.
- **Skyrim Together** (predecessor for SkyrimSE) — got working but with
  desync issues that informed several of the architecture choices here.

This project takes a different architectural bet: **native scene-graph
injection** (BSFadeNode → ShadowSceneNode) plus per-bone joint
replication via the engine's own `UpdateDownwardPass` propagation,
instead of reimplementing skinning from scratch. We let the engine do
the heavy lifting (skin upload, GPU constant buffers, lighting, shadows
when fixed) and feed it joint matrices via memory writes that match
exactly what its anim graph would produce.

Whether this scales cleanly to 10 peers is an open question — current
testing is 2-peer. The RE work for the 1.11.191 next-gen build (skin
pipeline, pointer-cache layout, NIF loader API) is the contribution
that should be most reusable for anyone else attempting the same thing.

## Known limitations

- **Fingers don't articulate** — finger joints exist only in the
  underlying havok skeleton (`.hkx`), not in the rendered scene-graph
  tree we walk. Receiver gets a sentinel quat for them and falls back
  to bind pose (slightly curled fingers, not extended T-pose).
- **1st-person sender → ghost adopts V/T-pose stub** — when the sender
  is in 1P view, the engine animates the alt-tree body to a simplified
  stub pose since the body is invisible to the local camera. Two
  detection heuristics were tried (Pelvis canary, rotation hash); both
  failed because the alt-tree retains all named bones and rotations
  jitter every tick. Proper fix needs `PlayerCamera` singleton RE.
  Workaround: keep the observed peer in 3rd-person.
- **Ghost body has no shadow** — separate render flag investigation,
  deferred.
- **Tested with 2 peers** — multi-peer ghost cache (peer-id keyed
  registry) not yet implemented; 10-peer scaling is theoretical.
- **Network rate-limited to 20Hz** — works smoothly on LAN, untested
  over real-world internet routes; receiver-side interpolation between
  POSE_BROADCAST frames is open work.

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

- RE dossiers (English, public): `re/M8P{1,2,3}_*.txt`,
  `re/M8_strategic_decision.txt` — full reverse-engineering writeups
  for the player-creation pipeline (NIF loader API, BSGeometry skin
  instance layout, BSSkin pipeline + bones_pri pointer cache).
- Full version history: [CHANGELOG.md](CHANGELOG.md)
