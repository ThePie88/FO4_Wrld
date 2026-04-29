
This project uses unconventional approaches in several critical areas (scene graph injection, skin buffer manipulation, binary patches). External contributions could inadvertently break invariants [...]

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
>
> **B6 wedge 1 shipped** — **door open/close sync** across peers:
> peer A presses E on a door, peer B sees the same door swing open in real
> time (and vice versa). First true world-state replication beyond the
> player avatar + inventory. Sender hooks engine `Activate worker`
> (`sub_140514180`); receiver re-invokes the same function on its local
> REFR via main-thread queue + `ApplyingRemoteGuard` feedback-loop guard.
> Toggle semantics — both clients converge from the same `world_base`
> save without server-side state tracking.
>
> **M9 wedge 1+2 PoC shipped** — **clothing sync between peers** [video coming
> soon]. Peer A equips Vault Suit / Raider outfit → Peer B sees the same
> clothing on A's ghost body, animated with A's pose. Sender hooks
> `ActorEquipManager::EquipObject/UnequipObject`, receiver walks
> `TESObjectARMO → TESObjectARMA → TESModel` to resolve the 3rd-person NIF
> path, loads the NIF, attaches it to the ghost, and re-binds the armor's
> skin to the shared skel.nif so animation propagates. Path scoring picks
> male 3rd-person variant over 1st-person/female fallbacks. Per-peer
> pending queue handles the boot-time race when ghost spawns after the
> peer's force-equip-cycle. Limitations: armor pieces ON TOP of outfits
> z-fight (no biped slot masking), some NIFs have bind-pose mismatch
> clipping (Vault Suit), Object Modifications (BGSMod) like shoulder
> pads/weapon mods not covered. See [CHANGELOG.md](CHANGELOG.md).

---

## Demo

[![FalloutWorld demo on YouTube](https://img.youtube.com/vi/Qs3dNzXnnko/maxresdefault.jpg)](https://www.youtube.com/watch?v=Qs3dNzXnnko)

▶ **[Watch the 90s demo on YouTube](https://www.youtube.com/watch?v=Qs3dNzXnnko)**

2 clients side-by-side. Movement + full-body animation sync, ground-pickup
replication (peer A picks up an item → peer B sees it disappear from the
world), and live container UI update across peers (peer A deposits items
into a nightstand → peer B's open ContainerMenu reflects the new entries
in real time).

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Python Server (asyncio UDP)                        │
│  authoritative state · identity-keyed (base, cell) · validator         │
│  reliable channel (SACK + retransmit) · JSON snapshot persistence      │
└─────────────────────────┬──────────────────────────────────────────────┘
                          │ binary protocol v5 (44B POS_BCAST · 36B DOOR_BCAST)
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
| **B6** World-state sync expansion *(composite — 12 wedges, multi-month epic)* | 🟡 1/12 done |
| ↳ **B6.1** Door open/close sync | ✅ done — `sub_140514180` Activate worker hook + dual-agent RE convergence, [30s demo](https://youtu.be/T8wLZmCqjxw), see [CHANGELOG.md](CHANGELOG.md) |
| **M9** Equipment sync between peers *(clothing + armor visual replication)* | 🟡 PoC shipped (wedges 1+2) |
| ↳ **M9.w1** Equip event detection + broadcast (sender hook OBSERVE-only) | ✅ done — `ActorEquipManager::EquipObject/UnequipObject` detour, EQUIP_OP/EQUIP_BCAST opcodes (protocol v6), [video coming soon] |
| ↳ **M9.w2** Receiver-side NIF resolution + ghost attach + animation | ✅ PoC done — TESObjectARMO struct walk, score-based male 3rd-person path selection, skin-rebind to ghost skel for animation propagation |
| ↳ **M9.w3** Biped slot masking (hide ghost body parts under armor) | ⏳ — fixes z-fight when armor pieces equipped over outfits (e.g. metal arm over vault suit) |
| ↳ **M9.w4** Object Modification (BGSMod) sync — shoulder pads, weapon mods, paint variants | ⏳ — not covered by ActorEquipManager hook; separate workshop-attachment path RE needed |
| ↳ **M9.w5** Peer rejoin equipment-state push | ⏳ — A-first-B-later case: A's force-equip-cycle broadcast lost when B was offline; server-side cache or PEER_JOIN trigger to re-broadcast |
| ↳ **M9.w6** Material swap variants (rusty/clean raider, paint jobs) | ⏳ — RE BSMaterialDB swap path used by `nsInventory3DManager::*MaterialSwap*Task` |
| ↳ **B6.2** Lights toggle sync (lamps, lanterns, generators) | ⏳ — same Activate worker pattern as doors, formType filter on `0x20` LIGH |
| ↳ **B6.3** Locks state sync (lockpicked → unlocked cross-client) | ⏳ — REFR lock extra-data + `OnLockedClick` callback hook |
| ↳ **B6.4** Terminals state sync (hacked / unlocked) | ⏳ — TerminalMenu activation event + persisted "hacked" flag |
| ↳ **B6.5** NPC actor pos + pose sync | ⏳ — extend POSE_BROADCAST to remote actors with authority-per-NPC model. The big one — turns "co-op chat in same world" into "actual multiplayer game" |
| ↳ **B6.6** NPC combat target + aggro sync | ⏳ — RE `CombatController::SetTarget`, broadcast NPC→target so observers see "raider shoots peer A" not "raider shoots air" |
| ↳ **B6.7** NPC dialogue state + faction joined | ⏳ — quest-stage adjacent; brainstorm §3.2 says 10 players = 1 entity, simplifies state |
| ↳ **B6.8** Companion state (recruited / position) | ⏳ — companions are NPCs with extra ownership flag |
| ↳ **B6.9** Cell-cleared status (no respawn after group clear) | ⏳ — `cleared` flag in cell extra-data, persisted server-side |
| ↳ **B6.10** One-shot loot pickups (bobbleheads, magazines, holotapes, skill books) | ⏳ — single-pickup persistence, partially covered by container `kill` events |
| ↳ **B6.11** Time of day + weather sync | ⏳ — GlobalVar `GameHour` + Sky weather state |
| ↳ **B6.12** Workshop / settlement build state sync | ⏳ — major epic; build/scrap/move workshop refs + furniture |
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
