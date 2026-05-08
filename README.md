
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
> peer's force-equip-cycle. Combat / outfit z-fight closed by M9.w3 body
> cull (v0.4.1, 2026-05-03). Vault Suit equip-cycle SEH crash + post-cycle
> body invisible / ghost armor disappears / T-pose closed by M9 v0.4.2
> (2026-05-04) via path-routed deep clone of the VS NIF subtree.
>
> **M9 v0.5.0 shipped (2026-05-07)** — **modded weapon visuals replicated
> on the ghost** for pistols. As far as I can tell this is the first time
> it has been done in the FO4 multiplayer modding scene: peer A equips a
> 10mm with reflex sight, suppressor, heavy receiver, and extended mag,
> and peer B sees the exact same configuration in A's ghost hand,
> animated with A's pose. The receiver runs the engine's own per-OMOD
> attach helper (`sub_140434DA0`), which internally matches mod sub-NIFs
> to the base via the BSConnectPoint extra-data system baked into the
> NIF files. Sender fires a tiny re-equip cycle 50 ms after each user
> equip to work around a first-equip render lag I couldn't fix on the
> receiver alone.
> [Demo (clothes + armor + modded firearms)](https://youtu.be/r34D4IL7wAk).
> See [CHANGELOG.md](CHANGELOG.md).
>
> **M9 v0.5.1 — M9 closed (2026-05-08).** Full pass on the weapon
> roster: pistols (10mm, handmade), sniper rifle, assault rifle, hunting
> rifle, combat shotgun, combat rifle, minigun, Fat Man, laser, plasma —
> all render correctly on the ghost with mods applied. The "rifles
> render invisible" caveat in v0.5.0 was a testing gap, not a code
> issue; the v0.5.0 BSConnectPoint pipeline already covered everything.
> No code changes in v0.5.1. M9 is closed, 5/5 wedges done across all
> firearms.
>
> **B6.1 v0.5.2 — Cell-aware ghost transitions (2026-05-08).** When a
> peer crosses a cell boundary (entering an interior, fast-travel,
> worldspace switch), the ghost on the remote client now stays synced.
> Co-op inside the same interior works too — both peers see each other's
> ghost in the same room. Wire proto v11 adds `cell_id` to the pos
> payloads; the server validator now accepts cross-cell teleports as a
> baseline reset instead of rejecting them as 2.4 M u/s "cheat" speed
> spikes. See [CHANGELOG.md](CHANGELOG.md).
>
> **B6.3 v0.5.3 — Lock state sync (2026-05-08).** When peer A picklocks
> a door, safe, weapon locker, or terminal-linked container, peer B's
> matching REFR unlocks too — no minigame prompt on B's side. Wire
> proto v12 adds `LOCK_OP` / `LOCK_BCAST`; sender hooks `ForceUnlock`
> (`sub_140563320`) + `ForceLock` (`sub_140563360`); receiver applies
> via the Papyrus `ObjectReference.Lock` binding (`sub_141158640`)
> with `ai_notify=0` to skip the minigame and key consumption. Server
> persists per-(base, cell) lock state and replays it to peers joining
> mid-session. See [CHANGELOG.md](CHANGELOG.md).

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
| **B6** World-state sync expansion *(composite — 13 wedges, multi-month epic)* | 🟡 3/13 done |
| ↳ **B6.0** Door open/close sync | ✅ done — `sub_140514180` Activate worker hook + dual-agent RE convergence, [30s demo](https://youtu.be/T8wLZmCqjxw), see [CHANGELOG.md](CHANGELOG.md) |
| ↳ **B6.1** Cell-aware ghost transitions (interior / fast-travel / worldspace switch) | ✅ done (v0.5.2, 2026-05-08) — wire proto v11 ships `cell_id` in pos payloads; server validator accepts cross-cell teleport as baseline reset instead of rejecting it at the 2500 u/s speed gate. Receiver is a plain coord-bind: cross-cell distance (~120k units) puts the ghost outside the local frustum naturally; same-interior co-op puts both peers in the same coord frame. |
| **M9** Equipment sync between peers *(clothing + armor + weapon visual replication)* | ✅ done (v0.5.1, 2026-05-08) — 5/5 wedges across **all firearm families**: pistols (10mm, handmade), sniper rifle, assault rifle, hunting rifle, combat shotgun, combat rifle, minigun, Fat Man, laser, plasma — all visible with mods on the remote ghost via engine BSConnectPoint pairing. Plus clothing + body cull + OMOD-driven ARMA tier + Vault Suit cycle stable. |
| ↳ **M9.w1** Equip event detection + broadcast (sender hook OBSERVE-only) | ✅ done — `ActorEquipManager::EquipObject/UnequipObject` detour, EQUIP_OP/EQUIP_BCAST opcodes (protocol v6), [video coming soon] |
| ↳ **M9.w2** Receiver-side NIF resolution + ghost attach + animation | ✅ done — TESObjectARMO struct walk, gender-aware path scoring (M3rd preferred over F/1stP), OMOD-driven priority extracted from `BGSObjectInstance.extra+0x56` and shipped via wire (proto v10) so ghost picks the correct ARMA tier (Lite/Mid/Heavy). Engine helper `sub_1404626A0` PrioritySelect algorithm reimplemented receiver-side. TTD-confirmed 2026-05-03. |
| ↳ **M9.w3** Biped slot masking (hide ghost body parts under armor) | ✅ done — `TESObjectARMO+0x1E8` bipedSlots bitmask, slot-3 BODY mask flips `NIAV_FLAG_APP_CULLED` on ghost's `BaseMaleBody:0` BSSubIndexTriShape (cached at body inject via vtable RVA `0x2697D40` walker). Body hidden under Vault Suit / Power Armor / Synth Armor — no more z-fight. |
| ↳ **M9.w4** Object Modification (BGSMod) sync — shoulder pads, weapon mods, paint variants | ✅ done (v0.5.1, 2026-05-08) — engine OMOD attacher `sub_140434DA0` + BSConnectPoint pairing, sender-side 50ms auto re-equip cycle for off-by-one render lag. Every firearm family verified with mods (pistols, sniper, assault, hunting, combat shotgun, combat rifle, minigun, Fat Man, laser, plasma). Receivers, mags, scopes, suppressors, grips, barrels — all replicated. [Demo](https://youtu.be/r34D4IL7wAk). |
| ↳ **M9.w5** Peer rejoin equipment-state push | ✅ done in v0.3.1 — PEER_JOIN trigger re-arms equip cycle (DONE→ARMED state transition), 1500ms delay, current outfit re-broadcast to newly-joined peer |
| ↳ **B6.2** Lights toggle sync (lamps, lanterns, generators) | ⏳ — same Activate worker pattern as doors, formType filter on `0x20` LIGH |
| ↳ **B6.3** Locks state sync (lockpicked → unlocked cross-client) | ✅ done (v0.5.3, 2026-05-08) — sender hooks `ForceUnlock` (`sub_140563320`) + `ForceLock` (`sub_140563360`); receiver applies via Papyrus `ObjectReference.Lock` binding (`sub_141158640`) with `ai_notify=0` to skip minigame + key consumption. Wire proto v12 ships `(form_id, base_id, cell_id, locked, ts)`. Covers doors, safes, weapon lockers, terminal-linked containers. Server persists per-(base, cell) state + replays on peer-join bootstrap. |
| ↳ **B6.4** Terminals state sync (hacked / unlocked) | ⏳ — TerminalMenu activation event + persisted "hacked" flag |
| ↳ **B6.5** NPC actor pos + pose sync | ⏳ — extend POSE_BROADCAST to remote actors with authority-per-NPC model. The big one — turns "co-op chat in same world" into "actual multiplayer game" |
| ↳ **B6.6** NPC combat target + aggro sync | ⏳ — RE `CombatController::SetTarget`, broadcast NPC→target so observers see "raider shoots peer A" not "raider shoots air" |
| ↳ **B6.7** NPC dialogue state + faction joined | ⏳ — quest-stage adjacent; brainstorm §3.2 says 10 players = 1 entity, simplifies state |
| ↳ **B6.8** Companion state (recruited / position) | ⏳ — companions are NPCs with extra ownership flag |
| ↳ **B6.9** Cell-cleared status (no respawn after group clear) | ⏳ — `cleared` flag in cell extra-data, persisted server-side |
| ↳ **B6.10** One-shot loot pickups (bobbleheads, magazines, holotapes, skill books) | ⏳ — single-pickup persistence, partially covered by container `kill` events |
| ↳ **B6.11** Time of day + weather sync | ⏳ — GlobalVar `GameHour` + Sky weather state |
| ↳ **B6.12** Workshop / settlement build state sync | ⏳ — major epic; build/scrap/move workshop refs + furniture |
| ↳ **B6.13** Power Armor frame + worn-state sync | ⏳ — chassis is a REFR with its own state (location, per-piece HP, fusion core); player-in-PA = chassis attached to player. Both visibilities require sync. Re-scoped from M9 to B6 (2026-05-04) — fundamentally world-state, not an equip event |
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

### B6.3 v0.5.3 (2026-05-08) — lock state sync — STABLE

- **Lock state now syncs across peers.** Picklock a Sanctuary safe on
  client A → client B's same safe is unlocked too, no minigame prompt
  on B's side. Covers doors, safes, weapon lockers, and terminal-linked
  containers. Server persists per-(base, cell) state across restarts;
  peers joining mid-session catch up via bootstrap `LOCK_BCAST` frames.
- **Sender** hooks the engine's two canonical mutators —
  `ForceUnlock` (`sub_140563320`) and `ForceLock` (`sub_140563360`).
  Coverage: lockpick minigame, terminal hack, key unlock, AI lock/unlock
  package, perk auto-unlock, savefile load. Detour reads post-state
  from `LockData` (flag bit 0 at `+0x10`), broadcasts
  `(form_id, base_id, cell_id, locked, ts)` as reliable `LOCK_OP`.
  `tls_applying_remote` guards the receiver-side recursion.
- **Receiver** applies via Papyrus `ObjectReference.Lock`/`Unlock`
  binding (`sub_141158640`) with `ai_notify=0` — flips ExtraLock,
  clears partial-pick state, refreshes visuals, and skips the
  minigame, key consumption, and AI events. Allocates ExtraLock if
  the REFR doesn't have one yet.
- **Wire proto v12** adds `LOCK_OP` (`0x0260`) + `LOCK_BCAST`
  (`0x0261`). `LockOpPayload` = 21 B; `LockBroadcastPayload` = 37 B.
  Server snapshot v4 adds a `locks` JSON section; v3 snapshots load
  fine (empty `lock_state`).
- **Bug fixed mid-session.** First test silently dropped
  `LOCK_BCAST` because `LockWorldState` wasn't imported in
  `server/main.py` — `_handle_lock_op` raised `NameError` inside the
  outer try/except, logged but didn't broadcast. One-line import fix;
  7/7 server integration tests pass. Tag
  `v0.5.3-b6.3-lock-state-sync`.

### B6.1 v0.5.2 (2026-05-08) — cell-aware ghost transitions — STABLE

- **Cell transitions now work across the network.** Peer enters an
  interior or fast-travels, the ghost on the remote client stays in
  sync. Both peers in the same interior see each other.
- **Root cause was server-side, not render-side.** The pos validator
  caps speed at 2500 u/s; a cross-cell teleport is ~120k units in
  50 ms ≈ 2.4 M u/s, so every POS_STATE got rejected as cheat. The
  ghost stayed pinned at the last accepted exterior pos — exactly at
  the door I just walked through.
- **Fix.** Wire proto v11 adds `cell_id` (u32) to `PosState` /
  `PosBroadcast`. Server validator now accepts `incoming.cell_id !=
  session.last_pos.cell_id` as a baseline reset (legit cell change,
  not cheat). Pre-v11 senders (`cell_id == 0`) keep the standard speed
  gate unchanged. Receiver-side rendering stays as a plain coord-bind:
  cross-cell distance pushes the ghost outside the local frustum
  naturally, same-interior co-op puts both peers in the same coord
  frame so the ghost is positioned correctly relative to whoever is
  watching.
- **What I tried first.** Four receiver-side hide attempts —
  `NIAV_FLAG_APP_CULLED` on body BSFadeNode root, `local.translate =
  (1e7, 1e7, 1e7)`, detach body from World SceneGraph, recursive
  `APP_CULLED` on every leaf — all failed because the rendered
  geometry comes through the skin pipeline independently of scene
  graph attachment and BSFadeNodeCuller logic. The diagnostic that
  mattered was `pos_bcast` counter stuck in the log while `pose-rx`
  ticked normally; the server was the only piece filtering pos
  differently. Lesson: counters before code. Tag
  `v0.5.2-b6.1-cell-aware-ghost`.

### M9 v0.5.1 (2026-05-08) — M9 closed: every weapon family confirmed — STABLE

- **M9 is closed.** Full pass on the weapon roster: pistols (10mm,
  handmade), sniper rifle, assault rifle, hunting rifle, combat
  shotgun, combat rifle, minigun, Fat Man, laser, plasma — all
  render correctly on the ghost with mods applied (receivers, mags,
  scopes, suppressors, grips, barrels). Same v0.5.0 BSConnectPoint
  pipeline; no code changes.
- **The "rifles render invisible" caveat in v0.5.0 was a testing gap,
  not a real bug.** I had only validated pistols + handmade before
  shipping; deeper coverage during the demo recording, then a roster
  pass at the start of this session, confirmed the v0.5.0 pipeline
  already covered every family.
- **Next:** B6 wedges (lights, locks, terminals — same Activate-worker
  pattern as B6.1 doors) and eventually B6.5 NPC pose sync — the real
  "co-op chat → playable multiplayer" turning point. Tag
  `v0.5.1-m9-closed`.

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
instead of reimplementing skinning from scratch. I let the engine do
the heavy lifting (skin upload, GPU constant buffers, lighting, shadows
when fixed) and feed it joint matrices via memory writes that match
what its anim graph would have produced.

Whether this scales cleanly to 10 peers is an open question — current
testing is 2-peer. The RE work for the 1.11.191 next-gen build (skin
pipeline, pointer-cache layout, NIF loader API) is the contribution
that should be most reusable for anyone else attempting the same thing.

## Known limitations

- **Fingers don't articulate** — finger joints exist only in the
  underlying havok skeleton (`.hkx`), not in the rendered scene-graph
  tree the receiver walks. Sentinel quat for them, falling back to
  bind pose (slightly curled fingers, not extended T-pose).
- **1st-person sender → ghost adopts V/T-pose stub** — when the sender
  is in 1P view, the engine animates the alt-tree body to a simplified
  stub pose since the body is invisible to the local camera. Two
  detection heuristics were tried (Pelvis canary, rotation hash); both
  failed because the alt-tree retains all named bones and rotations
  jitter every tick. Proper fix needs `PlayerCamera` singleton RE.
  Workaround: keep the observed peer in 3rd-person.
- **Ghost body has no shadow** — separate render flag investigation,
  deferred.
- **PipBoy animation is broken on the ghost** — when a peer opens their
  PipBoy, the engine plays a 1st-person camera-relative arm-raise anim
  on the local player. The ghost on observers' screens has no equivalent
  3rd-person animation set up (vanilla FO4 doesn't really animate a
  remote player's PipBoy because there are no remote players in
  vanilla), so the ghost's arms freeze / contort during the peer's
  PipBoy session. Cosmetic, doesn't crash. Workaround / future wedge:
  detect peer-PipBoy state and either despawn ghost or play a static
  "looking at PipBoy" placeholder pose.
- **Tested with 2 peers** — multi-peer ghost cache (peer-id keyed
  registry) not yet implemented; 10-peer scaling is theoretical.
- **Network rate-limited to 20Hz** — works smoothly on LAN, untested
  over real-world internet routes; receiver-side interpolation between
  POSE_BROADCAST frames is open work.
- **Sender sees a ~50 ms weapon flicker on equip** — visible side
  effect of the v0.5.0 auto re-equip cycle: 50 ms after the user's
  EquipObject the sender fires UnequipObject + EquipObject for the
  same form to make the receiver render correctly. The user's own
  weapon briefly disappears and reappears in their hand. Cosmetic; no
  gameplay impact (animation graph and damage state aren't affected).
- **Crash on TAKE-weapon from a B6.3-synced container** — taking a
  weapon out of a lockable container that was synced via B6.3 (e.g.
  one peer deposited it into a Sanctuary safe) freezes the taker's
  main thread for ~7 s in the engine's auto-equip pipeline, then the
  FO4 process dies silently. Lock and container sync apply correctly
  up to that point; the issue surfaces in the receiver's M9
  `EQUIP_BCAST` resolver, which reads a corrupted addon array (count
  ≈ 2.3 billion garbage, base pointer null) for the auto-equipped
  weapon form. Likely a pre-existing M9 receiver fragility that the
  heavier B6.3 sync stress exposes — not introduced by lock sync
  itself. Tracked separately. Workaround for now: deposit / take
  non-weapon items only from synced containers.
- **Container UI doesn't refresh on the observer when peers picklock
  the same container** — engine quirk in the ContainerMenu redraw
  path; closing and reopening the container forces the refresh.
  Cosmetic, no state impact.

## Reverse-engineering target

Fallout4.exe **1.11.191 next-gen** (December 2025).
ImageBase 0x140000000 (no ASLR in practice).
IDA Pro 9.3 used for static decomp; cached DB at `re/Fallout4.exe.i64` (NOT
committed — proprietary format + size). Regenerate locally from your own
copy of Fallout4.exe.

## License

Personal mod project. Not distributed. Requires owned copy of Fallout 4.
No Bethesda IP committed to this repo (no game binaries, no BA2 contents,
no decomp dumps — only my own analysis dossiers).

## Notes

- RE dossiers (English, public): `re/M8P{1,2,3}_*.txt`,
  `re/M8_strategic_decision.txt` — full reverse-engineering writeups
  for the player-creation pipeline (NIF loader API, BSGeometry skin
  instance layout, BSSkin pipeline + bones_pri pointer cache).
- Full version history: [CHANGELOG.md](CHANGELOG.md)
