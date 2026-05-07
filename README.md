
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
> receiver alone. Rifles next session to close M9 fully.
> [Demo (clothes + armor + modded firearms)](https://youtu.be/r34D4IL7wAk).
> See [CHANGELOG.md](CHANGELOG.md).

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
| **B6** World-state sync expansion *(composite — 13 wedges, multi-month epic)* | 🟡 1/13 done |
| ↳ **B6.1** Door open/close sync | ✅ done — `sub_140514180` Activate worker hook + dual-agent RE convergence, [30s demo](https://youtu.be/T8wLZmCqjxw), see [CHANGELOG.md](CHANGELOG.md) |
| **M9** Equipment sync between peers *(clothing + armor + weapon visual replication)* | 🟢 5/5 wedges done for pistols (v0.5.0): clothing + body cull + OMOD-driven ARMA tier + Vault Suit cycle stable + **modded firearm visualization** end-to-end via engine BSConnectPoint pairing. Rifles (sniper/assault/hunting) next session to fully close M9. |
| ↳ **M9.w1** Equip event detection + broadcast (sender hook OBSERVE-only) | ✅ done — `ActorEquipManager::EquipObject/UnequipObject` detour, EQUIP_OP/EQUIP_BCAST opcodes (protocol v6), [video coming soon] |
| ↳ **M9.w2** Receiver-side NIF resolution + ghost attach + animation | ✅ done — TESObjectARMO struct walk, gender-aware path scoring (M3rd preferred over F/1stP), OMOD-driven priority extracted from `BGSObjectInstance.extra+0x56` and shipped via wire (proto v10) so ghost picks the correct ARMA tier (Lite/Mid/Heavy). Engine helper `sub_1404626A0` PrioritySelect algorithm reimplemented receiver-side. TTD-confirmed 2026-05-03. |
| ↳ **M9.w3** Biped slot masking (hide ghost body parts under armor) | ✅ done — `TESObjectARMO+0x1E8` bipedSlots bitmask, slot-3 BODY mask flips `NIAV_FLAG_APP_CULLED` on ghost's `BaseMaleBody:0` BSSubIndexTriShape (cached at body inject via vtable RVA `0x2697D40` walker). Body hidden under Vault Suit / Power Armor / Synth Armor — no more z-fight. |
| ↳ **M9.w4** Object Modification (BGSMod) sync — shoulder pads, weapon mods, paint variants | 🟢 modded **pistols** end-to-end (v0.5.0, 2026-05-07) — engine OMOD attacher `sub_140434DA0` + BSConnectPoint pairing, sender-side 50ms auto re-equip cycle for off-by-one render lag. Modded 10mm/handmade pistol receivers/scopes/suppressors/mags all visible on the ghost, [demo](https://youtu.be/r34D4IL7wAk). Rifles (sniper/assault/hunting) next session to fully close M9. |
| ↳ **M9.w5** Peer rejoin equipment-state push | ✅ done in v0.3.1 — PEER_JOIN trigger re-arms equip cycle (DONE→ARMED state transition), 1500ms delay, current outfit re-broadcast to newly-joined peer |
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

### M9 v0.5.0 (2026-05-07) — modded weapons visible on ghost (pistols) — STABLE

- **Pistols with mods now render correctly on the remote ghost.** Peer A
  equips a 10mm with reflex sight, suppressor, heavy receiver and
  extended mag; peer B sees the exact same configuration in A's ghost
  hand, animated with A's pose. As far as I can tell this is the first
  time it has been done in the FO4 multiplayer modding scene — previous
  attempts (Fallout Together, F4MP) never reached this point.
  [Demo on YouTube](https://youtu.be/r34D4IL7wAk).
- **Per-OMOD attach is `sub_140434DA0(omod_form, base_BSFadeNode,
  placeholder_or_NULL, flags)`** (RVA `+0x00434DA0`). It reads the
  OMOD's `TESModel.modelPath` at `OMOD+0x50`, loads the sub-NIF,
  deep-clones, registers materials, then parents it under the base via
  `sub_14186E960`. The attach helper is **BSConnectPoint pairing**, not
  `NiNode::AttachChild`: the base weapon NIF carries a
  `BSConnectPoint::Children` extra-data array on its root, the mod
  sub-NIFs carry a matching `BSConnectPoint::Parents`, and the engine
  matches by string. All driven by data baked into the NIF files, not
  by anything on the form. Refuted ~10 plausible designs first
  (synthetic REFR via `vt[170]`, BSModelProcessor OIE post-hook,
  `find_node_by_name` + `AttachChild` driven by INNT, receiver-side
  primer + 50/100/500 ms refresh schedules); all failed live test or
  the 4-agent debate. See [CHANGELOG.md](CHANGELOG.md) for the full RE
  trace.
- **Sender fires a 50 ms auto re-equip cycle** to fix a first-equip
  render lag I couldn't fix on the receiver alone. The first equip of
  a modded weapon used to render on the ghost as either stock or as the
  previous weapon — one event behind. The fix mirrors a workaround I
  noticed manually (equip a Baton, then the modded weapon → renders
  correctly). 50 ms after the user's `EquipObject`, the sender posts
  `WM_APP+0x4F`; handler calls `UnequipObject(form, slot=0)` +
  `EquipObject(form, …)` for the same form, guarded by a TLS flag so
  it doesn't recurse. Receiver gets `EQUIP X / UNEQUIP X / EQUIP X` on
  the wire and the second `EQUIP X` is the one that renders correctly.
  A message-id collision (`FW_MSG_AUTO_RE_EQUIP` and `FW_MSG_EQUIP_APPLY`
  both at `WM_APP+0x4C`) cost me an afternoon — the cycle was scheduled
  but the WndProc routed every post to the wrong handler. Now at
  `WM_APP+0x4F`.
- **Net cleanup.** `MAX_RETRANSMITS` 8 → 32 (bursty equip traffic was
  killing the channel inside ~11 s); mesh-blob shipping disabled
  (`SHIP_LEGACY_BLOBS = false`) since everything I need now rides in
  the EQUIP_OP tail; OMOD form ids inline in `PendingEquipOp` instead
  of via a global stash (the old design had a refresh-vs-overwrite
  race); `UNEQUIP` ops with `slot_form_id == 0x4334D` (engine's
  internal `kReadiedWeapon` swap slot) are filtered in the drain so the
  freshly-attached weapon isn't wiped ~7 ms after attach.
- **Honest residual.** Rifles (sniper, assault, hunting, shotgun) still
  render invisible on the ghost. The same code path runs for them, so
  the failure is either in base path resolution (my canonical fallback
  may not match every rifle family's authoring convention) or in the
  BSConnectPoint authoring on rifle base NIFs. Next session I'll dump
  a rifle base subtree and check which `BSConnectPoint::Children`
  entries it actually carries. Tag
  `v0.5.0-w4-modded-firearms-pistols`.

### M9 v0.4.2 (2026-05-04) — Vault Suit cycle stability via path-routed deep clone — STABLE

- Closes four equip-cycle bugs on Vault Suit: SEH crash on spam
  unequip/equip, post-cycle local body invisible, ghost VS disappears
  after re-equip, ghost VS frozen in T-pose. Single root cause across
  all four: ghost shared the same cached `MaleBody.nif` / Vault Suit
  BSFadeNode with the local player; engine cleanup on each cycle freed
  state the ghost was still pointing at (`bones_pri[i]` raw `+0x70`
  pointers into freed `BSFlattenedBoneTree`, plus shared `APP_CULLED`
  bits leaking across actors).
- Path-whitelist routing in `ghost_attach_armor`: NIF paths containing
  `Vault111Suit` go through a manual deep-clone walker
  (`BSFadeNode`/`BSLeafAnimNode`/`NiNode`/`BSSubIndexTriShape` +
  manual `BSSkin::Instance` deep copy). Everything else
  (combat light/heavy, RusticUnderArmor jacket, regular outfits)
  stays on yesterday's v0.4.1 SHARED + snapshot/restore pipeline,
  which already had universal armor render.
- Body inject (`try_inject_body_nif`) deep-clones `MaleBody.nif`
  unconditionally so the ghost body has its own independent BSSITF;
  body cull `APP_CULLED` no longer bleeds across actors.
- Periodic 4Hz skin re-apply in `on_bone_tick_message` with silent flag
  refreshes ghost-skel binding on SHARED-path armors, neutralizing
  engine's local-actor re-bind drift during local equip churn.
- Whitelist instead of geometry-type detection because empirically
  combat heavy + RusticUnderArmor are also homogeneous BSSITF (no
  BSTriShape children) but their clones render invisible — the
  manual clone walker only survives for VS, likely due to its
  specific vertex layout tolerating a missing call to engine
  helper `sub_1416D5600` (NiSkinPartition / D3D resource binding
  setup).
- M9 still 4/5 wedges; w4 PROPER (weapon mod parts) is the remaining
  in-scope work. B8 boot-time force-equip-cycle workaround kept enabled
  — defense in depth, no harm. Tag `v0.4.2-vs-cycle-stable`.

### M9 v0.4.1 (2026-05-03) — wedge 2 PROPER + wedge 3 body cull — STABLE

- M9.w3 — biped slot body cull. `TESObjectARMO+0x1E8` `bipedSlots`
  bitmask drives `NIAV_FLAG_APP_CULLED` on the cached
  `BaseMaleBody:0` BSSubIndexTriShape (vtable RVA `0x2697D40`).
  When peer equips a slot-3 BODY armor (Vault Suit, Power Armor,
  Synth Armor) the ghost body is hidden under the armor mesh.
  Per-peer contributor set tracking handles concurrent BODY armors
  and guarantees correct restore on last-detach.
- M9.w2 PROPER — OMOD-driven ARMA tier selection. RE'd engine
  selector `sub_1404626A0` (`TESObjectARMO::ForEachAddonInstance`,
  RVA `0x4626A0`) and reimplemented its PrioritySelect algorithm
  receiver-side. Sender extracts effective priority from
  `BGSObjectInstance.extra+0x56`, TTD-confirmed against engine's
  r8 argument to the build-holder helper. Ships via wire (proto v10)
  so the ghost picks the same ARMA tier (Lite/Mid/Heavy) the player
  wears. Gender-fix in path scoring catches the `F_<X>` filename
  convention used by Combat Armor and DLC meshes.
- Both wedges settled by HIGH×HIGH consensus from independent IDA
  agents plus TTD ground-truth verification.

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
- **Rifles still render invisible on ghost** — pistols (10mm,
  Handmade pistol-form) work end-to-end with v0.5.0's BSConnectPoint
  pipeline; rifles (sniper / assault / hunting / shotgun) don't yet.
  Same code path executes — failure is in either base path resolution
  (canonical fallback `Weapons\<X>\<X>.nif` may not match every rifle
  family's authoring convention) or in BSConnectPoint::Children
  authoring differing for rifle base NIFs. Next session investigation
  to close M9 fully.
- **Sender sees a ~50 ms weapon flicker on equip** — visible side
  effect of the v0.5.0 auto re-equip cycle: 50 ms after the user's
  EquipObject the sender fires UnequipObject + EquipObject for the
  same form to make the receiver render correctly. The user's own
  weapon briefly disappears and reappears in their hand. Cosmetic; no
  gameplay impact (animation graph and damage state aren't affected).

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
