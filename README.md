
This project uses unconventional approaches in several critical areas (scene graph injection, skin buffer manipulation, binary patches). External contributions could inadvertently break invariants [...]

# FO4_Wrld

Fallout 4 1.11.191 next-gen — multiplayer mod (FoM-lite framework).
Solo-dev, evening project. Target: 10-player persistent-world survival MMO.

> **Status (2026-08-06):** **First-person ghost animation (v0.6.5).** A peer
> playing in first person appeared on the other screen as a V/T-pose mannequin
> with contorted arms — a limitation carried for months, and the reason a
> Pip-Boy or an aim pose looked impossible on the remote ghost. The capture
> was never at fault. `PlayerCharacter` overrides the post-update hook of the
> animation graph manager, and in first person that override copies the
> first-person skeleton over the third-person one every frame for the bones in
> an index map. It runs one call after the graph update, so whatever the
> third-person graph produced was erased before the pose capture could read
> it: first-person arms grafted onto a body whose legs never moved. Underneath
> that, the engine also parks the third-person graph on a camera switch —
> `BSAnimationGraphManager+0xD8` selects which of the player's two graphs is
> ticked — and deactivates its Havok behavior, so it stops producing poses at
> all. The fix drives that graph directly: revive it, refresh its active-node
> list, run the engine's own flush/generate/apply sequence with a forced update
> context (the LOD throttle resolves a hidden body to "generate nothing"),
> mirror animation events onto it so its state machine keeps transitioning,
> raise the behavior's base-state trigger at wake-up so a session starting in
> first person is not stuck in T-pose, keep it alive across camera switches
> instead of letting it be reborn, and suppress the skeleton copy while
> driving. Outward traffic stays muted through the engine's own null-event-sink
> idiom, so no duplicate footsteps or fire events reach gameplay, and the local
> player's arms are never touched. Also fixed: the Pip-Boy now attaches to
> `PipboyBone` instead of the ghost root (it used to render half-sunk between
> the feet), and the pose channel strips scale before converting to a
> quaternion, since it carries rotation only. Known residue: the walk clip
> plays at a rate that does not match the distance covered until a camera
> round-trip. See [CHANGELOG.md](CHANGELOG.md).
>
> **Status (2026-08-04):** **PIENUVO auth v0 + the player-death crash closed
> (v0.6.4).** Identity first: every client now proves an Ed25519 keypair
> instead of claiming a name. The launcher keeps the seed in a DPAPI-wrapped
> vault, signs the server's challenge bound to the server address, and hands
> the triple to the game via `FoM.exe --auth`; HELLO carries an optional
> 144 byte auth tail (wire v19), verification runs on vendored pure-Python
> ed25519, and a minimal master server (`net/master/`) handles discovery.
> `FoM.exe --connect` speaks pure JSON on stdout for the external
> server-browser launcher. Second: the crash that fired on the respawn load
> after a player death is closed. It was a freed-cell vcall in
> `TESObjectCELL::DetachReference`, produced by three cooperating defects:
> mirror driving via `vt[202]` re-hashes the actor in its current cell grid
> without ever re-filing `refr+0xB8`; the non-owner bail hooks kept eating
> the engine's own repair writes through the death window (650+ suppressed
> in one window, one from inside the engine's MoveTo worker); and the threat
> election kept scoring the dead client's frozen corpse position, handing it
> 7 NPCs 155 ms before one crash. Fix: a reliable NPC_UNLOAD per owned NPC
> at death (raiders flip to the survivor within a frame), full engine
> passthrough on the bail hooks from death to stand-down close, and
> ownership quiescence on both ends (claims deferred client-side, the dead
> session excluded from election server-side until its respawn jump).
> Validated: 4 two-client sessions, 8 deaths, 0 crashes, with the previously
> suppressed engine writes now visibly passing in the logs. Crash forensics
> stay in the tree: a 524k-record write ring dumped by the VEH on any AV, a
> register prober that names the crash victim by form id, and an ALT+F4
> marker that stamps teardown AVs so a force-close can never again be
> mistaken for a gameplay crash. Wire proto v19, 405 server tests. See
> [CHANGELOG.md](CHANGELOG.md).
>
> **Status (2026-07-29):** **N hardening — stability, position, locomotion,
> aggro.** This does not close branch N, it hardens it. The recurring client
> crashes were one bug: writes through stale bone pointers into recycled heap
> (caught red-handed as `1.0f` sitting where a smart pointer belongs, in a
> `PathingRequest` destructor). Fixed with the engine's own lifetime protocol —
> every cached bone is refcount-pinned at +0x08, so the free becomes impossible
> rather than unlikely, plus a one-deref parent probe that detects detachment.
> Raiders standing in the wrong place were not drift (measured 0.0 on 4,591 of
> 5,133 samples): the owner-state batch streamed the same first 17 NPCs forever,
> so 12 of 29 owned actors never received a position at all. Mirrors sliding
> like logs were not the bones either — every moving NPC was relayed as `idle`,
> so the graph played idle; the owner now derives WALKING/RUNNING from the
> position delta. Aggro had three separate defects: the engage signal was
> stamped once and decayed to zero forever, `Actor+0x380` is a handle and not a
> form id (so "am I fighting this NPC" was dead from birth), and the proximity
> tie-break was mathematically inert (weight 1.0 against a required delta of
> 3.0). Deaths are now remembered by the server and replayed to peers that were
> too far to receive them. Also: our own logger was the stutter (0.525 ms per
> line, fsync per line), and the crouch channel had been silently dead on a
> `WM_APP` id collision. Wire proto v18. See [CHANGELOG.md](CHANGELOG.md).
>
> **Status (2026-06-06):** **N3 shared HP — DONE; N4 player death — DONE.** The
> shared-HP enemy bar is now LIVE on both clients — the non-owner's local Health
> is driven to the combined server pool, so the vanilla enemy-health bar reads it
> and repaints as EITHER client deals damage (not only when the watching client
> shoots), and the aggro/first shot is counted instead of lost. A client's death
> ragdolls + respawns at Sanctuary with the raiders re-aggroing the survivor. Two
> removals made the bar land: `max = GetCurrent − cell` (the AVO GetMax leaf
> mis-reads) and dropping the client InCombat capture gate (raiders read
> InCombat=0 on the mirror). The bar is GREEN (non-hostile color — doubles as a
> "this client has no aggro" tell); a RED color is TODO. N1 (raider pos/pose) is
> REOPENED partial for small anim+position hardening at first-contact +
> post-mortem. Wire proto v18. See [CHANGELOG.md](CHANGELOG.md).

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
| **B2** Launcher (`FoM.exe`) | ✅ done — drop-in for `start_A.bat`/`start_B.bat`. v0.6.4 adds `--connect`: pure JSON on stdout, banners on stderr, pass-through of `--auth`/`--name`/`--client-id`, the machine interface for the external server-browser launcher |
| **P0** PIENUVO identity + auth (Ed25519 challenge-response, launcher vault, master server) | ✅ done (v0.6.4, 2026-08-04) — client id = `fw` + 13 hex of the pubkey hash, works on Steam and every non-Steam platform; signature binds the server address so a blob replays nowhere else; HELLO auth tail (wire v19), per-source challenge registry, vendored pure-Python ed25519, `net/master/` discovery server. 405 pytest |
| **B3** Auto-load save (delayed LoadGame via WndProc subclass) | ✅ done |
| **B4** Worldstate sync (GlobalVar + QuestStage) | 🟡 GlobalVar shipped; QuestStage RE done, apply pending wire |
| **M5–M6** Strada B ghost body (NIF native injection + textures) | ✅ done — body + head + hands textured, scene graph attached |
| **M7** Ghost animations (local memcpy from PC tree) | ✅ superseded by M8P3 |
| **M8P1** RE NiAVObject::Load3D | ✅ done — `sub_1417B3E90` public API |
| **M8P2** RE BSGeometry skin instance offsets | ✅ done — `+0x140` confirmed |
| **M8P3** Skin pipeline RE + per-bone pose replication | ✅ M8P3.23 — body+head+hands animated, see [CHANGELOG.md](CHANGELOG.md) |
| **M8P4** First-person ghost animation | ✅ done (v0.6.5, 2026-08-06) — a sender in first person no longer freezes the remote ghost into a V/T-pose with grafted arms. The engine parks and deactivates the third-person animation graph on a camera switch, then copies the first-person skeleton over the third-person one every frame in a post-update hook; the DLL now drives the parked graph (revive, active-node refresh, forced flush/generate/apply), mirrors animation events onto it, raises the behavior's base-state trigger at wake-up, keeps it alive across camera switches, and suppresses the skeleton copy while driving. Pip-Boy re-parented to `PipboyBone`; pose channel made scale-immune. Residue: walk clip rate |
| **B5** D3D11 custom render | 🗿 not needed — Strada B native injection replaced |
| **B6** World-state sync expansion *(composite epic; NPC pos/pose + combat split out to the N branch)* | 🟡 4/12 wedges done (doors, cell-transitions, locks, terminals) |
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
| ↳ **B6.4** Terminals state sync (hacked / unlocked) | ✅ done (v0.5.6, 2026-05-10) — implicit closure: a successful terminal hack flips `ExtraLock` via the engine's `ForceUnlock` (`sub_140563320`), already detoured by B6.3. Broadcast and receiver-apply paths are identical to those for doors / safes / weapon lockers. Zero new code. Verified live on the Sanctuary terminal-house during the v0.5.6 cell-entry crash fix test pass. |
| ↳ **B6.7** NPC dialogue state + faction joined | ⏳ — quest-stage adjacent; brainstorm §3.2 says 10 players = 1 entity, simplifies state |
| ↳ **B6.8** Companion state (recruited / position) | ⏳ — companions are NPCs with extra ownership flag |
| ↳ **B6.9** Cell-cleared status (no respawn after group clear) | ⏳ — `cleared` flag in cell extra-data, persisted server-side |
| ↳ **B6.10** One-shot loot pickups (bobbleheads, magazines, holotapes, skill books) | ⏳ — single-pickup persistence, partially covered by container `kill` events |
| ↳ **B6.11** Time of day + weather sync | ⏳ — GlobalVar `GameHour` + Sky weather state |
| ↳ **B6.12** Workshop / settlement build state sync | ⏳ — major epic; build/scrap/move workshop refs + furniture |
| ↳ **B6.13** Power Armor frame + worn-state sync | ⏳ — chassis is a REFR with its own state (location, per-piece HP, fusion core); player-in-PA = chassis attached to player. Both visibilities require sync. Re-scoped from M9 to B6 (2026-05-04) — fundamentally world-state, not an equip event |
| **N** NPC co-op combat *(split out from B6.5 / B6.6 — grew into its own epic; my first iteration on the game's AI)* | 🟡 N2 + N3 + N4 done; **hardened in v0.6.3** (stale-pointer crash class closed via NiRefObject pinning, owner-state starvation fixed, locomotion relayed, 3 aggro defects fixed, deaths replayed to distant peers); **v0.6.4 closed the respawn-load crash** (freed-cell vcall in DetachReference: death release + engine passthrough in the death window + ownership quiescence, 8 deaths / 0 crashes). N1 still open: creature pose schema + post-mortem hardening. Scope still hostile raiders. |
| ↳ **N1** NPC actor pos + pose sync (owner-driven) | 🟡 REOPENED partial (v0.6.2) — **major hardening in v0.6.3** (2026-07-29): the owner-state batch was capped at 17 entries with no rotation, so 12 of 29 owned NPCs never received a position at all (measured drift where data DID arrive: 0.0 on 4,591/5,133 samples) — now multi-batch, everyone at full 10 Hz; the engine's NATIVE position (AI char-controller proxy) is snapped via `sub_141894670` so it tracks the owner instead of diverging; locomotion is derived from the position delta and relayed (`anim=1/2 → SpeedSampled 100/200`), fixing the "slides like a log" mirrors; the bone cache is now refcount-pinned (+0x08) with a parent-detach probe, which closed the whole stale-pointer crash class. STILL OPEN: creature (non-humanoid) pose bleeds through a 1-name-match gate — a mole rat was seen stretched toward a map coordinate, needs a skeleton-schema gate, TODO in `scene_inject.cpp`; POST-mortem corpse hardening; leveled-list divergence means the same REFR can be a different NPC per client. |
| ↳ **N2** NPC combat target + aggro + death sync (owner-driven threat table) | ✅ done (v0.6.0, 2026-06-01) — the Python server holds a threat table and elects the owner from whoever the raiders natively aggro (engine-native: noise / line of sight), with hysteresis anti-thrash; live aggro hand-off; bidirectional death-sync (corpse + ragdoll at the synced pos, either client's kill propagates). Scope: hostile raiders. **v0.6.3 fixed three defects that made ownership effectively immovable**: the engage signal was stamped once per NPC and decayed to zero forever (across 1,711 evaluations the challenger threat never exceeded 1.0, so only damage could move aggro — combat observes now refresh at 1.5 s); `Actor+0x380` is an ObjectRefHandle and not a form id, so the "I am fighting this NPC" signal was a permanent false negative (now resolved through the handle table); and the proximity tie-break was mathematically inert (weight 1.0 vs a required delta of 3.0 — raised to 6.0 so it can break the engage tie two fighting clients produce). Deaths are also remembered server-side and replayed to peers that were out of range when they fired. |
| ↳ **N3** Shared authoritative HP / damage | ✅ done (v0.6.2, 2026-06-06) — both clients deplete ONE server-held HP pool (damage captured at the engine HP-write funnel `sub_140CC9650`, FINAL post-resist; DLL floor-1 clamp stops either client soloing the kill; server fires the kill at pool=0). v0.6.2 closed it: the enemy-health HUD now shows the LIVE combined pool on both clients (the non-owner's local Health is driven to the pool fraction so the vanilla bar reads it — `max = GetCurrent − cell`, since the AVO GetMax leaf mis-reads), the aggro/first shot is no longer lost (claimed pre-tracking, server-buffered until the NPC registers), and multi-feeder + server-driven death are confirmed. The HUD bar is GREEN (non-hostile color — handy as a "this client has no aggro" tell); a RED color is TODO. Wire proto v18. |
| ↳ **N4** Player death + respawn sync | ✅ done (v0.6.2, 2026-06-06) — a client's death is vanilla: it ragdolls + respawns at Sanctuary, and the raiders re-aggro the surviving client (the threat table re-elects on the death). **v0.6.4 closed the death transition properly**: the respawn-load crash is fixed (see N row), and the aggro flip is now a message, not a timeout: one reliable NPC_UNLOAD per owned NPC at death, so the raiders turn on the survivor within a frame instead of after 8 s. |
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

### v0.6.5 (2026-08-06) — first-person ghost animation

Tag v0.6.5. No protocol change.

- **The defect** — with the sender in first person, the remote ghost showed a
  V/T-pose body with first-person arms grafted on. Two independent causes, both
  in the engine's first-person path:
  1. `PlayerCharacter` overrides the animation-graph post-update hook and, in
     first person, copies the first-person skeleton onto the third-person one
     every frame through an index map. That call lands immediately after the
     graph update, so anything the third-person graph wrote was overwritten
     before the pose capture ran.
  2. A camera switch parks the third-person graph — the manager ticks only
     `graphs[activeGraph]` — and `SetActiveGraph` deactivates its Havok
     behavior, so every per-graph call early-outs and no pose is produced.
- **The fix** — drive the parked graph the way the engine's own out-of-band
  path does: reactivate it, refresh its active-node list, then flush bound
  channels, generate, and apply, using a forced update context (the distance
  LOD throttle resolves a hidden body to a zero bone count). Animation events
  are mirrored onto it so its state machine keeps transitioning; the
  behavior's base-state trigger plus a settle event are raised at wake-up so a
  session that starts in first person is not stuck in T-pose; the graph is kept
  alive across camera switches rather than being reactivated into its initial
  state; and the skeleton copy is suppressed while driving. All outward traffic
  is muted with the engine's own null-event-sink idiom, so no duplicate
  footsteps, fire events or root motion reach gameplay, and the graph feeding
  the local player's arms is never touched.
- **Also fixed** — the Pip-Boy attaches to `PipboyBone` instead of the ghost
  root, where it rendered half-sunk between the feet; the pose channel
  normalises each matrix row before converting to a quaternion, since it
  carries rotation only and any scale leaked straight onto the ghost.
- **Known residue** — the walk clip plays at a rate unrelated to the distance
  covered until a camera round-trip. Deriving the rate from frame-to-frame
  displacement was tried and reverted: this drive does not run every frame, so
  the displacement spans gaps the delta time does not account for (one client
  measured 5953 where 100-200 was expected, the other a constant 0). The
  engine's own movement speed is the correct source.

Full detail in [CHANGELOG.md](CHANGELOG.md).

### v0.6.4 (2026-08-04) — PIENUVO auth v0 + player-death crash closed

Tag v0.6.4, wire proto v19, 405 server tests.

- **Identity** — every client proves an Ed25519 keypair instead of claiming
  a name. Launcher-held seed in a DPAPI-wrapped vault; the signature binds
  the server address so an auth blob replays nowhere else; HELLO carries an
  optional 144 byte auth tail (legacy 26 byte HELLO still accepted). Client
  id = `fw` + 13 hex of the pubkey hash: Steam and every non-Steam platform
  get stable identities with zero platform dependencies. New `net/master/`
  discovery server. `FoM.exe --connect` speaks pure JSON on stdout for the
  external server-browser launcher.
- **The crash** — an AV on the respawn load after a player death, roughly
  one death in three: a freed-cell vcall in `TESObjectCELL::DetachReference`.
  Three cooperating defects, each confirmed by a capture: mirror driving via
  `vt[202]` re-hashes the actor in its current cell grid without re-filing
  `refr+0xB8`; the non-owner bail hooks ate the engine's own repair writes
  through the death window (650+ suppressed in one window, one from inside
  the engine's MoveTo worker); the threat election kept scoring the dead
  client's corpse position, handing it 7 NPCs 155 ms before one crash.
- **The fix** — one reliable NPC_UNLOAD per owned NPC at death (raiders
  flip to the survivor within a frame instead of after 8 s), full engine
  passthrough on the bail hooks from death to stand-down close, and
  ownership quiescence on both ends (claims deferred client-side, the dead
  session excluded from election server-side until its respawn jump).
  Validated: 4 two-client sessions, 8 deaths, 0 crashes.
- **Forensics kept in the tree** — a 524k-record ring of every DLL write
  into engine memory, dumped by the VEH on any AV with a crash-register
  scan; a register prober that names the crash victim by form id; an ALT+F4
  marker that stamps teardown AVs so a force-close is never again mistaken
  for a gameplay crash.

Full detail in [CHANGELOG.md](CHANGELOG.md).

### N3 (2026-06-05) — shared authoritative HP — PARTIAL

Working tree, tag v0.6.1. The boss-enabling piece: both clients deplete ONE
server-held HP pool per raider, so a raider dies from the COMBINED damage,
not from whichever client solo-deals its HP.

- **Capture** — a detour on the engine's single HP-write funnel
  `sub_140CC9650` (the chokepoint every Health delta passes through, incl.
  fire/DoT/radiation) reads the FINAL post-resist damage and reports it,
  firer-gated (each client only its own hits). Max HP = `absolute − modifier`
  via the AVO getter, shipped on the claim (wire proto v17, claim 8→12 B).
- **Pool** — `OwnershipRegistry` holds `hp_cur / hp_max` per form_id (survives
  handoffs); the first claim bootstraps max, both clients deplete the same pool.
- **Clamp** — a DLL clamp floors each client's absolute Health at 1 inside the
  funnel, so the engine's death cascade (keyed on `Health ≤ 0`) never starts.
  Gating `Actor::Kill` was REJECTED by the RE pass (it re-fires forever + leaves
  a ragdolled live actor); clamping the one HP store is the clean gate.
- **Death** — at pool 0 the server fires `NPC_DEATH_FROM_OWNER` to ALL clients
  (neither killed it locally), reusing the N1 / N2 death-sync, corpse synced.

Validated on the Concord raiders (clamp floors to 1 exactly, the pool kills at
combined = max, no double-count, no SEH). PARTIAL — wants broader testing +
other creatures. De-risked first by 3 decomp-verified RE agents + a read-only
probe build. Full detail in [CHANGELOG.md](CHANGELOG.md).

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

- **1st-person walk cycle plays at the wrong rate** — with the sender in
  first person the ghost now animates correctly (v0.6.5), but the walk
  clip runs at a rate unrelated to the ground covered until the sender
  switches view and back. The locomotion scalars the behavior scales its
  clips from are not written into a parked graph; deriving them from
  frame-to-frame displacement was tried and reverted (this drive does not
  run every frame, so the displacement spans gaps the delta time does not
  account for). The engine's own movement speed is the correct source.
  Workaround: one camera round-trip.
- **Ghost body casts no shadow** — the body is attached to the
  `ShadowSceneNode` and gets depth, lighting and occlusion from it, but it
  still does not appear in the shadow pass. Separate render-flag
  investigation, deferred.
- **No dedicated Pip-Boy pose on the ghost** — the Pip-Boy mesh itself is
  correct since v0.6.5 (parented to `PipboyBone`, riding the forearm and
  animating with it), and the ghost no longer contorts while a peer has it
  open. What is missing is the gesture: vanilla has no third-person
  arm-raise for a remote player consulting a Pip-Boy, so the ghost shows
  its normal standing pose instead of the animation the peer sees.
- **Tested with 2 peers** — multi-peer ghost cache (peer-id keyed
  registry) not yet implemented; 10-peer scaling is theoretical.
- **Network rate-limited to 20Hz** — works smoothly on LAN, untested
  over real-world internet routes; receiver-side interpolation between
  POSE_BROADCAST frames is open work.
- **Container UI doesn't refresh on the observer when peers picklock
  the same container** — engine quirk in the ContainerMenu redraw
  path; closing and reopening the container forces the refresh.
  Cosmetic, no state impact. Note: the antidupe layer is still
  enforced server-side by the container ack chain (server-validated
  count), so the observer can't actually take items that another peer
  has already removed even if the menu's local view is stale —
  attempts get rejected before they reach the inventory.
- **Peer ghosts spawn naked at startup until the peer actively equips
  something** — side effect of disabling B8 force-equip-cycle in
  v0.5.4 (bridge crash fix). Items already worn at save load don't
  fire engine equip events, so the M9 visual-sync pipeline never sees
  them. Items the peer actively equips/draws during the session show
  up correctly (modded weapons, swapped armor, clothes changes — all
  visible). A non-engine-call apparel bootstrap broadcast is
  scaffolded in `fw_native/src/hooks/equip_announce.{h,cpp}` for
  future implementation when the BipedAnim layout is RE'd.
- **Non-humanoid pose replication is unsafe** — ownership and sync are no
  longer limited to hostile raiders: the proximity sphere picks up any
  actor within its radius, so settlers, animals and creatures all enter
  the same pipeline. Pose replication, though, still assumes the human
  skeleton, and the match gate accepts a single coincidental bone-name hit
  — enough for a creature to be fed a human pose. A mole rat was seen with
  part of its body stretched toward a fixed map coordinate. Raising the
  threshold is not the fix (humanoid raiders themselves match only 4-7
  joints); this needs a skeleton-schema gate, tracked in
  `scene_inject.cpp` at `kNpcPoseMinMatch`.
- **A raider occasionally doesn't join the fight on the non-owner** —
  non-deterministic and rare. Aggro on noise / line of sight works as
  designed, but every so often one raider stays idle on the client that
  doesn't own it. Tolerated for now.
- **Raider appearance and loot diverge per client** — the Concord raiders
  are placed leveled refs, so the form_id matches across clients (pos /
  aggro / death sync all work), but each client's engine rolls a different
  NPC variant, outfit, weapon, and mods from the leveled lists with its
  own RNG. The same raider therefore looks different and drops different
  loot on each screen. Parked: a clean fix needs either an ESL of fixed
  content or a seeded-RNG / capture-replicate hook, and I'm deliberately
  staying engine-native (no ESL, no Creation Kit) for now.

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
