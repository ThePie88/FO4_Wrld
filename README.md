
This project uses unconventional approaches in several critical areas (scene graph injection, skin buffer manipulation, binary patches). External contributions could inadvertently break invariants [...]

# FO4_Wrld

Fallout 4 1.11.191 next-gen — multiplayer mod (FoM-lite framework).
Solo-dev, evening project. Target: 10-player persistent-world survival MMO.

## Support the project

[![Support me on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/thepie88)

Six months in, solo, evenings, paid for out of my own pocket. The code is free
forever under AGPLv3 and stays that way; a coffee goes to the API bill behind
the reverse engineering and to the server the test clients run on. The longer
write-up of where the project stands and why it is built this way is
[on Ko-fi](https://ko-fi.com/post/FO4Wrld-Building-the-Fallout-4-Multiplayer-Nobod-Z6U8271ZW7).

---

## Demo

[![FalloutWorld demo on YouTube](https://img.youtube.com/vi/r34D4IL7wAk/maxresdefault.jpg)](https://www.youtube.com/watch?v=r34D4IL7wAk)

▶ **[Watch the demo on YouTube](https://www.youtube.com/watch?v=r34D4IL7wAk)**

2 clients side-by-side, 1:52. Clothing and armor synced on the remote
player, weapons with every attachment assembled by the engine exactly as
equipped, and the full third-person animation set playing correctly on the
ghost.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Python Server (asyncio UDP)                        │
│  authoritative state · keyed by placed form_id · validator             │
│  reliable channel (SACK + retransmit) · durable journal + snapshot     │
└─────────────────────────┬──────────────────────────────────────────────┘
                          │ binary protocol v28 (44B POS_BCAST · reliable channel · appearance recipes · world objects · session lifecycle · container reconvergence)
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
       - in-game overlay (ImGui on the game's own device): character
         creator, chat, nametags
```

## Repository layout

| Path | Purpose |
|------|---------|
| `fw_native/` | C++ native client (dxgi.dll proxy + MinHook + scene graph injection) |
| `fw_native/src/native/` | Strada B native injection (NIF loader, scene graph, ghost body) |
| `fw_native/src/hooks/` | MinHook detours (kill, container, container menu, pos poll, main_menu, worldstate) |
| `fw_native/src/net/` | C++ port of Python protocol (byte-identical via static_assert) |
| `fw_native/src/render/` | Present hook on the game's own swapchain + ImGui overlay (character creation, chat, nametags) |
| `fw_native/deps/` | Vendored third-party deps (MinHook, Dear ImGui). Fetched locally, never committed |
| `fw_native/docs/` | Internal docs + tools list |
| `launcher/` | Python orchestrator (FO4 INI mgmt, side A/B startup, fw_config.ini) |
| `fw_launcher/` | C++ launcher wrapper (`FoM.exe`) |
| `net/` | Python server (asyncio UDP, validator, journal, snapshot v8) |
| `frida/` | Frida JS scripts + Python attach helpers (RE / live tracing) |
| `re/` | Reverse-engineering dossiers + IDA Python scripts |
| `tools/` | Maintenance scripts: Frida traces, decode helpers |

## Major milestones

| Milestone | Status |
|-----------|--------|
| **B0** Networking + native client port | ✅ done — 196+ pytest, byte-identical protocol |
| **B1** Container pre-mutation block | ✅ done — concurrent TAKE dup race closed; the blocking wait was replaced in v0.9.0 by optimistic ops with rollback |
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
| **B6** World-state sync expansion *(composite epic; NPC pos/pose + combat split out to the N branch)* | 🟡 6/13 wedges done (doors, cell-transitions, locks, terminals, world-object spawns, power armor); lights and time/weather parked, quests/companions/cell-cleared/one-shot loot/workshop open |
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
| ↳ **B6.13** Power Armor frame + worn-state sync | ✅ closed (v0.7.6, 2026-09-16) — the frame rides the spawn rails (enter = despawn, exit = rebirth); pieces, OMOD upgrade levels, condition, core charge and paint jobs travel with the object and persist in a per-wid server ledger; replicas are stocked through the engine's own `AddItem` (`sub_1411735A0`) and `AttachModToInventoryItem` (`sub_1411808F0`) workers and the Health extra is created the way the engine does it; manual take/put and the power armor station (`PowerArmorModMenu`, polled while it lives) ship full state; frames are exempt from the loot layer and re-seat themselves after a station edit. The wearer's ghost is dressed and painted: `Frame.nif` plus the model OMOD meshes of every piece, material swaps read from the OMOD property records, on a ghost skeleton grafted with the 20 PA-only bones and retargeted to PA proportions while worn. Residue: fingers do not articulate. The frame lost when the wearer quits is closed server side in v0.8.0 (handed back to the world on leave, eviction and timeout) and still owes the live test with a client killed from the task manager |
| ↳ **B6.14** World-object spawn sync | ✅ first version (v0.7.5, 2026-09-14) — `PlaceAtMe` detoured on both the Papyrus native and the console worker; server-assigned `wid`, JSON persistence, join bootstrap replay; receive-side placement = upright, ground snap, engine cell re-file, range-gated; lifecycle sweep reports deaths by wid, streaming losses re-queued, resurrection watch re-announces re-enabled refs; real removal idiom (`RemoveReference` + `DestroyByHandle`, no-save flag cleared first) |
| **N** NPC co-op combat *(split out from B6.5 / B6.6 — grew into its own epic; my first iteration on the game's AI)* | 🟡 N2 + N3 + N4 done; **hardened in v0.6.3** (stale-pointer crash class closed via NiRefObject pinning, owner-state starvation fixed, locomotion relayed, 3 aggro defects fixed, deaths replayed to distant peers); **v0.6.4 closed the respawn-load crash** (freed-cell vcall in DetachReference: death release + engine passthrough in the death window + ownership quiescence, 8 deaths / 0 crashes). N1 still open: creature pose schema + post-mortem hardening. Scope still hostile raiders. |
| ↳ **N1** NPC actor pos + pose sync (owner-driven) | 🟡 REOPENED partial (v0.6.2) — **major hardening in v0.6.3** (2026-07-29): the owner-state batch was capped at 17 entries with no rotation, so 12 of 29 owned NPCs never received a position at all (measured drift where data DID arrive: 0.0 on 4,591/5,133 samples) — now multi-batch, everyone at full 10 Hz; the engine's NATIVE position (AI char-controller proxy) is snapped via `sub_141894670` so it tracks the owner instead of diverging; locomotion is derived from the position delta and relayed (`anim=1/2 → SpeedSampled 100/200`), fixing the "slides like a log" mirrors; the bone cache is now refcount-pinned (+0x08) with a parent-detach probe, which closed the whole stale-pointer crash class. STILL OPEN: creature (non-humanoid) pose bleeds through a 1-name-match gate — a mole rat was seen stretched toward a map coordinate, needs a skeleton-schema gate, TODO in `scene_inject.cpp`; POST-mortem corpse hardening; leveled-list divergence means the same REFR can be a different NPC per client. |
| ↳ **N2** NPC combat target + aggro + death sync (owner-driven threat table) | ✅ done (v0.6.0, 2026-06-01) — the Python server holds a threat table and elects the owner from whoever the raiders natively aggro (engine-native: noise / line of sight), with hysteresis anti-thrash; live aggro hand-off; bidirectional death-sync (corpse + ragdoll at the synced pos, either client's kill propagates). Scope: hostile raiders. **v0.6.3 fixed three defects that made ownership effectively immovable**: the engage signal was stamped once per NPC and decayed to zero forever (across 1,711 evaluations the challenger threat never exceeded 1.0, so only damage could move aggro — combat observes now refresh at 1.5 s); `Actor+0x380` is an ObjectRefHandle and not a form id, so the "I am fighting this NPC" signal was a permanent false negative (now resolved through the handle table); and the proximity tie-break was mathematically inert (weight 1.0 vs a required delta of 3.0 — raised to 6.0 so it can break the engage tie two fighting clients produce). Deaths are also remembered server-side and replayed to peers that were out of range when they fired. |
| ↳ **N3** Shared authoritative HP / damage | ✅ done (v0.6.2, 2026-06-06) — both clients deplete ONE server-held HP pool (damage captured at the engine HP-write funnel `sub_140CC9650`, FINAL post-resist; DLL floor-1 clamp stops either client soloing the kill; server fires the kill at pool=0). v0.6.2 closed it: the enemy-health HUD now shows the LIVE combined pool on both clients (the non-owner's local Health is driven to the pool fraction so the vanilla bar reads it — `max = GetCurrent − cell`, since the AVO GetMax leaf mis-reads), the aggro/first shot is no longer lost (claimed pre-tracking, server-buffered until the NPC registers), and multi-feeder + server-driven death are confirmed. The HUD bar is GREEN (non-hostile color — handy as a "this client has no aggro" tell); a RED color is TODO. Wire proto v18. |
| ↳ **N4** Player death + respawn sync | ✅ done (v0.6.2, 2026-06-06) — a client's death is vanilla: it ragdolls + respawns at Sanctuary, and the raiders re-aggro the surviving client (the threat table re-elects on the death). **v0.6.4 closed the death transition properly**: the respawn-load crash is fixed (see N row), and the aggro flip is now a message, not a timeout: one reliable NPC_UNLOAD per owned NPC at death, so the raiders turn on the survivor within a frame instead of after 8 s. **v0.10.0 moved the respawn to the server**: a death is answered with the player's checkpoint moved onto the founder's respawn point and loaded once (11.7 s from 31,000 units away in the live test, against 2 to 6 minutes for a fast travel after the vanilla reload), the player healed, from an exterior or an interior, in power armour or not. |
| **CG1** Character creation + appearance identity *(new epic, my first custom in-game UI)* | 🟡 v1 shipped (v0.7.0, 2026-08-12), deliberately unfinished. Forced first-entry ritual (server flag), sky staging + pinned auto-vanity camera, runtime catalogs (filtered head parts, 32 hair colours, 9 tint groups from race CharGenData), live editing of hair / eyes / beard / teeth / brows / skin tone / marks through the engine's own apply calls, recipe v2 (parts + tints, wire v21) stored per identity on the server, adopted at join and replicated onto the ghost with private composite textures and engine-computed body skin. Open: morph sculpting, body build, sex switch, Markings tab placement, per-peer ghost cache; the ImGui panel is a placeholder for the final UI |
| **S1** Session lifecycle *(join / leave / disconnect / rejoin / late join)* | ✅ closed (v0.8.1, 2026-09-23) — phases 0-2 in v0.8.0: the ghost is born from PEER_JOIN and torn down on PEER_LEAVE instead of from a 30 s timer that never re-armed, a registry keyed by peer id replaces the single body pointer and the census of single-peer globals in the ghost path is empty; presence that outlives the session, resume tokens for a rejoin without the launcher, reject reasons on the wire, eviction with notice, a queued join bootstrap, a reconnection loop with backoff, a goodbye on ALT+F4. Phases 3-4 in v0.8.1: the worn outfit is read from the inventory and announced at every session start, global chat, nametags above the ghosts, the three reconnection holes closed with tests. Residue: matrix tests T4/T6/T7/T8 not run, a second remote ghost refused until a third client exists, a 100 ms race on a live container op, weapons not announced at session start |
| **L** Loot sync rework *(containers, corpses, player inventory, world items)* | 🟡 L1-L4 done (v0.9.0, 2026-09-26) — containers keyed by the placed reference, optimistic ops with rollback, the server view pushed and applied to every engine with a real-time menu redraw, corpses of placed NPCs. L5 stages 0-3 done (v0.10.0, 2026-10-02): no save or load the server did not command, a durable journal, mandatory login, the player's inventory read and its boundary tapped, the character in a checkpoint the server commands, keeps in custody and moves for the respawn and the first entry. Open: L5 stages 4-5 (restore and replay after the checkpoint, the save barrier) and L6, world items |
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
- **Moving a player inside a save** — the server rewrites a `.fos` that the
  engine then loads as its own: the Player Location global (two spaces, the
  grid, a position local to the cell inside an interior), the player's move
  data, and for a player taken out of an interior the sky (mode 1 inside, 3
  outside, followed by 29 bytes of outdoor state) and the acoustic space,
  transplanted from an exterior save. `net/server/savepos.py`.
- **Model-DB entry root shape** — a NIF loaded with the fade-wrap flag is
  stored with a `BSFadeNode` root, and the engine's biped build silently
  produces no geometry from such an entry. The engine never loads
  `Frame.nif` through the public loader, so a mod-created entry is the only
  one it finds. Biped loads must use the engine's own flags (`0x2C`).
- **`NiNode::AttachChild` growth** (`sub_1416BE170` / `sub_1404E7B50`) —
  a full children array is grown by `SetSize`, which frees the old buffer;
  file-loaded bones keep theirs in the loader arena, so the free faults.
  Pre-grow with the same pool allocation and never free the old block.
- **Power-armor pieces** — the ARMA is a placeholder shared by every PA
  model; the visible mesh is the model OMOD's `MODL`, skinned to PA-only
  bones. Condition and core charge are one Health extra (`0x25`) on the
  inventory stack; the engine's `AddItem` / `AttachModToInventoryItem`
  workers and the `ExtraDataList` add idiom are all callable from the DLL.

## Changelog

Latest 3 patches summarized below. **Full version history in
[CHANGELOG.md](CHANGELOG.md).**

### v0.10.0 (2026-10-02) — persistence, first half: checkpoints, custody and the respawn

Tag v0.10.0, wire proto v33, server snapshot v10. Stages 0 to 3 of the
inventory-persistence plan. Every save the engine attempts without the server's
command is refused by one lifecycle module in the DLL, the quicksave and quickload keys are dropped,
an uncommanded load is refused; the server appends every accepted change to
a durable journal and sends no reliable frame before its fsync; login is
mandatory, with a local key for the second test client. The DLL reads the
player's inventory the way the save writes it and taps the two engine
functions every inventory change goes through; items dropped from the
Pip-Boy exist for everyone. The character lives in a checkpoint the server
commands (at a quiet moment, on every exit, and the moment a player leaves
their power armour), keeps in custody and hands back at the next boot, on
any machine. A death is answered with the player's checkpoint moved onto the
founder's respawn point (`server.ini`): one load, no fast travel, the player
healed, from an exterior or an interior; a frame worn at the death goes
with the player or stays where they fell, never in two copies. A new
character starts on the same point. Detail in [CHANGELOG.md](CHANGELOG.md).

### v0.9.0 (2026-09-26) — loot rework, first half: containers and corpses

Tag v0.9.0, wire proto v27, server snapshot v6.

- **A container is its placed reference** — the server keys containers by
  the placed reference's form_id instead of (base, cell), which merged twins.
  Runtime references are refused; a placed actor, whose base the engine
  generates per client, is identified by its form_id alone.
- **Optimistic transactions with rollback** — the engine applies at once and
  a refusal is undone on the main thread. No more 100 ms freeze per take; ops
  made during a drop are sent again, and a repeat gets the stored verdict.
- **Every client converges on the server's view** — pushed at the join and
  whenever a record changes, applied with AddItem and RemoveItem at scene
  settle, cell change, activation and after every op. The open container menu
  redraws in real time. A constant wrong since April kept the mod from ever
  building an untouched container's inventory list.
- **Corpses** — a dead placed NPC is a container, a living one is never
  aligned, and a new death makes a new corpse.
- **Open** — the player's own inventory is not persisted yet, which is the
  next step; randomness is per client; corpses of runtime-spawned NPCs stay
  local.

Full detail in [CHANGELOG.md](CHANGELOG.md).

### v0.8.1 (2026-09-23) — nametags and chat, minor fixes

Tag v0.8.1, wire proto v26 unchanged.

- **Chat** — a small see-through box on the left, always on, "name: text".
  Enter opens the input with the game's controls paused, Enter sends, Escape
  closes. The server stamps the sender itself, echoes every line back to its
  author and keeps a flood limit. Enter in the Pip-Boy or the console goes to
  the game.
- **Nametags** — the peer's name above the ghost's head, bold white with a
  black outline, projected at Present with the world root camera and checked
  against the engine's own ray function. In this engine the rows of a world
  rotation are the camera axes, not Gamebryo's columns; that cost one test.
- **Outfit announced at session start** (phase 3) — the client reads what it
  wears from its inventory, with the OMODs, and the server forgets its stored
  copy on every (re)join.
- **The three reconnection holes** of v0.8.0 are closed, each with a test
  that failed on the old code.

Full detail in [CHANGELOG.md](CHANGELOG.md).

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
- **Tested with 2 peers** — the peer-keyed registry landed in v0.8.0 and the
  ghost path holds no single-peer global any more, but a second remote ghost
  is still refused on purpose: that path has never been executed, because two
  clients means one remote peer each. It opens when there is a third client to
  prove it with. 10-peer scaling stays theoretical.
- **Network rate-limited to 20Hz** — works smoothly on LAN, untested
  over real-world internet routes; receiver-side interpolation between
  POSE_BROADCAST frames is open work.
- **A crash rewinds the player to the last checkpoint** — since v0.10.0 the
  character lives in a checkpoint the server commands and keeps (written at
  a quiet moment on a timer, at every exit, and the moment a player leaves
  their power armour) and hands back at the next boot. A crash or a kill
  from the task manager writes none: the player comes back as the last one
  left them, at their last known position, while the world keeps what
  happened after it, so a take in that window is lost and a deposit is
  duplicated. Replaying after the checkpoint is the next stage.
- **A weapon equipped when the save loads is not shown on the ghost until
  the peer equips or draws one** — since v0.8.1 every piece of apparel worn
  at load is read from the inventory and announced at session start, so a
  ghost no longer starts naked; weapons are left to their own equip path on
  purpose and are not announced.
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
- **Raider appearance diverges per client, loot converges** — the Concord
  raiders are placed leveled refs, so the form_id matches across clients
  (pos / aggro / death sync all work), but each client's engine rolls a
  different NPC variant, outfit, weapon and mods from the leveled lists with
  its own RNG. Since v0.9.0 the loot converges: the first client to open a
  corpse or a container decides its contents, and every other client is
  aligned to it by base and count, so a weapon's mods are lost on the way.
  The appearance still diverges. Parked for a dedicated epic that makes the
  engine's random rolls deterministic, staying engine-native (no ESL, no
  Creation Kit).
- **A client that quits while wearing power armor** no longer loses the frame
  for everyone: v0.8.0 marks the record worn instead of deleting it and hands
  the frame back at its last known position on a graceful leave, an eviction
  or a timeout, taking the plates out of the stored outfit so the rejoining
  peer is not wearing an empty shell. Since v0.10.0 the checkpoint written at
  the quit brings the player back inside the frame, and the boot takes the
  standing frame back from the world: one armour, not two. Covered by unit
  tests; neither that boot nor the test with a wearer killed from the task
  manager (T7) has been run live yet.
- **Power-armor headlamps do not light up on the ghost** — the lamp mesh is
  an engine add-on point whose glow effect is bookkept globally, which is
  the crash class closed in v0.7.6; the ghost skips it.
- **Fingers and toes do not articulate on ghosts** — 53 of the 80
  canonical joints never leave the sender's render tree, so hands and
  feet ride their parent joints without bending.
- **A face master built while the local player wears power armor is not
  validated** — the master keeps pointers into the rig it was cloned from, and
  v0.8.0 anchors them to a reference skeleton this DLL owns so a power-armor
  rebuild cannot recycle them underneath. What is not checked is the master
  itself: nothing refuses to park one whose bone names do not exist in the
  human skeleton. The permanent tripwire is the `[face-slots]` debug line.

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
