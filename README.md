
This project uses unconventional approaches in several critical areas (scene graph injection, skin buffer manipulation, binary patches). External contributions could inadvertently break invariants [...]

# FO4_Wrld

Fallout 4 1.11.191 next-gen — multiplayer mod (FoM-lite framework).
Solo-dev, evening project. Target: 10-player persistent-world survival MMO.

> **Status (2026-06-05):** **N3 — shared authoritative HP (partial).** Both
> clients now deplete ONE server-held HP pool per raider: each reports its
> FINAL post-resist damage — captured at the engine's single HP-write funnel
> `sub_140CC9650` — and a raider dies when the COMBINED pool hits 0, not when
> one client solo-deals its HP. A DLL clamp floors each client's local Health
> at 1 so the engine never kills the raider on its own; the server then fires
> the kill, reusing the N1 / N2 death-sync, so the corpse lands on both clients
> together. This is the core mechanic the ~20k-HP boss needs. Validated on the
> Concord raiders; PARTIAL — wants broader testing and other creatures. Wire
> proto v17. See [CHANGELOG.md](CHANGELOG.md).
>
> **Status (2026-06-01):** **N1 / N2 — owner-driven NPC combat sync.** My
> first iteration on the game's AI. Hostile raiders (the Concord cluster)
> now fight both players together, synced across clients: world position,
> full-body pose/animation, aggro ownership with live hand-off, and death
> (ragdoll + corpse). Each raider is owned by exactly one client whose
> vanilla engine runs its AI and streams its pos + pose at ~30 Hz; the
> other client mirrors it — position-pinned, Havok-keyframed — and corpses
> it on a relayed kill. The Python server holds the ownership / threat
> table and elects the owner from whoever the raiders natively aggro
> (noise / line of sight), so both players are real threats. This work
> started as the B6.5 / B6.6 wedges of the B6 world-state epic, but it grew
> large enough to graduate into its own milestone branch (N) — and it
> replaces that earlier stack, where raiders were frozen and immortal.
> Scope today is hostile raiders only; other creatures and a shared-HP
> boss are the next wedges. Working tree, first commit of the N branch
> (v0.6.0); shared authoritative HP and the ~1 s aggro-switch idle are not
> done yet. See [CHANGELOG.md](CHANGELOG.md).
>
> **Status (2026-05-12):** **B6.5 / B6.6 NPC AI sync infrastructure WIP** —
> tracked raiders are frozen, immortal, and visually neutral on both
> peers (no aim, no head tracking, no hostile barks, no hit reaction).
> 10 MinHook detours cover the NPC AI / combat decision pipeline;
> Python server-side combat brain scaffold in
> `net/server/raider_brain.py` (25 passing unit tests). Headline hook:
> `Actor::vt[255] = sub_140CCFDF0` — bailing this single per-actor
> per-frame combat orchestrator short-circuits target promotion, fire
> decide, dispatch attack, and aim update in one shot. Working tree,
> no tag. Server-driven aggro / damage flow / movement substitution
> are the next wedges. See [CHANGELOG.md](CHANGELOG.md).

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
| **N** NPC co-op combat *(split out from B6.5 / B6.6 — grew into its own epic; my first iteration on the game's AI)* | 🟡 N1 + N2 done, N3 (shared HP) partial — all on hostile raiders; player-death + the rest of the creature roster pending |
| ↳ **N1** NPC actor pos + pose sync (owner-driven) | ✅ done (v0.6.0, 2026-06-01) — each raider is owned by one client whose vanilla engine runs its AI and streams pos + full-body pose (~30 Hz); the non-owner mirrors it (pos-pinned, Havok-keyframed). Teleport-on-handoff fixed by committing the synced pose to the new owner's engine via `Actor::MoveTo` (doProcessUpdate=1). Replaces the old B6.5 frozen-suppression stack. |
| ↳ **N2** NPC combat target + aggro + death sync (owner-driven threat table) | ✅ done (v0.6.0, 2026-06-01) — the Python server holds a threat table and elects the owner from whoever the raiders natively aggro (engine-native: noise / line of sight), with hysteresis anti-thrash; live aggro hand-off; bidirectional death-sync (corpse + ragdoll at the synced pos, either client's kill propagates). Scope: hostile raiders. |
| ↳ **N3** Shared authoritative HP / damage | 🟡 partial (v0.6.1, 2026-06-05) — both clients deplete ONE server-held HP pool: damage is captured at the engine HP-write funnel `sub_140CC9650` (FINAL post-resist value), a DLL floor-1 clamp stops either client killing the raider solo, and the server fires the kill at pool=0 (reusing the N1/N2 death-sync). Validated on Concord raiders; needs broader testing + other creatures. Wire proto v17. |
| ↳ **N4** Player death + respawn sync | ⏳ — the ghost dies / ragdolls / respawns on the peer; part of the boss-fight loop (deaths + respawns). |
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

### N1 / N2 (2026-06-01) — owner-driven NPC co-op combat — WIP

My first iteration on the game's AI. Hostile raiders (the Concord
Museum cluster) now fight both players together and stay consistent
across clients — position, full-body animation, aggro, and death. This
started as the B6.5 / B6.6 wedges but grew large enough to become its
own milestone branch (N), and it replaces that earlier suppression
stack, where raiders were frozen and immortal on both peers.

**Ownership model.** Every tracked raider is owned by exactly one
client. The owner runs the raider's vanilla engine AI untouched and
streams its authoritative state; the non-owner suppresses its own AI for
that raider and mirrors the owner — position pinned to the relayed
coords, the Havok body keyframed, and the full per-bone pose replayed at
~30 Hz so the raider animates correctly instead of sliding as a frozen
prop. The Python server is the single ownership authority; the DLL only
mirrors what the server elects (`is_owner_of` / `is_non_owner_tracked`
predicates drive every AI/motion hook).

**Aggro (engine-native).** The server keeps a per-raider threat table
and elects the owner from whoever the raiders actually aggro — the same
noise / line-of-sight perception the vanilla engine already runs — so
both players are real threats and ownership follows the fight. A
hysteresis band (minimum hold + flip margin + commitment window) stops
the owner from thrashing when both players trade fire.

**Death sync.** A kill on either client propagates to the other, which
corpses its mirror at the synced position (ragdoll + body stays down) —
no more "dead on one client, alive on the other" or vanishing corpses.

**Teleport fix.** The long-standing bug where a raider snapped to a
stale position the instant ownership changed is closed: at hand-off I
commit the synced pose into the new owner's engine ground-truth via
`Actor::MoveTo` (doProcessUpdate = 1), so the engine state and the
visible position no longer diverge.

Scope today is hostile raiders only; other creatures and a shared-HP
boss come later. Not done yet: shared authoritative HP (both clients
deplete one server-held pool — required for a high-HP boss) and the ~1 s
idle on aggro hand-off. Full per-hook / per-opcode detail in
[CHANGELOG.md](CHANGELOG.md).

### B6.5 / B6.6 WIP (2026-05-12) — NPC AI sync infrastructure — UNSTABLE

Working tree, no tag. Cross-client behaviour today: tracked raiders
are frozen, immortal, and visually neutral on both peers (no aim,
no head tracking, no hostile barks, no hit reaction). 10 MinHook
detours cover the NPC AI / combat decision pipeline; a Python
server-side combat brain scaffold sits in `net/server/raider_brain.py`
(25 passing unit tests). Server-driven aggression and damage flow
are the next wedges.

**RE pass.** 10-agent IDA pair arena on the Hex-Rays decomp;
dossiers under `re/B6.6w0_pair_AGENT_{A1,A2,B1,B2,C1,C2,D1,D2,E1,E2}.md`.
Two independent analysis paths per hook target. Headline finding:
the per-actor combat brain entry is `Actor::vt[255] = sub_140CCFDF0`,
called from `Main::TickFrame` via the AI fan-out chain. Bailing
this one function for tracked NPCs short-circuits the entire
combat pipeline — target promotion, fire decide, dispatch attack,
aim update — in a single hook.

**Unified freeze predicate.** `should_freeze_actor(form_id)` ORs
two sources: the server cache (`movement_override` pushed via
`NPC_STATE_BCAST`, symmetric across peers) and a local dynamic
set auto-populated by `npc_ai_suppress` from the `InCombat` flag
at `Actor+0x2D0 bit 0x4000`. Required after a B-vs-A asymmetry
where dyn-set-only checks left some actors uncovered on one peer.

**Hit-applier bail** (`sub_140CD2780`) — closed a deterministic
crash where damaging a frozen raider AV'd 3 seconds later. Root
cause: the engine's stagger and hit-react sub-handlers were
writing into a frozen anim graph and leaving the state machine
inconsistent for a later access. Bailing the orchestrator
short-circuits all three downstream handlers; tracked NPCs are
now invulnerable client-side and crash-free under fire. The
target Actor was misidentified at `rcx+0x300` in the initial D2
dossier; live test confirmed `rcx` itself is the target Actor.

**AIProcess→fid reverse map.** Populated lazily by
`npc_ai_suppress` (every Update_PerFrame fire reads `Actor+0x328`
and inserts the pair under a shared_mutex). Used by the
fire-decide and combat-target hooks where AIProcess is reachable
via a TLS chain but the owner Actor is not directly available.

**Server brain scaffold.** `net/server/raider_brain.py` (~430
lines, 25 passing unit tests). Combat state machine per raider:
target selection with hysteresis + lost-target timeout, fire
cooldown gating, chest-height aim bias, shoot-to-aggro, damage
application with lethal-tier transition, per-peer projection of
`combat_target_form_id` / `aim_target_xyz` / `fire_this_tick`
for each `NPC_STATE_BCAST` entry. Not yet wired into the main
tick loop.

**Wire proto v14** is already in place from earlier B6.5w12
work and carries the fields the substitution path needs
(`combat_target_form_id`, `aim_xyz`, `velocity_xyz`). No bump
required for the MVP combat substitution.

**Not done.** Server-driven aggro (raider attacks peer A on
server command — needs conditional bail in `should_freeze_actor`
plus Phase 2 substitution in `set_combat_target`); damage flow
opcode (`PEER_HIT_REPORT` C→S + validation +
`NPC_DAMAGE_TAKEN` BCAST); server-driven movement; `main.py`
wiring of `raider_brain`. Full per-hook detail in
[CHANGELOG.md](CHANGELOG.md).

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
- **NPC co-op (N1 / N2) is scoped to hostile raiders** — only the Concord
  Museum raider cluster is synced today. Other creatures and the rest of
  the actor roster aren't wired in yet; this is my first AI iteration, not
  a finished system.
- **A raider occasionally doesn't join the fight on the non-owner** —
  non-deterministic and rare. Aggro on noise / line of sight works as
  designed, but every so often one raider stays idle on the client that
  doesn't own it. Tolerated for now.
- **Pure-melee enemies aren't observed yet** — ownership election only
  picks a raider up once the engine flags it in combat or it fires a
  shot. A hostile that only ever melees and never trips the
  combat-controller flag is never observed, so it's never owned or synced.
  Fine for ranged raiders; needs a hostile-baseform-bounded perception
  gate before a melee boss.
- **~1 s idle on aggro hand-off** — when ownership switches to the player
  a raider just turned on, it can stand idle for about a second before
  facing the new target. The instant-switch fix exists but is disabled
  pending a safer guard.
- **No shared HP yet** — each client tracks a tracked NPC's HP locally
  (its own hits only), so a high-HP enemy has to be brought down by one
  client's own damage; the two clients don't yet pool damage into a single
  server-held pool. Main blocker for a co-op boss and the next wedge (N3).
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
