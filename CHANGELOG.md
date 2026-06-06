# FO4_Wrld — Changelog

Full version history. README has the latest 3 entries summarized; everything
older lives here. Format: newest first, milestones / patches inline.

---

## N3 shared HP — DONE · N4 player death — DONE (2026-06-06) — v0.6.2

Tag `v0.6.2`. Small follow-up that closes N3 + N4 and reopens N1 partial.

**N3 — the shared-HP enemy bar is now LIVE on both clients.** The non-owner
mirror's local Health is driven to the server pool fraction (deferred to the main
thread on each `NPC_HP_POOL_BCAST`), so the vanilla enemy-health bar reads the
COMBINED pool and repaints as either client deals damage — not only when the
watching client shoots. Two fixes made it work, both by REMOVING, not adding:

- **`max = GetCurrent − cell`** instead of calling the ActorValueOwner GetMax leaf.
  That leaf faults when called 1-arg and returns ~0 when called 2-arg under every
  signature tried (a float-in-xmm0 mis-read as a double), so the bar value was
  being skipped every frame. The permanent base = absolute current minus the
  `0x444` modifier cell is the SAME math the capture path already uses for max_hp.
- **dropped the client InCombat capture gate.** Raiders read InCombat=0 on the
  mirror (the perception walker clears the bit), so the gate I had added was
  dropping the real damage claims. Friendlies stay excluded SERVER-side: a pool is
  only ever born from an InCombat-gated `NPC_OBSERVED`.

Plus a producer change-cache poke in the G2 hook to force a per-frame repaint, and
the **first / aggro shot is no longer lost**: the client claims by-player Health
damage even before the NPC is tracked, and the server buffers the unknown-fid
claim (2 s TTL) and drains it into the pool — exactly once — the instant the NPC
registers. Confirmed live: multi-feeder pool (`totals={player_A, player_B}`),
first-shot DRAIN, kills from the combined pool, no crashes.

The HUD bar is GREEN — the engine's non-hostile color, since the mirror is neutral
to the watching client. Kept on purpose for now: it doubles as a free "which client
does NOT have aggro on this NPC" tell during testing. A RED color is TODO.

**N4 — player death is done.** A client's death is vanilla — ragdoll + respawn at
Sanctuary — and the raiders re-aggro the surviving client (the threat table
re-elects on the death). N1 / N2 already carried it; nothing new was needed.

**N1 — reopened partial.** The owner-driven pos / pose sync works, but small raider
animation + position glitches remain to harden at FIRST contact with a client and
POST-mortem. A future hardening wedge.

Wire proto v18 (unchanged from v0.6.1 — `NPC_HP_POOL_BCAST`). 339 server tests pass.

---

## N3 — shared authoritative HP (2026-06-05) — PARTIAL

Working tree, tag `v0.6.1`. The piece the boss needs: both co-op clients now
deplete ONE server-held HP pool per raider, so a raider dies from the COMBINED
damage of both players — not from whichever client happens to solo-deal its HP
first. Validated end-to-end on the Concord raiders; PARTIAL because it wants
broader testing and other creature types before it's "done".

### RE de-risk first (no blind code)

The whole HP / damage / death engine path was reverse-engineered against the
Hex-Rays decomp by three parallel agents before a line was written, because the
earlier plan dossiers had real errors that would have caused wack-a-mole:

- **Health ActorValue index.** The plan said `sub_140263120()[1]`; the decomp
  proved `[1]` is **ActionPoints** and Health is **`[27]`** (three independent
  confirmations). Writing HP at `[1]` would have drained Action Points.
- **The kill gate.** The plan said "gate `Actor::Kill`". The decomp proved that
  is **unsafe**: the `Health <= 0 && !IsDead -> Kill` decision is duplicated
  inline across >=3 per-frame checkers, so swallowing one `Kill` makes the
  engine re-fire it every frame forever, while the ragdoll (fired inside the hit
  orchestrator, independent of `Kill`) leaves a ragdolled-but-live actor. The
  safe gate is to **clamp Health so it never reaches 0** — one store, and no
  death code ever begins.
- **HP layout.** The Health cell at `Actor+0x444` holds only the 3 modifier
  columns (0 at full, negative as damage lands); the permanent base lives in the
  ActorValueOwner. So `max = absolute_current - cell_modifier_sum`, the absolute
  coming from the AVO getter (vtable +8).

A read-only probe build (`npc_hp_probe`) then confirmed all three at runtime
before any write: the funnel's `delta` arg equals the FINAL applied damage to
the centesimo (post-resist/perk, no `vtable+2440` re-derivation for raider
weapon damage), the `0x444` cell tracks HP, and the damage `source` decodes to
the firer. It also caught a trap — `avIdx==2` is shared by several AVs (Health,
AP, resists), so gating on the column alone would have fed -100 / -200 spurious
values into the pool; the real gate is the Health AVInfo.

### Damage capture — `sub_140CC9650` (the HP-write funnel)

A new detour on `sub_140CC9650` (RVA `0xCC9650`) — the single chokepoint EVERY
Health delta passes through (weapon, melee, explosion, **plus** fire / DoT /
poison `sub_14098DB00`, radiation / script `sub_140BA0610`, fall
`sub_140C62EE0`) — reports the local player's damage to the server. The value
is the FINAL post-resist `-delta` (not the pre-mitigation `HitData+0x90` the old
hit orchestrator read), firer-gated via the funnel's `source` arg so each client
reports only its own hits exactly once. Which writes are Health is learned at
runtime with no extra engine call: the first write that actually moves the
`0x444` cell teaches the Health AVInfo pointer, after which the clamp can gate
pre-write. Max HP (`absolute - modifier`) rides on the claim.

The old orchestrator-based claim (`ghost_ai_hit_applier`, pre-mitigation,
weapon-only) is disabled to avoid a double claim; the funnel claim is a superset
and more accurate, and still drives the aggro threat table.

### Server pool — `OwnershipRegistry`

`NPCOwnership` gains `hp_cur / hp_max / hp_dead / hp_dmg_by_peer`, keyed by
form_id so the pool **survives ownership handoffs**. `apply_hp_claim` bootstraps
`hp_max` from the first claim that carries it, subtracts every claim from the
shared `hp_cur` (floored at 0), and latches `hp_dead` the first time it crosses
zero (idempotent). The pool re-bootstraps cleanly when a raider respawns.

### Clamp — no premature solo-death

For tracked raiders the funnel detour floors the **absolute** Health at
`HP_FLOOR = 1`: if `absolute + delta < 1` it rewrites the delta so the new
absolute is exactly 1. The engine's death cascade is keyed on `Health <= 0`, so
it never starts; the raider stays alive and AI-functional, taking damage the
server is accumulating. Skipped while the raider is already dying (the server
kill is applying). The clamp is a detour on the engine's own call (engine
thread), NOT a write from our thread — the riskiest path the dossiers feared is
avoided entirely.

### Death — server-driven, reusing N1 / N2

When `apply_hp_claim` latches the pool at zero, the server's `_fire_npc_death`
sends `NPC_DEATH_FROM_OWNER` to ALL sessions (unlike the peer-relayed death,
NEITHER client killed it locally) and releases ownership. The clients apply it
through the existing N1 / N2 death-sync drain (un-keyframe -> `Actor::Kill` under
the applying-remote guard), so the corpse lands on both clients at the synced
position, exactly once.

### Wire proto v17

`NpcDamageClaim` 8 -> 12 B (`<Iff`): adds `max_hp`. `PROTOCOL_VERSION` 16 -> 17.
No new opcode — the existing `NPC_DAMAGE_CLAIM` (0x028D) carries the pool input
(it already drove aggro).

### Files

- DLL: `hooks/npc_hp_probe.{h,cpp}` (the funnel detour: capture + clamp +
  learn-Health-form), `hooks/ghost_ai_hit_applier.cpp` (claim disabled),
  `net/client.{h,cpp}`, `net/protocol.h`, `offsets.h` (`ACTOR_HP_FUNNEL_RVA`,
  `ACTOR_HEALTH_CELL_OFF`, AVO offsets).
- Server: `net/server/ownership.py` (pool + `apply_hp_claim`),
  `net/server/main.py` (`_fire_npc_death` + claim handler), `net/protocol.py`.

### Validation (in-engine)

- **Round 1 (pool math, log-only).** Server log shows `max` bootstrapping to the
  real raider HP (20, 30), both peers' post-resist damage summing into one pool,
  and the pool reaching 0 at COMBINED damage — incl. the key case where neither
  peer alone reached max (B 21.6 + A 17.8 on a 30-HP raider). No double-count.
- **Round 2 (clamp + kill).** Client log: `[hp-clamp]` floors HP to 1 exactly
  (abs 7.7, -11.2 hit -> `use_delta = -6.7` -> abs 1.0). Server: 6 `KILL-COMMAND`
  events at pool 0, each to both peers. Live: a raider held at 1 HP by one client
  and finished by the other dies on both at the same spot. No SEH.

### Not done (why PARTIAL)

- Broader testing + other creature types (only the Concord raiders so far).
- HP bar UI (players can't yet SEE the shared pool) — Tier 1, separate.
- Ragdoll direction is 0 (corpse drops in place; impulse is polish).
- Kill credit / killer form is 0 (server-origin death).

### Build path

`npc_hp_probe` read-only probe -> round 1 (capture + server pool, log-only) ->
round 2 (clamp + server kill). Kill-switches on capture and clamp.

### Note

Both clients show the known shutdown teardown crash `0x16632B9` (null+8 write)
when force-closed with alt+F4 — pre-existing (Tier 2), unrelated to N3 (the
funnel detour is SEH-caged and touches no heap; it fires only at process
teardown).

**Tag:** `v0.6.1`.

---

## N1 / N2 — owner-driven NPC co-op combat (2026-06-01) — WIP

Working tree, first commit of the N branch (tag `v0.6.0`). My first
iteration on the game's AI: hostile raiders (the Concord Museum cluster,
14 placed refs) now fight both players together and stay consistent across
clients — world position, full-body pose, aggro ownership with live
hand-off, and death. This started as the B6.5 / B6.6 wedges of the B6
world-state epic, but the NPC AI problem turned out to be large enough to
be its own epic, so I split it into the **N** branch (N1 = pos + pose,
N2 = combat target + aggro + death). It is also a hard pivot away from
B6.5 / B6.6: that stack tried to NUKE the engine's combat brain
(`Actor::vt[255]` bail) and leave raiders frozen + immortal. N keeps the
engine's vanilla AI running on exactly one client and replicates it.

### The pivot: suppress-everywhere → owner-driven

B6.5 / B6.6 ran the same AI-suppression stack on both peers, so neither
engine drove the raider. The N model is asymmetric:

- **One client owns each raider.** On the owner, the raider's vanilla
  engine AI runs untouched (perception, target select, movement, aim,
  fire, melee). The owner reads its authoritative state and streams it.
- **The other client is a puppet.** It suppresses its own AI decisions for
  that raider and replays the owner's stream: position pinned to the
  relayed coords, the Havok body keyframed, the full per-bone pose applied.
- **The server is the single ownership authority.** The Python
  `OwnershipRegistry` elects an owner per raider and broadcasts every
  transition; the DLL only mirrors it.

### Server: ownership + threat election (`net/server/ownership.py`)

`OwnershipRegistry` holds one record per tracked raider (owner peer, epoch,
last pos, threat accumulators). Election is server-authoritative:

- **Initial owner = the observer.** `NPC_OBSERVED` is gated on the client
  engine actually being in combat with the raider (see DLL gate), so the
  first peer to observe it is by definition the one fighting it → it claims
  ownership (`assign_owner_by_threat`).
- **Per-tick re-evaluation (`reeval_threat_owners`).** For every raider,
  each candidate peer's threat is

      threat = 10.0 * engage + 1.0 * proximity + 30.0 * damage

  where `engage` is 1.0 while a peer is in combat with the raider and
  decays to 0 over 4500 ms, `proximity` is 1.0 at the raider and 0 at the
  aggro-range edge, and `damage` is that peer's recent decayed damage
  (4000 ms window, normalised by 80). Damage is weighted to dominate so
  ownership follows whoever is actually fighting, not merely who is nearest.
- **Anti-thrash hysteresis.** A handoff fires only when the challenger
  decisively beats the owner: `MIN_HOLD = 2000 ms` since the last change,
  `FLIP_MARGIN = 1.3×`, `MIN_ABS_DELTA = 3.0`, plus a commitment band
  (`COMMIT_WINDOW = 3500 ms`, `COMMIT_ABS_DELTA = 8.0`) that lets a clearly
  committed challenger take over faster. This stops the owner from flipping
  every time both players trade fire.

This is engine-native aggro: the server never tells a raider who to hate —
it watches who the raiders *already* hate (via the in-combat signal below)
and routes ownership there, so both players are real threats.

### DLL: the per-actor gate (`hooks/npc_ai_suppress.cpp`)

`Actor::Update_PerFrame` (RVA `0xC636A0`, the single per-actor per-frame
funnel) is detoured. For every loaded actor:

1. **Observation gate.** I emit `NPC_OBSERVED` only for actors my engine
   sees as combat-relevant — `S1 || S2 || S3`:
   - **S1** = the InCombat flag (`Actor+0x2D0 & 0x4000`),
   - **S2** = `CombatController+0x98`,
   - **S3** = `recently_fired` (the actor fired in the last 1.5 s).

   The MQ102 Concord quest raiders fight through a *scripted package* and
   never set S1 / S2, so S3 (they do fire) is what catches them. I
   deliberately do **not** observe on raw HighProcess (`Actor+0x328`) —
   that would re-flag every idle settler / companion and reopen the
   UDP-observation storm an earlier build hit.
2. **Owner / non-owner branch** via the cheap predicates `is_owner_of(fid)`
   / `is_non_owner_tracked(fid)` (a `shared_mutex`-guarded map mirrored
   from the server):
   - **Owner** → record the raider's pos / yaw / anim into the TX cache and
     run vanilla `Update_PerFrame` normally. A periodic tick drains the
     cache into `NPC_STATE_FROM_OWNER` (~10 Hz) plus `NPC_POSE_FROM_OWNER`
     per-bone (~30 Hz).
   - **Non-owner** → I no longer bail `Update_PerFrame` (an earlier build
     did; it left the raider a frozen "wooden log" because the engine's
     anim walker never ran). Instead I let the engine tick but pin the
     result, set the mirror-suppress flag (`Actor+0x189 = 1`, stops the
     puppet aiming at / crouch-sliding toward the local player), and emit
     `NPC_ENGAGEMENT_CLAIM` when my engine has the InCombat bit on a raider
     I don't own (drives the server's combat-driven handoff).

A new `puppet_update_perframe` module implements the KEEP-ALWAYS subset of
the 106 `Update_PerFrame` call-sites (anim-graph tick, bone-tree, NIF
transforms, cell / extra-data bookkeeping) with zero AI decisions, for the
path where the puppet must look alive without taking any AI.

### Position + pose, and the teleport fix

The non-owner pins the raider to the relayed position. Two writers,
depending on engine state:

- **Normal:** `apply_npc_pos` writes `Actor+0xD0` through the engine.
- **During a teleport / cell-stream window:** `apply_npc_pos_raw`
  (`engine_calls.cpp`) does SEH-caged raw memory writes to `Actor+0xD0` +
  the NIF root local / world transforms only — zero engine calls. This
  exists because `SetPosition_NoCell` (`sub_140513A80`, RVA `0x513A80`) and
  `vt[202]` share a process-global cell-grid spinlock that the streaming
  thread can hold, which froze the main thread; the raw path can't reach
  the lock. The body is held by `NiAVObject::SetMotionType` (RVA
  `0x18763E0`) in **Keyframed** mode (2) on the puppet, flipped back to
  **Dynamic** (1) on death.

The headline bug this branch closes is the **teleport-on-handoff**: the
instant ownership changed, the raider snapped to a stale position. Root
cause — the visible-position pin (`Actor+0xD0` + NIF) was the only thing
kept in sync; the *engine ground truth* (AI-process, cell, Havok) on the
new owner had never moved from the raider's pre-aggro default, and surfaced
the moment that client's AI took over. Fix (`actor_teleport_handoff`): at
the handoff I commit the synced pose into the new owner's engine via
`Actor::MoveTo` (the atomic-teleport worker, RVA `0xC60BE0`) with
`doProcessUpdate = 1`, which reattaches the AI-process + cell at the
target, so engine state and visible position no longer diverge.

### Death sync (`hooks/kill_hook.cpp`)

`Actor::Kill` (RVA `0xC612E0`) is detoured. When a tracked raider dies, the
killing client emits `NPC_DEATH_FROM_OWNER`; the server relays it; the
other client corpses its mirror at the synced position: un-keyframe (motion
→ Dynamic), `apply_npc_pos_raw` to the death pos, then `kill_actor` under an
"applying-remote" guard so the re-entrant `Kill` detour bails
(`tls_applying_remote`) instead of echoing back into a loop.

- **Bidirectional:** either client's kill propagates (owner *or*
  non-owner). Originally only the owner emitted, so "B shoots a raider
  owned by A → dead on B, alive on A".
- **No vanishing corpses:** the legacy generic `ActorEvent KILL` (which
  routes to `set_disabled_validated` and *disables* the ref) is now skipped
  for tracked entities — for placed (`0x00`) refs the disable made the body
  disappear instead of ragdolling, because the dynamic-form vanish-guard
  only protected runtime (`0xFF`) spawns. Tracked raiders now corpse via
  `kill_actor` only.

### Wire protocol

`PROTOCOL_VERSION = 16`. The owner-driven NPC channel is opcodes `0x0280`–
`0x0290`:

| Opcode | Name | Dir | Role |
|---|---|---|---|
| `0x0280` | NPC_OWNERSHIP_BCAST | S→peer | bootstrap snapshot |
| `0x0283` | NPC_OWNERSHIP_HANDOFF_PHASE_2 | S→all | new owner for one NPC |
| `0x0284` | NPC_OWNER_HEARTBEAT | C→S | proof-of-life (~2 Hz) |
| `0x0285` | NPC_STATE_FROM_OWNER | C→S→all | owner state batch (~10 Hz) |
| `0x0286` | NPC_OBSERVED | C→S | election input |
| `0x0287` | NPC_UNLOAD | C→S | cell unload → release |
| `0x0288` | NPC_FIRE_FROM_OWNER | C→S→all | owner fire event |
| `0x0289` | NPC_DEATH_FROM_OWNER | C→S→all | owner death event |
| `0x028A` | NPC_DAMAGE_FROM_OWNER | C→S→all | hit-applier visual |
| `0x028B` | NPC_ENGAGEMENT_CLAIM | C→S | non-owner in-combat → force handoff |
| `0x028C` | NPC_POSE_FROM_OWNER | C→S→all | per-bone pose (~30 Hz) |
| `0x028D` | NPC_DAMAGE_CLAIM | C→S | damage → threat |
| `0x0290` | NPC_CROUCH_FROM_OWNER | C→S→all | crouch translation |

### Files / components

- **DLL:** `hooks/ownership_manager.{h,cpp}` (server-mirror registry +
  predicates + TX), `hooks/puppet_update_perframe.{h,cpp}`,
  `hooks/npc_ai_suppress.cpp` (the gate), `hooks/kill_hook.cpp` (death
  emit), `engine/engine_calls.cpp` (`apply_npc_pos_raw`,
  `actor_teleport_handoff`, `kill_actor`), `main_thread_dispatch.cpp`
  (death / owner-state / handoff / pose drains), `net/protocol.h` +
  `net/client.cpp`.
- **Server:** `net/server/ownership.py` (threat table),
  `net/server/main.py` (handlers + relay + per-tick reeval),
  `net/protocol.py`.

### Build path (key milestones)

Build 65 → 65.c.49.1, ~50 iterations. The ones that matter: **65**
owner-driven foundation (registry + relay + DLL mirror); **c.35** server
threat table; **c.36a** the S0–S3 combat detection + anti-thrash; **c.36b**
mirror-suppress (`+0x189`); **c.37** full per-bone pose replication;
**c.41b** the keyframe machine; **c.42** 30 Hz pose + receiver
interpolation; **c.44** the teleport fix (`MoveTo` engine-commit); **c.46**
the deadlock-safe raw pin; **c.47 / c.49 / c.49.1** death sync (owner →
bidirectional → corpse-vanish fix); **c.48** the S1‖S2‖S3 observation gate.

### Not done

- **Shared authoritative HP (N3).** Each client still tracks a raider's HP
  locally (its own hits only) via the engine HP funnel (`sub_140CC9650`);
  the two clients don't pool damage. A high-HP boss would die on whoever
  solo-deals its HP. The hit-claim / damage-threat infra exists; this needs
  a server-held HP pool + an `NPC_HP_STATE` opcode. The #1 boss blocker.
- **The ~1 s aggro-switch idle.** The fix (force the raider's combat target
  to the local player at the handoff commit) is implemented but
  kill-switched off (`kForceTargetPlayerOnHandoff = false`) — it was a
  suspect in an earlier crash that turned out to be the unsynced-death UAF
  (now fixed by death sync), so it can be re-enabled behind a
  dead / creature / already-killed guard.
- **Player death + respawn sync (N4).** The ghost doesn't yet die / ragdoll
  / respawn on the peer.
- Other creatures beyond hostile raiders.

### Known limitations (live)

A raider occasionally not joining on the non-owner (non-deterministic,
rare); pure-melee enemies not observed yet (no fire, no combat-controller
flag → never owned); raider appearance + loot diverge per client (placed
leveled refs, per-client RNG — pos / aggro / death still sync because the
form_id matches; parked, staying engine-native, no ESL / no Creation Kit).

### Dead code

Several hooks from the abandoned ghost-proxy / per-walker era (builds 55–63:
`ghost_hostility_guard`, `ghost_combat_force`, `ghost_is_attachable`,
`ghost_vt197_guard`, `ghost_global_walker_guards`, `ghost_ai_action_execute`)
are commented-out / inert but still compiled, kept as a record of what I
tried. Cleanup (~2.9k LOC) is deferred.

---

## B6.5 / B6.6 WIP — NPC AI sync infrastructure (2026-05-12) — UNSTABLE

Working tree, no tag. The pieces below land in the working tree but
the cross-client experience is "tracked raiders are frozen, immortal,
and visually neutral"; server-driven aggression / movement / damage
flow is the next wedge.

### Achieved cross-client

Both clients show identical state for tracked raiders (14 placed in
the Concord Museum cluster): position frozen, no combat behaviour
(no aim, no head tracking, no hostile barks, no hit reaction),
invulnerable to local player attacks (no hit reaction, no HP
decrement, no ragdoll on death). Knockdown anim still plays on
takedown via an engine sub-path independent of the hooked
orchestrator, but the NPC re-emerges in passive state and stays
cross-client consistent. Verified live on both peers.

### RE pass — 10-agent IDA pair arena

Ran on the full Hex-Rays decomp at `D:\falloutworld_decomp\out\`.
Each candidate hook target attacked from two independent paths
(downstream-from-output and upstream-from-projectile, for example)
to cross-check. Dossiers in
`re/B6.6w0_pair_AGENT_{A1,A2,B1,B2,C1,C2,D1,D2,E1,E2}.md`.

Headline findings:

- **Combat brain entry per-actor per-frame:**
  `Actor::vt[255] = sub_140CCFDF0`, called from
  `Main::TickFrame → sub_140ED2280 (AI fan-out) → sub_140ED4760
  (task thunk) → Actor::vt[255]`. Bailing this single function
  for tracked NPCs short-circuits the entire downstream pipeline
  (target promotion, fire decide, dispatch attack, aim update).
- **Real combat-target writer:** `sub_140C5CCE0` (mirror, our
  previous hook target) is a pure copy
  `AIProcess+0x6C → Actor+0x380`; the AI's actual reads come
  from `AIProcess+0x6C`, written by
  `AIProcess::SetCombatTarget @ sub_14087AB30(AIProcess* rcx,
  Actor* rdx)` per A1+A2 convergence. The new hook is on
  `sub_14087AB30`; the old mirror hook stays installed as a
  diagnostic but no longer drives substitution.
- **Universal attack-action funnel:**
  `Actor::DispatchAttackAction @ sub_140E6F830(Actor*, action_id, flags)`.
  C1+C2 convergence. Covers single-shot, burst, suppressive,
  suppressive-burst, melee, power attack. Bailing here silences
  everything in one hook (the leaf-level
  `CombatBehaviorGunFire::DecideAndFire @ sub_14086FCA0` covers
  single-shot only).
- **Movement decision funnel:**
  `AIProcess::ProcessPackages_Movement @ sub_140CEEC30(AIProcess*, Actor*, char)`
  per B1. Sits upstream of all pos writers already hooked.
- **Central hit applier orchestrator:**
  `sub_140CD2780(__m128* a1, __m128* a2)`. D2 dossier mis-typed
  the target Actor location as `*(a1+0x300)`; live test showed
  `a1` itself is the target Actor — pseudo-C reads `a1[13]` as
  the NiPoint3 world pos (= `Actor+0xD0`), confirming. Hook
  reads form_id at `a1+0x14`.
- **C1 mis-identification corrected:** `sub_140479680` was
  labelled "Actor::FireWeapon" in the C1 dossier. Live test
  proved `rcx` at entry is a stack pointer (~`0x000000F9XXX`
  range, not heap range), and pseudo-C confirmed the signature
  is `(__int64* stack_buf, __m128* arg2, ...)` — utility, not
  Actor::FireWeapon. Dropped that hook target.

### Hooks installed (10 total)

| Module | RVA / target | Role |
|---|---|---|
| `npc_ai_suppress` | `0xC636A0` | `Actor::Update_PerFrame` bail. Also populates the `AIProcess* → form_id` reverse map by reading `Actor+0x328` on every fire. |
| `ghost_ai_havok_step` | `0x18B9790` | `bhkCharRigidBodyController::FinishPhysicsStep` bail. Owner Actor at `controller+0x3E0`. |
| `ghost_ai_pos_belt` | `0x513A80` | `SetPosition_NiPoint3` bail. |
| `ghost_ai_actor_setpos` | Actor vt[202] | Full bail of the SetPosition path + the direct `NIF+0x60` write that bypasses `ghost_ai_pos_belt`. |
| `ghost_ai_fire` | `0x86FCA0` | `CombatBehaviorGunFire::DecideAndFire` bail. Single-shot only; burst/suppressive caught by `dispatch_attack`. Owner Actor identified via the TLS chain `*((TLS_array[*(u32*)0x143E5C658] + 0x8F0)) → +0x158 → +0x68` (yields AIProcess) plus the AIProcess→fid map. |
| `ghost_ai_dispatch_attack` | `0xE6F830` | `Actor::DispatchAttackAction` bail. Universal attack-action funnel. Actor* in `rcx`. |
| `ghost_ai_process_movement` | `0xCEEC30` | `AIProcess::ProcessPackages_Movement` bail. Actor* in `rdx`. |
| `ghost_ai_set_combat_target` | `0x87AB30` | `AIProcess::SetCombatTarget(AIProcess*, Actor*)` — diagnostic-only this iteration, ready for Phase 2 server-driven target substitution. Owner Actor resolved via the AIProcess→fid map. |
| `ghost_ai_hit_applier` | `0xCD2780` | Central hit applier orchestrator BAIL. Skips stagger applier + hit-react animator + HP write + ragdoll setup. Crash-prevention critical: tracked NPCs are now invulnerable client-side and crash-free under fire. |
| `ghost_ai_combat_orchestrator` | `0xCCFDF0` | `Actor::vt[255]` per-actor combat brain BAIL. The NUKE — short-circuits the entire per-actor per-frame combat pipeline. |

Existing diagnostic-only hooks left installed: `ghost_ai_aim`,
`ghost_ai_package`, `ghost_ai_combat_target` (the old mirror — not
the new `set_combat_target`).

### Unified freeze predicate

`should_freeze_actor(form_id)` consolidates two sources, OR'd:

1. **Server cache** — `fw::dispatch::get_cached_npc_state` reads
   `movement_override`, set from `NPC_STATE_BCAST`. Symmetric
   across peers because both receive the same broadcast and apply
   it identically.
2. **Local dynamic set** — `is_actor_bail_tracked` reads an
   `unordered_set<u32>` auto-populated by `npc_ai_suppress` when
   the `InCombat` flag (`Actor+0x2D0 bit 0x4000`) is observed
   during Update_PerFrame. Asymmetric: only catches actors the
   local engine has ticked into combat with the local player.

The OR is required after a live B-vs-A asymmetry: client B
auto-tracked only 13 raiders by the time client A had auto-tracked
16, leaving three Concord raiders un-bailed on B and free to
attack. The server-cache source closes that gap because the
14 raiders in `concord_museum_mvp.json` are pushed with
`movement_override=1` to every connected peer.

Used by every B6.5 freeze + B6.6 combat hook to decide bail.

### AIProcess → form_id reverse map

`npc_ai_suppress` populates a process-wide
`unordered_map<const void*, u32>` lazily: every Update_PerFrame
fire reads `Actor+0x328` (= AIProcess*) and inserts the pair
under a `shared_mutex`. Used by the fire-decide and
combat-target hooks where AIProcess is reachable (via a TLS
chain or as a direct arg) but the owner Actor is not. The
reverse map is asymmetric across clients (lazy from local
ticks), but the unified predicate compensates via the symmetric
server cache.

### Server brain scaffold

`net/server/raider_brain.py` — ~430 lines, 25 passing unit
tests (`net/tests/test_raider_brain.py`). Combat state machine
per raider:

- Target selection with hysteresis (`swap_hysteresis_ft`) +
  lost-target timeout (`target_loss_ms`).
- Fire cooldown gating per weapon (`fire_cooldown_ms`).
- Chest-height aim bias (`AIM_VERTICAL_OFFSET_FT = 70`).
- Shoot-to-aggro: damage from a peer immediately makes that peer
  the aggro target even if not previously selected.
- Damage application with lethal-tier transition.
- Per-peer projection: `project_for_peer(form_id, peer_id)`
  generates per-peer `combat_target_form_id` /
  `aim_target_xyz` / `fire_this_tick` fields. The
  `combat_target_form_id` substitution is per-peer (each
  client's own local `PlayerCharacter.formID = 0x14` for the
  chosen target peer, `0` for others); the aim point and fire
  timing are world-frame and identical across peers.

Not yet wired into `net/server/main.py`'s periodic tick loop.

### Wire proto v14

Already in place from earlier B6.5w12 work and unchanged here.
`NPCStateEntry` is 98 bytes and carries `package_form_id`,
`combat_target_form_id`, `aim_xyz`, `velocity_xyz`,
`weapon_state`, plus 6 1-bit locomotion fields packed into a
u16 `loco_state_pack`. No protocol bump required for the MVP
combat substitution.

### Not done

- **Server-driven aggro** (raider attacks peer A on server
  command). Requires inverting `should_freeze_actor` to return
  `false` when the server cache has an active opinion
  (`combat_target_form_id != 0`), plus Phase 2 substitution in
  `ghost_ai_set_combat_target` to swap `rdx` Actor* for the
  server-chosen target. With both in place the engine handles
  aim and fire automatically using the substituted target.
- **Damage flow opcode**: `PEER_HIT_REPORT(npc_form_id,
  weapon_form, dmg_claimed, hit_zone, ts)` C→S, server
  validation via `raider_brain.apply_damage`, server BCAST
  `NPC_DAMAGE_TAKEN(form_id, dmg, source, ts)`, client applies
  HP via the engine path. Tracked NPCs are currently
  unconditionally immortal client-side because `hit_applier`
  bails all damage processing.
- **Server-driven movement** (raider takes cover, advances).
  Requires conditional bail in `process_movement` plus
  per-peer velocity broadcast (the field exists in proto v14
  already). Navmesh remains deferred per the NPCs.md
  "Option B asymmetric peer query" plan.
- **`main.py` wiring** of `raider_brain` into the periodic
  tick loop, plus building the `peers` snapshot from
  `ServerState`.

### Notable iteration costs

- The first fire-suppression hook target (`sub_140479680`,
  labelled "Actor::FireWeapon" by C1) turned out to take a
  stack-buffer first arg, not Actor*. Spent an iteration
  debugging garbage form_ids (`0x178` every fire — the heap
  base prefix of a stack pointer read at `+0x14`). Pseudo-C
  inspection of the actual signature would have caught this
  upfront. Lesson logged inline in `offsets.h`.
- D2 dossier's "target Actor at hit_data+0x300" — wrong. Live
  test showed `rcx` itself is the target Actor; `+0x300` is an
  internal sub-component (MiddleProcess?). Pseudo-C
  `a1[13].m128_f32[0]` = `a1+0xD0` = NiPoint3 read confirmed
  `a1` is Actor. Lesson logged inline.
- C1's `bool sub_14086FCA0(void)` zero-arg signature with hidden
  TLS chain caught me out at first — the function reads a
  process-wide tlsIdx and indexes the per-thread TLS array.
  Sanity-checking `tls_idx == 0` as garbage was wrong (the
  engine's index legitimately starts at 0 in 1.11.191).

---

## B6.4 v0.5.6 — Interior cell-entry crash fix + B6.4 implicit closure (2026-05-10) — HOTFIX

Deterministic crash on a peer's machine when another peer crossed into
an interior cell. Reproduced on the Sanctuary terminal-house entry,
both clients, every time. Vanilla FO4 (no DLL) walked the same
transition cleanly, confirming the DLL was at fault.

### TTD trace

`NtTerminateProcess(ExitStatus=0xC0000005)` — access violation, not a
clean exit. Faulting RIP: `Fallout4+0x16C7539` = `sub_1416C7510 + 0x29`:

    mov r8, qword ptr [rax]     ; rax = 0x10 → AV at address 0x10

`sub_1416C7510` is a `BSFlattenedBoneTree` visitor. Disassembly:

    +0x14  test rcx, rcx; je out   ; null-checks `arg1` (this) only
    +0x1A  mov rax, [rdx]           ; rax = *ctx[0]
    +0x29  mov r8,  [rax]           ; r8 = **ctx[0]  ← faulting

Walking up: caller at RVA `0x16BFFF0` is a tree-walker wrapper that
builds a 3-field `ctx` struct on its own stack from `arg2` of its
caller. Its caller at RVA `0x35F560` is the iterator. Inner loop:

    LOOP:
      mov rdx, qword ptr [rbx]   ; rdx = *current_slot_in_array
      add rdx, 0x10              ; rdx = (*slot) + 0x10  ← UNCHECKED NULL
      ...
      call frame_1               ; → sub_1416C7510 → AV when *slot == NULL

The iterator walks an `NiAVObject*` array and adds `0x10` (a member
offset) blindly to each slot value without null-checking. When
`*slot == NULL`, that becomes `0x10`. The downstream visitor
dereferences it as `ctx`, hits the AV at `+0x29`.

### Root cause

Cross-referencing frame 3's call chain (`[obj+0x140] + 0x10`) with
the M8P3 dossier (`re/M8P3_skin_instance_dossier.txt`):

- `BSGeometry+0x140` = `NiPointer<BSSkin::Instance>`
- `BSSkin::Instance+0x10` = bones_fallback head (`NiAVObject**`)
- `BSSkin::Instance+0x20` = bones_fallback count (`u32`)

The iterator is walking `bones_fallback` of a ghost-side BSSITF skin
instance. TTD memory inspection of the array showed 38 slots with
only slots 3 and 6 holding valid `NiNode*` (heap range matching
skel.nif joints) and the remaining 36 NULL. The half-NULL state is
not freed memory — it's the engine's local-actor rebind cycle
interrupted mid-populate (reset-then-populate pattern: clear all
slots, repopulate from the local actor's skel).

The ghost's body NIF was deep-cloned at inject (M9.5 path,
`clone_nif_subtree` via engine `vt[26]`), so its skin instance is
independent of the local player's. **Head and hands NIFs were not
cloned** — they share the engine's cached `BSFadeNode` + skin
instance with the local player. Cell-load triggers a rebind cycle on
the local actor's skin instances; the rebind nukes `bones_fb` slots
mid-flight. Because the instance is shared, the ghost sees the same
nuked array. The visitor in the same render pass hits NULL slot[0]
before the rebind populate completes. AV.

Vanilla NPCs don't trip this: every actor gets its own instance via
the engine's internal clone-on-spawn pipeline. Strada B's
`nif_load_by_path` returns the cached node directly; cloning is on
the caller, and the caller (the ghost injector) was missing it for
head and hands.

### Fix

Three layers, all in `fw_native/src/native/`.

**1. Engine-bug shield** (`skin_rebind.cpp`, `install_bone_iter_shield`).
MinHook detour on `sub_1416C7510` (RVA `0x16C7510`) entry. Validates
`*ctx >= 0x10000`; on the NULL+offset pattern, increments
`g_iter_shield_skips` and returns early without invoking the original.
Skipping a single visitor call is safe semantically — the function
is a tree-walk visitor; missing one slot drops one bone deformation
contribution at most, and only on slots that were already broken
before the hook fired. Counter exposed via
`get_and_reset_iter_shield_stats()` for periodic logging.

**2. Independent skin instances** (`scene_inject.cpp`, `inject_body_nif`).
Deep-clone of head and hands NIFs immediately after
`load_nif_and_apply` returns, mirroring the body clone path. Uses
`clone_nif_subtree` → engine `sub_1416BA800` DeepClone front-end →
`vt[26]` dispatch. After clone, drops the +1 ref on the shared
instance (engine cache keeps its own slot ref, so the shared node
stays alive for the local player). The ghost's head + hands now hold
skin instances the engine local-actor rebind never touches.

**3. Body in periodic re-apply** (`scene_inject.cpp`,
`on_bone_tick_message`). The 4 Hz `swap_skin_bones_to_skeleton`
re-apply loop, previously iterating only `g_attached_armor`, now
also walks the body root. `walk_for_swap` recurses into all child
geometries (body / head / hands BSSITFs and any attached armor), so
a single call covers the entire ghost subtree. Idempotent:
`niptr_swap` early-returns if the slot already holds the new value.

Diagnostic line emitted per 4 Hz tick when either counter is non-zero:

    [skin-shield] last-tick: swap_NULL_fills=N iter_AV_skips=M

`swap_NULL_fills` is informational (counts NULL slots encountered by
`swap_for_geometry`, no mutation). `iter_AV_skips` is the engine bug
shield's actual interception count. Production traces show steady
state `swap_NULL_fills=36` (= 36 NULL slots persisting in some
ghost-side BSSITF, harmless because the GPU doesn't read them) and
`iter_AV_skips=0` outside cell-load events; at cell-entry the
shield's counter spikes to 36–108 in a single tick (= 1×36 to 3×36,
= number of BSSITFs the engine rebind touched in the burst), then
returns to zero.

### B6.4 closes for free

Verifying the cell-entry fix on the Sanctuary terminal-house, peer A
hacked the entry-room terminal successfully. Peer B's terminal
flipped to unlocked immediately, no minigame prompt — exactly the
B6.4 behaviour scoped for a future wedge.

A successful terminal hack flips `ExtraLock` via the engine's
standard `ForceUnlock` (`sub_140563320`). The B6.3 v0.5.3
lock-state-sync detour already hooks that function (xref coverage:
lockpick minigame, **terminal hack**, key unlock, AI lock/unlock
package, perk auto-unlock, savefile load). Terminals are `REFR`s
with `ExtraLock`; the broadcast and receiver-apply paths are
identical to those for any other lockable REFR.

Result: B6.4 needed zero code. README milestone table moves to done;
the `lock_hook.cpp` header comment is updated to call out terminal
coverage explicitly.

### Files changed

C++:

- `fw_native/src/native/skin_rebind.h` — `install_bone_iter_shield`,
  `get_and_reset_iter_shield_stats`,
  `get_and_reset_swap_shield_stats` prototypes with dossier-style
  block comment.
- `fw_native/src/native/skin_rebind.cpp` — bone-iter shield detour
  (`hook_bone_iter` + `install_bone_iter_shield`), atomic counters,
  POD `seh_deref_void_ptr` helper, swap-shield diagnostic counter
  in `swap_for_geometry`'s NULL-slot branch.
- `fw_native/src/native/scene_inject.cpp` —
  - `inject_body_nif`: deep-clone head and hands NIFs after
    `load_nif_and_apply`; install bone-iter shield right after
    `install_world_update_hook`.
  - `on_bone_tick_message`: body root added to 4 Hz re-apply loop;
    diagnostic stats line emitted per tick.

Docs:

- `README.md` — Status section, milestone table B6.4 → done,
  Changelog summary section refreshed.
- `CHANGELOG.md` — this entry.

### Wire format

No protocol change. v12 stays.

**Tag:** `v0.5.6-b6.4-interior-crash-fix`.

---

## B6.3.1 v0.5.5 — Lock bootstrap flush fix (2026-05-09) — HOTFIX

### Symptom

After the v0.5.4 bridge fix landed, lock state sync appeared broken on
re-test: peer A picklocks a safe, peer B's safe stays visually locked.
First instinct was a B8-removal regression. It wasn't — the bug was a
latent oversight in B6.3 itself, exposed by the user retesting with
server-persisted lock state.

### Investigation

Steam-side fw_native.log showed the server's peer-join bootstrap
arrived correctly at boot:

    [16:48:45.025][DBG] net: LOCK_BCAST enqueued for main-thread apply
                        peer=server form=0xB0D1A ... locked=0

But there was no follow-up `dispatch: drained N lock ops` and no
`engine: apply_lock_op_to_engine` line. The op was queued but never
applied. Then ~8 seconds later:

    [16:48:53.488][INF] [main_menu] WndProc subclassed on hwnd=...
    [16:48:53.489][INF] dispatch: target hwnd set to ...

So the bootstrap LOCK_BCAST arrived *before* `set_target_hwnd` had
been called. `post_wakeup_lock()` short-circuits with
`if (!h) return;` when the hwnd is null, dropping the wake-up
PostMessage silently. The lock op stayed in the queue.

When the WndProc subclass install finally ran, `set_target_hwnd`
flushed the container, door, equip, and mesh-blob queues — but **not
the lock queue**. The B6.3 ship had simply forgotten to add the lock
flush block alongside the others. Lock op stayed forever undrained.

### Why it didn't bite during the original B6.3 demo

The first B6.3 live test ("Cassaforte si unlocka in entrambi i client,
corretto") happened to pick the lock *after* the WndProc subclass was
installed, so the runtime LOCK_BCAST hit the dispatch queue with a
valid hwnd and drained normally. The bootstrap-on-connect path was
never exercised because the server had no stored lock state on first
run. As soon as state accumulated in the server's
state_snapshot.json's `locks` section across sessions, every
subsequent peer connect tried to bootstrap and silently failed.

### Compounding side effect: server dedup

The first failed bootstrap leaves the receiver's engine in a stale
state (safe shows locked even though server thinks unlocked). When
the sender re-picks the lock at runtime, the new LOCK_OP carries the
same `locked=false` value the server already stored. Server dedup
(per the B6.3 commit message: *"if state matches stored, skip
rebroadcast"*) kicks in — no rebroadcast — and the receiver never
gets a runtime opportunity to fix its stale engine state.

So the user saw zero LOCK_BCAST entries on the receiver after a fresh
unlock attempt. Bootstrap was swallowed; runtime was dedup'd. Two
effects, single root cause.

### Fix

`fw_native/src/main_thread_dispatch.cpp` `set_target_hwnd` — appended
the same flush block that already existed for container, door, equip,
and mesh-blob, with a long comment block documenting why the bug
existed and what the symptom looks like in the log. ~12 lines added,
no behavior change to other paths.

### Files changed

- `fw_native/src/main_thread_dispatch.cpp` — lock queue flush in
  `set_target_hwnd`.
- `CHANGELOG.md` — this entry.

### Wire format

No protocol change. v12 stays.

### Bonus discovery during this hotfix's live test

The v0.5.4 B8 disable also incidentally fixed the B6.3 "Known residual"
about taking a weapon out of a synced lockable container freezing the
taker's main thread for ~7 s and silently killing the FO4 process.
Same root cause — B8's corrupted engine state — surfaced via two
different triggers: bridge cell stream (fixed in v0.5.4) and
container auto-equip (turns out fixed by the same disable). Confirmed
by spamming TAKE on multi-item synced safes during this v0.5.5
verification; no crash, antidupe (server-validated container ack
chain) holds under stress. README "Known limitations" entry removed.

**Tag:** `v0.5.5-b6.3.1-lock-bootstrap-flush`.

---

## B6.4-pre v0.5.4 — Bridge crash fix: B8 force-equip-cycle disabled (2026-05-08) — HOTFIX

Discovered while heading to a terminal to test B6.4 (terminal hack
sync): client A crashed deterministically when crossing the
Sanctuary→Red Rocket bridge at ~50 m from the bridge entrance.
Reproduced on both clients, every time. Vanilla FO4 (no DLL) walked
through cleanly, confirming the DLL was at fault.

### Investigation

Frida + WinDbg pinned the freeze: main thread parked forever inside
`WaitForSingleObjectEx(JobListMgr+0x60, INFINITE)` from `sub_140BD4CA0`
(BSJobs serving-thread wait). The hung JobList is `PostMainRenderJobList`.
A worker assigned to it had stopped signaling completion — silent thread
death, no AV captured by our SEH wrappers because the AV happened on a
worker our hooks weren't watching.

Hypothesis bisection (each disproven by live test):

1. `FW_LOG`/`FlushFileBuffers` contention with worker hooks — no, crash
   persists with `log_level=error` filtering all detour logs at
   `log.cpp:100` before any mutex.
2. M9 wedge-4 worker hooks (`nif_path_cache`, `bsgeo_input_cache`,
   `ni_alloc_tracker`, `clone_factory_tracker`) — no, crash persists
   with all four uninstalled. Modded weapons still display correctly,
   showing the witness pattern wasn't strictly needed for that.
3. Strada B SSN injection + SPAI weapon prewarm — no, crash persists
   with both `arm_injection_after_boot` and `arm_prewarm` skipped.
4. **B8 force-equip-cycle (`hooks/equip_cycle.cpp`)** — yes. Bridge
   works after disabling, every other hook restored.

### Root cause

B8 was a workaround landed during M8P3 for an old ghost-pointer-sharing
bug ("first equip after peer-join crashes"). The cycle ran a direct
engine call to `ActorEquipManager::UnequipObject` then `EquipObject` on
the Vault Suit at T+10s post-LoadGame, with non-standard arguments
(`stack_id=1` literal to skip the AV-prone `sub_140505440` stack
recompute path). The engine call AV'd internally on every boot —
caught by our SEH and hidden from the user (`[equip-cycle] EQUIP: SEH
caught — engine call faulted` in every fw_native.log, every session).
The half-completed equip left engine state subtly corrupted: stack
allocations partially started, refcount transitions in progress,
addon-array linkage broken at a level invisible during normal play.

Sanctuary indoor + nearby cells didn't trigger the corrupted code paths,
so the issue was dormant. The Sanctuary→Red Rocket bridge is heavy
exterior cell-streaming territory; one of the streamed cells re-invokes
the auto-equip pipeline (LOD swap or cell-load auto-equip), this time
on a BSJobs `PostMainRender` worker thread with no SEH protection.
AV → silent thread termination → JobListMgr never receives completion
signal → main thread `INFINITE` wait → frozen process.

The B6.3 commit message had documented the same symptom on a different
trigger (taking a weapon out of a synced lockable container also hit
"corrupted addon array, count ≈ 2.3 billion, base = null" inside the
auto-equip pipeline). Same root cause, different surface — both ride
on top of the engine state B8 leaves corrupted.

### Fix

Disabled B8 at both arm sites:

- `fw_native/src/hooks/main_menu_hook.cpp` — boot-time arm in
  `fw_wndproc` post-`FW_MSG_LOAD_GAME`.
- `fw_native/src/net/client.cpp` — peer-join re-arm in `PEER_JOIN`
  handler.

`hooks/equip_cycle.{h,cpp}` is left compiled but uninvoked, and the
`offsets.h` "B8 force-equip-cycle" block stays as archeological
reference + RE'd engine fn signatures.

### Side effects (verified live 2026-05-08)

- **Bridge works.** Both clients walked from spawn across the bridge to
  Red Rocket gas station with no freeze.
- **Modded weapons still display correctly on peer ghosts.** The M9
  witness pattern is event-driven on real engine equip events
  (`clone_factory_tracker` firing on `sub_1416D99E0`), independent of
  B8. Whenever a peer draws a weapon during play, the cycle fires and
  mods are captured. Confirmed live: modded 10mm pistol (silencer +
  long barrel) visible on peer ghost.
- **Clothes change no longer crashes either.** B8's original purpose
  ("clothes change crashes on first cycle") is also fixed — verified
  by spam-equip/unequip on both clients with no crash. The original
  M8P3 bug that B8 was patching has been resolved as a side effect of
  later M9 / pose-tx evolution that decoupled the ghost's bone state
  from the local player's BipedAnim pointer-sharing.
- **Apparel passively worn at LoadGame doesn't broadcast to peers.**
  Without the synthetic equip events B8 generated as a side effect,
  peer ghosts spawn naked. Items the local player actively equips
  during the session appear correctly via the standard pipeline; only
  items already worn at save load are missing. Tracked in Known
  Limitations.

### Future replacement scaffolded (NON TESTATO)

`fw_native/src/hooks/equip_announce.{h,cpp}` lays out an Option B
client-side apparel-bootstrap broadcast that doesn't go through the
engine equip path: passive enumeration of `PlayerCharacter::BipedAnim`
and emission of one `EQUIP_OP` per non-empty apparel slot via the
existing `enqueue_equip_op` API. Receiver pipeline (M9 wedge 2) needs
no changes. Compiles clean, NOT invoked at runtime, header banner
documents wire-up steps and the BipedAnim-enumeration TODO that needs
RE work before this can do real work. Reserved `WM_APP+0x52` =
`FW_MSG_EQUIP_ANNOUNCE_FIRE` in the canonical message map.

### Wire format

No protocol change. v12 stays.

### Files changed

C++:

- `fw_native/src/hooks/main_menu_hook.cpp` — B8 boot arm commented out
  with permanent post-mortem comment block (replaces the temporary
  `CRASH-HUNT 2026-05-08` marker from the bisect phase).
- `fw_native/src/net/client.cpp` — B8 peer-join arm commented out with
  short reference to the post-mortem in `main_menu_hook.cpp`.
- `fw_native/src/hooks/equip_announce.{h,cpp}` (NEW) — scaffolding for
  future apparel bootstrap. NON TESTATO. Not invoked.
- `fw_native/src/main_thread_dispatch.h` — reserved `WM_APP+0x52` for
  `FW_MSG_EQUIP_ANNOUNCE_FIRE` in the canonical message map.
- `fw_native/CMakeLists.txt` — added `equip_announce.cpp` (compiles,
  not invoked).

Docs:

- `README.md` — Known Limitations: added "peer ghost spawns naked at
  startup" entry.

**Tag:** `v0.5.4-b6.4-pre-bridge-crash-fix`.

---

## B6.3 v0.5.3 — Lock state sync (2026-05-08) — STABLE

When peer A picklocks a door, safe, weapon locker, or terminal-linked
container, peer B's matching REFR unlocks too — no minigame prompt on
B's side. Server persists last-known state per `(base_id, cell_id)`;
clients joining mid-session catch up via bootstrap `LOCK_BCAST` frames.

### Sender hook

Two narrow detours on the engine's canonical lock-state mutators:

- `sub_140563320` — ForceUnlock, RVA `+0x563320`
- `sub_140563360` — ForceLock,   RVA `+0x563360`

Both `void(__fastcall)(TESObjectREFR*)`. Coverage across decomp xrefs:
lockpick minigame, terminal hack, key unlock, AI lock/unlock package,
perk auto-unlock, savefile load. The detour runs the engine flip
first, reads the post-state from LockData (`sub_140563170` returns
`LockData*` or null; flag bit 0 at `+0x10` = LOCKED), then broadcasts
`(form_id, base_id, cell_id, locked, ts)` as a reliable `LOCK_OP`.
`tls_applying_remote` guards the recursive fire from receiver-side
apply, so no echo loop.

### Receiver apply

`apply_lock_op_to_engine` resolves the local REFR via
`lookup_by_form_id`, validates against `(base_id, cell_id)`, then
calls the Papyrus `ObjectReference.Lock`/`Unlock` binding directly:

`sub_141158640(0, 0, refr, locked ? 1 : 0, /*ai_notify=*/0)`

With `ai_notify=0` the binding flips ExtraLock, clears partial-pick,
refreshes visuals, and skips the minigame, key consumption, and AI
events. Allocates ExtraLock if the REFR doesn't have one yet.

### Wire proto v12

- `LOCK_OP` (`0x0260`) + `LOCK_BCAST` (`0x0261`)
- `LockOpPayload`        = `<IIIBQ` = 21 B
- `LockBroadcastPayload` = `peer_id(16)` + 21 = 37 B

### Server persistence

`ServerState.lock_state` keyed by `(base_id, cell_id)`. Dedup: if the
incoming state matches what the server already has, skip rebroadcast.
This silences the savefile-load fire that would otherwise hit every
locked REFR on cell-load. Snapshot format v4 adds a `locks` JSON
section; v3 snapshots still load fine (empty `lock_state`).

Peer-join bootstrap: server replays every stored lock state as
individual `LOCK_BCAST` frames (peer_id="server") so a fresh client
sees correct state for every previously-cracked container.

### Bug fixed mid-session

First test silently dropped `LOCK_BCAST`. Cause: `LockWorldState`
wasn't imported in `net/server/main.py`, so `_handle_lock_op` raised
`NameError` inside the outer try/except — logged but didn't broadcast.
One-line import fix; 7/7 server integration tests pass.

### Files changed

C++:
- `fw_native/src/offsets.h` — 5 lock RVAs + LockData flag offset
- `fw_native/src/net/protocol.h` — `PROTOCOL_VERSION` 11→12, opcodes,
  payloads
- `fw_native/src/hooks/lock_hook.{cpp,h}` — ForceUnlock + ForceLock
  detours
- `fw_native/src/engine/engine_calls.{cpp,h}` —
  `apply_lock_op_to_engine` via Papyrus binding
- `fw_native/src/main_thread_dispatch.{cpp,h}` — `PendingLockOp` +
  `FW_MSG_LOCK_APPLY` (`WM_APP+0x51`) + drain
- `fw_native/src/net/client.{cpp,h}` — `enqueue_lock_op` +
  `LOCK_BCAST` dispatch
- `fw_native/src/hooks/install_all.{cpp,h}` — install + summary flag
- `fw_native/src/hooks/main_menu_hook.cpp` — WndProc route
- `fw_native/CMakeLists.txt` — `lock_hook.cpp` source

Python:
- `net/protocol.py` — mirror v12 + payloads
- `net/server/main.py` — `_handle_lock_op` + `_send_lock_state_bootstrap`
- `net/server/state.py` — `LockWorldState` + `lock_state` table
- `net/server/persistence.py` — v4 snapshot with `locks` section

### Known residual

Taking a weapon out of a synced lockable container (e.g. a safe one
peer just deposited everything into) can freeze the taker's main
thread for ~7 s in the engine's auto-equip pipeline, then the FO4
process dies silently. Lock and container sync apply correctly up to
that point — the issue surfaces in the receiver's M9 `EQUIP_BCAST`
resolver, which reads a corrupted addon array (count ≈ 2.3 billion,
base = null) for the auto-equipped weapon form. Likely a pre-existing
M9 receiver fragility that B6.3's heavier sync traffic exposes.
Tracked separately; not blocking B6.3 ship. Workaround for now:
deposit / take non-weapon items only.

**Tag:** `v0.5.3-b6.3-lock-state-sync`.

---

## B6.1 v0.5.2 — Cell-aware ghost transitions (2026-05-08) — STABLE

When a peer crosses a cell boundary (entering an interior, fast-travel,
worldspace switch), the ghost on the remote client now stays in sync.
Co-op inside the same interior works too: both peers see each other's
ghost in the same room.

### Root cause

The server pos validator caps speed at 2500 u/s. A cross-cell teleport
is ~120k units in 50 ms ≈ 2.4 M u/s — every POS_STATE got rejected as
cheat, so the ghost stayed pinned at the last accepted exterior pos
(the door I had just walked through).

### Fix

- **Wire proto v11** — `cell_id` (u32) added to `PosStatePayload`
  (32→36 B) and `PosBroadcastPayload` (48→52 B). Sender reads
  `PlayerCharacter.parentCell.formID`; server forwards.
- **Validator bypass** — when `incoming.cell_id != session.last_pos.cell_id`
  and both are non-zero, accept as baseline reset. Legit cell change,
  not cheat. Pre-v11 senders (`cell_id == 0`) keep the standard speed
  gate intact, so back-compat is clean.
- **Receiver stays simple** — bind ghost to peer coords as before. No
  manual cull / detach / hide. Cross-cell distance pushes the ghost
  outside the local frustum naturally; same-interior co-op puts both
  peers in the same coord frame so the ghost is correctly placed
  relative to whoever is watching.

### What I tried first that didn't work

I burned ~2 hours on the receiver side before checking the server.
Tried, in order:

1. **NIAV_FLAG_APP_CULLED on body BSFadeNode root** — `BSFadeNodeCuller`
   (vtable RVA `0x14290D088`) ignores the bit at root level.
2. **`body.local.translate = (1e7, 1e7, 1e7)`** — `BSFlattenedBoneTree`
   caches bone matrices independently from the BSFadeNode hierarchy,
   skin pipeline kept rendering at the original place.
3. **Detach body from World SceneGraph parent** — skin pipeline
   iterates `BSSkin::Instance` independently of scene-graph attachment.
4. **Recursive APP_CULLED on every leaf in the body subtree** — still
   visible.

All four were wasted cycles. The diagnostic that mattered was sitting
in the log the whole time: peer B's `pos_bcast` counter stayed pinned
at 1303 across the whole period peer A was inside, while `pose-rx`
ticked at 20 Hz normally. Net traffic was dropping pos but not pose —
the validator was the only piece that filtered pos differently.

**Lesson**: counters / state / log deltas first, code later.

### Files changed

- `fw_native/src/net/protocol.h` — `PROTOCOL_VERSION` 10→11; `cell_id`
  on the two pos payloads.
- `fw_native/src/hooks/player_pos_hook.cpp` — sender reads
  `parentCell.formID`.
- `fw_native/src/net/client.{h,cpp}` — receiver stores `cell_id` in
  `RemotePlayerSnapshot`.
- `fw_native/src/native/scene_inject.cpp` — `on_pos_update_message`
  back to a plain coord write; comment block documents the four failed
  hide attempts as memory.
- `net/protocol.py` — mirror v11 layout.
- `net/server/main.py` — forwards `cell_id` in broadcast.
- `net/server/validator.py` — cell-change baseline reset.

**Tag:** `v0.5.2-b6.1-cell-aware-ghost`.

---

## M9 v0.5.1 — M9 closed: every weapon family confirmed (2026-05-08) — STABLE

Full pass across the weapon roster after the v0.5.0 demo recording
showed rifles working when the v0.5.0 changelog still flagged them
as pending. Every family I tested renders correctly on the ghost
with mods applied:

- Pistols — 10mm, handmade
- Sniper rifle
- Assault rifle
- Hunting rifle
- Combat shotgun
- Combat rifle
- Minigun
- Fat Man
- Laser weapons
- Plasma weapons

Receivers, magazines, scopes, suppressors, grips, barrels — all
replicated through the same v0.5.0 BSConnectPoint pipeline. No code
changes; the v0.5.0 attach path already covered everything.

The "rifles render invisible" line in the v0.5.0 entry was a testing
gap, not a real bug. I had only validated pistols + handmade before
shipping; deeper coverage during the demo recording, then a proper
roster pass at the start of this session, confirmed full coverage.

**M9 is closed.** All five wedges done across all firearms (and on
top of clothing, body cull, ARMA tier, Vault Suit cycle stability).
Next session moves on to B6 wedges (lights, locks, terminals) and
eventually B6.5 NPC pose sync — the real "co-op chat → playable
multiplayer" turning point.

**Tag:** `v0.5.1-m9-closed`.

---

## M9 v0.5.0 — modded weapons visible on ghost (pistols) (2026-05-07) — STABLE

Pistols with mods now render correctly on the remote ghost: peer A
equips a 10mm with a reflex sight, suppressor, heavy receiver and
extended mag, and peer B sees the exact same configuration in A's
hand on the ghost. All mod parts visible, animated with A's pose,
geometry fully assembled by the engine itself.

As far as I can tell this is the first time it has been done in the
FO4 multiplayer modding scene; previous attempts (Fallout Together,
F4MP) never reached this point.

**Demo:** https://youtu.be/r34D4IL7wAk — clothes, armor, and modded
firearms (10mm pistol, assault rifle, hunting rifle) replicated on
both clients side-by-side.

### What was hard

The engine's weapon-mod assembly is not driven by any user-callable
"apply this OMOD list to this NiNode" function. I went through several
plausible designs before finding the one that actually works:

- **Synthetic `TESObjectREFR` + `vt[170]`** — refuted: `vt[170]` is just
  a flag setter on the REFR. The actual NIF load is run by a
  `NewInventoryMenuItemLoadTask` inside the Pipboy's
  `Inventory3DManager`, which I'd have to recreate end-to-end.
- **Direct `sub_1404580C0` sync load** — refuted: it returns a stock
  NIF clone, with no OMOD context.
- **BSModelProcessor post-hook reading the OIE** — refuted by live
  test: the loaded weapon NIF carries no `BGSObjectInstanceExtra` in
  its extra-data chain, so the OMOD-apply branch in the post-hook
  never fires. The static decomp suggested it would, but the live
  receiver path doesn't reach it.
- **`find_node_by_name` + `AttachChild` driven by INNT** — refuted by
  the 4-agent debate: the engine doesn't match by NiNode name for OMOD
  attach, and the INNT property defaults to the literal string
  `"Default"` for almost every vanilla receiver-replacement OMOD.
- **Receiver-side primer (Baton attach+detach + 500/100/50 ms refresh
  schedule)** — refuted: didn't fix the first-equip render lag.

### What actually works

Per-OMOD attach is `sub_140434DA0(omod_form, base_BSFadeNode,
placeholder_or_NULL, flags)` (RVA `+0x00434DA0`). It reads the OMOD's
`TESModel.modelPath` at `OMOD+0x50`, loads the sub-NIF via
`sub_1417B3E90`, deep-clones via `sub_1416BA8E0`, registers materials
via `sub_140255BA0`, then attaches via `sub_14186E960`.

The attach helper `sub_14186E960` is **BSConnectPoint pairing**, not
`NiNode::AttachChild`. The base weapon NIF authored by Bethesda carries
a `BSConnectPoint::Children` BSExtraData array on its root (entries
like `"Pistol10mmReceiver"`, `"WeaponMagazine"`, `"WeaponOptics1"`).
The mod sub-NIFs carry a matching `BSConnectPoint::Parents` array.
The engine matches the two arrays by string and parents the mod under
the right slot — all driven by data baked into the NIF files, not by
anything on the form.

`sub_14098C100(refr)` (RVA `+0x0098C100`) is the public convenience
entry that walks a REFR's OmodChain and calls `sub_140434DA0` per OMOD.
I don't use it directly because building the synthetic REFR with all
its preconditions would put me back at the failure mode the original
GAMMA path hit.

### Receiver pipeline

`ghost_attach_assembled_weapon` does this:

1. Resolve weapon `TESForm*` → `TESModel.modelPath`. The probe handles
   the case where the default mod redirects to `*RecieverDummy.nif`;
   the canonical fallback computes `Weapons\<folder>\<folder>.nif`
   and tries that first.
2. `nif_load_by_path` + `apply_materials` walker for the base.
3. Deep-clone via the vt[26] wrapper `sub_1416BA800`, so the ghost
   has its own per-peer instance and the cached NIF the local player
   uses doesn't get polluted.
4. Attach the base clone to the ghost's WEAPON bone.
5. For each OMOD form id: `lookup_by_form_id` → check
   `formType == 0x90` → `sub_140434DA0(omod, base_clone, NULL, 0)`.
   The engine takes care of the rest.

### Sender-side auto re-equip cycle (off-by-one fix)

The first equip of a modded weapon rendered on the ghost as either
stock or as the previous weapon — one event behind. Receiver-side
primers and refresh schedules all failed to fix it.

The fix mirrors a workaround I noticed manually: equipping a Baton
first and then the modded weapon makes the modded weapon render
correctly. So the sender now does this automatically.

50 ms after the user's `EquipObject` fires, the sender's detour
spawns a worker that posts `WM_APP+0x4F`. The handler sets a TLS
guard and calls `UnequipObject(actor, form, slot=0)` and
`EquipObject(actor, form, …)` for the same form. The TLS guard
prevents the cycle from re-scheduling itself, but events still go
out on the wire. The receiver gets `EQUIP X / UNEQUIP X / EQUIP X`
and applies each normally — the second `EQUIP X` is the one that
renders correctly.

A message-id collision cost me an afternoon: my first
`FW_MSG_AUTO_RE_EQUIP` constant was `WM_APP+0x4C`, the same as
`FW_MSG_EQUIP_APPLY`. The `WndProc` dispatcher matched the first
`if (msg == ...)` line and routed every auto-cycle `PostMessage` to
`drain_equip_apply_queue` instead of the real handler. The cycle was
scheduled fine but never fired. Now at `WM_APP+0x4F`. Reminder for
next time: `grep` every `FW_MSG_*` constant before adding a new one.

### Net cleanup

- `MAX_RETRANSMITS` 8 → 32. Bursty equip-cycle traffic was killing
  the channel inside ~11 s of relay hiccup; ~60 s tolerance now.
- Mesh-blob shipping disabled (`SHIP_LEGACY_BLOBS = false` in
  `weapon_capture::finalize_locked`). The v0.4.0 chunked mesh-blob
  payload was the biggest reliable-traffic generator and is no
  longer needed — everything I need rides in the EQUIP_OP tail.
- OMOD form ids now travel inline in `PendingEquipOp`, not via a
  global stash. The old global-stash design had a race: if a refresh
  fired 500 ms after the original equip, it could pick up the next
  weapon's mods because the stash had been overwritten in the meantime.

### Receiver UNEQUIP filter

`ActorEquipManager` fires `Equip(new) → Unequip(new from slot 0x4334D)
→ Unequip(old from 0x4334D)` as part of its own swap-into-slot
pattern. Before the fix, the middle `Unequip(new from 0x4334D)`
matched the slot and wiped the just-attached weapon ~7 ms after attach
(live trace 06:34:47.780 → .787). The drain now skips `UNEQUIP` ops
with `slot_form_id == 0x4334D` (the `kReadiedWeapon` BGSEquipSlot).
Player-initiated unequips arrive with `slot_form_id = 0` and pass
through.

### Files changed

- `fw_native/src/native/scene_inject.cpp/h` — new
  `ghost_attach_assembled_weapon`, `seh_call_omod_attach` POD
  wrapper, transient-slot filter notes; removed obsolete
  `run_baton_primer` and the receiver-side primer cycle.
- `fw_native/src/hooks/equip_hook.cpp/h` — `tls_in_auto_re_equip`,
  `schedule_auto_re_equip`, `on_auto_re_equip_message`,
  `FW_MSG_AUTO_RE_EQUIP = WM_APP + 0x4F`.
- `fw_native/src/main_thread_dispatch.h/.cpp` — inline OMOD fields on
  `PendingEquipOp`, drain routes EQUIP through the new path with
  legacy fallback, transient-slot filter on UNEQUIP.
- `fw_native/src/net/client.cpp` — EQUIP_BCAST decode fills
  `op.omod_form_ids` inline; `set_peer_omod_forms` gated on
  `is_equip`.
- `fw_native/src/hooks/main_menu_hook.cpp` — `WndProc` dispatch for
  `FW_MSG_AUTO_RE_EQUIP`.
- `fw_native/src/native/weapon_capture.cpp` — `SHIP_LEGACY_BLOBS =
  false`.
- `fw_native/src/net/reliable.h` — `MAX_RETRANSMITS = 32`.

### Dossiers (`re/`)

- `COLLAB_ALPHA_equip_chain.md` — top-down equip pipeline trace.
- `COLLAB_BETA_unequip_chain.md` — BipedAnim slot table layout,
  `slot[+0x40]` swap primitive `sub_1402C9BA0`.
- `COLLAB_GAMMA_alt_paths.md` — Inventory3DManager / WorkshopMenu
  synthetic REFR pattern (later refuted).
- `COLLAB_DELTA_synthetic_refr.md` — TESObjectREFR vtable map.
- `COLLAB_FOLLOWUP_vt170.md` — vt[170] decoded as flag-setter.
- `COLLAB_FOLLOWUP_loaded3d.md` — `*(refr+0xF0)+0x8` confirmed for
  plain REFR loaded3D.
- `COLLAB_FOLLOWUP_oie_construction.md` — manual
  `BGSObjectInstanceExtra` fabrication recipe (kept as fallback
  reference, not the active path).
- `COLLAB_FOLLOWUP_sub1404580C0.md` — `sub_1404580C0` body decoded;
  the 4th arg is a `BSFixedString*` for SetName, not modelExtraData.
- `COLLAB_FOLLOWUP_pipboy_omod_apply.md` — Inventory3DManager task
  processor decoded; no factored OMOD applier inside.
- `COLLAB_FOLLOWUP_omod_apply_xref.md` — bottom-up xref hunt that
  found `sub_140434DA0` and the BSConnectPoint mechanism.
- `COLLAB_DEBATE_omod_apply_VERDICT.md` — independent verification
  of the bottom-up finding, 98% confidence.

### Pending (next session, M9 close)

Rifles (sniper / assault / hunting / shotgun) still render invisible
on the ghost. The same code path runs for them as for pistols, so the
failure is either in base path resolution (the canonical fallback may
not match every rifle family's authoring convention) or in the
BSConnectPoint authoring on the rifle base NIFs. I'll start by
dumping the rifle base subtree and checking what `BSConnectPoint::
Children` it actually carries.

Once rifles are visible, M9 closes with all five wedges done.

**Tag:** `v0.5.0-w4-modded-firearms-pistols`.

---

## M9 v0.4.2 — Vault Suit cycle stability via path-routed deep clone (2026-05-04) — STABLE

Closes four long-standing equip-cycle bugs on Vault Suit and unifies the
fix with yesterday's v0.4.1 universal armor pipeline. M9 itself is not yet
100% (w4 PROPER weapon mods is the remaining in-scope wedge), which is why
this is a 0.4.2 patch rather than a 0.5 milestone bump.

**Bugs closed (screenshot list):**

- **#1 VS cycle SEH crash** — engine call faulted on spam unequip/equip
  of Vault Suit after a few iterations. Root cause: ghost's
  `bones_pri[i]` array contained raw `+0x70` pointers into the local
  player's `BSFlattenedBoneTree`. When the local engine rebuilt its
  `BipedAnim` on each cycle, the FBT was freed → ghost's pointers became
  stale → AV at next render through `vt[4]` dispatch on freed memory.
  Previously papered over by the B8 boot-time force-equip-cycle (which
  warmed up `BipedAnim` allocator state on the LOCAL player only, not a
  real fix for the cross-actor sharing).
- **#2 Post-cycle body invisible** — local player's body sometimes
  disappeared on its own client after a Vault Suit re-equip. Root
  cause: the cached `MaleBody.nif` BSFadeNode is shared between local
  player and ghost. The body-cull `NIAV_FLAG_APP_CULLED` bit we set on
  the ghost's body BSSubIndexTriShape was visible to the local player
  too because both pointed to the same `BaseMaleBody:0` node.
- **#3 Post-cycle ghost VS disappears** — receiver client saw the peer's
  Vault Suit vanish from the ghost after the peer cycled their suit.
  Same shared-cache class as #2: the engine's cleanup pass on the local
  cycle invalidated the cached NIF tree the ghost was rendering from.
- **#4 Post-cycle T-pose statica** — ghost VS frozen in T-pose despite
  ghost moving (pose-rx still flowing). Root cause: shared BSFadeNode
  → shared `BSSkin::Instance.bones_pri[]` head pointer at `+0x28`. Our
  `swap_skin_bones_to_skeleton` rebound the ghost's skin to ghost
  skel.nif, but engine's per-cycle re-bind on the LOCAL actor wrote
  the local skeleton's bones back into the same array head → ghost's
  swap got immediately overwritten back to local-player skel pointers.
- **#5 OIE-driven ARMA tier** — already addressed by v0.4.1 PROPER, kept
  intact in this patch.

**Pipeline (path-whitelist routing in `ghost_attach_armor`):**

- **Vault Suit family** (any path containing `"Vault111Suit"` —
  case-sensitive against canonical resolver output, plus lowercase
  fallback) → DEEP-CLONE path. Manual NIF subtree walker covering
  `BSFadeNode` / `BSLeafAnimNode` / `NiNode` / `BSSubIndexTriShape` with
  manual `BSSkin::Instance` deep-copy (engine's `sub_1416D7B30` copy
  ctor AV'd in our context — replaced with explicit memcpy + bone-array
  alloc + per-bone refbump). Ghost owns an independent skin instance
  and an independent `skel_root`, so engine cleanup of the local
  player's cached `BSFadeNode` no longer dangles ghost pointers.
- **Everything else** (combat light/heavy, RusticUnderArmor jacket,
  Atom Cats, Raider Underarmor, helmets, sub-pieces, …) → SHARED path
  = v0.4.1 yesterday's pipeline. `nif_load_by_path` + apply_materials +
  `attach_child_direct` + `swap_skin_bones_to_skeleton` + body cull +
  M9.w2 snapshot/restore on detach. Combat heavy and winter coat
  verified visually on ghost; nothing about yesterday's render pipeline
  was touched.

**Body inject (`try_inject_body_nif`):** deep-clones `MaleBody.nif`
unconditionally on every ghost spawn. Same rationale as the VS clone —
ghost body owns an independent BSSITF, body-cull `APP_CULLED` bit no
longer bleeds across actors, body-cull contributor set tracking
(per-peer, M9.w3) is preserved.

**Periodic re-apply (4Hz in `on_bone_tick_message`):** walks all
attached armors and re-runs `swap_skin_bones_to_skeleton` with a silent
flag to suppress per-tick log spam. Neutralizes engine's local-actor
re-bind drift on the SHARED-path armors that don't get the clone
isolation. Covers combat + atomic + sub-pieces during local
unequip/equip churn.

**Why path-whitelist instead of geometry-type detection:**

The first attempt was `tree_has_bssitf() && !tree_has_bstrishape()` —
"homogeneous BSSITF" — on the assumption that the manual clone walker
worked for BSSITF and broke for BSTriShape. Empirically wrong: combat
heavy and RusticUnderArmor jacket are also homogeneous BSSITF (no
BSTriShape children) but their clones render invisible. Vault Suit is
the *only* mesh that survives our memcpy-based clone — likely because
its specific vertex layout and absence of certain D3D-resource
dependencies happen to tolerate a missing call to engine clone factory
helper `sub_1416D5600` (NiSkinPartition / D3D resource binding setup).
Combat / RusticUnderArmor / etc. require that helper and render
invisible without it. Path-whitelist is conservative: explicit list of
known-cloneable meshes, everything else stays on the proven shared
pipeline. To enable clone for a future custom mesh, add a `strstr()`
match in the routing block.

**Files:** `scene_inject.cpp/h` (clone walker, path routing, body
clone), `skin_rebind.cpp/h` (silent flag for periodic re-apply),
`ni_offsets.h` (BSFadeNode / BSLeafAnimNode / BSSITF / BSSkin::Instance
/ BSDynamicTriShape ALT vtables + sizes).

**Tag:** `v0.4.2-vs-cycle-stable`.

**Known residuals (deferred to next patches):**

- M9.w4 PROPER (mod parts on weapons) — `BSVertexDesc` RE blocker,
  same as v0.4.0 changelog. Last in-scope wedge before M9 close.
- B8 boot-time force-equip-cycle is now redundant for the VS crash but
  kept enabled (no harm) until M9 closes fully — provides defense in
  depth for the few remaining engine state-warmup edge cases on first
  spawn.

**Out of M9 scope (post-project):**

- Material swap variants (rusty/clean raider, paint jobs) — same OIE
  pattern at shader/material level, addressable via `BSMaterialDB` swap
  path used by `nsInventory3DManager::*MaterialSwap*Task`. Removed from
  active roadmap 2026-05-04 — deferred until project complete.

**Re-scoped (not M9, belongs to world sync B6):**

- Power Armor — fundamentally world-state, not an equip event. The PA
  chassis is a REFR sitting in the world with its own state (location,
  per-piece HP, fusion core); the player-in-PA state is the chassis
  attached to a player. Both visibilities require sync in both clients.
  Moved to B6 as a new wedge 2026-05-04. Will be addressed inside the
  B6 world-sync milestone, not as an M9 residual.

---

## M9 v0.4.1 — wedge 2 PROPER + wedge 3 body cull (2026-05-03) — STABLE

Two long-standing M9 limitations closed in this patch.

**M9.w3 — Biped slot body cull** (fixes ghost body z-fighting under
full-body armor like Vault Suit / Power Armor / Synth Armor):

- RE'd `TESObjectARMO+0x1E8` = `bipedObjectSlots` u32 bitmask (HIGH×HIGH
  consensus from 2 independent IDA agents, see
  `re/M9w3_armo_biped_AGENT_A.md` / `_B.md`).
- RE'd `BSSubIndexTriShape` vtable RVA `0x2697D40` (HIGH×HIGH, agents A+B).
- Walker `find_first_bssitf` populates a cached `g_ghost_body_geom` pointer
  at body inject time (before any armor attaches → unambiguous body
  geometry pick). When peer equips a slot-3 BODY armor, `NIAV_FLAG_APP_CULLED`
  bit is set on the cached node → body hidden under armor mesh.
- Per-peer contributor set tracking handles concurrent BODY armors and
  guarantees correct restore on last-detach.
- Cache invalidated in `detach_debug_cube` together with `g_injected_cube`
  so cell-change re-injects start from a clean state.
- `BSSUBINDEXTRISHAPE_VTABLE_RVA` constant added to `ni_offsets.h`.

**M9.w2 PROPER — OMOD-driven ARMA tier selection** (fixes Combat Armor
Heavy/Mid upgrades rendering as Lite on ghost):

- RE'd engine ARMA selection function `sub_1404626A0`
  (`TESObjectARMO::ForEachAddonInstance`) at RVA `0x4626A0` — HIGH×HIGH
  consensus from 2 independent IDA agents
  (`re/M9_arma_select_AGENT_A.md` / `_B.md`).
- Algorithm: walk `armo+0x2A8[]` addons (count `armo+0x2B8`, stride 16,
  `ARMA*` at `entry+8`); per-entry priority WORD at `entry+0`; selection
  rules — priority 0 always invoked, priority == reqPrio invoked exact,
  else highest priority ≤ reqPrio.
- Reimplemented PrioritySelect in `resolve_armor_nif_path` with pass-3
  fallback (accept all addons when priority filter empty) so forms
  with non-zero default priority still resolve.
- Gender-fix: extended `path_is_female_variant` to recognize `F_<X>`
  filename convention (Combat Armor `F_Torso_Lite.nif` etc.) — previously
  scored 0 same as `M_Torso_Lite.nif`, resolver picked F arbitrarily.
- Sender-side priority extraction via TTD-confirmed `object[1]`
  (= `BGSObjectInstance.extra` field of `EquipObject` arg). Initial v10
  attempt used `extract_equipped_mods` inventory walk, which returned a
  DIFFERENT InstanceData pointer (default unmodded, priority=0). TTD
  trace 2026-05-03 proved engine passes `r8 = object[1]` to the build-
  holder helper, and that pointer holds the OMOD-applied priority at
  `+0x56`. Fix is 1-line: `safe_read_item_extra(object)` instead of
  inventory-derived OIE.
- Wire protocol bumped v9 → v10. Added `u16 effective_priority` to
  `EquipOpPayload` (21→23 B) and `EquipBroadcastPayload` (37→39 B).
  Server pure relay. Receiver feeds priority to PrioritySelect filter.

**Why this was hard**: agents initially mis-identified `sub_140436820` as
"build [ARMO*, InstanceData*] holder" — actual disasm showed when OIE
non-null the function leaves `holder[1] = OIE` (no InstanceData allocation).
The engine maintains MULTIPLE InstanceData allocations per inventory item:
one default (priority=0) and one OMOD-applied (priority=N). Inventory walk
returns the default; only `BGSObjectInstance.extra` (the engine's
explicit context pointer per equip event) routes to the right one. TTD
side-by-side comparison of engine's `r8` arg vs our extracted OIE
revealed the discrepancy.

**Known residuals (deferred to next patch)**:

- Texture / material variants (rusty vs clean armor) — same OIE pattern
  but on shader/material level. M9.w6 wedge.
- Vault Suit cycle SEH crash persists — engine internal AV during re-equip
  corrupts state; ghost body / armor visibility breaks post-cycle. Mitigated
  by anti-rottura auto-cycle at startup. Investigation deferred (needs
  dedicated TTD trace).

**Files**: `offsets.h`, `ni_offsets.h`, `scene_inject.cpp/h`, `equip_hook.cpp`,
`main_thread_dispatch.cpp/h`, `protocol.h`, `client.cpp/h`, `protocol.py`,
`server/main.py`. RE artifacts under `re/M9w3_*.md`, `re/M9_arma_select_*.md`.

---

## M9 v0.4.0 — wedge 4 foundation: weapon mesh replication on ghost (2026-05-01) — PoC, NEEDS DEEP POLISH

▶ **[Video coming soon]**

Wedge 4 (BGSMod / weapon mod sync) had a chicken-and-egg dependency: modded
weapons in FO4 are runtime-assembled from N sub-component NIFs (receiver +
barrel + scope + grip + …) into a single BSFadeNode tree. There is NO
canonical "AssaultRifleWithCompensatorAndScope.nif" on disk — the engine
composes it dynamically post-`EquipObject`. Replicating that on the peer's
ghost requires either (a) capturing the assembled BSGeometry leaves on the
sender and replaying them on the receiver, or (b) the receiver doing the
same runtime assembly itself.

This patch ships the FOUNDATION for path (a) — wire format, sender capture,
receiver state machine, smart NIF path resolution. **The full mod
replication is NOT achieved.** Modded weapons appear as their stock base
NIF; some assembled-only weapons show only one sub-component. The
infrastructure is there for v0.5+ work to plug in proper mesh
reconstruction.

### Why this was extremely hard — context for v0.5+ work

The PoC took a multi-hour deep-dive iteration cycle, and most of the time
was spent fighting hidden engine constraints. Documenting them so the next
attempt has the rake-stepping done already.

1. **Runtime-assembled weapons have no static NIF**. Engine composes the
   `Weapon (form_id)` BSFadeNode tree from N sub-NIFs at EquipObject time.
   The TESObjectWEAP `TESModel` slot at `+0x78` returns
   `Weapons\10mmPistol\10mmRecieverDummy.nif` for the pistol — a literally
   empty placeholder (no BSGeometry under it, confirmed via donor probe).
   The proper `10mmPistol.nif` is found indirectly via bgsm-derived path
   from the assembled mesh data. The engine probably reads from a struct
   slot Bethesda only populates at runtime; an offset probe in
   `[0x60..0x180]` step 8 didn't reveal a non-Dummy slot.

2. **Walker race with engine async weapon assembly**. Post-
   `g_orig_equip`, the engine is STILL composing the weapon tree on a
   worker thread. Synchronous walker call right after returns 0 meshes
   most of the time. Required `arm_deferred_mesh_tx(form, 300ms)` worker
   pattern that posts `WM_APP+0x4E` to the main thread WndProc; handler
   re-runs the walker once assembly has settled. ~70% capture success
   rate empirically. Cap on concurrent workers (4) prevents thread spam
   on rapid equips.

3. **BSVertexDesc proprietary format — donor shader sharing crashes**.
   Tried the elegant approach: load the base NIF (donor), grab its
   BSGeometry's `shader+0x138` and `alpha+0x130`, refcount-bump, share
   into our factory-built BSTriShape. CRASHED in render walk every time.
   Diag dump revealed donor's `vd=0x1B00000430205` (stride 20) vs our
   factory's `vd=0x1700000503206` (stride 24). The GPU vertex shader
   compiled against donor's layout reads attributes at wrong offsets in
   our buffer → reads garbage → access violation. Fixing requires full
   RE of all 8 bytes of `BSVertexDesc` (top byte flag bits + middle
   byte stream offsets, not just the low-nibble stride). Out of scope
   for this iteration; deferred to v0.5+.

4. **Wire format chunking — silent server fan-out drop**. Sender split
   blobs at `MESH_BLOB_OP_CHUNK_DATA_MAX = 1388` (= MAX_PAYLOAD - OP
   header). Server re-emits as `MESH_BLOB_BCAST` which has a 16-byte
   `peer_id` prefix — total payload = 28 + 1388 = 1416 > 1400 →
   `MeshBlobChunkBroadcastPayload.encode()` raises `ProtocolError`,
   silently dropped at server. Receivers got NOTHING. Took a Python
   roundtrip test to identify. Fix: sender always sizes chunks at
   1372 (BCAST-safe).

5. **Vault Suit channel saturation** — chasing the "is weapon" gate. The
   first `!wire_mods.empty()` filter (intended to mean "modded weapon")
   triggered for Vault Suit (`0x1EED7`) because it had a legendary OMOD.
   Walker on bipedAnim grabbed 15 BSGeometry leaves of body + clothing
   (≈106 KB blob, 77 chunks reliable) → saturated UDP reliable channel
   → `reliable_recv` froze at 3747, peer events stopped flowing → ghost
   stuck on previous weapon (baton). Required form-type filter
   (`is_weapon_form` via TESModel `Weapons\\` heuristic) to exclude
   armor entirely.

6. **Multiple shader/material binding strategies, all crashed**:
   - `bgsm_load + mat_bind_to_geom` (the v17.1 walker pattern): crashed
     on render walk; the `mat_bind_to_geom` (`sub_142169AD0`) needs an
     existing shader to bind into and silently no-ops with shader=NULL.
   - Manual `bslsp_new` + `bgsm_load` + swap material at `shader+0x58`
     + write shader to `geom+0x138`: crashed in next render frame.
     Suspected refcount management on shared default material destruction
     when the shader was destroyed mid-frame.
   - `apply_materials_walker` post-attach with shader=NULL: walker
     skipped (no shader to read bgsm path from at `shader+0x10`).
   - **Working approach** (this PoC): bypass factory entirely. Load the
     base weapon NIF directly via `nif_load_by_path` with FADE_WRAP +
     POSTPROC. Engine itself binds shader+material+textures correctly.
     Cost: only the BASE NIF visible — no mod parts.

7. **bgsm-to-NIF path heuristic varies wildly by weapon**:
   - 10mm pistol: `Materials\Weapons\10mmPistol\10mmPistol.bgsm` →
     `Weapons\10mmPistol\10mmPistol.nif` ✓ (canonical, folder ==
     filename)
   - Double-barrel shotgun: meshes have `ShotgunShell.bgsm` (the shell
     casing), `ShotgunStock.bgsm`, never `Shotgun.bgsm` →
     wrong NIF derived.
   - Assault rifle: `MachineGunBarrelLong01.bgsm`,
     `MachineGunReceiver01Dielectric.bgsm`, `308Casings.bgsm` —
     all sub-component names. Folder is `MachineGun`. **Required
     folder-derived canonical fallback**: for each unique parent folder,
     construct `Weapons\<folder>\<folder>.nif`. Catches `MachineGun.nif`,
     `Shotgun.nif`, `HuntingRifle.nif`. Even so, hunting rifle still
     fails — the proper NIF doesn't follow the canonical convention.
   - Cross-form contamination: walker sometimes captures bgsm from a
     PREVIOUSLY-equipped weapon still in bipedAnim subtree (observed:
     assault rifle equip captures hunting rifle .308 ammo bgsms).

8. **Multi-attach state corruption** — initial implementation tracked
   `g_attached_weapons[peer][form_id]` per-form. Switching weapons
   without explicit UNEQUIP left old form's NIF attached as sibling of
   new form's NIF under the same WEAPON bone → both rendered (visual
   mess). Required full state machine refactor: single slot per peer
   (`g_ghost_weapon_slot`), atomic transitions, mutex-guarded.

9. **Downgrade race** — once we had bgsm-derived path working for
   modded pistol, EQUIP_BCAST arriving AFTER MESH_BLOB would re-call
   `ghost_attach_weapon` with the legacy resolve path (RecieverDummy)
   → overwrote the proper NIF with placeholder → ghost weaponless.
   Required downgrade-protection in `ghost_set_weapon`: refuses to
   replace a non-placeholder NIF with a placeholder for the same
   form_id.

10. **Multiple bisects, each one masking deeper issues**. Iteration
    pattern: deploy fix → user tests → new symptom → bisect (disable
    last change, see if symptom changes) → identify culprit → re-fix.
    Often a single "fix" required 3-4 bisect rounds because earlier
    "fixes" had set up state that masked the root cause. The full
    iteration loop ate ~6 hours of focused debugging.

### Pipeline shipped

**Wire format (protocol v9)**:
- New message types `MESH_BLOB_OP` (0x0250, client→server) and
  `MESH_BLOB_BCAST` (0x0251, server→peers).
- Each frame carries one CHUNK of a serialized mesh blob (1372 B max
  chunk_data — sized for BCAST overhead so server can relay verbatim
  without re-fragmentation).
- A blob is a linear concatenation of N mesh records; each record:
  `m_name` + `parent_placeholder` + `bgsm_path` + `vert_count` +
  `tri_count` + `local_transform` + `positions[3*vc]` + `indices[3*tc]`.
- Receiver buffers chunks keyed on (peer_id, equip_seq), decodes once
  all arrive. 5 s timeout for incomplete reassemblies. Bitmap-based
  duplicate detection. Roundtrip tests added (22 new pytest cases —
  `test_protocol.py::TestMeshBlob*`).

**Sender mesh extraction**:
- `weapon_witness::snapshot_player_weapon_meshes()` walks the local
  player's bipedAnim WEAPON node, locates the assembled weapon
  BSFadeNode, then DFS-walks BSGeometry leaves.
- Per leaf: extracts `vert_count`, `tri_count`, `local_transform`,
  `m_name`, `parent_placeholder`, `bgsm_path`. Decodes positions
  from the packed half-prec stream via 3-level indirection on the
  `BSGeometryStreamHelper` at `clone+0x148` (full RE in
  `re/M9_w4_iter12_AGENT_analysis.md`).
- 300 ms deferred re-walk via `FW_MSG_DEFERRED_MESH_TX` worker
  thread.
- Form-type gate: only TESObjectWEAP forms with non-empty OMOD list
  trigger mesh-tx (excludes armor/ammo/clothing).
- Chunks cap 150 (≈200 KB/blob).

**Receiver state machine** (the centerpiece):
- `g_ghost_weapon_slot[peer_id] = {form_id, nif_node, nif_path}`
  — single slot per peer, mutex-guarded.
- `ghost_set_weapon(peer, form, candidate_paths[])` atomic transition:
  1. Try each candidate via `nif_load_by_path` until first success.
  2. Fall back to `resolve_weapon_nif_path` (legacy probe) if no
     candidate loads.
  3. Idempotent: same form + same path → no engine work.
  4. Downgrade protection: refuses to overwrite proper NIF with
     placeholder for the same `form_id`.
  5. Detach old + attach new + update slot atomically.
- `ghost_clear_weapon(peer, expected_form)` with form_id guard
  (no-op if peer already switched).
- All wire receivers (EQUIP_BCAST, MESH_BLOB_BCAST, UNEQUIP_BCAST)
  funnel through this API.

**Smart NIF path resolution**:
- Smart bgsm pick: per blob, walk all meshes' `bgsm_path`, pick the
  one matching canonical `Weapons\X\X.bgsm` pattern (folder name ==
  file basename).
- Folder-derived canonical fallback: for each unique parent folder
  in the blob's bgsm paths, construct `Weapons\<folder>\<folder>.nif`
  candidate. Catches assault rifle (MachineGun → MachineGun.nif),
  shotgun (Shotgun → Shotgun.nif), hunting rifle attempts.
- Sub-component bgsms as last-resort candidates.

**`resolve_weapon_nif_path` improvements**:
- Probe range extended `[0x60..0x180]` step 8.
- Generic case-insensitive "Dummy" filter (catches `RecieverDummy`,
  `DummyReciever`, `_Dummy_`, `*Dummy*` anywhere).

### Working scenarios (live-tested 2026-05-01)

- 10mm pistol (modded + stock): peer sees pistol on ghost, **stock
  visual** (no compensator/grip mods rendered).
- Baton (nightstick): visible, proper NIF.
- Fat Man: perfect.
- Grognak's Axe: visible (handle position slightly high — minor
  transform offset).
- Deathclaw Gauntlet: perfect.
- Missile Launcher: visible, half-textures broken.

### Known limitations — w4 PROPER not done

⚠️ **Status: foundation only. M9.w4 OFFICIAL = still TODO.**

- Modded firearms render as STOCK base NIF (no compensator, scope,
  custom barrel, etc. visible). The mod parts ARE captured in the
  wire data but the receiver doesn't reconstruct them.
- Heavily-modded assault rifles / shotguns: only ONE sub-component
  loads (e.g. shotgun shows only its wood stock; assault rifle only
  the barrel). The smart NIF resolution picks one candidate that
  loads, which is some sub-NIF rather than the assembled tree.
- Hunting rifle: invisible — neither smart pick nor folder-derived
  canonical finds a loadable NIF.
- Cross-form mesh contamination: walker sometimes captures bgsm from
  a previously-equipped weapon still in the bipedAnim subtree.

### What's needed for true w4

1. **Full RE of `BSVertexDesc`** (top byte + middle bytes + flag
   attributes, not just the stride nibble). Required to rebuild a
   factory-output BSTriShape that the engine's existing shaders can
   consume.
2. **Donor shader cloning with vd-aware patching**. Tried and
   crashed in this iteration; needs careful refcount + vertex layout
   matching.
3. **Mod NIF replay**: load each sub-component NIF (capture or derive
   paths), parent under a synthetic weapon root with correct
   `local_transform`s.
4. Or alternative architectural pivot: server-authoritative equip
   state + donor-actor approach — the GHOST becomes a real Actor with
   bipedAnim, receives equip via the same engine pipeline, runtime
   assembly happens identically on both clients. Multi-week refactor;
   deferred.

Tag: `v0.4.0-w4-foundation`.

---

## M9 v0.3.1 — peer-join re-broadcast + path scoring polish (2026-04-29) — STABLE / NEED MORE TESTING

Two follow-up patches on top of the wedge 1+2 PoC, addressing the two
non-cosmetic issues from the list:

### 1. Boot-timing race — peer-join re-broadcast

Problem: Client A starts first, runs its B8 force-equip-cycle ~10s post-
LoadGame. Cycle fires UNEQUIP+EQUIP for Vault Suit but no peer is
connected yet → broadcasts go nowhere. When peer B joins 5 minutes later,
B's ghost-of-A renders without clothing because A doesn't re-broadcast.
Receiver-side pending queue (which we already had) covers the symmetric
case but not this one.

Fix: `arm_equip_cycle_for_peer_join(1500)` — new public function in
`equip_cycle.cpp`. Called from `client.cpp::dispatch_message` on
`PEER_JOIN` reception. State machine extended: previously only allowed
`IDLE → ARMED`; now also `DONE → ARMED` for legitimate re-arming.
1500ms delay (vs 10s for boot) — engine is already in-world, no need
for the long settle. UNEQUIP+EQUIP broadcasts reach the just-joined peer
via the wedge 2 receiver pipeline and apply to their ghost-of-us.

Trade-off: 2s of "no clothing → re-equip" flicker on the LOCAL player
every time someone connects. Acceptable for correctness.

### 2. Path scoring — F<Uppercase> female detection + faceBones penalty

Two armor families resolved to wrong NIFs in the wedge 1+2 ship:

**Metal Torso `0x536C4`**: 6 candidates, all scored 0. Selected the
first found = `Armor\Metal\FToroso_Heavy_1.nif` (FEMALE — Bethesda's
convention is `F<PartName>` for female meshes, but my filter only
caught literal `_F.nif` suffix or `"female"` substring). Result: ghost
rendered female torso mesh on male body skel → mild visual mismatch.

**Gas Mask `0x1184C1`**: 4 candidates, all scored 0. Selected
`Armor\GasMask\MGasMask_faceBones.nif` — the variant with face anim
bones. swap_skin reported `failed=50` because face bones (eyebrow, lip,
eyelid, jaw, etc.) don't exist in our body-only `skel.nif`. Mask
rendered with bind-pose vertices → distorted shape.

Fixes (additive to existing scoring):
- `path_is_female_variant` extended: also detects basename starting
  with `F<UpperCase>` (e.g. `FToroso`, `FArm`, `FLeg`) — Bethesda's
  female-mesh prefix convention. False-positives on `Foliage`,
  `FrameMesh` etc. acceptable since those aren't armor.
- `path_is_face_bones` new filter: detects `faceBones` substring
  (case-insensitive). Penalty -8.
- New score table:
  - MALE 3rd-person → 0
  - MALE 1st-person → -5
  - faceBones variant → -8
  - FEMALE 3rd-person → -10
  - FEMALE 1st-person → -15

After fix:
- Metal Torso resolves to `MToroso_Heavy_1.nif` (score 0)
- Gas Mask resolves to `MGasMask.nif` (simple, score 0) instead of
  `MGasMask_faceBones.nif` (score -8)

### Status — STABLE / NEED MORE TESTING

Marker: things mostly work, but the  visual
inconsistencies between the local player's render and the ghost
rendition (local has fewer mesh pieces than ghost in some cases —
unclear if that's our resolver picking too many addons, the engine's
biped slot masking that we don't replicate, or weight-tier mismatch
across ARMA addons). Not blocking; documented for future iteration.

Tag: `v0.3.1-clothing-stable`.

---

## M9 wedge 1+2 — equipment sync between peers (2026-04-29)

▶ **[Video coming soon]**

Sender hooks `ActorEquipManager::EquipObject` / `::UnequipObject`, broadcasts
`EQUIP_OP` to server, server fans out `EQUIP_BCAST` to peers. Receiver looks
up the item form, walks `TESObjectARMO → TESObjectARMA → TESModel` for the
3rd-person NIF path, loads the NIF, attaches it as a child of the M8P3 ghost
body, and re-binds the armor's skin to the ghost's skel.nif so animation
propagates.

**Working scenarios** (live-tested 2026-04-29):
- Peer A equips Vault Suit / Raider Underarmor → Peer B sees it on A's ghost,
  animated
- Bidirectional A↔B sync within the same session
- Equipment changes mid-session (PipBoy → Inventory → equip/unequip)
- Multi-armor: equipping a different outfit replaces the previous

### Pipeline

**Sender side**: detour `ActorEquipManager::EquipObject` (RVA `0xCE5900`) and
`UnequipObject` (RVA `0xCE5DA0`).
- Filter to `actor.formID == 0x14` (local player only — NPC equip events
  would flood the network).
- Read item TESForm pointer from `BGSObjectInstance` arg, extract `formID`.
- Read slot `BGSEquipSlot.formID` if non-null.
- Enqueue `EQUIP_OP { item_form_id, kind, slot_form_id, count, ts }`.
- `tls_applying_remote` re-entry guard for forward-compat with wedge 3
  (currently unused — receiver doesn't call back into engine).

**Server**: pure fan-out (`net/server/main.py::_handle_equip_op`) — no
validation, mirrors `DOOR_OP` pattern from B6.1.

**Receiver side** (the heavy lift):
- Net thread: enqueue `PendingEquipOp`, post `FW_MSG_EQUIP_APPLY`
  (`WM_APP+0x4C`) to FO4 main window.
- Main thread `fw_wndproc`: drain queue, call `ghost_attach_armor` /
  `ghost_detach_armor`.
- `resolve_armor_nif_path`: walk `TESObjectARMO+0x2A8` (addon array, count
  at `+0x2B8`, stride 16 with `ARMA*` at entry+8). For each ARMA, probe
  candidate offsets `0x50, 0x90, 0xD0, 0x110, 0x150, 0x190` for embedded
  `TESModel` whose `+0x08` BSFixedString points at a 3rd-person NIF path.
- Score paths: prefer male 3rd-person (score 0) over male 1st-person
  (`-5`, arms-only mesh) and female variants (`-10` / `-15` — wrong
  bones for our `MaleBody.nif` ghost).
- Load NIF via `g_r.nif_load_by_path` with `NIF_OPT_FADE_WRAP | POSTPROC`
  (same as body load — POSTPROC triggers BSModelProcessor for material/
  texture resolution).
- `apply_materials` for shader+texture binding.
- `attach_child_direct(ghost, armor_node)` to add to ghost subtree.
- **Critical**: `skin_rebind::swap_skin_bones_to_skeleton(armor_node,
  cached_skel)` — re-binds the armor NIF's `bones_fb[i]` from the
  internal stub bones (loaded with the NIF, inert) to the GHOST's
  cached skel.nif joints. Without this, armor renders T-pose. With
  this, animation propagates from `pose-rx` to armor skinning naturally.

### Boot-timing race fix (pending queue)

When the local force-equip-cycle (B8) on a peer fires its UNEQUIP+EQUIP
broadcast, the OTHER peer's ghost might not yet be spawned (POSE_BROADCAST
hasn't started flowing). Without a queue these events would be permanently
lost.

`g_pending_armor_ops` is a per-peer FIFO deque of `{form_id, kind}`.
`ghost_attach_armor` / `ghost_detach_armor` enqueue when the ghost isn't
ready, then `flush_pending_armor_ops()` drains on `inject_debug_cube`
success. Order is FIFO so a UNEQUIP→EQUIP cycle drains correctly even
across the spawn boundary.

### Reverse engineering

- `re/M9_equipment_AGENT_A_dossier.txt`: original wedge 1 RE with sender
  hook signatures. Confirmed `a4-a5-a6` ARGUMENT ORDER differs between
  Equip and Unequip — yesterday's M9 hook attempt swapped them and
  introduced the 3-day crash class B8 papers over.
- `re/M9_w2_armo_layout.log`: ARMO struct layout at `+0x2A8/+0x2B8` from
  `sub_140462370` (FinalizeAfterLoad). 6 sub-component objects in ARMA
  (`+0x50, +0x90, +0xD0, +0x110, +0x150, +0x190` each 64 bytes).
  Empirical identification of male 3rd-person at `+0x50` from live test
  paths.
- `re/M9_w2_arch_hole.log`: dossier of REJECTED approaches:
  - `Inventory3DManager` (PipBoy 3D preview) — too coupled with the
    Scaleform menu infrastructure (requires `Inventory3DSceneRoot`
    wrapper class with vt[136], not a plain NiNode target)
  - `actor hijack` (Z.2, PlaceAtMe) — permanently shelved per project
    memory
  - Hooking `sub_140C45450` (engine attach task enqueue) — args are
    in-process NiNode pointers, not file paths, so cross-client
    replication impossible

### Known limitations

⚠️ **Status: PoC. Production polish pending.** This wedge ships a working
end-to-end pipeline but several sub-cases are documented unsupported:

1. **Limited NIF coverage tested**: Vault Suit (`0x1EED7`) and Raider
   Underarmor (`0x18E3F7`) confirmed end-to-end. Vault Suit shows
   clipping/compenetration patches on the ghost — bind-pose mismatch
   between `Vault111Suit_YanEdits` mesh and our `MaleBody.nif` skel.
   Raider Underarmor renders cleanly. Other outfits untested — expect
   variable results.

2. **Armor pieces ON TOP of outfits don't render visibly**: equipping
   e.g. Metal Arm armor (`0x4B933`) over Vault Suit succeeds at the
   network/attach level (logs show `armor-attach OK`) but the metal
   armor mesh is occluded by the vault suit's sleeve geometry — the
   engine's biped slot masking system would normally hide the suit's
   sleeve when arm armor is equipped, but we bypass that system and
   render BOTH meshes simultaneously → z-fighting / inner mesh
   invisible. Future wedge: replicate biped slot masking on the ghost.

3. **A-first-B-later misses A's initial outfit**: if Peer A connects
   first and runs the B8 force-equip-cycle BEFORE Peer B is online,
   the EQUIP broadcasts go nowhere (no listening peer). When B
   subsequently joins, A doesn't re-broadcast its current state →
   B's ghost of A renders without clothing. The receiver-side pending
   queue we added handles the SYMMETRIC case (B has ghost not ready
   when A's broadcast arrives) but not this case. Future wedge: peer
   re-broadcast on `PEER_JOIN`, or server-side equipment-state cache
   that's pushed to new joiners.

4. **Object Modifications (BGSMod) not covered**: shoulder pads, weapon
   mods, paint jobs etc. attach via the `BGSMod::Attachment::Mod` system
   (Workshop / weapon workbench), NOT via `ActorEquipManager`. Our hook
   doesn't observe these. Affected items are e.g. raider heavy shoulder
   pad, weapon scopes, etc. Future wedge: hook the mod-application
   path separately.

5. **T-pose ghost when peer is in 1st-person view**: pre-existing M8P3.22
   limitation. The 3rd-person body tree is animated by stub anim while
   the player is in 1P → sender reads stub → ghost shows V-pose.
   Workaround: keep peer in 3P view. Unrelated to wedge 2.

### Files

- New: `fw_native/src/hooks/equip_hook.{cpp,h}` (sender detour)
- Modified:
  - `net/protocol.py` + `fw_native/src/net/protocol.h` — `EQUIP_OP` /
    `EQUIP_BCAST` opcodes (`0x0240` / `0x0241`), `EquipOpKind` enum,
    payload structs (21B OP, 37B BCAST). PROTOCOL_VERSION 5→6.
  - `net/server/main.py` — `_handle_equip_op` fan-out
  - `fw_native/src/net/client.{cpp,h}` — `enqueue_equip_op` send,
    `EQUIP_BCAST` receive → main-thread dispatch
  - `fw_native/src/main_thread_dispatch.{cpp,h}` — `FW_MSG_EQUIP_APPLY`
    + `PendingEquipOp` queue
  - `fw_native/src/native/scene_inject.{cpp,h}` — `ghost_attach_armor` /
    `ghost_detach_armor` / `flush_pending_armor_ops` + path resolver
    + per-peer state map + pending queue
  - `fw_native/src/hooks/main_menu_hook.cpp` — WndProc handler
  - `fw_native/src/hooks/install_all.{cpp,h}` — wire-up
  - `fw_native/src/offsets.h` — TESObjectARMO/ARMA layout offsets
  - `fw_native/CMakeLists.txt` — new hook compilation unit

### Forward path

The PoC validates the end-to-end pipeline. Production-grade equipment
sync should add:
- Biped slot masking emulation (hide ghost body parts under armor)
- BGSMod attachment hook (shoulder pads, weapon mods, paint variants)
- Peer rejoin equipment state push (covers A-first-B-later)
- Material swap support (cosmetic variants like rusty/clean raider)
- More NIF testing (different outfit families: vault, raider, leather,
  combat, power armor frames)

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

My observation 2026-04-28: cycling Vault Suit
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
