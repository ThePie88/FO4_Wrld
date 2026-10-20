"""
FalloutWorld wire protocol v1.

Design principles:
- Pure data + pure functions. No I/O. No global state.
- Every wire-format field has explicit width and endianness (little-endian).
- Structs map 1:1 to Rust (dataclass frozen slots -> #[derive(Serialize)] bincode).
- Errors raised as ProtocolError (never silent corruption).
- Forward/backward compat: unknown msg_type decoded as RawMessage.

Frame layout (header is fixed 12 bytes, payload variable):

  offset  size  field
  0       1     magic       (0xFA)
  1       1     version     (currently 1)
  2       2     msg_type    (u16 LE, see MessageType)
  4       4     seq         (u32 LE, per-connection monotonic)
  8       2     payload_len (u16 LE, <= MAX_PAYLOAD_SIZE)
  10      1     flags       (bitmask: FLAG_RELIABLE, ...)
  11      1     reserved    (0)
  12      N     payload     (N = payload_len bytes)

Total frame size: 12 + payload_len bytes.
"""
from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar, Union

# ------------------------------------------------------------------ constants

PROTOCOL_MAGIC: int = 0xFA
PROTOCOL_VERSION: int = 43  # v43: NPC_UNLOAD with form_id 0 releases every NPC the sender owns (the death release in one message)
# v38 (2026-10-03): L5 realtime persistence, slice D1. A world spawn with
# flag WORLD_SPAWN_FLAG_CONTAINER (0x04) is a container of the server's (the
# death crate): its content travels by the container protocol under the
# key 0xFF000000 | wid (wid_container_key). No layout changes: a 0xFF
# container id was always refused before, so on the wire it can only name
# such a container now.
# v37 (2026-10-03): L5 realtime persistence, slice R4. STATS_STATE (0x02B5,
# client -> server) and PLAYER_STATS (0x02B6, server -> client, in the
# restore answer): XP, level, perk points, the SPECIAL base values, health,
# action points, rads and the perks held (64-byte header + 5-byte perks,
# 267 per frame). RESTORE_REQUEST grows to 16 bytes (last_stats_seq).
# v36 (2026-10-03): L5 realtime persistence, slice R2. RESTORE_REQUEST
# (0x02B2, client -> server, 12 B): a load is coming, send me my record;
# PLAYER_INV (0x02B3, server -> client, 20-byte header + 17-byte lines, 81
# per frame, after INSTANCE_DEFS of its named instances): the record;
# RESTORE_DONE (0x02B4, client -> server, 24 B): the player is aligned to it.
# The captures of a new process are refused until its RESTORE_DONE.
# v35 (2026-10-03): L5 realtime persistence, slice R1. INV_STATE (0x02B1,
# client -> server): the player's whole inventory by instance, captured at
# every change, chunked (30-byte header, 17 bytes per line, 80 per frame).
# The server keeps it as the player's record, with the container ops it
# accepts on top (the watermark names the last op a capture includes).
# v34 (2026-10-03): L5 stage 4b. A container line was (base, count) until
# v33: a modded pistol and a plain one were the same item. CONTAINER_OP and
# CONTAINER_BCAST now carry the instance fingerprint of the stack they move
# and the descriptor that rebuilds it (148 and 160 bytes), CONTAINER_OP_ACK
# the fingerprint of the line its count is about (29), and a
# CONTAINER_STATE / CONTAINER_SEED entry the fingerprint of its line (28,
# 49 per chunk). INSTANCE_DEFS (0x0205, both directions) carries the
# descriptors of the lines a STATE or a SEED refers to. ACK status
# REJ_INSTANCE (7): a descriptor that does not make its fingerprint.
# v27 (2026-09-23): loot rework L1. ContainerStateEntry (CONTAINER_SEED and
# CONTAINER_STATE) gains `container_form_id` in front: 16 -> 20 bytes per
# entry, 87 -> 69 entries per chunk. The server keys container state by the
# placed REFR's form_id (stable across processes with the same load order)
# instead of (base_id, cell_id), which merged every ref of one base in one
# cell into a single record. (base_id, cell_id) travels on as the check.
# Runtime refs (0xFF prefix) are refused: their ids alias across processes.
# CONTAINER_OP and CONTAINER_BCAST have carried the form_id since v5.
# v26 (2026-09-18): the session-lifecycle foundations. WELCOME gains a
# machine-readable reject reason and a resume token; PEER_JOIN carries the
# display name; HELLO_RESUME (0x0008) lets a client that already logged in
# rejoin without a fresh launcher proof. Every addition is APPENDED, so a
# receiver that only knows the older prefix keeps working - but note that
# the header version check (encode_header/decode_header) rejects foreign
# versions outright, so client and server must be rebuilt together.
# v16 (2026-05-31): ghost crouch — adds POSE_CROUCH_STATE (0x028E, C->S) and
# POSE_CROUCH_BROADCAST (0x028F, S->peers). A SEPARATE, additive channel
# alongside the working POSE_STATE/POSE_BROADCAST rotation pose: it replicates
# the vertical COM/Pelvis LOCAL TRANSLATION that a crouch produces (the body
# lowering), which the rotation-only pose could not carry (legs bent but body
# stayed at standing height → ghost feet "flew"). PoseCrouchEntry is
# {u16 bone_index; f32 tx,ty,tz} = 14 B, keyed on the SAME shared canonical
# bone index as the rotation pose. Tiny count (<=8, just COM + Pelvis). Does
# NOT touch PoseBoneEntry, the canonical bone filter, or the rotation
# capture/apply loops.
# v14 (2026-05-11): B6.5w12 Ghost AI decision-point sync — extends
# NPCStateEntry (53 → 98 B) with AI state fields the server pre-computes
# and pushes so the DLL's MinHook detours on engine decision functions
# (TESPackage::EvaluateConditions, Actor::SyncCombatTargetFromAIProcess,
# CombatAimController::SetAimTarget, Actor::TickMovementController, and
# the 7 anim-graph state-transition entry points) can substitute the
# server's value instead of letting local AI decide. This replaces the
# v13 "override engine output" pattern (B6.5w4 rounds 1-11, closed) with
# the inverse "redirect engine input" pattern — the engine still does
# all rendering, animation, IK, physics, collision natively. Wire growth
# per NPC: +45 B (package_form_id, combat_target_form_id, aim xyz,
# velocity xyz, weapon_state, sighted, sprinting, sneaking, gun_down,
# aggression, loco_state_pack, sandbox_marker_handle, sandbox_idle_index).
# MAX_NPC_STATES_PER_FRAME drops 26 → 14 (MTU 1400 still trivial; at
# 50 tracked NPCs the server emits 4 packets/tick instead of 2).
# v13 (2026-05-10): B6.5w2 NPC continuous state sync — adds
# NPC_STATE_BCAST (0x0270). Server-authoritative: the Python brain ticks
# all tracked NPCs at npc_tick_hz (default 10 Hz) and broadcasts a batched
# snapshot of (form_id, base_id, cell_id, pos, rot, anim_state, aggro,
# hp_pct, target, flags, ts) per NPC. Unreliable channel — drops are
# tolerable since the next tick resends. No peer_id (not relayed peer
# activity, fully server-authoritative). Wire growth: 53 B/NPC + 4 B
# header per frame, batched up to MAX_NPC_STATES_PER_FRAME = 26 entries
# per frame at MTU 1400. Receiver-side apply is B6.5w3 (engine bridge in
# fw_native using pos_update_seh + IAnimationGraphManagerHolder
# SetGraphVariable* RVAs from re/B6.5_npc_pipeline_AGENT_B.md). AI tick
# suppression on the receiver is B6.5w4. The DLL must rebuild + bump
# CLIENT_VERSION to handle this opcode; the receiver-less Python client
# parses + logs RX for end-to-end protocol verification.
# v12 (2026-05-08): B6.3 lock state sync — adds LOCK_OP (0x0240) and
# LOCK_BCAST (0x0241). Sender hooks engine ForceUnlock / ForceLock,
# broadcasts (form_id, base_id, cell_id, locked, timestamp_ms).
# Receiver applies via Papyrus binding sub_141158640 with ai_notify=0
# — bypasses the lockpicking minigame and key consumption. Server
# persists last-known state per (base_id, cell_id) and replays it to
# new peers on join. LockOpPayload = 21 B, LockBroadcastPayload = 37 B.
# v11 (2026-05-08): B6 prologue — cell-aware ghost. PosStatePayload and
# PosBroadcastPayload extended with `cell_id: u32` (parentCell.formID).
# Sender reads it from PlayerCharacter.parentCell.formID. Receiver compares
# with its own local cell every pos update and flips NIAV_FLAG_APP_CULLED
# on the ghost BSFadeNode when cells differ. Fixes the "ghost frozen at the
# door" bug when peer A enters an interior cell that peer B isn't loaded
# into. PosState 32→36 bytes, PosBroadcast 48→52 bytes.
# v9 (2026-04-30): M9 wedge 4 — raw mesh replication. New message types
# MESH_BLOB_OP (client→server) and MESH_BLOB_BCAST (server→peers) carry
# CHUNKS of a serialized mesh blob extracted from the local player's
# modded weapon. After 12 RE iterations + 4 failed hook strategies for
# the witness (NIF-path) pattern, we go BELOW the engine's mod-assembly
# pipeline and ship raw geometry: positions (decoded from packed half-prec
# stream), indices (u16), per-mesh metadata (m_name, parent_placeholder,
# bgsm_path), local transform. Receiver reconstructs each BSTriShape via
# the engine's clone factory (sub_14182FFD0) and attaches under the
# ghost's weapon root. See re/M9_w4_iter12_AGENT_analysis.md for the
# extraction layout (BSGeometryStreamHelper 32B at clone+0x148 →
# BSStreamDesc → raw vertex/index buffers).
# Wire format: chunked (per-mesh-blob), see MeshBlobChunkHeader below.
# Each MESH_BLOB_OP frame carries a slice of one logical mesh blob; the
# blob contains N meshes serialized linearly. Receiver reassembles by
# (peer_id, equip_seq) into the full blob then decodes the N meshes.
# v6 (2026-04-28): M9 wedge 1 equipment-event observation. New message types
# EQUIP_OP (client→server) and EQUIP_BCAST (server→peers) carrying
# {item_form_id, kind=equip|unequip, slot_form_id, count, timestamp_ms}.
# Sender hooks ActorEquipManager::EquipObject + UnequipObject in Fallout4.exe,
# filters local-player-only events, broadcasts. Receiver in wedge 1 just
# logs RX (no apply on ghost yet — wedge 2 will swap visuals on the M8P3
# ghost body using the same singleton + RVAs proven stable in B8).
# Wire growth: 21B for OP, 37B for BCAST.
# v5 (2026-04-21): B1.g container apply-to-engine. ContainerOpPayload and
# ContainerBroadcastPayload gain `container_form_id` (u32) — the sender's
# engine form_id for the touched container REFR. Receivers use
# `lookup_by_form_id(container_form_id)` + identity check (base, cell) to
# find their local REFR and invoke engine::apply_container_op_to_engine
# (AddItem/RemoveItem real). This is what finally makes "peer A takes
# item → peer B sees it disappear in their container UI" work end-to-end.
# Backward-compat: field defaults to 0 on Python side so existing call-
# sites stay valid; wire format grows by 4 bytes per CONTAINER_OP / BCAST.
# v4 (2026-04-20): B4 world-state expansion. New message types
# QUEST_STAGE_SET / QUEST_STAGE_BCAST, GLOBAL_VAR_SET / GLOBAL_VAR_BCAST,
# QUEST_STATE_BOOTSTRAP / GLOBAL_VAR_STATE_BOOTSTRAP for chunked snapshot
# on new-peer connect. Rationale §3.2 of the brainstorm: "10 player = 1
# entità narrativa" → quest progress is global, not per-peer. SetStage and
# GlobalVariable changes propagate to ALL peers, validator trivially
# monotonic (the engine already enforces it at the Papyrus level).
# v3 (2026-04-20): ContainerOpPayload carries `client_op_id` (monotonic per
# client) so the server can echo it back in CONTAINER_OP_ACK. The sender
# matches ACK-to-op via this id, enabling pre-mutation block: the C++ DLL
# holds a condvar keyed on op_id and waits ~100ms for the verdict before
# letting the engine's AddObjectToContainer proceed. Closes the container
# dup race that was a known limit after B0.
# v2 (2026-04-19): identity tuple (base_id, cell_id) — see above.
HEADER_SIZE: int = 12
MAX_PAYLOAD_SIZE: int = 1400   # stay under typical MTU 1500 minus IP+UDP headers
MAX_FRAME_SIZE: int = HEADER_SIZE + MAX_PAYLOAD_SIZE
MAX_CLIENT_ID_LEN: int = 15   # ASCII, null-terminated in 16 bytes

# ---- PIENUVO v0 auth (v19) ----
# Identity = Ed25519 keypair owned by the launcher. The wire never carries the
# private key: the server hands out a single-use 32-byte challenge, the
# launcher signs DOMAIN+challenge, and HELLO carries (pubkey, challenge,
# signature). Knowing someone's public ID is therefore worthless — proving the
# identity requires the private key file.
AUTH_PUBKEY_LEN: int = 32
AUTH_CHALLENGE_LEN: int = 32
AUTH_SIGNATURE_LEN: int = 64
MAX_PLAYER_NAME_LEN: int = 15   # ASCII, null-terminated in 16 bytes
# Domain separation: the launcher key only ever signs messages with this
# prefix, so an attacker can't trick it into signing bytes that are valid in
# some other protocol.
AUTH_SIGN_DOMAIN: bytes = b"FWAUTH1"


def auth_sign_message(server_addr: str, challenge: bytes) -> bytes:
    """The exact bytes the launcher signs at login. Mirrored verbatim by
    `MENU_PRINCIPALE/src-tauri/src/identity.rs::sign_challenge` — if one side
    changes, logins break loudly rather than silently weakening.

    Layout: DOMAIN || u16_le(len(addr)) || addr_utf8 || challenge

    The ADDRESS is what makes the proof non-transferable. Without it the
    signature says only "I answered some challenge", so a hostile server the
    player clicks can fetch a nonce from a victim server, pass it through, and
    replay the resulting proof there to log in as that player. Signing the
    address the launcher actually dialed means such a relayed proof names the
    attacker's server, and the victim server rejects it.

    The length prefix prevents an address/challenge boundary ambiguity: without
    it, ("1.2.3.4:31337", ch) and ("1.2.3.4:3133", b"7"+ch) would hash the same
    bytes."""
    addr = server_addr.encode("utf-8")
    return (AUTH_SIGN_DOMAIN + len(addr).to_bytes(2, "little")
            + addr + challenge)


# The public identity string derived from the public key. Mirrored verbatim by
# `MENU_PRINCIPALE/src-tauri/src/identity.rs::client_id` (2026-09-18): first 7
# bytes of SHA256(pubkey), hex, truncated to 13 characters, behind a "fw"
# prefix. Exactly MAX_CLIENT_ID_LEN characters, so it always fits the wire
# field with room for the terminator.
#
# Why the server needs it: every piece of persistent state (the appearance
# recipe, and from v26 the presence record) is keyed by the CLAIMED client_id.
# Deriving the same string here lets the server demand that an authenticated
# HELLO claims the id its own key produces, which turns the key into the
# account. Anonymous sessions keep claiming whatever they like, which is what
# the second client does on a test server.
AUTH_CLIENT_ID_PREFIX: str = "fw"
AUTH_CLIENT_ID_HEX_LEN: int = 13


def derive_client_id(pubkey: bytes) -> str:
    """Canonical client_id for an Ed25519 public key."""
    if len(pubkey) != AUTH_PUBKEY_LEN:
        raise ProtocolError(
            f"pubkey must be {AUTH_PUBKEY_LEN} bytes, got {len(pubkey)}")
    digest = hashlib.sha256(pubkey).digest()[:7].hex()
    return AUTH_CLIENT_ID_PREFIX + digest[:AUTH_CLIENT_ID_HEX_LEN]


# ---- v26 session lifecycle ----
# A resume token is an opaque bearer credential the server mints inside an
# accepted WELCOME. It exists because the launcher's login proof is SINGLE USE
# (the challenge is consumed on the first successful join) and the game DLL
# holds no private key, so a client that drops cannot re-prove who it is. The
# token is bound to the identity, expires, and is rotated on every use.
RESUME_TOKEN_LEN: int = 32
RESUME_TOKEN_TTL_S: float = 24 * 60 * 60.0

# Flag bitmask
FLAG_RELIABLE: int = 0x01   # sender requires ACK for this frame
FLAG_ACK_CARRIER: int = 0x02  # this frame piggybacks an ACK (future)


class MessageType(IntEnum):
    """Wire-level message type. Value is the u16 on wire."""

    # Connection management (0x00XX)
    HELLO         = 0x0001   # client -> server: introduce self
    WELCOME       = 0x0002   # server -> client: session accepted
    PEER_JOIN     = 0x0003   # server -> client: new peer
    PEER_LEAVE    = 0x0004   # server -> client: peer gone
    HEARTBEAT     = 0x0005   # client <-> server: keepalive
    DISCONNECT    = 0x0006   # either side: graceful close
    PEER_GHOST_REGISTER = 0x0007  # B6.6w5: client -> server: my local ghost-actor form_id (= the actor that represents the OTHER peer on my screen). Used by project_for_peer to substitute combat_target with the right local fid per-viewer.
    HELLO_RESUME  = 0x0008   # v26: client -> server, rejoin with a resume token

    # Reliability
    ACK           = 0x0010   # server/client: acknowledges reliable frames

    # Bootstrap (0x002X) — server authoritative state to new/reconnecting clients
    WORLD_STATE           = 0x0020   # server -> client: world actor alive/dead snapshot
    CONTAINER_STATE       = 0x0021   # server -> client: container inventory snapshot (chunked)
    QUEST_STATE_BOOT      = 0x0022   # v4: server -> client: quest-stage snapshot (chunked)
    GLOBAL_VAR_STATE_BOOT = 0x0023   # v4: server -> client: global-var snapshot (chunked)

    # Discovery / server browser (0x003X) — OUT OF SESSION.
    #
    # These are the only messages a server or master answers WITHOUT an
    # established session: they are stateless request/response, never reliable
    # (no channel, no ACK, no retransmit — the caller just re-asks), and they
    # never mutate world state. That is what lets a menu query a server it has
    # not joined, and lets a client list servers before picking one.
    #
    # Topology:
    #   client  --SERVER_INFO_REQUEST-->  game server      (direct IP:port)
    #   client  <-SERVER_INFO_RESPONSE--  game server
    #   server  --MASTER_REGISTER----->   master           (only if public)
    #   client  --MASTER_LIST_REQUEST->   master
    #   client  <-MASTER_LIST_RESPONSE-   master           (chunked)
    #
    # A public server registers itself by heartbeating the master; the master
    # records the SOURCE address of that heartbeat, which is the server's
    # public ip:port as seen from outside. That both avoids trusting a
    # self-reported address and keeps the NAT mapping alive.
    SERVER_INFO_REQUEST   = 0x0030   # client -> server: "who are you?" (no session)
    SERVER_INFO_RESPONSE  = 0x0031   # server -> client: name/players/version/motd
    MASTER_REGISTER       = 0x0032   # server -> master: publish/refresh listing
    MASTER_LIST_REQUEST   = 0x0033   # client -> master: give me public servers
    MASTER_LIST_RESPONSE  = 0x0034   # master -> client: listing chunk
    AUTH_CHALLENGE_REQUEST  = 0x0035  # launcher -> server: give me a login nonce
    AUTH_CHALLENGE_RESPONSE = 0x0036  # server -> launcher: single-use 32B nonce

    # State replication (0x01XX) — unreliable, best-effort
    POS_STATE     = 0x0100   # client -> server: my pos+rot
    POS_BROADCAST = 0x0101   # server -> client: other peer's pos+rot
    POSE_STATE    = 0x0110   # M8P3.15: client -> server: my per-bone rotations
    POSE_BROADCAST = 0x0111  # M8P3.15: server -> client: other peer's per-bone rotations

    # Game events (0x02XX) — reliable, ack required
    ACTOR_EVENT      = 0x0200   # spawn/kill/disable actor
    CONTAINER_OP     = 0x0201   # client -> server: take/put in container
    CONTAINER_BCAST  = 0x0202   # server -> client: relay of container op (authoritative)
    CONTAINER_SEED   = 0x0203   # client -> server: full inventory dump at first-open
    CONTAINER_OP_ACK = 0x0204   # server -> sender: verdict (accepted / rejected + reason)
    INSTANCE_DEFS    = 0x0205   # L5 stage 4b (v34): both ways: descriptors of the instances a STATE or a SEED names
    DOOR_OP          = 0x0230   # B6.1: client -> server: I activated door X (toggle)
    DOOR_BCAST       = 0x0231   # B6.1: server -> other peers: peer X activated door Y
    EQUIP_OP         = 0x0240   # M9 w1: client -> server: I equipped/unequipped item X
    EQUIP_BCAST      = 0x0241   # M9 w1: server -> other peers: peer X equipped/unequipped item Y
    MESH_BLOB_OP     = 0x0250   # M9 w4 v9: client -> server: chunked mesh blob for an equip event
    MESH_BLOB_BCAST  = 0x0251   # M9 w4 v9: server -> peers: chunked mesh blob (peer-attributed)
    LOCK_OP          = 0x0260   # B6.3 v0.5.3: client -> server: lock state changed (locked/unlocked)
    LOCK_BCAST       = 0x0261   # B6.3 v0.5.3: server -> peers: lock state changed
    WORLD_SPAWN_OP    = 0x02A0  # B6.14 v22: client -> server: I created a REFR in my world
    WORLD_SPAWN_BCAST = 0x02A1  # B6.14 v22: server -> ALL clients: place / bind wid
    WORLD_DESPAWN_OP    = 0x02A2  # B6.14 v22: client -> server: spawned object wid died locally
    WORLD_DESPAWN_BCAST = 0x02A3  # B6.14 v22: server -> ALL clients: remove your copy of wid
    WORLD_PA_PIECES_OP    = 0x02A4  # v23: client -> server: full piece list for wid
    WORLD_PA_PIECES_BCAST = 0x02A5  # v23: server -> OTHER clients: replace replica content
    INV_DIGEST            = 0x02B0  # L5 stage 2 (v28): client -> server: advisory digest of the player's inventory (reliable, no answer)
    INV_STATE             = 0x02B1  # L5 realtime R1 (v35): client -> server: the player's whole inventory by instance (reliable, chunked, no answer)
    RESTORE_REQUEST       = 0x02B2  # L5 realtime R2 (v36): client -> server: a load is coming, send the record (reliable)
    PLAYER_INV            = 0x02B3  # L5 realtime R2 (v36): server -> client: the record to align the player to (reliable, chunked)
    RESTORE_DONE          = 0x02B4  # L5 realtime R2 (v36): client -> server: the player is aligned (reliable, no answer)
    STATS_STATE           = 0x02B5  # L5 realtime R4 (v37): client -> server: XP, level, perks, SPECIAL... (reliable, chunked)
    PLAYER_STATS          = 0x02B6  # L5 realtime R4 (v37): server -> client: the stats of the record, in the restore answer
    WORLD_ITEM_OP         = 0x02B7  # L5 realtime R1b (v39): client -> server: a Pip-Boy drop that rested / a pickup from the world, as an op of the record (reliable)
    WORLD_ITEM_ACK        = 0x02B8  # L5 realtime R1b (v39): server -> sender: the verdict of a WORLD_ITEM_OP
    DEATH_CRATES          = 0x02B9  # L5 realtime D2 (v40): server -> owner: their death crates still in the world (reliable)
    LOCATION_DISCOVERED   = 0x02BA  # L5 realtime R5 (v42): client -> server: a map marker turned visible (reliable); the server asks a checkpoint
    CKPT_REQUEST          = 0x02C0  # L5 stage 3 (v29): server -> client: write a checkpoint at your next quiet moment
    CKPT_DONE             = 0x02C1  # L5 stage 3 (v29): client -> server: the checkpoint written (or why not)
    CKPT_BOOT             = 0x02C2  # L5 stage 3 (v29): server -> client, first bootstrap stage: boot from this checkpoint
    BOOT_RESULT           = 0x02C3  # L5 stage 3 (v29): client -> server: what the client actually loaded at boot
    PLAYER_LIFE           = 0x02C4  # L5 stage 3c (v32): client -> server: the local player died / respawned / fell back to the reload
    CKPT_RESPAWN          = 0x02C5  # L5 stage 3d (v33): server -> client: after your death load this checkpoint, moved onto the respawn point (or none)
    NPC_STATE_BCAST  = 0x0270   # B6.5w2 v13: server -> peers: batched NPC pos/anim state (unreliable, ~10 Hz)
    NPC_FIRE         = 0x0271   # B6.6w1 v15: server -> peers: "this raider fires its equipped weapon NOW" (event-driven)
    NPC_DISCOVER     = 0x0272   # B6.6w2 v16: client -> server: "I auto-tracked hostile NPC X (form+base+cell+pos)" (reliable, event-driven)
    NPC_PERCEPTION_TRIGGER = 0x0273  # Build 62 v17: server -> peers: "NPC X perceives peer Y's ghost — invoke CCF810 locally" (reliable, server-side sphere debounced 5s)

    # Build 65 — Owner-driven NPC sync (Solver 2 in re/agents_20/SOLVER_02_owner_driven.md).
    # Server elects one peer as the owner of each NPC. Owner runs full vanilla
    # engine AI; non-owners suppress local Update_PerFrame and apply the owner's
    # broadcast state. Wire opcodes ride alongside v15 — Phase A (server-only)
    # adds infrastructure that doesn't fire until Phase B (DLL) is matched.
    NPC_OWNERSHIP_BCAST           = 0x0280  # S→peer: bootstrap ownership snapshot (reliable, chunked) — sent on peer-join
    NPC_OWNERSHIP_HANDOFF_PHASE_1 = 0x0281  # S→old+new owner: release request for one NPC (reliable)
    NPC_OWNERSHIP_RELEASE_ACK     = 0x0282  # C→S: old owner acknowledges release (reliable)
    NPC_OWNERSHIP_HANDOFF_PHASE_2 = 0x0283  # S→all: new owner active for one NPC (reliable)
    NPC_OWNER_HEARTBEAT           = 0x0284  # C→S: list of fids+epochs we still own (unreliable, 2 Hz proof-of-life)
    NPC_STATE_FROM_OWNER          = 0x0285  # C→S→all: owner's authoritative state batch (unreliable, ~20-30 Hz)
    NPC_OBSERVED                  = 0x0286  # C→S: "I see NPC X at pos P, distance D" — election input (reliable)
    NPC_UNLOAD                    = 0x0287  # C→S: "NPC X left my loaded cell" — owner release / non-owner forget (reliable)
    NPC_FIRE_FROM_OWNER           = 0x0288  # C→S→all: owner's fire event (unreliable, replaces server-driven NPC_FIRE)
    NPC_DEATH_FROM_OWNER          = 0x0289  # C→S→all: owner's death event (reliable)
    NPC_DAMAGE_FROM_OWNER         = 0x028A  # C→S→all: owner's hit-applier event (unreliable, for ragdoll dir + visual cues)
    NPC_ENGAGEMENT_CLAIM          = 0x028B  # Build 65.c.23 — C→S: non-owner peer reports its local engine has InCombat flag set on a tracked NPC. Server uses this to force handoff if current owner hasn't reported engagement in last 3s. Fixes "wrong owner" architectural mismatch where first-observer wins but isn't the actual fighter.
    NPC_POSE_FROM_OWNER           = 0x028C  # c.37.0 — C→S→all: owner's per-bone rotation snapshot for ONE owned NPC, keyed by form_id. Full pose replication (like player→ghost) so the mirror animates bone-by-bone instead of the coarse pos/yaw/anim-enum relay. Unreliable, ~15-20 Hz per NPC.
    NPC_DAMAGE_CLAIM              = 0x028D  # c.39b — C→S: "my local player dealt D damage to NPC X". Drives damage-based ownership/aggro (whoever deals the most damage owns). Unreliable, client-throttled ~6 Hz/fid.
    NPC_CROUCH_FROM_OWNER         = 0x0290  # NPC crouch — C→S→all: owner's COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned NPC, keyed by form_id. The NPC analogue of POSE_CROUCH (rotation pose bends the raider's legs but leaves the body at standing height → feet "fly"; this carries the vertical drop). Unreliable, ~same rate as NPC_POSE_FROM_OWNER.
    NPC_HP_POOL_BCAST             = 0x0291  # v18: S→all: shared HP pool (form_id, hp_cur, hp_max) so the client enemy-bar shows the COMBINED pool instead of the locally-clamped Health. Unreliable, event-driven on damage claims.

    # v16 — ghost crouch. SEPARATE additive channel beside POSE_STATE/BROADCAST.
    # Replicates the vertical COM/Pelvis local translation a crouch produces
    # (rotation-only pose left the body at standing height → feet flew).
    POSE_CROUCH_STATE     = 0x028E  # v16: client -> server: my crouch bone translations (COM/Pelvis +0x60 local translate)
    POSE_CROUCH_BROADCAST = 0x028F  # v16: server -> other peers: peer X's crouch bone translations

    # Social (0x03XX) — reliable
    CHAT          = 0x0300

    # World state replication (0x04XX) — reliable, applied in-order per key
    QUEST_STATE       = 0x0400   # DEPRECATED legacy constant — use QUEST_STAGE_*
    QUEST_STAGE_SET   = 0x0401   # v4: client -> server: I set quest X to stage N
    QUEST_STAGE_BCAST = 0x0402   # v4: server -> other peers: peer X set quest Y to stage N
    GLOBAL_VAR_SET    = 0x0411   # v4: client -> server: I set GlobalVar X to value V
    GLOBAL_VAR_BCAST  = 0x0412   # v4: server -> other peers: peer X set GlobalVar Y to V

    # v20 — character appearance as a RECIPE: engine form ids only (race, sex,
    # head parts, hair colour), ~150 bytes of ASCII. One datagram per
    # character, no chunking. See CHARGEN_PLAN §17 for the format.
    APPEARANCE_SET    = 0x0421   # client -> server: this is what I look like
    APPEARANCE_BCAST  = 0x0422   # server -> clients: this is what peer X looks like


class ProtocolError(Exception):
    """Raised for any wire-format violation."""


# ------------------------------------------------------------------ header

@dataclass(frozen=True, slots=True)
class FrameHeader:
    msg_type: int      # u16 (MessageType value; raw int to support unknown)
    seq: int           # u32
    payload_len: int   # u16
    flags: int = 0     # u8

    # Constants duplicated for Rust portability (const VALUE in struct)
    MAGIC: ClassVar[int] = PROTOCOL_MAGIC
    VERSION: ClassVar[int] = PROTOCOL_VERSION
    SIZE: ClassVar[int] = HEADER_SIZE

    def __post_init__(self) -> None:
        if not 0 <= self.msg_type <= 0xFFFF:
            raise ProtocolError(f"msg_type out of u16 range: {self.msg_type}")
        if not 0 <= self.seq <= 0xFFFFFFFF:
            raise ProtocolError(f"seq out of u32 range: {self.seq}")
        if not 0 <= self.payload_len <= MAX_PAYLOAD_SIZE:
            raise ProtocolError(f"payload_len invalid: {self.payload_len}")
        if not 0 <= self.flags <= 0xFF:
            raise ProtocolError(f"flags out of u8 range: {self.flags}")

    @property
    def is_reliable(self) -> bool:
        return bool(self.flags & FLAG_RELIABLE)


_HEADER_STRUCT = struct.Struct("<BBHIHBB")  # magic, ver, mtype, seq, plen, flags, reserved


def encode_header(h: FrameHeader) -> bytes:
    """Serialize header to exactly HEADER_SIZE bytes."""
    return _HEADER_STRUCT.pack(
        PROTOCOL_MAGIC, PROTOCOL_VERSION,
        h.msg_type, h.seq, h.payload_len, h.flags, 0,
    )


def decode_header(data: bytes) -> FrameHeader:
    """Deserialize header from (at least) HEADER_SIZE bytes."""
    if len(data) < HEADER_SIZE:
        raise ProtocolError(f"header truncated: got {len(data)} bytes, need {HEADER_SIZE}")
    magic, ver, mtype, seq, plen, flags, _reserved = _HEADER_STRUCT.unpack_from(data, 0)
    if magic != PROTOCOL_MAGIC:
        raise ProtocolError(f"bad magic: 0x{magic:02X}")
    if ver != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {ver}")
    if plen > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"payload too big: {plen}")
    return FrameHeader(msg_type=mtype, seq=seq, payload_len=plen, flags=flags)


# ------------------------------------------------------------------ payloads

# Each payload class exposes .encode() -> bytes and classmethod .decode(data) -> Self.
# This symmetry makes code generation (to Rust) trivial.

def _encode_fixed_string(s: str, max_len: int) -> bytes:
    data = s.encode("ascii", errors="strict")
    if len(data) > max_len:
        raise ProtocolError(f"string too long ({len(data)} > {max_len}): {s!r}")
    return data.ljust(max_len + 1, b"\x00")[: max_len + 1]  # include null terminator


def _decode_fixed_string(buf: bytes, max_len: int) -> str:
    field = buf[: max_len + 1]
    null = field.find(b"\x00")
    if null < 0:
        raise ProtocolError("fixed string not null-terminated")
    try:
        return field[:null].decode("ascii", errors="strict")
    except UnicodeDecodeError as e:
        # A remote peer must never be able to raise something the frame-level
        # handler does not catch: UnicodeDecodeError is a ValueError, so it
        # escaped decode_frame's struct.error guard and reached the server's
        # blanket except as a full traceback — one spammable packet per log
        # storm. Non-ASCII in a fixed string is a malformed frame, nothing more.
        raise ProtocolError(f"fixed string not ASCII: {e}") from None


@dataclass(frozen=True, slots=True)
class HelloPayload:
    client_id: str            # ASCII max 15
    client_version_major: int # u8
    client_version_minor: int # u8
    steam_id: int = 0         # u64; 0 = unavailable (B6.6w5+)
    # v19 PIENUVO auth tail — all-or-nothing: either the full 144-byte block
    # (pubkey + challenge + signature + display_name) is present, or none of
    # it is and the HELLO counts as unauthenticated (server policy decides
    # whether that is accepted).
    auth_pubkey: bytes = b""     # 32B Ed25519 public key ("" = no auth)
    auth_challenge: bytes = b""  # 32B server-issued nonce being answered
    auth_signature: bytes = b""  # 64B sig over AUTH_SIGN_DOMAIN + challenge
    display_name: str = ""       # ASCII max 15, cosmetic (identity is the key)

    _STRUCT_HEAD: ClassVar[struct.Struct] = struct.Struct("<BB")
    _STRUCT_TAIL: ClassVar[struct.Struct] = struct.Struct("<Q")
    _AUTH_BLOCK_LEN: ClassVar[int] = (
        AUTH_PUBKEY_LEN + AUTH_CHALLENGE_LEN + AUTH_SIGNATURE_LEN
        + MAX_PLAYER_NAME_LEN + 1)   # 32+32+64+16 = 144

    @property
    def has_auth(self) -> bool:
        return len(self.auth_pubkey) == AUTH_PUBKEY_LEN

    def encode(self) -> bytes:
        out = (
            _encode_fixed_string(self.client_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT_HEAD.pack(
                self.client_version_major, self.client_version_minor)
            + self._STRUCT_TAIL.pack(self.steam_id & 0xFFFFFFFFFFFFFFFF)
        )
        if self.auth_pubkey:
            if (len(self.auth_pubkey) != AUTH_PUBKEY_LEN
                    or len(self.auth_challenge) != AUTH_CHALLENGE_LEN
                    or len(self.auth_signature) != AUTH_SIGNATURE_LEN):
                raise ProtocolError("HELLO auth block: bad field lengths")
            out += (self.auth_pubkey + self.auth_challenge
                    + self.auth_signature
                    + _encode_fixed_string(self.display_name,
                                           MAX_PLAYER_NAME_LEN))
        return out

    @classmethod
    def decode(cls, data: bytes) -> "HelloPayload":
        off = MAX_CLIENT_ID_LEN + 1   # 16
        head_size = cls._STRUCT_HEAD.size   # 2
        tail_size = cls._STRUCT_TAIL.size   # 8
        if len(data) < off + head_size:
            raise ProtocolError("HELLO truncated (head)")
        cid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        vma, vmi = cls._STRUCT_HEAD.unpack_from(data, off)
        # B6.6w5: steam_id tail is OPTIONAL for backwards compat.
        # Legacy 18-byte HELLO from old clients → steam_id defaults to 0.
        steam_id = 0
        if len(data) >= off + head_size + tail_size:
            (steam_id,) = cls._STRUCT_TAIL.unpack_from(
                data, off + head_size)
        # v19 auth tail. A partial block is a protocol error, not leniency:
        # truncation here would silently downgrade an authenticated login.
        auth_off = off + head_size + tail_size   # 26
        pk = ch = sig = b""
        name = ""
        if len(data) > auth_off:
            if len(data) < auth_off + cls._AUTH_BLOCK_LEN:
                raise ProtocolError("HELLO auth block truncated")
            p = auth_off
            pk = bytes(data[p:p + AUTH_PUBKEY_LEN]);     p += AUTH_PUBKEY_LEN
            ch = bytes(data[p:p + AUTH_CHALLENGE_LEN]);  p += AUTH_CHALLENGE_LEN
            sig = bytes(data[p:p + AUTH_SIGNATURE_LEN]); p += AUTH_SIGNATURE_LEN
            name = _decode_fixed_string(data[p:], MAX_PLAYER_NAME_LEN)
        return cls(cid, vma, vmi, steam_id, pk, ch, sig, name)


class RejectCode(IntEnum):
    """Why a HELLO or HELLO_RESUME was refused (v26).

    Before v26 a refusal was an `accepted=0` WELCOME and nothing else, so the
    client could only log "rejected" and die. Every reason below already
    existed as a string at the call site and was thrown away; this enum is
    that string, on the wire.
    """
    NONE               = 0   # accepted
    AUTH_INVALID       = 1   # signature/challenge did not verify
    AUTH_REQUIRED      = 2   # server runs --require-auth, HELLO was anonymous
    IDENTITY_TAKEN     = 3   # another LIVE session already holds this identity
    PEER_ID_TAKEN      = 4   # another LIVE session already holds this client_id
    PEER_ID_INVALID    = 5   # malformed client_id
    VERSION_MISMATCH   = 6   # client major version != server major version
    SERVER_FULL        = 7   # max_players reached
    CLIENT_ID_MISMATCH = 8   # authenticated, but client_id != derive(pubkey)
    RESUME_UNKNOWN     = 9   # resume token not recognised
    RESUME_EXPIRED     = 10  # resume token past its TTL


@dataclass(frozen=True, slots=True)
class WelcomePayload:
    session_id: int          # u32, server-assigned
    accepted: bool           # u8 (0/1)
    server_version_major: int
    server_version_minor: int
    tick_rate_hz: int        # u16, how often server broadcasts state
    # v21 — the entry ritual. 1 = this identity has no stored appearance and the
    # server wants one before the player is visible. Only the server can answer
    # it: the client's local save always has an appearance, and "the bootstrap
    # contained nothing for me" is indistinguishable from a slow network.
    # 0 covers both no-op reasons — an appearance is already stored, or the
    # server does not require creation at all.
    chargen_required: bool = False   # u8 (0/1)
    # v26 — why we said no. RejectCode.NONE on an accepted WELCOME.
    reject_code: int = RejectCode.NONE       # u8
    # v26 — the bearer token that lets this client rejoin without a fresh
    # launcher proof. All-zero when the server issues none (a refusal, or a
    # server with the feature off). See RESUME_TOKEN_LEN.
    resume_token: bytes = b""                # 32 bytes, zero-padded

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBBBHBB32s")

    def encode(self) -> bytes:
        token = self.resume_token or b""
        if len(token) > RESUME_TOKEN_LEN:
            raise ProtocolError("resume token too long")
        return self._STRUCT.pack(
            self.session_id,
            1 if self.accepted else 0,
            self.server_version_major,
            self.server_version_minor,
            self.tick_rate_hz,
            1 if self.chargen_required else 0,
            int(self.reject_code) & 0xFF,
            token.ljust(RESUME_TOKEN_LEN, b"\x00"),
        )

    @classmethod
    def decode(cls, data: bytes) -> "WelcomePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("WELCOME truncated")
        (sid, acc, vma, vmi, tick, chargen, rej,
         token) = cls._STRUCT.unpack_from(data, 0)
        # An all-zero token means "none issued"; keep it as b"" so callers can
        # test truthiness instead of comparing 32 zero bytes.
        if not any(token):
            token = b""
        return cls(sid, bool(acc), vma, vmi, tick, bool(chargen), rej, token)


@dataclass(frozen=True, slots=True)
class PeerJoinPayload:
    peer_id: str             # ASCII, max 15
    session_id: int          # u32
    # v26 — the player's chosen name. It reached the server in the HELLO and
    # then died in the join log line: peers could not learn each other's names,
    # which is the prerequisite for nametags and chat. Cosmetic and untrusted:
    # the identity is still the peer_id.
    display_name: str = ""   # ASCII, max 15

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.session_id)
            + _encode_fixed_string(self.display_name, MAX_PLAYER_NAME_LEN)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PeerJoinPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("PEER_JOIN truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        (sid,) = cls._STRUCT.unpack_from(data, off)
        name_off = off + cls._STRUCT.size
        name = ""
        if len(data) >= name_off + MAX_PLAYER_NAME_LEN + 1:
            name = _decode_fixed_string(data[name_off:], MAX_PLAYER_NAME_LEN)
        return cls(pid, sid, name)


@dataclass(frozen=True, slots=True)
class HelloResumePayload:
    """v26 — rejoin with the token from a previous WELCOME.

    This is the whole answer to "the login proof is single use and the DLL
    cannot mint one". The client keeps the token in memory, and on a drop it
    sends this instead of a HELLO: same peer_id, any UDP port. The server
    evicts whatever stale session that identity still holds and runs the full
    join bootstrap, because a client that dropped has lost all of it.
    """
    peer_id: str             # ASCII, max 15
    resume_token: bytes      # 32 bytes
    client_version_major: int
    client_version_minor: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<32sBB")

    def encode(self) -> bytes:
        token = self.resume_token or b""
        if len(token) > RESUME_TOKEN_LEN:
            raise ProtocolError("resume token too long")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                token.ljust(RESUME_TOKEN_LEN, b"\x00"),
                self.client_version_major,
                self.client_version_minor,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "HelloResumePayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("HELLO_RESUME truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        token, vma, vmi = cls._STRUCT.unpack_from(data, off)
        return cls(pid, token, vma, vmi)


@dataclass(frozen=True, slots=True)
class PeerLeavePayload:
    peer_id: str
    reason: int              # u8: 0=timeout, 1=disconnect, 2=kick

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<B")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.reason)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PeerLeavePayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("PEER_LEAVE truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        (reason,) = cls._STRUCT.unpack_from(data, off)
        return cls(pid, reason)


@dataclass(frozen=True, slots=True)
class HeartbeatPayload:
    timestamp_ms: int        # u64, sender wall clock
    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<Q")
    def encode(self) -> bytes: return self._STRUCT.pack(self.timestamp_ms)
    @classmethod
    def decode(cls, data: bytes) -> "HeartbeatPayload":
        if len(data) < cls._STRUCT.size: raise ProtocolError("HEARTBEAT truncated")
        return cls(cls._STRUCT.unpack_from(data, 0)[0])


@dataclass(frozen=True, slots=True)
class AckPayload:
    """Selective ACK: acks all frames up to highest_contiguous_seq,
    plus a 32-bit bitmap where bit N means highest_contiguous_seq+N+1 was received."""

    highest_contiguous_seq: int  # u32
    sack_bitmap: int             # u32

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.highest_contiguous_seq, self.sack_bitmap)

    @classmethod
    def decode(cls, data: bytes) -> "AckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("ACK truncated")
        return cls(*cls._STRUCT.unpack_from(data, 0))


@dataclass(frozen=True, slots=True)
class PosStatePayload:
    """Current local player pos+rot snapshot. Unreliable.

    v11 (B6 prologue): adds cell_id (parentCell.formID) so the receiver
    can compare with its own local cell and CULL the ghost when peers
    are in different cells.
    """
    x: float; y: float; z: float   # world coords (float32)
    rx: float; ry: float; rz: float # rotation radians (float32)
    timestamp_ms: int              # u64 client wall clock (for RTT/interp)
    cell_id: int = 0               # v11: parentCell.formID (u32)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<6fQI")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.x, self.y, self.z,
                                  self.rx, self.ry, self.rz,
                                  self.timestamp_ms,
                                  self.cell_id)

    @classmethod
    def decode(cls, data: bytes) -> "PosStatePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("POS_STATE truncated")
        return cls(*cls._STRUCT.unpack_from(data, 0))


@dataclass(frozen=True, slots=True)
class PosBroadcastPayload:
    """Pos+rot of a remote peer, as relayed by server. Extends PosState with peer_id.

    v11 (B6 prologue): adds cell_id, mirrored from PosStatePayload.
    """
    peer_id: str
    x: float; y: float; z: float
    rx: float; ry: float; rz: float
    timestamp_ms: int
    cell_id: int = 0               # v11: peer's parentCell.formID (u32)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<6fQI")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.x, self.y, self.z,
                                 self.rx, self.ry, self.rz,
                                 self.timestamp_ms,
                                 self.cell_id)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PosBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("POS_BROADCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        x, y, z, rx, ry, rz, ts, cell = cls._STRUCT.unpack_from(data, off)
        return cls(pid, x, y, z, rx, ry, rz, ts, cell)


# ---- M8P3.15 POSE replication ----------------------------------------------
# Header: <Q H = 10 bytes (timestamp_ms, bone_count)
# Tail:   bone_count × <ffff = 16 bytes (qx, qy, qz, qw)
# Max payload at 64 bones: 10 + 64*16 = 1034 bytes < MAX_PAYLOAD_SIZE 1400 ✓

MAX_POSE_BONES = 80   # M8P3.17: bumped from 64 (skel.nif has ~70 joints)


@dataclass(frozen=True, slots=True)
class PoseStatePayload:
    """Per-bone rotation snapshot (quaternions) of local player. Unreliable."""
    timestamp_ms: int          # u64
    quats: tuple[tuple[float, float, float, float], ...]
    # quats[i] = (qx, qy, qz, qw) for bone i in deterministic sort order

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QH")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<ffff")

    def encode(self) -> bytes:
        if len(self.quats) > MAX_POSE_BONES:
            raise ProtocolError(f"too many bones: {len(self.quats)}")
        head = self._HEADER.pack(self.timestamp_ms, len(self.quats))
        body = b''.join(self._ENTRY.pack(*q) for q in self.quats)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "PoseStatePayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("POSE_STATE truncated header")
        ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_BONES:
            raise ProtocolError(f"POSE_STATE bone_count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_STATE truncated body")
        quats = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(ts, quats)


@dataclass(frozen=True, slots=True)
class PoseBroadcastPayload:
    """Per-bone rotation of a remote peer, relayed by server."""
    peer_id: str
    timestamp_ms: int
    quats: tuple[tuple[float, float, float, float], ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QH")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<ffff")

    def encode(self) -> bytes:
        if len(self.quats) > MAX_POSE_BONES:
            raise ProtocolError(f"too many bones: {len(self.quats)}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HEADER.pack(self.timestamp_ms, len(self.quats))
            + b''.join(self._ENTRY.pack(*q) for q in self.quats)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PoseBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._HEADER.size:
            raise ProtocolError("POSE_BROADCAST truncated header")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        ts, n = cls._HEADER.unpack_from(data, off)
        if n > MAX_POSE_BONES:
            raise ProtocolError(f"POSE_BROADCAST bone_count too high: {n}")
        need = off + cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_BROADCAST truncated body")
        quats = tuple(
            cls._ENTRY.unpack_from(data, off + cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(pid, ts, quats)


# ---- v16 POSE_CROUCH replication -------------------------------------------
# A SEPARATE, additive channel beside POSE_STATE/POSE_BROADCAST. The rotation
# pose (PoseBoneEntry, 16 B) is unchanged and keeps working; this channel only
# carries the vertical COM/Pelvis LOCAL TRANSLATION that a crouch produces.
# Each entry is keyed on the SAME shared canonical bone index as the rotation
# pose (both clients walk the identical, sorted, UNFILTERED canonical list, so
# the index is a reliable cross-client key). count is tiny (<= 8 — just COM
# and Pelvis today).
#
# Header (STATE): <Q B = 9 bytes (timestamp_ms, count)
# Header (BCAST): FixedString(15+1) + <Q B = 25 bytes (peer_id, ts, count)
# Entry:          <H fff = 14 bytes (bone_index, tx, ty, tz)

MAX_POSE_CROUCH_BONES = 8


@dataclass(frozen=True, slots=True)
class PoseCrouchStatePayload:
    """Per-bone local-translation snapshot (crouch) of the local player.

    Unreliable. entries[i] = (bone_index, tx, ty, tz) where bone_index is the
    canonical index shared with the rotation pose. Mirrors the
    PoseStatePayload -> PoseBroadcastPayload server fan-out pattern.
    """
    timestamp_ms: int          # u64
    entries: tuple[tuple[int, float, float, float], ...]
    # entries[i] = (bone_index, tx, ty, tz)

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QB")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<Hfff")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"too many crouch bones: {len(self.entries)}")
        head = self._HEADER.pack(self.timestamp_ms, len(self.entries))
        body = b''.join(self._ENTRY.pack(*e) for e in self.entries)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "PoseCrouchStatePayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("POSE_CROUCH_STATE truncated header")
        ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"POSE_CROUCH_STATE count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_CROUCH_STATE truncated body")
        entries = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(ts, entries)


@dataclass(frozen=True, slots=True)
class PoseCrouchBroadcastPayload:
    """Crouch bone translations of a remote peer, relayed by server.

    Extends PoseCrouchStatePayload with peer_id (mirrors PoseBroadcastPayload).
    """
    peer_id: str
    timestamp_ms: int
    entries: tuple[tuple[int, float, float, float], ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QB")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<Hfff")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"too many crouch bones: {len(self.entries)}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HEADER.pack(self.timestamp_ms, len(self.entries))
            + b''.join(self._ENTRY.pack(*e) for e in self.entries)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PoseCrouchBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._HEADER.size:
            raise ProtocolError("POSE_CROUCH_BROADCAST truncated header")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        ts, n = cls._HEADER.unpack_from(data, off)
        if n > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"POSE_CROUCH_BROADCAST count too high: {n}")
        need = off + cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_CROUCH_BROADCAST truncated body")
        entries = tuple(
            cls._ENTRY.unpack_from(data, off + cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(pid, ts, entries)


@dataclass(frozen=True, slots=True)
class NPCPoseFromOwnerPayload:
    """c.37.0 — owner's per-bone rotation snapshot for ONE owned NPC.

    C→S→all (relayed unchanged). Same quaternion bone format as POSE_STATE,
    prefixed with the NPC's form_id so the receiver resolves the mirror
    actor via lookup_by_form_id and drives ITS skeleton exactly like the
    player→ghost pose path. Bone i aligns by the shared canonical joint-name
    list (identical human skeleton on both clients). Sentinel qw=2.0 means
    "joint absent on owner" → receiver skips that bone (keeps bind pose).

    Server validates the sender owns `form_id`, then fans the SAME frame out
    to every non-owner. No epoch gate: pose is cosmetic best-effort, a few
    stale frames during a handoff are invisible under the new owner's stream.

    Wire: 14 (header) + N × 16.
    """
    form_id: int
    timestamp_ms: int
    quats: tuple[tuple[float, float, float, float], ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IQH")  # form_id, ts, bone_count
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<ffff")

    def encode(self) -> bytes:
        if len(self.quats) > MAX_POSE_BONES:
            raise ProtocolError(f"NPC_POSE too many bones: {len(self.quats)}")
        head = self._HEADER.pack(
            self.form_id & 0xFFFFFFFF,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            len(self.quats),
        )
        body = b''.join(self._ENTRY.pack(*q) for q in self.quats)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "NPCPoseFromOwnerPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_POSE truncated header")
        fid, ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_BONES:
            raise ProtocolError(f"NPC_POSE bone_count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("NPC_POSE truncated body")
        quats = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(fid, ts, quats)


@dataclass(frozen=True, slots=True)
class NPCCrouchFromOwnerPayload:
    """NPC crouch — owner's COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned NPC.

    C→S→all (relayed unchanged). The NPC analogue of PoseCrouchStatePayload:
    same {bone_index, tx, ty, tz} entry format (the +0x60 m_kLocal.translate of
    the COM/Pelvis bones), prefixed with the NPC's form_id so the receiver
    resolves the mirror actor via lookup_by_form_id and lowers ITS skeleton —
    exactly like NPCPoseFromOwnerPayload does for the rotation pose. The
    rotation pose (NPC_POSE_FROM_OWNER) bends the legs but leaves the body at
    standing height; this carries the vertical drop so the raider's feet stop
    "flying". Entries keyed on the SAME shared canonical bone index as the
    rotation pose. count is tiny (<= MAX_POSE_CROUCH_BONES; COM + Pelvis today).

    Server validates the sender owns `form_id`, then fans the SAME frame out to
    every non-owner (mirrors `_handle_npc_pose_from_owner`). No epoch gate.

    Wire: 13 (header <IQB) + N × 14 (entry <Hfff).
    """
    form_id: int
    timestamp_ms: int
    entries: tuple[tuple[int, float, float, float], ...]
    # entries[i] = (bone_index, tx, ty, tz)

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IQB")  # form_id, ts, count
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<Hfff")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(
                f"NPC_CROUCH too many bones: {len(self.entries)}")
        head = self._HEADER.pack(
            self.form_id & 0xFFFFFFFF,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            len(self.entries),
        )
        body = b''.join(self._ENTRY.pack(*e) for e in self.entries)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "NPCCrouchFromOwnerPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_CROUCH truncated header")
        fid, ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"NPC_CROUCH count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("NPC_CROUCH truncated body")
        entries = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(fid, ts, entries)


@dataclass(frozen=True, slots=True)
class NPCDamageClaimPayload:
    """c.39b — C→S: the local player dealt `amount` damage to NPC `form_id`.

    Used by the threat table to make ownership/aggro follow the real fighter:
    the server accumulates a per-peer decayed damage sum per NPC, and the peer
    with the most recent damage wins ownership (even if both peers are engaged,
    which the combat-target signal alone can't disambiguate). Unreliable;
    client throttles to ~6 Hz/fid (accumulating between sends).

    N3 (v17): `max_hp` carries the raider's full Health so the server can
    bootstrap the shared HP pool (both clients deplete one server-held cur_hp).
    0.0 = unknown (server leaves the pool un-bootstrapped).

    Wire: 12 bytes.
    """
    form_id: int
    amount: float
    max_hp: float = 0.0

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<Iff")  # form_id, amount, max_hp

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF, float(self.amount), float(self.max_hp))

    @classmethod
    def decode(cls, data: bytes) -> "NPCDamageClaimPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("NPC_DAMAGE_CLAIM truncated")
        fid, amount, max_hp = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=fid, amount=amount, max_hp=max_hp)


@dataclass(frozen=True, slots=True)
class NPCHpPoolBcastPayload:
    """v18 — S→all: the SHARED authoritative HP pool for a tracked raider.

    The client enemy-health bar normally reads the raider's local Health, which
    N3 clamps to 1 → it reads ~empty. This carries the server pool so the bar can
    show the COMBINED hp_cur/hp_max. Unreliable, event-driven (on damage claims).

    Wire: 12 bytes.
    """
    form_id: int
    hp_cur: float
    hp_max: float

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<Iff")  # form_id, hp_cur, hp_max

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF, float(self.hp_cur), float(self.hp_max))

    @classmethod
    def decode(cls, data: bytes) -> "NPCHpPoolBcastPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("NPC_HP_POOL_BCAST truncated")
        fid, hp_cur, hp_max = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=fid, hp_cur=hp_cur, hp_max=hp_max)


class ActorEventKind(IntEnum):
    SPAWN   = 1
    KILL    = 2
    DISABLE = 3
    ENABLE  = 4


@dataclass(frozen=True, slots=True)
class ActorEventPayload:
    """A significant actor state change. Reliable (requires ACK).

    Identity fields (protocol v2+):
      - form_id      : session-scoped ref id. Stable for 0x00______ placed refs,
                       session-scoped for 0xFF______ runtime refs. Used as a
                       hint for fast-path LookupByFormID on the receiving peer.
      - actor_base_id: TESForm.formID of the ref's baseForm (stable across
                       processes — plugin-loaded). Part of the persistence key.
      - cell_id      : TESForm.formID of the ref's parentCell (stable across
                       processes). Second part of the persistence key.

    The server keys its authoritative world state on (actor_base_id, cell_id),
    NOT on form_id. This prevents the 0xFF______ aliasing bug where the same
    runtime id points to different objects in two separate Fallout4.exe
    processes.
    """
    kind: int                # ActorEventKind
    form_id: int             # u32 refid hint (0xFF_______ for runtime spawns)
    actor_base_id: int       # u32 base form id (identity key for persistence)
    x: float; y: float; z: float  # for SPAWN: location
    extra: int               # u32 flags (kind-specific)
    cell_id: int = 0         # u32 parentCell formid (identity key). 0 = unknown.

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfffII")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.kind, self.form_id, self.actor_base_id,
                                  self.x, self.y, self.z, self.extra,
                                  self.cell_id)

    @classmethod
    def decode(cls, data: bytes) -> "ActorEventPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("ACTOR_EVENT truncated")
        kind, fid, base, x, y, z, extra, cell = cls._STRUCT.unpack_from(data, 0)
        return cls(kind=kind, form_id=fid, actor_base_id=base,
                   x=x, y=y, z=z, extra=extra, cell_id=cell)


@dataclass(frozen=True, slots=True)
class ChatPayload:
    sender_id: str           # ASCII max 15
    text: str                # UTF-8, length-prefixed u16

    def encode(self) -> bytes:
        sender = _encode_fixed_string(self.sender_id, MAX_CLIENT_ID_LEN)
        text_b = self.text.encode("utf-8")
        if len(text_b) > MAX_PAYLOAD_SIZE - len(sender) - 2:
            raise ProtocolError("chat text too long")
        return sender + struct.pack("<H", len(text_b)) + text_b

    @classmethod
    def decode(cls, data: bytes) -> "ChatPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + 2:
            raise ProtocolError("CHAT truncated header")
        sender = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        (tlen,) = struct.unpack_from("<H", data, off)
        off += 2
        if len(data) < off + tlen:
            raise ProtocolError("CHAT truncated text")
        text = data[off:off + tlen].decode("utf-8", errors="replace")
        return cls(sender, text)


@dataclass(frozen=True, slots=True)
class DisconnectPayload:
    reason: int              # u8: 0=graceful, 1=error, 2=version_mismatch
    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<B")
    def encode(self) -> bytes: return self._STRUCT.pack(self.reason)
    @classmethod
    def decode(cls, data: bytes) -> "DisconnectPayload":
        if len(data) < cls._STRUCT.size: raise ProtocolError("DISCONNECT truncated")
        return cls(cls._STRUCT.unpack_from(data, 0)[0])


@dataclass(frozen=True, slots=True)
class WorldActorEntry:
    """One actor's authoritative alive/dead state.

    The persistence identity key is (base_id, cell_id), both stable across
    processes. The form_id is a hint — useful for fast-path LookupByFormID on
    placed refs (0x00______) where ref_id is itself stable, but must be
    validated against (base_id, cell_id) before applying any state change
    because runtime refs (0xFF______) alias across processes.
    """
    form_id: int        # u32 — last-known ref_id (hint, not key). 0 if unknown.
    alive: bool         # u8 (0/1)
    base_id: int = 0    # u32 — TESForm.formID of baseForm. 0 = legacy entry.
    cell_id: int = 0    # u32 — TESForm.formID of parentCell. 0 = legacy entry.


@dataclass(frozen=True, slots=True)
class WorldStatePayload:
    """Full world-actor snapshot from server to client.

    Variable-length list of actor states. The client applies these to its
    local FO4 instance so everyone starts from the same authoritative view.

    Wire format (protocol v2):
        u16  num_entries
        u16  chunk_index
        u16  total_chunks
        per entry (13B):
            u32 form_id   (ref_id hint)
            u32 base_id   (TESForm.formID of baseForm — identity key)
            u32 cell_id   (TESForm.formID of parentCell — identity key)
            u8  alive     (0/1)

    Entries per frame cap: (1400 - 6) // 13 = 107. Multi-chunk via
    `chunk_index` + `total_chunks`.
    """

    entries: tuple[WorldActorEntry, ...]
    chunk_index: int = 0     # u16 — 0-based
    total_chunks: int = 1    # u16 — total in this bootstrap sequence

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIB")  # 13B
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")  # 6B

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 13  # 107 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"WORLD_STATE too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(
                e.form_id, e.base_id, e.cell_id, 1 if e.alive else 0
            ))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "WorldStatePayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("WORLD_STATE header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected_size = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected_size:
            raise ProtocolError(f"WORLD_STATE payload truncated: got {len(data)}, need {expected_size}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            fid, base, cell, alive = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(WorldActorEntry(
                form_id=fid, alive=bool(alive),
                base_id=base, cell_id=cell,
            ))
            off += cls._ENTRY_STRUCT.size
        return cls(
            entries=tuple(entries),
            chunk_index=chunk_idx,
            total_chunks=total,
        )


class ContainerOpKind(IntEnum):
    """Kind of container modification."""
    TAKE = 1   # player removed N items from container
    PUT  = 2   # player added N items to container


def is_runtime_form_id(form_id: int) -> bool:
    """True for a ref created at runtime (0xFF______): its id names another
    object in every other Fallout4.exe process, so it can never be a key."""
    return (form_id >> 24) == 0xFF


# The largest count the wire carries: CONTAINER_STATE entries and the ACK's
# final_count pack an i32. Stage 0 of L5 (2026-09-27): a container record was
# allowed to grow past it (two console deposits of 2e9 caps made 4e9), the
# packers raised inside the join bootstrap, and every later bootstrap stage
# was lost for every joiner until the record was edited out of the snapshot.
COUNT_MAX: int = 2 ** 31 - 1


def identities_conflict(base_a: int, cell_a: int, base_b: int, cell_b: int) -> bool:
    """Whether two (base, cell) views of one placed REFR contradict each other.

    Loot rework L4 (2026-09-25): a placed actor's base is a runtime TESNPC
    (0xFF______) that every client generates on its own, with its own face,
    gear and loot roll, and its corpse can lie in another cell on another
    client (the ragdoll settles locally). Measured on four raiders: every op
    of the second client was refused with IDENTITY_MISMATCH and every
    alignment skipped. For such a REFR the identity is the placed form_id
    alone: a runtime base on either side makes (base, cell) unverifiable,
    never a contradiction. A static base (a container) keeps the full check,
    which catches load-order drift between clients."""
    if is_runtime_form_id(base_a) or is_runtime_form_id(base_b):
        return False
    return base_a != base_b or cell_a != cell_b


# ---------------------------------------------------------------- instances
#
# L5 stage 4b (2026-10-03) — what makes one stack of an item that particular
# instance. Measured live in 4a: the OIE's u16 at +0x20 is the index of the
# object template the instance was built from (the same on two clients for
# the same template), the OMOD records are what the mods are, and the Health
# extra is a piece's condition or a core's charge. The engine's own uid
# (ExtraUniqueID) is NOT part of it: weapons and armour do not carry one
# (their bases lack flag 0x400000), and where it exists it is local to one
# container and reassigned at every crossing.
#
# The fingerprint is FNV-1a 64 over:
#   u32 base | u8 has_oie | [u16 template | u8 n | n x (u32 form, u8 attach,
#   u8 rank), sorted] | u8 has_health | [i32 round(health * 1000), half away
#   from zero]
# A stack with neither an OIE nor a Health extra is PLAIN (0): ammo, aid,
# junk, exactly the lines of v33. UNKNOWN (all ones) names a line nobody can
# rebuild: a v33 record, or a stack a client could not read to the end. A
# hash that falls on either reserved value becomes 1. The record's flag byte,
# the uid, the stack flags and a custom name are left out: the name is not
# carried in v1, so two stacks that differ only by it are one instance.
# fw_native/src/persist/instance_fp.cpp computes the same bytes and checks a
# shared vector at startup.

FP_PLAIN: int = 0
FP_UNKNOWN: int = 0xFFFF_FFFF_FFFF_FFFF
INSTANCE_MAX_MODS: int = 16
INSTANCE_FLAG_OIE: int = 0x01
INSTANCE_FLAG_HEALTH: int = 0x02


@dataclass(frozen=True, slots=True)
class InstanceDescriptor:
    """The data an engine needs to rebuild one instance of a base: the
    template index (OIE+0x20, 0xFFFF none), the OMOD records (form, attach,
    rank) and the condition. Fixed 104 bytes on the wire: u16 template, u8
    flags, u8 mod count, f32 health, 16 x (u32 form, u8 attach, u8 rank)."""
    template: int = 0xFFFF
    flags: int = 0
    health: float = -1.0
    mods: tuple[tuple[int, int, int], ...] = ()

    SIZE: ClassVar[int] = 104
    _HEAD: ClassVar[struct.Struct] = struct.Struct("<HBBf")   # 8 B
    _MOD: ClassVar[struct.Struct] = struct.Struct("<IBB")     # 6 B

    def encode(self) -> bytes:
        if len(self.mods) > INSTANCE_MAX_MODS:
            raise ProtocolError(
                f"instance descriptor: {len(self.mods)} mods > {INSTANCE_MAX_MODS}")
        parts = [self._HEAD.pack(self.template & 0xFFFF, self.flags & 0xFF,
                                 len(self.mods), self.health)]
        for form, attach, rank in self.mods:
            parts.append(self._MOD.pack(form & 0xFFFFFFFF, attach & 0xFF, rank & 0xFF))
        parts.append(b"\x00" * (self._MOD.size * (INSTANCE_MAX_MODS - len(self.mods))))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes, off: int) -> tuple["InstanceDescriptor", int]:
        if len(data) < off + cls.SIZE:
            raise ProtocolError("instance descriptor truncated")
        template, flags, n, health = cls._HEAD.unpack_from(data, off)
        if n > INSTANCE_MAX_MODS:
            raise ProtocolError(f"instance descriptor: {n} mods > {INSTANCE_MAX_MODS}")
        mods = tuple(cls._MOD.unpack_from(data, off + cls._HEAD.size + cls._MOD.size * i)
                     for i in range(n))
        return cls(template=template, flags=flags, health=health, mods=mods), off + cls.SIZE

    def is_plain(self) -> bool:
        return (self.flags & (INSTANCE_FLAG_OIE | INSTANCE_FLAG_HEALTH)) == 0


def _health_q(health: float) -> int:
    """round(health * 1000) the way the DLL does it: the value as the f32
    the wire and the engine hold, times 1000 in double, half away from zero
    (std::lround), not Python's round-half-to-even."""
    v = struct.unpack("<f", struct.pack("<f", health))[0] * 1000.0
    a = abs(v)
    fl = math.floor(a)
    q = int(fl) + (1 if (a - fl) >= 0.5 else 0)
    return -q if v < 0 else q


def instance_fp(base_id: int, d: InstanceDescriptor) -> int:
    """The fingerprint of the instance `d` of `base_id` (see the block above)."""
    has_oie = bool(d.flags & INSTANCE_FLAG_OIE)
    has_health = bool(d.flags & INSTANCE_FLAG_HEALTH)
    if not has_oie and not has_health:
        return FP_PLAIN
    buf = bytearray(struct.pack("<IB", base_id & 0xFFFFFFFF, 1 if has_oie else 0))
    if has_oie:
        mods = sorted((m[0] & 0xFFFFFFFF, m[1] & 0xFF, m[2] & 0xFF) for m in d.mods)
        buf += struct.pack("<HB", d.template & 0xFFFF, len(mods))
        for form, attach, rank in mods:
            buf += struct.pack("<IBB", form, attach, rank)
    buf += struct.pack("<B", 1 if has_health else 0)
    if has_health:
        buf += struct.pack("<i", _health_q(d.health))
    h = 0xCBF29CE484222325
    for b in buf:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFF_FFFF_FFFF_FFFF
    if h in (FP_PLAIN, FP_UNKNOWN):
        h = 1
    return h


@dataclass(frozen=True, slots=True)
class InstanceDefEntry:
    """One descriptor with the base and the fingerprint it makes (116 B)."""
    base_id: int
    fp: int
    instance: InstanceDescriptor


@dataclass(frozen=True, slots=True)
class InstanceDefsPayload:
    """L5 stage 4b (v34), both ways: the descriptors of the instance lines
    a CONTAINER_STATE (server -> client) or a CONTAINER_SEED (client ->
    server) names. Sent before the lines; the reliable channel may still
    deliver it after them, so a receiver keeps a line whose descriptor has
    not arrived and builds it when it does.

    Wire: u16 num_entries, u16 chunk_index, u16 total_chunks, then per entry
    u32 base, u64 fp, descriptor (104 B). 12 entries per chunk."""
    entries: tuple[InstanceDefEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")
    _KEY: ClassVar[struct.Struct] = struct.Struct("<IQ")
    ENTRY_SIZE: ClassVar[int] = 12 + 104
    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (MAX_PAYLOAD_SIZE - 6) // (12 + 104)  # 12

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"INSTANCE_DEFS too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}")
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._KEY.pack(e.base_id, e.fp))
            parts.append(e.instance.encode())
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "InstanceDefsPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("INSTANCE_DEFS header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        if len(data) < cls._HEADER_STRUCT.size + num * cls.ENTRY_SIZE:
            raise ProtocolError("INSTANCE_DEFS payload truncated")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            base, fp = cls._KEY.unpack_from(data, off)
            desc, off = InstanceDescriptor.decode(data, off + cls._KEY.size)
            entries.append(InstanceDefEntry(base_id=base, fp=fp, instance=desc))
        return cls(entries=tuple(entries), chunk_index=chunk_idx, total_chunks=total)


class EquipOpKind(IntEnum):
    """M9 w1: kind of equipment-state change observed on the local player.

    Wedge 1 is OBSERVE-only: server fans out, peers log. Wedge 2 will branch
    on this enum to call ActorEquipManager::EquipObject vs ::UnequipObject
    on the M8P3 ghost body representing the originating peer.
    """
    EQUIP   = 1   # local player equipped (post-Equip detour fire)
    UNEQUIP = 2   # local player unequipped


@dataclass(frozen=True, slots=True)
class ContainerOpPayload:
    """Client -> server: a take/put operation on a container's inventory.

    v3: adds `client_op_id` (monotonic per client) so the server can echo
    it back in CONTAINER_OP_ACK for sender-side correlation. The sender
    uses it to wake a condvar-gated pre-mutation wait: if accepted, the
    engine's AddObjectToContainer proceeds; if rejected, the sender
    skips the call (blocks the mutation) before the item transfer happens.

    Identity is the (container_base_id, container_cell_id) tuple — same
    rationale as Option B for actors (stable across processes). item_base_id
    is a TESForm.formID of the item template (stable plugin-loaded).

    v34 (L5 stage 4b): `item_fp` is the instance fingerprint of the stack
    moved (FP_PLAIN for ammo, aid, junk; FP_UNKNOWN when the client could
    not read it) and `instance` the descriptor that makes it, so a modded
    10mm and a plain one are two lines and an observer rebuilds the right
    one. Until v33 they were the same item.

    count is SIGNED i32 for future-proofing but MUST be > 0 at send time.
    The OP kind (TAKE/PUT) conveys the direction; count stays positive.
    """
    kind: int                    # ContainerOpKind (1 or 2)
    container_base_id: int       # u32
    container_cell_id: int       # u32
    item_base_id: int            # u32
    count: int                   # i32, must be > 0
    timestamp_ms: int            # u64, client wall clock
    client_op_id: int = 0        # u32 — v3; echoed back in CONTAINER_OP_ACK.
    container_form_id: int = 0   # u32 — v5; sender's engine form_id for the
                                 # touched container REFR. Receivers use this
                                 # to find their local REFR via engine's
                                 # LookupByFormID, then validate (base, cell)
                                 # match, then invoke real AddItem/RemoveItem.
                                 # 0 = legacy / unknown → receiver can't apply.
    item_fp: int = FP_PLAIN      # u64 — v34; the instance fingerprint
    instance: InstanceDescriptor = InstanceDescriptor()   # v34; 104 B

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIIiQIIQ")  # 44B (v34: +8 fp), then the descriptor

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.kind, self.container_base_id, self.container_cell_id,
            self.item_base_id, self.count, self.timestamp_ms,
            self.client_op_id, self.container_form_id, self.item_fp,
        ) + self.instance.encode()

    @classmethod
    def decode(cls, data: bytes) -> "ContainerOpPayload":
        if len(data) < cls._STRUCT.size + InstanceDescriptor.SIZE:
            raise ProtocolError("CONTAINER_OP truncated")
        kind, cbase, ccell, ibase, cnt, ts, op_id, cfid, fp = cls._STRUCT.unpack_from(data, 0)
        desc, _ = InstanceDescriptor.decode(data, cls._STRUCT.size)
        return cls(
            kind=kind, container_base_id=cbase, container_cell_id=ccell,
            item_base_id=ibase, count=cnt, timestamp_ms=ts,
            client_op_id=op_id, container_form_id=cfid,
            item_fp=fp, instance=desc,
        )


@dataclass(frozen=True, slots=True)
class ContainerBroadcastPayload:
    """Server -> client: authoritative broadcast of a container op by a peer.

    Mirrors ContainerOpPayload but carries peer_id (the originating session's
    user id) so receivers can attribute the change and for telemetry/UI.
    """
    peer_id: str                 # ASCII max MAX_CLIENT_ID_LEN
    kind: int
    container_base_id: int
    container_cell_id: int
    item_base_id: int
    count: int
    timestamp_ms: int
    container_form_id: int = 0   # u32 — v5; sender's engine form_id for the
                                 # touched container REFR. Receivers use
                                 # lookup_by_form_id + identity check on
                                 # (base, cell) to find their local REFR and
                                 # invoke engine::apply_container_op_to_engine.
                                 # 0 = legacy / unknown → receiver can't apply.
    item_fp: int = FP_PLAIN      # u64 — v34, as in ContainerOpPayload
    instance: InstanceDescriptor = InstanceDescriptor()   # v34; 104 B

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIIiQIQ")  # 36B (v34: +8 fp), then the descriptor

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.kind, self.container_base_id, self.container_cell_id,
                self.item_base_id, self.count, self.timestamp_ms,
                self.container_form_id, self.item_fp,
            )
            + self.instance.encode()
        )

    @classmethod
    def decode(cls, data: bytes) -> "ContainerBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size + InstanceDescriptor.SIZE:
            raise ProtocolError("CONTAINER_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        kind, cbase, ccell, ibase, cnt, ts, cfid, fp = cls._STRUCT.unpack_from(data, off)
        desc, _ = InstanceDescriptor.decode(data, off + cls._STRUCT.size)
        return cls(
            peer_id=pid, kind=kind,
            container_base_id=cbase, container_cell_id=ccell,
            item_base_id=ibase, count=cnt, timestamp_ms=ts,
            container_form_id=cfid, item_fp=fp, instance=desc,
        )


@dataclass(frozen=True, slots=True)
class ContainerStateEntry:
    """One (container, item) pair with its authoritative count.

    A container with N distinct item types produces N entries. A fully
    looted container produces 0 entries (not a single entry with count=0).
    Bootstrap rebuilds the container's inventory by aggregating all entries
    with the same container_form_id (v27); base and cell are the check the
    receiver runs on its own REFR before applying anything.
    """
    container_form_id: int       # u32 — the placed REFR, the identity (v27)
    container_base_id: int       # u32
    container_cell_id: int       # u32
    item_base_id: int            # u32
    count: int                   # i32 (signed for future; >= 0 in practice)
    item_fp: int = FP_PLAIN      # u64 — v34: the instance fingerprint of the line


@dataclass(frozen=True, slots=True)
class ContainerStatePayload:
    """Chunked snapshot of all container inventories on the server.

    Wire format (protocol v34):
        u16  num_entries
        u16  chunk_index
        u16  total_chunks
        per entry (28B):
            u32 container_form_id   (the placed REFR: the identity)
            u32 container_base_id
            u32 container_cell_id
            u32 item_base_id
            i32 count
            u64 item_fp             (v34: the instance of the line)

    Entries per frame cap: (1400 - 6) // 28 = 49. Multi-chunk via
    chunk_index + total_chunks, same pattern as WorldStatePayload.
    """

    entries: tuple[ContainerStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIIiQ")  # 28B
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")  # 6B

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 28  # 49 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"CONTAINER_STATE too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(
                e.container_form_id, e.container_base_id, e.container_cell_id,
                e.item_base_id, e.count, e.item_fp,
            ))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "ContainerStatePayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("CONTAINER_STATE header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected_size = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected_size:
            raise ProtocolError(f"CONTAINER_STATE payload truncated: got {len(data)}, need {expected_size}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            cfid, cbase, ccell, ibase, cnt, fp = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(ContainerStateEntry(
                container_form_id=cfid,
                container_base_id=cbase, container_cell_id=ccell,
                item_base_id=ibase, count=cnt, item_fp=fp,
            ))
            off += cls._ENTRY_STRUCT.size
        return cls(
            entries=tuple(entries),
            chunk_index=chunk_idx,
            total_chunks=total,
        )


class ContainerOpAckStatus(IntEnum):
    """Verdict the server ships back to the sender of a CONTAINER_OP."""
    ACCEPTED        = 0
    REJ_RATE        = 1   # rate-limited
    REJ_IDENTITY    = 2   # missing / zero identity
    REJ_COUNT       = 3   # count <= 0 or absurd
    REJ_KIND        = 4   # unknown op kind
    REJ_INSUFFICIENT = 5  # TAKE count > what the container has (race loser)
    # L5 stage 1 (2026-09-27): the server's journal failed, so no result can
    # be made durable; the op is refused and the client undoes it, like any
    # refusal. Nothing was applied on the server.
    REJ_UNAVAILABLE = 6
    # L5 stage 4b (v34): the op's descriptor does not make its fingerprint, or
    # cannot be one (too many mods). Nothing was applied; the client undoes it.
    REJ_INSTANCE = 7


@dataclass(frozen=True, slots=True)
class ContainerOpAckPayload:
    """Server -> sender only: verdict for a previously-sent CONTAINER_OP.

    Identified by the client-supplied `client_op_id` (monotonic per client).
    The DLL/Python-client stamps each outgoing TAKE/PUT with an id and waits
    on a condvar keyed on that id. On receipt, the worker fires the waiter.
    A timeout on the waiter means "treat as rejected + log".

    status: one of ContainerOpAckStatus. On ACCEPTED the op is effective;
    the server also broadcasts a CONTAINER_BCAST to the OTHER peers.
    On any REJ_* the state is unchanged and no broadcast is emitted.
    """
    client_op_id: int           # u32 — echo of sender's id
    status: int                 # u8 (ContainerOpAckStatus)
    # Snapshot of the final server-side count for this item in this container
    # AFTER the op was processed. Lets the sender reconcile its local mirror
    # without a full bootstrap.
    container_base_id: int      # u32
    container_cell_id: int      # u32
    item_base_id: int           # u32
    final_count: int            # i32 — v34: the count of the (item, fp) line
    item_fp: int = FP_PLAIN     # u64 — v34: the instance the count is about

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIIIiQ")  # 29 bytes

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.client_op_id, self.status,
            self.container_base_id, self.container_cell_id,
            self.item_base_id, self.final_count, self.item_fp,
        )

    @classmethod
    def decode(cls, data: bytes) -> "ContainerOpAckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("CONTAINER_OP_ACK truncated")
        op_id, status, cbase, ccell, ibase, fcnt, fp = cls._STRUCT.unpack_from(data, 0)
        return cls(
            client_op_id=op_id, status=status,
            container_base_id=cbase, container_cell_id=ccell,
            item_base_id=ibase, final_count=fcnt, item_fp=fp,
        )


@dataclass(frozen=True, slots=True)
class ContainerSeedPayload:
    """Client -> server: full inventory of a container that the player just
    opened for the first time this session.

    Seeds the server's state for that REFR with the client's ground truth,
    first-seed-wins (B1.h): a REFR the server already knows keeps its
    record. This is what closes the "trust-the-client on first TAKE"
    loophole from B0 — once the server knows the full inventory, subsequent
    TAKEs can be validated with INSUFFICIENT_ITEMS.

    Wire format identical to CONTAINER_STATE (shared chunked-list primitive):
      u16 num_entries
      u16 chunk_index
      u16 total_chunks
      u32 container_form_id   (v27: the placed REFR, the identity; a SEED may
      u32 container_base_id    carry several containers, grouped by form_id)
      u32 container_cell_id
      u32 item_base_id
      i32 count
      u64 item_fp             (v34: the instance of the line; the descriptors
                               of its instance lines travel in INSTANCE_DEFS)

    Small inventories (<49 lines) ship in a single chunk. For very large
    containers (unlikely in FO4; >49 lines) we chunk.
    """
    entries: tuple["ContainerStateEntry", ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIIiQ")  # 28B
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 28  # 49
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"CONTAINER_SEED too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(
                e.container_form_id, e.container_base_id, e.container_cell_id,
                e.item_base_id, e.count, e.item_fp,
            ))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "ContainerSeedPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("CONTAINER_SEED header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected_size = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected_size:
            raise ProtocolError(
                f"CONTAINER_SEED payload truncated: got {len(data)}, need {expected_size}"
            )
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            cfid, cbase, ccell, ibase, cnt, fp = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(ContainerStateEntry(
                container_form_id=cfid,
                container_base_id=cbase, container_cell_id=ccell,
                item_base_id=ibase, count=cnt, item_fp=fp,
            ))
            off += cls._ENTRY_STRUCT.size
        return cls(
            entries=tuple(entries),
            chunk_index=chunk_idx,
            total_chunks=total,
        )


# =================================================================== B4
#
# World-state expansion: quest-stage sync + global-variable sync.
#
# Design notes:
#   - Quest progress is GLOBAL across all peers (brainstorm §3.2). No per-
#     peer filtering. SetStage is effectively monotonic at the Papyrus
#     level (the engine refuses to go backwards unless ResetQuest is
#     called), so the server validator is trivial: accept everything,
#     last-write-wins, broadcast to other peers.
#   - Global variables can be ints, shorts, or floats in the engine.
#     We represent them uniformly as f64 on the wire — f32 globals are
#     lossless, i32 globals fit in f64's 53-bit mantissa exactly.
#   - Both types follow the CONTAINER_OP/BCAST pattern: a client-side SET
#     payload and a server-side BCAST payload (BCAST adds peer_id).
#   - Bootstrap snapshots (QUEST_STATE_BOOT, GLOBAL_VAR_STATE_BOOT) use
#     the shared chunked-list primitive (ChunkHeader HHH prefix).

@dataclass(frozen=True, slots=True)
class QuestStageSetPayload:
    """Client -> server: "I just set quest X to stage N"."""
    quest_form_id: int       # u32
    new_stage: int           # u16 (engine stages fit u16; the few with
                             # >65535 stages are script-driven globals anyway)
    timestamp_ms: int        # u64, client wall clock

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IHQ")  # 14 bytes; H padded to Q-align

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.quest_form_id, self.new_stage, self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "QuestStageSetPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("QUEST_STAGE_SET truncated")
        fid, stage, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(quest_form_id=fid, new_stage=stage, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class QuestStageBroadcastPayload:
    """Server -> other peers: authoritative relay of a SetStage event."""
    peer_id: str             # ASCII max MAX_CLIENT_ID_LEN
    quest_form_id: int
    new_stage: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IHQ")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.quest_form_id, self.new_stage, self.timestamp_ms)
        )

    @classmethod
    def decode(cls, data: bytes) -> "QuestStageBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("QUEST_STAGE_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        fid, stage, ts = cls._STRUCT.unpack_from(data, off)
        return cls(peer_id=pid, quest_form_id=fid, new_stage=stage, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class QuestStageStateEntry:
    """One (quest_form_id, stage) pair for the bootstrap snapshot."""
    quest_form_id: int
    stage: int


@dataclass(frozen=True, slots=True)
class QuestStateBootPayload:
    """Server -> client: chunked quest-stage snapshot on new-peer connect.

    Wire format: ChunkHeader (HHH) + per entry (I H = 6 bytes).
    """
    entries: tuple[QuestStageStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IH")
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 6  # 232 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"QUEST_STATE_BOOT too many entries: {len(self.entries)} > "
                f"{self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(
            len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(e.quest_form_id, e.stage))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "QuestStateBootPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("QUEST_STATE_BOOT header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected:
            raise ProtocolError(
                f"QUEST_STATE_BOOT payload truncated: got {len(data)}, need {expected}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            fid, stage = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(QuestStageStateEntry(quest_form_id=fid, stage=stage))
            off += cls._ENTRY_STRUCT.size
        return cls(entries=tuple(entries), chunk_index=chunk_idx, total_chunks=total)


@dataclass(frozen=True, slots=True)
class GlobalVarSetPayload:
    """Client -> server: "I just set GlobalVar X to value V"."""
    global_form_id: int      # u32
    value: float             # f64 — carries i32/f32 globals losslessly
    timestamp_ms: int        # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IdQ")  # 20 bytes

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.global_form_id, self.value, self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "GlobalVarSetPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("GLOBAL_VAR_SET truncated")
        fid, val, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(global_form_id=fid, value=val, timestamp_ms=ts)


# --------------------------------------------------------------------- v20
# The payload is the recipe LINE itself — the same human-readable text the
# client logs. Deliberate: at ~150 bytes a packed binary form saves nothing
# worth having, and every byte saved would be repaid in debugging. MAX_RECIPE
# bounds what a receiver will accept instead of trusting the wire.
MAX_RECIPE: int = 1280  # v21: must match MAX_RECIPE_BYTES in protocol.h;
#                        bounded by MAX_PAYLOAD_SIZE minus the BCAST header


@dataclass(frozen=True, slots=True)
class AppearanceSetPayload:
    """Client -> server: my character's appearance recipe."""
    recipe: str

    _HDR: ClassVar[struct.Struct] = struct.Struct("<HH")

    def encode(self) -> bytes:
        raw = self.recipe.encode("ascii", errors="strict")
        if len(raw) > MAX_RECIPE:
            raise ProtocolError(f"recipe too long: {len(raw)} > {MAX_RECIPE}")
        return self._HDR.pack(len(raw), 0) + raw

    @classmethod
    def decode(cls, data: bytes) -> "AppearanceSetPayload":
        if len(data) < cls._HDR.size:
            raise ProtocolError("APPEARANCE_SET truncated")
        n, _ = cls._HDR.unpack_from(data, 0)
        if n > MAX_RECIPE:
            raise ProtocolError(f"APPEARANCE_SET recipe_len {n} > {MAX_RECIPE}")
        off = cls._HDR.size
        if len(data) < off + n:
            raise ProtocolError("APPEARANCE_SET recipe truncated")
        return cls(recipe=data[off:off + n].decode("ascii", errors="replace"))


@dataclass(frozen=True, slots=True)
class AppearanceBroadcastPayload:
    """Server -> clients: peer X's appearance recipe."""
    peer_id: str
    recipe: str

    _HDR: ClassVar[struct.Struct] = struct.Struct("<HH")

    def encode(self) -> bytes:
        raw = self.recipe.encode("ascii", errors="strict")
        if len(raw) > MAX_RECIPE:
            raise ProtocolError(f"recipe too long: {len(raw)} > {MAX_RECIPE}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HDR.pack(len(raw), 0)
            + raw
        )

    @classmethod
    def decode(cls, data: bytes) -> "AppearanceBroadcastPayload":
        base = MAX_CLIENT_ID_LEN + 1
        if len(data) < base + cls._HDR.size:
            raise ProtocolError("APPEARANCE_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        n, _ = cls._HDR.unpack_from(data, base)
        if n > MAX_RECIPE:
            raise ProtocolError(f"APPEARANCE_BCAST recipe_len {n} > {MAX_RECIPE}")
        off = base + cls._HDR.size
        if len(data) < off + n:
            raise ProtocolError("APPEARANCE_BCAST recipe truncated")
        return cls(peer_id=pid,
                   recipe=data[off:off + n].decode("ascii", errors="replace"))


@dataclass(frozen=True, slots=True)
class GlobalVarBroadcastPayload:
    """Server -> other peers: authoritative relay of a GlobalVar.SetValue."""
    peer_id: str
    global_form_id: int
    value: float
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IdQ")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.global_form_id, self.value, self.timestamp_ms)
        )

    @classmethod
    def decode(cls, data: bytes) -> "GlobalVarBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("GLOBAL_VAR_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        fid, val, ts = cls._STRUCT.unpack_from(data, off)
        return cls(peer_id=pid, global_form_id=fid, value=val, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class GlobalVarStateEntry:
    global_form_id: int
    value: float


@dataclass(frozen=True, slots=True)
class GlobalVarStateBootPayload:
    """Server -> client: chunked global-var snapshot on new-peer connect.

    Wire format: ChunkHeader (HHH) + per entry (I d = 12 bytes).
    """
    entries: tuple[GlobalVarStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<Id")
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 12  # 116 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"GLOBAL_VAR_STATE_BOOT too many entries: {len(self.entries)} > "
                f"{self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(
            len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(e.global_form_id, e.value))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "GlobalVarStateBootPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("GLOBAL_VAR_STATE_BOOT header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected:
            raise ProtocolError(
                f"GLOBAL_VAR_STATE_BOOT payload truncated: got {len(data)}, need {expected}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            fid, val = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(GlobalVarStateEntry(global_form_id=fid, value=val))
            off += cls._ENTRY_STRUCT.size
        return cls(entries=tuple(entries), chunk_index=chunk_idx, total_chunks=total)


@dataclass(frozen=True, slots=True)
class DoorOpPayload:
    """B6.1: client -> server: 'I just activated door X'.

    Toggle semantics — sub_140514180 (engine Activate worker) flips the
    door's open state on every call. The op is identity-only; the new
    state isn't carried because we don't need it: the receiver invokes
    its own Activate worker on the matching local REFR, which performs
    the same flip from whatever local state was. Both clients converge
    as long as they started from the same world_base save (engine load
    applies persisted state via vt[0x99] = sub_140510CE0 → all doors
    start in the save's recorded state).

    Identity is the (door_base_id, door_cell_id) tuple, plus form_id
    for the receiver to look up its local REFR. Same approach used by
    container ops — proven in B1 + B5.
    """
    door_form_id: int    # u32 — sender's REFR form_id (lookup_by_form_id on receiver)
    door_base_id: int    # u32 — base TESObjectACTI/DOOR formID (identity check)
    door_cell_id: int    # u32 — cell formID (identity check)
    timestamp_ms: int    # u64 — sender wall clock for ordering / telemetry

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIQ")  # 20B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.door_form_id, self.door_base_id,
            self.door_cell_id, self.timestamp_ms,
        )

    @classmethod
    def decode(cls, data: bytes) -> "DoorOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"DoorOpPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        fid, bid, cid, ts = cls._STRUCT.unpack(data)
        return cls(door_form_id=fid, door_base_id=bid,
                   door_cell_id=cid, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class DoorBroadcastPayload:
    """B6.1: server -> other peers: 'peer X activated door Y'.

    Mirrors DoorOpPayload but adds peer_id for attribution / telemetry.
    No validation server-side; doors are toggle-only and self-correcting
    (next press resyncs).
    """
    peer_id: str                 # ASCII max MAX_CLIENT_ID_LEN
    door_form_id: int
    door_base_id: int
    door_cell_id: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIQ")  # 20B + 16B peer_id = 36B total

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.door_form_id, self.door_base_id,
                self.door_cell_id, self.timestamp_ms,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "DoorBroadcastPayload":
        expected = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size  # 16 + 20 = 36
        if len(data) != expected:
            raise ValueError(
                f"DoorBroadcastPayload: expected {expected} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        fid, bid, cid, ts = cls._STRUCT.unpack(data[MAX_CLIENT_ID_LEN + 1:])
        return cls(peer_id=peer, door_form_id=fid, door_base_id=bid,
                   door_cell_id=cid, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class LockOpPayload:
    """B6.3 v0.5.3 — client -> server: 'I just changed lock state on REFR X'.

    Identity is (lock_form_id, lock_base_id, lock_cell_id) like doors —
    receiver looks up its local REFR via lookup_by_form_id and validates
    against base+cell. New state in `locked`: 0=unlocked, 1=locked.
    Sender hooks engine ForceUnlock (sub_140563320) and ForceLock
    (sub_140563360). Receiver applies via Papyrus binding sub_141158640
    with ai_notify=0 — bypasses minigame and key consumption.
    """
    lock_form_id: int    # u32 — sender's REFR form_id
    lock_base_id: int    # u32 — base form id (identity check)
    lock_cell_id: int    # u32 — cell form id (identity check)
    locked: int          # u8  — 0 = unlocked, 1 = locked
    timestamp_ms: int    # u64 — sender wall clock for ordering / dedup

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIBQ")  # 21B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.lock_form_id, self.lock_base_id, self.lock_cell_id,
            self.locked & 0xFF, self.timestamp_ms,
        )

    @classmethod
    def decode(cls, data: bytes) -> "LockOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"LockOpPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        fid, bid, cid, locked, ts = cls._STRUCT.unpack(data)
        return cls(lock_form_id=fid, lock_base_id=bid, lock_cell_id=cid,
                   locked=locked, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class LockBroadcastPayload:
    """B6.3 v0.5.3 — server -> other peers: 'peer X changed lock state on REFR Y'."""
    peer_id: str
    lock_form_id: int
    lock_base_id: int
    lock_cell_id: int
    locked: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIBQ")  # 21B + 16B peer_id = 37B total

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.lock_form_id, self.lock_base_id, self.lock_cell_id,
                self.locked & 0xFF, self.timestamp_ms,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "LockBroadcastPayload":
        expected = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size
        if len(data) != expected:
            raise ValueError(
                f"LockBroadcastPayload: expected {expected} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        fid, bid, cid, locked, ts = cls._STRUCT.unpack(data[MAX_CLIENT_ID_LEN + 1:])
        return cls(peer_id=peer, lock_form_id=fid, lock_base_id=bid,
                   lock_cell_id=cid, locked=locked, timestamp_ms=ts)


# v28: a piece carries up to 16 mods (a modded weapon on the ground holds 12
# OMOD records; 8 truncated the visible ones away in the first live test).
PIECE_MAX_MODS = 16
_PIECE_FMT = "IiB16If"          # form u32, count i32, mod_n u8, 16 mods, health f32
_PIECE_VALUES = 3 + PIECE_MAX_MODS + 1


def _flatten_pieces(pieces) -> list:
    """v28 wire shape per piece: form u32, count i32, mod_n u8, mods 16*u32,
    health f32 (the stack's Health extra, 0..1; -1.0 = none).

    A piece tuple is (form_id, count, mods_tuple, health); shorter legacy
    shapes are accepted: missing mods = (), missing health = -1.0."""
    flat: list = []
    for entry in list(pieces)[:12]:
        fid, cnt = entry[0], entry[1]
        mods = tuple(entry[2]) if len(entry) > 2 else ()
        mods = mods[:PIECE_MAX_MODS]
        health = float(entry[3]) if len(entry) > 3 else -1.0
        flat.extend((fid, cnt, len(mods)))
        flat.extend(mods)
        flat.extend((0,) * (PIECE_MAX_MODS - len(mods)))
        flat.append(health)
    while len(flat) < 12 * _PIECE_VALUES:
        flat.extend((0, 0, 0) + (0,) * PIECE_MAX_MODS + (-1.0,))
    return flat


def _unflatten_pieces(flat, n) -> tuple:
    out = []
    for i in range(min(n, 12)):
        base = i * _PIECE_VALUES
        fid, cnt, mod_n = flat[base], flat[base + 1], flat[base + 2]
        mods = tuple(flat[base + 3:base + 3 + min(mod_n, PIECE_MAX_MODS)])
        health = flat[base + 3 + PIECE_MAX_MODS]
        out.append((fid, cnt, mods, health))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class WorldSpawnOpPayload:
    """B6.14 v22 — client -> server: 'I just created a REFR in my world'.

    Sender is the PlaceAtMe detour (player-anchored creations only for now:
    console spawns, script spawns on the player). The sender's REFR is
    flagged TEMPORARY the moment this ships: from here on the SERVER owns the
    object's lifetime, and the join bootstrap re-creates it everywhere.
    flags bit0 = transient (broadcast, never persisted).
    flags bit1 = self-described (L5 stage 2, 2026-09-27): pieces[0] is the
    object ITSELF, a dropped item's base, world count, condition and mods;
    the receiver writes them onto its placed copy instead of stocking an
    inventory. Passed through and stored verbatim; no wire change.
    """
    base_form_id: int    # u32 — base form that was placed
    local_form_id: int   # u32 — sender's new REFR (bind target on echo)
    px: float
    py: float
    pz: float
    rx: float
    ry: float
    rz: float
    cell_id: int         # u32
    flags: int           # u8 — bit0 transient
    timestamp_ms: int    # u64
    # v23 — PA frame content at announce: up to 12 (form_id, count) pairs.
    pieces: tuple = ()

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<II6fIBQB" + _PIECE_FMT * 12)  # 970B (v28: 16 mods + health per piece)

    def encode(self) -> bytes:
        flat = _flatten_pieces(self.pieces)
        return self._STRUCT.pack(
            self.base_form_id, self.local_form_id,
            self.px, self.py, self.pz, self.rx, self.ry, self.rz,
            self.cell_id, self.flags & 0xFF, self.timestamp_ms,
            min(len(self.pieces), 12), *flat,
        )

    @classmethod
    def decode(cls, data: bytes) -> "WorldSpawnOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"WorldSpawnOpPayload: expected {cls._STRUCT.size} bytes, "
                f"got {len(data)}")
        vals = cls._STRUCT.unpack(data)
        (base, local, px, py, pz, rx, ry, rz, cell, flags, ts, n) = vals[:12]
        pieces = _unflatten_pieces(vals[12:], n)
        return cls(base, local, px, py, pz, rx, ry, rz, cell, flags, ts,
                   pieces)


@dataclass(frozen=True, slots=True)
class WorldSpawnBroadcastPayload:
    """B6.14 v22 — server -> ALL clients (sender included).

    The sender recognises itself by peer_id and binds wid -> its existing
    REFR instead of placing a second copy. On the join bootstrap peer_id is
    synthesized as 'server' (the lock-bootstrap idiom), so even the original
    spawner re-places: its TEMPORARY original did not survive the restart,
    which is exactly the design — the server owns spawned-object lifetime.
    """
    peer_id: str
    wid: int
    base_form_id: int
    spawner_local_fid: int
    px: float
    py: float
    pz: float
    rx: float
    ry: float
    rz: float
    cell_id: int
    flags: int
    timestamp_ms: int
    # v23 — the server-ledger piece list rides with every spawn broadcast.
    pieces: tuple = ()

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<16sIII6fIBQB" + _PIECE_FMT * 12)  # 990B (v28)

    def encode(self) -> bytes:
        pid = self.peer_id.encode("utf-8")[:16].ljust(16, b"\x00")
        flat = _flatten_pieces(self.pieces)
        return self._STRUCT.pack(
            pid, self.wid, self.base_form_id, self.spawner_local_fid,
            self.px, self.py, self.pz, self.rx, self.ry, self.rz,
            self.cell_id, self.flags & 0xFF, self.timestamp_ms,
            min(len(self.pieces), 12), *flat,
        )

    @classmethod
    def decode(cls, data: bytes) -> "WorldSpawnBroadcastPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"WorldSpawnBroadcastPayload: expected {cls._STRUCT.size} "
                f"bytes, got {len(data)}")
        vals = cls._STRUCT.unpack(data)
        (pid, wid, base, sfid, px, py, pz, rx, ry, rz,
         cell, flags, ts, n) = vals[:14]
        pieces = _unflatten_pieces(vals[14:], n)
        peer = pid.split(b"\x00", 1)[0].decode("utf-8", "replace")
        return cls(peer, wid, base, sfid, px, py, pz, rx, ry, rz,
                   cell, flags, ts, pieces)



@dataclass(frozen=True, slots=True)
class WorldDespawnOpPayload:
    """B6.14 v22 — client -> server: 'spawned object wid just died in my world'.

    Sent by the lifecycle sweep that polls every bound wid: the deleted flag,
    the disabled flag, or vanishing from the form table while its cell is the
    player's current cell all count as death. Reason codes are diagnostic.
    """
    wid: int             # u32
    reason: int          # u8 — 1 deleted, 2 disabled, 3 vanished same-cell
    timestamp_ms: int    # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBQ")  # 13B

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.wid, self.reason & 0xFF,
                                 self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "WorldDespawnOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"WorldDespawnOpPayload: expected {cls._STRUCT.size} bytes, "
                f"got {len(data)}")
        wid, reason, ts = cls._STRUCT.unpack(data)
        return cls(wid, reason, ts)


# L5 realtime R1b (2026-10-05) - the kinds of WorldItemOpPayload.
WORLD_ITEM_DROP = 1
WORLD_ITEM_PICKUP = 2


@dataclass(frozen=True, slots=True)
class WorldItemOpPayload:
    """L5 realtime R1b (v39), client -> server: an item of the player's moved
    between the inventory and the world, as an op of the record.

    Until R1b the record learned a drop and a pickup from the next capture
    only (250 ms after the tap): a crash in that window lost the item twice
    over (the world had moved it, the record had not), and two clients
    picking up the same object of ours both kept it.

    kind WORLD_ITEM_DROP: a Pip-Boy drop that has come to rest. The server
    mints the wid, stores the object self-described (pieces[0] from the
    descriptor), takes the line out of the record and tells everyone with
    WORLD_SPAWN_BCAST (the sender's echo binds the wid to `ref_form_id`).
    kind WORLD_ITEM_PICKUP: a world REFR taken into the inventory. `wid`
    names an object of the server's (removed, WORLD_DESPAWN_BCAST reason 5
    to all); a static `ref_form_id` names a REFR of the save (marked
    disabled, ACTOR_EVENT DISABLE to the others); a runtime one nobody knows
    (a drop never accepted) is trusted, the line only. `client_op_id` is in
    the same sequence as the container ops (epoch << 16 | seq): one
    watermark covers both, the verdict comes back in WORLD_ITEM_ACK, and
    the client holds its captures until it does.

    Wire: u8 kind, u32 client_op_id, u32 item, i32 count, u64 fp, u32
    ref_form_id, u32 wid, u32 cell, 6 x f32 pose, u8 flags, u64 timestamp
    (66 B), then the 104 B descriptor: 170 B."""
    kind: int
    client_op_id: int
    item_base_id: int
    count: int
    item_fp: int
    ref_form_id: int
    wid: int
    cell_id: int
    px: float
    py: float
    pz: float
    rx: float
    ry: float
    rz: float
    flags: int
    timestamp_ms: int
    instance: InstanceDescriptor = InstanceDescriptor()

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<BIIiQIII6fBQ")   # 66 B
    SIZE: ClassVar[int] = 66 + InstanceDescriptor.SIZE                   # 170 B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.kind & 0xFF, self.client_op_id & 0xFFFFFFFF,
            self.item_base_id & 0xFFFFFFFF, self.count,
            self.item_fp & 0xFFFF_FFFF_FFFF_FFFF, self.ref_form_id & 0xFFFFFFFF,
            self.wid & 0xFFFFFFFF, self.cell_id & 0xFFFFFFFF,
            self.px, self.py, self.pz, self.rx, self.ry, self.rz,
            self.flags & 0xFF, self.timestamp_ms & 0xFFFF_FFFF_FFFF_FFFF,
        ) + self.instance.encode()

    @classmethod
    def decode(cls, data: bytes) -> "WorldItemOpPayload":
        if len(data) < cls.SIZE:
            raise ProtocolError("WORLD_ITEM_OP truncated")
        (kind, op_id, item, count, fp, ref, wid, cell, px, py, pz, rx, ry, rz,
         flags, ts) = cls._STRUCT.unpack_from(data, 0)
        desc, _ = InstanceDescriptor.decode(data, cls._STRUCT.size)
        return cls(kind=kind, client_op_id=op_id, item_base_id=item, count=count,
                   item_fp=fp, ref_form_id=ref, wid=wid, cell_id=cell,
                   px=px, py=py, pz=pz, rx=rx, ry=ry, rz=rz, flags=flags,
                   timestamp_ms=ts, instance=desc)


@dataclass(frozen=True, slots=True)
class WorldItemAckPayload:
    """L5 realtime R1b (v39), server -> sender: the verdict of a WORLD_ITEM_OP,
    by `client_op_id`. `status` is a ContainerOpAckStatus: ACCEPTED, or a
    refusal the client undoes (a drop refused: the REFR goes, the item comes
    back; a pickup refused: the item is destroyed, REJ_INSUFFICIENT meaning
    someone else took the object first). `wid` is the wid minted for a drop
    or the one a pickup removed, `record_count` the record's line after the
    op.

    Wire: u32 op id, u8 status, u8 kind, u32 wid, u32 item, u64 fp, i32
    record count: 26 B."""
    client_op_id: int
    status: int
    kind: int
    wid: int
    item_base_id: int
    item_fp: int
    record_count: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBBIIQi")   # 26 B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.client_op_id & 0xFFFFFFFF, self.status & 0xFF, self.kind & 0xFF,
            self.wid & 0xFFFFFFFF, self.item_base_id & 0xFFFFFFFF,
            self.item_fp & 0xFFFF_FFFF_FFFF_FFFF, self.record_count)

    @classmethod
    def decode(cls, data: bytes) -> "WorldItemAckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("WORLD_ITEM_ACK truncated")
        op_id, status, kind, wid, item, fp, n = cls._STRUCT.unpack_from(data, 0)
        return cls(client_op_id=op_id, status=status, kind=kind, wid=wid,
                   item_base_id=item, item_fp=fp, record_count=n)


INV_STATE_FLAG_COMPLETE = 0x01
INV_STATE_FLAG_IN_POWER_ARMOR = 0x02
INV_ENTRY_EQUIPPED = 0x01


@dataclass(frozen=True, slots=True)
class InvStateEntry:
    """One line of the player's inventory: an instance and how many (17 B)."""
    item_base_id: int          # u32
    item_fp: int               # u64 - the instance fingerprint (FP_PLAIN, FP_UNKNOWN or one)
    count: int                 # i32, > 0
    flags: int = 0             # u8 - INV_ENTRY_*


@dataclass(frozen=True, slots=True)
class InvStatePayload:
    """L5 realtime persistence, R1 (v35), client -> server: the player's
    whole inventory by instance, as one capture saw it.

    The server keeps the last one as the player's record, with the
    container ops it accepted after `watermark` (the id of the last op the
    client had sent when it captured; every op up to it had its verdict
    applied) on top. The client sends one at every change, only from a
    complete capture, only with no op in flight and only once the record
    has been restored after the load. A capture spans `total_chunks`
    frames sharing (session, seq); the server applies it whole.

    Wire: u32 session, u32 seq, u32 watermark, u16 op_epoch, u8 flags,
    u8 pad, u64 digest, u16 num_entries, u16 chunk_index, u16
    total_chunks (30 B), then per line u32 item, u64 fp, i32 count, u8
    flags (17 B). 80 lines per frame."""
    session: int               # u32 - random per client process, never 0
    seq: int                   # u32 - the capture's number in that process
    watermark: int             # u32 - the last container op id sent before it (0 = none)
    op_epoch: int              # u16 - the high half of this process's op ids
    flags: int                 # u8 - INV_STATE_FLAG_*
    digest: int                # u64 - the capture's digest (FNV-1a 64)
    entries: tuple[InvStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IIIHBBQHHH")   # 30 B
    _ENTRY: ClassVar[struct.Struct] = struct.Struct("<IQiB")           # 17 B
    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (MAX_PAYLOAD_SIZE - 30) // 17   # 80

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"INV_STATE too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}")
        parts = [self._HEADER.pack(
            self.session & 0xFFFFFFFF, self.seq & 0xFFFFFFFF, self.watermark & 0xFFFFFFFF,
            self.op_epoch & 0xFFFF, self.flags & 0xFF, 0, self.digest & 0xFFFFFFFFFFFFFFFF,
            len(self.entries), self.chunk_index & 0xFFFF, self.total_chunks & 0xFFFF)]
        for e in self.entries:
            parts.append(self._ENTRY.pack(e.item_base_id & 0xFFFFFFFF,
                                          e.item_fp & 0xFFFFFFFFFFFFFFFF,
                                          e.count, e.flags & 0xFF))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "InvStatePayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("INV_STATE header truncated")
        (session, seq, watermark, epoch, flags, _pad, digest,
         num, chunk_idx, total) = cls._HEADER.unpack_from(data, 0)
        if len(data) < cls._HEADER.size + num * cls._ENTRY.size:
            raise ProtocolError("INV_STATE payload truncated")
        off = cls._HEADER.size
        entries = []
        for _ in range(num):
            item, fp, count, eflags = cls._ENTRY.unpack_from(data, off)
            entries.append(InvStateEntry(item, fp, count, eflags))
            off += cls._ENTRY.size
        return cls(session=session, seq=seq, watermark=watermark, op_epoch=epoch,
                   flags=flags, digest=digest, entries=tuple(entries),
                   chunk_index=chunk_idx, total_chunks=total)


RESTORE_REASON_BOOT = 0
RESTORE_REASON_DEATH = 1
RESTORE_REASON_RETRY = 2
RESTORE_REASON = {0: "boot", 1: "death", 2: "retry"}

PLAYER_INV_RECORD = 0   # the record, current up to the client's last capture
PLAYER_INV_NONE = 1     # nothing to align to (no record, or no capture under it)
PLAYER_INV_BEHIND = 2   # the record, but the client's last capture never arrived
PLAYER_INV_STATUS = {0: "record", 1: "none", 2: "behind"}

RESTORE_ALIGNED = 0     # every line of the record is in the game
RESTORE_PARTIAL = 1     # some lines could not be built or removed (counted)
RESTORE_NOTHING = 2     # PLAYER_INV said none: the game is the record
RESTORE_FAILED = 3      # the alignment did not run; the record stays closed
RESTORE_OUTCOME = {0: "aligned", 1: "partial", 2: "nothing to restore", 3: "failed"}


@dataclass(frozen=True, slots=True)
class RestoreRequestPayload:
    """L5 realtime R2 (v36), client -> server: a load is coming (the boot, or
    the reload after a death), send me my record. `session` is the
    process's INV_STATE session, `last_seq` the last inventory capture it
    sent and `last_stats_seq` (v37) the last STATS_STATE (0 = none): the
    server answers once both are in the record, or after a wait with what it
    has (PLAYER_INV_BEHIND). Wire: <IIIB3x = 16 B."""
    session: int          # u32
    last_seq: int         # u32
    reason: int           # u8 - RESTORE_REASON_*
    last_stats_seq: int = 0   # u32 - v37

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIB3x")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.session & 0xFFFFFFFF, self.last_seq & 0xFFFFFFFF,
                                 self.last_stats_seq & 0xFFFFFFFF, self.reason & 0xFF)

    @classmethod
    def decode(cls, data: bytes) -> "RestoreRequestPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("RESTORE_REQUEST truncated")
        session, last_seq, last_stats_seq, reason = cls._STRUCT.unpack_from(data, 0)
        return cls(session=session, last_seq=last_seq, reason=reason,
                   last_stats_seq=last_stats_seq)


@dataclass(frozen=True, slots=True)
class PlayerInvPayload:
    """L5 realtime R2 (v36), server -> client: the player's record, the
    lines to align the player to after the load. Preceded by INSTANCE_DEFS
    with the descriptors of its named instances. Wire: u32 session (the
    request's), u32 record_seq, u32 captures, u8 status, u8 pad, u16
    num_entries, u16 chunk_index, u16 total_chunks (20 B), then lines as in
    INV_STATE (17 B), 81 per frame."""
    session: int     # u32
    record_seq: int  # u32 - the capture the record stands on
    captures: int    # u32
    status: int      # u8 - PLAYER_INV_*
    entries: tuple[InvStateEntry, ...] = ()
    chunk_index: int = 0
    total_chunks: int = 1

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IIIBBHHH")   # 20 B
    _ENTRY: ClassVar[struct.Struct] = struct.Struct("<IQiB")         # 17 B
    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (MAX_PAYLOAD_SIZE - 20) // 17   # 81

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"PLAYER_INV too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}")
        parts = [self._HEADER.pack(self.session & 0xFFFFFFFF, self.record_seq & 0xFFFFFFFF,
                                   self.captures & 0xFFFFFFFF, self.status & 0xFF, 0,
                                   len(self.entries), self.chunk_index & 0xFFFF,
                                   self.total_chunks & 0xFFFF)]
        for e in self.entries:
            parts.append(self._ENTRY.pack(e.item_base_id & 0xFFFFFFFF,
                                          e.item_fp & 0xFFFFFFFFFFFFFFFF,
                                          e.count, e.flags & 0xFF))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "PlayerInvPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("PLAYER_INV header truncated")
        session, seq, captures, status, _pad, num, idx, total = cls._HEADER.unpack_from(data, 0)
        if len(data) < cls._HEADER.size + num * cls._ENTRY.size:
            raise ProtocolError("PLAYER_INV payload truncated")
        off = cls._HEADER.size
        entries = []
        for _ in range(num):
            item, fp, count, eflags = cls._ENTRY.unpack_from(data, off)
            entries.append(InvStateEntry(item, fp, count, eflags))
            off += cls._ENTRY.size
        return cls(session=session, record_seq=seq, captures=captures, status=status,
                   entries=tuple(entries), chunk_index=idx, total_chunks=total)


@dataclass(frozen=True, slots=True)
class RestoreDonePayload:
    """L5 realtime R2 (v36), client -> server: what the alignment did. Any
    outcome but RESTORE_FAILED opens the record to the process: its captures
    are the record from now. Wire: <IIBBHHHQ = 24 B."""
    session: int      # u32
    record_seq: int   # u32 - the PLAYER_INV it aligned to
    outcome: int      # u8 - RESTORE_*
    removed: int      # u16 - lines whose surplus was removed
    added: int        # u16 - lines whose shortfall was built
    unresolved: int   # u16 - lines left as they were (counted in the log)
    digest: int       # u64 - the capture after the alignment

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIBBHHHQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.session & 0xFFFFFFFF, self.record_seq & 0xFFFFFFFF,
                                 self.outcome & 0xFF, 0, self.removed & 0xFFFF,
                                 self.added & 0xFFFF, self.unresolved & 0xFFFF,
                                 self.digest & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "RestoreDonePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("RESTORE_DONE truncated")
        session, seq, outcome, _pad, removed, added, unresolved, digest = \
            cls._STRUCT.unpack_from(data, 0)
        return cls(session=session, record_seq=seq, outcome=outcome, removed=removed,
                   added=added, unresolved=unresolved, digest=digest)


SPECIAL_COUNT = 7       # Strength, Perception, Endurance, Charisma, Intelligence, Agility, Luck
STATS_FLAG_COMPLETE = 0x01
STATS_MAX_PERKS = 2048


@dataclass(frozen=True, slots=True)
class PerkEntry:
    """One perk the player holds and its rank (5 B). In Fallout 4 every
    rank of the perk chart is a form of its own, rank 1."""
    perk_form_id: int     # u32
    rank: int             # u8, >= 1


@dataclass(frozen=True, slots=True)
class PlayerStatsPayload:
    """L5 realtime R4 (v37): the character's numbers. STATS_STATE (client ->
    server, `flags` bit0 complete) at every change; PLAYER_STATS (server ->
    client) in the restore answer, `status` a PLAYER_INV_* code. XP is the
    current value of the Experience actor value (the level follows from it
    in the engine), `special` the seven base values, health, action points
    and rads the current ones. A capture spans `total_chunks` frames sharing
    (session, seq); every chunk repeats the numbers and carries a slice of
    the perks. Wire: <IIBBHfBB7ffffHHH = 64 B, then perks <IB = 5 B, 267
    per frame."""
    session: int
    seq: int
    status: int
    flags: int
    level: int            # u16
    xp: float
    perk_points: int      # u8
    special: tuple
    health: float
    action_points: float
    rads: float
    perks: tuple = ()
    chunk_index: int = 0
    total_chunks: int = 1

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IIBBHfBB7ffffHHH")   # 64 B
    _PERK: ClassVar[struct.Struct] = struct.Struct("<IB")                  # 5 B
    MAX_PERKS_PER_FRAME: ClassVar[int] = (MAX_PAYLOAD_SIZE - 64) // 5       # 267

    def encode(self) -> bytes:
        if len(self.special) != SPECIAL_COUNT:
            raise ProtocolError(f"stats: {len(self.special)} SPECIAL values, not {SPECIAL_COUNT}")
        if len(self.perks) > self.MAX_PERKS_PER_FRAME:
            raise ProtocolError(
                f"stats: too many perks in one frame: {len(self.perks)} > {self.MAX_PERKS_PER_FRAME}")
        parts = [self._HEADER.pack(
            self.session & 0xFFFFFFFF, self.seq & 0xFFFFFFFF, self.status & 0xFF,
            self.flags & 0xFF, self.level & 0xFFFF, self.xp, self.perk_points & 0xFF, 0,
            *self.special, self.health, self.action_points, self.rads,
            len(self.perks), self.chunk_index & 0xFFFF, self.total_chunks & 0xFFFF)]
        for pe in self.perks:
            parts.append(self._PERK.pack(pe.perk_form_id & 0xFFFFFFFF, pe.rank & 0xFF))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "PlayerStatsPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("stats header truncated")
        v = cls._HEADER.unpack_from(data, 0)
        session, seq, status, flags, level, xp, points, _pad = v[:8]
        special = tuple(v[8:15])
        health, ap, rads, num, idx, total = v[15:21]
        if len(data) < cls._HEADER.size + num * cls._PERK.size:
            raise ProtocolError("stats perks truncated")
        off = cls._HEADER.size
        perks = []
        for _ in range(num):
            form, rank = cls._PERK.unpack_from(data, off)
            perks.append(PerkEntry(form, rank))
            off += cls._PERK.size
        return cls(session=session, seq=seq, status=status, flags=flags, level=level, xp=xp,
                   perk_points=points, special=special, health=health, action_points=ap,
                   rads=rads, perks=tuple(perks), chunk_index=idx, total_chunks=total)


# L5 realtime D1 (v38): a world spawn whose content the server keeps as a
# container (the death crate), keyed 0xFF000000 | wid on the container wire.
WORLD_SPAWN_FLAG_CONTAINER = 0x04
# L5 stage 2 (2026-09-27): pieces[0] is the object ITSELF (a dropped item's base,
# count, mods and condition), not an inventory. The server sets it on every
# drop it records (R1b).
WORLD_SPAWN_FLAG_SELF_DESCRIBED = 0x02


def wid_container_key(wid: int) -> int:
    """The container key of the world spawn `wid` (D1)."""
    return 0xFF000000 | (wid & 0xFFFFFF)


def is_wid_container_key(form_id: int) -> bool:
    """A container key of a world spawn: 0xFF prefix, a wid under it."""
    return (form_id & 0xFF000000) == 0xFF000000 and (form_id & 0xFFFFFF) != 0


# 2026-10-05 - the "body" armours of a power armour frame (Fallout4.esm, every
# ARMO named ArmorPoweredFrame*): the engine puts one on the player on
# entering a frame and takes it off on leaving, and it occupies biped slot 30,
# the Pip-Boy's. They are never inventory: a capture drops them, a crate never
# holds them, a record never names them, and the restore takes them off a
# player on foot. Live tests of 2026-10-04/05: the raider one (0x1909D6) went
# into the death crate as loot, came back on the player with the loot, and
# every exit from a frame since left it equipped over the Pip-Boy, which then
# opened blurred with no device at the wrist.
PA_FRAME_WEARABLES = frozenset({
    0x0003E577,   # ArmorPoweredFrame
    0x001909D6,   # ArmorPoweredFrameRaider
    0x001909D5,   # ArmorPoweredFrameWastelander
    0x001909D1,   # ArmorPoweredFrameAtomCat
    0x00198B13,   # ArmorPoweredFrameBOS
    0x00140D7B,   # ArmorPoweredFrameIngram
    0x000B1C09,   # ArmorPoweredFrameWithModsNoHelmet
})

INV_DIGEST_FLAG_COMPLETE = 0x01
INV_DIGEST_FLAG_IN_POWER_ARMOR = 0x02
INV_DIGEST_WHY = {0: "changed", 1: "checkpoint", 2: "exit", 3: "first"}


@dataclass(frozen=True, slots=True)
class InvDigestPayload:
    """L5 stage 2 (2026-09-27) — client -> server: the player's inventory as
    the client's capture saw it, in one line: digest, counts, why it was sent.

    ADVISORY. The server records the last one per peer (journal + snapshot)
    and acts on nothing: stage 3 compares a checkpoint against the digest on
    record, stage 4's ledger is what will judge an inventory. The client sends
    it when the digest of a COMPLETE capture changes (at most every 10 s),
    before a test checkpoint and on the way out; an incomplete capture is
    never sent.
    """
    seq: int           # u32 — capture number in the client's session
    wall_ms: int       # u64 — client wall clock of the capture (Unix ms)
    digest: int        # u64 — FNV-1a 64 over the canonical records
    entries: int       # u32
    stacks: int        # u32 (transient stacks excluded)
    items: int         # u32 — sum of the stack counts
    reasons: int       # u32 — 0 = complete
    flags: int         # u8 — bit0 complete, bit1 in power armor
    why: int           # u8 — INV_DIGEST_WHY

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IQQIIIIBB")  # 38B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.seq & 0xFFFFFFFF, self.wall_ms & 0xFFFFFFFFFFFFFFFF,
            self.digest & 0xFFFFFFFFFFFFFFFF, self.entries & 0xFFFFFFFF,
            self.stacks & 0xFFFFFFFF, self.items & 0xFFFFFFFF,
            self.reasons & 0xFFFFFFFF, self.flags & 0xFF, self.why & 0xFF)

    @classmethod
    def decode(cls, data: bytes) -> "InvDigestPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"InvDigestPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        return cls(*cls._STRUCT.unpack(data))


# L5 stage 3a (2026-09-28) — the commanded checkpoint. See the C++ header
# for the contract; the codes and sizes here are the same bytes.
CKPT_NAME_MAX = 47                     # 48 bytes on the wire, null-terminated
CKPT_REASON = {0: "periodic", 1: "demand", 2: "exit", 3: "test"}
CKPT_STATUS = {0: "ok", 1: "deferred", 2: "save failed", 3: "no device", 4: "refused"}
BOOT_OUTCOME = {0: "checkpoint", 1: "genesis: none offered", 2: "genesis: file missing",
                3: "genesis: hash mismatch", 4: "genesis: checkpoint load failed",
                5: "genesis: no decision in time"}


@dataclass(frozen=True, slots=True)
class CkptRequestPayload:
    """server -> client: write a checkpoint at your next quiet moment."""
    seq: int          # u32
    reason: int       # u8 — CKPT_REASON
    deadline_s: int   # u16

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBH")  # 7B

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.seq & 0xFFFFFFFF, self.reason & 0xFF,
                                 self.deadline_s & 0xFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "CkptRequestPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(f"CkptRequestPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        return cls(*cls._STRUCT.unpack(data))


@dataclass(frozen=True, slots=True)
class CkptDonePayload:
    """client -> server: the checkpoint written, or why it was not."""
    seq: int          # u32 — the request answered (0 = unsolicited: exit, test key)
    status: int       # u8 — CKPT_STATUS
    name: str         # ASCII, max 47
    sha256: bytes     # 32 bytes
    size: int         # u32
    digest: int       # u64 — the inventory digest of the same instant (0 = none)
    digest_seq: int   # u32
    wall_ms: int      # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IB48s32sIQIQ")  # 109B

    def encode(self) -> bytes:
        sha = (self.sha256 or b"")[:32].ljust(32, b"\x00")
        return self._STRUCT.pack(
            self.seq & 0xFFFFFFFF, self.status & 0xFF,
            _encode_fixed_string(self.name, CKPT_NAME_MAX), sha,
            self.size & 0xFFFFFFFF, self.digest & 0xFFFFFFFFFFFFFFFF,
            self.digest_seq & 0xFFFFFFFF, self.wall_ms & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "CkptDonePayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(f"CkptDonePayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        seq, status, name, sha, size, digest, dseq, wall = cls._STRUCT.unpack(data)
        # An all-zero hash means "none" (a failed checkpoint has no file):
        # kept as b"" so callers test truthiness, like the resume token.
        if not any(sha):
            sha = b""
        return cls(seq, status, _decode_fixed_string(name, CKPT_NAME_MAX), sha,
                   size, digest, dseq, wall)


@dataclass(frozen=True, slots=True)
class CkptCandidate:
    """v31 — one checkpoint the client may boot from (CKPT_BOOT carries up
    to three, newest first) and whether the server holds its bytes."""
    name: str
    sha256: bytes
    size: int
    seq: int
    custody: bool

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<48s32sIIB")  # 89B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            _encode_fixed_string(self.name or "", CKPT_NAME_MAX),
            (self.sha256 or b"")[:32].ljust(32, b"\x00"),
            self.size & 0xFFFFFFFF, self.seq & 0xFFFFFFFF, 1 if self.custody else 0)

    @classmethod
    def decode(cls, data: bytes) -> "CkptCandidate":
        name, sha, size, seq, custody = cls._STRUCT.unpack(data)
        return cls(_decode_fixed_string(name, CKPT_NAME_MAX), sha if any(sha) else b"",
                   size, seq, bool(custody))


CKPT_CANDIDATES_MAX = 3


@dataclass(frozen=True, slots=True)
class CkptBootPayload:
    """server -> client, first bootstrap stage: boot from this checkpoint."""
    has: bool         # u8 — 0 = boot from the genesis save
    seq: int          # u32 — the server's record number
    name: str
    sha256: bytes
    size: int
    digest: int
    # v30 — the last known position, when newer than the checkpoint (see the
    # C++ header): the client teleports there once the loaded scene settled.
    has_pos: bool = False
    px: float = 0.0
    py: float = 0.0
    pz: float = 0.0
    yaw: float = 0.0
    pos_ms: int = 0
    # v31 — custody (stage 3b): the TCP port of the server's bulk service
    # (0 = none, the bytes stay on the client's disk), the token this
    # session uploads and fetches under, and the checkpoints on record
    # newest first, each with whether the server holds its bytes. The
    # client boots the newest it can get: on its disk, or fetched.
    bulk_port: int = 0
    token: bytes = b""
    candidates: tuple = ()
    # v32 — the respawn point (stage 3c): where a dead player comes back
    # without a reload. has_respawn False = the server names none and a
    # death reloads the last checkpoint, as in stage 3a.
    has_respawn: bool = False
    respawn_pos: tuple = (0.0, 0.0, 0.0)
    respawn_yaw: float = 0.0

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<BI48s32sIQB3ffQH32sB")  # 157B head
    _TAIL: ClassVar[struct.Struct] = struct.Struct("<B3ff")                    # 17B, after the candidates
    SIZE: ClassVar[int] = 157 + CKPT_CANDIDATES_MAX * 89 + 17                   # 441B

    def encode(self) -> bytes:
        sha = (self.sha256 or b"")[:32].ljust(32, b"\x00")
        if len(self.candidates) > CKPT_CANDIDATES_MAX:
            raise ProtocolError("too many boot candidates")
        head = self._STRUCT.pack(
            1 if self.has else 0, self.seq & 0xFFFFFFFF,
            _encode_fixed_string(self.name or "", CKPT_NAME_MAX), sha,
            self.size & 0xFFFFFFFF, self.digest & 0xFFFFFFFFFFFFFFFF,
            1 if self.has_pos else 0, self.px, self.py, self.pz, self.yaw,
            self.pos_ms & 0xFFFFFFFFFFFFFFFF,
            self.bulk_port & 0xFFFF, (self.token or b"")[:32].ljust(32, b"\x00"),
            len(self.candidates))
        tail = b"".join(c.encode() for c in self.candidates)
        tail += bytes(CkptCandidate._STRUCT.size) * (CKPT_CANDIDATES_MAX - len(self.candidates))
        rp = tuple(self.respawn_pos) + (0.0, 0.0, 0.0)
        tail += self._TAIL.pack(1 if self.has_respawn else 0, float(rp[0]), float(rp[1]),
                                float(rp[2]), float(self.respawn_yaw))
        return head + tail

    @classmethod
    def decode(cls, data: bytes) -> "CkptBootPayload":
        if len(data) != cls.SIZE:
            raise ValueError(f"CkptBootPayload: expected {cls.SIZE} bytes, got {len(data)}")
        (has, seq, name, sha, size, digest,
         has_pos, px, py, pz, yaw, pos_ms,
         bulk_port, token, n) = cls._STRUCT.unpack(data[:cls._STRUCT.size])
        if not any(sha):
            sha = b""
        if not any(token):
            token = b""
        csz = CkptCandidate._STRUCT.size
        cands = []
        for i in range(min(n, CKPT_CANDIDATES_MAX)):
            off = cls._STRUCT.size + i * csz
            cands.append(CkptCandidate.decode(data[off:off + csz]))
        toff = cls._STRUCT.size + CKPT_CANDIDATES_MAX * csz
        has_rp, rx, ry, rz, ryaw = cls._TAIL.unpack(data[toff:toff + cls._TAIL.size])
        return cls(bool(has), seq, _decode_fixed_string(name, CKPT_NAME_MAX), sha, size, digest,
                   bool(has_pos), px, py, pz, yaw, pos_ms, bulk_port, token, tuple(cands),
                   bool(has_rp), (rx, ry, rz), ryaw)


@dataclass(frozen=True, slots=True)
class PlayerLifePayload:
    """client -> server (v32, stage 3c): the local player died, respawned
    without a reload, or fell back to the reload."""
    event: int        # u8 — PLAYER_LIFE_EVENTS
    pos: tuple        # 3 x f32, where it happened
    wall_ms: int      # u64, client clock

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<B3fQ")  # 21B

    def encode(self) -> bytes:
        p = tuple(self.pos) + (0.0, 0.0, 0.0)
        return self._STRUCT.pack(self.event & 0xFF, float(p[0]), float(p[1]), float(p[2]),
                                 self.wall_ms & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "PlayerLifePayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(f"PlayerLifePayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        event, x, y, z, wall = cls._STRUCT.unpack(data)
        return cls(event, (x, y, z), wall)


PLAYER_LIFE_EVENTS = {0: "died", 1: "respawned", 2: "reload fallback"}


@dataclass(frozen=True, slots=True)
class CkptRespawnPayload:
    """server -> client (v33, stage 3d): the answer to a death. has = 1: the
    server booked `name`, the player's boot checkpoint moved onto the respawn
    point, in custody; the client fetches it and loads it instead of the
    engine's reload (one loading screen, no fast travel; a worn power
    armour frame moves with the player). has = 0: no such checkpoint (no
    point, no custody, an interior, a frame that cannot be found): the
    engine's reload and the fast travel of stage 3c run."""
    has: bool
    name: str
    sha256: bytes
    size: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<B48s32sI")  # 85B

    def encode(self) -> bytes:
        return self._STRUCT.pack(1 if self.has else 0,
                                 _encode_fixed_string(self.name or "", CKPT_NAME_MAX),
                                 (self.sha256 or b"")[:32].ljust(32, b"\x00"),
                                 self.size & 0xFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "CkptRespawnPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(f"CkptRespawnPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        has, name, sha, size = cls._STRUCT.unpack(data)
        return cls(bool(has), _decode_fixed_string(name, CKPT_NAME_MAX),
                   sha if any(sha) else b"", size)


@dataclass(frozen=True, slots=True)
class BootResultPayload:
    """client -> server: what the client actually loaded at boot."""
    seq: int          # u32 — the CKPT_BOOT answered (0 = none received)
    outcome: int      # u8 — BOOT_OUTCOME
    name: str         # what was loaded
    wall_ms: int      # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IB48sQ")  # 61B

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.seq & 0xFFFFFFFF, self.outcome & 0xFF,
                                 _encode_fixed_string(self.name or "", CKPT_NAME_MAX),
                                 self.wall_ms & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "BootResultPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(f"BootResultPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        seq, outcome, name, wall = cls._STRUCT.unpack(data)
        return cls(seq, outcome, _decode_fixed_string(name, CKPT_NAME_MAX), wall)


@dataclass(frozen=True, slots=True)
class WorldDespawnBroadcastPayload:
    """B6.14 v22 — server -> ALL clients: drop your copy of wid.

    The reporter included: it already lost its local object, so its handler
    just unbinds the registry entry. Everyone else disables their copy.
    """
    peer_id: str
    wid: int
    reason: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<16sIBQ")  # 29B

    def encode(self) -> bytes:
        pid = self.peer_id.encode("utf-8")[:16].ljust(16, bytes(1))
        return self._STRUCT.pack(pid, self.wid, self.reason & 0xFF,
                                 self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "WorldDespawnBroadcastPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"WorldDespawnBroadcastPayload: expected {cls._STRUCT.size} "
                f"bytes, got {len(data)}")
        pid, wid, reason, ts = cls._STRUCT.unpack(data)
        peer = pid.split(bytes(1), 1)[0].decode("utf-8", "replace")
        return cls(peer, wid, reason, ts)


@dataclass(frozen=True, slots=True)
class WorldPaPiecesOpPayload:
    """v23 — client -> server: full piece list for wid after a manual
    take/put on a PA frame. Full-state on purpose: the server ledger is
    REPLACED, never patched, so delta-ordering bugs cannot exist."""
    wid: int             # u32
    timestamp_ms: int    # u64
    pieces: tuple = ()   # up to 12 (form_id, count) pairs

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<IB" + _PIECE_FMT * 12 + "Q")  # 937B (v28)

    def encode(self) -> bytes:
        flat = _flatten_pieces(self.pieces)
        return self._STRUCT.pack(self.wid, min(len(self.pieces), 12),
                                 *flat, self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "WorldPaPiecesOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"WorldPaPiecesOpPayload: expected {cls._STRUCT.size} "
                f"bytes, got {len(data)}")
        vals = cls._STRUCT.unpack(data)
        wid, n = vals[0], vals[1]
        pieces = _unflatten_pieces(vals[2:-1], n)
        ts = vals[-1]
        return cls(wid, ts, pieces)


@dataclass(frozen=True, slots=True)
class WorldPaPiecesBroadcastPayload:
    """v23 — server -> OTHER clients (reporter excluded): replace your
    replica's content for wid. Applied by destroy-and-replace client-side."""
    peer_id: str
    wid: int
    timestamp_ms: int
    pieces: tuple = ()

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<16sIB" + _PIECE_FMT * 12 + "Q")  # 953B (v28)

    def encode(self) -> bytes:
        pid = self.peer_id.encode("utf-8")[:16].ljust(16, bytes(1))
        flat = _flatten_pieces(self.pieces)
        return self._STRUCT.pack(pid, self.wid, min(len(self.pieces), 12),
                                 *flat, self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "WorldPaPiecesBroadcastPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"WorldPaPiecesBroadcastPayload: expected {cls._STRUCT.size} "
                f"bytes, got {len(data)}")
        vals = cls._STRUCT.unpack(data)
        pid, wid, n = vals[0], vals[1], vals[2]
        pieces = _unflatten_pieces(vals[3:-1], n)
        ts = vals[-1]
        peer = pid.split(bytes(1), 1)[0].decode("utf-8", "replace")
        return cls(peer, wid, ts, pieces)


@dataclass(frozen=True, slots=True)
class EquipModRecord:
    """M9.w4 v7 — single OMOD attachment record (8 B).

    Mirrors the runtime ObjectModifier in BGSObjectInstanceExtra.inner.data.
    Each weapon/armor with mods carries an array of these. form_id is the
    TESForm.formID of a BGSMod::Attachment::Mod (formType=0x90); the
    receiver looks it up locally and applies to the ghost weapon NIF.

    Empirically across vanilla weapons: attach_index = 0 and rank = 1 in
    nearly all observed records (the actual attach-slot info is inside
    the BGSMod itself, not the OIE record). flag is always 0. pad must
    be 0 on encode (engine leaves uninitialised garbage at runtime, the
    DLL zeros it before send).
    """
    form_id: int        # u32 — BGSMod::Attachment::Mod.formID (formType 0x90)
    attach_index: int   # u8  — slot index (typically 0)
    rank: int           # u8  — index2/rank (typically 1)
    flag: int           # u8  — engine flag (typically 0)
    pad: int = 0        # u8  — MUST be zero on encode

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBBBB")  # 4+1+1+1+1 = 8B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id, self.attach_index, self.rank, self.flag, 0)

    @classmethod
    def decode(cls, data: bytes) -> "EquipModRecord":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"EquipModRecord: expected {cls._STRUCT.size} bytes, got {len(data)}")
        f, ai, rk, fl, _pad = cls._STRUCT.unpack(data)
        return cls(form_id=f, attach_index=ai, rank=rk, flag=fl, pad=0)


# Cap on per-weapon mod count. Vanilla ≤12; DLC up to ~20; 32 = safe ceiling.
MAX_EQUIP_MODS: int = 32


# === M9.w4 (witness) v8 — NIF descriptor records ===========================

# Cap on per-weapon NIF descriptors that the witness walker captures.
# Vanilla mods on a single weapon ≤6 typical; cap also bounded by
# MAX_PAYLOAD_SIZE remaining after fixed payload + OMOD records.
MAX_NIF_DESCRIPTORS: int = 8

# Per-string caps. Observed vanilla NIF paths max ~96 chars (Far Harbor
# harpoon mods); 192 cap leaves headroom for community mods. Parent node
# names are short — typically named NiNode attach points like
# "BarrelAttachNode" or "ScopeAttachNode". 64 cap is generous.
MAX_NIF_PATH_LEN: int = 192
MAX_NIF_NAME_LEN: int = 64


@dataclass(frozen=True, slots=True)
class NifDescriptor:
    """M9.w4 v8 — single NIF descriptor for a mod attached to a weapon.

    Sender extracts these by walking its own BipedAnim weapon subtree
    after the engine has finished mod assembly (post-equip). For each
    NiAVObject in the subtree that's a cache-hit on the nif_load_by_path
    detour (RVA 0x017B3E90), it records the .nif path, the parent node
    name, and the local NiTransform (16 floats = rotation 3x4 + translate
    vec3 + scale).

    Wire layout (variable-length per record):
        u8  path_len           # 0..192
        path_bytes (ASCII)
        u8  parent_name_len    # 0..64
        parent_name_bytes
        16 × float local_transform  # 64 bytes raw
    """
    nif_path: str
    parent_name: str
    # 16 floats = NiTransform from node+0x30..+0x70 (rot 3x4 SIMD + vec3 + scale).
    # Indices 12,13,14 hold local translate; index 15 holds local scale.
    local_transform: tuple  # tuple of 16 floats

    _XFORM_STRUCT: ClassVar[struct.Struct] = struct.Struct("<16f")  # 64B

    def encode(self) -> bytes:
        path_b = self.nif_path.encode("utf-8")[:MAX_NIF_PATH_LEN]
        name_b = self.parent_name.encode("utf-8")[:MAX_NIF_NAME_LEN]
        if len(self.local_transform) != 16:
            raise ValueError(
                f"NifDescriptor.local_transform: expected 16 floats, "
                f"got {len(self.local_transform)}")
        return (
            bytes([len(path_b)]) + path_b
            + bytes([len(name_b)]) + name_b
            + self._XFORM_STRUCT.pack(*self.local_transform)
        )

    @classmethod
    def decode_from(cls, data: bytes, offset: int = 0):
        """Decode a single NifDescriptor starting at `offset`. Returns
        (descriptor, bytes_consumed). Raises ValueError on malformed data.
        """
        if offset + 1 > len(data):
            raise ValueError("NifDescriptor: truncated path_len")
        pl = data[offset]
        if pl > MAX_NIF_PATH_LEN:
            raise ValueError(
                f"NifDescriptor: path_len {pl} exceeds cap {MAX_NIF_PATH_LEN}")
        off = offset + 1
        if off + pl + 1 > len(data):
            raise ValueError("NifDescriptor: truncated path / parent_len")
        path = data[off:off + pl].decode("utf-8", errors="replace")
        off += pl
        nl = data[off]
        if nl > MAX_NIF_NAME_LEN:
            raise ValueError(
                f"NifDescriptor: parent_name_len {nl} exceeds cap "
                f"{MAX_NIF_NAME_LEN}")
        off += 1
        if off + nl + cls._XFORM_STRUCT.size > len(data):
            raise ValueError("NifDescriptor: truncated parent_name / xform")
        name = data[off:off + nl].decode("utf-8", errors="replace")
        off += nl
        xf = cls._XFORM_STRUCT.unpack(data[off:off + cls._XFORM_STRUCT.size])
        off += cls._XFORM_STRUCT.size
        return cls(nif_path=path, parent_name=name, local_transform=xf), off - offset


def _encode_nif_tail(descs: tuple) -> bytes:
    """Encode a [u8 count][N × NifDescriptor] tail. Caps at MAX_NIF_DESCRIPTORS."""
    n = min(len(descs), MAX_NIF_DESCRIPTORS)
    out = bytearray([n])
    for d in descs[:n]:
        out.extend(d.encode())
    return bytes(out)


def _decode_nif_tail(data: bytes, offset: int) -> tuple:
    """Decode [u8 count][N × NifDescriptor] starting at `offset`. Returns
    a tuple of NifDescriptor (possibly empty). Tolerates `offset == len(data)`
    (no tail present, returns empty tuple)."""
    if offset >= len(data):
        return ()
    n = data[offset]
    n = min(n, MAX_NIF_DESCRIPTORS)
    off = offset + 1
    out: list = []
    for _ in range(n):
        try:
            d, used = NifDescriptor.decode_from(data, off)
        except ValueError:
            # Malformed — drop the rest of the tail (defensive).
            break
        out.append(d)
        off += used
    return tuple(out)


@dataclass(frozen=True, slots=True)
class EquipOpPayload:
    """M9 w1+w4: client -> server: 'I just equipped/unequipped item X'.

    Sender hooks ActorEquipManager::EquipObject (sub_140CE5900) and
    ::UnequipObject (sub_140CE5DA0) in the engine — both fire 11-arg with
    args 4-5-6 in DIFFERENT ORDER between equip and unequip (a4=count is
    common; a5/a6 are stack_id vs slot vs swapped — this trapped M9 day 1).
    Detour observes, filters to actor==player (form_id == 0x14), enqueues
    this payload, then chains to g_orig.

    M9.w4 (protocol v7): when the equipped weapon has OMOD attachments
    (BGSObjectInstanceExtra in inventory), they are appended as a tail
    after the fixed payload — { u8 mod_count; mod_count × EquipModRecord }.
    UNEQUIP events typically ship mod_count=0 (the receiver tracks attached
    mods by form_id locally and detaches everything for that weapon).

    Identity: item_form_id is a TESForm.formID, plugin-stable. slot_form_id
    is the BGSEquipSlot.formID; pass 0 to mean "engine auto-resolves from
    the item's biped data". count is signed for symmetry with container
    ops; in practice always >= 1.
    """
    item_form_id: int    # u32 — e.g. 0x1EED7 = Vault Suit 111
    kind: int            # u8 — EquipOpKind (1=EQUIP, 2=UNEQUIP)
    slot_form_id: int    # u32 — BGSEquipSlot.formID, 0 = auto
    count: int           # i32 — stack count (always positive in practice)
    timestamp_ms: int    # u64 — sender wall clock for ordering
    effective_priority: int = 0  # u16 — v10: OMOD-modified priority (or ARMO+0x2A6 default); 0 for non-ARMO
    mods: tuple = ()     # tuple[EquipModRecord, ...] — w4 OMOD list (empty if no mods)
    nif_descs: tuple = ()  # tuple[NifDescriptor, ...] — w4 v8 witness data

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIiQH")  # v10: 4+1+4+4+8+2 = 23B (fixed)

    def encode(self) -> bytes:
        head = self._STRUCT.pack(
            self.item_form_id, self.kind, self.slot_form_id,
            self.count, self.timestamp_ms, self.effective_priority,
        )
        n = min(len(self.mods), MAX_EQUIP_MODS)
        omod_tail = bytes([n]) + b"".join(m.encode() for m in self.mods[:n])
        nif_tail = _encode_nif_tail(self.nif_descs)
        return head + omod_tail + nif_tail

    @classmethod
    def decode(cls, data: bytes) -> "EquipOpPayload":
        if len(data) < cls._STRUCT.size:
            raise ValueError(
                f"EquipOpPayload: expected >={cls._STRUCT.size} bytes, got {len(data)}")
        ifid, kind, sfid, cnt, ts, eff_prio = cls._STRUCT.unpack(data[:cls._STRUCT.size])
        mods: tuple = ()
        omod_size = 0  # bytes consumed by the OMOD tail (incl count byte)
        # v7 OMOD tail (optional — older v6 senders won't include this)
        if len(data) > cls._STRUCT.size:
            n = data[cls._STRUCT.size]
            n = min(n, MAX_EQUIP_MODS)
            tail_off = cls._STRUCT.size + 1
            needed = tail_off + n * EquipModRecord._STRUCT.size
            if len(data) >= needed and n > 0:
                stride = EquipModRecord._STRUCT.size
                mods = tuple(
                    EquipModRecord.decode(data[tail_off + i * stride
                                                : tail_off + (i+1) * stride])
                    for i in range(n)
                )
                omod_size = 1 + n * stride
            else:
                # mod_count=0 still counted the byte itself
                omod_size = 1
        # v8 NIF descriptor tail (after OMOD tail)
        nif_descs = _decode_nif_tail(data, cls._STRUCT.size + omod_size)
        return cls(item_form_id=ifid, kind=kind, slot_form_id=sfid,
                   count=cnt, timestamp_ms=ts,
                   effective_priority=eff_prio,
                   mods=mods, nif_descs=nif_descs)


@dataclass(frozen=True, slots=True)
class EquipBroadcastPayload:
    """M9 w1+w4: server -> other peers: 'peer X equipped/unequipped item Y'.

    Mirrors EquipOpPayload + peer_id for attribution. Carries the OMOD list
    (mods tuple) verbatim from the originating EquipOpPayload via server
    fanout. Server fan-out is pure (no validation, no rate-limiting).
    """
    peer_id: str
    item_form_id: int
    kind: int
    slot_form_id: int
    count: int
    timestamp_ms: int
    effective_priority: int = 0  # u16 — v10: see EquipOpPayload
    mods: tuple = ()     # w4 OMOD list, mirror of EquipOpPayload.mods
    nif_descs: tuple = ()  # w4 v8 witness data, mirror of EquipOpPayload.nif_descs

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIiQH")  # v10: 23B fixed

    def encode(self) -> bytes:
        head = (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.item_form_id, self.kind, self.slot_form_id,
                self.count, self.timestamp_ms, self.effective_priority,
            )
        )
        n = min(len(self.mods), MAX_EQUIP_MODS)
        omod_tail = bytes([n]) + b"".join(m.encode() for m in self.mods[:n])
        nif_tail = _encode_nif_tail(self.nif_descs)
        return head + omod_tail + nif_tail

    @classmethod
    def decode(cls, data: bytes) -> "EquipBroadcastPayload":
        fixed = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size  # v10: 16 + 23 = 39
        if len(data) < fixed:
            raise ValueError(
                f"EquipBroadcastPayload: expected >={fixed} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        ifid, kind, sfid, cnt, ts, eff_prio = cls._STRUCT.unpack(
            data[MAX_CLIENT_ID_LEN + 1 : fixed])
        mods: tuple = ()
        omod_size = 0
        if len(data) > fixed:
            n = data[fixed]
            n = min(n, MAX_EQUIP_MODS)
            tail_off = fixed + 1
            needed = tail_off + n * EquipModRecord._STRUCT.size
            if len(data) >= needed and n > 0:
                stride = EquipModRecord._STRUCT.size
                mods = tuple(
                    EquipModRecord.decode(data[tail_off + i * stride
                                                : tail_off + (i+1) * stride])
                    for i in range(n)
                )
                omod_size = 1 + n * stride
            else:
                omod_size = 1
        nif_descs = _decode_nif_tail(data, fixed + omod_size)
        return cls(peer_id=peer, item_form_id=ifid, kind=kind,
                   slot_form_id=sfid, count=cnt, timestamp_ms=ts,
                   effective_priority=eff_prio,
                   mods=mods, nif_descs=nif_descs)


# =================================================================== M9.w4 v9
#
# MESH_BLOB — chunked raw-mesh replication for modded weapons.
#
# Why this exists: the witness pattern (NIF-path replay, v8) failed across
# 4 hook strategies because Fallout 4 builds modded-weapon geometry IN
# MEMORY at runtime — there is no on-disk .nif for "10mm pistol with Long
# Barrel + Reflex Sight". After 12 RE iterations we extract the resulting
# BSTriShape leaves directly from the player's loaded3D, decode positions
# from the packed half-prec stream and indices from the u16 index buffer,
# and ship the whole thing to peers as a chunked blob (single equip event
# = ~10 KB × 8 meshes = ~80 KB total → ~60 UDP frames).
#
# Reliability: each chunk is a reliable frame. Receiver buffers chunks
# keyed on (peer_id, equip_seq) and applies once all chunks land. Drops
# the buffer on partial timeout (5 s).
#
# Layout of one mesh blob (linear bytes — what gets chunked across N
# MESH_BLOB_OP frames):
#
#   BLOB HEADER (10 bytes):
#     u32 item_form_id            -- correlates with the EQUIP_OP that
#                                    triggered this blob; receiver uses it
#                                    to pair with the EQUIP_BCAST it just
#                                    applied (ghost weapon root).
#     u32 equip_seq               -- sender's per-equip monotonic counter;
#                                    same value used in chunk header.
#     u8  num_meshes              -- 0..MAX_MESHES_PER_BLOB
#     u8  reserved                -- (=0; align)
#
#   PER MESH (×num_meshes):
#     u8  m_name_len              -- 0..255
#     u8  parent_placeholder_len  -- 0..255
#     u16 bgsm_path_len           -- 0..65535
#     u16 vert_count
#     u16 reserved                -- (=0; align)
#     u32 tri_count               -- index_count = 3 * tri_count
#     16 × f32 local_transform    -- 64B raw NiTransform
#     m_name_len bytes (UTF-8)
#     parent_placeholder_len bytes
#     bgsm_path_len bytes
#     3 * vert_count × f32 positions   -- 12 * vc bytes (xyz per vertex)
#     3 * tri_count × u16 indices       -- 6 * tc bytes
#
# A typical 10mm pistol modded: 8 meshes × ~10 KB = ~80 KB.
# Cap MAX_MESHES_PER_BLOB = 32 (vanilla weapons ≤8; heavy-mod stacks ≤16).
# Cap MAX_BLOB_SIZE = 4 MB (hard ceiling to defend against malformed input).
#
# Chunk frame (MESH_BLOB_OP):
#   u32 equip_seq             -- correlation id (echo of blob header)
#   u32 total_blob_size       -- byte size of full assembled blob
#   u16 chunk_index           -- 0..total_chunks-1
#   u16 total_chunks          -- chunks for THIS blob
#   N bytes of payload        -- blob slice [chunk_index*CHUNK_SIZE..]
#
# Chunk frame (MESH_BLOB_BCAST): same + 16 B FixedClientId prefix.
# At MAX_PAYLOAD_SIZE=1400, per-chunk data slice:
#   OP    : 1400 - 12 = 1388 B
#   BCAST : 1400 - 28 = 1372 B
#
# Receiver reassembly state machine:
#   key = (peer_id, equip_seq)
#   value = { total_blob_size, total_chunks, received: bitset, buf: bytearray }
#   on chunk: write slice into buf[off..off+len]; mark received[chunk_idx]=1
#   when popcount(received) == total_chunks: decode_blob(buf), drop key
#   timeout 5 s without all chunks → drop key + warn

MAX_MESHES_PER_BLOB: int = 32
MAX_BLOB_SIZE: int = 4 * 1024 * 1024   # 4 MB hard ceiling

# Chunk header sizes (for derivation; see classes below)
_MESH_BLOB_OP_CHUNK_HEADER_SIZE: int = 12     # IIHH
_MESH_BLOB_BCAST_CHUNK_HEADER_SIZE: int = 28  # 16+IIHH

MESH_BLOB_OP_CHUNK_DATA_MAX: int = MAX_PAYLOAD_SIZE - _MESH_BLOB_OP_CHUNK_HEADER_SIZE     # 1388
MESH_BLOB_BCAST_CHUNK_DATA_MAX: int = MAX_PAYLOAD_SIZE - _MESH_BLOB_BCAST_CHUNK_HEADER_SIZE  # 1372


@dataclass(frozen=True, slots=True)
class ExtractedMesh:
    """One BSGeometry leaf extracted from a modded weapon assembly.

    `positions` is a flat tuple of 3*vert_count floats (xyz xyz xyz ...).
    `indices`   is a flat tuple of 3*tri_count u16 (one triangle = 3 indices).
    """
    m_name: str
    parent_placeholder: str
    bgsm_path: str
    vert_count: int
    tri_count: int
    local_transform: tuple   # 16 floats
    positions: tuple         # 3 * vert_count floats
    indices: tuple           # 3 * tri_count u16

    _MESH_HDR: ClassVar[struct.Struct] = struct.Struct("<BBHHHI16f")
    # Layout: u8 m_name_len, u8 parent_placeholder_len, u16 bgsm_path_len,
    #         u16 vert_count, u16 reserved, u32 tri_count, 16 × f32 transform.
    # Size = 1+1+2+2+2+4+64 = 76 bytes.

    def encode(self) -> bytes:
        m_name_b = self.m_name.encode("utf-8")[:255]
        parent_b = self.parent_placeholder.encode("utf-8")[:255]
        bgsm_b = self.bgsm_path.encode("utf-8")[:65535]
        if len(self.positions) != 3 * self.vert_count:
            raise ProtocolError(
                f"ExtractedMesh: positions len {len(self.positions)} != 3*vc {3*self.vert_count}")
        if len(self.indices) != 3 * self.tri_count:
            raise ProtocolError(
                f"ExtractedMesh: indices len {len(self.indices)} != 3*tc {3*self.tri_count}")
        if len(self.local_transform) != 16:
            raise ProtocolError(
                f"ExtractedMesh: local_transform len {len(self.local_transform)} != 16")

        head = self._MESH_HDR.pack(
            len(m_name_b), len(parent_b), len(bgsm_b),
            self.vert_count, 0, self.tri_count,
            *self.local_transform,
        )
        positions_b = struct.pack(f"<{3*self.vert_count}f", *self.positions)
        indices_b = struct.pack(f"<{3*self.tri_count}H", *self.indices)
        return head + m_name_b + parent_b + bgsm_b + positions_b + indices_b

    @classmethod
    def decode_from(cls, data: bytes, offset: int = 0):
        """Returns (mesh, bytes_consumed)."""
        if offset + cls._MESH_HDR.size > len(data):
            raise ProtocolError("ExtractedMesh: header truncated")
        (m_name_len, parent_len, bgsm_len, vc, _resv, tc,
         *xform) = cls._MESH_HDR.unpack_from(data, offset)
        off = offset + cls._MESH_HDR.size
        positions_size = 3 * vc * 4
        indices_size = 3 * tc * 2
        total_need = m_name_len + parent_len + bgsm_len + positions_size + indices_size
        if off + total_need > len(data):
            raise ProtocolError(
                f"ExtractedMesh: body truncated: off={off} need={total_need} have={len(data)-off}")

        m_name = data[off:off + m_name_len].decode("utf-8", errors="replace")
        off += m_name_len
        parent = data[off:off + parent_len].decode("utf-8", errors="replace")
        off += parent_len
        bgsm = data[off:off + bgsm_len].decode("utf-8", errors="replace")
        off += bgsm_len

        positions = struct.unpack_from(f"<{3*vc}f", data, off)
        off += positions_size
        indices = struct.unpack_from(f"<{3*tc}H", data, off)
        off += indices_size

        return cls(
            m_name=m_name,
            parent_placeholder=parent,
            bgsm_path=bgsm,
            vert_count=vc,
            tri_count=tc,
            local_transform=tuple(xform),
            positions=tuple(positions),
            indices=tuple(indices),
        ), off - offset


@dataclass(frozen=True, slots=True)
class MeshBlobPayload:
    """Top-level mesh blob (assembled from chunks on the receiver, or
    serialized on the sender BEFORE chunking).

    Encoded as a single linear byte buffer that's then split into
    MeshBlobChunkPayload frames for transport. NOT sent directly as a
    single frame — the encoded bytes are passed through the chunker.
    """
    item_form_id: int        # u32; correlates with EQUIP_OP/BCAST
    equip_seq: int           # u32; sender's per-equip monotonic counter
    meshes: tuple            # tuple[ExtractedMesh, ...]

    _BLOB_HDR: ClassVar[struct.Struct] = struct.Struct("<IIBB")  # 10B

    def encode(self) -> bytes:
        n = len(self.meshes)
        if n > MAX_MESHES_PER_BLOB:
            raise ProtocolError(
                f"MeshBlobPayload: {n} meshes > MAX_MESHES_PER_BLOB={MAX_MESHES_PER_BLOB}")
        head = self._BLOB_HDR.pack(self.item_form_id, self.equip_seq, n, 0)
        body = b"".join(m.encode() for m in self.meshes)
        out = head + body
        if len(out) > MAX_BLOB_SIZE:
            raise ProtocolError(
                f"MeshBlobPayload: encoded size {len(out)} > MAX_BLOB_SIZE={MAX_BLOB_SIZE}")
        return out

    @classmethod
    def decode(cls, data: bytes) -> "MeshBlobPayload":
        if len(data) < cls._BLOB_HDR.size:
            raise ProtocolError("MeshBlobPayload: header truncated")
        item_form_id, equip_seq, n, _resv = cls._BLOB_HDR.unpack_from(data, 0)
        if n > MAX_MESHES_PER_BLOB:
            raise ProtocolError(
                f"MeshBlobPayload: num_meshes {n} > MAX={MAX_MESHES_PER_BLOB}")
        meshes: list = []
        off = cls._BLOB_HDR.size
        for _ in range(n):
            mesh, used = ExtractedMesh.decode_from(data, off)
            meshes.append(mesh)
            off += used
        return cls(
            item_form_id=item_form_id,
            equip_seq=equip_seq,
            meshes=tuple(meshes),
        )


@dataclass(frozen=True, slots=True)
class MeshBlobChunkPayload:
    """Single MESH_BLOB_OP frame — one chunk of a serialized MeshBlobPayload.

    Wire format (12 B header + chunk_data):
        u32 equip_seq
        u32 total_blob_size
        u16 chunk_index
        u16 total_chunks
        N   chunk_data        (slice of the assembled blob)

    The receiver buffers chunks keyed on (peer_id, equip_seq); when all
    arrive it concatenates them in chunk_index order and decodes via
    MeshBlobPayload.decode().
    """
    equip_seq: int
    total_blob_size: int
    chunk_index: int
    total_chunks: int
    chunk_data: bytes

    _HDR: ClassVar[struct.Struct] = struct.Struct("<IIHH")  # 12B

    def encode(self) -> bytes:
        if len(self.chunk_data) > MESH_BLOB_OP_CHUNK_DATA_MAX:
            raise ProtocolError(
                f"MeshBlobChunkPayload: chunk_data {len(self.chunk_data)}B "
                f"> MAX={MESH_BLOB_OP_CHUNK_DATA_MAX}")
        return self._HDR.pack(
            self.equip_seq, self.total_blob_size,
            self.chunk_index, self.total_chunks,
        ) + self.chunk_data

    @classmethod
    def decode(cls, data: bytes) -> "MeshBlobChunkPayload":
        if len(data) < cls._HDR.size:
            raise ProtocolError("MeshBlobChunkPayload: header truncated")
        eq, sz, ci, tc = cls._HDR.unpack_from(data, 0)
        return cls(
            equip_seq=eq,
            total_blob_size=sz,
            chunk_index=ci,
            total_chunks=tc,
            chunk_data=bytes(data[cls._HDR.size:]),
        )


@dataclass(frozen=True, slots=True)
class MeshBlobChunkBroadcastPayload:
    """Server -> peers: one chunk of a serialized MeshBlobPayload, attributed.

    Wire format (28 B header + chunk_data):
        FixedString(16) peer_id
        u32 equip_seq
        u32 total_blob_size
        u16 chunk_index
        u16 total_chunks
        N   chunk_data
    """
    peer_id: str
    equip_seq: int
    total_blob_size: int
    chunk_index: int
    total_chunks: int
    chunk_data: bytes

    _HDR: ClassVar[struct.Struct] = struct.Struct("<IIHH")  # 12B (post peer_id)

    def encode(self) -> bytes:
        if len(self.chunk_data) > MESH_BLOB_BCAST_CHUNK_DATA_MAX:
            raise ProtocolError(
                f"MeshBlobChunkBroadcastPayload: chunk_data {len(self.chunk_data)}B "
                f"> MAX={MESH_BLOB_BCAST_CHUNK_DATA_MAX}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HDR.pack(
                self.equip_seq, self.total_blob_size,
                self.chunk_index, self.total_chunks,
            )
            + self.chunk_data
        )

    @classmethod
    def decode(cls, data: bytes) -> "MeshBlobChunkBroadcastPayload":
        peer_off = MAX_CLIENT_ID_LEN + 1
        if len(data) < peer_off + cls._HDR.size:
            raise ProtocolError("MeshBlobChunkBroadcastPayload: header truncated")
        peer = _decode_fixed_string(data[:peer_off], MAX_CLIENT_ID_LEN)
        eq, sz, ci, tc = cls._HDR.unpack_from(data, peer_off)
        return cls(
            peer_id=peer,
            equip_seq=eq,
            total_blob_size=sz,
            chunk_index=ci,
            total_chunks=tc,
            chunk_data=bytes(data[peer_off + cls._HDR.size:]),
        )


def chunk_mesh_blob(blob_bytes: bytes,
                    chunk_data_max: int = MESH_BLOB_OP_CHUNK_DATA_MAX
                    ) -> "list[tuple[int, int, bytes]]":
    """Split a serialized mesh blob into chunks.

    Returns a list of (chunk_index, total_chunks, chunk_data) triples.
    Caller wraps each in a MeshBlobChunkPayload (or BCAST variant) with
    the per-equip equip_seq and total_blob_size.
    """
    if len(blob_bytes) > MAX_BLOB_SIZE:
        raise ProtocolError(
            f"chunk_mesh_blob: blob {len(blob_bytes)}B > MAX={MAX_BLOB_SIZE}")
    if not blob_bytes:
        return []
    total_chunks = (len(blob_bytes) + chunk_data_max - 1) // chunk_data_max
    if total_chunks > 0xFFFF:
        raise ProtocolError(
            f"chunk_mesh_blob: total_chunks {total_chunks} > u16 max")
    out: list = []
    off = 0
    for ci in range(total_chunks):
        end = min(off + chunk_data_max, len(blob_bytes))
        out.append((ci, total_chunks, blob_bytes[off:end]))
        off = end
    return out


# ============================================================================
# B6.5w2 (v13) — NPC continuous-state broadcast
# ============================================================================
#
# Server-authoritative NPC sync. The Python brain (server/npc_brain.py) ticks
# every tracked NPC at npc_tick_hz (default 10) and emits NPC_STATE_BCAST to
# every connected peer. Receiver looks up the local Actor by form_id and
# applies pos/rot via the existing pos_update_seh pattern (B6.5w3) and anim
# graph variables via IAnimationGraphManagerHolder::SetGraphVariable*
# (RVA 0x818D60/D80/DA0; holder = Actor + 0x48; names from interned pool at
# qword_1430DBF78[2700..3020] — see re/B6.5_npc_pipeline_AGENT_B.md).
#
# Wire layout per entry (98 B in v14, no padding):
#
#   v13 baseline (53 B):
#     u32 form_id           # placed REFR formID — stable across processes
#     u32 base_id           # TESNPC base — validation hint
#     u32 cell_id           # parent cell formID
#     f32 pos_x, pos_y, pos_z
#     f32 yaw, pitch        # atan2 convention; receiver translates to engine heading
#     u64 target_id         # legacy general-purpose target (peer_id hash or form_id)
#     u64 timestamp_ms      # server tick timestamp
#     u8  anim_state        # legacy AnimState enum (server/npc_brain.py)
#     u8  aggro_state       # AggroState enum
#     u8  hp_pct            # 0..100, server-authoritative
#     u8  target_kind       # 0=NONE, 1=PEER, 2=NPC
#     u8  flags             # bit 0 = visible, bit 1 = invulnerable, bit 2 = essential
#
#   v14 additions for Ghost AI (45 B):
#     u32 package_form_id         # server-chosen TESPackage (hook on
#                                 # TESPackage::EvaluateConditions @ 0x00768CC0)
#     u32 combat_target_form_id   # combat target form_id (hook on
#                                 # Actor::SyncCombatTargetFromAIProcess @ 0x00C5CCE0)
#     f32 aim_x, aim_y, aim_z     # aim world pos (hook on
#                                 # CombatAimController::SetAimTarget @ 0x00E65820)
#     f32 velocity_x, _y, _z      # server-decreed velocity (hook on
#                                 # Actor::TickMovementController @ 0x00C65E20)
#     u8  weapon_state            # 0=none/1=drawing/2=drawn/3=holstering
#                                 # (hook on DrawWeapon dispatch @ 0x00C5D080)
#     u8  sighted                 # 0/1 ADS (hook on SetSightedState @ 0x00CB13F0)
#     u8  sprinting               # 0/1 (hook on SetSprintState @ 0x00CA6030)
#     u8  sneaking                # 0/1 (hook on SetSneakState @ 0x00CA6220)
#     u8  gun_down                # 0/1 gun lowered (hook on ResolveCombatStance @ 0x00CD6870)
#     u8  aggression              # 0..100 (hook on UpdateAggressionToGraph @ 0x00E4D8A0)
#     u16 loco_state_pack         # 6 sync ints packed (hook on LocoEventDispatch @ 0x00CEC200):
#                                 #   bits 0    : iSyncIdleLocomotion (1 bit)
#                                 #   bits 1-2  : iSyncTurnState      (2 bits, 0..2)
#                                 #   bits 3    : iSyncForwardState   (1 bit)
#                                 #   bits 4-5  : iSyncStrafeState    (2 bits, 0..2)
#                                 #   bits 6-7  : iSyncJumpState      (2 bits, 0/1/3)
#                                 #   bits 8    : iSyncSwimState      (1 bit)
#                                 #   bits 9-15 : reserved
#     u32 sandbox_marker_handle   # Sandbox marker ref handle (BGSProcedureSandbox state +88)
#                                 # — 0 if NPC not in Sandbox or marker unset
#     u8  sandbox_idle_index      # Sandbox idle index (state +100/+104), 0 = unused
#
# Frame layout:
#     u16 count             # number of entries (≤ MAX_NPC_STATES_PER_FRAME)
#     u16 reserved          # 0 — alignment + future flags
#     count × NPCStateEntry # 98 B each (v14)
#
# Bandwidth ceiling: at 10 NPC × 10 Hz × 98 B = 9.8 KB/s/peer outbound. At
# 50 NPC the chunked frames stay under MTU 1400 (4 packets / tick).
# ============================================================================


# v14 loco_state_pack helpers — pack/unpack the 6 sync ints into 16 bits.
def pack_loco_state(
    idle_loco: int = 0,    # 0..1
    turn: int = 0,         # 0..2
    forward: int = 0,      # 0..1
    strafe: int = 0,       # 0..2
    jump: int = 0,         # 0..3 (engine uses 0/1/3 but 2 bits cover them)
    swim: int = 0,         # 0..1
) -> int:
    """Pack 6 locomotion sync ints into a u16 per v14 wire layout."""
    return (
        (idle_loco & 0x1)
        | ((turn & 0x3) << 1)
        | ((forward & 0x1) << 3)
        | ((strafe & 0x3) << 4)
        | ((jump & 0x3) << 6)
        | ((swim & 0x1) << 8)
    ) & 0xFFFF


def unpack_loco_state(pack: int) -> tuple[int, int, int, int, int, int]:
    """Reverse of pack_loco_state. Returns (idle, turn, fwd, strafe, jump, swim)."""
    return (
        pack & 0x1,
        (pack >> 1) & 0x3,
        (pack >> 3) & 0x1,
        (pack >> 4) & 0x3,
        (pack >> 6) & 0x3,
        (pack >> 8) & 0x1,
    )


@dataclass(frozen=True, slots=True)
class NPCStateEntry:
    """One NPC's authoritative state. Width = 98 B (v14)."""
    # v13 fields ---------------------------------------------------------
    form_id: int
    base_id: int
    cell_id: int
    pos_x: float
    pos_y: float
    pos_z: float
    yaw: float
    pitch: float
    target_id: int
    timestamp_ms: int
    anim_state: int
    aggro_state: int
    hp_pct: int
    target_kind: int
    flags: int
    # v14 Ghost AI additions ---------------------------------------------
    package_form_id: int = 0
    combat_target_form_id: int = 0
    aim_x: float = 0.0
    aim_y: float = 0.0
    aim_z: float = 0.0
    velocity_x: float = 0.0
    velocity_y: float = 0.0
    velocity_z: float = 0.0
    weapon_state: int = 0
    sighted: int = 0
    sprinting: int = 0
    sneaking: int = 0
    gun_down: int = 0
    aggression: int = 0
    loco_state_pack: int = 0
    sandbox_marker_handle: int = 0
    sandbox_idle_index: int = 0

    # 53 B v13 prefix + 45 B v14 suffix = 98 B
    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<IIIfffffQQBBBBB"          # v13 (53 B)
        "IIffffffBBBBBBHIB"         # v14 (45 B): pkg/tgt + aim + vel + 6 u8 + u16 + u32 + u8
    )

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            # v13
            self.form_id & 0xFFFFFFFF,
            self.base_id & 0xFFFFFFFF,
            self.cell_id & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.yaw, self.pitch,
            self.target_id & 0xFFFFFFFFFFFFFFFF,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            self.anim_state & 0xFF,
            self.aggro_state & 0xFF,
            self.hp_pct & 0xFF,
            self.target_kind & 0xFF,
            self.flags & 0xFF,
            # v14
            self.package_form_id & 0xFFFFFFFF,
            self.combat_target_form_id & 0xFFFFFFFF,
            self.aim_x, self.aim_y, self.aim_z,
            self.velocity_x, self.velocity_y, self.velocity_z,
            self.weapon_state & 0xFF,
            self.sighted & 0xFF,
            self.sprinting & 0xFF,
            self.sneaking & 0xFF,
            self.gun_down & 0xFF,
            self.aggression & 0xFF,
            self.loco_state_pack & 0xFFFF,
            self.sandbox_marker_handle & 0xFFFFFFFF,
            self.sandbox_idle_index & 0xFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCStateEntry":
        if len(data) != cls._STRUCT.size:
            raise ProtocolError(
                f"NPCStateEntry: expected {cls._STRUCT.size} B, got {len(data)}")
        return cls(*cls._STRUCT.unpack(data))


# Cap derived from MTU: header (4) + N × 98 ≤ MAX_PAYLOAD_SIZE (1400).
MAX_NPC_STATES_PER_FRAME: int = (MAX_PAYLOAD_SIZE - 4) // 98  # = 14 (v14)


@dataclass(frozen=True, slots=True)
class NPCStateBroadcastPayload:
    """B6.5w2 — server -> all peers: batched NPC authoritative state.

    Unreliable channel. Server emits at npc_tick_hz; drops are tolerable
    because the next tick resends. Receivers apply pos/rot/anim to the
    local Actor identified by ``form_id`` (B6.5w3) and suppress local AI
    tick for tracked form_ids (B6.5w4).

    Cell-aware filtering / interest management is **not yet** implemented:
    every peer receives every tracked NPC regardless of cell. Filtering
    lands in B6.7+.
    """
    entries: tuple[NPCStateEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")   # count, reserved

    def encode(self) -> bytes:
        if len(self.entries) > MAX_NPC_STATES_PER_FRAME:
            raise ProtocolError(
                f"NPCStateBroadcastPayload: too many entries "
                f"({len(self.entries)} > {MAX_NPC_STATES_PER_FRAME}); "
                f"caller must chunk")
        head = self._HEADER.pack(len(self.entries), 0)
        body = b"".join(e.encode() for e in self.entries)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "NPCStateBroadcastPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_STATE_BCAST: truncated header")
        count, _reserved = cls._HEADER.unpack_from(data, 0)
        if count > MAX_NPC_STATES_PER_FRAME:
            raise ProtocolError(
                f"NPC_STATE_BCAST: count {count} > "
                f"MAX={MAX_NPC_STATES_PER_FRAME}")
        ent_size = NPCStateEntry._STRUCT.size
        need = cls._HEADER.size + count * ent_size
        if len(data) < need:
            raise ProtocolError(
                f"NPC_STATE_BCAST: truncated body "
                f"(need {need} B, got {len(data)})")
        entries = tuple(
            NPCStateEntry.decode(
                data[cls._HEADER.size + i * ent_size :
                     cls._HEADER.size + (i + 1) * ent_size])
            for i in range(count)
        )
        return cls(entries=entries)


@dataclass(frozen=True, slots=True)
class PeerGhostRegisterPayload:
    """B6.6w5 — client tells server its local ghost-actor form_id.

    The "ghost" is the engine-spawned Actor that represents the OTHER
    peer on this client's screen (currently a single global ghost; 2-peer
    MVP assumption). The form_id is dynamic per-client (allocated by
    PlaceAtMe at spawn). Server uses this to substitute the combat
    target in NPC_STATE_BCAST per-viewer: when a raider's aggro target
    is a remote peer, the broadcast carries the VIEWER's local ghost
    form_id so the engine targets the right thing visually.

    Send-side: client calls this once after ghost spawn succeeds.
    Server-side: latest registration wins (e.g., on re-spawn after
    cell reload).

    Wire: 4 bytes (u32 form_id).
    """
    ghost_form_id: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.ghost_form_id & 0xFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "PeerGhostRegisterPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"PEER_GHOST_REGISTER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        (fid,) = cls._STRUCT.unpack_from(data, 0)
        return cls(ghost_form_id=fid)


@dataclass(frozen=True, slots=True)
class NPCDiscoverPayload:
    """B6.6w2 — client -> server: "I auto-tracked hostile NPC X".

    Emitted by the client when its npc_ai_suppress detour first
    auto-tracks an actor (Path 2: vanilla AI set the InCombat flag bit
    0x4000 on the actor). The client reads identity + position off the
    Actor* directly via the stable offsets:

      form_id  = *(u32*)(actor + 0x14)
      base_id  = *(u32*)(*(TESForm**)(actor + 0xE0) + 0x14)
      cell_id  = *(u32*)(*(REFR**)(actor + 0xB8) + 0x14)
      pos_x/y/z = (float*)(actor + 0xD0)[0..2]

    Server uses this to register the raider dynamically in raider_brain
    so it participates in aggro selection + fire timing + sync without
    needing to be in the waypoint JSON.

    Reliable channel: discovery should not be dropped. Server is
    idempotent — duplicate discoveries are ignored.

    Wire: 24 bytes.
    """
    form_id: int
    base_id: int
    cell_id: int
    pos_x: float
    pos_y: float
    pos_z: float

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfff")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.base_id & 0xFFFFFFFF,
            self.cell_id & 0xFFFFFFFF,
            float(self.pos_x),
            float(self.pos_y),
            float(self.pos_z),
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCDiscoverPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_DISCOVER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        fid, bid, cid, x, y, z = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=fid, base_id=bid, cell_id=cid,
                   pos_x=x, pos_y=y, pos_z=z)


@dataclass(frozen=True, slots=True)
class NPCPerceptionTriggerPayload:
    """Build 62 (2026-05-24) — server -> all peers: "NPC X perceives
    peer Y's ghost — invoke CCF810 locally so engine allocates combat
    tier naturally."

    Emitted by the server's proximity-sphere check when a peer's pos
    enters an NPC's effective perception sphere (base 1024 units,
    scaled by peer posture: sneak=0.4x, walk=0.7x, stand/run=1.0x,
    sprint=1.3x). Server-side debounce: 5s per (npc_fid, peer_id) pair
    to prevent re-trigger spam.

    Receiver (each client):
      observer = lookup_by_form_id(npc_fid)
      target   = peer_registry.get_ghost_actor_for_peer(peer_id)
                 (or local PC if peer_id == self)
      trigger_npc_perception(observer, target)
        -> engine sub_140CCF810 allocates HighProcess+CombatController+
           AddTarget in 1 frame.

    Reliable channel: do not drop. Idempotent on engine side (re-call
    routes through merge path sub_140ED2490).

    Wire: 8 bytes (2 × u32).
    """
    npc_fid: int          # OBSERVER (the NPC that should perceive)
    peer_id: int          # TARGET   (peer whose ghost is the threat)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.npc_fid & 0xFFFFFFFF,
            self.peer_id & 0xFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCPerceptionTriggerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_PERCEPTION_TRIGGER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        nfid, pid = cls._STRUCT.unpack_from(data, 0)
        return cls(npc_fid=nfid, peer_id=pid)


@dataclass(frozen=True, slots=True)
class NPCFirePayload:
    """B6.6w1 — server -> all peers: "this raider fires its equipped
    weapon NOW".

    Emitted by the server's raider_brain when an aggro'd raider's fire
    cooldown elapses + a player is in line-of-sight + visible. Both peers
    receive the same event so the muzzle flash + projectile + audio +
    damage all play synchronously.

    Build 55a (proto v15, 2026-05-23) — adds `target_kind` byte. Server
    picks per-raider per-window (3-8 sec) whether the raider's current
    fire is aimed at LOCAL (= peer's natural target, vanilla AI handles)
    or at GHOST (= the cross-peer ghost; puppet-fire path on client).
    Eliminates the dual-target flicker where engine vanilla AI was
    competing with our puppet-fire on the same actor rotation field.

    Wire: 13 bytes (3 × u32 + 1 × u8).
    """
    TARGET_LOCAL: ClassVar[int] = 0
    TARGET_GHOST: ClassVar[int] = 1

    raider_form_id: int
    target_form_id: int   # 0x14 = player; 0 = unknown
    flags: int            # reserved (0); future: burst count / weapon hint
    target_kind: int = 0  # 0=LOCAL (vanilla AI), 1=GHOST (client puppet-fire)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIB")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.raider_form_id & 0xFFFFFFFF,
            self.target_form_id & 0xFFFFFFFF,
            self.flags & 0xFFFFFFFF,
            self.target_kind & 0xFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCFirePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_FIRE: expected {cls._STRUCT.size} B, got {len(data)}")
        r, t, f, tk = cls._STRUCT.unpack_from(data, 0)
        return cls(raider_form_id=r, target_form_id=t,
                   flags=f, target_kind=tk)


# ============================================================================
# Build 65 — Owner-driven NPC sync payloads (Solver 2 design).
#
# All 11 opcodes (0x0280-0x028A) introduced here. C++ mirrors at
# `fw_native/src/net/protocol.h`. Phase A ships these data structures +
# server-side registry; Phase B wires DLL handlers.
#
# Sizing kept compact; all u32 fids, ts_ms as u64 monotonic, peer_id as
# 16-byte FixedClientId (matches PeerJoinPayload).
# ============================================================================

PEER_ID_BYTES: int = 16  # FixedClientId byte length (matches PeerJoinPayload)


@dataclass(frozen=True, slots=True)
class NPCObservedPayload:
    """C→S: "I see NPC X at pos P". Election input — server uses
    reporter distance + cell load timing to decide ownership.

    Wire: 28 bytes (3 × u32 + 4 × f32).
    """
    form_id: int
    base_id: int
    cell_id: int
    pos_x: float
    pos_y: float
    pos_z: float
    observer_distance_sq: float   # server short-circuits election compute

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIffff")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.base_id & 0xFFFFFFFF,
            self.cell_id & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.observer_distance_sq,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCObservedPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_OBSERVED: expected {cls._STRUCT.size} B, got {len(data)}")
        f, b, c, px, py, pz, d = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, base_id=b, cell_id=c,
                   pos_x=px, pos_y=py, pos_z=pz,
                   observer_distance_sq=d)


# v43 (2026-10-20): an NPC_UNLOAD whose form_id is this releases EVERY NPC the
# sender owns, in one message. The client's death release used to send one
# NPC_UNLOAD per owned NPC: 637 at the live death of 2026-10-20 (in an
# interior the client observes, and owns, the NPCs of other cells too), a
# burst that filled its outbound queue and dropped the PLAYER_LIFE queued
# behind it, so the server never heard of the death. With the wildcard,
# `epoch` carries how many the client owned locally (for the log only) and
# the position fields are unused: the server releases from its own records.
NPC_UNLOAD_ALL_OWNED = 0


@dataclass(frozen=True, slots=True)
class NPCUnloadPayload:
    """C→S: "NPC X left my loaded cell — I'm no longer eligible to own it".
    Triggers owner release (if reporter was owner) and forgets the NPC on
    the non-owner side.

    Wire: 26 bytes (2 × u32 + 4 × f32 + 2 × u8).
    """
    form_id: int                # NPC_UNLOAD_ALL_OWNED (0, v43): every NPC the sender owns
    epoch: int                  # proof-of-ownership at unload time (the local count with the wildcard)
    last_pos_x: float
    last_pos_y: float
    last_pos_z: float
    last_yaw: float
    last_anim_state: int        # u8
    last_hp_pct: int            # u8

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIffffBB")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.epoch & 0xFFFFFFFF,
            self.last_pos_x, self.last_pos_y, self.last_pos_z,
            self.last_yaw,
            self.last_anim_state & 0xFF,
            self.last_hp_pct & 0xFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCUnloadPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_UNLOAD: expected {cls._STRUCT.size} B, got {len(data)}")
        f, e, px, py, pz, yaw, anim, hp = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, epoch=e,
                   last_pos_x=px, last_pos_y=py, last_pos_z=pz,
                   last_yaw=yaw,
                   last_anim_state=anim, last_hp_pct=hp)


@dataclass(frozen=True, slots=True)
class NPCOwnerHeartbeatEntry:
    """Single (fid, epoch) tuple in NPC_OWNER_HEARTBEAT body."""
    form_id: int
    epoch: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.epoch & 0xFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "NPCOwnerHeartbeatEntry":
        if len(data) - offset < cls._STRUCT.size:
            raise ProtocolError("HeartbeatEntry: truncated")
        f, e = cls._STRUCT.unpack_from(data, offset)
        return cls(form_id=f, epoch=e)


@dataclass(frozen=True, slots=True)
class NPCOwnerHeartbeatPayload:
    """C→S: "I still own these fids at these epochs". 2 Hz from every
    peer for every NPC it owns. Server uses last-seen ts as health-gate
    input. Unreliable — drop tolerance is generous (next tick recovers).

    Wire: 4 (header: num_entries u16 + reserved u16) + N × 8.
    """
    entries: tuple[NPCOwnerHeartbeatEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")

    MAX_ENTRIES: ClassVar[int] = 170   # 4 + 170*8 = 1364 ≤ MTU 1400

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES:
            raise ProtocolError(
                f"NPC_OWNER_HEARTBEAT: {len(self.entries)} > "
                f"max {self.MAX_ENTRIES} entries")
        buf = bytearray(self._HEADER.pack(len(self.entries), 0))
        for e in self.entries:
            buf.extend(e.encode())
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnerHeartbeatPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_OWNER_HEARTBEAT: truncated header")
        num, _reserved = cls._HEADER.unpack_from(data, 0)
        entry_size = NPCOwnerHeartbeatEntry._STRUCT.size
        if len(data) < cls._HEADER.size + num * entry_size:
            raise ProtocolError(
                f"NPC_OWNER_HEARTBEAT: truncated body "
                f"(num={num}, len={len(data)})")
        out: list[NPCOwnerHeartbeatEntry] = []
        off = cls._HEADER.size
        for _ in range(num):
            out.append(NPCOwnerHeartbeatEntry.decode(data, off))
            off += entry_size
        return cls(entries=tuple(out))


@dataclass(frozen=True, slots=True)
class NPCOwnershipHandoffPhase1Payload:
    """S→old+new owners: release request for one NPC. Reliable.

    The OLD owner must respond with NPC_OWNERSHIP_RELEASE_ACK before
    `deadline_ms`; the NEW owner waits silently until phase 2 announces it
    can start broadcasting state.

    Wire: 4 + 4 + 16 + 16 + 8 = 48 bytes.
    """
    form_id: int
    old_epoch: int
    old_owner_peer_id: bytes    # 16 B FixedClientId
    new_owner_peer_id: bytes    # 16 B
    deadline_ms: int            # u64 monotonic ms — hard ACK cutoff

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16s16sQ")

    def __post_init__(self) -> None:
        if len(self.old_owner_peer_id) != 16:
            raise ProtocolError("PHASE1: old_owner_peer_id must be 16B")
        if len(self.new_owner_peer_id) != 16:
            raise ProtocolError("PHASE1: new_owner_peer_id must be 16B")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.old_epoch & 0xFFFFFFFF,
            self.old_owner_peer_id,
            self.new_owner_peer_id,
            self.deadline_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipHandoffPhase1Payload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"PHASE1: expected {cls._STRUCT.size} B, got {len(data)}")
        f, oe, ooid, noid, dl = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, old_epoch=oe,
                   old_owner_peer_id=ooid, new_owner_peer_id=noid,
                   deadline_ms=dl)


@dataclass(frozen=True, slots=True)
class NPCOwnershipReleaseAckPayload:
    """C→S: old owner acknowledges release. Reliable.

    Wire: 4 + 4 + 16 + 8 = 32 bytes.
    """
    form_id: int
    old_epoch: int
    acker_peer_id: bytes        # 16 B — must match registered old owner
    ack_ts_ms: int              # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16sQ")

    def __post_init__(self) -> None:
        if len(self.acker_peer_id) != 16:
            raise ProtocolError("RELEASE_ACK: acker_peer_id must be 16B")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.old_epoch & 0xFFFFFFFF,
            self.acker_peer_id,
            self.ack_ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipReleaseAckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"RELEASE_ACK: expected {cls._STRUCT.size} B, got {len(data)}")
        f, oe, pid, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, old_epoch=oe,
                   acker_peer_id=pid, ack_ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCOwnershipHandoffPhase2Payload:
    """S→all: new owner active for one NPC. All peers update their local
    g_owner_map[fid] = new_owner_peer_id, epoch = new_epoch. Reliable.

    Wire: 4 + 4 + 16 + 8 = 32 bytes.
    """
    form_id: int
    new_epoch: int
    new_owner_peer_id: bytes
    handed_off_at_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16sQ")

    def __post_init__(self) -> None:
        if len(self.new_owner_peer_id) != 16:
            raise ProtocolError("PHASE2: new_owner_peer_id must be 16B")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.new_epoch & 0xFFFFFFFF,
            self.new_owner_peer_id,
            self.handed_off_at_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipHandoffPhase2Payload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"PHASE2: expected {cls._STRUCT.size} B, got {len(data)}")
        f, ne, pid, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, new_epoch=ne,
                   new_owner_peer_id=pid, handed_off_at_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCOwnershipBcastEntry:
    """Single (fid, epoch, owner_peer_id) entry in OWNERSHIP_BCAST."""
    form_id: int
    epoch: int
    owner_peer_id: bytes        # 16 B; all-zero = unowned (server-relayed)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16s")

    def encode(self) -> bytes:
        if len(self.owner_peer_id) != 16:
            raise ProtocolError("OWNERSHIP_BCAST entry: peer_id must be 16B")
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.epoch & 0xFFFFFFFF,
            self.owner_peer_id,
        )

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "NPCOwnershipBcastEntry":
        if len(data) - offset < cls._STRUCT.size:
            raise ProtocolError("OWNERSHIP_BCAST entry: truncated")
        f, e, pid = cls._STRUCT.unpack_from(data, offset)
        return cls(form_id=f, epoch=e, owner_peer_id=pid)


@dataclass(frozen=True, slots=True)
class NPCOwnershipBcastPayload:
    """S→peer (bootstrap on connect) or S→all (post-handoff cleanup).
    Carries up to ~50 ownership records per frame. Reliable.

    Wire: 4 + N × 24.
    """
    entries: tuple[NPCOwnershipBcastEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")

    MAX_ENTRIES: ClassVar[int] = 57   # 4 + 57*24 = 1372 ≤ MTU 1400

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES:
            raise ProtocolError(
                f"OWNERSHIP_BCAST: {len(self.entries)} > max {self.MAX_ENTRIES}")
        buf = bytearray(self._HEADER.pack(len(self.entries), 0))
        for e in self.entries:
            buf.extend(e.encode())
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipBcastPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("OWNERSHIP_BCAST: truncated header")
        num, _reserved = cls._HEADER.unpack_from(data, 0)
        es = NPCOwnershipBcastEntry._STRUCT.size
        if len(data) < cls._HEADER.size + num * es:
            raise ProtocolError(
                f"OWNERSHIP_BCAST: truncated body (num={num}, len={len(data)})")
        out: list[NPCOwnershipBcastEntry] = []
        off = cls._HEADER.size
        for _ in range(num):
            out.append(NPCOwnershipBcastEntry.decode(data, off))
            off += es
        return cls(entries=tuple(out))


@dataclass(frozen=True, slots=True)
class NPCOwnerStateEntry:
    """Single NPC state record inside NPC_STATE_FROM_OWNER.

    Same field set as NPCStateEntry (Build 55a v15) plus `epoch` for
    non-owner gating. Sized to keep batched packets MTU-safe.

    Wire: 76 bytes.
    """
    form_id: int
    epoch: int
    pos_x: float
    pos_y: float
    pos_z: float
    yaw_rad: float
    pitch_rad: float
    combat_target_fid: int      # owner's local AI's current combat target
    aim_x: float
    aim_y: float
    aim_z: float
    velocity_x: float
    velocity_y: float
    velocity_z: float
    anim_state: int             # u8
    aggro_state: int            # u8
    hp_pct: int                 # u8
    weapon_state: int           # u8 (bit 3 = fire_this_tick)
    sighted: int                # u8
    sprinting: int              # u8
    sneaking: int               # u8
    gun_down: int               # u8
    aggression: int             # u8
    _pad: int = 0               # u8 padding to align ts_ms
    loco_state_pack: int = 0    # u16
    ts_ms: int = 0              # u64 owner's monotonic ms

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<II"          # form_id, epoch
        "fff"          # pos xyz
        "ff"           # yaw, pitch
        "I"            # combat_target_fid
        "fff"          # aim xyz
        "fff"          # velocity xyz
        "BBBBBBBBB"    # anim, aggro, hp, weapon, sighted, sprint, sneak, gun_down, aggression
        "B"            # pad
        "H"            # loco_state_pack
        "Q"            # ts_ms
    )

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF, self.epoch & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.yaw_rad, self.pitch_rad,
            self.combat_target_fid & 0xFFFFFFFF,
            self.aim_x, self.aim_y, self.aim_z,
            self.velocity_x, self.velocity_y, self.velocity_z,
            self.anim_state & 0xFF, self.aggro_state & 0xFF,
            self.hp_pct & 0xFF, self.weapon_state & 0xFF,
            self.sighted & 0xFF, self.sprinting & 0xFF,
            self.sneaking & 0xFF, self.gun_down & 0xFF,
            self.aggression & 0xFF, self._pad & 0xFF,
            self.loco_state_pack & 0xFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "NPCOwnerStateEntry":
        if len(data) - offset < cls._STRUCT.size:
            raise ProtocolError("NPCOwnerStateEntry: truncated")
        unpacked = cls._STRUCT.unpack_from(data, offset)
        (f, ep, px, py, pz, yaw, pitch, ctf,
         ax, ay, az, vx, vy, vz,
         anim, aggro, hp, ws, sight, spr, sne, gd, ag, pad,
         loco, ts) = unpacked
        return cls(form_id=f, epoch=ep,
                   pos_x=px, pos_y=py, pos_z=pz,
                   yaw_rad=yaw, pitch_rad=pitch,
                   combat_target_fid=ctf,
                   aim_x=ax, aim_y=ay, aim_z=az,
                   velocity_x=vx, velocity_y=vy, velocity_z=vz,
                   anim_state=anim, aggro_state=aggro,
                   hp_pct=hp, weapon_state=ws,
                   sighted=sight, sprinting=spr, sneaking=sne,
                   gun_down=gd, aggression=ag, _pad=pad,
                   loco_state_pack=loco, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCStateFromOwnerPayload:
    """C→S→all (relayed): owner's authoritative state batch. Unreliable.

    Owner client emits at 20-30 Hz. Server validates ownership + epoch,
    fans out the filtered entries to every non-owner. Receivers gate on
    `entry.epoch >= local_epoch[fid]` and drop stale entries.

    Wire: 4 (header) + N × 80.
    """
    entries: tuple[NPCOwnerStateEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")

    MAX_ENTRIES: ClassVar[int] = 17   # 4 + 17*80 = 1364 ≤ MTU 1400

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES:
            raise ProtocolError(
                f"NPC_STATE_FROM_OWNER: {len(self.entries)} > max "
                f"{self.MAX_ENTRIES}")
        buf = bytearray(self._HEADER.pack(len(self.entries), 0))
        for e in self.entries:
            buf.extend(e.encode())
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "NPCStateFromOwnerPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_STATE_FROM_OWNER: truncated header")
        num, _reserved = cls._HEADER.unpack_from(data, 0)
        es = NPCOwnerStateEntry._STRUCT.size
        if len(data) < cls._HEADER.size + num * es:
            raise ProtocolError(
                f"NPC_STATE_FROM_OWNER: truncated body "
                f"(num={num}, len={len(data)})")
        out: list[NPCOwnerStateEntry] = []
        off = cls._HEADER.size
        for _ in range(num):
            out.append(NPCOwnerStateEntry.decode(data, off))
            off += es
        return cls(entries=tuple(out))


@dataclass(frozen=True, slots=True)
class NPCFireFromOwnerPayload:
    """C→S→all: owner's fire event. Unreliable.

    Replaces server-driven NPC_FIRE. Owner reports a single weapon
    discharge with a target hint. Receivers spawn muzzle flash + projectile
    + audio on the local replica.

    Wire: 4 + 4 + 4 + 12 + 8 = 32 bytes (form, target_fid, weapon_form,
    aim_xyz, ts_ms).
    """
    form_id: int               # raider
    target_form_id: int        # target hint (0x14 = local PC; 0 = unknown)
    weapon_form_id: int
    aim_x: float
    aim_y: float
    aim_z: float
    ts_ms: int                 # u64 owner monotonic ms

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfffQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.target_form_id & 0xFFFFFFFF,
            self.weapon_form_id & 0xFFFFFFFF,
            self.aim_x, self.aim_y, self.aim_z,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCFireFromOwnerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_FIRE_FROM_OWNER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        f, tf, wf, ax, ay, az, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, target_form_id=tf, weapon_form_id=wf,
                   aim_x=ax, aim_y=ay, aim_z=az, ts_ms=ts)


# Loot rework L4.1 (2026-09-25): NPCDeathFromOwnerPayload.flags bit 0 marks
# the REPLAY of a known death (an observer's engine has the actor alive
# because the save predates the death). A corpse record survives a replay;
# a death without the bit is a new corpse and drops it, on the server and
# in every client's mirror.
NPC_DEATH_FLAG_REPLAY = 0x01


@dataclass(frozen=True, slots=True)
class NPCDeathFromOwnerPayload:
    """C→S→all: owner's death event. Reliable.

    When the owner's vanilla AI observes HP reaching zero (or scripted
    kill), it reports the death. Non-owners apply `Actor::Kill` locally.

    Wire: 4 + 4 + 12 + 12 + 4 + 1 + 1 + 2 + 8 = 48 bytes.
    """
    form_id: int
    killer_form_id: int          # 0 = environmental
    pos_x: float                 # last-seen pos
    pos_y: float
    pos_z: float
    ragdoll_x: float
    ragdoll_y: float
    ragdoll_z: float
    damage: float
    hit_zone: int                # u8
    flags: int                   # u8 reserved (silent_kill etc.)
    _pad: int = 0                # u16 align
    ts_ms: int = 0               # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<IIfffffffBBHQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.killer_form_id & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.ragdoll_x, self.ragdoll_y, self.ragdoll_z,
            self.damage,
            self.hit_zone & 0xFF,
            self.flags & 0xFF,
            self._pad & 0xFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCDeathFromOwnerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_DEATH_FROM_OWNER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        (f, k, px, py, pz, rx, ry, rz, dmg,
         hz, fl, pad, ts) = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, killer_form_id=k,
                   pos_x=px, pos_y=py, pos_z=pz,
                   ragdoll_x=rx, ragdoll_y=ry, ragdoll_z=rz,
                   damage=dmg, hit_zone=hz, flags=fl,
                   _pad=pad, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCDamageFromOwnerPayload:
    """C→S→all: owner's hit-applier event. Unreliable (purely cosmetic —
    HP authority is the owner; this is for receiver-side hit-react +
    ragdoll-direction visuals).

    Wire: 4 + 4 + 4 + 4 + 1 + 1 + 2 + 8 = 28 bytes.
    """
    form_id: int                 # victim
    attacker_form_id: int        # who hit them (0 = unknown)
    weapon_form_id: int
    damage: float
    hit_zone: int                # u8
    flags: int                   # u8 reserved
    _pad: int = 0                # u16 align
    ts_ms: int = 0               # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfBBHQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.attacker_form_id & 0xFFFFFFFF,
            self.weapon_form_id & 0xFFFFFFFF,
            self.damage,
            self.hit_zone & 0xFF,
            self.flags & 0xFF,
            self._pad & 0xFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCDamageFromOwnerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_DAMAGE_FROM_OWNER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        f, a, w, d, hz, fl, pad, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, attacker_form_id=a, weapon_form_id=w,
                   damage=d, hit_zone=hz, flags=fl, _pad=pad, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCEngagementClaimPayload:
    """Build 65.c.23 — C→S: peer claims engagement with NPC.

    Sent by a non-owner peer when its LOCAL engine has the InCombat flag
    (bit 0x4000 at Actor+0x2D0) set on a tracked NPC. This is the engine's
    own evidence that the peer's player IS the natural combat opponent
    of that NPC — not a server prediction, not a heuristic.

    Server uses this to force handoff if the current owner has not been
    reporting engagement (i.e. their last STATE_FROM_OWNER carried
    anim_state < 3 for >= ENGAGEMENT_OWNERSHIP_GRACE_MS = 3000 ms).
    Fixes the "wrong owner" mismatch where first-observer claims a raider
    but isn't the one actually fighting it.

    Anti-spam: client dedups per fid with a 2 s cooldown. Server further
    rejects claims when handoff stickiness floor is not yet elapsed.

    Wire: 4 + 4 + 8 = 16 bytes (form_id, peer_id_hash, ts_ms).
    """
    form_id: int                # NPC the peer's engine has in combat
    peer_id_hash: int           # FNV-1a 32-bit of local peer_id (sanity)
    ts_ms: int                  # peer monotonic ms; for diag only

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.peer_id_hash & 0xFFFFFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCEngagementClaimPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_ENGAGEMENT_CLAIM: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        f, h, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, peer_id_hash=h, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class RawMessage:
    """Fallback for unknown msg_type — preserves payload for forward compat."""
    msg_type: int
    payload: bytes


# ------------------------------------------------------------------ codec

# Typed union for clarity
Payload = Union[
    HelloPayload, WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    HeartbeatPayload, AckPayload, PosStatePayload, PosBroadcastPayload,
    ActorEventPayload, ChatPayload, DisconnectPayload,
    WorldStatePayload,
    ContainerOpPayload, ContainerBroadcastPayload, ContainerStatePayload,
    ContainerOpAckPayload, ContainerSeedPayload, InstanceDefsPayload,
    QuestStageSetPayload, QuestStageBroadcastPayload, QuestStateBootPayload,
    GlobalVarSetPayload, GlobalVarBroadcastPayload, GlobalVarStateBootPayload,
    DoorOpPayload, DoorBroadcastPayload,
    EquipOpPayload, EquipBroadcastPayload,
    MeshBlobChunkPayload, MeshBlobChunkBroadcastPayload,
    LockOpPayload, LockBroadcastPayload,
    NPCStateEntry, NPCStateBroadcastPayload,
    NPCFirePayload, NPCDiscoverPayload,
    NPCPerceptionTriggerPayload,
    # Build 65 owner-driven (Solver 2)
    NPCObservedPayload, NPCUnloadPayload,
    NPCOwnerHeartbeatPayload,
    NPCOwnershipHandoffPhase1Payload, NPCOwnershipReleaseAckPayload,
    NPCOwnershipHandoffPhase2Payload, NPCOwnershipBcastPayload,
    NPCStateFromOwnerPayload,
    NPCFireFromOwnerPayload, NPCDeathFromOwnerPayload,
    NPCDamageFromOwnerPayload,
    NPCEngagementClaimPayload,   # Build 65.c.23 — combat-driven handoff
    PeerGhostRegisterPayload,
    RawMessage,
]


# ============================================================================
# Discovery / server browser (0x003X) — OUT OF SESSION
# ============================================================================
# Stateless request/response. Never reliable, never session-bound, never
# world-mutating: a menu must be able to ask "who are you?" of a server it has
# not joined, and to list public servers before picking one.

MAX_SERVER_NAME_LEN: int = 31    # ASCII, null-terminated in 32 bytes
MAX_MOTD_LEN: int = 63           # ASCII, null-terminated in 64 bytes
MAX_ADDR_LEN: int = 45           # fits an IPv6 literal, null-terminated in 46


@dataclass(frozen=True, slots=True)
class ServerInfoRequestPayload:
    """C->S, no session. `nonce` is echoed back so a browser can match the
    reply to the row it asked about and measure ping without keeping state."""

    nonce: int                      # u32, client-chosen

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.nonce)

    @classmethod
    def decode(cls, data: bytes) -> "ServerInfoRequestPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("SERVER_INFO_REQUEST truncated")
        (nonce,) = cls._STRUCT.unpack_from(data, 0)
        return cls(nonce)


@dataclass(frozen=True, slots=True)
class ServerInfoResponsePayload:
    """S->C, no session. Everything one browser row needs.

    players / max_players are live. passworded / public are advisory flags for
    the UI. version_* lets the browser grey out incompatible servers BEFORE the
    user tries to join (the join itself still rejects on mismatch).
    """

    nonce: int                      # u32, echoed from the request
    name: str                       # ASCII <= MAX_SERVER_NAME_LEN
    motd: str                       # ASCII <= MAX_MOTD_LEN
    players: int                    # u8
    max_players: int                # u8
    version_major: int              # u8
    version_minor: int              # u8
    tick_rate_hz: int               # u16
    passworded: bool                # u8
    public: bool                    # u8

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBBBBHBB")

    def encode(self) -> bytes:
        return (
            self._STRUCT.pack(
                self.nonce, self.players, self.max_players,
                self.version_major, self.version_minor, self.tick_rate_hz,
                1 if self.passworded else 0, 1 if self.public else 0)
            + _encode_fixed_string(self.name, MAX_SERVER_NAME_LEN)
            + _encode_fixed_string(self.motd, MAX_MOTD_LEN)
        )

    @classmethod
    def decode(cls, data: bytes) -> "ServerInfoResponsePayload":
        head = cls._STRUCT.size
        need = head + (MAX_SERVER_NAME_LEN + 1) + (MAX_MOTD_LEN + 1)
        if len(data) < need:
            raise ProtocolError("SERVER_INFO_RESPONSE truncated")
        (nonce, players, max_players, vmaj, vmin, tick,
         passworded, public) = cls._STRUCT.unpack_from(data, 0)
        name = _decode_fixed_string(data[head:], MAX_SERVER_NAME_LEN)
        motd = _decode_fixed_string(
            data[head + MAX_SERVER_NAME_LEN + 1:], MAX_MOTD_LEN)
        return cls(nonce, name, motd, players, max_players, vmaj, vmin, tick,
                   bool(passworded), bool(public))


@dataclass(frozen=True, slots=True)
class MasterRegisterPayload:
    """Game server -> master, resent every heartbeat while `public` is set.

    Deliberately carries NO address: the master uses the UDP source address of
    the datagram as the server's public ip:port. That lists a NAT'd server at
    the endpoint that actually works from outside, stops it from claiming
    someone else's address, and the periodic heartbeat keeps the NAT mapping
    open. Falling silent past the master's expiry de-lists it automatically, so
    a crashed server disappears with no graceful goodbye needed.
    """

    name: str
    motd: str
    players: int                    # u8
    max_players: int                # u8
    version_major: int              # u8
    version_minor: int              # u8
    passworded: bool                # u8

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBBBB")

    def encode(self) -> bytes:
        return (
            self._STRUCT.pack(
                self.players, self.max_players,
                self.version_major, self.version_minor,
                1 if self.passworded else 0)
            + _encode_fixed_string(self.name, MAX_SERVER_NAME_LEN)
            + _encode_fixed_string(self.motd, MAX_MOTD_LEN)
        )

    @classmethod
    def decode(cls, data: bytes) -> "MasterRegisterPayload":
        head = cls._STRUCT.size
        need = head + (MAX_SERVER_NAME_LEN + 1) + (MAX_MOTD_LEN + 1)
        if len(data) < need:
            raise ProtocolError("MASTER_REGISTER truncated")
        players, max_players, vmaj, vmin, passworded = \
            cls._STRUCT.unpack_from(data, 0)
        name = _decode_fixed_string(data[head:], MAX_SERVER_NAME_LEN)
        motd = _decode_fixed_string(
            data[head + MAX_SERVER_NAME_LEN + 1:], MAX_MOTD_LEN)
        return cls(name, motd, players, max_players, vmaj, vmin,
                   bool(passworded))


@dataclass(frozen=True, slots=True)
class MasterListRequestPayload:
    """C->master. `nonce` echoes back; `offset` pages the list so one response
    always fits in a single datagram."""

    nonce: int                      # u32
    offset: int = 0                 # u16, index of the first entry wanted

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IH")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.nonce, self.offset)

    @classmethod
    def decode(cls, data: bytes) -> "MasterListRequestPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("MASTER_LIST_REQUEST truncated")
        nonce, offset = cls._STRUCT.unpack_from(data, 0)
        return cls(nonce, offset)


@dataclass(frozen=True, slots=True)
class MasterServerEntry:
    """One browser row: where to connect + what to show."""

    address: str                    # "ip:port" as seen by the master
    name: str
    players: int                    # u8
    max_players: int                # u8
    version_major: int              # u8
    version_minor: int              # u8
    passworded: bool                # u8

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBBBB")
    SIZE: ClassVar[int] = (MAX_ADDR_LEN + 1) + (MAX_SERVER_NAME_LEN + 1) + 5

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.address, MAX_ADDR_LEN)
            + _encode_fixed_string(self.name, MAX_SERVER_NAME_LEN)
            + self._STRUCT.pack(
                self.players, self.max_players,
                self.version_major, self.version_minor,
                1 if self.passworded else 0)
        )

    @classmethod
    def decode_from(cls, data: bytes, off: int) -> "MasterServerEntry":
        if len(data) < off + cls.SIZE:
            raise ProtocolError("MasterServerEntry truncated")
        address = _decode_fixed_string(data[off:], MAX_ADDR_LEN)
        o = off + MAX_ADDR_LEN + 1
        name = _decode_fixed_string(data[o:], MAX_SERVER_NAME_LEN)
        o += MAX_SERVER_NAME_LEN + 1
        players, max_players, vmaj, vmin, passworded = \
            cls._STRUCT.unpack_from(data, o)
        return cls(address, name, players, max_players, vmaj, vmin,
                   bool(passworded))


# How many rows fit in one datagram (8 B header + N * entry).
MAX_SERVERS_PER_LIST_FRAME: int = (MAX_PAYLOAD_SIZE - 8) // MasterServerEntry.SIZE


@dataclass(frozen=True, slots=True)
class MasterListResponsePayload:
    """master->C. `total` is the full count, so the browser knows whether to
    ask for another page starting at offset + len(entries)."""

    nonce: int                      # u32
    offset: int                     # u16, index of entries[0]
    total: int                      # u16, servers currently known to the master
    entries: tuple

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IHH")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_SERVERS_PER_LIST_FRAME:
            raise ProtocolError(
                "too many servers in one frame: %d" % len(self.entries))
        return (self._HEADER.pack(self.nonce, self.offset, self.total)
                + b"".join(e.encode() for e in self.entries))

    @classmethod
    def decode(cls, data: bytes) -> "MasterListResponsePayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("MASTER_LIST_RESPONSE truncated header")
        nonce, offset, total = cls._HEADER.unpack_from(data, 0)
        body = len(data) - cls._HEADER.size
        n = body // MasterServerEntry.SIZE
        entries = tuple(
            MasterServerEntry.decode_from(
                data, cls._HEADER.size + i * MasterServerEntry.SIZE)
            for i in range(n)
        )
        return cls(nonce, offset, total, entries)


@dataclass(frozen=True, slots=True)
class AuthChallengeRequestPayload:
    """launcher->S, out-of-session like SERVER_INFO_REQUEST. `nonce_echo` is a
    client-chosen correlation id echoed back verbatim, so a launcher with
    several outstanding requests can match answers to questions."""

    nonce_echo: int   # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<Q")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.nonce_echo & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "AuthChallengeRequestPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("AUTH_CHALLENGE_REQUEST truncated")
        (nonce_echo,) = cls._STRUCT.unpack_from(data, 0)
        return cls(nonce_echo)


@dataclass(frozen=True, slots=True)
class AuthChallengeResponsePayload:
    """S->launcher. `challenge` is single-use with a short server-side TTL: it
    is consumed by the HELLO that answers it (or expires). `ttl_s` tells the
    launcher how long it can sit on the challenge before launching the game —
    the game boot takes ~40s, so the server TTL must comfortably exceed it."""

    nonce_echo: int    # u64, mirrors the request
    challenge: bytes   # 32B random
    ttl_s: int         # u16, seconds of validity from now

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<QH")

    def encode(self) -> bytes:
        if len(self.challenge) != AUTH_CHALLENGE_LEN:
            raise ProtocolError("AUTH_CHALLENGE_RESPONSE: bad challenge len")
        return (self._STRUCT.pack(self.nonce_echo & 0xFFFFFFFFFFFFFFFF,
                                  self.ttl_s & 0xFFFF)
                + self.challenge)

    @classmethod
    def decode(cls, data: bytes) -> "AuthChallengeResponsePayload":
        need = cls._STRUCT.size + AUTH_CHALLENGE_LEN
        if len(data) < need:
            raise ProtocolError("AUTH_CHALLENGE_RESPONSE truncated")
        nonce_echo, ttl_s = cls._STRUCT.unpack_from(data, 0)
        challenge = bytes(data[cls._STRUCT.size:need])
        return cls(nonce_echo, challenge, ttl_s)


# ---------------------------------------------------------------------------
# L5 realtime D2 (2026-10-15) — DEATH_CRATES. Server -> the owner, reliable:
# the owner's death marks still standing, oldest first: the death crates in
# the world (wid != 0) and the SPOTS of the deaths that left no crate (wid
# 0; the owner's decision of the fourth live test: a marker for 15 minutes
# where they died with nothing to drop). Each carries the ordinal of its
# death (1, 2, 3... per peer, durable), its age in ms at send time (the
# clocks of the two sides never meet: the client turns it into its own
# expiry), where it stands and in which cell. `death_count` is how many
# deaths the peer had. The client names them by recency: the newest mark is
# "LATEST DEATH" (map and compass), the ones before it "CORPSE #2", "#3"...
# (map only). Sent after the record (boot and death), after a crate goes
# and after a spot expires. Header <HHI = 8 bytes, entry <IIQfffI = 32
# bytes, at most DEATH_CRATES_MAX entries (the newest win, logged).
DEATH_CRATES_MAX: int = (MAX_PAYLOAD_SIZE - 8) // 32   # 43


@dataclass(frozen=True, slots=True)
class DeathCrateEntry:
    wid: int          # 0 = a spot (a death without a crate)
    ordinal: int
    age_ms: int       # ms since that death, at send time
    px: float
    py: float
    pz: float
    cell_id: int


@dataclass(frozen=True, slots=True)
class DeathCratesPayload:
    death_count: int
    crates: tuple = ()
    flags: int = 0

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HHI")       # 8 B
    _ENTRY: ClassVar[struct.Struct] = struct.Struct("<IIQfffI")    # 32 B

    def encode(self) -> bytes:
        if len(self.crates) > DEATH_CRATES_MAX:
            raise ProtocolError(
                f"death crates: {len(self.crates)} entries, at most {DEATH_CRATES_MAX}")
        parts = [self._HEADER.pack(len(self.crates) & 0xFFFF, self.flags & 0xFFFF,
                                   self.death_count & 0xFFFFFFFF)]
        for c in self.crates:
            parts.append(self._ENTRY.pack(
                c.wid & 0xFFFFFFFF, c.ordinal & 0xFFFFFFFF, max(0, int(c.age_ms)) & 0xFFFFFFFFFFFFFFFF,
                float(c.px), float(c.py), float(c.pz), c.cell_id & 0xFFFFFFFF))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "DeathCratesPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("death crates header truncated")
        n, flags, death_count = cls._HEADER.unpack_from(data, 0)
        if n > DEATH_CRATES_MAX:
            raise ProtocolError(f"death crates: {n} entries, at most {DEATH_CRATES_MAX}")
        if len(data) < cls._HEADER.size + n * cls._ENTRY.size:
            raise ProtocolError("death crates entries truncated")
        crates = []
        off = cls._HEADER.size
        for _ in range(n):
            wid, ordinal, age_ms, px, py, pz, cell_id = cls._ENTRY.unpack_from(data, off)
            crates.append(DeathCrateEntry(wid, ordinal, age_ms, px, py, pz, cell_id))
            off += cls._ENTRY.size
        return cls(death_count=death_count, crates=tuple(crates), flags=flags)


# ---------------------------------------------------------------------------
# L5 realtime R5 (2026-10-16) — LOCATION_DISCOVERED. Client -> server,
# reliable: a map marker of the world just turned visible on this player's
# map (the engine's own reveal on approach, a quest, AddToMap). R5 stays
# vanilla by the owner's decision: the server keeps no places, it asks a
# checkpoint so a crash a minute later does not undo the discovery (the XP
# is in the stats record already). <I64s = 68 bytes, the name for the log.
@dataclass(frozen=True, slots=True)
class LocationDiscoveredPayload:
    marker_form_id: int
    name: str = ""

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<I64s")   # 68 B

    def encode(self) -> bytes:
        raw = self.name.encode("utf-8", "replace")[:63]
        return self._STRUCT.pack(self.marker_form_id & 0xFFFFFFFF, raw.ljust(64, b"\x00"))

    @classmethod
    def decode(cls, data: bytes) -> "LocationDiscoveredPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("LOCATION_DISCOVERED truncated")
        fid, raw = cls._STRUCT.unpack_from(data, 0)
        return cls(fid, raw.split(b"\x00", 1)[0].decode("utf-8", "replace"))


_TYPE_TO_PAYLOAD_CLS: dict[int, type] = {
    MessageType.SERVER_INFO_REQUEST:   ServerInfoRequestPayload,
    MessageType.SERVER_INFO_RESPONSE:  ServerInfoResponsePayload,
    MessageType.MASTER_REGISTER:       MasterRegisterPayload,
    MessageType.MASTER_LIST_REQUEST:   MasterListRequestPayload,
    MessageType.MASTER_LIST_RESPONSE:  MasterListResponsePayload,
    MessageType.AUTH_CHALLENGE_REQUEST:  AuthChallengeRequestPayload,
    MessageType.AUTH_CHALLENGE_RESPONSE: AuthChallengeResponsePayload,

    MessageType.HELLO:            HelloPayload,
    MessageType.HELLO_RESUME:     HelloResumePayload,
    MessageType.WELCOME:          WelcomePayload,
    MessageType.PEER_JOIN:        PeerJoinPayload,
    MessageType.PEER_LEAVE:       PeerLeavePayload,
    MessageType.HEARTBEAT:        HeartbeatPayload,
    MessageType.DISCONNECT:       DisconnectPayload,
    MessageType.ACK:              AckPayload,
    MessageType.POS_STATE:        PosStatePayload,
    MessageType.POS_BROADCAST:    PosBroadcastPayload,
    MessageType.POSE_STATE:       PoseStatePayload,
    MessageType.POSE_BROADCAST:   PoseBroadcastPayload,
    MessageType.POSE_CROUCH_STATE:     PoseCrouchStatePayload,      # v16
    MessageType.POSE_CROUCH_BROADCAST: PoseCrouchBroadcastPayload,  # v16
    MessageType.ACTOR_EVENT:      ActorEventPayload,
    MessageType.CHAT:             ChatPayload,
    MessageType.WORLD_STATE:      WorldStatePayload,
    MessageType.CONTAINER_OP:     ContainerOpPayload,
    MessageType.CONTAINER_BCAST:  ContainerBroadcastPayload,
    MessageType.CONTAINER_STATE:  ContainerStatePayload,
    MessageType.CONTAINER_SEED:   ContainerSeedPayload,
    MessageType.CONTAINER_OP_ACK: ContainerOpAckPayload,
    MessageType.INSTANCE_DEFS:    InstanceDefsPayload,      # v34
    MessageType.QUEST_STAGE_SET:       QuestStageSetPayload,
    MessageType.QUEST_STAGE_BCAST:     QuestStageBroadcastPayload,
    MessageType.QUEST_STATE_BOOT:      QuestStateBootPayload,
    MessageType.GLOBAL_VAR_SET:        GlobalVarSetPayload,
    MessageType.GLOBAL_VAR_BCAST:      GlobalVarBroadcastPayload,
    MessageType.GLOBAL_VAR_STATE_BOOT: GlobalVarStateBootPayload,
    # v20 — without these two entries the opcode decodes to nothing and the
    # handler is never reached, which is a silent no-op rather than an error.
    MessageType.APPEARANCE_SET:        AppearanceSetPayload,
    MessageType.APPEARANCE_BCAST:      AppearanceBroadcastPayload,
    MessageType.DOOR_OP:               DoorOpPayload,
    MessageType.DOOR_BCAST:            DoorBroadcastPayload,
    MessageType.EQUIP_OP:              EquipOpPayload,
    MessageType.EQUIP_BCAST:           EquipBroadcastPayload,
    MessageType.MESH_BLOB_OP:          MeshBlobChunkPayload,
    MessageType.MESH_BLOB_BCAST:       MeshBlobChunkBroadcastPayload,
    MessageType.LOCK_OP:               LockOpPayload,
    MessageType.LOCK_BCAST:            LockBroadcastPayload,
    MessageType.WORLD_SPAWN_OP:        WorldSpawnOpPayload,
    MessageType.WORLD_SPAWN_BCAST:     WorldSpawnBroadcastPayload,
    MessageType.WORLD_DESPAWN_OP:      WorldDespawnOpPayload,
    MessageType.WORLD_DESPAWN_BCAST:   WorldDespawnBroadcastPayload,
    MessageType.WORLD_PA_PIECES_OP:    WorldPaPiecesOpPayload,
    MessageType.WORLD_PA_PIECES_BCAST: WorldPaPiecesBroadcastPayload,
    MessageType.INV_DIGEST:            InvDigestPayload,
    MessageType.INV_STATE:             InvStatePayload,
    MessageType.RESTORE_REQUEST:       RestoreRequestPayload,
    MessageType.PLAYER_INV:            PlayerInvPayload,
    MessageType.RESTORE_DONE:          RestoreDonePayload,
    MessageType.STATS_STATE:           PlayerStatsPayload,
    MessageType.PLAYER_STATS:          PlayerStatsPayload,
    MessageType.WORLD_ITEM_OP:         WorldItemOpPayload,
    MessageType.WORLD_ITEM_ACK:        WorldItemAckPayload,
    MessageType.DEATH_CRATES:          DeathCratesPayload,
    MessageType.LOCATION_DISCOVERED:   LocationDiscoveredPayload,
    MessageType.CKPT_REQUEST:          CkptRequestPayload,
    MessageType.CKPT_DONE:             CkptDonePayload,
    MessageType.CKPT_BOOT:             CkptBootPayload,
    MessageType.BOOT_RESULT:           BootResultPayload,
    MessageType.PLAYER_LIFE:           PlayerLifePayload,
    MessageType.CKPT_RESPAWN:          CkptRespawnPayload,
    MessageType.NPC_STATE_BCAST:       NPCStateBroadcastPayload,
    MessageType.NPC_FIRE:              NPCFirePayload,
    MessageType.NPC_DISCOVER:          NPCDiscoverPayload,
    MessageType.NPC_PERCEPTION_TRIGGER: NPCPerceptionTriggerPayload,  # Build 62 v17
    # Build 65 — owner-driven NPC sync (Solver 2)
    MessageType.NPC_OBSERVED:                   NPCObservedPayload,
    MessageType.NPC_UNLOAD:                     NPCUnloadPayload,
    MessageType.NPC_OWNER_HEARTBEAT:            NPCOwnerHeartbeatPayload,
    MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_1:  NPCOwnershipHandoffPhase1Payload,
    MessageType.NPC_OWNERSHIP_RELEASE_ACK:      NPCOwnershipReleaseAckPayload,
    MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2:  NPCOwnershipHandoffPhase2Payload,
    MessageType.NPC_OWNERSHIP_BCAST:            NPCOwnershipBcastPayload,
    MessageType.NPC_STATE_FROM_OWNER:           NPCStateFromOwnerPayload,
    MessageType.NPC_FIRE_FROM_OWNER:            NPCFireFromOwnerPayload,
    MessageType.NPC_DEATH_FROM_OWNER:           NPCDeathFromOwnerPayload,
    MessageType.NPC_DAMAGE_FROM_OWNER:          NPCDamageFromOwnerPayload,
    MessageType.NPC_ENGAGEMENT_CLAIM:           NPCEngagementClaimPayload,
    MessageType.NPC_POSE_FROM_OWNER:            NPCPoseFromOwnerPayload,
    MessageType.NPC_CROUCH_FROM_OWNER:          NPCCrouchFromOwnerPayload,
    MessageType.NPC_DAMAGE_CLAIM:               NPCDamageClaimPayload,
    MessageType.NPC_HP_POOL_BCAST:              NPCHpPoolBcastPayload,
    MessageType.PEER_GHOST_REGISTER:   PeerGhostRegisterPayload,
}


@dataclass(frozen=True, slots=True)
class Frame:
    """Full decoded frame: header + typed payload."""
    header: FrameHeader
    payload: Payload


def encode_payload(payload: Payload) -> bytes:
    """Serialize a payload alone, the step that can raise (a struct.error on a
    value outside its field, a ProtocolError on an oversized string). Split
    from the frame so a reliable sender can run it BEFORE allocating a
    sequence number: until 2026-09-27 the sequence was allocated first, and a
    failed encode left a hole the receiver could never fill (retransmits,
    then a kick), which is how a single overflowing container count took a
    session down."""
    if isinstance(payload, RawMessage):
        payload_bytes = payload.payload
    else:
        payload_bytes = payload.encode()
    if len(payload_bytes) > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"payload {len(payload_bytes)}B exceeds max {MAX_PAYLOAD_SIZE}")
    return payload_bytes


def encode_frame_from_bytes(msg_type: int, seq: int, payload_bytes: bytes, *,
                            reliable: bool = False) -> bytes:
    """Frame an already-serialized payload (see encode_payload)."""
    flags = FLAG_RELIABLE if reliable else 0
    header = FrameHeader(msg_type=int(msg_type), seq=seq, payload_len=len(payload_bytes), flags=flags)
    return encode_header(header) + payload_bytes


def encode_frame(msg_type: int, seq: int, payload: Payload, *, reliable: bool = False) -> bytes:
    """Encode a full frame (header + payload) to bytes."""
    return encode_frame_from_bytes(msg_type, seq, encode_payload(payload), reliable=reliable)


def decode_frame(data: bytes) -> Frame:
    """Decode a full frame from raw bytes (header + payload).

    Unknown msg_type is returned as RawMessage so the receiver can drop or forward.
    """
    header = decode_header(data)
    expected_total = HEADER_SIZE + header.payload_len
    if len(data) < expected_total:
        raise ProtocolError(f"frame truncated: expected {expected_total}B, got {len(data)}B")
    payload_bytes = data[HEADER_SIZE:expected_total]

    cls = _TYPE_TO_PAYLOAD_CLS.get(header.msg_type)
    if cls is None:
        return Frame(header=header, payload=RawMessage(msg_type=header.msg_type, payload=payload_bytes))
    try:
        payload = cls.decode(payload_bytes)
    except struct.error as e:
        raise ProtocolError(f"payload decode failed for {MessageType(header.msg_type).name}: {e}") from e
    return Frame(header=header, payload=payload)
