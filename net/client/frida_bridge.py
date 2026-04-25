"""
Frida bridge: attach to a running Fallout4.exe, read local player state and
write remote ghost actor state.

Isolation: all Frida-specific code lives here. The rest of the client talks
to this via a simple async-queue interface. This module can be swapped with
a no-op fake for headless testing.

Frida callbacks fire on a background thread (Frida runtime). We marshal to the
asyncio loop via `loop.call_soon_threadsafe`.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger("frida_bridge")

# -------------------------------------------------------------- Frida JS

# Reverse-engineered constants validated for FO4 1.11.191 (see memory/reference_fo4_offsets.md)
_FRIDA_JS = r"""
// --- Reverse-engineered offsets (Fallout4.exe 1.11.191) ---
const SINGLETON_RVA       = 0x32D2260;   // PlayerCharacter singleton pointer
const ROT_OFF             = 0xC0;        // AngleX/Y/Z (float32 radians)
const POS_OFF             = 0xD0;        // X/Y/Z (float32)
const FLAGS_OFF           = 0x10;        // TESForm flags (u32); bit 0x800 = disabled
const FLAG_DISABLED       = 0x800;
const LOOKUP_RVA          = 0x311850;    // TESForm::LookupByFormID(u32) -> void*
const DISABLE_ENQUEUE_RVA = 0x5B3EE0;    // enqueue_disable(ref*, u8 fade_out) -> void
                                         // (called by console 'disable'; drains on next frame)
const ENABLE_CLEANUP_RVA  = 0x5B4430;    // enable_cleanup(ref*) -> void (always called)
const ENABLE_APPLY_RVA    = 0x5B4140;    // enable_apply(ref*) -> void (only if flags & 0x800)
const KILL_ENGINE_RVA     = 0xC612E0;    // sub_140C612E0: core Actor::Kill
                                         // (converged entry for console KillActor + Papyrus KillSilent)
                                         // signature: (Actor* target, Actor* killer, ?, u8 silent, int)
const FORMID_OFF          = 0x14;        // TESForm.formID (u32)
const PARENT_CELL_OFF     = 0xB8;        // TESObjectREFR::parentCell (TESObjectCELL*)
                                         // verified via Papyrus GetParentCell native sub_141180FD0
const BASE_FORM_OFF       = 0xE0;        // TESObjectREFR::baseForm (TESForm*)
                                         // verified via Papyrus GetBaseObject native sub_141155BE0
                                         // (fallback branch when no ExtraLeveledCreature override @ +0x100)
// Engine SetPos (non-Papyrus, via console command dispatcher):
// The console 'SetPos' command resolves to sub_1405C0F60 which calls
// sub_140C44FE0(queue, eventId=4103, refr, axis, value) — an enqueue into
// the main-thread message queue. This yields a proper Havok/NiNode/AI
// synchronized teleport (no flicker, unlike raw writes to REFR+0xD0).
const SETPOS_DISPATCH_RVA = 0xC44FE0;    // sub_140C44FE0: __int64(queue, u32, ...varargs)
const SETPOS_QUEUE_RVA    = 0x32F46F8;   // qword_1432F46F8: global message queue
const SETPOS_EVENT_ID     = 4103;        // "SetPos axis" event

// TESObjectREFR vtable[0x7A] = AddObjectToContainer. Convergent entry point
// for both directions of a player-container transfer: TAKE (dest=player)
// and PUT (source=player). Hook captures the item, count, and both refs;
// direction is inferred from which ref has formID == 0x14 (PlayerCharacter).
// Signature: __fastcall(dest_this*, bound_obj*, sp<ExtraDataList>*, int count, old_container*)
const ADD_TO_CONTAINER_RVA = 0xC7A500;
const PLAYER_FORMID_SENTINEL = 0x14;

const base      = Process.findModuleByName('Fallout4.exe').base;
const singleton = base.add(SINGLETON_RVA);
const lookupByFormID = new NativeFunction(
    base.add(LOOKUP_RVA), 'pointer', ['uint32']
);
const fnDisableEnqueue = new NativeFunction(
    base.add(DISABLE_ENQUEUE_RVA), 'void', ['pointer', 'uint8']
);
const fnEnableCleanup = new NativeFunction(
    base.add(ENABLE_CLEANUP_RVA), 'void', ['pointer']
);
const fnEnableApply = new NativeFunction(
    base.add(ENABLE_APPLY_RVA), 'void', ['pointer']
);

// Engine SetPos dispatcher. The native is variadic (`__int64(__int64, int, ...)`)
// but at call-site for eventId=4103 the flattened signature is
//   (queue*, u32 eventId, REFR*, u32 axis, float value).
// Frida's NativeFunction handles this if we declare the concrete types.
let setposDispatch = null;
let setposQueue = null;
let setposEnabled = false;
try {
    setposDispatch = new NativeFunction(
        base.add(SETPOS_DISPATCH_RVA),
        'int64',
        ['pointer', 'uint32', 'pointer', 'uint32', 'float']
    );
    // The queue instance is a global qword — dereference at attach time.
    setposQueue = base.add(SETPOS_QUEUE_RVA).readPointer();
    if (!setposQueue.isNull()) setposEnabled = true;
    console.log('[js] SetPos dispatcher ready (queue=' + setposQueue + ')');
} catch (e) {
    console.log('[js] SetPos dispatcher setup failed: ' + e + ' — falling back to raw write');
}

// Engine-sanctioned position set. Calls the dispatcher 3 times, once per
// axis (X=0, Y=1, Z=2). Processed on the game thread's next tick, syncs
// Havok rigidbody + NiNode transform + AI pathfinding target.
// Returns true on success, false on any failure (caller may fall back to
// raw writes to avoid losing the update entirely).
function setPosEngine(refPtr, x, y, z) {
    if (!setposEnabled || refPtr.isNull()) return false;
    try {
        setposDispatch(setposQueue, SETPOS_EVENT_ID, refPtr, 0, x);
        setposDispatch(setposQueue, SETPOS_EVENT_ID, refPtr, 1, y);
        setposDispatch(setposQueue, SETPOS_EVENT_ID, refPtr, 2, z);
        return true;
    } catch (e) {
        console.log('[js] setPosEngine err: ' + e + ' — disabling dispatcher for session');
        setposEnabled = false;   // disable on first failure, stop retrying
        return false;
    }
}

// Ghost-actor pointer cache. Refreshed if the cached pointer goes stale.
const ghostCache = new Map();   // formid -> NativePointer

function getActor(formid) {
    let ptr = ghostCache.get(formid);
    if (ptr && !ptr.isNull()) return ptr;
    ptr = lookupByFormID(formid);
    if (ptr.isNull()) return null;
    ghostCache.set(formid, ptr);
    return ptr;
}

// Read the stable identity triple of a ref pointer: its own form_id (ref_id),
// its base form's form_id, and its parent cell's form_id. Used to validate
// that a persisted (base, cell) tuple really refers to the same logical actor
// in this process (defeats the 0xFF______ runtime-id aliasing bug).
function readRefIdentity(refPtr) {
    const out = { form_id: 0, base_id: 0, cell_id: 0 };
    if (refPtr.isNull()) return out;
    try {
        out.form_id = refPtr.add(FORMID_OFF).readU32();
    } catch (e) { return out; }
    try {
        const basePtr = refPtr.add(BASE_FORM_OFF).readPointer();
        if (!basePtr.isNull()) out.base_id = basePtr.add(FORMID_OFF).readU32();
    } catch (e) { /* partial identity — base missing */ }
    try {
        const cellPtr = refPtr.add(PARENT_CELL_OFF).readPointer();
        if (!cellPtr.isNull()) out.cell_id = cellPtr.add(FORMID_OFF).readU32();
    } catch (e) { /* partial identity — cell missing (uninstantiated ref?) */ }
    return out;
}

// --- poll player state at LOCAL_TICK_HZ, emit via send() ---
const LOCAL_TICK_MS = 50;  // 20Hz
let readErrors = 0;
let notReadyLogged = false;

// The PlayerCharacter ref has a hardcoded formID of 0x14 in all Bethesda
// Creation Engine games. If we read the singleton and see anything else,
// the struct isn't fully initialized yet (save still loading, main menu,
// alloc'd but unpopulated) and any position we read would be garbage.
// Sending garbage to the server propagates it to the other peer's ghost
// write and can make the ghost actor invisible (NaN/huge coords -> no
// render). Gate the send on a valid formID read.
const PLAYER_FORMID = 0x14;
// Any FO4 world coord should fit well under 1e7 in magnitude. Anything
// larger is almost certainly garbage memory.
const COORD_SANITY_BOUND = 1e7;

function isFiniteBounded(v) {
    // Using JS Number.isFinite (not the coerced global isFinite) so we
    // reject NaN, +Infinity, -Infinity, and (implicitly via the bound) huge
    // garbage. Math.abs(NaN) is NaN, which fails the > comparison — so the
    // bound check also rules NaN out.
    return Number.isFinite(v) && Math.abs(v) < COORD_SANITY_BOUND;
}

setInterval(() => {
    try {
        const pp = singleton.readPointer();
        if (pp.isNull()) return;
        // Player formID gate: 0x14 means the struct is populated and this
        // is really the player. Anything else = skip (avoid sending garbage).
        const formId = pp.add(FORMID_OFF).readU32();
        if (formId !== PLAYER_FORMID) {
            if (!notReadyLogged) {
                console.log('[js] player singleton not ready (formID=0x' +
                             formId.toString(16) + '), waiting...');
                notReadyLogged = true;
            }
            return;
        }
        // parentCell gate: FO4 pre-allocates the player struct at main menu
        // (for char-creation preview etc) with formID=0x14 already set, so
        // the formID check passes but the position is default (often 0,0,0).
        // The parentCell pointer is null at main menu / intro screens and
        // non-null once a save has loaded the player into a real cell.
        // Gating on this avoids shipping default pos to the other peer and
        // teleporting their ghost to world origin (observed live as
        // "Codsworth disappears in A when B hits the main menu").
        const cellPtr = pp.add(PARENT_CELL_OFF).readPointer();
        if (cellPtr.isNull()) {
            if (!notReadyLogged) {
                console.log('[js] player parentCell null (main menu / load screen), waiting...');
                notReadyLogged = true;
            }
            return;
        }
        const x  = pp.add(POS_OFF).readFloat();
        const y  = pp.add(POS_OFF + 4).readFloat();
        const z  = pp.add(POS_OFF + 8).readFloat();
        const rx = pp.add(ROT_OFF).readFloat();
        const ry = pp.add(ROT_OFF + 4).readFloat();
        const rz = pp.add(ROT_OFF + 8).readFloat();
        // Paranoid finite+bound check on every scalar. Rare but worth it —
        // a NaN that slips through here would disable the far-peer's ghost.
        if (!isFiniteBounded(x) || !isFiniteBounded(y) || !isFiniteBounded(z) ||
            !isFiniteBounded(rx) || !isFiniteBounded(ry) || !isFiniteBounded(rz)) {
            return;
        }
        send({
            kind: 'player_pos',
            x: x, y: y, z: z, rx: rx, ry: ry, rz: rz,
            ts: Date.now(),
        });
    } catch (e) {
        readErrors++;
        if (readErrors < 5) console.log('[js] read err: ' + e);
    }
}, LOCAL_TICK_MS);

// --- receive commands from Python ---
function onMsg(msg) {
    try {
        if (msg.op === 'write_ghost') {
            const ptr = getActor(msg.formid);
            if (!ptr) { recv(onMsg); return; }
            // Raw write on REFR+0xD0 for pos + 0xC0 for rotation. This is
            // the original approach: fast (no engine call per frame) but
            // fights Havok + NiNode (flicker). Requires manual `prid;tcl`
            // in console to tame Havok. Step 8b attempt to use the engine
            // SetPos dispatcher (eventId=4103, queue RVA 0x32F46F8) did NOT
            // move the REFR in tests (rotation-only behavior observed) —
            // the variadic type table for that event is not what we assumed.
            // Reverted until we RE the type table at off_142EDF200.
            ptr.add(POS_OFF).writeFloat(msg.x);
            ptr.add(POS_OFF + 4).writeFloat(msg.y);
            ptr.add(POS_OFF + 8).writeFloat(msg.z);
            ptr.add(ROT_OFF).writeFloat(msg.rx);
            ptr.add(ROT_OFF + 4).writeFloat(msg.ry);
            ptr.add(ROT_OFF + 8).writeFloat(msg.rz);
        } else if (msg.op === 'set_disabled') {
            // Call the engine functions used by console 'disable'/'enable' commands.
            // These enqueue the state change to be processed on the next game tick,
            // giving correct render+physics+AI cleanup (not just a cosmetic flag flip).
            const ptr = getActor(msg.formid);
            if (!ptr) { recv(onMsg); return; }
            const flags = ptr.add(FLAGS_OFF).readU32();
            const currentlyDisabled = (flags & FLAG_DISABLED) !== 0;
            if (msg.disabled && !currentlyDisabled) {
                fnDisableEnqueue(ptr, msg.fade_out ? 1 : 0);
                send({ kind: 'disabled_applied', formid: msg.formid, disabled: true,
                       flags_before: flags, validated: false });
            } else if (!msg.disabled && currentlyDisabled) {
                fnEnableCleanup(ptr);
                fnEnableApply(ptr);
                send({ kind: 'disabled_applied', formid: msg.formid, disabled: false,
                       flags_before: flags, validated: false });
            }
        } else if (msg.op === 'set_disabled_validated') {
            // Identity-validated disable/enable: resolves the ref by formid,
            // then checks that its parentCell.formID and baseForm.formID match
            // the expected identity. Only applies the change if they match.
            // This prevents applying persistence state to the wrong object when
            // the persisted ref_id coincidentally resolves to a different actor
            // in this process (the 0xFF______ runtime-id aliasing bug).
            //
            // If expected_base_id or expected_cell_id is 0 the corresponding
            // check is skipped — used as a graceful degrade when the server
            // lacks full identity info (legacy snapshot entries).
            const ptr = getActor(msg.formid);
            if (!ptr) {
                send({ kind: 'validate_miss', formid: msg.formid,
                       reason: 'lookup_null' });
                recv(onMsg); return;
            }
            const id = readRefIdentity(ptr);
            const baseMismatch = msg.expected_base_id !== 0
                                  && id.base_id !== msg.expected_base_id;
            const cellMismatch = msg.expected_cell_id !== 0
                                  && id.cell_id !== msg.expected_cell_id;
            if (baseMismatch || cellMismatch) {
                send({
                    kind: 'validate_miss',
                    formid: msg.formid,
                    reason: baseMismatch ? 'base_mismatch' : 'cell_mismatch',
                    got_base_id: id.base_id,
                    got_cell_id: id.cell_id,
                    expected_base_id: msg.expected_base_id,
                    expected_cell_id: msg.expected_cell_id,
                });
                recv(onMsg); return;
            }
            const flags = ptr.add(FLAGS_OFF).readU32();
            const currentlyDisabled = (flags & FLAG_DISABLED) !== 0;
            if (msg.disabled && !currentlyDisabled) {
                fnDisableEnqueue(ptr, msg.fade_out ? 1 : 0);
                send({ kind: 'disabled_applied', formid: msg.formid, disabled: true,
                       flags_before: flags, validated: true });
            } else if (!msg.disabled && currentlyDisabled) {
                fnEnableCleanup(ptr);
                fnEnableApply(ptr);
                send({ kind: 'disabled_applied', formid: msg.formid, disabled: false,
                       flags_before: flags, validated: true });
            }
        } else if (msg.op === 'invalidate_ghost') {
            ghostCache.delete(msg.formid);
        } else if (msg.op === 'ping') {
            send({ kind: 'pong' });
        }
    } catch (e) {
        console.log('[js] cmd err: ' + e);
    }
    recv(onMsg);
}
recv(onMsg);

// --- Kill-event capture: attach non-destructively to the engine kill function ---
// Every time a kill happens in-game (by player, AI, console, or any source)
// we get a callback with the victim's Actor pointer. We read its formID and
// notify Python. The original function proceeds unchanged.
try {
    Interceptor.attach(base.add(KILL_ENGINE_RVA), {
        onEnter: function (args) {
            try {
                const victim = args[0];
                const killer = args[1];
                if (victim.isNull()) return;
                const vi = readRefIdentity(victim);
                const ki = killer.isNull()
                    ? { form_id: 0, base_id: 0, cell_id: 0 }
                    : readRefIdentity(killer);
                send({
                    kind: 'actor_killed',
                    formid: vi.form_id,
                    base_id: vi.base_id,
                    cell_id: vi.cell_id,
                    killer_formid: ki.form_id,
                    killer_base_id: ki.base_id,
                    killer_cell_id: ki.cell_id,
                });
            } catch (e) {
                // silent — kill path must not be disrupted
            }
        },
    });
    console.log('[js] kill hook attached @ RVA 0x' + KILL_ENGINE_RVA.toString(16));
} catch (e) {
    console.log('[js] kill hook attach failed: ' + e);
}

// Container transfer hook: intercepts TESObjectREFR::AddObjectToContainer
// (vtable slot 0x7A). Fires on every item transfer between refs; we filter
// to only player-container transfers and emit a single 'container_op' event.
// Signature: (dest_REFR*, TESBoundObject* item, sp<ExtraDataList>**, int count,
//             source_REFR* oldContainer, ITEM_REMOVE_REASON reason)
try {
    Interceptor.attach(base.add(ADD_TO_CONTAINER_RVA), {
        onEnter: function (args) {
            try {
                const dest   = args[0];
                const bound  = args[1];
                const count  = args[3].toInt32();
                const source = args[4];

                if (bound.isNull() || count <= 0) return;

                // Read formIDs to detect player involvement.
                const destFid = dest.isNull()   ? 0 : dest.add(FORMID_OFF).readU32();
                const srcFid  = source.isNull() ? 0 : source.add(FORMID_OFF).readU32();

                let opKind = null;       // 'TAKE' or 'PUT'
                let containerPtr = null; // the non-player ref

                if (destFid === PLAYER_FORMID_SENTINEL) {
                    // Player is destination → player is TAKING from source
                    if (source.isNull()) return;   // no container to credit
                    opKind = 'TAKE';
                    containerPtr = source;
                } else if (srcFid === PLAYER_FORMID_SENTINEL) {
                    // Player is source → player is PUTTING into dest
                    if (dest.isNull()) return;
                    opKind = 'PUT';
                    containerPtr = dest;
                } else {
                    // Neither side is player — non-player transfer (NPC looting
                    // corpses, vendor restocks, script spawns). Ignore.
                    return;
                }

                const cid = readRefIdentity(containerPtr);
                if (cid.base_id === 0 || cid.cell_id === 0) {
                    // Container lacks stable identity — happens for refs that
                    // aren't properly placed or are mid-construction. Skip.
                    return;
                }

                const itemBaseId = bound.add(FORMID_OFF).readU32();
                if (itemBaseId === 0) return;

                send({
                    kind: 'container_op',
                    op: opKind,
                    container_base_id: cid.base_id,
                    container_cell_id: cid.cell_id,
                    container_form_id: cid.form_id,
                    item_base_id: itemBaseId,
                    count: count,
                });
            } catch (e) {
                // silent — container path must not be disrupted
            }
        },
    });
    console.log('[js] container hook attached @ RVA 0x' + ADD_TO_CONTAINER_RVA.toString(16));
} catch (e) {
    console.log('[js] container hook attach failed: ' + e);
}

console.log('[js] frida bridge armed');
"""


# -------------------------------------------------------------- data classes

@dataclass(frozen=True, slots=True)
class PlayerReading:
    x: float; y: float; z: float
    rx: float; ry: float; rz: float
    ts_ms: int


@dataclass(frozen=True, slots=True)
class KillEvent:
    """A kill captured live via the engine-hook in the Frida script.

    Carries both the ref-level form_id (session-scoped for 0xFF______ runtime
    refs, stable for 0x00______ placed refs) AND the stable identity tuple
    (base_id, cell_id) that survives process restarts. The server uses
    (base, cell) as the persistence key; ref_id is only a hint.
    """
    victim_form_id: int
    killer_form_id: int = 0     # 0 if unknown / environment kill
    victim_base_id: int = 0     # TESForm.formID of baseForm (TESNPC for Actor)
    victim_cell_id: int = 0     # TESForm.formID of parentCell (TESObjectCELL)
    killer_base_id: int = 0
    killer_cell_id: int = 0


@dataclass(frozen=True, slots=True)
class ContainerCapture:
    """A container TAKE/PUT captured from the engine hook.

    op_kind is 'TAKE' when the player just received an item (player was
    destination of the transfer), 'PUT' when the player placed one (player
    was source). The `container_*` fields identify the NON-player ref
    involved. container_form_id is a hint; (base_id, cell_id) is the key.
    """
    op_kind: str              # 'TAKE' or 'PUT'
    container_base_id: int
    container_cell_id: int
    container_form_id: int    # hint for client-side lookup, not authoritative
    item_base_id: int
    count: int


# -------------------------------------------------------------- bridge

class FridaBridge:
    """Manages the Frida session + script + async message queue.

    Lifecycle:
        bridge = FridaBridge(pid=1234)
        await bridge.start(loop)
        ... emits PlayerReading to bridge.player_queue ...
        bridge.write_ghost(formid, pos_payload)
        await bridge.stop()
    """

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._session = None  # frida.core.Session
        self._script = None   # frida.core.Script
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.player_queue: asyncio.Queue[PlayerReading] = asyncio.Queue(maxsize=256)
        self.kill_queue: asyncio.Queue[KillEvent] = asyncio.Queue(maxsize=256)
        self.container_queue: asyncio.Queue[ContainerCapture] = asyncio.Queue(maxsize=256)
        self._read_count = 0
        self._kill_count = 0
        self._container_count = 0

    async def start(self) -> None:
        """Attach Frida and load the bridge script. Must be called from within an async context."""
        import frida  # deferred import so tests without frida still work
        self._loop = asyncio.get_running_loop()
        dev = frida.get_local_device()
        try:
            self._session = dev.attach(self.pid)
        except Exception as e:
            raise RuntimeError(f"frida attach to pid={self.pid} failed: {e}") from e
        self._script = self._session.create_script(_FRIDA_JS)
        self._script.on("message", self._on_message)
        self._script.load()
        log.info("frida bridge attached to pid=%d", self.pid)

    async def stop(self) -> None:
        if self._script is not None:
            try:
                self._script.unload()
            except Exception:
                pass
            self._script = None
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

    def write_ghost(self, form_id: int, x: float, y: float, z: float,
                     rx: float, ry: float, rz: float) -> None:
        """Post a ghost-actor write command. Fire-and-forget (Frida handles in bg)."""
        if self._script is None:
            return
        self._script.post({
            "op": "write_ghost",
            "formid": form_id,
            "x": x, "y": y, "z": z,
            "rx": rx, "ry": ry, "rz": rz,
        })

    def set_disabled(self, form_id: int, disabled: bool, *, fade_out: bool = False) -> None:
        """Enable or disable an actor via the engine's console-disable/enable path.

        Calls sub_1405B3EE0 (disable-enqueue) or the sub_1405B4430+sub_1405B4140
        pair (enable-cleanup+apply) — the same functions the console 'disable'
        and 'enable' commands invoke. Changes materialize on the next game tick.

        WARNING: unvalidated. Applies to whatever formid resolves to in this
        process. For persistence apply use set_disabled_validated() instead —
        this variant is retained only for ad-hoc scripts and transitions
        between peers that share a live session (where ref_ids match by
        construction, not by persistence hop).
        """
        if self._script is None:
            return
        self._script.post({
            "op": "set_disabled",
            "formid": form_id,
            "disabled": disabled,
            "fade_out": fade_out,
        })

    def set_disabled_validated(
        self,
        form_id: int,
        *,
        expected_base_id: int,
        expected_cell_id: int,
        disabled: bool,
        fade_out: bool = False,
    ) -> None:
        """Disable/enable an actor ONLY if its identity matches the expected tuple.

        The JS side resolves the ref by `form_id` then checks
        `ref->baseForm.formID == expected_base_id` and
        `ref->parentCell.formID == expected_cell_id`. If either mismatches,
        emits a `validate_miss` log message and does not touch the ref.
        Pass 0 for expected_base_id or expected_cell_id to skip that check
        (graceful degrade for legacy persistence entries without full identity).
        """
        if self._script is None:
            return
        self._script.post({
            "op": "set_disabled_validated",
            "formid": form_id,
            "expected_base_id": expected_base_id,
            "expected_cell_id": expected_cell_id,
            "disabled": disabled,
            "fade_out": fade_out,
        })

    def invalidate_ghost(self, form_id: int) -> None:
        if self._script is None:
            return
        self._script.post({"op": "invalidate_ghost", "formid": form_id})

    # ---- Frida -> Python bridge (called on Frida thread) ----

    def _on_message(self, msg: dict, _data: bytes) -> None:
        if self._loop is None:
            return
        if msg.get("type") == "error":
            log.error("[js err] %s", msg.get("description"))
            return
        if msg.get("type") != "send":
            return
        payload = msg.get("payload") or {}
        kind = payload.get("kind")
        if kind == "player_pos":
            try:
                reading = PlayerReading(
                    x=payload["x"], y=payload["y"], z=payload["z"],
                    rx=payload["rx"], ry=payload["ry"], rz=payload["rz"],
                    ts_ms=int(payload["ts"]),
                )
            except (KeyError, TypeError) as e:
                log.warning("bad player_pos payload: %s", e)
                return
            self._loop.call_soon_threadsafe(self._enqueue_player, reading)
        elif kind == "actor_killed":
            try:
                kev = KillEvent(
                    victim_form_id=int(payload["formid"]),
                    killer_form_id=int(payload.get("killer_formid", 0)),
                    victim_base_id=int(payload.get("base_id", 0)),
                    victim_cell_id=int(payload.get("cell_id", 0)),
                    killer_base_id=int(payload.get("killer_base_id", 0)),
                    killer_cell_id=int(payload.get("killer_cell_id", 0)),
                )
            except (KeyError, TypeError) as e:
                log.warning("bad actor_killed payload: %s", e)
                return
            self._loop.call_soon_threadsafe(self._enqueue_kill, kev)
        elif kind == "container_op":
            try:
                cap = ContainerCapture(
                    op_kind=str(payload["op"]),
                    container_base_id=int(payload["container_base_id"]),
                    container_cell_id=int(payload["container_cell_id"]),
                    container_form_id=int(payload.get("container_form_id", 0)),
                    item_base_id=int(payload["item_base_id"]),
                    count=int(payload["count"]),
                )
            except (KeyError, TypeError, ValueError) as e:
                log.warning("bad container_op payload: %s (%r)", e, payload)
                return
            self._loop.call_soon_threadsafe(self._enqueue_container, cap)
        elif kind == "disabled_applied":
            log.info(
                "js confirmed disabled applied: formid=0x%X disabled=%s validated=%s",
                payload.get("formid", 0),
                payload.get("disabled"),
                payload.get("validated", False),
            )
        elif kind == "validate_miss":
            # Identity check rejected a persistence apply — LOUD log because
            # this is exactly the case that would have silently corrupted state
            # before step 2. Keeps us honest.
            log.warning(
                "validated disable REJECTED: formid=0x%X reason=%s "
                "got=(base=0x%X, cell=0x%X) expected=(base=0x%X, cell=0x%X)",
                payload.get("formid", 0),
                payload.get("reason", "?"),
                payload.get("got_base_id", 0),
                payload.get("got_cell_id", 0),
                payload.get("expected_base_id", 0),
                payload.get("expected_cell_id", 0),
            )
        else:
            log.debug("js msg: %s", payload)

    def _enqueue_player(self, reading: PlayerReading) -> None:
        """Called on the asyncio loop thread."""
        try:
            self.player_queue.put_nowait(reading)
            self._read_count += 1
        except asyncio.QueueFull:
            # Drop oldest, keep newest (latency-critical)
            try:
                self.player_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self.player_queue.put_nowait(reading)
            except asyncio.QueueFull:
                pass

    def _enqueue_kill(self, kev: KillEvent) -> None:
        """Called on the asyncio loop thread."""
        try:
            self.kill_queue.put_nowait(kev)
            self._kill_count += 1
        except asyncio.QueueFull:
            log.warning("kill_queue full; dropping event for 0x%X", kev.victim_form_id)

    def _enqueue_container(self, cap: ContainerCapture) -> None:
        """Called on the asyncio loop thread."""
        try:
            self.container_queue.put_nowait(cap)
            self._container_count += 1
        except asyncio.QueueFull:
            log.warning(
                "container_queue full; dropping %s op for container 0x%X/0x%X item 0x%X",
                cap.op_kind, cap.container_base_id, cap.container_cell_id, cap.item_base_id,
            )

    @property
    def read_count(self) -> int:
        return self._read_count

    @property
    def kill_count(self) -> int:
        return self._kill_count


# -------------------------------------------------------------- fake bridge (for tests)

class FakeFridaBridge:
    """Drop-in replacement that doesn't need Frida or FO4. Used by tests and headless smoke runs."""

    def __init__(self, pid: int = 0) -> None:
        self.pid = pid
        self.player_queue: asyncio.Queue[PlayerReading] = asyncio.Queue()
        self.kill_queue: asyncio.Queue[KillEvent] = asyncio.Queue()
        self.container_queue: asyncio.Queue[ContainerCapture] = asyncio.Queue()
        self.writes_received: list[tuple[int, PlayerReading]] = []
        # Start calls lists empty so tests can inspect them without checking
        # existence. This was a minor footgun pre-Option-B and caused one of
        # the test_live_kill_propagation regressions.
        self.disabled_calls: list[tuple[int, bool]] = []
        self.validated_disabled_calls: list[tuple[int, int, int, bool]] = []
        self._read_count = 0
        self._kill_count = 0
        self._container_count = 0

    async def start(self) -> None: pass
    async def stop(self) -> None: pass

    def write_ghost(self, form_id: int, x: float, y: float, z: float,
                     rx: float, ry: float, rz: float) -> None:
        self.writes_received.append((form_id, PlayerReading(x, y, z, rx, ry, rz, 0)))

    def set_disabled(self, form_id: int, disabled: bool, *, fade_out: bool = False) -> None:
        # Record for tests to introspect
        if not hasattr(self, "disabled_calls"):
            self.disabled_calls = []
        self.disabled_calls.append((form_id, disabled))

    def set_disabled_validated(
        self,
        form_id: int,
        *,
        expected_base_id: int,
        expected_cell_id: int,
        disabled: bool,
        fade_out: bool = False,
    ) -> None:
        # Record for tests to introspect identity-validated apply calls.
        if not hasattr(self, "validated_disabled_calls"):
            self.validated_disabled_calls: list[tuple[int, int, int, bool]] = []
        self.validated_disabled_calls.append(
            (form_id, expected_base_id, expected_cell_id, disabled)
        )

    def invalidate_ghost(self, form_id: int) -> None: pass

    def feed(self, reading: PlayerReading) -> None:
        """Test helper: simulate a player reading from Frida."""
        self.player_queue.put_nowait(reading)
        self._read_count += 1

    def feed_kill(self, event: KillEvent) -> None:
        """Test helper: simulate a kill event from Frida."""
        self.kill_queue.put_nowait(event)
        self._kill_count += 1

    def feed_container_op(self, cap: ContainerCapture) -> None:
        """Test helper: simulate a container op captured from the engine hook."""
        self.container_queue.put_nowait(cap)
        self._container_count += 1

    @property
    def read_count(self) -> int: return self._read_count

    @property
    def kill_count(self) -> int: return self._kill_count
