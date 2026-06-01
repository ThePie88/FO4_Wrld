// ============================================================================
// FalloutWorld — Combat AI Brain trace via Frida (v2 — quiet mode)
// Fallout 4 1.11.191 (next-gen). Image base assumed 0x140000000.
//
// v2 design: log ONLY interesting events.
//   - State changes (was X, now Y) — not every per-frame value
//   - Ghost-involved events (filter by default)
//   - Crashes with full register + stack dump
//   - Compact 2-second state heartbeat
//
// Per-fire logging is OFF for hot paths. Each hook tracks per-(actor,
// controller) state and logs only when it changes. This avoids the
// "hundreds of lines per second of the same thing" problem.
//
// USAGE:
//   frida -n Fallout4.exe -l combat_brain_trace.js -o trace.log
// ============================================================================

"use strict";

// ----------------------------------------------------------------------------
// Configuration — flip these to true to enable verbose per-fire logging
// (default OFF for everything except crash + ghost-involved state changes).
// ----------------------------------------------------------------------------

const MODULE_NAME = "Fallout4.exe";

const CFG = {
    // If true, also log calls that DON'T involve the ghost (very noisy).
    // Default: false — only ghost-involved events + state transitions.
    LOG_NON_GHOST: false,

    // Periodic compact state dump cadence. 0 to disable.
    STATE_DUMP_MS: 2000,

    // Log when a CombatController's `+0x110` alive count changes.
    LOG_ALIVE_TRANSITIONS: true,

    // Log when AIProcess's `+0x6C` target handle changes (per aiproc).
    LOG_TARGET_TRANSITIONS: true,

    // Log HostilityCore returns for ghost pairs.
    LOG_HOSTILITY_GHOST: true,

    // Log EnterCombat unconditionally — rare and important.
    LOG_ENTER_COMBAT: true,

    // Log fire pipeline (DispatchAttack, WeaponFireHandler, Projectile::Launch)
    // for ghost-targeted raiders only.
    LOG_FIRE_PIPELINE_GHOST: true,

    // Log when WeaponFireHandler returns NOT 1 (suppression).
    LOG_WFH_NONZERO_RC: true,

    // Log event dispatch (sub_140DEF780) when vt[3] is dangerous (outside
    // module range — Build 43b crash signature).
    LOG_EVENT_DISPATCH_DANGEROUS: true,

    // Log AddTarget calls with ghost as target.
    LOG_ADDTARGET_GHOST: true,

    // Log hit applier with ghost as target (= raider's projectile hit ghost).
    LOG_HITAPPLIER_GHOST: true,

    // Per-fire heartbeats for FYI (every Nth call). Set high to silence.
    HEARTBEAT_EVERY: 100000,

    // Crash handler: always on.
    CRASH_HANDLER: true,
};

const GHOST_FORMID = 0xFF000001;
const PLAYER_FORMID = 0x14;

// ----------------------------------------------------------------------------
// RVAs — re/AI_pipeline/MASTER.md + fw_native/src/offsets.h
// ----------------------------------------------------------------------------

const RVA = {
    Actor_vt255_orchestrator:       0x00CCFDF0,
    CombatController_Update:        0x00E918C0,
    CombatController_AddTarget:     0x00E91D70,
    AliveCounter:                   0x00E9E650,
    PostPickGate:                   0x0087A900,
    HostilityCore:                  0x00C8DFF0,
    IsHostile_master:               0x00C7AD40,
    CellLoaded:                     0x004FB890,
    EnterCombat:                    0x00CCF810,
    GunFire_DecideAndFire:          0x0086FCA0,
    Actor_DispatchAttackAction:     0x00E6F830,
    WeaponFireHandler:              0x00DFF6B0,
    Projectile_Launch:              0x00479680,
    HitApplier:                     0x00CD2780,
    EventDispatch:                  0x00DEF780,
    FormReader:                     0x002F9860,
    HandleTableBase:                0x030DA390,
};

const OFF = {
    FormID:                   0x14,
    Flags:                    0x10,
    ParentCell:               0xB8,
    BaseForm:                 0xE0,
    ActorFlags720:            0x2D0,
    InCombat_bit:             0x4000,
    AIProcess_combat:         0x328,

    AIP_Controller:           0x40,
    AIP_TargetHandle:         0x68,
    AIP_TargetHandle2:        0x6C,
    AIP_AliveByte:            0xDF,
    AIP_SelectorCount:        0x110,

    CC_Trackers_count:        0x18,
    CC_Allies_count:          0x30,
    CC_InCombatFlag:          0x98,
    CC_AliveTotal:            0x110,
    CC_AliveHostile:          0x114,
    CC_StateMarker:           0x11C,
};

// ----------------------------------------------------------------------------
// Module base resolution (Frida 16.x + 17.x compat)
// ----------------------------------------------------------------------------

function resolveModuleBase(name) {
    if (typeof Process !== "undefined") {
        if (typeof Process.findModuleByName === "function") {
            const m = Process.findModuleByName(name);
            if (m && m.base) return m.base;
        }
        if (typeof Process.enumerateModules === "function") {
            for (const m of Process.enumerateModules()) {
                if (m.name && m.name.toLowerCase() === name.toLowerCase()) {
                    return m.base;
                }
            }
        }
    }
    if (typeof Module !== "undefined" &&
        typeof Module.findBaseAddress === "function") {
        const p = Module.findBaseAddress(name);
        if (p && !p.isNull()) return p;
    }
    return null;
}

const base = resolveModuleBase(MODULE_NAME);
if (!base) {
    throw new Error("Module not found: " + MODULE_NAME);
}

// Module end estimate (for "in-module pointer?" checks).
let modEndAddr = base.add(0x10000000); // 256MB cap, generous
try {
    if (typeof Process !== "undefined" &&
        typeof Process.findModuleByName === "function") {
        const m = Process.findModuleByName(MODULE_NAME);
        if (m && m.size) modEndAddr = base.add(m.size);
    }
} catch (e) {}

const log = (...args) => console.log("[trace]", ...args);

log("module base:", base.toString());
log("module end (est):", modEndAddr.toString());

// ----------------------------------------------------------------------------
// Memory read helpers (Frida 16.x/17.x compat)
// ----------------------------------------------------------------------------

const HAS_MEM_READ = (typeof Memory !== "undefined" &&
                     typeof Memory.readPointer === "function");

function safeReadPointer(p) {
    try { return HAS_MEM_READ ? Memory.readPointer(p) : p.readPointer(); }
    catch (e) { return ptr(0); }
}
function safeReadU32(p) {
    try { return HAS_MEM_READ ? Memory.readU32(p) : p.readU32(); }
    catch (e) { return 0; }
}
function safeReadU8(p) {
    try { return HAS_MEM_READ ? Memory.readU8(p) : p.readU8(); }
    catch (e) { return 0; }
}

function hex(p) { return p && p.toString ? p.toString() : "" + p; }
function fid(p) {
    if (!p || p.isNull()) return "<null>";
    return "0x" + safeReadU32(p.add(OFF.FormID)).toString(16).padStart(8, "0");
}
function isGhost(p) {
    if (!p || p.isNull()) return false;
    return safeReadU32(p.add(OFF.FormID)) === GHOST_FORMID;
}
function inModule(p) {
    try {
        const n = parseInt(p.toString(), 16);
        const lo = parseInt(base.toString(), 16);
        const hi = parseInt(modEndAddr.toString(), 16);
        return n >= lo && n < hi;
    } catch (e) { return false; }
}

// ----------------------------------------------------------------------------
// State-change trackers — per (object, field) memory of last value
// ----------------------------------------------------------------------------

// Map: address.toString() → last known value
const lastAlive = new Map();         // controller → alive_total
const lastAliveHostile = new Map();  // controller → alive_hostile
const lastInCombatFlag = new Map();  // controller → in_combat dword
const lastStateMarker = new Map();   // controller → state byte
const lastTargetHandle = new Map();  // aiproc → handle DWORD
const lastHostilityResult = new Map(); // "a1Ptr|a2Ptr" → rank int

const trackedControllers = new Set(); // addrs we've seen — periodic dump
const ghostEngagedAips = new Set();   // aiprocs that ever pointed at ghost

function trackController(p) {
    if (!p || p.isNull()) return;
    trackedControllers.add(p.toString());
}

// ----------------------------------------------------------------------------
// Compact periodic state dump
// ----------------------------------------------------------------------------

if (CFG.STATE_DUMP_MS > 0) {
    setInterval(() => {
        if (trackedControllers.size === 0) return;
        const lines = [];
        for (const s of trackedControllers) {
            const p = ptr(s);
            const at = safeReadU32(p.add(OFF.CC_AliveTotal));
            const ah = safeReadU32(p.add(OFF.CC_AliveHostile));
            const inc = safeReadU32(p.add(OFF.CC_InCombatFlag));
            const sm = safeReadU8(p.add(OFF.CC_StateMarker));
            const tc = safeReadU32(p.add(OFF.CC_Trackers_count));
            const ac = safeReadU32(p.add(OFF.CC_Allies_count));
            lines.push(
                "ctrl=" + s.slice(-9) +
                " a(t/h)=" + at + "/" + ah +
                " inc=" + inc +
                " sm=0x" + sm.toString(16) +
                " trk=" + tc + " ally=" + ac);
        }
        log("[heartbeat]", lines.length, "ctrl(s):");
        for (const l of lines) log("  " + l);
    }, CFG.STATE_DUMP_MS);
}

// ----------------------------------------------------------------------------
// Hook utility
// ----------------------------------------------------------------------------

function hook(name, addr, onEnter, onLeave) {
    try {
        Interceptor.attach(addr, { onEnter, onLeave });
        log("hooked", name, "@", hex(addr));
    } catch (e) {
        log("FAILED to hook", name, "@", hex(addr), ":", e.message);
    }
}

// ----------------------------------------------------------------------------
// HOOK: CombatController::Update sub_140E918C0
// Logs ONLY when controller state changes (alive count, in-combat, state byte).
// ----------------------------------------------------------------------------

hook("CombatController::Update",
    base.add(RVA.CombatController_Update),
    function (args) {
        const ctrl = args[0];
        trackController(ctrl);
        this.ctrl = ctrl;
    },
    function () {
        if (!this.ctrl) return;
        const k = this.ctrl.toString();
        const at = safeReadU32(this.ctrl.add(OFF.CC_AliveTotal));
        const ah = safeReadU32(this.ctrl.add(OFF.CC_AliveHostile));
        const inc = safeReadU32(this.ctrl.add(OFF.CC_InCombatFlag));
        const sm = safeReadU8(this.ctrl.add(OFF.CC_StateMarker));

        const prevAt = lastAlive.get(k);
        const prevAh = lastAliveHostile.get(k);
        const prevInc = lastInCombatFlag.get(k);
        const prevSm = lastStateMarker.get(k);

        const change = (prevAt !== at || prevAh !== ah ||
                        prevInc !== inc || prevSm !== sm);
        if (change) {
            log("[ctrl-state] ctrl=" + k.slice(-9),
                "alive(t/h)=" + (prevAt === undefined ? "?" : prevAt) +
                "→" + at +
                "/" + (prevAh === undefined ? "?" : prevAh) +
                "→" + ah,
                "inCombat=" + (prevInc === undefined ? "?" : prevInc) +
                "→" + inc,
                "state=0x" + (prevSm === undefined ? "?" :
                              prevSm.toString(16)) +
                "→0x" + sm.toString(16));
            lastAlive.set(k, at);
            lastAliveHostile.set(k, ah);
            lastInCombatFlag.set(k, inc);
            lastStateMarker.set(k, sm);
        }
    });

// ----------------------------------------------------------------------------
// HOOK: AddTarget sub_140E91D70 — log ghost targets, return code always
// ----------------------------------------------------------------------------

hook("AddTarget",
    base.add(RVA.CombatController_AddTarget),
    function (args) {
        const ctrl = args[0];
        const target = args[1];
        this.ctrl = ctrl;
        this.target = target;
        this.ghostInvolved = isGhost(target);
    },
    function (retval) {
        if (this.ghostInvolved || CFG.LOG_NON_GHOST) {
            log("[AddTarget] ctrl=" + hex(this.ctrl).slice(-9),
                "target=" + hex(this.target).slice(-9),
                "fid=" + fid(this.target),
                "→ " + retval.toInt32(),
                this.ghostInvolved ? "GHOST" : "");
        }
    });

// ----------------------------------------------------------------------------
// HOOK: AIProcess target handle change (via PostPickGate which fires on
// every "did engine pick a target this frame?" — we sample aiproc+0x6C here)
// ----------------------------------------------------------------------------

if (CFG.LOG_TARGET_TRANSITIONS) {
    hook("PostPickGate (target watch)",
        base.add(RVA.PostPickGate),
        function (args) {
            const aip = args[0];
            this.aip = aip;
            if (!aip || aip.isNull()) return;
            const k = aip.toString();
            const h = safeReadU32(aip.add(OFF.AIP_TargetHandle2));
            const prev = lastTargetHandle.get(k);
            if (prev !== h) {
                // Only log if NEW value is meaningful (ghost or transition)
                const wasGhost = ghostEngagedAips.has(k);
                const isGhostNow = (h !== 0 && h !== 0xFFFFFFFF);
                // Heuristic: ghost handle has 0x21AD?? pattern in this session
                // (preallocated by spawn). We just log every transition.
                log("[aip-target] aip=" + k.slice(-9),
                    "+0x6C: 0x" + (prev === undefined ? "?" :
                                   prev.toString(16)) +
                    " → 0x" + h.toString(16));
                lastTargetHandle.set(k, h);
                if (isGhostNow) ghostEngagedAips.add(k);
            }
        });
}

// ----------------------------------------------------------------------------
// HOOK: HostilityCore sub_140C8DFF0 — log only when:
//   - Ghost involved
//   - Result changes for same pair
// ----------------------------------------------------------------------------

if (CFG.LOG_HOSTILITY_GHOST) {
    hook("HostilityCore",
        base.add(RVA.HostilityCore),
        function (args) {
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = args[2].toInt32();
            this.ghostInvolved = isGhost(this.a1) || isGhost(this.a2);
        },
        function (retval) {
            if (!this.ghostInvolved && !CFG.LOG_NON_GHOST) return;
            const rank = retval.toInt32();
            const k = this.a1.toString() + "|" + this.a2.toString();
            const prev = lastHostilityResult.get(k);
            if (prev === rank) return; // no change
            lastHostilityResult.set(k, rank);
            log("[host] a1=" + hex(this.a1).slice(-9) +
                "(fid=" + fid(this.a1) + ")",
                "a2=" + hex(this.a2).slice(-9) +
                "(fid=" + fid(this.a2) + ")",
                "→ rank=" + rank +
                " (0=neutral 1=hostile 2=friend 3=ally)",
                this.ghostInvolved ? "GHOST" : "");
        });
}

// ----------------------------------------------------------------------------
// HOOK: EnterCombat sub_140CCF810
// ----------------------------------------------------------------------------

if (CFG.LOG_ENTER_COMBAT) {
    hook("EnterCombat",
        base.add(RVA.EnterCombat),
        function (args) {
            const actor = args[0];
            const target = args[1];
            if (isGhost(target) || isGhost(actor) || CFG.LOG_NON_GHOST) {
                log("[EnterCombat] actor=" + hex(actor).slice(-9) +
                    "(fid=" + fid(actor) + ")",
                    "target=" + hex(target).slice(-9) +
                    "(fid=" + fid(target) + ")",
                    isGhost(target) ? "→GHOST" : "");
            }
        },
        function (retval) {
            // Only log return when ghost-related
        });
}

// ----------------------------------------------------------------------------
// HOOK: DispatchAttackAction sub_140E6F830
// ----------------------------------------------------------------------------

if (CFG.LOG_FIRE_PIPELINE_GHOST) {
    hook("DispatchAttackAction",
        base.add(RVA.Actor_DispatchAttackAction),
        function (args) {
            const actor = args[0];
            // Check if this actor's aiproc targets ghost
            let isGhostTargeting = false;
            try {
                const aip = safeReadPointer(actor.add(OFF.AIProcess_combat));
                if (!aip.isNull()) {
                    const k = aip.toString();
                    if (ghostEngagedAips.has(k)) isGhostTargeting = true;
                }
            } catch (e) {}
            if (isGhostTargeting || CFG.LOG_NON_GHOST) {
                log("[DispAtk] actor=" + hex(actor).slice(-9) +
                    "(fid=" + fid(actor) + ")",
                    isGhostTargeting ? "→GHOST_TGT" : "");
            }
        });
}

// ----------------------------------------------------------------------------
// HOOK: WeaponFireHandler sub_140DFF6B0
// ----------------------------------------------------------------------------

if (CFG.LOG_FIRE_PIPELINE_GHOST || CFG.LOG_WFH_NONZERO_RC) {
    hook("WeaponFireHandler",
        base.add(RVA.WeaponFireHandler),
        function (args) {
            const actor = args[1]; // sig: (_, Actor*, anim_arg)
            this.actor = actor;
            let isGhostTargeting = false;
            try {
                const aip = safeReadPointer(actor.add(OFF.AIProcess_combat));
                if (!aip.isNull()) {
                    if (ghostEngagedAips.has(aip.toString())) {
                        isGhostTargeting = true;
                    }
                }
            } catch (e) {}
            this.ghostTgt = isGhostTargeting;
        },
        function (retval) {
            const rc = retval.toInt32() & 0xFF;
            if (this.ghostTgt && CFG.LOG_FIRE_PIPELINE_GHOST) {
                log("[WFH] actor=" + hex(this.actor).slice(-9) +
                    "(fid=" + fid(this.actor) + ")",
                    "rc=" + rc, "→GHOST_TGT");
            } else if (rc !== 1 && CFG.LOG_WFH_NONZERO_RC) {
                log("[WFH-suppress] actor=" + hex(this.actor).slice(-9) +
                    "(fid=" + fid(this.actor) + ")",
                    "rc=" + rc, "(non-1 return)");
            }
        });
}

// ----------------------------------------------------------------------------
// HOOK: Projectile::Launch sub_140479680 — log only for ghost-targeting actors
// ----------------------------------------------------------------------------

if (CFG.LOG_FIRE_PIPELINE_GHOST) {
    hook("Projectile_Launch",
        base.add(RVA.Projectile_Launch),
        function (args) {
            // Can't easily detect ghost involvement here; log all.
            // We rely on user filtering by timestamp.
            // Disabled by default — uncomment if needed.
        });
}

// ----------------------------------------------------------------------------
// HOOK: HitApplier sub_140CD2780
// ----------------------------------------------------------------------------

if (CFG.LOG_HITAPPLIER_GHOST) {
    hook("HitApplier",
        base.add(RVA.HitApplier),
        function (args) {
            const target = args[0];
            if (isGhost(target) || CFG.LOG_NON_GHOST) {
                log("[HitAppl] target=" + hex(target).slice(-9) +
                    "(fid=" + fid(target) + ")",
                    isGhost(target) ? "→GHOST" : "");
            }
        });
}

// ----------------------------------------------------------------------------
// HOOK: EventDispatch sub_140DEF780 — Build 43b crash site
// Log only when vt[3] is OUT of module range (dangerous, indicates UAF).
// ----------------------------------------------------------------------------

if (CFG.LOG_EVENT_DISPATCH_DANGEROUS) {
    hook("EventDispatch",
        base.add(RVA.EventDispatch),
        function (args) {
            const a2 = args[1];
            if (!a2 || a2.isNull()) return;
            let vt = ptr(0), vt3 = ptr(0), danger = false;
            try {
                vt = safeReadPointer(a2);
                vt3 = safeReadPointer(vt.add(0x18));
                danger = !inModule(vt3);
            } catch (e) { danger = true; }
            if (danger) {
                log("[EvtDisp-DANGER] a2=" + hex(a2).slice(-9),
                    "vt=" + hex(vt).slice(-9),
                    "vt[3]=" + hex(vt3),
                    "OUT-OF-MODULE — likely UAF crash if not guarded");
            }
        });
}

// ----------------------------------------------------------------------------
// Crash interception
// ----------------------------------------------------------------------------

if (CFG.CRASH_HANDLER) {
    Process.setExceptionHandler(function (exception) {
        const ctx = exception.context;
        log("==============================================");
        log("[!! EXCEPTION !!]", exception.type,
            "addr=" + hex(exception.address));
        try {
            const rva = ptr(exception.address).sub(base);
            log("[!!] in module @ RVA=" + hex(rva));
        } catch (e) {}
        if (exception.memory) {
            log("[!!] mem.addr=" + hex(exception.memory.address),
                "op=" + exception.memory.operation);
        }
        log("[!!] rip=" + hex(ctx.rip),
            "rsp=" + hex(ctx.rsp), "rbp=" + hex(ctx.rbp));
        log("[!!] rax=" + hex(ctx.rax),
            "rbx=" + hex(ctx.rbx), "rcx=" + hex(ctx.rcx),
            "rdx=" + hex(ctx.rdx));
        log("[!!] rsi=" + hex(ctx.rsi),
            "rdi=" + hex(ctx.rdi), "r8=" + hex(ctx.r8),
            "r9=" + hex(ctx.r9));
        log("[!!] r10=" + hex(ctx.r10), "r11=" + hex(ctx.r11),
            "r12=" + hex(ctx.r12), "r13=" + hex(ctx.r13),
            "r14=" + hex(ctx.r14), "r15=" + hex(ctx.r15));
        // Stack
        try {
            log("[!!] stack:");
            for (let i = 0; i < 16; ++i) {
                const v = safeReadPointer(ctx.rsp.add(i * 8));
                let tag = "";
                if (inModule(v)) {
                    try {
                        const offs = v.sub(base);
                        tag = " (RVA " + hex(offs) + ")";
                    } catch (e) {}
                }
                log("[!!]   [rsp+0x" + (i * 8).toString(16) + "]=" +
                    hex(v) + tag);
            }
        } catch (e) {}
        try {
            const bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress);
            log("[!!] backtrace:");
            for (let i = 0; i < bt.length && i < 12; ++i) {
                log("[!!]   #" + i + " " + bt[i]);
            }
        } catch (e) {}
        log("==============================================");
        return false; // let OS handle — game crashes normally
    });
}

log("=== trace v2 (quiet) ready ===");
log("verbosity: ghost-only + state transitions. Tweak CFG block to expand.");
log("Run your test scenario now.");
