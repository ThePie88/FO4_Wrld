// M8 Phase 1.3 — Load3D callees live-trace.
// =====================================================================
//
// Goal: capture EVERY function called by PlayerCharacter::Load3D during
// a vanilla load (loadgame or fast-travel or coc QASmoke) so we can
// build the call sequence we need to replicate for ghost players.
//
// Run plan:
//   1. Build/inject fw_native as usual; launch FO4 to main menu
//   2. Attach this Frida script: python frida/attach_load3d_trace.py
//   3. In game: load a save (or `coc QASmoke`) — triggers player Load3D
//   4. Walk around / open inventory — triggers possible re-loads
//   5. Detach. Inspect frida/load3d_trace.log
//
// Hook strategy (two-tier):
//   TIER 1 (always on): Interceptor on Load3D + known anchors
//     - PlayerCharacter::Load3D entry/exit + args/retval
//     - sub_1417B3E90 (NIF loader)        — what loads .nif files
//     - sub_1417A9620 (bgsm loader)        — what loads materials
//     - sub_140255BA0 (apply_materials)    — material walker
//     - sub_1403F85E0 (bone resolver)      — bone-by-name with _skin fallback
//
//   TIER 2 (on demand, expensive): Stalker on Load3D's thread for the
//     duration of the Load3D call — logs every CALL instruction with target
//     RVA. Enables building the FULL direct-callee list. Slow (~10x), but
//     we only run it once per session to capture the call graph.
//
// Output lines tagged [load3d] [nif] [bgsm] [walker] [bone] [stalker]
// for `grep -E '^\[load3d\]'` style filtering post-capture.

console.log('[load3d-trace] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[load3d-trace] Fallout4.exe base = ' + base);

// ------------------------------------------------------------------
// RVAs — KNOWN
// ------------------------------------------------------------------
const RVA_NIF_LOADER      = 0x17B3E90;  // sub_1417B3E90
const RVA_BGSM_LOAD       = 0x17A9620;  // sub_1417A9620
const RVA_APPLY_WALKER    = 0x255BA0;   // sub_140255BA0
const RVA_BONE_RESOLVE    = 0x3F85E0;   // sub_1403F85E0

// ------------------------------------------------------------------
// RVAs — TO FILL FROM re/M8P1_load3d_dossier.txt
// ------------------------------------------------------------------
// PlayerCharacter::Load3D — vt[134] @ PC vt 0x142564838  (M8P1 dossier)
const RVA_LOAD3D       = 0xD5B250;   // sub_140D5B250  size 0x77A
const RVA_ACTOR_LOAD3D = 0xC584F0;   // sub_140C584F0  size 0x332
const RVA_REFR_LOAD3D  = 0x50AC10;   // sub_14050AC10  size 0x1009 (4KB heavy lifter)

// Anim graph + scene-attach helpers from PC::Load3D body
const RVA_BUILD_NIF_PATH = 0xD623D0;   // sub_140D623D0 race+sex → BSFixedString
const RVA_SCENE_ATTACH   = 0xC9AAC0;   // sub_140C9AAC0 attach to cell scene graph
const RVA_ANIM_VAR_PUSH  = 0xD9AF10;   // sub_140D9AF10 push 4 anim vars from a1+26
const RVA_ANIM_DIRTY_ALL = 0x1895000;  // sub_141895000 OR-mark all anim vars dirty
const RVA_GET_GRAPH_MGR  = 0x187FF20;  // sub_14187FF20 get embedded anim graph mgr

// ------------------------------------------------------------------
// Toggles
// ------------------------------------------------------------------
const ENABLE_STALKER = false;   // set true when we want full call graph
const STALKER_BUDGET_MS = 200;  // auto-stop stalker after N ms inside Load3D

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
function rva(p) {
    if (p.isNull()) return '0';
    try { return '0x' + p.sub(base).toString(16); }
    catch (e) { return '<AV>'; }
}

function readBSFixedString(p) {
    if (p.isNull()) return '<null>';
    try {
        const poolEntry = p.readPointer();
        if (poolEntry.isNull()) return '<null>';
        return poolEntry.add(0x18).readUtf8String();
    } catch (e) {
        try { return p.readPointer().readUtf8String(); }
        catch (e2) { return '<read-fail>'; }
    }
}

let g_call_id = 0;
let g_in_load3d = 0;  // depth counter — re-entrancy possible (skeleton triggers more loads)

// ------------------------------------------------------------------
// Player-singleton resolution — tag PC vs NPC in trace
// PLAYER_SINGLETON_RVA = 0x32D2260 (TESPlayerCharacter** double-indirect)
// ------------------------------------------------------------------
const PLAYER_SINGLETON_RVA = 0x32D2260;
function readPlayerActor() {
    try {
        const slot = base.add(PLAYER_SINGLETON_RVA);
        const pc = slot.readPointer();
        return pc;
    } catch (e) { return ptr(0); }
}
const g_player_actor_initial = readPlayerActor();
console.log(`[load3d-trace] player singleton @ ${base.add(PLAYER_SINGLETON_RVA)} -> ${g_player_actor_initial}`);

function tagActor(actor) {
    if (actor.isNull()) return 'NULL';
    const cur = readPlayerActor();
    if (!cur.isNull() && actor.equals(cur)) return 'PLAYER';
    return 'NPC';
}

// ------------------------------------------------------------------
// Load3D — the centerpiece
// ------------------------------------------------------------------
if (RVA_LOAD3D !== 0) {
    const load3dAddr = base.add(RVA_LOAD3D);
    Interceptor.attach(load3dAddr, {
        onEnter(args) {
            this.callId = ++g_call_id;
            this.actor = args[0];
            this.flag = args[1].toInt32();  // typical: bool backgroundLoaded
            g_in_load3d++;
            console.log(`[load3d] #${this.callId} ENTER fn=PC::Load3D actor=${this.actor} tag=${tagActor(this.actor)} flag=${this.flag} depth=${g_in_load3d}`);

            // Snapshot key actor offsets BEFORE Load3D modifies them
            try {
                const loaded3D = this.actor.add(0xB78).readPointer();
                console.log(`[load3d] #${this.callId}  pre  actor+0xB78 (loaded3D) = ${loaded3D} rva=${rva(loaded3D)}`);
            } catch (e) {}
            try {
                const altTreeContainer = this.actor.add(0xF0).readPointer();
                if (!altTreeContainer.isNull()) {
                    const altTreeRoot = altTreeContainer.add(0x08).readPointer();
                    console.log(`[load3d] #${this.callId}  pre  actor+0xF0->+0x08 (alt scene tree) = ${altTreeRoot}`);
                }
            } catch (e) {}

            if (ENABLE_STALKER) {
                Stalker.follow(Process.getCurrentThreadId(), {
                    events: { call: true, ret: false, exec: false, block: false, compile: false },
                    onReceive(events) {
                        const parsed = Stalker.parse(events);
                        for (const ev of parsed) {
                            // ev = ['call', from, to, depth]
                            console.log(`[stalker] from=${rva(ptr(ev[1]))} to=${rva(ptr(ev[2]))} depth=${ev[3]}`);
                        }
                    }
                });
                this.stalkerStarted = true;
                console.log(`[load3d] #${this.callId} stalker started (budget ${STALKER_BUDGET_MS}ms)`);
                this.stalkerStartMs = Date.now();
            }
        },
        onLeave(retval) {
            if (this.stalkerStarted) {
                Stalker.unfollow(Process.getCurrentThreadId());
                Stalker.flush();
                console.log(`[load3d] #${this.callId} stalker stopped (${Date.now() - this.stalkerStartMs}ms)`);
            }
            // Snapshot after
            try {
                const loaded3D = this.actor.add(0xB78).readPointer();
                console.log(`[load3d] #${this.callId}  post actor+0xB78 (loaded3D) = ${loaded3D} rva=${rva(loaded3D)}`);
            } catch (e) {}
            g_in_load3d--;
            console.log(`[load3d] #${this.callId} LEAVE retval=${retval} depth=${g_in_load3d}`);
        }
    });
    console.log('[load3d-trace] hooked PC::Load3D @ ' + load3dAddr);
} else {
    console.log('[load3d-trace] !! RVA_LOAD3D=0 — fill from dossier and re-attach');
}

// ------------------------------------------------------------------
// Actor::Load3D — fires for all NPCs too (vanilla baseline)
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_ACTOR_LOAD3D), {
    onEnter(args) {
        this.callId = ++g_call_id;
        this.actor = args[0];
        g_in_load3d++;
        console.log(`[load3d] #${this.callId} ENTER fn=Actor::Load3D actor=${this.actor} tag=${tagActor(this.actor)} depth=${g_in_load3d}`);
    },
    onLeave(retval) {
        g_in_load3d--;
        console.log(`[load3d] #${this.callId} LEAVE fn=Actor::Load3D retval=${retval} depth=${g_in_load3d}`);
    }
});
console.log('[load3d-trace] hooked Actor::Load3D @ ' + base.add(RVA_ACTOR_LOAD3D));

// ------------------------------------------------------------------
// REFR::Load3D — biggest body, where apply_materials fires
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_REFR_LOAD3D), {
    onEnter(args) {
        this.callId = ++g_call_id;
        this.actor = args[0];
        g_in_load3d++;
        console.log(`[load3d] #${this.callId} ENTER fn=REFR::Load3D actor=${this.actor} tag=${tagActor(this.actor)} depth=${g_in_load3d}`);
    },
    onLeave(retval) {
        g_in_load3d--;
        console.log(`[load3d] #${this.callId} LEAVE fn=REFR::Load3D retval=${retval} depth=${g_in_load3d}`);
    }
});
console.log('[load3d-trace] hooked REFR::Load3D @ ' + base.add(RVA_REFR_LOAD3D));

// ------------------------------------------------------------------
// sub_140D623D0 — NIF path builder (race + sex → BSFixedString)
// Signature: bool __fastcall(Actor* this, BSFixedString* out)
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_BUILD_NIF_PATH), {
    onEnter(args) {
        if (g_in_load3d === 0) return;
        this.callId = ++g_call_id;
        this.outPath = args[1];
        this.actor = args[0];
        console.log(`[pathfn] #${this.callId} ENTER actor=${this.actor} tag=${tagActor(this.actor)}`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        let path = '<unread>';
        try { path = readBSFixedString(this.outPath); } catch (e) {}
        console.log(`[pathfn] #${this.callId} LEAVE rc=${retval.toInt32()} path='${path}'`);
    }
});

// ------------------------------------------------------------------
// sub_140C9AAC0 — scene-graph attach (cell parent set + broadcast)
// Signature: void __fastcall(Actor*, BSFadeNode* loaded3D, void* out)
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_SCENE_ATTACH), {
    onEnter(args) {
        if (g_in_load3d === 0) return;
        this.callId = ++g_call_id;
        const actor = args[0];
        const loaded3D = args[1];
        let loadedVt = '<AV>';
        try { loadedVt = rva(loaded3D.readPointer()); } catch (e) {}
        console.log(`[attach] #${this.callId} ENTER actor=${actor} tag=${tagActor(actor)} loaded3D=${loaded3D} vt=${loadedVt}`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        console.log(`[attach] #${this.callId} LEAVE`);
    }
});

// ------------------------------------------------------------------
// sub_140D9AF10 — push 4 anim variables (vec3 from this+0xD0)
// Signature: void __fastcall(BSFadeNode*, ?, vec3*)
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_ANIM_VAR_PUSH), {
    onEnter(args) {
        if (g_in_load3d === 0) return;
        this.callId = ++g_call_id;
        const vec3 = args[2];
        let xyz = '?';
        try {
            const x = vec3.readFloat();
            const y = vec3.add(4).readFloat();
            const z = vec3.add(8).readFloat();
            xyz = `(${x.toFixed(2)}, ${y.toFixed(2)}, ${z.toFixed(2)})`;
        } catch (e) {}
        console.log(`[animvar] #${this.callId} ENTER target=${args[0]} arg2=${args[1]} vec3=${xyz}`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        console.log(`[animvar] #${this.callId} LEAVE`);
    }
});

// ------------------------------------------------------------------
// sub_141895000 — OR-mark all anim vars dirty
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_ANIM_DIRTY_ALL), {
    onEnter(args) {
        if (g_in_load3d === 0) return;
        this.callId = ++g_call_id;
        console.log(`[animdirty] #${this.callId} ENTER mgr=${args[0]}`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        console.log(`[animdirty] #${this.callId} LEAVE`);
    }
});

// ------------------------------------------------------------------
// NIF loader  sub_1417B3E90  (path, **out, opts)
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_NIF_LOADER), {
    onEnter(args) {
        if (g_in_load3d === 0) return;  // only log when Load3D is on the stack
        this.callId = ++g_call_id;
        this.path = '<unread>';
        try { this.path = args[0].readUtf8String(); } catch (e) {}
        this.outPtr = args[1];
        let flags = 0;
        try { flags = args[2].add(8).readU8(); } catch (e) {}
        console.log(`[nif] #${this.callId} ENTER path='${this.path}' flags=0x${flags.toString(16)}`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        const rc = retval.toInt32();
        let outNode = '<null>';
        try {
            const node = this.outPtr.readPointer();
            if (!node.isNull()) outNode = `${node} vt=${rva(node.readPointer())}`;
        } catch (e) {}
        console.log(`[nif] #${this.callId} LEAVE rc=${rc} out=${outNode}`);
    }
});

// ------------------------------------------------------------------
// bgsm loader
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_BGSM_LOAD), {
    onEnter(args) {
        if (g_in_load3d === 0) return;
        this.callId = ++g_call_id;
        this.path = '<unread>';
        try { this.path = args[0].readUtf8String(); } catch (e) {}
        console.log(`[bgsm] #${this.callId} ENTER path='${this.path}'`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        console.log(`[bgsm] #${this.callId} LEAVE rc=${retval.toInt32()}`);
    }
});

// ------------------------------------------------------------------
// apply_materials walker
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_APPLY_WALKER), {
    onEnter(args) {
        if (g_in_load3d === 0) return;
        this.callId = ++g_call_id;
        const root = args[0];
        console.log(`[walker] #${this.callId} ENTER root=${root} vt=${rva(root.readPointer())}`);
    },
    onLeave(retval) {
        if (this.callId === undefined) return;
        console.log(`[walker] #${this.callId} LEAVE`);
    }
});

// ------------------------------------------------------------------
// bone resolver — UNGATED. Dossier says it is NOT called inside Load3D.
// We want to capture WHEN it fires (timeline relative to Load3D enter/exit)
// to nail down whether it runs in AnimGraph init or first Update tick.
// Log only _skin fallbacks (the M7 bug source) to keep noise down.
// Tag with current load3d depth so we know if we're inside a Load3D or not.
// ------------------------------------------------------------------
Interceptor.attach(base.add(RVA_BONE_RESOLVE), {
    onEnter(args) {
        this.parent = args[0];
        this.searchName = '<unread>';
        try { this.searchName = args[1].readUtf8String(); } catch (e) {}
        this.depthAtEnter = g_in_load3d;
    },
    onLeave(retval) {
        if (this.searchName === undefined) return;
        if (retval.isNull()) return;
        let foundName = '<unread>';
        try { foundName = readBSFixedString(retval.add(0x10)); } catch (e) {}
        const fallback = (foundName === this.searchName + '_skin');
        if (fallback) {
            console.log(`[bone] _SKIN_FALLBACK search='${this.searchName}' → found='${foundName}' load3d_depth=${this.depthAtEnter}`);
        }
    }
});

console.log('[load3d-trace] all hooks installed:');
console.log('  PC::Load3D, Actor::Load3D, REFR::Load3D');
console.log('  pathfn (NIF path builder), attach (scene graph attach)');
console.log('  animvar (vec3 push), animdirty (var-mark dirty)');
console.log('  nif, bgsm, walker (gated by g_in_load3d > 0)');
console.log('  bone (ungated, _skin fallback only, tagged with load3d_depth)');
console.log('Triggering: loadgame or coc QASmoke. Walk + placeatme some settlers for NPC baseline.');
