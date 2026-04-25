// M7 — bgsm load + bone resolver + apply_materials tree walker tracer.
// =====================================================================
//
// Goal: figure out WHY our standalone-loaded ghost body has placeholder
// materials (vt 0x290A190) instead of resolved (vt 0x290B640), and WHY
// its skin instance is bound to "_skin" stubs instead of real skel bones.
//
// Run plan:
//   1. User launches Side A FO4 normally + waits to in-game state.
//   2. We attach Frida to running A process.
//   3. Capture for 10-30s while user walks near a vanilla NPC (Codsworth
//      at Sanctuary or similar). Log shows the SUCCESSFUL pattern of
//      bgsm loads + bone resolves for vanilla.
//   4. Trigger ghost spawn (T+~40s after boot) — log shows OUR pattern.
//   5. Diff vanilla vs ghost → identify what we're missing.
//
// Hooks installed:
//   - sub_1417A9620  bgsm loader (path, &outMat, forceReload) → u32 rc
//   - sub_140255BA0  apply_materials walker (root, ...) entry/exit
//   - sub_140256070  per-geometry apply (ctx, geom) entry/exit
//   - sub_1403F85E0  bone resolver with _skin fallback (parent, name) → bone*
//
// Output is line-prefixed with [bgsm], [walker], [pergeom], [boneres]
// so we can grep by category.

console.log('[m7-trace] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[m7-trace] Fallout4.exe base = ' + base);

// ------------------------------------------------------------------
// RVAs (from re/_bgsm_loader.log + re/_bone_drive_correct.log)
// ------------------------------------------------------------------
const RVA_BGSM_LOAD       = 0x17A9620;  // bgsm file loader
const RVA_APPLY_WALKER    = 0x255BA0;   // apply_materials tree walker
const RVA_PER_GEOM_APPLY  = 0x256070;   // per-geometry apply
const RVA_BONE_RESOLVE    = 0x3F85E0;   // FindBoneByName w/ _skin fallback
const RVA_NIF_LOADER      = 0x17B3E90;  // sub_1417B3E90 — what WE call

// NiObjectNET name offset (BSFixedString at +0x10 → pool ptr → c_str at +0x18)
const OFF_NAME = 0x10;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
function readBSFixedString(p) {
    if (p.isNull()) return '<null>';
    try {
        const poolEntry = p.readPointer();
        if (poolEntry.isNull()) return '<null>';
        // c_str typically at poolEntry + 0x18 (header before string)
        return poolEntry.add(0x18).readUtf8String();
    } catch (e) {
        // fallback: try direct cstring
        try { return p.readPointer().readUtf8String(); }
        catch (e2) { return '<read-fail>'; }
    }
}

function readNiName(obj) {
    if (obj.isNull()) return '<null>';
    try {
        return readBSFixedString(obj.add(OFF_NAME));
    } catch (e) {
        return '<AV>';
    }
}

function readVtableRVA(obj) {
    if (obj.isNull()) return '0';
    try {
        const vt = obj.readPointer();
        return '0x' + vt.sub(base).toString(16);
    } catch (e) {
        return '<AV>';
    }
}

let g_call_id = 0;

// ------------------------------------------------------------------
// Hook: bgsm loader  sub_1417A9620
// Signature: u32 __fastcall(const char* path, BSShaderMaterial** outMat,
//                           char forceReload)
// ------------------------------------------------------------------
const bgsmLoad = base.add(RVA_BGSM_LOAD);
Interceptor.attach(bgsmLoad, {
    onEnter(args) {
        this.callId = ++g_call_id;
        this.path = '<unread>';
        try { this.path = args[0].readUtf8String(); } catch (e) {}
        this.outMatPtr = args[1];
        this.force = args[2].toInt32() & 0xFF;
        console.log(`[bgsm] #${this.callId} ENTER path='${this.path}' force=${this.force}`);
    },
    onLeave(retval) {
        const rc = retval.toInt32();
        let outMatStr = '<null>';
        try {
            const mat = this.outMatPtr.readPointer();
            if (!mat.isNull()) {
                outMatStr = `${mat} (vt=${readVtableRVA(mat)})`;
            }
        } catch (e) {}
        console.log(`[bgsm] #${this.callId} LEAVE rc=${rc} outMat=${outMatStr}`);
    }
});
console.log('[m7-trace] hooked bgsm_load @ ' + bgsmLoad);

// ------------------------------------------------------------------
// Hook: apply_materials walker  sub_140255BA0
// Signature: void __fastcall(NiAVObject* root, ...)
// ------------------------------------------------------------------
const applyWalker = base.add(RVA_APPLY_WALKER);
Interceptor.attach(applyWalker, {
    onEnter(args) {
        this.callId = ++g_call_id;
        const root = args[0];
        const name = readNiName(root);
        const vtRva = readVtableRVA(root);
        console.log(`[walker] #${this.callId} ENTER root=${root} vt=${vtRva} name='${name}'`);
    },
    onLeave(retval) {
        console.log(`[walker] #${this.callId} LEAVE`);
    }
});
console.log('[m7-trace] hooked apply_walker @ ' + applyWalker);

// ------------------------------------------------------------------
// Hook: per-geometry apply  sub_140256070
// Signature: void __fastcall(void* ctx, BSGeometry* geom)
// ------------------------------------------------------------------
const perGeomApply = base.add(RVA_PER_GEOM_APPLY);
Interceptor.attach(perGeomApply, {
    onEnter(args) {
        this.callId = ++g_call_id;
        const geom = args[1];
        const name = readNiName(geom);
        const vtRva = readVtableRVA(geom);
        // Read shader+0x10 = BSFixedString containing bgsm path
        let bgsmPath = '<no-shader>';
        try {
            const shader = geom.add(0x138).readPointer();
            if (!shader.isNull()) {
                bgsmPath = readBSFixedString(shader.add(0x10));
            }
        } catch (e) {}
        console.log(`[pergeom] #${this.callId} ENTER geom=${geom} vt=${vtRva} name='${name}' bgsm='${bgsmPath}'`);
    },
    onLeave(retval) {
        // Read material vtable AFTER apply
        const geom = this.geom;
        let postMat = '<unread>';
        // We didn't save geom. Skip. Just log leave.
        console.log(`[pergeom] #${this.callId} LEAVE`);
    }
});
console.log('[m7-trace] hooked per_geom_apply @ ' + perGeomApply);

// ------------------------------------------------------------------
// Hook: bone resolver  sub_1403F85E0
// Signature: NiNode* __fastcall(NiNode* parent, const char* name)
// (Per agent dossier: tries name first, then name + "_skin" fallback.)
// ------------------------------------------------------------------
const boneResolve = base.add(RVA_BONE_RESOLVE);
Interceptor.attach(boneResolve, {
    onEnter(args) {
        this.callId = ++g_call_id;
        this.parent = args[0];
        let parentName = readNiName(this.parent);
        let nameArg = '<unread>';
        try { nameArg = args[1].readUtf8String(); } catch (e) {}
        this.searchName = nameArg;
        // Don't log every call — too noisy. Save state for onLeave.
    },
    onLeave(retval) {
        // Only log if return value is non-null — the interesting cases.
        if (retval.isNull()) return;
        const foundName = readNiName(retval);
        const usedFallback = (foundName === this.searchName + '_skin');
        const tag = usedFallback ? '_SKIN_FALLBACK' : 'EXACT';
        console.log(`[boneres] #${this.callId} parent='${readNiName(this.parent)}' search='${this.searchName}' → found='${foundName}' [${tag}]`);
    }
});
console.log('[m7-trace] hooked bone_resolve @ ' + boneResolve);

// ------------------------------------------------------------------
// Hook: NIF loader  sub_1417B3E90  (THE one we call from fw_native)
// Signature: u32 __fastcall(const char* path, void** out_node, void* opts)
// ------------------------------------------------------------------
const nifLoader = base.add(RVA_NIF_LOADER);
Interceptor.attach(nifLoader, {
    onEnter(args) {
        this.callId = ++g_call_id;
        this.path = '<unread>';
        try { this.path = args[0].readUtf8String(); } catch (e) {}
        this.outPtr = args[1];
        // opts is at args[2], byte+8 = flags
        let flags = 0;
        try { flags = args[2].add(8).readU8(); } catch (e) {}
        console.log(`[nifload] #${this.callId} ENTER path='${this.path}' flags=0x${flags.toString(16)}`);
    },
    onLeave(retval) {
        const rc = retval.toInt32();
        let outNode = '<null>';
        let outVtRva = '0';
        let outName = '<null>';
        let childCount = 0;
        try {
            const node = this.outPtr.readPointer();
            if (!node.isNull()) {
                outNode = node.toString();
                outVtRva = readVtableRVA(node);
                outName = readNiName(node);
                childCount = node.add(0x132).readU16();
            }
        } catch (e) {}
        console.log(`[nifload] #${this.callId} LEAVE rc=${rc} out=${outNode} vt=${outVtRva} name='${outName}' children=${childCount}`);
    }
});
console.log('[m7-trace] hooked nif_loader @ ' + nifLoader);

console.log('[m7-trace] all hooks installed. Waiting for game activity...');
