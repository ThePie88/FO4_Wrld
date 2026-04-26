// M8P3.5 — Live bone-memory diff on the local player's skinned body.
// =====================================================================
//
// Goal: find which memory addresses the engine writes to during a real
// vanilla animation. Step 3 swap correctly rebound bones_fb to skel
// nodes, but mesh doesn't deform when we drive bone.local — meaning
// the engine's skin update reads from somewhere else we haven't yet
// identified.
//
// Plan: poll a known animating bone (player's body, walking/3P-cam)
// every 50ms, diff against previous snapshot, log which bytes change.
// Coalesce consecutive 4-byte changes into ranges for readability.
//
// Run plan:
//   1. Launch FO4 normally, get in-game
//   2. Press F or `tfc 1` to enter 3rd person — player body now visible
//      and animating with locomotion
//   3. Attach this script: python frida/attach_player_bone_diff.py
//   4. Wait for "[bone-watch] target acquired" log line
//   5. Walk forward for 5s, jump, walk back. Idle 5s.
//   6. Detach. Inspect frida/player_bone_diff.log
//
// Output:
//   [bone-watch] T+12345ms 4 diffs:
//     +0x70..+0x7F (16 bytes — world matrix row 0+1)
//     +0x80..+0x9F (32 bytes — world matrix rows 2+3)
//     +0xA0..+0xAB (12 bytes — world translation)
//
// Conclusion (expected): we'll see local stays static (no anim graph
// driving it) but world is recomputed from somewhere — hopefully not
// a fully-cached buffer the engine bypasses our writes.

console.log('[bone-watch] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[bone-watch] Fallout4.exe base = ' + base);

// ------------------------------------------------------------------
// RVAs / offsets (re/M8P3_skin_instance_dossier.txt + M1 dossier)
// ------------------------------------------------------------------
const PLAYER_SINGLETON_RVA      = 0x32D2260;
const ACTOR_ALT_TREE_OFF        = 0xF0;     // actor+0xF0 → container
const ALT_TREE_INNER_OFF        = 0x08;     // container+0x08 → root NiNode
const NIAV_NAME_OFF             = 0x10;
const NIAV_LOCAL_OFF            = 0x30;
const NIAV_WORLD_OFF            = 0x70;
const NIAV_REFCOUNT_OFF         = 0x08;
const NINODE_CHILDREN_PTR_OFF   = 0x128;
const NINODE_CHILDREN_CNT_OFF   = 0x132;
const BSGEOM_SKIN_INSTANCE_OFF  = 0x140;
const SKIN_BONES_FB_HEAD_OFF    = 0x10;
const SKIN_BONES_FB_COUNT_OFF   = 0x20;

const NINODE_VT_RVA      = 0x267C888;
const BSFADENODE_VT_RVA  = 0x28FA3E8;
const BSTRISHAPE_VT_RVA  = 0x267E948;
const BSSUBINDEX_VT_RVA  = 0x2697D40;
const BSDYNAMIC_VT_RVA_A = 0x267F758;
const BSDYNAMIC_VT_RVA_B = 0x267F948;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
function rvaOf(p) {
    if (p.isNull()) return 0;
    try { return p.sub(base).toInt32(); } catch (e) { return -1; }
}

function readBSFixedString(p) {
    if (p.isNull()) return '<null>';
    try {
        const pool = p.readPointer();
        if (pool.isNull()) return '<empty>';
        return pool.add(0x18).readUtf8String();
    } catch (e) { return '<av>'; }
}

function readNiName(obj) {
    if (obj.isNull()) return '<null>';
    try { return readBSFixedString(obj.add(NIAV_NAME_OFF)); }
    catch (e) { return '<av>'; }
}

function isNodeLike(vtRva) {
    return vtRva === NINODE_VT_RVA || vtRva === BSFADENODE_VT_RVA;
}

function isGeometry(vtRva) {
    return vtRva === BSTRISHAPE_VT_RVA
        || vtRva === BSSUBINDEX_VT_RVA
        || vtRva === BSDYNAMIC_VT_RVA_A
        || vtRva === BSDYNAMIC_VT_RVA_B;
}

function vtRva(obj) {
    if (obj.isNull()) return 0;
    try { return obj.readPointer().sub(base).toInt32(); } catch (e) { return -1; }
}

// ------------------------------------------------------------------
// Walk player's alt tree to find a skinned BSGeometry
// ------------------------------------------------------------------
function findFirstSkinnedGeometry(node, depth, log) {
    if (!node || node.isNull() || depth > 24) return null;
    const vt = vtRva(node);
    if (isGeometry(vt)) {
        try {
            const skin = node.add(BSGEOM_SKIN_INSTANCE_OFF).readPointer();
            if (!skin.isNull()) {
                return { geom: node, skin: skin };
            }
        } catch (e) {}
        return null;
    }
    if (!isNodeLike(vt)) return null;
    try {
        const cp = node.add(NINODE_CHILDREN_PTR_OFF).readPointer();
        const cc = node.add(NINODE_CHILDREN_CNT_OFF).readU16();
        if (log && depth <= 2) {
            console.log(`[bone-watch] ${'  '.repeat(depth)}node=${node} name='${readNiName(node)}' vt_rva=0x${vt.toString(16)} children=${cc}`);
        }
        for (let i = 0; i < cc && i < 64; i++) {
            let child;
            try { child = cp.add(i * 8).readPointer(); }
            catch (e) { continue; }
            const found = findFirstSkinnedGeometry(child, depth + 1, log);
            if (found) return found;
        }
    } catch (e) {}
    return null;
}

function findTarget(verbose) {
    const playerSlot = base.add(PLAYER_SINGLETON_RVA);
    const player = playerSlot.readPointer();
    if (player.isNull()) {
        console.log('[bone-watch] player singleton null — wait for in-game');
        return null;
    }
    console.log('[bone-watch] player @ ' + player);

    // alt tree: actor + 0xF0 → container, +0x08 → root
    let altContainer, altRoot;
    try { altContainer = player.add(ACTOR_ALT_TREE_OFF).readPointer(); }
    catch (e) { console.log('[bone-watch] AV reading actor+0xF0'); return null; }
    if (altContainer.isNull()) {
        console.log('[bone-watch] alt tree container null — actor not yet 3D-loaded');
        return null;
    }
    try { altRoot = altContainer.add(ALT_TREE_INNER_OFF).readPointer(); }
    catch (e) { console.log('[bone-watch] AV reading altContainer+0x08'); return null; }
    if (altRoot.isNull()) {
        console.log('[bone-watch] alt tree root null');
        return null;
    }
    console.log('[bone-watch] alt root=' + altRoot + ' name=' + readNiName(altRoot)
                + ' vt_rva=0x' + vtRva(altRoot).toString(16));

    const found = findFirstSkinnedGeometry(altRoot, 0, verbose);
    if (!found) {
        console.log('[bone-watch] no skinned geometry found in alt tree');
        return null;
    }
    console.log('[bone-watch] geom=' + found.geom + ' name=' + readNiName(found.geom));
    console.log('[bone-watch] skin=' + found.skin);

    // Read bones_fb head + count
    let bonesHead, bonesCount;
    try {
        bonesHead = found.skin.add(SKIN_BONES_FB_HEAD_OFF).readPointer();
        bonesCount = found.skin.add(SKIN_BONES_FB_COUNT_OFF).readU32();
    } catch (e) {
        console.log('[bone-watch] AV reading skin bones_fb');
        return null;
    }
    console.log('[bone-watch] bones_fb head=' + bonesHead + ' count=' + bonesCount);

    if (bonesCount === 0) return null;

    // Try bone[0]; we don't filter by name — any animating bone is fine.
    // Optionally search for a specific name. For diff capture, bone[0]
    // is fine (player body always has its bones animating).
    let targetBone = null;
    let targetIdx = 0;
    let targetName = '';
    for (let i = 0; i < bonesCount && i < 64; i++) {
        try {
            const b = bonesHead.add(i * 8).readPointer();
            if (b.isNull()) continue;
            const n = readNiName(b);
            if (i === 0) {
                targetBone = b;
                targetIdx = i;
                targetName = n;
            }
            console.log(`[bone-watch] bones_fb[${i}]=${b} name='${n}'`);
        } catch (e) {}
    }
    if (!targetBone) return null;
    console.log(`[bone-watch] target acquired: bones_fb[${targetIdx}]=${targetBone} name='${targetName}'`);
    return { skin: found.skin, bone: targetBone, name: targetName };
}

// ------------------------------------------------------------------
// Polling diff
// ------------------------------------------------------------------
const SNAP_SIZE = 0xC0;  // bytes of NiNode-ish state to capture
let lastSnap = null;
let target = null;
let lastFindAttemptT = 0;
const startT = Date.now();

function tick() {
    const t = Date.now() - startT;

    if (!target) {
        // Retry every 1 second to acquire (player not yet in 3D-loaded state)
        if (t - lastFindAttemptT < 1000) return;
        lastFindAttemptT = t;
        target = findTarget(false);
        if (!target) return;
        try { lastSnap = target.bone.readByteArray(SNAP_SIZE); }
        catch (e) { console.log('[bone-watch] AV initial snapshot'); target = null; return; }
        console.log('[bone-watch] initial snapshot taken, polling for diffs...');
        return;
    }

    let cur;
    try { cur = target.bone.readByteArray(SNAP_SIZE); }
    catch (e) { console.log('[bone-watch] AV reading snapshot — bone freed?'); target = null; return; }

    // Compare 4 bytes at a time
    const curU8 = new Uint8Array(cur);
    const prevU8 = new Uint8Array(lastSnap);
    const ranges = [];
    let curRangeStart = -1;
    let curRangeEnd = -1;
    for (let off = 0; off < SNAP_SIZE; off += 4) {
        let differ = false;
        for (let b = 0; b < 4; b++) {
            if (curU8[off + b] !== prevU8[off + b]) { differ = true; break; }
        }
        if (differ) {
            if (curRangeStart < 0) { curRangeStart = off; curRangeEnd = off + 4; }
            else if (off === curRangeEnd) { curRangeEnd = off + 4; }
            else { ranges.push([curRangeStart, curRangeEnd]); curRangeStart = off; curRangeEnd = off + 4; }
        }
    }
    if (curRangeStart >= 0) ranges.push([curRangeStart, curRangeEnd]);

    if (ranges.length > 0) {
        const fmt = ranges.map(r => `+0x${r[0].toString(16)}..+0x${(r[1]-1).toString(16)} (${r[1]-r[0]}B)`).join(', ');
        console.log(`[bone-watch] T+${t}ms bone='${target.name}' diffs: ${fmt}`);
    }

    lastSnap = cur;
}

setInterval(tick, 50);
console.log('[bone-watch] poll loop armed @ 50ms');
