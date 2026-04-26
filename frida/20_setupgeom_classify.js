// M8P3.10 — SetupGeometry args classifier.
// =====================================================================
// Resolve player FIRST. Then hook sub_1421FDA30. For each of first N
// calls, classify *a1+0x10 and *a1+0x18 by reading their vtables.
// Report immediately when player skin/geom matched.

console.log('[classify] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;

const TARGET_RVA = 0x21FDA30;
const PLAYER_SINGLETON_RVA = 0x32D2260;
const ALT_TREE_OFF         = 0xF0;
const ALT_TREE_INNER_OFF   = 0x08;
const NINODE_CHILDREN_PTR  = 0x128;
const NINODE_CHILDREN_CNT  = 0x132;
const BSGEOM_SKIN_OFF      = 0x140;
const NINODE_VT       = 0x267C888;
const BSFADENODE_VT   = 0x28FA3E8;
const BSTRISHAPE_VT   = 0x267E948;
const BSSUBINDEX_VT   = 0x2697D40;
const BSDYN_VT_A      = 0x267F758;
const BSDYN_VT_B      = 0x267F948;
const BSSKIN_INST_VT  = 0x267E5C8;

function vtRva(p) {
    try {
        if (!p || p.isNull()) return 0;
        return p.readPointer().sub(base).toInt32();
    } catch(e) { return -1; }
}

function classify(p) {
    try {
        if (!p || p.isNull()) return 'null';
        const vt = vtRva(p);
        if (vt === BSSKIN_INST_VT) return 'BSSkinInst';
        if (vt === BSTRISHAPE_VT) return 'BSTriShape';
        if (vt === BSSUBINDEX_VT) return 'BSSubIndex';
        if (vt === BSDYN_VT_A || vt === BSDYN_VT_B) return 'BSDynTri';
        if (vt === NINODE_VT) return 'NiNode';
        if (vt === BSFADENODE_VT) return 'BSFadeNode';
        // Look up vt in known list
        if (vt > 0 && vt < 0x10000000) return 'vt_rva=0x' + vt.toString(16);
        return 'no-vt';
    } catch(e) { return 'err'; }
}

function isGeomVt(vt) {
    return vt === BSTRISHAPE_VT || vt === BSSUBINDEX_VT
        || vt === BSDYN_VT_A || vt === BSDYN_VT_B;
}
function isNodeVt(vt) {
    return vt === NINODE_VT || vt === BSFADENODE_VT;
}

function findFirstSkinned(node, depth) {
    if (!node || node.isNull() || depth > 24) return null;
    const vt = vtRva(node);
    if (isGeomVt(vt)) {
        try {
            const skin = node.add(BSGEOM_SKIN_OFF).readPointer();
            if (!skin.isNull()) return { geom: node, skin: skin };
        } catch(e) {}
        return null;
    }
    if (!isNodeVt(vt)) return null;
    try {
        const cp = node.add(NINODE_CHILDREN_PTR).readPointer();
        const cc = node.add(NINODE_CHILDREN_CNT).readU16();
        for (let i = 0; i < cc && i < 64; i++) {
            const c = cp.add(i*8).readPointer();
            const r = findFirstSkinned(c, depth+1);
            if (r) return r;
        }
    } catch(e) {}
    return null;
}

function tryResolvePlayer() {
    try {
        const player = base.add(PLAYER_SINGLETON_RVA).readPointer();
        if (player.isNull()) return null;
        const c = player.add(ALT_TREE_OFF).readPointer();
        if (c.isNull()) return null;
        const alt = c.add(ALT_TREE_INNER_OFF).readPointer();
        if (alt.isNull()) return null;
        return findFirstSkinned(alt, 0);
    } catch(e) { return null; }
}

// Try resolving player NOW (during script load, may fail if too early)
let playerSkin = null;
let playerGeom = null;
const t0 = tryResolvePlayer();
if (t0) {
    playerSkin = t0.skin;
    playerGeom = t0.geom;
    console.log('[classify] player resolved EARLY: skin=' + playerSkin + ' geom=' + playerGeom);
} else {
    console.log('[classify] player NOT YET resolvable (will retry per-tick)');
}

let totalCalls = 0;
let dumpCount = 0;
const MAX_DUMPS = 50;
let playerHits = 0;

// Type histogram for +0x10 and +0x18 across all calls
const histA = {};
const histB = {};

const TARGET_ADDR = base.add(TARGET_RVA);
console.log('[classify] hooking ' + TARGET_ADDR);

Interceptor.attach(TARGET_ADDR, {
    onEnter: function(args) {
        totalCalls++;
        const a1 = args[1];
        if (!a1 || a1.isNull()) return;

        let A, B;
        try {
            A = a1.add(0x10).readPointer();
            B = a1.add(0x18).readPointer();
        } catch(e) { return; }

        const aClass = classify(A);
        const bClass = classify(B);
        histA[aClass] = (histA[aClass] || 0) + 1;
        histB[bClass] = (histB[bClass] || 0) + 1;

        // Player match check
        let isPlayer = false;
        if (playerSkin && playerGeom) {
            if (A.equals(playerSkin) || A.equals(playerGeom)
             || B.equals(playerSkin) || B.equals(playerGeom)) {
                isPlayer = true;
                playerHits++;
            }
        }

        if (dumpCount < MAX_DUMPS && (isPlayer || dumpCount < 8)) {
            dumpCount++;
            const flag = isPlayer ? ' [PLAYER MATCH]' : '';
            console.log('[classify] call#' + totalCalls + ' a1=' + a1
                        + ' +0x10=' + A + ' (' + aClass + ')'
                        + ' +0x18=' + B + ' (' + bClass + ')' + flag);

            // Special: if +0x10 is a BSGeometry, walk to skin instance
            if (aClass === 'BSTriShape' || aClass === 'BSSubIndex' || aClass === 'BSDynTri') {
                try {
                    const skinInst = A.add(BSGEOM_SKIN_OFF).readPointer();
                    console.log('  ' + aClass + '@A.+0x140 (skinInst) = ' + skinInst);
                } catch(e) {}
            }
            if (bClass === 'BSTriShape' || bClass === 'BSSubIndex' || bClass === 'BSDynTri') {
                try {
                    const skinInst = B.add(BSGEOM_SKIN_OFF).readPointer();
                    console.log('  ' + bClass + '@B.+0x140 (skinInst) = ' + skinInst);
                } catch(e) {}
            }
        }
    }
});

console.log('[classify] hook installed');

setInterval(() => {
    if (!playerSkin) {
        const t = tryResolvePlayer();
        if (t) {
            playerSkin = t.skin;
            playerGeom = t.geom;
            console.log('[classify] player resolved: skin=' + playerSkin + ' geom=' + playerGeom);
        }
    }
    console.log('[classify] tick total=' + totalCalls + ' dumps=' + dumpCount
                + ' player_hits=' + playerHits);
    console.log('  histogram +0x10 (top 10):');
    Object.entries(histA).sort((a,b) => b[1]-a[1]).slice(0, 10).forEach(([k,v]) => {
        console.log('    ' + k + ': ' + v);
    });
    console.log('  histogram +0x18 (top 10):');
    Object.entries(histB).sort((a,b) => b[1]-a[1]).slice(0, 10).forEach(([k,v]) => {
        console.log('    ' + k + ': ' + v);
    });
}, 3000);

console.log('[classify] sampler armed @ 3s');
