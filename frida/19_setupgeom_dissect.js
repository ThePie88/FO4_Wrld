// M8P3.9 — Dissect BSDFPrePassShader::SetupGeometry (sub_1421FDA30) args.
// =====================================================================
//
// Hook the per-geometry skin upload worker. For first N calls, dump 256
// bytes of args[1] (the render-entry struct) to identify its layout.
// Then for subsequent calls, search args[1] for a pointer to our
// player's BSGeometry or BSSkin::Instance.

console.log('[dissect] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[dissect] Fallout4.exe base = ' + base);

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

function isGeomVt(vt) {
    return vt === BSTRISHAPE_VT || vt === BSSUBINDEX_VT
        || vt === BSDYN_VT_A || vt === BSDYN_VT_B;
}
function isNodeVt(vt) {
    return vt === NINODE_VT || vt === BSFADENODE_VT;
}

function findFirstSkinned(node, depth) {
    if (!node || node.isNull() || depth > 24) return null;
    let vt;
    try { vt = node.readPointer().sub(base).toInt32(); } catch(e) { return null; }
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

let playerSkin = null;
let playerGeom = null;

function tryResolvePlayer() {
    try {
        const player = base.add(PLAYER_SINGLETON_RVA).readPointer();
        if (player.isNull()) return false;
        const c = player.add(ALT_TREE_OFF).readPointer();
        if (c.isNull()) return false;
        const alt = c.add(ALT_TREE_INNER_OFF).readPointer();
        if (alt.isNull()) return false;
        const r = findFirstSkinned(alt, 0);
        if (r) {
            playerSkin = r.skin;
            playerGeom = r.geom;
            return true;
        }
    } catch(e) {}
    return false;
}

let dumpCount = 0;
const MAX_DUMPS = 8;
let totalCalls = 0;
let playerHits = 0;
let scanHits = 0;

// Sample 1 in N for full a1-scan to find where player ptr lives
const SCAN_EVERY = 100;

function dumpStruct(label, p, sz) {
    if (!p || p.isNull()) {
        console.log('  ' + label + ': null');
        return;
    }
    console.log('  ' + label + ' @ ' + p + ' (first ' + sz + 'B):');
    try {
        const buf = new Uint8Array(p.readByteArray(sz));
        for (let row = 0; row < sz; row += 16) {
            const hex = Array.from(buf.slice(row, row+16))
                .map(b => b.toString(16).padStart(2, '0')).join(' ');
            // Try to decode each qword as a pointer
            let ptrAnno = '';
            for (let q = 0; q < 16; q += 8) {
                if (row+q+8 > sz) break;
                let qv = 0n;
                for (let i = 7; i >= 0; i--) {
                    qv = (qv << 8n) | BigInt(buf[row+q+i]);
                }
                // Heap or module addresses
                if (qv >= 0x100000000n && qv < 0x1000000000000n) {
                    ptrAnno += ' [+' + (row+q).toString(16) + ']=0x' + qv.toString(16);
                }
            }
            console.log('    +0x' + row.toString(16).padStart(3,'0') + ': ' + hex + ptrAnno);
        }
    } catch(e) {
        console.log('    <read failed: ' + e + '>');
    }
}

function scanForPlayer(p, sz) {
    if (!p || p.isNull() || !playerSkin || !playerGeom) return null;
    try {
        const buf = new Uint8Array(p.readByteArray(sz));
        const skinHi = parseInt(playerSkin.toString().slice(2), 16);
        const geomHi = parseInt(playerGeom.toString().slice(2), 16);
        for (let off = 0; off + 8 <= sz; off += 8) {
            let qv = 0n;
            for (let i = 7; i >= 0; i--) {
                qv = (qv << 8n) | BigInt(buf[off+i]);
            }
            const qNum = Number(qv);
            if (qNum === skinHi) return { off: off, kind: 'PLAYER_SKIN' };
            if (qNum === geomHi) return { off: off, kind: 'PLAYER_GEOM' };
        }
    } catch(e) {}
    return null;
}

const TARGET_ADDR = base.add(TARGET_RVA);
console.log('[dissect] hooking ' + TARGET_ADDR);

Interceptor.attach(TARGET_ADDR, {
    onEnter: function(args) {
        totalCalls++;
        // Dump first MAX_DUMPS calls in full
        if (dumpCount < MAX_DUMPS) {
            dumpCount++;
            console.log('\n[dissect] === call ' + dumpCount + ' total=' + totalCalls + ' ===');
            console.log('  a0=' + args[0] + ' a1=' + args[1] + ' a2=' + args[2] + ' a3=' + args[3]);
            dumpStruct('a1', args[1], 256);
        }
        // Sample 1 in SCAN_EVERY for player-ptr scan
        if (totalCalls % SCAN_EVERY === 0) {
            if (!playerSkin) tryResolvePlayer();
            const hit = scanForPlayer(args[1], 256);
            if (hit) {
                scanHits++;
                if (scanHits <= 3) {
                    console.log('\n[dissect] PLAYER PTR FOUND in a1+0x' + hit.off.toString(16)
                                + ' kind=' + hit.kind + ' (call ' + totalCalls + ')');
                }
                playerHits++;
            }
        }
    }
});

console.log('[dissect] hook installed');

setInterval(() => {
    if (!playerSkin) tryResolvePlayer();
    console.log('[dissect] tick total=' + totalCalls + ' dumps=' + dumpCount
                + ' scan_hits=' + scanHits
                + (playerSkin ? ' player.skin=' + playerSkin + ' geom=' + playerGeom : ' player=unresolved'));
}, 5000);

console.log('[dissect] sampler armed @ 5s');
