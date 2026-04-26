// M8P3.7v2 — Targeted hunt: follow pointers from BSSkin::Instance and
// scan their destinations for per-frame changing data.
// =====================================================================
//
// v1 finding: skin+0x80..0xA0 = skel-root local matrix (changes per
// frame because body moves, but it's NOT the bone matrix buffer).
//
// v2 strategy: every pointer field inside BSSkin::Instance points to
// a separate heap allocation. Read each pointer, scan a 16KB window
// around the destination, hash 64-byte chunks, log per-frame changes.
//
// Pointers we follow (from M8P3 dossier):
//   skin+0x10 = bones_fallback head      (NiAVObject** array)
//   skin+0x28 = bones_primary head       (NiAVObject** array)
//   skin+0x40 = boneData                 (BSSkin::BoneData*)
//   skin+0x48 = skel_root                (NiAVObject*)
//   skin+0x50 = unknown qword            (?)
//   skin+0xA0 = unknown NiPointer        (?)
//   skin+0xA8 = unknown NiPointer        (?)
//   skin+0xB0 = unknown NiPointer        (?)
//
// HIGH PRIORITY: boneData+0x10 is documented to contain per-bone
// transforms stride 0x50. If that array changes per frame, IT IS the
// runtime skin matrix buffer. Test conclusively.

console.log('[buffer-hunt-v2] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[buffer-hunt-v2] Fallout4.exe base = ' + base);

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

function vtRva(p) {
    if (p.isNull()) return 0;
    try { return p.readPointer().sub(base).toInt32(); } catch(e) { return -1; }
}

function isNode(vt) { return vt === NINODE_VT || vt === BSFADENODE_VT; }
function isGeom(vt) {
    return vt === BSTRISHAPE_VT || vt === BSSUBINDEX_VT
        || vt === BSDYN_VT_A || vt === BSDYN_VT_B;
}

function findFirstSkinned(node, depth) {
    if (!node || node.isNull() || depth > 24) return null;
    const vt = vtRva(node);
    if (isGeom(vt)) {
        try {
            const skin = node.add(BSGEOM_SKIN_OFF).readPointer();
            if (!skin.isNull()) return { geom: node, geom_vt: vt, skin: skin };
        } catch(e) {}
        return null;
    }
    if (!isNode(vt)) return null;
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

function findTarget() {
    const player = base.add(PLAYER_SINGLETON_RVA).readPointer();
    if (player.isNull()) return null;
    let alt;
    try {
        const c = player.add(ALT_TREE_OFF).readPointer();
        if (c.isNull()) return null;
        alt = c.add(ALT_TREE_INNER_OFF).readPointer();
    } catch(e) { return null; }
    if (alt.isNull()) return null;
    return findFirstSkinned(alt, 0);
}

function hashChunk(buf, off, size) {
    let h = 0x811c9dc5;
    for (let i = 0; i < size; i++) {
        h ^= buf[off+i];
        h = (h * 0x01000193) >>> 0;
    }
    return h;
}

const CHUNK_SIZE = 64;
const SCAN_REGIONS = [];
let prev_hashes = new Map();
const change_counts = new Map();
let sample_count = 0;
const startT = Date.now();

let target = null;
let lastTry = 0;
let regions_built = false;

function safeReadPtr(p) {
    try { return p.readPointer(); } catch(e) { return ptr(0); }
}

function buildRegions(t) {
    SCAN_REGIONS.length = 0;
    const skin = t.skin;
    console.log(`[buffer-hunt-v2] geom_vt_rva = 0x${t.geom_vt.toString(16)}`);
    console.log(`  ${t.geom_vt === BSDYN_VT_A || t.geom_vt === BSDYN_VT_B ? 'BSDynamicTriShape (CPU-skinned)' : 'BSTriShape/BSSubIndex (GPU-skinned)'}`);

    // Print full BSSkin::Instance hex for reference
    console.log('[buffer-hunt-v2] BSSkin::Instance @ ' + skin + ' (size 0xC0):');
    try {
        const buf = new Uint8Array(skin.readByteArray(0xC0));
        for (let row = 0; row < 0xC0; row += 16) {
            const hex = Array.from(buf.slice(row, row+16))
                .map(b => b.toString(16).padStart(2, '0')).join(' ');
            console.log(`  +0x${row.toString(16).padStart(2,'0')}: ${hex}`);
        }
    } catch(e) { console.log('  <read failed: ' + e + '>'); }

    // Follow pointers and add scan regions
    const POINTER_FIELDS = [
        { off: 0x10, name: 'p10_bones_fb_head', size: 0x2000 },
        { off: 0x28, name: 'p28_bones_pri_head', size: 0x2000 },
        { off: 0x40, name: 'p40_boneData', size: 0x4000 },
        { off: 0x48, name: 'p48_skel_root', size: 0x1000 },
        { off: 0x50, name: 'p50_unk', size: 0x2000 },
        { off: 0xA0, name: 'pA0_unk', size: 0x2000 },
        { off: 0xA8, name: 'pA8_unk', size: 0x2000 },
        { off: 0xB0, name: 'pB0_unk', size: 0x2000 },
    ];

    POINTER_FIELDS.forEach(pf => {
        try {
            const dst = skin.add(pf.off).readPointer();
            if (dst.isNull()) {
                console.log(`  ${pf.name} = NULL (skip)`);
                return;
            }
            console.log(`  ${pf.name} @ +0x${pf.off.toString(16)} -> ${dst} (scan ${pf.size}B)`);
            SCAN_REGIONS.push({ label: pf.name, addr: dst, size: pf.size });
        } catch(e) {
            console.log(`  ${pf.name} <read failed>`);
        }
    });

    // Special: boneData[+0x10] is per-bone array. Read it.
    try {
        const boneData = skin.add(0x40).readPointer();
        if (!boneData.isNull()) {
            const arr = boneData.add(0x10).readPointer();
            if (!arr.isNull()) {
                console.log('  boneData+0x10 (per-bone array head) -> ' + arr);
                SCAN_REGIONS.push({ label: 'boneData_arr', addr: arr, size: 0x4000 });
            }
        }
    } catch(e) {}

    console.log('[buffer-hunt-v2] built ' + SCAN_REGIONS.length + ' regions');
    regions_built = true;
}

function tick() {
    if (!target) {
        const now = Date.now() - startT;
        if (now - lastTry < 1000) return;
        lastTry = now;
        target = findTarget();
        if (!target) return;
        console.log('[buffer-hunt-v2] target acquired: skin=' + target.skin
                    + ' geom=' + target.geom);
        buildRegions(target);
        return;
    }
    if (!regions_built) return;
    sample_count++;

    SCAN_REGIONS.forEach(r => {
        let buf;
        try { buf = new Uint8Array(r.addr.readByteArray(r.size)); }
        catch(e) { return; }
        for (let off = 0; off < r.size; off += CHUNK_SIZE) {
            const key = r.label + '@' + off.toString(16);
            const h = hashChunk(buf, off, CHUNK_SIZE);
            const prev = prev_hashes.get(key);
            if (prev !== undefined && prev !== h) {
                change_counts.set(key, (change_counts.get(key) || 0) + 1);
            }
            prev_hashes.set(key, h);
        }
    });
}

setInterval(tick, 32);

setInterval(() => {
    if (!target || !regions_built) return;
    const t = Date.now() - startT;
    const ranked = Array.from(change_counts.entries())
        .filter(([k, v]) => v > 5)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 30);
    console.log(`[buffer-hunt-v2] T+${t}ms samples=${sample_count} top changing 64B chunks:`);

    // Group by region label, count contiguous runs
    const byRegion = {};
    ranked.forEach(([k, v]) => {
        const [region, offHex] = k.split('@');
        if (!byRegion[region]) byRegion[region] = [];
        byRegion[region].push({ off: parseInt(offHex, 16), v: v });
    });

    Object.keys(byRegion).forEach(region => {
        const list = byRegion[region].sort((a,b) => a.off - b.off);
        const r = SCAN_REGIONS.find(x => x.label === region);
        if (!r) return;
        // Find contiguous runs (chunks at consecutive 64B offsets)
        let runStart = list[0].off;
        let runEnd = list[0].off;
        let runCount = 1;
        let runs = [];
        for (let i = 1; i < list.length; i++) {
            if (list[i].off === runEnd + CHUNK_SIZE) {
                runEnd = list[i].off;
                runCount++;
            } else {
                runs.push({ start: runStart, end: runEnd, count: runCount });
                runStart = list[i].off;
                runEnd = list[i].off;
                runCount = 1;
            }
        }
        runs.push({ start: runStart, end: runEnd, count: runCount });
        const longestRun = runs.reduce((a,b) => b.count > a.count ? b : a);
        console.log(`  [${region}] ${list.length} active chunks, longest contig run: ${longestRun.count} chunks @ +0x${longestRun.start.toString(16)}..+0x${longestRun.end.toString(16)} (${longestRun.count*CHUNK_SIZE}B)`);
        list.slice(0, 10).forEach(item => {
            const addr = r.addr.add(item.off);
            console.log(`    +0x${item.off.toString(16).padStart(4,'0')} @ ${addr} changed ${item.v}/${sample_count}`);
        });
    });
}, 5000);

console.log('[buffer-hunt-v2] hash-diff scan armed @ 32ms; 5sec ranking');
