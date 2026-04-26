// M8P3.7 — Hunt for the flat per-bone skinning matrix buffer.
// =====================================================================
//
// GPT theory: the engine has a CPU SKIN UPDATE PASS that reads
// bone.world matrices, multiplies by inverse-bind, and writes a flat
// per-bone matrix buffer (~bones×64 bytes). That buffer is uploaded to
// GPU as a constant buffer. The vertex shader reads from THERE — not
// from bone+0x70 directly. Our writes hit bone+0x70 (scene graph) but
// the GPU CB is pre-computed elsewhere.
//
// This script:
//   1. Locates the player's body BSSkin::Instance via alt tree walk
//   2. Periodically scans memory in a window around the skin instance
//      AND around the BSGraphics::Renderer global (qword_1434380A8)
//   3. Computes per-page hashes; identifies pages that change every
//      frame during animation
//   4. Logs candidate "buffer size N bytes that changes per-frame"
//
// Strategy: 27 bones for player → 27×64 = 1728 bytes flat buffer.
// Or maybe stride is 0x50 (with bound) → 27×80 = 2160 bytes.
//
// Run while player is animating in 3rd person (`tfc 1` and walk).
// Detach after ~30s. Look at log for N-byte regions that change
// constantly during anim. Those are skin buffer candidates.

console.log('[buffer-hunt] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[buffer-hunt] Fallout4.exe base = ' + base);

const PLAYER_SINGLETON_RVA = 0x32D2260;
const ALT_TREE_OFF         = 0xF0;
const ALT_TREE_INNER_OFF   = 0x08;
const NIAV_NAME_OFF        = 0x10;
const NINODE_CHILDREN_PTR  = 0x128;
const NINODE_CHILDREN_CNT  = 0x132;
const BSGEOM_SKIN_OFF      = 0x140;
const BSGRAPHICS_RENDERER_RVA = 0x34380A8;

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

function isNode(vt) {
    return vt === NINODE_VT || vt === BSFADENODE_VT;
}

function isGeom(vt) {
    return vt === BSTRISHAPE_VT || vt === BSSUBINDEX_VT
        || vt === BSDYN_VT_A || vt === BSDYN_VT_B;
}

function readBSFS(p) {
    if (p.isNull()) return '<null>';
    try {
        const e = p.readPointer();
        if (e.isNull()) return '<empty>';
        return e.add(0x18).readUtf8String();
    } catch(e) { return '<av>'; }
}

function findFirstSkinned(node, depth) {
    if (!node || node.isNull() || depth > 24) return null;
    const vt = vtRva(node);
    if (isGeom(vt)) {
        try {
            const skin = node.add(BSGEOM_SKIN_OFF).readPointer();
            if (!skin.isNull()) return { geom: node, skin: skin };
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
    const found = findFirstSkinned(alt, 0);
    return found;
}

// ------------------------------------------------------------------
// Memory hash scan: divide a window into 64-byte chunks, hash each.
// Track which chunks change between samples.
// ------------------------------------------------------------------
function hashChunk(buf, off, size) {
    // FNV-1a 32-bit
    let h = 0x811c9dc5;
    for (let i = 0; i < size; i++) {
        h ^= buf[off+i];
        h = (h * 0x01000193) >>> 0;
    }
    return h;
}

const CHUNK_SIZE = 64;  // matrix-sized
const SCAN_REGIONS = [];   // {label, addr, size}
let prev_hashes = new Map();    // key=region_label_offset → hash
const change_counts = new Map(); // key=region_label_offset → count
let sample_count = 0;
const startT = Date.now();

let target = null;
let lastTry = 0;

function buildRegions(t) {
    SCAN_REGIONS.length = 0;
    // Region 1: 4KB window AROUND the skin instance
    SCAN_REGIONS.push({
        label: 'skin',
        addr: t.skin.sub(0x800),
        size: 0x1000,
    });
    // Region 2: 4KB after skin instance (beyond struct end)
    SCAN_REGIONS.push({
        label: 'skin_post',
        addr: t.skin.add(0xC0),
        size: 0x1000,
    });
    // Region 3: 8KB around BSGraphics::Renderer global
    try {
        const r = base.add(BSGRAPHICS_RENDERER_RVA).readPointer();
        if (!r.isNull()) {
            SCAN_REGIONS.push({
                label: 'renderer',
                addr: r,
                size: 0x2000,
            });
        }
    } catch(e) {}
    // Region 4: 4KB around the geometry
    SCAN_REGIONS.push({
        label: 'geom',
        addr: t.geom.sub(0x400),
        size: 0x1000,
    });
    console.log('[buffer-hunt] scanning ' + SCAN_REGIONS.length + ' regions');
    SCAN_REGIONS.forEach(r => console.log(`  ${r.label} @ ${r.addr} size=0x${r.size.toString(16)}`));
}

function tick() {
    const now = Date.now() - startT;
    if (!target) {
        if (now - lastTry < 1000) return;
        lastTry = now;
        target = findTarget();
        if (!target) return;
        console.log('[buffer-hunt] target acquired: skin=' + target.skin
                    + ' geom=' + target.geom);
        buildRegions(target);
        return;
    }
    sample_count++;

    SCAN_REGIONS.forEach(r => {
        let buf;
        try { buf = new Uint8Array(r.addr.readByteArray(r.size)); }
        catch(e) { return; }
        for (let off = 0; off < r.size; off += CHUNK_SIZE) {
            const key = r.label + '_' + off.toString(16);
            const h = hashChunk(buf, off, CHUNK_SIZE);
            const prev = prev_hashes.get(key);
            if (prev !== undefined && prev !== h) {
                change_counts.set(key, (change_counts.get(key) || 0) + 1);
            }
            prev_hashes.set(key, h);
        }
    });
}

// Run hash scan every 32ms (~30Hz)
setInterval(tick, 32);

// Every 5 seconds, log top-N most-changing 64B chunks
setInterval(() => {
    if (!target) return;
    const t = Date.now() - startT;
    const ranked = Array.from(change_counts.entries())
        .filter(([k, v]) => v > 5)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20);
    console.log(`[buffer-hunt] T+${t}ms samples=${sample_count} top changing 64B chunks:`);
    ranked.forEach(([k, v]) => {
        const [region, offHex] = k.split('_');
        const r = SCAN_REGIONS.find(x => x.label === region);
        if (r) {
            const off = parseInt(offHex, 16);
            const addr = r.addr.add(off);
            console.log(`  ${k} @ ${addr} changed ${v}/${sample_count} samples`);
        }
    });
}, 5000);

console.log('[buffer-hunt] hash-diff scan armed @ 32ms; 5sec ranking');
