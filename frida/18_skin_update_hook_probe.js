// M8P3.8 v2 — Defensive discriminator probe.
// =====================================================================
// Reduced to 4 most likely candidates. onEnter does ZERO classification
// (just counters and stash arg). Reports try/catch'd so a single bad
// pointer doesn't kill the timer.

console.log('[skin-probe] script starting');

const game = Process.getModuleByName('Fallout4.exe');
const base = game.base;
console.log('[skin-probe] Fallout4.exe base = ' + base);

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

const CANDIDATES = [
    { rva: 0x21FDA30, label: 'B_21FDA30_TOP' },
    { rva: 0x21B4730, label: 'A_21B4730_TOP' },
    { rva: 0xE3DBA0,  label: 'B_E3DBA0_HOT' },
    { rva: 0xC5F0E0,  label: 'A_C5F0E0_alt' },
];

// stats[label] = { count, last_a0, last_a1 }
const stats = {};
CANDIDATES.forEach(c => stats[c.label] = { count: 0, last_a0: ptr(0), last_a1: ptr(0) });

function vtRva(p) {
    try {
        if (!p || p.isNull()) return 0;
        return p.readPointer().sub(base).toInt32();
    } catch(e) { return -1; }
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
function findPlayerSkin() {
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

function classifyArg(p) {
    try {
        if (!p || p.isNull()) return 'null';
        const vt = vtRva(p);
        if (vt === 0 || vt === -1) return p + '/no-vt';
        if (vt === BSSKIN_INST_VT) return p + '/BSSkinInst';
        if (vt === BSTRISHAPE_VT) return p + '/BSTriShape';
        if (vt === BSSUBINDEX_VT) return p + '/BSSubIndex';
        if (vt === BSDYN_VT_A || vt === BSDYN_VT_B) return p + '/BSDynTri';
        if (vt === NINODE_VT) return p + '/NiNode';
        if (vt === BSFADENODE_VT) return p + '/BSFadeNode';
        return p + '/vt=0x' + vt.toString(16);
    } catch(e) { return 'err'; }
}

// Install hooks
CANDIDATES.forEach(c => {
    const addr = base.add(c.rva);
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                const s = stats[c.label];
                s.count++;
                s.last_a0 = args[0];
                s.last_a1 = args[1];
            }
        });
        console.log('[skin-probe] hooked ' + c.label + ' @ ' + addr);
    } catch(e) {
        console.log('[skin-probe] FAIL hook ' + c.label + ': ' + e);
    }
});

console.log('[skin-probe] all hooks installed');

let playerSkin = null;
let playerGeom = null;
let lastReport = Date.now();
const reportT0 = Date.now();
const lastCounts = {};
CANDIDATES.forEach(c => lastCounts[c.label] = 0);
let tickN = 0;

setInterval(() => {
    try {
        tickN++;
        // Heartbeat
        console.log('[skin-probe] tick ' + tickN + ' t=' + ((Date.now()-reportT0)/1000).toFixed(1) + 's');

        if (!playerSkin) {
            const t = findPlayerSkin();
            if (t) {
                playerSkin = t.skin;
                playerGeom = t.geom;
                console.log('[skin-probe] resolved player: skin=' + playerSkin + ' geom=' + playerGeom);
            } else {
                console.log('[skin-probe] player not yet resolved');
            }
        }

        const now = Date.now();
        const dtSec = (now - lastReport) / 1000;
        lastReport = now;

        // Build per-candidate snapshot
        const rows = [];
        CANDIDATES.forEach(c => {
            const s = stats[c.label];
            const last = lastCounts[c.label];
            const delta = s.count - last;
            lastCounts[c.label] = s.count;
            const rate = delta / dtSec;
            let a0_class = 'n/a';
            let a1_class = 'n/a';
            let a0_player = false;
            try {
                a0_class = classifyArg(s.last_a0);
                a1_class = classifyArg(s.last_a1);
                if (playerSkin && (s.last_a0.equals(playerSkin) || s.last_a1.equals(playerSkin))) a0_player = true;
                if (playerGeom && (s.last_a0.equals(playerGeom) || s.last_a1.equals(playerGeom))) a0_player = true;
            } catch(e) {}
            rows.push({ label: c.label, total: s.count, rate: rate.toFixed(1),
                        a0: a0_class, a1: a1_class, player: a0_player });
        });
        rows.sort((a, b) => parseFloat(b.rate) - parseFloat(a.rate));
        rows.forEach(r => {
            const flag = parseFloat(r.rate) > 30 ? '[PER-FRAME]' : (parseFloat(r.rate) > 1 ? '[active]' : '');
            const pf = r.player ? '[PLAYER]' : '';
            console.log('  ' + r.label + ': rate=' + r.rate + '/s total=' + r.total
                        + ' ' + flag + ' ' + pf);
            console.log('    a0=' + r.a0 + ' a1=' + r.a1);
        });
    } catch(e) {
        console.log('[skin-probe] ERR in tick ' + tickN + ': ' + e + ' stack=' + (e.stack||'?'));
    }
}, 2000);

console.log('[skin-probe] sampler armed @ 2s interval');
