// Step 3 v3: pattern multipli (rounding), scan su Y, verifica X/Z con tolleranza

const TARGET_X = -79985.19;
const TARGET_Y =  90818.66;
const TARGET_Z =   7851.19;
const TOL = 1.0;
const MAX_RANGE_MB = 50;

function floatToPattern(val) {
    const buf = new ArrayBuffer(4);
    new Float32Array(buf)[0] = val;
    const bytes = new Uint8Array(buf);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

// Genera pattern per valori vicini a Y (copre rounding 2-decimali del display)
function patternsNear(val, step, count) {
    const pats = new Set();
    for (let i = -count; i <= count; i++) {
        const v = val + i * step;
        pats.add(floatToPattern(v));
    }
    return Array.from(pats);
}

const patsY = patternsNear(TARGET_Y, 0.005, 4); // ±0.020
console.log('[+] Patterns for Y (near ' + TARGET_Y + '): ' + patsY.length + ' variants');
patsY.forEach(p => console.log('    ' + p));

function runScan() {
    const allRanges = Process.enumerateRanges({ protection: 'rw-', coalesce: true });
    const ranges = allRanges.filter(r => r.size <= MAX_RANGE_MB * 1024 * 1024);
    const mb = (ranges.reduce((s, r) => s + r.size, 0) / 1024 / 1024).toFixed(0);
    console.log('[+] RW ranges: ' + ranges.length + ' (' + mb + ' MB, cap ' + MAX_RANGE_MB + ' MB)');

    const hits = [];
    const t0 = Date.now();

    function chunk(startIdx) {
        const end = Math.min(startIdx + 50, ranges.length);
        for (let i = startIdx; i < end; i++) {
            const range = ranges[i];
            for (const pat of patsY) {
                try {
                    const matches = Memory.scanSync(range.base, range.size, pat);
                    for (const m of matches) {
                        try {
                            // Y at m, X at m-4, Z at m+4
                            const x = m.address.sub(4).readFloat();
                            const z = m.address.add(4).readFloat();
                            if (Math.abs(x - TARGET_X) < TOL && Math.abs(z - TARGET_Z) < TOL) {
                                const y = m.address.readFloat();
                                hits.push({ addr: m.address.sub(4).toString(), x: x, y: y, z: z });
                            }
                        } catch (e) {}
                    }
                } catch (e) {}
            }
        }

        if (end < ranges.length) {
            setTimeout(() => chunk(end), 0);
        } else {
            const el = ((Date.now() - t0) / 1000).toFixed(1);
            console.log('[+] DONE in ' + el + 's. Hits: ' + hits.length);
            hits.forEach((h, idx) => {
                console.log('  #' + idx + ' base=' + h.addr + ' x=' + h.x.toFixed(4) + ' y=' + h.y.toFixed(4) + ' z=' + h.z.toFixed(4));
            });
            send({ type: 'scan_done', hits: hits });
        }
    }

    chunk(0);
}

setTimeout(runScan, 100);
console.log('[+] Loaded, scan starting...');
