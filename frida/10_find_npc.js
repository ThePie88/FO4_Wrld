// Trova l'Actor con formID 0x0001CA7D (Codsworth) scanning memoria.
// Ogni Actor ha formID a offset 0x14 (ereditato da TESForm).

const TARGET_FORMID = 0x0001CA7D;
const FORMID_OFF = 0x14;
const POS_OFF = 0xD0;
const ROT_OFF = 0xC0;
const MAX_RANGE_MB = 200;

function toBytesPattern(val) {
    const buf = new ArrayBuffer(4);
    new Uint32Array(buf)[0] = val;
    const b = new Uint8Array(buf);
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(' ');
}

const pattern = toBytesPattern(TARGET_FORMID);
console.log('[+] Looking for formID 0x' + TARGET_FORMID.toString(16).toUpperCase() + ' pattern="' + pattern + '"');

const fo4 = Process.findModuleByName('Fallout4.exe');
const fo4End = fo4.base.add(fo4.size);
console.log('[+] Fallout4.exe base=' + fo4.base + ' end=' + fo4End);

function runScan() {
    const ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: true })
        .filter(r => r.size <= MAX_RANGE_MB * 1024 * 1024);
    console.log('[+] Scanning ' + ranges.length + ' rw ranges (<' + MAX_RANGE_MB + 'MB)');

    const candidates = [];
    const t0 = Date.now();

    function chunk(startIdx) {
        const end = Math.min(startIdx + 80, ranges.length);
        for (let i = startIdx; i < end; i++) {
            try {
                const matches = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
                for (const m of matches) {
                    // Candidato Actor = m.address - 0x14
                    const actor = m.address.sub(FORMID_OFF);
                    try {
                        const vtable = actor.readPointer();
                        // Relaxed: accetta qualsiasi vtable plausibile (non NULL, allineata)
                        if (!vtable.isNull() && vtable.and(7).equals(ptr(0))) {
                            candidates.push({ actor: actor, vtable: vtable, inFo4: vtable.compare(fo4.base) > 0 && vtable.compare(fo4End) < 0 });
                        }
                    } catch (e) {}
                }
            } catch (e) {}
        }
        if (end < ranges.length) {
            setTimeout(() => chunk(end), 0);
        } else {
            const el = ((Date.now() - t0) / 1000).toFixed(1);
            console.log('[+] Scan done in ' + el + 's. Candidates: ' + candidates.length);
            candidates.forEach((c, i) => {
                try {
                    const x = c.actor.add(POS_OFF).readFloat();
                    const y = c.actor.add(POS_OFF + 4).readFloat();
                    const z = c.actor.add(POS_OFF + 8).readFloat();
                    const rx = c.actor.add(ROT_OFF).readFloat();
                    const ry = c.actor.add(ROT_OFF + 4).readFloat();
                    const rz = c.actor.add(ROT_OFF + 8).readFloat();
                    const vtDesc = c.inFo4 ? ('rva=0x' + c.vtable.sub(fo4.base).toString(16)) : ('abs=' + c.vtable);
                    console.log('  #' + i + ' actor=' + c.actor + ' vt.' + vtDesc +
                                '  pos=(' + x.toFixed(1) + ', ' + y.toFixed(1) + ', ' + z.toFixed(1) + ')' +
                                '  rot=(' + (rx*180/Math.PI).toFixed(1) + 'deg, ' + (ry*180/Math.PI).toFixed(1) + 'deg, ' + (rz*180/Math.PI).toFixed(1) + 'deg)');
                } catch (e) {
                    console.log('  #' + i + ' actor=' + c.actor + ' <read err: ' + e + '>');
                }
            });
            send({ type: 'done', candidates: candidates.map(c => c.actor.toString()) });
        }
    }
    chunk(0);
}

setTimeout(runScan, 100);
console.log('[+] Loaded, scan deferred');
