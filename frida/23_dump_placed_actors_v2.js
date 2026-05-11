// 23_dump_placed_actors_v2.js — B6.5w3 prep, continuous capture
//
// v2 changes over 22_dump_placed_actors.js:
//   - No auto-detach. Runs until you kill Frida (Ctrl+C / q in REPL).
//   - Fixed the filter bug: `formId >= 0xFF000000` instead of bitwise
//     AND with sign-extension in JS Int32 land.
//   - Dumps THREE candidate position offsets per actor so we can triangulate
//     which one holds the real world pos for generic Actor (the existing
//     scripts assumed +0xD0 from PlayerCharacter; that may not match a
//     vanilla raider). We pick the right offset post-hoc by cross-
//     referencing one known actor (e.g. Preston 0x0001A4D7) against the
//     console `prid; getpos x/y/z` ground truth.
//   - Tries to read parent cell formID (Actor + 0x60 → cellPtr → +0x14).
//   - Periodic status line every 10 s ("captured N placed actors so far")
//     so a long capture run is observable.
//
// Usage (capture flow Sanctuary → Concord → Museum):
//   1. Boot game from a save where Concord/MQ102 is NOT yet triggered.
//   2. frida -p <fo4_pid> -l frida/23_dump_placed_actors_v2.js > capture.txt 2>&1
//   3. Walk from Sanctuary, through Red Rocket, to the museum. Let raiders
//      kill the player if you want — that puts them in High tier and they
//      tick more often, so they're guaranteed captured.
//   4. Ctrl+C Frida when done. `capture.txt` has every unique placed actor
//      observed during the run, with 3 pos candidates per entry.
//
// Output format per actor line:
//   placed actor formid=0xFFFFFFFF cell=0xFFFFFFFF posA=(x,y,z) posB=(x,y,z) posC=(x,y,z)
//
// pos candidates:
//   posA  = Actor + 0x54   (TESObjectREFR translation candidate)
//   posB  = Actor + 0xC0   (10_find_npc.js used as "rotation"; let's see)
//   posC  = Actor + 0xD0   (PlayerCharacter live pos — known good for PC,
//                           uncertain for generic Actor)

const FORMID_OFF        = 0x14;
const PARENT_CELL_OFF   = 0x60;       // best-guess TESObjectREFR.parentCell ptr
const PER_ACTOR_TICK    = 0xC636A0;   // B6.5w0 dossier: single AI funnel
const RUNTIME_THRESHOLD = 0xFF000000; // form_ids >= this are runtime (leveled-spawn)
const STATUS_EVERY_MS   = 10000;

const POS_CANDIDATES = [
    { name: 'A', off: 0x54 },
    { name: 'B', off: 0xC0 },
    { name: 'C', off: 0xD0 },
];

const fo4 = Process.findModuleByName('Fallout4.exe');
console.log('[+] Fallout4.exe base=' + fo4.base);

const tickAddr = fo4.base.add(PER_ACTOR_TICK);
console.log('[+] Hooking Actor::Update_PerFrame at ' + tickAddr +
            ' (RVA 0x' + PER_ACTOR_TICK.toString(16) + ')');

const seen = new Map();
const startedAt = Date.now();

function safeFloat(p) { try { return p.readFloat(); } catch (e) { return null; } }
function safeU32(p)   { try { return p.readU32();   } catch (e) { return null; } }
function safePtr(p)   { try { return p.readPointer(); } catch (e) { return null; } }

function readPosTriplet(actor, off) {
    const x = safeFloat(actor.add(off));
    const y = safeFloat(actor.add(off + 4));
    const z = safeFloat(actor.add(off + 8));
    if (x === null || y === null || z === null) return null;
    return [x, y, z];
}

function formatPos(p) {
    if (p === null) return '?';
    return '(' + p[0].toFixed(1) + ',' + p[1].toFixed(1) + ',' + p[2].toFixed(1) + ')';
}

const hook = Interceptor.attach(tickAddr, {
    onEnter: function (args) {
        try {
            const actor = args[0];
            const formId = safeU32(actor.add(FORMID_OFF));
            if (formId === null) return;
            // Filter: skip runtime spawns (correct unsigned comparison this time).
            if (formId >= RUNTIME_THRESHOLD) return;
            // Skip player (well-known refs).
            if (formId === 0x14 || formId === 0x07) return;
            if (seen.has(formId)) return;
            seen.set(formId, true);

            // Parent cell — best effort, may NULL out during streaming.
            let cellId = null;
            const cellPtr = safePtr(actor.add(PARENT_CELL_OFF));
            if (cellPtr !== null && !cellPtr.isNull()) {
                cellId = safeU32(cellPtr.add(FORMID_OFF));
            }

            // Read each candidate pos offset.
            const positions = POS_CANDIDATES.map(c => readPosTriplet(actor, c.off));

            // Emit one line — single fixed format for easy post-hoc grep.
            let line = '  placed actor formid=0x' + formId.toString(16).padStart(8, '0');
            line += '  cell=' + (cellId === null ? '?' : '0x' + cellId.toString(16).padStart(8, '0'));
            for (let i = 0; i < POS_CANDIDATES.length; i++) {
                line += '  pos' + POS_CANDIDATES[i].name + '=' + formatPos(positions[i]);
            }
            console.log(line);
        } catch (e) {
            // Defensive — bad reads happen during cell streaming.
        }
    },
});

console.log('[+] Continuous capture started. Ctrl+C to stop.');
console.log('[+] Filter: placed (form_id < 0xFF000000), dedup by form_id, skip player.');
console.log('[+] Posizioni: A=+0x54, B=+0xC0, C=+0xD0 — incrociare post-hoc con `prid <id>; getpos x/y/z` in console per identificare quale ha valori veri.');

setInterval(function () {
    const elapsed = Math.round((Date.now() - startedAt) / 1000);
    console.log('=== status: ' + seen.size + ' unique placed actor(s) ' +
                '(elapsed=' + elapsed + 's) ===');
}, STATUS_EVERY_MS);
