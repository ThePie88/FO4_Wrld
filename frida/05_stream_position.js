// Step 5: stream posizione player a 20Hz, logga deltas quando ti muovi
// Questo è il primitive che userà il sender per il ghost player.

const SINGLETON_RVA = 0x32D2260;
const POS_OFF = 0xD0; // X a +0xD0, Y +0xD4, Z +0xD8

const base = Process.findModuleByName('Fallout4.exe').base;
const singletonAddr = base.add(SINGLETON_RVA);
const playerPtr = singletonAddr.readPointer();

console.log('[+] Player Actor* = ' + playerPtr);
console.log('[+] Streaming position @ 20Hz for 30s. Muoviti in-game per vedere gli update.');

let lastX = 0, lastY = 0, lastZ = 0;
let ticks = 0;
let changes = 0;
const DURATION_MS = 30000;
const TICK_MS = 50;
const MOVE_THRESHOLD = 0.1; // unit di gioco

const start = Date.now();
const posAddr = playerPtr.add(POS_OFF);

const interval = setInterval(() => {
    // Attenzione: playerPtr potrebbe diventare invalido se cambia cella?
    // Per ora rileggilo ogni volta dal singleton per safety.
    let pp;
    try {
        pp = singletonAddr.readPointer();
    } catch (e) {
        console.log('[-] Lost singleton read: ' + e.message);
        clearInterval(interval);
        return;
    }
    if (pp.isNull()) {
        console.log('[-] Player singleton is now null');
        clearInterval(interval);
        return;
    }

    const x = pp.add(POS_OFF).readFloat();
    const y = pp.add(POS_OFF + 4).readFloat();
    const z = pp.add(POS_OFF + 8).readFloat();

    ticks++;
    const dx = x - lastX, dy = y - lastY, dz = z - lastZ;
    if (Math.abs(dx) > MOVE_THRESHOLD || Math.abs(dy) > MOVE_THRESHOLD || Math.abs(dz) > MOVE_THRESHOLD) {
        if (lastX !== 0 || lastY !== 0) {
            changes++;
            const elapsed = ((Date.now() - start) / 1000).toFixed(2);
            console.log('  t=' + elapsed + 's  X=' + x.toFixed(2) + '  Y=' + y.toFixed(2) + '  Z=' + z.toFixed(2) +
                         '  dX=' + dx.toFixed(2) + '  dY=' + dy.toFixed(2) + '  dZ=' + dz.toFixed(2));
        }
        lastX = x; lastY = y; lastZ = z;
    }

    if (Date.now() - start > DURATION_MS) {
        clearInterval(interval);
        console.log('[+] Stream end. Ticks=' + ticks + '  movement-events=' + changes);
        send({ type: 'done', ticks: ticks, changes: changes });
    }
}, TICK_MS);
