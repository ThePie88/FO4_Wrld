// Step 6: streaming completo di posizione + rotazione a 20Hz

const SINGLETON_RVA = 0x32D2260;
const ROT_OFF = 0xC0;  // C0=pitch, C4=roll, C8=yaw (radianti)
const POS_OFF = 0xD0;  // D0=X, D4=Y, D8=Z

const RAD_TO_DEG = 180 / Math.PI;

const base = Process.findModuleByName('Fallout4.exe').base;
const singletonAddr = base.add(SINGLETON_RVA);
const playerPtr = singletonAddr.readPointer();
console.log('[+] Player Actor* = ' + playerPtr);

if (playerPtr.isNull()) {
    console.log('[-] Player singleton null — not in-game');
} else {
    console.log('[+] Streaming pos+rot @ 20Hz per 20s. Cammina E guardati intorno (mouse).');

    let ticks = 0;
    let changes = 0;
    const start = Date.now();
    const DURATION = 20000;
    const MOVE_THR = 0.1;
    const ROT_THR = 0.01; // rad (~0.57°)

    let lastX=0, lastY=0, lastZ=0, lastRX=0, lastRY=0, lastRZ=0;

    const h = setInterval(() => {
        const pp = singletonAddr.readPointer();
        if (pp.isNull()) { clearInterval(h); return; }

        const rx = pp.add(ROT_OFF).readFloat();
        const ry = pp.add(ROT_OFF+4).readFloat();
        const rz = pp.add(ROT_OFF+8).readFloat();
        const x  = pp.add(POS_OFF).readFloat();
        const y  = pp.add(POS_OFF+4).readFloat();
        const z  = pp.add(POS_OFF+8).readFloat();

        ticks++;
        const dPos = Math.abs(x-lastX) + Math.abs(y-lastY) + Math.abs(z-lastZ);
        const dRot = Math.abs(rx-lastRX) + Math.abs(ry-lastRY) + Math.abs(rz-lastRZ);
        if ((dPos > MOVE_THR || dRot > ROT_THR) && (lastX !== 0 || lastY !== 0)) {
            changes++;
            const t = ((Date.now()-start)/1000).toFixed(2);
            console.log(`  t=${t}s pos=(${x.toFixed(1)}, ${y.toFixed(1)}, ${z.toFixed(1)})  rot=(${(rx*RAD_TO_DEG).toFixed(1)}°, ${(ry*RAD_TO_DEG).toFixed(1)}°, ${(rz*RAD_TO_DEG).toFixed(1)}°)  dPos=${dPos.toFixed(2)}  dYaw=${((rz-lastRZ)*RAD_TO_DEG).toFixed(2)}°`);
        }
        lastX=x; lastY=y; lastZ=z; lastRX=rx; lastRY=ry; lastRZ=rz;

        if (Date.now()-start > DURATION) {
            clearInterval(h);
            console.log(`[+] End. ticks=${ticks} events=${changes}`);
            send({ type: 'done', ticks, changes });
        }
    }, 50);
}
