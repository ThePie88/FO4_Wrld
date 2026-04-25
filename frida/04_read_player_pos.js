// Step 4: leggi player X/Y/Z usando il singleton recuperato via IDA
// Singleton: Fallout4.exe + 0x32D2260 (puntatore ad Actor*)
// Position: actor + 0xD0 (X), +0xD4 (Y), +0xD8 (Z)

const SINGLETON_RVA = 0x32D2260;
const POS_X_OFF = 0xD0;
const POS_Y_OFF = 0xD4;
const POS_Z_OFF = 0xD8;

const base = Process.findModuleByName('Fallout4.exe').base;
console.log('[+] Fallout4.exe base: ' + base);

const singletonAddr = base.add(SINGLETON_RVA);
console.log('[+] Singleton address: ' + singletonAddr + ' (RVA 0x' + SINGLETON_RVA.toString(16) + ')');

const playerPtr = singletonAddr.readPointer();
console.log('[+] Player Actor* = ' + playerPtr);

if (playerPtr.isNull()) {
    console.log('[-] Player pointer is NULL. Non sei in-game o non ancora spawnato.');
} else {
    // Sanity: leggi i primi 8 byte del player — dovrebbe essere un vtable pointer
    const vtable = playerPtr.readPointer();
    console.log('[+] Player vtable @ ' + vtable);

    // Leggi posizione
    const x = playerPtr.add(POS_X_OFF).readFloat();
    const y = playerPtr.add(POS_Y_OFF).readFloat();
    const z = playerPtr.add(POS_Z_OFF).readFloat();

    console.log('[+] Player position: X=' + x.toFixed(3) + '  Y=' + y.toFixed(3) + '  Z=' + z.toFixed(3));

    // Live readout per 5 secondi (muoviti in-game per vedere aggiornamenti)
    console.log('[+] Live readout per 5s (muoviti in-game):');
    let tick = 0;
    const interval = setInterval(() => {
        const x2 = playerPtr.add(POS_X_OFF).readFloat();
        const y2 = playerPtr.add(POS_Y_OFF).readFloat();
        const z2 = playerPtr.add(POS_Z_OFF).readFloat();
        console.log('    t=' + tick + 'ms  X=' + x2.toFixed(2) + '  Y=' + y2.toFixed(2) + '  Z=' + z2.toFixed(2));
        tick += 500;
        if (tick > 5000) {
            clearInterval(interval);
            console.log('[+] Done.');
            send({ type: 'pos_test_done' });
        }
    }, 500);
}
