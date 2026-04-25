// Verifica che formID sia a offset 0x14 dell'Actor: leggi il player.

const SINGLETON_RVA = 0x32D2260;
const base = Process.findModuleByName('Fallout4.exe').base;
const playerPtr = base.add(SINGLETON_RVA).readPointer();

console.log('[+] Player ptr: ' + playerPtr);

// Tentativi a vari offset
const offsets = [0x00, 0x08, 0x10, 0x14, 0x18, 0x20, 0x28, 0x30];
offsets.forEach(off => {
    try {
        const val = playerPtr.add(off).readU32();
        console.log('  +0x' + off.toString(16).padStart(2, '0') + ' = 0x' + val.toString(16).padStart(8, '0'));
    } catch (e) {
        console.log('  +0x' + off.toString(16) + ' <err>');
    }
});
