// FalloutWorld — Step 1: prova di aggancio e mappa moduli
// Uso: frida -n Fallout4.exe -l 01_enumerate.js --no-pause

console.log('[+] Attached to process');
console.log('[+] Pointer size: ' + Process.pointerSize);
console.log('[+] Arch: ' + Process.arch);
console.log('[+] Platform: ' + Process.platform);

const target = 'Fallout4.exe';
const fo4 = Process.findModuleByName(target);
if (!fo4) {
    console.log('[-] ' + target + ' not found in loaded modules');
} else {
    console.log('[+] ' + target + ' base: ' + fo4.base + '  size: 0x' + fo4.size.toString(16));
}

// F4SE loader + runtime DLL
const modules = Process.enumerateModules();
console.log('[+] Total modules loaded: ' + modules.length);

const interesting = modules.filter(m =>
    /fallout|f4se|Nvngx|d3d|x3daudio/i.test(m.name)
);
console.log('[+] Interesting modules:');
interesting.forEach(m => {
    console.log('    ' + m.name.padEnd(30) + ' base=' + m.base + ' size=0x' + m.size.toString(16));
});

// Conta export e import per Fallout4.exe per dare un senso della scala
if (fo4) {
    const exports = fo4.enumerateExports();
    const imports = fo4.enumerateImports();
    console.log('[+] Fallout4.exe exports: ' + exports.length + ', imports: ' + imports.length);
    if (exports.length > 0) {
        console.log('[+] First 5 exports:');
        exports.slice(0, 5).forEach(e => console.log('    ' + e.name + ' @ ' + e.address));
    }
}

console.log('[+] Enumeration complete. Detach with Ctrl+C or wait for hooks to fire.');
