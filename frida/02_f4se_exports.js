// Step 2: scava negli export di F4SE e cerca utility player/camera/position
// Se F4SE espone GetPlayerCharacter o simili, bypassiamo settimane di RE.

const f4se = Process.findModuleByName('f4se_1_11_191.dll');
if (!f4se) {
    console.log('[-] F4SE DLL not found');
} else {
    console.log('[+] F4SE base: ' + f4se.base + ' size: 0x' + f4se.size.toString(16));

    const exports = f4se.enumerateExports();
    const imports = f4se.enumerateImports();
    console.log('[+] F4SE exports: ' + exports.length);
    console.log('[+] F4SE imports: ' + imports.length);

    // Filtro per simboli "interessanti" per il nostro use case
    const keywords = /player|camera|position|actor|location|cell|world/i;
    const interesting = exports.filter(e => keywords.test(e.name));

    console.log('[+] Relevant F4SE exports (' + interesting.length + '):');
    interesting.forEach(e => {
        console.log('    ' + e.name + ' @ ' + e.address);
    });

    // Cerca anche import di F4SE verso Fallout4.exe — dove F4SE hooka l'engine
    const fo4imports = imports.filter(i =>
        i.module === 'Fallout4.exe' && keywords.test(i.name)
    );
    console.log('[+] Relevant F4SE imports from Fallout4.exe (' + fo4imports.length + '):');
    fo4imports.forEach(i => {
        console.log('    ' + i.name + ' @ ' + i.address + ' (from ' + i.module + ')');
    });

    // Stampa primi 20 export generici per avere visibilità
    console.log('[+] First 20 F4SE exports (sample):');
    exports.slice(0, 20).forEach(e => {
        console.log('    ' + e.name);
    });
}
