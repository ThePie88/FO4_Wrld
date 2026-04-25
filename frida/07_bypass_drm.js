// Minimalista: hook solo ShellExecuteW per bloccare steam:// protocol handler.

console.log('[+] Script starting...');

const shell32 = Process.getModuleByName('shell32.dll');
console.log('[+] shell32 base: ' + shell32.base);

const shellExec = shell32.findExportByName('ShellExecuteW');
console.log('[+] ShellExecuteW @ ' + shellExec);

Interceptor.attach(shellExec, {
    onEnter: function (args) {
        try {
            const url = args[2].readUtf16String();
            console.log('[ShellExecuteW] op=' + args[1].readUtf16String() + '  target=' + url);
            if (url && url.toLowerCase().startsWith('steam:')) {
                console.log('[BLOCK] steam protocol handler: ' + url);
                this.blocked = true;
            }
        } catch (e) {
            console.log('[ShellExec] onEnter error: ' + e);
        }
    },
    onLeave: function (retval) {
        if (this.blocked) {
            retval.replace(ptr(42)); // > 32 = fake success
        }
    }
});

console.log('[+] ShellExecuteW hook installed');
