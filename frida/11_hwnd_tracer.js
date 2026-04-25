// Logga TUTTE le API Win32 che ritornano un hwnd o gestiscono kernel objects con nome.
// Scopo: capire come la seconda istanza trova la prima.

console.log('[+] hwnd+kernel-obj tracer loading');

const user32 = Process.getModuleByName('user32.dll');
const k32 = Process.getModuleByName('kernel32.dll');
const kb = Process.getModuleByName('kernelbase.dll');

function hookRet(mod, name, argsFn) {
    const f = mod.findExportByName(name);
    if (!f) return;
    Interceptor.attach(f, {
        onEnter: function (args) { try { this.info = argsFn ? argsFn(args) : ''; } catch(e){} },
        onLeave: function (retval) {
            if (!retval.isNull()) {
                console.log('[' + name + '] ' + (this.info || '') + ' -> ' + retval);
            }
        }
    });
}

// Hwnd returners
hookRet(user32, 'GetTopWindow', args => 'parent=' + args[0]);
hookRet(user32, 'GetForegroundWindow');
hookRet(user32, 'GetActiveWindow');
hookRet(user32, 'GetDesktopWindow');
hookRet(user32, 'GetShellWindow');
hookRet(user32, 'GetWindow', args => 'hwnd=' + args[0] + ' cmd=' + args[1]);
hookRet(user32, 'GetAncestor', args => 'hwnd=' + args[0] + ' flags=' + args[1]);
hookRet(user32, 'WindowFromPoint');
hookRet(user32, 'GetParent', args => 'hwnd=' + args[0]);
hookRet(user32, 'FindWindowA', args => 'cls=' + (args[0].isNull() ? '<N>' : args[0].readUtf8String()));
hookRet(user32, 'FindWindowW', args => 'cls=' + (args[0].isNull() ? '<N>' : args[0].readUtf16String()));

// Named kernel objects (la prima istanza potrebbe pubblicare hwnd in shared memory / event / file mapping)
function hookNamedObj(mod, name, argIdx, isUnicode) {
    const f = mod.findExportByName(name);
    if (!f) return;
    Interceptor.attach(f, {
        onEnter: function (args) {
            try {
                const p = args[argIdx];
                if (!p.isNull()) {
                    const n = isUnicode ? p.readUtf16String() : p.readUtf8String();
                    if (n && n.length > 0) console.log('[' + name + '] name=' + JSON.stringify(n));
                }
            } catch (e) {}
        }
    });
}

hookNamedObj(k32, 'OpenMutexA', 2, false);
hookNamedObj(k32, 'OpenMutexW', 2, true);
hookNamedObj(k32, 'OpenEventA', 2, false);
hookNamedObj(k32, 'OpenEventW', 2, true);
hookNamedObj(k32, 'OpenFileMappingA', 2, false);
hookNamedObj(k32, 'OpenFileMappingW', 2, true);
hookNamedObj(k32, 'CreateMutexA', 2, false);
hookNamedObj(k32, 'CreateMutexW', 2, true);
hookNamedObj(k32, 'CreateEventA', 3, false);
hookNamedObj(k32, 'CreateEventW', 3, true);
hookNamedObj(k32, 'CreateFileMappingA', 5, false);
hookNamedObj(k32, 'CreateFileMappingW', 5, true);
hookNamedObj(kb, 'CreateMutexExW', 3, true);
hookNamedObj(kb, 'OpenFileMappingFromAppW', 2, true);

// Log anche CreateFileW/A per sapere se apre qualche file "FalloutHwnd.dat" o simili
const cfw = kb.findExportByName('CreateFileW');
if (cfw) {
    Interceptor.attach(cfw, {
        onEnter: function (args) {
            try {
                const path = args[0].isNull() ? null : args[0].readUtf16String();
                if (path && /fallout|FO4/i.test(path)) console.log('[CreateFileW] ' + JSON.stringify(path));
            } catch (e) {}
        }
    });
}

console.log('[+] tracer armed');
