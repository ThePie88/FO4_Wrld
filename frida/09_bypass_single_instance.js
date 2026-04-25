// Bypass single-instance v4: FindWindow NULL + blocco SetForegroundWindow su hwnd esterni + traccia ExitProcess

console.log('[+] Bypass v4 loading');

function hookFindWindow(name, isUnicode) {
    const f = Process.getModuleByName('user32.dll').findExportByName(name);
    if (!f) return;
    Interceptor.attach(f, {
        onEnter: function (args) {
            try {
                const cn = args[0].isNull() ? null : (isUnicode ? args[0].readUtf16String() : args[0].readUtf8String());
                if (cn === 'Fallout4') { this.fake = true; console.log('[BYPASS] ' + name); }
            } catch (e) {}
        },
        onLeave: function (retval) { if (this.fake) retval.replace(ptr(0)); }
    });
}
function hookFindWindowEx(name, isUnicode) {
    const f = Process.getModuleByName('user32.dll').findExportByName(name);
    if (!f) return;
    Interceptor.attach(f, {
        onEnter: function (args) {
            try {
                const cn = args[2].isNull() ? null : (isUnicode ? args[2].readUtf16String() : args[2].readUtf8String());
                if (cn === 'Fallout4') { this.fake = true; console.log('[BYPASS] ' + name); }
            } catch (e) {}
        },
        onLeave: function (retval) { if (this.fake) retval.replace(ptr(0)); }
    });
}
hookFindWindow('FindWindowA', false);
hookFindWindow('FindWindowW', true);
hookFindWindowEx('FindWindowExA', false);
hookFindWindowEx('FindWindowExW', true);

// EnumWindows - spesso usato per scansionare tutte le finestre e trovare quella del gioco
const enumWin = Process.getModuleByName('user32.dll').findExportByName('EnumWindows');
if (enumWin) {
    Interceptor.replace(enumWin, new NativeCallback(function (cb, lparam) {
        console.log('[BLOCK] EnumWindows');
        return 1; // TRUE, non scansiona niente
    }, 'int', ['pointer', 'pointer']));
}

// GetClassNameA/W
function hookGetClass(name, isUnicode) {
    const f = Process.getModuleByName('user32.dll').findExportByName(name);
    if (!f) return;
    Interceptor.attach(f, {
        onLeave: function (retval) {
            if (retval.toInt32() > 0) {
                try {
                    const buf = this.context.rdx;
                    if (buf) {
                        const s = isUnicode ? buf.readUtf16String() : buf.readUtf8String();
                        if (s === 'Fallout4') {
                            // Cambia la stringa ritornata per ingannare il chiamante
                            if (isUnicode) buf.writeUtf16String('XxXxXxXx');
                            else buf.writeUtf8String('XxXxXxXx');
                            console.log('[MASK] ' + name + ' Fallout4 -> XxXxXxXx');
                        }
                    }
                } catch (e) {}
            }
        }
    });
}
hookGetClass('GetClassNameA', false);
hookGetClass('GetClassNameW', true);

// SetForegroundWindow — nopp se proveniente dalla seconda istanza
const setFg = Process.getModuleByName('user32.dll').findExportByName('SetForegroundWindow');
if (setFg) {
    Interceptor.replace(setFg, new NativeCallback(function (hwnd) {
        console.log('[BLOCK] SetForegroundWindow(' + hwnd + ')');
        return 1; // TRUE, ma non fa niente
    }, 'int', ['pointer']));
}

// NtTerminateProcess/ExitProcess/RtlExitUserProcess: blocca i primi 5 call su self
let exitBlocked = 0;
const MAX_BLOCKED_EXITS = 5;
const ntTermOrig = Process.getModuleByName('ntdll.dll').findExportByName('NtTerminateProcess');
if (ntTermOrig) {
    Interceptor.replace(ntTermOrig, new NativeCallback(function (procHandle, exitStatus) {
        const hex = procHandle.toString(16);
        if (hex.endsWith('ffffffff') || procHandle.isNull()) {
            exitBlocked++;
            console.log('[STOP-EXIT] NtTerminateProcess(self, 0x' + exitStatus.toString(16) + ') blocked #' + exitBlocked);
            if (exitBlocked <= MAX_BLOCKED_EXITS) {
                return 0; // STATUS_SUCCESS, ma non ha terminato niente
            }
        }
        // altrimenti passa: processo esterno o quit legittimo dopo i primi blocchi
        const fn = new NativeFunction(ntTermOrig, 'int', ['pointer', 'int']);
        return fn(procHandle, exitStatus.toInt32());
    }, 'int', ['pointer', 'int']));
}

const rtlExit = Process.getModuleByName('ntdll.dll').findExportByName('RtlExitUserProcess');
if (rtlExit) {
    Interceptor.replace(rtlExit, new NativeCallback(function (exitCode) {
        exitBlocked++;
        console.log('[STOP-EXIT] RtlExitUserProcess(0x' + exitCode.toString(16) + ') blocked #' + exitBlocked);
        if (exitBlocked <= MAX_BLOCKED_EXITS) return;
        const fn = new NativeFunction(rtlExit, 'void', ['int']);
        fn(exitCode);
    }, 'void', ['int']));
}

console.log('[+] Hooks armed (v4 aggressive)');
