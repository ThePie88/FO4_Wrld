// Logger ampio: FindWindow, CreateEvent, CreateFileMapping, SetForegroundWindow.

console.log('[+] Broad single-instance detector hooks loading');

function hookFn(modName, fnName, argsExtractor) {
    const mod = Process.getModuleByName(modName);
    if (!mod) return;
    const f = mod.findExportByName(fnName);
    if (!f) return;
    console.log('[+] ' + modName + '!' + fnName);
    Interceptor.attach(f, {
        onEnter: function (args) {
            try {
                const info = argsExtractor(args);
                if (info) console.log('[' + fnName + '] ' + info);
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this._skip) return;
        }
    });
}

// FindWindowA/W: (className, windowName)
hookFn('user32.dll', 'FindWindowA', args => {
    const cn = args[0].isNull() ? '<NULL>' : args[0].readUtf8String();
    const wn = args[1].isNull() ? '<NULL>' : args[1].readUtf8String();
    return 'class=' + JSON.stringify(cn) + ' title=' + JSON.stringify(wn);
});
hookFn('user32.dll', 'FindWindowW', args => {
    const cn = args[0].isNull() ? '<NULL>' : args[0].readUtf16String();
    const wn = args[1].isNull() ? '<NULL>' : args[1].readUtf16String();
    return 'class=' + JSON.stringify(cn) + ' title=' + JSON.stringify(wn);
});
hookFn('user32.dll', 'FindWindowExA', args => {
    const cn = args[2].isNull() ? '<NULL>' : args[2].readUtf8String();
    const wn = args[3].isNull() ? '<NULL>' : args[3].readUtf8String();
    return 'class=' + JSON.stringify(cn) + ' title=' + JSON.stringify(wn);
});
hookFn('user32.dll', 'FindWindowExW', args => {
    const cn = args[2].isNull() ? '<NULL>' : args[2].readUtf16String();
    const wn = args[3].isNull() ? '<NULL>' : args[3].readUtf16String();
    return 'class=' + JSON.stringify(cn) + ' title=' + JSON.stringify(wn);
});

// CreateEventA/W (lpEventAttributes, bManualReset, bInitialState, lpName)
hookFn('kernel32.dll', 'CreateEventA', args => {
    const n = args[3].isNull() ? '<NULL>' : args[3].readUtf8String();
    return 'name=' + JSON.stringify(n);
});
hookFn('kernel32.dll', 'CreateEventW', args => {
    const n = args[3].isNull() ? '<NULL>' : args[3].readUtf16String();
    return 'name=' + JSON.stringify(n);
});

// CreateFileMappingA/W (hFile, lpAttr, protect, sizeHigh, sizeLow, lpName)
hookFn('kernel32.dll', 'CreateFileMappingA', args => {
    const n = args[5].isNull() ? '<NULL>' : args[5].readUtf8String();
    return n && n !== '<NULL>' ? 'name=' + JSON.stringify(n) : null;
});
hookFn('kernel32.dll', 'CreateFileMappingW', args => {
    const n = args[5].isNull() ? '<NULL>' : args[5].readUtf16String();
    return n && n !== '<NULL>' ? 'name=' + JSON.stringify(n) : null;
});

// SetForegroundWindow e SendMessage possono essere chiamati dalla seconda istanza
hookFn('user32.dll', 'SetForegroundWindow', args => 'hwnd=' + args[0]);
hookFn('user32.dll', 'BringWindowToTop', args => 'hwnd=' + args[0]);
hookFn('user32.dll', 'AllowSetForegroundWindow', args => 'pid=' + args[0]);

console.log('[+] Hooks done');
