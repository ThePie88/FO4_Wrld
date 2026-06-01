// 21_crash_diag.js — FalloutWorld crash diagnostic via Frida.
//
// Captures access violations + main-thread freeze signals while the user
// reproduces a crash. Writes structured records to
// `FalloutWorld\frida_crash.log` for post-mortem.
//
// What it captures
// ----------------
//   1. Access violations / first-chance exceptions on any thread, BEFORE
//      Fallout4.exe's own SEH frames see them. Each record dumps:
//        - exception type + thread id
//        - faulting RIP (with Fallout4.exe-relative offset)
//        - faulting memory address (if applicable) + access kind
//        - register snapshot (rax, rcx, rdx, r8, r9, rsp, rbp)
//        - up-to-20-frame backtrace (Fallout4.exe RVA where possible)
//
//   2. Main-thread RIP sampler (~10 Hz). If the RIP stays in the same
//      8 KB window for > 2.5 s, log it as a freeze candidate with backtrace.
//      Catches tight loops / spinlocks / deadlocks that don't raise
//      exceptions.
//
// Usage (admin PowerShell, after FO4 is running and the player is in-game)
// -----------------------------------------------------------------------
//   frida -p <FO4 PID> -l 21_crash_diag.js
//
// Both clients can be instrumented in parallel — just run two attached
// frida sessions, each pointing at one PID. The log path includes the PID
// so the two streams don't clobber.

'use strict';

// ---------------------------------------------------------------- log file
const LOG_DIR  = 'C:\\Users\\filip\\Desktop\\FalloutWorld';
const LOG_PATH = `${LOG_DIR}\\frida_crash.${Process.id}.log`;

let _fd = null;
try { _fd = new File(LOG_PATH, 'a'); } catch (e) {
    console.log(`[crash-diag] cannot open log file ${LOG_PATH}: ${e}`);
}

function log(msg) {
    const ts = new Date().toISOString();
    const line = `[${ts}] ${msg}\n`;
    if (_fd) {
        try { _fd.write(line); _fd.flush(); } catch (e) {}
    }
    console.log(`[${ts}] ${msg}`);
}

log('===========================================================');
log(`=== FRIDA CRASH DIAG ATTACHED  pid=${Process.id} ===`);
log(`=== log file: ${LOG_PATH} ===`);

// ------------------------------------------------------------ FO4 module
const fo4 = Process.findModuleByName('Fallout4.exe');
if (!fo4) {
    log('[FATAL] Fallout4.exe module not found in target — abort');
    throw new Error('No Fallout4.exe module');
}
const baseAddr = fo4.base;
const baseEnd  = baseAddr.add(fo4.size);
log(`Fallout4.exe base=${baseAddr} size=0x${fo4.size.toString(16)} end=${baseEnd}`);

function rva(p) {
    if (p === null || p.isNull()) return '<null>';
    if (p.compare(baseAddr) >= 0 && p.compare(baseEnd) < 0) {
        return `+0x${p.sub(baseAddr).toString(16)}`;
    }
    // Try other modules so the backtrace is readable
    const m = Process.findModuleByAddress(p);
    if (m) return `${m.name}+0x${p.sub(m.base).toString(16)}`;
    return `extern@${p}`;
}

// ----------------------------------------------------------- exception trap
// Process.setExceptionHandler runs at first-chance, before any __try frame
// in Fallout4.exe handles it. Returning false lets the program continue to
// its own SEH chain (so we don't change behaviour, just observe).
let excSeen = 0;
Process.setExceptionHandler(details => {
    try {
        excSeen++;
        const tid  = Process.getCurrentThreadId();
        const ctx  = details.context;
        const rip  = ctx.rip;
        let memInfo = '';
        if (details.memory) {
            const ma = details.memory.address;
            memInfo = ` mem=${ma} (${rva(ma)}) op=${details.memory.operation || '?'}`;
        }
        log(`[EXC #${excSeen}] type=${details.type} tid=${tid} ` +
            `rip=${rip} (${rva(rip)})${memInfo}`);
        log(`[EXC #${excSeen}] regs: ` +
            `rax=${ctx.rax} rcx=${ctx.rcx} rdx=${ctx.rdx} ` +
            `r8=${ctx.r8} r9=${ctx.r9} rsp=${ctx.rsp} rbp=${ctx.rbp}`);
        try {
            const bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
            if (bt && bt.length) {
                const top = bt.slice(0, 20).map(p => `  ${p} (${rva(p)})`).join('\n');
                log(`[EXC #${excSeen}] backtrace:\n${top}`);
            } else {
                log(`[EXC #${excSeen}] backtrace empty`);
            }
        } catch (e) {
            log(`[EXC #${excSeen}] backtrace failed: ${e.message}`);
        }
    } catch (e) {
        // never throw out of an exception handler
    }
    return false; // EXCEPTION_CONTINUE_SEARCH — let FO4's SEH have it
});
log('[EXC] handler installed (first-chance observer)');

// ---------------------------------------------------------- main thread
// Main thread is normally the lowest-tid thread executing inside Fallout4.exe
// at the moment of attach. Pick the first thread whose RIP is in [base,
// base+size). Fallback: the very first thread by enumeration order.
function pickMainThread() {
    const ts = Process.enumerateThreads();
    for (const t of ts) {
        try {
            const r = t.context.rip;
            if (r.compare(baseAddr) >= 0 && r.compare(baseEnd) < 0) return t.id;
        } catch (e) {}
    }
    return ts.length ? ts[0].id : null;
}
let mainTid = pickMainThread();
log(`[SAMPLER] candidate main thread tid=${mainTid} ` +
    `(of ${Process.enumerateThreads().length} total)`);

// --------------------------------------------------------- RIP sampler
// Poll the main thread's RIP at ~10 Hz. If it stays in the same 8 KB
// window (a single function more or less) for > 2.5 s, dump backtrace
// and flag freeze. Resumes silently when RIP moves out of the window.
const SAMPLE_MS       = 100;
const FREEZE_AFTER_MS = 2500;
const WINDOW_MASK     = ptr('0xFFFFFFFFFFFFE000');  // 8 KB grain

let lastWin     = ptr(0);
let winStartMs  = Date.now();
let inFreeze    = false;
const recent    = [];           // ring buffer of last 50 (rip, ts)
const RECENT_N  = 50;

setInterval(() => {
    let mt = null;
    const ts = Process.enumerateThreads();
    for (const t of ts) { if (t.id === mainTid) { mt = t; break; } }
    if (!mt) {
        // Main thread might have been recreated (unlikely on Windows) or our
        // pick was wrong. Try to repick.
        const np = pickMainThread();
        if (np !== null && np !== mainTid) {
            log(`[SAMPLER] main thread tid changed ${mainTid} → ${np}`);
            mainTid = np;
        }
        return;
    }
    let rip;
    try { rip = mt.context.rip; } catch (e) { return; }

    recent.push({ rip, ts: Date.now() });
    if (recent.length > RECENT_N) recent.shift();

    const win = rip.and(WINDOW_MASK);
    if (win.equals(lastWin)) {
        const stuckMs = Date.now() - winStartMs;
        if (stuckMs > FREEZE_AFTER_MS && !inFreeze) {
            inFreeze = true;
            log(`[FREEZE] main thread tid=${mainTid} stuck in 8 KB window ` +
                `${win} (rip=${rip} ${rva(rip)}) for ${stuckMs}ms`);
            try {
                const bt = Thread.backtrace(mt.context, Backtracer.ACCURATE);
                if (bt && bt.length) {
                    const top = bt.slice(0, 20).map(p => `  ${p} (${rva(p)})`).join('\n');
                    log(`[FREEZE] backtrace:\n${top}`);
                }
            } catch (e) {
                log(`[FREEZE] backtrace failed: ${e.message}`);
            }
            // Print last 10 RIP samples for context — useful when it's a
            // tight loop bouncing between a few instructions.
            const tail = recent.slice(-10).map(s =>
                `  ${new Date(s.ts).toISOString().slice(11,23)} rip=${s.rip} (${rva(s.rip)})`
            ).join('\n');
            log(`[FREEZE] last 10 RIP samples:\n${tail}`);
        }
    } else {
        if (inFreeze) {
            log(`[FREEZE] released — rip=${rip} (${rva(rip)})`);
            inFreeze = false;
        }
        lastWin     = win;
        winStartMs  = Date.now();
    }
}, SAMPLE_MS);
log(`[SAMPLER] running at ${1000/SAMPLE_MS} Hz, freeze threshold ${FREEZE_AFTER_MS} ms`);

log('=== SETUP COMPLETE — waiting for crash event ===');
