"""
Poll for Fallout4.exe to appear, then immediately attach the load3d trace
script. Designed for the auto-loadgame flow where the window between
"FO4 process exists" and "player Load3D fires" is ~5-10 seconds.

Usage:
    python frida\wait_and_attach_load3d.py > frida\load3d_trace.log

Polls every 200ms, max 120s before giving up.
"""
import sys
import time
from pathlib import Path

import frida

SCRIPT = Path(__file__).parent / "14_load3d_callees_trace.js"
POLL_INTERVAL = 0.02   # 20ms — was 200ms, 10x faster process detection
TIMEOUT_S = 60


def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f"[ERR] {msg.get('description')}", flush=True)
    else:
        print(msg.get('payload', msg), flush=True)


def main():
    dev = frida.get_local_device()
    print(f"[+] Polling for Fallout4.exe (every {int(POLL_INTERVAL*1000)}ms, timeout {TIMEOUT_S}s)...", flush=True)
    # Pre-read script source so attach->load is back-to-back (no disk wait inline)
    src = SCRIPT.read_text(encoding='utf-8')
    print(f"[+] Script pre-loaded ({len(src)} bytes)", flush=True)

    t_start = time.time()
    deadline = t_start + TIMEOUT_S
    pid = None
    while time.time() < deadline:
        procs = [p for p in dev.enumerate_processes() if p.name == 'Fallout4.exe']
        if procs:
            pid = procs[0].pid
            t_found = time.time() - t_start
            print(f"[+] FOUND Fallout4.exe pid={pid} (waited {t_found*1000:.0f}ms)", flush=True)
            break
        time.sleep(POLL_INTERVAL)

    if pid is None:
        print(f"[ERR] Timeout: no Fallout4.exe in {TIMEOUT_S}s", flush=True)
        sys.exit(1)

    t0 = time.time()
    try:
        session = dev.attach(pid)
    except Exception as e:
        print(f"[ERR] Attach failed: {e}", flush=True)
        print(f"[HINT] If 'AccessDenied', re-run from Admin PowerShell.", flush=True)
        sys.exit(2)
    print(f"[+] dev.attach took {(time.time()-t0)*1000:.0f}ms", flush=True)

    t0 = time.time()
    script = session.create_script(src)
    script.on('message', on_message)
    print(f"[+] create_script took {(time.time()-t0)*1000:.0f}ms", flush=True)

    t0 = time.time()
    script.load()
    print(f"[+] script.load took {(time.time()-t0)*1000:.0f}ms — HOOKS LIVE", flush=True)
    print(f"[+] Total: process found -> hooks live = {(time.time()-t_start)*1000:.0f}ms", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Detaching.", flush=True)


if __name__ == "__main__":
    main()
