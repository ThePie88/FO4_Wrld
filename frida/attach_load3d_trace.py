"""
Attach Frida Load3D trace script to a running Fallout4.exe.

Usage (admin shell required for Frida ptrace):
    python frida\attach_load3d_trace.py [pid]

If PID omitted, finds the FIRST Fallout4.exe in the local process list.
For multi-instance setups (Side A + Side B), pass explicit PID.

Output: stdout. Recommended:
    python frida\attach_load3d_trace.py > frida\load3d_trace.log

Capture protocol:
    1. Launch FO4 normally; wait until main menu
    2. Start this attacher
    3. In game: load a save (or `coc QASmoke`) — triggers PlayerCharacter::Load3D
    4. Walk around, open inventory, fast-travel — triggers reloads
    5. Ctrl+C to detach
    6. Inspect frida\load3d_trace.log:
       grep -E '^\\[load3d\\]' load3d_trace.log     # Load3D entry/exit + actor offsets
       grep -E '^\\[nif\\]'    load3d_trace.log     # NIF loads inside Load3D scope
       grep -E '^\\[bgsm\\]'   load3d_trace.log     # bgsm loads
       grep -E '^\\[bone\\]'   load3d_trace.log     # _skin fallback hits
       grep -E '^\\[stalker\\]' load3d_trace.log    # only if ENABLE_STALKER=true in JS
"""
import sys
import time
from pathlib import Path

import frida

SCRIPT = Path(__file__).parent / "14_load3d_callees_trace.js"


def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f"[ERR] {msg.get('description')}", flush=True)
    else:
        print(msg.get('payload', msg), flush=True)


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    dev = frida.get_local_device()

    if pid is None:
        procs = [p for p in dev.enumerate_processes() if p.name == 'Fallout4.exe']
        if not procs:
            print("[ERR] No Fallout4.exe process found. Launch the game first.")
            sys.exit(1)
        if len(procs) > 1:
            print(f"[INFO] Multiple Fallout4.exe found:")
            for p in procs:
                print(f"  pid={p.pid} name={p.name}")
            print(f"[INFO] Auto-picking first: pid={procs[0].pid}")
            print(f"[INFO] If wrong, rerun with explicit pid arg.")
        pid = procs[0].pid

    print(f"[+] Attaching to pid={pid} ...", flush=True)
    session = dev.attach(pid)

    src = SCRIPT.read_text(encoding='utf-8')
    script = session.create_script(src)
    script.on('message', on_message)
    script.load()

    print(f"[+] Script loaded. Tracing Load3D + callees. Ctrl+C to detach.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Detaching (game continues running).", flush=True)


if __name__ == "__main__":
    main()
