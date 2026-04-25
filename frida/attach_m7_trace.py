"""
Attach Frida M7 trace script to a running Fallout4.exe (Client A — main).

Usage (admin shell required for Frida ptrace):
    python frida\attach_m7_trace.py [pid]

If PID omitted, finds the FIRST Fallout4.exe in the local process list.
For multi-instance setups (Side A + Side B), pass the explicit PID of A
(visible in Task Manager or via `python -c "import frida; ..."`).

Output: prints all script log lines to stdout. Pipe to a file:
    python frida\attach_m7_trace.py > m7_trace.log
"""
import sys
import time
from pathlib import Path

import frida

SCRIPT = Path(__file__).parent / "13_m7_skin_bgsm_trace.js"


def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f"[ERR] {msg.get('description')}", flush=True)
    else:
        print(msg.get('payload', msg), flush=True)


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    dev = frida.get_local_device()

    if pid is None:
        # Auto-pick first Fallout4.exe — for multi-instance, pass PID
        # explicitly to disambiguate.
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

    print(f"[+] Script loaded. Tracing M7 hooks. Ctrl+C to detach.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Detaching (game continues running).", flush=True)


if __name__ == "__main__":
    main()
