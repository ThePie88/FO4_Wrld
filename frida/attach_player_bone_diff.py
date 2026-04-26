"""
Attach M8P3.5 player-bone runtime diff. See JS for protocol.

Usage (admin shell):
    python frida\attach_player_bone_diff.py > frida\player_bone_diff.log
"""
import sys, time
from pathlib import Path
import frida

SCRIPT = Path(__file__).parent / "15_player_bone_runtime_diff.js"


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
            print("[ERR] No Fallout4.exe process. Launch FO4 first.")
            sys.exit(1)
        pid = procs[0].pid

    print(f"[+] Attaching to pid={pid}", flush=True)
    session = dev.attach(pid)
    src = SCRIPT.read_text(encoding='utf-8')
    script = session.create_script(src)
    script.on('message', on_message)
    script.load()
    print("[+] Loaded. Ctrl+C to detach.", flush=True)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Detaching.", flush=True)


if __name__ == "__main__":
    main()
