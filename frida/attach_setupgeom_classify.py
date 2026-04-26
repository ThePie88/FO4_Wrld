"""Attach M8P3.10 SetupGeometry classify probe."""
import sys, time, io
from pathlib import Path
import frida

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

SCRIPT = Path(__file__).parent / "20_setupgeom_classify.js"


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
            print("[ERR] No Fallout4.exe running.")
            sys.exit(1)
        pid = procs[0].pid
    print(f"[+] Attaching pid={pid}", flush=True)
    session = dev.attach(pid)
    src = SCRIPT.read_text(encoding='utf-8')
    script = session.create_script(src)
    script.on('message', on_message)
    script.load()
    print("[+] Wait for ticks at 3s/6s/9s/... then Ctrl+C after ~15s.", flush=True)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Detaching.", flush=True)


if __name__ == "__main__":
    main()
