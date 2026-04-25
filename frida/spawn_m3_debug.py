"""
M3.2 rotation crash tracer.

Usage:
  1. Start the game normally via FoM.exe (launches Client A + Client B)
  2. In parallel, run:  python frida/spawn_m3_debug.py
  3. The script polls for FO4_b's Fallout4.exe, attaches Frida with the
     12_m3_rotation_trace.js hooks, and waits for the crash.
  4. When Client B crashes, the exception handler prints RIP + registers
     + backtrace. Also prints per-call state of UpdateDownwardPass calls
     on the injected cube leading up to the crash.

Note: safe to run before or after FoM.exe. If FO4_b isn't running yet,
the script polls every 1s until it sees the process.
"""
import frida
import psutil
import time
import sys
from pathlib import Path

FO4B_EXE_PATH = r"C:\Users\filip\Desktop\FalloutWorld\FO4_b\Fallout4.exe"
SCRIPT_PATH = Path(__file__).parent / "12_m3_rotation_trace.js"


def find_fo4b_pid():
    """Return the PID of the Fallout4.exe instance whose executable path
    matches FO4_b (not the Steam install)."""
    target = Path(FO4B_EXE_PATH).resolve()
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == 'fallout4.exe':
                exe = proc.info['exe']
                if exe and Path(exe).resolve() == target:
                    return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def on_message(msg, data):
    if msg.get('type') == 'error':
        desc = msg.get('description', msg)
        stack = msg.get('stack', '')
        print(f"[SCRIPT ERROR] {desc}", flush=True)
        if stack:
            print(stack, flush=True)
    elif msg.get('type') == 'log':
        print(msg.get('payload', ''), flush=True)
    else:
        print(msg, flush=True)


def main():
    print(f"[m3-trace] Target: {FO4B_EXE_PATH}")
    print(f"[m3-trace] Script: {SCRIPT_PATH}")
    print(f"[m3-trace] Polling for FO4_b's Fallout4.exe...")
    print(f"[m3-trace] (launch FoM.exe now if you haven't)")

    pid = None
    tries = 0
    while pid is None:
        pid = find_fo4b_pid()
        if pid is None:
            tries += 1
            if tries % 10 == 0:
                print(f"[m3-trace] ...still waiting ({tries}s)")
            time.sleep(1)

    print(f"[m3-trace] Found FO4_b pid={pid} — attaching")

    src = SCRIPT_PATH.read_text(encoding="utf-8")
    dev = frida.get_local_device()
    session = dev.attach(pid)
    print(f"[m3-trace] Attached")

    script = session.create_script(src)
    script.on('message', on_message)
    script.load()
    print(f"[m3-trace] Script loaded — hooks armed")
    print(f"[m3-trace] Ctrl+C to detach and exit")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[m3-trace] Detaching...")
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[m3-trace] fatal: {e}", file=sys.stderr)
        sys.exit(1)
