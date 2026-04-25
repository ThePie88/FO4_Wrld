"""
Spawner per FO4_b con DRM bypass Frida.
Uso: python spawn_fo4b.py
"""
import frida
import sys
import time
from pathlib import Path

EXE = r"C:\Users\filip\Desktop\FalloutWorld\FO4_b\Fallout4.exe"
SCRIPT = Path(__file__).parent / "07_bypass_drm.js"

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f"[SCRIPT ERROR] {msg.get('description', msg)}")
    elif msg.get('type') == 'log':
        print(f"[JS] {msg.get('payload', '')}")
    else:
        print(f"[MSG] {msg}")

def main():
    src = SCRIPT.read_text(encoding="utf-8")
    print(f"[+] Loading script from {SCRIPT}")

    dev = frida.get_local_device()
    print(f"[+] Device: {dev.name}")

    print(f"[+] Spawning {EXE}")
    pid = dev.spawn([EXE])
    print(f"[+] Spawned pid={pid} (suspended)")

    session = dev.attach(pid)
    print(f"[+] Attached to pid={pid}")

    script = session.create_script(src)
    script.on('message', on_message)
    script.load()
    print(f"[+] Script loaded, hooks armed")

    dev.resume(pid)
    print(f"[+] Process resumed")

    # Keep alive to print messages. Ctrl+C per uscire.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Detaching...")

if __name__ == "__main__":
    main()
