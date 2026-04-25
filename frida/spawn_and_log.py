"""
Spawn FO4_b/Fallout4.exe con mutex logger, stampa tutto alla console.
"""
import frida
import sys
import time
from pathlib import Path

EXE = r"C:\Users\filip\Desktop\FalloutWorld\FO4_b\Fallout4.exe"
SCRIPT = Path(__file__).parent / "09_bypass_single_instance.js"

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f"[ERR] {msg.get('description')}")
    else:
        print(msg.get('payload', msg))

def main():
    src = SCRIPT.read_text(encoding="utf-8")
    dev = frida.get_local_device()
    pid = dev.spawn([EXE])
    print(f"[+] Spawned pid={pid}")
    session = dev.attach(pid)
    script = session.create_script(src)
    script.on('message', on_message)
    script.load()
    dev.resume(pid)
    print(f"[+] Resumed. Gioco running. Ctrl+C per detach (il gioco continua).")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[+] Detach (game keeps running).")

if __name__ == "__main__":
    main()
