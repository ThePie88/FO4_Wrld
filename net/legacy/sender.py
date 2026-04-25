"""Sender: Frida attach a FO4 via PID, streamma pos+rot player 20Hz.
Uso: python sender.py --pid <PID> --id <client_id>"""
import argparse
import frida
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from packet import pack_pos, pack_hello

SERVER = ("127.0.0.1", 31337)

FRIDA_JS = r"""
const SINGLETON_RVA = 0x32D2260;
const ROT_OFF = 0xC0;
const POS_OFF = 0xD0;
const base = Process.findModuleByName('Fallout4.exe').base;
const singleton = base.add(SINGLETON_RVA);
setInterval(() => {
    try {
        const pp = singleton.readPointer();
        if (pp.isNull()) return;
        send({
            x:  pp.add(POS_OFF).readFloat(),
            y:  pp.add(POS_OFF + 4).readFloat(),
            z:  pp.add(POS_OFF + 8).readFloat(),
            rx: pp.add(ROT_OFF).readFloat(),
            ry: pp.add(ROT_OFF + 4).readFloat(),
            rz: pp.add(ROT_OFF + 8).readFloat()
        });
    } catch (e) {}
}, 50);
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, required=True, help='PID of Fallout4.exe')
    ap.add_argument('--id', required=True, help='client id (max 15 chars)')
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = [0]; sent = [0]

    def keepalive():
        while True:
            sock.sendto(pack_hello(args.id), SERVER)
            time.sleep(2.0)

    def on_message(msg, data):
        if msg.get('type') == 'error':
            print(f"[sender-js ERR] {msg.get('description')}", file=sys.stderr); return
        if msg.get('type') != 'send': return
        p = msg['payload']
        pkt = pack_pos(args.id, seq[0], p['x'], p['y'], p['z'], p['rx'], p['ry'], p['rz'])
        sock.sendto(pkt, SERVER)
        seq[0] += 1; sent[0] += 1
        if sent[0] % 500 == 0:
            print(f"[sender {args.id}] sent {sent[0]}")

    dev = frida.get_local_device()
    try:
        session = dev.attach(args.pid)
    except Exception as e:
        print(f"[sender] attach pid={args.pid} failed: {e}"); sys.exit(1)
    script = session.create_script(FRIDA_JS)
    script.on('message', on_message)
    script.load()
    threading.Thread(target=keepalive, daemon=True).start()
    print(f"[sender id={args.id} pid={args.pid}] streaming -> {SERVER}")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[sender {args.id}] sent={sent[0]}")

if __name__ == "__main__":
    main()
