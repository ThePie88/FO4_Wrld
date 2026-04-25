"""Receiver NPC-driver: Frida attach via PID, riceve pos di ALTRI peer e le scrive
dentro un target (default Codsworth 0x1CA7D).
Uso: python receiver_npc.py --pid <PID> --id <client_id> [--target-formid 0x1CA7D]"""
import argparse
import frida
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from packet import unpack, pack_hello, TYPE_POS

SERVER = ("127.0.0.1", 31337)

FRIDA_JS_TEMPLATE = r"""
const LOOKUP_RVA = 0x311850;
const POS_OFF = 0xD0;
const ROT_OFF = 0xC0;
const TARGET_FORMID = __FORMID__;

const base = Process.findModuleByName('Fallout4.exe').base;
const lookupByFormID = new NativeFunction(base.add(LOOKUP_RVA), 'pointer', ['uint32']);

let target = lookupByFormID(TARGET_FORMID);
console.log('[js] target Actor @ ' + target);

let writes = 0;
function onMsg(msg) {
    try {
        if (target.isNull()) {
            target = lookupByFormID(TARGET_FORMID);
            if (target.isNull()) { recv(onMsg); return; }
        }
        target.add(POS_OFF).writeFloat(msg.x);
        target.add(POS_OFF + 4).writeFloat(msg.y);
        target.add(POS_OFF + 8).writeFloat(msg.z);
        target.add(ROT_OFF).writeFloat(msg.rx);
        target.add(ROT_OFF + 4).writeFloat(msg.ry);
        target.add(ROT_OFF + 8).writeFloat(msg.rz);
        writes++;
        if (writes % 500 === 0) console.log('[js] wrote ' + writes);
    } catch (e) { console.log('[js err] ' + e); }
    recv(onMsg);
}
recv(onMsg);
console.log('[js] recv armed');
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--id', required=True)
    ap.add_argument('--target-formid', default='0x1CA7D')
    ap.add_argument('--exclude-id', default=None, help='ignora pacchetti da questo client id (local player)')
    args = ap.parse_args()

    target_formid = int(args.target_formid, 16) if args.target_formid.startswith('0x') else int(args.target_formid)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    print(f"[npc-drv id={args.id} pid={args.pid}] port {sock.getsockname()[1]} target formid 0x{target_formid:X}")

    def keepalive():
        while True:
            sock.sendto(pack_hello(args.id), SERVER)
            time.sleep(2.0)
    threading.Thread(target=keepalive, daemon=True).start()

    dev = frida.get_local_device()
    try:
        session = dev.attach(args.pid)
    except Exception as e:
        print(f"[npc-drv] attach pid={args.pid} failed: {e}"); sys.exit(1)

    js = FRIDA_JS_TEMPLATE.replace("__FORMID__", hex(target_formid))
    script = session.create_script(js)
    script.on('message', lambda m, d: print(f"[js {args.id}] {m.get('payload', m)}"))
    script.load()
    print(f"[npc-drv {args.id}] Frida armed. Listening UDP...")

    dispatched = 0
    while True:
        data, addr = sock.recvfrom(2048)
        m = unpack(data)
        if m is None or m['type'] != TYPE_POS:
            continue
        if m['id'] == args.id:
            continue  # skip self
        if args.exclude_id and m['id'] == args.exclude_id:
            continue  # skip local player
        script.post({
            'x': m['x'], 'y': m['y'], 'z': m['z'],
            'rx': m['rx'], 'ry': m['ry'], 'rz': m['rz']
        })
        dispatched += 1
        if dispatched % 500 == 0:
            print(f"[npc-drv {args.id}] dispatched {dispatched}")

if __name__ == "__main__":
    main()
