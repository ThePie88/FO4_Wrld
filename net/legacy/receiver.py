"""Receiver binario: unpack struct, stampa solo quando cambia (delta pos/yaw)."""
import math
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from packet import unpack, pack_hello, TYPE_POS

SERVER = ("127.0.0.1", 31337)
CLIENT_ID = "viewer_B"
POS_THR = 0.5
YAW_THR_DEG = 1.0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 0))
print(f"[recv] id={CLIENT_ID} port {sock.getsockname()[1]} server {SERVER}")

def keepalive():
    while True:
        sock.sendto(pack_hello(CLIENT_ID), SERVER)
        time.sleep(2.0)
threading.Thread(target=keepalive, daemon=True).start()

last_seq = {}
last_printed = {}
received = 0
dropped = 0
last_stats = time.time()

while True:
    data, addr = sock.recvfrom(2048)
    msg = unpack(data)
    if msg is None or msg['type'] != TYPE_POS:
        continue

    pid = msg['id']
    seq = msg['seq']
    prev = last_seq.get(pid, -1)
    if seq <= prev and prev != -1:
        dropped += 1; continue
    if seq > prev + 1 and prev != -1:
        dropped += (seq - prev - 1)
    last_seq[pid] = seq
    received += 1

    x, y, z = msg['x'], msg['y'], msg['z']
    yaw = msg['rz'] * 180.0 / math.pi

    lp = last_printed.get(pid)
    should_print = lp is None
    if lp is not None:
        lx, ly, lz, lyaw = lp
        dpos = abs(x - lx) + abs(y - ly) + abs(z - lz)
        dyaw = abs(yaw - lyaw)
        if dyaw > 180: dyaw = 360 - dyaw
        should_print = dpos > POS_THR or dyaw > YAW_THR_DEG

    if should_print:
        print(f"[{pid}] seq={seq:5d} pos=({x:9.1f},{y:9.1f},{z:8.1f}) yaw={yaw:6.1f}deg")
        last_printed[pid] = (x, y, z, yaw)

    now = time.time()
    if now - last_stats > 5.0:
        print(f"  -- stats: rx={received} drop={dropped} peers={list(last_seq.keys())}")
        last_stats = now
