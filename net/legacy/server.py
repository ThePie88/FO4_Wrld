"""UDP hub multi-peer. Binary packet 44B. Hello = registra peer (no broadcast), Pos = broadcast agli altri."""
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from packet import SIZE, TYPE_HELLO, TYPE_POS, unpack

HOST = "127.0.0.1"
PORT = 31337
PEER_TIMEOUT = 5.0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
sock.settimeout(1.0)

peers = {}  # addr -> (last_seen, client_id)
relayed = 0

print(f"[server] UDP hub {HOST}:{PORT} | packet size {SIZE}B | peer timeout {PEER_TIMEOUT}s")

while True:
    now = time.time()
    stale = [a for a, (t, _) in peers.items() if now - t > PEER_TIMEOUT]
    for a in stale:
        cid = peers[a][1]
        del peers[a]
        print(f"[server] timeout peer {cid} at {a}")

    try:
        data, addr = sock.recvfrom(2048)
    except socket.timeout:
        continue

    msg = unpack(data)
    if msg is None:
        continue  # discard malformed

    if addr not in peers:
        print(f"[server] new peer {msg['id']!r} at {addr}")
    peers[addr] = (now, msg['id'])

    if msg['type'] == TYPE_HELLO:
        continue  # non broadcast

    # TYPE_POS -> broadcast a tutti gli altri
    for other in peers:
        if other == addr:
            continue
        try:
            sock.sendto(data, other)
        except Exception as e:
            print(f"[server] send err to {other}: {e}")

    relayed += 1
    if relayed % 500 == 0:
        print(f"[server] relayed {relayed} pos pkts | peers {[(a, c) for a,(t,c) in peers.items()]}")
