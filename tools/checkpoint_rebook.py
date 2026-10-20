r"""Book the genesis save (or any save) as a player's newest checkpoint, offline.

2026-10-05. A player whose save lineage is spoilt (client A: a Pip-Boy that no
longer draws after a death inside power armour, no clean checkpoint left in
custody) starts again from the genesis save moved onto the founder's point,
exactly as a new character does at its first entry (server/respawn.py,
make_first_checkpoint): the engine boots a clean body, and the server's
record brings the rest back on top of it, the inventory lines (R1/R2), the
level, XP, perks and SPECIAL (R4). What that save held besides is what the
genesis holds. The old checkpoints stay in custody until the rotation drops
them.

--file books another save instead of the genesis (a vanilla save of the same
character, say); it goes through the same move onto the point.

Usage (the game server must be stopped; the tool refuses otherwise):
  python tools/checkpoint_rebook.py --peer fwdaea9b724bd5f --point sanctuary
  python tools/checkpoint_rebook.py --peer fwdaea9b724bd5f --point sanctuary --apply
  python tools/checkpoint_rebook.py --peer fwdaea9b724bd5f --at=-79857.5,89852.6,7821.7 --apply
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))           # server.auth imports net.protocol
sys.path.insert(0, str(ROOT / "net"))   # the server's own imports: server.*, protocol

from server.custody import CustodyStore  # noqa: E402
from server.journal import Journal  # noqa: E402
from server.main import parse_respawn, read_genesis_path  # noqa: E402
from server.persistence import restore_state  # noqa: E402
from server.respawn import RespawnError, RespawnPoint, make_first_checkpoint  # noqa: E402
from server.savepos import SaveFormatError, read_position  # noqa: E402
from server.state import ServerState  # noqa: E402


def server_running(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--peer", required=True, help="the player's peer id (fw...)")
    ap.add_argument("--at", default=None, metavar="X,Y,Z[,YAW]", help="the point, engine units")
    ap.add_argument("--point", default=None, metavar="NAME", help="a named point of the server (sanctuary)")
    ap.add_argument("--file", type=Path, default=None,
                    help="the save to book (default: the genesis save of server.ini)")
    ap.add_argument("--snapshot", type=Path, default=ROOT / "net" / "state_snapshot.json")
    ap.add_argument("--journal-dir", type=Path, default=ROOT / "net" / "state_snapshot_journal")
    ap.add_argument("--custody-dir", type=Path, default=ROOT / "net" / "state_checkpoints")
    ap.add_argument("--port", type=int, default=31337, help="the game server's UDP port")
    ap.add_argument("--apply", action="store_true", help="without it the tool only shows the plan")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if (args.at is None) == (args.point is None):
        ap.error("give exactly one of --at or --point")
    try:
        p = parse_respawn(args.at if args.at is not None else args.point)
    except ValueError as e:
        ap.error(str(e))
    if p is None:
        ap.error("the point is 'off'")
    point = RespawnPoint(p[0], p[1], p[2], p[3])

    if server_running(args.port):
        print(f"REFUSED: UDP port {args.port} is in use, the game server is running. Stop it first:"
              " two writers on one journal would corrupt it.")
        return 2

    source = args.file
    if source is None:
        g = read_genesis_path(ROOT / "server.ini")
        if not g:
            print("REFUSED: no [genesis] save in server.ini and no --file")
            return 2
        source = (ROOT / g) if not Path(g).is_absolute() else Path(g)
    try:
        data = source.read_bytes()
        _, mv = read_position(data)
    except (OSError, SaveFormatError) as e:
        print(f"REFUSED: {source} is not a save this tool can move: {e}")
        return 2

    state = ServerState()
    if restore_state(state, args.snapshot) is None:
        print(f"REFUSED: no snapshot at {args.snapshot}")
        return 2
    journal = Journal.open(args.journal_dir)
    replayed = journal.replay(state, after_lsn=state.applied_lsn)
    state.applied_lsn = max(state.applied_lsn, journal.head_lsn)
    state.journal = journal
    store = CustodyStore(args.custody_dir)
    print(f"world loaded: snapshot + {replayed} journal record(s), head lsn {journal.head_lsn}")

    recs = state.checkpoints(args.peer)
    identity_hex = recs[0].identity_hex if recs else ""
    if not identity_hex:
        print(f"REFUSED: {args.peer} has no checkpoint on record, so no identity to book under")
        journal.close()
        return 1
    print(f"{args.peer}: {len(recs)} checkpoint(s) on record, newest '{recs[0].name}'")
    print(f"source {source} ({len(data)} bytes): the player stands at ({mv.pos[0]:.1f}, "
          f"{mv.pos[1]:.1f}, {mv.pos[2]:.1f}) in space 0x{mv.space:06X}")
    print(f"target: ({point.x:.1f}, {point.y:.1f}, {point.z:.1f}) yaw {point.yaw:.2f}")
    print("the record (inventory, numbers) comes back on top at the boot; the world the save "
          "held is the save's own")
    if not args.apply:
        print("nothing written: run again with --apply")
        journal.close()
        return 0

    try:
        rec = make_first_checkpoint(state, store, args.peer, identity_hex, data, point,
                                    time.time() * 1000.0)
    except RespawnError as e:
        print(f"NOT DONE: {e}")
        journal.close()
        return 1
    gone = store.keep_only(args.peer, {r.name for r in state.checkpoints(args.peer)})
    ok = journal.flush()
    journal.close()
    print(f"booked '{rec.name}' ({rec.size} bytes) as the newest checkpoint of {args.peer}, in "
          f"custody; {gone} old file(s) pruned; journal head lsn {journal.head_lsn}, "
          f"{'durable' if ok else 'NOT DURABLE: check the journal directory'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
