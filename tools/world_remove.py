r"""Remove objects from the server's world while the server is stopped.

L5 test housekeeping (2026-09-28). The world lives in the snapshot plus the
journal replayed over it. This tool opens both exactly as the server does at
start (restore_state, Journal.open, replay from the snapshot's mark), removes
the chosen spawned objects through the server's own journaled operation
(ServerState.remove_world_spawn), and makes the removals durable. The next
server start replays them: nothing is edited by hand.

A copy of a removed object saved inside a player's checkpoint is purged by
that client at its next load, through the world manifest of the checkpoint.

Usage (the game server must be stopped; the tool refuses otherwise):
  python tools/world_remove.py --base 0x2079E            # list only
  python tools/world_remove.py --base 0x2079E --apply    # remove them
  python tools/world_remove.py --wid 61 --wid 65 --apply
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "net"))

from server.journal import Journal  # noqa: E402
from server.persistence import restore_state  # noqa: E402
from server.state import ServerState  # noqa: E402

PA_FRAME_BASE = 0x2079E


def server_running(port: int) -> bool:
    """True when something holds the server's UDP port."""
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
    ap.add_argument("--snapshot", type=Path, default=ROOT / "net" / "state_snapshot.json")
    ap.add_argument("--journal-dir", type=Path, default=ROOT / "net" / "state_snapshot_journal")
    ap.add_argument("--port", type=int, default=31337, help="the game server's UDP port")
    ap.add_argument("--base", type=lambda v: int(v, 0), action="append", default=[],
                    help=f"remove every object with this base form (PA frame: 0x{PA_FRAME_BASE:X})")
    ap.add_argument("--wid", type=int, action="append", default=[], help="remove this world id")
    ap.add_argument("--apply", action="store_true", help="without it the tool only lists")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if not args.base and not args.wid:
        ap.error("name at least one --base or --wid")
    if server_running(args.port):
        print(f"REFUSED: UDP port {args.port} is in use, the game server is running. Stop it first:"
              " two writers on one journal would corrupt it.")
        return 2

    state = ServerState()
    if restore_state(state, args.snapshot) is None:
        print(f"REFUSED: no snapshot at {args.snapshot}")
        return 2
    journal = Journal.open(args.journal_dir)
    replayed = journal.replay(state, after_lsn=state.applied_lsn)
    state.applied_lsn = max(state.applied_lsn, journal.head_lsn)
    state.journal = journal
    print(f"world loaded: snapshot + {replayed} journal record(s), head lsn {journal.head_lsn}, "
          f"{len(state.all_world_spawns())} spawned object(s)")

    victims = [w for w in state.all_world_spawns()
               if w.wid in args.wid or w.base_form_id in args.base]
    for w in victims:
        worn = f", worn by {w.worn_by_peer_id}" if w.worn_by_peer_id else ""
        print(f"  wid {w.wid:4d} base 0x{w.base_form_id:08X} by {w.spawner_peer or '?'} at "
              f"({w.px:.0f}, {w.py:.0f}, {w.pz:.0f}) cell 0x{w.cell_id:X}, "
              f"{len(w.pieces or [])} piece(s){worn}")
    gone = {w.wid for w in victims}
    for p in state.all_presence():
        if getattr(p, "worn_frame_wid", 0) in gone:
            print(f"  NOTE: presence of {p.peer_id} says it wears wid {p.worn_frame_wid}")

    if not victims:
        print("nothing matches")
        journal.close()
        return 0
    if not args.apply:
        print(f"{len(victims)} object(s) would be removed: run again with --apply")
        journal.close()
        return 0

    removed = sum(1 for w in victims if state.remove_world_spawn(w.wid))
    ok = journal.flush()
    journal.close()
    print(f"{removed} object(s) removed, journal head lsn {journal.head_lsn}, "
          f"{'durable' if ok else 'NOT DURABLE: check the journal directory'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
