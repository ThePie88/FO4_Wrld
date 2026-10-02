r"""Move a player inside their next checkpoint while the server is stopped.

L5 stage 3d (2026-09-29), the offline twin of what the server will do at a
death: the checkpoint the player's next boot would load is copied, the
player's position rewritten inside the copy (net/server/savepos.py), and the
copy booked as the player's newest checkpoint, in custody, through the
server's own journaled operations (net/server/respawn.py). At the next
boot the client fetches it from custody and the engine loads it: the player
stands on the point, with one loading screen.

This is live test #13 of RESEARCH_L5.md §8 3d: it proves the engine takes a
position written by the server before the death path is wired to it.

Usage (the game server must be stopped; the tool refuses otherwise):
  python tools/respawn_patch.py --peer fw697d1c84d3e62 --at=-55911.7,101867.7,8542.9
  python tools/respawn_patch.py --peer fw697d1c84d3e62 --at=-55911.7,101867.7,8542.9 --apply
  python tools/respawn_patch.py --peer fw697d1c84d3e62 --point sanctuary --apply
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
from server.respawn import RespawnError, RespawnPoint, make_respawn_checkpoint  # noqa: E402
from server.savepos import SaveFormatError, exterior_sky, read_position, read_worn_frame  # noqa: E402
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
    ap.add_argument("--at", default=None, metavar="X,Y,Z[,YAW]", help="the point, engine units, yaw in radians; write it --at=X,... when X is negative")
    ap.add_argument("--point", default=None, metavar="NAME", help="a named point of the server (sanctuary)")
    ap.add_argument("--snapshot", type=Path, default=ROOT / "net" / "state_snapshot.json")
    ap.add_argument("--journal-dir", type=Path, default=ROOT / "net" / "state_snapshot_journal")
    ap.add_argument("--custody-dir", type=Path, default=ROOT / "net" / "state_checkpoints")
    ap.add_argument("--port", type=int, default=31337, help="the game server's UDP port")
    ap.add_argument("--genesis", type=Path, default=None,
                    help="the genesis save, whose sky a checkpoint moved out of an interior gets "
                         "(default: [genesis] save of server.ini)")
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

    genesis = args.genesis
    if genesis is None:
        g = read_genesis_path(ROOT / "server.ini")
        genesis = (ROOT / g) if g and not Path(g).is_absolute() else (Path(g) if g else None)
    exterior_globals = None
    if genesis is not None:
        try:
            exterior_globals = exterior_sky(genesis.read_bytes())
            print(f"genesis save {genesis}: its sky goes to a checkpoint moved out of an interior")
        except (OSError, SaveFormatError) as e:
            print(f"genesis save {genesis} is not usable ({e}): an interior cannot be moved")
    else:
        print("no genesis save: an interior cannot be moved")

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

    src = state.checkpoint_to_boot(args.peer)
    if src is None:
        print(f"{args.peer} has no checkpoint: its next boot is the genesis save")
        journal.close()
        return 1
    print(f"next boot of {args.peer}: '{src.name}' (seq {src.seq}, {src.size} bytes, "
          f"{'in custody' if src.custody else 'NOT in custody'}, {src.status})")
    got = store.read(args.peer, src.name)
    if got is not None:
        try:
            _, mv = read_position(got[0])
            print(f"  the player stands at ({mv.pos[0]:.1f}, {mv.pos[1]:.1f}, {mv.pos[2]:.1f}) "
                  f"yaw {mv.rot[2]:.2f} in space 0x{mv.space:06X}")
            wf = read_worn_frame(got[0])
            if wf is not None:
                print(f"  wearing power armour frame 0x{wf.refid:06X} (saved at ({wf.move.pos[0]:.1f}, "
                      f"{wf.move.pos[1]:.1f}), flags 0x{wf.form_flags:08X}): it moves with the player")
        except SaveFormatError as e:
            print(f"  its position does not read: {e}")
    print(f"  target: ({point.x:.1f}, {point.y:.1f}, {point.z:.1f}) yaw {point.yaw:.2f}")
    if not args.apply:
        print("nothing written: run again with --apply")
        journal.close()
        return 0

    try:
        rec = make_respawn_checkpoint(state, store, args.peer, point, time.time() * 1000.0,
                                      exterior_globals=exterior_globals)
    except RespawnError as e:
        print(f"NOT DONE: {e}")
        journal.close()
        return 1
    ok = journal.flush()
    journal.close()
    print(f"booked '{rec.name}' ({rec.size} bytes) as the newest checkpoint of {args.peer}, in custody; "
          f"journal {'durable' if ok else 'NOT DURABLE: check the journal directory'}")
    print("at its next boot the client fetches it from custody and stands on the point")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
