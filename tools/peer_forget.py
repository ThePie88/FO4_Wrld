r"""Make the server forget a player's character, offline: the next hello of
that identity is a first entry.

2026-10-05. Client A's save lineage was spoilt (a Pip-Boy that no longer
draws after a death inside power armour) and no clean checkpoint of its
character was left anywhere. The owner's decision: start A over, stock,
with the character creation and the genesis inventory. One journal record
(ServerState.forget_peer) drops the inventory record, the numbers, the
appearance, the checkpoints, the presence, the inventory digest and the
resume tokens of the peer; this tool also deletes the peer's custody files,
after copying them to <custody dir>/_forgotten/<peer>_<time>/ (the spoilt save
is the evidence for a vanilla run: whether the fault lives in the save or in
the DLL).
What the peer put in the world (its spawns, its crates) stays the world's.
At the next hello the server runs the first entry (the genesis save moved
onto the point) and, when started with --require-chargen, asks for the
character creation.

Usage (the game server must be stopped; the tool refuses otherwise):
  python tools/peer_forget.py --peer fwdaea9b724bd5f
  python tools/peer_forget.py --peer fwdaea9b724bd5f --apply
"""
from __future__ import annotations

import argparse
import logging
import shutil
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))           # server.auth imports net.protocol
sys.path.insert(0, str(ROOT / "net"))   # the server's own imports: server.*, protocol

from server.custody import CustodyStore  # noqa: E402
from server.journal import Journal  # noqa: E402
from server.persistence import restore_state  # noqa: E402
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
    ap.add_argument("--snapshot", type=Path, default=ROOT / "net" / "state_snapshot.json")
    ap.add_argument("--journal-dir", type=Path, default=ROOT / "net" / "state_snapshot_journal")
    ap.add_argument("--custody-dir", type=Path, default=ROOT / "net" / "state_checkpoints")
    ap.add_argument("--port", type=int, default=31337, help="the game server's UDP port")
    ap.add_argument("--apply", action="store_true", help="without it the tool only shows the plan")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

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
    store = CustodyStore(args.custody_dir)
    print(f"world loaded: snapshot + {replayed} journal record(s), head lsn {journal.head_lsn}")

    peer = args.peer
    inv = state.player_inventory(peer)
    st = state.player_stats(peer)
    recs = state.checkpoints(peer)
    pres = state.presence(peer)
    files = store.names(peer)
    print(f"{peer}:")
    print(f"  inventory record: {'%d line(s)' % len(inv.lines) if inv is not None else 'none'}")
    print(f"  numbers: {'level %d, %d perk(s)' % (st.level, len(st.perks)) if st is not None else 'none'}")
    print(f"  appearance: {'%d byte(s)' % len(state.appearance(peer)) if state.appearance(peer) else 'none'}")
    print(f"  checkpoints: {len(recs)} on record, {len(files)} file(s) in custody")
    print(f"  presence: {'yes' if pres is not None else 'none'}")
    spawns = [w for w in state.all_world_spawns() if w.spawner_peer == peer]
    print(f"  world objects announced by this peer: {len(spawns)} (they stay the world's)")
    if not args.apply:
        print("nothing written: run again with --apply")
        journal.close()
        return 0

    # The copy comes first: no destruction without the evidence kept.
    src = args.custody_dir / peer
    kept = None
    if files:
        kept = args.custody_dir / "_forgotten" / f"{peer}_{time.strftime('%Y%m%d_%H%M%S')}"
        try:
            kept.mkdir(parents=True, exist_ok=False)
            copied = 0
            for f in sorted(src.iterdir()):
                if f.is_file():
                    shutil.copy2(f, kept / f.name)
                    copied += 1
        except OSError as e:
            print(f"NOT DONE: could not keep a copy of the custody files in {kept}: {e}")
            journal.close()
            return 1
        print(f"{copied} custody file(s) copied to {kept}")
    gone = state.forget_peer(peer)
    pruned = store.keep_only(peer, set())
    ok = journal.flush()
    journal.close()
    what = ", ".join(f"{v} {k}" for k, v in gone.items()) or "nothing was on record"
    print(f"forgotten: {what}; {pruned} custody file(s) deleted; journal head lsn "
          f"{journal.head_lsn}, {'durable' if ok else 'NOT DURABLE: check the journal directory'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
