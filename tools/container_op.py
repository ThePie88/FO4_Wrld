"""Manual container op injector — appends a JSON line to the per-peer
ops file that the client's _manual_ops_loop drains every 500ms.

Usage:
    python tools/container_op.py --peer player_A take 0xDEAD01 0x1696A 0x23736 3
    python tools/container_op.py --peer player_B put  0xDEAD01 0x1696A 0x23736 1

After running, the client for that peer will:
  1. See the line within <= 500ms
  2. Call send_container_op() -> reliable CONTAINER_OP to server
  3. Server validates + persists + broadcasts
  4. The OTHER peer's client receives CONTAINER_BCAST and mirrors the state

Watch the [A] / [B] / [srv] terminals for logs like:
    [A] manual op: TAKE container=0xDEAD01/0x1696A item=0x23736 count=3
    [A] sent container op: kind=TAKE ...
    [srv] peers=2 stats={... 'rejections': N}
    [B] container op from A: kind=TAKE container=0xDEAD01/0x1696A item=0x23736 count=3 -> now 7

And check net/state_snapshot.json for the `containers` section to confirm
server-side persistence.

This tool is a development aid. Once the Frida container hook (A.8) is
live, the player's UI actions will generate these events automatically
and this helper will be obsolete.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Inject a manual container op for a peer (pre-Frida test aid).",
    )
    ap.add_argument("--peer", required=True,
                    help="client_id of the peer sending the op, e.g. player_A")
    ap.add_argument("op", choices=["take", "put"],
                    help="TAKE removes from container, PUT adds to container")
    ap.add_argument("container_base", type=str,
                    help="TESNPC/TESObjectCONT base formid (hex 0xDEAD01 or decimal)")
    ap.add_argument("container_cell", type=str,
                    help="parentCell formid (hex or decimal)")
    ap.add_argument("item_base", type=str,
                    help="item TESForm.formid (hex or decimal)")
    ap.add_argument("count", type=int,
                    help="how many (must be > 0)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    if args.count <= 0:
        print(f"error: count must be > 0 (got {args.count})", file=sys.stderr)
        return 2

    entry = {
        "op": args.op,
        "container_base": args.container_base,
        "container_cell": args.container_cell,
        "item_base": args.item_base,
        "count": args.count,
    }
    ops_path = REPO_ROOT / f"manual_ops_{args.peer}.jsonl"
    # Append so concurrent invocations don't clobber each other.
    with ops_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    print(f"queued for {args.peer}: {entry}")
    print(f"  file: {ops_path}")
    print(f"  client will pick it up within 500ms if connected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
