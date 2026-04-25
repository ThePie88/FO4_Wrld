"""Launcher CLI entry point. Usage:

    python -m launcher.main --side A     # Steam + F4SE
    python -m launcher.main --side B     # ColdClient + FO4_b
    python -m launcher.main --side A --no-server   # don't auto-start server

Or double-click start_A.bat / start_B.bat.
"""
from __future__ import annotations

import argparse
import sys

from launcher import config, orchestrator


def main() -> int:
    ap = argparse.ArgumentParser(description="FalloutWorld one-click launcher")
    ap.add_argument("--side", choices=["A", "B", "a", "b"], required=True,
                    help="A=Steam+F4SE, B=ColdClient+FO4_b")
    ap.add_argument("--no-server", action="store_true",
                    help="don't auto-start server (use if you run it manually)")
    ap.add_argument("--python", default=sys.executable,
                    help="python executable for child processes")
    args = ap.parse_args()

    side = config.side_from_name(args.side)
    return orchestrator.run(side, start_server=not args.no_server, python_exe=args.python)


if __name__ == "__main__":
    sys.exit(main())
