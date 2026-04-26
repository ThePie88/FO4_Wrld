"""Launcher CLI entry point. Usage:

    python -m launcher.main --side A     # Steam + F4SE
    python -m launcher.main --side B     # ColdClient + FO4_b
    python -m launcher.main --side A --no-server   # don't auto-start server

Or double-click start_A.bat / start_B.bat.
"""
from __future__ import annotations

import argparse
import dataclasses
import sys

from launcher import config, orchestrator


def main() -> int:
    ap = argparse.ArgumentParser(description="FalloutWorld one-click launcher")
    ap.add_argument("--side", choices=["A", "B", "a", "b"], required=True,
                    help="A=Steam+F4SE, B=ColdClient+FO4_b")
    ap.add_argument("--no-server", action="store_true",
                    help="don't auto-start server (use if you run it manually)")
    ap.add_argument("--no-auto-load", action="store_true",
                    help="disable B3.b auto-load — main menu shows normally "
                         "(useful for Frida tracing of fresh PC::Load3D)")
    ap.add_argument("--python", default=sys.executable,
                    help="python executable for child processes")
    args = ap.parse_args()

    side = config.side_from_name(args.side)
    if args.no_auto_load:
        # Override the side's auto_load_save to empty → fw_config.ini gets
        # auto_load_save= (empty) → main_menu_hook detour returns without
        # scheduling LoadGame → main menu shows normally. User must click
        # "Load" manually to enter the world.
        side = dataclasses.replace(side, auto_load_save="")
        print(f"[launcher] --no-auto-load: main menu will show normally "
              f"(auto_load_save cleared)", flush=True)
    return orchestrator.run(side, start_server=not args.no_server, python_exe=args.python)


if __name__ == "__main__":
    sys.exit(main())
