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
    # --side is OPTIONAL now: the external launcher only knows an address, not
    # our two local test installs. It defaults to A so `--connect <addr>` is a
    # complete command on its own; --side B stays for the two-instance local
    # test and disappears by itself the day there is a single install.
    ap.add_argument("--side", choices=["A", "B", "a", "b"], default="A",
                    help="A=Steam+F4SE, B=ColdClient+FO4_b (default A)")
    ap.add_argument("--connect", metavar="HOST:PORT", default=None,
                    help="join this server: probe it, point the DLL at it, "
                         "launch the game, and report progress as one JSON "
                         "event per line on stdout (external-launcher mode)")
    ap.add_argument("--auth", metavar="PK:CH:SIG", default="",
                    help="v19 PIENUVO login proof minted by the external "
                         "launcher (pubkeyhex:challengehex:sighex). Written "
                         "into fw_config.ini as auth_blob; the DLL forwards "
                         "it in HELLO. Empty = anonymous session")
    ap.add_argument("--client-id", metavar="ID", default="",
                    help="session id (ASCII alnum/_-, <=15) derived from the "
                         "launcher identity. Overrides the side's hardcoded "
                         "player_A/player_B, which collide when two launcher "
                         "players join the same server")
    ap.add_argument("--name", metavar="NICK", default="",
                    help="display name shown to other players (ASCII, <=15). "
                         "Cosmetic only — identity is the auth key")
    # The server is now a DEDICATED process (start_server.bat / start_master.bat).
    # Launching a game client no longer brings a server up with it: that
    # coupling meant client A owned the server's lifetime, so quitting A killed
    # everyone's session and B could never run alone. --with-server restores
    # the old all-in-one behaviour for quick solo testing.
    ap.add_argument("--with-server", action="store_true",
                    help="also start a local server as a child process "
                         "(legacy all-in-one mode; normally you run "
                         "start_server.bat separately)")
    ap.add_argument("--no-server", action="store_true",
                    help=argparse.SUPPRESS)   # legacy no-op, kept for scripts
    ap.add_argument("--no-mirror-suppress", action="store_true",
                    help="EXPERIMENT: write suppress_mirror_combat=false into "
                         "fw_config.ini, so this client does NOT drive "
                         "HighProcess+0x189 on mirrored NPCs. Control run for "
                         "the hp-churn probe. Expect mirrors to aim at you and "
                         "the combat-crouch sliding to return")
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
    if args.connect:
        # External-launcher mode. Probe first so a bad address / wrong version
        # / full server is reported in one second, instead of surfacing as an
        # unexplained silence 40 seconds into the game's boot.
        from launcher import connect as connect_api
        connect_api.emit("starting", server=args.connect)
        if connect_api.preflight(args.connect) is None:
            return 1        # preflight already emitted the precise error
        return orchestrator.run(side, start_server=False,
                                python_exe=args.python,
                                connect_addr=args.connect,
                                auth_blob=args.auth,
                                player_name=args.name,
                                client_id=args.client_id,
                                suppress_mirror_combat=not args.no_mirror_suppress)

    return orchestrator.run(side, start_server=args.with_server,
                            python_exe=args.python,
                            auth_blob=args.auth,
                            player_name=args.name,
                            client_id=args.client_id,
                            suppress_mirror_combat=not args.no_mirror_suppress)


if __name__ == "__main__":
    sys.exit(main())
