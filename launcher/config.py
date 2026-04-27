"""Paths and defaults for the launcher.

Edit these constants if your install layout differs. No code changes needed
elsewhere — every other module reads from here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


# Repository root (one level above launcher/)
REPO_ROOT: Path = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ player A (Steam)

# f4se_loader.exe of the legitimate Steam install. Launches Fallout 4 via Steam
# runtime (Steam client must be running and game owned).
STEAM_FO4_DIR: Path = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Fallout 4")
STEAM_F4SE_LOADER: Path = STEAM_FO4_DIR / "f4se_loader.exe"


# ------------------------------------------------------------------ player B (ColdClient)

# FO4_b directory: hardlinked FO4 install + Steamless-unpacked Fallout4.exe
# + Goldberg ColdClient files + single-instance binary patch at RVA 0xC2FB62.
FO4B_DIR: Path = REPO_ROOT / "FO4_b"
FO4B_COLDCLIENT_LOADER: Path = FO4B_DIR / "steamclient_loader.exe"


# ------------------------------------------------------------------ network

SERVER_HOST: str = "127.0.0.1"
SERVER_PORT: int = 31337
SERVER_SNAPSHOT: Path = REPO_ROOT / "net" / "state_snapshot.json"
SERVER_SNAPSHOT_INTERVAL_S: float = 10.0

# ------------------------------------------------------------------ native DLL

# When True, the launcher:
#   - writes fw_config.ini into the game dir for fw_native/dxgi.dll to read
#   - SKIPS starting the Python+Frida client (the DLL replaces it)
#
# When False (legacy), the launcher runs the Python+Frida client as before
# and the DLL (if deployed) just no-ops above it (different client_id
# required to avoid peer_id_taken collision — not handled here).
NATIVE_MODE: bool = True

# DLL log verbosity written into fw_config.ini each launch. One of:
#   "error", "warn", "info", "debug"
# Set to "debug" to dump the container-hook diagnostic trace
# ([container] ENTRY / OBSERVE / SUBMIT / ACK / calling g_orig_add / returned)
# and other fine-grained lines. Production default: "info".
DLL_LOG_LEVEL: str = "debug"


# ------------------------------------------------------------------ client defaults

# Default ghost mapping: peer_id -> formid to drive as their avatar in our FO4.
# Codsworth (0x1CA7D) is permanent and present in both saves of Sanctuary-start
# playthroughs. Override via --ghost-map on launcher cli.
DEFAULT_GHOST_MAP: dict[str, int] = {
    "player_A": 0x1CA7D,
    "player_B": 0x1CA7D,
}


# ------------------------------------------------------------------ process detection

# Seconds to wait for Fallout4.exe to appear after launching the game binary.
# First boot can be slow on HDDs; adjust if needed.
FO4_PROCESS_WAIT_S: float = 45.0

# Additional seconds after process appears before we attach Frida. Gives time
# for engine to fully load — attaching too early can have LookupByFormID
# missing forms or crash Frida.
FO4_ATTACH_DELAY_S: float = 5.0


# ------------------------------------------------------------------ per-side config

@dataclass(frozen=True)
class SideConfig:
    name: str           # "A" or "B"
    peer_id: str        # "player_A" or "player_B"
    launcher_exe: Path  # what to spawn
    other_peer_id: str  # whom we ghost-map
    log_prefix: str     # colored prefix
    # B3.b: save filename (no path, no .fos) the DLL should direct-load at
    # boot instead of showing the main menu. Empty disables the feature.
    # Saves live in %USERPROFILE%\Documents\My Games\Fallout4\Saves\.
    auto_load_save: str = ""

    @property
    def ghost_formid(self) -> int:
        return DEFAULT_GHOST_MAP[self.other_peer_id]


SIDE_A = SideConfig(
    name="A",
    peer_id="player_A",
    launcher_exe=STEAM_F4SE_LOADER,
    other_peer_id="player_B",
    log_prefix="\x1b[36m[A]\x1b[0m",  # cyan
    auto_load_save="world_base",   # set to your save filename to skip the main menu
)

SIDE_B = SideConfig(
    name="B",
    peer_id="player_B",
    launcher_exe=FO4B_COLDCLIENT_LOADER,
    other_peer_id="player_A",
    log_prefix="\x1b[35m[B]\x1b[0m",  # magenta
    auto_load_save="world_base",   # set to your save filename to skip the main menu
)


def side_from_name(name: str) -> SideConfig:
    if name.upper() == "A": return SIDE_A
    if name.upper() == "B": return SIDE_B
    raise ValueError(f"unknown side {name!r}: must be A or B")
