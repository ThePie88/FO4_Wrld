"""Launcher orchestration: server check + FO4 launch + client spawn + log merge.

This module is stdlib-only and runs everything via subprocess. Each child's
stdout is piped back to the launcher's terminal with a colored prefix.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from launcher import config, fo4_ini, fw_config
from launcher.procutil import fallout_pids, wait_for_new_fallout_pid
from launcher import connect as connect_api


# ANSI palette
BOLD = "\x1b[1m"; DIM = "\x1b[2m"; RESET = "\x1b[0m"
RED = "\x1b[31m"; GREEN = "\x1b[32m"; YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"; CYAN = "\x1b[36m"; MAGENTA = "\x1b[35m"


def enable_ansi_on_windows() -> None:
    """Flip the VIRTUAL_TERMINAL_PROCESSING flag on Windows 10+ consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)  # STDOUT
        mode = ctypes.c_uint()
        k32.GetConsoleMode(h, ctypes.byref(mode))
        k32.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


LOG_TO_STDERR: bool = False
"""External-launcher mode sends human logs to STDERR.

stdout is then a pure machine channel — one JSON event per line — so the
launcher can read it line by line without having to skip our colored prose.
Set by run() when connect_addr is given."""


def log(prefix: str, msg: str, *, color: str = "") -> None:
    print(f"{prefix} {color}{msg}{RESET}", flush=True,
          file=sys.stderr if LOG_TO_STDERR else sys.stdout)


# ------------------------------------------------------------------ server

def is_server_up(host: str = config.SERVER_HOST, port: int = config.SERVER_PORT) -> bool:
    """Best-effort: try a quick UDP bind on the server port. If in use, server likely running."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((host, port))
    except OSError:
        return True  # port in use -> server (or something) is there
    finally:
        s.close()
    return False


def start_server_detached(python_exe: str = sys.executable) -> subprocess.Popen:
    """Launch server as a background subprocess, its stdout piped to the launcher."""
    cmd = [
        python_exe, "-u", "-m", "net.server.main",
        "--snapshot-path", str(config.SERVER_SNAPSHOT),
        "--snapshot-interval-s", str(config.SERVER_SNAPSHOT_INTERVAL_S),
        "--log-level", "INFO",
    ]
    # B6.5+: NPC brain — only enable if the waypoints dir exists with at
    # least one .json. Missing dir = brain stays idle (no NPC_STATE_BCAST
    # emission), preserving backward compatibility with pre-B6.5 sessions.
    if config.SERVER_WAYPOINTS_DIR.is_dir() and \
            any(config.SERVER_WAYPOINTS_DIR.glob("*.json")):
        cmd.extend([
            "--waypoints-dir", str(config.SERVER_WAYPOINTS_DIR),
            "--npc-tick-hz", str(config.SERVER_NPC_TICK_HZ),
        ])
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.Popen(
        cmd, cwd=config.REPO_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        env=env,
    )


def wait_for_server_ready(timeout_s: float = 45.0,
                          proc: Optional[subprocess.Popen] = None) -> bool:
    """Poll port binding until something's listening.

    Timeout was 5.0s and started failing every launch after a couple of months
    of not running the project: measured cold start is now ~11s to bind (python
    interpreter start + imports, snapshot restore of 263 world actors, brain
    JSON load) — well past 5s, so the launcher killed a perfectly healthy
    server and aborted with "server failed to listen in 5s". 45s leaves room
    for a cold disk / AV-scanned python start. If `proc` is given we also bail
    out immediately when it dies, so a real crash still fails fast instead of
    waiting out the full timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if is_server_up():
            return True
        if proc is not None and proc.poll() is not None:
            return False        # server process died — no point waiting
        time.sleep(0.2)
    return False


# ------------------------------------------------------------------ FO4 launch

def launch_fo4(side: config.SideConfig) -> subprocess.Popen:
    """Spawn the appropriate launcher (Steam f4se_loader / FO4_b coldclient)."""
    exe = side.launcher_exe
    if not exe.is_file():
        raise FileNotFoundError(f"launcher exe not found for side {side.name}: {exe}")
    return subprocess.Popen(
        [str(exe)],
        cwd=exe.parent,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


# ------------------------------------------------------------------ client

def start_client(python_exe: str, side: config.SideConfig, pid: int) -> subprocess.Popen:
    """Launch the FalloutWorld client attached to the given Fallout4.exe PID."""
    ghost_arg = f"{side.other_peer_id}=0x{side.ghost_formid:X}"
    cmd = [
        python_exe, "-u", "-m", "net.client.main",
        "--pid", str(pid),
        "--id", side.peer_id,
        "--ghost-map", ghost_arg,
        "--server", f"{config.SERVER_HOST}:{config.SERVER_PORT}",
        "--log-level", "INFO",
    ]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.Popen(
        cmd, cwd=config.REPO_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        env=env,
    )


# ------------------------------------------------------------------ log piping

def pipe_output(proc: subprocess.Popen, prefix: str, stop_evt: threading.Event) -> threading.Thread:
    """Background thread that reads proc.stdout and prefixes each line."""
    def worker():
        if proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                if stop_evt.is_set(): break
                line = line.rstrip()
                if line:
                    # Child output is human log: keep stdout clean for the
                    # JSON event stream in external-launcher mode.
                    print(f"{prefix} {line}", flush=True,
                          file=sys.stderr if LOG_TO_STDERR else sys.stdout)
        except Exception:
            pass
    t = threading.Thread(target=worker, daemon=True, name=f"pipe-{prefix}")
    t.start()
    return t


# ------------------------------------------------------------------ orchestration

def run(
    side: config.SideConfig,
    *,
    start_server: bool = True,
    python_exe: str = sys.executable,
    connect_addr: Optional[str] = None,
    auth_blob: str = "",
    player_name: str = "",
    client_id: str = "",
    suppress_mirror_combat: bool = True,
) -> int:
    """Full launcher flow. Blocks until Ctrl+C or child crashes.

    `connect_addr` ("host:port") is the external-launcher path: the player
    picked a server in the browser, so we point the DLL at THAT address instead
    of the hardcoded local one, and we report progress as JSON events on stdout
    for the launcher to mirror into its overlay.
    """
    global LOG_TO_STDERR
    if connect_addr:
        LOG_TO_STDERR = True    # keep stdout a clean JSON event stream
    enable_ansi_on_windows()
    stop_evt = threading.Event()
    threads: list[threading.Thread] = []
    procs: list[tuple[str, subprocess.Popen]] = []

    def shutdown(rc: int) -> int:
        stop_evt.set()
        for name, p in procs:
            if p.poll() is None:
                log(side.log_prefix, f"shutting down {name} (pid={p.pid})", color=DIM)
                try:
                    p.terminate()
                    p.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    p.kill()
                except Exception:
                    pass
        return rc

    log(side.log_prefix, f"{BOLD}FalloutWorld Launcher — Side {side.name}{RESET}")
    log(side.log_prefix, f"peer_id={side.peer_id}  ghost->{side.other_peer_id}=0x{side.ghost_formid:X}")

    # 0. Apply managed FO4 INI overrides (autosave off, bAlwaysActive on).
    # Idempotent: does nothing if already configured. User can opt out by
    # removing our marker from Fallout4Custom.ini — see fo4_ini.py.
    try:
        written, skipped = fo4_ini.apply()
        if skipped:
            log(side.log_prefix, "FO4 INI: user opted out — autosave settings NOT enforced",
                color=YELLOW)
        elif written > 0:
            log(side.log_prefix, f"FO4 INI: applied {written} override(s) (autosave disabled)",
                color=GREEN)
        else:
            log(side.log_prefix, "FO4 INI: already configured (autosave disabled)", color=DIM)
    except Exception as e:
        log(side.log_prefix, f"FO4 INI: {e} — continuing anyway", color=YELLOW)

    # 0.5. Write fw_config.ini for the native DLL (FoM-lite B0.4+).
    # The fw_native/dxgi.dll sitting next to Fallout4.exe will read this
    # at boot to pick server endpoint, client_id, ghost mapping.
    try:
        fwcfg_path = fw_config.write_for_side(
            side,
            log_level=config.DLL_LOG_LEVEL,
            auto_load_save=side.auto_load_save,
            server_addr=connect_addr,
            # v19 PIENUVO: launcher-minted login proof, forwarded verbatim
            # to the DLL. Empty when starting without the external launcher.
            auth_blob=auth_blob,
            player_name=player_name,
            client_id=client_id or None,
            suppress_mirror_combat=suppress_mirror_combat,
        )
        if side.auto_load_save:
            log(side.log_prefix,
                f"fw_config.ini written -> {fwcfg_path} (auto-load: {side.auto_load_save!r})",
                color=GREEN)
        else:
            log(side.log_prefix,
                f"fw_config.ini written -> {fwcfg_path} (no auto-load)",
                color=GREEN)
    except Exception as e:
        log(side.log_prefix, f"fw_config.ini write failed: {e}", color=YELLOW)

    # 1. Server check
    server_proc: Optional[subprocess.Popen] = None
    if is_server_up():
        log(side.log_prefix, f"server already listening on {config.SERVER_HOST}:{config.SERVER_PORT}",
            color=GREEN)
    elif start_server:
        log(side.log_prefix, "server not running — starting...", color=YELLOW)
        server_proc = start_server_detached(python_exe)
        procs.append(("server", server_proc))
        threads.append(pipe_output(server_proc, f"{DIM}[srv]{RESET}", stop_evt))
        if not wait_for_server_ready(45.0, server_proc):
            log(side.log_prefix, "server failed to listen in 45s", color=RED)
            return shutdown(1)
        log(side.log_prefix, "server up", color=GREEN)
    elif connect_addr:
        # Remote server chosen in the browser: it was already probed by
        # preflight, and is_server_up() only ever inspects the LOCAL port, so
        # there is nothing to check here. Carry on and launch the game.
        log(side.log_prefix, f"connecting to remote server {connect_addr}",
            color=GREEN)
    else:
        log(side.log_prefix,
            f"no server listening on {config.SERVER_HOST}:{config.SERVER_PORT}",
            color=RED)
        log(side.log_prefix,
            "the server is a separate process now — start it first with "
            "start_server.bat (or pass --with-server for the old all-in-one "
            "mode)", color=YELLOW)
        return shutdown(1)

    # 2. Capture baseline FO4 PIDs, launch game
    pre_pids = fallout_pids()
    log(side.log_prefix, f"existing Fallout4.exe PIDs: {sorted(pre_pids) or 'none'}")
    log(side.log_prefix, f"launching {side.launcher_exe.name}...", color=CYAN)
    if connect_addr:
        connect_api.emit("launching", side=side.name)
    try:
        _ = launch_fo4(side)
    except FileNotFoundError as e:
        log(side.log_prefix, f"ERROR: {e}", color=RED)
        if connect_addr:
            connect_api.emit_error(
                "game_not_found",
                "Installazione di Fallout 4 non trovata. Verifica il percorso "
                "del gioco nelle impostazioni.")
        return shutdown(1)

    # 3. Wait for new Fallout4.exe to appear
    log(side.log_prefix, f"waiting up to {config.FO4_PROCESS_WAIT_S}s for Fallout4.exe...",
        color=CYAN)
    pid = wait_for_new_fallout_pid(pre_pids, timeout_s=config.FO4_PROCESS_WAIT_S)
    if pid is None:
        log(side.log_prefix, "Fallout4.exe did not spawn in time — is Steam running? "
            "Side B: is ColdClient configured?", color=RED)
        if connect_addr:
            # The launcher started but no game process appeared: from the
            # player's point of view the game "did not open", which is the same
            # bucket as a missing install.
            connect_api.emit_error(
                "game_not_found",
                "Il gioco non si e' avviato. Controlla che Steam sia in "
                "esecuzione e che Fallout 4 sia installato correttamente.")
        return shutdown(1)
    log(side.log_prefix, f"Fallout4.exe PID={pid} detected", color=GREEN)
    if connect_addr:
        connect_api.emit("game_launched", pid=pid)

    client_proc: Optional[subprocess.Popen] = None

    if config.NATIVE_MODE:
        # FoM-lite mode: fw_native/dxgi.dll replaces the Python+Frida client.
        # The DLL loads during FO4's loader phase, reads fw_config.ini, opens
        # its own UDP socket to the server. We just wait on the game + server
        # liveness here; there's no Python client subprocess to monitor.
        log(side.log_prefix, f"NATIVE_MODE — fw_native/dxgi.dll is the client. "
            f"No Python+Frida client started.", color=GREEN)
        log(side.log_prefix, f"{BOLD}{GREEN}READY{RESET} — Ctrl+C to stop", color="")
    else:
        # Legacy Python+Frida path. Kept for rollback if the native DLL breaks.
        log(side.log_prefix, f"grace window {config.FO4_ATTACH_DELAY_S}s before attach...",
            color=DIM)
        time.sleep(config.FO4_ATTACH_DELAY_S)
        log(side.log_prefix, f"attaching FalloutWorld client to PID {pid}", color=CYAN)
        client_proc = start_client(python_exe, side, pid)
        procs.append(("client", client_proc))
        threads.append(pipe_output(client_proc, side.log_prefix, stop_evt))
        log(side.log_prefix, f"{BOLD}{GREEN}READY{RESET} — Ctrl+C to stop", color="")

    # 6. Main loop: watch liveness
    try:
        while True:
            if client_proc is not None and client_proc.poll() is not None:
                rc = client_proc.returncode
                log(side.log_prefix, f"client exited with code {rc}", color=YELLOW)
                break
            if server_proc is not None and server_proc.poll() is not None:
                log(side.log_prefix, "server exited — stopping", color=RED)
                break
            # In NATIVE_MODE we also want to detect Fallout4.exe exit so we
            # don't hang forever if the user just closes the game window.
            if config.NATIVE_MODE:
                from launcher.procutil import pid_is_alive
                if not pid_is_alive(pid):
                    log(side.log_prefix, f"Fallout4.exe (pid={pid}) exited — stopping",
                        color=YELLOW)
                    break
            time.sleep(0.5)
    except KeyboardInterrupt:
        log(side.log_prefix, "Ctrl+C — stopping", color=YELLOW)

    return shutdown(0)
