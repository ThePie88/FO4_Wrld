#!/usr/bin/env python3
"""L5 realtime R6 (2026-10-16) - the crash campaign.

A tool, not game code. Each cycle: client A alive and settled, a random
pause, the process killed (never a clean exit), A back, and the state after
the relaunch compared with the state before the kill, from the logs and the
server's snapshot. One report per cycle in tools/crash_campaign_reports/.

Launch modes:
  --launch manual  (default) the user starts A from the launcher, as always,
                   when the tool says so (the Tauri launcher holds the vault
                   identity; nothing else can start that character).
  --launch dev     the tool runs `python -m launcher.main --side A`, which
                   mints a DEV identity from launcher/.dev_keys/A.key: another
                   character, a first entry the first time.

What a cycle asserts (red = a bug to open with the log cut by the tool):
  - no [ERR], FAILED, REFUSED, FAULTED or "open for more than" line in the
    new session up to the settled point (+ a grace window);
  - the restore ALIGNED with 0 still differing and 0 outfit failures;
  - level, XP, perk points, perks and SPECIAL of the first stats record
    after the relaunch equal to the last before the kill;
  - the first position after the relaunch within --pos-tolerance units of
    the last position before the kill (the server's last known position,
    put back by the boot);
  - the server's world (spawns by base, crates, death marks) unchanged
    across the kill (an info line, not a red, when --attended: the player
    plays in between and the world legitimately moves);
  - the map markers published after the relaunch with the sink present.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parents[1]
LOG_A = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Fallout 4\fw_native.log")
SNAPSHOT = REPO / "net" / "state_snapshot.json"
SERVER_LOG = REPO / "server.log"
REPORT_ROOT = REPO / "tools" / "crash_campaign_reports"

RE_TS = re.compile(r"^\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\]")
RE_STATS = re.compile(
    r"\[stats\] #(\d+) sent: level (\d+), XP (\d+), (\d+) perk point\(s\), (\d+) perk\(s\), "
    r"SPECIAL ([\d/]+), health (-?\d+), AP (-?\d+), rads (-?\d+)")
RE_POS = re.compile(r"\[stats\] position \((-?[\d.]+), (-?[\d.]+), (-?[\d.]+)\) cell 0x([0-9A-Fa-f]+)")
RE_BOOT = re.compile(r"\[boot\] last position (\w[\w ]*?): \((-?[\d.]+), (-?[\d.]+), (-?[\d.]+)\)")
RE_ALIGNED = re.compile(
    r"\[restore\] ALIGNED to record #(\d+): (\d+) line\(s\) with a surplus removed, (\d+) built, "
    r"(\d+) without a descriptor, (\d+) still differing; outfit: (\d+) put on, (\d+) taken off, (\d+) failed")
RE_SERVER_STATS = re.compile(
    r"^(\d\d:\d\d:\d\d) \[INFO\] server: stats record of (\w+): #(\d+), level (\d+), XP (-?\d+), (\d+) perk point\(s\), "
    r"(\d+) perk\(s\), SPECIAL ([\d/]+), health (-?\d+), AP (-?\d+), rads (-?\d+)")
RE_SERVER_RESTORE = re.compile(r"^(\d\d:\d\d:\d\d) \[INFO\] server: restore requested by (\w+) \(process \w+, boot")
RE_PUBLISHED = re.compile(r"\[map-markers\] published \(([^)]*)\): .*sinks (\d+), array (\d+) \((\d+) resolve")
# The main-thread watchdog reports a stall of 1.7 s at every boot (the engine
# in win32u.dll while the window comes up; the same line in a session that
# never crashed): yellow, with the milliseconds, never red. The server's
# npc_brain warning about a missing waypoints dir is older than the
# campaign and unrelated: ignored.
YELLOW_PATTERNS = [
    (re.compile(r"\[mt-watchdog\]"), "a main-thread stall report (the watchdog)"),
]
SERVER_IGNORE = [
    re.compile(r"npc_brain: --waypoints-dir"),
]
# Lines of A's log that carry a red word by design: the lifecycle REFUSES
# every save the engine tries on its own (an Exitsave at a clean quit, an
# autosave): that is the rule, not a failure.
A_IGNORE = [
    re.compile(r"\[lifecycle\] save '.*' REFUSED"),
]
RED_PATTERNS = [
    (re.compile(r"\[ERR\]"), "an [ERR] line"),
    (re.compile(r"\bFAILED\b"), "a FAILED"),
    (re.compile(r"\bREFUSED\b"), "a REFUSED"),
    (re.compile(r"FAULTED"), "a FAULTED (an SEH cage caught a fault)"),
    (re.compile(r"open for more than"), "an op open for more than 30 s"),
]
READY_MARKERS = ("tick heartbeat ON",)
READY_ANY = ("[restore] ALIGNED to record", "[stats] #")   # a record aligned, or the first stats sent (a new character has no record)


def now_s() -> str:
    return datetime.now().strftime("%H:%M:%S")


def say(msg: str) -> None:
    print(f"[{now_s()}] {msg}", flush=True)


# ----------------------------------------------------------------- the logs

def read_log(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []
    except OSError as e:
        say(f"log {path.name}: {e}")
        return []


def log_signature(path: Path) -> Optional[tuple[int, int]]:
    """(sessions, lines) of A's log: the DLL APPENDS every session to the same
    file under a "--- session start ---" line, so a new session is one more
    marker (clear_logs.bat deletes the file between tests; a missing log is
    normal and counts as no session yet)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (FileNotFoundError, OSError):
        return None
    return (sum(1 for ln in lines if ln.startswith("--- session start ---")), len(lines))


def session_lines(lines: list[str]) -> list[str]:
    """The lines of the LAST session in the file."""
    start = 0
    for i, ln in enumerate(lines):
        if ln.startswith("--- session start ---"):
            start = i
    return lines[start:]


def ts_of(line: str) -> Optional[float]:
    m = RE_TS.match(line)
    if not m:
        return None
    h, mi, s, ms = (int(x) for x in m.groups())
    return h * 3600 + mi * 60 + s + ms / 1000.0


def wait_new_session(prev: Optional[tuple[float, int]], timeout_s: float,
                     launcher: "Optional[DevLauncher]" = None) -> Optional[tuple[float, int]]:
    """Until A's log holds one session more than `prev` (or any, when none).
    In dev mode a launcher that gave up (no server listening, Steam asleep)
    is started again every 15 s, and said."""
    deadline = time.time() + timeout_s
    retry_at = 0.0
    while time.time() < deadline:
        sig = log_signature(LOG_A)
        if sig is not None and sig[0] > 0 and (prev is None or sig[0] > prev[0]) and fo4_running():
            return sig
        if launcher is not None and launcher.exited():
            if retry_at == 0.0:
                say(f"the launcher exited with code {launcher.proc.returncode} before a session of A "
                    f"(see {launcher.report_dir / f'launcher_{launcher.n:02d}.log'}): started again every 15 s "
                    "until A comes up (is the server up? start_server.bat)")
                retry_at = time.time() + 15.0
            elif time.time() >= retry_at:
                launcher.start()
                retry_at = 0.0
        time.sleep(1.0)
    return None


def wait_ready(timeout_s: float) -> tuple[bool, list[str], float]:
    """Until the last session's log has every READY marker. (ready, lines, seconds)."""
    t0 = time.time()
    deadline = t0 + timeout_s
    while time.time() < deadline:
        lines = session_lines(read_log(LOG_A))
        text = "\n".join(lines)
        if all(m in text for m in READY_MARKERS) and any(m in text for m in READY_ANY):
            return True, lines, time.time() - t0
        time.sleep(1.0)
    return False, session_lines(read_log(LOG_A)), time.time() - t0


# ---------------------------------------------------------------- the state

def last_match(lines: list[str], rx: re.Pattern, first: bool = False):
    found = None
    for ln in lines:
        m = rx.search(ln)
        if m:
            found = (ln, m)
            if first:
                break
    return found


def snapshot_state() -> dict:
    try:
        d = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {"error": str(e)}
    spawns = d.get("world_spawns", []) or []
    by_base = Counter(int(s.get("base_form_id", 0)) for s in spawns)
    crates = [c for c in (d.get("containers", []) or []) if int(c.get("wid", 0) or 0) != 0]
    presence = {}
    for p in d.get("presence", []) or []:
        lp = p.get("last_pos")
        if lp:
            presence[p.get("peer_id")] = (float(lp["x"]), float(lp["y"]), float(lp["z"]), int(lp.get("timestamp_ms", 0)))
    return {
        "spawns": len(spawns),
        "by_base": {f"0x{b:X}": n for b, n in sorted(by_base.items())},
        "crates": len(crates),
        "death_counts": d.get("death_counts", {}),
        "presence": presence,
        "timestamp_ms": d.get("timestamp_ms"),
    }


def read_state(lines: list[str]) -> dict:
    st: dict = {"stats": None, "pos": None, "boot": None, "aligned": None}
    m = last_match(lines, RE_STATS)
    if m:
        g = m[1].groups()
        st["stats"] = {"seq": int(g[0]), "level": int(g[1]), "xp": int(g[2]), "perk_points": int(g[3]),
                       "perks": int(g[4]), "special": g[5], "health": int(g[6]), "ap": int(g[7]),
                       "rads": int(g[8])}
    m = last_match(lines, RE_POS)
    if m:
        g = m[1].groups()
        st["pos"] = (float(g[0]), float(g[1]), float(g[2]), g[3])
    m = last_match(lines, RE_BOOT, first=True)
    if m:
        g = m[1].groups()
        st["boot"] = (g[0], float(g[1]), float(g[2]), float(g[3]))
    m = last_match(lines, RE_ALIGNED, first=True)
    if m:
        g = m[1].groups()
        st["aligned"] = {"record": int(g[0]), "removed": int(g[1]), "built": int(g[2]), "no_desc": int(g[3]),
                         "differing": int(g[4]), "put_on": int(g[5]), "taken_off": int(g[6]), "failed": int(g[7])}
    st["snapshot"] = snapshot_state()
    return st


def server_stats_before_kill(server_before: int) -> Optional[dict]:
    """The server's last stats record of the peer that relaunched (named by
    its boot restore request after the kill), among the lines before the
    kill. None when the server log says nothing usable."""
    lines = read_log(SERVER_LOG)
    peer = None
    for ln in lines[server_before:]:
        m = RE_SERVER_RESTORE.match(ln)
        if m:
            peer = m.group(2)
            break
    found = None
    for ln in lines[:server_before] if server_before > 0 else lines:
        m = RE_SERVER_STATS.match(ln)
        if m and (peer is None or m.group(2) == peer):
            g = m.groups()
            found = {"peer": g[1], "seq": int(g[2]), "level": int(g[3]), "xp": int(g[4]), "perk_points": int(g[5]),
                     "perks": int(g[6]), "special": g[7], "health": int(g[8]), "ap": int(g[9]), "rads": int(g[10])}
    return found


def special_lower(after: str, before: str) -> bool:
    try:
        a = [int(x) for x in after.split("/")]
        b = [int(x) for x in before.split("/")]
    except ValueError:
        return False
    return len(a) == len(b) and any(x < y for x, y in zip(a, b))


def first_after_ready(lines: list[str], rx: re.Pattern):
    """The first match AFTER the settled line (the restore's own lines come before it)."""
    seen_ready = False
    for ln in lines:
        if "tick heartbeat ON" in ln:
            seen_ready = True
            continue
        if seen_ready:
            m = rx.search(ln)
            if m:
                return ln, m
    return None


def red_lines(lines: list[str]) -> list[tuple[int, str, str]]:
    out = []
    for i, ln in enumerate(lines):
        if any(rx.search(ln) for rx, _ in YELLOW_PATTERNS):
            continue
        if any(rx.search(ln) for rx in A_IGNORE):
            continue
        for rx, why in RED_PATTERNS:
            if rx.search(ln):
                out.append((i, why, ln))
                break
    return out


def yellow_lines(lines: list[str]) -> list[tuple[int, str, str]]:
    out = []
    for i, ln in enumerate(lines):
        for rx, why in YELLOW_PATTERNS:
            if rx.search(ln) and ("[ERR]" in ln or "[WRN]" in ln):
                out.append((i, why, ln))
                break
    return out


def context(lines: list[str], idx: int, around: int = 3) -> list[str]:
    lo, hi = max(0, idx - around), min(len(lines), idx + around + 1)
    return lines[lo:hi]


# ------------------------------------------------------------- the process

def fo4_running() -> bool:
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Fallout4.exe"], capture_output=True,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "Fallout4.exe" in out


def kill_fo4() -> bool:
    try:
        subprocess.run(["taskkill", "/F", "/IM", "Fallout4.exe"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        say(f"taskkill: {e}")
        return False
    for _ in range(30):
        if not fo4_running():
            return True
        time.sleep(0.5)
    return not fo4_running()


class DevLauncher:
    """`python -m launcher.main --side A`: the launcher exits on its own when
    the game dies, so a relaunch is a new process."""

    def __init__(self, report_dir: Path):
        self.report_dir = report_dir
        self.proc: Optional[subprocess.Popen] = None
        self.n = 0

    def start(self) -> None:
        self.n += 1
        out = open(self.report_dir / f"launcher_{self.n:02d}.log", "w", encoding="utf-8")
        # --connect: the launcher's own "is the local server up" probe binds
        # the port and is fooled by a server bound on 0.0.0.0 (it said "no
        # server listening" with the server answering challenges); with an
        # address given it trusts the address and launches the game.
        self.proc = subprocess.Popen([sys.executable, "-m", "launcher.main", "--side", "A",
                                      "--connect", "127.0.0.1:31337"], cwd=str(REPO),
                                     stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        say(f"launcher started (pid {self.proc.pid}), a DEV identity (launcher/.dev_keys/A.key)")

    def exited(self) -> bool:
        return self.proc is not None and self.proc.poll() is not None

    def wait_exit(self, timeout_s: float) -> None:
        if self.proc is None:
            return
        try:
            self.proc.wait(timeout=timeout_s)
            say(f"launcher exited with code {self.proc.returncode}")
        except subprocess.TimeoutExpired:
            say("launcher still up after the kill: stopped")
            self.proc.kill()
        self.proc = None


# ---------------------------------------------------------------- a cycle

def run_cycle(n: int, args, report_dir: Path, launcher: Optional[DevLauncher], prev_sig) -> tuple[str, dict, tuple]:
    rep: dict = {"cycle": n, "started": now_s()}
    verdicts: list[tuple[str, str]] = []   # (level, text): RED / YELLOW / OK / INFO

    def add(level: str, text: str) -> None:
        verdicts.append((level, text))
        say(f"  {level:6s} {text}")

    # 1. A alive and settled (the first cycle may find it already up).
    if launcher is not None and (prev_sig is None or not fo4_running()):
        launcher.start()
    elif launcher is None and not fo4_running():
        say(f">>> START CLIENT A FROM THE LAUNCHER NOW (the tool waits up to {args.wait / 60:.0f} min)")
    sig = (wait_new_session(prev_sig, args.wait, launcher) if (prev_sig is None or not fo4_running())
           else log_signature(LOG_A))
    if sig is None:
        add("RED", f"no new session of A in {args.wait / 60:.0f} min")
        return "RED", rep, prev_sig
    if n == 1 and args.go_file:
        go = Path(args.go_file)
        say(f">>> waiting for the go file {go} (the character to create, the world to reach)")
        deadline = time.time() + args.wait
        while not go.exists() and time.time() < deadline:
            time.sleep(2.0)
        if not go.exists():
            add("RED", "no go file in time")
            return "RED", rep, sig
        try:
            go.unlink()
        except OSError:
            pass
        say("go file seen: on with the cycle")
    ready, lines, secs = wait_ready(args.ready_timeout)
    if not ready:
        add("RED", f"A not settled in {args.ready_timeout:.0f} s (markers {READY_MARKERS})")
        (report_dir / f"cycle_{n:02d}_A_before.log").write_text("\n".join(lines), encoding="utf-8")
        return "RED", rep, sig
    say(f"A settled in {secs:.0f} s; letting the position lines come (8 s)")
    time.sleep(8.0)
    before = read_state(session_lines(read_log(LOG_A)))
    rep["before"] = before
    if before["stats"] is None:
        add("YELLOW", "no stats record sent before the kill (nothing to compare)")
    if before["pos"] is None:
        add("YELLOW", "no position line before the kill")

    # 2. The random pause, then the kill.
    alive = random.uniform(args.alive[0], args.alive[1])
    say(f"alive for {alive:.0f} s before the kill" + (" (play if you like)" if args.attended else ""))
    time.sleep(alive)
    if args.attended:
        # A kill in the middle of a load (the three-minute loads are real)
        # steals the play and tests nothing new: the settled scene first,
        # up to three minutes.
        t0 = time.time()
        said = False
        while time.time() - t0 < 180.0:
            tail = session_lines(read_log(LOG_A))
            last_on = max((i for i, ln in enumerate(tail) if "tick heartbeat ON" in ln), default=-1)
            last_off = max((i for i, ln in enumerate(tail) if "tick heartbeat OFF" in ln), default=-1)
            if last_on > last_off:
                break
            if not said:
                say("the scene is not settled (a load): the kill waits for it, up to 3 min")
                said = True
            time.sleep(2.0)
    before = read_state(session_lines(read_log(LOG_A)))     # the freshest position and stats
    rep["before"] = before
    before_lines = session_lines(read_log(LOG_A))
    (report_dir / f"cycle_{n:02d}_A_before.log").write_text("\n".join(before_lines), encoding="utf-8")
    server_before = len(read_log(SERVER_LOG))
    kill_at = time.time()
    if not kill_fo4():
        add("RED", "Fallout4.exe did not die on taskkill")
        return "RED", rep, sig
    say("Fallout4.exe KILLED")
    rep["killed_at"] = now_s()

    # 3. A back.
    if launcher is not None:
        launcher.wait_exit(30.0)
        time.sleep(2.0)
        launcher.start()
    else:
        say(f">>> RESTART CLIENT A FROM THE LAUNCHER NOW (the tool waits up to {args.wait / 60:.0f} min)")
    sig2 = wait_new_session(sig, args.wait, launcher)
    if sig2 is None:
        add("RED", f"no new session of A after the kill in {args.wait / 60:.0f} min")
        return "RED", rep, sig
    ready, lines, secs = wait_ready(args.ready_timeout)
    rep["relaunch_to_ready_s"] = round(secs, 1)
    if not ready:
        add("RED", f"A not settled after the relaunch in {args.ready_timeout:.0f} s")
        (report_dir / f"cycle_{n:02d}_A_after.log").write_text("\n".join(lines), encoding="utf-8")
        return "RED", rep, sig2
    add("INFO", f"back and settled {secs:.0f} s after the relaunch")
    time.sleep(args.grace)
    lines = session_lines(read_log(LOG_A))
    (report_dir / f"cycle_{n:02d}_A_after.log").write_text("\n".join(lines), encoding="utf-8")
    worst = assess(before, lines, server_before, args, rep, add)
    rep["verdicts"] = verdicts
    rep["verdict"] = worst
    return worst, rep, sig2


def assess(before: dict, lines: list[str], server_before: int, args, rep: dict, add_outer) -> str:
    """The comparisons of a cycle: the state before the kill against the new
    session's lines. The worst level found."""
    verdicts: list[tuple[str, str]] = []

    def add(level: str, text: str) -> None:
        verdicts.append((level, text))
        add_outer(level, text)
    after = read_state(lines)
    rep["after"] = after

    # 4. The assertions.
    reds = red_lines(lines)
    if reds:
        for idx, why, ln in reds[:20]:
            add("RED", f"{why}: {ln.strip()[:200]}")
            rep.setdefault("red_context", []).append(context(lines, idx))
    else:
        add("OK", "no [ERR] / FAILED / REFUSED / FAULTED / open-for-more-than line after the relaunch")
    # The watchdog's stall at the boot (before the settled line) is the engine
    # bringing the window up, seen in every session: info. One after the
    # settled line is worth a look: yellow.
    settled_idx = next((i for i, ln in enumerate(lines) if "tick heartbeat ON" in ln), len(lines))
    for idx, why, ln in yellow_lines(lines)[:5]:
        add("INFO" if idx < settled_idx else "YELLOW", f"{why}{' at the boot' if idx < settled_idx else ''}: {ln.strip()[:160]}")
    al = after["aligned"]
    if al is None:
        add("YELLOW" if after["stats"] else "RED",
            "no ALIGNED line after the relaunch" + (" (a character without a record yet)" if after["stats"] else ""))
    elif al["differing"] == 0 and al["failed"] == 0:
        add("OK", f"restore ALIGNED to record #{al['record']}: {al['built']} built, {al['removed']} removed, "
                  f"0 still differing, outfit {al['put_on']} on / {al['taken_off']} off / 0 failed")
    else:
        add("RED", f"restore ALIGNED with {al['differing']} still differing, {al['failed']} outfit failures")
    # The FIRST stats sent after the relaunch is what the restore put back;
    # a later one already carries the play after it (the attended campaign
    # read +7 XP of play as a change).
    first_stats = last_match(lines, RE_STATS, first=True)
    if first_stats:
        g = first_stats[1].groups()
        after["stats"] = {"seq": int(g[0]), "level": int(g[1]), "xp": int(g[2]), "perk_points": int(g[3]),
                          "perks": int(g[4]), "special": g[5], "health": int(g[6]), "ap": int(g[7]),
                          "rads": int(g[8])}
    # The truth the restore puts back is the SERVER's last record before the
    # kill (the client's log loses its last seconds to the kill, and a perk
    # taken in that second may be in the checkpoint and not in the record):
    # equal or more after the relaunch is fine (the record catches up at
    # the next send), less is progress lost.
    bs, as_ = before["stats"], after["stats"]
    srv = server_stats_before_kill(server_before)
    base = srv or bs
    if base and as_:
        keys = ("level", "xp", "perk_points", "perks")
        lost = any(as_[k] < base[k] for k in keys) or special_lower(as_["special"], base["special"])
        gained = any(as_[k] > base[k] for k in keys) or (as_["special"] != base["special"])
        src = "the server's last record before the kill" if srv else "the client's last send before the kill"
        txt = (f"level {base['level']}->{as_['level']}, XP {base['xp']}->{as_['xp']}, perk points "
               f"{base['perk_points']}->{as_['perk_points']}, perks {base['perks']}->{as_['perks']}, "
               f"SPECIAL {base['special']}->{as_['special']} (against {src})")
        if lost:
            add("RED", "stats LOST: " + txt)
        elif gained:
            add("OK", "stats kept, the checkpoint carried a little more than the record (it catches up): " + txt)
        else:
            add("OK", "stats kept: " + txt)
        if bs:
            add("INFO", f"the client's last send before the kill said XP {bs['xp']}, {bs['perks']} perk(s); vitals: "
                        f"health {bs['health']}->{as_['health']}, AP {bs['ap']}->{as_['ap']}, rads {bs['rads']}->{as_['rads']} "
                        "(the checkpoint's, by design)")
    else:
        add("YELLOW", "stats before or after missing: not compared")
    bp = before["pos"]
    ap_ = first_after_ready(lines, RE_POS) or last_match(lines, RE_POS)
    if bp and ap_:
        g = ap_[1].groups()
        x, y, z = float(g[0]), float(g[1]), float(g[2])
        d = ((x - bp[0]) ** 2 + (y - bp[1]) ** 2) ** 0.5
        rep["pos_delta"] = round(d, 1)
        boot = after["boot"]
        bt = f"; the boot said '{boot[0]}' at ({boot[1]:.0f}, {boot[2]:.0f}, {boot[3]:.0f})" if boot else "; no [boot] line"
        add("OK" if d <= args.pos_tolerance else "RED",
            f"position: before ({bp[0]:.0f}, {bp[1]:.0f}, {bp[2]:.0f}) cell 0x{bp[3]}, after ({x:.0f}, {y:.0f}, {z:.0f}) "
            f"cell 0x{g[3]}: {d:.0f} units apart (tolerance {args.pos_tolerance:.0f}){bt}")
    else:
        add("YELLOW", "position before or after missing: not compared")
    sb, sa = before["snapshot"], after["snapshot"]
    if "error" in sb or "error" in sa:
        add("YELLOW", f"snapshot unreadable: {sb.get('error') or sa.get('error')}")
    else:
        same_world = sb["by_base"] == sa["by_base"] and sb["crates"] == sa["crates"] and sb["death_counts"] == sa["death_counts"]
        txt = (f"world spawns {sb['spawns']}->{sa['spawns']}, crates {sb['crates']}->{sa['crates']}, "
               f"death counts {sb['death_counts']}->{sa['death_counts']}")
        if same_world:
            add("OK", "the server's world unchanged across the kill: " + txt)
        else:
            diff = {b: (sb["by_base"].get(b, 0), sa["by_base"].get(b, 0)) for b in set(sb["by_base"]) | set(sa["by_base"])
                    if sb["by_base"].get(b, 0) != sa["by_base"].get(b, 0)}
            add("INFO" if args.attended else "RED", f"the server's world moved across the kill: {txt}; by base {diff}")
    # The markers publish as soon as the world is there, often before the
    # settled line: the LAST publish of the session is the one to judge.
    pub = last_match(lines, RE_PUBLISHED)
    if pub:
        g = pub[1].groups()
        add("OK" if int(g[1]) >= 1 else "RED", f"map markers published after the relaunch ({g[0]}): sinks {g[1]}, "
                                                 f"array {g[2]} ({g[3]} resolve)")
    else:
        add("INFO", "no map-marker publish after the relaunch (nothing of ours to show, or not yet)")
    server_lines = read_log(SERVER_LOG)[server_before:]
    bad = [ln for ln in server_lines if ("[WARNING]" in ln or "[ERROR]" in ln)
           and not any(rx.search(ln) for rx in SERVER_IGNORE)]
    rep["server_warnings"] = bad[:20]
    if bad:
        add("YELLOW", f"{len(bad)} server WARNING/ERROR line(s) since the kill (in the report)")
    else:
        add("OK", f"server: no WARNING/ERROR in {len(server_lines)} line(s) since the kill")
    return "RED" if any(v[0] == "RED" for v in verdicts) else ("YELLOW" if any(v[0] == "YELLOW" for v in verdicts) else "OK")


def write_report(report_dir: Path, rep: dict) -> None:
    n = rep["cycle"]
    md = [f"# Crash campaign cycle {n}: {rep.get('verdict', '?')}", "",
          f"- started {rep.get('started')}, killed at {rep.get('killed_at', '?')}, back and settled in "
          f"{rep.get('relaunch_to_ready_s', '?')} s", ""]
    for level, text in rep.get("verdicts", []):
        md.append(f"- **{level}** {text}")
    if rep.get("red_context"):
        md += ["", "## Red lines with context", ""]
        for ctx in rep["red_context"]:
            md += ["```", *ctx, "```", ""]
    if rep.get("server_warnings"):
        md += ["", "## Server warnings since the kill", "", "```", *rep["server_warnings"], "```"]
    md += ["", "## State", "", "```", json.dumps({k: rep.get(k) for k in ("before", "after", "pos_delta")},
                                                    indent=1, default=str), "```"]
    (report_dir / f"cycle_{n:02d}.md").write_text("\n".join(md), encoding="utf-8")
    with open(report_dir / "summary.md", "a", encoding="utf-8") as f:
        f.write(f"- cycle {n}: {rep.get('verdict', '?')} (back in {rep.get('relaunch_to_ready_s', '?')} s, "
                f"position delta {rep.get('pos_delta', '?')})\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cycles", type=int, default=1)
    ap.add_argument("--alive", type=float, nargs=2, default=(10.0, 20.0), metavar=("MIN", "MAX"),
                    help="seconds A stays alive before the kill (random in the range)")
    ap.add_argument("--launch", choices=["manual", "dev"], default="manual")
    ap.add_argument("--attended", action="store_true", help="the player plays in between: world moves are info, not red")
    ap.add_argument("--pos-tolerance", type=float, default=1500.0, help="units between the last position and the first after")
    ap.add_argument("--ready-timeout", type=float, default=300.0)
    ap.add_argument("--grace", type=float, default=20.0, help="seconds after the settled point before the assertions")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--wait", type=float, default=600.0, help="seconds to wait for a (re)launch of A in manual mode")
    ap.add_argument("--assess", metavar="BEFORE_LOG", default=None,
                    help="no kill: compare the saved before-log of a cycle with A's current session and write the report")
    ap.add_argument("--report-dir", default=None)
    ap.add_argument("--cycle", type=int, default=1, help="with --assess: the cycle number the report gets")
    ap.add_argument("--go-file", default=None,
                    help="first cycle only: wait for this file to appear before counting A as ready (a character to create)")
    args = ap.parse_args()
    if args.assess:
        report_dir = Path(args.report_dir) if args.report_dir else REPORT_ROOT / datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir.mkdir(parents=True, exist_ok=True)
        before_lines = session_lines(Path(args.assess).read_text(encoding="utf-8", errors="replace").splitlines())
        before = read_state(before_lines)
        lines = session_lines(read_log(LOG_A))
        rep: dict = {"cycle": args.cycle, "started": now_s(), "killed_at": "(assessed after the fact)", "before": before}
        verdicts: list[tuple[str, str]] = []

        def add(level: str, text: str) -> None:
            verdicts.append((level, text))
            say(f"  {level:6s} {text}")
        say(f"assessing: before = {args.assess}, after = A's current session ({len(lines)} lines)")
        worst = assess(before, lines, 0, args, rep, add)
        rep["verdicts"] = verdicts
        rep["verdict"] = worst
        write_report(report_dir, rep)
        say(f"=== cycle {args.cycle}: {worst} (report {report_dir / f'cycle_{args.cycle:02d}.md'}) ===")
        return 0 if worst != "RED" else 1
    if args.seed is not None:
        random.seed(args.seed)
    report_dir = REPORT_ROOT / datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir.mkdir(parents=True, exist_ok=True)
    say(f"crash campaign: {args.cycles} cycle(s), alive {args.alive[0]:.0f}-{args.alive[1]:.0f} s, launch {args.launch}, "
        f"reports in {report_dir}")
    say(f"A's log: {LOG_A} ({'present' if LOG_A.exists() else 'absent, normal after clear_logs.bat'}); "
        f"Fallout4.exe {'RUNNING' if fo4_running() else 'not running'}")
    launcher = DevLauncher(report_dir) if args.launch == "dev" else None
    # The sessions already in the log are the past, whether or not the game
    # runs: a new session is one more than these (the first campaign run took
    # a dead session's lines for the live game and killed it at the boot).
    prev_sig = log_signature(LOG_A)
    say(f"sessions already in A's log: {prev_sig[0] if prev_sig else 0}")
    results = []
    for n in range(1, args.cycles + 1):
        say(f"=== cycle {n}/{args.cycles} ===")
        verdict, rep, prev_sig = run_cycle(n, args, report_dir, launcher, prev_sig)
        write_report(report_dir, rep)
        results.append(verdict)
        say(f"=== cycle {n}: {verdict} (report {report_dir / f'cycle_{n:02d}.md'}) ===")
        if verdict == "RED" and args.cycles > 1:
            say("a red cycle: the campaign stops here so the logs stay fresh")
            break
    say(f"done: {Counter(results)}")
    return 0 if all(r != "RED" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
