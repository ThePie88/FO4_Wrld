"""Process utilities: scan tasklist, detect newly-spawned Fallout4.exe.

Stdlib-only (uses `tasklist` on Windows). Avoids psutil dependency so the
launcher runs on a fresh Python install without pip install.
"""
from __future__ import annotations

import csv
import io
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    image: str
    session: str
    mem_kb: int


def list_processes(image_name: Optional[str] = None) -> list[ProcInfo]:
    """Return list of all processes. If `image_name` given, filter by it."""
    cmd = ["tasklist", "/FO", "CSV"]
    if image_name is not None:
        cmd.extend(["/FI", f"IMAGENAME eq {image_name}"])
    try:
        out = subprocess.check_output(cmd, text=True, errors="replace")
    except subprocess.CalledProcessError:
        return []
    # CSV: "Image Name","PID","Session Name","Session#","Mem Usage"
    rows = list(csv.reader(io.StringIO(out)))
    if not rows:
        return []
    # First row is header; may be missing if no matches ("Informazioni: nessuna...")
    result: list[ProcInfo] = []
    for r in rows[1:]:
        if len(r) < 5: continue
        try:
            pid = int(r[1])
        except ValueError:
            continue
        mem_str = r[4].replace(".", "").replace("\u00a0K", "").replace(" K", "").strip()
        try:
            mem = int(mem_str)
        except ValueError:
            mem = 0
        result.append(ProcInfo(pid=pid, image=r[0], session=r[2], mem_kb=mem))
    return result


def fallout_pids() -> set[int]:
    """Return current set of Fallout4.exe PIDs."""
    return {p.pid for p in list_processes("Fallout4.exe")}


def wait_for_new_fallout_pid(
    pre_existing: set[int],
    *,
    timeout_s: float,
    check_interval_s: float = 0.5,
) -> Optional[int]:
    """Poll until a new Fallout4.exe PID appears (not in pre_existing set).

    Returns the new PID or None if timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        current = fallout_pids()
        new_pids = current - pre_existing
        if new_pids:
            # If multiple appeared, take the lowest (first spawned)
            return min(new_pids)
        time.sleep(check_interval_s)
    return None


def pid_is_alive(pid: int, image_name: str = "Fallout4.exe") -> bool:
    return pid in {p.pid for p in list_processes(image_name)}
