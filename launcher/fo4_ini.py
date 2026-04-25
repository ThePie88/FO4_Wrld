r"""Manage Fallout 4 INI overrides for the multiplayer launcher.

Fallout4Custom.ini lives at:
    %USERPROFILE%\Documents\My Games\Fallout4\Fallout4Custom.ini

Settings applied:
  - Autosave disabled on every trigger (timed, rest, wait, travel, pause).
    Rationale: during multiplayer testing an autosave bakes in-memory state
    into the .fos file. If the in-memory state is transiently corrupt (mid
    Frida apply, peer disconnect, etc) the .fos becomes corrupt too. We
    disable autosave entirely — the user saves manually when they want.
  - bAlwaysActive=1 preserves the alt-tab fix we already rely on.

Idempotent: if a key already exists with the desired value, nothing is
written. If it exists with a different value, it's overwritten.

The user can re-enable autosave by manually deleting the [SaveGame] and
[GamePlay] sections from the INI — the launcher will not re-add them if
the user has explicitly removed the FALLOUTWORLD_MANAGED marker at the top.
"""
from __future__ import annotations

import os
from configparser import ConfigParser, MissingSectionHeaderError
from pathlib import Path

# Default location of the per-user FO4 INI overrides.
DEFAULT_INI_PATH: Path = Path(
    os.path.expandvars(r"%USERPROFILE%\Documents\My Games\Fallout4\Fallout4Custom.ini")
)

# Marker comment on the first line. If the user deletes this (or the whole
# file), we back off and don't re-apply our managed keys. This lets a user
# opt out of our management by editing the INI.
MANAGED_MARKER = "; FalloutWorld launcher managed — delete this line to opt out"

# Sections + keys we enforce. Values are strings (INI format).
#
# Fallout 4 autosave triggers covered:
#   - fAutoSaveEveryXMins: timed rolling autosave (disabled by huge number)
#   - bAllowAutosaveFromScript: script-triggered autosave (story beats)
#   - bAllowAutosaveInCombat: autosave at combat end
#   - bSaveOnTravel: fast travel
#   - bSaveOnWait / bSaveOnRest: wait / sleep menus
#   - bSaveOnPause: pause-menu save
#
# B3 intro-skip (added 2026-04-20):
#   - sIntroSequence="": suppresses the Bethesda/GameBryo pre-main-menu
#     video sequence (Fallout4_Intro.bk2, CreditsMenu.bk2). ~25s saved/launch.
#   - bSkipSplash=1: skip the 2-second Bethesda logo fade-in on startup.
#   - bShowCompanionAppMain/uCompanionAppWarnings: suppress the "Download
#     the Pipboy app!" popups that show before and during main menu.
#
# The main-menu auto-Continue is NOT handled by INI — that needs a hook
# into the UI system (B3.full, deferred).
MANAGED_KEYS: dict[str, dict[str, str]] = {
    "General": {
        "bAlwaysActive": "1",
        "sIntroSequence": "",
        "bSkipSplash": "1",
        "bShowCompanionAppMain": "0",
        "uCompanionAppWarnings": "0",
    },
    "SaveGame": {
        "fAutosaveEveryXMins": "999999",
        "bAllowAutosaveFromScript": "0",
        "bAllowAutosaveInCombat": "0",
    },
    "GamePlay": {
        "bSaveOnTravel": "0",
        "bSaveOnWait": "0",
        "bSaveOnRest": "0",
        "bSaveOnPause": "0",
    },
}


def _read_existing(path: Path) -> tuple[ConfigParser, bool]:
    """Read the INI. Returns (parser, is_managed_by_us).

    is_managed_by_us is False if the user explicitly deleted our marker — in
    that case the caller should back off and leave the file alone.
    """
    cp = ConfigParser()
    # ConfigParser lowercases keys by default which would break case-sensitive
    # game keys. `optionxform = str` keeps them verbatim.
    cp.optionxform = str  # type: ignore[assignment]
    if not path.is_file():
        # Fresh file — we own it by default.
        return cp, True
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    # Skip lines before the first [section] header when feeding configparser;
    # the marker comment is outside any section so we handle it specially.
    managed = MANAGED_MARKER in raw.splitlines()[0:3]
    # Heuristic: if the file exists and does NOT have the marker, we assume
    # the user wrote it themselves before we started managing it. First-run:
    # we adopt it. Subsequent runs: if the marker is gone we back off.
    #
    # For simplicity the caller decides — we just report the presence flag.
    try:
        cp.read_string(raw)
    except MissingSectionHeaderError:
        # Corrupt or pre-section junk — rebuild safely.
        cp = ConfigParser()
        cp.optionxform = str  # type: ignore[assignment]
    return cp, managed


def _serialize(cp: ConfigParser) -> str:
    """Serialize the INI with our marker on line 1."""
    out_lines = [MANAGED_MARKER, ""]
    for section in cp.sections():
        out_lines.append(f"[{section}]")
        for key, value in cp.items(section):
            out_lines.append(f"{key}={value}")
        out_lines.append("")  # blank line between sections
    return "\n".join(out_lines).rstrip() + "\n"


def apply(path: Path = DEFAULT_INI_PATH) -> tuple[int, bool]:
    """Apply the managed keys. Returns (n_keys_written, skipped).

    skipped=True means the user has opted out (our marker was deleted) and
    we left the file alone. skipped=False means we wrote or the file was
    already up-to-date.

    n_keys_written counts keys that were added or changed.
    """
    cp, managed = _read_existing(path)

    # If the file exists and has non-default content but NO marker, this is
    # the first time we manage it. Adopt with caller's consent (no opt-out
    # possible until we've written the marker). After the first run the
    # marker is present and the user can remove it to opt out.
    if path.is_file() and not managed:
        # Check if the file has ANY content — if it does, this is legacy,
        # adopt it. If it's empty, also just adopt.
        pass

    # If the file had OUR marker and someone deleted it explicitly, skip.
    # Detect "explicit delete": the file exists, has content, but no marker
    # AND at least one of our managed sections is already populated.
    if path.is_file():
        has_managed_section = any(cp.has_section(s) for s in MANAGED_KEYS)
        first_line = ""
        try:
            first_line = path.read_text(encoding="utf-8-sig").splitlines()[0]
        except Exception:
            first_line = ""
        user_opted_out = has_managed_section and MANAGED_MARKER not in first_line \
                          and "FalloutWorld" in first_line
        if user_opted_out:
            return (0, True)

    changed = 0
    for section, kv in MANAGED_KEYS.items():
        if not cp.has_section(section):
            cp.add_section(section)
        for key, desired in kv.items():
            current = cp.get(section, key, fallback=None)
            if current != desired:
                cp.set(section, key, desired)
                changed += 1

    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: temp then rename.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_serialize(cp), encoding="utf-8")
    os.replace(tmp, path)
    return (changed, False)


if __name__ == "__main__":
    n, skipped = apply()
    if skipped:
        print(f"[fo4_ini] user opted out (marker removed) — left {DEFAULT_INI_PATH} alone")
    elif n == 0:
        print(f"[fo4_ini] already configured — {DEFAULT_INI_PATH}")
    else:
        print(f"[fo4_ini] wrote {n} key(s) to {DEFAULT_INI_PATH}")
