"""
SPAI Tier 1 — BA2 archive enumerator.

Parses Bethesda BSAv1 (BTDX) archives shipped with FO4 and extracts paths
matching the weapon NIF pattern. Output: JSON catalog used by our DLL to
force-prewarm the engine's NIF resource manager at game start so the
ghost-side resmgr-lookup-by-m_name always hits.

Usage:
    python spai_enum_weapons.py [--data-dir PATH] [--out PATH]

Defaults:
    --data-dir = C:\\Program Files (x86)\\Steam\\steamapps\\common\\Fallout 4\\Data
    --out      = ../assets/weapon_nif_catalog.json (relative to script)

BA2 format (per UESP / xEdit source):
  Header (24 bytes):
    char[4]   magic ("BTDX")
    uint32    version (1=original, 7=DLC, 8=Creation Club)
    char[4]   type ("GNRL"=general meshes/audio/etc, "DX10"=textures)
    uint32    file_count
    uint64    name_table_offset

  GNRL file record (36 bytes each):
    uint32    name_hash
    char[4]   ext (lowercase 4-char extension)
    uint32    dir_hash
    uint32    flags
    uint64    data_offset
    uint32    packed_size  (0 if uncompressed)
    uint32    unpacked_size
    uint32    pad (0xBAADF00D)

  Name table (at name_table_offset):
    For each file (in record order):
      uint16  length
      bytes   ascii path (lowercase, '\\' separators)

We don't decode file contents — just paths. Paths matching one of the
weapon patterns are added to the catalog with a stable form-id-agnostic key.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

DEFAULT_DATA_DIR = Path(
    r"C:\Program Files (x86)\Steam\steamapps\common\Fallout 4\Data"
)
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "assets" / \
    "weapon_nif_catalog.json"

# Archives most likely to contain weapon meshes. We try all but only enumerate
# paths from those that exist.
CANDIDATE_ARCHIVES = [
    "Fallout4 - Meshes.ba2",
    "Fallout4 - MeshesExtra.ba2",
    "DLCRobot - Main.ba2",
    "DLCworkshop01 - Main.ba2",
    "DLCworkshop02 - Main.ba2",
    "DLCworkshop03 - Main.ba2",
    "DLCCoast - Main.ba2",
    "DLCNukaWorld - Main.ba2",
]

# Path patterns that count as "weapon NIFs". Lowercase match (BA2 stores
# paths lowercase). DLC archives use "meshes\\dlc0X\\weapons\\..." so we
# match any path containing "\\weapons\\" after the leading meshes\\
# (or no leading meshes\\ at all).
WEAPON_SUBSTR = "\\weapons\\"


def parse_ba2(path: Path) -> tuple[list[str], dict]:
    """Parse a BA2 archive and return (list of paths, summary dict).

    Returns ([], {}) on parse failure (e.g. corrupted, unsupported version).
    """
    if not path.is_file():
        return ([], {"error": "not found", "path": str(path)})

    with path.open("rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return ([], {"error": "header truncated", "path": str(path)})
        magic, version, type_id, file_count, name_table_off = struct.unpack(
            "<4sI4sIQ", header)
        if magic != b"BTDX":
            return ([], {"error": f"bad magic {magic!r}", "path": str(path)})

        summary = {
            "version": version,
            "type": type_id.decode("ascii", "replace"),
            "file_count": file_count,
        }

        if type_id != b"GNRL":
            # Texture archives (DX10) have a different record layout — we
            # don't need them since weapon NIFs live in GNRL meshes archives.
            return ([], {**summary, "skipped": "non-GNRL type"})

        # Records: 36 bytes each, immediately after the 24-byte header.
        records_size = 36 * file_count
        records_blob = f.read(records_size)
        if len(records_blob) < records_size:
            return ([], {**summary, "error": "records truncated"})

        # Name table at name_table_off. Each entry: uint16 length + bytes.
        f.seek(name_table_off)
        names: list[str] = []
        for _ in range(file_count):
            length_bytes = f.read(2)
            if len(length_bytes) < 2:
                names.append("")
                continue
            (length,) = struct.unpack("<H", length_bytes)
            raw = f.read(length)
            try:
                names.append(raw.decode("ascii", errors="replace"))
            except Exception:
                names.append("")

        return names, summary


def is_weapon_nif(path_lower: str) -> bool:
    if not path_lower.endswith(".nif"):
        return False
    # Match any path with "\weapons\" segment (covers vanilla
    # "meshes\weapons\..." and DLC "meshes\dlc0X\weapons\...").
    if WEAPON_SUBSTR in path_lower:
        return True
    # Fallback for paths without the "meshes\\" prefix (some archives
    # strip it).
    return path_lower.startswith("weapons\\")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not args.data_dir.is_dir():
        print(f"[ERR] Data dir not found: {args.data_dir}", file=sys.stderr)
        return 1

    print(f"[spai] Data dir: {args.data_dir}")
    print(f"[spai] Output:   {args.out}")

    all_paths: set[str] = set()
    archive_summaries: dict[str, dict] = {}

    for name in CANDIDATE_ARCHIVES:
        ar_path = args.data_dir / name
        if not ar_path.is_file():
            print(f"[spai] SKIP {name} (not present)")
            continue
        paths, summary = parse_ba2(ar_path)
        archive_summaries[name] = {
            "version": summary.get("version"),
            "type": summary.get("type"),
            "file_count": summary.get("file_count"),
            "weapon_nif_count": 0,
            "error": summary.get("error") or summary.get("skipped"),
        }
        weapon_count = 0
        for p in paths:
            if is_weapon_nif(p.lower()):
                # Strip "meshes\\" prefix if present — engine's
                # nif_load_by_path expects paths relative to meshes\\.
                normalized = p
                low = p.lower()
                if low.startswith("meshes\\"):
                    normalized = p[len("meshes\\"):]
                all_paths.add(normalized)
                weapon_count += 1
                if args.verbose:
                    print(f"  + {normalized}")
        archive_summaries[name]["weapon_nif_count"] = weapon_count
        print(f"[spai] {name}: {summary.get('file_count', '?')} files, "
              f"{weapon_count} weapon NIFs")

    sorted_paths = sorted(all_paths)
    print(f"[spai] Total unique weapon NIF paths: {len(sorted_paths)}")

    catalog = {
        "schema_version": 1,
        "generator": "tools/spai_enum_weapons.py",
        "archive_summaries": archive_summaries,
        "weapon_nif_count": len(sorted_paths),
        "paths": sorted_paths,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)
    print(f"[spai] Wrote {args.out}")

    # Also emit a plain-text sibling .manifest so the DLL can load the
    # path list without pulling in a JSON parser. Format: one ASCII path
    # per line, '#' lines are comments, blank lines ignored. Same dir as
    # the JSON catalog, same stem with '.manifest' extension.
    manifest_path = args.out.with_suffix(".manifest")
    with manifest_path.open("w", encoding="ascii", newline="\n") as f:
        f.write(f"# spai_weapon_nif_catalog v1\n")
        f.write(f"# generator: tools/spai_enum_weapons.py\n")
        f.write(f"# weapon_nif_count: {len(sorted_paths)}\n")
        for p in sorted_paths:
            f.write(p + "\n")
    print(f"[spai] Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
