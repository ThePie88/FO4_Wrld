"""List every address-like hex literal in fw_native/src (comments and strings stripped).

Usage: python tools/rva_port/inventory.py [--json out.json]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "fw_native" / "src"

HEX = re.compile(r"\b0x([0-9A-Fa-f]+)(?:ull|ULL|u|U|ll|LL)?\b")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")
STRING = re.compile(r'"(?:\\.|[^"\\\n])*"')

# Fallout4.exe 1.11.x is ~0x5000000 bytes mapped; RVAs below 0x1000 are headers.
RVA_MIN, RVA_MAX = 0x1000, 0x6000000
VA_BASE = 0x140000000


def strip(text: str) -> str:
    def blank(m):  # keep line numbers stable
        return re.sub(r"[^\n]", " ", m.group(0))

    text = BLOCK_COMMENT.sub(blank, text)
    text = STRING.sub(blank, text)
    return LINE_COMMENT.sub(blank, text)


def scan(min_value: int = 0x10000):
    hits = []
    for p in sorted(SRC.rglob("*")):
        if p.suffix not in (".cpp", ".h"):
            continue
        raw = p.read_text(encoding="utf-8", errors="replace")
        code = strip(raw)
        for lineno, line in enumerate(code.splitlines(), 1):
            for m in HEX.finditer(line):
                v = int(m.group(1), 16)
                kind = None
                if VA_BASE + RVA_MIN <= v < VA_BASE + RVA_MAX:
                    kind, rva = "va", v - VA_BASE
                elif max(min_value, RVA_MIN) <= v < RVA_MAX:
                    kind, rva = "rva", v
                if kind:
                    hits.append({
                        "file": p.relative_to(SRC).as_posix(), "line": lineno, "col": m.start(),
                        "text": m.group(0), "kind": kind, "rva": rva,
                        "context": raw.splitlines()[lineno - 1].strip()[:160],
                    })
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--min", type=lambda s: int(s, 0), default=0x10000)
    a = ap.parse_args()
    hits = scan(a.min)
    by_rva = collections.defaultdict(list)
    for h in hits:
        by_rva[h["rva"]].append(h)
    print(f"{len(hits)} uses, {len(by_rva)} distinct addresses, "
          f"{len({h['file'] for h in hits})} files, {sum(h['kind'] == 'va' for h in hits)} absolute VAs")
    if a.json:
        Path(a.json).write_text(json.dumps(hits, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
