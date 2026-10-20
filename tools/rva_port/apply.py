"""Rewrite fw_native/src so every moved RVA reads FW_RVA(rva_191, rva_240).

    python tools/rva_port/apply.py tools/rva_port/rva_map_191_to_240.json [--dry-run]

Only literals whose line looks like an address (see ADDRESS_HINTS) are touched;
form ids, masks and sizes are skipped. Writes tools/rva_port/report.md with
everything rewritten, unchanged, skipped or unresolved.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import inventory  # noqa: E402

ADDRESS_HINTS = re.compile(
    r"RVA|Rva|rva|VTBL|VTABLE|[Vv]table|\bVT_|_VT\b|_VT_|_FN\b|_FN_|\bFN_|Fn\b|SINGLETON|Singleton|"
    r"_PTR|PTR_|_SLOT|SLOT_|Slot\b|qword_|sub_|off_|unk_|dword_|byte_|base\s*\+|module_base|ADDR|Addr|"
    r"GLOBAL|Global|g_[a-z_]+_va|kMatLeaf|PATCH|Patch|HOOK|Hook|CALLSITE|CallSite|RET_|_RET"
)
NOT_ADDRESS = re.compile(r"FORM_?ID|FormId|form_id|formid|kBaseFormId|FORMID|_MASK|Mask\b|mask\b|& *0x|0x[0-9A-Fa-f]+u? *&")
# Names that only ever hold addresses win over NOT_ADDRESS (LOOKUP_BY_FORMID_RVA, VT_TPL_MASK).
STRONG = re.compile(r"_RVA\b|\bRVA_|Rva\b|\bVT_|_VT\b|VTBL|VTABLE|[a-z]Vt[AB]?\b|\bqword_|\bsub_14|\boff_14")
# Vtable name tables: { 0x0267C888, "NiNode" },
VTABLE_TABLE_ROW = re.compile(r'^\s*\{\s*0x[0-9A-Fa-f]{7,8}\s*,\s*"')
VTABLE_TABLE_FILES = ("native/scene_walker.cpp", "native/anatomy_probe.cpp")
# Function-range tables: {0x5007B0, 0x5007B0 + 0xB4, "..."}
RANGE_ROW = re.compile(r"\{\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*\+\s*(0x[0-9A-Fa-f]+)\s*,")


def classify(ctx: str, file: str = "") -> bool:
    if STRONG.search(ctx):
        return True
    if file in VTABLE_TABLE_FILES and VTABLE_TABLE_ROW.search(ctx):
        return True
    if file == "persist/inventory_tap.cpp" and RANGE_ROW.search(ctx):
        return True
    return bool(ADDRESS_HINTS.search(ctx)) and not NOT_ADDRESS.search(ctx)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("map")
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    amap = json.loads(Path(a.map).read_text(encoding="utf-8"))
    ov_file = Path(a.map).with_name(Path(a.map).name.replace("rva_map", "overrides"))
    if ov_file.is_file():
        for old, o in json.loads(ov_file.read_text(encoding="utf-8")).items():
            key = str(int(old, 16))
            amap.setdefault(key, {"old": old, "section": ".text", "context": ""})
            amap[key].update({"new": o["new"], "method": "manual override: " + o["why"][:60], "confidence": 1.0})
    hits = inventory.scan()

    edits = collections.defaultdict(list)    # file -> [(line, col, old_text, new_text)]
    report = collections.defaultdict(list)
    for h in hits:
        e = amap.get(str(h["rva"])) or amap.get(h["rva"])
        if e is None:
            e = next((v for v in amap.values() if int(v["old"], 16) == h["rva"]), None)
        where = f"`{h['file']}:{h['line']}`"
        if not classify(h["context"], h["file"]):
            report["skipped (not an address)"].append(f"{where} `{h['text']}` — {h['context'][:90]}")
            continue
        if e is None or e["new"] is None:
            why = e["method"] if e else "not in map"
            report["UNRESOLVED"].append(f"{where} `{h['text']}` ({why}) — {h['context'][:90]}")
            continue
        new = int(e["new"], 16)
        if e["confidence"] < a.min_confidence:
            report["LOW CONFIDENCE (left as is)"].append(
                f"{where} `{h['text']}` -> {e['new']} via {e['method']} ({e['confidence']}) — {h['context'][:80]}")
            continue
        if new == h["rva"]:
            report["unchanged (same address in both builds)"].append(f"{where} `{h['text']}`")
            continue
        width = max(8, len(h["text"]) - 2) if h["text"].lower().startswith("0x") else 8
        suffix = re.search(r"(ull|ULL|u|U|ll|LL)$", h["text"])
        new_text = f"0x{new:0{width}X}" + (suffix.group(1) if suffix else "")
        line_text = (inventory.SRC / h["file"]).read_text(encoding="utf-8").splitlines()[h["line"] - 1]
        rm = RANGE_ROW.search(line_text) if h["file"] == "persist/inventory_tap.cpp" else None
        if rm:
            # {lo, lo + len, ...}: both ends follow the function; len follows its new size.
            if h["col"] != rm.start(1):
                continue  # the second occurrence is rewritten together with the first
            old_len = int(rm.group(3), 16)
            new_len = old_len if e.get("identical_code") else (e.get("new_size") or old_len)
            if e.get("old_size") and old_len > e["old_size"]:
                new_len = old_len  # range is not exactly the function body; keep length
            span = line_text[rm.start(1):rm.end(3)]
            repl = (f"static_cast<std::uint32_t>(FW_RVA({rm.group(1)}u, {new_text}u)), "
                    f"static_cast<std::uint32_t>(FW_RVA({rm.group(2)}u + {rm.group(3)}u, {new_text}u + 0x{new_len:X}u))")
            edits[h["file"]].append((h["line"], rm.start(1), span, repl))
            report["rewritten"].append(f"{where} range `{span}` -> start `{new_text}`, len `0x{new_len:X}` ({e['method']})")
            continue
        edits[h["file"]].append((h["line"], h["col"], h["text"], f"FW_RVA({h['text']}, {new_text})"))
        report["rewritten"].append(f"{where} `{h['text']}` -> `{new_text}` ({e['method']}, {e['confidence']})")

    src = inventory.SRC
    changed_files = 0
    for f, items in edits.items():
        path = src / f
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        by_line = collections.defaultdict(list)
        for ln, col, old, new in items:
            by_line[ln].append((col, old, new))
        for ln, subs in by_line.items():
            line = lines[ln - 1]
            for col, old, new in sorted(subs, reverse=True):
                assert line[col:col + len(old)] == old, (f, ln, line, old)
                line = line[:col] + new + line[col + len(old):]
            # FW_RVA is a runtime call: constexpr declarations become const.
            # Headers: namespace/class scope (inline const). Sources: namespace or
            # function scope, where plain const works and inline is not allowed.
            if path.suffix == ".h":
                line = re.sub(r"\bstatic\s+constexpr\b", "static inline const", line)
                line = re.sub(r"\binline\s+constexpr\b", "inline const", line)
                line = re.sub(r"(?<!inline )\bconstexpr\b", "inline const", line)
            else:
                line = re.sub(r"\binline\s+constexpr\b", "const", line)
                line = re.sub(r"\bconstexpr\b", "const", line)
            lines[ln - 1] = line
        if not a.dry_run:
            text = "".join(lines)
            if '#include "game_build.h"' not in text and "game_build.h" not in f:
                rel = "../" * (len(Path(f).parts) - 1)
                text = re.sub(r"(#pragma once\s*\n)", rf'\1\n#include "{rel}game_build.h"\n', text, count=1) \
                    if "#pragma once" in text else f'#include "{rel}game_build.h"\n' + text
            path.write_text(text, encoding="utf-8")
        changed_files += 1

    out = Path(__file__).parent / "report.md"
    parts = ["# RVA port 1.11.191 -> 1.11.240\n"]
    for k in ("rewritten", "unchanged (same address in both builds)", "UNRESOLVED",
              "LOW CONFIDENCE (left as is)", "skipped (not an address)"):
        parts.append(f"\n## {k} ({len(report[k])})\n")
        parts.extend(f"- {x}\n" for x in report[k])
    out.write_text("".join(parts), encoding="utf-8")
    print({k: len(v) for k, v in report.items()}, f"files changed: {changed_files}",
          "(dry run)" if a.dry_run else "")


if __name__ == "__main__":
    main()
