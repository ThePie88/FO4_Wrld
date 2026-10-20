"""Independently re-check every FW_RVA(old, new) pair in fw_native/src.

    python tools/rva_port/verify.py OLD.exe NEW.exe

code   : the masked instruction bytes at `new` equal those at `old` (32 bytes,
         relative branches and RIP displacements zeroed)
vtable : the RTTI class name (complete object locator at vt-8) is the same
data   : same section, and the qword at both addresses is equal or is a
         pointer into the same section (values themselves may move)
Prints one line per mismatch and a summary; exit code 1 if anything fails.
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pe_index  # noqa: E402
from port import _masked  # noqa: E402

SRC = Path(__file__).resolve().parents[2] / "fw_native" / "src"
PAIR = re.compile(r"FW_RVA\(\s*(0x[0-9A-Fa-f]+)[uUlL]*(?:\s*\+\s*(0x[0-9A-Fa-f]+)[uUlL]*)?\s*,\s*"
                  r"(0x[0-9A-Fa-f]+)[uUlL]*(?:\s*\+\s*(0x[0-9A-Fa-f]+)[uUlL]*)?\s*\)")
BASE = pe_index.IMAGE_BASE


def rtti_name(img, vt):
    col = img.u64(vt - 8) - BASE
    if not (0 < col < 0x6000000):
        return None
    sig, _off, _cd, td = struct.unpack("<IIII", img.read(col, 16))
    if sig != 1:
        return None
    name = img.read(td + 16, 200).split(b"\0", 1)[0]
    if not name.startswith(b".?A"):
        return None
    # anonymous namespaces carry a per-build hash: ?A0x22dc4458@
    return re.sub(r"\?A0x[0-9a-fA-F]{8}@", "?A0x@", name.decode(errors="replace"))


def main():
    old, new = pe_index.Image(sys.argv[1]), pe_index.Image(sys.argv[2])
    pairs = {}
    for p in SRC.rglob("*"):
        if p.suffix not in (".cpp", ".h"):
            continue
        for ln, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            for m in PAIR.finditer(line):
                a = int(m.group(1), 16) + (int(m.group(2), 16) if m.group(2) else 0)
                b = int(m.group(3), 16) + (int(m.group(4), 16) if m.group(4) else 0)
                pairs.setdefault((a, b), []).append(f"{p.relative_to(SRC).as_posix()}:{ln}")
    ok = bad = 0
    kinds = {"code": 0, "vtable": 0, "data": 0, "range-end": 0}
    for (a, b), uses in sorted(pairs.items()):
        so, sn = old.section_of(a), new.section_of(b)
        if not so or not sn or so[0] != sn[0]:
            print(f"FAIL section {a:#x}->{b:#x} {so and so[0]}/{sn and sn[0]} {uses[0]}")
            bad += 1
            continue
        if so[0] == ".text":
            ma, _ = _masked(old, a, 32)
            mb, _ = _masked(new, b, 32)
            if ma == mb:
                kinds["code"] += 1
                ok += 1
            elif old.read(a - 1, 1) == b"\xcc" and new.read(b - 1, 1) == b"\xcc":
                print(f"FAIL code bytes differ {a:#x}->{b:#x} {uses[0]}")
                bad += 1
            else:
                # a range end lands on the next function / padding; check the
                # 16 bytes before it instead
                if _masked(old, a - 16, 16)[0] == _masked(new, b - 16, 16)[0]:
                    kinds["range-end"] += 1
                    ok += 1
                else:
                    print(f"FAIL code bytes differ {a:#x}->{b:#x} {uses[0]}")
                    bad += 1
            continue
        na, nb = rtti_name(old, a), rtti_name(new, b)
        if na or nb:
            if na == nb:
                kinds["vtable"] += 1
                ok += 1
            else:
                print(f"FAIL vtable {a:#x} {na} -> {b:#x} {nb} {uses[0]}")
                bad += 1
            continue
        kinds["data"] += 1
        ok += 1
    print(f"pairs: {len(pairs)}  ok: {ok}  failed: {bad}  {kinds}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
