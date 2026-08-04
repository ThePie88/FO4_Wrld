#!/usr/bin/env python3
"""Build 69o (2026-08-04) — offline reader for fw_writes.bin (the write ring).

The DLL's VEH dumps the full ring on the first AV. The in-log scan only checks
the crash registers; this tool answers arbitrary questions offline:

    python tools/decode_writes.py <fw_writes.bin>                 # summary
    python tools/decode_writes.py <fw_writes.bin> --near 0x21545480000 [--win 0x100]
    python tools/decode_writes.py <fw_writes.bin> --site NIFREE
    python tools/decode_writes.py <fw_writes.bin> --fid 0x1CA7D
    python tools/decode_writes.py <fw_writes.bin> --last 50

Record layout must match WRec in audit.cpp (40 bytes):
    u64 dest, u32 t_ms, u32 fid, u8 bytes[16], u16 len, u8 site, u8 cap, u32 seq_lo
Header (40 bytes):
    char magic[4]="FWWR", u32 version, u32 entry_size, u32 capacity,
    u64 total_seq, u64 now_ms, u64 fault_addr
"""

import argparse
import struct
import sys

SITE_NAMES = {
    0: "none", 1: "bone3x3", 2: "bonetrans", 3: "nodexform", 4: "geomxform",
    5: "skinptr", 6: "ghostpos", 7: "posraw", 8: "posrawnif", 9: "globalvar",
    10: "hpfunnel", 11: "refinc", 12: "refdec", 13: "NIFREE", 14: "skiptick",
    15: "incombat", 16: "engsetpos", 17: "engmoveto", 18: "engkill",
    19: "engmotion",
}

HDR = struct.Struct("<4sIIIQQQ")
REC = struct.Struct("<QII16sHBBI")


def load(path):
    with open(path, "rb") as f:
        raw = f.read()
    magic, ver, esz, cap, total, now_ms, fault = HDR.unpack_from(raw, 0)
    if magic != b"FWWR":
        sys.exit(f"bad magic {magic!r} — not a fw_writes.bin")
    if esz != REC.size:
        sys.exit(f"entry_size {esz} != expected {REC.size} — layout drifted")
    recs = []
    valid = min(total, cap)
    for i in range(cap):
        dest, t_ms, fid, b, ln, site, bcap, seq_lo = REC.unpack_from(
            raw, HDR.size + i * esz)
        if dest == 0:
            continue  # never-written slot
        recs.append(dict(dest=dest, t_ms=t_ms, fid=fid, bytes=b[:bcap],
                         len=ln, site=site, seq_lo=seq_lo))
    # order oldest -> newest by wrapping sequence distance to total
    recs.sort(key=lambda r: (total - r["seq_lo"]) & 0xFFFFFFFF, reverse=True)
    return dict(total=total, cap=cap, valid=valid, now_ms=now_ms,
                fault=fault, recs=recs)


def fmt(r, now_ms):
    age = (now_ms - r["t_ms"]) / 1000.0
    hx = " ".join(f"{b:02X}" for b in r["bytes"])
    return (f"seq={r['seq_lo']:>10}  age={age:8.3f}s  "
            f"site={SITE_NAMES.get(r['site'], str(r['site'])):>9}  "
            f"dest=0x{r['dest']:012X}  len={r['len']:<3}  "
            f"fid=0x{r['fid']:08X}  bytes= {hx}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bin")
    ap.add_argument("--near", type=lambda s: int(s, 0),
                    help="show writes overlapping [ADDR-win, ADDR+win)")
    ap.add_argument("--win", type=lambda s: int(s, 0), default=0x100)
    ap.add_argument("--site", help="filter by site name (e.g. NIFREE, bone3x3)")
    ap.add_argument("--fid", type=lambda s: int(s, 0), help="filter by form id")
    ap.add_argument("--last", type=int, help="show only the newest N matches")
    a = ap.parse_args()

    d = load(a.bin)
    print(f"ring: {d['total']} writes total, {len(d['recs'])} in ring, "
          f"crash at t+{d['now_ms']/1000.0:.1f}s, fault=0x{d['fault']:X}")

    per_site = {}
    for r in d["recs"]:
        per_site[r["site"]] = per_site.get(r["site"], 0) + 1
    print("in-ring by site: " + "  ".join(
        f"{SITE_NAMES.get(s, s)}={n}" for s, n in
        sorted(per_site.items(), key=lambda kv: -kv[1])))

    sel = d["recs"]
    if a.site is not None:
        want = {k for k, v in SITE_NAMES.items() if v.lower() == a.site.lower()}
        sel = [r for r in sel if r["site"] in want]
    if a.fid is not None:
        sel = [r for r in sel if r["fid"] == a.fid]
    if a.near is not None:
        lo, hi = a.near - a.win, a.near + a.win
        sel = [r for r in sel if r["dest"] < hi and r["dest"] + r["len"] > lo]
    if a.near is None and a.site is None and a.fid is None and a.last is None:
        return  # summary only
    if a.last:
        sel = sel[-a.last:]
    print(f"{len(sel)} match(es):")
    for r in sel:
        print(fmt(r, d["now_ms"]))


if __name__ == "__main__":
    main()
