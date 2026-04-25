"""Level-0 find_materializer — who actually writes REFR+0xF8?

vtable[167] = sub_140D57400 is suspiciously minimal. Two paths to verify
what actually populates the runtime BGSInventoryList:

  A. Decomp the two inner calls: sub_140511F10 + sub_141047020
  B. Brute-force scan: find all functions that write to [rcx + 0xF8] or
     [rdi + 0xF8] etc. where 0xF8 is the list ptr offset. Those are the
     real materializers.

Also look at sub_1416579C0 callers with size 0x80..0x120 — likely
BGSInventoryList allocations.

Output: re/find_materializer_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes, ida_ida

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\find_materializer_report.txt"

INTEREST = [
    ("vt167_sub_140D57400",       0xD57400),
    ("sub_140511F10",             0x511F10),
    ("sub_141047020",             0x1047020),
    ("vt168_sub_140D57420",       0xD57420),   # sibling slot — maybe related
    # The two functions sub_140272730 seen in sub_140502940 inner work:
    ("sub_140272730",             0x272730),
    # And sub_140254DD0 (was called in sub_140502940 body at line 439):
    ("sub_140254DD0",             0x254DD0),
    # sub_141659520 — the "array grow" helper
    ("sub_141659520",             0x1659520),
    # sub_140DABB40 was in vt[0x7A] body
    ("sub_140DABB40",             0xDABB40),
    # sub_14022CD40 was the "find owner" in vt[0x7A]
    ("sub_14022CD40",             0x22CD40),
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decomp(ea, max_len=10000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def find_writes_to_F8():
    """Scan code segments for `mov [rXX+0F8h], rYY` instructions.
    Return list of (ea, fn_start_ea, mnem_str)."""
    hits = []
    for seg_start, seg_end in ((s, idc.get_segm_end(s)) for s in idautils.Segments()):
        if not idc.get_segm_attr(seg_start, idc.SEGATTR_PERM) & 4:  # not executable
            continue
        ea = seg_start
        while ea < seg_end and ea != idc.BADADDR:
            mnem = idc.print_insn_mnem(ea)
            if mnem == "mov":
                op0 = idc.print_operand(ea, 0)
                op1 = idc.print_operand(ea, 1)
                if "+0F8h" in op0 and op0.startswith("["):
                    fn = ida_funcs.get_func(ea)
                    fn_start = fn.start_ea if fn else 0
                    hits.append((ea, fn_start, f"{op0}, {op1}"))
            ea = idc.next_head(ea, seg_end)
    return hits


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    for name, rva in INTEREST:
        log(f"\n==== {name} (RVA 0x{rva:X}) ====", fh)
        log(decomp(img + rva), fh)

    log("\n" + "=" * 72, fh)
    log("== SCAN: mov [+0xF8] writes (runtime list ptr materializers)", fh)
    log("=" * 72, fh)
    hits = find_writes_to_F8()
    log(f"  total hits: {len(hits)}", fh)
    seen_fns: set[int] = set()
    for ea, fn_ea, insn in hits[:200]:
        if fn_ea in seen_fns and len(seen_fns) > 50:
            continue
        seen_fns.add(fn_ea)
        log(f"  0x{ea:X}  (fn RVA 0x{fn_ea - img if fn_ea else 0:X})  {insn}", fh)

    # Decomp the top 5 unique functions that write +0xF8
    log("\n== top unique functions writing to +0xF8 ==", fh)
    unique_fns = []
    seen = set()
    for ea, fn_ea, insn in hits:
        if fn_ea and fn_ea not in seen:
            seen.add(fn_ea)
            unique_fns.append(fn_ea)
            if len(unique_fns) >= 8:
                break
    for fn_ea in unique_fns:
        log(f"\n---- fn @ RVA 0x{fn_ea - img:X} ----", fh)
        log(decomp(fn_ea, 8000), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
