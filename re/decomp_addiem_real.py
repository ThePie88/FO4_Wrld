"""Decomp the real AddItem path to understand why our direct call may silently fail.

Targets:
  - sub_1411735A0 : presumed "real AddItem" (full dump)
  - sub_1411825A0 : presumed "real RemoveItem" (full dump, for symmetric diff)
  - sub_141173900 : alternate "single ref add" path (first 6000 chars)

Also lists the xrefs TO each target (so we can see who normally calls it)
and, if present, expands the first-level callees (name + RVA) so we can tell
at-a-glance whether AddObjectToContainer (vt[0x7A]) or an OnItemAdded
dispatcher is involved.
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\addiem_real_report.txt"


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def decomp(ea, max_len=40000):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def list_xrefs_to(ea, fh, img, limit=20):
    log(f"  Xrefs TO 0x{ea:X} (RVA 0x{ea-img:X}):", fh)
    count = 0
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fn_name = get_name(fn.start_ea) if fn else "<no func>"
        fn_rva = (fn.start_ea - img) if fn else 0
        log(f"    from 0x{xref.frm:X}  in {fn_name} (RVA 0x{fn_rva:X})  type={xref.type}", fh)
        count += 1
        if count >= limit:
            log(f"    ... (truncated at {limit})", fh)
            break
    if count == 0:
        log("    <none>", fh)


def list_callees(ea, fh, img, limit=40):
    """First-level callees: names + RVAs."""
    log(f"  Callees FROM 0x{ea:X} (first-level, unique):", fh)
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log("    <no func>", fh); return
    seen = set()
    count = 0
    for head in idautils.FuncItems(fn.start_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            tgt = xref.to
            if tgt in seen:
                continue
            seen.add(tgt)
            tfn = ida_funcs.get_func(tgt)
            tname = get_name(tfn.start_ea if tfn else tgt)
            trva = (tgt - img)
            log(f"    call 0x{tgt:X}  RVA 0x{trva:X}  {tname}", fh)
            count += 1
            if count >= limit:
                log(f"    ... (truncated at {limit})", fh)
                return


def dump_target(label, rva, fh, img, full=True):
    ea = img + rva
    log("\n" + "=" * 78, fh)
    log(f"== {label}   EA=0x{ea:X}  RVA=0x{rva:X}", fh)
    log("=" * 78, fh)
    list_xrefs_to(ea, fh, img)
    log("", fh)
    list_callees(ea, fh, img)
    log("\n--- Hex-Rays ---", fh)
    if full:
        log(decomp(ea, 60000), fh)
    else:
        log(decomp(ea, 6000), fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh)
        fh.close()
        ida_pro.qexit(2)

    # Target 1: the "real AddItem" full dump
    dump_target("sub_1411735A0 (real AddItem, TARGET)", 0x11735A0, fh, img, full=True)

    # Target 2: the "real RemoveItem" full dump (symmetric comparison)
    dump_target("sub_1411825A0 (real RemoveItem, for symmetric diff)", 0x11825A0, fh, img, full=True)

    # Target 3: alternate single-ref path (truncated)
    dump_target("sub_141173900 (alternate single-ref add path)", 0x173900, fh, img, full=False)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
