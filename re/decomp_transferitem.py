"""Dump the function that references the 'TransferItem' Scaleform string.

Finding: sub_140A548B0 references aTransferitem; it is ContainerMenuBase's
vtable slot [2] (also appearing in ContainerMenu's vtable and FXQuantityMenu's
vtable at slot [8]/[5] respectively). This is the Scaleform callback router.

Goal of this script:
  - Full decomp of sub_140A548B0 (50k chars).
  - Full decomp of sub_140A54830, sub_140A54850, sub_140A548B0 (the 3 adjacent
    vtable slots on ContainerMenuBase — likely {Invoke, ProcessMessage,
    DispatchEvent} cluster).
  - For each call site inside sub_140A548B0 with target in executable pages,
    list callee name + RVA. We want to spot the one that performs the engine
    AddObject call.
  - Also decomp nearby ContainerMenuBase slot handlers:
        slot[0] sub_140A57970, slot[15] sub_140A52700, slot[34] sub_140A57908,
        slot[35] sub_140A54A30 -> plausible Open/Close/UpdateInventory handlers
  - Dump xrefs from sub_140A548B0 to sub_1411735A0, sub_140502940,
    sub_1405007B0 (none of the trace candidates in existing reports
    directly showed it — but the string ref is very strong).
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\transferitem_report.txt"


def log(m, fh):
    print(m); fh.write(m + "\n"); fh.flush()


def section(t, fh):
    log("\n" + "=" * 78, fh); log(f"== {t}", fh); log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, cap=50000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= cap else s[:cap] + "\n...<trunc>"
    except Exception as e:
        return f"<err: {e}>"


def list_callees(ea, fh, img, limit=80):
    fn = ida_funcs.get_func(ea)
    if fn is None: return
    seen = set()
    count = 0
    for head in idautils.FuncItems(fn.start_ea):
        for x in idautils.XrefsFrom(head, 0):
            if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            if x.to in seen: continue
            seen.add(x.to)
            log(f"    call -> 0x{x.to:X} RVA=0x{x.to-img:X}  {get_name(x.to)}", fh)
            count += 1
            if count >= limit:
                log("    ...(truncated)", fh); return


def list_strings_in_func(ea, fh, img):
    fn = ida_funcs.get_func(ea)
    if fn is None: return
    for head in idautils.FuncItems(fn.start_ea):
        for x in idautils.XrefsFrom(head, 0):
            if x.to < img: continue
            # read ASCII if present
            s = idc.get_strlit_contents(x.to, -1, idc.STRTYPE_C)
            if s and len(s) >= 3 and len(s) < 80:
                try:
                    txt = s.decode('utf-8', errors='replace')
                    if all(32 <= ord(c) < 127 for c in txt):
                        log(f"    str @ 0x{x.to:X}: {txt!r}", fh)
                except Exception:
                    pass


def dump(label, ea, fh, img, cap=50000):
    section(f"{label}   at 0x{ea:X} RVA=0x{ea-img:X}", fh)
    log("-- callees (first-level) --", fh)
    list_callees(ea, fh, img)
    log("-- strings referenced --", fh)
    list_strings_in_func(ea, fh, img)
    log("-- Hex-Rays --", fh)
    log(decomp(ea, cap), fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] hexrays missing", fh); fh.close(); ida_pro.qexit(2)

    # The prime suspect: function that references the "TransferItem" string
    dump("sub_140A548B0 — Scaleform callback router (references aTransferitem)",
         img + 0xA548B0, fh, img, cap=60000)

    # Adjacent vtable slots on ContainerMenuBase — candidate handlers
    for label, rva in [
        ("ContainerMenuBase::vt[0] sub_140A57970", 0xA57970),
        ("ContainerMenuBase::vt[1] sub_140A54210", 0xA54210),
        ("ContainerMenuBase::vt[4] sub_140A54850", 0xA54850),
        ("ContainerMenuBase::vt[5] sub_140A54830", 0xA54830),
        ("ContainerMenuBase::vt[15] sub_140A52700",0xA52700),
        ("ContainerMenuBase::vt[34] sub_140A57908",0xA57908),
        ("ContainerMenuBase::vt[35] sub_140A54A30",0xA54A30),
        ("ContainerMenuBase::vt[38] sub_140A54B00",0xA54B00),
        ("ContainerMenuBase::vt[45] sub_140A54BD0",0xA54BD0),
        ("ContainerMenu::ctor? sub_141041000",     0x1041000),
    ]:
        dump(label, img + rva, fh, img, cap=15000)

    log("\n==== done ====", fh); fh.close(); ida_pro.qexit(0)


main()
