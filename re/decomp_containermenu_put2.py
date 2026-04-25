"""Follow-up: which vtable(s) contain the raw xrefs to the AddItem/RemoveItem
real functions?  We observed xrefs with no enclosing function at RVAs
~0x2B54604 (AddItem) and ~0x2CD4FA8 (RemoveItem) — these look like .rdata
vtable entries.  Identify the enclosing symbol (e.g. "??_7AddItemFunctor...").

Also: dump the ContainerMenu vftable slots (0x25A45C8) — a dedicated slot
for "transfer" / "put" should surface here.

Also: for each caller of sub_140502940 and 0x5007B0, grep its decomp for
call-through patterns that look like menu callback dispatch (sub_FF*,
MenuManager).  Print the callers sorted by match-score.
"""
import re
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, ida_segment, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\containermenu_put_report2.txt"

T_ADDITEM_REAL       = 0x11735A0
T_REMOVEITEM_REAL    = 0x11825A0
T_ADDOBJ_WORKHORSE   = 0x0502940
T_ADDOBJ_INNER       = 0x05007B0


def log(m, fh):
    print(m); fh.write(m + "\n"); fh.flush()


def section(t, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {t}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, cap=3000):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= cap else s[:cap] + "\n...<trunc>"
    except Exception as e:
        return f"<err: {e}>"


def nearest_named_before(ea, max_back=0x800):
    """Walk back from ea looking for the nearest labelled .rdata symbol
    (typically a vtable ??_7Xxxx@@6B@ or similar).  Return (sym_ea, name)."""
    cur = ea
    for _ in range(max_back):
        n = ida_name.get_ea_name(cur)
        if n and not n.startswith("unk_") and not n.startswith("off_"):
            return (cur, n)
        cur -= 1
        if cur < 0x140000000:
            break
    return (0, "<none>")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # --- 1) Identify the vtables that reference AddItemReal/RemoveItemReal
    for label, rva in [
        ("AddItemReal (sub_1411735A0)",     T_ADDITEM_REAL),
        ("RemoveItemReal (sub_1411825A0)",  T_REMOVEITEM_REAL),
        ("AddObjWorkhorse (sub_140502940)", T_ADDOBJ_WORKHORSE),
        ("AddObjInner (sub_1405007B0)",     T_ADDOBJ_INNER),
    ]:
        section(f"RAW-XREFS (no enclosing func) for {label}", fh)
        ea = img + rva
        for xref in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(xref.frm)
            if fn is not None:
                continue  # already reported
            (sym_ea, sym_name) = nearest_named_before(xref.frm)
            rel = xref.frm - sym_ea if sym_ea else 0
            log(f"  xref site 0x{xref.frm:X}   nearest label: {sym_name} @ 0x{sym_ea:X} (offset +0x{rel:X})", fh)

    # --- 2) Dump ContainerMenu vftable and ContainerMenuBase vftable slots
    for label, vt_ea in [
        ("ContainerMenu@@6B@",             0x1425A45C8),
        ("ContainerMenu@@6B@_0",           0x1425A46D8),
        ("ContainerMenu@@6B@_1",           0x1425A4728),
        ("ContainerMenu@@6B@_2",           0x1425A4740),
        ("ContainerMenuBase@@6B@",         0x14252D148),
        ("ContainerMenuBase@@6B@_0",       0x14252D2C0),
        ("ContainerMenuBase@@6B@_1",       0x14252D258),
        ("ContainerMenuBase@@6B@_2",       0x14252D2A8),
        ("FXQuantityMenu@ContainerMenuBase@@6B@",   0x14252D118),
        ("FXQuantityMenu@ContainerMenuBase@@6B@_0", 0x14252D130),
    ]:
        section(f"Vtable dump: {label} @ 0x{vt_ea:X}", fh)
        for k in range(48):
            slot = vt_ea + k * 8
            t = ida_bytes.get_qword(slot)
            if t < img or t >= img + 0x10000000:
                log(f"  slot[{k:2}] -> 0x{t:X}   <non-code>", fh)
                break
            n = get_name(t)
            log(f"  slot[{k:2}] -> 0x{t:X}  RVA=0x{t-img:X}  {n}", fh)

    # --- 3) Decomp ContainerMenu main constructor / handlers if findable
    # Names with ContainerMenu but NOT in vftable / RTTI / string aliases
    section("Symbols referencing ContainerMenu that are CODE (not vtable/RTTI/string)", fh)
    seen_code = []
    for ea, name in idautils.Names():
        low = name.lower()
        if "containermenu" not in low:
            continue
        # skip string literals
        if name.startswith(("a", "str_")) and not name.startswith("??"):
            continue
        # skip pure vtable / rtti symbols
        if "??_7" in name or "??_R" in name:
            continue
        fn = ida_funcs.get_func(ea)
        if fn is None:
            continue
        seen_code.append((ea, name))
    seen_code.sort()
    log(f"Total code symbols: {len(seen_code)}", fh)
    for ea, name in seen_code:
        log(f"  {name} @ 0x{ea:X}  RVA=0x{ea-img:X}", fh)

    # --- 4) TransferItem string refs — who calls the code that uses it?
    section("TransferItem / aTransferitem string xrefs", fh)
    # look at every name that contains 'ransferitem' (case-insensitive)
    rx = re.compile(r"ransferitem", re.IGNORECASE)
    for ea, name in idautils.Names():
        if not rx.search(name):
            continue
        log(f"\n  STRING/SYM: {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)
        for xref in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(xref.frm)
            if fn:
                log(f"    referenced by {get_name(fn.start_ea)} @ 0x{fn.start_ea:X} (site 0x{xref.frm:X})", fh)
            else:
                (sym_ea, sym_name) = nearest_named_before(xref.frm)
                log(f"    raw xref @ 0x{xref.frm:X}  nearest label: {sym_name} @ 0x{sym_ea:X}", fh)

    # --- 5) Same for DepositItem / MoveToContainer (maybe present)
    section("DepositItem / MoveToContainer string xrefs (if any)", fh)
    rx2 = re.compile(r"depositit|movetocontainer", re.IGNORECASE)
    found = 0
    for ea, name in idautils.Names():
        if not rx2.search(name):
            continue
        found += 1
        log(f"\n  SYM: {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)
        for xref in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(xref.frm)
            if fn:
                log(f"    referenced by {get_name(fn.start_ea)} @ 0x{fn.start_ea:X}", fh)
            else:
                (sym_ea, sym_name) = nearest_named_before(xref.frm)
                log(f"    raw xref @ 0x{xref.frm:X}  nearest: {sym_name} @ 0x{sym_ea:X}", fh)
    if found == 0:
        log("  <no deposit/moveToContainer symbols in IDB>", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
