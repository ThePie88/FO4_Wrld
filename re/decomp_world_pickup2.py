"""Follow up on sub_140CA7D20 (strong candidate for world-pickup).

- Lists callers of sub_140CA7D20 and decompiles each.
- Checks if any caller is an Activate-vtable slot on the REFR/Player vtable.
- Dumps decomp of sub_140CA7D20 full (up to 8000 chars).
- Check qword_1431E2D50 meaning (look at its xrefs).
- Also dump callers of sub_140988080 (UI-hints=Inventory) and sub_140989A40.

Output: re/world_pickup_report2.txt
"""
import re
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report2.txt"

TARGET_CA7D20 = 0xCA7D20     # prime suspect
TARGET_988080 = 0x988080     # UI-hints=Inventory caller #1
TARGET_989A40 = 0x989A40     # UI-hints=Inventory caller #2
TARGET_504280 = 0x504280     # AddObject wrapper
TARGET_504FC0 = 0x504FC0
TARGET_508280 = 0x508280     # called from 504280
TARGET_CACB80 = 0xCACB80
TARGET_CAE6A0 = 0xCAE6A0     # ContainerMenu path
TARGET_DA2330 = 0xDA2330
TARGET_106BE80 = 0x106BE80
TARGET_CA7D20_player_sing = 0x31E2D50  # qword_1431E2D50 - possible second player sing
TARGET_32D2260 = 0x32D2260    # documented player singleton

REFR_VTABLE_RVA = 0x2564838


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=4000):
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


def list_xrefs_to(ea):
    out = []
    seen = set()
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn is None:
            out.append((None, "<no func>", xref.frm))
            continue
        key = fn.start_ea
        if key in seen:
            continue
        seen.add(key)
        out.append((fn.start_ea, get_name(fn.start_ea), xref.frm))
    return out


def dump_fn(fh, img, rva, label, max_len=8000):
    ea = img + rva
    section(f"FULL DECOMP: {label}  sub_{ea:X}  RVA=0x{rva:X}", fh)
    d = decomp(ea, max_len)
    log(d, fh)


def dump_callers(fh, img, rva, label):
    ea = img + rva
    section(f"XREFS TO {label}  sub_{ea:X}  RVA=0x{rva:X}", fh)
    xrefs = list_xrefs_to(ea)
    log(f"Found {len(xrefs)} unique caller function(s).", fh)
    for (cea, cname, from_ea) in xrefs:
        if cea is None:
            log(f"\n-- raw xref from 0x{from_ea:X} (no enclosing func)", fh)
            continue
        crva = cea - img
        vflag = " [VTABLE-RDATA]" if (cname and ("vftable" in cname.lower() or "??_7" in cname)) else ""
        log(f"\n-- caller {cname}  RVA=0x{crva:X}  site=0x{from_ea:X}{vflag}", fh)
        d = decomp(cea, 3000)
        log("--- decomp (first 3000 chars) ---", fh)
        log(d, fh)


def find_vtable_slot(img, slot_target_rva):
    """Scan REFR vtable; return list of slot-indices whose entry == target."""
    vt_ea = img + REFR_VTABLE_RVA
    tgt_ea = img + slot_target_rva
    hits = []
    for slot in range(0, 0x150):
        slot_ea = vt_ea + slot * 8
        v = ida_bytes.get_qword(slot_ea)
        if v == tgt_ea:
            hits.append(slot)
    return hits


def dump_xref_sites_rdata(fh, img, rva, label):
    """Look at all xrefs to target RVA — including rdata-only ones — to
    identify if it's referenced in a vtable."""
    ea = img + rva
    section(f"ALL XREFS (any type) to {label}  @0x{ea:X}  RVA=0x{rva:X}", fh)
    for xref in idautils.XrefsTo(ea, 0):
        seg = idc.get_segm_name(xref.frm)
        log(f"  type={xref.type}  from=0x{xref.frm:X}  seg={seg}  name={get_name(xref.frm)}", fh)


def dump_qword_xrefs(fh, img, rva, label):
    ea = img + rva
    section(f"XREFS TO {label}  @0x{ea:X}  RVA=0x{rva:X}  (data global)", fh)
    refs = list(idautils.XrefsTo(ea, 0))
    log(f"Found {len(refs)} xref(s).", fh)
    seen_fns = set()
    for x in refs:
        fn = ida_funcs.get_func(x.frm)
        if fn is None:
            continue
        if fn.start_ea in seen_fns:
            continue
        seen_fns.add(fn.start_ea)
    log(f"Unique enclosing functions: {len(seen_fns)}", fh)
    for fea in sorted(seen_fns):
        log(f"  {get_name(fea)}  RVA=0x{fea - img:X}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Prime suspect full decomp
    dump_fn(fh, img, TARGET_CA7D20, "PRIME SUSPECT sub_140CA7D20", 8000)

    # Find if TARGET_CA7D20 is in the REFR vtable
    section("Is sub_140CA7D20 in REFR vtable?", fh)
    hits = find_vtable_slot(img, TARGET_CA7D20)
    if hits:
        for h in hits:
            log(f"  YES -- REFR vtable slot[0x{h:X}] @ RVA=0x{REFR_VTABLE_RVA + h*8:X}", fh)
    else:
        log("  NO -- not in first 0x150 slots of REFR vtable", fh)

    # Its callers
    dump_callers(fh, img, TARGET_CA7D20, "sub_140CA7D20")
    dump_xref_sites_rdata(fh, img, TARGET_CA7D20, "sub_140CA7D20")

    # Secondary candidate: UI-hints=Inventory caller
    dump_fn(fh, img, TARGET_988080, "UI-hints=Inv #1 sub_140988080", 6000)
    dump_callers(fh, img, TARGET_988080, "sub_140988080")

    dump_fn(fh, img, TARGET_989A40, "UI-hints=Inv #2 sub_140989A40", 6000)
    dump_callers(fh, img, TARGET_989A40, "sub_140989A40")

    # And check what qword_1431E2D50 is used for
    dump_qword_xrefs(fh, img, TARGET_CA7D20_player_sing, "qword_1431E2D50 (?? second player ptr)")

    # Also for completeness: 504280, 504FC0
    dump_fn(fh, img, TARGET_504280, "sub_140504280 (AddObject wrapper)", 6000)
    dump_callers(fh, img, TARGET_504280, "sub_140504280")
    dump_fn(fh, img, TARGET_504FC0, "sub_140504FC0 (AddObject wrapper2)", 6000)
    dump_callers(fh, img, TARGET_504FC0, "sub_140504FC0")

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
