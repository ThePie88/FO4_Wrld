"""Who calls sub_140C4C9A0 (the event-133 producer wrapper)?

This wrapper is the "schedule a world-pickup" entry. Find and decompile
all callers to identify whether it's only called from ONE place (an
Activate handler) or many.

Also: find if sub_140C4C9A0 is in a vtable slot (likely!) so that the
hook can go at either the function or the vtable slot.

Output: re/world_pickup_report6.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report6.txt"

T_PRODUCER = 0xC4C9A0
T_CA7D20   = 0xCA7D20
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
            out.append((None, "<no func>", xref.frm, xref.type))
            continue
        key = fn.start_ea
        if key in seen:
            continue
        seen.add(key)
        out.append((fn.start_ea, get_name(fn.start_ea), xref.frm, xref.type))
    return out


def find_vtable_slot(img, target_rva):
    """Search REFR vtable first 0x200 slots for the target."""
    vt_ea = img + REFR_VTABLE_RVA
    tgt_ea = img + target_rva
    hits = []
    for slot in range(0, 0x200):
        slot_ea = vt_ea + slot * 8
        v = ida_bytes.get_qword(slot_ea)
        if v == tgt_ea:
            hits.append(slot)
    return hits


def scan_all_vtables_for_target(img, target_rva, fh):
    """Search all qwords in .rdata for target pointer."""
    section(f"Scan .rdata for any pointer == sub_{target_rva+img:X}", fh)
    seg = ida_segment.get_segm_by_name(".rdata")
    if not seg:
        log("  no .rdata segment", fh)
        return
    target = img + target_rva
    ea = seg.start_ea
    end = seg.end_ea
    # Align to 8
    ea = (ea + 7) & ~7
    hits = []
    while ea + 8 <= end:
        v = ida_bytes.get_qword(ea)
        if v == target:
            hits.append(ea)
        ea += 8
    log(f"  Total .rdata qword refs: {len(hits)}", fh)
    for h in hits[:30]:
        # Try to find which class vtable it's inside (walk backwards to ??_7)
        log(f"    0x{h:X}  (name: {get_name(h)})", fh)
        # Find nearest vtable marker
        cur = h
        for _ in range(60):
            cur -= 8
            nm = ida_name.get_ea_name(cur)
            if nm and "??_7" in nm:
                log(f"      -> likely vtable: {nm} @ 0x{cur:X}, slot idx=0x{(h-cur)//8:X}", fh)
                break


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # 1. Full decomp of producer
    section("Full decomp sub_140C4C9A0 (event-133 producer)", fh)
    log(decomp(img + T_PRODUCER, 5000), fh)

    # 2. Check if in REFR vtable
    section("Is sub_140C4C9A0 in REFR vtable?", fh)
    hits = find_vtable_slot(img, T_PRODUCER)
    if hits:
        for h in hits:
            log(f"  YES -- REFR vtable slot[0x{h:X}] @ RVA=0x{REFR_VTABLE_RVA+h*8:X}", fh)
    else:
        log("  NO -- not in first 0x200 REFR vtable slots", fh)

    # 3. Scan .rdata for references (any vtable)
    scan_all_vtables_for_target(img, T_PRODUCER, fh)

    # 4. All callers — decomp each
    section("Callers of sub_140C4C9A0", fh)
    xrefs = list_xrefs_to(img + T_PRODUCER)
    log(f"Total unique caller funcs: {len(xrefs)}", fh)
    for (cea, cname, from_ea, xtype) in xrefs:
        if cea is None:
            seg = idc.get_segm_name(from_ea)
            log(f"\n-- raw xref from 0x{from_ea:X}  seg={seg}  type={xtype}", fh)
            continue
        crva = cea - img
        seg = idc.get_segm_name(from_ea)
        log(f"\n-- caller {cname}  RVA=0x{crva:X}  site=0x{from_ea:X}  seg={seg}  type={xtype}", fh)
        log("--- decomp (first 3500 chars) ---", fh)
        log(decomp(cea, 3500), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
