"""Finalize: confirm sub_140D62930 (REFR vtable slot 0xEC) is the Activate.

- Decomp full sub_140D62930.
- Find all xrefs to it (including vtable refs in other classes).
- Does it also appear in Actor/PlayerCharacter/etc vtables?
- Find its callers.
- Map what slot 0xEC is on TESObjectREFR (which class is the 'real'
  vtable holder of slot 0xEC).
- Also look at ref vtable slot 0xEC via TESObjectREFR vtable @ 0x249CBC8.
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report_final2.txt"

T_D62930 = 0xD62930
T_PICKUP = 0x500430
TESREFR_VTABLE = 0x249CBC8
PC_VTABLE      = 0x2564838


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=12000):
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


def scan_all_vtables_for_target(img, target_rva, fh, label):
    seg = ida_segment.get_segm_by_name(".rdata")
    target = img + target_rva
    ea = seg.start_ea
    end = seg.end_ea
    ea = (ea + 7) & ~7
    hits = []
    while ea + 8 <= end:
        if ida_bytes.get_qword(ea) == target:
            hits.append(ea)
        ea += 8
    section(f"{label}: .rdata qword refs ({len(hits)} total)", fh)
    for h in hits[:30]:
        cur = h
        found_vtable = None
        for back in range(200):
            cur -= 8
            nm = ida_name.get_ea_name(cur)
            if nm and "??_7" in nm:
                slot_idx = (h - cur) // 8
                log(f"  0x{h:X} => {nm} slot[0x{slot_idx:X}] (vtable RVA=0x{cur-img:X})", fh)
                found_vtable = nm
                break
        if found_vtable is None:
            log(f"  0x{h:X} => <unknown vtable>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Full decomp of D62930
    section("Full decomp sub_140D62930 (the slot[0xEC] candidate)", fh)
    log(decomp(img + T_D62930, 10000), fh)

    # What classes reference this function? (slot placements)
    scan_all_vtables_for_target(img, T_D62930, fh, "sub_140D62930 vtable placements")

    # What classes reference the pickup helper?
    scan_all_vtables_for_target(img, T_PICKUP, fh, "sub_140500430 vtable placements")

    # Report TESObjectREFR slot 0xEC (if exists)
    section("Check TESObjectREFR vtable @ 0x249CBC8 slot 0xEC", fh)
    rt_ea = img + TESREFR_VTABLE
    slot_ea = rt_ea + 0xEC * 8
    t = ida_bytes.get_qword(slot_ea)
    log(f"  slot[0xEC] @ 0x{slot_ea:X} -> {get_name(t)}  RVA=0x{t - img:X}", fh)

    # Full scan: all REFR-ish vtables' slot 0xEC
    section("For each vtable whose name matches, what's at slot 0xEC?", fh)
    for vt_rva in [0x249CBC8, PC_VTABLE]:
        vt_ea = img + vt_rva
        nm = get_name(vt_ea)
        slot_ea = vt_ea + 0xEC * 8
        t = ida_bytes.get_qword(slot_ea)
        log(f"  {nm} vtable slot[0xEC] -> {get_name(t)}  RVA=0x{t-img:X}", fh)

    # All callers
    section("All callers of sub_140D62930", fh)
    callers = list_xrefs_to(img + T_D62930)
    log(f"Unique code callers: {len(callers)}", fh)
    for (cea, cname, from_ea, xtype) in callers:
        if cea is None:
            seg = idc.get_segm_name(from_ea)
            log(f"  -- raw xref from 0x{from_ea:X}  seg={seg}  type={xtype}", fh)
            continue
        crva = cea - img
        log(f"\n  -- {cname}  RVA=0x{crva:X}  site=0x{from_ea:X}", fh)
        log("     decomp first 3000 chars:", fh)
        log(decomp(cea, 3000), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
