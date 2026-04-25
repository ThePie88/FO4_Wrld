"""Verify sub_140500430 is THE world-item pickup entry.

- Dump all xrefs to sub_140500430.
- Decomp each caller.
- Check if any caller is a REFR vtable slot (-> that slot IS Activate).
- Also dump xrefs to sub_140504280 (LootAll-from-corpse) for contrast.
- Look at PlayerCharacter offset 0xD28 (=3368) to confirm this is
  "current rolled-over REFR" or "ActivateRef"
- Check sub_140D72DE0 @ 0xD72DE0 — expected to be
  'PlayerCharacter::ClearActivateRef' or similar
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report9.txt"

T_PICKUP_CAND = 0x500430
T_LOOTALL     = 0x504280
T_ACTIVATEREF_CLEAR = 0xD72DE0   # sub_140D72DE0
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


def decomp(ea, max_len=6000):
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


def find_vtable_slot(img, target_rva, vtable_rva=REFR_VTABLE_RVA, max_slots=0x200):
    vt_ea = img + vtable_rva
    tgt_ea = img + target_rva
    hits = []
    for slot in range(0, max_slots):
        slot_ea = vt_ea + slot * 8
        v = ida_bytes.get_qword(slot_ea)
        if v == tgt_ea:
            hits.append(slot)
    return hits


def scan_all_vtables_for_target(img, target_rva, fh):
    seg = ida_segment.get_segm_by_name(".rdata")
    if not seg:
        log("  no .rdata segment", fh)
        return
    target = img + target_rva
    ea = seg.start_ea
    end = seg.end_ea
    ea = (ea + 7) & ~7
    hits = []
    while ea + 8 <= end:
        v = ida_bytes.get_qword(ea)
        if v == target:
            hits.append(ea)
        ea += 8
    return hits


def dump_target(img, fh, rva, label):
    section(f"TARGET {label} sub_{rva+img:X} RVA=0x{rva:X}", fh)
    # Is it in REFR vtable?
    slots = find_vtable_slot(img, rva)
    if slots:
        for s in slots:
            log(f"  *** REFR vtable slot[0x{s:X}] ***", fh)
    else:
        log(f"  Not in REFR vtable", fh)
    # .rdata qword hits
    hits = scan_all_vtables_for_target(img, rva, fh)
    log(f"  .rdata qword hits: {len(hits)}", fh)
    for h in hits[:20]:
        cur = h
        vtable_name = None
        for _ in range(100):
            cur -= 8
            nm = ida_name.get_ea_name(cur)
            if nm and "??_7" in nm:
                vtable_name = nm
                slot_idx = (h - cur) // 8
                log(f"    -> {vtable_name} slot[0x{slot_idx:X}] @ 0x{h:X}", fh)
                break
        if vtable_name is None:
            log(f"    -> unknown vtable @ 0x{h:X}", fh)
    # Full decomp
    log("\n--- full decomp (up to 8000 chars) ---", fh)
    log(decomp(img + rva, 8000), fh)
    # Callers
    callers = list_xrefs_to(img + rva)
    log(f"\nUnique code callers: {len(callers)}", fh)
    for (cea, cname, fea_site, xtype) in callers:
        if cea is None:
            seg = idc.get_segm_name(fea_site)
            log(f"  -- raw xref from 0x{fea_site:X}  seg={seg}  type={xtype}", fh)
            continue
        crva = cea - img
        log(f"\n  -- caller {cname}  RVA=0x{crva:X}  site=0x{fea_site:X}", fh)
        # Is this caller in REFR vtable?
        caller_slots = find_vtable_slot(img, crva)
        if caller_slots:
            log(f"     *** THIS CALLER IS REFR vtable slot[0x{caller_slots[0]:X}] !!!", fh)
        # Any .rdata qword refs to the caller?
        c_hits = scan_all_vtables_for_target(img, crva, fh)
        if c_hits:
            log(f"     caller is in {len(c_hits)} .rdata slot(s)", fh)
            for h in c_hits[:5]:
                cur = h
                for _ in range(100):
                    cur -= 8
                    nm = ida_name.get_ea_name(cur)
                    if nm and "??_7" in nm:
                        slot_idx = (h - cur) // 8
                        log(f"       -> {nm} slot[0x{slot_idx:X}]", fh)
                        break
        log(f"  --- decomp first 3500 chars ---", fh)
        log(decomp(cea, 3500), fh)


def dump_cleanly(img, fh, rva, label):
    section(f"FN {label} sub_{rva+img:X} RVA=0x{rva:X}", fh)
    log(decomp(img + rva, 3000), fh)
    callers = list_xrefs_to(img + rva)
    log(f"Callers: {len(callers)}", fh)
    for c in callers[:15]:
        if c[0] is None:
            continue
        log(f"  {c[1]}  RVA=0x{c[0] - img:X}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    dump_target(img, fh, T_PICKUP_CAND, "sub_140500430 (PICKUP CANDIDATE)")
    dump_target(img, fh, T_LOOTALL, "sub_140504280 (LOOT-ALL candidate)")

    dump_cleanly(img, fh, T_ACTIVATEREF_CLEAR, "sub_140D72DE0 (ActivateRef clear?)")

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
