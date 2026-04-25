"""Find out what vtables hold sub_140D62930 and what slot name it is.

- For each of the 4 xrefs (all in .rdata/.pdata), find the enclosing
  vtable and surrounding slots.
- Also look at what sub_140D62930 does more carefully: what virtual it
  is for PlayerCharacter.
- Map slot 0xEC — this should be some PlayerCharacter-specific method.
- Check who calls PlayerCharacter vtable slot 0xEC (look for instruction
  patterns *(vtable + 0xEC*8)(...) == *(vtable + 1888)(...)).
- Scan .text for 'call qword ptr [rax+760h]' or similar (0xEC*8 = 0x760).
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report_final3.txt"

T_D62930 = 0xD62930
PC_VTABLE = 0x2564838


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


def scan_text_for_displ_call(displ_const, img, fh):
    """Search .text for `call qword ptr [reg + displ_const]` instructions.
    This finds *(rax + 0x760) where 0x760 = 0xEC * 8 = slot 0xEC.
    Also disp 1888 = slot 0xEC.

    Heuristic: walk each head, check if it's a call with indirect
    operand, if the indirect operand's displacement equals displ_const.
    """
    section(f"Search .text for `call qword ptr [reg+0x{displ_const:X}]` (potential vt[0x{displ_const//8:X}] calls)", fh)
    seg = ida_segment.get_segm_by_name(".text")
    ea = seg.start_ea
    end = seg.end_ea
    count = 0
    hits = []
    max_scan = 60_000_000
    while ea < end:
        count += 1
        if count > max_scan:
            log(f"  [scan limit {max_scan} reached]", fh)
            break
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem == "call":
            op0_type = idc.get_operand_type(ea, 0)
            if op0_type == idc.o_displ or op0_type == idc.o_phrase:
                # Read displacement
                disasm = idc.generate_disasm_line(ea, 0)
                # Check for specific displacement
                if f"+{displ_const:X}h" in disasm or f"+{displ_const:X}]" in disasm or f"+0{displ_const:X}h" in disasm:
                    hits.append(ea)
        nxt = idc.next_head(ea)
        if nxt == idc.BADADDR or nxt <= ea:
            break
        ea = nxt
    log(f"  Total hits: {len(hits)} (scanned {count:,} insns)", fh)
    for ea in hits[:40]:
        fn = ida_funcs.get_func(ea)
        fname = get_name(fn.start_ea) if fn else "<no fn>"
        frva = (fn.start_ea - img) if fn else 0
        log(f"  0x{ea:X}  in {fname} RVA=0x{frva:X}", fh)
        # Print 4 lines of context
        cur = ea
        for _ in range(2):
            p = idc.prev_head(cur)
            if p == idc.BADADDR:
                break
            cur = p
        for _ in range(5):
            log(f"    0x{cur:X}  {idc.generate_disasm_line(cur, 0)}", fh)
            nxt = idc.next_head(cur)
            if nxt == idc.BADADDR:
                break
            cur = nxt


def inspect_vtable_neighborhood(vt_name_or_ea, center_slot, radius, img, fh):
    """For a vtable, dump slot[center - radius] .. slot[center + radius]."""
    section(f"Vtable @ {vt_name_or_ea:X} slots [0x{center_slot - radius:X} .. 0x{center_slot + radius:X}]", fh)
    for i in range(center_slot - radius, center_slot + radius + 1):
        slot_ea = vt_name_or_ea + i * 8
        t = ida_bytes.get_qword(slot_ea)
        name = get_name(t) if t else "<null>"
        rva = (t - img) if t else 0
        marker = " <<<" if i == center_slot else ""
        log(f"  slot[0x{i:X}] -> {name}  RVA=0x{rva:X}{marker}", fh)


def find_enclosing_vtable(img, ea_ref, fh):
    """For a qword reference at ea_ref, walk backwards to find the
    nearest ??_7 symbol marking a vtable."""
    cur = ea_ref
    for _ in range(400):
        cur -= 8
        nm = ida_name.get_ea_name(cur)
        if nm and "??_7" in nm:
            slot_idx = (ea_ref - cur) // 8
            return (nm, cur, slot_idx)
    return (None, 0, 0)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # For each of the 4 xrefs, find vtable
    section("Identify each vtable that contains sub_140D62930", fh)
    target = img + T_D62930
    seg = ida_segment.get_segm_by_name(".rdata")
    ea = seg.start_ea
    end = seg.end_ea
    ea = (ea + 7) & ~7
    while ea + 8 <= end:
        v = ida_bytes.get_qword(ea)
        if v == target:
            nm, vt_ea, slot_idx = find_enclosing_vtable(img, ea, fh)
            if nm:
                log(f"  0x{ea:X} => {nm} slot[0x{slot_idx:X}] vtable=0x{vt_ea:X} RVA=0x{vt_ea-img:X}", fh)
            else:
                # Walk further back for unknown
                cur = ea
                found_any = False
                for back in range(800):
                    cur -= 8
                    nm = ida_name.get_ea_name(cur)
                    if nm:
                        log(f"  0x{ea:X} => (unknown vtable; nearest sym '{nm}' @ 0x{cur:X}, delta {(ea-cur)//8} slots)", fh)
                        found_any = True
                        break
                if not found_any:
                    log(f"  0x{ea:X} => no nearby symbol", fh)
        ea += 8

    # Now dump PC vtable neighborhood around 0xEC
    pc_vt_ea = img + PC_VTABLE
    log(f"\nPlayerCharacter vtable @ 0x{pc_vt_ea:X}", fh)
    inspect_vtable_neighborhood(pc_vt_ea, 0xEC, 8, img, fh)

    # Dump TESObjectREFR vtable around 0xEC for comparison
    tesrefr_vt = img + 0x249CBC8
    log(f"\nTESObjectREFR vtable @ 0x{tesrefr_vt:X}", fh)
    inspect_vtable_neighborhood(tesrefr_vt, 0xEC, 8, img, fh)

    # Scan for calls to [reg + 0x760]
    scan_text_for_displ_call(0x760, img, fh)

    # Also look at PlayerCharacter slots 0xE0..0xF0 decomp briefly
    section("PlayerCharacter vtable slots 0xE0..0xF0 decomp brief", fh)
    for i in range(0xE0, 0xF1):
        slot_ea = pc_vt_ea + i * 8
        t = ida_bytes.get_qword(slot_ea)
        if t == 0 or t == 0xFFFFFFFFFFFFFFFF:
            continue
        d = decomp(t, 1200)
        log(f"\n  slot[0x{i:X}] -> {get_name(t)}  RVA=0x{t-img:X}", fh)
        log("    decomp:", fh)
        log(d, fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
