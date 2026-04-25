"""
Scan .rdata for ALL qword refs to sub_14221E6A0 (CONSUMER) and
sub_1421DC480 (PRODUCER). Also check for thunks/jumps.
"""
import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_hexrays
BASE = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\hookcheck_report6.txt"

def dump(m, f=None):
    print(m)
    if f: f.write(m+"\n")

with open(OUT, "w") as f:
    dump("="*80, f)
    dump(" HOOK CHECK 6 - FINAL vtable/qword scan", f)
    dump("="*80, f)

    # ==== scan .rdata for qwords pointing to CONSUMER/PRODUCER ====
    TARGETS = [
        (0x14221E6A0, "CONSUMER sub_14221E6A0"),
        (0x1421DC480, "PRODUCER sub_1421DC480"),
        (0x14223F110, "per-geometry WVP sub_14223F110"),
        (0x1421DC190, "PRODUCER parent"),
        (0x1421DBAF0, "PRODUCER grandparent"),
    ]
    # also look in .data
    for seg_name in [".rdata", ".data", ".pdata"]:
        seg = idaapi.get_segm_by_name(seg_name)
        if not seg:
            continue
        dump(f"\n### Scan {seg_name} (0x{seg.start_ea:X} - 0x{seg.end_ea:X}) ###", f)
        for tgt, label in TARGETS:
            dump(f"\n  Looking for qword = 0x{tgt:X} ({label}):", f)
            ea = seg.start_ea
            hits = []
            while ea < seg.end_ea:
                v = ida_bytes.get_qword(ea)
                if v == tgt:
                    hits.append(ea)
                ea += 8
            for h in hits[:30]:
                # find which vtable this belongs to (scan back)
                dump(f"    hit @ 0x{h:X}  (RVA 0x{h-BASE:X})", f)
                # look back 8*0..8*32 to find classname RTTI
                for back in range(0, 40*8, 8):
                    v = ida_bytes.get_qword(h - back)
                    if v == 0 and back > 0:
                        continue
                    # test if looks like start of vtable (qword is code addr inside binary)
                    # simpler: dump 5 qwords before
                pass
            dump(f"    total hits: {len(hits)}", f)

    # ==== also use DataRefsTo fully ====
    dump("\n\n### DataRefsTo for each target ###", f)
    for tgt, label in TARGETS:
        dump(f"\n  {label}:", f)
        refs = list(idautils.DataRefsTo(tgt))
        for r in refs[:20]:
            sn = idc.get_segm_name(r) or "?"
            dump(f"    0x{r:X}  seg={sn}", f)
        dump(f"    total refs: {len(refs)}", f)

    # ==== get Fallout4 PE signature to confirm binary loaded correctly ====
    dump("\n\n### Binary identification ###", f)
    import ida_nalt
    info = idaapi.get_inf_structure()
    dump(f"  base: 0x{info.min_ea:X}", f)
    dump(f"  entry: 0x{info.start_ip:X}", f)
    # get file path
    dump(f"  path: {idaapi.get_input_file_path()}", f)
    dump(f"  md5: {ida_nalt.retrieve_input_file_md5()}", f)

    # verify prologue byte of each target matches expected MinHook-compatible
    dump("\n\n### Prologue byte verification ###", f)
    for tgt, label in TARGETS:
        b = ida_bytes.get_bytes(tgt, 8)
        bhex = b.hex() if b else "??"
        dump(f"  {label} @ 0x{tgt:X}: first8={bhex}", f)

    # LAST: find what sub_14221E6A0 IS at index 8 in — so we know the vtable
    # that actually has it.
    CONS = 0x14221E6A0
    dump("\n\n### Find vtables containing CONSUMER sub_14221E6A0 ###", f)
    for seg_name in [".rdata", ".data"]:
        seg = idaapi.get_segm_by_name(seg_name)
        if not seg:
            continue
        ea = seg.start_ea
        hits = []
        while ea < seg.end_ea:
            v = ida_bytes.get_qword(ea)
            if v == CONS:
                hits.append(ea)
            ea += 8
        for h in hits:
            # dump 16 qwords before to find start of vtable
            dump(f"\n    hit @ 0x{h:X}:", f)
            # find start of vtable: walk back while qwords point into .text
            start = h
            while start >= seg.start_ea:
                v = ida_bytes.get_qword(start - 8)
                if 0x140000000 <= v < 0x150000000:
                    start -= 8
                else:
                    break
            dump(f"    vtable start: 0x{start:X}  (RVA 0x{start-BASE:X})", f)
            # dump slots 0..16 with slot index
            slot_of_cons = (h - start) // 8
            dump(f"    CONSUMER is at slot[{slot_of_cons}]", f)
            for i in range(min(20, slot_of_cons + 3)):
                v = ida_bytes.get_qword(start + i*8)
                nm = idc.get_func_name(v) or ""
                dump(f"      [{i:2}] -> 0x{v:X}  {nm}", f)

    dump("\nDONE.", f)
idc.qexit(0)
