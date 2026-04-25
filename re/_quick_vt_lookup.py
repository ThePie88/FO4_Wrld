"""Quick lookup: what vtable contains the slot at 0x143EA9FEC that points to sub_14031C310?"""
import ida_auto, ida_bytes, ida_name, ida_nalt, ida_funcs, ida_segment, ida_pro, idautils

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_quick_vt_lookup.txt"


def main():
    fh = open(OUT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    fh.write(f"[+] Image base: 0x{img:X}\n")

    slot_ea = 0x143EA9FEC
    target  = ida_bytes.get_qword(slot_ea)
    fh.write(f"slot @ 0x{slot_ea:X} RVA 0x{slot_ea-img:X}  target=0x{target:X}\n")

    # Scan backwards in 8-byte steps looking for start of vtable (previous qword NOT a func in .text)
    seg = ida_segment.getseg(slot_ea)
    if seg:
        fh.write(f"segment: {ida_segment.get_segm_name(seg)} [0x{seg.start_ea:X}..0x{seg.end_ea:X}]\n")

    # Walk backwards, listing up to 40 preceding qwords
    fh.write("\n-- preceding 40 qwords (so we can find the RTTI/vtable head) --\n")
    for i in range(40, -1, -1):
        ea = slot_ea - i * 8
        q = ida_bytes.get_qword(ea)
        n = ida_name.get_ea_name(ea) or ""
        tn = ida_name.get_ea_name(q) or ""
        fn = ida_funcs.get_func(q)
        is_func = "F" if fn else " "
        fh.write(f"  [{-i:+d}] 0x{ea:X}  q=0x{q:X} {is_func}  {n!s:40s}  ->  {tn}\n")

    # Also walk forwards to find slot index
    fh.write("\n-- following 20 qwords --\n")
    for i in range(1, 20):
        ea = slot_ea + i * 8
        q = ida_bytes.get_qword(ea)
        n = ida_name.get_ea_name(ea) or ""
        tn = ida_name.get_ea_name(q) or ""
        fn = ida_funcs.get_func(q)
        is_func = "F" if fn else " "
        fh.write(f"  [+{i}] 0x{ea:X}  q=0x{q:X} {is_func}  {n!s:40s}  ->  {tn}\n")

    # Look at xrefs TO the slot itself
    fh.write(f"\n-- xrefs TO slot 0x{slot_ea:X} (who reads this vtable entry) --\n")
    cnt = 0
    for xref in idautils.XrefsTo(slot_ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fn_name = ida_name.get_ea_name(fn.start_ea) if fn else "<no func>"
        fh.write(f"  from 0x{xref.frm:X} in {fn_name} type={xref.type}\n")
        cnt += 1
        if cnt >= 20: break

    fh.close()
    ida_pro.qexit(0)


main()
