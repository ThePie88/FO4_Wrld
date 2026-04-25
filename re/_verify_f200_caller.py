"""Find xrefs TO sub_14033F200 and dump caller context."""
import idc
import ida_xref
import ida_hexrays
ida_hexrays.init_hexrays_plugin()

def log(fh, msg):
    print(msg, flush=True)
    fh.write(msg + "\n")

def dump_range(fh, start, end, label):
    log(fh, f"\n-- {label} --")
    ea = start
    while ea <= end:
        log(fh, f"  0x{ea:x}  {idc.generate_disasm_line(ea, 0)}")
        ea = idc.next_head(ea)
        if ea == idc.BADADDR:
            break

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_verify_f200_caller.log"
with open(OUT, "w", encoding="utf-8") as fh:
    target = 0x14033F200
    log(fh, f"== Xrefs TO sub_14033F200 @ 0x{target:X} ==")
    xr = ida_xref.xrefblk_t()
    ok = xr.first_to(target, ida_xref.XREF_ALL)
    sites = []
    while ok:
        log(fh, f"  from 0x{xr.frm:X} type={xr.type}")
        sites.append(xr.frm)
        ok = xr.next_to()

    # For each site, dump 32 bytes of context before
    for s in sites:
        dump_range(fh, s - 48, s + 8, f"Context before call at 0x{s:X}")

    # Also — find what calls sub_14033EE60 (caller2 passed modelDB)
    log(fh, "\n\n== Callers of sub_14033EE60 ==")
    xr = ida_xref.xrefblk_t()
    ok = xr.first_to(0x14033EE60, ida_xref.XREF_ALL)
    while ok:
        log(fh, f"  from 0x{xr.frm:X} type={xr.type}")
        dump_range(fh, xr.frm - 64, xr.frm + 8, f"Context call to 14033EE60 at 0x{xr.frm:X}")
        ok = xr.next_to()

    log(fh, "\nDONE")

idc.qexit(0)
