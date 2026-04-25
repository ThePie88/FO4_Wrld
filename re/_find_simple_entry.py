"""Find all xrefs TO sub_1417B3480 (the inner loader), decomp each parent for a simple API."""
import idc
import ida_xref
import ida_funcs
import ida_hexrays
ida_hexrays.init_hexrays_plugin()

def log(fh, msg):
    print(msg, flush=True)
    fh.write(msg + "\n")

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_find_simple_entry.log"
with open(OUT, "w", encoding="utf-8") as fh:
    # Also find callers of sub_14033EC90 and sub_14033EE60 — simpler entries.
    # Let's just look at who uses these most commonly.
    for target, tname in [
        (0x14033EC90, "sub_14033EC90_batch"),
        (0x14033EE60, "sub_14033EE60_caller2"),
        (0x1417B5A60, "sub_1417B5A60_thunk"),
        (0x14033FA70, "maybe_simple"),
    ]:
        log(fh, f"\n== Xrefs TO {tname} @ 0x{target:X} ==")
        xr = ida_xref.xrefblk_t()
        ok = xr.first_to(target, ida_xref.XREF_ALL)
        n = 0
        while ok and n < 20:
            parent = ida_funcs.get_func(xr.frm)
            pname = f"sub_{parent.start_ea:X}" if parent else "?"
            log(fh, f"  from 0x{xr.frm:X} in {pname} type={xr.type}")
            ok = xr.next_to()
            n += 1

    # Specifically decomp sub_1417B5A60 and find all its callers
    log(fh, "\n\n== sub_1417B5A60 full xrefs ==")
    xr = ida_xref.xrefblk_t()
    ok = xr.first_to(0x1417B5A60, ida_xref.XREF_ALL)
    while ok:
        parent = ida_funcs.get_func(xr.frm)
        pname = f"sub_{parent.start_ea:X}" if parent else "?"
        log(fh, f"  from 0x{xr.frm:X} in {pname} type={xr.type}")
        if xr.type == 17 and parent:  # call type
            c = ida_hexrays.decompile(parent.start_ea)
            if c:
                s = str(c)[:2500]
                log(fh, f"\n-- {pname} decomp --")
                log(fh, s)
        ok = xr.next_to()

    # What does sub_1417B5A60's CALLER look like? The trivial 3-line thunk tells us
    # RM is passed as a1. Let's find the "path-based" loader which would use formID or filename.
    # Also decomp sub_140340170
    log(fh, "\n\n== sub_140340170 ==")
    c = ida_hexrays.decompile(0x140340170)
    if c:
        log(fh, str(c)[:3000])

    log(fh, "\nDONE")

idc.qexit(0)
