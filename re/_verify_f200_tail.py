"""Dump caller of sub_14033F200 at 0x1417B5A6A tail-call, and recursive caller at 0x14033F91B."""
import idc
import ida_funcs
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

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_verify_f200_tail.log"
with open(OUT, "w", encoding="utf-8") as fh:
    # Who is the func containing 0x1417B5A6A?
    f = ida_funcs.get_func(0x1417B5A6A)
    if f:
        log(fh, f"== Function containing 0x1417B5A6A: 0x{f.start_ea:X} .. 0x{f.end_ea:X} ==")
        dump_range(fh, f.start_ea, min(f.start_ea + 200, f.end_ea), "head")
        c = ida_hexrays.decompile(f.start_ea)
        if c:
            log(fh, "\n-- decomp --")
            log(fh, str(c))

    # Recursive caller inside sub_14033F870 at 0x14033F91B
    log(fh, "\n\n== Recursive caller at 0x14033F91B (inside sub_14033F870?) ==")
    f = ida_funcs.get_func(0x14033F91B)
    if f:
        log(fh, f"Function: 0x{f.start_ea:X} .. 0x{f.end_ea:X}")
        dump_range(fh, f.start_ea, f.start_ea + 100, "head")
        # Find what rsi holds at the call site
        dump_range(fh, 0x14033F91B - 120, 0x14033F920, "context")
        c = ida_hexrays.decompile(f.start_ea)
        if c:
            # Clip decomp to reasonable length
            s = str(c)
            log(fh, "\n-- decomp (up to 6000 chars) --")
            log(fh, s[:6000])

    # Also decomp sub_14033F420 to confirm its a1 is modelDB
    log(fh, "\n\n== Decomp sub_14033F420 (what is its a1?) ==")
    c = ida_hexrays.decompile(0x14033F420)
    if c:
        s = str(c)
        # first 3000 chars
        log(fh, s[:3000])

    log(fh, "\nDONE")

idc.qexit(0)
