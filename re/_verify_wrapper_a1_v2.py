"""
Dump prolog of sub_14033F200 to understand what rbp holds.
Also dump raw disasm of sub_14026E1C0 wrapper prolog and
sub_14026E530 access pattern to see what field offsets are used.
"""
import idc
import ida_hexrays
import ida_funcs, ida_ua
ida_hexrays.init_hexrays_plugin()

def log(fh, msg):
    print(msg, flush=True)
    fh.write(msg + "\n")

def dump_range(fh, start, end, label):
    log(fh, f"\n-- {label} (0x{start:X} .. 0x{end:X}) --")
    ea = start
    while ea <= end:
        log(fh, f"  0x{ea:x}  {idc.generate_disasm_line(ea, 0)}")
        ea = idc.next_head(ea)
        if ea == idc.BADADDR:
            break

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_verify_wrapper_a1_v2.log"
with open(OUT, "w", encoding="utf-8") as fh:
    log(fh, "="*60)
    log(fh, "Prolog sub_14033F200 — what is rbp at +26A call site?")
    log(fh, "="*60)
    dump_range(fh, 0x14033F200, 0x14033F240, "prolog")

    log(fh, "\n" + "="*60)
    log(fh, "Prolog sub_14026E1C0 (wrapper) — what it reads from a1")
    log(fh, "="*60)
    dump_range(fh, 0x14026E1C0, 0x14026E2F4, "wrapper body")

    log(fh, "\n" + "="*60)
    log(fh, "Prolog sub_14026E530 (post_hit) — what offset off a1 is used")
    log(fh, "="*60)
    dump_range(fh, 0x14026E530, 0x14026E5D4, "post_hit body")

    log(fh, "\n" + "="*60)
    log(fh, "Prolog sub_1416A6D00 (cache lookup) — check a1+12 meaning")
    log(fh, "="*60)
    dump_range(fh, 0x1416A6D00, 0x1416A6D60, "cache lookup prolog")

    log(fh, "\n" + "="*60)
    log(fh, "Decomp sub_14026E530")
    log(fh, "="*60)
    c = ida_hexrays.decompile(0x14026E530)
    if c:
        log(fh, str(c))

    log(fh, "\n" + "="*60)
    log(fh, "Check sub_14033F200 @ 0x14033F257..+20 to see what rbp is")
    log(fh, "="*60)
    # Check context around 14033F25F ..+26A
    dump_range(fh, 0x14033F200, 0x14033F280, "f200 start")

    log(fh, "\nDONE")

idc.qexit(0)
