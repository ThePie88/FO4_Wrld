"""
verify what callers of sub_14026E1C0 pass as a1.
"""
import idc
import ida_hexrays
import ida_funcs, ida_ua
ida_hexrays.init_hexrays_plugin()

def log(fh, msg):
    print(msg, flush=True)
    fh.write(msg + "\n")

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_verify_wrapper_a1.log"
with open(OUT, "w", encoding="utf-8") as fh:
    log(fh, "="*60)
    log(fh, "Raw disasm of call sites to sub_14026E1C0")
    log(fh, "="*60)

    for call_ea, caller_name in [
        (0x14026DDC6, "sub_14026DD50"),
        (0x14033EEBD, "sub_14033EE60"),
        (0x14033F26A, "sub_14033F200"),
    ]:
        log(fh, f"\n-- Call site at 0x{call_ea:X} in {caller_name} --")
        ea = call_ea - 60
        while ea <= call_ea + 8:
            log(fh, f"  0x{ea:x}  {idc.generate_disasm_line(ea, 0)}")
            ea = idc.next_head(ea)
            if ea == idc.BADADDR:
                break

    log(fh, "\n" + "="*60)
    log(fh, "Full decomp sub_14026DD50 (caller1)")
    log(fh, "="*60)
    c = ida_hexrays.decompile(0x14026DD50)
    if c:
        log(fh, str(c))

    log(fh, "\n" + "="*60)
    log(fh, "Full decomp sub_14033EE60 (caller2)")
    log(fh, "="*60)
    c = ida_hexrays.decompile(0x14033EE60)
    if c:
        log(fh, str(c))

    log(fh, "\n" + "="*60)
    log(fh, "Find call to sub_14033EE60 inside sub_14033D1E0")
    log(fh, "="*60)
    f = ida_funcs.get_func(0x14033D1E0)
    if f:
        for h in range(f.start_ea, f.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, h):
                target = idc.get_operand_value(h, 0)
                if target == 0x14033EE60:
                    log(fh, f"\n-- Call to sub_14033EE60 at 0x{h:X} --")
                    ea = h - 80
                    while ea <= h + 8:
                        log(fh, f"  0x{ea:x}  {idc.generate_disasm_line(ea, 0)}")
                        ea = idc.next_head(ea)
                        if ea == idc.BADADDR:
                            break

    log(fh, "\nDONE")

idc.qexit(0)
