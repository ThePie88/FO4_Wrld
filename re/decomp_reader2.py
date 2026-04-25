"""Dump asm & decomp of the promising non-stack readers:
  sub_1416D9460 (NiCamera range, reg=rbx)
  sub_141406310 (rdi)
  sub_141448D10 (r14)
  sub_141504E20 (rcx)
  sub_14225B7F0 (rdx)
Also check if they're a classic row-by-row mat*vec multiplier pattern.
"""
import idaapi, idautils, idc, ida_funcs, ida_ua, ida_hexrays

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\reader_candidates.txt"
IMG = 0x140000000
lines = []
def P(s=""): lines.append(str(s))

TARGETS = [
    0x1416D9460,
    0x141406310,
    0x141448D10,
    0x141504E20,
    0x141A34930,
    0x14225B7F0,
    0x141D56250,
]

for fn_ea in TARGETS:
    P("="*70)
    P(" fn 0x%X (RVA 0x%X)" % (fn_ea, fn_ea - IMG))
    P("="*70)
    f = ida_funcs.get_func(fn_ea)
    if not f:
        P("  <no func>"); continue
    # decomp
    try:
        d = str(ida_hexrays.decompile(fn_ea))
        P("\n-- DECOMPILED --")
        for ln in d.splitlines()[:200]:
            P("  " + ln)
    except Exception as e:
        P("  <decomp fail>: %s" % e)
    P("")
    # dump a few asm lines around +0x120 reads
    P("\n-- ASM lines that touch +0x120/130/140/150 --")
    for ea in idautils.Heads(f.start_ea, f.end_ea):
        if not idc.is_code(idc.get_full_flags(ea)): continue
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0: continue
        mn = insn.get_canon_mnem().lower()
        if mn not in ("movss", "movaps", "movups", "movsd", "mulss", "addss"): continue
        for op in insn.ops:
            if op.type == ida_ua.o_displ and op.addr in (0x120, 0x130, 0x140, 0x150):
                P("  0x%X  %s" % (ea, idc.GetDisasm(ea)))
                break

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))
print("wrote", OUT)
idaapi.qexit(0)
