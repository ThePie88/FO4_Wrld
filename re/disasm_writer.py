"""Disassemble sub_1416D20B0 (the NiCamera worldToCam writer) and dump
the raw XMM stores so we can confirm it's a full 4x4 (64 byte) write or just
4x3 (48 byte) floats. Also dump sub_1416DB760 (reader) and sub_1416DC400
(helper).
"""
import idaapi, idautils, idc, ida_funcs, ida_ua, ida_segment, ida_hexrays

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\writer_disasm.txt"
IMG = 0x140000000
lines = []
def P(s=""):
    lines.append(str(s))

def dump_fn(fn_ea, tag):
    P("="*70)
    P(" %s  @ 0x%X (RVA 0x%X)" % (tag, fn_ea, fn_ea - IMG))
    P("="*70)
    f = ida_funcs.get_func(fn_ea)
    if not f:
        P("  <no function>"); return
    # dump all insns with operand info for xmm stores
    for ea in idautils.Heads(f.start_ea, f.end_ea):
        if not idc.is_code(idc.get_full_flags(ea)): continue
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0: continue
        mn = insn.get_canon_mnem().lower()
        if mn in ("movaps", "movups", "movss", "movsd", "movapd", "movupd",
                  "mulss", "mulps", "addss", "addps", "subss", "subps",
                  "divss", "divps", "shufps", "unpcklps", "unpckhps"):
            d = idc.GetDisasm(ea)
            P("  0x%X  %s" % (ea, d))
    P("")

# NiCamera worldToCam writer
dump_fn(0x1416D20B0, "NICAMERA::BuildWorldToCam (sub_1416D20B0)")

# Then look at two readers/users
dump_fn(0x1416DB760, "NICAMERA::PrepareFrustum? (sub_1416DB760)")
dump_fn(0x1416DC400, "helper sub_1416DC400")

# Also dump the callers of sub_1416D20B0 to see what triggers it
P("=== Callers of sub_1416D20B0 ===")
for xref in idautils.CodeRefsTo(0x1416D20B0, 0):
    f = ida_funcs.get_func(xref)
    P("  caller 0x%X (fn 0x%X RVA 0x%X)" % (xref, f.start_ea if f else 0, (f.start_ea if f else 0) - IMG))

# Hex-rays decomp a couple of callers (skim for "view * projection" composition)
for xref in list(idautils.CodeRefsTo(0x1416D20B0, 0))[:4]:
    f = ida_funcs.get_func(xref)
    if not f: continue
    P("-"*70)
    P(" Caller decomp @ 0x%X (RVA 0x%X)" % (f.start_ea, f.start_ea - IMG))
    try:
        d = str(ida_hexrays.decompile(f.start_ea))
        for ln in d.splitlines()[:150]:
            P("  " + ln)
    except Exception:
        P("  <decomp fail>")

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))
print("wrote", OUT)
idaapi.qexit(0)
