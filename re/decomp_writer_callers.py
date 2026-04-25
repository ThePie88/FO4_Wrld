"""Find callers of the NiCamera worldToCam writer sub_1416D20B0 and
inspect what they do with the matrix after building it.  This reveals
the matrix's consumers in the rendering pipeline.

Also re-check ViewProj matrix reads: the matrix could be exported to
a struct field outside NiCamera (e.g. stored in BSGraphics::State+0x230).
"""
import idaapi, idautils, idc, ida_funcs, ida_ua, ida_hexrays
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\writer_callers.txt"
IMG = 0x140000000
lines = []
def P(s=""): lines.append(str(s))

WRITER_EA = 0x1416D20B0  # NiCamera::BuildWorldToCam

callers = set()
for xref in idautils.CodeRefsTo(WRITER_EA, 0):
    f = ida_funcs.get_func(xref)
    if f:
        callers.add((f.start_ea, xref))

P("Callers of BuildWorldToCam sub_1416D20B0: %d" % len(callers))
for fn_ea, site in sorted(callers):
    nm = ida_funcs.get_func_name(fn_ea) or ""
    P("  call_site 0x%X  in fn 0x%X (RVA 0x%X) %s" %
      (site, fn_ea, fn_ea - IMG, nm))

# decompile each caller
for fn_ea, site in sorted(callers):
    P("-"*70)
    P("CALLER fn 0x%X (RVA 0x%X)" % (fn_ea, fn_ea - IMG))
    try:
        d = str(ida_hexrays.decompile(fn_ea))
        for ln in d.splitlines()[:200]:
            P("  " + ln)
    except Exception:
        P("  <decomp fail>")

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))
print("wrote", OUT)
idaapi.qexit(0)
