"""
FINAL HOOK VERIFICATION - zero in on a per-frame entry point.
Strategy: decompile the CONSUMER's signature, and find the direct invocation
sites by looking at where the vtable (0x14290D158) itself gets populated. Then
find per-frame dispatchers that loop over accumulator BSTArray.

Also: verify the "byte_143E48C70" gate in PRODUCER - if that's 0, PRODUCER
writes NOTHING. Then user never sees matrix.

Also identify sub_14223F110 (per-geometry WorldView/WorldViewProj)
which is called from D3D11 CB upload path.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes
BASE = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\hookcheck_report3.txt"


def dump(m, f=None):
    print(m)
    if f: f.write(m+"\n")


def decomp(ea, maxlen=8000):
    ida_hexrays.init_hexrays_plugin()
    cf = ida_hexrays.decompile(ea)
    if not cf: return "<decompile failed>"
    s = str(cf)
    return s[:maxlen]


def callers(ea):
    out=[]
    for r in idautils.CodeRefsTo(ea, 0):
        fn = ida_funcs.get_func(r)
        if fn:
            out.append((fn.start_ea, r))
    return out


def dataref_count(ea):
    return sum(1 for _ in idautils.DataRefsTo(ea))


with open(OUT, "w") as f:
    dump("="*80, f)
    dump(" FINAL HOOK CHECK", f)
    dump("="*80, f)

    # ===== Q1-A: Is byte_143E48C70 the gate for PRODUCER? =====
    dump("\n### PRODUCER gating — byte_143E48C70 ###", f)
    GATE = 0x143E48C70
    v = ida_bytes.get_byte(GATE)
    dump(f"  byte @ 0x{GATE:X} current value (static): {v}", f)
    dump(f"  data refs to gate: {dataref_count(GATE)}", f)
    # find writers
    dump("  writers of byte_143E48C70:", f)
    for r in idautils.DataRefsTo(GATE):
        fn = ida_funcs.get_func(r)
        mnem = idc.print_insn_mnem(r)
        if mnem in ("mov", "and", "or", "xor"):
            nm = idc.get_func_name(fn.start_ea) if fn else ""
            dump(f"    0x{r:X} ({mnem}) in {nm}", f)

    # ===== Q1-B: callers of sub_1421DBAF0 (grandparent of PRODUCER) =====
    dump("\n\n### Caller chain PRODUCER up to top ###", f)
    chain = [0x1421DC480, 0x1421DC190, 0x1421DBAF0]
    for ea in chain:
        dump(f"\n  callers of 0x{ea:X} (RVA 0x{ea-BASE:X}):", f)
        for (cf, cs) in callers(ea):
            nm = idc.get_func_name(cf) or ""
            dump(f"    {nm}  RVA 0x{cf-BASE:X}  from 0x{cs:X}", f)

    # callers of sub_140458740
    ea=0x140458740
    dump(f"\n  callers of sub_140458740 (RVA 0x{ea-BASE:X}):", f)
    for (cf, cs) in callers(ea):
        nm = idc.get_func_name(cf) or ""
        dump(f"    {nm}  RVA 0x{cf-BASE:X}  from 0x{cs:X}", f)

    # Try to decompile sub_1421DBAF0 — likely "iterate accumulator list and call updater"
    dump("\n\n### sub_1421DBAF0 decomp ###", f)
    dump(decomp(0x1421DBAF0, 5000), f)

    dump("\n\n### sub_140458740 decomp ###", f)
    dump(decomp(0x140458740, 5000), f)

    # ===== Q3: sub_14223F110 (WorldViewProj CB upload, per-geometry) =====
    dump("\n\n### sub_14223F110 — per-geometry WVP writer ###", f)
    ea=0x14223F110
    dump(f"  RVA 0x{ea-BASE:X}", f)
    dump(f"  callers of sub_14223F110:", f)
    for (cf, cs) in callers(ea):
        nm = idc.get_func_name(cf) or ""
        dump(f"    {nm}  RVA 0x{cf-BASE:X}  from 0x{cs:X}", f)
    dump("\n  decomp (first 6000):", f)
    dump(decomp(ea, 6000), f)

    # ===== Dispatch candidates — functions named or likely BSBatchRenderer::Dispatch =====
    dump("\n\n### sub_14221BC90 — BSBatchRenderer vt[4] (Dispatch) ###", f)
    ea=0x14221BC90
    dump(f"  callers of sub_14221BC90:", f)
    for (cf, cs) in callers(ea):
        nm = idc.get_func_name(cf) or ""
        dump(f"    {nm}  RVA 0x{cf-BASE:X}  from 0x{cs:X}", f)

    # ===== Find the ACTIVE 'scene' BSShaderAccumulator — is it global? =====
    dump("\n\n### Global accumulator candidates ###", f)
    # look for references to the BSShaderAccumulator vtable (0x14290A6B0) in a write context
    VT_ACC = 0x14290A6B0
    dump(f"  vtable 0x14290A6B0 data refs:", f)
    cnt = 0
    for r in idautils.DataRefsTo(VT_ACC):
        fn = ida_funcs.get_func(r)
        nm = idc.get_func_name(fn.start_ea) if fn else "<nofn>"
        dump(f"    0x{r:X} in {nm}", f)
        cnt += 1
        if cnt>20: break

    # ===== D3D11 per-frame opportunities =====
    # locate D3D11DeviceContext::VSSetConstantBuffers / Map / DrawIndexed via imports
    dump("\n\n### D3D11 import analysis ###", f)
    for s_ea in idautils.Functions():
        n = idc.get_func_name(s_ea) or ""
        if "D3D11" in n or "D3DCompile" in n or "VSSet" in n:
            dump(f"    {n}  RVA 0x{s_ea-BASE:X}", f)

    # Look at imports directly
    dump("\n  imports containing d3d11/dxgi:", f)
    nimps = idaapi.get_import_module_qty()
    for mi in range(nimps):
        mn = idaapi.get_import_module_name(mi) or ""
        if "d3d11" in mn.lower() or "dxgi" in mn.lower():
            dump(f"    module: {mn}", f)
            def cb(ea, name, ord_):
                dump(f"      0x{ea:X}  {name}", f)
                return True
            idaapi.enum_import_names(mi, cb)

    dump("\n\nDONE.", f)

idc.qexit(0)
