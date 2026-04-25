"""Depth RE v8 - dump asm around CTX/DEVICE global reads to see what comes after.
Then use Scaleform apply function as anchor.
"""
import idaapi, idautils, idc, ida_funcs

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report8.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

CTX_GLOBALS = [0x1438CAA90, 0x1438CAAB8]
DEVICE_GLOBAL = 0x1438CAAA8

W(f"[*] imagebase = {imagebase:#x}")

# Dump asm around first 10 read sites for CTX_GLOBAL_A
W("\n[*] Asm around first reads of ctx global 0x1438CAA90:")
for xr in list(idautils.XrefsTo(0x1438CAA90))[:10]:
    ea = xr.frm
    fn = idaapi.get_func(ea)
    fn_name = idc.get_func_name(fn.start_ea) if fn else "?"
    fn_rva = rva(fn.start_ea) if fn else 0
    W(f"\n  read at {ea:#x} in fn RVA{fn_rva:#x} ({fn_name}):")
    cur = ea
    for _ in range(2): cur = idc.prev_head(cur)
    for _ in range(12):
        if cur == idaapi.BADADDR: break
        dl = idc.generate_disasm_line(cur, 0)
        W(f"    {cur:#x}: {dl}")
        cur = idc.next_head(cur, idaapi.BADADDR)

# Same for CTX global B
W("\n[*] Asm around reads of ctx global 0x1438CAAB8:")
for xr in list(idautils.XrefsTo(0x1438CAAB8))[:10]:
    ea = xr.frm
    fn = idaapi.get_func(ea)
    fn_name = idc.get_func_name(fn.start_ea) if fn else "?"
    fn_rva = rva(fn.start_ea) if fn else 0
    W(f"\n  read at {ea:#x} in fn RVA{fn_rva:#x} ({fn_name}):")
    cur = ea
    for _ in range(2): cur = idc.prev_head(cur)
    for _ in range(12):
        if cur == idaapi.BADADDR: break
        dl = idc.generate_disasm_line(cur, 0)
        W(f"    {cur:#x}: {dl}")
        cur = idc.next_head(cur, idaapi.BADADDR)

# Also for DEVICE global
W("\n[*] Asm around first 5 reads of device global 0x1438CAAA8:")
for xr in list(idautils.XrefsTo(0x1438CAAA8))[:5]:
    ea = xr.frm
    fn = idaapi.get_func(ea)
    fn_rva = rva(fn.start_ea) if fn else 0
    W(f"\n  read at {ea:#x} in fn RVA{fn_rva:#x}:")
    cur = ea
    for _ in range(2): cur = idc.prev_head(cur)
    for _ in range(12):
        if cur == idaapi.BADADDR: break
        dl = idc.generate_disasm_line(cur, 0)
        W(f"    {cur:#x}: {dl}")
        cur = idc.next_head(cur, idaapi.BADADDR)

# Scaleform applyDepthStencilMode xrefs
ea_apply = None
for s in idautils.Strings():
    try:
        if str(s) == "Scaleform::Render::D3D1x::HAL::applyDepthStencilMode":
            ea_apply = s.ea
            break
    except: pass
W(f"\n[*] Scaleform::applyDepthStencilMode string at {ea_apply}")
if ea_apply:
    for xr in idautils.XrefsTo(ea_apply):
        fn = idaapi.get_func(xr.frm)
        if fn:
            W(f"  xref from RVA{rva(xr.frm):#x} in fn RVA{rva(fn.start_ea):#x}")
            # Decompile this fn
            try:
                import ida_hexrays
                ida_hexrays.init_hexrays_plugin()
                cfunc = ida_hexrays.decompile(fn.start_ea)
                if cfunc:
                    src = str(cfunc)
                    # Print lines that mention DepthStencil / DepthFunc / OMSet
                    for i, line in enumerate(src.split("\n")):
                        if any(k in line for k in ("DepthStencil", "DepthFunc", "lpVtbl", "DepthEnable", "0x1A8", "Clear", "0x48", "0xA0", "OMSet")):
                            W(f"    {i}: {line}")
            except Exception as e:
                W(f"  decomp err: {e}")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
idc.qexit(0)
