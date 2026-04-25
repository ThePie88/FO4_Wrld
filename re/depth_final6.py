"""Depth RE v6 - find real callers of D3D11CreateDeviceAndSwapChain thunk,
then identify the ID3D11Device/ID3D11DeviceContext globals.
"""
import idaapi, idautils, idc, ida_funcs, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report6.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase
W(f"[*] imagebase = {imagebase:#x}")

THUNK = 0x1422bd1c9  # jmp to IAT D3D11CreateDeviceAndSwapChain

# Find the function containing THUNK
fn = idaapi.get_func(THUNK)
if fn:
    W(f"[*] thunk fn: RVA{rva(fn.start_ea):#x}..RVA{rva(fn.end_ea):#x}")

# Find callers of THUNK fn start
thunk_fn_ea = fn.start_ea if fn else THUNK
W(f"[*] finding callers to thunk fn @ {thunk_fn_ea:#x}")
callers = []
for xr in idautils.XrefsTo(thunk_fn_ea):
    callers.append(xr.frm)
    cfn = idaapi.get_func(xr.frm)
    if cfn:
        W(f"   call from RVA{rva(xr.frm):#x} in fn RVA{rva(cfn.start_ea):#x} ({idc.get_func_name(cfn.start_ea)})")

# Also find xrefs to the thunk ea directly
for xr in idautils.XrefsTo(THUNK):
    if xr.frm not in callers:
        callers.append(xr.frm)
        cfn = idaapi.get_func(xr.frm)
        if cfn:
            W(f"   direct xref RVA{rva(xr.frm):#x} in fn RVA{rva(cfn.start_ea):#x}")

# Take the first real caller
REAL_CALLER = None
for ea in callers:
    cfn = idaapi.get_func(ea)
    if cfn and cfn.end_ea - cfn.start_ea > 0x100:
        REAL_CALLER = cfn.start_ea
        break
W(f"[*] real caller fn: RVA{rva(REAL_CALLER):#x}")

# Decompile it
import ida_hexrays
ida_hexrays.init_hexrays_plugin()
try:
    cfunc = ida_hexrays.decompile(REAL_CALLER)
    if cfunc:
        src = str(cfunc)
        W("\n[*] Decompiled (first 400 lines):")
        for i, line in enumerate(src.split("\n")[:400]):
            W(f"    {i:4d}: {line}")
except Exception as e:
    W(f"decomp err: {e}")

# Dump raw asm around the thunk call
for call_ea in callers:
    cfn = idaapi.get_func(call_ea)
    if not cfn or cfn.start_ea != REAL_CALLER: continue
    W(f"\n[*] Raw asm around thunk call at {call_ea:#x}:")
    cur = call_ea
    for _ in range(80):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR or cur < cfn.start_ea: break
    while cur <= call_ea + 0x30 and cur != idaapi.BADADDR:
        dl = idc.generate_disasm_line(cur, 0)
        W(f"    {cur:#x}: {dl}")
        cur = idc.next_head(cur, cfn.end_ea)

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
idc.qexit(0)
