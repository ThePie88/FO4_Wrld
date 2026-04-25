"""Depth RE v5 - Use the D3D11CreateDeviceAndSwapChain caller to find
the ID3D11Device / ID3D11DeviceContext globals in the Fallout 4 binary.

Then find all indirect calls through those globals.
"""
import idaapi, idautils, idc, ida_funcs, ida_bytes, struct, ida_nalt

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report5.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

W(f"[*] imagebase = {imagebase:#x}")

# Find D3D11CreateDeviceAndSwapChain IAT
D3D11_IMPORT = 0x142439758  # from report 4

# Find caller
callers = list(idautils.XrefsTo(D3D11_IMPORT))
W(f"[*] D3D11CreateDeviceAndSwapChain xrefs: {len(callers)}")
create_fn_ea = None
for xr in callers:
    fn = idaapi.get_func(xr.frm)
    if fn:
        create_fn_ea = fn.start_ea
        W(f"   caller fn: RVA{rva(fn.start_ea):#x} size=0x{fn.end_ea-fn.start_ea:x}")

if not create_fn_ea:
    W("ERROR: no caller found")
    idc.qexit(0)

# Decompile the caller to find where the resulting device/context pointers are stored
try:
    import ida_hexrays
    ida_hexrays.init_hexrays_plugin()
    cfunc = ida_hexrays.decompile(create_fn_ea)
    if cfunc:
        src = str(cfunc)
        W("\n[*] Decompilation of D3D11CreateDeviceAndSwapChain caller:")
        # Print first 200 lines
        for i, line in enumerate(src.split("\n")[:300]):
            W(f"    {i:4d}: {line}")
except Exception as e:
    W(f"decompile failed: {e}")

# After decomp, we'd know globals. For now, try static scan:
# D3D11CreateDeviceAndSwapChain signature:
# HRESULT(IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE, HMODULE, UINT Flags,
#         const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
#         UINT SDKVersion, const DXGI_SWAP_CHAIN_DESC*,
#         IDXGISwapChain** ppSwapChain, ID3D11Device** ppDevice,
#         D3D_FEATURE_LEVEL* pFeatureLevel,
#         ID3D11DeviceContext** ppImmediateContext)
# So after the call, arg9 (ppSwapChain on stack), arg10 (ppDevice), arg11 (pFeatureLevel), arg12 (ppImmediateContext)
# These are passed via stack [rsp+32]..
# Before the call, we'd see lea r9, [something] for argument passing (arg 9 onwards goes via stack).
# Actually args 9..12 in Win x64 fastcall go on stack at [rsp+0x28], [rsp+0x30], [rsp+0x38], [rsp+0x40].

# Let me trace backward from the call ea=0x1422bd1c9 looking for "lea rax, [global]; mov [rsp+0x40], rax"
# The ppImmediateContext arg is arg 12, at [rsp+0x40] (since after rcx,rdx,r8,r9 -> +0x20 shadow space,
# then args 5..12 at +0x20..+0x48).

call_ea = 0x1422bd1c9
W(f"\n[*] Backtracking from call site {call_ea:#x} to find ID3D11DeviceContext** arg")

# Scan backward ~80 insns looking for lea r?, [global]; mov [rsp+NN], r?
# Use a robust approach: decompile and inspect.
# OR: look for any `lea rax, [global]` where global is in .data and xref to it after.

cur = call_ea
global_refs = []
for _ in range(120):
    cur = idc.prev_head(cur)
    if cur == idaapi.BADADDR: break
    m = idc.print_insn_mnem(cur).lower()
    if m == "lea":
        insn = idautils.DecodeInstruction(cur)
        if not insn: continue
        op1 = insn.ops[1]
        if op1.type == idaapi.o_mem:
            global_refs.append((cur, insn.ops[0], op1.addr))
W(f"  lea insns found: {len(global_refs)}")
for cur, op0, addr in global_refs:
    reg = idc.print_operand(cur, 0)
    dl = idc.generate_disasm_line(cur, 0)
    W(f"    {cur:#x}: {dl}  (target={addr:#x})")

# Also look for "mov [rsp+NN], reg" after each lea to link the lea to the stack slot
# and thus to the arg index
# Actually simpler: dump 60 lines of asm around the call
W(f"\n[*] Raw asm around call at {call_ea:#x}")
s = idc.prev_head(call_ea)
for _ in range(60): s = idc.prev_head(s)
cur = s
while cur <= call_ea:
    dl = idc.generate_disasm_line(cur, 0)
    W(f"    {cur:#x}: {dl}")
    cur = idc.next_head(cur, call_ea+1)
    if cur == idaapi.BADADDR: break

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
W(f"\nReport: {OUT}")
idc.qexit(0)
