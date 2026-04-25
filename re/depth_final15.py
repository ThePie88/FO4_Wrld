"""Depth RE v15 - Full decompile of sub_141821D50 (the DSV creator) and
investigate context caching in TLS.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, re, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report15.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()
ida_hexrays.init_hexrays_plugin()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

# 1. Decompile sub_141821D50 entirely
W("="*72); W("FULL: sub_141821D50 — DSV creation + Tex2D"); W("="*72)
fn_ea = 0x141821D50
cf = ida_hexrays.decompile(fn_ea)
if cf:
    for i, line in enumerate(str(cf).split("\n")):
        W(f"  {i:4d}: {line}")

# 2. Decompile sub_141824350 entirely (the D3D init - there may be depth setup near the end)
W("\n" + "="*72); W("FULL: sub_141824350 (D3D11 init) ending"); W("="*72)
cf = ida_hexrays.decompile(0x141824350)
if cf:
    lines = str(cf).split("\n")
    W(f"  total lines: {len(lines)}")
    # Print last 200 lines to see depth setup
    start = max(0, len(lines)-200)
    for i in range(start, len(lines)):
        W(f"  {i:4d}: {lines[i]}")

# 3. Decompile sub_1418220A0 which has CreateRTV
W("\n" + "="*72); W("FULL: sub_1418220A0 — RTV + etc"); W("="*72)
cf = ida_hexrays.decompile(0x1418220A0)
if cf:
    lines = str(cf).split("\n")
    for i, line in enumerate(lines):
        W(f"  {i:4d}: {line}")

# 4. Look for TLS-based D3D11 context access: `NtCurrentTeb()->ThreadLocalStoragePointer + ... + 2840`
# This was in the init function (`v18 + 2840`). Let's find all functions that access TLS+2840 and see if they call D3D11.
W("\n" + "="*72); W("TLS offset 2840 access — D3D11 ctx via TLS?"); W("="*72)
# Scan ALL functions for pattern: NtCurrentTeb + 2840 (0xB18)
# In asm: `mov rax, gs:58h; mov rax, [rax + tlsIndex*8]; ...; mov rax/rcx, [rax+2840]`
# Simpler: look for any ImmVal 2840 or 0xB18 in moves
# Actually, decompiling all is too expensive. Instead, search for the pattern:
# "mov rXX, cs:TlsIndex" followed by "mov rXX, [rXX + 2840]"
# Just grep all decompiled xrefers of TlsIndex:
TLS_IDX = idaapi.get_name_ea(idaapi.BADADDR, "TlsIndex")
if TLS_IDX and TLS_IDX != idaapi.BADADDR:
    W(f"  TlsIndex at {TLS_IDX:#x}")
    xrs = list(idautils.XrefsTo(TLS_IDX))
    W(f"  TlsIndex xrefs: {len(xrs)}")
    # Decompile small subset
    fns = set()
    for xr in xrs:
        fn = idaapi.get_func(xr.frm)
        if fn: fns.add(fn.start_ea)
    W(f"  unique funcs using TlsIndex: {len(fns)}")

# 5. Search for any vtable-indirect-call pattern calling slot 0x1A8 where base reg
# was last seen as read from a [reg+2840] (TLS context)
W("\n" + "="*72); W("Find D3D11 calls via TLS-cached context (offset 2840)"); W("="*72)
# More direct: find all call [rax+0x1A8] sites and dump asm context around them
num_funcs = ida_funcs.get_func_qty()
slot_calls = {0x1A8: [], 0xA8: [], 0x108: [], 0x120: [], 0x50: [], 0x28: []}
for fi in range(num_funcs):
    fn = ida_funcs.getn_func(fi)
    if not fn: continue
    ea = fn.start_ea
    while ea < fn.end_ea:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            ea = idc.next_head(ea, fn.end_ea)
            if ea == idaapi.BADADDR: break
            continue
        if insn.get_canon_mnem().startswith("call"):
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                d = op.addr & 0xFFFFFFFFFFFFFFFF
                if d in slot_calls:
                    slot_calls[d].append(ea)
        ea += insn.size
        if insn.size == 0: break

W(f"  slot 0x1A8: {len(slot_calls[0x1A8])}")
W(f"  slot 0xA8:  {len(slot_calls[0xA8])}")
W(f"  slot 0x50:  {len(slot_calls[0x50])}")
W(f"  slot 0x120: {len(slot_calls[0x120])}")
W(f"  slot 0x108: {len(slot_calls[0x108])}")
W(f"  slot 0x28:  {len(slot_calls[0x28])}")

# For slot 0x1A8 (ClearDSV), dump asm of first 30 sites with small context
W("\n  slot 0x1A8 asm dumps (10 lines before each call):")
for ea in slot_calls[0x1A8][:20]:
    W(f"\n  -- site {ea:#x} in RVA{rva(idaapi.get_func(ea).start_ea):#x} --")
    cur = ea
    for _ in range(15): cur = idc.prev_head(cur)
    while cur <= ea:
        if cur == idaapi.BADADDR: break
        dl = idc.generate_disasm_line(cur, 0)
        W(f"    {cur:#x}: {dl}")
        cur = idc.next_head(cur, ea+1)

# For slot 0xA8 (CreateDSS)
W("\n  slot 0xA8 asm dumps:")
for ea in slot_calls[0xA8][:10]:
    fn = idaapi.get_func(ea)
    W(f"\n  -- site {ea:#x} in RVA{rva(fn.start_ea) if fn else 0:#x} --")
    cur = ea
    for _ in range(20): cur = idc.prev_head(cur)
    while cur <= ea:
        if cur == idaapi.BADADDR: break
        dl = idc.generate_disasm_line(cur, 0)
        W(f"    {cur:#x}: {dl}")
        cur = idc.next_head(cur, ea+1)

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
idc.qexit(0)
