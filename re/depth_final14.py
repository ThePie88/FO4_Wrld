"""Depth RE v14 - Find all calls through qword_1438CAA90 / qword_1438CAAA8
with correct slot numbers for D3D11 methods, by searching in decompilation
for "qword_1438CAA90 + NLL" patterns.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, struct, re

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report14.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()
ida_hexrays.init_hexrays_plugin()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

# Correct D3D11 vtable offsets:
DEVICE_SLOTS = {
    0x18: "CreateBuffer",
    0x20: "CreateTexture1D",
    0x28: "CreateTexture2D",
    0x30: "CreateTexture3D",
    0x38: "CreateShaderResourceView",
    0x40: "CreateUnorderedAccessView",
    0x48: "CreateRenderTargetView",
    0x50: "CreateDepthStencilView",
    0x58: "CreateInputLayout",
    0x60: "CreateVertexShader",
    0x68: "CreateGeometryShader",
    0x78: "CreatePixelShader",
    0xA0: "CreateBlendState",
    0xA8: "CreateDepthStencilState",
    0xB0: "CreateRasterizerState",
    0xB8: "CreateSamplerState",
    0xC0: "CreateQuery",
}
CTX_SLOTS = {
    0xE8: "GetData",
    0x108: "OMSetRenderTargets",
    0x118: "OMSetBlendState",
    0x120: "OMSetDepthStencilState",
    0x158: "RSSetState",
    0x160: "RSSetViewports",
    0x168: "RSSetScissorRects",
    0x190: "ClearRenderTargetView",
    0x198: "ClearUAVUint",
    0x1A0: "ClearUAVFloat",
    0x1A8: "ClearDepthStencilView",
}

# Get reader functions for ctx / device globals - but also includeALL funcs that
# call through these vtable patterns. Best approach: walk ALL functions,
# decompile, and grep for 'qword_1438CAA90 + NLL' or 'qword_1438CAAA8 + NLL'.
CTX_A = 0x1438CAA90
CTX_B = 0x1438CAAB8
DEVICE = 0x1438CAAA8

ALL_SLOTS = set(DEVICE_SLOTS.keys()) | set(CTX_SLOTS.keys())

# Since decompiling all 204807 funcs is too slow, just decompile xrefers
def get_reader_funcs(glob):
    fns = set()
    for xr in idautils.XrefsTo(glob):
        fn = idaapi.get_func(xr.frm)
        if fn: fns.add(fn.start_ea)
    return fns

all_funcs = get_reader_funcs(CTX_A) | get_reader_funcs(CTX_B) | get_reader_funcs(DEVICE)
W(f"[*] Total functions to decompile: {len(all_funcs)}")

# Pattern: "qword_1438CAA90 + NLL" or "qword_1438CAAA8 + NLL"
# Regex matches decimal offset
OFFSET_RE = re.compile(r"qword_1438CAA(90|B8|A8)\s*\+\s*(\d+)L?L?")
# Also match the common pattern "(*(_QWORD *)qword_XXX + NLL)"
OFFSET_RE2 = re.compile(r"\(\s*\*\s*\(\s*_QWORD\s*\*\s*\)\s*(qword_1438CAA(?:90|B8|A8))\s*\+\s*(\d+)L?L?\s*\)")

# Results: {(global, slot): [ (fn_ea, line_num, line) ]}
hits = {}

for fn_ea in all_funcs:
    try:
        cf = ida_hexrays.decompile(fn_ea)
        if not cf: continue
        src = str(cf)
    except Exception:
        continue
    for i, line in enumerate(src.split("\n")):
        for m in OFFSET_RE.finditer(line):
            suffix = m.group(1)  # 90, B8, or A8
            offset = int(m.group(2))
            glob = {"90": "ctx_A", "B8": "ctx_B", "A8": "device"}[suffix]
            key = (glob, offset)
            hits.setdefault(key, []).append((fn_ea, i, line.strip()))

# Summary
W("\n[*] Call distribution by (global, slot):")
slot_tally_dev = {}
slot_tally_ctx = {}
for (glob, off), lst in sorted(hits.items()):
    slot_name = None
    if glob == "device":
        slot_name = DEVICE_SLOTS.get(off, f"?")
        slot_tally_dev[off] = slot_tally_dev.get(off, 0) + len(lst)
    else:
        slot_name = CTX_SLOTS.get(off, f"?")
        slot_tally_ctx[off] = slot_tally_ctx.get(off, 0) + len(lst)
    W(f"   {glob} +{off} (0x{off:x}) {slot_name}: {len(lst)} hits")

# Show samples for key slots
W("\n[*] Key slot details:")

def show_slot_hits(glob, off, max_show=40):
    slot_name = DEVICE_SLOTS.get(off) if glob == "device" else CTX_SLOTS.get(off)
    key = (glob, off)
    if key not in hits: return
    lst = hits[key]
    W(f"\n-- {glob} +{off} ({slot_name}) — {len(lst)} hits --")
    for fn_ea, i, line in lst[:max_show]:
        W(f"   RVA{rva(fn_ea):#x}:{i:4d} {line}")

# Device: CreateTexture2D (0x28), CreateDSV (0x50), CreateDSS (0xA8), CreateRTV (0x48)
for off in (0x28, 0x48, 0x50, 0xA8, 0xA0):
    show_slot_hits("device", off, 30)

# Ctx: OMSetRT (0x108), OMSetDSS (0x120), ClearDSV (0x1A8), ClearRTV (0x190)
for off in (0x108, 0x120, 0x190, 0x1A8, 0x118):
    for g in ("ctx_A", "ctx_B"):
        show_slot_hits(g, off, 30)

# Now for ClearDepthStencilView (ctx + 424), find full line to extract the
# 4th argument (depth clear value). The argument is a float literal in the C
# decomp typically like: f(ctx, DSV, 3, 1.0, 0)
W("\n" + "="*72)
W("Q1A: ClearDepthStencilView depth clear value extraction")
W("="*72)
ctx_clear = hits.get(("ctx_A", 0x1A8), []) + hits.get(("ctx_B", 0x1A8), [])
W(f"  Total ClearDSV hits: {len(ctx_clear)}")
for fn_ea, ln, line in ctx_clear:
    # Decompile function again, take ~5 lines of context around 'ln'
    try:
        cf = ida_hexrays.decompile(fn_ea)
        if not cf: continue
        lines = str(cf).split("\n")
        start = max(0, ln - 1)
        end = min(len(lines), ln + 10)
        W(f"\n  RVA{rva(fn_ea):#x} line {ln}:")
        for i in range(start, end):
            W(f"    {i:4d}: {lines[i]}")
    except Exception as e:
        W(f"  decomp err RVA{rva(fn_ea):#x}: {e}")

# Similarly for CreateDepthStencilState — we want to find the D3D11_DEPTH_STENCIL_DESC
W("\n" + "="*72)
W("Q1B: CreateDepthStencilState desc extraction")
W("="*72)
dss_hits = hits.get(("device", 0xA8), [])
W(f"  Total CreateDSS hits: {len(dss_hits)}")
for fn_ea, ln, line in dss_hits[:40]:
    try:
        cf = ida_hexrays.decompile(fn_ea)
        if not cf: continue
        lines = str(cf).split("\n")
        start = max(0, ln - 10)
        end = min(len(lines), ln + 5)
        W(f"\n  RVA{rva(fn_ea):#x} line {ln}:")
        for i in range(start, end):
            W(f"    {i:4d}: {lines[i]}")
    except Exception as e:
        W(f"  decomp err: {e}")

# Q4 — CreateTexture2D at device+0x28, look at large DSV-bound allocations
W("\n" + "="*72)
W("Q4: CreateTexture2D call contexts")
W("="*72)
t2d_hits = hits.get(("device", 0x28), [])
W(f"  Total CreateTex2D hits: {len(t2d_hits)}")
for fn_ea, ln, line in t2d_hits[:20]:
    try:
        cf = ida_hexrays.decompile(fn_ea)
        if not cf: continue
        lines = str(cf).split("\n")
        start = max(0, ln - 10)
        end = min(len(lines), ln + 5)
        W(f"\n  RVA{rva(fn_ea):#x} line {ln}:")
        for i in range(start, end):
            W(f"    {i:4d}: {lines[i]}")
    except Exception as e:
        pass

# CreateDepthStencilView
W("\n" + "="*72)
W("Q2 extra: CreateDepthStencilView contexts")
W("="*72)
dsv_hits = hits.get(("device", 0x50), [])
W(f"  Total CreateDSV hits: {len(dsv_hits)}")
for fn_ea, ln, line in dsv_hits[:30]:
    try:
        cf = ida_hexrays.decompile(fn_ea)
        if not cf: continue
        lines = str(cf).split("\n")
        start = max(0, ln - 10)
        end = min(len(lines), ln + 5)
        W(f"\n  RVA{rva(fn_ea):#x} line {ln}:")
        for i in range(start, end):
            W(f"    {i:4d}: {lines[i]}")
    except:
        pass

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
idc.qexit(0)
