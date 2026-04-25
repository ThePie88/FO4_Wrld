"""Depth RE v4 - find D3D11 device context globals by string + vtable patterns
   and identify depth-convention usage.

Strategy:
1. Find import ref to d3d11!D3D11CreateDevice (or CreateDXGIFactory) via .idata / IAT strings.
2. From those imports, find functions that receive ID3D11Device** / ID3D11DeviceContext**.
3. Find the GLOBAL that stores the device context (usually BSGraphics::Renderer::DeviceContext).
4. Find all `call [<global>+slot]` or `mov rax, [global]; call [rax+slot]` indirect calls.
5. For indirect calls with disp 0x1A8, backtrack xmm3 to find clear-depth value.

Alternative, more robust:
- Search .data / .rdata for the exact byte pattern of D3D11_DEPTH_STENCIL_DESC
  (DepthEnable=1, WriteMask=1, Func=LESS_EQUAL or GREATER_EQUAL, StencilEnable=0|1, ...)
  followed by typical StencilOp fields.
- Match patterns to count DepthFunc distribution.
"""
import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_segment, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report4.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()

def rva(ea): return ea - imagebase

W(f"[*] imagebase = {imagebase:#x}")

# ---------------------------------------------------------------------------
# Step 1: find import names related to d3d11 / dxgi
# ---------------------------------------------------------------------------
W("\n[*] Scanning imports")
import ida_nalt

nimports = ida_nalt.get_import_module_qty()
d3d11_imports = []
for i in range(nimports):
    mod = ida_nalt.get_import_module_name(i)
    if not mod:
        continue
    if "d3d11" not in mod.lower() and "dxgi" not in mod.lower():
        continue
    W(f"   module: {mod}")
    def cb(ea, name, ord_):
        d3d11_imports.append((ea, mod, name or "", ord_))
        return True
    ida_nalt.enum_import_names(i, cb)
W(f"   total d3d11/dxgi imports: {len(d3d11_imports)}")
for ea, mod, name, ordv in d3d11_imports[:30]:
    W(f"    {ea:#x}  {mod}!{name}  ord={ordv}")

# ---------------------------------------------------------------------------
# Step 2: look for imported function to create D3D11 device; find xref
# ---------------------------------------------------------------------------
def find_import_ea(needle):
    for ea, mod, name, _ in d3d11_imports:
        if needle.lower() in (name or "").lower():
            return ea
    return None

d3d11_create = find_import_ea("D3D11CreateDevice")
dxgi_create = find_import_ea("CreateDXGIFactory")
W(f"\n[*] D3D11CreateDevice IAT: {hex(d3d11_create) if d3d11_create else 'NOT FOUND'}")
W(f"[*] CreateDXGIFactory IAT: {hex(dxgi_create) if dxgi_create else 'NOT FOUND'}")

# Find callers of d3d11_create
if d3d11_create:
    W("\n[*] Callers of D3D11CreateDevice:")
    for xr in idautils.XrefsTo(d3d11_create):
        fn = idaapi.get_func(xr.frm)
        if fn:
            W(f"    from {xr.frm:#x}  in fn RVA{rva(fn.start_ea):#x} ({idc.get_func_name(fn.start_ea)})")

# Find callers of CreateDXGIFactory
if dxgi_create:
    W("\n[*] Callers of CreateDXGIFactory:")
    for xr in idautils.XrefsTo(dxgi_create):
        fn = idaapi.get_func(xr.frm)
        if fn:
            W(f"    from {xr.frm:#x}  in fn RVA{rva(fn.start_ea):#x}")

# ---------------------------------------------------------------------------
# Step 3: Search .data for D3D11_DEPTH_STENCIL_DESC patterns
# Struct (dword-aligned):
#   BOOL DepthEnable (4)
#   UINT DepthWriteMask (4, 0=ZERO 1=ALL)
#   D3D11_COMPARISON_FUNC DepthFunc (4, 1..8)
#   BOOL StencilEnable (4)
#   UINT8 StencilReadMask (1)    -- actually spec says UINT8 but struct is 4-aligned
#   UINT8 StencilWriteMask (1)
#   ... front face stencil: 4 fields x UINT
#   ... back face stencil: 4 fields x UINT
#
# Total: 4 + 4 + 4 + 4 + 4 + 4 + 4*4 + 4*4 = ~0x34 bytes
#
# Detection strategy: look for 12 byte prefix where:
#   [ea+0] in {0, 1} (DepthEnable)
#   [ea+4] in {0, 1} (DepthWriteMask)
#   [ea+8] in {1..8} (DepthFunc)
#   Followed by a reasonable StencilEnable
# AND the prefix must be 4-byte aligned.
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q1B: Search for D3D11_DEPTH_STENCIL_DESC patterns in .data/.rdata")
W("="*72)

D3D_CMP = {1:"NEVER",2:"LESS",3:"EQUAL",4:"LESS_EQUAL",5:"GREATER",6:"NOT_EQUAL",7:"GREATER_EQUAL",8:"ALWAYS"}

def scan_segment(name):
    seg = idaapi.get_segm_by_name(name)
    if not seg: return []
    hits = []
    ea = seg.start_ea
    end = seg.end_ea
    while ea < end - 0x10:
        de = idc.get_wide_dword(ea) or 0
        dm = idc.get_wide_dword(ea+4) or 0
        df = idc.get_wide_dword(ea+8) or 0
        se = idc.get_wide_dword(ea+12) or 0
        if de in (0,1) and dm in (0,1) and df in range(1,9) and se in (0,1):
            # additional gating: the NEXT 2 bytes should be stencil R/W masks
            # StencilReadMask/StencilWriteMask commonly 0xFF or 0
            sr = ida_bytes.get_byte(ea+16)
            sw = ida_bytes.get_byte(ea+17)
            if sr in (0, 0xFF) and sw in (0, 0xFF):
                # valid-ish descriptor
                hits.append((ea, de, dm, df, se, sr, sw))
        ea += 4
    return hits

rdata_hits = scan_segment(".rdata")
data_hits = scan_segment(".data")
W(f"  .rdata candidate desc: {len(rdata_hits)}")
W(f"  .data candidate desc:  {len(data_hits)}")

# Frequency by DepthFunc
def freq_by_df(lst):
    f = {}
    for _, de, dm, df, se, sr, sw in lst:
        key = (de, dm, df)
        f[key] = f.get(key, 0) + 1
    return f

rf = freq_by_df(rdata_hits)
df_f = freq_by_df(data_hits)
W("\n  .rdata unique (DepthEnable, WriteMask, DepthFunc) top 15:")
for k, c in sorted(rf.items(), key=lambda kv:-kv[1])[:15]:
    de, dm, df = k
    W(f"    (en={de}, mask={dm}, func={df}/{D3D_CMP.get(df,'?')}) x {c}")
W("\n  .data unique top 15:")
for k, c in sorted(df_f.items(), key=lambda kv:-kv[1])[:15]:
    de, dm, df = k
    W(f"    (en={de}, mask={dm}, func={df}/{D3D_CMP.get(df,'?')}) x {c}")

# Only desc patterns with non-zero stencil read/write = 0xFF are probably true descs
def genuine(lst):
    return [h for h in lst if h[5] == 0xFF or h[6] == 0xFF]

genr = genuine(rdata_hits)
gend = genuine(data_hits)
W(f"\n  .rdata 'genuine' descs (stencil-mask=0xFF): {len(genr)}")
W(f"  .data  'genuine' descs (stencil-mask=0xFF): {len(gend)}")

def freq_df_only(lst):
    f = {}
    for _, de, dm, df, se, sr, sw in lst:
        f[df] = f.get(df, 0) + 1
    return f

for lbl, lst in (("rdata", genr), ("data", gend)):
    f = freq_df_only(lst)
    W(f"  {lbl} DepthFunc distribution (genuine only):")
    for k, c in sorted(f.items(), key=lambda kv:-kv[1]):
        W(f"    {k}/{D3D_CMP.get(k,'?')} x {c}")

# Show first 30 genuine descs from .rdata
W("\n  first 30 'genuine' rdata descs (with xrefs):")
for ea, de, dm, df, se, sr, sw in genr[:30]:
    xrs = list(idautils.XrefsTo(ea))
    xref_str = f" xrefs={len(xrs)}"
    if xrs:
        first = xrs[0]
        fn = idaapi.get_func(first.frm)
        if fn:
            xref_str += f" (e.g. from RVA{rva(first.frm):#x} in RVA{rva(fn.start_ea):#x})"
    W(f"    {ea:#x}: En={de} Mask={dm} Func={df}({D3D_CMP.get(df,'?')}) StEn={se} SR={sr:#x} SW={sw:#x}{xref_str}")

# ---------------------------------------------------------------------------
# Q1A: ClearDepthStencilView - now we have imports, but D3D11 methods aren't
# imports (they're COM method indirect calls). We need the ID3D11DeviceContext
# global. BUT an alternative: search .rdata for constant 0.0 and 1.0 floats,
# then check nearby xmm3 loads feeding into indirect calls with disp 0x1A8.
#
# SIMPLER: IF we saw only LESS_EQUAL or GREATER_EQUAL descs, we already know
# the convention. So Q1 is answered by the desc frequency above.
#
# Additional heuristic: scan .rdata for the EXACT floats 0.0f and 1.0f that
# are loaded into xmm3. Float 0.0 = 0x00000000, 1.0 = 0x3F800000.
# The pattern: movss xmm3, cs:flt_...; call qword ptr [rax+1A8h].
# But we can also directly count: disp=0x1A8 in top 40 is not present, but
# how many total?
# ---------------------------------------------------------------------------

W("\n" + "="*72)
W("Q1A: Look for disp=0x1A8 via function scan")
W("="*72)
# rescan all funcs counting calls at disp 0x1A8
num_funcs = ida_funcs.get_func_qty()
slot_1a8 = []
slot_1a0 = []
slot_108 = []
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
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi):
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                d = op.addr & 0xFFFFFFFFFFFFFFFF
                if d > 0x7FFFFFFFFFFFFFFF:
                    d -= 0x10000000000000000
                if d == 0x1A8: slot_1a8.append(ea)
                elif d == 0x1A0: slot_1a0.append(ea)
                elif d == 0x108: slot_108.append(ea)
        ea += insn.size

W(f"  disp=0x1A8 (ClearDepthStencilView): {len(slot_1a8)} calls")
W(f"  disp=0x1A0 (ClearRenderTargetView): {len(slot_1a0)} calls")
W(f"  disp=0x108 (OMSetRenderTargets):    {len(slot_108)} calls")

# Disambiguate which calls are actually D3D11 (vs any coincidental vtable slot).
# Heuristic: the caller sequence is "mov rax, [global]; ...; mov rdx, <DSV>;
# mov r8d, 3; movss xmm3, flt_...; call [rax+1A8h]". Most importantly, xmm3
# loaded from a float near the call. Let's backtrack xmm3 for these 0x1A8 calls.
def as_float(val):
    try: return struct.unpack("<f", struct.pack("<I", val & 0xFFFFFFFF))[0]
    except: return None

def backtrack_xmm(call_ea, xmm_name, limit=50):
    cur = call_ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR: return None
        m = idc.print_insn_mnem(cur).lower()
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != xmm_name: continue
        in2 = idautils.DecodeInstruction(cur)
        if not in2: continue
        if m in ("xorps","xorpd","pxor","vxorps","vpxor"):
            if idc.print_operand(cur, 1).lower() == xmm_name:
                return (0.0, cur, "xor->0")
        op1 = in2.ops[1]
        if op1.type == idaapi.o_mem:
            dw = idc.get_wide_dword(op1.addr)
            if dw is not None:
                return (as_float(dw), cur, f"@{op1.addr:#x}")
        elif op1.type == idaapi.o_reg:
            sr = idc.print_operand(cur, 1).lower()
            return backtrack_xmm(cur, sr, limit)
        return (None, cur, m)
    return None

depth_val_freq = {}
samples_1a8 = []
for ea in slot_1a8:
    r = backtrack_xmm(ea, "xmm3", 50)
    v = r[0] if r else None
    k = f"{v:.6f}" if isinstance(v, float) else "unknown"
    depth_val_freq[k] = depth_val_freq.get(k, 0) + 1
    if len(samples_1a8) < 40:
        fn = idaapi.get_func(ea)
        fr = rva(fn.start_ea) if fn else 0
        samples_1a8.append((ea, v, fr, r[2] if r else "?"))
W(f"  depth-clear-value freq: {depth_val_freq}")
W("  first 40 (ea, val, fn):")
for ea, v, fr, src in samples_1a8:
    vs = f"{v}" if isinstance(v, float) else "unknown"
    W(f"    call=RVA{rva(ea):#x} val={vs} src={src}  caller RVA{fr:#x}")

# ---------------------------------------------------------------------------
# Q2: OMSet callers - disp 0x108, top-callers
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q2: OMSetRenderTargets callers")
W("="*72)
caller_counts = {}
for ea in slot_108:
    fn = idaapi.get_func(ea)
    if fn:
        caller_counts[fn.start_ea] = caller_counts.get(fn.start_ea, 0) + 1
W(f"  unique callers: {len(caller_counts)}")
for fn_ea, ct in sorted(caller_counts.items(), key=lambda kv:-kv[1])[:30]:
    W(f"    RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x {ct}")

# Check if main render (0x140C38F80) has direct calls to 0x108-slot functions
MAIN_RENDER = 0x140C38F80
MR_OMSETS_DIRECT = caller_counts.get(MAIN_RENDER, 0)
W(f"\n  MAIN_RENDER (sub_140C38F80) direct 0x108 calls: {MR_OMSETS_DIRECT}")

# ---------------------------------------------------------------------------
# Q4: Dimensions and formats - skip structured detection, use the
# stack-desc-count and global-desc-count from D3D11_TEXTURE2D_DESC patterns
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q4: Look for D3D11_TEXTURE2D_DESC in .rdata/.data with BIND_DEPTH_STENCIL")
W("="*72)
DXGI = {0:"UNKNOWN",19:"D32_FLOAT_S8X24",20:"R32_FLOAT_X8X24_TYPELESS",
        39:"R32_TYPELESS",40:"D32_FLOAT",41:"R32_FLOAT",
        44:"R24G8_TYPELESS",45:"D24_UNORM_S8_UINT",46:"R24_UNORM_X8_TYPELESS",
        55:"R16_TYPELESS",56:"D16_UNORM",57:"R16_UNORM"}

def scan_tex2d(name):
    seg = idaapi.get_segm_by_name(name)
    if not seg: return []
    hits = []
    ea = seg.start_ea
    end = seg.end_ea
    while ea < end - 0x40:
        w = idc.get_wide_dword(ea) or 0
        h = idc.get_wide_dword(ea+4) or 0
        mips = idc.get_wide_dword(ea+8) or 0
        arr = idc.get_wide_dword(ea+0xC) or 0
        fmt = idc.get_wide_dword(ea+0x10) or 0
        samp = idc.get_wide_dword(ea+0x14) or 0
        usage = idc.get_wide_dword(ea+0x1C) or 0
        bind = idc.get_wide_dword(ea+0x20) or 0
        # Very tight filter: bind must include BIND_DEPTH_STENCIL (0x40) and
        # format must be a depth format
        if (bind & 0x40) and fmt in (19, 20, 39, 40, 44, 45, 46, 55, 56, 57):
            if 16 <= w <= 16384 and 16 <= h <= 16384:
                hits.append((ea, w, h, mips, arr, fmt, samp, usage, bind))
        ea += 4
    return hits

for sname in (".rdata", ".data"):
    hits = scan_tex2d(sname)
    W(f"  {sname} DEPTH-bind Tex2D descs: {len(hits)}")
    for h in hits[:30]:
        ea, w, hh, mips, arr, fmt, samp, usage, bind = h
        W(f"    {ea:#x}: {w}x{hh} mips={mips} arr={arr} fmt={fmt}({DXGI.get(fmt,'?')}) samp={samp} usage={usage} bind={bind:#x}")

# ---------------------------------------------------------------------------
W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
W(f"\nReport: {OUT}")
idc.qexit(0)
