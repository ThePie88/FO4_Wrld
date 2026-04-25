"""Depth RE v2 - iterate function bodies for call instructions."""
import idaapi, idautils, idc, ida_name, ida_funcs
import struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report2.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)

idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
W(f"[*] imagebase = {imagebase:#x}")

# List all segments and their types
W("\n[*] segments:")
for si in range(idaapi.get_segm_qty()):
    s = idaapi.getnseg(si)
    if not s:
        continue
    name = idaapi.get_segm_name(s)
    perm = s.perm
    sclass = idaapi.get_segm_class(s)
    W(f"   {name} [{sclass}] perm={perm:#x} {s.start_ea:#x}..{s.end_ea:#x}  len={s.end_ea-s.start_ea:#x}")

# Enumerate call-sites by iterating all functions and their instructions
CLEAR_DSV_SLOT = 0x1A8
CLEAR_RTV_SLOT = 0x1A0
OMSET_RT_SLOT  = 0x108
OMSET_DSS_SLOT = 0x120
CREATE_TEX2D_SLOT = 0x28
CREATE_DSS_SLOT = 0xA0
CREATE_DSV_SLOT = 0x48

SLOTS = {
    CLEAR_DSV_SLOT: "ClearDepthStencilView",
    CLEAR_RTV_SLOT: "ClearRenderTargetView",
    OMSET_RT_SLOT: "OMSetRenderTargets",
    OMSET_DSS_SLOT: "OMSetDepthStencilState",
    CREATE_TEX2D_SLOT: "CreateTexture2D",
    CREATE_DSS_SLOT: "CreateDepthStencilState",
    CREATE_DSV_SLOT: "CreateDepthStencilView",
}

def rva(ea):
    return ea - imagebase

vcalls = {s: [] for s in SLOTS}

num_funcs = ida_funcs.get_func_qty()
W(f"\n[*] total functions: {num_funcs}")

total_calls = 0
total_insns = 0
for fi in range(num_funcs):
    fn = ida_funcs.getn_func(fi)
    if not fn:
        continue
    ea = fn.start_ea
    while ea < fn.end_ea:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            ea = idc.next_head(ea, fn.end_ea)
            if ea == idaapi.BADADDR:
                break
            continue
        total_insns += 1
        if insn.itype == idaapi.NN_call or insn.itype == idaapi.NN_callfi:
            total_calls += 1
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                disp = op.addr & 0xFFFFFFFF
                if disp > 0x7FFFFFFF:
                    disp -= 0x100000000
                if disp in SLOTS:
                    vcalls[disp].append(ea)
        ea = ea + insn.size
W(f"[*] total insns scanned: {total_insns}  total calls: {total_calls}")
for s, lst in vcalls.items():
    W(f"   slot {s:#x} ({SLOTS[s]}): {len(lst)}")

def as_float(val):
    try:
        return struct.unpack("<f", struct.pack("<I", val & 0xFFFFFFFF))[0]
    except Exception:
        return None

# ---------- Q1A: clear depth values ----------
def backtrack_xmm(call_ea, xmm_name, limit=40):
    cur = call_ea
    xmm_name = xmm_name.lower()
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur).lower()
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != xmm_name:
            continue
        if mnem in ("xorps", "vxorps", "pxor", "vpxor"):
            op1 = idc.print_operand(cur, 1).lower()
            if op1 == xmm_name:
                return (0.0, cur, "xor=0")
        in2 = idautils.DecodeInstruction(cur)
        if not in2:
            continue
        op1 = in2.ops[1]
        if op1.type == idaapi.o_mem:
            dw = idc.get_wide_dword(op1.addr)
            if dw is not None:
                return (as_float(dw), cur, f"mem@{op1.addr:#x}")
        if op1.type == idaapi.o_reg:
            src = idc.print_operand(cur, 1).lower()
            # Recurse on src reg
            val = backtrack_xmm(cur, src, limit)
            if val is not None:
                return val
        return (None, cur, "unknown")
    return None

W("\n" + "="*72)
W("Q1A: ClearDepthStencilView analysis")
W("="*72)
clear_depth_freq = {}
first_samples = []
for i, ea in enumerate(vcalls[CLEAR_DSV_SLOT]):
    res = backtrack_xmm(ea, "xmm3", 40)
    depth_val = res[0] if res else None
    key = f"{depth_val:.6f}" if isinstance(depth_val, float) else "unknown"
    clear_depth_freq[key] = clear_depth_freq.get(key, 0) + 1
    if i < 30:
        fn = idaapi.get_func(ea)
        fn_rva = rva(fn.start_ea) if fn else 0
        first_samples.append((ea, depth_val, fn_rva))
W(f"  total sites: {len(vcalls[CLEAR_DSV_SLOT])}")
W(f"  depth-clear-value frequency: {clear_depth_freq}")
W("  first 30 samples:")
for ea, v, fr in first_samples:
    vs = f"{v:.6f}" if isinstance(v, float) else "unknown"
    W(f"    ea=RVA{rva(ea):#x} depth={vs}  in fn RVA{fr:#x}")

# ---------- Q1B: CreateDepthStencilState descs ----------
def resolve_lea_rdx_before_call(call_ea, limit=60):
    cur = call_ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR:
            return None
        mnem = idc.print_insn_mnem(cur).lower()
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != "rdx":
            continue
        if mnem != "lea":
            continue
        insn = idautils.DecodeInstruction(cur)
        if not insn:
            continue
        op1 = insn.ops[1]
        if op1.type == idaapi.o_mem:
            return ("mem", op1.addr, cur)
        if op1.type == idaapi.o_displ:
            return ("stack", op1.addr, cur)
    return None

W("\n" + "="*72)
W("Q1B: CreateDepthStencilState desc decode")
W("="*72)
D3D_CMP = {1:"NEVER",2:"LESS",3:"EQUAL",4:"LESS_EQUAL",5:"GREATER",6:"NOT_EQUAL",7:"GREATER_EQUAL",8:"ALWAYS"}
depth_func_freq = {}
depth_enable_freq = {}
depth_mask_freq = {}
samples = []
dss_stack = 0
for ea in vcalls[CREATE_DSS_SLOT]:
    info = resolve_lea_rdx_before_call(ea)
    if not info:
        continue
    kind, addr, _ = info
    if kind == "stack":
        dss_stack += 1
        continue
    d_en = idc.get_wide_dword(addr)
    d_mk = idc.get_wide_dword(addr + 4)
    d_fn = idc.get_wide_dword(addr + 8)
    s_en = idc.get_wide_dword(addr + 12)
    depth_func_freq[d_fn] = depth_func_freq.get(d_fn, 0) + 1
    depth_enable_freq[d_en] = depth_enable_freq.get(d_en, 0) + 1
    depth_mask_freq[d_mk] = depth_mask_freq.get(d_mk, 0) + 1
    samples.append((ea, addr, d_en, d_mk, d_fn, s_en))
W(f"  total sites: {len(vcalls[CREATE_DSS_SLOT])}  (stack-desc: {dss_stack})")
W(f"  DepthEnable freq: {depth_enable_freq}")
W(f"  DepthWriteMask freq (0=ZERO 1=ALL): {depth_mask_freq}")
W(f"  DepthFunc freq:")
for k, v in sorted(depth_func_freq.items(), key=lambda kv: -kv[1]):
    W(f"    {k} ({D3D_CMP.get(k,'?')}) x {v}")
W("  first 40 samples:")
for ea, addr, de, dm, df, se in samples[:40]:
    fn = idaapi.get_func(ea)
    fr = rva(fn.start_ea) if fn else 0
    W(f"    call=RVA{rva(ea):#x} desc@{addr:#x}  DepthEnable={de} WriteMask={dm} Func={df}({D3D_CMP.get(df,'?')}) StencilEn={se}  caller=RVA{fr:#x}")

# ---------- Q4: CreateTexture2D DSV-bound ----------
W("\n" + "="*72)
W("Q4: CreateTexture2D DSV-bound descs")
W("="*72)
DXGI = {0:"UNKNOWN",2:"R32G32B32A32_FLOAT",10:"R16G16B16A16_FLOAT",19:"D32_FLOAT_S8X24_UINT",
        20:"R32_FLOAT_X8X24_TYPELESS",23:"R10G10B10A2_UNORM",28:"R8G8B8A8_UNORM",
        29:"R8G8B8A8_UNORM_SRGB",39:"R32_TYPELESS",40:"D32_FLOAT",41:"R32_FLOAT",
        44:"R24G8_TYPELESS",45:"D24_UNORM_S8_UINT",46:"R24_UNORM_X8_TYPELESS",
        55:"R16_TYPELESS",56:"D16_UNORM",57:"R16_UNORM"}

fmt_freq = {}
dims_seen = {}
depth_tex_rows = []
stack_tex = 0
for ea in vcalls[CREATE_TEX2D_SLOT]:
    info = resolve_lea_rdx_before_call(ea)
    if not info:
        continue
    kind, addr, _ = info
    if kind == "stack":
        stack_tex += 1
        continue
    w  = idc.get_wide_dword(addr + 0x00) or 0
    h  = idc.get_wide_dword(addr + 0x04) or 0
    m  = idc.get_wide_dword(addr + 0x08) or 0
    a  = idc.get_wide_dword(addr + 0x0C) or 0
    fmt = idc.get_wide_dword(addr + 0x10) or 0
    sc = idc.get_wide_dword(addr + 0x14) or 0
    usage = idc.get_wide_dword(addr + 0x1C) or 0
    bind = idc.get_wide_dword(addr + 0x20) or 0
    if bind & 0x40:
        fmt_freq[fmt] = fmt_freq.get(fmt, 0) + 1
        dk = f"{w}x{h}"
        dims_seen[dk] = dims_seen.get(dk, 0) + 1
        depth_tex_rows.append((ea, addr, w, h, m, a, fmt, sc, bind, usage))
W(f"  CreateTexture2D global-desc DSV-bound: {len(depth_tex_rows)}  (stack-desc: {stack_tex})")
W(f"  format freq: {[(f, DXGI.get(f,'?'), c) for f,c in fmt_freq.items()]}")
W(f"  dim freq: {dims_seen}")
for ea, addr, w, h, m, a, fmt, sc, bind, usage in depth_tex_rows[:40]:
    fn = idaapi.get_func(ea)
    fr = rva(fn.start_ea) if fn else 0
    W(f"    RVA{rva(ea):#x} desc@{addr:#x} {w}x{h} mips={m} arr={a} fmt={fmt}({DXGI.get(fmt,'?')}) samp={sc} usage={usage} bind={bind:#x} caller=RVA{fr:#x}")

# ---------- Q2: OMSet render target callers ----------
W("\n" + "="*72)
W("Q2: OMSetRenderTargets analysis (callers + reachability from MAIN_RENDER)")
W("="*72)
caller_counts = {}
for ea in vcalls[OMSET_RT_SLOT]:
    fn = idaapi.get_func(ea)
    if fn:
        caller_counts[fn.start_ea] = caller_counts.get(fn.start_ea, 0) + 1
W(f"  total OMSetRenderTargets sites: {len(vcalls[OMSET_RT_SLOT])}")
W(f"  unique caller functions: {len(caller_counts)}")
W("  top 30 callers:")
for fn_ea, ct in sorted(caller_counts.items(), key=lambda kv: -kv[1])[:30]:
    W(f"    RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{ct}")

MAIN_RENDER = 0x140C38F80
main_fn = idaapi.get_func(MAIN_RENDER)
W(f"\n  MAIN_RENDER body OMSet count: {caller_counts.get(MAIN_RENDER, 0)}")
if main_fn:
    call_tgts = set()
    ea = main_fn.start_ea
    while ea < main_fn.end_ea:
        insn = idautils.DecodeInstruction(ea)
        if insn and idaapi.is_call_insn(ea):
            tgt = idc.get_operand_value(ea, 0)
            if tgt > 0 and tgt != idaapi.BADADDR:
                call_tgts.add(tgt)
        ea = idc.next_head(ea, main_fn.end_ea)
        if ea == idaapi.BADADDR:
            break
    relevant = []
    for tgt in call_tgts:
        fn2 = idaapi.get_func(tgt)
        if not fn2:
            continue
        ct = caller_counts.get(fn2.start_ea, 0)
        if ct > 0:
            relevant.append((fn2.start_ea, ct))
    relevant.sort(key=lambda x: -x[1])
    W(f"  sub-functions of MAIN_RENDER that directly call OMSet: {len(relevant)}")
    for fn_ea, ct in relevant[:30]:
        W(f"    RVA{rva(fn_ea):#x} x{ct}  ({idc.get_func_name(fn_ea)})")

# ---------- Q3: NiFrustum near/far ----------
W("\n" + "="*72)
W("Q3: NiFrustum near/far search")
W("="*72)
# Find setup code for NiCamera class. Common 1.11.191 RVAs:
# NiCamera vtable has ctor with frustum default. Check classic pattern:
# mov [rcx+0x170], 1.0 (left), [rcx+0x174], 1.0 (right), [rcx+0x178]=?, etc.
# Simpler: search refs to near/far pairs we found.
for pair_ea in (0x1426293F4, 0x142781A00):
    W(f"  pair @ {pair_ea:#x}:")
    for xr in idautils.XrefsTo(pair_ea):
        fn = idaapi.get_func(xr.frm)
        if fn:
            W(f"    xref from RVA{rva(xr.frm):#x} in fn RVA{rva(fn.start_ea):#x} ({idc.get_func_name(fn.start_ea)})")
        else:
            W(f"    xref from RVA{rva(xr.frm):#x} (no func)")

# Search for xrefs to "NiCamera" string and inspect enclosing fn names
ni_cam_ea = None
for s in idautils.Strings():
    try:
        if str(s) == "NiCamera":
            ni_cam_ea = s.ea
            break
    except Exception:
        pass
W(f"  'NiCamera' string: {ni_cam_ea:#x if ni_cam_ea else 0}")
if ni_cam_ea:
    xrs = list(idautils.XrefsTo(ni_cam_ea))
    W(f"  xrefs: {len(xrs)}")
    for xr in xrs[:20]:
        fn = idaapi.get_func(xr.frm)
        fr = rva(fn.start_ea) if fn else 0
        fname = idc.get_func_name(fn.start_ea) if fn else "?"
        W(f"    from RVA{rva(xr.frm):#x} in fn RVA{fr:#x} ({fname})")

# Search .rdata for the triple (1.0, large, ortho=0) which is NiFrustum default.
# Actually NiFrustum is: left,right,top,bottom,near,far,ortho. So 4*floats+2*floats.
# Typical default: left=-1, right=1, top=1, bottom=-1, near=1, far=1000, ortho=0.
seg_rdata = idaapi.get_segm_by_name(".rdata")
if seg_rdata:
    ea = seg_rdata.start_ea
    end = seg_rdata.end_ea
    found = []
    while ea < end - 0x1C:
        try:
            vals = [as_float(idc.get_wide_dword(ea + i*4) or 0) for i in range(6)]
        except Exception:
            ea += 4
            continue
        if all(v is not None for v in vals):
            L, R, T, B, N, F = vals
            # Simple default pattern
            if L == -1.0 and R == 1.0 and T == 1.0 and B == -1.0 and 0.1 <= N <= 10 and F > 100:
                found.append((ea, L, R, T, B, N, F))
        ea += 4
    W(f"  NiFrustum-like rdata defaults: {len(found)}")
    for fe, L, R, T, B, N, F in found[:20]:
        W(f"    {fe:#x}: [{L},{R},{T},{B}]  near={N} far={F}")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
W(f"\nReport: {OUT}")
idc.qexit(0)
