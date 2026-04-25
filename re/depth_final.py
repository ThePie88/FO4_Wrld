"""
FINAL DEPTH RE - Answer Q1-Q4 about Fallout 4 1.11.191 depth convention.

Q1: Depth convention (forward-Z vs reverse-Z) - find ClearDepthStencilView + clear val.
Q2: Scene main depth DSV identification.
Q3: Camera near/far planes (NiFrustum).
Q4: Format of the main scene depth buffer (CreateTexture2D DSV format).
"""
import idaapi, idautils, idc
import ida_bytes, ida_funcs, ida_name, ida_xref, ida_hexrays, ida_nalt, ida_ua
import struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)

idaapi.auto_wait()

imagebase = idaapi.get_imagebase()
W(f"[*] imagebase = {imagebase:#x}")
W(f"[*] file type = {idaapi.get_file_type_name()}")

# ---------------------------------------------------------------------------
# 0. Resolve interesting import thunks by name
# ---------------------------------------------------------------------------
def find_name(n):
    ea = ida_name.get_name_ea(idaapi.BADADDR, n)
    return ea if ea != idaapi.BADADDR else None

# D3D11 device context methods and ID3D11Device methods we care about:
TARGET_NAMES = [
    # ID3D11DeviceContext
    "ID3D11DeviceContext_ClearDepthStencilView",
    "ClearDepthStencilView",
    "ID3D11DeviceContext_OMSetRenderTargets",
    "OMSetRenderTargets",
    "ID3D11DeviceContext_OMSetDepthStencilState",
    "OMSetDepthStencilState",
    # ID3D11Device
    "ID3D11Device_CreateDepthStencilState",
    "CreateDepthStencilState",
    "ID3D11Device_CreateDepthStencilView",
    "CreateDepthStencilView",
    "ID3D11Device_CreateTexture2D",
    "CreateTexture2D",
]

W("\n[*] Searching for D3D11 API names")
for n in TARGET_NAMES:
    ea = find_name(n)
    if ea:
        W(f"   name hit: {n} -> {ea:#x}")

# ---------------------------------------------------------------------------
# 1. D3D11 call sites via vtable indirect calls.
# In the 1.11.191 binary, D3D11 methods are reached through a vtable pointer
# kept in a global. We'll search by string "ClearDepthStencilView" + cross
# references, and by pattern "mov rax, [vtable]; call qword ptr [rax+offset]".
# Since direct export naming won't exist for COM methods, we use a heuristic:
# Look for xrefs to a small set of floats (1.0, 0.0) near conspicuous depth
# writes at patterns like call [rax+NNN] where NNN matches vtable slot.
# ---------------------------------------------------------------------------

# ID3D11DeviceContext1 vtable slot offsets (in 8-byte units from vtable ptr):
#   53: ClearDepthStencilView (slot 54 indexed from 1; 53 from 0; offset = 53*8=0x1A8)
# Slots index (from MSDN ID3D11DeviceContext):
#  0-2 IUnknown. 3+ COM methods. ClearDepthStencilView = method index 53,
#  so vtable offset = 53*8 = 0x1A8.
# OMSetRenderTargets = method index 33, offset = 33*8 = 0x108.
# OMSetDepthStencilState = method index 36, offset = 0x120.
# ID3D11Device:
# CreateTexture2D = method index 5, offset 0x28.
# CreateDepthStencilView = method index 9, offset 0x48.
# CreateDepthStencilState = method index 20, offset 0xA0.

W("\n" + "="*72)
W("Q1 part A: search for ClearDepthStencilView calls (vtable slot 0x1A8)")
W("="*72)

# Strategy: enumerate all code, find instructions:
#   call qword ptr [rax+1A8h]  OR similar via rcx/rdx
# D3D11 COM call is:
#   mov  rax, [this_ptr]       ; vtable
#   call qword ptr [rax+offset]
# Then scan ~20 insns backward for the 4th argument (depth clear value) which
# is a float passed in XMM3 (Windows x64 fastcall).

CLEAR_DSV_SLOT = 0x1A8  # ClearDepthStencilView in ID3D11DeviceContext1
CLEAR_RTV_SLOT = 0x1A0  # ClearRenderTargetView
OMSET_RT_SLOT  = 0x108  # OMSetRenderTargets
OMSET_DSS_SLOT = 0x120  # OMSetDepthStencilState
CREATE_TEX2D_SLOT = 0x28  # ID3D11Device::CreateTexture2D
CREATE_DSS_SLOT = 0xA0   # ID3D11Device::CreateDepthStencilState
CREATE_DSV_SLOT = 0x48   # ID3D11Device::CreateDepthStencilView

def find_vcall_sites(slot_offset):
    """Scan .text for 'call qword ptr [reg + slot_offset]'."""
    hits = []
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        return hits
    ea = seg.start_ea
    end = seg.end_ea
    # Enumerate code instructions via idautils.Heads.
    for h in idautils.Heads(ea, end):
        insn = idautils.DecodeInstruction(h)
        if not insn or insn.itype not in (idaapi.NN_call, idaapi.NN_callfi):
            continue
        op = insn.ops[0]
        # Memory operand = [reg + disp]
        if op.type == idaapi.o_displ:
            # ops.addr holds displacement
            disp = op.addr & 0xFFFFFFFF
            if disp > 0x7FFFFFFF:
                disp -= 0x100000000
            if disp == slot_offset:
                hits.append(h)
    return hits

def rva(ea):
    return ea - imagebase

# Warning: enumerating all .text heads is slow; let's do it once and keep a
# map slot -> list.
def scan_all_vcalls():
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        return {}
    ea = seg.start_ea
    end = seg.end_ea
    out = {}
    cnt = 0
    for h in idautils.Heads(ea, end):
        insn = idautils.DecodeInstruction(h)
        if not insn or insn.itype not in (idaapi.NN_call, idaapi.NN_callfi):
            continue
        op = insn.ops[0]
        if op.type != idaapi.o_displ:
            continue
        disp = op.addr & 0xFFFFFFFF
        if disp > 0x7FFFFFFF:
            disp -= 0x100000000
        # only watch slots of interest
        if disp in (CLEAR_DSV_SLOT, CLEAR_RTV_SLOT, OMSET_RT_SLOT,
                    OMSET_DSS_SLOT, CREATE_TEX2D_SLOT, CREATE_DSS_SLOT,
                    CREATE_DSV_SLOT):
            out.setdefault(disp, []).append(h)
        cnt += 1
    W(f"   scanned {cnt} call/callfi instructions")
    return out

vcalls = scan_all_vcalls()
for slot, lst in vcalls.items():
    W(f"   slot {slot:#x} hits: {len(lst)}")

# ---------------------------------------------------------------------------
# Helpers: decode float argument
# ---------------------------------------------------------------------------
def as_float(val):
    try:
        return struct.unpack("<f", struct.pack("<I", val & 0xFFFFFFFF))[0]
    except Exception:
        return None

def backtrack_xmm3(call_ea, limit=40):
    """Walk backwards from call looking for 'movss xmm3, <...>' or
    'movaps xmm3, xmm?' chains; resolve to float if possible."""
    insn_list = []
    cur = call_ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR:
            break
        insn = idautils.DecodeInstruction(cur)
        if not insn:
            continue
        insn_list.append((cur, insn))
    # find last write to xmm3
    val = None
    for ea, insn in insn_list:
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem not in ("movss", "movaps", "movups", "xorps", "vmovss", "vxorps", "pxor", "vpxor"):
            continue
        op0 = idc.print_operand(ea, 0).lower()
        if op0 != "xmm3":
            continue
        if mnem in ("xorps", "vxorps", "pxor", "vpxor"):
            op1 = idc.print_operand(ea, 1).lower()
            if op1 == "xmm3":
                val = 0.0
                src_ea = ea
                break
        else:
            # movss xmm3, cs:flt_XXX  ; op1 is memory
            # Check for immediate memory reference
            op1 = insn.ops[1]
            if op1.type in (idaapi.o_mem, idaapi.o_imm):
                addr = op1.addr if op1.type == idaapi.o_mem else op1.value
                dw = idc.get_wide_dword(addr)
                if dw is not None:
                    val = as_float(dw)
                    src_ea = ea
                    break
            # movss xmm3, xmm? - follow the source xmm reg
            if op1.type == idaapi.o_reg:
                src_reg = idc.print_operand(ea, 1).lower()
                # walk backward from ea to find last write to src_reg
                cur2 = ea
                for _ in range(limit):
                    cur2 = idc.prev_head(cur2)
                    if cur2 == idaapi.BADADDR:
                        break
                    m2 = idc.print_insn_mnem(cur2).lower()
                    o0 = idc.print_operand(cur2, 0).lower()
                    if o0 != src_reg:
                        continue
                    in2 = idautils.DecodeInstruction(cur2)
                    if not in2:
                        continue
                    if m2 in ("xorps", "vxorps", "pxor", "vpxor") and idc.print_operand(cur2, 1).lower() == src_reg:
                        val = 0.0
                        src_ea = cur2
                        break
                    op12 = in2.ops[1]
                    if op12.type in (idaapi.o_mem, idaapi.o_imm):
                        addr2 = op12.addr if op12.type == idaapi.o_mem else op12.value
                        dw2 = idc.get_wide_dword(addr2)
                        val = as_float(dw2) if dw2 is not None else None
                        src_ea = cur2
                        break
                break
    return val

def backtrack_arg(call_ea, arg_reg, limit=40):
    """Find last write to a general register (rdx, r8, r9, ecx...) before call."""
    cur = call_ea
    arg_reg = arg_reg.lower()
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur).lower()
        o0 = idc.print_operand(cur, 0).lower()
        if o0 == arg_reg:
            return (cur, mnem, idc.print_operand(cur, 1))
    return None

# ---------------------------------------------------------------------------
# Q1A: ClearDepthStencilView analysis
# Signature: ClearDepthStencilView(this, pDSV, ClearFlags, Depth, Stencil)
# x64 fastcall: rcx=this, rdx=pDSV, r8=ClearFlags (u32), xmm3=Depth (float), stack=Stencil(u8)
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q1A: ClearDepthStencilView call sites & depth clear values")
W("="*72)
clear_hits = vcalls.get(CLEAR_DSV_SLOT, [])
clear_values = []
for ea in clear_hits[:200]:  # cap
    depth_val = backtrack_xmm3(ea)
    flags_info = backtrack_arg(ea, "r8d")
    clear_values.append((ea, depth_val, flags_info))
W(f"  total CSV sites: {len(clear_hits)}")
# frequency table
freq = {}
for ea, v, _ in clear_values:
    key = f"{v:.3f}" if isinstance(v, float) else "unknown"
    freq[key] = freq.get(key, 0) + 1
W(f"  clear-value frequency: {freq}")
# sample first 20 sites
W("  -- first 20 sites --")
for ea, v, f_info in clear_values[:20]:
    func = idaapi.get_func(ea)
    fn_name = idc.get_func_name(func.start_ea) if func else "?"
    fn_rva = rva(func.start_ea) if func else 0
    v_str = f"{v:.6f}" if isinstance(v, float) else "unknown"
    W(f"   ea={rva(ea):#x} depth={v_str} flags={f_info}  in {fn_name}@RVA{fn_rva:#x}")

# ---------------------------------------------------------------------------
# Q1B: CreateDepthStencilState calls - look for D3D11_DEPTH_STENCIL_DESC
# The function signature:
# HRESULT CreateDepthStencilState(this, const D3D11_DEPTH_STENCIL_DESC* desc, **ppState)
# The desc struct layout:
# BOOL DepthEnable;        // +0x00
# D3D11_DEPTH_WRITE_MASK;  // +0x04
# D3D11_COMPARISON_FUNC DepthFunc; // +0x08
# BOOL StencilEnable;      // +0x0C
# ...
# DepthFunc values: 1=NEVER, 2=LESS, 3=EQUAL, 4=LESS_EQUAL, 5=GREATER,
# 6=NOT_EQUAL, 7=GREATER_EQUAL, 8=ALWAYS
# rdx = pointer to desc, so scan for pointer loaded into rdx prior to call.
# The desc is usually .rdata/.data or on stack (lea rdx, [rsp+NN]).
# Strategy:
#   - pattern: lea rdx, [something]; (maybe other insns); call [rax+0xA0]
#   - If lea rdx points to .rdata/.data, read 16 bytes from there.
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q1B: CreateDepthStencilState call sites & DepthFunc values")
W("="*72)

def resolve_lea_rdx_before_call(call_ea, limit=50):
    cur = call_ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR:
            return None
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem != "lea":
            continue
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != "rdx":
            continue
        insn = idautils.DecodeInstruction(cur)
        if not insn:
            continue
        op1 = insn.ops[1]
        # If displacement references global memory ([rip+disp] etc), value is addr
        if op1.type == idaapi.o_mem:
            return ("mem", op1.addr, cur)
        if op1.type == idaapi.o_displ:
            # Could be [rsp + X] (stack) or [rbp + X]
            return ("stack", op1.addr, cur)
    return None

dss_hits = vcalls.get(CREATE_DSS_SLOT, [])
W(f"  total CreateDepthStencilState sites: {len(dss_hits)}")
depth_func_counts = {}
stencil_on_counts = {}
dss_rows = []
for ea in dss_hits[:200]:
    info = resolve_lea_rdx_before_call(ea)
    if not info:
        dss_rows.append((ea, None, None, None, None))
        continue
    kind, addr, lea_ea = info
    if kind == "mem":
        depth_enable = idc.get_wide_dword(addr)
        depth_mask   = idc.get_wide_dword(addr + 4)
        depth_func   = idc.get_wide_dword(addr + 8)
        stencil_en   = idc.get_wide_dword(addr + 12)
    else:
        depth_enable = depth_mask = depth_func = stencil_en = None
    dss_rows.append((ea, kind, addr, depth_func, stencil_en))
    if depth_func is not None:
        depth_func_counts[depth_func] = depth_func_counts.get(depth_func, 0) + 1
    if stencil_en is not None:
        stencil_on_counts[stencil_en] = stencil_on_counts.get(stencil_en, 0) + 1
W(f"  DepthFunc frequency (global descs only): {depth_func_counts}")
W(f"  StencilEnable frequency:                 {stencil_on_counts}")
D3D_CMP = {1:"NEVER",2:"LESS",3:"EQUAL",4:"LESS_EQUAL",5:"GREATER",6:"NOT_EQUAL",7:"GREATER_EQUAL",8:"ALWAYS"}
for df, ct in sorted(depth_func_counts.items()):
    W(f"    {df} ({D3D_CMP.get(df,'?')}) x {ct}")

# Examples
W("  -- first 30 sites --")
for ea, kind, addr, depth_func, se in dss_rows[:30]:
    func = idaapi.get_func(ea)
    fn_rva = rva(func.start_ea) if func else 0
    if kind == "mem":
        W(f"   ea={rva(ea):#x} desc@{addr:#x} DepthFunc={depth_func}({D3D_CMP.get(depth_func or 0, '?')}) Stencil={se}  in RVA{fn_rva:#x}")
    else:
        W(f"   ea={rva(ea):#x} desc=stack (runtime filled) in RVA{fn_rva:#x}")

# ---------------------------------------------------------------------------
# Q4: CreateTexture2D calls - find those with BindFlags containing DEPTH_STENCIL
# Desc layout: D3D11_TEXTURE2D_DESC
#   UINT Width;           +0x00
#   UINT Height;          +0x04
#   UINT MipLevels;       +0x08
#   UINT ArraySize;       +0x0C
#   DXGI_FORMAT Format;   +0x10
#   DXGI_SAMPLE_DESC      +0x14 (Count +0x14, Quality +0x18)
#   D3D11_USAGE Usage;    +0x1C
#   UINT BindFlags;       +0x20
#   ...
# BindFlags DEPTH_STENCIL = 0x40
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q4: CreateTexture2D calls with DEPTH_STENCIL bind flag")
W("="*72)

DXGI_FORMATS = {
    0:"UNKNOWN",
    2:"R32G32B32A32_FLOAT",
    10:"R16G16B16A16_FLOAT",
    20:"R32G32_FLOAT",
    24:"R10G10B10A2_UNORM",
    28:"R8G8B8A8_UNORM",
    29:"R8G8B8A8_UNORM_SRGB",
    39:"R32_TYPELESS",  # will appear sometimes
    40:"D32_FLOAT",
    41:"R32_FLOAT",
    44:"R24G8_TYPELESS",
    45:"D24_UNORM_S8_UINT",
    46:"R24_UNORM_X8_TYPELESS",
    55:"R16_TYPELESS",
    56:"D16_UNORM",
    57:"R16_UNORM",
    19:"D32_FLOAT_S8X24_UINT",
}

tex_hits = vcalls.get(CREATE_TEX2D_SLOT, [])
W(f"  total CreateTexture2D sites: {len(tex_hits)}")
depth_tex_rows = []
format_freq = {}
for ea in tex_hits[:500]:
    info = resolve_lea_rdx_before_call(ea)
    if not info:
        continue
    kind, addr, lea_ea = info
    if kind != "mem":
        continue
    # need global desc
    width  = idc.get_wide_dword(addr + 0x00) or 0
    height = idc.get_wide_dword(addr + 0x04) or 0
    mips   = idc.get_wide_dword(addr + 0x08) or 0
    array_ = idc.get_wide_dword(addr + 0x0C) or 0
    fmt    = idc.get_wide_dword(addr + 0x10) or 0
    samp   = idc.get_wide_dword(addr + 0x14) or 0
    usage  = idc.get_wide_dword(addr + 0x1C) or 0
    bind   = idc.get_wide_dword(addr + 0x20) or 0
    if bind & 0x40:  # D3D11_BIND_DEPTH_STENCIL
        depth_tex_rows.append((ea, addr, width, height, mips, array_, fmt, samp, bind))
        format_freq[fmt] = format_freq.get(fmt, 0) + 1
W(f"  depth-stencil-bind textures (GLOBAL desc only): {len(depth_tex_rows)}")
W(f"  format frequency: {[(DXGI_FORMATS.get(f, f'fmt#{f}'), c) for f, c in format_freq.items()]}")

W("  -- depth textures list --")
for ea, addr, w, h, m, a, f, s, b in depth_tex_rows:
    func = idaapi.get_func(ea)
    fn_rva = rva(func.start_ea) if func else 0
    W(f"   ea={rva(ea):#x} desc@{addr:#x} {w}x{h} mips={m} arr={a} fmt={f}({DXGI_FORMATS.get(f,'?')}) samp={s} bind={b:#x} in RVA{fn_rva:#x}")

# Also count stack-based desc sites (dynamic size)
stack_tex = 0
for ea in tex_hits:
    info = resolve_lea_rdx_before_call(ea)
    if info and info[0] == "stack":
        stack_tex += 1
W(f"  stack-filled CreateTexture2D sites (dynamic desc): {stack_tex}")

# ---------------------------------------------------------------------------
# Q3: Camera near/far defaults - search NiCamera constructor or frustum setup.
# NiFrustum is 24-byte struct:
#   float left, right, top, bottom, near, far
#   BOOL ortho (bool)
# Typical sentinel values: FO4 main world uses near=1.0, far=very_large (~100000).
# Search for references to "NiCamera" string + trace back.
# Also search immediate usage of "fWorldPointMult" or "fDefaultWorldFOV".
# Shortcut: look for default NiFrustum where near=1.0, far > 10000
# Scan .rdata for float pattern [1.0, 10000.0] etc.
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q3: Search for NiCamera + NiFrustum defaults (near, far)")
W("="*72)

def find_string(s):
    hits = []
    for sea in idautils.Strings():
        try:
            if str(sea) == s:
                hits.append(sea.ea)
        except Exception:
            pass
    return hits

ni_cam = find_string("NiCamera")
W(f"  'NiCamera' strings: {[hex(x) for x in ni_cam[:5]]}")
for s_ea in ni_cam[:5]:
    for xr in idautils.XrefsTo(s_ea):
        fn = idaapi.get_func(xr.frm)
        if fn:
            W(f"   xref from {rva(xr.frm):#x}  in RVA{rva(fn.start_ea):#x}")

# Scan .rdata for plausible (near,far) pairs: near=1.0, far in {10000, 50000, 100000, 1e6, 1e7}
NEARS = {1.0, 0.1, 0.01, 4.0, 5.0, 10.0}
FARS = {1000.0, 5000.0, 10000.0, 20000.0, 50000.0, 100000.0, 500000.0, 1e6, 1e7, 1.1754944e38, 3.4028235e38}
seg_rdata = idaapi.get_segm_by_name(".rdata")
pairs = []
if seg_rdata:
    ea = seg_rdata.start_ea
    end = seg_rdata.end_ea
    while ea < end - 8:
        f1 = as_float(idc.get_wide_dword(ea) or 0)
        f2 = as_float(idc.get_wide_dword(ea + 4) or 0)
        if f1 is not None and f2 is not None and f1 in NEARS and f2 in FARS:
            pairs.append((ea, f1, f2))
        ea += 4
W(f"  (near,far) candidate pairs in .rdata: {len(pairs)}")
for ea, f1, f2 in pairs[:30]:
    W(f"   {ea:#x}: near={f1} far={f2}")

# ---------------------------------------------------------------------------
# Q2: Scene main depth DSV identification
# Strategy: iterate OMSetRenderTargets call sites. Inspect which DSV was bound.
# But at static time we can't know runtime size. The scene opaque pass is the
# one that uses the LARGEST CreateTexture2D depth tex with BIND_DEPTH_STENCIL
# + BIND_SHADER_RESOURCE at runtime-computed size (stack desc).
# Most likely signature: a specific function pulls BindFlags = 0x40|0x08 = 0x48.
# We report OMSetRenderTargets call sites most commonly reached from the
# main-render function (sub_140C38F80 from existing report).
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q2: Scene DSV identification — OMSetRenderTargets sites (top callers)")
W("="*72)
omset_hits = vcalls.get(OMSET_RT_SLOT, [])
W(f"  total OMSetRenderTargets sites: {len(omset_hits)}")
caller_counts = {}
for ea in omset_hits:
    fn = idaapi.get_func(ea)
    if fn:
        caller_counts[fn.start_ea] = caller_counts.get(fn.start_ea, 0) + 1
sorted_callers = sorted(caller_counts.items(), key=lambda kv: -kv[1])
W("  top 20 callers of OMSetRenderTargets:")
for fn_ea, ct in sorted_callers[:20]:
    name = idc.get_func_name(fn_ea)
    W(f"   RVA{rva(fn_ea):#x} ({name}) x{ct}")

# Is sub_140C38F80 (main 3D scene render) in the callers chain?
MAIN_RENDER = 0x140C38F80
W(f"  MAIN_RENDER sub_140C38F80 OMSet count in its body: {caller_counts.get(MAIN_RENDER, 0)}")
# Also show callers transitively reachable from MAIN_RENDER at depth 1
W("  sub-functions of main render that call OMSetRenderTargets (depth 1):")
main_fn = idaapi.get_func(MAIN_RENDER)
if main_fn:
    # collect call targets from main render body
    targets = set()
    for h in idautils.Heads(main_fn.start_ea, main_fn.end_ea):
        if idaapi.is_call_insn(h):
            tgt = idc.get_operand_value(h, 0)
            if tgt != idaapi.BADADDR and tgt != 0 and tgt != -1:
                targets.add(tgt)
    # which of these call OMSetRenderTargets?
    relevant = []
    for tgt in targets:
        fn2 = idaapi.get_func(tgt)
        if not fn2:
            continue
        ct = caller_counts.get(fn2.start_ea, 0)
        if ct > 0:
            relevant.append((fn2.start_ea, ct))
    relevant.sort(key=lambda x: -x[1])
    for fn_ea, ct in relevant[:30]:
        W(f"   RVA{rva(fn_ea):#x} x{ct}")

# ---------------------------------------------------------------------------
# Q2 bonus: CreateDepthStencilView call sites + desc for every DSV created
# ---------------------------------------------------------------------------
W("\n" + "="*72)
W("Q2 bonus: CreateDepthStencilView call sites")
W("="*72)
dsv_hits = vcalls.get(CREATE_DSV_SLOT, [])
W(f"  total CreateDepthStencilView sites: {len(dsv_hits)}")
for ea in dsv_hits[:40]:
    fn = idaapi.get_func(ea)
    fn_rva = rva(fn.start_ea) if fn else 0
    fn_name = idc.get_func_name(fn.start_ea) if fn else "?"
    W(f"   ea={rva(ea):#x}  in {fn_name}@RVA{fn_rva:#x}")

# ---------------------------------------------------------------------------
# Done.
# ---------------------------------------------------------------------------
W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
W(f"\nReport written to {OUT}")

idc.qexit(0)
