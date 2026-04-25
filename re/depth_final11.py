"""Depth RE v11 - include NN_callni. Full pipeline."""
import idaapi, idautils, idc, ida_funcs, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report11.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

CTX_A = 0x1438CAA90
CTX_B = 0x1438CAAB8
DEVICE = 0x1438CAAA8

def is_call_insn(insn):
    if insn is None: return False
    mnem = insn.get_canon_mnem()
    return mnem.startswith("call")

# Enumerate all vtable-indirect calls
W(f"[*] imagebase = {imagebase:#x}")
W("[*] Scanning all call insns for displ operand...")
slots_of_interest = {0x28, 0x48, 0xA0, 0x108, 0x118, 0x120, 0x190, 0x198, 0x1A0, 0x1A8}
slot_sites = {d: [] for d in slots_of_interest}

num_funcs = ida_funcs.get_func_qty()
total_calls = 0
total_displ_calls = 0
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
        if is_call_insn(insn):
            total_calls += 1
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                total_displ_calls += 1
                d = op.addr & 0xFFFFFFFFFFFFFFFF
                if d in slots_of_interest:
                    slot_sites[d].append(ea)
        ea += insn.size
        if insn.size == 0: break
W(f"[*] total call insns: {total_calls}")
W(f"[*] total displ-indirect calls: {total_displ_calls}")
for d, lst in sorted(slot_sites.items()):
    W(f"   disp={d:#x}: {len(lst)}")

# Disambiguate by base-register chain
def base_reg_of_call(call_ea):
    opstr = idc.print_operand(call_ea, 0).lower()
    # e.g. "qword ptr [rax+1A8h]" -> find base register
    import re
    m = re.search(r"\[([a-z0-9]+)([+\-].*?)?\]", opstr)
    if m:
        return m.group(1)
    return None

def trace_base_origin(call_ea, base_reg, limit=50):
    """Walk backward to find what `base_reg` holds: value of ctx/device global?"""
    cur = call_ea
    reg = base_reg.lower()
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR: return None
        m = idc.print_insn_mnem(cur).lower()
        if m != "mov": continue
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != reg: continue
        insn = idautils.DecodeInstruction(cur)
        if not insn: continue
        op1 = insn.ops[1]
        # mov rax, [rcx]  → rax is vtable; follow rcx instead
        if op1.type == idaapi.o_phrase:
            src = idc.print_operand(cur, 1).lower()
            # extract inner register from [rxx]
            inner = src.strip("[]").replace("qword ptr ", "")
            if inner:
                return trace_base_origin(cur, inner, limit)
        if op1.type == idaapi.o_displ:
            # mov rax, [reg+N] or mov rax, cs:global
            src = idc.print_operand(cur, 1).lower()
            # "cs:qword_1438CAA90" is o_mem, not o_displ
            # displ with base reg - e.g. [rcx+8]
            # We could recurse, but keep simple
            return ("displ_unk", op1.addr, cur)
        if op1.type == idaapi.o_mem:
            return ("mem", op1.addr, cur)
        if op1.type == idaapi.o_reg:
            # mov rax, rcx → follow rcx
            src = idc.print_operand(cur, 1).lower()
            return trace_base_origin(cur, src, limit)
        return ("unknown", 0, cur)
    return None

# For each site, classify whether it's through our known globals
W("\n[*] Classifying each site by global origin...")
def classify_sites(sites_list):
    """Return list of (ea, via_global)."""
    out = []
    for ea in sites_list:
        base = base_reg_of_call(ea)
        if not base:
            out.append((ea, None)); continue
        tr = trace_base_origin(ea, base, 80)
        if not tr:
            out.append((ea, None))
        else:
            kind, val, _ = tr
            if kind == "mem":
                if val == CTX_A: out.append((ea, "ctx_A"))
                elif val == CTX_B: out.append((ea, "ctx_B"))
                elif val == DEVICE: out.append((ea, "device"))
                else: out.append((ea, f"other_mem@{val:#x}"))
            else:
                out.append((ea, f"{kind}"))
    return out

# Only classify the key slots
for slot in [0x1A8, 0xA0, 0x108, 0x28, 0x48, 0x120, 0x190]:
    lst = slot_sites[slot]
    classified = classify_sites(lst)
    tag_counts = {}
    for _, t in classified:
        k = t or "no_trace"
        tag_counts[k] = tag_counts.get(k, 0) + 1
    W(f"  slot {slot:#x}: total {len(lst)}  tags {tag_counts}")

# ---------- Q1A: ClearDSV ----------
def as_float(val):
    try: return struct.unpack("<f", struct.pack("<I", val & 0xFFFFFFFF))[0]
    except: return None

def backtrack_xmm(call_ea, xmm_name, limit=80):
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
            if dw is not None: return (as_float(dw), cur, f"@{op1.addr:#x}")
        elif op1.type == idaapi.o_reg:
            sr = idc.print_operand(cur, 1).lower()
            return backtrack_xmm(cur, sr, limit)
        return (None, cur, m)
    return None

W("\n" + "="*72); W("Q1A: ClearDepthStencilView depth clear values"); W("="*72)
cdsv_sites = slot_sites[0x1A8]
cdsv_class = classify_sites(cdsv_sites)
W(f"  total sites: {len(cdsv_sites)}")
freq = {}
all_freq = {}
for ea, tag in cdsv_class:
    r = backtrack_xmm(ea, "xmm3", 80)
    v = r[0] if r else None
    k = f"{v:.6f}" if isinstance(v, float) else "unknown"
    all_freq[k] = all_freq.get(k, 0) + 1
    if tag in ("ctx_A", "ctx_B"):
        freq[k] = freq.get(k, 0) + 1
W(f"  overall depth-clear-value freq (all ClearDSV sites, even in other contexts): {all_freq}")
W(f"  BSGraphics-ctx only depth-clear-value freq: {freq}")
W("  first 40 sites:")
for i, (ea, tag) in enumerate(cdsv_class[:40]):
    r = backtrack_xmm(ea, "xmm3", 80)
    fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
    W(f"   RVA{rva(ea):#x} via={tag} val={r[0] if r else '?'}  fn RVA{fr:#x}")

# ---------- Q1B: CreateDSS ----------
def backtrack_lea_rdx(call_ea, limit=100):
    cur = call_ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR: return None
        m = idc.print_insn_mnem(cur).lower()
        if m != "lea": continue
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != "rdx": continue
        in2 = idautils.DecodeInstruction(cur)
        if not in2: continue
        op1 = in2.ops[1]
        if op1.type == idaapi.o_mem: return ("mem", op1.addr, cur)
        if op1.type == idaapi.o_displ: return ("stack", op1.addr, cur)
    return None

D3D_CMP = {1:"NEVER",2:"LESS",3:"EQUAL",4:"LESS_EQUAL",5:"GREATER",6:"NOT_EQUAL",7:"GREATER_EQUAL",8:"ALWAYS"}
W("\n" + "="*72); W("Q1B: CreateDepthStencilState DepthFunc values"); W("="*72)
cds_sites = slot_sites[0xA0]
cds_class = classify_sites(cds_sites)
W(f"  total sites: {len(cds_sites)}")
dev_sites = [ea for ea, t in cds_class if t == "device"]
W(f"  device-global-sourced sites: {len(dev_sites)}")

df_freq = {}
df_freq_dev = {}
stack_cnt = 0
dev_stack_cnt = 0
samples = []
for ea, tag in cds_class:
    info = backtrack_lea_rdx(ea, 120)
    if not info: continue
    kind, addr, _ = info
    if kind == "stack":
        stack_cnt += 1
        if tag == "device": dev_stack_cnt += 1
        continue
    de = idc.get_wide_dword(addr) or 0
    dm = idc.get_wide_dword(addr+4) or 0
    df = idc.get_wide_dword(addr+8) or 0
    se = idc.get_wide_dword(addr+12) or 0
    df_freq[df] = df_freq.get(df, 0) + 1
    if tag == "device":
        df_freq_dev[df] = df_freq_dev.get(df, 0) + 1
    samples.append((ea, tag, addr, de, dm, df, se))
W(f"  stack-desc total: {stack_cnt}   (device-global: {dev_stack_cnt})")
W(f"  DepthFunc distribution (ALL sites): {df_freq}")
W(f"  DepthFunc distribution (device-global ONLY): {df_freq_dev}")
for d in sorted(df_freq.keys()):
    W(f"    {d}/{D3D_CMP.get(d,'?')}: all={df_freq.get(d,0)} device={df_freq_dev.get(d,0)}")
W("  first 40 samples:")
for s in samples[:40]:
    ea, tag, addr, de, dm, df, se = s
    fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
    W(f"   RVA{rva(ea):#x} via={tag} desc@{addr:#x} En={de} Mask={dm} Func={df}({D3D_CMP.get(df,'?')}) StEn={se}  fn RVA{fr:#x}")

# ---------- Q4: CreateTexture2D ----------
DXGI = {0:"UNKNOWN",2:"R32G32B32A32_FLOAT",10:"R16G16B16A16_FLOAT",19:"D32_FLOAT_S8X24",20:"R32_FLOAT_X8X24_TYPELESS",
        39:"R32_TYPELESS",40:"D32_FLOAT",41:"R32_FLOAT",
        44:"R24G8_TYPELESS",45:"D24_UNORM_S8_UINT",46:"R24_UNORM_X8_TYPELESS",
        55:"R16_TYPELESS",56:"D16_UNORM",57:"R16_UNORM"}
W("\n" + "="*72); W("Q4: CreateTexture2D DSV-bound formats"); W("="*72)
ct_sites = slot_sites[0x28]
ct_class = classify_sites(ct_sites)
W(f"  total sites: {len(ct_sites)}")
dev_ct = [ea for ea, t in ct_class if t == "device"]
W(f"  device-global-sourced: {len(dev_ct)}")
tex_rows = []
stack_cnt = 0
dev_stack_cnt = 0
for ea, tag in ct_class:
    info = backtrack_lea_rdx(ea, 120)
    if not info: continue
    kind, addr, _ = info
    if kind == "stack":
        stack_cnt += 1
        if tag == "device": dev_stack_cnt += 1
        continue
    w = idc.get_wide_dword(addr) or 0
    h = idc.get_wide_dword(addr+4) or 0
    mips = idc.get_wide_dword(addr+8) or 0
    arr = idc.get_wide_dword(addr+0xC) or 0
    fmt = idc.get_wide_dword(addr+0x10) or 0
    samp = idc.get_wide_dword(addr+0x14) or 0
    usage = idc.get_wide_dword(addr+0x1C) or 0
    bind = idc.get_wide_dword(addr+0x20) or 0
    tex_rows.append((ea, tag, addr, w, h, mips, arr, fmt, samp, usage, bind))
dsv_rows = [r for r in tex_rows if (r[10] & 0x40)]
W(f"  stack-desc: {stack_cnt} (device: {dev_stack_cnt})")
W(f"  mem-desc total: {len(tex_rows)}  ; with BIND_DSV: {len(dsv_rows)}")
fmt_freq = {}
for r in dsv_rows:
    fmt_freq[r[7]] = fmt_freq.get(r[7], 0) + 1
W(f"  format freq: {fmt_freq}")
for r in dsv_rows[:30]:
    ea, tag, addr, w, h, m, a, fmt, samp, usage, bind = r
    fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
    W(f"   RVA{rva(ea):#x} via={tag} desc@{addr:#x} {w}x{h} mips={m} arr={a} fmt={fmt}({DXGI.get(fmt,'?')}) samp={samp} usage={usage} bind={bind:#x}  fn RVA{fr:#x}")

# Top stack-desc Tex2D callers (THIS is typically where the MAIN scene depth is made)
W("\n  stack-desc Tex2D callers (likely the main depth buffer creator):")
stk_fn = {}
for ea, tag in ct_class:
    info = backtrack_lea_rdx(ea, 120)
    if info and info[0] == "stack":
        fn = idaapi.get_func(ea)
        if fn: stk_fn[fn.start_ea] = stk_fn.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(stk_fn.items(), key=lambda kv:-kv[1])[:20]:
    W(f"    RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

# ---------- Q2: OMSet ----------
W("\n" + "="*72); W("Q2: OMSetRenderTargets callers"); W("="*72)
oms_sites = slot_sites[0x108]
oms_class = classify_sites(oms_sites)
W(f"  total sites: {len(oms_sites)}")
ctx_oms = [ea for ea, t in oms_class if t in ("ctx_A", "ctx_B")]
W(f"  ctx-global-sourced: {len(ctx_oms)}")
cc = {}
for ea, tag in oms_class:
    fn = idaapi.get_func(ea)
    if fn: cc[fn.start_ea] = cc.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(cc.items(), key=lambda kv:-kv[1])[:30]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

# ---------- Q2 extra: CreateDepthStencilView callers ----------
W("\n" + "="*72); W("Q2 extra: CreateDepthStencilView"); W("="*72)
cdv_sites = slot_sites[0x48]
cdv_class = classify_sites(cdv_sites)
W(f"  total sites: {len(cdv_sites)}")
dev_cdv = [ea for ea, t in cdv_class if t == "device"]
W(f"  device-sourced: {len(dev_cdv)}")
cc = {}
for ea, tag in cdv_class:
    fn = idaapi.get_func(ea)
    if fn: cc[fn.start_ea] = cc.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(cc.items(), key=lambda kv:-kv[1])[:20]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
W(f"Report: {OUT}")
idc.qexit(0)
