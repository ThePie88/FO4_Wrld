"""Depth RE v7 - find calls through the D3D11 context/device globals.

Device  global: 0x1438CAAA8 (qword_1438CAAA8 in IDA)
Context global: 0x1438CAA90 (qword_1438CAA90) and 0x1438CAAB8 (qword_1438CAAB8)

Strategy:
 1. Find xrefs to these three globals (reads).
 2. For each read (typically 'mov rax, cs:global'), walk forward to find the
    next call [rax+disp] with disp matching our slots.
 3. For each such site, backtrack xmm3 (if ClearDSV) for clear value, etc.
"""
import idaapi, idautils, idc, ida_funcs, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report7.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase
W(f"[*] imagebase = {imagebase:#x}")

DEVICE_GLOBAL  = 0x1438CAAA8
CTX_GLOBAL_A   = 0x1438CAA90
CTX_GLOBAL_B   = 0x1438CAAB8
# Also we can check qword_1432D2260 is player singleton; qword_1438CAAA0 is BSGraphics state.

# Slots of interest
SLOTS = {
    # Context methods
    0x108: ("OMSetRenderTargets", "ctx"),
    0x110: ("OMSetRenderTargetsAndUnorderedAccessViews", "ctx"),
    0x120: ("OMSetDepthStencilState", "ctx"),
    0x1A0: ("ClearRenderTargetView", "ctx"),
    0x1A8: ("ClearDepthStencilView", "ctx"),
    0x1B0: ("ClearUnorderedAccessViewUint", "ctx"),
    # Device methods
    0x28:  ("CreateTexture2D", "device"),
    0x48:  ("CreateDepthStencilView", "device"),
    0x50:  ("CreateShaderResourceView (maybe)", "device"),
    0xA0:  ("CreateDepthStencilState", "device"),
}

# Collect xrefs to globals
def collect_reads(global_ea):
    """Return list of (ea, dest_reg) where instruction reads from global."""
    hits = []
    for xr in idautils.XrefsTo(global_ea):
        ea = xr.frm
        insn = idautils.DecodeInstruction(ea)
        if not insn: continue
        m = idc.print_insn_mnem(ea).lower()
        if m != "mov":  # filter only to `mov reg, global`
            continue
        op0 = insn.ops[0]
        if op0.type != idaapi.o_reg: continue
        dst_reg = idc.print_operand(ea, 0).lower()
        hits.append((ea, dst_reg))
    return hits

device_reads = collect_reads(DEVICE_GLOBAL)
ctx_a_reads = collect_reads(CTX_GLOBAL_A)
ctx_b_reads = collect_reads(CTX_GLOBAL_B)
W(f"[*] mov-from-global counts: device={len(device_reads)} ctxA={len(ctx_a_reads)} ctxB={len(ctx_b_reads)}")

def walk_forward_for_indirect_call(start_ea, reg, max_insns=30):
    """Walk forward from start_ea until we find call qword ptr [reg+disp] or
    until reg is overwritten. Return list of (call_ea, disp) encountered."""
    out = []
    reg = reg.lower()
    cur = start_ea
    # Skip past the original mov
    cur = idc.next_head(cur, idaapi.BADADDR)
    for _ in range(max_insns):
        if cur == idaapi.BADADDR: break
        insn = idautils.DecodeInstruction(cur)
        if not insn:
            cur = idc.next_head(cur, idaapi.BADADDR)
            continue
        # Check if reg is written to (overwritten)
        m = idc.print_insn_mnem(cur).lower()
        op0 = insn.ops[0]
        # handle call
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi):
            if op0.type == idaapi.o_displ:
                # Check if base register matches
                base = idc.print_operand(cur, 0).lower()
                # Operand string is like "qword ptr [rax+1A8h]"
                if reg in base:
                    disp = op0.addr & 0xFFFFFFFFFFFFFFFF
                    if disp > 0x7FFFFFFFFFFFFFFF: disp -= 0x10000000000000000
                    out.append((cur, disp))
                    # After call, rax typically holds return value so continue but reg likely dead
                    if reg == "rax":
                        return out  # rax is almost surely clobbered
        # Check if reg is overwritten (not through call since we catch above)
        if op0.type == idaapi.o_reg:
            dst = idc.print_operand(cur, 0).lower()
            if dst == reg:
                return out
        cur = idc.next_head(cur, idaapi.BADADDR)
    return out

# For each context read, find subsequent indirect calls
def as_float(val):
    try: return struct.unpack("<f", struct.pack("<I", val & 0xFFFFFFFF))[0]
    except: return None

def backtrack_xmm(call_ea, xmm_name, limit=60):
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

def backtrack_lea_rdx(call_ea, limit=60):
    """Find last `lea rdx, [addr]` before call, return (kind, addr)."""
    cur = call_ea
    for _ in range(limit):
        cur = idc.prev_head(cur)
        if cur == idaapi.BADADDR: return None
        m = idc.print_insn_mnem(cur).lower()
        op0 = idc.print_operand(cur, 0).lower()
        if op0 != "rdx" or m != "lea": continue
        in2 = idautils.DecodeInstruction(cur)
        if not in2: continue
        op1 = in2.ops[1]
        if op1.type == idaapi.o_mem: return ("mem", op1.addr, cur)
        if op1.type == idaapi.o_displ: return ("stack", op1.addr, cur)
    return None

# Process context reads
print_ctr = {}
collected = {s: [] for s in SLOTS}

for reads, label in ((ctx_a_reads, "ctxA"), (ctx_b_reads, "ctxB")):
    for ea, reg in reads:
        calls = walk_forward_for_indirect_call(ea, reg, 40)
        for call_ea, disp in calls:
            if disp in SLOTS:
                collected[disp].append((call_ea, label))

for reads, label in ((device_reads, "device"),):
    for ea, reg in reads:
        calls = walk_forward_for_indirect_call(ea, reg, 40)
        for call_ea, disp in calls:
            if disp in SLOTS:
                collected[disp].append((call_ea, label))

W("\n[*] Call counts through BSGraphics globals by slot:")
for s, lst in collected.items():
    W(f"   disp={s:#x} ({SLOTS[s][0]}): {len(lst)} calls via {SLOTS[s][1]} global")

# ---------------- Q1A: ClearDepthStencilView depth values ----------------
W("\n" + "="*72)
W("Q1A: ClearDepthStencilView (slot 0x1A8) — depth clear values")
W("="*72)
slot_clear = collected[0x1A8]
W(f"  total confirmed-through-ctx calls: {len(slot_clear)}")
freq = {}
for call_ea, lbl in slot_clear:
    r = backtrack_xmm(call_ea, "xmm3", 60)
    v = r[0] if r else None
    key = f"{v:.6f}" if isinstance(v, float) else "unknown"
    freq[key] = freq.get(key, 0) + 1
W(f"  depth-clear-value freq: {freq}")
for i, (call_ea, lbl) in enumerate(slot_clear[:40]):
    r = backtrack_xmm(call_ea, "xmm3", 60)
    v = r[0] if r else None
    fn = idaapi.get_func(call_ea)
    fr = rva(fn.start_ea) if fn else 0
    W(f"   ea=RVA{rva(call_ea):#x} via={lbl} val={v}  caller=RVA{fr:#x}  src={r[2] if r else '?'}")

# ---------------- Q1B: CreateDepthStencilState descs ----------------
W("\n" + "="*72)
W("Q1B: CreateDepthStencilState (slot 0xA0) — DepthFunc values")
W("="*72)
D3D_CMP = {1:"NEVER",2:"LESS",3:"EQUAL",4:"LESS_EQUAL",5:"GREATER",6:"NOT_EQUAL",7:"GREATER_EQUAL",8:"ALWAYS"}
slot_dss = collected[0xA0]
W(f"  total confirmed-through-device calls: {len(slot_dss)}")
df_freq = {}
samples = []
stack_cnt = 0
for call_ea, lbl in slot_dss:
    info = backtrack_lea_rdx(call_ea, 80)
    if not info:
        continue
    kind, addr, lea_ea = info
    if kind == "stack":
        stack_cnt += 1
        samples.append((call_ea, "stack", addr, None, None, None))
        continue
    de = idc.get_wide_dword(addr) or 0
    dm = idc.get_wide_dword(addr+4) or 0
    df = idc.get_wide_dword(addr+8) or 0
    se = idc.get_wide_dword(addr+12) or 0
    df_freq[df] = df_freq.get(df, 0) + 1
    samples.append((call_ea, "mem", addr, de, dm, df, se))
W(f"  stack-desc (dynamic): {stack_cnt}   mem-desc (static): {len(slot_dss) - stack_cnt}")
W(f"  DepthFunc freq (static descs):")
for k, c in sorted(df_freq.items(), key=lambda kv:-kv[1]):
    W(f"    {k}/{D3D_CMP.get(k,'?')} x {c}")
W("  first 50 samples:")
for s in samples[:50]:
    ea = s[0]
    if s[1] == "stack":
        W(f"   RVA{rva(ea):#x} desc=stack@{s[2]:#x}")
    else:
        _, kind, addr, de, dm, df, se = s
        fn = idaapi.get_func(ea)
        fr = rva(fn.start_ea) if fn else 0
        W(f"   RVA{rva(ea):#x} desc@{addr:#x} En={de} Mask={dm} Func={df}({D3D_CMP.get(df,'?')}) StEn={se}  caller RVA{fr:#x}")

# ---------------- Q4: CreateTexture2D DSV-bound ----------------
W("\n" + "="*72)
W("Q4: CreateTexture2D (slot 0x28) — DSV-bound formats")
W("="*72)
DXGI = {0:"UNKNOWN",19:"D32_FLOAT_S8X24",20:"R32_FLOAT_X8X24_TYPELESS",
        39:"R32_TYPELESS",40:"D32_FLOAT",41:"R32_FLOAT",
        44:"R24G8_TYPELESS",45:"D24_UNORM_S8_UINT",46:"R24_UNORM_X8_TYPELESS",
        55:"R16_TYPELESS",56:"D16_UNORM",57:"R16_UNORM"}

slot_tex = collected[0x28]
W(f"  total confirmed CreateTexture2D calls: {len(slot_tex)}")
tex_rows = []
stack_cnt = 0
for call_ea, lbl in slot_tex:
    info = backtrack_lea_rdx(call_ea, 100)
    if not info:
        continue
    kind, addr, lea_ea = info
    if kind == "stack":
        stack_cnt += 1
        continue
    w = idc.get_wide_dword(addr) or 0
    h = idc.get_wide_dword(addr+4) or 0
    mips = idc.get_wide_dword(addr+8) or 0
    arr = idc.get_wide_dword(addr+0xC) or 0
    fmt = idc.get_wide_dword(addr+0x10) or 0
    samp = idc.get_wide_dword(addr+0x14) or 0
    usage = idc.get_wide_dword(addr+0x1C) or 0
    bind = idc.get_wide_dword(addr+0x20) or 0
    tex_rows.append((call_ea, addr, w, h, mips, arr, fmt, samp, usage, bind))
W(f"  stack-desc: {stack_cnt}   mem-desc: {len(tex_rows)}")

dsv_rows = [r for r in tex_rows if (r[9] & 0x40)]
W(f"  mem-desc with BIND_DEPTH_STENCIL: {len(dsv_rows)}")
fmt_freq = {}
for _, _, w, h, m, a, fmt, _, _, _ in dsv_rows:
    fmt_freq[fmt] = fmt_freq.get(fmt, 0) + 1
W(f"  format distribution (mem-desc DSV): {fmt_freq}")
for r in dsv_rows[:30]:
    ea, addr, w, h, m, a, fmt, samp, usage, bind = r
    fn = idaapi.get_func(ea)
    fr = rva(fn.start_ea) if fn else 0
    W(f"   RVA{rva(ea):#x} desc@{addr:#x} {w}x{h} mips={m} arr={a} fmt={fmt}({DXGI.get(fmt,'?')}) samp={samp} usage={usage} bind={bind:#x}  caller RVA{fr:#x}")

# Also examine stack-desc calls: print what's at local stack slot (won't have static vals)
# But: many Tex2D descs are actually stack-filled then passed. We can't read vals.
# Show first few stack calls anyway to identify WHICH function is creating the main depth.
W("\n  stack-desc CreateTexture2D calls (top callers):")
stk_callers = {}
for call_ea, lbl in slot_tex:
    info = backtrack_lea_rdx(call_ea, 100)
    if info and info[0] == "stack":
        fn = idaapi.get_func(call_ea)
        if fn:
            stk_callers[fn.start_ea] = stk_callers.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(stk_callers.items(), key=lambda kv:-kv[1])[:20]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

# ---------------- Q2: OMSetRenderTargets callers ----------------
W("\n" + "="*72)
W("Q2: OMSetRenderTargets (slot 0x108) — caller functions")
W("="*72)
slot_oms = collected[0x108]
W(f"  total confirmed calls: {len(slot_oms)}")
caller_counts = {}
for call_ea, lbl in slot_oms:
    fn = idaapi.get_func(call_ea)
    if fn:
        caller_counts[fn.start_ea] = caller_counts.get(fn.start_ea, 0) + 1
W(f"  unique callers: {len(caller_counts)}")
for fn_ea, c in sorted(caller_counts.items(), key=lambda kv:-kv[1])[:30]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

# ---------------- Q2 extra: CreateDepthStencilView callers ----------------
W("\n" + "="*72)
W("Q2 extra: CreateDepthStencilView (slot 0x48) — callers")
W("="*72)
slot_dsv = collected[0x48]
W(f"  total calls: {len(slot_dsv)}")
callers = {}
for ea, lbl in slot_dsv:
    fn = idaapi.get_func(ea)
    if fn:
        callers[fn.start_ea] = callers.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(callers.items(), key=lambda kv:-kv[1])[:20]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")
for ea, lbl in slot_dsv[:20]:
    fn = idaapi.get_func(ea)
    fr = rva(fn.start_ea) if fn else 0
    W(f"   site RVA{rva(ea):#x} in fn RVA{fr:#x}")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
W(f"\nReport: {OUT}")
idc.qexit(0)
