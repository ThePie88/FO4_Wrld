"""Depth RE v9 - properly trace `mov reg, [global]; mov rax, [reg]; call [rax+disp]`.

Also widen search: for each 'mov reg, [ctx_global]', track vtable=mov rax,[reg]
then scan for 'call qword ptr [rax+disp]'. The disp is the vtable method.
"""
import idaapi, idautils, idc, ida_funcs, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report9.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

CTX_A  = 0x1438CAA90
CTX_B  = 0x1438CAAB8
DEVICE = 0x1438CAAA8

W(f"[*] imagebase = {imagebase:#x}")

SLOTS = {
    0x108: "OMSetRenderTargets",
    0x110: "OMSetRenderTargetsAndUAV",
    0x118: "OMSetBlendState",
    0x120: "OMSetDepthStencilState",
    0x190: "ClearRenderTargetView",
    0x198: "ClearUAV_Uint",
    0x1A0: "ClearUAV_Float",
    0x1A8: "ClearDepthStencilView",
    0x1B0: "GenerateMips",
    # Device slots
    0x28:  "Device::CreateTexture2D",
    0x48:  "Device::CreateDepthStencilView",
    0xA0:  "Device::CreateDepthStencilState",
}

def find_calls_from_global_read(read_ea, held_reg, max_insns=40):
    """Starting at `mov held_reg, [global]`, walk forward looking for
    'mov rax, [held_reg]; call [rax+disp]'. Return list of (call_ea, disp).
    Also follow moves of held_reg to other regs.
    """
    tracked = {held_reg}  # registers that hold the context pointer
    vtable_regs = set()   # registers that hold vtable pointer
    out = []
    cur = read_ea
    for step in range(max_insns):
        cur = idc.next_head(cur, idaapi.BADADDR)
        if cur == idaapi.BADADDR: break
        insn = idautils.DecodeInstruction(cur)
        if not insn: continue
        m = idc.print_insn_mnem(cur).lower()
        op0 = insn.ops[0]

        # Indirect call via vtable reg
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi):
            if op0.type == idaapi.o_displ:
                opstr = idc.print_operand(cur, 0).lower()
                disp = op0.addr & 0xFFFFFFFFFFFFFFFF
                if disp > 0x7FFFFFFFFFFFFFFF: disp -= 0x10000000000000000
                # Check whether base reg is vtable-reg
                for vr in vtable_regs:
                    if vr in opstr:
                        out.append((cur, disp))
                        break
            # Return? After a call, rax is clobbered, so drop it from both sets
            tracked.discard("rax"); vtable_regs.discard("rax")
            continue

        # mov reg, [other_reg] - could be vtable load if src is context pointer
        if m in ("mov", "mov"):
            op1 = insn.ops[1]
            dst_str = idc.print_operand(cur, 0).lower()
            # mov reg, [tracked_reg]  → reg becomes vtable reg
            if op0.type == idaapi.o_reg and op1.type in (idaapi.o_phrase, idaapi.o_displ):
                src_str = idc.print_operand(cur, 1).lower()
                # phrase: [rcx]; displ: [rcx+N]
                for tr in list(tracked):
                    if src_str == f"[{tr}]" or src_str == f"qword ptr [{tr}]":
                        # This is the vtable load
                        vtable_regs.add(dst_str)
                        # dst may have been tracked as context; remove
                        tracked.discard(dst_str)
                        break
                else:
                    # not vtable load — if dst overwrites tracked/vtable, drop
                    if dst_str in tracked: tracked.discard(dst_str)
                    if dst_str in vtable_regs: vtable_regs.discard(dst_str)
            # mov reg, another_reg (where src is tracked) → copy tracking
            elif op0.type == idaapi.o_reg and op1.type == idaapi.o_reg:
                src_str = idc.print_operand(cur, 1).lower()
                if src_str in tracked:
                    tracked.add(dst_str)
                elif src_str in vtable_regs:
                    vtable_regs.add(dst_str)
                else:
                    if dst_str in tracked: tracked.discard(dst_str)
                    if dst_str in vtable_regs: vtable_regs.discard(dst_str)
            else:
                # other kinds of mov - if dst overwrites tracked/vtable regs, drop
                if op0.type == idaapi.o_reg:
                    if dst_str in tracked: tracked.discard(dst_str)
                    if dst_str in vtable_regs: vtable_regs.discard(dst_str)
        else:
            # any instruction that writes to tracked/vtable reg invalidates it
            if op0.type == idaapi.o_reg:
                dst_str = idc.print_operand(cur, 0).lower()
                if dst_str in tracked: tracked.discard(dst_str)
                if dst_str in vtable_regs: vtable_regs.discard(dst_str)

        # Stop if both sets empty
        if not tracked and not vtable_regs:
            break
    return out

# Enumerate reads of each global
def collect_reads(glob):
    hits = []
    for xr in idautils.XrefsTo(glob):
        ea = xr.frm
        m = idc.print_insn_mnem(ea).lower()
        if m != "mov": continue
        op0_str = idc.print_operand(ea, 0).lower()
        # Only reads where dst is a register (not memory)
        insn = idautils.DecodeInstruction(ea)
        if not insn: continue
        if insn.ops[0].type == idaapi.o_reg and insn.ops[1].type == idaapi.o_mem:
            hits.append((ea, op0_str))
    return hits

ctx_reads = collect_reads(CTX_A) + collect_reads(CTX_B)
device_reads = collect_reads(DEVICE)
W(f"[*] context global reads: {len(ctx_reads)}  device global reads: {len(device_reads)}")

# Walk from each
collected = {s: [] for s in SLOTS}
for ea, reg in ctx_reads:
    calls = find_calls_from_global_read(ea, reg, 50)
    for call_ea, disp in calls:
        if disp in SLOTS:
            collected[disp].append((call_ea, "ctx"))

for ea, reg in device_reads:
    calls = find_calls_from_global_read(ea, reg, 50)
    for call_ea, disp in calls:
        if disp in SLOTS:
            collected[disp].append((call_ea, "dev"))

W("\n[*] Direct D3D11 call counts through BSGraphics globals by slot:")
for s, lst in sorted(collected.items()):
    W(f"   disp={s:#x} ({SLOTS[s]}): {len(lst)} calls")

# ---------------- Q1A: ClearDepthStencilView ----------------
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

W("\n" + "="*72); W("Q1A: ClearDepthStencilView depth clear values"); W("="*72)
slot_clear = collected[0x1A8]
W(f"  total direct calls: {len(slot_clear)}")
freq = {}
for call_ea, _ in slot_clear:
    r = backtrack_xmm(call_ea, "xmm3", 60)
    v = r[0] if r else None
    k = f"{v:.6f}" if isinstance(v, float) else "unknown"
    freq[k] = freq.get(k, 0) + 1
W(f"  depth-clear-value freq: {freq}")
for i, (call_ea, _) in enumerate(slot_clear[:40]):
    r = backtrack_xmm(call_ea, "xmm3", 60)
    fn = idaapi.get_func(call_ea)
    fr = rva(fn.start_ea) if fn else 0
    vs = f"{r[0]}" if (r and isinstance(r[0], float)) else "?"
    W(f"   RVA{rva(call_ea):#x} val={vs}  caller=RVA{fr:#x}")

# ---------------- Q1B: CreateDepthStencilState ----------------
def backtrack_lea_rdx(call_ea, limit=80):
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
slot_dss = collected[0xA0]
W(f"  total direct calls: {len(slot_dss)}")
df_freq = {}
samples = []
stack_cnt = 0
for call_ea, _ in slot_dss:
    info = backtrack_lea_rdx(call_ea, 100)
    if not info:
        samples.append((call_ea, "norel", 0, None, None, None, None))
        continue
    kind, addr, _ = info
    if kind == "stack":
        stack_cnt += 1
        samples.append((call_ea, "stack", addr, None, None, None, None))
        continue
    de = idc.get_wide_dword(addr) or 0
    dm = idc.get_wide_dword(addr+4) or 0
    df = idc.get_wide_dword(addr+8) or 0
    se = idc.get_wide_dword(addr+12) or 0
    df_freq[df] = df_freq.get(df, 0) + 1
    samples.append((call_ea, "mem", addr, de, dm, df, se))
W(f"  stack-desc: {stack_cnt}")
W(f"  DepthFunc distribution (static descs):")
for k, c in sorted(df_freq.items(), key=lambda kv:-kv[1]):
    W(f"    {k}/{D3D_CMP.get(k,'?')} x {c}")
W("  first 40 samples:")
for s in samples[:40]:
    ea = s[0]
    fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
    if s[1] == "stack":
        W(f"   RVA{rva(ea):#x} stack@{s[2]:#x}  caller RVA{fr:#x}")
    elif s[1] == "mem":
        _, _, addr, de, dm, df, se = s
        W(f"   RVA{rva(ea):#x} desc@{addr:#x} En={de} Mask={dm} Func={df}({D3D_CMP.get(df,'?')}) StEn={se}  caller RVA{fr:#x}")
    else:
        W(f"   RVA{rva(ea):#x} norel  caller RVA{fr:#x}")

# ---------------- Q4: CreateTexture2D ----------------
DXGI = {0:"UNKNOWN",2:"R32G32B32A32_FLOAT",10:"R16G16B16A16_FLOAT",19:"D32_FLOAT_S8X24",20:"R32_FLOAT_X8X24_TYPELESS",
        39:"R32_TYPELESS",40:"D32_FLOAT",41:"R32_FLOAT",
        44:"R24G8_TYPELESS",45:"D24_UNORM_S8_UINT",46:"R24_UNORM_X8_TYPELESS",
        55:"R16_TYPELESS",56:"D16_UNORM",57:"R16_UNORM"}

W("\n" + "="*72); W("Q4: CreateTexture2D DSV-bound formats"); W("="*72)
slot_tex = collected[0x28]
W(f"  total direct CreateTexture2D calls: {len(slot_tex)}")
tex_rows = []
stack_cnt = 0
for call_ea, _ in slot_tex:
    info = backtrack_lea_rdx(call_ea, 100)
    if not info: continue
    kind, addr, _ = info
    if kind == "stack":
        stack_cnt += 1; continue
    w = idc.get_wide_dword(addr) or 0
    h = idc.get_wide_dword(addr+4) or 0
    mips = idc.get_wide_dword(addr+8) or 0
    arr = idc.get_wide_dword(addr+0xC) or 0
    fmt = idc.get_wide_dword(addr+0x10) or 0
    samp = idc.get_wide_dword(addr+0x14) or 0
    usage = idc.get_wide_dword(addr+0x1C) or 0
    bind = idc.get_wide_dword(addr+0x20) or 0
    tex_rows.append((call_ea, addr, w, h, mips, arr, fmt, samp, usage, bind))
dsv_rows = [r for r in tex_rows if (r[9] & 0x40)]
W(f"  stack-desc: {stack_cnt}   mem-desc: {len(tex_rows)}")
W(f"  mem-desc with BIND_DEPTH_STENCIL: {len(dsv_rows)}")
fmt_freq = {}
for _, _, w, h, m, a, fmt, _, _, _ in dsv_rows:
    fmt_freq[fmt] = fmt_freq.get(fmt, 0) + 1
W(f"  format freq: {[(DXGI.get(f,f'fmt{f}'), c) for f, c in fmt_freq.items()]}")
for r in dsv_rows[:30]:
    ea, addr, w, h, m, a, fmt, samp, usage, bind = r
    fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
    W(f"   RVA{rva(ea):#x} desc@{addr:#x} {w}x{h} mips={m} arr={a} fmt={fmt}({DXGI.get(fmt,'?')}) samp={samp} usage={usage} bind={bind:#x}  caller RVA{fr:#x}")

# Also: for stack-desc tex calls, locate callers
W("  stack-desc Tex2D top callers:")
stk_callers = {}
for call_ea, _ in slot_tex:
    info = backtrack_lea_rdx(call_ea, 100)
    if info and info[0] == "stack":
        fn = idaapi.get_func(call_ea)
        if fn: stk_callers[fn.start_ea] = stk_callers.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(stk_callers.items(), key=lambda kv:-kv[1])[:15]:
    W(f"    RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

# ---------------- Q2: OMSet ----------------
W("\n" + "="*72); W("Q2: OMSetRenderTargets callers"); W("="*72)
slot_oms = collected[0x108]
W(f"  total direct calls: {len(slot_oms)}")
caller_counts = {}
for ea, _ in slot_oms:
    fn = idaapi.get_func(ea)
    if fn: caller_counts[fn.start_ea] = caller_counts.get(fn.start_ea, 0) + 1
W(f"  unique callers: {len(caller_counts)}")
for fn_ea, c in sorted(caller_counts.items(), key=lambda kv:-kv[1])[:30]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

# Q2 extra: CreateDepthStencilView
W("\n" + "="*72); W("Q2 extra: CreateDepthStencilView callers"); W("="*72)
slot_dsv = collected[0x48]
W(f"  total direct calls: {len(slot_dsv)}")
dcallers = {}
for ea, _ in slot_dsv:
    fn = idaapi.get_func(ea)
    if fn: dcallers[fn.start_ea] = dcallers.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(dcallers.items(), key=lambda kv:-kv[1])[:20]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")
for ea, _ in slot_dsv[:20]:
    fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
    W(f"   site RVA{rva(ea):#x} in fn RVA{fr:#x}")

# OMSetDepthStencilState too
W("\n" + "="*72); W("Extra: OMSetDepthStencilState callers (for DSS usage freq)"); W("="*72)
slot_dss_set = collected[0x120]
W(f"  total direct calls: {len(slot_dss_set)}")
cc = {}
for ea, _ in slot_dss_set:
    fn = idaapi.get_func(ea)
    if fn: cc[fn.start_ea] = cc.get(fn.start_ea, 0) + 1
for fn_ea, c in sorted(cc.items(), key=lambda kv:-kv[1])[:20]:
    W(f"   RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)}) x{c}")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
idc.qexit(0)
