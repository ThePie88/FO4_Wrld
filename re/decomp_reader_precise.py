"""
Narrowly find functions that load +0x120 from a base which is ALSO a
NiCamera instance. Restrict to functions that:
  (a) call NiCamera virtual methods OR reference NiCamera vtable
  (b) have 4 consecutive loads [base+0x120] [base+0x130] [base+0x140] [base+0x150] using same base reg
  (c) multiply with a Vec3/Vec4 world coord (look for mulss patterns following)
We'll narrowly match by:
  (i) 4 movss xmmN, [reg+0x120/130/140/150] within a 64-byte window
  (ii) the same reg
"""
import idaapi, idautils, idc, ida_funcs, ida_ua, ida_segment, ida_hexrays

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\reader_precise.txt"
IMG = 0x140000000
lines = []
def P(s=""): lines.append(str(s))
def rva(ea): return ea-IMG

seg_text = ida_segment.get_segm_by_name(".text")
t_start, t_end = seg_text.start_ea, seg_text.end_ea

# Build per-function list of [disp, ea, base_reg] reads
per_fn = {}  # fn_ea -> list of (ea, disp, base_reg)
for ea in idautils.Heads(t_start, t_end):
    if not idc.is_code(idc.get_full_flags(ea)): continue
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0: continue
    mn = insn.get_canon_mnem().lower()
    if mn not in ("movss", "movaps", "movups", "movsd"): continue
    op0 = insn.ops[0]; op1 = insn.ops[1]
    # Load (read): op0 = reg, op1 = o_displ
    if op0.type == ida_ua.o_reg and op1.type == ida_ua.o_displ:
        disp = op1.addr & 0xFFFFFFFF
        if disp in (0x120, 0x130, 0x140, 0x150):
            base_reg = op1.reg
            f = ida_funcs.get_func(ea)
            if f:
                per_fn.setdefault(f.start_ea, []).append((ea, disp, base_reg))

# Filter: functions that have all four rows, with the SAME base_reg,
# and the 4 reads are within 64 bytes of code of each other.
cands = []
for fn_ea, reads in per_fn.items():
    # group by base_reg
    by_reg = {}
    for ea, disp, reg in reads:
        by_reg.setdefault(reg, []).append((ea, disp))
    for reg, rs in by_reg.items():
        disps = {d for _, d in rs}
        if not {0x120, 0x130, 0x140, 0x150}.issubset(disps):
            continue
        # find a 4-row window
        rs_sorted = sorted(rs, key=lambda x: x[0])
        # sliding window of 4 that covers all 4 disps
        for i in range(len(rs_sorted) - 3):
            window = rs_sorted[i:i+8]
            ds = {d for _, d in window}
            if {0x120, 0x130, 0x140, 0x150}.issubset(ds):
                span = window[-1][0] - window[0][0]
                cands.append((fn_ea, reg, window[0][0], window[-1][0], span))
                break

P("precise reader candidates: %d" % len(cands))
# sort by span (tighter = more likely to be a matrix-vec mul)
cands.sort(key=lambda x: x[4])
seen_fns = set()
for fn_ea, reg, start, end, span in cands:
    if fn_ea in seen_fns: continue
    seen_fns.add(fn_ea)
    nm = ida_funcs.get_func_name(fn_ea) or ""
    P("  fn 0x%X (RVA 0x%X) reg=%d window 0x%X..0x%X span=%d %s" %
      (fn_ea, rva(fn_ea), reg, start, end, span, nm))

# decompile top 6 tightest candidates
P("\n=== DECOMPILE TOP 6 TIGHTEST READERS ===")
top6 = []
seen = set()
for fn_ea, reg, start, end, span in cands:
    if fn_ea in seen: continue
    seen.add(fn_ea)
    top6.append((fn_ea, start))
    if len(top6) == 6: break

for fn_ea, start in top6:
    P("-"*60)
    P("fn 0x%X (RVA 0x%X)  reads-at 0x%X" % (fn_ea, rva(fn_ea), start))
    try:
        d = str(ida_hexrays.decompile(fn_ea))
        for ln in d.splitlines()[:200]:
            P("  " + ln)
    except Exception:
        P("  <decomp fail>")
    P("")
    # also dump raw asm of reads plus following 16 insns
    P("Raw asm around read window:")
    cur = start
    n_insns = 0
    while cur < end + 0x100 and n_insns < 60:
        if not idc.is_code(idc.get_full_flags(cur)): break
        sz = idc.get_item_size(cur)
        if sz == 0: break
        d = idc.GetDisasm(cur)
        P("   0x%X  %s" % (cur, d))
        cur += sz
        n_insns += 1

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))
print("wrote", OUT)
idaapi.qexit(0)
