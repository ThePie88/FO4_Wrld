"""
realvp 6th pass - verify:
  - a2 = BSShaderAccumulator? Check by finding xrefs from
    BSShaderAccumulator::vtable @ RVA 0x290A6B0 to locate instances
  - Find producer side: who writes accumulator +0x17C ?
  - Verify qword_143E5AC90 is just SRV slots (not accumulator pointer)
"""
import idaapi, idc, ida_hexrays, ida_funcs, ida_bytes, ida_xref, ida_name
import ida_ua, ida_ida, idautils

IMG = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\realvp_main6.txt"
f = open(OUT, "w", encoding="utf-8")
def w(s=""): f.write(s + "\n")

def decompile(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc) if cfunc else None
    except Exception:
        return None

def func_size(ea):
    fn = ida_funcs.get_func(ea)
    return fn.end_ea - fn.start_ea if fn else 0


# ---- A. BSShaderAccumulator instance size and offset 0x17C ----
w("="*80)
w("PART A :: BSShaderAccumulator - instance size / what is at +0x17C")
w("="*80)
# xrefs TO BSShaderAccumulator vtable
BSSA_VT = IMG + 0x290A6B0
xrefs = list(idautils.XrefsTo(BSSA_VT, 0))
w("xrefs to BSShaderAccumulator vtable @ 0x%X: %d" % (BSSA_VT, len(xrefs)))
for x in xrefs[:15]:
    fn = ida_funcs.get_func(x.frm)
    fn_s = fn.start_ea if fn else 0
    w("  %X in fn 0x%X : %s" % (x.frm, fn_s, idc.GetDisasm(x.frm)))

# Look at the ctor — typically the first xref
ctor_candidates = set()
for x in xrefs:
    fn = ida_funcs.get_func(x.frm)
    if fn and func_size(fn.start_ea) < 0x2000:
        ctor_candidates.add(fn.start_ea)

# Look for allocation with size — find sub_1416579C0 call preceding vftable install
# scan: lea rax,[rip+BSSA_VT]; mov [reg],rax  — reg is the instance
# then within ~80 insns before, sub_1416579C0(, size, ...).
w("\n-- BSShaderAccumulator ctor candidates (fn with vtable install) --")
for c in sorted(ctor_candidates):
    w("  fn 0x%X size=0x%X" % (c, func_size(c)))

# Decomp ctor-like functions
for c in list(ctor_candidates)[:3]:
    w("\n-- decomp 0x%X --" % c)
    d = decompile(c)
    if d:
        for line in d.splitlines()[:80]:
            w("  " + line)

# ---- B. WRITERS to +0x17C (+380 bytes) in functions that xref BSShaderAccumulator vt ----
w("\n" + "="*80)
w("PART B :: Writers to +0x17C (+0x18C,+0x19C,+0x1AC) — the VP matrix source")
w("="*80)

MAT_OFFS = (0x17C, 0x18C, 0x19C, 0x1AC)
candidates = []
for fn_ea in idautils.Functions():
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    cur = fn.start_ea
    hit_offs = set()
    samples = {}
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps"):
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_displ and op1t == idc.o_reg:
                disp = idc.get_operand_value(cur, 0)
                if disp in MAT_OFFS:
                    hit_offs.add(disp)
                    samples[disp] = cur
        cur = idc.next_head(cur, fn.end_ea)
    if len(hit_offs) >= 3:
        candidates.append((fn_ea, hit_offs, samples))

candidates.sort(key=lambda t: -len(t[1]))
w("fns writing >=3 of (0x17C,0x18C,0x19C,0x1AC): %d" % len(candidates))
for (fn_ea, offs, samples) in candidates[:20]:
    w("  fn 0x%X  size=0x%X  offsets=%s" %
      (fn_ea, func_size(fn_ea), sorted(offs)))
    for off in sorted(samples.keys()):
        w("    %X  +0x%X" % (samples[off], off))

# decomp top 3
w("\n-- decomp top 3 --")
for (fn_ea, offs, _) in candidates[:3]:
    w("\n" + "="*60)
    w("== fn 0x%X ==" % fn_ea)
    w("="*60)
    d = decompile(fn_ea)
    if d:
        for line in d.splitlines()[:120]:
            w("  " + line)


# ---- C. Global BSShaderAccumulator pointer? Find where it's stored ----
w("\n" + "="*80)
w("PART C :: Global BSShaderAccumulator pointer?")
w("="*80)
# Scan for ` mov [rip+disp], rax ` right after a call that ends with BSShaderAccumulator ctor.
# Candidates to check: the mgmt globals qword_143E5AC90..0xACB0
# and also qword_143E4B7F0..0xB828
# Scan xrefs to those for writes that store a pointer.
interesting_globals = [
    0x143E5AC90, 0x143E5AC98, 0x143E5ACA0, 0x143E5ACA8, 0x143E5ACB0,
    0x143E4B7F0, 0x143E4B818, 0x143E4B7F8, 0x143E4B800,
    0x143E4B850, 0x143E4B868, 0x1430EB7A0, 0x1430EB7A8,
]
for g in interesting_globals:
    w("\n-- global 0x%X --" % g)
    # what's the init value? (just read)
    val = idc.get_qword(g)
    w("  runtime-init 0x%X" % val)
    # xrefs (samples)
    count = 0
    seen_fn = set()
    for x in idautils.XrefsTo(g, 0):
        ins = idc.GetDisasm(x.frm)
        fn = ida_funcs.get_func(x.frm)
        fn_s = fn.start_ea if fn else 0
        if fn_s in seen_fn: continue
        seen_fn.add(fn_s)
        # care only about writes
        if f"mov     cs:qword_{g:X}" in ins or f"mov     qword_{g:X}" in ins:
            w("  WRITE: %X in fn 0x%X : %s" % (x.frm, fn_s, ins))
            count += 1
        if count > 5: break

# ---- D. sub_14221E6A0: What is a2?  ----
# If a2 is an instance of class X, its vtable is *a2.
# Find where sub_14221E6A0 is CALLED and get the a2 argument.
# This was failing in part B (no callers). Maybe it's indirect vtable dispatch.
# Search all indirect calls via vtable that resolve to 0x14221E6A0.

w("\n" + "="*80)
w("PART D :: Find callers of sub_14221E6A0 - through vtable dispatches")
w("="*80)
# scan all vtables in .rdata for the entry 0x14221E6A0
import ida_segment
seg = ida_segment.get_segm_by_name(".rdata")
if seg:
    start, end = seg.start_ea, seg.end_ea
    w(".rdata: 0x%X..0x%X  size %d" % (start, end, end-start))
    hits = []
    for addr in range(start, end - 8, 8):
        if idc.get_qword(addr) == 0x14221E6A0:
            hits.append(addr)
    w("vtable slots that reference sub_14221E6A0: %d" % len(hits))
    for addr in hits[:10]:
        # find vtable start by walking backwards for valid vtable entries
        vtbl_start = addr
        for off in range(0, 0x200, 8):
            tgt = idc.get_qword(vtbl_start - 8)
            if tgt and (IMG <= tgt < IMG + 0x10000000):
                vtbl_start -= 8
            else:
                break
        slot_idx = (addr - vtbl_start) // 8
        w("  vtbl @ 0x%X  slot[%d] = sub_14221E6A0" % (vtbl_start, slot_idx))

# Also: what is BSShaderAccumulator vt[+504/8=63] doing? Called at line 945 in the decomp.
w("\n-- BSShaderAccumulator vt slot 63 (0x290A6B0 + 63*8 = 0x290A8A8) --")
slot_ea = BSSA_VT + 63*8
tgt = idc.get_qword(slot_ea)
if IMG <= tgt < IMG + 0x10000000:
    w("  -> 0x%X (RVA 0x%X) size=0x%X" % (tgt, tgt - IMG, func_size(tgt)))
    d = decompile(tgt)
    if d:
        for line in d.splitlines()[:30]:
            w("  " + line)

# Finally: what is BSShaderAccumulator size?  Look for sub_1416579C0 call with
# sizeof right before BSShaderAccumulator vt install.
w("\n-- scan for sub_1416579C0(X, SIZE, ...) immediately before BSShaderAccum vt install --")
for x in xrefs[:30]:
    fn = ida_funcs.get_func(x.frm)
    if fn is None: continue
    cur = fn.start_ea
    last_size = None
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        # edx is the size arg; look at 'mov edx, immed'
        if mnem == "mov" and idc.print_operand(cur, 0) == "edx":
            v = idc.get_operand_value(cur, 1)
            if v and v < 0x10000 and v > 0x40:
                last_size = (v, cur)
        if cur == x.frm:
            if last_size:
                w("  ctor fn 0x%X: vt @ %X preceded by size=%d (0x%X)" %
                  (fn.start_ea, x.frm, last_size[0], last_size[0]))
            break
        cur = idc.next_head(cur, fn.end_ea)

f.close()
print("done")
idaapi.qexit(0)
