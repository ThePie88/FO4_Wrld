"""
realvp: decompile the ~20 RenderGlobals setters called by sub_140C38910
and identify the matrix (64-byte) writer(s).  Also decompile:
  - PlayerCamera::Update (sub_1410262F0)
  - CB_Map_A / CB_Map_B (already known, refetch)
  - Top CB_Map_A callers to find which one copies the VP matrix

Writes   C:/Users/filip/Desktop/FalloutWorld/re/realvp_main.txt
"""
import idaapi, idc, ida_hexrays, ida_funcs, ida_bytes, ida_xref, ida_name
import ida_ua, ida_ida, idautils

IMG = 0x140000000

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\realvp_main.txt"
f = open(OUT, "w", encoding="utf-8")
def w(s=""): f.write(s + "\n")

w("image base 0x%X" % IMG)

# -- 20 setters called by sub_140C38910.
#    RVAs derived from render_pipeline_report4.txt.
SETTER_RVAS = [
    0x21F2EA0, 0x21F2970, 0x21F2A60, 0x21F2A80, 0x21F29A0, 0x21F29B0, 0x21F29C0,
    0x21F29F0, 0x21F2A00, 0x21F2A10, 0x21F2A50, 0x21F2A70, 0x21F2A90, 0x21F2AA0,
    0x21F2AB0, 0x21F2AC0, 0x21F2AE0, 0x21F2AF0, 0x21F2B00, 0x21F2B10, 0x21F2B20,
    0x21F2B30, 0x21F2B40, 0x21F2B50, 0x21F2B60, 0x21F2B70, 0x21F2B80, 0x21F2B90,
    0x21F2BA0, 0x21F2BB0, 0x21F2BC0, 0x21F2BD0, 0x21F2BE0, 0x21F2BF0, 0x21F2C00,
    0x21F2C10, 0x21F2C20, 0x21F2C30, 0x21F2C40, 0x21F2C50, 0x21F2C80,
    0x21F2930,
]

def decompile(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return None
        return str(cfunc)
    except Exception as e:
        return None

def func_size(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return 0
    return fn.end_ea - fn.start_ea

# also get disasm to eyeball store sizes
def disasm_all(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return "<no func>"
    out = []
    cur = fn.start_ea
    while cur < fn.end_ea:
        ins = idc.GetDisasm(cur)
        out.append("  %X  %s" % (cur, ins))
        cur = idc.next_head(cur, fn.end_ea)
    return "\n".join(out)


# --- 1: Setters ---
w("="*80)
w("PART 1 :: RenderGlobals SETTERS called by sub_140C38910")
w("="*80)

for rva in SETTER_RVAS:
    ea = IMG + rva
    sz = func_size(ea)
    w("")
    w("==== setter sub_%X (RVA 0x%X)  size=0x%X ====" % (ea, rva, sz))
    # print the full disasm first (setters are tiny)
    w(disasm_all(ea))
    w("----")
    d = decompile(ea)
    if d:
        for line in d.splitlines():
            w("  " + line)
    else:
        w("  <decompile failed>")

# --- 2: PlayerCamera::Update sub_1410262F0 ---
w("")
w("="*80)
w("PART 2 :: PlayerCamera::Update  sub_1410262F0")
w("="*80)
ea = IMG + 0x10262F0
sz = func_size(ea)
w("size=0x%X" % sz)
d = decompile(ea)
if d:
    for line in d.splitlines():
        w("  " + line)
else:
    w("  <decompile failed>")

# --- 3: CB_Map_A / CB_Map_B ---
w("")
w("="*80)
w("PART 3 :: CB_Map_A / CB_Map_B (re-confirm & find wrappers)")
w("="*80)

for name, rva in (("CB_Map_A", 0x1A0680), ("CB_Map_B", 0x1A05E0)):
    ea = IMG + rva
    w("")
    w("-- %s @ 0x%X  size=0x%X --" % (name, ea, func_size(ea)))
    d = decompile(ea)
    if d:
        for line in d.splitlines():
            w("  " + line)

# --- 4: ALL CB_Map_A callers, count + filter any that write 0xC0+ bytes ---
w("")
w("="*80)
w("PART 4 :: CB_Map_A callers that WRITE a 4x4 matrix (64+ contiguous bytes)")
w("="*80)

cb_map_a_ea = IMG + 0x1A0680
callers = set()
for xref in idautils.XrefsTo(cb_map_a_ea, 0):
    fn = ida_funcs.get_func(xref.frm)
    if fn:
        callers.add(fn.start_ea)
w("caller count: %d" % len(callers))

# for each caller: scan disasm for sequences of XMM stores to CB-return-buffer
# (the pattern is:   movups xmm0, [src];  movups [rbx+disp], xmm0  )
# Count XMM stores per caller; >=4 consecutive == 4x4 matrix likely.
matrix_callers = []

def count_xmm_stores(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return 0
    cur = fn.start_ea
    cnt = 0
    max_consecutive = 0
    cons = 0
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps", "movdqu", "movdqa"):
            # is the operand 0 a memory write?
            op0t = idc.get_operand_type(cur, 0)
            if op0t in (idc.o_displ, idc.o_phrase, idc.o_mem):
                cnt += 1
                cons += 1
                if cons > max_consecutive:
                    max_consecutive = cons
            else:
                cons = 0
        else:
            # allow small non-xmm ops between
            if mnem not in ("mov", "lea", "test", "jz", "jnz", "cmp"):
                cons = 0
        cur = idc.next_head(cur, fn.end_ea)
    return cnt, max_consecutive

for c in sorted(callers):
    xmmcnt, maxcon = count_xmm_stores(c)
    if xmmcnt >= 4:
        matrix_callers.append((c, xmmcnt, maxcon))

matrix_callers.sort(key=lambda t: -t[1])
w("")
w("callers with >=4 XMM stores (likely matrix writers):")
for (c, cnt, con) in matrix_callers:
    w("  fn 0x%X  xmm_stores=%d max_consecutive=%d  size=0x%X" %
      (c, cnt, con, func_size(c)))

# decomp top 6 matrix callers
w("")
w("DECOMP of top 6 matrix-writing callers:")
for (c, cnt, con) in matrix_callers[:6]:
    w("")
    w("="*70)
    w("== caller 0x%X  xmm_stores=%d ==" % (c, cnt))
    w("="*70)
    d = decompile(c)
    if d:
        for line in d.splitlines():
            w("  " + line)


# --- 5: sub_140C38910 full decompile for reference ---
w("")
w("="*80)
w("PART 5 :: sub_140C38910 full decompile (reference)")
w("="*80)
ea = IMG + 0xC38910
d = decompile(ea)
if d:
    for line in d.splitlines():
        w("  " + line)

# --- 6: also find the 1112LL vtable call accessor for MainCullingCamera ---
w("")
w("="*80)
w("PART 6 :: qword_1432D2260 = MainCullingCamera singleton; vt[1112/8=139] GetCurrentState")
w("="*80)

# vtable RVA 0x255DB08  (from main_culling_camera_report.txt)
VTBL = IMG + 0x255DB08
slot_idx = 1112 // 8
slot_ea = VTBL + slot_idx * 8
tgt = idc.get_qword(slot_ea)
w("MainCullingCamera vtable RVA 0x255DB08 slot[%d] @ 0x%X -> 0x%X (RVA 0x%X)" %
  (slot_idx, slot_ea, tgt, tgt - IMG))
w("")
w("-- decomp of vt[1112] (GetCurrentState-like accessor) --")
d = decompile(tgt)
if d:
    for line in d.splitlines():
        w("  " + line)
else:
    w(disasm_all(tgt))

# what does *(qword_1432D2260+208) contain? find writers of [rcx+208] on
# MainCullingCamera. For this, scan .text for `mov*ps [reg+0D0h]` inside
# functions that also reference qword_1432D2260.
w("")
w("="*80)
w("PART 7 :: writers to offset +208 (0xD0) of MainCullingCamera")
w("         (the `*(__m128*)(qword_1432D2260 + 208)` in sub_140C38F80 + sub_140C32D30)")
w("="*80)
# Also offset +296 (0x128) appears in camera_report.
# xrefs of the singleton:
sing_ea = 0x1432D2260
w("MainCullingCamera singleton @ 0x%X" % sing_ea)
xref_sites = []
for xref in idautils.XrefsTo(sing_ea, 0):
    xref_sites.append(xref.frm)
w("xrefs: %d" % len(xref_sites))

# find writers to +0xD0 and +0x128 inside the exec segment
# scan for pattern: movups xmmword ptr [rbx/rcx/rsi/rdi+0xD0], xmm?
# Restrict this scan to functions that also xref qword_1432D2260.
# First collect those functions once.
xref_fns = set()
for xref in idautils.XrefsTo(sing_ea, 0):
    fn = ida_funcs.get_func(xref.frm)
    if fn:
        xref_fns.add(fn.start_ea)
w("functions that reference qword_1432D2260: %d" % len(xref_fns))

for target_off in (0xD0, 0xE0, 0xF0, 0x100, 0x128, 0x138, 0x148, 0x158):
    hits = 0
    sample = []
    for fn_ea in xref_fns:
        fn = ida_funcs.get_func(fn_ea)
        if fn is None: continue
        cur = fn.start_ea
        end = fn.end_ea
        matched = False
        while cur < end:
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("movups", "movaps"):
                disp = idc.get_operand_value(cur, 0)
                op0t = idc.get_operand_type(cur, 0)
                if op0t == idc.o_displ and disp == target_off:
                    op1t = idc.get_operand_type(cur, 1)
                    if op1t == idc.o_reg:
                        hits += 1
                        if len(sample) < 15:
                            sample.append((cur, fn_ea))
                        matched = True
                        break
            cur = idc.next_head(cur, end)
    w("  +0x%X: %d writer functions" % (target_off, hits))
    for (ea2, fn2) in sample:
        w("     %X in fn %X" % (ea2, fn2))

f.close()
print("done")
idaapi.qexit(0)
