"""
realvp 4th pass - narrow laser focus:
  - sub_14223F110 body middle section to find ViewProj copy into CB
  - sub_140C3E3C0 caller: what writes qword_1432D2260 - is it a Scene class?
    0xE10 = 3600 bytes allocation.
  - Check a2 (second arg) of sub_140D52350: ctor of what?
  - Walk PART G body more carefully
  - Also: FIND the *first* function that ALSO reads qword_1432D2260+208/+D0 (the VP)
    AND writes it to CB_Map_A output pointer - follow one level of indirection.
"""
import idaapi, idc, ida_hexrays, ida_funcs, ida_bytes, ida_xref, ida_name
import ida_ua, ida_ida, idautils

IMG = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\realvp_main4.txt"
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

# ---- A. sub_140D52350 (constructor of the object at qword_1432D2260) ----
w("="*80)
w("PART A :: sub_140D52350 (ctor of the 3600-byte obj at qword_1432D2260)")
w("="*80)
d = decompile(0x140D52350)
if d:
    lines = d.splitlines()
    for line in lines[:100]:
        w("  " + line)
    if len(lines) > 100:
        w("  ... [%d more]" % (len(lines)-100))

# ---- B. sub_14223F110 body  (find ViewProj copy) ----
w("\n" + "="*80)
w("PART B :: sub_14223F110 - lines 500..1000 of decomp (body where CB matrix writes happen)")
w("="*80)
d = decompile(0x14223F110)
if d:
    lines = d.splitlines()
    w("total lines: %d" % len(lines))
    # look for specific patterns
    keywords = ("+ 64", "+ 128", "0x80", "0x40", "0xC0", "+0x40", "+0x80",
                "ViewProj", "WorldView", "_mm_store", "memcpy", "m128",
                "[v4]", "[v5]", "[v6]", "[v7]", "+ 16*", "sub_1421A0680")
    hit_lines = set()
    for i, line in enumerate(lines):
        if any(k in line for k in keywords):
            for j in range(max(0, i-1), min(len(lines), i+2)):
                hit_lines.add(j)
    if hit_lines:
        prev = -2
        for i in sorted(hit_lines):
            if i > prev + 1:
                w("  ---")
            w("  [%d] %s" % (i, lines[i]))
            prev = i


# ---- C. Also do the same for sub_1421FDA30 (49 stores) and sub_14221E6A0 (47 stores)
# These are likely SetupTechnique-level functions that DO copy the VP matrix.
w("\n" + "="*80)
w("PART C :: sub_1421FDA30 (0x2738 bytes, 49 XMM stores) — ViewProj copy site?")
w("="*80)

d = decompile(0x1421FDA30)
if d:
    lines = d.splitlines()
    w("total lines: %d" % len(lines))
    # grep for mat copy
    keywords = ("sub_1421A0680", "sub_1421A05E0", "0x40", "*(_QWORD *)v",
                "memcpy", "m128", "VP", "ViewProj", "World", "Proj")
    hit_lines = set()
    for i, line in enumerate(lines):
        if any(k in line for k in keywords):
            for j in range(max(0, i-2), min(len(lines), i+3)):
                hit_lines.add(j)
    if hit_lines:
        prev = -2
        for i in sorted(hit_lines):
            if i > prev + 1:
                w("  ---")
            w("  [%d] %s" % (i, lines[i]))
            prev = i

# ---- D. sub_14221E6A0 (47 XMM stores, 0x1672 bytes) --
w("\n" + "="*80)
w("PART D :: sub_14221E6A0 (0x1672, 47 XMM stores)")
w("="*80)
d = decompile(0x14221E6A0)
if d:
    lines = d.splitlines()
    w("total lines: %d" % len(lines))
    # dump first 350 lines (usually covers ctor/setup) and any with matrix writes
    # First, summary
    keywords = ("sub_1421A0680", "+ 64", "+ 128", "memcpy", "m128",
                "Proj", "World", "View")
    hit_lines = set()
    for i, line in enumerate(lines):
        if any(k in line for k in keywords):
            for j in range(max(0, i-2), min(len(lines), i+3)):
                hit_lines.add(j)
    prev = -2
    for i in sorted(hit_lines):
        if i > prev + 1:
            w("  ---")
        w("  [%d] %s" % (i, lines[i]))
        prev = i

# ---- E. What writes [v4]=ptr+0x40 = first 64 bytes of CB output?
# CB_Map_A returns a ptr to a struct where *p = GPU buffer handle and p[1] = mapped GPU mem.
# The VS constant buffer BSDFPrePassShaderVertexConstants has WorldView@0x40 and ViewProj@0x80.
# So the callers writing [ptr+0x40], [ptr+0x80] are the VP setters.
# Let me find XMM stores to +0x40 and +0x80 inside CB_Map_A callers.
w("\n" + "="*80)
w("PART E :: CB_Map_A callers: XMM writes at +0x40 (WorldView) / +0x80 (ViewProj)")
w("="*80)

cb_map_a = IMG + 0x21A0680
cb_map_a_callers = set()
for x in idautils.XrefsTo(cb_map_a, 0):
    fn = ida_funcs.get_func(x.frm)
    if fn: cb_map_a_callers.add(fn.start_ea)

for fn_ea in sorted(cb_map_a_callers):
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    has_40 = has_80 = False
    sample = []
    cur = fn.start_ea
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps"):
            disp = idc.get_operand_value(cur, 0)
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_displ and op1t == idc.o_reg:
                if disp == 0x40:
                    has_40 = True; sample.append((cur, 0x40))
                elif disp == 0x80:
                    has_80 = True; sample.append((cur, 0x80))
                elif disp == 0x50 or disp == 0x90 or disp == 0x60 or disp == 0xA0 or disp == 0x70 or disp == 0xB0:
                    sample.append((cur, disp))
        cur = idc.next_head(cur, fn.end_ea)
    if has_40 and has_80:
        w("  FN 0x%X  size=0x%X  has +40 AND +80" % (fn_ea, func_size(fn_ea)))
        for (ea, off) in sample[:15]:
            w("    %X  +0x%X" % (ea, off))

# ---- F. Look for functions that copy ptr_src_matrix -> cb_dst with patterns:
# movups xmm0, [src+0x00] ; movups [dst+0x40], xmm0
# movups xmm0, [src+0x10] ; movups [dst+0x50], xmm0
# etc.  Look for such sequence loaders.
w("\n" + "="*80)
w("PART F :: Match 4-row matrix copy pattern inside CB_Map_A callers")
w("="*80)

for fn_ea in sorted(cb_map_a_callers):
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    cur = fn.start_ea
    # detect: movups xmmR, [base + 0x00]  immediately followed by movups [dst + 0x40], xmmR
    # track last movups load destination register
    last_xmm_load = None
    last_xmm_load_disp = None
    hits = []
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem == "movups" or mnem == "movaps":
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_reg and op1t == idc.o_displ:
                # load from mem -> xmm
                reg_name = idc.print_operand(cur, 0)
                last_xmm_load = reg_name
                last_xmm_load_disp = idc.get_operand_value(cur, 1)
            elif op0t == idc.o_displ and op1t == idc.o_reg:
                # store xmm -> mem
                dst_disp = idc.get_operand_value(cur, 0)
                store_reg = idc.print_operand(cur, 1)
                if last_xmm_load == store_reg and dst_disp in (0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0):
                    hits.append((cur, last_xmm_load_disp, dst_disp))
                last_xmm_load = None
                last_xmm_load_disp = None
            else:
                last_xmm_load = None
        cur = idc.next_head(cur, fn.end_ea)
    # does the function have at least 4 such row copies?
    if len(hits) >= 4:
        w("  FN 0x%X  size=0x%X  %d load-store pairs:" % (fn_ea, func_size(fn_ea), len(hits)))
        for (ea, src_disp, dst_disp) in hits[:16]:
            w("    %X  ld+0x%X -> st+0x%X" % (ea, src_disp, dst_disp))

# ---- G. Pivot: maybe the matrix is copied via memcpy/rep movsd - scan for that.
w("\n" + "="*80)
w("PART G :: Look for matrix blits via rep movsd/q or memcpy in CB_Map_A callers")
w("="*80)
for fn_ea in sorted(cb_map_a_callers):
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    cur = fn.start_ea
    memcpy_like = 0
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if "movs" in mnem and "movss" not in mnem:
            memcpy_like += 1
        cur = idc.next_head(cur, fn.end_ea)
    if memcpy_like:
        w("  FN 0x%X  rep-movs count=%d  size=0x%X" % (fn_ea, memcpy_like, func_size(fn_ea)))

# ---- H. Maybe the VP matrix is NOT copied through CB_Map_A at all.
# It's plausible the CB upload happens INSIDE the caller's assembly via intrinsics.
# Search xrefs TO qword_143E4B8F8 (first setter writes this, likely part of RenderGlobals)
w("\n" + "="*80)
w("PART H :: xrefs to qword_143E4B8F8 (dword_143E4B8F8 first render-globals float)")
w("  and to dword_143E4B958 (sub_1421F2C50's first float dest)")
w("="*80)
for a in (0x143E4B8F8, 0x143E4B958, 0x143E4B968, 0x143E4B818, 0x143E4B848, 0x143E4B860):
    w("\n-- xrefs to 0x%X --" % a)
    count = 0
    seen_fns = set()
    for x in idautils.XrefsTo(a, 0):
        ins = idc.GetDisasm(x.frm)
        fn = ida_funcs.get_func(x.frm)
        fn_s = fn.start_ea if fn else 0
        if fn_s in seen_fns: continue
        seen_fns.add(fn_s)
        w("  %X in fn 0x%X : %s" % (x.frm, fn_s, ins))
        count += 1
        if count > 15: break

f.close()
print("done")
idaapi.qexit(0)
