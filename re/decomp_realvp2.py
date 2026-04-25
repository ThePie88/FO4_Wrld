"""
realvp 2nd pass — fix RVAs and focus on:
  - REAL CB_Map_A (0x21A0680) / CB_Map_B (0x21A05E0) callers
  - sub_1416D20B0 (claimed view-matrix updater called from NiCamera ctor)
  - Who writes qword_1432D2260+0xD0/+0xE0/+0xF0/+0x100 (4-row matrix)
  - MainCullingCamera full vtable (up to slot 160 to cover +1112/+1120)
  - qword_1432D2260 +296 (0x128) is a view struct per sub_140C38F80 code
"""
import idaapi, idc, ida_hexrays, ida_funcs, ida_bytes, ida_xref, ida_name
import ida_ua, ida_ida, idautils

IMG = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\realvp_main2.txt"
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


# ---- 1. Correct CB_Map_A/B helpers -----
w("="*80)
w("PART 1 :: CB_Map_A @ 0x1421A0680 / CB_Map_B @ 0x1421A05E0")
w("="*80)
for name, rva in (("CB_Map_A", 0x21A0680), ("CB_Map_B", 0x21A05E0)):
    ea = IMG + rva
    sz = func_size(ea)
    w("\n-- %s @ 0x%X  size=0x%X --" % (name, ea, sz))
    d = decompile(ea)
    if d:
        for line in d.splitlines(): w("  " + line)

# ---- 2. All callers of CB_Map_A — count XMM stores per caller ----
w("\n" + "="*80)
w("PART 2 :: CB_Map_A (0x21A0680) callers — rank by XMM stores")
w("="*80)
cb_map_a_ea = IMG + 0x21A0680
callers = set()
for xref in idautils.XrefsTo(cb_map_a_ea, 0):
    fn = ida_funcs.get_func(xref.frm)
    if fn: callers.add(fn.start_ea)
w("caller count: %d" % len(callers))

def count_xmm_stores(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None: return (0, 0)
    cur = fn.start_ea
    cnt, cons, maxc = 0, 0, 0
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps", "movdqu", "movdqa"):
            op0t = idc.get_operand_type(cur, 0)
            if op0t in (idc.o_displ, idc.o_phrase, idc.o_mem):
                cnt += 1; cons += 1
                if cons > maxc: maxc = cons
            else:
                cons = 0
        else:
            cons = 0
        cur = idc.next_head(cur, fn.end_ea)
    return (cnt, maxc)

ranked = []
for c in sorted(callers):
    cnt, mx = count_xmm_stores(c)
    ranked.append((c, cnt, mx))
ranked.sort(key=lambda t: -t[1])
for (c, cnt, mx) in ranked[:30]:
    w("  fn 0x%X  xmm=%d max_consecutive=%d  size=0x%X" % (c, cnt, mx, func_size(c)))

# decomp top 10 matrix-writer callers
w("\n-- DECOMP of top 10 matrix-writer callers --")
for (c, cnt, mx) in ranked[:10]:
    if cnt < 4: break
    w("\n" + "="*60)
    w("== fn 0x%X  xmm_stores=%d  max_consec=%d ==" % (c, cnt, mx))
    w("="*60)
    d = decompile(c)
    if d:
        # snapshot - first 80 lines
        lines = d.splitlines()
        for line in lines[:120]:
            w("  " + line)
        if len(lines) > 120:
            w("  ... [%d more lines] ..." % (len(lines)-120))


# ---- 3. sub_1416D20B0 (claimed "writes the view matrix every tick") ----
w("\n" + "="*80)
w("PART 3 :: sub_1416D20B0 (NiCamera vt? view-matrix updater, claimed in sub_1416D0510)")
w("="*80)
ea = IMG + 0x16D20B0
w("size=0x%X" % func_size(ea))
d = decompile(ea)
if d:
    for line in d.splitlines(): w("  " + line)

# ---- 4. qword_1432D2260 writers at +0xD0/+0xE0/+0xF0/+0x100 — detailed ----
w("\n" + "="*80)
w("PART 4 :: Writers to +0xD0/+0xE0/+0xF0/+0x100 in functions that xref qword_1432D2260")
w("   (find the ONE function that writes all 4 rows - that's the VP setter)")
w("="*80)

sing_ea = 0x1432D2260
xref_fns = set()
for xref in idautils.XrefsTo(sing_ea, 0):
    fn = ida_funcs.get_func(xref.frm)
    if fn: xref_fns.add(fn.start_ea)
w("functions that reference qword_1432D2260: %d" % len(xref_fns))

# Find functions that write to ALL of +D0, +E0, +F0, +100 in a short span
TARGET_OFFS = (0xD0, 0xE0, 0xF0, 0x100)
matrix_writer_fns = []
for fn_ea in xref_fns:
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    writes = {off: [] for off in TARGET_OFFS}
    cur = fn.start_ea
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps"):
            disp = idc.get_operand_value(cur, 0)
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_displ and op1t == idc.o_reg and disp in TARGET_OFFS:
                writes[disp].append(cur)
        cur = idc.next_head(cur, fn.end_ea)
    hits = sum(1 for off, sites in writes.items() if sites)
    if hits >= 3:  # writes to at least 3 of the 4 rows
        matrix_writer_fns.append((fn_ea, hits, writes))

matrix_writer_fns.sort(key=lambda t: -t[1])
w("functions that write >=3 of (D0,E0,F0,100): %d" % len(matrix_writer_fns))
for (fn_ea, hits, writes) in matrix_writer_fns[:30]:
    w("  fn 0x%X  hits=%d  size=0x%X" % (fn_ea, hits, func_size(fn_ea)))
    for off in TARGET_OFFS:
        for s in writes[off]:
            w("     +0x%X at 0x%X" % (off, s))

# decomp top 5
w("\n-- decomp top 5 matrix-writer fns --")
for (fn_ea, hits, _) in matrix_writer_fns[:5]:
    w("\n"+"="*60)
    w("== fn 0x%X (hits %d) ==" % (fn_ea, hits))
    w("="*60)
    d = decompile(fn_ea)
    if d:
        lines = d.splitlines()
        for line in lines[:200]:
            w("  " + line)
        if len(lines) > 200:
            w("  ... [%d more] ..." % (len(lines)-200))


# ---- 5. MainCullingCamera vtable up to slot 160 ----
w("\n" + "="*80)
w("PART 5 :: MainCullingCamera vtable slots 0..160 (qword_1432D2260 vt)")
w("  target slot +1112 = 1112/8 = 139")
w("="*80)
# But wait - qword_1432D2260 may not even have MainCullingCamera vt.
# It's accessed via **(__int64 **)(qword_1432D2260 + 1112LL)) so the vtable
# is at *qword_1432D2260, and slot 1112 is byte offset 1112.  We need to
# get *qword_1432D2260 at static-init time to figure out its vtable.
#
# Since we can't run the binary, let's find what ctor writes to
# qword_1432D2260.  Search for 'mov [rip+_], rax' near qword_1432D2260.

sing_ea = 0x1432D2260
# search for writers to the singleton
ctor_sites = []
for xref in idautils.XrefsTo(sing_ea, 0):
    insn = idc.GetDisasm(xref.frm)
    if "mov" in insn.lower() and (" cs:qword_1432D2260" in insn or " qword_1432D2260" in insn or "qword_1432D2260," in insn):
        # is this a write (singleton is destination)?
        if "qword_1432D2260," not in insn:
            ctor_sites.append((xref.frm, insn))

w("writers (mov [rip+..., rax]) to qword_1432D2260:")
for (ea, s) in ctor_sites[:20]:
    fn = ida_funcs.get_func(ea)
    fn_start = fn.start_ea if fn else 0
    w("  %X in fn %X : %s" % (ea, fn_start, s))

# print MainCullingCamera vt entries up to slot 160 by raw qword reads
VTBL = IMG + 0x255DB08
w("\nMainCullingCamera vtable at 0x%X - slots 0..160:" % VTBL)
for i in range(0, 160):
    slot_ea = VTBL + i * 8
    tgt = idc.get_qword(slot_ea)
    # only print non-zero and that look like function EAs (within image)
    if tgt and (IMG <= tgt < IMG + 0x10000000):
        w("  [%3d] +0x%X -> 0x%X (RVA 0x%X)" % (i, i*8, tgt, tgt - IMG))

# Decompile slot 139 if valid
slot139_tgt = idc.get_qword(VTBL + 139*8)
w("\nslot 139 target: 0x%X" % slot139_tgt)
if slot139_tgt and IMG <= slot139_tgt < IMG + 0x10000000:
    d = decompile(slot139_tgt)
    if d:
        for line in d.splitlines()[:20]:
            w("  " + line)


# ---- 6. Who calls sub_1416D20B0 ? ----
w("\n" + "="*80)
w("PART 6 :: callers of sub_1416D20B0 (view-matrix updater)")
w("="*80)
v_upd = IMG + 0x16D20B0
callers_vupd = set()
for xref in idautils.XrefsTo(v_upd, 0):
    fn = ida_funcs.get_func(xref.frm)
    if fn: callers_vupd.add(fn.start_ea)
w("callers: %d" % len(callers_vupd))
for c in sorted(callers_vupd):
    w("  fn 0x%X  size=0x%X" % (c, func_size(c)))


# ---- 7. Check +0xD0..+0x110 bytewise - the "OWORD" writes like
# *(_OWORD *)(qword_1432D2260 + 208) = ...  in sub_140C38F80.
# The 'sub_141E285B0(qword_1432D2260 + 296, v45, v6)' at line 139 is interesting.
w("\n" + "="*80)
w("PART 7 :: sub_141E285B0 (called with qword_1432D2260+296 in sub_140C38F80)")
w("="*80)
ea = IMG + 0x1E285B0
w("size=0x%X" % func_size(ea))
d = decompile(ea)
if d:
    lines = d.splitlines()
    for line in lines[:120]: w("  " + line)
    if len(lines) > 120:
        w("  ... [%d more] ..." % (len(lines)-120))

f.close()
print("done")
idaapi.qexit(0)
