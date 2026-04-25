"""
realvp 3rd pass - the critical final dig.
  - qword_1432D2260 is NOT MainCullingCamera (slot 139 purecall)
  - Find its actual class by decompiling the init-time writer
  - Decompile the key matrix writers: sub_140DDDA70, sub_141031910,
    sub_1407FAAC0 cleanly
  - Also decompile sub_14223F110 (the MAIN CB_Map_A user with 116 stores)
    in a modest window around line 300..900 to find the ViewProj copy
"""
import idaapi, idc, ida_hexrays, ida_funcs, ida_bytes, ida_xref, ida_name
import ida_ua, ida_ida, idautils

IMG = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\realvp_main3.txt"
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

# ---- 1. find the class vtable of qword_1432D2260 ---
# Writers to the singleton.  Hunt for the ctor that installs a vtable.
# We need to find "mov qword_1432D2260, rax" THEN look at rax's origin - it's a
# constructed object with an installed vtable.
w("="*80)
w("PART A :: REAL ctor / class of qword_1432D2260")
w("="*80)

sing_ea = 0x1432D2260

# Use idautils to get writes TO the singleton (o_mem, write class)
# Look at xrefs with flags for "write"
writers = []
for x in idautils.XrefsTo(sing_ea, 0):
    t = x.type
    # in IDA: dr_W = 3 (data write), dr_R=2
    if t == 3 or ("qword_1432D2260," in idc.GetDisasm(x.frm) or "mov     cs:qword_1432D2260" in idc.GetDisasm(x.frm)):
        writers.append(x.frm)

# From last run we see 14023BB16 in fn 14023B9C0. Let's decomp that.
for ea_guess in (0x14023B9C0, 0x140222E80, 0x140223380):
    w("\n-- decomp 0x%X --" % ea_guess)
    d = decompile(ea_guess)
    if d:
        lines = d.splitlines()
        for line in lines[:80]: w("  " + line)
        if len(lines) > 80: w("  ... [%d more]" % (len(lines)-80))

# xref where "mov cs:qword_1432D2260, rax" happens:
w("\n-- ALL disasm near references 'qword_1432D2260' with 'mov' as writes --")
seen_fns = set()
for x in idautils.XrefsTo(sing_ea, 0):
    ins = idc.GetDisasm(x.frm)
    if "mov" in ins.lower() and "qword_1432D2260" in ins:
        # Is destination the singleton?
        if "mov     cs:qword_1432D2260," in ins or "mov     qword_1432D2260," in ins:
            fn = ida_funcs.get_func(x.frm)
            fn_s = fn.start_ea if fn else 0
            if fn_s in seen_fns: continue
            seen_fns.add(fn_s)
            w("  write @ %X (in fn %X): %s" % (x.frm, fn_s, ins))
            # decomp
            d = decompile(fn_s)
            if d:
                # print only the relevant 30 lines
                for line in d.splitlines()[:40]:
                    w("    " + line)
                w("    ---")

# Also: check a dword nearby at qword_1432D2260 to see its initial contents
w("\n-- raw bytes at qword_1432D2260 in the .data section --")
for off in (0, 8, 16, 24, 32):
    v = idc.get_qword(sing_ea + off)
    w("  +%d: 0x%X" % (off, v))

# ---- 2. key matrix-writer decompiles ----
w("\n" + "="*80)
w("PART B :: Full decomp of compact matrix writers at +D0/E0/F0/100")
w("="*80)

# from realvp_main2: top 'clean small' ones with hits=4
for name, ea in (
    ("sub_140DDDA70 (0x36B)",   0x140DDDA70),
    ("sub_1405BCB70 (0x475)",   0x1405BCB70),
    ("sub_140E63DB0 (0xBB9)",   0x140E63DB0),
    ("sub_141031910 (0xA05)",   0x141031910),
):
    w("\n-- %s --" % name)
    d = decompile(ea)
    if d:
        lines = d.splitlines()
        for line in lines[:250]:
            w("  " + line)
        if len(lines) > 250:
            w("  ... [%d more]" % (len(lines)-250))

# ---- 3. Scan for matrix-writer fns that ALSO call CB_Map_A ---
# This is THE function set we care about - writes matrix to +D0/E0/F0/100 AND calls CB_Map_A
w("\n" + "="*80)
w("PART C :: Writers that ALSO call CB_Map_A (= matrix is copied to GPU CB)")
w("="*80)

cb_map_a = IMG + 0x21A0680
cb_map_a_callers = set()
for x in idautils.XrefsTo(cb_map_a, 0):
    fn = ida_funcs.get_func(x.frm)
    if fn: cb_map_a_callers.add(fn.start_ea)

matrix_writer_fns = set()
TARGET_OFFS = (0xD0, 0xE0, 0xF0, 0x100)
sing_xref_fns = set()
for xref in idautils.XrefsTo(sing_ea, 0):
    fn = ida_funcs.get_func(xref.frm)
    if fn: sing_xref_fns.add(fn.start_ea)

for fn_ea in sing_xref_fns:
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    writes_hit = {off: False for off in TARGET_OFFS}
    cur = fn.start_ea
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps"):
            disp = idc.get_operand_value(cur, 0)
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_displ and op1t == idc.o_reg and disp in TARGET_OFFS:
                writes_hit[disp] = True
        cur = idc.next_head(cur, fn.end_ea)
    if sum(writes_hit.values()) >= 3:
        matrix_writer_fns.add(fn_ea)

intersection = matrix_writer_fns & cb_map_a_callers
w("matrix writers AND CB_Map_A callers: %d" % len(intersection))
for fn_ea in sorted(intersection):
    w("  fn 0x%X size=0x%X" % (fn_ea, func_size(fn_ea)))

# ---- 4. sub_1416D2500 (the other caller of sub_1416D20B0) ----
w("\n" + "="*80)
w("PART D :: sub_1416D2500 (the 2nd caller of sub_1416D20B0)")
w("="*80)
d = decompile(0x1416D2500)
if d:
    for line in d.splitlines()[:80]: w("  " + line)

# ---- 5. What writes to MEMORY offset +288..+332 (NiCamera world-to-view) ----
# Callers of sub_1416D20B0 tell us WHO touches the NiCamera view matrix.
# Now: who calls these callers, chained up to the render loop?
w("\n" + "="*80)
w("PART E :: callers of sub_1416D0510 (NiCamera ctor that calls sub_1416D20B0)")
w("="*80)
c = 0
for x in idautils.XrefsTo(0x1416D0510, 0):
    fn = ida_funcs.get_func(x.frm)
    if fn:
        w("  call @ 0x%X  from fn 0x%X size=0x%X" % (x.frm, fn.start_ea, func_size(fn.start_ea)))
        c += 1
        if c > 30: break

# ---- 6. sub_1421F2930 is a GETTER not setter - and returns qword_143E4B968
# Who writes qword_143E4B968?  It's stored FROM and READ FROM in the setter list
w("\n" + "="*80)
w("PART F :: qword_143E4B968 writers (sub_1421F2930 returns this)")
w("   Also scan +0xC0 bytes BEFORE this address: block of RenderGlobals")
w("="*80)

for off in range(0, 0xD0, 8):
    a = 0x143E4B8F8 + off  # the setters wrote 143E4B8F8..143E4B8D8
    # just dump bytes at that location in the .data segment
    try:
        val = idc.get_qword(a)
        w("  [0x%X]  = 0x%X" % (a, val))
    except:
        pass

w("\n-- xrefs TO qword_143E4B968 --")
count = 0
for x in idautils.XrefsTo(0x143E4B968, 0):
    ins = idc.GetDisasm(x.frm)
    fn = ida_funcs.get_func(x.frm)
    fn_s = fn.start_ea if fn else 0
    w("  %X in fn 0x%X : %s" % (x.frm, fn_s, ins))
    count += 1
    if count > 20: break

# ---- 7. also: sub_14223F110 (the MAIN 116-store CB_Map_A caller) — likely SetupGeometry
w("\n" + "="*80)
w("PART G :: sub_14223F110 (BSLightingShader::SetupGeometry? 116 XMM stores)")
w("  Find where ViewProj matrix gets copied in")
w("="*80)
d = decompile(0x14223F110)
if d:
    lines = d.splitlines()
    # only lines 280..420 - the middle where matrix copies happen
    out_from = 200
    out_to = 450
    for i, line in enumerate(lines):
        if out_from <= i <= out_to:
            w("  [%d] %s" % (i, line))
    w("  ... (total %d lines)" % len(lines))

f.close()
print("done")
idaapi.qexit(0)
