"""
realvp 5th pass - final answer.
Focus: sub_14221E6A0 writes to CB+0x40 and CB+0x80. Need to find
the SOURCE of those writes. The CB output = ViewProj matrix bonus.

Also: decompile caller chain of sub_14221E6A0 — who calls it?
Is it once per frame, per draw, or other cadence?
"""
import idaapi, idc, ida_hexrays, ida_funcs, ida_bytes, ida_xref, ida_name
import ida_ua, ida_ida, idautils

IMG = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\realvp_main5.txt"
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

# ---- A. Disasm sub_14221E6A0 around 14221EE4A and 14221EECA ----
# the +0x40 and +0x80 writes.
w("="*80)
w("PART A :: sub_14221E6A0 disasm around key CB writes")
w("="*80)

TARGETS = [0x14221EE4A, 0x14221EECA, 0x14221EED1, 0x14221EEF3, 0x14221EF33]
for t in TARGETS:
    w("\n-- window around 0x%X --" % t)
    cur = t - 0x60
    while cur < t + 0x40:
        ins = idc.GetDisasm(cur)
        marker = " <--" if cur == t else ""
        w("  %X  %s%s" % (cur, ins, marker))
        cur = idc.next_head(cur)

# ---- B. Callers of sub_14221E6A0 ----
w("\n" + "="*80)
w("PART B :: callers of sub_14221E6A0")
w("="*80)
for x in idautils.XrefsTo(0x14221E6A0, 0):
    fn = ida_funcs.get_func(x.frm)
    if fn:
        w("  call @ 0x%X from fn 0x%X  size=0x%X" % (x.frm, fn.start_ea, func_size(fn.start_ea)))

# ---- C. decompile sub_14221E6A0 body focus on lines 350..500 ---
w("\n" + "="*80)
w("PART C :: sub_14221E6A0 decomp - specific sections")
w("="*80)
d = decompile(0x14221E6A0)
if d:
    lines = d.splitlines()
    # lines with XMM/m128 or specific patterns
    for i, line in enumerate(lines):
        if 300 <= i <= 550:
            w("  [%d] %s" % (i, line))

# ---- D. Look at sub_140C38910 to find where ViewProj gets built ----
# maybe the matrix is computed on-the-fly rather than cached.
# The PROJ*VIEW multiply usually happens in BSShaderAccumulator.
# Search for functions that read NiCamera+288 (the 3x4 view mat we RE'd)
# AND write a 4x4 somewhere (VP composition).
w("\n" + "="*80)
w("PART D :: Look for functions that READ NiCamera+288/292/296...+332 (view mtx)")
w("   AND compute VP - candidates for the VP-matrix writer")
w("="*80)

# NiCamera vtable @ 0x14267DD50. NiCamera instances are pointed to by
# TESCameraState structs. To find WHERE VP gets composed: scan for
# functions with XMM loads from [reg + 0x120] (that's NiCamera+288).
read_count = {}
for fn_ea in idautils.Functions():
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    cur = fn.start_ea
    hits = []
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps"):
            # reading from [reg + disp] into xmm
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_reg and op1t == idc.o_displ:
                disp = idc.get_operand_value(cur, 1)
                if disp in (0x120, 0x130, 0x140, 0x150):
                    hits.append((cur, disp))
        cur = idc.next_head(cur, fn.end_ea)
    if len(hits) >= 3:
        read_count[fn_ea] = hits

w("functions that READ >= 3 XMM from [reg+0x120..0x150]: %d" % len(read_count))
for fn_ea, hits in sorted(read_count.items(), key=lambda t: -len(t[1]))[:20]:
    w("  fn 0x%X size=0x%X hits=%d" % (fn_ea, func_size(fn_ea), len(hits)))
    for (ea, disp) in hits[:6]:
        w("    %X  read +0x%X" % (ea, disp))

# ---- E. Now: who writes OFFSETS 0x120, 0x130, 0x140, 0x150 on some base
# (likely NiCamera or derived) ?
# In older work disp 0x120 had 0 writers. Let me broaden search:
# scan both o_displ AND o_mem, and larger offset range around +288..+332.
w("\n" + "="*80)
w("PART E :: writers to offsets +288..+332 (NiCamera view mat) via ANY insn")
w("="*80)
writer_counts = {}
for fn_ea in idautils.Functions():
    fn = ida_funcs.get_func(fn_ea)
    if fn is None: continue
    cur = fn.start_ea
    hits = {}
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("movups", "movaps", "movss"):
            op0t = idc.get_operand_type(cur, 0)
            op1t = idc.get_operand_type(cur, 1)
            if op0t == idc.o_displ and op1t == idc.o_reg:
                disp = idc.get_operand_value(cur, 0)
                if 0x120 <= disp <= 0x158 and disp % 4 == 0:
                    hits[disp] = hits.get(disp, 0) + 1
        cur = idc.next_head(cur, fn.end_ea)
    if len(hits) >= 4:
        writer_counts[fn_ea] = hits

w("fns writing to 4+ distinct offsets in +0x120..+0x158: %d" % len(writer_counts))
for fn_ea, hits in sorted(writer_counts.items(), key=lambda t: -sum(t[1].values()))[:15]:
    total = sum(hits.values())
    w("  fn 0x%X  total=%d  %s" % (fn_ea, total, dict(sorted(hits.items()))))

# ---- F. Quick lookup: the PlayerCharacter vtable slot 139 -> what is it?
# PlayerCharacter vtable's first entry RVA. Find via RTTI.
w("\n" + "="*80)
w("PART F :: PlayerCharacter vtable - slot 139 target (called in sub_140C38910)")
w("="*80)

# find 'PlayerCharacter::vftable'
PC_VTBL_EAS = []
for ea, name in idautils.Names():
    if "PlayerCharacter::`vftable'" in name or "PlayerCharacter@@6B" in name or \
       (".?AVPlayerCharacter@@" in name):
        PC_VTBL_EAS.append((ea, name))
for (ea, name) in PC_VTBL_EAS[:20]:
    w("  0x%X  %s" % (ea, name))

# The vtable addresses referenced in sub_140D52350:
# *(_QWORD *)a1 = &PlayerCharacter::`vftable';
# The actual VAs are what IDA resolves. Try to find them.
# scan sub_140D52350 for "lea rax, off_XXX" with sym containing 'PlayerCharacter'
fn = ida_funcs.get_func(0x140D52350)
if fn:
    cur = fn.start_ea
    addrs = set()
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem == "lea":
            op1 = idc.print_operand(cur, 1)
            if "PlayerCharacter" in op1 or "off_" in op1:
                addrs.add(idc.get_operand_value(cur, 1))
        cur = idc.next_head(cur, fn.end_ea)
    for a in sorted(addrs):
        # read first few slots
        for i in range(0, 10):
            tgt = idc.get_qword(a + i*8)
            if IMG <= tgt < IMG + 0x10000000:
                name = idc.get_name(tgt) or ("sub_%X" % tgt)
                w("  vtbl 0x%X slot[%d] = 0x%X %s" % (a, i, tgt, name))
            else:
                break

# specifically: the main vtable. After the first 10 slots we want slot 139.
# Let me try RVA 0x2A40000+ for PlayerCharacter vftable location from PDB-like names.
# Instead: sub_140D52350 first LEA is the primary vtable. Get it.
first_vtbl = None
if fn:
    cur = fn.start_ea
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem == "lea":
            op1n = idc.print_operand(cur, 1)
            if "vftable" in op1n or "off_14" in op1n:
                first_vtbl = idc.get_operand_value(cur, 1)
                break
        cur = idc.next_head(cur, fn.end_ea)
if first_vtbl:
    w("\nPrimary PlayerCharacter vtable @ 0x%X:" % first_vtbl)
    for i in range(130, 145):
        tgt = idc.get_qword(first_vtbl + i*8)
        if IMG <= tgt < IMG + 0x10000000:
            w("  [%d] +0x%X -> 0x%X (RVA 0x%X)" % (i, i*8, tgt, tgt - IMG))

    # Also decomp slot 139
    slot139 = idc.get_qword(first_vtbl + 139*8)
    w("\nSlot 139 target 0x%X decomp:" % slot139)
    d = decompile(slot139)
    if d:
        for line in d.splitlines()[:30]:
            w("  " + line)

# ---- G. Check what arg 'a2' is in sub_14221E6A0 — that's the BSShaderAccumulator
# since the vftable at [v166->m128_u64[0]+504] is called.
w("\n" + "="*80)
w("PART G :: sub_14221E6A0 arg a2 type hints")
w("="*80)
# Look at the first 80 lines of decomp
d = decompile(0x14221E6A0)
if d:
    for line in d.splitlines()[:80]:
        w("  " + line)

f.close()
print("done")
idaapi.qexit(0)
