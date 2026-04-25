"""
Proper instruction-level scan for writers/readers of NiCamera+0x120.

We iterate every instruction in .text via idautils.Heads and check operand
displacements. This catches movaps/movups/movss etc. with disp32 regardless
of prefix bytes.
"""

import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_ua, ida_hexrays, ida_name, ida_segment, ida_nalt
import struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\worldtocam_report2.txt"
IMG = 0x140000000

lines = []
def P(s=""):
    lines.append(str(s))

def rva(ea): return ea - IMG
def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idc.BADADDR
def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception:
        return None

seg = ida_segment.get_segm_by_name(".text")
t_start, t_end = seg.start_ea, seg.end_ea
P("image_base 0x%X, .text %X..%X" % (IMG, t_start, t_end))

# Target displacements we care about:
#  NiCamera:   +0x120, +0x130, +0x140, +0x150  (worldToCam matrix rows)
#  ViewData:   +0xD0, +0xE0, +0xF0, +0x100     (viewProjMat rows inside BSGraphics::State)
NICAM_DISPS = [0x120, 0x130, 0x140, 0x150]
VD_DISPS    = [0xD0, 0xE0, 0xF0, 0x100]
ALL_DISPS   = set(NICAM_DISPS + VD_DISPS)

# For each function, collect a map of disp -> list of (ea, is_write, base_reg)
fn_stores = {}  # fn_ea -> {disp -> [(ea, is_write)]}

XMM_OPS = {"movaps", "movups", "movss", "movsd", "movapd", "movupd"}

# walk every head
count = 0
for ea in idautils.Heads(t_start, t_end):
    if not idc.is_code(idc.get_full_flags(ea)):
        continue
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        continue
    mn = insn.get_canon_mnem().lower()
    if mn not in XMM_OPS:
        continue
    op0 = insn.ops[0]
    op1 = insn.ops[1]
    # Either operand can be a displacement
    is_write = None
    disp = None
    if op0.type == ida_ua.o_displ and op1.type == ida_ua.o_reg:
        is_write = True
        disp = op0.addr & 0xFFFFFFFF
    elif op1.type == ida_ua.o_displ and op0.type == ida_ua.o_reg:
        is_write = False
        disp = op1.addr & 0xFFFFFFFF
    else:
        continue
    if disp not in ALL_DISPS:
        continue
    f = fn_start(ea)
    if f == idc.BADADDR:
        continue
    fn_stores.setdefault(f, {}).setdefault(disp, []).append((ea, is_write))
    count += 1

P("total matching insns: %d" % count)

# NiCamera full-matrix writers: functions that write all 4 rows (120/130/140/150)
nicam_writers = []
nicam_readers = []
for f, dmap in fn_stores.items():
    wrote_rows = set()
    read_rows = set()
    for disp, hits in dmap.items():
        for ea, is_write in hits:
            if is_write:
                wrote_rows.add(disp)
            else:
                read_rows.add(disp)
    if set(NICAM_DISPS).issubset(wrote_rows):
        nicam_writers.append(f)
    if set(NICAM_DISPS).issubset(read_rows):
        nicam_readers.append(f)

P("\n== NICAMERA writers (write 120+130+140+150) %d ==" % len(nicam_writers))
for f in nicam_writers:
    nm = ida_funcs.get_func_name(f) or ""
    P("  fn 0x%X (RVA 0x%X) %s" % (f, rva(f), nm))

P("\n== NICAMERA readers (read 120+130+140+150) %d ==" % len(nicam_readers))
for f in nicam_readers:
    nm = ida_funcs.get_func_name(f) or ""
    P("  fn 0x%X (RVA 0x%X) %s" % (f, rva(f), nm))

# Decompile everything that matters
P("\n=============================================================")
P(" DECOMPILED NICAMERA WRITERS")
P("=============================================================")
for f in nicam_writers:
    P("-" * 60)
    P("fn 0x%X (RVA 0x%X)" % (f, rva(f)))
    d = safe_decompile(f)
    if d:
        for ln in d.splitlines()[:280]:
            P("  " + ln)
    else:
        P("  <no decomp>")

P("\n=============================================================")
P(" DECOMPILED NICAMERA READERS")
P("=============================================================")
for f in nicam_readers:
    P("-" * 60)
    P("fn 0x%X (RVA 0x%X)" % (f, rva(f)))
    d = safe_decompile(f)
    if d:
        for ln in d.splitlines()[:280]:
            P("  " + ln)
    else:
        P("  <no decomp>")

# --- ViewData / BSGraphics::State
vd_writers = []
for f, dmap in fn_stores.items():
    wrote_rows = set()
    for disp, hits in dmap.items():
        for ea, is_write in hits:
            if is_write and disp in VD_DISPS:
                wrote_rows.add(disp)
    if set(VD_DISPS).issubset(wrote_rows):
        vd_writers.append(f)

P("\n=============================================================")
P(" VIEWDATA viewProjMat writers (write D0+E0+F0+100) %d" % len(vd_writers))
P("=============================================================")
for f in vd_writers:
    nm = ida_funcs.get_func_name(f) or ""
    P("  fn 0x%X (RVA 0x%X) %s" % (f, rva(f), nm))

# Decompile top 8 ViewData writers
for f in vd_writers[:8]:
    P("-" * 60)
    P("VD_WRITER fn 0x%X (RVA 0x%X)" % (f, rva(f)))
    d = safe_decompile(f)
    if d:
        for ln in d.splitlines()[:300]:
            P("  " + ln)
    else:
        P("  <no decomp>")

# --- Scan for absolute-address xmm stores (mov [rip+disp], xmm) into data seg
# These reveal the State data global absolute RVA if viewProjMat lives there.
P("\n== Absolute-mem xmm stores that target data segments (matrix pattern) ==")
abs_stores = {}  # target_addr -> list of (ea, fn)
for ea in idautils.Heads(t_start, t_end):
    if not idc.is_code(idc.get_full_flags(ea)): continue
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0: continue
    mn = insn.get_canon_mnem().lower()
    if mn not in XMM_OPS: continue
    op0 = insn.ops[0]
    op1 = insn.ops[1]
    # RIP-relative memory operand -> o_mem with addr = absolute VA
    if op0.type == ida_ua.o_mem and op1.type == ida_ua.o_reg:
        tgt = op0.addr
        if tgt >= IMG + 0x2000000 and tgt < IMG + 0x4000000:
            f = fn_start(ea)
            abs_stores.setdefault(tgt, []).append((ea, f))

# Group into 16-byte matrix clusters
clusters = {}
for tgt, hits in abs_stores.items():
    base = tgt & ~0xF
    clusters.setdefault(base, set()).add(tgt - base)

matrix_globals = [(b, sorted(offs)) for b, offs in clusters.items()
                   if {0, 0x10, 0x20, 0x30}.issubset(offs)]

P(" matrix globals (>=4 rows, 16-byte stride): %d" % len(matrix_globals))
for base, offs in matrix_globals[:40]:
    P("  base 0x%X (RVA 0x%X) rows=%s" % (base, rva(base), [hex(o) for o in offs[:6]]))

# For each matrix global, find the nearest labeled data name (indicates State struct start)
from ida_name import get_ea_name
P("\n== Nearby names for matrix globals ==")
for base, offs in matrix_globals[:40]:
    # walk back up to 0x400 bytes to find a named label
    for back in range(0, 0x400, 8):
        nm = get_ea_name(base - back)
        if nm:
            P("  base 0x%X  back 0x%X -> %s" % (base, back, nm))
            break

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))
print("wrote", OUT)
idaapi.qexit(0)
