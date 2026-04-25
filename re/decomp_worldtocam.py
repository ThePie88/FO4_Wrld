"""
Deep RE pass for NiCamera worldToCam matrix at offset +0x120.

Tasks:
A) Find writers: disasm pattern 'movups/movaps [reg+120h], xmm*' and
   look only at code paths where the base register is a NiCamera instance
   (owns the NiCamera vtable). Decompile each writer.
B) Find readers: pattern 'movups/movaps xmm*, [reg+120h]' (or +0x130/+0x140/+0x150
   for continuation rows). Decompile readers that multiply a Vec3/Vec4 world
   pos through it (matrix-vector multiply pattern = 4 shuffles × 4 rows).
C) Find BSGraphics::State singleton:
   - Look for '[rip+imm] -> pointer chain' that lands on structure sized ~0x800
     containing consecutive 4-float writes at +0x230, +0x240, +0x250, +0x260
     (this would be viewProjMat[0..3] inside State if CommonLibF4 is right).
   - Alternative: look for a small func that `mov rax, [rip+disp]; ret` returning
     the global -- classic GetSingleton signature.
"""

import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_ua, ida_hexrays, ida_name, ida_segment, ida_nalt
import struct, re

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\worldtocam_report.txt"
IMG = 0x140000000
NICAMERA_VTBL_RVA = 0x267DD50     # from camera_report
NICAMERA_VTBL = IMG + NICAMERA_VTBL_RVA
WORLDTOCAM_OFF = 0x120

lines = []
def P(s=""):
    lines.append(str(s))
    print(s)

def rva(ea): return ea - IMG

def safe_decompile(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None: return None
        return str(cfunc)
    except Exception as e:
        return None

def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idc.BADADDR

def iter_code_seg():
    # iterate .text only
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return 0, 0
    return seg.start_ea, seg.end_ea

P("=" * 72)
P(" worldToCam (NiCamera+0x120) + BSGraphics::State RE")
P(" image base = 0x%X" % IMG)
P(" NiCamera vtable RVA = 0x%X  VA = 0x%X" % (NICAMERA_VTBL_RVA, NICAMERA_VTBL))
P(" worldToCam offset = +0x%X" % WORLDTOCAM_OFF)
P("=" * 72)

# ---------------------------------------------------------------
# PART A: pattern-scan for writes [reg+120h], xmm*
# Also capture nearby writes to +0x130/+0x140/+0x150 = matrix rows.
# ---------------------------------------------------------------
P("\n== PART A: writes to [reg+0x120] (candidate NiCamera::worldToCam row 0) ==\n")

t_start, t_end = iter_code_seg()
P(" .text scan %X..%X (size %X)" % (t_start, t_end, t_end - t_start))

# A raw disassembly scan is cheaper than iterating all funcs. We look for
# movups/movaps  xmmN, [regA + 0x120]  OR  [regA + 0x120], xmmN  within code.
# Signature opcodes:
#   0F 11 xx xx xx xx xx     movups  [reg+disp32], xmmN      (disp32 form)
#   0F 11 xx xx               movups  [reg+disp8], xmmN       (disp8 form; 0x120 wants disp32)
#   0F 10 ...                movups  xmmN, [reg+disp32]
#   66 0F 29 ...             movaps (aligned) store
#   66 0F 28 ...             movaps load
#   (no 66 prefix for movups/movaps — actually movaps is 66 0F 28/29, movups is 0F 10/11)
# For disp32 = 0x120 little-endian bytes: 20 01 00 00.
# The next-row disps: 0x130=30 01 00 00; 0x140=40 01 00 00; 0x150=50 01 00 00.
# We brute scan for byte sequences ending in each disp.

DISPS = {
    0x120: b"\x20\x01\x00\x00",
    0x130: b"\x30\x01\x00\x00",
    0x140: b"\x40\x01\x00\x00",
    0x150: b"\x50\x01\x00\x00",
    0x160: b"\x60\x01\x00\x00",
}

# build signatures (both 0F and 66 0F) with any modrm.
# We'll iterate bytes and test insn decoding at each candidate hit for disp=0x120.

hits_120_write = []  # writers (store: movups/movaps mem, xmm)
hits_120_read  = []  # readers (load:  movups/movaps xmm, mem)

def scan_for_disp(disp_bytes, disp_val):
    """Naive byte-window scan for occurrences of disp_bytes then confirm via ida_ua."""
    # grab whole .text
    data = ida_bytes.get_bytes(t_start, t_end - t_start)
    if not data: return []
    ret = []
    idx = 0
    while True:
        i = data.find(disp_bytes, idx)
        if i < 0: break
        ea = t_start + i
        # walk backwards up to 12 bytes to find the insn start
        for back in range(1, 12):
            cand = ea - back
            insn = ida_ua.insn_t()
            n = ida_ua.decode_insn(insn, cand)
            if n == 0:
                continue
            if cand + n != ea + 4 and cand + n < ea + 4:
                continue
            # mnemonic check
            m = insn.get_canon_mnem().lower()
            if m in ("movups", "movaps", "movss", "movsd"):
                # check operand has displacement disp_val
                for op in insn.ops:
                    if op.type == ida_ua.o_displ and op.addr == disp_val:
                        ret.append((cand, m, insn))
                        break
            break
        idx = i + 1
    return ret

for dv, db in DISPS.items():
    hits = scan_for_disp(db, dv)
    P(" disp 0x%X : %d candidate insns" % (dv, len(hits)))

# focused: get 0x120 hits only
hits120 = scan_for_disp(DISPS[0x120], 0x120)
P(" focusing on 0x120 hits: %d" % len(hits120))

# classify into writers vs readers
writers = set()
readers = set()
write_sites = []
read_sites = []
for ea, mnem, insn in hits120:
    op0 = insn.ops[0]
    op1 = insn.ops[1]
    # movups/movaps: op0 = dest, op1 = src
    # writer: op0 is mem (o_displ), op1 is xmm register
    if op0.type == ida_ua.o_displ and op0.addr == 0x120 and op1.type == ida_ua.o_reg:
        f = fn_start(ea)
        if f != idc.BADADDR:
            writers.add(f)
            write_sites.append((ea, f, idc.GetDisasm(ea)))
    elif op1.type == ida_ua.o_displ and op1.addr == 0x120 and op0.type == ida_ua.o_reg:
        f = fn_start(ea)
        if f != idc.BADADDR:
            readers.add(f)
            read_sites.append((ea, f, idc.GetDisasm(ea)))

P(" unique writer funcs: %d" % len(writers))
P(" unique reader funcs: %d" % len(readers))

# quick list of sites
P("\n-- write sites (first 40) --")
for ea, f, dis in write_sites[:40]:
    P("  %X  fn=%X  %s" % (ea, f, dis))
P("\n-- read sites (first 40) --")
for ea, f, dis in read_sites[:40]:
    P("  %X  fn=%X  %s" % (ea, f, dis))

# ---------------------------------------------------------------
# PART A2: Cross-check writers that also touch +0x130, +0x140, +0x150
# (These are the ones writing an entire 4x4 matrix = worldToCam.)
# ---------------------------------------------------------------
P("\n== PART A2: writers that also write +0x130, +0x140, +0x150 (full matrix writers) ==\n")

# build per-func map of displacements written
fn_write_disps = {}
for dv in DISPS:
    for ea, mnem, insn in scan_for_disp(DISPS[dv], dv):
        op0 = insn.ops[0]
        op1 = insn.ops[1]
        if op0.type == ida_ua.o_displ and op0.addr == dv and op1.type == ida_ua.o_reg:
            f = fn_start(ea)
            if f == idc.BADADDR: continue
            fn_write_disps.setdefault(f, set()).add(dv)

full_matrix_writers = [f for f,ds in fn_write_disps.items() if {0x120, 0x130, 0x140, 0x150}.issubset(ds)]
P(" full-matrix writers (touch 120+130+140+150): %d" % len(full_matrix_writers))
for f in full_matrix_writers[:30]:
    nm = ida_funcs.get_func_name(f) or ""
    P("   fn 0x%X (RVA 0x%X) %s  disps=%s" % (f, rva(f), nm, sorted(fn_write_disps[f])))

# ---------------------------------------------------------------
# PART A3: decompile top writers
# ---------------------------------------------------------------
P("\n== PART A3: decompile full-matrix writers ==\n")
for f in full_matrix_writers[:6]:
    P("-" * 64)
    P("WRITER fn 0x%X (RVA 0x%X)" % (f, rva(f)))
    d = safe_decompile(f)
    if d:
        # only print first 200 lines to keep report sane
        out = d.splitlines()
        for ln in out[:250]:
            P("  " + ln)
    else:
        P("  <decompile failed>")

# ---------------------------------------------------------------
# PART B: readers — focus on ones that appear to do matrix*vec mul
# ---------------------------------------------------------------
P("\n== PART B: decompile readers at +0x120 ==\n")

# readers set also includes readers at 120/130/140/150.
# Re-scan reads for all disps.
fn_read_disps = {}
for dv in DISPS:
    for ea, mnem, insn in scan_for_disp(DISPS[dv], dv):
        op0 = insn.ops[0]
        op1 = insn.ops[1]
        if op1.type == ida_ua.o_displ and op1.addr == dv and op0.type == ida_ua.o_reg:
            f = fn_start(ea)
            if f == idc.BADADDR: continue
            fn_read_disps.setdefault(f, set()).add(dv)

full_matrix_readers = [f for f,ds in fn_read_disps.items() if {0x120, 0x130, 0x140, 0x150}.issubset(ds)]
P(" full-matrix readers (read 120+130+140+150): %d" % len(full_matrix_readers))
for f in full_matrix_readers[:30]:
    nm = ida_funcs.get_func_name(f) or ""
    P("   fn 0x%X (RVA 0x%X) %s  disps=%s" % (f, rva(f), nm, sorted(fn_read_disps[f])))

P("\n== PART B2: decompile full-matrix readers (matrix*vec candidates) ==\n")
for f in full_matrix_readers[:6]:
    P("-" * 64)
    P("READER fn 0x%X (RVA 0x%X)" % (f, rva(f)))
    d = safe_decompile(f)
    if d:
        out = d.splitlines()
        for ln in out[:250]:
            P("  " + ln)
    else:
        P("  <decompile failed>")

# ---------------------------------------------------------------
# PART C: BSGraphics::State singleton search
# Strategy: look for small functions that do
#    mov rax, cs:qword_XXXXXXX ; retn
# or
#    lea rax, cs:byte_XXXXXXX ; retn
# where XXXXXXX is a data address. Those are GetSingleton-style accessors.
# Filter: the returned-to global must have size/structure where at offset
# +0x160 there's a CameraStateData (ViewData) struct. CommonLibF4 says
# viewProjMat begins at State+0x230 (= 0x160 (ViewData) + 0xD0 (viewProjMat)).
# We also search for 'movaps/movups [reg+0xD0], xmm0' patterns inside a
# function that reads a global — which would be the ViewData writer.
# ---------------------------------------------------------------
P("\n== PART C: BSGraphics::State singleton candidates ==\n")

# enumerate all functions and find ones of size <= 16 bytes that consist of
# mov rax,[rip+x]; ret  (or similar).
tiny_accessors = []
for fn_ea in idautils.Functions(t_start, t_end):
    fn = ida_funcs.get_func(fn_ea)
    if not fn: continue
    if fn.size() > 20: continue
    # decode first insn
    insn = ida_ua.insn_t()
    n = ida_ua.decode_insn(insn, fn_ea)
    if n == 0: continue
    m = insn.get_canon_mnem().lower()
    if m not in ("mov", "lea"): continue
    # first operand reg eax/rax
    if insn.ops[0].type != ida_ua.o_reg: continue
    if insn.ops[1].type not in (ida_ua.o_mem, ida_ua.o_displ): continue
    # target is a data address (rip-relative)
    target = insn.ops[1].addr
    if target < IMG + 0x2000000 or target > IMG + 0x4000000:
        continue
    # next insn should be ret (or jmp to something)
    insn2 = ida_ua.insn_t()
    n2 = ida_ua.decode_insn(insn2, fn_ea + n)
    if n2 == 0: continue
    m2 = insn2.get_canon_mnem().lower()
    if m2 not in ("retn", "ret", "jmp"): continue
    tiny_accessors.append((fn_ea, target, m, m2))

P(" tiny-accessor candidates: %d" % len(tiny_accessors))
# print first 20
for ea, tgt, m, m2 in tiny_accessors[:20]:
    P("  fn %X (RVA %X)  %s [0x%X]  %s" % (ea, rva(ea), m, tgt, m2))

# ---------------------------------------------------------------
# PART C2: identify candidate by searching for a function that writes
# 4 consecutive rows (0x230/240/250/260 or 0xD0/E0/F0/100 relative to base)
# where base = reg loaded from a global singleton.
# Easier: scan for *movaps/movups [RIP+abs], xmm*  pattern on data globals
# at four offsets separated by 0x10.  Then look at the global's RVA range.
# ---------------------------------------------------------------
P("\n== PART C2: data globals that receive 4 consecutive 16-byte writes (matrix) ==\n")

# Simpler: Look for  movups [reg+0xD0], xmm ... [reg+0xE0] ... etc.
# That's the same pattern as worldToCam writers, but here "reg" holds
# ViewData* (offset 0xD0 = viewProjMat[0]).  The ViewData pointer ought to
# be loaded from State singleton via  mov reg, [rip+?]  or reg = singleton+0x160.

DISPS_VP = {
    0xD0: b"\xD0\x00\x00\x00",
    0xE0: b"\xE0\x00\x00\x00",
    0xF0: b"\xF0\x00\x00\x00",
    0x100: b"\x00\x01\x00\x00",
}
fn_vp_writes = {}
for dv, db in DISPS_VP.items():
    for ea, mnem, insn in scan_for_disp(db, dv):
        op0 = insn.ops[0]
        op1 = insn.ops[1]
        if op0.type == ida_ua.o_displ and op0.addr == dv and op1.type == ida_ua.o_reg:
            f = fn_start(ea)
            if f == idc.BADADDR: continue
            fn_vp_writes.setdefault(f, set()).add(dv)

vp_writers = [f for f,ds in fn_vp_writes.items() if {0xD0, 0xE0, 0xF0, 0x100}.issubset(ds)]
P(" matrix writers at +D0/E0/F0/100 (ViewData viewProjMat candidates): %d" % len(vp_writers))
for f in vp_writers[:30]:
    nm = ida_funcs.get_func_name(f) or ""
    P("   fn 0x%X (RVA 0x%X) %s  disps=%s" % (f, rva(f), nm, sorted(fn_vp_writes[f])))

P("\n== PART C3: decompile top ViewData viewProjMat writers ==\n")
for f in vp_writers[:4]:
    P("-" * 64)
    P("VD_WRITER fn 0x%X (RVA 0x%X)" % (f, rva(f)))
    d = safe_decompile(f)
    if d:
        out = d.splitlines()
        for ln in out[:250]:
            P("  " + ln)
    else:
        P("  <decompile failed>")

# ---------------------------------------------------------------
# PART C4: Also check for writes at ABSOLUTE 0x230/0x240 inside State,
# meaning `movups [rip+disp], xmm*` with disp targeting State+0x230.
# This tells us the State RVA even without finding getter.
# ---------------------------------------------------------------
P("\n== PART C4: absolute-address XMM stores to data segment ==\n")
# movaps  [rip+disp32], xmmN :  0F 29 05 xx xx xx xx  or  66 0F 29 05 ...
# movups  [rip+disp32], xmmN :  0F 11 05 xx xx xx xx
abs_stores = {}
data = ida_bytes.get_bytes(t_start, t_end - t_start)
for i in range(len(data) - 7):
    # look for 0F 11 05 / 0F 29 05 / 66 0F 11 05 / 66 0F 29 05
    if data[i] == 0x0F and data[i+1] in (0x11, 0x29) and data[i+2] == 0x05:
        disp = struct.unpack("<i", data[i+3:i+7])[0]
        ea = t_start + i
        tgt = ea + 7 + disp
        if IMG + 0x2000000 < tgt < IMG + 0x4000000:
            f = fn_start(ea)
            abs_stores.setdefault(tgt, []).append((ea, f))
    if i+1 < len(data) and data[i] == 0x66 and data[i+1] == 0x0F and i+3 < len(data) and data[i+2] in (0x11, 0x29) and data[i+3] == 0x05:
        disp = struct.unpack("<i", data[i+4:i+8])[0]
        ea = t_start + i
        tgt = ea + 8 + disp
        if IMG + 0x2000000 < tgt < IMG + 0x4000000:
            f = fn_start(ea)
            abs_stores.setdefault(tgt, []).append((ea, f))

# For each target address, see if there are writes at 0x10 strides — indicates matrix write at that data global
groups = {}
for tgt, hits in abs_stores.items():
    groups.setdefault(tgt & ~0xF, []).append((tgt, hits))

matrix_globals = []
for basetgt, items in groups.items():
    offsets = set(t - basetgt for t, _ in items)
    # ensure we have at least four consecutive 16-byte strides
    if {0, 0x10, 0x20, 0x30}.issubset(offsets):
        matrix_globals.append((basetgt, sorted(offsets)))

P(" data-globals receiving 4-row matrix stores: %d" % len(matrix_globals))
for base, offs in matrix_globals[:60]:
    P("   base 0x%X (RVA 0x%X) offsets=%s" % (base, rva(base), [hex(o) for o in offs]))

# ---------------------------------------------------------------
# PART C5: look for TLS-based state access pattern mentioned in bsgraphics_state_report6.txt:
# `(_QWORD **) NtCurrentTeb()->ThreadLocalStoragePointer + TlsIndex` is the
# BSGraphicsRenderer state (not the same as State singleton).  CommonLibF4
# BSGraphics::State::GetSingleton returns a singleton pointer. Let's search
# strings for a hint.
# ---------------------------------------------------------------
P("\n== PART C5: String search for 'BSGraphics' to find refs ==\n")
scnt = 0
for s in idautils.Strings():
    try:
        v = str(s)
    except Exception:
        continue
    if "BSGraphics" in v or "bsgraphics" in v:
        P("   str @ 0x%X : %s" % (s.ea, v[:120]))
        scnt += 1
        if scnt > 30: break

P("\n== DONE ==")

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))

print("wrote", OUT)
idaapi.qexit(0)
