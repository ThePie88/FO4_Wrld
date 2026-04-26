"""
M8P3 — AGENT A v6: Find consumer of NiSkinInstance+0x30 cached pointer array.

Discovery: sub_1416EEBE0 (NiSkinInstance vt slot 28 = Load) builds a flat
array of pointers to bone.world matrices. Each entry = bone+0x70.
The cache lives at NiSkinInstance+0x30 (a1[6]).

Now find the function that reads from there and uploads to GPU.

Strategy:
  1. Find all functions accessing NiSkinInstance+0x30 (i.e. *(QWORD*)(skin+48))
     via decomp text patterns.
  2. Filter by callsite proximity to D3D11 Map/UpdateSubresource.
  3. Look at ReadAdditional (sub_1416EE980) — clone path that COPIES from +0x30.

Also:
  - Look at sub_1416EFC90 (slot 26 caller — clone helper)
  - Look at NiSkinInstance partition vtable functions
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_xref, ida_segment

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_update_AGENT_A_v6_raw.log"
IMG = 0x140000000
out = []
def log(s=""): out.append(s if isinstance(s, str) else str(s))
def hexs(x): return "0x%X" % x if isinstance(x, int) else str(x)
def rva(ea): return ea - IMG
def fn_size(ea):
    f = ida_funcs.get_func(ea)
    return (f.end_ea - f.start_ea) if f else 0
def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR
def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception as e:
        return "<decomp error: %s>" % e
def xrefs_to_code(ea):
    refs = []
    x = idaapi.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = idaapi.get_next_cref_to(ea, x)
    return refs

log("=" * 80)
log(" M8P3 SKIN UPDATE — AGENT A v6 (consumer of NiSkinInstance+0x30)")
log("=" * 80)

# =============================================================================
# SECTION 1 — Find functions referencing NiSkinInstance vt itself + reading +0x30
# =============================================================================

NSI_VT = 0x142680DA8

# All functions that touch the NSI vt
nsi_callers = set()
x = idaapi.get_first_dref_to(NSI_VT)
while x != idaapi.BADADDR:
    f = fn_start(x)
    if f != idaapi.BADADDR:
        nsi_callers.add(f)
    x = idaapi.get_next_dref_to(NSI_VT, x)

log(" functions referencing NSI vt: %d" % len(nsi_callers))
for f in sorted(nsi_callers):
    nm = ida_funcs.get_func_name(f) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(f), nm, fn_size(f), hexs(rva(f))))

# =============================================================================
# SECTION 2 — Look for any function that accesses both +0x10 (skinData ptr)
# AND +0x30 (cached bone+0x70 ptr array) of a presumed NSI object.
# These should be skin-update-pass candidates.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 2 — Functions reading both NSI+0x10 and NSI+0x30")
log("=" * 80)

seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(seg.start_ea, seg.end_ea))

# Decomp every fn in size 0x80..0x600 and check for distinct patterns
candidates = []
for fea in fns:
    sz = fn_size(fea)
    if sz < 0x80 or sz > 0x600: continue
    cur = ida_funcs.get_func(fea).start_ea
    end = ida_funcs.get_func(fea).end_ea
    has_10 = has_30 = has_loop_back = False
    has_70 = False
    while cur < end and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+10h]" in ds: has_10 = True
        if "+30h]" in ds: has_30 = True
        if "+70h]" in ds: has_70 = True
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("jne","jnz","jl","jle","jb","jbe","ja","jae"):
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt < cur and tgt >= ida_funcs.get_func(fea).start_ea:
                has_loop_back = True
        cur = idc.next_head(cur)
    if has_10 and has_30 and has_loop_back:
        candidates.append((fea, sz, has_70))

candidates.sort(key=lambda x: -x[1])
log(" candidates (read +0x10 + +0x30 + loop): %d" % len(candidates))
for fea, sz, h70 in candidates[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X has70=%s rva=%s" % (hexs(fea), nm, sz, h70, hexs(rva(fea))))

# =============================================================================
# SECTION 3 — Direct scan for "+0x30 + 8*i" pattern: typical iteration over
# pointer array. Look at all callers of sub_1416EEBE0 (slot 28) — which are 0
# but the SLOT itself is invoked via vtable dispatch from stream readers.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 3 — Specifically locate skin-cache consumer")
log("=" * 80)

# Look at the bsgraphic state — sub_1416FE030 was a candidate from v1
# (BSGraphics::Renderer caller with skin offsets + 10 xmm stores)
log("\n -- sub_1416FE030 (size 0x31B, BSGraph + skin offsets, 10 xmm) --")
dec = safe_decompile(0x1416FE030)
if dec:
    for ln in dec.split("\n")[:300]:
        log("   " + ln)

log("\n -- sub_141796880 (size 0x45B, BSGraph + skin, 35 xmm) --")
dec = safe_decompile(0x141796880)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

log("\n -- sub_1417D7080 (size 0x345, BSGraph + skin, 15 xmm) --")
dec = safe_decompile(0x1417D7080)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

log("\n -- sub_1417D69D0 (size 0x37A, BSGraph + skin, 15 xmm) --")
dec = safe_decompile(0x1417D69D0)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

# =============================================================================
# Save log
# =============================================================================
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "(", len(out), "lines )")
idaapi.qexit(0)
