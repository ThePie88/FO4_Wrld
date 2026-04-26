"""
M8P3 — AGENT A v4: Final search for the skin matrix flatten/upload pass.

Insight: The function we're looking for likely sits in BSGraphics::Renderer
between scene-graph render dispatch and D3D11 cb upload. It walks
bones_pri[i] reading bone+0x70 world matrices and writes them flat.

Key targets:
  1. sub_1421B69D0 (size 0xFC1) — scenegraph render driver: decomp
  2. Look at BSTriShape rendering vtable slots 28-31 (the override).
  3. Look at sub_1404055F0 (mul4x4 caller, size 0xCB9): callers + decomp.
  4. Look at sub_140C58C70 (called from sub_140C883E0): NIF deserialization?
  5. Look for functions with "Map" + "skin offset" + "loop with stride 8"
     (writes to GPU constant buffer per bone).
  6. Look at NiSkinPartition vt (0x142680A70).
  7. Look at NiSkinInstance vt (0x142680DA8).
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_update_AGENT_A_v4_raw.log"
IMG = 0x140000000
out = []
def log(s=""): out.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)
def rva(ea): return ea - IMG
def fn_size(ea):
    f = ida_funcs.get_func(ea)
    if not f: return 0
    return f.end_ea - f.start_ea
def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR
def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception as e:
        return "<decomp error: %s>" % e
def xrefs_to_data(ea):
    refs = []
    x = ida_xref.get_first_dref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_dref_to(ea, x)
    return refs
def xrefs_to_code(ea):
    refs = []
    x = ida_xref.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_cref_to(ea, x)
    return refs

# Anchors
NISKIN_INSTANCE_VT = 0x142680DA8
NISKIN_DATA_VT     = 0x142680BB8
NISKIN_PARTITION_VT= 0x142680A70

log("=" * 80)
log(" M8P3 SKIN UPDATE — AGENT A v4 (final search)")
log("=" * 80)

# =============================================================================
# SECTION 1 — sub_1421B69D0 deep dive (scenegraph render driver, size 0xFC1)
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 1 — sub_1421B69D0 (scenegraph render driver, size 0xFC1)")
log("=" * 80)
RENDER_DRIVER = 0x1421B69D0
log("\n -- direct callees of sub_1421B69D0 --")
f = ida_funcs.get_func(RENDER_DRIVER)
if f:
    callees = set()
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        if idc.print_insn_mnem(cur).lower() == "call":
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt > IMG and tgt < IMG + 0x4000000:
                callees.add(tgt)
        cur = idc.next_head(cur)
    for c in sorted(callees):
        sz = fn_size(c)
        nm = ida_funcs.get_func_name(c) or ""
        log("   %s %s sz=0x%X rva=%s" % (hexs(c), nm, sz, hexs(rva(c))))

log("\n -- decomp first 300 lines of sub_1421B69D0 --")
dec = safe_decompile(RENDER_DRIVER)
if dec:
    for ln in dec.split("\n")[:300]:
        log("   " + ln)

# =============================================================================
# SECTION 2 — Examine NiSkinInstance vtable (parallel hierarchy, NOT BSSkin)
# Maybe the OLD NiSkinInstance still has the apply-to-buffer routine.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 2 — NiSkinInstance vtable (vt 0x142680DA8)")
log("=" * 80)

for i in range(50):
    slot_ea = NISKIN_INSTANCE_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    nm = ida_funcs.get_func_name(v) or ""
    sz = fn_size(v)
    log("   nisi[%2d] %s %s sz=0x%X rva=%s" % (i, hexs(v), nm, sz, hexs(rva(v))))

log("\n -- NiSkinInstance code refs (functions touching the vt) --")
refs = xrefs_to_data(NISKIN_INSTANCE_VT)
for r in refs:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   ref %s in fn %s %s sz=0x%X rva=%s" % (
        hexs(r), hexs(f), nm, fn_size(f), hexs(rva(f))))

# =============================================================================
# SECTION 3 — Examine NiSkinPartition vtable
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 3 — NiSkinPartition vtable (vt 0x142680A70)")
log("=" * 80)

for i in range(50):
    slot_ea = NISKIN_PARTITION_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    nm = ida_funcs.get_func_name(v) or ""
    sz = fn_size(v)
    log("   nisp[%2d] %s %s sz=0x%X rva=%s" % (i, hexs(v), nm, sz, hexs(rva(v))))

log("\n -- NiSkinPartition code refs --")
refs = xrefs_to_data(NISKIN_PARTITION_VT)
for r in refs:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   ref %s in fn %s %s sz=0x%X rva=%s" % (
        hexs(r), hexs(f), nm, fn_size(f), hexs(rva(f))))

# =============================================================================
# SECTION 4 — sub_1404055F0 (mul4x4 caller, size 0xCB9) and its callers.
# This is one of the largest mul4x4 callers — high probability of being the
# skin update or a related camera/transform pipeline.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 4 — sub_1404055F0 (size 0xCB9, mul4x4 caller)")
log("=" * 80)

callers = set()
for r in xrefs_to_code(0x1404055F0):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        callers.add(f)
log(" callers: %d" % len(callers))
for c in callers:
    nm = ida_funcs.get_func_name(c) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(c), nm, fn_size(c), hexs(rva(c))))

log("\n -- decomp first 400 lines of sub_1404055F0 --")
dec = safe_decompile(0x1404055F0)
if dec:
    for ln in dec.split("\n")[:400]:
        log("   " + ln)

# =============================================================================
# SECTION 5 — Look at the FOUR common ancestors found in v3
#  sub_1402D36F0 (sz 0x2B1)
#  sub_1402FE060 (sz 0x13AE - 5038 bytes!)
#  sub_140C4CE00 (sz 0x3328 - 13096 bytes!)
#  sub_140E4CBF0 (sz 0x5DE)
# Each could be the master driver. Decomp partial.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 5 — Common ancestors of UWD + skin-mul")
log("=" * 80)

ANCESTORS = [
    ("sub_1402D36F0", 0x1402D36F0, 80),    # small
    ("sub_1402FE060", 0x1402FE060, 200),   # medium
    ("sub_140E4CBF0", 0x140E4CBF0, 200),   # medium
    # skipping the huge 13K-byte fn — too big to digest
]

for name, ea, lim in ANCESTORS:
    log("\n -- %s @ %s rva=%s sz=0x%X --" % (name, hexs(ea), hexs(rva(ea)), fn_size(ea)))
    callers = set()
    for r in xrefs_to_code(ea):
        f = fn_start(r)
        if f != idaapi.BADADDR:
            callers.add(f)
    log("   callers: %d" % len(callers))
    for c in callers:
        nm = ida_funcs.get_func_name(c) or ""
        log("     %s %s sz=0x%X rva=%s" % (hexs(c), nm, fn_size(c), hexs(rva(c))))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:lim]:
            log("   " + ln)

# =============================================================================
# SECTION 6 — Search for functions with literal pattern: read [reg+28h] (head),
# load count from [reg+38h], loop "for i=0; i<count; i++" with stride 8 read,
# inside loop deref [bone+70h] reading 4 xmms. This is the cleanest signature.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 6 — Strict pattern hunt: bones_pri walker reading bone+0x70")
log("=" * 80)

seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(seg.start_ea, seg.end_ea))
log(" total fns: %d" % len(fns))

# Use textual decompile pattern matching now
strict_candidates = []
count = 0
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    # Narrow size range — looking for a focused skin update fn (not a giant orchestrator)
    if sz < 0x100 or sz > 0x500: continue
    cur = f.start_ea
    has_28 = has_38 = False
    has_70_xmm_load = False
    has_loop_back = False
    has_xmm_writes = 0
    has_imul_50 = has_lea_inc8 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        ds_l = ds.lower()
        if "+28h]" in ds: has_28 = True
        if "+38h]" in ds: has_38 = True
        if "+70h]" in ds_l and ("xmm" in ds_l or "movups" in ds_l or "movaps" in ds_l):
            has_70_xmm_load = True
        if ("movups " in ds_l or "movaps " in ds_l) and "xmm" in ds_l:
            br = ds.find("[")
            xpos = ds.lower().find("xmm")
            if br > 0 and br < xpos:
                has_xmm_writes += 1
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("jne","jnz","jl","jle","jb","jbe","jg","jge","ja","jae"):
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt < cur and tgt >= f.start_ea:
                has_loop_back = True
        # Increment by 8 (stride) in a register: "add reg, 8"
        if mnem == "add":
            op0 = idc.print_operand(cur, 0).lower()
            op1 = idc.print_operand(cur, 1).lower()
            if op1 == "8" and op0.startswith("r") and len(op0) <= 4:
                has_lea_inc8 = True
        if "imul" in ds_l and "50h" in ds_l: has_imul_50 = True
        cur = idc.next_head(cur)
    score = 0
    if has_28: score += 3
    if has_38: score += 3
    if has_70_xmm_load: score += 4
    if has_loop_back: score += 2
    if has_xmm_writes >= 4: score += 2
    if has_lea_inc8: score += 2
    if has_imul_50: score += 2
    if score >= 12:
        strict_candidates.append((fea, sz, score))

strict_candidates.sort(key=lambda x: -x[2])
log(" strict skin-walker candidates (score >=12, sz 0x100..0x500): %d" % len(strict_candidates))
for fea, sz, score in strict_candidates[:25]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X score=%d rva=%s" % (hexs(fea), nm, sz, score, hexs(rva(fea))))

# Decomp top 5
for fea, sz, score in strict_candidates[:5]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- STRICT_CAND %s %s sz=0x%X score=%d rva=%s -----" % (
        hexs(fea), nm, sz, score, hexs(rva(fea))))
    dec = safe_decompile(fea)
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
