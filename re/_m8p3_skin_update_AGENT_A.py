"""
M8P3 — AGENT A: CPU skin update function hunt.

Goal: Find the function that walks BSSkin::Instance->bones_pri[i] each frame,
reads each bone's world matrix at NiAVObject+0x70, multiplies by inverse-bind
from BoneData, and writes the result into a flat per-bone matrix buffer that
gets uploaded to GPU as a constant buffer.

This script combines all four strategies:
  1. BSSkin::Instance vtable scan (already done — empty result).
  2. Xref scan to BSSkin::Instance vt + decomp top callers.
  3. Pattern: functions that loop with stride 0x40 and read both inv_bind
     (skin+0x40 -> +0x10 stride 0x50) AND bones (skin+0x28 stride 8).
  4. D3D11 constant buffer upload sites (Map/UpdateSubresource trace).

Output: re/_m8p3_skin_update_AGENT_A_raw.log
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_update_AGENT_A_raw.log"
IMG = 0x140000000
out = []
def log(s=""): out.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)
def rva(ea): return ea - IMG
def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR
def fn_name(ea):
    f = ida_funcs.get_func(ea)
    if not f: return "?"
    n = ida_funcs.get_func_name(f.start_ea)
    return n or hexs(f.start_ea)
def fn_size(ea):
    f = ida_funcs.get_func(ea)
    if not f: return 0
    return f.end_ea - f.start_ea
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
BSI_VT     = 0x14267E5C8     # BSSkin::Instance vtable
BSGEOM_VT  = 0x14267E0B8     # BSGeometry vtable
BSTRI_VT   = 0x14267E948     # BSTriShape vtable
BSSITS_VT  = 0x142697D40     # BSSubIndexTriShape vtable
BSI_BD_VT  = 0x14267E480     # BSSkin::BoneData vtable
FRAME_TICK = 0x140C334B0
NIAVUWD    = 0x1416C85A0     # NiAVObject::UpdateWorldData
NINOUWD    = 0x1416BEAC0     # NiNode::UpdateWorldData
NIAVUDP    = 0x1416BF1C0     # NiAVObject::UpdateDownwardPass
MUL4X4     = 0x1403444F0
BSGEOM_VT_SLOT_53 = 0x1416C8A60  # BSGeometry pre-render hook
BSGEOM_VT_SLOT_51 = 0x1416D4F80  # candidate: largest BSGeometry virtual
BSGEOM_VT_SLOT_32 = 0x1416D5260
BSGEOM_VT_SLOT_55 = 0x1416C8AD0
BSGEOM_VT_SLOT_56 = 0x1416C8B10  # 0x48 size
BSGEOM_VT_SLOT_57 = 0x1416D5200  # 0x57 size — may be Render
BSGEOM_VT_SLOT_46 = 0x1416C8210
BSGEOM_VT_SLOT_45 = 0x1416C81A0
BSGRAPH_RENDERER  = 0x1434380A8

log("=" * 80)
log(" M8P3 SKIN UPDATE PASS — AGENT A")
log(" Hunt: CPU function that produces flat per-bone skin matrix buffer")
log("=" * 80)
log(" BSSkin::Instance vt = %s" % hexs(BSI_VT))
log(" BSGeometry vt       = %s" % hexs(BSGEOM_VT))
log(" frame_tick          = %s (rva %s)" % (hexs(FRAME_TICK), hexs(rva(FRAME_TICK))))
log(" NiAVObject::UpdateWorldData = %s" % hexs(NIAVUWD))

# =============================================================================
# SECTION 1 — Decomp BSGeometry virtual slot 53 (sub_1416C8A60) and ITS CALLEES
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 1 — BSGeometry vt slot 53 (sub_1416C8A60) — pre-render hook")
log("=" * 80)

dec = safe_decompile(BSGEOM_VT_SLOT_53)
if dec:
    log("\n -- sub_1416C8A60 (slot 53) full decomp --")
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

# Look at the indirect calls — slot 53 calls vt[+0x1A0]=slot 52 and vt[+0x198]=slot 51.
# slot 52 = sub_1416D54E0, slot 51 = sub_1416D4F80
log("\n -- decomp slot 51 sub_1416D4F80 (size 0x279) --")
dec = safe_decompile(BSGEOM_VT_SLOT_51)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

log("\n -- decomp slot 52 sub_1416D54E0 (calls UpdateWorldData) --")
dec = safe_decompile(0x1416D54E0)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

log("\n -- decomp slot 55 sub_1416C8AD0 (size 0x2D) --")
dec = safe_decompile(BSGEOM_VT_SLOT_55)
if dec:
    for ln in dec.split("\n")[:50]:
        log("   " + ln)

log("\n -- decomp slot 56 sub_1416C8B10 (size 0x48) --")
dec = safe_decompile(BSGEOM_VT_SLOT_56)
if dec:
    for ln in dec.split("\n")[:50]:
        log("   " + ln)

log("\n -- decomp slot 57 sub_1416D5200 (size 0x57) --")
dec = safe_decompile(BSGEOM_VT_SLOT_57)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

log("\n -- decomp slot 45 sub_1416C81A0 (size 0x69) --")
dec = safe_decompile(BSGEOM_VT_SLOT_45)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

# =============================================================================
# SECTION 2 — Find callers of NiAVObject::UpdateWorldData (1416C85A0) that
# read BSSkin::Instance fields. These are the candidates that combine bone
# tree walking with skin-instance access.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 2 — Functions that BOTH access skin instance AND walk bones")
log("=" * 80)

# Find functions which call mul4x4 AND read [reg+28h] AND [reg+38h] AND [reg+40h].
# These are extremely likely to be skin-update functions.
mul4x4_callers = set()
for r in xrefs_to_code(MUL4X4):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        mul4x4_callers.add(f)

log(" mul4x4 callers: %d" % len(mul4x4_callers))

# Check each: does it touch skin layout offsets (+0x10, +0x20, +0x28, +0x38, +0x40)?
candidates = []
for fea in mul4x4_callers:
    f = ida_funcs.get_func(fea)
    if not f: continue
    has_28 = has_38 = has_40 = has_loop = False
    sz = f.end_ea - f.start_ea
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+28h]" in ds: has_28 = True
        if "+38h]" in ds: has_38 = True
        if "+40h]" in ds: has_40 = True
        # Loop indicator: jne/jl back to earlier in function
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("jne","jnz","jl","jle","jg","jge","jb","jbe","ja","jae"):
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt < cur and tgt >= f.start_ea:
                has_loop = True
        cur = idc.next_head(cur)
    if has_loop and (has_28 or has_38) and has_40:
        candidates.append((fea, sz, has_28, has_38, has_40))

candidates.sort(key=lambda x: -x[1])
log(" candidates (mul4x4 + skin offsets + loop): %d" % len(candidates))
for fea, sz, h28, h38, h40 in candidates[:25]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X +28=%s +38=%s +40=%s rva=%s" % (
        hexs(fea), nm, sz, h28, h38, h40, hexs(rva(fea))))

# =============================================================================
# SECTION 3 — Decomp top candidates from Section 2
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 3 — Decomp top candidates")
log("=" * 80)

DECOMP_LIMIT = 5
for fea, sz, _, _, _ in candidates[:DECOMP_LIMIT]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- %s %s sz=0x%X rva=%s -----" % (hexs(fea), nm, sz, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# =============================================================================
# SECTION 4 — Look for D3D11 cb upload calls (UpdateSubresource pattern).
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 4 — D3D11 cb upload sites")
log("=" * 80)

# Find imports for d3d11 functions. In x64 PE, IAT entries are in .idata or
# imported via __imp_*. Look for strings or external refs.
# Common D3D11 hook names: D3D11_CreateBuffer, ID3D11DeviceContext::Map,
# ID3D11DeviceContext::Unmap, ID3D11DeviceContext::UpdateSubresource.
# We can't introspect by name (stripped from MS DLLs in PE). Instead, look for
# vtable invocations on context with known offsets:
#   IDDeviceContext::Map = vt slot 14 (offset 0x70)
#   IDDeviceContext::Unmap = vt slot 15 (offset 0x78)
#   ID3D11DeviceContext::UpdateSubresource = vt slot 48 (offset 0x180)
# We'll search for vtable calls with these offsets occurring in functions
# that also contain 0x40-stride loops.

# A simpler proxy: find functions calling BSGraphics::Renderer global (0x1434380A8)
# which is the engine-level renderer pointer. It contains D3D11 device + ctx.

bsgraph_refs = xrefs_to_data(BSGRAPH_RENDERER)
log(" refs to BSGraphics::Renderer global @ %s: %d" % (hexs(BSGRAPH_RENDERER), len(bsgraph_refs)))

# Filter to functions
bsgraph_callers = set()
for r in bsgraph_refs:
    f = fn_start(r)
    if f != idaapi.BADADDR:
        bsgraph_callers.add(f)
log(" unique callers: %d" % len(bsgraph_callers))

# Find which of these are also "matrix-stride" (have lots of XMM stores AND
# loops with stride 64) AND access skin offsets.
graph_skin_candidates = []
for fea in bsgraph_callers:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz > 0x600 or sz < 0x80: continue  # probably an upload helper
    has_skin = has_xmm_stride = False
    cur = f.start_ea
    xmm_stores = 0
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+28h]" in ds or "+38h]" in ds or "+40h]" in ds: has_skin = True
        if ("movups " in ds or "movaps " in ds) and "xmm" in ds and ds.find("[") < ds.find("xmm"):
            xmm_stores += 1
        cur = idc.next_head(cur)
    if xmm_stores >= 4 and has_skin:
        graph_skin_candidates.append((fea, sz, xmm_stores))
graph_skin_candidates.sort(key=lambda x: -x[2])
log(" BSGraphics callers with skin offsets + 4+ xmm stores: %d" % len(graph_skin_candidates))
for fea, sz, xn in graph_skin_candidates[:15]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X xmm=%d rva=%s" % (hexs(fea), nm, sz, xn, hexs(rva(fea))))

# =============================================================================
# SECTION 5 — Look at all callers of sub_1416C8A60 (BSGeometry slot 53 hook)
# These are the per-frame entry points.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 5 — Callers of BSGeometry slot 53 (sub_1416C8A60) — pre-render")
log("=" * 80)

# Direct callers
slot53_callers = set()
for r in xrefs_to_code(BSGEOM_VT_SLOT_53):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        slot53_callers.add(f)
log(" direct callers: %d" % len(slot53_callers))
for fea in slot53_callers:
    nm = ida_funcs.get_func_name(fea) or ""
    sz = fn_size(fea)
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# Also indirect callers (vtable dispatch). Hard to detect without symbolic
# execution. We rely on the fact that vtable slot 53 is invoked from the
# UpdateDownwardPass (sub_1416BF1C0), but let's also check for direct
# decomp of the slot 53 to see the indirect calls within it.

# =============================================================================
# SECTION 6 — Search for the actual SKIN MATRIX BUFFER UPLOAD pattern:
# Look for functions that write to a contiguous output buffer with stride 0x40
# AND read inv_bind matrices (skin->boneData->boneArray, stride 0x50).
# The pattern is:
#   for (i=0; i<count; i++) {
#       bone = bones_pri[i];           // read skin+0x28 + 8*i
#       inv_bind = boneData->boneArray[i*0x50 + 0x10];  // 4x4 matrix
#       out[i*0x40] = bone.world * inv_bind;             // 64-byte stride
#   }
# Heuristic: function contains "imul rXX, 50h" (boneData stride) AND
# "imul rXX, 40h" (output stride) AND xmm stores.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 6 — Stride 0x50 (boneData) + stride 0x40 (output) pattern")
log("=" * 80)

seg = ida_segment.get_segm_by_name(".text")
text_start = seg.start_ea
text_end = seg.end_ea

stride_pattern_candidates = []
fns = list(idautils.Functions(text_start, text_end))
log(" total functions: %d" % len(fns))

# Pre-filter: functions touching +0x40 first (boneData ptr)
fns_with_40 = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x80 or sz > 0x800: continue
    cur = f.start_ea
    has_40 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+40h]" in ds:
            has_40 = True
            break
        cur = idc.next_head(cur)
    if has_40:
        fns_with_40.append(fea)
log(" functions with [+40h] reads in size 0x80-0x800: %d" % len(fns_with_40))

for fea in fns_with_40:
    f = ida_funcs.get_func(fea)
    if not f: continue
    has_stride_50 = has_stride_40 = has_28 = has_70 = False
    xmm_stores = 0
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "imul" in ds and "50h" in ds: has_stride_50 = True
        if "imul" in ds and "40h" in ds: has_stride_40 = True
        if "+28h]" in ds: has_28 = True
        if "+70h]" in ds: has_70 = True
        if ("movups " in ds or "movaps " in ds) and "xmm" in ds:
            br = ds.find("[")
            xpos = ds.find("xmm")
            if br > 0 and br < xpos:
                xmm_stores += 1
        cur = idc.next_head(cur)
    score = 0
    if has_stride_50: score += 3
    if has_stride_40: score += 3
    if has_28: score += 2
    if has_70: score += 2
    if xmm_stores >= 4: score += 2
    if score >= 5:
        stride_pattern_candidates.append((fea, score, has_stride_50, has_stride_40, has_28, has_70, xmm_stores))

stride_pattern_candidates.sort(key=lambda x: -x[1])
log(" stride pattern candidates (score >=5): %d" % len(stride_pattern_candidates))
for fea, score, s50, s40, h28, h70, xn in stride_pattern_candidates[:15]:
    nm = ida_funcs.get_func_name(fea) or ""
    sz = fn_size(fea)
    log("   %s %s score=%d s50=%s s40=%s h28=%s h70=%s xmm=%d sz=0x%X rva=%s" % (
        hexs(fea), nm, score, s50, s40, h28, h70, xn, sz, hexs(rva(fea))))

# Decomp top 3 from this pass
for fea, score, _, _, _, _, _ in stride_pattern_candidates[:3]:
    nm = ida_funcs.get_func_name(fea) or ""
    sz = fn_size(fea)
    log("\n----- STRIDE_CANDIDATE %s %s sz=0x%X rva=%s -----" % (hexs(fea), nm, sz, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# =============================================================================
# SECTION 7 — Look at sub_1416BCE00 area (BSSkin::Instance binders / stream
# loaders) and look for any anchor that touches BoneData->boneArray reads.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 7 — BSSkin::BoneData (vt 0x14267E480) deep inspection")
log("=" * 80)

bd_refs = xrefs_to_data(BSI_BD_VT)
log(" code refs to BSSkin::BoneData vtable: %d" % len(bd_refs))
bd_fns = set()
for r in bd_refs:
    f = fn_start(r)
    if f != idaapi.BADADDR:
        bd_fns.add(f)
        nm = ida_funcs.get_func_name(f) or ""
        log("   ref %s in %s %s sz=0x%X rva=%s" % (hexs(r), hexs(f), nm, fn_size(f), hexs(rva(f))))

# Also dump BSSkin::BoneData vtable to identify any "ApplyToBuffer"-style virtuals
log("\n -- BSSkin::BoneData vtable (first 40 slots) --")
for i in range(40):
    slot_ea = BSI_BD_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    nm = ida_funcs.get_func_name(v) or ""
    sz = fn_size(v)
    log("   bd[%2d] %s %s sz=0x%X rva=%s" % (i, hexs(v), nm, sz, hexs(rva(v))))

# Decomp largest BoneData virtuals
log("\n -- Decomp BoneData largest virtuals --")
bd_slots = []
for i in range(40):
    slot_ea = BSI_BD_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    bd_slots.append((i, v, fn_size(v)))
bd_slots.sort(key=lambda x: -x[2])
for i, v, sz in bd_slots[:5]:
    nm = ida_funcs.get_func_name(v) or ""
    log("\n----- BoneData slot[%d] %s %s sz=0x%X -----" % (i, hexs(v), nm, sz))
    dec = safe_decompile(v)
    if dec:
        for ln in dec.split("\n")[:80]:
            log("   " + ln)

# =============================================================================
# SECTION 8 — sub_1404E87C0 (frame_tick child) callees that walk bones.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 8 — sub_1421B27D0 (render-thread inner) callee analysis")
log("=" * 80)

RENDER_INNER = 0x1421B27D0
dec = safe_decompile(RENDER_INNER)
if dec:
    log("\n -- decomp sub_1421B27D0 --")
    for ln in dec.split("\n")[:300]:
        log("   " + ln)

# =============================================================================
# Save log
# =============================================================================
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "(", len(out), "lines )")
idaapi.qexit(0)
