"""
M8P3 — AGENT A v2: Targeted hunt for the per-bone skin matrix upload pass.

Strategy refined based on v1 findings:
  - BSSkin::Instance vtable is empty (no skin update virtual)
  - BSGeometry slot 51/52/53 are the standard NetImmerse pre-render gates
  - The actual matrix multiply must be in a callee invoked from somewhere
    AFTER UpdateWorldData has filled bone+0x70

Key insights for v2:
  - The skin matrix array is uploaded via a D3D11 dynamic constant buffer.
  - 58 bones * 64 bytes = 3712 bytes (matches typical skin cb size).
  - The upload site MUST call ID3D11DeviceContext::Map (vt slot 14 = +0x70) or
    UpdateSubresource (vt slot 48 = +0x180).
  - Above the upload, the function loops over bones reading inv_bind from
    BoneData (stride 0x50, +0x10 offset) and bone.world from NiAVObject+0x70.

New strategies:
  1. Find functions calling ID3D11DeviceContext vt slot 14 (Map) by looking
     for "(*ctx)->lpVtbl[14]" patterns: indirect call through reg+0x70.
  2. Look for "SkinningCB" or "BoneTransforms" string references.
  3. Find functions that walk bones_pri (stride 8) AND boneData (stride 0x50)
     in the SAME LOOP — these are the perfect signature.
  4. Look at sub_1421B3110 + sub_1421B27D0 (render-thread inner) callees.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua
import struct
import re

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_update_AGENT_A_v2_raw.log"
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
BSI_VT     = 0x14267E5C8
BSGEOM_VT  = 0x14267E0B8
FRAME_TICK = 0x140C334B0
NIAVUWD    = 0x1416C85A0
MUL4X4     = 0x1403444F0

log("=" * 80)
log(" M8P3 SKIN UPDATE — AGENT A v2 (D3D11 + dual-stride hunt)")
log("=" * 80)

# =============================================================================
# SECTION 1 — Find string xrefs that hint at "Skin" / "Bone" / "Transform" CBs
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 1 — Skin/Bone string xrefs (cb names, debug names)")
log("=" * 80)

# Search the binary for likely skin-related identifier strings
search_strs = [
    "SkinningTransforms",
    "SkinTransforms",
    "BoneTransforms",
    "BoneMatrices",
    "Bones",
    "CB_Skin",
    "SkinCB",
    "PerSkin",
    "BSSkin",
    "SetBoneMatrix",
    "UpdateBoneMatrices",
    "SkinUpdate",
    "SkinningPass",
    "SkinShader",
]

def find_string_ea(s):
    # Search in .rdata/.data for an exact null-terminated string
    seg_data = ida_segment.get_segm_by_name(".rdata")
    if not seg_data: return []
    found = []
    cur = seg_data.start_ea
    target = s.encode('ascii') + b'\x00'
    while cur < seg_data.end_ea:
        ea = ida_bytes.find_bytes(target, cur)
        if ea == idaapi.BADADDR: break
        found.append(ea)
        cur = ea + 1
    return found

string_hits = []
for s in search_strs:
    eas = find_string_ea(s)
    for ea in eas:
        refs = xrefs_to_data(ea)
        for r in refs:
            f = fn_start(r)
            string_hits.append((s, ea, r, f))

log(" string hits: %d" % len(string_hits))
seen_funcs = set()
for s, sea, ref, fea in string_hits[:60]:
    if fea in seen_funcs: continue
    seen_funcs.add(fea)
    nm = ida_funcs.get_func_name(fea) or ""
    log("   '%s' @ %s ref %s in fn %s %s sz=0x%X" % (
        s, hexs(sea), hexs(ref), hexs(fea), nm, fn_size(fea)))

# =============================================================================
# SECTION 2 — Find functions that BOTH walk a stride-8 array (NiAVObject*[])
# AND a stride-0x50 array (BoneData entries) IN THE SAME LOOP.
# Signature: imul/lea with 0x50, AND additions of 8 to a separate loop var.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 2 — Dual-stride pattern (bones[] + boneData) in same fn")
log("=" * 80)

seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(seg.start_ea, seg.end_ea))
log(" total fns: %d" % len(fns))

dual_stride_candidates = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x80 or sz > 0xC00: continue
    cur = f.start_ea
    has_imul_50 = has_imul_40 = has_lea_50 = has_skin_28 = has_skin_38 = has_skin_40 = False
    has_70_read = has_xmm_4store = False
    xmm_writes = 0
    has_loop = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        ds_l = ds.lower()
        # Stride markers
        if "imul" in ds_l and "50h" in ds_l: has_imul_50 = True
        if "imul" in ds_l and ", 50" in ds_l: has_imul_50 = True
        if "imul" in ds_l and "40h" in ds_l: has_imul_40 = True
        if "lea" in ds_l and ("50h" in ds_l or "*5" in ds_l): has_lea_50 = True
        # Skin offsets
        if "+28h]" in ds: has_skin_28 = True
        if "+38h]" in ds: has_skin_38 = True
        if "+40h]" in ds: has_skin_40 = True
        if "+70h]" in ds: has_70_read = True
        # XMM writes
        if ("movups " in ds_l or "movaps " in ds_l) and "xmm" in ds_l:
            br = ds.find("[")
            xpos = ds.lower().find("xmm")
            if br > 0 and br < xpos:
                xmm_writes += 1
        # Loop check
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("jne","jnz","jl","jle","jg","jge","jb","jbe","ja","jae","loop"):
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt < cur and tgt >= f.start_ea:
                has_loop = True
        cur = idc.next_head(cur)
    # Score:
    #  Need at least: stride-50 evidence + +0x40 read + loop + xmm writes
    score = 0
    if has_imul_50 or has_lea_50: score += 4
    if has_skin_40: score += 3
    if has_skin_28: score += 2
    if has_skin_38: score += 1
    if has_70_read: score += 3
    if has_loop: score += 2
    if xmm_writes >= 4: score += 3
    if xmm_writes >= 8: score += 2
    if has_imul_40: score += 1
    if score >= 9:
        dual_stride_candidates.append((fea, sz, score, has_imul_50, has_imul_40, has_skin_40, has_skin_28, has_70_read, xmm_writes))

dual_stride_candidates.sort(key=lambda x: -x[2])
log(" dual-stride candidates (score >=9): %d" % len(dual_stride_candidates))
for fea, sz, score, s50, s40, h40, h28, h70, xn in dual_stride_candidates[:20]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X score=%d imul50=%s imul40=%s +40=%s +28=%s +70=%s xmm=%d rva=%s" % (
        hexs(fea), nm, sz, score, s50, s40, h40, h28, h70, xn, hexs(rva(fea))))

# Decomp top 5
for fea, sz, score, _, _, _, _, _, _ in dual_stride_candidates[:5]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- DUAL_STRIDE %s %s sz=0x%X score=%d rva=%s -----" % (
        hexs(fea), nm, sz, score, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        # Skip past variable declarations
        lines = dec.split("\n")
        # Find first { line and start logging from there
        start_i = 0
        for i, ln in enumerate(lines):
            if ln.strip().startswith("{") or "//" in ln:
                continue
            if "=" in ln or "(" in ln and ";" in ln:
                start_i = i
                break
        for ln in lines[:300]:
            log("   " + ln)

# =============================================================================
# SECTION 3 — D3D11 device context vt[14] (Map) and vt[48] (UpdateSubresource)
# Look for indirect calls "call qword ptr [reg+70h]" (Map) or [reg+180h]
# (UpdateSubresource) that would target the device ctx vtable.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 3 — D3D11 device context callsites (Map @+0x70, UpdateSubresource @+0x180)")
log("=" * 80)

map_callsites = []      # call qword ptr [rxx+70h]
us_callsites = []       # call qword ptr [rxx+180h]
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x80 or sz > 0x1500: continue
    cur = f.start_ea
    has_map_call = has_us_call = False
    # Also check if the function reads BSGraphics::Renderer or device ctx
    has_grafix = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem == "call":
            op0 = idc.print_operand(cur, 0).lower()
            # Indirect call through register offset
            if "qword ptr [" in op0:
                # Map = +0x70 (slot 14 * 8 = 0x70)
                if "+70h]" in op0: has_map_call = True
                # UpdateSubresource = +0x180 (slot 48 * 8 = 0x180)
                if "+180h]" in op0: has_us_call = True
        cur = idc.next_head(cur)
    if has_map_call or has_us_call:
        if has_map_call: map_callsites.append((fea, sz))
        if has_us_call: us_callsites.append((fea, sz))

log(" Map (+0x70) callsites: %d" % len(map_callsites))
for fea, sz in map_callsites[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

log(" UpdateSubresource (+0x180) callsites: %d" % len(us_callsites))
for fea, sz in us_callsites[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# Filter to "skin-relevant" callsites: those that ALSO read +0x40 (boneData)
# or +0x140 (BSGeometry skin slot) of some pointer.
log("\n -- Filtered Map callsites referencing skin offsets --")
filt_map = []
for fea, sz in map_callsites:
    f = ida_funcs.get_func(fea)
    cur = f.start_ea
    has_skin_offset = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+40h]" in ds or "+28h]" in ds or "+140h]" in ds:
            has_skin_offset = True; break
        cur = idc.next_head(cur)
    if has_skin_offset:
        filt_map.append((fea, sz))

for fea, sz in filt_map[:20]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# Decomp top 3 of these filtered candidates
log("\n -- Decomp top filtered Map callsites --")
for fea, sz in filt_map[:3]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- MAP_CB_CANDIDATE %s %s sz=0x%X rva=%s -----" % (
        hexs(fea), nm, sz, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:300]:
            log("   " + ln)

# =============================================================================
# SECTION 4 — Look at the actual SkinUpdate signature: if v3 = (skin*) and
# count = skin->+0x38, then the loop is "for (i=0; i<count; i++) { ... }"
# We can find this pattern via decomp of all functions referencing +0x38.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 4 — Functions using BSSkin::Instance count at +0x38 in loops")
log("=" * 80)

# +0x38 (decimal 56) is unique enough — narrow set
fns_with_38 = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x60 or sz > 0xA00: continue
    cur = f.start_ea
    has_38 = has_28 = has_40 = False
    has_loop_tied_to_38 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+38h]" in ds:
            has_38 = True
        if "+28h]" in ds: has_28 = True
        if "+40h]" in ds: has_40 = True
        cur = idc.next_head(cur)
    if has_38 and has_28 and has_40 and sz > 0x100:
        fns_with_38.append((fea, sz))

log(" fns with +0x38 + +0x28 + +0x40, size 0x100..0xA00: %d" % len(fns_with_38))
for fea, sz in fns_with_38[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# =============================================================================
# SECTION 5 — Look at the DUAL_STRIDE candidates more carefully — focus on
# decomps that show a SkinningPass-like signature.
# Specifically: each iteration reads bone (at +0x70 offset of pointed object)
# then computes mat*invBind and writes to a flat output.
# =============================================================================
# (Done inline above — section 2 already prints decomps.)

# =============================================================================
# SECTION 6 — Look at all callers of sub_1416D4F80 (BSGeometry vt slot 51,
# the largest virtual at size 0x279). It's the candidate "UpdateBound +
# WorldBoundCalc" virtual but might also drive skinning.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 6 — Callers of BSGeometry vt slot 51 (sub_1416D4F80)")
log("=" * 80)
slot51_callers = set()
for r in xrefs_to_code(0x1416D4F80):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        slot51_callers.add(f)
for fea in slot51_callers:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, fn_size(fea), hexs(rva(fea))))

# =============================================================================
# SECTION 7 — sub_1421B3110 (render-thread mid) callee tree: this is just
# above sub_1421B27D0 (inner). It's where per-geometry render dispatch happens.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 7 — sub_1421B3110 + callees (BSGeometry render dispatch)")
log("=" * 80)
RENDER_MID = 0x1421B3110
log("\n -- decomp sub_1421B3110 --")
dec = safe_decompile(RENDER_MID)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

# Section 7B: callees of sub_1421B3110 (functions called inside it)
log("\n -- callees of sub_1421B3110 --")
f = ida_funcs.get_func(RENDER_MID)
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

# =============================================================================
# Save log
# =============================================================================
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "(", len(out), "lines )")
idaapi.qexit(0)
