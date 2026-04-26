"""
M8P3 — Skin walker hunt.

Find the engine function(s) that WRITE per-frame 4x4 skinning matrices to
BSSkin::Instance bones_pri (skin+0x28). Engine pattern is:
    for i in 0..count(+0x38):
        bone     = bones_pri[i]                  (read +0x28 head + 8*i)
        invBind  = boneData[i].matrix            (read +0x40 -> +0x10 stride 0x50)
        out      = bone.world * invBind          (4x4 * 4x4 multiply)
        store at *(bones_pri+8*i) | bone+offset | a separate per-bone matrix

We don't know yet whether the result is stored AT bones_pri[i] (the entry IS a
matrix struct) or at *(bones_pri[i] + some_offset) (the entry points to a
NiAVObject which contains a matrix slot). The dossier from M8P3 has bones_pri
as NiAVObject** but a live test confirmed writes to bones_pri[i]'s 64-byte
target deform the mesh, so the layout differs from the load-time layout.

Strategy:
  1) Find xrefs to BSSkin::Instance vtable (0x14267E5C8) from .text.
  2) Find functions that read +0x28, +0x38, +0x40 from a BSSkin::Instance and
     contain XMM stores to a computed pointer (= writer candidates).
  3) Find xrefs to boneData inverse-bind (skin+0x40 -> +0x10) — those are
     READERS, then look at functions that BOTH read inv_bind AND write a 4x4
     somewhere. The unique ones are the walker.
  4) For each candidate, decompile and trace caller chain up to per-frame.
  5) Verify: cross-reference against the BSGeometry vtable (0x267E0B8) to find
     any virtual that would be called per-geom each frame.
  6) Look at ScenegraphRender / NiAVObject::UpdateWorldTransforms callers.

Output: re/_m8p3_skin_walker_raw.log
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw.log"
IMG = 0x140000000
out_lines = []
def log(s=""): out_lines.append(s if isinstance(s, str) else str(s))
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

def func_iter_instrs(f_ea):
    f = ida_funcs.get_func(f_ea)
    if not f: return
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        yield cur
        cur = idc.next_head(cur)

# -----------------------------------------------------------------------------
# Anchors
# -----------------------------------------------------------------------------
BSI_VT     = 0x14267E5C8     # BSSkin::Instance vtable
BSGEOM_VT  = 0x142_67E0B8    # BSGeometry vtable
BSTRI_VT   = 0x14267E948     # BSTriShape vtable
BSSITS_VT  = 0x142697D40     # BSSubIndexTriShape vtable
BSI_BD_VT  = 0x14267E480     # BSSkin::BoneData vtable
FRAME_TICK = 0x140C334B0     # per-frame tick

log("=" * 78)
log(" M8P3 SKIN WALKER HUNT")
log("=" * 78)
log(" BSSkin::Instance vt    = %s (RVA %s)" % (hexs(BSI_VT), hexs(rva(BSI_VT))))
log(" BSGeometry vt          = %s (RVA %s)" % (hexs(BSGEOM_VT), hexs(rva(BSGEOM_VT))))
log(" BSTriShape vt          = %s (RVA %s)" % (hexs(BSTRI_VT), hexs(rva(BSTRI_VT))))
log(" BSSubIndexTriShape vt  = %s (RVA %s)" % (hexs(BSSITS_VT), hexs(rva(BSSITS_VT))))
log(" BSSkin::BoneData vt    = %s (RVA %s)" % (hexs(BSI_BD_VT), hexs(rva(BSI_BD_VT))))

# -----------------------------------------------------------------------------
# SECTION A — All xrefs from code to BSSkin::Instance vtable
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION A — code refs to BSSkin::Instance vtable (ctors, dtors, virtuals)")
log("=" * 78)

bsi_refs = xrefs_to_data(BSI_VT)
log(" total: %d refs" % len(bsi_refs))
for r in bsi_refs:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   ref %s in %s %s" % (hexs(r), hexs(f), nm))

# -----------------------------------------------------------------------------
# SECTION B — Find functions that contain instructions touching BOTH
#             [reg+28h] (bones_pri) AND [reg+38h] (bones count) AND [reg+40h] (boneData)
#             of what we believe is a BSSkin::Instance.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — heuristic scan: functions referencing +0x28, +0x38, +0x40 together")
log("=" * 78)

# Iterate every function in .text. Track instructions that contain "+28h", "+38h", "+40h" displacements.
seg = ida_segment.get_segm_by_name(".text")
text_start = seg.start_ea
text_end = seg.end_ea

candidates_b = []  # (func_ea, hits_28, hits_38, hits_40, hits_xmm_store)
processed = 0
fns = list(idautils.Functions(text_start, text_end))
log(" total functions in .text: %d" % len(fns))

# We don't want to scan ALL functions (too slow). Filter via a pre-screening:
# functions that have at least one "+28h" displacement reference get scanned in detail.
# We collect them based on disasm.

# First pass: find functions with "+28h]" in disasm
fns_with_28 = set()
fns_with_38 = set()
fns_with_40 = set()

for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    has_28 = has_38 = has_40 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+28h]" in ds: has_28 = True
        if "+38h]" in ds: has_38 = True
        if "+40h]" in ds: has_40 = True
        if has_28 and has_38 and has_40: break
        cur = idc.next_head(cur)
    if has_28 and has_38 and has_40:
        candidates_b.append(fea)

log(" functions touching +0x28, +0x38, +0x40 simultaneously: %d" % len(candidates_b))

# Filter further: must contain XMM movups/movaps writes (matrix store pattern)
candidates_b_xmm = []
for fea in candidates_b:
    f = ida_funcs.get_func(fea)
    if not f: continue
    xmm_writes = 0
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        # look for "movups [rxx+...], xmmN" or "movaps [..], xmmN"
        if ("movups " in ds or "movaps " in ds) and "xmm" in ds and "[" in ds:
            # Find a leading destination operand pattern
            # Format "movups xmmword ptr [r..+...], xmm0"
            if ds.find("[") < ds.rfind("xmm"):
                # destination is memory? check token order
                pass
            # heuristic: bracket comes BEFORE xmm => store
            br = ds.find("[")
            xpos = ds.find("xmm")
            if br < xpos and xpos > 0:
                xmm_writes += 1
        cur = idc.next_head(cur)
    if xmm_writes >= 4:  # need at least 4 stores (4 rows of a 4x4)
        candidates_b_xmm.append((fea, xmm_writes))

candidates_b_xmm.sort(key=lambda x: -x[1])
log(" of those, with >=4 XMM stores: %d" % len(candidates_b_xmm))
for fea, xn in candidates_b_xmm[:20]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s xmm_writes=%d" % (hexs(fea), nm, xn))

# -----------------------------------------------------------------------------
# SECTION C — Find functions that call sub_1403444F0 (4x4 mul) AND read
#             from a BSSkin::Instance-like pattern (+0x40 then +0x10)
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — callers of sub_1403444F0 (4x4 multiply)")
log("=" * 78)

mul4x4 = 0x1403444F0
mul4x4_refs = xrefs_to_code(mul4x4)
log(" callers of sub_1403444F0: %d" % len(mul4x4_refs))
seen_callers = set()
for r in mul4x4_refs:
    f = fn_start(r)
    if f in seen_callers: continue
    seen_callers.add(f)
    nm = ida_funcs.get_func_name(f) or ""
    log("   call @ %s in %s %s (rva %s)" % (hexs(r), hexs(f), nm, hexs(rva(f))))
log(" unique callers: %d" % len(seen_callers))

# -----------------------------------------------------------------------------
# SECTION D — Look at virtual functions on BSSkin::Instance vtable (40 slots)
#             and on BSGeometry vtable. Each slot may have a per-frame walker.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — vtable contents (BSSkin::Instance, BSGeometry, BSTriShape)")
log("=" * 78)

def dump_vtable(vt_ea, name, slots=64):
    log("\n -- %s @ %s --" % (name, hexs(vt_ea)))
    for i in range(slots):
        slot_ea = vt_ea + i * 8
        v = ida_bytes.get_qword(slot_ea)
        if not v or v < IMG or v > IMG + 0x4000000:
            break
        nm = ida_funcs.get_func_name(v) or ""
        log("   slot[%2d] %s -> %s %s (rva %s)" % (i, hexs(slot_ea), hexs(v), nm, hexs(rva(v))))

dump_vtable(BSI_VT, "BSSkin::Instance", 40)
dump_vtable(BSGEOM_VT, "BSGeometry", 60)
dump_vtable(BSTRI_VT, "BSTriShape", 80)
dump_vtable(BSSITS_VT, "BSSubIndexTriShape", 80)

# -----------------------------------------------------------------------------
# SECTION E — Decompile the top XMM-write candidates
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — Decompilations of top candidates")
log("=" * 78)

DECOMP_LIMIT = 8
for fea, xn in candidates_b_xmm[:DECOMP_LIMIT]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- %s %s (xmm_stores=%d, rva=%s) -----" % (hexs(fea), nm, xn, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        lines = dec.split("\n")
        # Limit to 200 lines per fn
        for ln in lines[:200]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION F — Find direct WRITES to memory at displacement 0x28 from a BSSkin::Instance.
# Look for "mov [rxx+28h], rXX" instructions, but filter by: function must also touch
# either the BSI vtable, or BSI ctor calls, or +0x40 reads, etc.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION F — memory WRITES to [reg+0x28] near BSSkin::Instance refs")
log("=" * 78)

# Collect all functions that already showed up via SECTION A (BSI vtable refs)
fns_via_vt = set()
for r in bsi_refs:
    f = fn_start(r)
    if f != idaapi.BADADDR:
        fns_via_vt.add(f)

log(" functions touching BSSkin::Instance vtable: %d" % len(fns_via_vt))

writes_28 = []
for fea in fns_via_vt:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        # Looking for stores: mov/movups [xxx+28h], yyy
        # IDA disasm has "+28h]" at the END after the displacement
        if "+28h]" in ds:
            low = ds.lower()
            # Mnemonic check: store == destination is memory
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("mov", "movups", "movaps", "movdqa", "movq"):
                # Check if first operand is memory
                op0 = idc.print_operand(cur, 0)
                if "[" in op0 and "+28h" in op0.lower():
                    writes_28.append((cur, fea, ds))
        cur = idc.next_head(cur)

log(" writes to [reg+0x28] inside BSI-touching functions: %d" % len(writes_28))
for cur, fea, ds in writes_28[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s [in %s %s]  %s" % (hexs(cur), hexs(fea), nm, ds))

# -----------------------------------------------------------------------------
# SECTION G — Examine BSGeometry vtable and find candidates for "per-frame
# update" (typical NiAVObject vt slots: 0x68 (Update), 0x70 (UpdateProperties),
# 0x78 (UpdateRigid), or render-time virtuals around slot 30-40).
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION G — Inspect BSGeometry vtable slots that look like per-frame updates")
log("=" * 78)

# Print first 50 slots of BSGeometry vtable, decompile each into a one-liner header
for i in range(60):
    slot_ea = BSGEOM_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    nm = ida_funcs.get_func_name(v) or ""
    sz = 0
    f = ida_funcs.get_func(v)
    if f: sz = f.end_ea - f.start_ea
    log("   bsgeom[%2d] %s %s rva=%s size=0x%X" % (i, hexs(v), nm, hexs(rva(v)), sz))

# -----------------------------------------------------------------------------
# SECTION H — Search the binary for the constant "10 * idx" (lea reg, [rax+rax*4])
# that we know boneData uses for stride 0x50, AND check what stores follow the read.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION H — Find boneData reads (stride 0x50) and trace what stores 4 xmms")
log("=" * 78)

# We'll scan functions that contain BOTH:
#   - a read from [reg+40h] (boneData ptr from skin)
#   - a read from [reg+10h] (boneData->boneArray head)
#   - a 0x50 stride (lea reg, [reg+rax*4 + ...] or imul reg, 0x50 / shifts)
candidates_h = []
for fea in fns_via_vt:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    has_40 = has_10_after_40 = has_stride_50 = False
    last_was_40 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+40h]" in ds: has_40 = True; last_was_40 = True
        if last_was_40 and "+10h]" in ds: has_10_after_40 = True
        # Stride markers: imul Xh,50h, or shl,then add (0x50 = 80 = 64+16)
        if "imul" in ds and "50h" in ds: has_stride_50 = True
        if "imul" in ds and ", 50" in ds: has_stride_50 = True
        if "lea" in ds and "*8" in ds and "*5" in ds: has_stride_50 = True  # weak
        cur = idc.next_head(cur)
    if has_40 and has_10_after_40:
        candidates_h.append(fea)

log(" candidates touching skin+0x40 then deref +0x10 (boneData reads): %d" % len(candidates_h))
for fea in candidates_h[:20]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s rva=%s" % (hexs(fea), nm, hexs(rva(fea))))

# -----------------------------------------------------------------------------
# SECTION I — sub_14040D4C0 callers chain UP (look at what calls into it,
# then up to per-frame). These are anim/skin orchestrators.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION I — Caller chain UP from sub_14040D4C0 (and its iterators)")
log("=" * 78)

def upchain(start_ea, depth):
    seen = set()
    queue = [(start_ea, 0)]
    while queue:
        ea, d = queue.pop(0)
        if ea in seen or d > depth: continue
        seen.add(ea)
        nm = ida_funcs.get_func_name(ea) or ""
        log("   %s %sea=%s %s rva=%s" % ("  " * d, "fn ", hexs(ea), nm, hexs(rva(ea))))
        if d >= depth: continue
        for r in xrefs_to_code(ea):
            f = fn_start(r)
            if f != idaapi.BADADDR:
                queue.append((f, d + 1))

log("\n -- chain up from sub_14040D4C0 --")
upchain(0x14040D4C0, 4)

log("\n -- chain up from sub_140407C80 (iterator caller) --")
upchain(0x140407C80, 3)

log("\n -- chain up from sub_140408EB0 (iterator caller 2) --")
upchain(0x140408EB0, 3)

# -----------------------------------------------------------------------------
# SECTION J — BSSkin::Instance has 40-ish vt slots; one of them is likely the
# per-frame "UpdateBones" or "ApplySkinTransforms" call. Print decomp of a few.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION J — Decomp of BSSkin::Instance vtable slots that look big")
log("=" * 78)

vt_slot_eas = []
for i in range(40):
    slot_ea = BSI_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000:
        break
    f = ida_funcs.get_func(v)
    sz = (f.end_ea - f.start_ea) if f else 0
    vt_slot_eas.append((i, v, sz))

# Sort by size descending; bigger functions are more likely to be the walker
vt_slot_eas.sort(key=lambda x: -x[2])
log(" largest BSI vt slots:")
for i, v, sz in vt_slot_eas[:10]:
    nm = ida_funcs.get_func_name(v) or ""
    log("   slot[%2d] %s %s size=0x%X" % (i, hexs(v), nm, sz))

# Print decomp of top 5 by size
for i, v, sz in vt_slot_eas[:5]:
    nm = ida_funcs.get_func_name(v) or ""
    log("\n----- BSI vt slot[%d] %s %s (size=0x%X) -----" % (i, hexs(v), nm, sz))
    dec = safe_decompile(v)
    if dec:
        lines = dec.split("\n")
        for ln in lines[:120]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION K — DECOMP sub_140408EB0 (already known iterator caller of D4C0)
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION K — Decomp sub_140408EB0 (iterator caller of D4C0)")
log("=" * 78)

dec = safe_decompile(0x140408EB0)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

# Same for sub_140407C80
log("\n -- sub_140407C80 --")
dec = safe_decompile(0x140407C80)
if dec:
    for ln in dec.split("\n")[:120]:
        log("   " + ln)

# -----------------------------------------------------------------------------
# Save
# -----------------------------------------------------------------------------
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines )")
idaapi.qexit(0)
