"""
M8P3 v6 — DEEP DIVE on the per-frame world transform walker.

CONFIRMED so far:
  - sub_1416C85A0 at slot 53 of NiAVObject and all derived vtables
    (53 * 8 = 0x1A8 vtable offset). It's NiAVObject::UpdateWorldData
    (composes parent.world * local = world for ONE node).
  - The walker chain to per-frame:
       sub_1416C85A0  -> ... -> sub_1421B27D0 -> sub_1404E87C0 -> sub_140C334B0

We want the function that calls UpdateWorldData FOR EACH BONE. Likely it's
NiNode::UpdateDownwardPass (a recursive walker) or BSScene::Update.

This script:
  1) Decompile sub_1421B27D0, sub_1421B3110, sub_1421B69D0, sub_1421B5D80
  2) Decompile sub_1404E87C0 (frame_tick child)
  3) Find the function that LOOPS over skeleton bones (one of the wrappers
     of sub_1416C85A0 that takes a NiNode and recurses on its children).
  4) Extract NiNode::UpdateWorldData (the recursive walker) - that IS what
     overwrites bone world transforms each frame.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw6.log"
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
def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception as e:
        return "<decomp error: %s>" % e
def xrefs_to_code(ea):
    refs = []
    x = ida_xref.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_cref_to(ea, x)
    return refs

# -----------------------------------------------------------------------------
# SECTION A — Look at the BSScenegraph hierarchy by walking the path
# sub_1404E87C0 -> sub_1421B27D0 -> sub_1421B3110 -> sub_1421B69D0
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — Path inspection: scenegraph render walker")
log("=" * 78)

PATH = [0x1404E87C0, 0x1421B27D0, 0x1421B3110, 0x1421B69D0]
for ea in PATH:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("\n----- %s %s sz=0x%X rva=%s -----" % (hexs(ea), nm, sz, hexs(rva(ea))))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION B — Look for NiNode::UpdateWorldData (recursive walker on children).
# Pattern: a function that calls some Update virtual via vt[53]=>0x1A8 offset
# AND then iterates child[] of node.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — Find recursive UpdateWorldData (NiNode override)")
log("=" * 78)

# The overrides at slot 53 (we found 36 vtables). The OVERRIDE in NiNode does:
#   1. Call NiAVObject::UpdateWorldData (via base, or inline)
#   2. For each child: child->vt[53]() (recursive)
# Let's find such a function.

# All other functions appearing at slot 53 - let's find them.
# Check the original list again and look for one that has a loop calling vt[53] virtually.

NINODE_ALIKE_OVERRIDES = []
seg_rdata = idaapi.get_segm_by_name(".rdata")
target = 0x1416C85A0

# The vtables containing target at slot 53 - we know there are 36. The overrides
# are AT slot 53 of vtables that DON'T have target = sub_1416C85A0 at slot 53,
# but instead have a class-specific function.

# To enumerate: scan all vtables and read slot 53. Group by function value.
# Heuristic: vtables of NiAVObject derivatives have sub_1416C85A0 at slot 53.
# Some derivatives have a different function at slot 53 (override).

# Find every "vtable" (= sequence of >= 30 function pointers in .rdata).
log("\n -- enumerate slot-53 functions across vtables --")

# Naive enumeration: iterate .rdata, find runs of pointers >= 30
slot53_fns = {}
if seg_rdata:
    cur = seg_rdata.start_ea
    while cur < seg_rdata.end_ea:
        # check if this position starts a vtable
        vt_start = cur
        run = 0
        while cur < seg_rdata.end_ea:
            v = ida_bytes.get_qword(cur)
            if v and IMG <= v < IMG + 0x4000000:
                run += 1
                cur += 8
            else:
                break
        if run >= 30:
            # vt_start is a vtable
            if 53 < run:
                slot53_val = ida_bytes.get_qword(vt_start + 53 * 8)
                slot53_fns.setdefault(slot53_val, []).append(vt_start)
        else:
            cur += 8

log(" unique slot-53 functions: %d" % len(slot53_fns))
for fn, vts in sorted(slot53_fns.items(), key=lambda kv: -len(kv[1])):
    if not fn or fn == 0: continue
    nm = ida_funcs.get_func_name(fn) or ""
    fobj = ida_funcs.get_func(fn)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s (#vtables=%d) sz=0x%X" % (hexs(fn), nm, len(vts), sz))

# -----------------------------------------------------------------------------
# SECTION C — For the overrides at slot 53, decompile each one and see if it
# loops over children and recursively calls vt[53] (i.e., it's NiNode::UpdateWorldData).
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — Decompile slot-53 OVERRIDES (non-1416C85A0 versions)")
log("=" * 78)

for fn, vts in sorted(slot53_fns.items(), key=lambda kv: -len(kv[1])):
    if not fn or fn == target or fn == 0: continue  # skip base
    nm = ida_funcs.get_func_name(fn) or ""
    fobj = ida_funcs.get_func(fn)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    if sz < 0x40 or sz > 0xC00:
        continue
    log("\n----- %s %s (sz=0x%X, #vt=%d) -----" % (hexs(fn), nm, sz, len(vts)))
    # Show what RTTI types these vtables represent
    for vt in vts[:5]:
        col = ida_bytes.get_qword(vt - 8)
        if col and IMG <= col < IMG + 0x4000000:
            try:
                td_rva = ida_bytes.get_dword(col + 0x0C)
                tn = idc.get_strlit_contents(IMG + td_rva + 0x10, -1, 0)
                if tn:
                    log("     vt=%s rtti=%s" % (hexs(vt), tn.decode("ascii", errors="replace")))
            except: pass
    dec = safe_decompile(fn)
    if dec:
        for ln in dec.split("\n")[:120]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION D — Check if NiNode RTTI string at 0x142F99810 has a vtable nearby.
# RTTI string is the "TypeDescriptor" - the COL points at it. Find the COL
# that points at NiNode TypeDescriptor.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — locate NiNode vtable via RTTI cross-reference")
log("=" * 78)

# Find the typedesc-string containing "NiNode" - the typedesc is the bytes
# starting 16 bytes BEFORE the string (a TypeDescriptor has +0x00 vtable, +0x08 spare,
# +0x10 string). The string is at 0x142F99810.
ninode_str_ea = 0x142F99810  # ".?AVNiNode@@" starts here per Section A (raw5)
typedesc_ea = ninode_str_ea - 0x10  # type descriptor start
log(" putative NiNode TypeDescriptor at %s" % hexs(typedesc_ea))

# Search for any DWORD in .rdata equal to (typedesc_ea - IMG) at offset 0xC of a
# COL structure. COL has typedesc at offset +0xC (RVA).
target_rva = typedesc_ea - IMG
log(" searching for COL with typedesc RVA = 0x%X" % target_rva)

cols = []
if seg_rdata:
    cur = seg_rdata.start_ea
    end = seg_rdata.end_ea
    while cur < end:
        v = ida_bytes.get_dword(cur)
        if v == target_rva:
            cols.append(cur - 0xC)  # subtract offset to get COL start
        cur += 4

log(" found %d possible COLs" % len(cols))
for col in cols[:5]:
    # Find the vtable that points at this COL: the previous qword to the vtable
    # equals the COL address.
    # Search for any qword in .rdata equal to col.
    vt = None
    if seg_rdata:
        cur = seg_rdata.start_ea
        while cur < seg_rdata.end_ea:
            if ida_bytes.get_qword(cur) == col:
                vt = cur + 8  # vtable starts right after COL ptr
                break
            cur += 8
    if vt:
        log(" COL @ %s -> vtable @ %s" % (hexs(col), hexs(vt)))
        # Dump first 70 slots of this vtable
        for i in range(70):
            slot = ida_bytes.get_qword(vt + i * 8)
            if not slot or not (IMG <= slot < IMG + 0x4000000):
                break
            nm = ida_funcs.get_func_name(slot) or ""
            log("   slot[%2d] %s %s" % (i, hexs(slot), nm))

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines)")
idaapi.qexit(0)
