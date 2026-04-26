"""
M8P3 v7 — Final dossier prep.

Verify: sub_1416C85A0 = NiAVObject::UpdateWorldData (writes world at +0x70)
Identify: NiNode override (recursive walker) — slot 53 of NiNode vtable
Identify: per-frame entry point that triggers full skeleton walk

Key checks:
  - Decompile sub_1416C8A60 (BSGeometry slot 53)
  - Check what calls it (and whether it loops over children)
  - Find BSScene::UpdateWorld / NiNode::UpdateWorldData override
  - Walk down from sub_1404E87C0 (frame_tick child) to find what triggers
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw7.log"
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
# Section A — Decompile slot 53 functions on BSGeometry vt and similar
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — slot 53 + nearby for BSGeometry / NiAVObject")
log("=" * 78)

# BSGeometry vt (0x14267E0B8) slot 53 = +53*8 = +0x1A8 -> 0x14267E260
# Let's read this slot directly:
slot53_bsgeom = ida_bytes.get_qword(0x14267E0B8 + 53 * 8)
log(" BSGeometry vt slot 53 = %s (=%s)" % (hexs(slot53_bsgeom), ida_funcs.get_func_name(slot53_bsgeom) or "?"))

# Now examine the whole BSGeometry vt around slot 53:
log("\n -- BSGeometry vt slots 50..60 --")
for i in range(50, 60):
    v = ida_bytes.get_qword(0x14267E0B8 + i * 8)
    nm = ida_funcs.get_func_name(v) or ""
    f = ida_funcs.get_func(v)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("   slot[%d] %s %s sz=0x%X" % (i, hexs(v), nm, sz))

# Decomp slot 53 of BSGeometry vt:
log("\n -- Decomp BSGeometry vt slot 53 --")
dec = safe_decompile(slot53_bsgeom)
if dec:
    for ln in dec.split("\n")[:60]:
        log("   " + ln)

# -----------------------------------------------------------------------------
# Section B — check sub_1416C85A0 directly: it's the function that writes
# world transform at NiAVObject+0x70. Confirm vt slot via xref count.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — confirm sub_1416C85A0 is NiAVObject::UpdateWorldData")
log("=" * 78)

# Find which BSGeometry slot points at sub_1416C85A0:
target = 0x1416C85A0
# scan all slots 0..70 of BSGeometry vt
for i in range(70):
    v = ida_bytes.get_qword(0x14267E0B8 + i * 8)
    if v == target:
        log(" BSGeometry vt has 1416C85A0 at slot %d" % i)

# Check NiAVObject base vt: derive from a vtable that DOESN'T override slot 53
# i.e. has 1416C85A0 at slot 53. Find one.
log("\n -- check vtables containing 1416C85A0 --")
seg_rdata = idaapi.get_segm_by_name(".rdata")
positions = []
if seg_rdata:
    cur = seg_rdata.start_ea
    while cur < seg_rdata.end_ea:
        v = ida_bytes.get_qword(cur)
        if v == target:
            positions.append(cur)
        cur += 8
log(" #vtable positions: %d" % len(positions))

# For first 5 positions, identify vtable origin (boundary scan)
for pos in positions[:5]:
    # walk backward
    boundary = pos
    while boundary - 8 >= seg_rdata.start_ea:
        v = ida_bytes.get_qword(boundary - 8)
        if not (v and IMG <= v < IMG + 0x4000000):
            break
        boundary -= 8
    vt_start = boundary
    slot_num = (pos - vt_start) // 8
    col = ida_bytes.get_qword(vt_start - 8)
    typedesc_str = "?"
    if col and IMG <= col < IMG + 0x4000000:
        try:
            typedesc_rva = ida_bytes.get_dword(col + 0x0C)
            tname = idc.get_strlit_contents(IMG + typedesc_rva + 0x10, -1, 0)
            if tname: typedesc_str = tname.decode("ascii", errors="replace")
        except:
            pass
    log("  pos=%s vt=%s slot=%d rtti=%s" % (hexs(pos), hexs(vt_start), slot_num, typedesc_str))

# -----------------------------------------------------------------------------
# Section C — Find NiNode vtable + locate the recursive UpdateWorldData override
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — search for NiNode-like override (recursive child walker)")
log("=" * 78)

# Heuristic: a recursive walker (NiNode::UpdateWorldData) calls the BASE
# (sub_1416C85A0 or its own logic) AND then iterates children at +0x128 with
# count at +0x130, calling vt[X] on each child.
#
# Pattern:
#   v3 = a1+128h   ; head ptr to children
#   v4 = a1+130h   ; count
#   for i in 0..v4:
#       child = v3[i]
#       child->vt[X](a2)
#
# We want to find a function that:
#   - calls sub_1416C85A0 (recursively or via vt) OR has the world-transform write pattern
#   - loops over children at +0x128
#   - calls a virtual via +0x1A8 (slot 53)

# Search pattern: callers of sub_1416C85A0 that ALSO have a loop with virtual call
log("\n -- callers of sub_1416C85A0 --")
direct_callers = set()
for r in xrefs_to_code(target):
    fea = fn_start(r)
    if fea != idaapi.BADADDR:
        direct_callers.add(fea)

for fea in direct_callers:
    nm = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    # look for "+128h]" and "+130h]" disasm
    cur = fobj.start_ea if fobj else 0
    has_128 = has_130 = has_1a8 = False
    while cur < (fobj.end_ea if fobj else 0) and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+128h]" in ds: has_128 = True
        if "+130h]" in ds: has_130 = True
        if "+1a8h]" in ds: has_1a8 = True
        cur = idc.next_head(cur)
    flags = []
    if has_128: flags.append("c128")
    if has_130: flags.append("c130")
    if has_1a8: flags.append("vt53")
    log("   %s %s sz=0x%X flags=[%s]" % (hexs(fea), nm, sz, ",".join(flags)))

# Decomp those that have all three
log("\n -- decomp callers with c128+c130+vt53 (recursive walker) --")
for fea in direct_callers:
    fobj = ida_funcs.get_func(fea)
    if not fobj: continue
    cur = fobj.start_ea
    has_128 = has_130 = has_1a8 = False
    while cur < fobj.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+128h]" in ds: has_128 = True
        if "+130h]" in ds: has_130 = True
        if "+1a8h]" in ds: has_1a8 = True
        cur = idc.next_head(cur)
    if not (has_128 or has_130):
        continue
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n  -- %s %s --" % (hexs(fea), nm))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:120]:
            log("   " + ln)

# Try a broader search: any function in the binary that calls sub_1416C85A0 directly
# OR has a loop calling vt[+0x1A8] (slot 53)
log("\n" + "=" * 78)
log(" SECTION D — search for recursive walker (vt+1a8 calls)")
log("=" * 78)

text_seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(text_seg.start_ea, text_seg.end_ea))

walker_candidates = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x40 or sz > 0x600: continue
    cur = f.start_ea
    has_1a8_call = False
    has_128 = has_130 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        # virtual call via offset +1A8
        if "1a8h]" in ds and ("call" in idc.print_insn_mnem(cur).lower()):
            has_1a8_call = True
        if "+128h]" in ds: has_128 = True
        if "+130h]" in ds: has_130 = True
        cur = idc.next_head(cur)
    if has_1a8_call and (has_128 or has_130):
        walker_candidates.append((fea, sz))

walker_candidates.sort(key=lambda x: x[1])
log(" candidates calling vt[1A8] (slot 53) AND iterating children: %d" % len(walker_candidates))
for fea, sz in walker_candidates[:20]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# Decomp top 5
for fea, sz in walker_candidates[:5]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- %s %s sz=0x%X -----" % (hexs(fea), nm, sz))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:120]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# Section E — tighter trace: find the FRAME-TICK level entry that invokes
# scenegraph world-transform update. Look at sub_1404E87C0 (already found) callees.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — decomp sub_1404E87C0 fully + its callees")
log("=" * 78)

ea = 0x1404E87C0
nm = ida_funcs.get_func_name(ea) or ""
f = ida_funcs.get_func(ea)
sz = (f.end_ea - f.start_ea) if f else 0
log(" sub_1404E87C0 sz=0x%X" % sz)
dec = safe_decompile(ea)
if dec:
    for ln in dec.split("\n")[:300]:
        log("   " + ln)

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines)")
idaapi.qexit(0)
