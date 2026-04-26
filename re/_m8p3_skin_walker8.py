"""
M8P3 v8 — Final identification of skin walker chain.

CONFIRMED:
  sub_1416C85A0 = NiAVObject::UpdateWorldData (writes world matrix at NiAVObject+0x70)
  sub_1416BF1C0 = candidate NiNode::UpdateWorldData (recursive child walker)
                  - reads children[] at +0x128 (offset 296)
                  - reads children count at +0x132 (offset 306)
                  - calls vt[+0x1A8] = slot 53 on each child

Now we need to:
  1) Confirm sub_1416BF1C0 by checking its content (does it ALSO call NiAVObject::UpdateWorldData?)
  2) Find sub_1416BF1C0's vt slot — which class overrides slot 53 with this?
  3) Trace UPCHAIN to per-frame entry
  4) Decompile fully sub_1416BF1C0
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw8.log"
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
# Section A — sub_1416BF1C0 full decomp + call locations
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — sub_1416BF1C0 detail (NiNode::UpdateWorldData candidate)")
log("=" * 78)

ea = 0x1416BF1C0
nm = ida_funcs.get_func_name(ea) or ""
f = ida_funcs.get_func(ea)
sz = (f.end_ea - f.start_ea) if f else 0
log(" %s %s sz=0x%X rva=%s" % (hexs(ea), nm, sz, hexs(rva(ea))))
dec = safe_decompile(ea)
if dec:
    for ln in dec.split("\n"):
        log("   " + ln)

# Check: is it AT slot 53 of any vtable?
log("\n -- vt slot positions of sub_1416BF1C0 --")
seg_rdata = idaapi.get_segm_by_name(".rdata")
positions = []
if seg_rdata:
    cur = seg_rdata.start_ea
    while cur < seg_rdata.end_ea:
        v = ida_bytes.get_qword(cur)
        if v == ea:
            positions.append(cur)
        cur += 8
log(" #positions: %d" % len(positions))
for pos in positions[:10]:
    # walk back
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
            td_rva = ida_bytes.get_dword(col + 0x0C)
            tn = idc.get_strlit_contents(IMG + td_rva + 0x10, -1, 0)
            if tn: typedesc_str = tn.decode("ascii", errors="replace")
        except: pass
    log("   pos=%s vt=%s slot=%d rtti=%s" % (hexs(pos), hexs(vt_start), slot_num, typedesc_str))

# -----------------------------------------------------------------------------
# Section B — UPCHAIN from sub_1416BF1C0 to find frame_tick anchor
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — upchain from sub_1416BF1C0")
log("=" * 78)

PER_FRAME = {
    0x140C334B0: "frame_tick",
    0x140C30FD0: "main_loop",
    0x140BD5320: "scene_render?",
    0x140C00590: "scene_render2?",
    0x1404E87C0: "ft_inner1",
    0x1421B27D0: "render_inner",
    0x1421B69D0: "scenegraph_render?",
    0x1402CDDD0: "PC_update",
    0x140CE1720: "?",
}

def upchain(start_ea, max_depth=12, max_breadth=4000):
    found_anchors = []
    seen = set([start_ea])
    queue = [(start_ea, 0, [start_ea])]
    while queue and len(seen) < max_breadth:
        e, d, path = queue.pop(0)
        if e in PER_FRAME:
            found_anchors.append((e, d, path))
        if d >= max_depth: continue
        for r in xrefs_to_code(e):
            ff = fn_start(r)
            if ff == idaapi.BADADDR or ff in seen: continue
            seen.add(ff)
            queue.append((ff, d + 1, path + [ff]))
    return found_anchors, seen

anchors, seen = upchain(0x1416BF1C0, 14, 5000)
log(" upchain visited %d unique callers; anchors: %d" % (len(seen), len(anchors)))
for ea2, d, path in anchors[:10]:
    log("\n -- anchor %s (%s) at depth %d --" % (hexs(ea2), PER_FRAME.get(ea2, "?"), d))
    log("    path: %s" % " -> ".join([hexs(p) for p in path]))

# -----------------------------------------------------------------------------
# Section C — Find what triggers sub_1416BF1C0 from a per-frame entry.
# Decompile the IMMEDIATE caller (depth 1) to confirm it kicks off the walk.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — direct callers of sub_1416BF1C0")
log("=" * 78)

direct = set()
for r in xrefs_to_code(0x1416BF1C0):
    fea = fn_start(r)
    if fea != idaapi.BADADDR:
        direct.add(fea)
log(" direct callers: %d" % len(direct))
for fea in direct:
    nm = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s sz=0x%X" % (hexs(fea), nm, sz))

# -----------------------------------------------------------------------------
# Section D — Get the SAME information for sub_1404E5B40 (alt walker)
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — sub_1404E5B40 (alt walker) detail")
log("=" * 78)

ea = 0x1404E5B40
log(" %s %s sz=0x%X rva=%s" % (hexs(ea), ida_funcs.get_func_name(ea) or "",
    ida_funcs.get_func(ea).end_ea - ida_funcs.get_func(ea).start_ea, hexs(rva(ea))))

# vt slots
positions = []
if seg_rdata:
    cur = seg_rdata.start_ea
    while cur < seg_rdata.end_ea:
        v = ida_bytes.get_qword(cur)
        if v == ea:
            positions.append(cur)
        cur += 8
log(" #positions in vtables: %d" % len(positions))
for pos in positions[:10]:
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
            td_rva = ida_bytes.get_dword(col + 0x0C)
            tn = idc.get_strlit_contents(IMG + td_rva + 0x10, -1, 0)
            if tn: typedesc_str = tn.decode("ascii", errors="replace")
        except: pass
    log("   pos=%s vt=%s slot=%d rtti=%s" % (hexs(pos), hexs(vt_start), slot_num, typedesc_str))

# Also print direct callers
log("\n -- direct callers of sub_1404E5B40 --")
for r in xrefs_to_code(0x1404E5B40):
    fea = fn_start(r)
    if fea == idaapi.BADADDR: continue
    nm = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s sz=0x%X" % (hexs(fea), nm, sz))

# -----------------------------------------------------------------------------
# Section E — Now look at sub_1416BEAC0 (sz 0x1F1) and sub_141AC9FC0 (sz 0x2BB) -
# slot-53 functions that might be NiNode-like.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — Slot-53 candidates: 1416BEAC0, 141AC9FC0")
log("=" * 78)

for ea in [0x1416BEAC0, 0x141AC9FC0]:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("\n----- %s %s sz=0x%X -----" % (hexs(ea), nm, sz))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:120]:
            log("   " + ln)

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines)")
idaapi.qexit(0)
