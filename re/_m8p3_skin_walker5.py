"""
M8P3 — Skin walker hunt v5: NiAVObject world transform writer.

Hypothesis revised: the user's "bones_pri[i] writes deform mesh" means the
shader uses the bones referenced by bones_pri[i] (as pointers to NiAVObjects)
and reads each bone's WORLD MATRIX (typically NiAVObject+0x70). The engine's
per-frame walker that overwrites the user's writes is NiAVObject::UpdateWorldData
applied to each bone in the skeleton.

Strategy:
  1) Find NiNode::Update virtual (slot ~17, 18 of NiNode vtable). Decompile.
  2) Find NiAVObject::UpdateWorldData (recursive parent->child propagator).
  3) Trace from frame_tick down to the Update entry that walks the scene.
  4) Specifically look at sub_1416C85A0 (visited earlier — it writes a1+0x70..+0xA0
     which IS the world matrix). Trace its callers.
  5) The bones in skeleton.nif are all NiNodes; the per-frame walker is
     NiNode::UpdateWorldData (a virtual).

Output: re/_m8p3_skin_walker_raw5.log
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw5.log"
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
# SECTION A — sub_1416C85A0 in detail (suspected NiAVObject::UpdateWorldData):
#  - upchain ALL callers to find the recursive entry point
#  - decompile its callees to confirm structure
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — sub_1416C85A0 caller chain (NiAVObject::UpdateWorldData?)")
log("=" * 78)

ea = 0x1416C85A0
nm = ida_funcs.get_func_name(ea) or ""
f = ida_funcs.get_func(ea)
sz = f.end_ea - f.start_ea
log(" target: %s %s sz=0x%X rva=%s" % (hexs(ea), nm, sz, hexs(rva(ea))))

# direct callers
log("\n direct callers of sub_1416C85A0:")
for r in xrefs_to_code(ea):
    fea = fn_start(r)
    if fea == idaapi.BADADDR: continue
    nmc = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz2 = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nmc, sz2, hexs(rva(fea))))

# Decompile callers - up to 5 unique
seen_callers = set()
for r in xrefs_to_code(ea):
    fea = fn_start(r)
    if fea == idaapi.BADADDR or fea in seen_callers: continue
    seen_callers.add(fea)
    if len(seen_callers) > 6: break
    nmc = ida_funcs.get_func_name(fea) or ""
    log("\n----- caller %s %s -----" % (hexs(fea), nmc))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:120]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION B — Find NiNode vtable (look for ".?AVNiNode@@" RTTI)
# Then dump its vtable to find Update virtuals.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — NiNode vtable + Update virtuals")
log("=" * 78)

def find_string_addr(s):
    needle = s.encode("utf-8") + b"\x00"
    matches = []
    seg = idaapi.get_first_seg()
    while seg:
        ea2 = seg.start_ea
        end = seg.end_ea
        f2 = ida_bytes.find_bytes(needle, ea2, end)
        while f2 != idaapi.BADADDR:
            matches.append(f2)
            f2 = ida_bytes.find_bytes(needle, f2 + len(needle), end)
        seg = idaapi.get_next_seg(seg.start_ea)
        if len(matches) >= 16: break
    return matches

# Find NiNode RTTI string
ninode_str = find_string_addr(".?AVNiNode@@")
log(" '.?AVNiNode@@' addrs: %s" % [hexs(a) for a in ninode_str])

# Per RTTI scheme: data refs to RTTI string lead to TypeDescriptor;
# RTTI:CompleteObjectLocator references TypeDescriptor; vtable[-8] points to COL.
# Easier: search for any qword in .rdata that, when offset back by 8, has a value
# that points to a COL with our typedesc.
# For brevity: known NiNode vt RVA from BGS / FO4LE = 0x14267DF40 area; let's
# just dump 0x14267DF40 in case it's it.
# Actually we know NiAVObject RTTI is at 0x142F997C0 (per dossier);
# let's also check 0x14267DBF0..0x14267E0B8 (BSGeometry) is the BSGeometry vt.

CANDIDATE_VTS = [
    (0x14267DF40, "guess: NiNode?"),
    (0x14267DC00, "?"),
    (0x14267DDA0, "?"),
    (0x14267DEC0, "?"),
    (0x14267E040, "?"),
]
# Also check: scan all qwords in .rdata for those whose typedesc-string ends in "NiNode@@"
# Actually let's find COL-typedesc references specifically.
# Skip complex RTTI parsing - just look at the most-referenced vtables.
# A more reliable approach: find a function that we KNOW is NiAVObject::Update,
# then trace its xrefs.

# sub_1416C85A0 size 0x354 - very likely NiAVObject::UpdateWorldData. Find vt slot.
# Iterate over all qwords in .rdata and find any vtable slot equal to 0x1416C85A0.
log("\n -- find vtables containing sub_1416C85A0 --")
seg_rdata = idaapi.get_segm_by_name(".rdata")
if seg_rdata:
    s = seg_rdata.start_ea
    e = seg_rdata.end_ea
    cur = s
    target = 0x1416C85A0
    found = []
    while cur < e:
        v = ida_bytes.get_qword(cur)
        if v == target:
            # Check if this is part of a vtable: previous qwords also point to functions
            prev = ida_bytes.get_qword(cur - 8)
            nxt = ida_bytes.get_qword(cur + 8)
            if (prev and IMG <= prev < IMG + 0x4000000) or \
               (nxt and IMG <= nxt < IMG + 0x4000000):
                found.append(cur)
        cur += 8
    log(" found in .rdata at %d positions" % len(found))
    for fea in found[:10]:
        log("   slot %s -> sub_1416C85A0" % hexs(fea))
        # Try to find the vtable start by walking backward looking for COL ptr (~)
        # COL is in .rdata typically.
        # Find first qword preceding that's NOT a function (=> vtable header).
        cur = fea
        while cur > seg_rdata.start_ea:
            prev = ida_bytes.get_qword(cur - 8)
            if not (prev and IMG <= prev < IMG + 0x4000000):
                break
            cur -= 8
        vt_start = cur
        offset_in_vt = (fea - vt_start) // 8
        log("     candidate vtable starts at %s (slot %d)" % (hexs(vt_start), offset_in_vt))
        # Try to read COL at vt_start - 8
        col = ida_bytes.get_qword(vt_start - 8)
        log("     COL @ %s = %s" % (hexs(vt_start - 8), hexs(col)))
        if col and IMG <= col < IMG + 0x4000000:
            typedesc_rva = ida_bytes.get_dword(col + 0x0C)
            typedesc_ea = IMG + typedesc_rva
            try:
                tname = idc.get_strlit_contents(typedesc_ea + 0x10, -1, 0)
                log("     typedesc-string = %s" % tname)
            except: pass

# -----------------------------------------------------------------------------
# SECTION C — Find vtable references to sub_1416C85A0 (it's in MULTIPLE vtables
# probably — every class derived from NiAVObject's UpdateWorldData base shares it)
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — Find every vtable slot that contains sub_1416C85A0")
log("=" * 78)
# Already done above — we found `found` list.

# -----------------------------------------------------------------------------
# SECTION D — Decompile sub_1416C85A0 properly + look at callers more deeply.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — sub_1416C85A0 callers' callers (find frame anchor)")
log("=" * 78)

def upchain_full(start_ea, max_depth=10, max_breadth=2000):
    found_anchors = []
    seen = set([start_ea])
    queue = [(start_ea, 0, [start_ea])]
    PER_FRAME = {
        0x140C334B0: "frame_tick",
        0x140C30FD0: "main_loop",
        0x140BD5320: "scene_render?",
        0x140C00590: "scene_render2?",
        0x1404E87C0: "ft_inner1",
        0x1421B27D0: "render_inner",
        0x1421B69D0: "scenegraph_render?",
        0x14219EE60: "render2",  # guess
        0x1402CDDD0: "PC_update",
        0x140CE1720: "?",
    }
    while queue and len(seen) < max_breadth:
        ea, d, path = queue.pop(0)
        if ea in PER_FRAME:
            found_anchors.append((ea, d, path))
        if d >= max_depth: continue
        for r in xrefs_to_code(ea):
            f = fn_start(r)
            if f == idaapi.BADADDR: continue
            if f in seen: continue
            seen.add(f)
            queue.append((f, d + 1, path + [f]))
    return found_anchors, seen

anchors, seen = upchain_full(0x1416C85A0, 12, 4000)
log(" upchain visited %d unique callers; anchors found: %d" % (len(seen), len(anchors)))
for ea, d, path in anchors[:10]:
    log("\n -- anchor %s at depth %d --" % (hexs(ea), d))
    log("    path: %s" % " -> ".join([hexs(p) for p in path]))

# -----------------------------------------------------------------------------
# SECTION E — Look at NiNode-type Update virtuals.
# Find vtables containing sub_140239580/590 (likely Update slots) etc.
# Look for NiNode-specific UpdateWorldData (recursive child walker).
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — Trace from BSGeometry::Update virtual slot 17,18,19")
log("=" * 78)

# In BSGeometry vtable, slots 17,18,19 = sub_140239590, 580, 510 (all sz=3)
# These are stubs forwarding to base. Check what calls them via virtual call.
# The actual UpdateWorldData of BSGeometry could be one of slots 27..33.

# Decompile slot 32: sub_1416D5260 (sz 0x132) — biggest BSGeometry-specific virtual
log("\n -- BSGeometry vtable slot 32: sub_1416D5260 --")
dec = safe_decompile(0x1416D5260)
if dec:
    for ln in dec.split("\n")[:60]:
        log("   " + ln)

# Decompile slot 33: sub_1416D53A0 (sz 0xFC)
log("\n -- BSGeometry vtable slot 33: sub_1416D53A0 --")
dec = safe_decompile(0x1416D53A0)
if dec:
    for ln in dec.split("\n")[:60]:
        log("   " + ln)

# Decompile slot 51: sub_1416D4F80 (sz 0x279) — biggest of all BSGeometry virtuals
log("\n -- BSGeometry vtable slot 51: sub_1416D4F80 --")
dec = safe_decompile(0x1416D4F80)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION F — find the Update virtual that does world transform composition
# by looking at NiAVObject base's slot 27, 28, 29, 30, 31, 32, 33 in BSGeometry vt.
# Compare with NiNode's vtable (which we don't have RVA for yet).
# Instead: find vtables whose slot N contains sub_1416C85A0.
# We can use the result from the .rdata scan.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION F — slot positions of sub_1416C85A0 in vtables")
log("=" * 78)

# Scan all .rdata qwords for sub_1416C85A0
seg_rdata = idaapi.get_segm_by_name(".rdata")
target = 0x1416C85A0
positions = []
if seg_rdata:
    cur = seg_rdata.start_ea
    while cur < seg_rdata.end_ea:
        v = ida_bytes.get_qword(cur)
        if v == target:
            positions.append(cur)
        cur += 8
log(" sub_1416C85A0 appears in .rdata at %d positions" % len(positions))

# For each position, try to identify which vtable + slot it's in:
for pos in positions[:20]:
    # Walk backward to find vt start (where preceding qword stops being a function)
    cur = pos
    f = idaapi.get_func(cur)
    # Scan back: find COL-bound vtable boundary
    boundary = pos
    while boundary - 8 >= seg_rdata.start_ea:
        v = ida_bytes.get_qword(boundary - 8)
        if not (v and IMG <= v < IMG + 0x4000000):
            break
        boundary -= 8
    # Now boundary is start of vtable
    vt_start = boundary
    slot_num = (pos - vt_start) // 8
    col = ida_bytes.get_qword(vt_start - 8)
    typedesc_str = "?"
    if col and IMG <= col < IMG + 0x4000000:
        try:
            typedesc_rva = ida_bytes.get_dword(col + 0x0C)
            tname = idc.get_strlit_contents(IMG + typedesc_rva + 0x10, -1, 0)
            if tname:
                typedesc_str = tname.decode("ascii", errors="replace")
        except:
            pass
    log("  pos %s in vt %s slot %d  rtti=%s" %
        (hexs(pos), hexs(vt_start), slot_num, typedesc_str))

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines)")
idaapi.qexit(0)
