"""
M8P3 — Skin walker hunt v3 (deep investigation)

Key clue: user reports that writing 4x4 matrices to bones_pri[i] (the slots
themselves, treating each as a 64-byte struct head) DOES deform the mesh.
Combined with the existing dossier (entries are NiPointer<NiAVObject>), we
infer: the entry is an 8-byte NiAVObject* pointer; the GPU shader reads the
NiAVObject's worldTransform (typically NiAVObject+0x70 or +0x80) and uses
that as the skinning matrix.

The engine per-frame walker likely:
  1) Iterates skin->bones[i] (NiAVObject*)
  2) Composes bone.world = (parent.world * bone.local) per the NiAVObject
     UpdateWorldData chain
  3) Stores at bone+0x70 (or wherever NiAVObject keeps world matrix)

Strategy:
  - Find function that:
    a) reads count from [r+0x38]
    b) reads head from [r+0x28]
    c) loops, dereferencing each entry to get a NiAVObject*
    d) does NOT necessarily call sub_1403444F0 (could inline matmul)
  - Look for callers of the BSGeometry-specific virtuals (the skin update
    might be a free function called from BSGeometry::Render or similar)
  - Specifically inspect sub_1416D5260, sub_1416D53A0 (BSGeometry virtuals
    found in vt slots 32, 33)
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw3.log"
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
# SECTION A — Decompile interesting BSGeometry virtuals (sub_1416D5260, sub_1416D53A0)
# These look like big specific virtuals at slots 32-33.
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — Decomp of BSGeometry virtuals slot 32, 33 + their callees")
log("=" * 78)

CANDIDATES_A = [0x1416D5260, 0x1416D53A0, 0x1416D4F80, 0x1416D71E0, 0x1416D7310,
                0x1416D74B0]

for ea in CANDIDATES_A:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("\n----- %s %s sz=0x%X rva=%s -----" % (hexs(ea), nm, sz, hexs(rva(ea))))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:130]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION B — Find callers of NiAVObject::UpdateWorldData / UpdateNodeBound type fns
# These are typically at slot 17, 18, 19 of NiAVObject vtable (Update virtuals).
# In BSGeometry vtable, slot 17, 18, 19 = sub_140239590, 580, 510.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — examine NiAVObject Update virtuals (slot 17-19)")
log("=" * 78)

# slots 17, 18, 19 of BSGeometry vtable are:
#   slot 17 = sub_140239590 (Update?)
#   slot 18 = sub_140239580
#   slot 19 = sub_140239510 (Update virtual returning void)
for ea in [0x140239590, 0x140239580, 0x140239510, 0x140239570, 0x140239560]:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("\n -- %s %s sz=0x%X --" % (hexs(ea), nm, sz))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:30]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION C — Search the binary for the SKINNING-OUTPUT pattern:
# A function that reads [reg+0x28] AND [reg+0x38] AND [reg+0x40] AND
# does NOT necessarily call sub_1403444F0 but DOES have a tight loop iterating
# bones (i.e., iterates over count from +0x38, dereferencing entries from +0x28).
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — Tight loops over bone array")
log("=" * 78)

text_seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(text_seg.start_ea, text_seg.end_ea))

candidates_c = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    has_28 = has_38 = False
    has_loop_inc = False
    has_xmm_store = 0
    cur_was_38 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        # Read pattern for count (+0x38)
        if "+38h]" in ds:
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("mov", "movzx", "cmp", "movq"):
                has_38 = True
        # Read pattern for head ptr (+0x28)
        if "+28h]" in ds:
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("mov", "movzx", "lea"):
                has_28 = True
        # Detect loop-style increments
        if "add" in ds and (", 8" in ds or ", 50h" in ds):
            has_loop_inc = True
        # Detect XMM stores
        if ("movups" in ds or "movaps" in ds) and "xmm" in ds:
            br = ds.find("[")
            xpos = ds.find("xmm")
            if br > 0 and br < xpos:
                has_xmm_store += 1
        cur = idc.next_head(cur)
    # Filter: bones loop pattern + writes
    if has_28 and has_38 and has_loop_inc and has_xmm_store >= 4:
        candidates_c.append((fea, has_xmm_store))

candidates_c.sort(key=lambda x: -x[1])
log(" total candidates with bones loop + XMM stores: %d" % len(candidates_c))
for fea, xn in candidates_c[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("   %s %s xmm_writes=%d sz=0x%X rva=%s" %
        (hexs(fea), nm, xn, sz, hexs(rva(fea))))

# -----------------------------------------------------------------------------
# SECTION D — Decompile top 10 of section C
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — decomps")
log("=" * 78)

DECOMPLIM = 12
for fea, xn in candidates_c[:DECOMPLIM]:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("\n========= %s %s sz=0x%X xmm=%d rva=%s =========" %
        (hexs(fea), nm, sz, xn, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        # Limit decomp lines
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION E — Search for the OPERATING string "BSSkin" / "ApplySkin" / etc. in
# the binary. The walker function may have a nearby string.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — string search for skin-related literals")
log("=" * 78)

def find_string_addr(s):
    needle = s.encode("utf-8") + b"\x00"
    matches = []
    seg = idaapi.get_first_seg()
    while seg:
        ea = seg.start_ea
        end = seg.end_ea
        f = ida_bytes.find_bytes(needle, ea, end)
        while f != idaapi.BADADDR:
            matches.append(f)
            f = ida_bytes.find_bytes(needle, f + len(needle), end)
        seg = idaapi.get_next_seg(seg.start_ea)
        if len(matches) >= 16: break
    return matches

for kw in ["UpdateBoundData", "UpdateBoneTransforms", "ApplySkin",
           "SkinUpdate", "SkinTransform", "skinning",
           "BSSkin::Update", "ApplyBoneTransforms", "UpdateSkinning"]:
    addrs = find_string_addr(kw)
    log(" '%s' addrs: %s" % (kw, [hexs(a) for a in addrs]))

# -----------------------------------------------------------------------------
# SECTION F — ScenegraphRender path: look for func that takes BSGeometry and
# updates skin. The engine usually has BSGeometry::PreRender or similar.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION F — sub_140C00590 / sub_1404E87C0 (frame_tick child) decomp")
log("=" * 78)

for ea in [0x140C00590, 0x1404E87C0, 0x1421B27D0, 0x1421B3110, 0x1421B69D0,
           0x1416D0510, 0x1416C85A0]:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("\n -- %s %s sz=0x%X --" % (hexs(ea), nm, sz))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:60]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION G — Find functions where the loop pattern reads from SECONDARY POINTER
# (entries at [head+8*idx]) THEN reads from a NESTED OFFSET (typical world
# transform read at +0x70 of NiAVObject) and stores 4 xmms.
# This is the smoking gun for `for each bone: write bone+0x70 = composed`.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION G — smoking-gun pattern: loop over bones, write at deref+offset")
log("=" * 78)

# Pattern (in disasm tokens):
#   mov rax, [r..+28h]    ; head
#   xor rcx, rcx          ; idx
# loop:
#   mov rdx, [rax+rcx*8]  ; bone = head[idx]
#   ... XMM math ...
#   movups [rdx+70h], xmm0
#   movups [rdx+80h], xmm1
#   movups [rdx+90h], xmm2
#   add rcx, 1
#   cmp rcx, [r..+38h]    ; count
#   jb loop
#
# We'll scan for "movups [r..+70h]" or "movups [r..+80h]" within candidates.

# Look in full text segment, count fns having writes "[reg+70h] xmm" near "+28h]"
text_seg = ida_segment.get_segm_by_name(".text")
candidates_g = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    has_28 = False
    has_70_xmm = 0
    has_38 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+28h]" in ds:
            has_28 = True
        if "+38h]" in ds:
            has_38 = True
        if ("+70h]" in ds or "+80h]" in ds or "+90h]" in ds or "+0a0h]" in ds) and ("movups" in ds or "movaps" in ds):
            has_70_xmm += 1
        cur = idc.next_head(cur)
    if has_28 and has_38 and has_70_xmm >= 3:
        candidates_g.append((fea, has_70_xmm))

candidates_g.sort(key=lambda x: -x[1])
log(" candidates for 'write to deref+70h..+a0h with bones loop': %d" % len(candidates_g))
for fea, xn in candidates_g[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("   %s %s 70h_writes=%d sz=0x%X rva=%s" %
        (hexs(fea), nm, xn, sz, hexs(rva(fea))))

# Decomp first 6
for fea, xn in candidates_g[:6]:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("\n========= %s %s xn=%d sz=0x%X rva=%s =========" %
        (hexs(fea), nm, xn, sz, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION H — Trace upchain from each candidate_g to per-frame anchors
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION H — upchain from candidates_g to per-frame")
log("=" * 78)

PER_FRAME = {
    0x140C334B0: "frame_tick",
    0x140C30FD0: "main_loop",
    0x140BD5320: "scene_render?",
    0x140C00590: "scene_render2?",
    0x1404E87C0: "ft_inner1",
    0x1421B27D0: "render_inner",
}

def upchain(start_ea, max_depth=8, max_breadth=400):
    found_anchors = []
    seen = set([start_ea])
    queue = [(start_ea, 0, [])]
    while queue and len(seen) < max_breadth:
        ea, d, path = queue.pop(0)
        if ea in PER_FRAME:
            found_anchors.append((ea, d, path + [ea]))
        if d >= max_depth: continue
        for r in xrefs_to_code(ea):
            f = fn_start(r)
            if f == idaapi.BADADDR: continue
            if f in seen: continue
            seen.add(f)
            queue.append((f, d + 1, path + [ea]))
    return found_anchors, seen

for fea, xn in candidates_g[:10]:
    nm = ida_funcs.get_func_name(fea) or ""
    anchors, seen = upchain(fea, 7, 600)
    log("\n -- chain from %s %s (xn=%d) --" % (hexs(fea), nm, xn))
    log("   visited %d unique callers" % len(seen))
    if not anchors:
        log("   no per-frame anchor in depth 7")
    for ea, d, path in anchors[:3]:
        log("   anchor %s (%s) at depth %d" % (hexs(ea), PER_FRAME[ea], d))
        log("   path: %s" % " -> ".join([hexs(p) for p in path]))

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines)")
idaapi.qexit(0)
