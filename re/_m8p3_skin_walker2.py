"""
M8P3 — Skin walker hunt v2 (deeper).

Section A: dump 30 unique callers of sub_1403444F0 with decomp summaries.
Section B: identify functions that loop reading a count and loop body multiplies
           4x4 matrices and stores them somewhere.
Section C: trace the upchain from each iterator-pattern candidate to a frame-tick.
Section D: examine BSGeometry virtuals at slot 27..52 (NiAVObject::Update virtuals).
Section E: BSDynamicTriShape vtable & Update slots (these are SKINNED at runtime).
Section F: scan binary for any code that has a loop body with both
              (a) read of [reg+0x40] (bone struct -> matrix?)
              (b) write of 4 xmm regs to [reg+somecomputed]
Section G: identify the well-known "BSSkin update" function via xrefs to
           sub_141B26AB0 / NiAVObject::UpdateWorldTransform-pattern callers.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw2.log"
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

# -----------------------------------------------------------------------------
# SECTION A — All unique callers of sub_1403444F0 (4x4 multiply): decomp-screen
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — full decomp of sub_1403444F0 callers (mat4 mul)")
log("=" * 78)

mul4x4 = 0x1403444F0
unique_callers = set()
for r in xrefs_to_code(mul4x4):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        unique_callers.add(f)
log(" unique callers: %d" % len(unique_callers))

# Filter callers: those that have "+28h" disp AND "+38h" disp AND "+40h" disp
# in their disasm (i.e. they touch the BSSkin layout somehow).
filtered = []
for fea in unique_callers:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    has28 = has38 = has40 = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+28h]" in ds: has28 = True
        if "+38h]" in ds: has38 = True
        if "+40h]" in ds: has40 = True
        cur = idc.next_head(cur)
    if has28 and has38 and has40:
        filtered.append(fea)
log(" callers touching skin-shaped layout (+0x28, +0x38, +0x40): %d" % len(filtered))

for fea in filtered:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("\n----- %s %s rva=%s size=0x%X -----" % (hexs(fea), nm, hexs(rva(fea)), sz))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:160]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION B — Find functions with explicit pattern:
#    LOOP_HEAD: read [reg+38h] count
#               read [reg+28h] head pointer
#               loop body: multiply 4x4 + store
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — find skin loop pattern: read +0x38 (count) + +0x28 (head) + loop")
log("=" * 78)

# Heuristic: scan all functions. For each, find pairs of disasm lines:
#   movzx/mov reg32, [rxx+38h]    ; load count
#   cmp/test ...                  ; loop guard
#   mov rxx, [rxx+28h]            ; load head
# AND check that the function calls sub_1403444F0 (mul) somewhere.

text_seg = ida_segment.get_segm_by_name(".text")
functions = list(idautils.Functions(text_seg.start_ea, text_seg.end_ea))

# First pass: callers of mul4x4
direct_mul_callers = unique_callers
log(" callers of sub_1403444F0: %d" % len(direct_mul_callers))

# Second pass: those that ALSO have a "+38h" load (count read)
candidates_b = []
for fea in direct_mul_callers:
    f = ida_funcs.get_func(fea)
    if not f: continue
    cur = f.start_ea
    has_38_read = False
    has_28_read = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        # Read pattern: "mov reg32d, [reg+38h]" or "cmp [reg+38h], reg"
        if "+38h]" in ds:
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("mov", "movzx", "movq", "cmp"):
                has_38_read = True
        if "+28h]" in ds:
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("mov", "movzx", "lea"):
                has_28_read = True
        cur = idc.next_head(cur)
    if has_38_read and has_28_read:
        candidates_b.append(fea)

log(" mul-callers with both +0x28 and +0x38 reads: %d" % len(candidates_b))
for fea in candidates_b:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("   %s %s rva=%s size=0x%X" % (hexs(fea), nm, hexs(rva(fea)), sz))

# -----------------------------------------------------------------------------
# SECTION C — Decompile each candidate from B (full decomp, up to 250 lines)
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — decomps of candidates from Section B")
log("=" * 78)

for fea in candidates_b[:12]:
    nm = ida_funcs.get_func_name(fea) or ""
    f = ida_funcs.get_func(fea)
    sz = f.end_ea - f.start_ea
    log("\n========== %s %s rva=%s size=0x%X ==========" % (hexs(fea), nm, hexs(rva(fea)), sz))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:250]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION D — Trace upchain from each candidate to a per-frame entry.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — upchain to per-frame for each candidate")
log("=" * 78)

# Mark known per-frame anchors: frame_tick at 0x140C334B0, render path
PER_FRAME_ANCHORS = {
    0x140C334B0: "frame_tick",
    0x140C30FD0: "main_loop",
    0x140BD5320: "scene_render?",
    0x140C00590: "scene_render2?",
}

def upchain_with_anchor(start_ea, max_depth=6, max_breadth=200):
    chain_log = []
    seen = set([start_ea])
    queue = [(start_ea, 0, [])]
    found_anchors = []
    while queue and len(seen) < max_breadth:
        ea, d, path = queue.pop(0)
        if ea in PER_FRAME_ANCHORS:
            found_anchors.append((ea, d, path + [ea]))
        if d >= max_depth: continue
        for r in xrefs_to_code(ea):
            f = fn_start(r)
            if f == idaapi.BADADDR: continue
            if f in seen: continue
            seen.add(f)
            queue.append((f, d + 1, path + [ea]))
    return found_anchors, seen

for fea in candidates_b[:8]:
    anchors, seen = upchain_with_anchor(fea, 8, 400)
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n -- chain from %s %s --" % (hexs(fea), nm))
    log("   (visited %d unique callers)" % len(seen))
    if not anchors:
        log("   no per-frame anchor found within depth 8")
    for ea, d, path in anchors[:5]:
        log("   anchor %s (%s) at depth %d" % (hexs(ea), PER_FRAME_ANCHORS[ea], d))
        log("   path: %s" % " -> ".join([hexs(p) for p in path]))

# -----------------------------------------------------------------------------
# SECTION E — Explicitly find functions that are virtuals slotted on
# BSGeometry / BSTriShape / BSSubIndexTriShape / BSDynamicTriShape vtables
# with size > 0x100 and which call sub_1403444F0.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — BSGeometry-family virtuals that call sub_1403444F0")
log("=" * 78)

VTS = {
    "BSGeometry": 0x14267E0B8,
    "BSTriShape": 0x14267E948,
    "BSSubIndexTriShape": 0x142697D40,
}

# Collect every virtual function across these vtables and check if it calls mul4x4
all_virtuals = set()
for nm, vt in VTS.items():
    for i in range(120):
        slot_ea = vt + i * 8
        v = ida_bytes.get_qword(slot_ea)
        if not v or v < IMG or v > IMG + 0x4000000: break
        all_virtuals.add(v)

log(" total unique virtuals across BS* vtables: %d" % len(all_virtuals))

vt_callers_of_mul = []
for v in all_virtuals:
    f = ida_funcs.get_func(v)
    if not f: continue
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        if idc.print_insn_mnem(cur).lower() == "call":
            tgt = idc.get_operand_value(cur, 0)
            if tgt == mul4x4:
                vt_callers_of_mul.append(v)
                break
        cur = idc.next_head(cur)
log(" of those, callers of sub_1403444F0: %d" % len(vt_callers_of_mul))
for v in vt_callers_of_mul:
    nm = ida_funcs.get_func_name(v) or ""
    log("   virtual %s %s rva=%s" % (hexs(v), nm, hexs(rva(v))))

# -----------------------------------------------------------------------------
# SECTION F — Read sub_140C334B0 frame tick to find calls related to skin/animation
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION F — sub_140C334B0 frame tick: list call targets")
log("=" * 78)

ft = 0x140C334B0
f = ida_funcs.get_func(ft)
calls = []
if f:
    cur = f.start_ea
    while cur < f.end_ea and cur != idaapi.BADADDR:
        if idc.print_insn_mnem(cur).lower() == "call":
            tgt = idc.get_operand_value(cur, 0)
            calls.append((cur, tgt))
        cur = idc.next_head(cur)

log(" total calls: %d" % len(calls))
seen_tgts = set()
for cur, t in calls:
    if t in seen_tgts: continue
    seen_tgts.add(t)
    nm = ida_funcs.get_func_name(t) or ""
    fobj = ida_funcs.get_func(t) if t and t != idaapi.BADADDR else None
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s -> %s %s sz=0x%X" % (hexs(cur), hexs(t), nm, sz))

# -----------------------------------------------------------------------------
# SECTION G — Examine known anim/skin-related candidates by name pattern.
# Also check for a function literally named-like "ProcessSkinned" (skinning).
# Look for callers of sub_1416BAB30/40/50 (NiAVObject Update virtuals on skin).
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION G — NiAVObject Update virtuals on BSSkin::Instance")
log("=" * 78)

# slot 34..39 of BSSkin::Instance = sub_1416BAB30, 40, 50, 60, 70, 80
for ea in [0x1416BAB30, 0x1416BAB40, 0x1416BAB50, 0x1416BAB60, 0x1416BAB70, 0x1416BAB80]:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = f.end_ea - f.start_ea if f else 0
    log("\n -- %s %s sz=0x%X --" % (hexs(ea), nm, sz))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:50]:
            log("   " + ln)

# These slots 34..39 in BSGeometry are the NiAVObject Update virtuals!
# Slot 34 = UpdateDownwardPass / UpdateNodeBound, etc. Let's see if any of them
# in BSGeometry vtable is overridden — slot 34..39 in BSGeometry are also
# 0x1416BAB30..0x1416BAB80, same as BSSkin!! (shared vt entries from NiAVObject)

# So the skin walker is NOT a virtual on BSSkin::Instance.
# Let me look at virtuals shared by BSGeometry+BSTriShape that could be the
# UpdateBound or UpdateWorldData. In BSGeometry vt slot 27..33:
#   slot 27 = sub_1416D4980
#   slot 28 = sub_1416D49F0
#   slot 29 = sub_1416D4AB0
#   slot 30 = sub_1416D4B30
#   slot 31 = sub_1416D4BC0
#   slot 32 = sub_1416D5260
#   slot 33 = sub_1416D53A0
# These are the BSGeometry-specific virtuals. Examine them.

log("\n" + "=" * 78)
log(" SECTION G2 — BSGeometry-specific virtuals slot 27..33")
log("=" * 78)

for ea in [0x1416D4980, 0x1416D49F0, 0x1416D4AB0, 0x1416D4B30, 0x1416D4BC0,
           0x1416D5260, 0x1416D53A0]:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = f.end_ea - f.start_ea if f else 0
    log("\n -- %s %s sz=0x%X --" % (hexs(ea), nm, sz))
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:80]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION H — BSSkin::BoneData (vt 0x14267E480) — examine its vt.
# Possibly the walker is a method on BoneData.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION H — BSSkin::BoneData vtable contents")
log("=" * 78)

for i in range(40):
    slot_ea = 0x14267E480 + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    nm = ida_funcs.get_func_name(v) or ""
    f = ida_funcs.get_func(v)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("   bonedata[%2d] %s %s sz=0x%X rva=%s" % (i, hexs(v), nm, sz, hexs(rva(v))))

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines )")
idaapi.qexit(0)
