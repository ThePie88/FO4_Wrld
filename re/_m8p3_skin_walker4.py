"""
M8P3 — Skin walker hunt v4 (final)

Refined search: the engine walker must:
- Iterate ALL bones in BSSkin::Instance (loop)
- Read each bone's worldTransform (typically NiAVObject+0x4C..+0x80 area)
  AND boneData inv_bind matrix
- Compute composed = bone.world * inv_bind (or inverse pattern)
- Store result in some target buffer reachable by the GPU

KEY HYPOTHESIS: there are TWO write targets to investigate:
  A) Each bone's world transform (NiAVObject internal)  - written by
     NiAVObject::UpdateWorldData walker (per-frame), independent of skin.
     This is upstream of the skin computation. NOT what we want.
  B) The skinning matrix (bone.world * inv_bind), written into either:
       - skin->bones_pri[i] (if entries ARE matrix slots, not pointers)
       - or inside the NiAVObject pointed by entries (a cached field)
       - or into a shader constant buffer (uploaded per draw)

We need to find B). Look at:
  1. Decompile sub_1403F7320 (used by sub_1403FA980 to read bone world)
  2. Search for callers of "boneData[i].invBind" reads (skin+0x40 -> deref+0x10
     -> stride 80) that ALSO loop over bone count.
  3. Examine the Render virtual on BSGeometry/BSTriShape/BSSubIndexTriShape
     (typically at slot 35 or 50 of the vtable — the BSGeometry slots show
     0x1416BAB40 = sub_1416BAB40 at slot 35, but that's a tiny stub).
  4. Check the actual D3D11 cbuffer upload sites — the engine uploads bone
     matrices to a cbuffer for each skinned mesh.

Also: check sub_1403FA980 callers — maybe the actual walker is a CALLER of
sub_1403FA980 that loops through bones.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_walker_raw4.log"
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
# SECTION A — Investigate sub_1403F7320 (bone world fetcher)
# -----------------------------------------------------------------------------
log("=" * 78)
log(" SECTION A — sub_1403F7320 decomp + callers")
log("=" * 78)

ea = 0x1403F7320
nm = ida_funcs.get_func_name(ea) or ""
f = ida_funcs.get_func(ea)
sz = (f.end_ea - f.start_ea) if f else 0
log(" %s %s sz=0x%X" % (hexs(ea), nm, sz))
dec = safe_decompile(ea)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

log("\n -- callers of sub_1403F7320 --")
for r in xrefs_to_code(ea):
    fea = fn_start(r)
    if fea == idaapi.BADADDR: continue
    nm = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s call@%s sz=0x%X" % (hexs(fea), nm, hexs(r), sz))

# -----------------------------------------------------------------------------
# SECTION B — Decompile sub_1403FA980 (single-bone writer to skin+0x60)
#   Then check its CALLERS — maybe there's a function that loops calling FA980
#   for each bone.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION B — sub_1403FA980 callers (looped per-bone caller?)")
log("=" * 78)

ea = 0x1403FA980
log(" callers of sub_1403FA980:")
for r in xrefs_to_code(ea):
    fea = fn_start(r)
    if fea == idaapi.BADADDR: continue
    nm = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s call@%s sz=0x%X rva=%s" % (hexs(fea), nm, hexs(r), sz, hexs(rva(fea))))
    # Decomp the caller
    dec = safe_decompile(fea)
    if dec:
        log("\n  ---- decomp of caller %s ----" % hexs(fea))
        for ln in dec.split("\n")[:80]:
            log("    " + ln)

# Also check sub_1403FA7C0 (sister function from earlier list)
log("\n -- sub_1403FA7C0 decomp + callers --")
ea = 0x1403FA7C0
nm = ida_funcs.get_func_name(ea) or ""
log(" %s %s" % (hexs(ea), nm))
dec = safe_decompile(ea)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

log("\n -- callers of sub_1403FA7C0 --")
for r in xrefs_to_code(0x1403FA7C0):
    fea = fn_start(r)
    if fea == idaapi.BADADDR: continue
    nm = ida_funcs.get_func_name(fea) or ""
    fobj = ida_funcs.get_func(fea)
    sz = (fobj.end_ea - fobj.start_ea) if fobj else 0
    log("   %s %s call@%s sz=0x%X" % (hexs(fea), nm, hexs(r), sz))

# -----------------------------------------------------------------------------
# SECTION C — Look at BSSkin::BoneData vtable methods.
# These should include the per-frame "compute skinning matrices" function.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION C — BSSkin::BoneData vtable (full content + decomp of big slots)")
log("=" * 78)

BSI_BD_VT = 0x14267E480
slots = []
for i in range(40):
    slot_ea = BSI_BD_VT + i * 8
    v = ida_bytes.get_qword(slot_ea)
    if not v or v < IMG or v > IMG + 0x4000000: break
    f = ida_funcs.get_func(v)
    sz = (f.end_ea - f.start_ea) if f else 0
    slots.append((i, v, sz))
    nm = ida_funcs.get_func_name(v) or ""
    log("   bonedata[%2d] %s %s sz=0x%X rva=%s" % (i, hexs(v), nm, sz, hexs(rva(v))))

# Decomp top 5 by size
slots.sort(key=lambda x: -x[2])
for i, v, sz in slots[:5]:
    nm = ida_funcs.get_func_name(v) or ""
    log("\n -- bonedata vt slot[%d] %s %s sz=0x%X --" % (i, hexs(v), nm, sz))
    dec = safe_decompile(v)
    if dec:
        for ln in dec.split("\n")[:100]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION D — Find functions that read [reg+0x40] and immediately follow with
#             [reg+0x28] read AND a tight loop over the count read from +0x38.
#             This is the WALKER PATTERN literally:
#               boneData = *(skin+0x40)
#               bones_pri = *(skin+0x28)
#               for i in 0..*(skin+0x38): { ... }
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION D — strict walker pattern: reads +0x40, +0x28, +0x38, has loop")
log("=" * 78)

text_seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(text_seg.start_ea, text_seg.end_ea))

# Heuristic via decomp: scan top 200 candidates with all three offsets.
# Only consider those with size 0x100 .. 0x600 (the walker isn't huge).
candidates = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x80 or sz > 0xA00: continue
    cur = f.start_ea
    has_28 = has_38 = has_40 = False
    has_loop_back = False
    last_addr_with_28 = 0
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        if "+28h]" in ds: has_28 = True
        if "+38h]" in ds: has_38 = True
        if "+40h]" in ds: has_40 = True
        # Detect backward branch (loop)
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("jb", "jbe", "jl", "jle", "jne", "jnz", "jge", "jg",
                    "ja", "jae"):
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt < cur:
                has_loop_back = True
        cur = idc.next_head(cur)
    if has_28 and has_38 and has_40 and has_loop_back:
        candidates.append((fea, sz))

candidates.sort(key=lambda x: x[1])
log(" total walker-pattern candidates (size 0x80..0xA00, has loop): %d" % len(candidates))
for fea, sz in candidates[:40]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# Decomp top 8
log("\n -- decomp of top 8 candidates --")
for fea, sz in candidates[:8]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- %s %s sz=0x%X rva=%s -----" % (hexs(fea), nm, sz, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# -----------------------------------------------------------------------------
# SECTION E — Walk the trail from sub_140C334B0 frame_tick down looking for
# a DRAW / scenegraph render entry. Specifically, dig into sub_140CE1720
# (called by frame tick) and other big children.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION E — frame_tick big children: examine for skin walker")
log("=" * 78)

# Big children of frame_tick from earlier list
FRAME_KIDS = [
    0x1402CDDD0,  # sz=0xAA6 - PlayerCharacter::Update?
    0x1404E87C0,  # sz=0x7E2 - 3rd person/anim?
    0x140C32D30,  # sz=0x404 - render driver?
    0x140A36F20,  # tiny
    0x140C351B0,  # sz=0x4CB
    0x141036350,  # sz=0x3A8
    0x140CE1720,  # sz=0x2D5
    0x140C419E0,  # sz=0x56C
    0x140375DB0,  # sz=0x253
    0x140C24670,  # sz=0x1CE
    0x141A80030,  # sz=0x11F3
    0x141A81230,  # sz=0x36E
]

for ea in FRAME_KIDS:
    nm = ida_funcs.get_func_name(ea) or ""
    f = ida_funcs.get_func(ea)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("\n -- %s %s sz=0x%X rva=%s --" % (hexs(ea), nm, sz, hexs(rva(ea))))
    # Find what FAMILY this function belongs to: scan first 30 calls
    if not f: continue
    cur = f.start_ea
    callees = []
    while cur < f.end_ea and cur != idaapi.BADADDR:
        if idc.print_insn_mnem(cur).lower() == "call":
            tgt = idc.get_operand_value(cur, 0)
            if tgt:
                callees.append((cur, tgt))
        cur = idc.next_head(cur)
        if len(callees) > 30: break
    for c, t in callees[:20]:
        cn = ida_funcs.get_func_name(t) or ""
        log("    call %s -> %s %s" % (hexs(c), hexs(t), cn))

# -----------------------------------------------------------------------------
# SECTION F — Search disasm for the SPECIFIC pattern
# `mov rcx, [reg+38h]` IMMEDIATELY followed by use as loop bound, AND
# `mov rdx, [reg+28h]` to load head ptr. These are usually adjacent in walker.
# -----------------------------------------------------------------------------
log("\n" + "=" * 78)
log(" SECTION F — adjacent +0x28 and +0x38 reads (walker init)")
log("=" * 78)

cands_f = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x40 or sz > 0x800: continue
    # Look for windows of 5 instructions where +0x28 and +0x38 both appear
    cur = f.start_ea
    insts = []
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur).lower()
        insts.append((cur, ds))
        cur = idc.next_head(cur)
    found = False
    for i in range(len(insts) - 4):
        window = " | ".join(insts[i+j][1] for j in range(5))
        if "+28h]" in window and "+38h]" in window:
            # Also require +40h or matrix-like pattern
            if "+40h]" in window or "movups" in window:
                found = True
                break
    if found:
        cands_f.append((fea, sz))

cands_f.sort(key=lambda x: x[1])
log(" candidates with adjacent +0x28/+0x38/+0x40 in 5-insn window: %d" % len(cands_f))
for fea, sz in cands_f[:30]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(fea), nm, sz, hexs(rva(fea))))

# Decomp top 6
for fea, sz in cands_f[:6]:
    nm = ida_funcs.get_func_name(fea) or ""
    log("\n----- %s %s sz=0x%X rva=%s -----" % (hexs(fea), nm, sz, hexs(rva(fea))))
    dec = safe_decompile(fea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "(", len(out_lines), "lines)")
idaapi.qexit(0)
