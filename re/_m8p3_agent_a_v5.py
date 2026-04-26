"""
M8P3 — AGENT A v5: Pinpoint the function that flattens bone+0x70 into a flat
upload buffer. Strategy: directly look for instructions reading 16 bytes
from a pointer dereferenced through bones_pri[i], then storing to consecutive
output bytes.

Key targets:
  1. NiSkinInstance vt slot 28 (sub_1416EEBE0, sz 0x13A) — likely UpdateBones
  2. Look at functions that READ "+70h]" of a dereferenced pointer-array entry
     in a tight loop.
  3. Look at all callers of mul4x4 (sub_1403444F0) under 0x300 size and
     filter for those reading bones/+0x40/+0x70.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_xref, ida_segment

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_update_AGENT_A_v5_raw.log"
IMG = 0x140000000
out = []
def log(s=""): out.append(s if isinstance(s, str) else str(s))
def hexs(x): return "0x%X" % x if isinstance(x, int) else str(x)
def rva(ea): return ea - IMG
def fn_size(ea):
    f = ida_funcs.get_func(ea)
    return (f.end_ea - f.start_ea) if f else 0
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
    x = idaapi.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = idaapi.get_next_cref_to(ea, x)
    return refs

log("=" * 80)
log(" M8P3 SKIN UPDATE — AGENT A v5 (final pinpoint)")
log("=" * 80)

# =============================================================================
# SECTION 1 — NiSkinInstance vt slot 28 (sub_1416EEBE0) deep dive
# =============================================================================
log("\n -- NiSkinInstance vt slot 28: sub_1416EEBE0 (sz 0x13A) --")
dec = safe_decompile(0x1416EEBE0)
if dec:
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

log("\n -- NiSkinInstance vt slot 0 (dtor): sub_1416EFD10 (sz 0x77) --")
dec = safe_decompile(0x1416EFD10)
if dec:
    for ln in dec.split("\n")[:50]:
        log("   " + ln)

log("\n -- NiSkinInstance vt slot 26 (clone?): sub_1416EE980 (sz 0x170) --")
dec = safe_decompile(0x1416EE980)
if dec:
    for ln in dec.split("\n")[:80]:
        log("   " + ln)

log("\n -- NiSkinInstance vt slot 29: sub_1416EED20 (sz 0xA7) --")
dec = safe_decompile(0x1416EED20)
if dec:
    for ln in dec.split("\n")[:50]:
        log("   " + ln)

log("\n -- NiSkinInstance vt slot 30: sub_1416EEDD0 (sz 0xAA) --")
dec = safe_decompile(0x1416EEDD0)
if dec:
    for ln in dec.split("\n")[:50]:
        log("   " + ln)

log("\n -- NiSkinInstance vt slot 31: sub_1416EEE80 (sz 0x70) --")
dec = safe_decompile(0x1416EEE80)
if dec:
    for ln in dec.split("\n")[:50]:
        log("   " + ln)

# =============================================================================
# SECTION 2 — All callers of NiSkinInstance vt slot 28 (this is the target!)
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 2 — Callers of NiSkinInstance vt slot 28 (sub_1416EEBE0)")
log("=" * 80)
SLOT28 = 0x1416EEBE0
callers = set()
for r in xrefs_to_code(SLOT28):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        callers.add(f)
log(" callers: %d" % len(callers))
for c in callers:
    nm = ida_funcs.get_func_name(c) or ""
    log("   %s %s sz=0x%X rva=%s" % (hexs(c), nm, fn_size(c), hexs(rva(c))))

# =============================================================================
# SECTION 3 — Search for functions that:
#   - read from arr[i] where arr is at +0x28 (bones_pri head)
#   - then do "*(__m128*)(arr[i] + 0x70)" loads (4 of them = 4 rows)
#   - have count comparison against val at +0x38
# This is the strict skin-update signature.
# =============================================================================
log("\n" + "=" * 80)
log(" SECTION 3 — Refined pattern: load4xmm from [bone+0x70] in tight loop")
log("=" * 80)

# Look at decomp text for "*(_QWORD *)(*(_QWORD *)(skin + 40)" or similar
# This will catch real skin walkers at the C source level.
# Strategy: decompile every function in size 0x80-0x500 that contains
# both "+ 40" and "+ 112" substrings (40 = +0x28, 112 = +0x70)

seg = ida_segment.get_segm_by_name(".text")
fns = list(idautils.Functions(seg.start_ea, seg.end_ea))
log(" total fns: %d" % len(fns))

# Pre-filter via disasm for loops + skin offsets
prefilter = []
for fea in fns:
    f = ida_funcs.get_func(fea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 0x100 or sz > 0x600: continue
    cur = f.start_ea
    has_28 = has_38 = has_loop_back = False
    has_70_xmm = False
    while cur < f.end_ea and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "+28h]" in ds: has_28 = True
        if "+38h]" in ds: has_38 = True
        if "+70h]" in ds and ("xmm" in ds.lower() or "movups" in ds.lower() or "movaps" in ds.lower()):
            has_70_xmm = True
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem in ("jne","jnz","jl","jle","jb","jbe"):
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt < cur and tgt >= f.start_ea:
                has_loop_back = True
        cur = idc.next_head(cur)
    if has_28 and has_38 and has_loop_back and has_70_xmm:
        prefilter.append(fea)

log(" pre-filter (28+38+70+loop, sz 0x100-0x600): %d" % len(prefilter))

# Now decompile each and look for substring patterns
hits = []
for fea in prefilter:
    dec = safe_decompile(fea)
    if not dec: continue
    # Look for these tell-tale patterns:
    #   "v? = *(_QWORD *)(... + 40);"  -> bones_pri head
    #   "(... + 56)" or "+ 0x38" -> bones_pri count
    #   "(... + 112)" -> bone+0x70 (world)
    score = 0
    if "+ 40)" in dec or "+ 40LL)" in dec: score += 1
    if "+ 56)" in dec or "+ 56LL)" in dec or "+ 0x38)" in dec: score += 1
    if "+ 112)" in dec or "+ 112LL)" in dec or "+ 0x70)" in dec: score += 2
    if "+ 64)" in dec or "+ 64LL)" in dec: score += 1  # boneData ptr at +0x40
    if "* 0x40" in dec or "<< 6" in dec: score += 2  # output stride 64
    if "* 80" in dec or "* 0x50" in dec: score += 2  # boneData stride
    if score >= 5:
        hits.append((fea, score, dec))

hits.sort(key=lambda x: -x[1])
log(" hits with score >=5: %d" % len(hits))

for fea, score, dec in hits[:10]:
    nm = ida_funcs.get_func_name(fea) or ""
    sz = fn_size(fea)
    log("\n----- FINAL_CAND %s %s sz=0x%X score=%d rva=%s -----" % (
        hexs(fea), nm, sz, score, hexs(rva(fea))))
    for ln in dec.split("\n")[:200]:
        log("   " + ln)

# =============================================================================
# Save log
# =============================================================================
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "(", len(out), "lines )")
idaapi.qexit(0)
