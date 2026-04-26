"""
M8P3 v5 — Confirm the +0x140 offset is the skin instance pointer slot ON THE GEOMETRY.

Strategy:
  - Find functions that LOAD the BSSkin::Instance vtable (0x14267E5C8) into a fresh allocation.
    Those are constructors/factories.
  - Look at the IMMEDIATE caller of each ctor. The caller writes the resulting
    `new BSSkin::Instance*` somewhere — that "somewhere" should be the +0x140 slot
    on a geometry.
  - Scan code for: `mov [rdi+140h], rax` after `call new_BSSkin::Instance`.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_raw5.log"
IMG = 0x140000000
out_lines = []
def log(s=""): out_lines.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)
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

def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR

# ============================================================================
# Section A — Find ALL functions that contain an instruction sequence
# `mov [reg+0x140], rXX` and `lea rcx/rdx, [BSSkin::Instance::vftable]`,
# meaning they store a BSSkin::Instance into a +0x140 slot.
# ============================================================================
log("=" * 78)
log(" Section A — scan code for [reg+0x140] write near a 'new BSSkin::Instance' call")
log("=" * 78)

bsi_vt = 0x14267E5C8
seg = ida_segment.get_segm_by_name(".text")
ea = seg.start_ea
end = seg.end_ea

# Find all instructions that reference BSSkin::Instance vtable as immediate
# operand (LEA/MOV displacement = bsi_vt). Then look for nearby [reg+140h] store.
hits = []
for r in xrefs_to_data(bsi_vt):
    # Check next ~50 instructions for [r+0x140] write
    cur = r
    for i in range(60):
        nxt = idc.next_head(cur)
        if nxt == idaapi.BADADDR or nxt - r > 0x180: break
        ds = idc.GetDisasm(nxt)
        if "+140h" in ds and "mov " in ds and "[" in ds:
            hits.append((r, nxt, ds))
        cur = nxt
log(" hits near BSSkin::Instance vtable lea: %d" % len(hits))
for r, w, d in hits[:20]:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   vt-load @ %s, +140h-write @ %s [%s]  in fn %s %s" % (hexs(r), hexs(w), d, hexs(f), nm))

# ============================================================================
# Section B — Find functions that have BOTH "mov [reg+140h], rax" AND a call
# to one of the BSSkin::Instance ctor candidates (sub_1416D7640, sub_1416D7710,
# sub_1416D8CC0, sub_1416D6EA0).
# ============================================================================
log("\n" + "=" * 78)
log(" Section B — broader scan: functions that call new BSSkin::Instance + write to +140h")
log("=" * 78)

ctor_eas = [0x1416D7640, 0x1416D7710, 0x1416D8CC0, 0x1416D6EA0,
            0x1416D86B0, 0x141835150, 0x141837A70]
candidates_by_ctor = {}
for c in ctor_eas:
    refs = xrefs_to_code(c)
    candidates_by_ctor[c] = refs
    log(" ctor %s: %d callers" % (hexs(c), len(refs)))
    for r in refs[:8]:
        f = fn_start(r)
        nm = ida_funcs.get_func_name(f) or ""
        log("   call @ %s in fn %s %s" % (hexs(r), hexs(f), nm))

# decomp the most interesting callers
log("\n top 6 unique callers of any ctor:")
unique = {}
for c, rs in candidates_by_ctor.items():
    for r in rs:
        f = fn_start(r)
        unique.setdefault(f, []).append((c, r))
sorted_unique = sorted(unique.items(), key=lambda kv: -len(kv[1]))
for f, info in sorted_unique[:8]:
    nm = ida_funcs.get_func_name(f) or ""
    log("   fn %s %s — %d ctor-calls inside" % (hexs(f), nm, len(info)))

# Decomp top callers that aren't themselves ctors
for f, info in sorted_unique[:6]:
    if f in ctor_eas: continue
    log("\n========= caller fn %s decomp =========" % hexs(f))
    dec = safe_decompile(f)
    if dec:
        # Just the first ~120 lines
        lines = dec.split("\n")
        for ln in lines[:120]:
            log("  " + ln)

# ============================================================================
# Section C — search for any "[reg+140h], rax" write in the binary.
# Filter: only functions that could plausibly be NIF-loaders (have many BSSkin
# refs).
# ============================================================================
log("\n" + "=" * 78)
log(" Section C — full scan for 'mov [reg+0x140], rax' instructions near 'lea rax, [BSSkin::Instance vt]'")
log("=" * 78)

# Naive instruction scan
for r in xrefs_to_data(bsi_vt):
    f = fn_start(r)
    if f == idaapi.BADADDR: continue
    fn_obj = ida_funcs.get_func(f)
    # Within this function, look for any [reg+140h] write
    fea = fn_obj.start_ea
    fend = fn_obj.end_ea
    cur = fea
    while cur < fend and cur != idaapi.BADADDR:
        ds = idc.GetDisasm(cur)
        if "140h" in ds and ("mov" in ds.lower() or "movups" in ds.lower()):
            log("   %s [in %s]   %s" % (hexs(cur), hexs(f), ds))
        cur = idc.next_head(cur)

# ============================================================================
# Section D — find the field structure beyond +0x140 by looking at how it's used
# in sub_14040D4C0:
#   v3 = *(*(a2) + 0x140)
#   v3 + 0x40 → *(qword*)(v3+0x40) is then *(.+0x10) → BoneData?
#   v3 + 0x60..0x90 → 4×4 matrix
#
# Decomp the inner of v3+0x40 to see what type. Look for what writes that
# offset on a BSGeometry-derived class.
# ============================================================================
log("\n" + "=" * 78)
log(" Section D — type of (*a2) — confirm by looking at sub_14040D230's a2 type")
log("=" * 78)
# Already have decomp. Add the NiObject vtable trail to confirm.
# qword_1430EEEC8 — what's that RTTI?
for ea in [0x1430EEEC8, 0x1430EEEB0, 0x1430E1928]:
    log("  data @ %s value: " % hexs(ea))
    val = ida_bytes.get_qword(ea)
    log("    qword = %s" % hexs(val))
    # If it's an RTTI symbol pointer, the symbol points to a typedesc
    # (`<class>::`RTTI Type Descriptor''). Look at the name.
    nm = ida_name.get_name(val) if val else ""
    log("    name = %s" % nm)
    # Try to find what string lives there
    if val and IMG <= val < IMG + 0x4000000:
        s = idc.get_strlit_contents(val + 0x10, -1, 0)
        log("    typedesc-string = %r" % s)

# ============================================================================
# Section E — verify BSGeometry/BSTriShape size and +0x140 location
# ============================================================================
log("\n" + "=" * 78)
log(" Section E — BSTriShape vtable 0x267E948 — verify class")
log("=" * 78)
bts_vt = 0x140000000 + 0x267E948
log(" BSTriShape vtable @ %s" % hexs(bts_vt))
# Find COL at vt-8
col = ida_bytes.get_qword(bts_vt - 8)
log(" COL @ %s" % hexs(col))
if col:
    typedesc_rva = ida_bytes.get_dword(col + 0x0C)  # pTypeDescriptor RVA
    typedesc = IMG + typedesc_rva
    s = idc.get_strlit_contents(typedesc + 0x10, -1, 0)
    log(" typedesc @ %s -> string %r" % (hexs(typedesc), s))

# Same for any BSGeometry vtable nearby (RTTI .?AVBSGeometry@@)
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

for cls in ["BSGeometry", "BSTriShape", "BSSubIndexTriShape", "BSDynamicTriShape", "NiAVObject"]:
    rt = ".?AV%s@@" % cls
    a = find_string_addr(rt)
    log(" '%s' addrs: %s" % (rt, [hexs(x) for x in a]))

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH)
idaapi.qexit(0)
