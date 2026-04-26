"""
M8P3 v2 — Continue investigation:
  - Find BSDismemberSkinInstance RTTI with broader matching (try .?AVBSDismember*).
  - Find callers of sub_14040D4C0 to determine what type arg2 is.
  - Decomp inherited ctor sub_1416BAB90 (NiObject?) for layout below offset 0.
  - Search for the ctor of BSDismemberSkinInstance via its vtable.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref
import struct, re

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_raw2.log"
IMG = 0x140000000
out_lines = []

def log(s=""):
    out_lines.append(s if isinstance(s, str) else str(s))

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
        if len(matches) >= 32:
            break
    return matches

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

# ============================================================================
# Search for BSDismemberSkinInstance RTTI string with relaxed matching
# ============================================================================
log("=" * 78)
log(" Section A — Broad RTTI search for skin-related classes")
log("=" * 78)

# Search for any string that contains "Dismember" in .rdata
seg = ida_segment.get_segm_by_name(".rdata")
if seg:
    needle = b"Dismember"
    ea = seg.start_ea
    f = ida_bytes.find_bytes(needle, ea, seg.end_ea)
    matches = []
    while f != idaapi.BADADDR and len(matches) < 32:
        # Find the start of the string by searching backwards for null
        s_start = f
        while s_start > seg.start_ea and ida_bytes.get_byte(s_start - 1) != 0:
            s_start -= 1
        s_str = idc.get_strlit_contents(s_start, -1, 0)
        matches.append((s_start, s_str))
        f = ida_bytes.find_bytes(needle, f + 1, seg.end_ea)
    log(" 'Dismember' substring matches:")
    for sa, ss in matches[:32]:
        log("   %s : %r" % (hexs(sa), ss))

# Same for "BSSkinInstance"
if seg:
    needle = b"BSSkin"
    ea = seg.start_ea
    f = ida_bytes.find_bytes(needle, ea, seg.end_ea)
    matches = []
    while f != idaapi.BADADDR and len(matches) < 32:
        s_start = f
        while s_start > seg.start_ea and ida_bytes.get_byte(s_start - 1) != 0:
            s_start -= 1
        s_str = idc.get_strlit_contents(s_start, -1, 0)
        matches.append((s_start, s_str))
        f = ida_bytes.find_bytes(needle, f + 1, seg.end_ea)
    log("\n 'BSSkin' substring matches:")
    for sa, ss in matches[:32]:
        log("   %s : %r" % (hexs(sa), ss))

# ============================================================================
# Section B — Now find vtables for BSSkinInstance / BSDismemberSkinInstance
# ============================================================================
log("\n" + "=" * 78)
log(" Section B — Find vtables for any BSSkin/Dismember RTTI types")
log("=" * 78)

def find_vtable_for_rtti_string_ea(rtti_str_ea):
    """Given the EA of an RTTI type-name string, find the vtable that points
    at the COL referencing this typedesc.
    """
    base = rtti_str_ea - 0x10
    target_rva = (base - IMG) & 0xFFFFFFFF
    needle = struct.pack("<I", target_rva)
    matches = []
    for seg_name in [".rdata", ".data"]:
        seg = ida_segment.get_segm_by_name(seg_name)
        if not seg: continue
        ea = seg.start_ea
        f = ida_bytes.find_bytes(needle, ea, seg.end_ea)
        while f != idaapi.BADADDR:
            matches.append(f)
            f = ida_bytes.find_bytes(needle, f + 4, seg.end_ea)
            if len(matches) >= 64: break
        if len(matches) >= 64: break
    cols = []
    for h in matches:
        try:
            sig = ida_bytes.get_dword(h - 0x0C)
            ofs = ida_bytes.get_dword(h - 0x08)
            if sig in (0, 1) and ofs < 0x10000:
                cols.append(h - 0x0C)
        except Exception:
            pass
    vts = []
    for col_ea in cols:
        needle2 = struct.pack("<Q", col_ea)
        seg = ida_segment.get_segm_by_name(".rdata")
        if not seg: continue
        ea = seg.start_ea
        f = ida_bytes.find_bytes(needle2, ea, seg.end_ea)
        while f != idaapi.BADADDR:
            vts.append(f + 8)
            f = ida_bytes.find_bytes(needle2, f + 8, seg.end_ea)
    return cols, vts

# Try every name we found above
candidates = [
    "BSDismemberSkinInstance",
    "BSSkinInstance",
    "BSSkinBoneTrans",
    "NiSkinInstance",
    "NiSkinPartition",
    "NiSkinData",
]
for cls in candidates:
    rt = ".?AV%s@@" % cls
    addrs = find_string_addr(rt)
    log("\n RTTI '%s' addrs: %s" % (rt, [hexs(a) for a in addrs]))
    for a in addrs[:4]:
        cols, vts = find_vtable_for_rtti_string_ea(a)
        log("   COLs: %s   vtables: %s" % ([hexs(c) for c in cols],
                                            [hexs(v) for v in vts]))

# ============================================================================
# Section C — callers of sub_14040D4C0 to determine arg2 type
# ============================================================================
log("\n" + "=" * 78)
log(" Section C — callers of sub_14040D4C0")
log("=" * 78)

caller_ea = 0x14040D4C0
crefs = xrefs_to_code(caller_ea)
log(" callers: %d" % len(crefs))
for r in crefs[:20]:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   call @ %s in fn %s %s" % (hexs(r), hexs(f), nm))

# decomp top 4 callers
for r in crefs[:4]:
    f = fn_start(r)
    log("\n========= caller fn %s decomp =========" % hexs(f))
    dec = safe_decompile(f)
    if dec:
        for ln in dec.split("\n"):
            log("  " + ln)

# ============================================================================
# Section D — sub_1416BAB90 (NiObject base ctor?) for layout context
# ============================================================================
log("\n" + "=" * 78)
log(" Section D — base ctor sub_1416BAB90 decomp")
log("=" * 78)

dec = safe_decompile(0x1416BAB90)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

# Decomp inner helpers from NiSkinInstance ctor
for fn_ea, label in [(0x1416EEB00, "sub_1416EEB00 (NiSkin helper 1)"),
                      (0x1416EF7C0, "sub_1416EF7C0 (NiSkin helper 2)"),
                      (0x14167BDF0, "sub_14167BDF0 (BSFixedString init?)")]:
    log("\n========= %s decomp =========" % label)
    dec = safe_decompile(fn_ea)
    if dec:
        for ln in dec.split("\n"):
            log("  " + ln)

# ============================================================================
# Section E — sub_1416BD0B0 (RTTI dynamic-cast helper?) and qword_1430EEEC8
# ============================================================================
log("\n" + "=" * 78)
log(" Section E — helpers used in sub_1404080E0")
log("=" * 78)

# What is qword_1430EEEC8 — looks like an RTTI key
for ea in [0x1430EEEC8, 0x1430E1928]:
    log(" data @ %s xrefs:" % hexs(ea))
    for r in xrefs_to_data(ea)[:8]:
        f = fn_start(r)
        nm = ida_funcs.get_func_name(f) or ""
        log("   ref @ %s in fn %s %s" % (hexs(r), hexs(f), nm))

dec = safe_decompile(0x1416BD0B0)
log("\n========= sub_1416BD0B0 decomp =========")
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

# Also dump sub_1417A0A30 — this is the dynamic_cast-like used in sub_1404080E0
dec = safe_decompile(0x1417A0A30)
log("\n========= sub_1417A0A30 decomp =========")
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH)
idaapi.qexit(0)
