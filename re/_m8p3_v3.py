"""
M8P3 v3 — Continue:
  - Find BSSkin::Instance vtable via the RTTI string "BSSkin::Instance"
  - Find its ctor; map fields up to and beyond 0x140
  - Find BSSkin::BoneData ctor
  - Decomp sub_14040B630, sub_140407B70 — bone iteration helpers
  - Decomp depth-3 / what builds the bone-list array
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_raw3.log"
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
        if len(matches) >= 32: break
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

def find_vtable_for_rtti_at(rtti_str_ea):
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
        sig = ida_bytes.get_dword(h - 0x0C)
        ofs = ida_bytes.get_dword(h - 0x08)
        if sig in (0, 1) and ofs < 0x10000:
            cols.append(h - 0x0C)
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

# ============================================================================
# Section A — find BSSkin::Instance and BSSkin::BoneData vtables/ctors
# ============================================================================
log("=" * 78)
log(" Section A — BSSkin::{Instance,BoneData} vtables + ctors")
log("=" * 78)

for cls_short in ["Instance@BSSkin", "BoneData@BSSkin"]:
    rtti = ".?AV%s@@" % cls_short
    addrs = find_string_addr(rtti)
    log("\n RTTI '%s' addrs: %s" % (rtti, [hexs(a) for a in addrs]))
    for a in addrs[:2]:
        cols, vts = find_vtable_for_rtti_at(a)
        log("   vtables: %s" % [hexs(v) for v in vts])
        for vt in vts:
            drefs = xrefs_to_data(vt)
            log("    vt %s data-refs: %s" % (hexs(vt), [hexs(r) for r in drefs[:8]]))
            for r in drefs[:8]:
                f = fn_start(r)
                nm = ida_funcs.get_func_name(f) or ""
                log("      ref @ %s in fn %s %s" % (hexs(r), hexs(f), nm))
        # decomp ctor candidates
        cand = {}
        for vt in vts:
            for r in xrefs_to_data(vt):
                f = fn_start(r)
                if f != idaapi.BADADDR:
                    cand.setdefault(f, []).append(r)
        ranked = sorted(cand.items(), key=lambda kv: -len(kv[1]))
        log("    ctor candidates ranked:")
        for f, rs in ranked[:5]:
            log("     fn %s — %d refs" % (hexs(f), len(rs)))
        for f, rs in ranked[:3]:
            log("\n  ====== %s ctor cand %s decomp ======" % (cls_short, hexs(f)))
            dec = safe_decompile(f)
            if dec:
                for ln in dec.split("\n"):
                    log("    " + ln)

# ============================================================================
# Section B — sub_14040B630 — bone-iteration helper called from sub_140408EB0
# ============================================================================
log("\n" + "=" * 78)
log(" Section B — sub_14040B630 (skin iteration helper)")
log("=" * 78)
dec = safe_decompile(0x14040B630)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

# ============================================================================
# Section C — sub_140407B70 (skin->geom transform builder?)
# ============================================================================
log("\n" + "=" * 78)
log(" Section C — sub_140407B70")
log("=" * 78)
dec = safe_decompile(0x140407B70)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

# ============================================================================
# Section D — find BSSkin::Instance allocations: who creates and assigns into a slot?
#    pattern: lea rcx, [vtable]; mov [r?+offs], rax (where rax is fresh allocation)
# ============================================================================
log("\n" + "=" * 78)
log(" Section D — BSSkin::Instance vtable cross-call: who CREATES it?")
log("=" * 78)
# from above: BSSkin::Instance vtable will be discovered. Iterate xrefs; for each
# ref, find the surrounding context.

# (Already covered above via ctor candidates.)

# ============================================================================
# Section E — Decompile sub_140407EC0 and sub_140408530 (sibling helpers)
# ============================================================================
log("\n" + "=" * 78)
log(" Section E — sub_140407EC0 and sub_140408530 (sibling helpers in skin path)")
log("=" * 78)
for fn_ea, label in [(0x140407EC0, "sub_140407EC0"),
                      (0x140408530, "sub_140408530"),
                      (0x140408B10, "sub_140408B10"),
                      (0x14040D230, "sub_14040D230"),
                      (0x14040DAF0, "sub_14040DAF0")]:
    log("\n========= %s decomp =========" % label)
    dec = safe_decompile(fn_ea)
    if dec:
        for ln in dec.split("\n"):
            log("  " + ln)

# ============================================================================
# Section F — Look at the +0x140 offset usage. We expect skin_inst.+0x140 to be
# the skel_root pointer. So the BSSkin::Instance ctor must initialize +0x140
# (for example, to NULL or to an external arg).
# ============================================================================
log("\n" + "=" * 78)
log(" Section F — search code for [reg+0x140] writes that look like skin-inst init")
log("=" * 78)
# Skip — the ctor decomps above will show this.

# ============================================================================
# Section G — Decomp sub_14040B630 caller `sub_140408EB0` first half + verify
# what type is in *(a2+72) (the 'v8' passed into 14040B630)
# ============================================================================
log("\n" + "=" * 78)
log(" Section G — decomp sub_14040B630 callers")
log("=" * 78)
for r in xrefs_to_code(0x14040B630)[:8]:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   call @ %s in fn %s %s" % (hexs(r), hexs(f), nm))

# ============================================================================
# Section H — Look for a function called the FIRST time the BSSkin::Instance
# vtable is loaded (i.e. find new()/sub_NEW_BSSI). Check via heap allocator
# pattern: BSScrapHeap or sub_141677A80 calls followed by writing the vtable.
# ============================================================================
log("\n" + "=" * 78)
log(" Section H — sub_141677A80 (allocator?) signature")
log("=" * 78)
dec = safe_decompile(0x141677A80)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH)
idaapi.qexit(0)
