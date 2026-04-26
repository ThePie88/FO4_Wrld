"""
M8P3 — BSDismemberSkinInstance class layout + bone-resolver flow RE.

Goals:
  Section 1: RTTI scan -> vtable -> ctor -> field offsets
  Section 2: skin instance offset on BSGeometry (verify +0x140/+0x148/+0x150)
  Section 3: bone resolver sub_1403F85E0 — what type is `parent`? where does "_skin" stub get added?
  Section 4: full decomp of sub_14040D4C0 — map arg1 / arg2 layouts
  Section 5: pseudo-C swap recipe (assembled in dossier writer)
  Section 6: hook approach feasibility
  Section 7: confidence + risks (assembled in dossier writer)

Outputs raw evidence to _m8p3_raw.log; the human-readable dossier is assembled
in a separate writer step (see _m8p3_assemble.py).
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua
import struct, re

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_raw.log"
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
            ea2 = f + len(needle)
            f = ida_bytes.find_bytes(needle, ea2, end)
        seg = idaapi.get_next_seg(seg.start_ea)
        if len(matches) >= 16:
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
# SECTION 1 — Find BSDismemberSkinInstance via RTTI, then vtable, then ctor.
# ============================================================================
log("=" * 78)
log(" SECTION 1 — BSDismemberSkinInstance RTTI / vtable / ctor")
log("=" * 78)

# RTTI type descriptor strings start with .?AV...
rtti_strings = [
    ".?AVBSDismemberSkinInstance@@",
    ".?AVBSSkinInstance@@",
    ".?AVNiSkinInstance@@",
    ".?AVNiObject@@",
]

rtti_addrs = {}
for s in rtti_strings:
    found = find_string_addr(s)
    log(" RTTI '%s' found at %s" % (s, [hexs(a) for a in found]))
    if found:
        rtti_addrs[s] = found[0]

# Each RTTI string is referenced by the type descriptor structure; data xrefs
# from the type descriptor go to BCD entries; from BCD to BCA; from BCA to
# COL (CompleteObjectLocator); from COL to vtable. We can shortcut: search
# for an RIP-relative reference to (rtti_str - 0x10) which is the type-info
# pointer in the descriptor, but in MSVC RTTI the layout is:
#   typedesc: { ptr_typeinfo, ptr_spare, name[] }
# So strings @ rtti_str - 0x10. The classDescriptor has an xref to its name at offset 0x10.
# Easier: scan all qword globals that POINT into [rtti_str-0x10, rtti_str+1)
# i.e. that are descriptor base addresses.

def find_typedesc_for_rtti_string(str_ea):
    # The TypeDescriptor structure: its name field starts at offset 0x10. So
    # the structure base is str_ea - 0x10. Scan data xrefs to that base.
    base = str_ea - 0x10
    # MSVC TypeDescriptor doesn't have a clean RIP-relative reference; it's
    # referenced from BCD by raw 4-byte image offset (delta from imagebase).
    # In x64, RTTI uses 4-byte RVAs, not 8-byte pointers. So we scan .data /
    # .rdata for a 32-bit dword equal to (base - IMG) i.e. the RVA.
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
    return base, matches

vtables = {}  # rtti_str -> [vtable_addr,...]
for s, addr in rtti_addrs.items():
    base, hits = find_typedesc_for_rtti_string(addr)
    log("\n RTTI typedesc base for '%s' = %s, image-RVA-references count=%d"
        % (s, hexs(base), len(hits)))
    # The first reference is usually at +0x0C of a BCD record (offset to
    # TypeDescriptor) inside _RTTIBaseClassDescriptor. Then BCD record is
    # referenced by BCA, then BCA by COL. The COL is referenced by the vtable
    # at -8 from the vtable start.
    # Since x64 RVAs are signed 32-bit, multiple hits exist for parent classes
    # (the typedesc is referenced by every class that derives from it).
    for h in hits[:20]:
        log("    ref @ %s" % hexs(h))
    # We try: for each match, if it is at (some BCD)+0, treat the match-ea as
    # the BCD entry. Then look for who references THIS BCD address (as RVA).
    # The chain is messy; we instead use a heuristic for the *exact* class:
    # find the COL whose typedesc points to OUR rtti_str specifically (not a parent).
    # COL layout: { signature(4), offset(4), cdOffset(4), pTypeDescriptor(rva 4),
    #               pClassHierarchyDescriptor(rva 4), pSelf(rva 4) (newer ABI) }
    # signature is 0 (32-bit) or 1 (64-bit). offset is typically 0 for primary.
    # Heuristic: scan xrefs to this typedesc; for each ref, check if dword at
    # ref-0x0C is 0 or 1 (signature) and dword at ref-0x08 is small (offset).
    cols = []
    for h in hits:
        try:
            sig = ida_bytes.get_dword(h - 0x0C)
            ofs = ida_bytes.get_dword(h - 0x08)
            cdo = ida_bytes.get_dword(h - 0x04)
            if sig in (0, 1) and ofs < 0x10000:
                cols.append((h - 0x0C, sig, ofs, cdo))
        except Exception:
            pass
    log("    COL candidates (sig in 0/1): %d" % len(cols))
    for col_ea, sig, ofs, cdo in cols[:8]:
        log("      COL @ %s sig=%d offset=%d cdOffset=%d" % (hexs(col_ea), sig, ofs, cdo))
    # Now for each COL, find a qword in .rdata that equals col_ea: that's the
    # vtable's preceding "RTTICompleteObjectLocator*" slot at vtable-8.
    vts = []
    for col_ea, sig, ofs, cdo in cols:
        needle = struct.pack("<Q", col_ea)
        seg = ida_segment.get_segm_by_name(".rdata")
        if not seg: continue
        ea = seg.start_ea
        f = ida_bytes.find_bytes(needle, ea, seg.end_ea)
        while f != idaapi.BADADDR:
            vts.append(f + 8)  # vtable starts 8 bytes after the COL pointer
            f = ida_bytes.find_bytes(needle, f + 8, seg.end_ea)
    log("    vtable candidates (vt = COL+8): %d" % len(vts))
    for vt in vts[:8]:
        log("      vtable @ %s (RVA %s)" % (hexs(vt), hexs(rva(vt))))
    vtables[s] = vts

# Pick the BSDismemberSkinInstance vtable
bdsi_vts = vtables.get(".?AVBSDismemberSkinInstance@@", [])
log("\n>>> BSDismemberSkinInstance vtables: %s" % [hexs(v) for v in bdsi_vts])

# ============================================================================
# Find ctor: scan code that does "lea reg, [vtable]" where vtable is bdsi_vts[0]
# ============================================================================
log("\n" + "-" * 78)
log(" Searching for ctor: code that loads vtable into a fresh allocation")
log("-" * 78)

ctor_candidates = {}
for vt in bdsi_vts:
    needle = struct.pack("<Q", vt)
    refs = []
    seg = ida_segment.get_segm_by_name(".text")
    ea = seg.start_ea
    f = ida_bytes.find_bytes(needle, ea, seg.end_ea)
    while f != idaapi.BADADDR:
        refs.append(f)
        f = ida_bytes.find_bytes(needle, f + 8, seg.end_ea)
    # Also LEA-relative: scan instruction stream for lea with this displacement
    # Easier: data xrefs in IDA db
    drefs = xrefs_to_data(vt)
    for r in drefs:
        refs.append(r)
    refs = list(set(refs))
    log(" vtable %s — refs: %d" % (hexs(vt), len(refs)))
    for r in refs[:30]:
        f = fn_start(r)
        nm = ida_funcs.get_func_name(f) or ""
        log("   ref @ %s (in fn %s %s)" % (hexs(r), hexs(f), nm))
        ctor_candidates.setdefault(f, []).append(r)

log("\n ctor candidate functions (sorted by # of vtable refs):")
ranked = sorted(ctor_candidates.items(), key=lambda kv: -len(kv[1]))
for f, rs in ranked[:8]:
    nm = ida_funcs.get_func_name(f) or ""
    log("   fn %s %s — %d vtable refs" % (hexs(f), nm, len(rs)))

# Decomp the top 3 candidates (most likely ctor / dtor / vtable assigner)
log("\n" + "-" * 78)
log(" Decomp of top ctor candidates")
log("-" * 78)
for f, rs in ranked[:5]:
    if f == idaapi.BADADDR: continue
    log("\n========= candidate fn %s =========" % hexs(f))
    log("  RVA %s, size %d" % (hexs(rva(f)), ida_funcs.get_func(f).size()))
    log("  vtable-loading sites in this fn: %s" % [hexs(r) for r in rs])
    dec = safe_decompile(f)
    if dec:
        for ln in dec.split("\n"):
            log("    " + ln)

# ============================================================================
# SECTION 2 — Skin instance offset on BSGeometry; verify via sub_14040D4C0
# ============================================================================
log("\n" + "=" * 78)
log(" SECTION 2 — skin instance offset on BSGeometry; verify via sub_14040D4C0")
log("=" * 78)

# Decomp sub_14040D4C0 — bone resolver caller — to see what offset it reads
# from arg2 to get the skin instance.
caller_ea = 0x14040D4C0
log("\n========= sub_14040D4C0 (bone resolver caller) decomp =========")
dec = safe_decompile(caller_ea)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

# Also dump the full disasm of the first ~80 instructions for offset clues
log("\n========= sub_14040D4C0 disasm (first 100 insns) =========")
ea = caller_ea
for i in range(120):
    if ea == idaapi.BADADDR: break
    log("  %s   %s" % (hexs(ea), idc.GetDisasm(ea)))
    nxt = idc.next_head(ea)
    if nxt == idaapi.BADADDR: break
    ea = nxt

# ============================================================================
# SECTION 3 — bone resolver sub_1403F85E0: what is `parent`?
# ============================================================================
log("\n" + "=" * 78)
log(" SECTION 3 — sub_1403F85E0 (bone resolver) full decomp + caller chain")
log("=" * 78)

resolver_ea = 0x1403F85E0
log("\n========= sub_1403F85E0 decomp =========")
dec = safe_decompile(resolver_ea)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

log("\n========= sub_1403F85E0 disasm (first 200 insns) =========")
ea = resolver_ea
for i in range(220):
    if ea == idaapi.BADADDR: break
    log("  %s   %s" % (hexs(ea), idc.GetDisasm(ea)))
    nxt = idc.next_head(ea)
    if nxt == idaapi.BADADDR: break
    ea = nxt

# Search for "_skin" string usage
log("\n========= '_skin' string in binary =========")
for tag in ["_skin", "Skin"]:
    matches = find_string_addr(tag)
    log(" '%s' string addrs: %s" % (tag, [hexs(a) for a in matches[:8]]))
    for m in matches[:8]:
        # who references this string?
        crefs = xrefs_to_data(m)
        log("   refs to %s: %s" % (hexs(m), [hexs(r) for r in crefs[:8]]))
        for r in crefs[:8]:
            f = fn_start(r)
            nm = ida_funcs.get_func_name(f) or ""
            log("     in fn %s %s" % (hexs(f), nm))

# ============================================================================
# SECTION 4 — depth-2 caller sub_1404080E0 + sub_1404052A0
# ============================================================================
log("\n" + "=" * 78)
log(" SECTION 4 — depth-2/3 callers")
log("=" * 78)

for fn_ea, label in [(0x1404080E0, "sub_1404080E0 (depth-2)"),
                      (0x1404052A0, "sub_1404052A0 (depth-3)")]:
    log("\n========= %s decomp =========" % label)
    dec = safe_decompile(fn_ea)
    if dec:
        for ln in dec.split("\n"):
            log("  " + ln)

# ============================================================================
# Section 2b: enumerate xrefs to the BSDismemberSkinInstance vtable in code,
# look for *(qword*)(geom + 0x140 / 0x148 / 0x150) = newly_constructed_BSDSI
# ============================================================================
log("\n" + "=" * 78)
log(" SECTION 2b — find code that WRITES BSDSI* into a BSGeometry slot")
log("=" * 78)

# After ctor returns, the result is typically stored in a slot on the geometry.
# Look at all callers of any of the ctor candidates:
for f, rs in ranked[:3]:
    if f == idaapi.BADADDR: continue
    crefs = xrefs_to_code(f)
    log("\n callers of ctor cand fn %s: %d" % (hexs(f), len(crefs)))
    for r in crefs[:12]:
        cf = fn_start(r)
        nm = ida_funcs.get_func_name(cf) or ""
        log("   call from %s in fn %s %s" % (hexs(r), hexs(cf), nm))

# ============================================================================
# Section 5 — find bone count / bones array offsets by looking at how the
# ctor zeros memory and how the resolver caller iterates.
# ============================================================================
log("\n" + "=" * 78)
log(" SECTION 5 — offset tables inside ctor (bzero patterns + writes)")
log("=" * 78)

# Already have ctor decomp above. Just dump disasm explicitly for top candidate.
top_ctor = ranked[0][0] if ranked else idaapi.BADADDR
log("\n========= top ctor cand %s — disasm (first 200 insns) =========" % hexs(top_ctor))
if top_ctor != idaapi.BADADDR:
    ea = top_ctor
    for i in range(220):
        if ea == idaapi.BADADDR: break
        log("  %s   %s" % (hexs(ea), idc.GetDisasm(ea)))
        nxt = idc.next_head(ea)
        if nxt == idaapi.BADADDR: break
        ea = nxt

# Also check parent class ctor (BSSkinInstance) for inherited fields
bsskin_vts = vtables.get(".?AVBSSkinInstance@@", [])
log("\n>>> BSSkinInstance vtables: %s" % [hexs(v) for v in bsskin_vts])
for vt in bsskin_vts[:4]:
    drefs = xrefs_to_data(vt)
    log(" BSSkinInstance vt %s drefs: %s" % (hexs(vt), [hexs(r) for r in drefs[:8]]))
    for r in drefs[:6]:
        f = fn_start(r)
        nm = ida_funcs.get_func_name(f) or ""
        log("   in fn %s %s" % (hexs(f), nm))

niskin_vts = vtables.get(".?AVNiSkinInstance@@", [])
log("\n>>> NiSkinInstance vtables: %s" % [hexs(v) for v in niskin_vts])
for vt in niskin_vts[:4]:
    drefs = xrefs_to_data(vt)
    log(" NiSkinInstance vt %s drefs: %s" % (hexs(vt), [hexs(r) for r in drefs[:8]]))
    for r in drefs[:6]:
        f = fn_start(r)
        nm = ida_funcs.get_func_name(f) or ""
        log("   in fn %s %s" % (hexs(f), nm))

# Decomp NiSkinInstance ctor — most critical for layout because the deepest
# parent class often initializes the bones array / count.
if niskin_vts:
    ni_drefs = xrefs_to_data(niskin_vts[0])
    ni_ctor_cands = {}
    for r in ni_drefs:
        cf = fn_start(r)
        if cf != idaapi.BADADDR:
            ni_ctor_cands.setdefault(cf, []).append(r)
    ranked_ni = sorted(ni_ctor_cands.items(), key=lambda kv: -len(kv[1]))
    log("\n NiSkinInstance ctor candidates:")
    for f, rs in ranked_ni[:5]:
        log("   fn %s — %d refs" % (hexs(f), len(rs)))
    for f, rs in ranked_ni[:3]:
        log("\n========= NiSkinInstance ctor cand %s decomp =========" % hexs(f))
        dec = safe_decompile(f)
        if dec:
            for ln in dec.split("\n"):
                log("  " + ln)

# Also decomp BSSkinInstance ctor candidates
if bsskin_vts:
    bs_drefs = xrefs_to_data(bsskin_vts[0])
    bs_ctor_cands = {}
    for r in bs_drefs:
        cf = fn_start(r)
        if cf != idaapi.BADADDR:
            bs_ctor_cands.setdefault(cf, []).append(r)
    ranked_bs = sorted(bs_ctor_cands.items(), key=lambda kv: -len(kv[1]))
    log("\n BSSkinInstance ctor candidates:")
    for f, rs in ranked_bs[:5]:
        log("   fn %s — %d refs" % (hexs(f), len(rs)))
    for f, rs in ranked_bs[:3]:
        log("\n========= BSSkinInstance ctor cand %s decomp =========" % hexs(f))
        dec = safe_decompile(f)
        if dec:
            for ln in dec.split("\n"):
                log("  " + ln)

# ============================================================================
# Section 6 — look for the "_skin" string and trace how it's appended/used
# ============================================================================
log("\n" + "=" * 78)
log(" SECTION 6 — '_skin' string analysis in bone resolver context")
log("=" * 78)

# Specifically search for the pattern where "_skin" is appended to a name,
# i.e. a function that builds "<name>_skin" stub bones.
suffix_strs = ["_skin", " [skin]", ":skin"]
for s in suffix_strs:
    matches = find_string_addr(s)
    log(" '%s' addrs: %s" % (s, [hexs(a) for a in matches[:6]]))
    for m in matches[:4]:
        for r in xrefs_to_data(m):
            f = fn_start(r)
            nm = ida_funcs.get_func_name(f) or ""
            log("   ref @ %s in fn %s %s" % (hexs(r), hexs(f), nm))

# Write log
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "lines:", len(out_lines))
idaapi.qexit(0)
