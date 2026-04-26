"""
M8P3 — AGENT A v3: TARGETED final analysis.

Found candidate sub_1403FA7C0 — multiplies bone.world * inv_bind per bone.
Verify by:
  1. Decomp sub_1403F7AD0 (sole caller of FA7C0, size 0xDC) — likely the
     per-bone iterator.
  2. Decomp sub_1403FA980 (sister fn from raw4 — also reads invbind)
  3. Decomp sub_1403F74F0 + sub_1403FABF0 (callers of FA980).
  4. Trace caller chain UP from sub_1403F74F0 / sub_1403FABF0 / sub_1403F7AD0
     to see if they connect to per-frame.
  5. Decomp sub_1403FA450 (the matcher) and sub_1403F85E0 (resolver) for context.
  6. Map all callers of NiAVObject::UpdateWorldData (1416C85A0) and confirm they
     don't double as the skin update.

Output: re/_m8p3_skin_update_AGENT_A_v3_raw.log
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref, ida_ua
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_skin_update_AGENT_A_v3_raw.log"
IMG = 0x140000000
out = []
def log(s=""): out.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)
def rva(ea): return ea - IMG
def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR
def fn_size(ea):
    f = ida_funcs.get_func(ea)
    if not f: return 0
    return f.end_ea - f.start_ea
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

# Targets
TARGETS = [
    ("sub_1403FA7C0", 0x1403FA7C0),  # *** PRIME CANDIDATE: per-bone multiply
    ("sub_1403F7AD0", 0x1403F7AD0),  # caller of 1403FA7C0
    ("sub_1403FA980", 0x1403FA980),  # sister fn
    ("sub_1403F74F0", 0x1403F74F0),  # caller of 1403FA980
    ("sub_1403FABF0", 0x1403FABF0),  # caller of 1403FA980 (recursive)
    ("sub_1403F7320", 0x1403F7320),  # caller (the one in raw4 that reads name)
    ("sub_1403FA450", 0x1403FA450),  # matcher used by FA7C0
    ("sub_1404055F0", 0x1404055F0),  # mul4x4 caller — context unknown
    ("sub_1403F85E0", 0x1403F85E0),  # bone-index resolver (context only)
    ("sub_14040D770", 0x14040D770),  # caller of F7320
    ("sub_140C883E0", 0x140C883E0),  # caller of F7320 (size 0x561)
    ("sub_140CBCA00", 0x140CBCA00),  # caller of F7320 (size 0x7D2)
    ("sub_1403FB7D0", 0x1403FB7D0),  # caller of F7320 (size 0x1037, big!)
]

log("=" * 80)
log(" M8P3 SKIN UPDATE — AGENT A v3 (verify candidate sub_1403FA7C0)")
log("=" * 80)

for name, ea in TARGETS:
    sz = fn_size(ea)
    log("\n" + "=" * 80)
    log(" %s @ %s rva=%s sz=0x%X" % (name, hexs(ea), hexs(rva(ea)), sz))
    log("=" * 80)

    # Direct callers
    callers = set()
    for r in xrefs_to_code(ea):
        f = fn_start(r)
        if f != idaapi.BADADDR:
            callers.add(f)
    log(" -- callers: %d --" % len(callers))
    for c in sorted(callers):
        nm = ida_funcs.get_func_name(c) or ""
        log("   call from %s %s sz=0x%X rva=%s" % (hexs(c), nm, fn_size(c), hexs(rva(c))))

    # Decompile
    log(" -- decomp --")
    dec = safe_decompile(ea)
    if dec:
        for ln in dec.split("\n")[:200]:
            log("   " + ln)

# Also do a focused check on which fn calls into BOTH UpdateWorldData
# (1416C85A0) AND sub_1403FA7C0/FA980 — if such a fn exists, that's the master driver.
log("\n" + "=" * 80)
log(" Master driver search — fn calling UpdateWorldData AND skin-mul")
log("=" * 80)

UWD = 0x1416C85A0
SKIN_MUL_FA7C0 = 0x1403FA7C0
SKIN_MUL_FA980 = 0x1403FA980

uwd_callers = set()
for r in xrefs_to_code(UWD):
    f = fn_start(r)
    if f != idaapi.BADADDR:
        uwd_callers.add(f)

mul_callers = set()
for fn in (SKIN_MUL_FA7C0, SKIN_MUL_FA980):
    for r in xrefs_to_code(fn):
        f = fn_start(r)
        if f != idaapi.BADADDR:
            mul_callers.add(f)

# Look for transitive callers: any function that calls something in uwd_callers
# AND something in mul_callers.
log(" UWD callers: %d" % len(uwd_callers))
for f in sorted(uwd_callers):
    nm = ida_funcs.get_func_name(f) or ""
    log("   uwd %s %s sz=0x%X rva=%s" % (hexs(f), nm, fn_size(f), hexs(rva(f))))
log(" SKIN_MUL callers: %d" % len(mul_callers))
for f in sorted(mul_callers):
    nm = ida_funcs.get_func_name(f) or ""
    log("   mul %s %s sz=0x%X rva=%s" % (hexs(f), nm, fn_size(f), hexs(rva(f))))

# Walk up: find all callers of either set, look for a common ancestor.
def upcallers(ea_set, depth=4):
    seen = set(ea_set)
    layer = list(ea_set)
    for d in range(depth):
        next_layer = []
        for ea in layer:
            for r in xrefs_to_code(ea):
                f = fn_start(r)
                if f != idaapi.BADADDR and f not in seen:
                    seen.add(f)
                    next_layer.append(f)
        layer = next_layer
        if not layer:
            break
    return seen

uwd_anc = upcallers(uwd_callers, 5)
mul_anc = upcallers(mul_callers, 5)
common = uwd_anc & mul_anc

log("\n UWD ancestors (5 deep): %d" % len(uwd_anc))
log(" SKIN ancestors (5 deep): %d" % len(mul_anc))
log(" Common ancestors: %d" % len(common))
for f in sorted(common):
    nm = ida_funcs.get_func_name(f) or ""
    log("   common %s %s sz=0x%X rva=%s" % (hexs(f), nm, fn_size(f), hexs(rva(f))))

# Now look at sub_140405AC2 (caller of mul4x4 at sub_1404055F0)
# That callee context might be the actual skin matrix walker.
log("\n" + "=" * 80)
log(" sub_1404055F0 deep dive (mul4x4 caller @ +0x4D2)")
log("=" * 80)
dec = safe_decompile(0x1404055F0)
if dec:
    for ln in dec.split("\n")[:300]:
        log("   " + ln)

# =============================================================================
# Save log
# =============================================================================
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "(", len(out), "lines )")
idaapi.qexit(0)
