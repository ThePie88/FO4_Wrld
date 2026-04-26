"""
M8P3 v4 — Pin down the resolver chain:
  - Decomp sub_1416C6B30 (hash helper)
  - Decomp sub_1403FB5F0 (real lookup)
  - Decomp sub_1403FCA10 ("%s_skin" sprintf-like)
  - Look at the FIRST argument 'parent' to the resolver: what are its likely types?
  - Find type of *a2 in sub_14040D4C0 by tracing — look at sub_14040D230's a2:
      v4 = (*(qword*)a2 + 32)(a2)  — virtual call on a2->vt[4]
      a2->vt[13] returns NiAVObject* (the BSGeometry)
  - Now check which slot stores the skin instance — check if it's truly +0x140 in a BSGeometry-ish layout, or if it's on the BSDismemberSkinInstance partition (32-byte entry).
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_raw4.log"
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
# Decomp resolver helpers
# ============================================================================
log("=" * 78)
log(" Section A — sub_1416C6B30 (hash helper)")
log("=" * 78)
dec = safe_decompile(0x1416C6B30)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

log("\n" + "=" * 78)
log(" Section B — sub_1403FB5F0 (real lookup)")
log("=" * 78)
dec = safe_decompile(0x1403FB5F0)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

log("\n" + "=" * 78)
log(" Section C — sub_1403FCA10 ('%s_skin' formatter)")
log("=" * 78)
dec = safe_decompile(0x1403FCA10)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

log("\n" + "=" * 78)
log(" Section D — sub_14167C070 (BSFixedString getter on name?)")
log("=" * 78)
dec = safe_decompile(0x14167C070)
if dec:
    for ln in dec.split("\n"):
        log("  " + ln)

# ============================================================================
# Section E — find what types `parent` (a1 of resolver) and the context structure
# look like. The resolver does:
#   v13 = sub_1416C6B30(*(qword*)(a1 + 72), 1);
#   v8[0] = &v13;
#   v8[1] = &v12;     // v12 = a1 itself
#   v8[2] = ...;       // not visible — probably a hash/equal callback
#
# So 'a1+72=+0x48' is a "key" passed to a hash-init helper.
# Let's check sub_1403FB5F0's signature & layout to see what context struct it
# expects.
# ============================================================================
log("\n" + "=" * 78)
log(" Section E — sub_1403FB5F0 disasm first 80 insns")
log("=" * 78)
ea = 0x1403FB5F0
for i in range(80):
    if ea == idaapi.BADADDR: break
    log("  %s   %s" % (hexs(ea), idc.GetDisasm(ea)))
    nxt = idc.next_head(ea)
    if nxt == idaapi.BADADDR: break
    ea = nxt

# ============================================================================
# Section F — look at the OTHER caller of sub_1403F85E0 to confirm the parent
# is/isn't a skin instance vs a NiNode.
# ============================================================================
log("\n" + "=" * 78)
log(" Section F — all callers of sub_1403F85E0 (resolver)")
log("=" * 78)
crefs = xrefs_to_code(0x1403F85E0)
log(" callers count: %d" % len(crefs))
for r in crefs[:20]:
    f = fn_start(r)
    nm = ida_funcs.get_func_name(f) or ""
    log("   call @ %s in fn %s %s" % (hexs(r), hexs(f), nm))

# Decomp top 4 callers
for r in crefs[:6]:
    f = fn_start(r)
    if f == idaapi.BADADDR: continue
    log("\n========= caller fn %s decomp =========" % hexs(f))
    dec = safe_decompile(f)
    if dec:
        for ln in dec.split("\n"):
            log("  " + ln)

# ============================================================================
# Section G — sub_140651780 / sub_140664AD0 (the only places that ref "_skin"
# string directly as a literal — likely the place that names "_skin" stub bones
# during NIF parse). Decomp them.
# ============================================================================
log("\n" + "=" * 78)
log(" Section G — '_skin' stub-naming functions")
log("=" * 78)
for fn_ea, label in [(0x140651780, "sub_140651780"),
                      (0x140664AD0, "sub_140664AD0")]:
    log("\n========= %s decomp =========" % label)
    dec = safe_decompile(fn_ea)
    if dec:
        for ln in dec.split("\n"):
            log("  " + ln)

# ============================================================================
# Section H — Check if BSSkin::Instance has a derived class containing +0x140
# ============================================================================
log("\n" + "=" * 78)
log(" Section H — extra: vtable size of 0x14267E5C8 (BSSkin::Instance)")
log("=" * 78)
vt = 0x14267E5C8
slot_count = 0
for i in range(80):
    addr = vt + 8 * i
    val = ida_bytes.get_qword(addr)
    if val == 0 or not (IMG <= val < IMG + 0x4000000):
        break
    slot_count = i + 1
    name = ida_funcs.get_func_name(val) or ""
    log("  vt[%2d] = %s %s" % (i, hexs(val), name))
log(" total visible vt slots: %d" % slot_count)

# Cross-class check: see if there's a derived class. Maybe BSSkin::Instance
# itself contains the bone array. From ctor sub_1416D7640 we see:
#   +0x10 — BSTArray init (sub_1416597B0) → bones array
#   +0x20 — DWORD count (sub_141659470) → bone_count
# Or maybe:
#   +0x28 — second BSTArray
#   +0x38 — its DWORD count
# So bones[] is at +0x10 and bone_count is at +0x20. Need to verify which.
# +0x40 — qword (NiPointer? skel root)
# +0x48 — qword (this is what the resolver reads as "key")
# +0x50, +0x58 — qword/dword
# +0x60..+0x9F — 4 OWORDs (transform matrix)
# +0xA0..+0xB8 — 3 qwords + 2 dwords
log("\n EXPECTED LAYOUT FROM CTOR:")
log("  +0x00  vtable (NiObject)")
log("  +0x08  refcount (DWORD), padding")
log("  +0x10  BSTArray<NiPointer<NiAVObject>> bones — head ptr")
log("  +0x18  BSTArray<...>      capacity / etc")
log("  +0x20  BSTArray<...>      count (DWORD)")
log("  +0x28  BSTArray (second array — possibly transforms or partitions)")
log("  +0x30  BSTArray (cap)")
log("  +0x38  BSTArray count")
log("  +0x40  qword (BSSkin::BoneData* — the partition/inverse-bind data)")
log("  +0x48  qword (a 'key' field — possibly skel_root NiPointer or BSFixedString name)")
log("  +0x50  qword")
log("  +0x58  DWORD,+0x5C DWORD")
log("  +0x60..+0x9F  4 OWORDs (transform matrix 4x4)")
log("  +0xA0..+0xB8  qwords")

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH)
idaapi.qexit(0)
