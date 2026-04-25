"""
M7.b Pass 2 — Find Actor::Get3D / loaded3D offset.

Approach: Papyrus Is3DLoaded at sub_14115EFB0 calls Actor::Get3D internally.
Decompile and walk the chain to find the actual offset.

Also decompile:
  - sub_140255D40 (the recurse-into-children fn called by walker)
  - small Get3D-style accessors that may match patterns
  - REFR Setup3D path

Output: re/_player_copy_m7_2_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_2_raw.log"
out_lines = []

def log(s):
    out_lines.append(s if isinstance(s, str) else str(s))

def hexs(x):
    try:
        return "0x%X" % x
    except:
        return str(x)

def decomp(ea, label=""):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            log("\n========== %s @ %s ==========" % (label, hexs(ea)))
            log(str(cfunc))
            return cfunc
    except Exception as e:
        log("decomp err %s: %s" % (hexs(ea), e))
    return None

def xrefs_to(ea, max_=20):
    out = []
    for r in idautils.XrefsTo(ea):
        out.append((r.frm, r.iscode, r.type))
        if len(out) >= max_:
            break
    return out

def func_containing(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None

# ============================================================================
# Q1: Decompile Papyrus Is3DLoaded (sub_14115EFB0)
# ============================================================================
log("=" * 80)
log(" M7.b PASS 2 — Get3D offset hunt")
log("=" * 80)

log("\n--- Q1.A: Papyrus Is3DLoaded sub_14115EFB0 ---")
decomp(0x14115EFB0, "sub_14115EFB0 Papyrus Is3DLoaded")

# Surrounding Papyrus natives may also reveal the offset
log("\n--- Q1.B: Decompile sub_140255D40 (walker recurse-into-children) ---")
decomp(0x140255D40, "sub_140255D40 walker_recurse_or_filter")

# ============================================================================
# Q1.C: Search for "Loaded3D" string xrefs (the engine debug-prints this)
# ============================================================================
log("\n--- Q1.C: 'Loaded3D' string xrefs ---")
loaded3d_addr = 0x1424B6F13
for fr, _, _ in xrefs_to(loaded3d_addr, 30):
    f = func_containing(fr)
    log("  xref from %s (in fn %s)" % (hexs(fr), hexs(f) if f else "?"))
    if f:
        decomp(f, "Loaded3D xref fn @ %s" % hexs(f))

# ============================================================================
# Q1.D: Decompile suspected Get3D — the engine frequently has small fns
# returning loadedData ptr. CommonLibF4 layout puts loadedData at TESObjectREFR
# offset 0x68 in older builds; for FO4 next-gen could be 0x68 or different.
# Find the Get3D accessor by xref to sub_140255BA0 (apply_materials walker)
# from REFR::Load3D / Actor::Load3D. The walker is called RIGHT AFTER 3D load.
# ============================================================================
log("\n--- Q1.D: Xrefs to sub_140255BA0 apply_materials walker ---")
for fr, _, _ in xrefs_to(0x140255BA0, 30):
    f = func_containing(fr)
    n = ida_name.get_ea_name(f) if f else "?"
    log("  xref from %s (in fn %s, %s)" % (hexs(fr), hexs(f) if f else "?", n))

# ============================================================================
# Q1.E: REFR::Load3D was sub_14033D1E0 per prior dossier — decomp it
# ============================================================================
log("\n--- Q1.E: sub_14033D1E0 REFR::Load3D ---")
decomp(0x14033D1E0, "sub_14033D1E0 REFR::Load3D")

# ============================================================================
# Q1.F: PC vt[17] sub_140D63490 — could be Setup3D / Load3D wrapper
# (vt[18] turned out to be LoadGame deserializer)
# ============================================================================
log("\n--- Q1.F: PC vt[17] sub_140D63490 ---")
decomp(0x140D63490, "sub_140D63490 PC vt[17]")

# ============================================================================
# Q2: SetParent — find children offset confirmation. Already known but
# also look at NiNode::DetachChildAt to confirm bone structure manipulation.
# ============================================================================
log("\n--- Q2.A: sub_1416BE390 NiNode::DetachChild ---")
decomp(0x1416BE390, "sub_1416BE390 NiNode::DetachChild")

log("\n--- Q2.B: sub_1416C8B60 NiAVObject::SetParent ---")
decomp(0x1416C8B60, "sub_1416C8B60 NiAVObject::SetParent")

# ============================================================================
# Q3: Find functions that read NiAVObject local.rotate (offset 0x30) or
# local.translate (offset 0x60) — confirms our offsets are right and shows
# where in code we'd inject.
# ============================================================================

# Find NiTransform::ApplyTransform / NiAVObject::UpdateNode functions —
# they read +0x30/+0x60 and write +0x70/+0xA0.
log("\n--- Q3.A: sub_1416B6530 (called 3x in NiAVObject::ctor — transform init) ---")
decomp(0x1416B6530, "sub_1416B6530 NiTransform::Init")

# ============================================================================
# Q4: Find xrefs to UpdateDownwardPass to see canonical caller pattern
# ============================================================================
log("\n--- Q4.A: Xrefs to sub_1416C8050 UpdateDownwardPass ---")
for fr, _, _ in xrefs_to(0x1416C8050, 40):
    f = func_containing(fr)
    n = ida_name.get_ea_name(f) if f else "?"
    log("  xref from %s (in fn %s, %s)" % (hexs(fr), hexs(f) if f else "?", n))

# ============================================================================
# Q5: Find the bone-by-name search function. Look at xrefs to "SPINE2", "HEAD"
# and find which engine fn iterates bones.
# ============================================================================

# CommonLibF4 has NiNode::GetObjectByName which is a vt slot, not a free fn.
# Let's find it by searching for short fns that walk children and compare names.
# Pattern hint: GetObjectByName recursively walks children[i] checking m_name.
# Such fn calls itself recursively on children.

log("\n--- Q5.A: Look up vt[?] of NiNode for GetObjectByName ---")
# NiNode vtable @ 0x267C888 — read a few slots
NINODE_VT = 0x14267C888
for slot in range(0, 75):
    fn = ida_bytes.get_qword(NINODE_VT + slot * 8)
    if not fn or fn == idaapi.BADADDR:
        continue
    name = ida_name.get_ea_name(fn)
    f = ida_funcs.get_func(fn)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("  NiNode vt[%2d] = %s  size=%-6d  %s" % (slot, hexs(fn), sz, name or ""))

# ============================================================================
# Q6: Sample one suspect Get3D-fingerprint from the previous dump and decompile
# ============================================================================
# 0x141297720: 488b41088b4020c3  — mov rax, [rcx+8]; mov eax, [rax+0x20]; ret
# Not 3D — too small dword.
# Look for fns that return a pointer-sized value through a 1-2 step deref.
log("\n--- Q6.A: Decomp some likely Get3D candidates (medium-size accessors) ---")

# These look like 2-deref fns from disp 0x60 or 0x68.
# 0x140E58440 size=8 disp=0x48
# Let's try 0x1402182F0 (different shape)
candidates = [0x1402182F0, 0x140E58440, 0x140E58730, 0x141441850, 0x1414DD580,
              0x141297720, 0x14130DA60]
for c in candidates:
    decomp(c, "candidate fn @ %s" % hexs(c))

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))

print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
