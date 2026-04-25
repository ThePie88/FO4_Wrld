"""
M7.b Ghost body anim graph RE script.

Investigates:
  Q1 — Standalone BSFadeNode animatable? SimpleAnimationGraphManagerHolder ctor
  Q2 — SetAnimationVariableFloat signature + RVA
  Q3 — Which behavior .hkx for MaleBody humanoid
  Q4 — Full Actor::Load3D pipeline at sub_140458740
  Q5 — Minimal recipe with RVAs
  Q6 — Gotchas

Output: re/_anim_graph_m7.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_anim_graph_m7.log"
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

def find_string_addr(s):
    """Find ANSI string in data segments."""
    for seg in ["RVA", ".rdata", ".data"]:
        pass
    matches = []
    # Search all segments for the literal bytes.
    needle = s.encode("utf-8") + b"\x00"
    ea = 0
    seg = idaapi.get_first_seg()
    while seg:
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            f = ida_bytes.find_bytes(needle, ea, end)
            if f == idaapi.BADADDR:
                break
            matches.append(f)
            ea = f + len(needle)
        seg = idaapi.get_next_seg(seg.start_ea)
        if len(matches) >= 16:
            break
    return matches

_STRING_CACHE = None

def _build_string_cache():
    """Build a dict {string -> [ea,...]} once."""
    global _STRING_CACHE
    if _STRING_CACHE is not None:
        return _STRING_CACHE
    _STRING_CACHE = {}
    try:
        ss = idautils.Strings()
        try:
            ss.setup()  # may not exist in 9.x
        except:
            pass
        for sx in ss:
            try:
                t = str(sx)
                _STRING_CACHE.setdefault(t, []).append(sx.ea)
            except:
                pass
    except Exception as e:
        log("string-cache err: %s" % e)
    return _STRING_CACHE

def find_string_simple(s):
    cache = _build_string_cache()
    return list(cache.get(s, []))

def xrefs_to(ea):
    try:
        return list(idautils.XrefsTo(ea))
    except:
        return []

def code_xrefs_to(ea):
    return [x for x in xrefs_to(ea) if x.iscode]

def name_at(ea):
    try:
        n = ida_name.get_name(ea)
        if n: return n
    except: pass
    try:
        n = ida_funcs.get_func_name(ea)
        if n: return n
    except: pass
    return "?"

# =============================================================
log("=" * 78)
log(" M7.b GHOST BODY ANIMATION RE")
log(" Fallout4.exe 1.11.191 next-gen   |  ImageBase 0x140000000")
log("=" * 78)

# =============================================================
# SECTION A — Find RTTI anchors for anim graph classes
# =============================================================
log("")
log("=" * 78)
log(" A. RTTI ANCHORS — anim graph class type info")
log("=" * 78)

rtti_targets = [
    ".?AVIAnimationGraphManagerHolder@@",
    ".?AVSimpleAnimationGraphManagerHolder@@",
    ".?AVExtraAnimGraphManager@@",
    ".?AVExtraAnimGraphPreload@@",
    ".?AVIAnimationGraphManagerLoadingTask@@",
    ".?AVhkbBehaviorGraph@@",
    ".?AVhkbCharacter@@",
    ".?AVhkbCharacterSetup@@",
    ".?AVhkbCharacterStringData@@",
]

rtti_eas = {}
for t in rtti_targets:
    eas = find_string_simple(t)
    if eas:
        log("  %s @ %s" % (t, ", ".join(hexs(e) for e in eas)))
        rtti_eas[t] = eas[0]
    else:
        log("  %s — NOT FOUND" % t)

# For each RTTI string, find the TypeDescriptor reference (xrefs from data)
log("")
log("--- Searching for TypeDescriptor + COL + vtable for SimpleAnimationGraphManagerHolder")
def find_typedescriptors(rtti_str_ea):
    """Vtable->ObjLocator->ClassHierarchy->... eventually points at the type-name string.
       In x64 MSVC RTTI, .data has TypeDescriptors with: vftable_ptr, _0, name[].
       We expect xrefs FROM data segments TO rtti_str_ea+0x10 typically (the name field
       is at +0x10 inside the TypeDescriptor)."""
    type_descs = []
    # The RTTI string is contained INSIDE a TypeDescriptor — the TD starts 0x10 bytes earlier.
    td_ea = rtti_str_ea - 0x10
    type_descs.append(td_ea)
    return type_descs

for t, ea in rtti_eas.items():
    if "AnimationGraphManagerHolder" in t or "ExtraAnimGraph" in t:
        td = ea - 0x10  # MSVC RTTI: TypeDescriptor.name is at offset +0x10
        log("  %s — TypeDescriptor @ %s (string @ %s)" % (t, hexs(td), hexs(ea)))
        # Now find xrefs to the TypeDescriptor (these are "Object Locator" references in vtables)
        x = list(xrefs_to(td))
        for xr in x[:8]:
            log("    xref -> %s (type %d, iscode %d)" % (hexs(xr.frm), xr.type, xr.iscode))

# =============================================================
# SECTION B — Find SetAnimationVariableFloat Papyrus native + engine fn
# =============================================================
log("")
log("=" * 78)
log(" B. SetAnimationVariableFloat — Papyrus native + engine function")
log("=" * 78)

papyrus_strings = {
    "SetAnimationVariableFloat": [],
    "SetAnimationVariableBool":  [],
    "SetAnimationVariableInt":   [],
    "GetAnimationVariableFloat": [],
    "GetAnimationVariableBool":  [],
    "Papyrus SetAnimationVariableFloat": [],
}

for s in list(papyrus_strings.keys()):
    eas = find_string_simple(s)
    papyrus_strings[s] = eas
    log("  %r — %d hits: %s" % (s, len(eas), ", ".join(hexs(e) for e in eas)))

# For SetAnimationVariableFloat, walk xrefs to find the binding fn (Papyrus native registrar)
log("")
log("--- Walking xrefs to 'SetAnimationVariableFloat' string ---")
for str_ea in papyrus_strings.get("SetAnimationVariableFloat", []):
    log("  String @ %s:" % hexs(str_ea))
    for xr in xrefs_to(str_ea):
        log("    xref from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))
        # The binder pattern: lea rdx, "SetAnimationVariableFloat" / lea rcx, NativeFn / call BindNative
        # Walk forward up to ~32 bytes from xref looking for a "lea rcx, sub_...." pattern.
        ea = xr.frm
        for step in range(16):
            cur = ea + step
            mnem = idc.print_insn_mnem(cur)
            if mnem == "lea":
                op1 = idc.print_operand(cur, 0)
                op2 = idc.print_operand(cur, 1)
                if "rcx" in op1.lower():
                    target = idc.get_operand_value(cur, 1)
                    if target and ida_funcs.get_func(target):
                        log("      FOUND lea rcx -> %s (%s) at %s" %
                            (hexs(target), name_at(target), hexs(cur)))
                        # This is the Papyrus native fn. Decomp it.
                        decomp(target, "Papyrus SetAnimationVariableFloat native")
                        break

# =============================================================
# SECTION C — Find SimpleAnimationGraphManagerHolder ctor + vtable
# =============================================================
log("")
log("=" * 78)
log(" C. SimpleAnimationGraphManagerHolder — ctor, vtable, methods")
log("=" * 78)

# Strategy: TypeDescriptor xrefs lead to Object Locators (PMD), which are referenced
# by vtables. We look for data refs to a pattern: TypeDescriptor inside ObjLocator.
sahmh_str_ea = rtti_eas.get(".?AVSimpleAnimationGraphManagerHolder@@", None)
def find_vtables_via_typedescriptor(td_ea, label=""):
    """Walk MSVC RTTI: TD <- COL <- vtable[-1].
       Returns list of vtable_start EAs (the EA of vt[0])."""
    vtables = []
    image_base = 0x140000000
    # Find xrefs to TD; these are inside Object Locators (COL).
    # The COL has the TD as a 32-bit RVA at offset +0xC.
    # IDA may have created an xref for the RVA32 -> ea_in_image.
    log("    [%s] xrefs to TypeDescriptor %s:" % (label, hexs(td_ea)))
    for xr in xrefs_to(td_ea):
        # xr.frm should be inside a COL data structure. The COL starts 0xC bytes earlier.
        col_ea = xr.frm - 0xC
        log("      possible COL @ %s" % hexs(col_ea))
        # Now find xrefs to the COL — these will be the vtable[-1] slots.
        # vtable starts at slot+8.
        for xr2 in xrefs_to(col_ea):
            vt_start = xr2.frm + 8
            vtables.append(vt_start)
            log("        vtable @ %s (xref slot at %s)" % (hexs(vt_start), hexs(xr2.frm)))
    return vtables

if sahmh_str_ea:
    td = sahmh_str_ea - 0x10
    log("SAHMH TypeDescriptor @ %s" % hexs(td))
    # Find references to the TypeDescriptor
    log("Direct xrefs to TypeDescriptor:")
    for xr in xrefs_to(td):
        log("  from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))
    sahmh_vts = find_vtables_via_typedescriptor(td, "SimpleAnimationGraphManagerHolder")

# The Object Locator in MSVC RTTI structure:
#   +0  signature
#   +4  offset
#   +8  cdOffset
#   +0xC TypeDescriptor (RVA32)
#   +0x10 ClassDescriptor (RVA32)
# So we want to look for a 4-byte slot near 'td' that equals (td - imagebase).
# Then up-stream vtables point at the Object Locator.

# Easier approach: scan .rdata for any qword dereferenced as (objLocPtr - 8)
# i.e. typical vtable layout: vtable[-1] = ObjLocator.

# Actually simplest: enumerate names that contain "SimpleAnimationGraphManagerHolder"
log("")
log("--- IDA names containing 'SimpleAnimationGraph' ---")
for n_ea, n in idautils.Names():
    if "SimpleAnimationGraph" in n or "AnimationGraphManagerHolder" in n:
        log("  %s  %s" % (hexs(n_ea), n))

# Also names with hkb-prefix
log("")
log("--- IDA names containing 'hkbBehaviorGraph' or 'hkbCharacter' ---")
for n_ea, n in idautils.Names():
    if "hkbBehaviorGraph" in n or "hkbCharacter" in n:
        log("  %s  %s" % (hexs(n_ea), n))

# =============================================================
# SECTION D — SetAnimGraphVar console command
# =============================================================
log("")
log("=" * 78)
log(" D. 'SetAnimGraphVar' console command — code path to engine fn")
log("=" * 78)

sagv_eas = find_string_simple("SetAnimGraphVar")
log("'SetAnimGraphVar' string locations: %s" % ", ".join(hexs(e) for e in sagv_eas))
for str_ea in sagv_eas:
    for xr in xrefs_to(str_ea):
        log("  xref from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))
        # Find enclosing function
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("    fn: %s @ %s..%s" % (name_at(f.start_ea), hexs(f.start_ea), hexs(f.end_ea)))

# =============================================================
# SECTION E — Anim graph variable strings (xrefs)
# =============================================================
log("")
log("=" * 78)
log(" E. Anim graph variable strings (engine usage of names)")
log("=" * 78)

vars_to_check = [
    "AimPitchCurrent",
    "AimPitchMaxUp",
    "AimPitchMaxDown",
    "HeadPitch", "HeadYaw", "HeadRoll",
    "SpeedSampled", "SpeedSmoothed",
    "Direction", "DirectionDegrees",
    "TurnDelta", "TurnDeltaSmoothed",
    "Strafe Mult",
    "IsMoving", "IsRunning",
    "iAnimatedTransitionMillis:Camera",
]

for v in vars_to_check:
    eas = find_string_simple(v)
    if eas:
        for str_ea in eas:
            xrs = list(xrefs_to(str_ea))
            log("  %r @ %s — %d xrefs" % (v, hexs(str_ea), len(xrs)))
            for xr in xrs[:4]:
                f = ida_funcs.get_func(xr.frm)
                fn = name_at(f.start_ea) if f else "?"
                log("      from %s in %s" % (hexs(xr.frm), fn))

# =============================================================
# SECTION F — Actor::Load3D pipeline
# =============================================================
log("")
log("=" * 78)
log(" F. Actor::Load3D (sub_140458740) — full pipeline decomp")
log("=" * 78)

decomp(0x140458740, "sub_140458740 Actor::Load3D-like")
log("")
decomp(0x14033D1E0, "sub_14033D1E0 REFR::Load3D")

# =============================================================
# SECTION G — NIF loader sub_1417B3E90 — what about behavior loading?
# =============================================================
log("")
log("=" * 78)
log(" G. NIF loader sub_1417B3E90 (the one we use) — flags + behavior?")
log("=" * 78)

decomp(0x1417B3E90, "sub_1417B3E90 (NIF loader entry we use)")

# =============================================================
# SECTION H — Find the function that creates anim graph manager from vanilla load path
# =============================================================
log("")
log("=" * 78)
log(" H. Searching for likely SimpleAnimationGraphManagerHolder ctor candidates")
log("=" * 78)

# The ctor will reference the vtable, which points back at the Object Locator,
# which points at the TypeDescriptor. So we walk: TypeDescriptor -> ObjLocator -> vtable -> ctor.

if sahmh_str_ea:
    td = sahmh_str_ea - 0x10
    # Find all xrefs to the TypeDescriptor — they'll be Object Locators.
    log("Looking for Object Locators referencing the TD %s..." % hexs(td))
    for xr in xrefs_to(td):
        if not xr.iscode:
            ol_ea = xr.frm - 0xC  # ObjectLocator field cdOffset+TD ref at +0xC
            log("  Possible ObjectLocator @ %s (xref slot at %s)" % (hexs(ol_ea), hexs(xr.frm)))
            # Now find xrefs to this ObjectLocator — they'll be vtables (vtable[-1])
            for xr2 in xrefs_to(ol_ea):
                vt_ea = xr2.frm + 8  # vtable starts 8 bytes after ObjectLocator pointer slot
                log("    Possible vtable starts at %s" % hexs(vt_ea))
                # Dump first 16 vtable entries
                for i in range(16):
                    v = ida_bytes.get_qword(vt_ea + i*8)
                    fn = name_at(v) if ida_funcs.get_func(v) else "?"
                    log("      vt[%d] = %s (%s)" % (i, hexs(v), fn))
                # vt[0] is typically the dtor. The CTOR sets vt_ea - we look for
                # functions that write vt_ea to *rcx. Scan xrefs to vt_ea (data refs).
                log("    vtable xrefs (looking for ctor writing vtable):")
                for xr3 in xrefs_to(vt_ea):
                    f = ida_funcs.get_func(xr3.frm)
                    if f:
                        log("      from %s in %s @ %s" %
                            (hexs(xr3.frm), name_at(f.start_ea), hexs(f.start_ea)))

# =============================================================
# SECTION I — Looking for 'Behaviors' folder string + load behavior fn
# =============================================================
log("")
log("=" * 78)
log(" I. Behavior .hkx loading — search for paths and loader")
log("=" * 78)

beh_strings = [
    "FirstPersonBase.hkx",
    "Behaviors\\",
    "Behaviors/",
    ".hkx",
    "Meshes\\Actors\\",
    "Actors\\Character\\Behaviors",
    "Race\\Behavior",
    "BehaviorPath",
]
for s in beh_strings:
    eas = find_string_simple(s)
    if eas:
        for str_ea in eas:
            log("  %r @ %s" % (s, hexs(str_ea)))
            for xr in list(xrefs_to(str_ea))[:6]:
                f = ida_funcs.get_func(xr.frm)
                fn = name_at(f.start_ea) if f else "?"
                log("      xref from %s in %s" % (hexs(xr.frm), fn))

# =============================================================
# SECTION J — IAnimationGraphManagerHolder vtable methods (likely entry points)
# =============================================================
log("")
log("=" * 78)
log(" J. IAnimationGraphManagerHolder — interface dispatch entry points")
log("=" * 78)

iah_str = rtti_eas.get(".?AVIAnimationGraphManagerHolder@@")
if iah_str:
    td = iah_str - 0x10
    log("IAnimationGraphManagerHolder TD @ %s" % hexs(td))
    for xr in xrefs_to(td):
        if not xr.iscode:
            ol_ea = xr.frm - 0xC
            log("  Possible ObjLocator @ %s" % hexs(ol_ea))
            for xr2 in xrefs_to(ol_ea):
                vt_ea = xr2.frm + 8
                log("    vtable @ %s" % hexs(vt_ea))
                for i in range(20):
                    v = ida_bytes.get_qword(vt_ea + i*8)
                    if v == 0:
                        break
                    fn = name_at(v) if ida_funcs.get_func(v) else "?"
                    log("      vt[%d] = %s (%s)" % (i, hexs(v), fn))

# =============================================================
# DONE
# =============================================================
log("")
log("=" * 78)
log(" END")
log("=" * 78)

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Wrote %s (%d lines)" % (LOG_PATH, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
