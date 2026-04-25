import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_search
import ida_hexrays
import ida_xref
import ida_ua
import ida_typeinf

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_bgsm_loader.log"
out_lines = []

def log(s):
    out_lines.append(s if isinstance(s, str) else str(s))

def decomp(ea, label=""):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            log("\n== %s @ 0x%X ==" % (label, ea))
            log(str(cfunc))
            return str(cfunc)
    except Exception as e:
        log("decomp err 0x%X: %s" % (ea, e))
    return None

def xrefs_to(ea):
    return list(idautils.XrefsTo(ea))

def xrefs_from(ea):
    return list(idautils.XrefsFrom(ea))

log("\n\n========================================================================")
log(" DEEP DIVE — BGSM LOADER FUNCTIONS")
log("========================================================================")

# ----------------------------------------------------------------
# 1. Decompile sub_14216B820 — refs "Path to the root bgsm file"
# ----------------------------------------------------------------
log("\n\n--- STEP 1: sub_14216B820 (refs 'Path to the root bgsm file') ---")
decomp(0x14216B820, "sub_14216B820")

# ----------------------------------------------------------------
# 2. "data\\materials\\" at 0x142462738 — find xrefs
# ----------------------------------------------------------------
log("\n\n--- STEP 2: xrefs to 'data\\materials\\' family ---")
for s_ea, s_label in [
    (0x142462738, "data\\\\materials\\\\"),
    (0x142462748, "materials\\\\"),
    (0x142462758, "data\\\\materials\\\\%s"),
    (0x14246D5B4, ".bgsm"),
    (0x14246D5BC, ".bgem"),
]:
    log("\n  === xrefs to 0x%X (%s) ===" % (s_ea, s_label))
    try:
        xrefs = xrefs_to(s_ea)
        log("    xrefs: %d" % len(xrefs))
        for x in xrefs[:20]:
            f = ida_funcs.get_func(x.frm)
            fstart = f.start_ea if f else 0
            fname = ida_funcs.get_func_name(fstart) if f else "?"
            log("      xref from 0x%X   func 0x%X %s" % (x.frm, fstart, fname))
    except Exception as e:
        log("    err %s" % e)

# ----------------------------------------------------------------
# 3. BSMaterialDB anchors — find TypeDescriptor cross-refs to find vtables / factories
# ----------------------------------------------------------------
log("\n\n--- STEP 3: find functions on BSMaterialDB EntryDB vtable ---")
# For RTTI at 0x14309C140 — find TypeDescriptor 16 bytes earlier
for rtti_name_ea in [0x14309C140, 0x14309C4C8, 0x142F98400]:
    td = rtti_name_ea - 0x10
    log("\n  TypeDescriptor candidate @ 0x%X (for RTTI name @ 0x%X)" % (td, rtti_name_ea))
    xrefs = xrefs_to(td)
    log("    xrefs to TD: %d" % len(xrefs))
    for x in xrefs[:20]:
        log("      from 0x%X" % x.frm)

# ----------------------------------------------------------------
# 4. Trace xrefs to "BSLightingShaderMaterialBase" and "BSLightingShaderMaterial"
#    to find their ctors / dispatch fn.
# ----------------------------------------------------------------
log("\n\n--- STEP 4: BSLightingShaderMaterial type hierarchy xrefs ---")
for rtti_ea, name in [
    (0x1430D0CC0, "BSLightingShaderMaterial@@"),
    (0x1430D0CF0, "BSLightingShaderMaterialBase@@"),
]:
    td = rtti_ea - 0x10
    log("\n  TypeDescriptor @ 0x%X (%s)" % (td, name))
    xrefs = xrefs_to(td)
    log("    xrefs to TD: %d" % len(xrefs))
    for x in xrefs[:30]:
        log("      from 0x%X" % x.frm)

# ----------------------------------------------------------------
# 5. Search for the signature string "materialVersion" or identifying bytes
#    that only .bgsm parser would reference
# ----------------------------------------------------------------
log("\n\n--- STEP 5: search for BGSM internal field strings ---")
try:
    for s in idautils.Strings():
        try:
            sval = str(s)
            key = False
            for kw in ["sDiffuseTexture", "diffuseTexture", "bgsmVersion", "bSlotted",
                       "bIsModelSpaceNormal", "bHideSecret", "sNormalTexture",
                       "bSubsurfaceLighting", "subsurface", "Subsurface", "materialVersion",
                       "sRootMaterialPath", "ClassVersion", "RootMaterialPath",
                       "bEnableEditorAlphaRef", "bReceiveShadows"]:
                if kw.lower() in sval.lower():
                    key = True
                    break
            if key:
                log("  str 0x%X: %r" % (s.ea, sval[:80]))
        except:
            pass
except Exception as e:
    log("err: %s" % e)

# ----------------------------------------------------------------
# 6. Decompile sub_14216B820 (the bgsm-path diag fn) + larger context
# ----------------------------------------------------------------
log("\n\n--- STEP 6: decompile context around 0x14216B820 ---")
# try up-to-5 callers
cx = xrefs_to(0x14216B820)
log("  xrefs to sub_14216B820: %d" % len(cx))
for x in cx[:10]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("    call from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("deep probe done")
idc.qexit(0)
