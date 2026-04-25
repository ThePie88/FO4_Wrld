import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_search
import ida_hexrays
import ida_xref

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

def find_string_ea(needle, ci=True):
    """find all EAs whose string content contains `needle`."""
    out = []
    try:
        for s in idautils.Strings():
            try:
                sval = str(s)
                if (sval.lower().find(needle.lower()) != -1 if ci else sval.find(needle) != -1):
                    out.append((s.ea, sval))
            except:
                pass
    except Exception as e:
        log("find_string_ea err: %s" % e)
    return out

def xrefs_to(ea):
    return list(idautils.XrefsTo(ea))

log("=" * 72)
log("BGSM LOADER PROBE")
log("=" * 72)

# ----------------------------------------------------------------
# 1. Look for .bgsm extension strings (case-insensitive)
# ----------------------------------------------------------------
log("\n--- STEP 1: search .bgsm extension strings ---")
bgsm_hits = find_string_ea(".bgsm")
log("Found %d .bgsm string hits" % len(bgsm_hits))
for ea, sv in bgsm_hits[:30]:
    log("  0x%X: %r" % (ea, sv))

bgem_hits = find_string_ea(".bgem")
log("\nFound %d .bgem string hits" % len(bgem_hits))
for ea, sv in bgem_hits[:20]:
    log("  0x%X: %r" % (ea, sv))

# ----------------------------------------------------------------
# 2. Search for BGSMaterial/BSMaterialDB/Materials path strings
# ----------------------------------------------------------------
log("\n--- STEP 2: BSMaterialDB anchors ---")
for needle in ["BSMaterialDB", "BGSMaterial", "materials\\", "Materials\\",
               "BSLightingShaderMaterialBase", "BSLightingShaderMaterial",
               ".BGSM", "bgsm", "BGSM"]:
    hits = find_string_ea(needle, ci=False)
    log("\nNeedle %r -> %d hits" % (needle, len(hits)))
    for ea, sv in hits[:10]:
        log("  0x%X: %r" % (ea, sv))

# ----------------------------------------------------------------
# 3. Look for 'default_wet.bgsm' cross-references (the one known string)
# ----------------------------------------------------------------
log("\n--- STEP 3: cross-refs to defaultTemplate_wet.bgsm ---")
wet_hits = find_string_ea("defaultTemplate_wet.bgsm", ci=True)
for ea, sv in wet_hits[:5]:
    log("  string at 0x%X: %r" % (ea, sv))
    xrefs = xrefs_to(ea)
    log("  xrefs: %d" % len(xrefs))
    for x in xrefs[:10]:
        f = ida_funcs.get_func(x.frm)
        fstart = f.start_ea if f else 0
        log("    xref from 0x%X (func 0x%X)" % (x.frm, fstart))

# ----------------------------------------------------------------
# 4. Cross-refs to "Path to the root bgsm file" and "materialBase"
# ----------------------------------------------------------------
log("\n--- STEP 4: xrefs to diagnostic strings 'Path to the root bgsm file' ---")
root_bgsm = find_string_ea("Path to the root bgsm file", ci=True)
for ea, sv in root_bgsm:
    log("  string at 0x%X: %r" % (ea, sv))
    xrefs = xrefs_to(ea)
    log("  xrefs: %d" % len(xrefs))
    for x in xrefs[:10]:
        f = ida_funcs.get_func(x.frm)
        fstart = f.start_ea if f else 0
        log("    xref from 0x%X (func 0x%X)" % (x.frm, fstart))

log("\n--- STEP 4b: xrefs to 'materialBase' ---")
matbase = find_string_ea("materialBase", ci=False)
for ea, sv in matbase[:5]:
    log("  string at 0x%X: %r" % (ea, sv))
    xrefs = xrefs_to(ea)
    log("  xrefs: %d" % len(xrefs))
    for x in xrefs[:10]:
        f = ida_funcs.get_func(x.frm)
        fstart = f.start_ea if f else 0
        log("    xref from 0x%X (func 0x%X)" % (x.frm, fstart))

# ----------------------------------------------------------------
# 5. RTTI class anchors - find BSMaterialDB EntryDB vtables
# ----------------------------------------------------------------
log("\n--- STEP 5: BSMaterialDB/EntryDB RTTI anchors ---")
for needle in ["BSMaterialDB", "EntryDB", "QueuedHandles", "BSLightingShaderMaterialBase@@"]:
    hits = find_string_ea(needle, ci=False)
    log("\nRTTI search %r -> %d hits" % (needle, len(hits)))
    for ea, sv in hits[:10]:
        log("  0x%X: %r" % (ea, sv))

with open(LOG_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("BGSM probe done, wrote %d lines" % len(out_lines))
idc.qexit(0)
