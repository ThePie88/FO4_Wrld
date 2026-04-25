import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes

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
            return True
    except Exception as e:
        log("decomp err 0x%X: %s" % (ea, e))
    return False

def xrefs_to(ea):
    return list(idautils.XrefsTo(ea))

def xrefs_from(ea):
    return list(idautils.XrefsFrom(ea))

log("\n\n========================================================================")
log(" FINAL ANALYSIS - CALL CHAINS + BSMODELPROCESSOR VTABLE")
log("========================================================================")

# 1. Find who calls sub_140255F30 (tree walker entry)
log("\n--- Callers of sub_140255F30 (tree walker) ---")
for x in xrefs_to(0x140255F30)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# 2. Check ALL xrefs to sub_140256070 (material apply per-object)
log("\n--- Callers of sub_140256070 (material-apply per object) ---")
for x in xrefs_to(0x140256070)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# 3. Direct callers of sub_1417A9620 (BGSM loader)
log("\n--- Callers of sub_1417A9620 (main BGSM loader) ---")
for x in xrefs_to(0x1417A9620)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# 4. Callers of sub_1417A94D0
log("\n--- Callers of sub_1417A94D0 (lightweight bgsm loader) ---")
for x in xrefs_to(0x1417A94D0)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# 5. BSModelProcessor vtable - find it via RTTI
log("\n--- Find BSModelProcessor vtable via RTTI ---")
# string ".?AVBSModelProcessor@BSModelDB@@" @ 0x2F98370 per previous dossier
rtti_td = 0x142F98370 - 0x10   # typedesc prefix
log("  search xrefs to BSModelProcessor TypeDescriptor 0x%X" % rtti_td)
# actually find the STRING first:
for s in idautils.Strings():
    try:
        if "BSModelProcessor@BSModelDB" in str(s):
            log("    string at 0x%X: %r" % (s.ea, str(s)))
            td = s.ea - 0x10
            for x in xrefs_to(td)[:10]:
                log("      TD xref from 0x%X" % x.frm)
                # Each TD xref is inside a _TypeDescriptor reference used by a Complete Object Locator
                # Walk back to find vftable...
    except:
        pass

# 6. Call chain: check what calls sub_140458740 (Actor::Load3D)
log("\n--- Callers of sub_140458740 (Actor::Load3D) ---")
for x in xrefs_to(0x140458740)[:10]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# 7. Callers of sub_14033D1E0 (REFR::Load3D)
log("\n--- Callers of sub_14033D1E0 (REFR::Load3D) ---")
for x in xrefs_to(0x14033D1E0)[:10]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# 8. Also check what sub_142163480 does (called in sub_142169AD0 with material)
decomp(0x142163480, "sub_142163480 (material-stage in 142169AD0)")

# 9. Check sub_14221C7E0 — material init in sub_142169AD0
decomp(0x14221C7E0, "sub_14221C7E0 (material init 228 bytes)")

# 10. Look at what happens at 0x14033EF00 → cache lookup?
decomp(0x14033EF00, "sub_14033EF00 (cache lookup)")

# 11. Decompile sub_14033EC90 (the load-one-file function from NIF loader) to compare
decomp(0x14033EC90, "sub_14033EC90 (NIF batch-load wrapper)")

# 12. See ".bgsm" / ".bgem" reference is @ 0x14345E000 / 0x14345E010 — find what uses those
log("\n--- xrefs to 0x14345E000 (.bgsm BSFixedString) ---")
for x in xrefs_to(0x14345E000)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

log("\n--- xrefs to 0x14345E014 (bgsm filter dword) ---")
for x in xrefs_to(0x14345E014)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

log("\n--- xrefs to 0x1430DC2A8 (BSMaterialDB singleton) ---")
for x in xrefs_to(0x1430DC2A8)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("final probe done")
idc.qexit(0)
