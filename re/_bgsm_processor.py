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
log(" BSMODELPROCESSOR HOOK + MATERIAL APPLICATION")
log("========================================================================")

# qword_1430E0290 = BSModelProcessor singleton per nif loader dossier
# Dereference to find its vtable + the post-hook method.
v = ida_bytes.get_qword(0x1430E0290)
log("\nqword_1430E0290 (BSModelProcessor ptr) value = 0x%X" % v)

# See who initialized it
log("\nxrefs to qword_1430E0290:")
for x in xrefs_to(0x1430E0290)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, ida_funcs.get_func_name(fstart) if f else "?"))

# Decompile the NIF loader sub_1417B3480 tail to find exactly what flag_0x08 does
log("\n\n--- NIF loader sub_1417B3480 (already known, just confirm the 0x08 branch) ---")
decomp(0x1417B3480, "sub_1417B3480 NIF loader")

# Material apply function sub_142169AD0 - called from sub_140256070 (BSModelProcessor)
log("\n\n--- sub_142169AD0 (material -> geometry bind, called from BSModelProcessor) ---")
decomp(0x142169AD0, "sub_142169AD0")

# sub_140256070 caller - sub_140255F30 (may be the pipeline entry)
log("\n\n--- sub_140255F30 (caller of BSModelProcessor material apply) ---")
decomp(0x140255F30, "sub_140255F30")

# Actor::Load3D-like from the dossier
log("\n\n--- sub_140458740 (Actor::Load3D-like) ---")
try:
    decomp(0x140458740, "sub_140458740 Actor::Load3D-like")
except Exception as e:
    log("decomp fail: %s" % e)

# sub_14033D1E0 REFR::Load3D full pipeline
log("\n\n--- sub_14033D1E0 REFR::Load3D pipeline ---")
try:
    decomp(0x14033D1E0, "sub_14033D1E0 REFR::Load3D full pipeline")
except Exception as e:
    log("decomp fail: %s" % e)

# Material-apply to geometry sub_142162340 — used in BSModelProcessor
decomp(0x142162340, "sub_142162340 (texture slot getter)")

# sub_1417A4A30 — texture resolve called from BSModelProcessor
decomp(0x1417A4A30, "sub_1417A4A30 (texture resolve)")

# Check sub_142160DA0 — init that runs inside BSLSP ctor (may init default material)
decomp(0x142160DA0, "sub_142160DA0 (BSLSP global init)")

# sub_1416BCD30 - called when byte_142ECDB58 set, post-hook
decomp(0x1416BCD30, "sub_1416BCD30")

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("processor probe done")
idc.qexit(0)
