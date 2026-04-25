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

log("\n\n========================================================================")
log(" KEY BGSM FUNCTIONS — DECOMPILATION")
log("========================================================================")

# sub_140187E70 references ".bgsm" — very promising
decomp(0x140187E70, "sub_140187E70 (refs .bgsm string)")
# sub_140187E50 references ".bgem" — sibling
decomp(0x140187E50, "sub_140187E50 (refs .bgem string)")
# sub_140256070 references "data\\materials\\%s" — FILESYSTEM-level path builder
decomp(0x140256070, "sub_140256070 (data\\materials\\%s)")

# These functions all ref "materials\\" prefix:
decomp(0x1417A94D0, "sub_1417A94D0 (materials\\)")
decomp(0x1417A9620, "sub_1417A9620 (materials\\)")
decomp(0x1417A9B40, "sub_1417A9B40 (materials\\)")
decomp(0x1417A9D50, "sub_1417A9D50 (materials\\)")
decomp(0x142230C30, "sub_142230C30 (materials\\)")
decomp(0x142230E90, "sub_142230E90 (materials\\)")

# Now find callers of sub_140187E70 to see WHO requests .bgsm loading
log("\n\n--- CALLERS of sub_140187E70 (.bgsm loader entry) ---")
for x in xrefs_to(0x140187E70)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

log("\n\n--- CALLERS of sub_140256070 (data\\materials path builder) ---")
for x in xrefs_to(0x140256070)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

log("\n\n--- CALLERS of sub_1417A94D0 ---")
for x in xrefs_to(0x1417A94D0)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

log("\n\n--- CALLERS of sub_142230C30 ---")
for x in xrefs_to(0x142230C30)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

log("\n\n--- CALLERS of sub_142230E90 ---")
for x in xrefs_to(0x142230E90)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("key fns done")
idc.qexit(0)
