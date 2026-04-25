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
log(" TREE WALKER ENTRIES + BSMODELPROCESSOR VTABLE")
log("========================================================================")

# The tree walker entry points that call sub_140255F30 (which calls sub_140256070 material-apply)
decomp(0x140255BA0, "sub_140255BA0 (walker entry)")
decomp(0x140255D40, "sub_140255D40 (walker entry)")
# 140255F30 already decompiled

# BSModelProcessor vtable references are at 0x142B00BE4-0x142B00CD0 (NOT function starts)
# These are within a vtable. Let's dump the vtable region.
log("\n--- DUMP BSModelProcessor vtable region 0x142B00BD0..0x142B00CF0 ---")
addr = 0x142B00BD0
while addr < 0x142B00CF0:
    v = ida_bytes.get_qword(addr)
    name = ida_funcs.get_func_name(v) if ida_funcs.get_func(v) else "?"
    log("  [0x%X] -> 0x%X (%s)" % (addr, v, name))
    addr += 8

# Also dump near 0x142D65000 (vtable with bgsm loaders)
log("\n--- DUMP vtable region 0x142D64FE0..0x142D65080 ---")
addr = 0x142D64FE0
while addr < 0x142D65080:
    v = ida_bytes.get_qword(addr)
    name = ida_funcs.get_func_name(v) if ida_funcs.get_func(v) else "?"
    log("  [0x%X] -> 0x%X (%s)" % (addr, v, name))
    addr += 8

# Also check caller sub_140255BA0 context
log("\n--- Callers of sub_140255BA0 ---")
for x in xrefs_to(0x140255BA0)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, ida_funcs.get_func_name(fstart) if f else "?"))

log("\n--- Callers of sub_140255D40 ---")
for x in xrefs_to(0x140255D40)[:20]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, ida_funcs.get_func_name(fstart) if f else "?"))

# Decompile sub_14033EF00 and sub_14033EC90 more carefully - they use the ModelDB cache
# Let me look for the high-level entry: sub_14033EC90 at RVA 0x33EC90 — the batch loader
# Callers of sub_14033EC90 show the "recipe"

# Check sub_140255F30 — the tree walker — we need to see who ROOT-calls it.
# The call from a vtable 0x142B00C54 suggests it's a vtable method of BSModelProcessor.
# Let's interpret 0x142B00BD0 as BSModelProcessor::vftable and identify vt slot for "ProcessShape"
# By offset:
#   0x142B00BD0 + 8*0  = base
# Let me decompile sub_140255BA0 and sub_140255D40 to see their actual signatures (if they take a
# NiNode* and walk it, they're the tree walkers).

# sub_140255F30 also recurses and calls sub_140256070 — the material apply.
# The NIF loader flag_0x08 calls qword_1430E0290 vt[1] (offset +8) — let's see what qword_1430E0290
# points to as a vtable. It's not initialized at rest (sentinel 0xFFFFFFFFFFFFFFFF), so this
# singleton is initialized at runtime.

# Check the initializer function sub_1402FBDF0 that WRITES qword_1430E0290:
decomp(0x1402FBDF0, "sub_1402FBDF0 (inits BSModelProcessor qword_1430E0290)")
decomp(0x1402FBEC0, "sub_1402FBEC0 (reads/writes qword_1430E0290)")

# Decompile sub_142230C30 callers - these look like BSLightingShaderMaterial vtable wrappers
decomp(0x142230E90, "sub_142230E90 (material variant)")

# sub_1417A9870 calls sub_1417A9620 (bgsm loader) - decompile to see context
decomp(0x1417A9850, "sub_1417A9850 (caller of bgsm loader)")

# sub_1421C66A0 - also calls bgsm loader
decomp(0x1421C66A0, "sub_1421C66A0 (caller of bgsm loader)")

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("walker probe done")
idc.qexit(0)
