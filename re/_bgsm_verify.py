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
log(" VERIFY — TESModelDB::TESProcessor vtable + its vt[1] method")
log("========================================================================")

# Find the string "TESModelDB::TESProcessor" or similar to anchor vtable
found = []
for s in idautils.Strings():
    try:
        sv = str(s)
        if "TESProcessor" in sv or "BSModelProcessor" in sv or "ProcessModel" in sv:
            found.append((s.ea, sv))
    except:
        pass
log("\nTESProcessor / BSModelProcessor strings:")
for ea, sv in found[:20]:
    log("  0x%X: %r" % (ea, sv))

# Look up vtable for TESModelDB::TESProcessor by scanning for it.
# Since sub_1402FBDF0 assigns `*v3 = &TESModelDB::...TESProcessor::vftable`,
# let's grep its disassembly for the vtable immediate.
log("\n--- disassemble sub_1402FBDF0 to find TESProcessor vtable immediate ---")
ea = 0x1402FBDF0
end = ea + 0x140  # enough
while ea < end:
    mnem = idc.print_insn_mnem(ea)
    disasm = idc.generate_disasm_line(ea, 0)
    log("  0x%X  %s" % (ea, disasm))
    ea = idc.next_head(ea)

# Scan the vtable pointed to for vt[1] method
# To avoid manual vtable lookup, use the assertion that vt[0] is dtor-family and
# vt[1] is the ProcessModel hook. Let's try a different approach: decompile
# sub_1402FBDF0 again and look for the immediate address.

# Alternative: search for references from vtable data to sub_140255BA0 since
# the walker is likely vt[...].
log("\n--- Direct search: functions that could be TESProcessor vt[1] ProcessModel ---")
log("Searching xrefs to sub_140255BA0 (the main walker) from vtable data regions...")

# Also search for functions that match signature of "ProcessModel(opts, stream, outNode, userCtx)"
# These should accept 4-5 args, likely at a small RVA, and near the TESProcessor::vftable.

# The cleanest way: decompile sub_1402FBEC0 — its body reveals vt[0]
decomp(0x1402FBEC0, "sub_1402FBEC0 confirm")

# And check if there's another function that takes (qword_1430E0290, opts, stream, outNode, userCtx)
# by looking at xrefs to qword_1430E0290 not already seen
log("\n--- All xrefs to qword_1430E0290 ---")
for x in xrefs_to(0x1430E0290)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# Decompile the NIF loader fragment that calls qword_1430E0290 vt[1] directly
# We already have this but let's extract just that block.
# From log line 2077-2087 we saw the call signature:
#   (*(_QWORD*)qword_1430E0290 + 8LL)(qword_1430E0290, v7, v5, v6, a5)
# where:
#   v7 = a3 = opts struct
#   v5 = a2 = stream context
#   v6 = a4 = outNode**
#   a5 = user context
# The receiver gets: (this, opts, stream, outNode**, user)
# Now — if vt[1] IS the walker, then the walker sub_140255BA0 signature is
#   (NiNode*, parent_transform, context, ...)
# which does NOT match (this, opts, stream, outNode**).
# So vt[1] is LIKELY an adapter that extracts outNode and calls the walker.

# Let's check sub_140255F30 direct callers with NON-vtable origins:
# sub_140255F30 is called with (a1, a2) where a1 is what a walker passes as
# root. If a different function calls sub_140255BA0 with (fadenode, 0, 0, ...),
# that IS the TESProcessor::vt[1] adapter. It must exist as a small function.

# Let's just list callers of sub_140255BA0 again with full function names.
log("\n--- Recheck sub_140255BA0 callers (looking for TESProcessor adapter) ---")
for x in xrefs_to(0x140255BA0)[:30]:
    f = ida_funcs.get_func(x.frm)
    fstart = f.start_ea if f else 0
    fname = ida_funcs.get_func_name(fstart) if f else "?"
    log("  from 0x%X (func 0x%X %s)" % (x.frm, fstart, fname))

# Decompile a candidate: sub_140247C70 (first caller)
decomp(0x140247C70, "sub_140247C70 (caller of walker sub_140255BA0)")

# Let's also look at the vtable dump near 0x143E98EEC (which was caller of sub_140255F30)
log("\n--- Dump vtable region 0x143E98EB0..0x143E98F80 ---")
addr = 0x143E98EB0
while addr < 0x143E98F80:
    v = ida_bytes.get_qword(addr)
    name = ida_funcs.get_func_name(v) if ida_funcs.get_func(v) else "?"
    log("  [0x%X] -> 0x%X (%s)" % (addr, v, name))
    addr += 8

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("verify probe done")
idc.qexit(0)
