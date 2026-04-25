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

log("\n\n========================================================================")
log(" FINAL - sub_1417B39F0 (TESProcessor inner - tree walker caller)")
log("========================================================================")

decomp(0x1417B39F0, "sub_1417B39F0")

# Also look at sub_140365610 (first call in TESProcessor::vt[1])
decomp(0x140365610, "sub_140365610")

# And sub_140366530 (last call before return)
decomp(0x140366530, "sub_140366530")

# sub_1402FBAF0 mentioned in sub_1402FBEC0 disasm
decomp(0x1402FBAF0, "sub_1402FBAF0")

# sub_1417B3B30 - called from sub_1402FBEC0
decomp(0x1417B3B30, "sub_1417B3B30")

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("last probe done")
idc.qexit(0)
