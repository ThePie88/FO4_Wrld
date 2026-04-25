import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name

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
log(" TESMODELDB::TESPROCESSOR VTABLE DUMP")
log("========================================================================")

# Find vtable named TESProcessor
names = ida_name.get_nlist_size()
for i in range(names):
    n = ida_name.get_nlist_name(i)
    ea = ida_name.get_nlist_ea(i)
    if "TESProcessor" in n and "vftable" in n:
        log("\nvtable candidate: %s @ 0x%X" % (n, ea))
        # Dump 8 vt slots
        for slot in range(10):
            v = ida_bytes.get_qword(ea + slot*8)
            fname = ida_funcs.get_func_name(v) if ida_funcs.get_func(v) else "?"
            log("  vt[%d] @ 0x%X -> 0x%X (%s)" % (slot, ea+slot*8, v, fname))

# Alternative: find by bytes in .rdata around __7TESProcessor
# Scan for the TESProcessor vtable by disasm reference from 0x1402FBE5D
# The insn `lea rcx, <vtable>` uses a RIP-relative offset. Address is
# insn_end + disp32. sub_1402FBE5D instruction is 7 bytes.
ea = 0x1402FBE5D
disp = ida_bytes.get_dword(ea + 3)  # bytes at +3 are the disp32
if disp & 0x80000000:
    disp = disp - 0x100000000
vtable_addr = ea + 7 + disp
log("\n[computed] TESProcessor vtable @ 0x%X" % vtable_addr)

for slot in range(10):
    v = ida_bytes.get_qword(vtable_addr + slot*8)
    fname = ida_funcs.get_func_name(v) if ida_funcs.get_func(v) else "?"
    log("  vt[%d] @ 0x%X -> 0x%X (%s)" % (slot, vtable_addr+slot*8, v, fname))

# Decompile vt[1] — the ProcessModel hook
vt1 = ida_bytes.get_qword(vtable_addr + 8)
log("\nvt[1] is 0x%X" % vt1)
decomp(vt1, "TESProcessor::vt[1] (ProcessModel hook)")

# Also dump vt[0]
vt0 = ida_bytes.get_qword(vtable_addr + 0)
log("\nvt[0] is 0x%X" % vt0)
decomp(vt0, "TESProcessor::vt[0] (dtor/dispatcher)")

with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write("\n".join(out_lines))

print("tesvt probe done")
idc.qexit(0)
