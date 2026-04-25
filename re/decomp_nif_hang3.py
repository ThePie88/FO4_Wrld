"""Decompile the low-level helpers to find which has a Sleep loop or lock."""
import idaapi, idautils, idc, ida_hexrays, ida_bytes, ida_funcs, ida_name

IMG = 0x140000000
LOG = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_ida_nif_hang3.log", "w", encoding="utf-8")
def log(s):
    LOG.write(s+"\n"); LOG.flush()

ida_hexrays.init_hexrays_plugin()

TARGETS = [
    (0x1416C99E0, "sub_1416C99E0_state_save"),
    (0x1416C99B0, "sub_1416C99B0_state_restore"),
    (0x14169DFB0, "sub_14169DFB0"),
    (0x14169E620, "sub_14169E620"),
    (0x14169DDF0, "sub_14169DDF0"),
    (0x1402F0E00, "sub_1402F0E00_NiPointer_or_write"),
    (0x14026E390, "sub_14026E390_precheck"),
    (0x1417B40F0, "sub_1417B40F0_file_exists"),
    (0x1416B9820, "sub_1416B9820_BSStream_ctor"),
    (0x1416DCB50, "sub_1416DCB50"),
    (0x1416DCD80, "sub_1416DCD80"),
    (0x1416A7470, "sub_1416A7470"),
]

for ea, name in TARGETS:
    try:
        f = ida_funcs.get_func(ea)
        if not f:
            log(f"-- {name} @ {ea:#x} : NO FUNC --")
            continue
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            log(f"-- {name} @ {ea:#x} : DECOMP FAILED --")
            continue
        log(f"\n================================================")
        log(f"-- {name} @ {ea:#x} (RVA {(ea-IMG):#x}) size={f.size():#x} --")
        log(f"================================================")
        log(str(cf))
    except Exception as e:
        log(f"-- {name} @ {ea:#x} : EXC {e} --")

# Disassemble first 20 instructions of sub_1416C99E0 & sub_1416C99B0 (they might be tiny asm)
log("\n================================================")
log("RAW DISASM of sub_1416C99E0 & sub_1416C99B0")
log("================================================")
for ea in (0x1416C99E0, 0x1416C99B0):
    log(f"\n-- {ea:#x} --")
    for i in range(20):
        insn = idc.generate_disasm_line(ea, 0)
        log(f"  {ea:#x}  {insn}")
        ea = idc.next_head(ea)

LOG.close()
idc.qexit(0)
