"""Decompile the three callers of sub_14026E1C0 to determine a1 expectation."""
import idaapi, idautils, idc, ida_hexrays, ida_bytes, ida_funcs, ida_name

IMG = 0x140000000
LOG = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_ida_nif_hang2.log", "w", encoding="utf-8")
def log(s):
    LOG.write(s+"\n"); LOG.flush()

ida_hexrays.init_hexrays_plugin()

TARGETS = [
    (0x14026DD50, "caller1_sub_14026DD50"),
    (0x14033EE60, "caller2_sub_14033EE60"),
    (0x14033F200, "caller3_sub_14033F200_already_known"),
    # wrappers of wrappers
    (0x14033D1E0, "refr_load3d"),
    (0x140458740, "actor_load3d"),
    # and the BSFadeNode ctor so we can verify refcount semantics
    (0x142174DC0, "BSFadeNode_ctor"),
    (0x1416BDFE0, "NiNode_ctor"),
    # + more
    (0x14033EF00, "sub_14033EF00_resolve_by_path"),
    (0x1416A6670, "sub_1416A6670"),
    (0x14033EA60, "sub_14033EA60"),
    (0x14033F0F0, "sub_14033F0F0"),
    (0x14033F420, "sub_14033F420"),
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

LOG.close()
idc.qexit(0)
