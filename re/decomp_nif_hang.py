"""
Decompile targeted funcs to diagnose NIF loader hang.
Focus:
  - sub_14026E1C0 (wrapper) — verify a1 expectation
  - sub_1416A6D00 (cache lookup) — confirm Sleep loops
  - sub_1416A6C30 (helper) — what does it do when called from cache?
  - sub_140458740 (Actor::Load3D-like, canonical caller) - check real a1 value
  - sub_14033D1E0 (REFR::Load3D) - another canonical caller
  - sub_14026E530 - post-hit handler (uses a1 + 0x8B500 = +570880)
"""
import idaapi, idautils, idc, ida_hexrays, ida_bytes, ida_funcs, ida_name
import sys

IMG = 0x140000000
LOG = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_ida_nif_hang.log", "w", encoding="utf-8")
def log(s):
    LOG.write(s+"\n"); LOG.flush()
    print(s)

ida_hexrays.init_hexrays_plugin()

TARGETS = [
    (0x14026E1C0, "wrapper_sub_14026E1C0"),
    (0x1416A6D00, "cache_sub_1416A6D00"),
    (0x1416A6C30, "helper_sub_1416A6C30"),
    (0x1416A7040, "helper_sub_1416A7040"),
    (0x14026E530, "post_hit_sub_14026E530"),
    (0x14033D1E0, "refr_load3d_sub_14033D1E0"),
    (0x140458740, "actor_load3d_sub_140458740"),
    (0x1417B3480, "inner_loader_sub_1417B3480"),
    (0x141657F90, "init_once_sub_141657F90"),
    (0x1417EFD70, "nif_parse_sub_1417EFD70"),
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

# Also find direct callers of sub_14026E1C0 to see exactly what a1 they pass.
log("\n================================================")
log("xrefs TO sub_14026E1C0 — parent function + call site context")
log("================================================")
target = 0x14026E1C0
for xref in idautils.XrefsTo(target):
    pf = ida_funcs.get_func(xref.frm)
    pname = ida_name.get_name(pf.start_ea) if pf else "?"
    log(f"  xref from {xref.frm:#x} in {pname} @ {pf.start_ea if pf else 0:#x}")

# Look up the globals 0x30DD618
log("\n================================================")
log("ResourceManager singleton pointer @ 0x1430DD618 / layout hint")
log("================================================")
log(f"IDA name @ 0x1430DD618: {ida_name.get_name(0x1430DD618)!r}")
log(f"qword @ 0x1430DD618 (raw) = NOT RESOLVED (requires running binary)")

LOG.close()
print("DONE")
idc.qexit(0)
