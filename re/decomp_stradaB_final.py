"""
decomp_stradaB_final.py

Phase 5 — Final cleanup:
  - Decompile sub_142179140 (writes to SSN global — cell-load swap function)
  - Decompile name-allocation (sub_14167BDC0, sub_14167BF60, sub_14167BEF0)
  - Decompile BSDynamicTriShape ctor to get its sizeof
  - Decompile NiAVObject::ctor fully
  - Verify the NiCamera global (0x30DBD58 we knew) — find its frustum setter
  - Find the Update() vtable slot (slot that pumps world data down)
  - Find the world transform offset: +0x70 (we had this from NiAVObject but re-confirm)
  - Dump `sub_1416C8050` — used after scene graph init (looks like Update Worldbound)
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_final.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea, fh, label="", max_lines=150):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            t = str(cf)
            lines = t.split("\n")
            if len(lines) > max_lines:
                lines = lines[:max_lines] + [f"  ... (truncated, {len(t.split(chr(10)))} total)"]
            log(fh, "\n".join(lines))
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — final verification pass ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    log(fh, f"image base = 0x{ida_nalt.get_imagebase():X}")

    TARGETS = [
        (0x142179140, "SSN global writer (cell swap?) sub_142179140"),
        (0x14167BDC0, "NiFixedString::Create? sub_14167BDC0"),
        (0x14167BEF0, "NiFixedString::Release sub_14167BEF0"),
        (0x14167BF60, "NiFixedString::Assign sub_14167BF60"),
        (0x14167D900, "name_intern sub_14167D900"),
        (0x1416C8050, "post-init call sub_1416C8050 (UpdateBound?)"),
        (0x1416C8B60, "set-parent helper sub_1416C8B60"),
        (0x1416BFEB0, "child-array insert sub_1416BFEB0"),
        (0x1416BFBA0, "child-array-at-idx sub_1416BFBA0"),
        (0x1416BFDD0, "child-array-remove sub_1416BFDD0"),
        (0x1404E7B50, "NiTPrimitiveArray::Resize sub_1404E7B50"),
        (0x1416BDEF0, "NiNode ctor (alloc-free variant) sub_1416BDEF0"),
        (0x1416BDFE0, "NiNode ctor (in-place, with capacity param) sub_1416BDFE0"),
        (0x1421B08A0, "ShadowSceneNode ctor sub_1421B08A0"),
        (0x14217A8B0, "SSN set-slot sub_14217A8B0"),
        (0x141806CA0, "SSN reader sub_141806CA0"),
        (0x1416D0510, "NiCamera ctor sub_1416D0510"),
    ]

    for ea, lbl in TARGETS:
        decomp(ea, fh, lbl, max_lines=120)

    log(fh, "\n==== END ====")
    fh.close()
    ida_pro.qexit(0)


main()
