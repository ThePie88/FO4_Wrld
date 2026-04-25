"""
decomp_render_dispatch.py — decompile the per-frame render dispatch functions.
"""

import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_dispatch_decomp.txt"

TARGETS = [
    (0x140C32D30, "RenderDispatch_1 (sub_140C32D30 - called during FrameTick)"),
    (0x140C351B0, "RenderDispatch_2 (sub_140C351B0 - called after RenderDispatch_1)"),
    (0x140C34FC0, "RenderDispatch_pre (sub_140C34FC0 - called when active)"),
    (0x140C34A80, "RenderDispatch_alt (sub_140C34A80)"),
    (0x1421AA0F0, "Scene_SubmitRoot (sub_1421AA0F0)"),
    (0x1421C11B0, "Scene_visit (sub_1421C11B0)"),
    (0x14217BD60, "Scene_finalize (sub_14217BD60)"),
    (0x1421AB6D0, "Scene_action (sub_1421AB6D0)"),
    (0x1421AA0D0, "Scene_check (sub_1421AA0D0)"),
    (0x1421CF090, "Scene_helper (sub_1421CF090)"),
    (0x1421F2930, "Scene_helper2 (sub_1421F2930)"),
    (0x1421F2950, "Scene_helper3 (sub_1421F2950)"),
    (0x1402D77F0, "Scene_helper4 (sub_1402D77F0)"),
    (0x1402D71D0, "Scene_helper5 (sub_1402D71D0)"),
]


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea, fh, label):
    log(fh, "")
    log(fh, "============================================================")
    log(fh, f"  {label}")
    log(fh, f"  ea=0x{ea:X}  RVA=0x{rva(ea):X}")
    log(fh, "============================================================")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            log(fh, "---- BEGIN DECOMP ----")
            log(fh, str(cfunc))
            log(fh, "---- END DECOMP ----")
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    for ea, label in TARGETS:
        decomp(ea, fh, label)
    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
