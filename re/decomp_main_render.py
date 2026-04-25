"""
decomp_main_render.py
Decompile the main render loop + neighbours.  Goal: find the EXACT line where
the scene pass ends and UI compositing begins.
"""

import ida_auto
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_pro
import idc
import idautils

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\main_render_decomp.txt"

# From render_pipeline_anchors.txt
TARGETS = [
    (0x140BD3F80, "MainRenderLoop_candidate (has all 4 JobList names)"),
    (0x140C2FAD0, "MainRender_caller_framedispatch"),
    (0x140C2F3F0, "MainRender_top_trampoline"),
    (0x141D20C00, "Scaleform_BeginFrame_wrapper"),
    (0x141D20CF0, "Scaleform_BeginScene_wrapper"),
    (0x141D23EF0, "Scaleform_beginDisplay_wrapper"),
    (0x14220EAF0, "DFComposite_user_1"),
    (0x1421792E0, "DFComposite_user_2_large"),
    (0x140C322C0, "DFComposite_chain_caller"),
    (0x142210C10, "BSDFComposite_user"),
    (0x141B4C6B0, "Scaleform_PushRenderTarget_wrapper"),
    (0x141B4FCA0, "Scaleform_applyDepthStencilMode_wrapper"),
]


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def decomp_func(ea, fh, label):
    log(fh, "")
    log(fh, "============================================================")
    log(fh, f"  {label}")
    log(fh, f"  ea=0x{ea:X}  RVA=0x{ea - ida_nalt.get_imagebase():X}")
    log(fh, "============================================================")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")
        return
    if cfunc is None:
        log(fh, "  [!] decompile returned None")
        return
    text = str(cfunc)
    log(fh, "---- BEGIN DECOMP ----")
    log(fh, text)
    log(fh, "---- END DECOMP ----")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        log(fh, "[!] Hex-Rays NOT available — dumping disasm instead")
        for ea, label in TARGETS:
            log(fh, "")
            log(fh, "============================================================")
            log(fh, f"  {label}")
            log(fh, f"  ea=0x{ea:X} RVA=0x{ea - ida_nalt.get_imagebase():X}")
            log(fh, "============================================================")
            fn = ida_funcs.get_func(ea)
            if not fn:
                log(fh, "  [!] NO FUNC")
                continue
            cur = fn.start_ea
            n = 0
            while cur < fn.end_ea and n < 300:
                log(fh, f"  0x{cur:X}: {idc.generate_disasm_line(cur, 0)}")
                cur = idc.next_head(cur, fn.end_ea)
                n += 1
        fh.close()
        ida_pro.qexit(0)
        return

    for ea, label in TARGETS:
        decomp_func(ea, fh, label)

    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
