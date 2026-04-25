"""
decomp_frame_tick.py — decompile the per-frame function sub_140C334B0 and related.
Also decompile callers of Scaleform BeginFrame/BeginScene indirection sites.
"""

import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\frame_tick_decomp.txt"

TARGETS = [
    (0x140C334B0, "FrameTick (called each frame from sub_140C30FD0 main loop)"),
    (0x141B484D0, "BeginScene caller small (38 bytes)"),
    (0x141B48510, "BeginScene caller medium (96 bytes)"),
    (0x140C33190, "FrameTick inner callee — called before tick"),
    (0x140BD4CE0, "called during FrameTick on exit"),
    (0x141E08F90, "another tick helper (possibly scene update)"),
    (0x141070A10, "UI helper"),
    (0x1422A7780, "called before tick"),
    (0x1422A77D0, "called at end of loop iter"),
    # DFComposite family - likely per-frame scene composite
    (0x14217A220, "DFComposite tiny wrapper (from report 1)"),
    (0x14220EAF0, "DFComposite user 1 (called during scene init)"),
    (0x1421792E0, "DFComposite INIT (called from scene tree build)"),
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
    if not ida_hexrays.init_hexrays_plugin():
        log(fh, "[!] hex-rays unavailable")
    for ea, label in TARGETS:
        decomp(ea, fh, label)
    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
