"""
decomp_scene_submit.py — Find exactly where D3D11 context calls happen.
Look inside sub_140C37D20 and scan for [reg+0x108] / [reg+0x1A0] / [reg+0x188].
Also decompile sub_1417EE8F0 callers (where is scene flushed).
"""

import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_segment
import ida_bytes
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\scene_submit_decomp.txt"

TARGETS = [
    (0x140C37D20, "Renderer_sub2 / scene submit"),
    (0x141A815B0, "sub_141A815B0"),
    (0x141DEBC20, "sub_141DEBC20"),
    (0x141A81BB0, "sub_141A81BB0"),
    (0x141A81DB0, "sub_141A81DB0"),
    (0x140A3B300, "sub_140A3B300"),
    (0x1421F2EA0, "Renderer_set_flag0 (sub_1421F2EA0)"),
    (0x1421F2970, "Renderer_set_A (sub_1421F2970)"),
    (0x1421F2AF0, "Renderer_set_last (sub_1421F2AF0)"),
    (0x1421F2B00, "Renderer_set_4 (sub_1421F2B00)"),
    (0x1421F2B10, "Renderer_set_3 (sub_1421F2B10)"),
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


SLOT_NAMES = {
    0x60:  "DrawIndexed",
    0x68:  "Draw",
    0x70:  "Map",
    0x40:  "PSSetShaderResources",
    0x108: "OMSetRenderTargets",
    0x110: "OMSetRTAndUAV",
    0x118: "OMSetBlendState",
    0x188: "ClearRenderTargetView",
    0x190: "ClearUAVuint",
    0x198: "ClearUAVfloat",
    0x1A0: "ClearDepthStencilView",
    0x1A8: "GenerateMips",
}


def scan_vtbl_uses_in_func(ea, fh):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return
    log(fh, "")
    log(fh, f"--- vtbl-slot scan in 0x{ea:X} (size 0x{fn.end_ea-fn.start_ea:X}) ---")
    cur = fn.start_ea
    while cur < fn.end_ea:
        b0 = ida_bytes.get_byte(cur)
        b1 = ida_bytes.get_byte(cur + 1)
        if b0 == 0xFF and b1 in (0x90, 0x91, 0x92, 0x93, 0x95, 0x96, 0x97):
            disp = ida_bytes.get_dword(cur + 2)
            name = SLOT_NAMES.get(disp)
            if name:
                log(fh, f"  0x{cur:X}: call [reg+0x{disp:X}]  ({name})")
        elif b0 == 0x41 and b1 == 0xFF:
            b2 = ida_bytes.get_byte(cur + 2)
            if b2 in (0x90, 0x91, 0x92, 0x93, 0x95, 0x96, 0x97):
                disp = ida_bytes.get_dword(cur + 3)
                name = SLOT_NAMES.get(disp)
                if name:
                    log(fh, f"  0x{cur:X}: call [reg+0x{disp:X}]  ({name})")
        cur = idc.next_head(cur, fn.end_ea)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    for ea, label in TARGETS:
        decomp(ea, fh, label)

    # scan ALL frame-relevant functions for D3D11 vtbl-slot calls
    scan_targets = [
        0x140C32D30,  # Render dispatch 1
        0x140C351B0,  # Render dispatch 2
        0x140C334B0,  # Frame tick
        0x140C38910,  # Pre-render setup
        0x140C37D20,  # Renderer 2
        0x1417EE8F0,  # Scene flush
        0x141A815B0,
        0x141DEBC20,
        0x141A81BB0,
        0x141A81DB0,
    ]
    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  VTABLE SLOT SCAN (D3D11 context calls)")
    log(fh, "============================================================")
    for ea in scan_targets:
        scan_vtbl_uses_in_func(ea, fh)

    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
