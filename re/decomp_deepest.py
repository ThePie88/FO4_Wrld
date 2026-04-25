"""
decomp_deepest.py — decompile:
 - sub_141697E10 (JobList dispatcher)
 - sub_1417EE8F0 (scene render / handoff — called after JobList 6)
 - BSBatchRenderer callers
 - the UI/BeginFrame dispatch that's reached via vtable
"""

import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_segment
import ida_bytes
import ida_name
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\deepest_decomp.txt"

TARGETS = [
    (0x141697E10, "JobListDispatcher (sub_141697E10)"),
    (0x1417EE8F0, "SceneRender_or_Handoff (sub_1417EE8F0)"),
    (0x140C38910, "Renderer_sub1 (sub_140C38910)"),
    (0x140C37D20, "Renderer_sub2 (sub_140C37D20)"),
    (0x141A815B0, "Renderer_ui_path1 (sub_141A815B0)"),
    (0x141DEBC20, "Renderer_ui_path2 (sub_141DEBC20)"),
    (0x141A81BB0, "Renderer_ui_path3 (sub_141A81BB0)"),
    (0x141A81DB0, "Renderer_ui_path4 (sub_141A81DB0)"),
    (0x1417EE8F0, "Scene_after_jobs"),
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


def find_calls_from(fea, fh, max_hits=60):
    """List every CALL instruction inside a function."""
    log(fh, "")
    log(fh, f"--- CALL list inside 0x{fea:X} ---")
    fn = ida_funcs.get_func(fea)
    if not fn:
        log(fh, "  no func")
        return
    ea = fn.start_ea
    count = 0
    while ea < fn.end_ea and count < max_hits:
        insn = idc.print_insn_mnem(ea)
        if insn == "call":
            op = idc.print_operand(ea, 0)
            tgt = idc.get_operand_value(ea, 0)
            tgt_fn = ida_funcs.get_func(tgt)
            tgt_name = ""
            if tgt_fn:
                tgt_name = ida_funcs.get_func_name(tgt_fn.start_ea) or ""
            log(fh, f"  0x{ea:X}: call {op}  (target 0x{tgt:X} {tgt_name})")
            count += 1
        ea = idc.next_head(ea, fn.end_ea)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    seen = set()
    for ea, label in TARGETS:
        if ea in seen:
            continue
        seen.add(ea)
        decomp(ea, fh, label)

    # List calls inside the main frame-render dispatchers
    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  CALL SEQUENCES in render dispatchers")
    log(fh, "============================================================")
    for ea in [0x140C32D30, 0x140C351B0, 0x140C334B0]:
        find_calls_from(ea, fh, max_hits=200)

    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
