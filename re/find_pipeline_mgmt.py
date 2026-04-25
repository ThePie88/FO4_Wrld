"""
find_pipeline_mgmt.py — locate "RenderPipelineManagement" string owner and "CopyMainToMenuBG" owner.
Also decomp sub_14217E540 (the blit function) and sub_14217E540 callers.
"""

import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\pipeline_mgmt_report.txt"


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


def find_string_refs(needle, fh):
    for s in idautils.Strings():
        try:
            if str(s) == needle:
                ea = s.ea
                log(fh, f"[+] String {needle!r} @ 0x{ea:X} (RVA 0x{rva(ea):X})")
                for x in idautils.XrefsTo(ea, 0):
                    fn = ida_funcs.get_func(x.frm)
                    name = ida_funcs.get_func_name(fn.start_ea) if fn else "(not in func)"
                    fs = fn.start_ea if fn else 0
                    sz = (fn.end_ea - fn.start_ea) if fn else 0
                    log(fh, f"    xref from 0x{x.frm:X} (RVA 0x{rva(x.frm):X}) in {name} @ 0x{fs:X} size=0x{sz:X}")
                    if fn:
                        try:
                            cfunc = ida_hexrays.decompile(fs)
                            if cfunc:
                                log(fh, "    --- CONTAINING FUNC DECOMP ---")
                                for ln in str(cfunc).splitlines()[:200]:
                                    log(fh, f"      {ln}")
                                log(fh, "    --- END DECOMP ---")
                        except Exception as e:
                            log(fh, f"    decomp fail: {e}")
        except Exception:
            pass


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    for needle in ["CopyMainToMenuBG", "RenderPipelineManagement"]:
        find_string_refs(needle, fh)

    # Also decomp the blit function
    decomp(0x14217E540, fh, "sub_14217E540 — 'blit scene to menu BG' candidate")

    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
