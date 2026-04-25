"""B4.c — decompile the Quest.SetCurrentStageID native (the Papyrus SetStage)."""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\setstage_report.txt"

TARGETS = [
    ("Quest_SetCurrentStageID", 0x1185DD0),   # sub_141185DD0 — Papyrus SetStage
    ("Quest_GetCurrentStageID", 0x1188820),   # sub_141188820 — Papyrus GetStage
    ("GlobalVar_SetValue_body", 0x11459E0),   # sub_1411459E0 — confirmed earlier
    ("GlobalVar_SetValue_wrapper", 0x1145AA0),# sub_141145AA0 — the Papyrus wrapper
]


def decomp(ea, max_len=6000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    fh.write(f"[+] Image base: 0x{img:X}\n\n")
    if not ida_hexrays.init_hexrays_plugin():
        fh.write("[-] no hexrays\n"); fh.close(); ida_pro.qexit(2)
    for name, rva in TARGETS:
        fh.write(f"==== {name} (RVA 0x{rva:X}) ====\n")
        fh.write(decomp(img + rva))
        fh.write("\n\n")
    fh.close()
    ida_pro.qexit(0)


main()
