"""B4.c — decompile the engine-level SetStage workers underneath Papyrus."""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stage_core_report.txt"

TARGETS = [
    ("sub_1410D41D0_set_stage_inactive", 0x10D41D0),
    ("sub_1410D5FA0_set_stage_started",  0x10D5FA0),
    ("sub_14066B100_is_quest_started",   0x66B100),
    ("sub_14066B210_post_set_stage_work",0x66B210),
    ("sub_1410E07F0_current_quest_id",   0x10E07F0),
]


def decomp(ea, max_len=8000):
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
