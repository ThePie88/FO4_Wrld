"""B4.c followup — decompile the Quest Papyrus registrar to find SetStage.

From the previous pass:
  - CompleteQuest native @ RVA 0x1185670
  - It's referenced from RVA 0x11861C0 (code xref "0x141186304 in RVA 0x11861C0")
  - That RVA 0x11861C0 is the Quest Papyrus script registrar — a big function
    binding all Quest methods via a helper call per method.

We decompile the registrar + the known SetStage native candidates nearby
(functions close to CompleteQuest @ 0x1185670 by RVA, likely sibling methods).

Outputs: re/quest_registrar_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\quest_registrar_report.txt"

TARGETS = [
    ("quest_registrar",       0x11861C0),  # sub_1411861C0
    ("complete_quest_native", 0x1185670),  # sub_141185670 (known CompleteQuest)
    ("set_completed_state",   0x066A9A0),  # sub_14066A9A0 (called by CompleteQuest)
]


def decomp(ea, max_len=80000):
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
