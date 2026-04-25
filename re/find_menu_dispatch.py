"""B3 RE followup — the AS3→C++ dispatch pattern for MainMenu.

From the previous report we found:
  sub_140B01290  — MainMenu register-all: binds "onContinuePress"@0,
                    "ContinueGame"@2, "requestLoadGame"@13, etc. via
                    sub_141B1A340(menu_obj, name, idx).

What we need for auto-Continue from the DLL:
  - How sub_141B1A340 stores the (name, idx) mapping.
  - What function actually invokes the handler for a given AS3 event.
  - Whether the handler is a plain function pointer or a virtual slot on
    the menu object.

Outputs: re/menu_dispatch_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\menu_dispatch_report.txt"

TARGETS = [
    ("MainMenu_register_all", 0xB01290),   # sub_140B01290
    ("register_callback",     0x1B1A340),  # sub_141B1A340
    # The handler at index 0 (onContinuePress) is sub_141073DC0 per
    # the "aMainmenu" call in sub_1401698F0. Decompile that.
    ("on_continue_handler",   0x1073DC0),
    # Parent singleton registration (gives us the MainMenu object getter)
    ("mainmenu_registry",     0x1698F0),
]


def decomp(ea, max_len=5000):
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
