"""angr confirmed sub_140511F10 writes [rbx+0xF8] = materializer.
Decomp it + contiguous sub_140511FD0 + inner callees for complete picture.
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\materializer_report.txt"

TARGETS = [
    ("sub_140511F10_MATERIALIZER", 0x511F10),
    ("sub_140511FD0_sibling",      0x511FD0),
    ("sub_140D57400_vt167",        0xD57400),   # re-check with args
    ("sub_141047020_vt167_inner2", 0x1047020),
    ("sub_140511F10_likely_inner1",0x511F10),   # might be called from vt167
]


def decomp(ea, max_len=10000):
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
    seen = set()
    for name, rva in TARGETS:
        if rva in seen: continue
        seen.add(rva)
        fh.write(f"==== {name} (RVA 0x{rva:X}) ====\n")
        fh.write(decomp(img + rva))
        fh.write("\n\n")
    fh.close()
    ida_pro.qexit(0)


main()
