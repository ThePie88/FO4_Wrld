"""Level-0 deep dive on ContainerMenu (phase 4 followup).

From level0_container_report: "ContainerMenu" string appears with xrefs at:
  - RVA 0x1A85DD0 (str @ 0x142715A80)
  - RVA 0x163970  (str @ 0x142F2EA78, also used by 0x103C460, 0x10405C0)

Decomp each fully so we can identify:
  - the factory/registrar (analogous to sub_1401698F0 for MainMenu)
  - the Scaleform callbacks bound for ContainerMenu
  - the AS3→C++ name that populates items for display
  - the AS3→C++ name invoked when user clicks TAKE/PUT

Also we need to find where the engine materializes base-CONT items into
REFR+0xF8. That's the critical function for our patch strategy. Candidate
names: any function called near container-open that operates on both
REFR+0xE0 (baseForm) and REFR+0xF8 (runtime list).

Output: re/container_menu_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\container_menu_report.txt"

CANDIDATES = [
    ("xref_1A85DD0",  0x1A85DD0),
    ("xref_163970",   0x163970),
    ("xref_103C460",  0x103C460),
    ("xref_10405C0",  0x10405C0),
    # Container-related: the "find entry index" helper used by sub_14034D910
    ("sub_14034DA10_find_entry", 0x34DA10),
    # Allocator of BGSInventoryItem::Stack (from sub_140349830 body)
    ("sub_140272730",  0x272730),
    # sub_14022CD40 was called from vt[0x7A] — "find owner?"
    ("sub_14022CD40",  0x22CD40),
    # sub_140280090 was called from vt[0x7A] — first op before the transfer
    ("sub_140280090",  0x280090),
    # sub_1405007B0 was the real "AddObject" worker called by the Papyrus
    # AddItem native — it's called from vt[0x7A]?  re-check
    ("sub_1405007B0",  0x5007B0),
    # sub_140502940 — called from sub_1405007B0
    ("sub_140502940",  0x502940),
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


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
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    for name, rva in CANDIDATES:
        log(f"\n==== {name} (RVA 0x{rva:X}) ====", fh)
        log(decomp(img + rva), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
