"""B1.c final pin — decompile the 4 accessor functions that landed from pass 2.

Target RVAs:
  sub_1405088C0  : "is container?" (checks TESObjectREFR baseForm kind)
  sub_140507660  : GetItemCount real impl (REFR, &out, item, flags)
  sub_1405007B0  : AddObjectToContainer real mutator
  sub_140D3D1A0  : BGSInventoryList accessor (returns the entries array holder)
  sub_140D3D180  : BGSInventoryList accessor sibling

Outputs: re/inventory_list_report3.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\inventory_list_report3.txt"

TARGETS = [
    ("is_container",       0x5088C0),
    ("GetItemCount_real",  0x507660),
    ("AddObjToCont_real",  0x5007B0),
    ("BGSInvList_accA",    0xD3D1A0),
    ("BGSInvList_accB",    0xD3D180),
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
    fh.write(f"[+] Image base: 0x{img:X}\n")
    if not ida_hexrays.init_hexrays_plugin():
        fh.write("[-] no hexrays\n"); fh.close(); ida_pro.qexit(2)

    for name, rva in TARGETS:
        fh.write(f"\n==== {name} (RVA 0x{rva:X}) ====\n")
        fh.write(decomp(img + rva))
        fh.write("\n")

    fh.close()
    ida_pro.qexit(0)


main()
