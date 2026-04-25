"""
decomp_stradaB_M2_virt42.py

Follow-up: decompile BSGeometry::vtable[42] (setter for alpha property) and
vtable[8] (likely downcast or "as BSGeometry") to find the exact offset the
alpha property slot lives at.

Also decomp:
  - sub_1416D5930 (BSGeometry vt[42]) — SetProperty / SetAlphaProperty
  - sub_1416D5520 (BSGeometry vt[8])  — GetGeometry / ToBSGeometry ?
  - sub_1416D4890 (called at end of BSTriShape::ctor)
  - sub_1416D5600 (called in BSTriShape::ctor) — material installer?
  - sub_142214640 (wraps the 0xB0 alloc) — material wrapper ctor
  - sub_14216F9C0 (wraps the 0x88 alloc)
  - sub_1417E91F0 (wraps the 0x150 alloc)
  - sub_1416BD6F0 (called before setting NiAlphaProperty vt)
"""
import ida_auto, ida_funcs, ida_nalt, ida_hexrays, ida_pro, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_virt42_raw.txt"


def log(fh, msg):
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea, fh, label="", max_lines=400):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            t = str(cf)
            lines = t.split("\n")
            if len(lines) > max_lines:
                log(fh, "\n".join(lines[:max_lines]))
                log(fh, f"  ... (truncated, total={len(lines)} lines)")
            else:
                log(fh, t)
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")


def dump_disasm(ea, fh, label="", insn_count=160):
    log(fh, f"\n-- disasm {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    cur = ea
    end = min(fn.end_ea, ea + insn_count * 16)
    i = 0
    while cur < end and i < insn_count:
        dis = idc.generate_disasm_line(cur, 0) or "?"
        log(fh, f"  0x{cur:X}  {dis}")
        cur = idc.next_head(cur, end)
        i += 1
        if cur == idc.BADADDR:
            break


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    targets = [
        (0x1416D5930, "BSGeometry::vt[42] (SetAlphaProperty? — slot +0x150)"),
        (0x1416D5520, "BSGeometry::vt[8] (Cast-to/GetSomething?)"),
        (0x1416D4890, "sub_1416D4890 (called end of BSTriShape::ctor)"),
        (0x1416D5600, "sub_1416D5600 (called in BSTriShape::ctor)"),
        (0x142214640, "sub_142214640 (wraps 0xB0 alloc in sub_1406B60C0)"),
        (0x14216F9C0, "sub_14216F9C0 (wraps 0x88 alloc in sub_140372CC0)"),
        (0x1417E91F0, "sub_1417E91F0 (wraps 0x150 alloc)"),
        (0x1416BD6F0, "sub_1416BD6F0 (called before NiAlphaProperty vt set)"),
        (0x14182FFD0, "sub_14182FFD0 (BSTriShape factory)"),
    ]
    for ea, lbl in targets:
        decomp(ea, fh, lbl, max_lines=200)

    # Specifically dump disasm of vt[42] in case hexrays is noisy
    dump_disasm(0x1416D5930, fh, "vt[42] disasm", insn_count=80)

    # Also dump BSTriShape and BSDynamicTriShape overrides of vt[42], [8], etc.
    # BSTriShape vtable RVA 0x267E948
    # BSDynamicTriShape vtable RVA 0x267F948
    log(fh, "\n\n==== BSTriShape vtable [42] / [8] ====")
    VT_BSTri = IMG + 0x267E948
    slot42 = ida_bytes.get_qword(VT_BSTri + 8*42)
    slot8  = ida_bytes.get_qword(VT_BSTri + 8*8)
    log(fh, f"BSTriShape vt[8]  -> 0x{slot8:X}  RVA 0x{rva(slot8):X}")
    log(fh, f"BSTriShape vt[42] -> 0x{slot42:X} RVA 0x{rva(slot42):X}")
    if slot42:
        decomp(slot42, fh, "BSTriShape::vt[42]", 200)
    if slot8 and slot8 != IMG + 0x16D5520:
        decomp(slot8, fh, "BSTriShape::vt[8]", 200)

    log(fh, "\n==== BSDynamicTriShape vtable [42] / [8] ====")
    VT_BSDyn = IMG + 0x267F948
    slot42d = ida_bytes.get_qword(VT_BSDyn + 8*42)
    slot8d  = ida_bytes.get_qword(VT_BSDyn + 8*8)
    log(fh, f"BSDynamicTriShape vt[8]  -> 0x{slot8d:X}  RVA 0x{rva(slot8d):X}")
    log(fh, f"BSDynamicTriShape vt[42] -> 0x{slot42d:X} RVA 0x{rva(slot42d):X}")

    log(fh, "\n==== END ====")
    fh.close()
    ida_pro.qexit(0)


main()
