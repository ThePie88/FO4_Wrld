"""Decompile specific RVAs to pin down the exact struct offsets.

From registrar_dump.txt we identified these native function addresses. Now
we want the actual memory offsets they read from the REFR.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\decomp_targets_report.txt"

# (label, RVA) — all RVAs relative to image base 0x140000000
TARGETS = [
    ("GetParentCell native",        0x1180FD0),
    ("GetWorldSpace native",        0x1181010),
    ("GetWorldSpace helper (fwd)",  0x0516FB0),
    ("GetBaseObject native",        0x1155BE0),
    ("GetBaseObject extra helper",  0x0284C10),  # called from GetBaseObject native
    # Control:
    ("GetPositionX native (ctrl)",  0x11567D0),
]


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def decompile(rva, img, fh):
    ea = img + rva
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log(f"  <no func at 0x{ea:X}>", fh)
        return
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("  <decomp failed>", fh)
            return
        src = str(cf)
        log(src, fh)
    except Exception as e:
        log(f"  <decomp err: {e}>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh)
        fh.close()
        ida_pro.qexit(2)

    for label, rva in TARGETS:
        log(f"\n==== {label} (RVA 0x{rva:X}) ====", fh)
        decompile(rva, img, fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
