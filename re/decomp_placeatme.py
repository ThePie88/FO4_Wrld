"""Decompile PlaceAtMe / PlaceActorAtMe natives (skipped in previous run)
and also walk into the first callee to understand what core primitive they use.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\placeatme_decomp.txt"

TARGETS = [
    ("PlaceAtMe_native",        0x1159C10),
    ("PlaceActorAtMe_native",   0x1159FB0),
    ("MoveTo_native",           0x11588D0),   # for cross-ref
    ("Disable_native",          0x11543B0),
    ("Delete_native",           0x11541C0),
]


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def decomp(ea, fh):
    try:
        fn = ida_funcs.get_func(ea)
        if not fn:
            log("  [no func at 0x{:X}]".format(ea), fh)
            return
        cf = ida_hexrays.decompile(fn.start_ea)
        if not cf:
            log("  [decompile returned None]", fh)
            return
        src = str(cf)
        log(src, fh)
    except Exception as e:
        log("  [decomp error: {}]".format(e), fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log("[+] Image base: 0x{:X}".format(img), fh)

    if not ida_hexrays.init_hexrays_plugin():
        log("[-] Hex-Rays unavailable", fh)
        fh.close()
        ida_pro.qexit(2)
        return

    for name, rva in TARGETS:
        ea = img + rva
        log("\n==== {} @ RVA 0x{:X} (EA 0x{:X}) ====".format(name, rva, ea), fh)
        decomp(ea, fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
