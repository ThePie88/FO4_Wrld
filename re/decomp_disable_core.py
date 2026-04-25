"""Decompile the actual core disable/hide worker at RVA 0x1173D80
(called inline by Papyrus Disable). Also decompile sub_140C57640 (REFR ctor)
and sub_1402E4DF0 (PlaceRefIntoWorld) — core primitives PlaceAtMe uses.
Also dump sub_140CA4420 (ChangeRace core, called by SetRace native).
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\hijack_primitives_decomp.txt"

TARGETS = [
    ("Disable_worker_sub_141173D80", 0x1173D80),
    ("REFR_ctor_sub_140C57640",      0xC57640),
    ("PlaceRefIntoWorld_sub_1402E4DF0", 0x2E4DF0),
    ("ChangeRace_sub_140CA4420",     0xCA4420),
    ("CombatStyle_set_sub_140CCD400", 0xCCD400),
    ("StopCombat_worker_sub_140DAF2D0", 0xDAF2D0),
    ("EvalPackage_core_sub_140C690B0",  0xC690B0),
    ("Outfit_set_sub_140654C00",    0x654C00),
    ("Outfit_set_sleep_sub_140654C20", 0x654C20),
]


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def decomp(ea, fh, max_lines=200):
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
        nlines = src.count("\n")
        if nlines > max_lines:
            # print only first max_lines
            log("--- decompile (clipped to first {} of {} lines) ---".format(max_lines, nlines), fh)
            log("\n".join(src.split("\n")[:max_lines]), fh)
            log("--- (truncated) ---", fh)
        else:
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
        decomp(ea, fh, max_lines=120)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
