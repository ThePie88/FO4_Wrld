"""Decomp sub_14033EC90 and sub_14033EF00 to find a simpler path."""
import idc
import ida_hexrays
ida_hexrays.init_hexrays_plugin()

def log(fh, msg):
    print(msg, flush=True)
    fh.write(msg + "\n")

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_verify_ec90.log"
with open(OUT, "w", encoding="utf-8") as fh:
    for ea, name in [
        (0x14033EC90, "sub_14033EC90_batch_wrapper"),
        (0x14033EF00, "sub_14033EF00_lookup"),
        (0x14033E340, "sub_14033E340_entry_alloc"),
        (0x14026E390, "sub_14026E390_precheck"),
    ]:
        log(fh, f"\n== {name} @ 0x{ea:X} ==")
        c = ida_hexrays.decompile(ea)
        if c:
            s = str(c)
            log(fh, s[:5000])

    log(fh, "\nDONE")

idc.qexit(0)
