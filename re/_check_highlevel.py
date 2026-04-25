"""Check high-level NIF load callers for a 'load by path' API."""
import idc
import ida_hexrays
ida_hexrays.init_hexrays_plugin()

def log(fh, msg):
    print(msg, flush=True)
    fh.write(msg + "\n")

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\_check_highlevel.log"
with open(OUT, "w", encoding="utf-8") as fh:
    for ea, name in [
        (0x1407758D0, "caller_of_ec90_a"),
        (0x140771100, "caller_of_ee60_sub_140771100"),
        (0x1417B3D10, "caller_of_ec90_sub_1417B3D10"),
        (0x1417B3E90, "caller_of_ec90_sub_1417B3E90"),
        (0x1417B59C0, "caller_of_ec90_sub_1417B59C0"),
    ]:
        log(fh, f"\n== {name} @ 0x{ea:X} ==")
        c = ida_hexrays.decompile(ea)
        if c:
            s = str(c)[:3500]
            log(fh, s)

    log(fh, "\nDONE")

idc.qexit(0)
