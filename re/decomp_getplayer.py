"""
Decompila sub_141122670 (Game.GetPlayer nativo) e sub_14059A3F0 (GetPos handler).
Estrae il riferimento al singleton player dal disassembly.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\getplayer_report.txt"

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def image_base():
    return ida_nalt.get_imagebase()

def rva(ea, img):
    return ea - img

def disasm_all(start, length, fh, img):
    """Disassembla tutte le istruzioni da start per `length` byte."""
    ea = start
    end = start + length
    while ea < end:
        insn = idc.GetDisasm(ea)
        log(f"    0x{ea:X} [RVA 0x{rva(ea, img):X}]  {insn}", fh)
        nxt = idc.next_head(ea)
        if nxt <= ea or nxt == idc.BADADDR:
            break
        ea = nxt

def decompile_fn(start_ea, label, fh, img):
    fn = ida_funcs.get_func(start_ea)
    if not fn:
        log(f"[-] No function at 0x{start_ea:X}", fh)
        return
    log(f"\n=== {label} @ 0x{fn.start_ea:X} (RVA 0x{rva(fn.start_ea, img):X}), size=0x{fn.size():X} ===", fh)
    log(f"--- Disassembly ---", fh)
    disasm_all(fn.start_ea, fn.size(), fh, img)
    log(f"--- Hex-Rays ---", fh)
    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if cfunc:
            log(str(cfunc), fh)
        else:
            log("[-] decompile returned None", fh)
    except Exception as e:
        log(f"[-] decompile exception: {e}", fh)

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = image_base()
    log(f"[+] Image base: 0x{img:X}", fh)

    if not ida_hexrays.init_hexrays_plugin():
        log("[-] Hex-Rays unavailable", fh)
        fh.close()
        ida_pro.qexit(2)

    # Papyrus Game.GetPlayer native
    decompile_fn(0x141122670, "Papyrus Game.GetPlayer native (sub_141122670)", fh, img)

    # Console GetPos handler
    decompile_fn(0x14059A3F0, "Console GetPos handler (sub_14059A3F0)", fh, img)

    log("\n==== Done ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
