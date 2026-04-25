"""
Decompila il contesto attorno agli xref di 'GetPlayer' e 'GetPos', estrae
il puntatore a funzione registrato e trace il singleton player.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_ua
import ida_bytes
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\decomp_report.txt"
IMG = None

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def rva(ea):
    return ea - IMG

def disasm_window(ea, before=6, after=6, fh=None):
    """Disassembla N istruzioni prima e dopo ea."""
    lines = []
    cur = ea
    for _ in range(before):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR or prev >= cur:
            break
        cur = prev
    for _ in range(before + after + 1):
        if cur == idc.BADADDR:
            break
        insn = idc.GetDisasm(cur)
        marker = "  >>" if cur == ea else "    "
        lines.append(f"{marker} 0x{cur:X}  {insn}")
        cur = idc.next_head(cur)
    return "\n".join(lines)

def decompile_func(ea, fh, label=""):
    """Decompila la funzione che contiene ea."""
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(f"[-] No function at 0x{ea:X}", fh)
        return
    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if cfunc is None:
            log(f"[-] Hex-Rays failed on 0x{fn.start_ea:X}", fh)
            return
        log(f"=== Decompiled {label} function @ 0x{fn.start_ea:X} (RVA 0x{rva(fn.start_ea):X}) ===", fh)
        log(str(cfunc), fh)
        log(f"=== end decompile ===", fh)
    except Exception as e:
        log(f"[-] Decompile exception on 0x{fn.start_ea:X}: {e}", fh)

def main():
    global IMG
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    IMG = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{IMG:X}", fh)

    # Init hex-rays
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] Hex-Rays not available!", fh)
        fh.close()
        ida_pro.qexit(2)

    # === 1) Papyrus 'GetPlayer' — decompila sub_141123910 e vicini ===
    log("\n========== PAPYRUS GetPlayer CONTEXT ==========", fh)
    getplayer_xrefs = [0x141124B68, 0x141124C30]
    for xref in getplayer_xrefs:
        log(f"\n[*] xref @ 0x{xref:X} (RVA 0x{rva(xref):X})", fh)
        log(disasm_window(xref, before=4, after=10), fh)

    # Decompila la funzione che li contiene
    log("\n[*] Decompile containing function sub_141123910:", fh)
    decompile_func(0x141123910, fh, "GetPlayer registrar")

    # === 2) Console 'GetPos' — decompila contesto della tabella comandi ===
    log("\n========== CONSOLE GetPos CONTEXT ==========", fh)
    getpos_xref = 0x142EDF3E0
    log(f"\n[*] GetPos table entry @ 0x{getpos_xref:X} (RVA 0x{rva(getpos_xref):X})", fh)
    # Dump 64 bytes (probabile struct command: name_ptr, short_name_ptr, help_ptr, handler_ptr, ...)
    log("[*] Raw bytes around table entry:", fh)
    for off in range(-16, 80, 8):
        ea = getpos_xref + off
        try:
            qw = idc.get_qword(ea)
            marker = "  >>" if off == 0 else "    "
            sym = idc.get_name(qw) or ""
            log(f"{marker} 0x{ea:X} [RVA 0x{rva(ea):X}]: 0x{qw:016X}  {sym}", fh)
        except Exception as e:
            log(f"    0x{ea:X}: <read error> {e}", fh)

    # === 3) Dump primo COL di PlayerCharacter per trovare la vtable ===
    log("\n========== PlayerCharacter COLs (25 xrefs to TD) ==========", fh)
    # Prima COL è a 0x1429CC83C, ma l'xref è l'indirizzo dell'istruzione, non del COL stesso.
    # COLs sono in .rdata da ~0x1429CC800 a ~0x1429CD100 basandoci sugli xref.
    # Cerchiamo xref a questa range da .rdata (non da .text) = vtable ref (la COL è prima della vtable)
    # Ma in MSVC x64, COL è direttamente a [vtable - 8]. Cerchiamo xref a ciascuna COL.
    # Per ora dump bytes attorno al primo xref per capire layout.
    col_range_start = 0x1429CC800
    col_range_end = 0x1429CD200
    log(f"[*] Scanning xrefs TO COL range 0x{col_range_start:X} - 0x{col_range_end:X}", fh)
    vtable_candidates = []
    for ea in range(col_range_start, col_range_end, 8):
        for x in idautils.XrefsTo(ea, 0):
            # Ignora xref da .text (sono RTTI code refs); vogliamo xref da .rdata (vtable layout)
            seg_name = idc.get_segm_name(x.frm)
            if seg_name and seg_name in (".rdata", ".data"):
                vtable_candidates.append((ea, x.frm, seg_name))

    log(f"[+] Found {len(vtable_candidates)} potential vtable refs:", fh)
    for col, vt_ref, seg in vtable_candidates[:30]:
        # vtable_base = vt_ref + 8 (vtable[0] è 8 byte dopo la COL ref)
        vt = vt_ref + 8
        log(f"    COL 0x{col:X} referenced from 0x{vt_ref:X} (seg {seg}) → vtable @ 0x{vt:X} (RVA 0x{rva(vt):X})", fh)

    log("\n==== decomp_report complete ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
