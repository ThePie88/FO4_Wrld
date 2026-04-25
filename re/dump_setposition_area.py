"""Dump raw disassembly around the SetPosition Papyrus string xref to
figure out the exact registrar pattern FO4 uses for this native."""
import ida_auto
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\setposition_dump.txt"

# From the previous run: SetPosition xref at 0x141165520
DUMP_POINT = 0x141165520
BEFORE = 15
AFTER  = 40


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    log(f"[+] Dumping ±{BEFORE}/{AFTER} around 0x{DUMP_POINT:X}\n", fh)

    # Walk back
    cur = DUMP_POINT
    back = []
    for _ in range(BEFORE):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR: break
        back.append(prev); cur = prev
    back.reverse()

    # Walk forward
    cur = DUMP_POINT
    fwd = [DUMP_POINT]
    for _ in range(AFTER):
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR: break
        fwd.append(nxt); cur = nxt

    for a in back + fwd:
        marker = "  >>>" if a == DUMP_POINT else "     "
        disasm = idc.generate_disasm_line(a, 0) or ""
        log(f"{marker} 0x{a:X}  {disasm}", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
