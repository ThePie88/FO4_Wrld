"""Dump raw disassembly around Papyrus native string xrefs to understand
the actual registration pattern on FO4 1.11.191.

We know GetPositionX's native is sub_1411567D0 (it reads *(float*)(a3+0xD0)).
Its string xref is at 0x141161DD1. Dumping ±40 insns around that xref will
reveal the real registration idiom, so we can write a correct extractor.

Also dumps the area around GetParentCell xref for comparison — they are likely
in the same registrar block, so the same pattern should apply.
"""
import ida_auto
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\registrar_dump.txt"

# Known xrefs from prior passes
DUMP_POINTS = [
    ("GetPositionX xref (known native = sub_1411567D0)", 0x141161DD1),
    ("GetParentCell xref",                                 0x141161D8E),
    ("GetBaseObject xref (ObjectReference)",               0x1411611B3),
    ("GetWorldSpace xref",                                 0x1411626DA),
]

BEFORE = 15
AFTER = 30


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def dump_area(ea, before, after, fh):
    # Walk backwards
    cur = ea
    back = []
    for _ in range(before):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR:
            break
        back.append(prev)
        cur = prev
    back.reverse()
    # Now forward including the xref
    fwd = [ea]
    cur = ea
    for _ in range(after):
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR:
            break
        fwd.append(nxt)
        cur = nxt
    addrs = back + fwd
    for a in addrs:
        marker = "  >>>" if a == ea else "     "
        disasm = idc.generate_disasm_line(a, 0) or ""
        # Also get operand values where helpful
        log(f"{marker} 0x{a:X}  {disasm}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)

    for label, ea in DUMP_POINTS:
        log(f"\n==== {label} @ 0x{ea:X} (RVA 0x{ea - img:X}) ====", fh)
        dump_area(ea, BEFORE, AFTER, fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
