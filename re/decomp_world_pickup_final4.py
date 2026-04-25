"""Decomp the 7 callers of vt[0xEC] (PlayerCharacter::PickUp candidate).

Known callers (from call qword ptr [reg+0x760] scan):
  1. sub_140458470  RVA=0x458470
  2. sub_1404652F0  RVA=0x4652F0
  3. sub_140505D00  RVA=0x505D00
  4. sub_140A0A270  RVA=0xA0A270
  5. sub_140A4E690  RVA=0xA4E690
  6. sub_141033580  RVA=0x1033580
  7. sub_14103D3E0  RVA=0x103D3E0

Goal: identify which is the player-activate entry vs ContainerMenu
(withdraw), Steal, etc.
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report_final4.txt"

CALLERS = [
    (0x458470, "sub_140458470"),
    (0x4652F0, "sub_1404652F0"),
    (0x505D00, "sub_140505D00"),
    (0xA0A270, "sub_140A0A270"),
    (0xA4E690, "sub_140A4E690"),
    (0x1033580, "sub_141033580"),
    (0x103D3E0, "sub_14103D3E0"),
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=8000):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def list_xrefs_to(ea):
    out = []
    seen = set()
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn is None:
            out.append((None, "<no func>", xref.frm, xref.type))
            continue
        key = fn.start_ea
        if key in seen:
            continue
        seen.add(key)
        out.append((fn.start_ea, get_name(fn.start_ea), xref.frm, xref.type))
    return out


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    for rva, name in CALLERS:
        ea = img + rva
        section(f"Caller of vt[0xEC]: {name}  RVA=0x{rva:X}", fh)
        # Callers of this caller
        xrefs = list_xrefs_to(ea)
        log(f"  This function has {len(xrefs)} code callers", fh)
        for (cea, cname, _fea, _xt) in xrefs[:8]:
            if cea is None:
                continue
            log(f"    - {cname} (RVA=0x{cea-img:X})", fh)
        log("", fh)
        log("--- decomp first 5000 chars ---", fh)
        log(decomp(ea, 5000), fh)
        log("", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
