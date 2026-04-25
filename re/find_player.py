"""
IDAPython v2 — usa idautils.Strings() (API pulita, funziona in IDA 9.x)
"""
import ida_auto
import ida_funcs
import ida_segment
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\find_player_report.txt"

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def image_base():
    return ida_nalt.get_imagebase()

def to_rva(ea):
    return ea - image_base()

def list_xrefs_to(ea, fh, label=""):
    xrefs = list(idautils.XrefsTo(ea, 0))
    log(f"[+] {label} @ 0x{ea:X} (RVA 0x{to_rva(ea):X}) has {len(xrefs)} xrefs:", fh)
    for x in xrefs[:30]:
        fn = ida_funcs.get_func(x.frm)
        fname = ida_funcs.get_func_name(fn.start_ea) if fn else "?"
        log(f"    from 0x{x.frm:X} (RVA 0x{to_rva(x.frm):X}) func={fname} type={x.type}", fh)
    return xrefs

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log("==== waiting for auto_wait ====", fh)
    ida_auto.auto_wait()
    log(f"[+] Image base: 0x{image_base():X}", fh)

    # Costruisci lista strings una volta sola (è lento)
    log("[*] Enumerating strings...", fh)
    strs = list(idautils.Strings())
    log(f"[+] Total strings: {len(strs)}", fh)

    targets = {
        ".?AVPlayerCharacter@@":     "RTTI PlayerCharacter",
        ".?AVActor@@":               "RTTI Actor",
        ".?AVTESObjectREFR@@":       "RTTI TESObjectREFR",
        ".?AVTESForm@@":             "RTTI TESForm",
        "GetPos":                    "Console GetPos",
        "GetPlayer":                 "Papyrus GetPlayer",
        "PlayerRef":                 "Editor ID PlayerRef",
        "PlayerCharacter":           "Class name literal",
    }

    found = {}
    for s in strs:
        try:
            txt = str(s)
        except Exception:
            continue
        for needle, label in targets.items():
            if txt == needle:
                found.setdefault(needle, []).append(s.ea)

    for needle, label in targets.items():
        hits = found.get(needle, [])
        log(f"[+] {label!r} ({needle!r}): {len(hits)} hits", fh)
        for h in hits:
            log(f"    string at 0x{h:X} (RVA 0x{to_rva(h):X})", fh)
            list_xrefs_to(h, fh, f"  {label} string")

            # Per RTTI, prova anche TypeDescriptor a string-0x10
            if needle.startswith(".?AV"):
                td = h - 0x10
                log(f"    presumed TypeDescriptor @ 0x{td:X} (RVA 0x{to_rva(td):X})", fh)
                list_xrefs_to(td, fh, f"  {label} TypeDescriptor")

    log("==== Report complete ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
