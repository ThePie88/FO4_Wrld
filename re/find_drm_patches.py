"""
Trova punti da patchare per rendere Fallout4.exe steamless:
- Call sites di SteamAPI_RestartAppIfNecessary
- Stringhe 'steam://' + loro xref (ShellExecute targets)
Output: lista RVA + bytes da scrivere.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_ua
import ida_bytes
import ida_name
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\drm_patches.txt"

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)

    # === 1) Trova l'import SteamAPI_RestartAppIfNecessary ===
    log("\n[*] Searching imports for SteamAPI_RestartAppIfNecessary", fh)
    target_name = "SteamAPI_RestartAppIfNecessary"
    import_ea = None

    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name:
            continue
        def cb(ea, name, ordinal):
            nonlocal import_ea
            if name == target_name:
                import_ea = ea
                log(f"[+] Found import {name} in {mod_name} @ 0x{ea:X} (RVA 0x{ea - img:X})", fh)
                return False
            return True
        ida_nalt.enum_import_names(i, cb)

    if import_ea is None:
        # Fallback: ricerca per nome globale
        ea = ida_name.get_name_ea(idc.BADADDR, target_name)
        if ea != idc.BADADDR:
            import_ea = ea
            log(f"[+] Fallback found {target_name} @ 0x{ea:X} (RVA 0x{ea - img:X})", fh)

    if import_ea is None:
        log("[-] SteamAPI_RestartAppIfNecessary not found!", fh)
    else:
        # === 2) Trova call sites ===
        log(f"\n[*] Finding xrefs to {target_name}", fh)
        xrefs = list(idautils.XrefsTo(import_ea, 0))
        log(f"[+] {len(xrefs)} xrefs", fh)
        for x in xrefs:
            insn = idc.GetDisasm(x.frm)
            # Funzione di 5 byte tipica: E8 XX XX XX XX (CALL rel32) o FF 15 XX XX XX XX (CALL [rip+rel32])
            size = idc.get_item_size(x.frm)
            raw = ida_bytes.get_bytes(x.frm, size) or b""
            log(f"    xref 0x{x.frm:X} (RVA 0x{x.frm - img:X}) size={size} bytes={raw.hex()} insn: {insn}", fh)

    # === 3) Stringhe "steam://" ===
    log("\n[*] Searching strings 'steam:'", fh)
    steam_urls = []
    strs = list(idautils.Strings())
    for s in strs:
        try:
            txt = str(s)
        except Exception:
            continue
        if txt.lower().startswith("steam:"):
            steam_urls.append((s.ea, txt))
            log(f"    string @ 0x{s.ea:X} (RVA 0x{s.ea - img:X}): {txt!r}", fh)

    log(f"[+] {len(steam_urls)} steam:// strings found", fh)

    # Per ciascuna, trova xref
    for sea, txt in steam_urls:
        log(f"\n[*] xrefs to {txt!r} @ 0x{sea:X}:", fh)
        xrefs = list(idautils.XrefsTo(sea, 0))
        for x in xrefs:
            insn = idc.GetDisasm(x.frm)
            log(f"    from 0x{x.frm:X} (RVA 0x{x.frm - img:X}) insn: {insn}", fh)
            fn = ida_funcs.get_func(x.frm)
            if fn:
                log(f"      in func 0x{fn.start_ea:X} size=0x{fn.size():X}", fh)

    log("\n==== Report done ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
