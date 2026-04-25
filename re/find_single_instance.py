"""
Trova la funzione di single-instance detection:
- xrefs a SetForegroundWindow
- per ogni caller, decompila la funzione che lo chiama
- xrefs a NtTerminateProcess / RtlExitUserProcess / ExitProcess
- intersezione: quale funzione chiama SetForegroundWindow E poi exit?
"""
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_name
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\single_instance_report.txt"

def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()

def image_base():
    return ida_nalt.get_imagebase()

def decompile_short(ea, fh, max_chars=2000):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return None
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf:
            src = str(cf)
            if len(src) < max_chars:
                log(src, fh)
            else:
                log(src[:max_chars] + "\n... (truncated)", fh)
            return fn.start_ea
    except Exception as e:
        log(f"    decompile err: {e}", fh)
    return None

def find_import(name):
    """Cerca un import per nome, restituisce ea dove il puntatore è in IAT."""
    nimps = ida_nalt.get_import_module_qty()
    found_eas = []
    for i in range(nimps):
        def cb(ea, imp_name, ordinal):
            if imp_name == name:
                found_eas.append(ea)
            return True
        ida_nalt.enum_import_names(i, cb)
    return found_eas

def xrefs_to_name_ea(name, fh):
    """Trova l'EA dove Windows API name è importata, poi ritorna xrefs a quell'EA."""
    imp_eas = find_import(name)
    log(f"[+] import {name}: {len(imp_eas)} IAT entries", fh)
    all_xrefs = []
    for imp_ea in imp_eas:
        log(f"    IAT @ 0x{imp_ea:X} (RVA 0x{imp_ea - image_base():X})", fh)
        xrefs = list(idautils.XrefsTo(imp_ea, 0))
        log(f"    {len(xrefs)} xrefs", fh)
        for x in xrefs:
            fn = ida_funcs.get_func(x.frm)
            all_xrefs.append((x.frm, fn.start_ea if fn else None))
    # Anche ricerca per nome globale (alcuni IDA normalizzano gli import)
    ea_by_name = ida_name.get_name_ea(idc.BADADDR, name)
    if ea_by_name != idc.BADADDR and all(ea_by_name != e for e, _ in all_xrefs):
        log(f"    also via get_name_ea: 0x{ea_by_name:X}", fh)
        for x in idautils.XrefsTo(ea_by_name, 0):
            fn = ida_funcs.get_func(x.frm)
            all_xrefs.append((x.frm, fn.start_ea if fn else None))
    return all_xrefs

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = image_base()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # ===== SetForegroundWindow callers =====
    log("\n========== SetForegroundWindow xrefs ==========", fh)
    sfg = xrefs_to_name_ea("SetForegroundWindow", fh)
    sfg_callers = set(fn for _, fn in sfg if fn)

    # ===== NtTerminateProcess / RtlExitUserProcess / ExitProcess =====
    log("\n========== Exit API xrefs ==========", fh)
    exit_callers = set()
    for api in ("NtTerminateProcess", "RtlExitUserProcess", "ExitProcess", "TerminateProcess"):
        log(f"\n--- {api} ---", fh)
        r = xrefs_to_name_ea(api, fh)
        for _, fn in r:
            if fn:
                exit_callers.add(fn)

    # ===== Intersezione =====
    log("\n========== Intersezione (funzioni che chiamano BOTH SetForegroundWindow e exit) ==========", fh)
    intersection = sfg_callers & exit_callers
    log(f"[+] {len(intersection)} funzioni sospette:", fh)
    for fn_ea in intersection:
        log(f"\n>>> Suspect function @ 0x{fn_ea:X} (RVA 0x{fn_ea - img:X})", fh)
        decompile_short(fn_ea, fh)

    # ===== Tutti i SetForegroundWindow callers (anche senza exit) =====
    log("\n========== Tutti i SetForegroundWindow callers (fallback) ==========", fh)
    for fn_ea in sfg_callers:
        if fn_ea in intersection:
            continue  # già dumpato
        fn_size = ida_funcs.get_func(fn_ea).size() if ida_funcs.get_func(fn_ea) else 0
        log(f"  fn @ 0x{fn_ea:X} (RVA 0x{fn_ea - img:X}) size=0x{fn_size:X}", fh)
        if fn_size and fn_size < 0x400:  # solo funzioni piccole (init probabili)
            decompile_short(fn_ea, fh, max_chars=1500)
            log("", fh)

    log("\n==== report done ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
