"""Trova Papyrus Game.GetForm o TESForm::LookupByFormID e decompila."""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\getform_report.txt"

def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    strs = list(idautils.Strings())

    targets = ["GetForm", "GetFormFromFile", "LookupByID", "LookupByFormID",
               "GetObjectReference", "FindReferenceById"]
    for target in targets:
        hits = [s.ea for s in strs if str(s) == target]
        log(f"\n[+] {target!r}: {len(hits)} hits", fh)
        for h in hits:
            log(f"    @ 0x{h:X} (RVA 0x{h - img:X})", fh)
            xrefs = list(idautils.XrefsTo(h, 0))
            for x in xrefs[:3]:
                fn = ida_funcs.get_func(x.frm)
                log(f"      xref 0x{x.frm:X} in func 0x{fn.start_ea:X} (RVA 0x{fn.start_ea - img:X})" if fn else f"      xref 0x{x.frm:X}", fh)

                # Cerca "lea rax, sub_X" nelle 25 istruzioni dopo (native function pointer)
                cur = x.frm
                for _ in range(25):
                    cur = idc.next_head(cur)
                    if cur == idc.BADADDR: break
                    if idc.print_insn_mnem(cur) == "lea" and idc.print_operand(cur, 1).startswith("sub_"):
                        target_ea = idc.get_operand_value(cur, 1)
                        log(f"        candidate native @ 0x{target_ea:X} (RVA 0x{target_ea - img:X})", fh)
                        try:
                            fnn = ida_funcs.get_func(target_ea)
                            if fnn:
                                cf = ida_hexrays.decompile(fnn.start_ea)
                                if cf:
                                    src = str(cf)
                                    if len(src) < 1500:
                                        log(f"        --- decompile ---", fh)
                                        log(src, fh)
                                        log(f"        ---", fh)
                        except Exception as e:
                            log(f"        decompile err: {e}", fh)
                        break

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
