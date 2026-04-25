"""B4.c — find the Papyrus Quest.SetStage + GlobalVariable.SetValue natives.

Strategy (mirrors the ObjectReference registrar RE from earlier passes):
  Each Papyrus script type (Quest, GlobalVariable, etc.) has a registrar
  function that binds methods like "SetStage" -> native_handler via the
  same sub_1420F9D00 / sub_14116C6E0 idiom used for ObjectReference.

  For each xref to the relevant string, we:
    - Scan backward for `lea r9, sub_NATIVE` (Idiom B, handler-before-register)
    - Scan forward past the next `call` for `lea rax, sub_NATIVE` (Idiom A,
      handler-after-register via sub_1420F9D00)
  Then decompile the native to pin its signature.

  Target strings:
    'SetStage'       — Quest method
    'GetStage'       — Quest method (sanity neighbor)
    'CompleteQuest'  — Quest method (sanity neighbor)
    'SetValue'       — GlobalVariable method (also Form.* but filter by xref)
    'GetValue'       — GlobalVariable method

Output: re/quest_global_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\quest_global_report.txt"

TARGETS = ["SetStage", "GetStage", "CompleteQuest", "ResetQuest",
           "SetValue", "GetValue",
           "SetStageInstance"]

MAX_SCAN = 80


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decomp(rva, img, fh, max_len=3500):
    ea = img + rva
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log(f"  <no func at 0x{ea:X}>", fh); return
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("  <decomp failed>", fh); return
        s = str(cf)
        if len(s) > max_len:
            s = s[:max_len] + "\n...<truncated>"
        log(s, fh)
    except Exception as e:
        log(f"  <decomp err: {e}>", fh)


def extract_native_from_xref(xref_ea):
    """Returns (lea_r9_before, lea_rax_after_call). Either may be None."""
    cur = xref_ea
    lea_r9_before = None
    back = cur
    for _ in range(20):
        back = idc.prev_head(back)
        if back == idc.BADADDR: break
        if idc.print_insn_mnem(back) == "lea":
            op0 = idc.print_operand(back, 0); op1 = idc.print_operand(back, 1)
            if op0 == "r9" and op1.startswith("sub_"):
                lea_r9_before = idc.get_operand_value(back, 1)
                break

    call_ea = None
    cur = xref_ea
    for _ in range(MAX_SCAN):
        cur = idc.next_head(cur)
        if cur == idc.BADADDR: break
        if idc.print_insn_mnem(cur) == "call":
            call_ea = cur
            break
    lea_rax_after = None
    if call_ea is not None:
        fwd = call_ea
        for _ in range(15):
            fwd = idc.next_head(fwd)
            if fwd == idc.BADADDR: break
            if idc.print_insn_mnem(fwd) == "lea":
                op0 = idc.print_operand(fwd, 0); op1 = idc.print_operand(fwd, 1)
                if op0 == "rax" and op1.startswith("sub_"):
                    lea_rax_after = idc.get_operand_value(fwd, 1)
                    break
    return lea_r9_before, lea_rax_after


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    strs = list(idautils.Strings())
    name_to_ea: dict[str, list[int]] = {}
    for s in strs:
        sv = str(s)
        if sv in TARGETS:
            name_to_ea.setdefault(sv, []).append(s.ea)

    for target in TARGETS:
        log(f"\n==== {target!r} ====", fh)
        if target not in name_to_ea:
            log("  <string not found>", fh); continue
        for str_ea in name_to_ea[target][:3]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            xrefs = list(idautils.XrefsTo(str_ea, 0))
            for x in xrefs[:4]:
                fn = ida_funcs.get_func(x.frm)
                fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
                log(f"    xref 0x{x.frm:X} in {fn_lbl}", fh)
                lea_r9, lea_rax = extract_native_from_xref(x.frm)
                for label, native_ea in [
                    ("idiom-B r9 (before)", lea_r9),
                    ("idiom-A rax (after call)", lea_rax),
                ]:
                    if native_ea is None: continue
                    log(f"      [{label}] native @ RVA 0x{native_ea - img:X}", fh)
                    decomp(native_ea - img, img, fh)
                    log("      ---", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
