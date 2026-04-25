"""Find the BGSInventoryList pointer offset on TESObjectREFR, plus the
iteration layout (array pointer + count) we can use from Frida/DLL to
scan a container's inventory.

Strategy (mirrors the kill/container/pos RE passes):
  1. Locate the Papyrus native "GetInventoryItems" (on ObjectReference or
     Actor). Its body reads the REFR+offset pointer and walks the list.
  2. Decompile and eyeball the struct layout.
  3. Fall back to "GetItemCount" (simpler, just reads the list count for
     one item) if GetInventoryItems is too wrapped.

Outputs to: re/inventory_list_report.txt
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro
import re

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\inventory_list_report.txt"

TARGETS = [
    "GetInventoryItems",
    "GetItemCount",
    "GetItemHealthPercent",
    "AddItem",        # already RE'd via vt[0x7A] but Papyrus AddItem native
                      # may expose the list offset more directly
    "RemoveItem",     # vt[0x6D] equivalent
    "HasItem",        # simpler: just a presence lookup
]

MAX_SCAN = 80


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decompile(rva, img, fh, max_len=3000):
    ea = img + rva
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log(f"  <no func at 0x{ea:X}>", fh); return
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("  <decomp failed>", fh); return
        src = str(cf)
        if len(src) > max_len:
            src = src[:max_len] + "\n...<truncated>"
        log(src, fh)
    except Exception as e:
        log(f"  <decomp err: {e}>", fh)


# The Papyrus native registrar for ObjectReference lives at sub_14115EFB0;
# within it, each native registration follows one of two idioms:
#   A) lea rax, sub_NATIVE (AFTER the register call) via sub_1420F9D00
#   B) lea r9, sub_NATIVE (BEFORE the register call) via sub_14116C6E0
# We scan both windows around each string xref.
def extract_native_from_xref(xref_ea, img):
    cur = xref_ea
    lea_r9_before = None
    # Scan backward up to 20 insns for lea r9, sub_X
    back = cur
    for _ in range(20):
        back = idc.prev_head(back)
        if back == idc.BADADDR: break
        if idc.print_insn_mnem(back) == "lea":
            op0 = idc.print_operand(back, 0); op1 = idc.print_operand(back, 1)
            if op0 == "r9" and op1.startswith("sub_"):
                lea_r9_before = idc.get_operand_value(back, 1)
                break
    # Scan forward: find the next `call`, then look for `lea rax, sub_X`
    # within a small window AFTER that call.
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
        sval = str(s)
        if sval in TARGETS:
            name_to_ea.setdefault(sval, []).append(s.ea)

    for target in TARGETS:
        log(f"\n==== {target!r} ====", fh)
        if target not in name_to_ea:
            log("  <string not found>", fh); continue
        for str_ea in name_to_ea[target][:2]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            xrefs = list(idautils.XrefsTo(str_ea, 0))
            for x in xrefs[:3]:
                fn = ida_funcs.get_func(x.frm)
                fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
                log(f"    xref 0x{x.frm:X} in {fn_lbl}", fh)
                lea_r9, lea_rax = extract_native_from_xref(x.frm, img)
                for label, native_ea in [
                    ("idiom-B r9 (before)", lea_r9),
                    ("idiom-A rax (after call)", lea_rax),
                ]:
                    if native_ea is None: continue
                    log(f"      [{label}] native @ RVA 0x{native_ea - img:X}", fh)
                    decompile(native_ea - img, img, fh)
                    log("      ---", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
