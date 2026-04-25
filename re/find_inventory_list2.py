"""B1.c deeper pass. First script showed Papyrus natives are functor-dispatch
wrappers — they don't read the BGSInventoryList directly. The real work
functions are:
  - sub_141174FD0  -- GetItemCount impl (tail-called from Papyrus wrapper)
  - TESObjectREFR::vtable[0x7A]  -- AddObjectToContainer (our container hook)
  - sub_141152A00 / sub_14115BA70  -- AddItem/RemoveItem functor ctors (use a2
                                       = item base form, a3 = target REFR?)

This script decompiles those, plus follows 1-level of calls from each to
find the TESObjectREFR+offset access that points at BGSInventoryList.

Outputs: re/inventory_list_report2.txt
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro
import ida_bytes

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\inventory_list_report2.txt"

# Known-good RVAs from earlier RE passes + report 1
TESOBJECTREFR_VTABLE_RVA = 0x2564838
ADD_TO_CONTAINER_SLOT    = 0x7A
GET_ITEM_COUNT_IMPL_RVA  = 0x1174FD0
ADDITEM_FUNCTOR_CTOR_RVA = 0x1152A00
REMOVEITEM_FUNCTOR_CTOR_RVA = 0x115BA70


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decomp_str(ea, max_len=6000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        if len(s) > max_len: s = s[:max_len] + "\n...<truncated>"
        return s
    except Exception as e:
        return f"<decomp err: {e}>"


def read_vtable_slot(vt_ea, slot):
    """vtable is array of 8-byte function pointers."""
    return ida_bytes.get_qword(vt_ea + slot * 8)


def list_callees(ea, max_callees=30):
    """Walk instructions of function, collect direct call targets (sub_X)."""
    fn = ida_funcs.get_func(ea)
    if fn is None: return []
    out = []
    cur = fn.start_ea
    while cur < fn.end_ea and len(out) < max_callees:
        if idc.print_insn_mnem(cur) == "call":
            op = idc.print_operand(cur, 0)
            if op.startswith("sub_"):
                tgt = idc.get_operand_value(cur, 0)
                if tgt not in out:
                    out.append(tgt)
        cur = idc.next_head(cur)
        if cur == idc.BADADDR: break
    return out


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # 1) AddObjectToContainer via vt[0x7A]
    vt_ea = img + TESOBJECTREFR_VTABLE_RVA
    add_to_container_ea = read_vtable_slot(vt_ea, ADD_TO_CONTAINER_SLOT)
    log(f"\n==== vt[0x{ADD_TO_CONTAINER_SLOT:X}] AddObjectToContainer ====", fh)
    log(f"  vt @ 0x{vt_ea:X}  slot -> 0x{add_to_container_ea:X} (RVA 0x{add_to_container_ea - img:X})", fh)
    log(decomp_str(add_to_container_ea), fh)
    log("  --- callees ---", fh)
    for c in list_callees(add_to_container_ea):
        log(f"  sub_{c - img:X} (RVA)", fh)

    # 2) GetItemCount impl (sub_141174FD0)
    log(f"\n==== GetItemCount impl (RVA 0x{GET_ITEM_COUNT_IMPL_RVA:X}) ====", fh)
    log(decomp_str(img + GET_ITEM_COUNT_IMPL_RVA), fh)
    log("  --- callees ---", fh)
    for c in list_callees(img + GET_ITEM_COUNT_IMPL_RVA):
        log(f"  sub_{c - img:X} (RVA)", fh)

    # 3) Walk from AddItemFunctor / RemoveItemFunctor — they were spawned as
    # async tasks; look at their vtable's function (the operator() that
    # actually does the add). Because ctor stored vftable ptr, decomp shows it.
    # Fallback: dump them as they are.
    log(f"\n==== AddItemFunctor ctor (RVA 0x{ADDITEM_FUNCTOR_CTOR_RVA:X}) ====", fh)
    log(decomp_str(img + ADDITEM_FUNCTOR_CTOR_RVA), fh)
    log(f"\n==== RemoveItemFunctor ctor (RVA 0x{REMOVEITEM_FUNCTOR_CTOR_RVA:X}) ====", fh)
    log(decomp_str(img + REMOVEITEM_FUNCTOR_CTOR_RVA), fh)

    # 4) Any string hints on "BGSInventoryList" or "InventoryList" in the image
    log("\n==== strings containing 'Inventory' ====", fh)
    hits = 0
    for s in idautils.Strings():
        sv = str(s)
        if "inventory" in sv.lower() and hits < 30:
            log(f"  0x{s.ea:X} (RVA 0x{s.ea - img:X}) : {sv!r}", fh)
            hits += 1

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
