"""Search REFR vtable for Activate: use different heuristics.

1. Find slots whose body contains strings or sub_140561B50 (IsInWorld/
   IsInContainer check) + sub_140502940.
2. Find slots that reference both sub_140502940 (workhorse, add) AND
   "removeOwnership"/"delete" patterns.
3. Try the formID matching the BGSEntryPointFunctionData vtables to
   pinpoint the Activate entrypoint in the PerkManager code.
4. Also: examine `sub_140504280` and `sub_140508280` from the 34-caller
   list in more detail — they could be the Activate handler.
5. Check sub_140C5BE50 (slot 0x5C) and sub_140C68F20 (slot 0x5B) which
   are small — might be thin wrappers.
6. Dump REFR vtable size by reading past the last valid slot.

Output: re/world_pickup_report8.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report8.txt"
REFR_VTABLE_RVA = 0x2564838
T_WORKHORSE = 0x502940
T_REMOVE_IT = 0xC9A7B0   # vt[0x6D]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=10000):
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


def func_len(ea):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return 0
    return fn.end_ea - fn.start_ea


def find_thin_REFR_slots(img, fh):
    """Walk REFR vtable, report slots whose FUNCTION size is 20..400
    bytes (small, thin). Thin Activate wrappers possible."""
    section("REFR vtable thin slots (fn size 20..400 bytes) decomp", fh)
    base = img + REFR_VTABLE_RVA
    for i in range(0, 0x120):
        slot = base + i * 8
        tgt = ida_bytes.get_qword(slot)
        if tgt == 0 or tgt == 0xFFFFFFFFFFFFFFFF:
            continue
        sz = func_len(tgt)
        if 20 <= sz <= 400:
            log(f"\n  slot[0x{i:X}] -> {get_name(tgt)}  RVA=0x{tgt-img:X}  sz=0x{sz:X}", fh)
            log(decomp(tgt, 1500), fh)


def scan_refr_vtable_for_both(img, fh):
    """Find slot whose body has BOTH add+remove workhorse usage."""
    section("REFR vtable scan for slots calling BOTH workhorse + removeItem", fh)
    base = img + REFR_VTABLE_RVA
    wh = f"sub_{T_WORKHORSE + img:X}"
    rm = f"sub_{T_REMOVE_IT + img:X}"
    for i in range(0, 0x120):
        slot = base + i * 8
        tgt = ida_bytes.get_qword(slot)
        if tgt == 0 or tgt == 0xFFFFFFFFFFFFFFFF:
            continue
        d = decomp(tgt, 10000)
        if not isinstance(d, str):
            continue
        if (wh in d or "sub_140502940" in d) and (rm in d or "sub_140C9A7B0" in d):
            log(f"\n  slot[0x{i:X}] -> {get_name(tgt)}  RVA=0x{tgt-img:X}  BOTH add+remove", fh)
            log("  --- decomp first 4000 chars ---", fh)
            log(d[:4000], fh)


def scan_for_activate_strings(img, fh):
    """Scan .text for instructions that load 'RefActivated' / '__AddedXX' etc."""
    section("Search decompiled-any-function for distinctive pickup strings", fh)
    # Search name-table for strings
    targets = ["aAvbgspickupput", "aPickedup", "aIactivatepickl", "aFactivatepickr", "aFactivatepickl", "aRefonactivate", "aOnactivate"]
    found = []
    for ea, name in idautils.Names():
        if any(t in name.lower() for t in [x.lower() for x in targets]):
            found.append((ea, name))
    for ea, name in found:
        log(f"  string {name} @ 0x{ea:X}", fh)
        refs = list(idautils.XrefsTo(ea, 0))
        for x in refs[:8]:
            fn = ida_funcs.get_func(x.frm)
            if fn:
                log(f"    used in {get_name(fn.start_ea)}  RVA=0x{fn.start_ea - img:X}  site=0x{x.frm:X}", fh)


def decomp_specific(img, fh, rvas):
    for rva, label in rvas:
        section(f"Full decomp {label} sub_{rva+img:X} RVA=0x{rva:X}", fh)
        log(decomp(img + rva, 10000), fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Find slots calling both add+remove (like a transfer)
    scan_refr_vtable_for_both(img, fh)

    # Find thin slots (likely virtual wrappers)
    find_thin_REFR_slots(img, fh)

    # Search for pickup-related strings and their callers
    scan_for_activate_strings(img, fh)

    # And dump the 4 caller candidates that might be the activate dispatcher
    decomp_specific(img, fh, [
        (0x504280, "sub_140504280 (DropObject?)"),
        (0x504FC0, "sub_140504FC0"),
        (0x508280, "sub_140508280"),
        (0x503D10, "sub_140503D10"),
        (0x522370, "sub_140522370"),
        (0x522B00, "sub_140522B00"),
        (0x523E70, "sub_140523E70"),
        (0x500430, "sub_140500430"),
        (0x501EE0, "sub_140501EE0"),
    ])

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
