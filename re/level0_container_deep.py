"""Level-0 aggressive RE pass for container inventory data flow.

Goal: map the FULL engine data flow for container inventory so we can
choose PATCH POINTS (replace engine function bodies with our own) rather
than hooks. No assumptions, no shortcuts — every structure + function
captured with enough detail to decide where to intervene.

Phases (all in one script, all output to re/level0_container_report.txt):

  1. BGSInventoryList struct discovery
     - start from sub_140507660 (GetItemCount real impl)
     - also trace from vt[0x7A] (sub_140C7A500)
     - trace sub_1416579C0 / sub_141659470 / sub_141658FE0 / sub_1416592B0
       (allocator / mutex helpers already seen in decomps)
     - dump the first ~100 bytes worth of field accesses on REFR+0xF8 and
       on the list itself

  2. BGSInventoryItem entry struct (16 bytes)
     - sub_140349B30 FULL decomp — what does it read, what loops
     - trace callers to see how the +8 second qword is used

  3. Base CONT flow
     - sub_140313570(baseForm, 'CONT') = 1414415171 — the component
       extractor. Decomp.
     - What does it return (BGSContainer component)?
     - Find where base CONT entries get walked / materialized

  4. ContainerMenu Scaleform path
     - find the ContainerMenu registrar (same pattern as sub_140B01290 for
       MainMenu, sub_1411861C0 for Quest, sub_141145AA0 for GlobalVar)
     - dump all AS3 callbacks + native handlers
     - Look for "populate", "refresh", "items", "addItem"-style names
     - identify the function that enumerates inventory items for display

  5. Transfer path
     - find what calls vt[0x7A] AddObjectToContainer
     - trace from the AS3 event down to vt[0x7A]

Output is verbose and intended to be read carefully before writing code.
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\level0_container_report.txt"


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 72, fh)
    log(f"== {title}", fh)
    log("=" * 72, fh)


def decomp(ea, max_len=12000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def read_q(ea): return ida_bytes.get_qword(ea)
def read_d(ea): return ida_bytes.get_dword(ea)


def dump_function_block(name, rva, fh, img, max_len=10000):
    section(f"{name}  (RVA 0x{rva:X})", fh)
    ea = img + rva
    log(decomp(ea, max_len), fh)


def find_strings(values):
    """Return {str_value: [ea, ...]}"""
    out: dict[str, list[int]] = {}
    for s in idautils.Strings():
        sv = str(s)
        if sv in values:
            out.setdefault(sv, []).append(s.ea)
    return out


def find_papyrus_registrar_like(marker_strings, fh, img):
    """Like we did for MainMenu/Quest: find function that calls
    sub_1420F9D00(..., STRING, CLASSNAME, ...) for our marker strings.
    Decomp that function for inspection."""
    found = find_strings(marker_strings)
    for target in marker_strings:
        eas = found.get(target, [])
        log(f"\n---- marker {target!r} — {len(eas)} string(s) ----", fh)
        for str_ea in eas[:2]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            for xr in list(idautils.XrefsTo(str_ea, 0))[:3]:
                fn = ida_funcs.get_func(xr.frm)
                fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
                log(f"    xref 0x{xr.frm:X} in {fn_lbl}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # ============ PHASE 1: BGSInventoryList struct discovery ============
    section("PHASE 1 — BGSInventoryList via GetItemCount real impl", fh)
    dump_function_block("sub_140507660 (GetItemCount impl, runtime list walker)",
                         0x507660, fh, img, max_len=20000)

    section("PHASE 1 — AddObjectToContainer vt[0x7A] (full)", fh)
    dump_function_block("sub_140C7A500 (AddObjectToContainer)",
                         0xC7A500, fh, img, max_len=20000)

    section("PHASE 1 — Allocator / mutex helpers", fh)
    dump_function_block("sub_1416579C0 (allocator — seen in many inventory fns)",
                         0x16579C0, fh, img)
    dump_function_block("sub_141659470 (another alloc-like helper)",
                         0x1659470, fh, img)
    dump_function_block("sub_141658FE0 (mutex lock)",
                         0x1658FE0, fh, img)
    dump_function_block("sub_1416592B0 (mutex unlock)",
                         0x16592B0, fh, img)
    dump_function_block("sub_1416597B0 (used by set_stage_started as allocator init?)",
                         0x16597B0, fh, img)

    # ============ PHASE 2: BGSInventoryItem + sub_140349B30 ============
    section("PHASE 2 — sub_140349B30 BGSInventoryItem::GetCount", fh)
    dump_function_block("sub_140349B30 (entry count — previously black-box)",
                         0x349B30, fh, img, max_len=15000)

    section("PHASE 2 — sub_140349830 (seen in fallback GetItemCount branch)", fh)
    dump_function_block("sub_140349830", 0x349830, fh, img)

    # ============ PHASE 3: Base CONT flow ============
    section("PHASE 3 — Base CONT component extractor", fh)
    dump_function_block("sub_140313570 (takes form + sig 'CONT'=1414415171)",
                         0x313570, fh, img, max_len=12000)

    # The fallback branch in GetItemCount also uses sub_14030E0B0 — CONT
    # component walking helper (AddItem via CONT).
    section("PHASE 3 — sub_14030E0B0 (CONT item add helper)", fh)
    dump_function_block("sub_14030E0B0", 0x30E0B0, fh, img)

    # And sub_14034D910 for Actor inventory lookup
    section("PHASE 3 — sub_14034D910 (actor inventory lookup from CONT)", fh)
    dump_function_block("sub_14034D910", 0x34D910, fh, img)

    # ============ PHASE 4: ContainerMenu Scaleform ============
    section("PHASE 4 — ContainerMenu Scaleform registrar hunt", fh)
    find_papyrus_registrar_like([
        "ContainerMenu", "Container",
        "PopulateItems", "PopulateContainerItems",
        "RequestTransfer", "TransferItem", "TransferAll",
        "TakeAll", "ExitContainerMenu",
        "UpdateItem", "SetContainerItems",
        # Also cover the UI element names
        "ItemList", "InvItemList",
    ], fh, img)

    # Heuristic: some containers have "LootMenu" or "BarterMenu" which
    # inherit similar patterns.
    find_papyrus_registrar_like([
        "LootMenu", "BarterMenu",
        "BuyItem", "SellItem",
    ], fh, img)

    # ============ PHASE 5: Transfer path ============
    section("PHASE 5 — callers of sub_140C7A500 (vt[0x7A])", fh)
    vt_target = img + 0xC7A500
    log(f"  target @ 0x{vt_target:X}", fh)
    n_xrefs = 0
    for xr in idautils.XrefsTo(vt_target, 0):
        n_xrefs += 1
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"    caller 0x{xr.frm:X} in {fn_lbl}", fh)
        if n_xrefs >= 15: break
    log(f"  total xrefs: {n_xrefs}", fh)

    # Also the vtable slot itself
    vt_addr = img + 0x2564838
    slot_addr = vt_addr + 0x7A * 8
    log(f"\n  vtable slot @ 0x{slot_addr:X} holds fn ptr to 0x{read_q(slot_addr):X}", fh)
    log(f"  data-xrefs to that slot (who reads it?):", fh)
    n = 0
    for xr in idautils.XrefsTo(slot_addr, 0):
        n += 1
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"    0x{xr.frm:X} in {fn_lbl}", fh)
        if n >= 15: break

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
