"""Confirm: ContainerMenu::vt[21] = sub_14103E950 is ContainerMenu::TransferItem.

Walk-through so far:
  sub_140A548B0 (Scaleform callback registrar) registers the string
  'transferItem' with enum id = 1.
  sub_140A54210 (ContainerMenuBase::vt[1], the Scaleform dispatch router)
  case 1LL:
      (*(*this + 168))(this, formId, amount, isPlayerSide)
  where 168/8 == 21. ContainerMenu::vt[21] == sub_14103E950 (RVA 0x103E950).
  So sub_14103E950 is ContainerMenu::TransferItem — the deposit/withdraw entry.

Also note: the 'this' pointer passed is the ContainerMenu C++ object.
The signature is:
    void TransferItem(ContainerMenu* this, uint32_t formID, uint32_t count, uint8_t isPlayer)
(based on the cast: __int64 *a1 + 168, then formID=u32 @ v12+16, count=u32 @ v12+48,
 flag=u8 @ v12+80).

Action:
  1. Full Hex-Rays of sub_14103E950 (TransferItem).
  2. First-level callees: is sub_1411735A0 / sub_140502940 / 0x5007B0 in there?
     What about vt[0x7A] through a TESObjectREFR*?
  3. Full Hex-Rays of the sibling BarterMenu TransferItem (likely slot[21] on
     any BarterMenu vtable too) — search for '??_7BarterMenu@@6B@'.
  4. Check xrefs TO sub_14103E950 so we can gauge scope (confirm it really is
     the unique transfer call target).
  5. Peek into sub_141040F7C (the ContainerMenu vtable _0 secondary first-slot)
     for potential thunk relevance.
"""
import re
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\vt21_transferitem_report.txt"


def log(m, fh):
    print(m); fh.write(m + "\n"); fh.flush()


def section(t, fh):
    log("\n" + "=" * 78, fh); log(f"== {t}", fh); log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, cap=60000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= cap else s[:cap] + "\n...<trunc>"
    except Exception as e:
        return f"<err: {e}>"


def list_callees(ea, fh, img):
    fn = ida_funcs.get_func(ea)
    if fn is None: return
    seen = set()
    for head in idautils.FuncItems(fn.start_ea):
        for x in idautils.XrefsFrom(head, 0):
            if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            if x.to in seen: continue
            seen.add(x.to)
            log(f"    call-> 0x{x.to:X} RVA=0x{x.to-img:X}  {get_name(x.to)}", fh)


def list_strings(ea, fh):
    fn = ida_funcs.get_func(ea)
    if fn is None: return
    for head in idautils.FuncItems(fn.start_ea):
        for x in idautils.XrefsFrom(head, 0):
            s = idc.get_strlit_contents(x.to, -1, idc.STRTYPE_C)
            if s and 3 <= len(s) < 80:
                try:
                    t = s.decode('utf-8', errors='replace')
                    if all(32 <= ord(c) < 127 for c in t):
                        log(f"    str @ 0x{x.to:X}: {t!r}", fh)
                except: pass


def list_xrefs_to(ea, fh, img, limit=40):
    log(f"  xrefs TO 0x{ea:X}:", fh)
    cnt = 0
    for x in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(x.frm)
        if fn:
            log(f"    from {get_name(fn.start_ea)} 0x{fn.start_ea:X} (RVA 0x{fn.start_ea-img:X}) site 0x{x.frm:X}", fh)
        else:
            log(f"    raw @ 0x{x.frm:X}", fh)
        cnt += 1
        if cnt >= limit: break
    if cnt == 0: log("    <none>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # ---- MAIN TARGET: ContainerMenu::TransferItem = sub_14103E950
    section("ContainerMenu::TransferItem  (vt[21]) = sub_14103E950", fh)
    ea = img + 0x103E950
    list_xrefs_to(ea, fh, img)
    log("-- callees --", fh); list_callees(ea, fh, img)
    log("-- strings --", fh); list_strings(ea, fh)
    log("-- Hex-Rays --", fh)
    log(decomp(ea, 60000), fh)

    # ---- Related TransferItem cluster slots (ContainerMenu vtable 22,21 mirrored)
    for label, rva in [
        ("ContainerMenu::vt[15] sub_14103CFC0", 0x103CFC0),
        ("ContainerMenu::vt[21] sub_14103E950  (TransferItem)", 0x103E950),
        ("ContainerMenu::vt[22] sub_140A55D40", 0xA55D40),
        ("ContainerMenu::vt[23] sub_14103ED80", 0x103ED80),
        ("ContainerMenu::vt[24] sub_14103EF60", 0x103EF60),
        ("ContainerMenu::vt[25] sub_14103F030", 0x103F030),
        ("ContainerMenu::vt[26] sub_140A55D80", 0xA55D80),
        ("ContainerMenu::vt[27] sub_140A55E20", 0xA55E20),
        ("ContainerMenu::vt[28] sub_14103E160", 0x103E160),
        ("ContainerMenu::vt[29] sub_140A56000", 0xA56000),
        ("ContainerMenu::vt[30] sub_140A56120", 0xA56120),
        ("ContainerMenu::vt[31] sub_14103E3E0", 0x103E3E0),
        ("ContainerMenu::vt[32] sub_14103E700", 0x103E700),
    ]:
        if rva == 0x103E950:   # already dumped full
            continue
        section(label, fh)
        ea = img + rva
        log("-- callees --", fh); list_callees(ea, fh, img)
        log("-- strings --", fh); list_strings(ea, fh)
        log("-- Hex-Rays --", fh)
        log(decomp(ea, 14000), fh)

    # ---- Search for BarterMenu and other sibling menus that inherit from
    # ContainerMenuBase — their vt[21] should also be TransferItem.
    section("Vtable symbols with 'Menu@@6B@' that include transfer-like class", fh)
    rx = re.compile(r"(BarterMenu|ContainerMenu|FXQuantityMenu|FavoritesMenu)@@6B@", re.IGNORECASE)
    for ea, name in idautils.Names():
        if rx.search(name) and "??_7" in name:
            slot21 = ida_bytes.get_qword(ea + 21 * 8)
            if slot21 > img and slot21 < img + 0x10000000:
                log(f"  {name} @ 0x{ea:X}  slot[21] -> 0x{slot21:X} (RVA 0x{slot21-img:X}) {get_name(slot21)}", fh)

    log("\n==== done ====", fh); fh.close(); ida_pro.qexit(0)


main()
