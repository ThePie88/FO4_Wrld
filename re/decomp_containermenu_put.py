"""Hunt the ContainerMenu "deposit" (TRASFERISCI left->right) engine entry.

Already ruled out:
  - vt[0x7A] AddObjectToContainer : captures TAKE only, not PUT.
  - sub_14031C310 : zero fires during live transfer-menu test.

Working hypothesis: ContainerMenu PUT goes through EITHER
  - sub_1411735A0 (Papyrus "real AddItem", bottom of AddItemFunctor), or
  - a ContainerMenu-specific C++ method that wraps sub_140502940
    / sub_1405007B0 (AddObject inner workers).

This script:
  1. Lists ALL xrefs TO sub_1411735A0 (real AddItem).  For each caller,
     log fn name/RVA + first 2500 chars of Hex-Rays decomp.
  2. Lists ALL xrefs TO sub_1411825A0 (real RemoveItem) — symmetric.
  3. Lists ALL xrefs TO sub_140502940 (AddObject workhorse).
  4. Lists ALL xrefs TO sub_1405007B0 (AddObject inner, broadest net).
  5. Searches the IDB names table for any symbol matching
        ContainerMenu / TransferItem / DepositItem / MoveToContainer
     (case-insensitive regex).  Dumps name + RVA.
  6. For every unique caller discovered in (1)-(4), notes whether the
     caller's name contains "vftable" (= vtable slot dispatch) and
     whether its decomp references strings that look menu/UI-ish
     ("ContainerMenu", "TransferItem", "SHOW", "Menu", "UIMessage",
      "Scaleform", "fxManager", "Transfer").

Output: re/containermenu_put_report.txt
"""
import re
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\containermenu_put_report.txt"

# --- targets ---------------------------------------------------------------
T_ADDITEM_REAL       = 0x11735A0   # sub_1411735A0
T_REMOVEITEM_REAL    = 0x11825A0   # sub_1411825A0
T_ADDOBJ_WORKHORSE   = 0x0502940   # sub_140502940
T_ADDOBJ_INNER       = 0x05007B0   # sub_1405007B0

MENU_KEYWORDS = [
    "containermenu", "transferitem", "depositit", "movetocontainer",
    "container", "transfer", "menu",
]

UI_HINT_STRINGS = [
    "ContainerMenu", "TransferItem", "Menu", "UIMessage",
    "Scaleform", "fxManager", "Transfer", "Container",
    "ItemButton", "BarterMenu", "InventoryMenu",
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=2500, timeout_ok=True):
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


def list_xrefs_to(ea):
    """Return list of (caller_fn_start, caller_name, xref_ea)."""
    out = []
    seen = set()
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn is None:
            out.append((None, "<no func>", xref.frm))
            continue
        key = fn.start_ea
        if key in seen:
            continue
        seen.add(key)
        out.append((fn.start_ea, get_name(fn.start_ea), xref.frm))
    return out


def scan_ui_hints(decomp_text):
    hits = [s for s in UI_HINT_STRINGS if s.lower() in decomp_text.lower()]
    return hits


def is_vftable_caller(name):
    return "vftable" in name.lower() or "::`vftable'" in name


def dump_xref_block(label, target_rva, fh, img):
    ea = img + target_rva
    section(f"{label}   target=sub_{ea:X}  RVA=0x{target_rva:X}", fh)
    xrefs = list_xrefs_to(ea)
    log(f"Found {len(xrefs)} unique caller function(s).", fh)
    for (cea, cname, from_ea) in xrefs:
        if cea is None:
            log(f"\n-- raw xref from 0x{from_ea:X} (no enclosing func)", fh)
            continue
        rva = cea - img
        vflag = " [VTABLE SLOT]" if is_vftable_caller(cname) else ""
        log(f"\n-- caller {cname}  RVA=0x{rva:X}  (xref site 0x{from_ea:X}){vflag}", fh)
        d = decomp(cea, 2500)
        ui_hits = scan_ui_hints(d)
        if ui_hits:
            log(f"   UI-hint strings inside decomp: {', '.join(ui_hits)}", fh)
        else:
            log(f"   UI-hint strings inside decomp: <none>", fh)
        log("--- decomp (first 2500 chars) ---", fh)
        log(d, fh)


def scan_name_table(fh, img):
    section("Symbol search: ContainerMenu / TransferItem / DepositItem / MoveToContainer", fh)
    pat = re.compile(
        r"(containermenu|transferitem|depositit|movetocontainer)",
        re.IGNORECASE,
    )
    hits = []
    for ea, name in idautils.Names():
        if pat.search(name):
            hits.append((ea, name))
    hits.sort()
    log(f"Total matches: {len(hits)}", fh)
    for ea, name in hits:
        rva = ea - img
        log(f"  {name} @ 0x{ea:X}  RVA=0x{rva:X}", fh)


def scan_broader_menu_names(fh, img):
    section("Broader symbol scan: any name containing 'ontainer' AND 'enu' (case-sensitive bits to skip noise)", fh)
    # A relaxed pass to surface anything looking like Container*Menu* or *Menu*Container*.
    rx = re.compile(r"ontainer.*enu|enu.*ontainer", re.IGNORECASE)
    hits = []
    for ea, name in idautils.Names():
        if rx.search(name):
            hits.append((ea, name))
    log(f"Total matches: {len(hits)}", fh)
    for ea, name in sorted(hits):
        log(f"  {name} @ 0x{ea:X}  RVA=0x{ea-img:X}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # ---- (1) real AddItem (Papyrus native)
    dump_xref_block(
        "(1) XREFS TO sub_1411735A0 (Papyrus 'real AddItem', AddItemFunctor bottom)",
        T_ADDITEM_REAL, fh, img)

    # ---- (2) real RemoveItem (symmetric)
    dump_xref_block(
        "(2) XREFS TO sub_1411825A0 (Papyrus 'real RemoveItem', symmetric)",
        T_REMOVEITEM_REAL, fh, img)

    # ---- (3) AddObject workhorse (broader)
    dump_xref_block(
        "(3) XREFS TO sub_140502940 (AddObject workhorse)",
        T_ADDOBJ_WORKHORSE, fh, img)

    # ---- (4) AddObject inner (broadest)
    dump_xref_block(
        "(4) XREFS TO sub_1405007B0 (AddObject inner, broadest net)",
        T_ADDOBJ_INNER, fh, img)

    # ---- (5) symbol search
    scan_name_table(fh, img)
    scan_broader_menu_names(fh, img)

    # ---- (6) meta-summary: tabulate callers and UI hints
    section("(6) Meta: unique callers across (1)-(4) with UI-hint flags", fh)
    all_callers = {}  # rva -> (name, which_targets)
    for tag, rva in [
        ("AddItemReal",     T_ADDITEM_REAL),
        ("RemoveItemReal",  T_REMOVEITEM_REAL),
        ("AddObjWorkhorse", T_ADDOBJ_WORKHORSE),
        ("AddObjInner",     T_ADDOBJ_INNER),
    ]:
        for cea, cname, _fea in list_xrefs_to(img + rva):
            if cea is None:
                continue
            crva = cea - img
            entry = all_callers.setdefault(crva, {"name": cname, "targets": []})
            entry["targets"].append(tag)

    log(f"Total unique callers across all 4 targets: {len(all_callers)}", fh)
    for crva in sorted(all_callers):
        e = all_callers[crva]
        vflag = " [VTABLE SLOT]" if is_vftable_caller(e["name"]) else ""
        d = decomp(crva + img, 6000)  # slightly larger window for hints
        hints = scan_ui_hints(d)
        hstr = ",".join(hints) if hints else "-"
        log(f"  RVA=0x{crva:X}  {e['name']}  targets={'+'.join(e['targets'])}  UI-hints={hstr}{vflag}", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
