"""PUT path RE pass #2 — focused targets.

PRECISE:
  T1. Find RemoveItemFunctor and AddItemFunctor vtable symbols. Search
      relaxed (allow backticks, anonymous namespace). Dump slots.
      The vtable's [0] slot is usually the type's dtor/finalize; slot
      [n] is operator(). Bethesda's typical layout:
        +0x00 vftable ptr
        +0x08 atomic refcount
        +0x10 ...data...
      Bulk of class methods: dtor + operator() + utility.

  T2. Find ALL callers of sub_1405007B0 (vt[0x7A]'s inner AddObject).
      If vt[0x7A] is the ONLY caller, the PUT path doesn't go through
      this chain. Otherwise, another entry point exists.

  T3. Find ALL callers of sub_140502940 (AddObject workhorse).

  T4. ContainerMenu vtable symbol — try different name patterns.

  T5. Dump ContainerMenu ctor's body (re-check) to see what vtable base
      addr is assigned. Trace back to find the actual vftable.

Output: re/put_path2_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes, ida_name

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\put_path2_report.txt"


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


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # ============ T1: RemoveItemFunctor / AddItemFunctor vtables ============
    section("T1 — Functor vtable search (loose pattern)", fh)
    for ea, name in idautils.Names():
        # Case-insensitive, any form including anonymous namespace etc.
        low = name.lower().replace("'", "")
        if ("itemfunctor" in low or "movefunctor" in low) and ("vftable" in low or "vtable" in low):
            log(f"  {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)
            for k in range(8):
                slot = ea + k * 8
                t = read_q(slot)
                nm = get_name(t)
                log(f"    slot[{k}] -> 0x{t:X} (RVA 0x{t-img:X})  {nm}", fh)

    # Also broader: any symbol mentioning "RemoveItem" or "AddItem"
    section("T1b — all RemoveItem/AddItem symbols", fh)
    for ea, name in idautils.Names():
        if any(k in name for k in ("RemoveItem", "AddItem", "MoveItem", "Transfer")):
            log(f"  {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)

    # ============ T2: callers of sub_1405007B0 (vt[0x7A] inner) ============
    section("T2 — callers of sub_1405007B0 (AddObject inner)", fh)
    for xr in list(idautils.XrefsTo(img + 0x5007B0, 0))[:20]:
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"  caller 0x{xr.frm:X} in {fn_lbl}  {get_name(xr.frm)}", fh)

    # ============ T3: callers of sub_140502940 (AddObject workhorse) ============
    section("T3 — callers of sub_140502940 (AddObject workhorse)", fh)
    for xr in list(idautils.XrefsTo(img + 0x502940, 0))[:20]:
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"  caller 0x{xr.frm:X} in {fn_lbl}  {get_name(xr.frm)}", fh)
        if fn:
            # Decomp the caller too — short preview
            dc = decomp(fn.start_ea, 3000)
            log(f"    --- preview ---", fh)
            log(dc, fh)
            log("    ---", fh)

    # ============ T4: ContainerMenu vtable ============
    section("T4 — ContainerMenu / subclass vtables (broader search)", fh)
    for ea, name in idautils.Names():
        low = name.lower()
        if "containermenu" in low:
            log(f"  {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)

    # ============ T5: the AddObject chain — sub_14034D320 (populate) callers ============
    section("T5 — callers of sub_14034D320 (list populate from CONT)", fh)
    for xr in list(idautils.XrefsTo(img + 0x34D320, 0))[:10]:
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"  caller 0x{xr.frm:X} in {fn_lbl}", fh)

    # Also: find the "remove from list" symmetric function — maybe its
    # RVA is near sub_14034D320. Dump neighbors.
    section("T5b — functions adjacent to sub_14034D320", fh)
    for off in range(-0x400, 0x401, 0x80):
        ea = img + 0x34D320 + off
        fn = ida_funcs.get_func(ea)
        if fn and fn.start_ea == ea:
            log(f"  RVA 0x{ea - img:X}  {get_name(ea)}", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
