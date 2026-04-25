"""Final RE pass — where does ContainerMenu hold the target REFR?

Goals:
  1. Full decomp of sub_1410412B0 (ContainerMenu factory) — signature
     should reveal if REFR is passed in as arg.
  2. Full decomp of sub_14103C460 (ContainerMenu ctor) — see if REFR
     is stored in a struct offset immediately, or set later.
  3. Callers of sub_1410412B0: who spawns a ContainerMenu and with
     what arguments.
  4. Callers of sub_14103C460: who constructs the ContainerMenu
     object directly (might be the engine's menu-stack logic).
  5. Look for "Activate"-style methods on TESObjectREFR that would
     open ContainerMenu. Common names: Activate, ActivateRef,
     OpenContainer, LootContainer. We already know TESObjectREFR
     vtable is at RVA 0x2564838; specific activation slots unknown.

Also check sub_14016399D and sub_14103C474 and sub_1410405F9 (xrefs
to "ContainerMenu" string from level0_container_report) — those
are likely the engine-side call sites that open the menu.

Output: re/containermenu_refr_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes, ida_name

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\containermenu_refr_report.txt"


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 72, fh)
    log(f"== {title}", fh)
    log("=" * 72, fh)


def decomp(ea, max_len=20000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # 1. ContainerMenu factory — full decomp
    section("sub_1410412B0 (ContainerMenu factory) FULL", fh)
    log(decomp(img + 0x10412B0), fh)

    # 2. ContainerMenu ctor — full decomp (we have partial but let's re-dump)
    section("sub_14103C460 (ContainerMenu ctor) FULL", fh)
    log(decomp(img + 0x103C460, 30000), fh)

    # 3. Callers of sub_1410412B0 (factory)
    section("callers of sub_1410412B0 (ContainerMenu factory)", fh)
    for xr in list(idautils.XrefsTo(img + 0x10412B0, 0)):
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        n = ida_name.get_ea_name(xr.frm) or ""
        log(f"  0x{xr.frm:X} in {fn_lbl}  {n}", fh)
        if fn:
            log("    --- caller decomp (first 6000 chars) ---", fh)
            log(decomp(fn.start_ea, 6000), fh)
            log("    ---", fh)

    # 4. Callers of sub_14103C460 (ctor)
    section("callers of sub_14103C460 (ContainerMenu ctor)", fh)
    for xr in list(idautils.XrefsTo(img + 0x103C460, 0)):
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"  0x{xr.frm:X} in {fn_lbl}", fh)

    # 5. xrefs to "ContainerMenu" string in code paths (from phase 4 earlier)
    section("ContainerMenu string xref contexts", fh)
    for name, rva in [
        ("sub_14016399D (in 0x163970)",   0x163970),
        ("sub_14103C474 (in 0x103C460)",  0x103C460),
        ("sub_1410405F9 (in 0x10405C0)",  0x10405C0),
    ]:
        log(f"\n  ---- {name} ----", fh)
        log(decomp(img + rva, 8000), fh)

    # 6. TESObjectREFR::Activate — common slot numbers from Bethesda class
    # hierarchy. Activate is typically vt[0x37] or nearby in Skyrim.
    # Dump slots 50-90 which cover Activate + related in FO4 likely.
    section("TESObjectREFR vtable slots 50-90 (Activate candidates)", fh)
    vt_base = img + 0x2564838
    for i in range(50, 91):
        slot_ea = vt_base + i * 8
        t = ida_bytes.get_qword(slot_ea)
        nm = ida_name.get_ea_name(t) or f"sub_{t:X}"
        log(f"  slot[{i:3}] (off 0x{i*8:X}) -> 0x{t:X} (RVA 0x{t-img:X})  {nm}", fh)

    # 7. Search for strings mentioning "Activate" which often appear as
    # help text / debug output near the activation path.
    section("strings 'Activate' xrefs (search for activation path)", fh)
    for s in idautils.Strings():
        sv = str(s)
        if sv in ("Activate", "ActivateRef", "OpenContainer", "Loot"):
            log(f"  string {sv!r} @ 0x{s.ea:X} (RVA 0x{s.ea-img:X})", fh)
            for xr in list(idautils.XrefsTo(s.ea, 0))[:3]:
                fn = ida_funcs.get_func(xr.frm)
                fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
                log(f"    xref 0x{xr.frm:X} in {fn_lbl}", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
