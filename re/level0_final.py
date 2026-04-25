"""Level-0 aggressive RE pass — FINAL before patch implementation.

Four precise targets, dumped fully. No shortcuts.

  T1. TESObjectREFR::vtable[167] — the "materialize runtime list from
      base CONT" method. Called from sub_140502940 via
      `(*(fn**)(*refr + 1336))(refr, bgscont)`.
      Read the slot at vtable_base + 0x538, decompile the target.

  T2. ContainerMenu factory sub_1410412B0 — who instantiates the
      ContainerMenu and where is the target REFR stored on it.

  T3. sub_140502940 — the REAL AddObject workhorse. Full decomp
      (previous pass truncated). Understand the materialization path
      end-to-end, including error returns.

  T4. ContainerMenu vtable — identify virtual methods, especially
      the "message handler" / "process input" slots which is how user
      clicks reach C++. Also dump the ContainerMenu ctor postscript to
      see what delegates are bound.

  Also: all data-xref locations for vt[0x7A] (0x140C7A500) — these
  are vtables of derived REFR classes that inherit vt[0x7A] either
  verbatim or overridden. Useful to know which REFR classes hit our
  hook.

Output: re/level0_final_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes, ida_name

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\level0_final_report.txt"

IMG_BASE_EXPECTED = 0x140000000
TESOBJECTREFR_VTABLE_RVA = 0x2564838
VT_MATERIALIZE_SLOT      = 167       # = 0x538 / 8


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 72, fh)
    log(f"== {title}", fh)
    log("=" * 72, fh)


def decomp(ea, max_len=15000):
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

    # ============ T1: vtable[167] of TESObjectREFR ============
    section("T1 — TESObjectREFR::vtable[167] (the materialize method)", fh)
    vt_base = img + TESOBJECTREFR_VTABLE_RVA
    slot_ea = vt_base + VT_MATERIALIZE_SLOT * 8
    target = read_q(slot_ea)
    log(f"  TESObjectREFR vtable base: 0x{vt_base:X}", fh)
    log(f"  slot 167 @ 0x{slot_ea:X}  (offset 0x{VT_MATERIALIZE_SLOT * 8:X})", fh)
    log(f"  target fn: 0x{target:X}  (RVA 0x{target - img:X})", fh)
    log(f"  IDA name : {get_name(target)}", fh)
    log("\n  --- decomp ---", fh)
    log(decomp(target, 15000), fh)

    # Also dump context: 20 slots around 167 so we see neighbors — helps
    # identify class hierarchy and sibling virtuals.
    section("T1b — neighboring vtable slots (TESObjectREFR, 150–180)", fh)
    for i in range(150, 181):
        slot = vt_base + i * 8
        t = read_q(slot)
        log(f"  slot[{i:3}] (off 0x{i*8:X}) -> 0x{t:X} (RVA 0x{t-img:X})  {get_name(t)}", fh)

    # ============ T2: ContainerMenu factory sub_1410412B0 ============
    section("T2 — ContainerMenu factory sub_1410412B0", fh)
    log(decomp(img + 0x10412B0, 12000), fh)

    # Also its caller chain — who invokes the factory?
    section("T2b — callers of ContainerMenu factory", fh)
    for xr in list(idautils.XrefsTo(img + 0x10412B0, 0))[:12]:
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
        log(f"    caller 0x{xr.frm:X} in {fn_lbl}", fh)

    # The ContainerMenu REFR reference is stored somewhere on the menu
    # object. Look at the ctor (sub_14103C460) AND sub_1410412B0 for
    # assignments to specific offsets.
    section("T2c — re-decomp of ContainerMenu ctor sub_14103C460 (full)", fh)
    log(decomp(img + 0x103C460, 15000), fh)

    # ============ T3: sub_140502940 complete ============
    section("T3 — sub_140502940 full (AddObject inner workhorse)", fh)
    log(decomp(img + 0x502940, 30000), fh)

    # ============ T4: vt[0x7A] data xrefs — derived REFR vtables ============
    section("T4 — vt[0x7A] (sub_140C7A500) vtable slot data refs — "
            "identifies classes that inherit/override AddObjectToContainer", fh)
    vt7a = img + 0xC7A500
    n = 0
    for xr in idautils.XrefsTo(vt7a, 0):
        n += 1
        fn = ida_funcs.get_func(xr.frm)
        fn_lbl = f"in RVA 0x{fn.start_ea - img:X}" if fn else "(data/vtable slot)"
        log(f"  xref 0x{xr.frm:X} (RVA 0x{xr.frm - img:X}) {fn_lbl}  name={get_name(xr.frm)}", fh)
        if n >= 25: break

    # Dump what's around each xref — if it's a vtable, adjacent slots help
    # identify the class.
    section("T4b — 10 qwords around each vt[0x7A] data ref", fh)
    n = 0
    for xr in idautils.XrefsTo(vt7a, 0):
        fn = ida_funcs.get_func(xr.frm)
        if fn is not None: continue   # skip code xrefs; we want only data
        base = xr.frm - 8 * 3   # 3 slots before
        log(f"  --- around 0x{xr.frm:X} ---", fh)
        for k in range(7):
            ea = base + 8 * k
            q = read_q(ea)
            marker = " <-- vt[0x7A]" if ea == xr.frm else ""
            log(f"    0x{ea:X}: 0x{q:X} ({get_name(q)}){marker}", fh)
        n += 1
        if n >= 10: break

    # ============ T5: ContainerMenu vtable dump ============
    # The ctor line was `*a1 = &ContainerMenu::vftable;` and IDA should
    # have named that symbol. Look for it.
    section("T5 — ContainerMenu vtable (if symbol present)", fh)
    # Search all names for "ContainerMenu::`vftable'" and adjacent
    found = False
    for ea, name in idautils.Names():
        if "ContainerMenu" in name and "vftable" in name:
            log(f"  found symbol: {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)
            found = True
            # dump 40 slots
            for i in range(40):
                slot = ea + i * 8
                t = read_q(slot)
                log(f"    slot[{i:3}] -> 0x{t:X} (RVA 0x{t-img:X})  {get_name(t)}", fh)
            break
    if not found:
        log("  <ContainerMenu::vftable symbol not found by IDA>", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
