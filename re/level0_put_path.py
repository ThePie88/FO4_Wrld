"""Level-0 RE — find the PUT engine path (left→right drag in ContainerMenu).

PRECISE targets:

  T1. Dump TESObjectREFR vtable slots 0x70–0x90. Slot 0x7A is
      AddObjectToContainer (our hook). Adjacent slots are likely
      RemoveItem / MoveItemsTo / DropObject / etc. If PUT uses a
      different vtable slot, it's here.

  T2. sub_14115BA70 = ObjectReference.RemoveItem Papyrus native.
      Already partially seen; re-dump completely. It's a functor
      constructor (sets up GameScript::RemoveItemFunctor vftable at
      +0x00 of a heap object). The functor's operator() is the real
      engine call. Trace via the vtable symbol lookup.

  T3. Find functions with BOTH patterns:
         - read REFR+0xF8 (inventory list access)
         - call through a vtable with offset matching known transfer slots
      These are candidate TRANSFER wrappers. Prune by size (< 300 insns)
      to avoid unrelated large fns.

  T4. Symbol search: RemoveItemFunctor / TransferManager / BGSInventory
      related classes. IDA RTTI usually resolves these.

Output: re/put_path_report.txt

PARALLELISM: IDA Python is single-threaded inside idat.exe, so we
can't parallelize the decomp calls. But the disk I/O of writing the
report is minor. Multi-process parallel idat would help only if we
had truly independent sub-analyses — we don't here (all on same DB).
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes, ida_name

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\put_path_report.txt"


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

    # ============ T1: TESObjectREFR vtable 0x70..0x90 ============
    section("T1 — TESObjectREFR vtable slots 0x70..0x90 (near vt[0x7A])", fh)
    vt_base = img + 0x2564838
    for i in range(0x70, 0x91):
        slot = vt_base + i * 8
        t = read_q(slot)
        n = get_name(t)
        marker = "  ← vt[0x7A] AddObjectToContainer" if i == 0x7A else ""
        log(f"  slot[{i:02X}] (off 0x{i*8:03X}) -> 0x{t:X} (RVA 0x{t-img:X})  {n}{marker}", fh)

    # Decomp the slots NEAR 0x7A specifically
    section("T1b — decomp of slots 0x78..0x7C (likely inventory transfer cluster)", fh)
    for i in [0x78, 0x79, 0x7A, 0x7B, 0x7C]:
        slot = vt_base + i * 8
        t = read_q(slot)
        log(f"\n  ---- slot[{i:02X}] -> 0x{t:X} (RVA 0x{t-img:X}) ----", fh)
        log(decomp(t, 6000), fh)

    # ============ T2: Papyrus RemoveItem native ============
    section("T2 — sub_14115BA70 (ObjectReference.RemoveItem Papyrus native)", fh)
    log(decomp(img + 0x115BA70, 10000), fh)

    # Also AddItem native (sub_141152A00) for symmetry — same functor pattern
    section("T2b — sub_141152A00 (ObjectReference.AddItem Papyrus native)", fh)
    log(decomp(img + 0x1152A00, 10000), fh)

    # The functor pattern in both: the task enqueued is identified by its
    # vtable. RemoveItemFunctor::vftable symbol lookup:
    section("T2c — RemoveItemFunctor / AddItemFunctor vftable symbols", fh)
    for ea, name in idautils.Names():
        low = name.lower()
        if ("removeitemfunctor" in low or "additemfunctor" in low) and "vftable" in low:
            log(f"  {name} @ 0x{ea:X} (RVA 0x{ea - img:X})", fh)
            # Dump the first 5 vtable slots (ctor, dtor, op(), ...)
            for k in range(6):
                slot = ea + k * 8
                t = read_q(slot)
                nm = get_name(t)
                log(f"    slot[{k}] -> 0x{t:X} (RVA 0x{t-img:X})  {nm}", fh)

    # ============ T3: find functions that READ REFR+0xF8 (inv list access) ============
    # We already have the list of writers from angr. Now find functions that
    # READ from [reg+0xF8]. These are inventory consumers — likely include
    # the transfer path.
    section("T3 — instructions reading [reg+0xF8] (sample, inventory consumers)", fh)
    hits = 0
    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        if not (idc.get_segm_attr(seg_start, idc.SEGATTR_PERM) & 4):  # not exec
            continue
        ea = seg_start
        while ea < seg_end and ea != idc.BADADDR:
            mnem = idc.print_insn_mnem(ea)
            if mnem == "mov":
                op0 = idc.print_operand(ea, 0)
                op1 = idc.print_operand(ea, 1)
                # rhs is [reg+0xf8] — that's a read
                if "+0F8h" in op1 and op1.startswith("["):
                    # rhs is the mem read. lhs is dest register.
                    fn = ida_funcs.get_func(ea)
                    if fn:
                        n = get_name(fn.start_ea)
                        if hits < 30:
                            log(f"  0x{ea:X} in {n} (RVA 0x{fn.start_ea-img:X}): {mnem} {op0}, {op1}", fh)
                        hits += 1
            ea = idc.next_head(ea, seg_end)
    log(f"  total reads of [reg+0xF8]: {hits}", fh)

    # ============ T4: ContainerMenu vtable + related class names ============
    section("T4 — ContainerMenu / ContainerManager / MenuManager vtables", fh)
    relevant = []
    for ea, name in idautils.Names():
        low = name.lower()
        if "vftable" in low and any(k in low for k in (
            "containermenu", "menumanager", "menucontrols",
            "transfer", "inventorymenu",
        )):
            relevant.append((ea, name))
    for ea, name in relevant:
        log(f"\n  {name} @ 0x{ea:X} (RVA 0x{ea-img:X})", fh)
        for k in range(12):
            slot = ea + k * 8
            t = read_q(slot)
            nm = get_name(t)
            log(f"    slot[{k:2}] -> 0x{t:X} (RVA 0x{t-img:X})  {nm}", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
