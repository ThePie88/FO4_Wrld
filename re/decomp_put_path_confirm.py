"""Confirm sub_14031C310 is the "PUT from player to container" entry point.

Plan (driven by task spec):
  1. Decompile sub_14031C310 full body (RVA 0x31C310).
  2. List all xrefs TO sub_14031C310 (callers): name, RVA, plus decompile of
     each caller (first 3000 chars) so we can see the call-site context.
  3. Decompile sub_1405007B0 (AddObject inner worker) full body — to verify
     the semantics when it is called from sub_14031C310.
  4. Highlight any caller inside ContainerMenu / inventory-transfer dispatch.
  5. List xrefs FROM sub_14031C310 (first-level callees) with names/RVAs.
  6. Scan REFR vtable at RVA 0x2564838 slots 0x70..0x85: find any slot whose
     target function calls sub_14031C310 or sub_1405007B0 directly.

Output: C:\\Users\\filip\\Desktop\\FalloutWorld\\re\\put_path_confirm_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\put_path_confirm_report.txt"

IMG = None  # set in main()
PUT_CANDIDATE_RVA = 0x31C310
ADDOBJECT_RVA     = 0x5007B0
REFR_VTABLE_RVA   = 0x2564838
VT_SLOT_LO        = 0x70
VT_SLOT_HI        = 0x85


def log(msg, fh):
    print(msg)
    try:
        fh.write(msg + "\n")
        fh.flush()
    except Exception:
        pass


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=40000):
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


def list_xrefs_to(ea, fh, limit=60):
    log(f"  Xrefs TO 0x{ea:X} (RVA 0x{ea-IMG:X}):", fh)
    out = []
    count = 0
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fn_start = fn.start_ea if fn else 0
        fn_name = get_name(fn_start) if fn else "<no func>"
        fn_rva = (fn_start - IMG) if fn else 0
        log(f"    from 0x{xref.frm:X}  in {fn_name} (RVA 0x{fn_rva:X})  type={xref.type}", fh)
        out.append((xref.frm, fn_start, fn_name, fn_rva))
        count += 1
        if count >= limit:
            log(f"    ... (truncated at {limit})", fh)
            break
    if count == 0:
        log("    <none>", fh)
    return out


def list_callees(ea, fh, limit=80):
    """First-level callees: names + RVAs."""
    log(f"  Callees FROM 0x{ea:X} (first-level, unique):", fh)
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log("    <no func>", fh); return []
    seen = set()
    out = []
    count = 0
    for head in idautils.FuncItems(fn.start_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            tgt = xref.to
            if tgt in seen:
                continue
            seen.add(tgt)
            tfn = ida_funcs.get_func(tgt)
            tstart = tfn.start_ea if tfn else tgt
            tname = get_name(tstart)
            trva = (tgt - IMG)
            log(f"    call 0x{tgt:X}  RVA 0x{trva:X}  {tname}", fh)
            out.append((tgt, tname, trva))
            count += 1
            if count >= limit:
                log(f"    ... (truncated at {limit})", fh)
                return out
    return out


def func_calls_any_of(fn_ea, target_eas):
    """Return set of target_eas that are called from the function at fn_ea."""
    hits = set()
    fn = ida_funcs.get_func(fn_ea)
    if fn is None:
        return hits
    targets = set(target_eas)
    for head in idautils.FuncItems(fn.start_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            tgt = xref.to
            tfn = ida_funcs.get_func(tgt)
            tstart = tfn.start_ea if tfn else tgt
            if tgt in targets:
                hits.add(tgt)
            if tstart in targets:
                hits.add(tstart)
    return hits


def main():
    global IMG
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    IMG = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{IMG:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh)
        fh.close()
        ida_pro.qexit(2)

    put_ea  = IMG + PUT_CANDIDATE_RVA
    add_ea  = IMG + ADDOBJECT_RVA
    vt_base = IMG + REFR_VTABLE_RVA

    # ---------- STEP 1: decomp sub_14031C310 full body ----------
    log("\n" + "=" * 78, fh)
    log(f"== STEP 1: sub_14031C310 (PUT candidate) EA=0x{put_ea:X} RVA=0x{PUT_CANDIDATE_RVA:X}", fh)
    log("=" * 78, fh)
    log(f"  name in IDB: {get_name(put_ea)}", fh)
    log("", fh)
    log(decomp(put_ea, 60000), fh)

    # ---------- STEP 2: xrefs TO sub_14031C310 + decompile each caller ----------
    log("\n" + "=" * 78, fh)
    log(f"== STEP 2: xrefs TO sub_14031C310 + caller decompile (first 3000 chars)", fh)
    log("=" * 78, fh)
    callers = list_xrefs_to(put_ea, fh, limit=60)

    # unique caller functions
    unique_callers = {}
    for frm, fn_start, fn_name, fn_rva in callers:
        if fn_start and fn_start not in unique_callers:
            unique_callers[fn_start] = (fn_name, fn_rva)

    log(f"\n  Unique caller functions: {len(unique_callers)}", fh)
    for fn_start, (fn_name, fn_rva) in unique_callers.items():
        log("\n" + "-" * 76, fh)
        log(f"  CALLER: {fn_name}  EA=0x{fn_start:X} RVA=0x{fn_rva:X}", fh)
        log("-" * 76, fh)
        log(decomp(fn_start, 3000), fh)

    # ---------- STEP 3: decomp sub_1405007B0 full body ----------
    log("\n" + "=" * 78, fh)
    log(f"== STEP 3: sub_1405007B0 (AddObject inner) EA=0x{add_ea:X} RVA=0x{ADDOBJECT_RVA:X}", fh)
    log("=" * 78, fh)
    log(f"  name in IDB: {get_name(add_ea)}", fh)
    log("", fh)
    log(decomp(add_ea, 40000), fh)

    # ---------- STEP 4: highlight ContainerMenu / dispatcher callers ----------
    log("\n" + "=" * 78, fh)
    log("== STEP 4: look for ContainerMenu / transfer-dispatcher callers", fh)
    log("=" * 78, fh)
    keywords = ("Container", "Menu", "Inventory", "Transfer", "Put",
                "OnAccept", "OnSelect", "Move", "Dispatch")
    matched = []
    for fn_start, (fn_name, fn_rva) in unique_callers.items():
        for kw in keywords:
            if kw.lower() in fn_name.lower():
                matched.append((fn_start, fn_name, fn_rva, kw))
                break
    if matched:
        for fn_start, fn_name, fn_rva, kw in matched:
            log(f"  HIT (kw={kw!r}) {fn_name} EA=0x{fn_start:X} RVA=0x{fn_rva:X}", fh)
    else:
        log("  No callers with Container/Menu/Inventory/Transfer/etc. names found.", fh)
        log("  (Expected when callers are sub_* only; inspect the decompiles in step 2.)", fh)

    # ---------- STEP 5: xrefs FROM sub_14031C310 ----------
    log("\n" + "=" * 78, fh)
    log("== STEP 5: xrefs FROM sub_14031C310 (first-level callees)", fh)
    log("=" * 78, fh)
    list_callees(put_ea, fh, limit=120)

    # ---------- STEP 6: scan REFR vtable slots 0x70..0x85 ----------
    log("\n" + "=" * 78, fh)
    log(f"== STEP 6: REFR vtable @ RVA 0x{REFR_VTABLE_RVA:X} slots 0x{VT_SLOT_LO:X}..0x{VT_SLOT_HI:X}", fh)
    log(f"    looking for any slot calling sub_14031C310 or sub_1405007B0 (direct)", fh)
    log("=" * 78, fh)
    target_set = {put_ea, add_ea}
    # Resolve actual function-start EAs for put/add
    put_fn = ida_funcs.get_func(put_ea)
    add_fn = ida_funcs.get_func(add_ea)
    if put_fn: target_set.add(put_fn.start_ea)
    if add_fn: target_set.add(add_fn.start_ea)

    interesting_slots = []
    for slot_idx in range(VT_SLOT_LO, VT_SLOT_HI + 1):
        slot_ea = vt_base + slot_idx * 8
        target = ida_bytes.get_qword(slot_ea)
        tfn = ida_funcs.get_func(target)
        tstart = tfn.start_ea if tfn else target
        tname = get_name(tstart)
        trva = target - IMG
        hits = func_calls_any_of(target, target_set)
        note = ""
        if put_ea in hits or (put_fn and put_fn.start_ea in hits):
            note += " [calls PUT_CANDIDATE]"
        if add_ea in hits or (add_fn and add_fn.start_ea in hits):
            note += " [calls ADDOBJECT_INNER]"
        log(f"  slot[0x{slot_idx:02X}] @ 0x{slot_ea:X} -> 0x{target:X} (RVA 0x{trva:X}) {tname}{note}", fh)
        if note:
            interesting_slots.append((slot_idx, target, tname, note))

    if interesting_slots:
        log("\n  === SLOTS WORTH DECOMPILING ===", fh)
        for slot_idx, target, tname, note in interesting_slots:
            log("\n" + "-" * 76, fh)
            log(f"  slot[0x{slot_idx:02X}] -> {tname} @ 0x{target:X} RVA 0x{target-IMG:X}{note}", fh)
            log("-" * 76, fh)
            log(decomp(target, 8000), fh)
    else:
        log("\n  No vtable slot in 0x70..0x85 directly calls PUT_CANDIDATE or ADDOBJECT_INNER.", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
