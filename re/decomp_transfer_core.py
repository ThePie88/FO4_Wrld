"""Drill into sub_140A56360 — the actual move-item engine call inside
ContainerMenu::TransferItem. We need to know:
  - Does it call vt[0x7A] AddObjectToContainer?  (feedback-loop risk)
  - Does it call sub_1411735A0 (Papyrus real AddItem)?
  - What's its signature / side selection?
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\transfer_core_report.txt"

REFR_VTABLE_RVA = 0x2564838
VT_0x7A_RVA     = 0x2564838 + 0x7A * 8   # RVA of the slot, NOT the function


def log(m, fh):
    print(m); fh.write(m + "\n"); fh.flush()


def section(t, fh):
    log("\n" + "=" * 78, fh); log(f"== {t}", fh); log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, cap=50000):
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
            if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF): continue
            if x.to in seen: continue
            seen.add(x.to)
            log(f"    call-> 0x{x.to:X} RVA=0x{x.to-img:X}  {get_name(x.to)}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] hexrays missing", fh); fh.close(); ida_pro.qexit(2)

    # Resolve the concrete function at vt[0x7A]
    vt7a_slot = img + 0x2564838 + 0x7A * 8
    vt7a_target = ida_bytes.get_qword(vt7a_slot)
    log(f"[+] vt[0x7A] slot @ 0x{vt7a_slot:X} -> func 0x{vt7a_target:X} (RVA 0x{vt7a_target-img:X}) {get_name(vt7a_target)}", fh)

    # ---- sub_140A56360 : the workhorse inside TransferItem
    section("sub_140A56360  (movement-worker inside ContainerMenu::TransferItem)", fh)
    ea = img + 0xA56360
    log("-- callees --", fh); list_callees(ea, fh, img)
    log("-- Hex-Rays --", fh)
    log(decomp(ea, 50000), fh)

    # ---- helper fns mentioned at top of TransferItem
    for label, rva in [
        ("sub_141041210 (pre-transfer gate/check)", 0x1041210),
        ("sub_14103D3E0 (post-transfer UI update)", 0x103D3E0),
        ("sub_140513300 (qty-menu?)", 0x513300),
    ]:
        section(label, fh)
        ea = img + rva
        log("-- callees --", fh); list_callees(ea, fh, img)
        log("-- Hex-Rays --", fh)
        log(decomp(ea, 12000), fh)

    # ---- check whether sub_140A56360 (or a nested callee) calls vt[0x7A] target
    section("Does sub_140A56360 transitively reach vt[0x7A] target?", fh)
    target_fn_ea = vt7a_target
    log(f"target vt[0x7A] function EA: 0x{target_fn_ea:X}", fh)

    visited = set()
    stack = [img + 0xA56360]
    hits = []
    while stack:
        cur = stack.pop()
        if cur in visited: continue
        visited.add(cur)
        if len(visited) > 800:
            log("  (call-graph depth cap reached)", fh); break
        fn = ida_funcs.get_func(cur)
        if fn is None: continue
        for head in idautils.FuncItems(fn.start_ea):
            for x in idautils.XrefsFrom(head, 0):
                if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF): continue
                if x.to == target_fn_ea:
                    hits.append((cur, head))
                if x.to not in visited:
                    # only recurse into small-ish funcs to keep bounded
                    tf = ida_funcs.get_func(x.to)
                    if tf and (tf.end_ea - tf.start_ea) < 0x2000:
                        stack.append(x.to)
    if hits:
        for caller_fn, site in hits:
            log(f"  HIT: vt[0x7A]-target called inside {get_name(caller_fn)} @ site 0x{site:X}", fh)
    else:
        log("  <no direct or transitive call to vt[0x7A] target from sub_140A56360 within depth cap>", fh)

    log("\n==== done ====", fh); fh.close(); ida_pro.qexit(0)


main()
