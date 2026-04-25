"""sub_140A56360 is just a thunk: return sub_140A53270(a1+1048, a2, a3, a4, ...).
So the REAL inventory worker is sub_140A53270. Dump it.

Also:
  - Call graph check: does sub_140A53270 (transitively) reach vt[0x7A] target
    sub_140C7A500?
  - Which top-level functions (any RVA) call sub_140A53270?
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\transfer_worker_report.txt"

REFR_VT_RVA = 0x2564838


def log(m, fh): print(m); fh.write(m+"\n"); fh.flush()
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
            if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF): continue
            if x.to in seen: continue
            seen.add(x.to)
            log(f"    call-> 0x{x.to:X} RVA=0x{x.to-img:X}  {get_name(x.to)}", fh)


def list_xrefs_to(ea, fh, img, limit=30):
    log(f"  xrefs TO 0x{ea:X} ({get_name(ea)}):", fh)
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


def reach_vtslot_7a_from(start_ea, fh, img, max_nodes=3000, max_depth=7):
    """BFS: does 'start_ea' reach the vt[0x7A] slot address (indirect call via
    slot address) or the vt[0x7A] target function itself?"""
    vt7a_slot_addr = img + REFR_VT_RVA + 0x7A * 8
    vt7a_target_ea = ida_bytes.get_qword(vt7a_slot_addr)
    log(f"  vt[0x7A] slot addr = 0x{vt7a_slot_addr:X}; target fn = 0x{vt7a_target_ea:X}", fh)

    # BFS over call edges
    visited = set()
    to_visit = [(start_ea, 0)]
    hits_fn = []
    hits_slot = []
    nodes = 0
    while to_visit:
        ea, depth = to_visit.pop(0)
        if ea in visited or depth > max_depth: continue
        visited.add(ea)
        nodes += 1
        if nodes > max_nodes:
            log("  <BFS node cap reached>", fh); break
        fn = ida_funcs.get_func(ea)
        if fn is None: continue
        for head in idautils.FuncItems(fn.start_ea):
            for x in idautils.XrefsFrom(head, 0):
                # direct calls
                if x.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    if x.to == vt7a_target_ea:
                        hits_fn.append((fn.start_ea, head, depth))
                    if x.to not in visited:
                        tf = ida_funcs.get_func(x.to)
                        if tf and (tf.end_ea - tf.start_ea) < 0x2000:
                            to_visit.append((x.to, depth + 1))
                # data refs — detect mov rax,[REFR_vt+0xX] style dereferences
                # that load from the slot address
                if x.type == ida_xref.dr_R or x.type == ida_xref.dr_O:
                    if x.to == vt7a_slot_addr:
                        hits_slot.append((fn.start_ea, head, depth))

    log(f"  traversed {nodes} funcs; depth cap {max_depth}", fh)
    if hits_fn:
        for fnstart, site, depth in hits_fn:
            log(f"  DIRECT-CALL HIT to vt7a-target in {get_name(fnstart)} @ site 0x{site:X} (depth {depth})", fh)
    else:
        log("  <no DIRECT call to vt[0x7A] target>", fh)
    if hits_slot:
        for fnstart, site, depth in hits_slot:
            log(f"  SLOT-ADDR ref in {get_name(fnstart)} @ site 0x{site:X} (depth {depth})", fh)
    else:
        log("  <no direct reference to vt[0x7A] slot addr>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] hexrays missing", fh); fh.close(); ida_pro.qexit(2)

    # ---- The real worker: sub_140A53270
    section("sub_140A53270  (real inventory-transfer worker — thunked by sub_140A56360)", fh)
    ea_w = img + 0xA53270
    list_xrefs_to(ea_w, fh, img)
    log("-- callees --", fh); list_callees(ea_w, fh, img)
    log("-- Hex-Rays --", fh)
    log(decomp(ea_w, 60000), fh)

    # ---- xrefs to the ContainerMenu::TransferItem entry itself
    section("xrefs TO sub_14103E950 (ContainerMenu::TransferItem)", fh)
    list_xrefs_to(img + 0x103E950, fh, img)

    # ---- call-graph: does TransferItem / worker reach vt[0x7A]?
    section("Call-graph reach: ContainerMenu::TransferItem -> vt[0x7A]?", fh)
    reach_vtslot_7a_from(img + 0x103E950, fh, img)

    section("Call-graph reach: sub_140A53270 worker -> vt[0x7A]?", fh)
    reach_vtslot_7a_from(img + 0xA53270, fh, img)

    # ---- also look up 'ContainerMenu' RTTI names for the actual class vtable
    # (we already dumped the ??_7ContainerMenu@@6B@ contents earlier)

    log("\n==== done ====", fh); fh.close(); ida_pro.qexit(0)


main()
