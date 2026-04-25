"""sub_14103D3E0 is the REAL do-transfer, called from ContainerMenu::TransferItem
after the weight check. Dump full Hex-Rays and call-graph reach to vt[0x7A].

Also: dump sub_14098AE30 and sub_140CA34B0 and sub_140D71AC0 — these appear in
14103D3E0's callees and are the most suspicious (Objects/Animation/Physics
engine nodes by size clusters).
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\real_transfer_report.txt"
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


def reach_vtslot_7a_from(start_ea, fh, img, max_nodes=6000, max_depth=8):
    vt7a_slot_addr = img + REFR_VT_RVA + 0x7A * 8
    vt7a_target_ea = ida_bytes.get_qword(vt7a_slot_addr)
    log(f"  vt[0x7A] slot=0x{vt7a_slot_addr:X} target=0x{vt7a_target_ea:X}", fh)
    visited = set()
    to_visit = [(start_ea, 0, "<root>")]
    hits_fn, hits_slot = [], []
    nodes = 0
    while to_visit:
        ea, depth, path = to_visit.pop(0)
        if ea in visited or depth > max_depth: continue
        visited.add(ea); nodes += 1
        if nodes > max_nodes:
            log("  <BFS node cap reached>", fh); break
        fn = ida_funcs.get_func(ea)
        if fn is None: continue
        for head in idautils.FuncItems(fn.start_ea):
            for x in idautils.XrefsFrom(head, 0):
                if x.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    if x.to == vt7a_target_ea:
                        hits_fn.append((fn.start_ea, head, depth, path))
                    if x.to not in visited:
                        tf = ida_funcs.get_func(x.to)
                        if tf and (tf.end_ea - tf.start_ea) < 0x3000:
                            to_visit.append((x.to, depth+1, f"{path}->{get_name(x.to)}"))
                if x.type in (ida_xref.dr_R, ida_xref.dr_O):
                    if x.to == vt7a_slot_addr:
                        hits_slot.append((fn.start_ea, head, depth, path))
    log(f"  traversed {nodes} funcs, depth cap {max_depth}", fh)
    for fnstart, site, depth, path in hits_fn[:20]:
        log(f"  DIRECT-HIT vt7a-target at {get_name(fnstart)} site 0x{site:X} depth {depth}", fh)
        log(f"     path: {path}", fh)
    if not hits_fn:
        log("  <no direct call to vt[0x7A] target>", fh)
    for fnstart, site, depth, path in hits_slot[:20]:
        log(f"  SLOT-ADDR-REF at {get_name(fnstart)} site 0x{site:X} depth {depth}", fh)
        log(f"     path: {path}", fh)
    if not hits_slot:
        log("  <no direct ref to vt[0x7A] slot addr>", fh)


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
    log(f"[+] image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] hexrays missing", fh); fh.close(); ida_pro.qexit(2)

    # ---- Main target: sub_14103D3E0 (called from TransferItem after weight check)
    section("sub_14103D3E0  (THE real do-transfer body, inside ContainerMenu::TransferItem)", fh)
    ea = img + 0x103D3E0
    log("-- callees --", fh); list_callees(ea, fh, img)
    log("-- Hex-Rays --", fh)
    log(decomp(ea, 60000), fh)

    # Reach-vt7a from inside D3E0
    section("Call-graph reach: sub_14103D3E0 -> vt[0x7A]?", fh)
    reach_vtslot_7a_from(ea, fh, img)

    # ---- Also: does sub_14103D3E0 transitively call sub_1411735A0 or 0x502940?
    section("Call-graph reach: sub_14103D3E0 -> sub_1411735A0 / sub_140502940 / sub_1405007B0?", fh)
    for label, tgt_rva in [("sub_1411735A0", 0x11735A0),
                           ("sub_140502940", 0x502940),
                           ("sub_1405007B0", 0x5007B0)]:
        tgt = img + tgt_rva
        # mini BFS
        visited = set(); q = [(img + 0x103D3E0, 0)]
        found = None
        while q and len(visited) < 6000:
            cur, d = q.pop(0)
            if cur in visited or d > 7: continue
            visited.add(cur)
            fn = ida_funcs.get_func(cur)
            if fn is None: continue
            for head in idautils.FuncItems(fn.start_ea):
                for x in idautils.XrefsFrom(head, 0):
                    if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF): continue
                    if x.to == tgt:
                        found = (fn.start_ea, head, d); break
                    if x.to not in visited:
                        tf = ida_funcs.get_func(x.to)
                        if tf and (tf.end_ea - tf.start_ea) < 0x3000:
                            q.append((x.to, d+1))
                if found: break
            if found: break
        if found:
            log(f"  REACH {label}: HIT in {get_name(found[0])} site 0x{found[1]:X} depth {found[2]}", fh)
        else:
            log(f"  REACH {label}: NO HIT within depth/node cap", fh)

    log("\n==== done ====", fh); fh.close(); ida_pro.qexit(0)


main()
