"""Find who ENQUEUES event 133 (the one that fires sub_140CA7D20 in the main-thread pump).

Strategy:
 1. sub_140C44FE0 is the dispatcher that builds 128-byte messages and
    enqueues them to qword_1432F46F8. Search for all callers that push
    event id 133 (= 0x85). scan .text for 'mov edx/imm 0x85' or
    'push 85h' near call sub_140C44FE0 or similar.
 2. Alternative: walk xrefs to sub_140C44FE0 and for each caller
    disassemble & look for immediate 133 / 0x85 loaded into rdx/r8.
 3. Also: scan IDB globally for any instruction that moves the
    literal value 0x85 into a register within 50 bytes of a `call
    sub_140C44FE0`.

Additionally:
 - confirm whether sub_140CA7D20 ever calls vt[0x7A] (feedback-loop test):
   check callgraph BFS from sub_140CA7D20 for any reference to
   sub_140C7A500 either direct or via a vtable indirection pattern.
 - Inspect the Activate virtual on REFR — check slots that *could* be
   virtual-dispatched from inside CA7D20 (line `(*(*a1 + 912LL))`).

Output: re/world_pickup_report4.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report4.txt"

TARGET_CA7D20 = 0xCA7D20
DISPATCHER_RVA = 0xC44FE0
T_VT7A = 0xC7A500
REFR_VTABLE_RVA = 0x2564838


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=4000):
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


def scan_event_133_producers(img, fh):
    """Scan each caller of the dispatcher. For each call-site, look back
    ~20 insns for `mov edx, 85h` OR `mov edx, 0x85` or `mov dword ptr,
    133`. Print matching callers."""
    section("Scan callers of sub_140C44FE0 that push event-id 133 (0x85)", fh)
    disp_ea = img + DISPATCHER_RVA
    callers = list_xrefs_to(disp_ea)
    log(f"Total callers of dispatcher: {len(callers)}", fh)
    hits = []
    for (cea, cname, from_ea) in callers:
        if cea is None:
            continue
        # Walk back up to 40 insns from from_ea and check for:
        #  mov edx, 0x85     OR
        #  mov r8d, 0x85     OR
        #  mov ecx, 0x85     OR
        #  push 85h
        cur = from_ea
        found = False
        found_ea = None
        for _ in range(40):
            prev = idc.prev_head(cur)
            if prev == idc.BADADDR or prev < cea:
                break
            cur = prev
            # Check operands
            mnem = idc.print_insn_mnem(cur).lower()
            if mnem in ("mov", "push", "lea"):
                op_text = idc.generate_disasm_line(cur, 0).lower()
                if "85h" in op_text or "133" in op_text:
                    # double-check by reading immediate
                    for op_i in range(3):
                        op_type = idc.get_operand_type(cur, op_i)
                        if op_type == idc.o_imm:
                            v = idc.get_operand_value(cur, op_i)
                            if v == 0x85:
                                found = True
                                found_ea = cur
                                break
                    if found:
                        break
        if found:
            hits.append((cea, cname, from_ea, found_ea))
    log(f"Found {len(hits)} call-site(s) enqueuing event 133 (0x85):", fh)
    for cea, cname, from_ea, found_ea in hits:
        crva = cea - img
        log(f"\n-- {cname} (RVA=0x{crva:X})  call_site=0x{from_ea:X}  imm_at=0x{found_ea:X}", fh)
        # Print 10 lines of context around found_ea
        cur = found_ea
        for _ in range(3):
            p = idc.prev_head(cur)
            if p == idc.BADADDR:
                break
            cur = p
        for _ in range(12):
            disp = idc.generate_disasm_line(cur, 0)
            log(f"    0x{cur:X}  {disp}", fh)
            nxt = idc.next_head(cur)
            if nxt == idc.BADADDR:
                break
            cur = nxt
        log("--- decomp of caller (first 3500 chars) ---", fh)
        log(decomp(cea, 3500), fh)


def bfs_reaches_vt7a(img, start_rva, depth_limit=8, node_limit=8000, fh=None):
    """Forward call-graph BFS from start. Return True if any node calls
    sub_140C7A500, else False. Skip funcs > 0x3000 bytes."""
    section(f"BFS from sub_{start_rva+img:X} depth={depth_limit} — does it reach vt[0x7A] sub_140C7A500?", fh)
    target = img + T_VT7A
    visited = set()
    frontier = {img + start_rva}
    found = False
    hits = []
    for level in range(depth_limit):
        next_frontier = set()
        for fea in frontier:
            if fea in visited:
                continue
            visited.add(fea)
            if len(visited) > node_limit:
                log(f"  [node limit {node_limit} reached]", fh)
                return found, hits
            fn = ida_funcs.get_func(fea)
            if fn is None:
                continue
            if (fn.end_ea - fn.start_ea) > 0x3000:
                continue
            # Walk each instruction of this function
            cur = fn.start_ea
            while cur < fn.end_ea:
                mnem = idc.print_insn_mnem(cur).lower()
                if mnem in ("call", "jmp"):
                    # get call target
                    op_type = idc.get_operand_type(cur, 0)
                    if op_type == idc.o_near or op_type == idc.o_far:
                        tgt = idc.get_operand_value(cur, 0)
                        if tgt == target:
                            found = True
                            hits.append((fea, cur))
                            log(f"  HIT -- sub_{fea:X} calls sub_140C7A500 at 0x{cur:X}", fh)
                        else:
                            next_frontier.add(tgt)
                cur = idc.next_head(cur)
                if cur == idc.BADADDR:
                    break
        frontier = next_frontier - visited
        if not frontier:
            break
    if not found:
        log(f"  BFS clean after visiting {len(visited)} funcs -- no direct reach to sub_140C7A500", fh)
    else:
        log(f"  TOTAL hits: {len(hits)}", fh)
    return found, hits


def dump_vtable_slot(img, fh, slot_index):
    ea = img + REFR_VTABLE_RVA + slot_index * 8
    tgt = ida_bytes.get_qword(ea)
    log(f"  vt[0x{slot_index:X}] @ 0x{ea:X} -> {get_name(tgt)}  RVA=0x{tgt - img:X}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Find who enqueues event 133
    scan_event_133_producers(img, fh)

    # BFS: does sub_140CA7D20 reach sub_140C7A500 via non-virtual calls?
    bfs_reaches_vt7a(img, TARGET_CA7D20, depth_limit=6, node_limit=6000, fh=fh)

    # Decode the virtual call inside CA7D20: *(*a1 + 912LL) = vt[912/8 = 114 = 0x72]
    # and *(*a1 + 872LL) = vt[872/8 = 109 = 0x6D]
    section("Which REFR vtable slots does CA7D20 call virtually?", fh)
    # 912/8 = 114 = 0x72
    # 872/8 = 109 = 0x6D  (RemoveItem!)
    log(f"  *(this->vt + 912) = slot 0x72 (114)", fh)
    dump_vtable_slot(img, fh, 0x72)
    log(f"  *(this->vt + 872) = slot 0x6D (109)", fh)
    dump_vtable_slot(img, fh, 0x6D)
    log(f"  Reminder: vt[0x7A] @ vtable+0x3D0 = sub_140C7A500 AddObjectToContainer", fh)

    # Also, what's 872 and 912?
    # 872 = 0x368 -> slot 0x6D
    # 912 = 0x390 -> slot 0x72
    log(f"\n[context] CA7D20 uses *(this->vt + 872LL)(this, &tmp, &evt_flags) — slot 0x6D", fh)
    log(f"[context] CA7D20 uses *(this->vt + 912LL)(this, item, flags) — slot 0x72", fh)
    log(f"[context] CA7D20 calls sub_140502940 (AddObject workhorse) DIRECTLY, NOT vt[0x7A]", fh)

    # XREFS to sub_140CA7D20 in data segment (check if in a vtable)
    section("All xrefs to sub_140CA7D20 in .rdata (is it in a vtable slot?)", fh)
    for x in idautils.XrefsTo(img + TARGET_CA7D20, 0):
        seg = idc.get_segm_name(x.frm)
        if seg.lower().startswith(".rdata") or seg.lower().startswith(".data"):
            log(f"  type={x.type}  from=0x{x.frm:X}  seg={seg}", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
