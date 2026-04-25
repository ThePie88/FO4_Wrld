"""find_bsgraphics_state3.py — refined

Strategy: find functions that:
  (1) load a singleton pointer from a global (.data/.bss) via `mov rax, [rip+G]`
  (2) write 4 consecutive __m128 values to [rax + 0xD0], [rax + 0xE0], [rax + 0xF0], [rax + 0x100]
      (or same pattern at +0x230..+0x260 if cameraState sits at offset 0x160 inside State)

Output: singleton global RVA and the writer function.

Also scan: function that reads a global and writes to +0x210, +0x21C (posAdjust).
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua, ida_xref
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report3.txt"
def ib(): return ida_nalt.get_imagebase()
def rva(ea): return ea - ib()
def log(msg, fh):
    print(msg); fh.write(msg+"\n"); fh.flush()

def decomp(fea, fh, label, maxc=6000):
    fn = ida_funcs.get_func(fea)
    if not fn: return None
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if not cf: return None
        txt = str(cf)
        log(f"\n--- {label} @ RVA 0x{rva(fn.start_ea):X} ---", fh)
        log(txt[:maxc] + ("\n...[truncated]" if len(txt) > maxc else ""), fh)
        return txt
    except Exception as e:
        log(f"  decomp err: {e}", fh); return None

def scan(fh, disps_target, label):
    """Find functions that:
       - have `mov reg, [rip+G]` (load global ptr)
       - then write movaps/mov to [reg+disps_target]
    Returns list of (fn_ea, global_ea, reg)."""
    TEXT = ida_segment.get_segm_by_name('.text')
    DATA = [ida_segment.get_segm_by_name(n) for n in ('.data', '.bss', '.rdata')]
    DATA = [d for d in DATA if d]
    def in_data(ea):
        for d in DATA:
            if d.start_ea <= ea < d.end_ea: return True
        return False
    hits = []
    scanned = 0
    for fnea in idautils.Functions(TEXT.start_ea, TEXT.end_ea):
        fn = ida_funcs.get_func(fnea)
        if not fn: continue
        sz = fn.end_ea - fn.start_ea
        if sz < 0x20 or sz > 0x800: continue
        scanned += 1
        # Pass 1: collect (reg, global_ea) from "mov reg, [rip+G]" where G in .data/.bss
        ea = fn.start_ea
        loads = {}  # reg -> global_ea
        writes_to_reg = {}  # reg -> set(disps)
        while ea < fn.end_ea:
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, ea):
                ea += 1; continue
            m = ins.get_canon_mnem()
            # mov reg, [mem]
            if m == 'mov' and ins.ops[0].type == ida_ua.o_reg and ins.ops[1].type == ida_ua.o_mem:
                tgt = ins.ops[1].addr
                if in_data(tgt):
                    loads.setdefault(ins.ops[0].reg, set()).add(tgt)
            # movaps/movups/mov to [reg+disp]
            if m in ('movaps','movups','movdqa','movdqu','mov'):
                for op in ins.ops:
                    if op.type == ida_ua.o_displ:
                        # write side: only if op is destination (ins.ops[0] == this op)
                        if op.n == 0:
                            writes_to_reg.setdefault(op.reg, set()).add(op.addr)
            ea += ins.size
        # Now match
        for reg, disps in writes_to_reg.items():
            if set(disps_target).issubset(disps) and reg in loads:
                for g in loads[reg]:
                    hits.append((fn.start_ea, g, reg))
                break
        if len(hits) > 40: break
    log(f"  [{label}] scanned {scanned} fns, hits={len(hits)}", fh)
    return hits

def scan_posAdjust_writers(fh):
    """Functions that write 3 floats at +0x210 and +0x21C of a global-loaded pointer."""
    TEXT = ida_segment.get_segm_by_name('.text')
    DATA = [ida_segment.get_segm_by_name(n) for n in ('.data','.bss','.rdata')]
    DATA = [d for d in DATA if d]
    def in_data(ea):
        for d in DATA:
            if d.start_ea <= ea < d.end_ea: return True
        return False
    hits = []
    for fnea in idautils.Functions(TEXT.start_ea, TEXT.end_ea):
        fn = ida_funcs.get_func(fnea)
        if not fn: continue
        if fn.end_ea - fn.start_ea > 0x800: continue
        loads = {}; writes = {}
        ea = fn.start_ea
        while ea < fn.end_ea:
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, ea):
                ea += 1; continue
            m = ins.get_canon_mnem()
            if m == 'mov' and ins.ops[0].type == ida_ua.o_reg and ins.ops[1].type == ida_ua.o_mem:
                if in_data(ins.ops[1].addr):
                    loads.setdefault(ins.ops[0].reg, set()).add(ins.ops[1].addr)
            if m in ('mov','movss','movd') and ins.ops[0].type == ida_ua.o_displ:
                writes.setdefault(ins.ops[0].reg, set()).add(ins.ops[0].addr)
            ea += ins.size
        for reg, ds in writes.items():
            # Looking for writes at +0x210, +0x214, +0x218, +0x21C, +0x220, +0x224
            req = {0x210, 0x214, 0x218, 0x21C}
            if req.issubset(ds) and reg in loads:
                for g in loads[reg]:
                    hits.append((fn.start_ea, g, reg, sorted(ds)))
                break
        if len(hits) > 40: break
    return hits

def main():
    with open(OUT, 'w', encoding='utf8') as fh:
        log(f"image base 0x{ib():X}", fh)

        # Direct ViewData case: singleton loaded then +0xD0..+0x100 written
        log("\n== A: ViewData singleton (0xD0..0x100) ==", fh)
        A = scan(fh, [0xD0, 0xE0, 0xF0, 0x100], "ViewData@+0xD0")
        # Distinct by global
        by_g = {}
        for (fea, g, r) in A:
            by_g.setdefault(g, []).append(fea)
        log(f"  unique globals: {len(by_g)}", fh)
        for g, feas in sorted(by_g.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]:
            log(f"    global 0x{rva(g):X} writers: {[hex(rva(f)) for f in feas[:6]]}", fh)

        # Try CameraStateData-in-State case: viewProj at +0x160+0xD0 = +0x230
        log("\n== B: cameraState-in-State (0x230..0x260) ==", fh)
        B = scan(fh, [0x230, 0x240, 0x250, 0x260], "VP@+0x230")
        by_g = {}
        for (fea, g, r) in B:
            by_g.setdefault(g, []).append(fea)
        log(f"  unique globals: {len(by_g)}", fh)
        for g, feas in sorted(by_g.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]:
            log(f"    global 0x{rva(g):X} writers: {[hex(rva(f)) for f in feas[:6]]}", fh)

        # Decompile top few from A
        log("\n-- decomp top A candidates --", fh)
        top_a = sorted(by_g_A.items() if False else {g: feas for g, feas in sorted({k:v for k,v in ((g,feas) for (fea,g,r) in A for feas in [[fea]])}.items())}.items(), key=lambda kv: -len(kv[1]))[:0]
        # just decompile A writers directly
        done = set()
        for (fea, g, r) in A[:12]:
            if fea in done: continue
            done.add(fea)
            decomp(fea, fh, f"A-writer g=0x{rva(g):X}")

        # posAdjust writer
        log("\n== C: posAdjust writers (+0x210..+0x21C) ==", fh)
        C = scan_posAdjust_writers(fh)
        log(f"  posAdjust writers: {len(C)}", fh)
        for (fea, g, r, ds) in C[:10]:
            log(f"    fn RVA 0x{rva(fea):X} global RVA 0x{rva(g):X} disps={[hex(d) for d in ds[:30]]}", fh)
        for (fea, g, r, ds) in C[:3]:
            decomp(fea, fh, f"C-posAdjust g=0x{rva(g):X}")

        log("\n== DONE ==", fh)

main()
