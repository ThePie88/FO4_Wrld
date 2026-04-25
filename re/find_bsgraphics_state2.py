"""find_bsgraphics_state2.py — v2 with fixes."""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua, ida_search, ida_xref
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report2.txt"

def ib(): return ida_nalt.get_imagebase()
def rva(ea): return ea - ib()

def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()

def decomp_fn(fea, fh, label, maxc=9000):
    fn = ida_funcs.get_func(fea)
    if not fn:
        log(f"  [{label}] no func", fh); return None
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if not cf: log(f"  [{label}] decomp=None", fh); return None
        txt = str(cf)
        log(f"\n--- {label} @ RVA 0x{rva(fn.start_ea):X} (size 0x{fn.end_ea-fn.start_ea:X}) ---", fh)
        if len(txt) > maxc:
            log(txt[:maxc] + f"\n...[truncated, {len(txt)} total]", fh)
        else:
            log(txt, fh)
        return txt
    except Exception as e:
        log(f"  [{label}] {e}", fh); return None

def find_string_xrefs(s, fh):
    """Find all code xrefs to string s. Returns list of (caller_fn_ea, site_ea)."""
    hits = []
    # Brute: iterate all string items in .rdata/.data
    for seg_name in ('.rdata', '.data'):
        seg = ida_segment.get_segm_by_name(seg_name)
        if not seg: continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            # Get string at ea
            s_len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
            if s_len >= len(s) + 1:
                got = ida_bytes.get_strlit_contents(ea, s_len, ida_nalt.STRTYPE_C)
                if got and got.decode('ascii', 'ignore') == s:
                    log(f"  string '{s}' @ 0x{ea:X} (RVA 0x{rva(ea):X})", fh)
                    for x in idautils.XrefsTo(ea, 0):
                        fn = ida_funcs.get_func(x.frm)
                        hits.append((fn.start_ea if fn else None, x.frm))
                    break
            ea += 1
            if ea % 0x100000 == 0:
                pass
    return hits

def pattern_viewproj_writer(fh):
    """Scan ALL functions for any that emit movaps-style writes to [reg+0xD0],
    [reg+0xE0], [reg+0xF0], [reg+0x100] *using the same base register*.
    Returns list of fn EAs."""
    TEXT = ida_segment.get_segm_by_name('.text')
    if not TEXT: return []
    # We scan in 2 passes: first cheap pre-filter (all 4 disps present anywhere
    # in fn), then precise check (same base).
    candidates = []
    scanned = 0
    for fnea in idautils.Functions(TEXT.start_ea, TEXT.end_ea):
        fn = ida_funcs.get_func(fnea)
        if not fn: continue
        sz = fn.end_ea - fn.start_ea
        if sz < 0x40 or sz > 0x600: continue
        scanned += 1
        disp_by_base = {}  # base reg -> set(disps)
        ea = fn.start_ea
        while ea < fn.end_ea:
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, ea):
                ea += 1; continue
            m = ins.get_canon_mnem()
            if m in ('movaps', 'movups', 'movdqa', 'movdqu'):
                # look for memory op with [base+disp]
                for op in ins.ops:
                    if op.type == 0: continue
                    if op.type == ida_ua.o_displ:
                        d = op.addr
                        base = op.reg
                        disp_by_base.setdefault(base, set()).add(d)
            ea += ins.size
        for base, ds in disp_by_base.items():
            if {0xD0, 0xE0, 0xF0, 0x100}.issubset(ds):
                candidates.append((fnea, base, sorted(ds)))
                break
        if len(candidates) > 80: break
    log(f"  scanned {scanned} fns, found {len(candidates)} candidates", fh)
    return candidates

def main():
    with open(OUT, 'w', encoding='utf8') as fh:
        log(f"image base 0x{ib():X}", fh)

        # PART A: find D3D11CreateDeviceAndSwapChain via string *scan* then xrefs
        log("\n== A: D3D11 anchor ==", fh)
        for target in ("D3D11CreateDeviceAndSwapChain", "CreateDXGIFactory", "D3D11CreateDevice"):
            log(f"\n-- string '{target}' --", fh)
            hits = find_string_xrefs(target, fh)
            seen_fn = set()
            for (fn_ea, site) in hits:
                if fn_ea and fn_ea not in seen_fn:
                    seen_fn.add(fn_ea)
                    log(f"    caller fn @ RVA 0x{rva(fn_ea):X} (site 0x{rva(site):X})", fh)
            # Decompile first 3 unique callers
            for fn_ea in list(seen_fn)[:3]:
                decomp_fn(fn_ea, fh, f"{target}-caller", maxc=6000)

        # PART B: viewProjMat writer pattern scan (fixed)
        log("\n== B: viewProjMat writer pattern scan ==", fh)
        cands = pattern_viewproj_writer(fh)
        for (fnea, base, ds) in cands[:15]:
            log(f"  fn RVA 0x{rva(fnea):X} base_reg={base} disps={[hex(d) for d in ds]}", fh)
        # Decompile top 5
        for (fnea, base, ds) in cands[:5]:
            decomp_fn(fnea, fh, f"vproj-writer-cand", maxc=4500)

        # PART C: look for a function that takes a NiCamera-like ptr and writes +0xD0 to a global pointer.
        # The Renderer singleton likely stores ViewData; cameraState offset 0x160, viewProjMat +0xD0 → +0x230.
        log("\n== C: pattern for state+0x230 writes (viewProj in cameraState) ==", fh)
        cands2 = []
        TEXT = ida_segment.get_segm_by_name('.text')
        for fnea in idautils.Functions(TEXT.start_ea, TEXT.end_ea):
            fn = ida_funcs.get_func(fnea)
            if not fn: continue
            sz = fn.end_ea - fn.start_ea
            if sz < 0x40 or sz > 0x600: continue
            disp_by_base = {}
            ea = fn.start_ea
            while ea < fn.end_ea:
                ins = ida_ua.insn_t()
                if not ida_ua.decode_insn(ins, ea):
                    ea += 1; continue
                m = ins.get_canon_mnem()
                if m in ('movaps','movups','movdqa','movdqu'):
                    for op in ins.ops:
                        if op.type == ida_ua.o_displ:
                            disp_by_base.setdefault(op.reg, set()).add(op.addr)
                ea += ins.size
            for base, ds in disp_by_base.items():
                if {0x230, 0x240, 0x250, 0x260}.issubset(ds):
                    cands2.append(fnea); break
            if len(cands2) > 30: break
        log(f"  cameraState-in-State candidates: {len(cands2)}", fh)
        for fnea in cands2[:5]:
            decomp_fn(fnea, fh, "cam-state-writer", maxc=3500)

        log("\n== DONE ==", fh)

main()
