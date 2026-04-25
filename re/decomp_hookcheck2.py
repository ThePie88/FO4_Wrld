"""
URGENT part 2: verify sub_14221E6A0 decompilation, find vtable call sites
that dispatch slot[8], and confirm per-frame D3D11 calls.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_xref

BASE = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\hookcheck_report2.txt"


def dump(msg, f=None):
    print(msg)
    if f:
        f.write(msg + "\n")


def decomp_to_str(ea):
    ida_hexrays.init_hexrays_plugin()
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        return "<decompile failed>"
    return str(cfunc)


def disasm_range(ea, n):
    out = []
    cur = ea
    for _ in range(n):
        d = idc.generate_disasm_line(cur, 0) or ""
        out.append(f"  0x{cur:X}: {d}")
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR:
            break
        cur = nxt
    return "\n".join(out)


with open(OUT, "w") as f:
    dump("=" * 80, f)
    dump(" HOOK CHECK 2 — verify CONSUMER + find per-frame entry", f)
    dump("=" * 80, f)

    # ==================== verify producer is really called ====================
    dump("\n\n### CALLER CHAIN sub_1421DC190 -> sub_1421DC480 ###", f)
    PROD = 0x1421DC480
    CALLER = 0x1421DC190
    dump(f"\n  sub_1421DC190 decomp (caller of PRODUCER):\n", f)
    d = decomp_to_str(CALLER)
    dump(d[:6000], f)

    # who calls sub_1421DC190?
    dump(f"\n\n  sub_1421DC190 callers:", f)
    for ref in idautils.CodeRefsTo(CALLER, 0):
        fn = ida_funcs.get_func(ref)
        if fn:
            n = idc.get_func_name(fn.start_ea) or ""
            dump(f"    {n}  RVA 0x{fn.start_ea-BASE:X}  from 0x{ref:X}", f)

    # ==================== decompile CONSUMER prologue ====================
    dump("\n\n### CONSUMER sub_14221E6A0 disasm prologue ###", f)
    CONS = 0x14221E6A0
    dump(disasm_range(CONS, 32), f)

    # CONSUMER decomp (first part)
    dump("\n\n### CONSUMER sub_14221E6A0 decomp (first 8000 chars) ###", f)
    d = decomp_to_str(CONS)
    dump(d[:8000], f)

    # ==================== find ALL indirect callers via vtable dispatch ====================
    dump("\n\n### Find code sites that INDIRECT-CALL through vtable 0x14290D158 slot[8] ###", f)
    # Look for 'call qword ptr [rax+40h]' since slot[8]*8 = 0x40
    # Scan the whole .text segment - this is big, so limit to functions that also reference 0x14290D158
    VT = 0x14290D158

    # Find all references to the vtable
    dump(f"\n  Data refs to vtable 0x{VT:X}:", f)
    refs = list(idautils.DataRefsTo(VT))
    for r in refs[:50]:
        fn = ida_funcs.get_func(r)
        nm = idc.get_func_name(fn.start_ea) if fn else "<no func>"
        dump(f"    0x{r:X}  in {nm} (RVA 0x{(fn.start_ea-BASE) if fn else 0:X})", f)

    # Now look for 'call qword [reg+40h]' across the binary where reg holds a
    # BSLightingShader-derived vtable. Instead of scanning everything, look at
    # functions that could be the render dispatch — i.e. those calling many
    # vtable slots in sequence near each other.
    # Practical heuristic: find references in MAIN render loop.
    # Search for the string pattern "call qword ptr [r?+40h]" via pattern match:

    dump("\n\n### Functions that invoke slot[8] of ANY vtable via [reg+40h]: ###", f)
    # Use findBinary to locate 'FF 50 40' (call qword ptr [rax+40h])
    # The byte FF /2 with [reg+disp8=0x40] - multiple encodings:
    # FF 50 40 = call qword ptr [rax+40]
    # FF 51 40 = call qword ptr [rcx+40]
    # FF 52 40 = call qword ptr [rdx+40]
    # FF 53 40 = call qword ptr [rbx+40]
    # ...
    # FF 57 40 = call qword ptr [rdi+40]
    # 41 FF 50 40 = call qword ptr [r8+40]
    # etc.
    from ida_search import find_binary, SEARCH_DOWN
    import ida_search
    seg = idaapi.get_segm_by_name(".text")
    if not seg:
        dump("  .text segment not found!", f)
    else:
        found_count = 0
        for pat in ["FF 50 40", "FF 51 40", "FF 52 40", "FF 53 40",
                    "FF 55 40", "FF 56 40", "FF 57 40"]:
            ea = seg.start_ea
            end = seg.end_ea
            while ea < end:
                e2 = ida_search.find_binary(ea, end, pat, 16, SEARCH_DOWN)
                if e2 == idc.BADADDR or e2 >= end:
                    break
                # check preceding byte isn't 0F or similar prefix that makes it not a call
                fn = ida_funcs.get_func(e2)
                if fn and found_count < 200:
                    # check if the function references vtable 0x14290D158
                    has_vt_ref = False
                    # Simple: scan function body for reference to VT
                    for h in idautils.FuncItems(fn.start_ea):
                        for xref in idautils.DataRefsFrom(h):
                            if xref == VT:
                                has_vt_ref = True
                                break
                        if has_vt_ref:
                            break
                    if has_vt_ref:
                        dump(f"    {pat} @ 0x{e2:X} in sub_{fn.start_ea:X} (RVA 0x{fn.start_ea-BASE:X})", f)
                        found_count += 1
                ea = e2 + 1
            if found_count > 40:
                break
        dump(f"  total candidate slot[8] call-sites in functions referencing VT: {found_count}", f)

    # ==================== find the "scene walk" caller chain ====================
    dump("\n\n### Callers-chain-up from CONSUMER via vtable ###", f)
    # Who calls sub_140C38F80? (3D scene walker)
    SW = 0x140C38F80
    for ref in idautils.CodeRefsTo(SW, 0):
        fn = ida_funcs.get_func(ref)
        if fn:
            nm = idc.get_func_name(fn.start_ea) or ""
            dump(f"  caller of scene walker (0x{SW:X}): {nm} RVA 0x{fn.start_ea-BASE:X}", f)

    SS = 0x140C38910
    dump("\n  caller chain from sub_140C38910 up:", f)
    visited = set([SS])
    stack = [SS]
    while stack:
        cur = stack.pop()
        for ref in idautils.CodeRefsTo(cur, 0):
            fn = ida_funcs.get_func(ref)
            if fn and fn.start_ea not in visited:
                visited.add(fn.start_ea)
                nm = idc.get_func_name(fn.start_ea) or f"sub_{fn.start_ea:X}"
                dump(f"    <- {nm} RVA 0x{fn.start_ea-BASE:X}", f)
                if len(visited) < 25:
                    stack.append(fn.start_ea)

    dump("\n\nDONE.", f)

idc.qexit(0)
