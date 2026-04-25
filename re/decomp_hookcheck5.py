"""
Final final. Focus: the CONSUMER is the better hook because:
- sub_14221E6A0 is GUARANTEED per-frame (per-BSLightingShader dispatch)
- It reads the matrix FROM the accumulator so the matrix exists when hook fires
- Its prologue has clean 5 bytes: 488bc44889 (mov rax,rsp; mov ...) - hookable

BUT vtable dispatch means the static call-count shows 0. This explains
why the prev hook MIGHT have worked on CONSUMER. The USER's problem is they
hooked PRODUCER which IS called (tail-called via jmp) but gated by the
dynamic condition on a2+0x200 (vt+512 == getVisibility?).

Verify: in sub_1421DC480, the very first check `(*(a2+512LL))(a2)` returns 0,
killing execution before matrix write. Let's decompile what it returns.

Alternative per-frame hook: sub_1421BE240 (matmul). Called only 2x within
PRODUCER, so equally gated.

Plan: recommend sub_14221E6A0 CONSUMER with caveat about vtable dispatch.
"""
import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_hexrays
BASE = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\hookcheck_report5.txt"

def dump(m, f=None):
    print(m)
    if f: f.write(m+"\n")

def decomp(ea, maxlen=5000):
    ida_hexrays.init_hexrays_plugin()
    cf = ida_hexrays.decompile(ea)
    return (str(cf)[:maxlen]) if cf else "<decompile failed>"

with open(OUT, "w") as f:
    dump("="*80, f)
    dump(" HOOK CHECK 5 - pick winner", f)
    dump("="*80, f)

    # ==== Understanding why the PRODUCER hook may not fire ====
    # The very first check is vtable slot 64 (offset 512 / 8 = 64):
    # (*(_QWORD *)a2 + 512LL) -> that's slot [64]
    # That's on the ACCUMULATOR's vtable (0x14290A6B0 or derivative).
    # Look up that slot.
    dump("\n### BSShaderAccumulator vtable 0x14290A6B0 slot [64] ###", f)
    VT = 0x14290A6B0
    for idx in [0, 32, 40, 48, 56, 60, 62, 63, 64, 65, 66, 70]:
        slot_addr = VT + idx*8
        v = ida_bytes.get_qword(slot_addr)
        nm = idc.get_func_name(v) or f"sub_{v:X}"
        dump(f"  [{idx:3}] 0x{slot_addr:X} -> 0x{v:X} ({nm})", f)

    # decomp slot [64]
    slot_val = ida_bytes.get_qword(VT + 64*8)
    dump(f"\n  slot[64] = 0x{slot_val:X} - decomp:", f)
    dump(decomp(slot_val, 3000), f)

    # ==== Find the BSShaderAccumulator-derived vtable that is the OPAQUE pass one ====
    dump("\n\n### BSShaderAccumulator DERIVATIVES: search for other vtables linking to similar slots ###", f)
    # Simpler test: locate the function sub_1421DC480's unique neighbors that reference it via vtable
    for r in idautils.DataRefsTo(0x1421DC480):
        seg = idaapi.getseg(r)
        seg_name = idc.get_segm_name(r) if seg else "?"
        dump(f"  dataref 0x{r:X} ({seg_name})", f)

    # Are there vtables where sub_1421DC480 appears? Scan .rdata for 8-byte aligned pointers
    dump("\n  scan .rdata for qword == 0x1421DC480:", f)
    seg = idaapi.get_segm_by_name(".rdata")
    if seg:
        target = 0x1421DC480
        ea = seg.start_ea
        count = 0
        while ea < seg.end_ea and count < 20:
            v = ida_bytes.get_qword(ea)
            if v == target:
                dump(f"    hit @ 0x{ea:X}  RVA 0x{ea-BASE:X}", f)
                count += 1
            ea += 8
        dump(f"  total = {count}", f)

    # ==== Study sub_1421DC190's vtable slot [8] usage (a1+64) ====
    # v5 = (a1->vt[64/8=8])(a1)  — returns the BSShaderAccumulator or nullptr
    # If NULL, it recurses into (a1+32+296) children.
    # That means sub_1421DC190 is an n-ary tree walker! Deep recursion.
    # First visit (from sub_1421DBAF0) always a1 != null
    # but vt[8](a1) may be null, then it recurses on children's accumulators.

    # So every frame sub_1421DC480 IS called once per accumulator in the tree.
    # A normal scene has multiple (opaque, shadow, effects) accumulators.

    # ==== LETS test a simple "canary": how many functions write directly to memory +380/+17C ====
    # The report claimed sub_1421DC480 is the only writer.
    # Quick scan for 'movups xmmword ptr [r?+17Ch]' or '[r?+180h]'
    dump("\n\n### Scan for OTHER writers of +0x17C matrix (sanity) ###", f)
    from ida_search import find_binary, SEARCH_DOWN
    import ida_search
    seg = idaapi.get_segm_by_name(".text")
    # pattern for movups xmmword [rdx+17Ch]: 0F 29 82 7C 01 00 00
    # or 0F 11 82 7C 01 00 00 (movups)
    found = 0
    for pat in ["0F 29 82 7C 01 00 00", "0F 11 82 7C 01 00 00",
                "41 0F 29 82 7C 01 00 00", "41 0F 11 82 7C 01 00 00",
                "0F 29 80 7C 01 00 00", "0F 11 80 7C 01 00 00",
                "0F 29 81 7C 01 00 00", "0F 11 81 7C 01 00 00"]:
        ea = seg.start_ea
        while ea < seg.end_ea:
            e2 = find_binary(ea, seg.end_ea, pat, 16, SEARCH_DOWN)
            if e2 == idc.BADADDR or e2 >= seg.end_ea:
                break
            fn = ida_funcs.get_func(e2)
            fname = idc.get_func_name(fn.start_ea) if fn else "<nofn>"
            dump(f"  {pat} @ 0x{e2:X}  in {fname} RVA 0x{(fn.start_ea-BASE) if fn else 0:X}", f)
            found += 1
            if found > 30:
                break
            ea = e2 + 1
        if found > 30:
            break

    # ==== also find writers of +380 literal ====
    dump("\n\n### Scan for OTHER writers of +0x18C (row 1 offset) ###", f)
    # pattern for movups xmmword [r?+18Ch]: 8C 01 00 00
    # same byte-pattern search
    for pat in ["0F 29 82 8C 01 00 00", "0F 11 82 8C 01 00 00",
                "0F 29 80 8C 01 00 00", "0F 11 80 8C 01 00 00",
                "0F 29 81 8C 01 00 00", "0F 11 81 8C 01 00 00"]:
        ea = seg.start_ea
        while ea < seg.end_ea:
            e2 = find_binary(ea, seg.end_ea, pat, 16, SEARCH_DOWN)
            if e2 == idc.BADADDR or e2 >= seg.end_ea:
                break
            fn = ida_funcs.get_func(e2)
            fname = idc.get_func_name(fn.start_ea) if fn else "<nofn>"
            dump(f"  {pat} @ 0x{e2:X}  in {fname} RVA 0x{(fn.start_ea-BASE) if fn else 0:X}", f)
            ea = e2 + 1

    # ==== FINAL RECOMMENDATION: hook at D3D11 DeviceContext::VSSetConstantBuffers ====
    # Find it via import table or vtable search
    # IDXGISwapChain::Present via the swap chain created via CreateDeviceAndSwapChain
    dump("\n\n### D3D11CreateDeviceAndSwapChain callers ###", f)
    for r in idautils.CodeRefsTo(0x142439758, 0):  # from import analysis in prev run
        fn = ida_funcs.get_func(r)
        if fn:
            nm = idc.get_func_name(fn.start_ea) or ""
            dump(f"  caller: {nm} RVA 0x{fn.start_ea-BASE:X} from 0x{r:X}", f)

    # Also find imp symbol directly
    dump("\n### Check imp_D3D11CreateDeviceAndSwapChain location ###", f)
    nm_ea = idc.get_name_ea_simple("__imp_D3D11CreateDeviceAndSwapChain")
    dump(f"  name ea: 0x{nm_ea:X}", f)
    if nm_ea != idc.BADADDR:
        for r in idautils.CodeRefsTo(nm_ea, 0):
            fn = ida_funcs.get_func(r)
            if fn:
                nm = idc.get_func_name(fn.start_ea) or ""
                dump(f"    ref: {nm} RVA 0x{fn.start_ea-BASE:X}", f)

    dump("\n### Look for 'DrawIndexed' / 'Draw' strings ###", f)
    for s in idautils.Strings():
        st = str(s)
        if "Draw" in st and len(st) < 60:
            dump(f"    0x{s.ea:X}: {st}", f)

    dump("\nDONE.", f)
idc.qexit(0)
