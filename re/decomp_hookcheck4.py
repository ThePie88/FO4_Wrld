"""
Final verification. Critical questions:
1) Does the PRODUCER's prologue start at the RVA we think?
2) Are there PDATA / exception records? (Some functions have multiple entry bytes)
3) Is sub_1421DC480 ACTUALLY reached in the actual dispatch via call?
   - Find absolute CALL E8 at 0x1421DC1C3 targeting sub_1421DC480.
4) Find the per-frame 'present' / render-present function via dxgi imports.
5) Double-check the producer prologue bytes actually match the IDA DB.
"""
import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_hexrays
BASE = 0x140000000
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\hookcheck_report4.txt"


def dump(m, f=None):
    print(m)
    if f: f.write(m+"\n")


def hexb(ea, n):
    b = ida_bytes.get_bytes(ea, n)
    return b.hex() if b else "??"


def callers(ea):
    out=[]
    for r in idautils.CodeRefsTo(ea, 0):
        fn = ida_funcs.get_func(r)
        if fn:
            out.append((fn.start_ea, r))
    return out


with open(OUT, "w") as f:
    dump("="*80, f)
    dump(" HOOK CHECK 4 - VERIFY INSTALLATION TARGETS", f)
    dump("="*80, f)

    # bytes at each hook candidate
    dump("\n### Prologue bytes at each hook candidate ###", f)
    for ea, name in [
        (0x1421DC480, "PRODUCER"),
        (0x14221E6A0, "CONSUMER"),
        (0x1421DC190, "PRODUCER parent"),
        (0x1421DBAF0, "PRODUCER grandparent"),
        (0x140458740, "scene dispatcher"),
        (0x14223F110, "per-geometry WVP"),
        (0x1421A0680, "CB_Map_A"),
        (0x1421A05E0, "CB_Map_B"),
    ]:
        f1 = ida_funcs.get_func(ea)
        sz = (f1.end_ea - f1.start_ea) if f1 else 0
        b = hexb(ea, 24)
        b2 = hexb(ea, 5)  # MinHook needs 5 bytes for jmp
        dump(f"  {name:22} RVA 0x{ea-BASE:X}  size=0x{sz:X}  prolog24={b}  first5={b2}", f)

    # Verify CALL site in sub_1421DC190 at 0x1421DC1C3
    dump("\n### CALL at 0x1421DC1C3 in sub_1421DC190 — verify target ###", f)
    ea = 0x1421DC1C3
    b = hexb(ea, 5)
    dump(f"  bytes at 0x{ea:X}: {b}", f)
    # E8 rel32 => call; compute target
    if b.startswith("e8"):
        disp = ida_bytes.get_dword(ea+1)
        if disp >= 0x80000000:
            disp -= 0x100000000
        target = (ea + 5 + disp) & 0xFFFFFFFFFFFFFFFF
        dump(f"  decoded call target: 0x{target:X} (RVA 0x{target-BASE:X})", f)
    # disasm too
    dump(f"  disasm: {idc.generate_disasm_line(ea, 0)}", f)

    # ==== IMPORTANT: find the true per-frame entry via dxgi Present ====
    dump("\n\n### Find IDXGISwapChain::Present via .rdata ###", f)
    # Try to find all xrefs from the IAT for dxgi!CreateDXGIFactory — no, we need runtime vtbl
    # Instead: search for 'Present' being called. Look for pattern FF 50 40 (call [rax+40h])
    # where rax was loaded from the swapchain vtable. Too heavy. Skip.

    # ==== Find the RenderWindow / D3D11 main render thread ====
    # Look for Begin-End scene or a known render loop anchor string
    dump("\n### Find strings 'Render' / 'Present' / 'ScenePaint' in binary ###", f)
    for s in idautils.Strings():
        st = str(s)
        low = st.lower()
        if any(k in low for k in ("renderpass", "ready to render", "begin render", "end render", "frame begin", "frame end", "scenerender")):
            dump(f"    0x{s.ea:X}: {st}", f)

    # ==== find the main render dispatcher (call chain root) ====
    dump("\n\n### Callers upstream of scene dispatcher sub_140458740 ###", f)
    seen = set([0x140458740])
    stack = [0x140458740]
    depth = 0
    result = []
    while stack and depth < 10:
        cur = stack.pop(0)
        for (cf, cs) in callers(cur):
            if cf not in seen:
                seen.add(cf)
                nm = idc.get_func_name(cf) or f"sub_{cf:X}"
                dump(f"    <- {nm}  RVA 0x{cf-BASE:X}  (depth ~{depth})", f)
                stack.append(cf)
        depth += 1
        if len(seen) > 50:
            break

    # ==== Confirm sub_1421DC480 body reaches the matrix store ====
    dump("\n\n### sub_1421DC480 decomp (first 6000) ###", f)
    cf = ida_hexrays.decompile(0x1421DC480)
    if cf:
        dump(str(cf)[:6000], f)

    # Decomp sub_1421DC190 one more time for clarity
    dump("\n### sub_1421DC190 decomp ###", f)
    cf = ida_hexrays.decompile(0x1421DC190)
    if cf:
        dump(str(cf)[:3000], f)

    # ==== LAST resort: find a guaranteed per-frame function via 'GameFrame' string ====
    dump("\n\n### Search 'GameFrame' / 'Main' / 'Loop' strings ###", f)
    for s in idautils.Strings():
        st = str(s)
        if any(k in st for k in ("GameMain", "gameMain", "FrameBegin", "FrameEnd", "Begin Frame", "End Frame", "RenderFrame", "Graphics:")):
            dump(f"    0x{s.ea:X}: {st}", f)

    dump("\nDONE.", f)

idc.qexit(0)
