"""
decomp_render_pipeline2.py
Followup: fix threading discovery, identify scene root singleton type,
dump sub_141067250, check RenderDispatch_1 is running on the same thread
as FrameTick (which runs on the main thread per sub_140C30FD0 pattern).
"""
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro
import ida_name
import idaapi
import idc
import idautils

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_pipeline_report2.txt"

def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def rva(ea):
    return ea - ida_nalt.get_imagebase()

def decomp(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception as e:
        return f"<{e}>"

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    imb = ida_nalt.get_imagebase()
    BADADDR = idaapi.BADADDR

    # 1) Threading: who calls CreateThread / _beginthreadex / SetThreadDescription
    log(fh, "==== Threading ====")
    for n in ["CreateThread", "_beginthreadex", "_beginthread", "SetThreadDescription",
              "SetThreadName", "CreateRemoteThread"]:
        ea = ida_name.get_name_ea(BADADDR, n)
        if ea == BADADDR:
            log(fh, f"  [missing symbol] {n}")
            continue
        log(fh, f"\n-- {n} @ 0x{ea:X} (first 20 call sites) --")
        seen = set()
        cnt = 0
        for xr in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(xr.frm)
            if not fn:
                continue
            if fn.start_ea in seen:
                continue
            seen.add(fn.start_ea)
            fname = ida_funcs.get_func_name(fn.start_ea) or "?"
            log(fh, f"  from fn 0x{fn.start_ea:X}  RVA=0x{rva(fn.start_ea):X}  {fname}")
            cnt += 1
            if cnt >= 20:
                break

    # 2) Dump the ALT caller of Phase1/Phase2 : sub_141067250
    log(fh, "\n==== sub_141067250 alt-caller of phase dispatcher ====")
    ea = 0x141067250
    txt = decomp(ea)
    if txt:
        lines = txt.splitlines()
        for ln in lines[:200]:
            log(fh, f"  {ln}")

    # 3) Is qword_1430DD830 the ShadowSceneNode/BSShaderAccumulator?
    # Look for its ctor / type. Find writes TO qword_1430DD830
    log(fh, "\n==== writers to qword_1430DD830 (scene root / shader accumulator) ====")
    g = 0x1430DD830
    for xr in idautils.XrefsTo(g, 0):
        # check if it's a write (mov [rip+xxx], rax style)
        disasm = idc.generate_disasm_line(xr.frm, 0)
        if disasm and ("mov " in disasm and "," in disasm and "qword_1430DD830" in disasm):
            fn = ida_funcs.get_func(xr.frm)
            label = f"func=0x{fn.start_ea:X}" if fn else "no func"
            log(fh, f"  WRITE at 0x{xr.frm:X}  {disasm}   {label}")
    # also search for constructor patterns
    log(fh, "\n  -- disasm of first few xrefs --")
    n = 0
    for xr in idautils.XrefsTo(g, 0):
        disasm = idc.generate_disasm_line(xr.frm, 0)
        log(fh, f"    0x{xr.frm:X}: {disasm}")
        n += 1
        if n >= 30:
            break

    # 4) Dump sub_140C00E80 / sub_1404D5E30 callers of RenderDispatch_1 —
    # these may be alt execution paths (photo mode? shadow-only pass?)
    log(fh, "\n==== Alt callers of RenderDispatch_1 ====")
    for ea in [0x140C00E80, 0x1404D5E30, 0x140BF9010]:
        log(fh, f"\n-- decomp of 0x{ea:X} (first 100 lines) --")
        txt = decomp(ea)
        if txt:
            for ln in txt.splitlines()[:100]:
                log(fh, f"  {ln}")

    # 5) Verify that sub_140C30FD0 (main render loop in UI thread) is the ONLY
    # FrameTick caller, and check its own callers (to confirm main thread)
    log(fh, "\n==== sub_140C30FD0 & sub_140C2F3F0 decompilation (top of loop) ====")
    for ea, lab in [(0x140C30FD0, "main_loop"), (0x140C2F3F0, "top_trampoline")]:
        log(fh, f"\n-- {lab} @ 0x{ea:X} --")
        txt = decomp(ea)
        if txt:
            for ln in txt.splitlines()[:80]:
                log(fh, f"  {ln}")

    # 6) BSShaderAccumulator SetCamera — vtable [21]=sub_1402394B0 / [22]=sub_140239490 etc. small
    # functions. Dump them all to verify which one sets the camera matrix.
    log(fh, "\n==== BSShaderAccumulator small vtable methods disasm ====")
    for off, name in [
        (21, "0x2394B0"), (22, "0x239490"), (23, "0x2394C0"), (24, "0x2394A0"),
        (15, "0x239540"), (16, "0x239550"), (17, "0x239590"),
    ]:
        vt = 0x14290A6B0
        slot = vt + 8 * off
        q = ida_bytes.get_qword(slot)
        log(fh, f"\n-- BSShaderAccumulator::vt[{off}] -> 0x{q:X} --")
        # list all instructions in the tiny function
        fn = ida_funcs.get_func(q)
        if not fn:
            log(fh, "  NO FUNC")
            continue
        cur = fn.start_ea
        while cur < fn.end_ea:
            log(fh, f"    0x{cur:X}: {idc.generate_disasm_line(cur, 0)}")
            cur = idc.next_head(cur, fn.end_ea)

    # 7) Dump scene root vt[7] = vtable slot +56 of the object passed in qword_1430DD830
    # - first we need to find the type of object in qword_1430DD830 — scan the
    #   initial writer to find the vtable assigned
    log(fh, "\n==== Trying to resolve the vtable stored at qword_1430DD830 ====")
    # Best way: find a mov to [1430DD830] where the RHS is a known vtable
    for xr in idautils.XrefsTo(g, 0):
        ea = xr.frm
        # disasm prev insn to see "lea rax, off_vtable"
        prev = idc.prev_head(ea, ea - 0x30)
        # Also disassemble the current and prev
        d_cur = idc.generate_disasm_line(ea, 0)
        d_prev = idc.generate_disasm_line(prev, 0) if prev != idaapi.BADADDR else "?"
        if d_cur and "mov" in d_cur and "qword_1430DD830" in d_cur:
            log(fh, f"  at 0x{ea:X}: {d_cur}")
            log(fh, f"  prev at 0x{prev:X}: {d_prev}")

    log(fh, "\n==== DONE ====")
    fh.close()
    ida_pro.qexit(0)

main()
