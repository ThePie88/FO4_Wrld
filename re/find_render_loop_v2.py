"""
find_render_loop_v2.py
Find the per-frame render dispatcher by:
 1. Identifying where Scaleform BeginFrame wrapper (sub_141D20C00) is CALLED per frame.
 2. Identifying the vtable that owns the "WaitDFComposite" / JobList entries at 0x142F25FF0.
 3. Following the WinMain trampoline sub_140C2F3F0 -> sub_140C30FD0 (second call).
 4. Dump xrefs/callgraph for sub_141D20C00 (BeginFrame) and its parent.
 5. Dump sub_140C30FD0 (post-init = main loop or run-app).
 6. Find xrefs TO sub_142F25FF0 (the vtable / struct) - see what it is.
"""

import ida_auto
import ida_funcs
import ida_nalt
import ida_segment
import ida_hexrays
import ida_bytes
import ida_name
import ida_pro
import idc
import idautils

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_loop_v2_report.txt"

TARGETS_TO_DECOMP = [
    (0x140C30FD0, "sub_140C30FD0 post-init (likely main loop)"),
    (0x140C311E0, "sub_140C311E0 post-loop cleanup"),
    (0x141D20C00, "Scaleform BeginFrame wrapper (for xref walk)"),
]

XREFS_WALK = [
    (0x141D20C00, "BeginFrame wrapper callers"),
    (0x141D20CF0, "BeginScene wrapper callers"),
    (0x141D23EF0, "beginDisplay wrapper callers"),
    (0x141B4C6B0, "PushRenderTarget wrapper callers"),
    (0x141B4FCA0, "applyDepthStencilMode wrapper callers"),
]

# Data table references we want to explore
DATA_TABLES = [
    (0x142F25FF0, "WaitDFComposite xref target"),
    (0x142556348, "DuringMainRenderJobList string"),
    (0x142C3C558, "table A (DuringMainRenderJobList xref)"),
    (0x143F53000, "table B area (DuringMainRenderJobList xref)"),
]


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def walk_callers(ea, fh, depth=0, max_depth=4, seen=None, label=""):
    if seen is None:
        seen = set()
    if depth > max_depth:
        return
    xrefs = list(idautils.XrefsTo(ea, 0))
    if depth == 0:
        log(fh, f"[+] Walking callers of 0x{ea:X} ({label}) RVA=0x{rva(ea):X}  xrefs={len(xrefs)}")
    for x in xrefs:
        frm = x.frm
        fn = ida_funcs.get_func(frm)
        if fn is None:
            # pointer in data — print the location
            log(fh, f"    {'  '*depth}PTR from 0x{frm:X} (RVA 0x{rva(frm):X}) — NOT IN CODE")
            continue
        fs = fn.start_ea
        if fs in seen:
            continue
        seen.add(fs)
        name = ida_funcs.get_func_name(fs) or "?"
        size = fn.end_ea - fs
        log(fh, f"    {'  '*depth}CALLER 0x{fs:X} (RVA 0x{rva(fs):X}) size=0x{size:X} name={name} (from 0x{frm:X})")
        walk_callers(fs, fh, depth + 1, max_depth, seen, label)


def dump_data_region(ea, fh, count=32, stride=8):
    log(fh, f"[+] Data dump at 0x{ea:X} (RVA 0x{rva(ea):X}) ({count} qwords):")
    for i in range(count):
        addr = ea + i * stride
        if not ida_bytes.is_loaded(addr):
            continue
        val = ida_bytes.get_qword(addr)
        name = ida_name.get_name(val) or ""
        sym = ""
        fn = ida_funcs.get_func(val)
        if fn:
            fn_name = ida_funcs.get_func_name(fn.start_ea) or ""
            sym = f"FN:{fn_name}"
        else:
            s = idc.get_strlit_contents(val, -1, 0)
            if s:
                try:
                    sym = f"STR:{s.decode('utf-8', errors='replace')[:60]}"
                except Exception:
                    pass
        log(fh, f"    +0x{i*stride:03X}  0x{val:016X} {name} {sym}")


def decomp(ea, fh, label):
    log(fh, "")
    log(fh, "============================================================")
    log(fh, f"  DECOMP: {label}")
    log(fh, f"  ea=0x{ea:X}  RVA=0x{rva(ea):X}")
    log(fh, "============================================================")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            log(fh, "---- BEGIN DECOMP ----")
            log(fh, str(cfunc))
            log(fh, "---- END DECOMP ----")
            return
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")
    # fallback
    log(fh, "  [!] falling back to disasm")
    cur = fn.start_ea
    n = 0
    while cur < fn.end_ea and n < 400:
        log(fh, f"  0x{cur:X}: {idc.generate_disasm_line(cur, 0)}")
        cur = idc.next_head(cur, fn.end_ea)
        n += 1


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        log(fh, "[!] hex-rays unavailable — decomp will fall back to disasm")

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 1: DEEP XREF WALK (up to 4 levels)")
    log(fh, "============================================================")
    for ea, label in XREFS_WALK:
        log(fh, "")
        walk_callers(ea, fh, depth=0, max_depth=4, seen=set(), label=label)

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 2: DECOMPILE CANDIDATES")
    log(fh, "============================================================")
    for ea, label in TARGETS_TO_DECOMP:
        decomp(ea, fh, label)

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 3: DATA TABLE CONTENTS")
    log(fh, "============================================================")
    for ea, label in DATA_TABLES:
        log(fh, "")
        log(fh, f"--- {label} at 0x{ea:X} RVA=0x{rva(ea):X} ---")
        dump_data_region(ea, fh, count=16, stride=8)

    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
