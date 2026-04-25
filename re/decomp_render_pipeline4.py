"""
decomp_render_pipeline4.py
Final critical script:
  - sub_140C38910 = the REAL 3D scene submit (called right BEFORE sub_140C37D20 in sub_140C32D30)
  - sub_140C39760 & sub_140C39960 (called in sub_140C37D20 when UI takeover)
  - Manual BSBatchRenderer vtable via RTTI RVA chain
  - sub_141A81AB0 (last line of alt sub_141067250)
"""
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro
import ida_name
import ida_segment
import idaapi
import idc
import idautils

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_pipeline_report4.txt"

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

    # The real 3D scene: sub_140C38910 called BEFORE sub_140C37D20 (Scaleform)
    log(fh, "==== sub_140C38910 = REAL 3D scene render (called before Scaleform in sub_140C32D30) ====")
    ea = 0x140C38910
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:350]:
            log(fh, f"  {ln}")

    # Also dump sub_140C39760 & sub_140C39960 which are bypass paths
    log(fh, "\n==== sub_140C39760 (early-out in sub_140C37D20) ====")
    for ea in [0x140C39760, 0x140C39960, 0x140C399E0]:
        log(fh, f"\n-- 0x{ea:X} --")
        txt = decomp(ea)
        if txt:
            for ln in txt.splitlines()[:80]:
                log(fh, f"  {ln}")

    # BSBatchRenderer: manually find the vtable
    # In x64 MSVC RTTI, the pattern is:
    #   TypeDescriptor: { void* vtable_of_type_info; char* name_ptr; char mangled_name[0] }
    #   The mangled name is stored INLINE (not pointed to) — the string '.?AVBSBatchRenderer@@'
    #   is AT the typedesc location, starting at offset 0x10 (after the two qwords).
    # So 0x1430D4E80 IS the name-inline-location; the TypeDescriptor BASE is at 0x1430D4E70.
    # RTTI CompleteObjectLocator stores the TypeDescriptor RVA at offset 0xC (x64),
    # which is (typedesc_base - imb).
    log(fh, "\n==== Manual BSBatchRenderer vtable lookup via RTTI RVA scan ====")
    typedesc_base = 0x1430D4E80 - 0x10   # 0x1430D4E70
    typedesc_rva = typedesc_base - imb
    log(fh, f"  Typedesc base @ 0x{typedesc_base:X}  RVA=0x{typedesc_rva:X}")

    # Now scan .rdata / any data segment for a dword matching this RVA
    # (this is the pointer from COL.pTypeDescriptor)
    seg = ida_segment.get_segm_by_name(".rdata")
    if not seg:
        log(fh, "  .rdata segment not found; scanning all")
        seg_start, seg_end = 0x140001000, 0x144200000
    else:
        seg_start, seg_end = seg.start_ea, seg.end_ea
    log(fh, f"  Scanning 0x{seg_start:X}..0x{seg_end:X} for DWORD = 0x{typedesc_rva:X}")
    cur = seg_start
    hits = []
    while cur < seg_end:
        v = ida_bytes.get_dword(cur)
        if v == typedesc_rva:
            hits.append(cur)
        cur += 4
    log(fh, f"  Found {len(hits)} hit(s)")
    for h in hits[:20]:
        log(fh, f"    COL.pTypeDescriptor @ 0x{h:X}")
        # COL layout (x64): signature(4), offset(4), cdOffset(4), pTypeDescriptor(4), pClassHierarchy(4), pSelf(4)
        # So the COL starts at h - 0xC
        col = h - 0xC
        log(fh, f"    COL candidate @ 0x{col:X}  signature=0x{ida_bytes.get_dword(col):X}")
        # Find xrefs to COL — each should be the vtable-1 slot
        for xr in idautils.XrefsTo(col, 0):
            vt_base = xr.frm + 8
            first_fn = ida_bytes.get_qword(vt_base)
            if 0x140000000 <= first_fn <= 0x150000000:
                log(fh, f"      *** BSBatchRenderer VTABLE @ 0x{vt_base:X}  RVA=0x{vt_base-imb:X}")
                # dump first ~25 slots
                for i in range(40):
                    q = ida_bytes.get_qword(vt_base + 8 * i)
                    if q < 0x140000000 or q > 0x150000000:
                        break
                    fn = ida_funcs.get_func(q)
                    sz = (fn.end_ea - fn.start_ea) if fn else 0
                    fname = ida_funcs.get_func_name(q) or "?"
                    log(fh, f"        [{i:2d}] +0x{8*i:03X} -> 0x{q:X}  RVA=0x{q-imb:X}  size=0x{sz:X}  {fname}")

    # Also do this for BSGeometry, BSShaderAccumulator, BSDFPrePassShader
    log(fh, "\n==== Same for other classes ====")
    targets = [
        ("BSGeometry", 0x143098960 - 0x10),
        ("BSShaderAccumulator", 0x1430D3B50 - 0x10),
        ("BSDFPrePassShader", 0x1430D4B28 - 0x10),
        ("BSDynamicTriShape", 0x1430991F0 - 0x10),
        ("BSLightingShader", 0x1430D5260 - 0x10),  # guess - may not match
    ]
    for name, tdb in targets:
        log(fh, f"\n  [{name}] typedesc @ 0x{tdb:X}")
        rva_val = tdb - imb
        cur = seg_start
        matched = 0
        while cur < seg_end and matched < 5:
            v = ida_bytes.get_dword(cur)
            if v == rva_val:
                col = cur - 0xC
                for xr in idautils.XrefsTo(col, 0):
                    vt_base = xr.frm + 8
                    first_fn = ida_bytes.get_qword(vt_base)
                    if 0x140000000 <= first_fn <= 0x150000000:
                        log(fh, f"    vt @ 0x{vt_base:X}  RVA=0x{vt_base-imb:X}  first_fn=0x{first_fn:X}")
                        matched += 1
            cur += 4

    log(fh, "\n==== sub_141A81AB0 (last call in alt 141067250 when !920) ====")
    ea = 0x141A81AB0
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:120]:
            log(fh, f"  {ln}")

    log(fh, "\n==== DONE ====")
    fh.close()
    ida_pro.qexit(0)

main()
