"""
decomp_render_pipeline3.py
Final missing pieces:
  - sub_141A7F600 = creator/adder of scene roots (called before every write to qword_1430DD830)
  - BSBatchRenderer RTTI string at 0x1430D4E80 -> find vtable, instantiation site
  - Actual object type at qword_1430DD830 (ShadowSceneNode? or BSShaderAccumulator container?)
  - The +56 (vt[7]) slot on the shape objects iterated in phase dispatchers:
    read from (a1 + 400) with count (a1 + 416) — each is a BSShape*
  - sub_141A83090 (called at start of phase 1) — this likely sets up view state
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_pipeline_report3.txt"

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

    # 1) Decompile sub_141A7F600 - initializer of the scene root
    log(fh, "==== sub_141A7F600 (creator/adder of roots into qword_1430DD830) ====")
    ea = 0x141A7F600
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:100]:
            log(fh, f"  {ln}")

    # 2) sub_141A83090 (called at start of phase 1 — view setup?)
    log(fh, "\n==== sub_141A83090 (called from Phase1 top) ====")
    ea = 0x141A83090
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:120]:
            log(fh, f"  {ln}")

    # 3) sub_141A89D00 / sub_141A89EE0 / sub_141A89E00 / sub_141A89D80 - called around each phase
    for ea in [0x141A89D00, 0x141A89EE0, 0x141A89E00, 0x141A89D80, 0x141A89D50, 0x141A89AA0]:
        log(fh, f"\n==== 0x{ea:X} (called from phase dispatchers) ====")
        txt = decomp(ea)
        if txt:
            for ln in txt.splitlines()[:60]:
                log(fh, f"  {ln}")

    # 4) BSBatchRenderer: from RTTI string at 0x1430D4E80, find the vtable that references it
    # RTTI type descriptor pattern: the string is referenced by a TypeDescriptor struct,
    # which is in turn referenced by the CompleteObjectLocator at vtable[-1].
    log(fh, "\n==== BSBatchRenderer RTTI-to-vtable lookup ====")
    rtti_str = 0x1430D4E80
    log(fh, f"  RTTI string @ 0x{rtti_str:X}")
    # walk xrefs backward — the first xref should be from the TypeDescriptor
    xrefs1 = list(idautils.XrefsTo(rtti_str, 0))
    log(fh, f"  direct xrefs to string: {len(xrefs1)}")
    for xr in xrefs1[:5]:
        log(fh, f"    from 0x{xr.frm:X}")
        # this is likely inside TypeDescriptor (offset 0x10 of typedesc has 'name')
        # find xrefs to the typedesc (xr.frm - 0x10)
        typedesc_base = xr.frm - 0x10
        log(fh, f"      -> typedesc candidate @ 0x{typedesc_base:X}")
        for xr2 in idautils.XrefsTo(typedesc_base, 0):
            log(fh, f"        xref from 0x{xr2.frm:X}")
            # this is inside a class-hierarchy-descriptor (CHD) or CompleteObjectLocator (COL)
            # COL: has signature '1' at offset 0x0, then offsets at 0x4/0x8, then pointer to TypeDescriptor at 0xC
            # For 64-bit, COL fields are RVAs so offsets differ.
            col_base = xr2.frm - 0xC   # classic 32-bit; for x64, typedesc is at +0x10 of COL so we subtract 0x10
            # Also try -0x10 (x64)
            for offset_test in [0x10, 0xC]:
                col = xr2.frm - offset_test
                # walk backward: COL is referenced by vtable[-1]
                for xr3 in idautils.XrefsTo(col, 0):
                    # this should be vtable - 8 (RTTI slot)
                    vt_slot = xr3.frm
                    vt_base = vt_slot + 8
                    first_func = ida_bytes.get_qword(vt_base)
                    log(fh, f"          COL offset {offset_test}: xref @ 0x{xr3.frm:X}  vt_base candidate=0x{vt_base:X}  first_fn=0x{first_func:X}")
                    # If first_func is in text segment, this is the vtable
                    if 0x140000000 <= first_func <= 0x150000000:
                        log(fh, f"            *** BSBatchRenderer VTABLE candidate @ 0x{vt_base:X}  RVA=0x{vt_base-imb:X} ***")
                        # dump first 20 slots
                        for i in range(30):
                            q = ida_bytes.get_qword(vt_base + 8 * i)
                            if q < 0x140000000 or q > 0x150000000:
                                break
                            fn = ida_funcs.get_func(q)
                            sz = (fn.end_ea - fn.start_ea) if fn else 0
                            fnn = ida_funcs.get_func_name(q) or "?"
                            log(fh, f"              [{i:2d}] +0x{8*i:03X} -> 0x{q:X}  RVA=0x{q-imb:X}  size=0x{sz:X}  {fnn}")

    # 5) also do it via xrefs to the BSGeometryListCullingProcess RTTI and similar
    # for reference
    log(fh, "\n==== other RTTI strings (quick test) ====")
    for name, rs in [("BSDynamicTriShape", 0x1430991F0),
                     ("BSGeometry", 0x143098960),
                     ("BSGeometryListCullingProcess", 0x1430D4A98),
                     ("BSShaderAccumulator", 0x1430D3B50)]:
        log(fh, f"\n  [{name}] RTTI string @ 0x{rs:X}")
        for xr in list(idautils.XrefsTo(rs, 0))[:3]:
            typedesc_base = xr.frm - 0x10
            log(fh, f"    typedesc_candidate @ 0x{typedesc_base:X}")
            for xr2 in list(idautils.XrefsTo(typedesc_base, 0))[:3]:
                for offset_test in [0x10, 0xC]:
                    col = xr2.frm - offset_test
                    for xr3 in list(idautils.XrefsTo(col, 0))[:2]:
                        vt_base = xr3.frm + 8
                        first_fn = ida_bytes.get_qword(vt_base)
                        if 0x140000000 <= first_fn <= 0x150000000:
                            log(fh, f"      *** vt @ 0x{vt_base:X}  RVA=0x{vt_base-imb:X}")

    # 6) Check vt[7]=off_56 of the shape type.
    # In phase1, v9 = *v8 (first qword of shape = its vtable);
    # (vt + 56) is slot [7]
    # BSGeometry vtable will have slot 7 as the "Visit" / "AccumulateDraw" method
    # We need to find BSGeometry's full vtable to see what slot 7 is.
    log(fh, "\n==== BSGeometry::vtable[7] attempt ====")
    # BSGeometry RTTI string at 0x143098960 — decode via COL
    # We already emit it above; let me specifically enumerate the vtable
    # when we find it.

    log(fh, "\n==== DONE ====")
    fh.close()
    ida_pro.qexit(0)

main()
