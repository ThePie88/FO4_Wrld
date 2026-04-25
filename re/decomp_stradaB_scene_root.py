"""
decomp_stradaB_scene_root.py

Goal: Find the "world scene root" NiNode for Strada B (native body integration).

Strategy:
  1. Locate RTTI for ShadowSceneNode / BSFadeNode / NiNode / BSTriShape.
  2. Walk xrefs from RTTI descriptor -> vtable -> discover vtable RVA.
  3. From each vtable RVA, find xrefs (callers of vtable) -> most are ctors/binders.
  4. Follow ctor -> find which global it stores `this` into (that's the singleton).
  5. Dump first 40 decompiled bytes of xref functions to try to identify ShadowSceneNode
     singleton access pattern (tiny accessor: `mov rax, cs:qword_XXX; ret`).
  6. For BSFadeNode: same pattern; if no singleton, check the player-cam ctor uses.

Output: re/stradaB_scene_root.txt
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_segment
import ida_bytes
import ida_name
import ida_xref
import ida_ua
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_scene_root.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def find_string_ea(needle, exact=False):
    """Return list of (ea, full_str) matching `needle` (substring search)."""
    hits = []
    for s in idautils.Strings():
        try:
            v = str(s)
        except Exception:
            continue
        if (exact and v == needle) or ((not exact) and needle in v):
            hits.append((s.ea, v))
    return hits


def xrefs_to_ea(ea):
    """Return list of (xref_ea, xref_type) to ea."""
    out = []
    for x in idautils.XrefsTo(ea, 0):
        out.append((x.frm, x.type))
    return out


def find_rtti_typedesc_xrefs(fh, class_name_mangled):
    """MSVC RTTI TypeDescriptor has a cstr that is `.?AV<Name>@@`. Find TDs and
    follow their xrefs (which end at COL -> BCD -> BCA -> class vftable)."""
    log(fh, f"\n-- RTTI search: {class_name_mangled} --")
    hits = find_string_ea(class_name_mangled, exact=True)
    if not hits:
        hits = find_string_ea(class_name_mangled, exact=False)
    for str_ea, full in hits:
        log(fh, f"  str @ 0x{str_ea:X}  RVA=0x{rva(str_ea):X}  full='{full}'")
        # TypeDescriptor layout: [vftable_of_typeinfo][spare][name...] — name is at TD+0x10
        td_ea = str_ea - 0x10
        log(fh, f"  candidate TD @ 0x{td_ea:X}  RVA=0x{rva(td_ea):X}")
        # Xrefs to TD
        xr = xrefs_to_ea(td_ea)
        log(fh, f"  xrefs-to-TD count={len(xr)}")
        for f, t in xr[:20]:
            log(fh, f"    xref from 0x{f:X}  type={t}")


def find_class_vtable_via_rtti(fh, class_name_mangled):
    """Attempt: locate vftable RVA via the 0x14XXXXXXX pattern. The MSVC RTTI
    Complete Object Locator sits at vftable[-1]. We walk xrefs from TD through
    BCD to COL, then find the function that references COL (which is the
    vftable ctor)."""
    log(fh, f"\n== Resolve vtable for {class_name_mangled} ==")
    strs = find_string_ea(class_name_mangled, exact=True)
    if not strs:
        log(fh, f"  NOT FOUND")
        return None
    str_ea, _ = strs[0]
    td_ea = str_ea - 0x10

    # Walk xrefs from TD.  The first level is BCDs (pointing TD in their first field).
    # Data-type xrefs: we scan .rdata for QWORDs equal to td_ea.
    rdata_seg = ida_segment.get_segm_by_name(".rdata")
    if not rdata_seg:
        # fallback — scan all segments
        segs = []
        for s in idautils.Segments():
            segs.append(s)
    else:
        segs = [rdata_seg.start_ea]

    # Scan .rdata for qwords matching td_ea
    found_col = []
    seg = ida_segment.get_segm_by_name(".rdata")
    if seg:
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end - 8:
            try:
                if ida_bytes.get_qword(ea) == td_ea:
                    # candidate BCD[0] = &TD. BCD is 0x20 bytes (UINT32 fields + &TD).
                    # Let's log this address for inspection.
                    pass  # too noisy; rely on COL scan instead
            except Exception:
                pass
            ea += 8

    # Alternative: scan for Complete Object Locator. COL is 0x28 bytes:
    #   DWORD signature = 1
    #   DWORD offset
    #   DWORD cdOffset
    #   DWORD pTypeDescriptor  (image-rel RVA to TD)
    #   DWORD pClassDescriptor (image-rel RVA to CHD)
    #   DWORD pSelf            (image-rel RVA to self)
    # then a function-address (? not quite — ObjLocator is the last one; vftable just above.)
    base = ida_nalt.get_imagebase()
    td_rva = td_ea - base

    if seg:
        ea = seg.start_ea
        end = seg.end_ea - 0x28
        while ea < end:
            try:
                sig = ida_bytes.get_dword(ea)
                if sig in (0, 1):
                    pTD = ida_bytes.get_dword(ea + 0x0C)
                    pSelf = ida_bytes.get_dword(ea + 0x14)
                    if pTD == td_rva and pSelf == (ea - base):
                        found_col.append(ea)
            except Exception:
                pass
            ea += 4

    log(fh, f"  COL candidates: {len(found_col)}")
    for col_ea in found_col[:5]:
        log(fh, f"    COL @ 0x{col_ea:X}  RVA=0x{rva(col_ea):X}")
        # xrefs TO col (the qword_COL just above the vtable)
        # Find xrefs to col_ea — should be EXACTLY 1 .rdata qword that is vftable[-1].
        for xr in idautils.XrefsTo(col_ea, 0):
            log(fh, f"      xref-to-COL from 0x{xr.frm:X}  RVA=0x{rva(xr.frm):X}")
            # The xref is the qword `vftable[-1]` -> vftable starts at xr.frm + 8.
            vt_ea = xr.frm + 8
            log(fh, f"      VTABLE candidate @ 0x{vt_ea:X}  RVA=0x{rva(vt_ea):X}")
            # Dump first 8 slots
            for i in range(8):
                slot = ida_bytes.get_qword(vt_ea + 8*i)
                log(fh, f"        [{i:2d}] -> 0x{slot:X} (RVA 0x{rva(slot):X})")
            # xrefs TO the vtable itself -> ctors
            ct = list(idautils.XrefsTo(vt_ea, 0))
            log(fh, f"      xrefs-to-vtable count={len(ct)}")
            for cx in ct[:10]:
                fn = ida_funcs.get_func(cx.frm)
                fnstart = fn.start_ea if fn else 0
                log(fh, f"        xref from 0x{cx.frm:X} in func 0x{fnstart:X} (RVA 0x{rva(fnstart) if fnstart else 0:X})")
    return found_col


def search_tiny_accessor(fh, label):
    """Find 'mov rax, cs:qword_XXX; ret' tiny accessors in .text.
    Returns list of (fn_ea, global_addr).
    """
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return []
    out = []
    ea = seg.start_ea
    end = seg.end_ea
    # Pattern: 48 8B 05 xx xx xx xx  C3   -> mov rax, [rip+disp32]; ret
    while ea < end - 8:
        try:
            if (ida_bytes.get_byte(ea) == 0x48 and
                ida_bytes.get_byte(ea+1) == 0x8B and
                ida_bytes.get_byte(ea+2) == 0x05 and
                ida_bytes.get_byte(ea+7) == 0xC3):
                disp = ida_bytes.get_dword(ea+3)
                if disp & 0x80000000:
                    disp -= 0x100000000
                target = ea + 7 + disp  # rip after decoding = ea+7; target = ea+7+disp
                out.append((ea, target))
        except Exception:
            pass
        ea += 1
    log(fh, f"  tiny accessors total: {len(out)}")
    return out


def decomp_func(ea, fh, label="", max_lines=80):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            text = str(cfunc)
            lines = text.split("\n")[:max_lines]
            log(fh, "\n".join(lines))
            if len(text.split("\n")) > max_lines:
                log(fh, f"  ... (truncated, {len(text.split('n'))} lines total)")
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")


def find_writes_to_global(fh, global_ea, label=""):
    """Find functions that WRITE (mov [global], reg) to global_ea in .text."""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return []
    base = ida_nalt.get_imagebase()
    out = set()
    ea = seg.start_ea
    end = seg.end_ea
    # Pattern: 48 89 XX XX XX XX XX  -> mov [rip+disp32], r??  (reg-to-mem)
    # REX.W 89 /r
    # Actually any xref is better
    for x in idautils.XrefsTo(global_ea, 0):
        fn = ida_funcs.get_func(x.frm)
        if fn:
            out.add(fn.start_ea)
    log(fh, f"  writers/readers to global @ 0x{global_ea:X} ({label}): {len(out)} funcs")
    for fe in sorted(out)[:20]:
        fn_name = ida_funcs.get_func_name(fe) or "?"
        log(fh, f"    0x{fe:X}  RVA=0x{rva(fe):X}  {fn_name}")
    return sorted(out)


def examine_scene_walker():
    """The known scene walker sub_140C38F80 tells us how scene root is accessed.
    Also `qword_1430DD830` appears all over scene_submit."""
    return [
        (0x140C38F80, "scene_walker_sub_140C38F80"),
        (0x1430DD830, "qword_1430DD830 — ShadowSceneNode ptr? (global)"),
        (0x1430DA390, "qword_1430DA390 — cell ref table?"),
        (0x1430EAC90, "qword_1430EAC90 — renderer state container"),
    ]


def scan_qword_writes(fh, global_ea):
    """Find 'mov [global], rcx/rdx/rax' sites = singleton ctor setters."""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return []
    base = ida_nalt.get_imagebase()
    out = []
    ea = seg.start_ea
    end = seg.end_ea
    while ea < end - 8:
        try:
            # REX.W 89 mod/reg/rm disp32  (mov [rip+disp32], reg)
            # Full pattern: 48 89 XX 05 YY YY YY YY (where XX high bits encode reg)
            if ida_bytes.get_byte(ea) == 0x48 and ida_bytes.get_byte(ea+1) == 0x89:
                mr = ida_bytes.get_byte(ea+2)
                # mod=00, rm=101 -> rip-rel. reg in bits 3-5.
                if (mr & 0xC7) == 0x05:
                    disp = ida_bytes.get_dword(ea+3)
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    target = ea + 7 + disp
                    if target == global_ea:
                        fn = ida_funcs.get_func(ea)
                        out.append((ea, fn.start_ea if fn else 0))
        except Exception:
            pass
        ea += 1
    log(fh, f"  writes (mov [global], reg) to 0x{global_ea:X}: {len(out)}")
    for ins_ea, fn_ea in out[:20]:
        nm = ida_funcs.get_func_name(fn_ea) if fn_ea else "?"
        log(fh, f"    ins 0x{ins_ea:X}  in func 0x{fn_ea:X} (RVA 0x{rva(fn_ea) if fn_ea else 0:X}) {nm}")
    return out


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — scene root RE ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    log(fh, f"image base = 0x{ida_nalt.get_imagebase():X}")

    # 1) Identify vtables via RTTI for key classes
    for cls in [
        ".?AVShadowSceneNode@@",
        ".?AVBSFadeNode@@",
        ".?AVNiNode@@",
        ".?AVBSTriShape@@",
        ".?AVBSDynamicTriShape@@",
        ".?AVBSLightingShaderProperty@@",
        ".?AVNiAlphaProperty@@",
        ".?AVBSGeometry@@",
        ".?AVNiAVObject@@",
        ".?AVNiRefObject@@",
    ]:
        find_class_vtable_via_rtti(fh, cls)

    # 2) Known globals — who writes to them?
    log(fh, "\n\n==== GLOBAL WRITE/READ ANALYSIS ====")
    candidate_globals = [
        (0x1430DD830, "qword_1430DD830 scene/shadow"),
        (0x1430DA390, "qword_1430DA390 cell table"),
        (0x1430EAC90, "qword_1430EAC90 renderer state"),
        (0x1430DBD58, "PlayerCamera singleton"),
    ]
    for g_ea, lbl in candidate_globals:
        log(fh, f"\n-- writes to {lbl} (0x{g_ea:X}) --")
        scan_qword_writes(fh, g_ea)

    # 3) Examine scene_walker
    log(fh, "\n\n==== SCENE WALKER DECOMP ====")
    decomp_func(0x140C38F80, fh, "scene_walker_sub_140C38F80", max_lines=80)

    # 4) Tiny accessors — find those whose target global might be scene root
    log(fh, "\n\n==== TINY ACCESSORS (mov rax, cs:global; ret) ====")
    acc = search_tiny_accessor(fh, "tiny_accessor")
    # Filter to .data segment targets
    dseg = ida_segment.get_segm_by_name(".data")
    if dseg:
        near = [a for a in acc if dseg.start_ea <= a[1] < dseg.end_ea]
        log(fh, f"  accessors targeting .data: {len(near)}")
        # Just log a sample around scene addresses
        for ea_fn, tgt in near[:40]:
            log(fh, f"    fn 0x{ea_fn:X} RVA 0x{rva(ea_fn):X}  -> global 0x{tgt:X} RVA 0x{rva(tgt):X}")

    log(fh, "\n==== END ====")
    fh.close()
    ida_pro.qexit(0)


main()
