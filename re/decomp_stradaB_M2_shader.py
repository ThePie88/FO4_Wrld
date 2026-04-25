"""
decomp_stradaB_M2_shader.py

Goal: validate hypothesis that BSGeometry.shaderProperty is at +0x130
      and alphaProperty at +0x138, based on:
        - BSGeometry::ctor  sub_1416D4BD0  @ RVA 0x16D4BD0
        - BSTriShape::ctor  sub_1416D99E0  @ RVA 0x16D99E0
        - BSDynamicTriShape::ctor sub_1416E4090 @ RVA 0x16E4090
        - BSLightingShaderProperty vtable @ RVA 0x28F9FF8
        - NiAlphaProperty vtable           @ RVA 0x2474400

Method:
 1) Decomp the ctors, capture all member writes (offsets + values).
 2) Find xrefs to BSLightingShaderProperty vtable and for each xref
    that looks like a "setter" (stores newly created shader into a
    BSGeometry), decompile it and detect which offset the new shader
    gets written to.
 3) Same for NiAlphaProperty vtable.
 4) Bonus: also dump BSDynamicTriShape ctor so we can see extra
    member writes at +0x170..+0x190.
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_segment
import ida_name
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_shader_raw.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=400):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return None
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            t = str(cf)
            lines = t.split("\n")
            if len(lines) > max_lines:
                log(fh, "\n".join(lines[:max_lines]))
                log(fh, f"  ... (truncated, total={len(lines)} lines)")
            else:
                log(fh, t)
            return t
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")
    return None


def disasm_dump(ea, fh, label="", insn_count=120):
    log(fh, f"\n-- disasm {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    cur = ea
    end = min(fn.end_ea, ea + insn_count * 16)
    i = 0
    while cur < end and i < insn_count:
        dis = idc.generate_disasm_line(cur, 0) or "?"
        log(fh, f"  0x{cur:X}  {dis}")
        cur = idc.next_head(cur, end)
        i += 1
        if cur == idc.BADADDR:
            break


def xrefs_to_vt(fh, vt_ea, label, limit=60):
    """List all code references to a vtable address. These are typically
    `lea rax, vtable` writes into an object header during ctor init."""
    log(fh, f"\n==== XREFS TO {label} @ 0x{vt_ea:X} (RVA 0x{rva(vt_ea):X}) ====")
    results = []
    for xref in idautils.XrefsTo(vt_ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        fn_start = fn.start_ea if fn else 0
        fn_rva = rva(fn_start) if fn_start else 0
        log(fh, f"  xref from 0x{xref.frm:X} in {fname} (func @ 0x{fn_start:X} RVA 0x{fn_rva:X}) type={xref.type}")
        results.append((xref.frm, fn_start))
        if len(results) >= limit:
            break
    return results


def find_ctor_call_sites(fh, ctor_ea, label, limit=30):
    """List up to N call sites of a ctor (who constructs instances)."""
    log(fh, f"\n-- call sites of {label} ctor @ 0x{ctor_ea:X} --")
    results = []
    for xref in idautils.XrefsTo(ctor_ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fn_start = fn.start_ea if fn else 0
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        log(fh, f"  call @ 0x{xref.frm:X} in {fname} (func @ 0x{fn_start:X} RVA 0x{rva(fn_start):X}) type={xref.type}")
        results.append((xref.frm, fn_start))
        if len(results) >= limit:
            break
    return results


def scan_mov_imm_offsets(fh, ea, label, insn_count=200):
    """Scan the function for `mov [rcx+IMM], X` / `mov [rbx+IMM], X` / etc.
    patterns. Useful to catch writes on *this inside a ctor."""
    log(fh, f"\n-- mov-offsets in {label} @ 0x{ea:X} --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    cur = ea
    end = fn.end_ea
    hits = {}
    while cur < end:
        dis = (idc.generate_disasm_line(cur, 0) or "").lower()
        # Very loose: catch "mov [r??+??h]" / "mov [r??+xxxxh]" lines
        if dis.startswith("mov ") and "[" in dis and "+" in dis:
            log(fh, f"  0x{cur:X}  {dis}")
        cur = idc.next_head(cur, end)
        if cur == idc.BADADDR:
            break


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B M2 — shader/alpha offset validation ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # Addresses
    BSGEO_CTOR   = IMG + 0x16D4BD0
    BSTRI_CTOR   = IMG + 0x16D99E0
    BSDYN_CTOR   = IMG + 0x16E4090
    BSLSP_VT     = IMG + 0x28F9FF8   # BSLightingShaderProperty vtable
    BSGEO_VT     = IMG + 0x267E0B8
    BSTRI_VT     = IMG + 0x267E948
    BSDYN_VT     = IMG + 0x267F948
    NIALPHA_VT   = IMG + 0x2474400
    NIALPHA_CTOR = IMG + 0x365DB0     # guess per M1 dossier

    log(fh, f"BSGeometry::ctor              @ 0x{BSGEO_CTOR:X}")
    log(fh, f"BSTriShape::ctor              @ 0x{BSTRI_CTOR:X}")
    log(fh, f"BSDynamicTriShape::ctor       @ 0x{BSDYN_CTOR:X}")
    log(fh, f"BSGeometry vtable             @ 0x{BSGEO_VT:X}")
    log(fh, f"BSTriShape vtable             @ 0x{BSTRI_VT:X}")
    log(fh, f"BSDynamicTriShape vtable      @ 0x{BSDYN_VT:X}")
    log(fh, f"BSLightingShaderProperty vt   @ 0x{BSLSP_VT:X}")
    log(fh, f"NiAlphaProperty vtable        @ 0x{NIALPHA_VT:X}")

    # 1) Decomp the three ctors
    log(fh, "\n\n========================================")
    log(fh, "  STEP 1 — CTOR DECOMP")
    log(fh, "========================================")
    decomp_full(BSGEO_CTOR, fh, "BSGeometry::ctor", max_lines=500)
    scan_mov_imm_offsets(fh, BSGEO_CTOR, "BSGeometry::ctor")
    decomp_full(BSTRI_CTOR, fh, "BSTriShape::ctor", max_lines=500)
    scan_mov_imm_offsets(fh, BSTRI_CTOR, "BSTriShape::ctor")
    decomp_full(BSDYN_CTOR, fh, "BSDynamicTriShape::ctor", max_lines=500)
    scan_mov_imm_offsets(fh, BSDYN_CTOR, "BSDynamicTriShape::ctor")

    # 2) XREFs to BSLightingShaderProperty vtable. First entry is typically
    #    the ctor (which writes vt into *this). Other xrefs may include
    #    RTTI-like registrations.
    log(fh, "\n\n========================================")
    log(fh, "  STEP 2 — BSLightingShaderProperty xrefs")
    log(fh, "========================================")
    bslsp_xrefs = xrefs_to_vt(fh, BSLSP_VT, "BSLightingShaderProperty")

    # For each UNIQUE func referencing BSLSP vtable, decompile it (to look for
    # "new BSLSP(...)" patterns where the caller stores the fresh pointer
    # into a BSGeometry slot).
    seen_funcs = set()
    for (ref_ea, fn_ea) in bslsp_xrefs[:20]:
        if fn_ea and fn_ea not in seen_funcs:
            seen_funcs.add(fn_ea)
            decomp_full(fn_ea, fh, f"xref-func @ RVA 0x{rva(fn_ea):X}", max_lines=250)

    # 3) XREFs to NiAlphaProperty vtable
    log(fh, "\n\n========================================")
    log(fh, "  STEP 3 — NiAlphaProperty xrefs")
    log(fh, "========================================")
    alpha_xrefs = xrefs_to_vt(fh, NIALPHA_VT, "NiAlphaProperty")
    seen_funcs = set()
    for (ref_ea, fn_ea) in alpha_xrefs[:20]:
        if fn_ea and fn_ea not in seen_funcs:
            seen_funcs.add(fn_ea)
            decomp_full(fn_ea, fh, f"alpha-xref-func @ RVA 0x{rva(fn_ea):X}", max_lines=250)

    # 4) Search for callers of BSLightingShaderProperty ctor (if we can find
    #    it). The first xref to BSLSP_VT IS probably the ctor. Use that.
    log(fh, "\n\n========================================")
    log(fh, "  STEP 4 — hunt BSLSP ctor + its callers")
    log(fh, "========================================")
    # Heuristic: the first xref whose containing function writes the vt
    # into *this is the ctor. Take the first function for now.
    bslsp_ctor = None
    if bslsp_xrefs:
        first_fn = bslsp_xrefs[0][1]
        log(fh, f"First xref container (candidate BSLSP ctor) @ 0x{first_fn:X} RVA 0x{rva(first_fn):X}")
        bslsp_ctor = first_fn
        find_ctor_call_sites(fh, bslsp_ctor, "BSLightingShaderProperty", limit=40)

    # 5) NiAlphaProperty ctor (if any). Try the M1 guess 0x365DB0 first.
    log(fh, "\n\n========================================")
    log(fh, "  STEP 5 — NiAlphaProperty ctor sniff")
    log(fh, "========================================")
    try:
        decomp_full(NIALPHA_CTOR, fh, "NiAlphaProperty::ctor (guess 0x365DB0)", max_lines=200)
        find_ctor_call_sites(fh, NIALPHA_CTOR, "NiAlphaProperty (guess)", limit=30)
    except Exception as e:
        log(fh, f"  fail: {e}")

    # Additionally, try to find the real ctor by looking at the first xref
    # to NIALPHA_VT.
    if alpha_xrefs:
        first_fn = alpha_xrefs[0][1]
        if first_fn and first_fn != NIALPHA_CTOR:
            log(fh, f"Real NiAlphaProperty ctor candidate @ 0x{first_fn:X} RVA 0x{rva(first_fn):X}")
            decomp_full(first_fn, fh, "NiAlphaProperty::ctor (from xref)", max_lines=200)
            find_ctor_call_sites(fh, first_fn, "NiAlphaProperty (real)", limit=30)

    # 6) Look for any function whose disasm pattern writes
    #    "shaderProperty" to a BSGeometry-like object. Scan all functions
    #    that both (a) reference BSLSP vt AND (b) call the allocator
    #    sub_1416579C0. Those are the "make a new shader + install it"
    #    sites.
    log(fh, "\n\n========================================")
    log(fh, "  STEP 6 — installer sites (BSLSP alloc + ctor + install)")
    log(fh, "========================================")
    ALLOC_EA = IMG + 0x16579C0
    log(fh, f"Allocator @ 0x{ALLOC_EA:X}")
    # For each BSLSP ctor caller, see if it then stores the pointer somewhere.
    if bslsp_ctor:
        for (call_ea, fn_ea) in list(idautils.XrefsTo(bslsp_ctor, 0))[:30]:
            if fn_ea:
                t = decomp_full(fn_ea, fh, f"bslsp-caller @ RVA 0x{rva(fn_ea):X}", max_lines=200)

    log(fh, "\n==== END M2 DUMP ====")
    fh.close()
    ida_pro.qexit(0)


main()
