"""
decomp_stradaB_bslsp_finalize.py

Follow-up: deep-dive into the ACTUAL bind + install sequence.

KEY INSIGHT FROM PREVIOUS PASS:
  - sub_1421C6870 has ONLY 4 callers, all internal to the BSLSP class:
       sub_140360A90  (??? — might be vanilla runtime geometry installer)
       sub_14040AB10  (??? — another candidate)
       sub_1421711F0  (BSLSP vt[28] = "LoadTextures from type ID")
       sub_142171F90  (sibling)
  - sub_142171050 has ONLY 2 callers:
       sub_1421792E0 (startup — shader factory registration)
       sub_14217A2E0 (??? — could be runtime)

  So there IS NO single vanilla site that does
    "alloc + texset + direct bind_mat_texset + install to geom".
  Instead, the PROPER BSLSP pathway appears to go through
    sub_1421711F0 (BSLSP::LoadTextures).

Goals of this pass:
  1. Full decomp of sub_140360A90, sub_14040AB10, sub_14217A2E0 —
     find which of these is a runtime geometry installer.
  2. Full decomp of sub_1421711F0 (BSLSP::LoadTextures) —
     see exactly what it does.
  3. Decomp sub_142171F90 (sibling helper).
  4. Find if there's a "SetShader" function that bolts a BSLSP
     onto a BSGeometry, installing the reverse pointer.
  5. Decomp sub_142174B20 (BSLSP vt[0] — dtor) to understand the
     lifecycle invariants.
  6. Decomp sub_142160C10 (called at start of sub_1421711F0) —
     this is probably a "material reinit".
  7. sub_1416DE030 — the type-name → factory lookup that
     sub_1421711F0 uses. What does it return when given an id?
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_name
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_bslsp_finalize_raw.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=800):
    log(fh, f"\n---- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) ----")
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


def list_callers(fh, fn_ea, label):
    log(fh, f"\n==== Callers of {label} ====")
    callers = set()
    for xref in idautils.XrefsTo(fn_ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if not fn:
            continue
        if fn.start_ea in callers:
            continue
        callers.add(fn.start_ea)
        fname = ida_funcs.get_func_name(fn.start_ea) or "?"
        log(fh, f"  0x{fn.start_ea:X}  {fname}  (RVA 0x{rva(fn.start_ea):X})")
    return callers


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — BSLSP finalize RE pass ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # ============================================================
    # PART A — Deep decomp the OTHER two bind_mat_texset callers.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART A — The 'outer' callers of sub_1421C6870")
    log(fh, "=========================================")
    decomp_full(IMG + 0x360A90, fh, "sub_140360A90 (bind caller)", max_lines=600)
    decomp_full(IMG + 0x40AB10, fh, "sub_14040AB10 (bind caller)", max_lines=600)
    decomp_full(IMG + 0x171F90 + 0x2000000, fh, "sub_142171F90 (bind caller)", max_lines=400)

    # ============================================================
    # PART B — Full decomp of BSLSP::LoadTextures sub_1421711F0
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART B — sub_1421711F0 (BSLSP::LoadTextures) full")
    log(fh, "=========================================")
    decomp_full(IMG + 0x21711F0, fh, "sub_1421711F0 FULL", max_lines=500)

    # ============================================================
    # PART C — sub_142160C10 (called from sub_1421711F0 prologue)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART C — sub_142160C10 (material prep?)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x2160C10, fh, "sub_142160C10", max_lines=300)

    # ============================================================
    # PART D — sub_1416DE030 — the type-name → id lookup
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART D — sub_1416DE030 (type factory lookup)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x16DE030, fh, "sub_1416DE030", max_lines=200)

    # ============================================================
    # PART E — sub_14217A2E0 (2nd BSLSP alloc caller)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART E — sub_14217A2E0 (BSLSP alloc caller)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x217A2E0, fh, "sub_14217A2E0", max_lines=400)

    # ============================================================
    # PART F — Find xrefs to sub_1421711F0 (vt[28] of BSLSP) —
    # THIS is what should be called to make BSLSP draw.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART F — callers of sub_1421711F0 (BSLSP::LoadTextures)")
    log(fh, "=========================================")
    callers_loadtex = list_callers(fh, IMG + 0x21711F0, "sub_1421711F0")

    # ============================================================
    # PART G — All callers of sub_142170E60 (BSLSP template init).
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART G — callers of sub_142170E60 (BSLSP template)")
    log(fh, "=========================================")
    list_callers(fh, IMG + 0x2170E60, "sub_142170E60")

    # ============================================================
    # PART H — sub_142174A70 (dup of sub_142171050 per dossier)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART H — sub_142174A70 (dup alloc?) callers")
    log(fh, "=========================================")
    list_callers(fh, IMG + 0x2174A70, "sub_142174A70")
    decomp_full(IMG + 0x2174A70, fh, "sub_142174A70", max_lines=200)

    # ============================================================
    # PART I — Find runtime BSLSP install pattern. Scan for sites
    # that write to BSGeometry+0x138 (offset 312) after alloc.
    # We need to find the disassembly of the 'mov [reg+138h], ?'
    # pattern and see if it follows a BSLSP alloc.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART I — scanning for 'mov [reg+138h], reg2' patterns")
    log(fh, "=========================================")

    def iter_text_segments():
        import ida_segment
        qty = ida_segment.get_segm_qty()
        for i in range(qty):
            seg = ida_segment.getnseg(i)
            if not seg:
                continue
            name = ida_segment.get_segm_name(seg)
            if name and "text" in name.lower():
                yield seg.start_ea, seg.end_ea

    n = 0
    max_hits = 60
    for s, e in iter_text_segments():
        ea = s
        while ea < e and n < max_hits:
            mnem = idc.print_insn_mnem(ea)
            if mnem == "mov":
                # Look for instructions of the form `mov [r+138h], reg`
                # where r is a register and the immediate displacement equals 0x138.
                operand0 = idc.print_operand(ea, 0)
                if "[" in operand0 and "138" in operand0:
                    disp = idc.get_operand_value(ea, 0)
                    if disp == 0x138:
                        fn = ida_funcs.get_func(ea)
                        fname = ida_funcs.get_func_name(fn.start_ea) if fn else "?"
                        fn_rva = rva(fn.start_ea) if fn else 0
                        dis = idc.generate_disasm_line(ea, 0)
                        log(fh, f"  0x{ea:X} (fn 0x{fn.start_ea if fn else 0:X} RVA=0x{fn_rva:X} {fname}): {dis}")
                        n += 1
            ea = idc.next_head(ea, e)

    # ============================================================
    # PART J — decomp sub_140360A90 caller if applicable (candidate
    # vanilla runtime geometry install site).
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART J — sub_140360A90 deep (already done above, full)")
    log(fh, "=========================================")
    # Already done in PART A.

    # ============================================================
    # PART K — BSEffectShaderProperty vt[42] → the same 'attach'
    # — what does it do? Find EXACT difference with BSLSP vt[42].
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART K — BSEffectShader vt[42] (compare to BSLSP vt[42])")
    log(fh, "=========================================")
    BSEFFECT_VTABLE = 0  # Need to find it
    # From texture api dossier: BSEffectShaderProperty vtable is undefined,
    # so let's find via xrefs to &BSEffectShaderProperty::vftable string.
    # Easier: the FogOfWar installer calls (v49->vt+336)(v49, geom) where v49 is
    # allocated via sub_14216F9C0. Let's look at sub_14216F9C0 to find the
    # vtable write, then read vtable[42].
    decomp_full(IMG + 0x216F9C0, fh, "sub_14216F9C0 BSEffectShader ctor (find vtable)", max_lines=80)

    # Find BSEffectShaderProperty vt address by scanning:
    for name, nea in idautils.Names():
        if "BSEffectShaderProperty" in name and "vftable" in name:
            log(fh, f"  FOUND BSEffectShaderProperty vtable @ 0x{nea:X} RVA=0x{rva(nea):X}")
            vt_ea = nea
            # decomp vt[42]
            q42 = ida_bytes.get_qword(vt_ea + 42*8)
            log(fh, f"  vt[42] = 0x{q42:X} RVA=0x{rva(q42):X}")
            if ida_funcs.get_func(q42):
                decomp_full(q42, fh, "BSEffectShader vt[42]", max_lines=200)
            break

    # Do the same for BSSkyShaderProperty (Moon uses it):
    for name, nea in idautils.Names():
        if "BSSkyShaderProperty" in name and "vftable" in name:
            log(fh, f"  FOUND BSSkyShaderProperty vtable @ 0x{nea:X} RVA=0x{rva(nea):X}")
            vt_ea = nea
            q42 = ida_bytes.get_qword(vt_ea + 42*8)
            log(fh, f"  vt[42] = 0x{q42:X} RVA=0x{rva(q42):X}")
            if ida_funcs.get_func(q42):
                decomp_full(q42, fh, "BSSkyShader vt[42]", max_lines=200)
            break

    # ============================================================
    # PART L — BSGeometry (BSTriShape) vt slots we might have missed.
    # Specifically find the "register geom" entry point — common
    # engine pattern: when geometry is attached/ready, it calls a
    # "register with render system" hook.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART L — BSTriShape vt[52] (UpdateControllers?) and vt[63-66]")
    log(fh, "=========================================")
    BSTRISHAPE_VT = IMG + 0x267E948
    for slot in [28, 30, 32, 40, 44, 46, 47, 48, 49, 50, 52, 56, 62, 63, 64, 65, 66]:
        q = ida_bytes.get_qword(BSTRISHAPE_VT + slot*8)
        fname = ida_funcs.get_func_name(q) or "?"
        log(fh, f"  BSTriShape vt[{slot}] = 0x{q:X} RVA=0x{rva(q):X}  {fname}")

    # ============================================================
    # PART M — EXACT disassembly of FogOfWar installer shader
    # install section. We want the byte-for-byte pattern.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART M — disasm-level FogOfWar shader install")
    log(fh, "=========================================")
    # Scan around 0x140373030 (the shader vtable+336 call site)
    start_scan = IMG + 0x372CC0
    end_scan = IMG + 0x373400
    ea = start_scan
    while ea < end_scan:
        if idc.print_insn_mnem(ea) == "call":
            dis = idc.generate_disasm_line(ea, 0)
            if "150h" in dis or "138h" in dis or "130h" in dis or "168h" in dis or "108h" in dis:
                log(fh, f"  0x{ea:X}: {dis}")
        ea = idc.next_head(ea, end_scan)

    log(fh, "\n==== END finalize pass ====")
    fh.close()
    ida_pro.qexit(0)


main()
