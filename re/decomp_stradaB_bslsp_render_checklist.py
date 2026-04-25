"""
decomp_stradaB_bslsp_render_checklist.py

Mission: find the VANILLA BSLightingShaderProperty runtime-install sequence that
produces VISIBLE geometry. Compare to our install sequence and identify the
missing step(s) that prevent the cube from rendering.

Strategy:
  1. Find callers of sub_1421C6870 (bind_material_to_texset) — these are the
     shader→material binding sites.
  2. Find callers of sub_142171050 (BSLSP alloc wrapper) — these are fresh BSLSP
     allocation sites.
  3. Intersect: functions that call BOTH. Among those, prefer sites that ALSO
     call the GEO_BUILDER factory sub_14182FFD0 (runtime geometry, not NIF
     import) OR the AttachChild vtable slot 58.
  4. Dump their full decompile.
  5. Find the BSLSP vt[42] slot (shader-side AttachGeometry) — we suspect this
     is the missing call.
  6. Dump the BSLSP vtable + any "SetFlags"/init-state helpers likely called
     after ctor but before install.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_bslsp_render_raw.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=500):
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


def list_xrefs_to_fn(fh, label, fn_ea, max_entries=40):
    log(fh, f"\n==== xrefs TO {label} @ 0x{fn_ea:X} (RVA 0x{rva(fn_ea):X}) ====")
    seen_funcs = set()
    total = 0
    for xref in idautils.XrefsTo(fn_ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if not fn:
            continue
        key = fn.start_ea
        seen_funcs.add(key)
        fname = ida_funcs.get_func_name(key) or "?"
        log(fh, f"  caller @ 0x{xref.frm:X} in {fname} (fn RVA 0x{rva(key):X})")
        total += 1
        if total >= max_entries:
            break
    return seen_funcs


def get_callers(fn_ea):
    """Return set of caller function start EAs (unique)."""
    out = set()
    for xref in idautils.XrefsTo(fn_ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if not fn:
            continue
        out.add(fn.start_ea)
    return out


def dump_vtable(fh, vt_ea, label, count=67):
    log(fh, f"\n==== vtable {label} @ 0x{vt_ea:X} (RVA 0x{rva(vt_ea):X}) first {count} slots ====")
    for i in range(count):
        q = ida_bytes.get_qword(vt_ea + 8 * i)
        if q == 0:
            log(fh, f"  [{i:3d}] 0x{q:X}  NULL/END")
            break
        fname = ida_funcs.get_func_name(q) or "?"
        if not ida_funcs.get_func(q):
            log(fh, f"  [{i:3d}] 0x{q:X}  (not-a-func — possibly alignment) {fname}")
            continue
        log(fh, f"  [{i:3d}] 0x{q:X}  RVA=0x{rva(q):X}  {fname}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — BSLSP render checklist RE pass ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # --- primary RVAs ---
    BIND_FN        = IMG + 0x21C6870   # sub_1421C6870 bind_mat_texset
    BSLSP_NEW_FN   = IMG + 0x2171050   # sub_142171050 BSLSP alloc+ctor wrapper
    BSLSP_CTOR_FN  = IMG + 0x2171620   # sub_142171620 BSLSP in-place ctor
    TEX_LOAD_FN    = IMG + 0x217A910   # sub_14217A910 NiSourceTexture loader
    ATTACH_CHILD_FN = IMG + 0x16BE170  # NiNode::AttachChild
    GEO_BUILDER    = IMG + 0x182FFD0   # factory sub_14182FFD0
    BSLSP_VTABLE   = IMG + 0x28F9FF8   # per user's claim
    BSTRISHAPE_VT  = IMG + 0x267E948
    BSEFFECT_CTOR  = IMG + 0x216F9C0
    BSLSP_BIND_ARG2_OFF = 0x208

    # ============================================================
    # PART A — List all callers of sub_1421C6870 (bind_mat_texset)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART A — callers of sub_1421C6870 (bind_mat_texset)")
    log(fh, "=========================================")
    callers_bind = list_xrefs_to_fn(fh, "sub_1421C6870", BIND_FN, max_entries=80)

    # ============================================================
    # PART B — List all callers of sub_142171050 (BSLSP alloc wrapper)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART B — callers of sub_142171050 (BSLSP alloc)")
    log(fh, "=========================================")
    callers_alloc = list_xrefs_to_fn(fh, "sub_142171050", BSLSP_NEW_FN, max_entries=80)

    # ============================================================
    # PART B.2 — Callers of the BSLSP in-place ctor sub_142171620
    # (bypasses the alloc wrapper for some internal pathways)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART B.2 — callers of sub_142171620 (BSLSP in-place ctor)")
    log(fh, "=========================================")
    callers_ctor = list_xrefs_to_fn(fh, "sub_142171620", BSLSP_CTOR_FN, max_entries=80)

    # ============================================================
    # PART C — Intersections
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART C — intersection: functions that call BOTH BSLSP alloc AND bind")
    log(fh, "=========================================")
    combined_bslsp = callers_alloc | callers_ctor
    intersect = callers_bind & combined_bslsp
    log(fh, f"  callers_bind     count = {len(callers_bind)}")
    log(fh, f"  combined_bslsp   count = {len(combined_bslsp)}")
    log(fh, f"  intersection     count = {len(intersect)}")
    for e in sorted(intersect):
        fname = ida_funcs.get_func_name(e) or "?"
        log(fh, f"    0x{e:X}  {fname}  (RVA 0x{rva(e):X})")

    # ============================================================
    # PART D — For each intersecting caller, also check if they call:
    #   - geo_builder (sub_14182FFD0)   → runtime geometry
    #   - NiNode::AttachChild           → scene attach
    #   - sub_14216ED10 (texset ctor)
    #   - sub_1421627B0 (texset SetTexturePath)
    # and decomp the ones that do.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART D — qualifying intersections (call geo_builder OR AttachChild too)")
    log(fh, "=========================================")
    TEXSET_CTOR_FN = IMG + 0x216ED10
    TEXSET_SET_PATH_FN = IMG + 0x21627B0

    def fn_calls(caller_ea, callee_ea):
        """True if caller_ea directly calls callee_ea anywhere."""
        fn = ida_funcs.get_func(caller_ea)
        if not fn:
            return False
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            if idc.print_insn_mnem(head) in ("call", "jmp"):
                tgt = idc.get_operand_value(head, 0)
                if tgt == callee_ea:
                    return True
        return False

    qualified = []
    for caller in intersect:
        flags = []
        if fn_calls(caller, GEO_BUILDER):
            flags.append("geo_builder")
        if fn_calls(caller, ATTACH_CHILD_FN):
            flags.append("attach_child")
        if fn_calls(caller, TEXSET_CTOR_FN):
            flags.append("texset_ctor")
        if fn_calls(caller, TEXSET_SET_PATH_FN):
            flags.append("texset_setpath")
        if fn_calls(caller, TEX_LOAD_FN):
            flags.append("tex_load")
        qualified.append((caller, flags))

    log(fh, f"  Qualified set (score by flag count):")
    qualified.sort(key=lambda p: (-len(p[1]), p[0]))
    for ea, flags in qualified:
        fname = ida_funcs.get_func_name(ea) or "?"
        log(fh, f"    0x{ea:X} RVA=0x{rva(ea):X}  {fname}   [{', '.join(flags)}]")

    # ============================================================
    # PART E — FULL DECOMP the best 3 intersecting callers.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART E — Full decomp of best intersecting callers")
    log(fh, "=========================================")
    for ea, flags in qualified[:4]:
        fname = ida_funcs.get_func_name(ea) or "?"
        decomp_full(ea, fh, f"INTERSECTING CALLER {fname} flags={flags}", max_lines=800)

    # ============================================================
    # PART F — BSLightingShaderProperty vtable dump.
    # Find "AttachGeometry" candidate slot — the BSEffectShader variant
    # has vt[42] for this; see if BSLSP has the same.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART F — BSLightingShaderProperty vtable")
    log(fh, "=========================================")
    dump_vtable(fh, BSLSP_VTABLE, "BSLightingShaderProperty", count=80)

    # ============================================================
    # PART G — decomp vt[42] of BSLSP (claimed AttachGeometry)
    # + the bind wrapper alternative sub_1421711F0 (BSLSP LoadTextures)
    # + sub_1421C6690 (complementary load-textures)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART G — BSLSP vt[42] + install helpers")
    log(fh, "=========================================")
    bslsp_vt_42 = ida_bytes.get_qword(BSLSP_VTABLE + 42 * 8)
    log(fh, f"  BSLSP vt[42] = 0x{bslsp_vt_42:X} RVA=0x{rva(bslsp_vt_42):X}")
    if ida_funcs.get_func(bslsp_vt_42):
        decomp_full(bslsp_vt_42, fh, "BSLSP::vt[42] (AttachGeometry?)", max_lines=200)

    # Also dump vt[41] (previous slot — FogOfWar uses vt[42] on effect shader)
    bslsp_vt_41 = ida_bytes.get_qword(BSLSP_VTABLE + 41 * 8)
    log(fh, f"  BSLSP vt[41] = 0x{bslsp_vt_41:X} RVA=0x{rva(bslsp_vt_41):X}")
    if ida_funcs.get_func(bslsp_vt_41):
        decomp_full(bslsp_vt_41, fh, "BSLSP::vt[41]", max_lines=200)

    # BSLSP LoadTextures helper (known RVA from dossier).
    decomp_full(IMG + 0x21711F0, fh, "sub_1421711F0 (BSLSP LoadTextures wrapper)", max_lines=200)
    decomp_full(IMG + 0x21C6690, fh, "sub_1421C6690 (complementary load)", max_lines=200)

    # ============================================================
    # PART H — Check sub_1421792E0 — startup init that registers
    # "BSLightingShaderProperty" as a shader-type factory entry.
    # This shows the expected type-identifier for runtime alloc.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART H — sub_1421792E0 (startup shader registration)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x21792E0, fh, "sub_1421792E0", max_lines=600)

    # ============================================================
    # PART I — Specific candidate: FogOfWarOverlay installer
    # sub_140372CC0 — uses BSEffectShader (not BSLSP) but IS the
    # canonical "runtime runtime factory → attach to scene" pattern
    # that results in a VISIBLE rendered geometry. We need the full
    # decomp and then diff against our current code.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART I — FogOfWarOverlay installer (sub_140372CC0) — canonical template")
    log(fh, "=========================================")
    decomp_full(IMG + 0x372CC0, fh, "sub_140372CC0 FogOfWarOverlay installer", max_lines=1200)

    # Full decomp of Moon (sub_1406B60C0) — uses BSSkyShaderProperty
    # which is another visible runtime install template.
    decomp_full(IMG + 0x6B60C0, fh, "sub_1406B60C0 Moon installer", max_lines=800)

    # ============================================================
    # PART J — sub_1406BF310 — explicitly loads textures into an
    # arbitrary slot. It's a direct user of sub_14217A910 and may
    # show a BSLSP-like install path.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART J — sub_1406BF310 (direct texture slot install)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x6BF310, fh, "sub_1406BF310", max_lines=400)

    # ============================================================
    # PART K — find "Pipboy world" / "workshop" BSLSP install sites
    # by looking for specific callers that cross-reference
    # PipBoy-related strings AND BSLSP_NEW_FN.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART K — sub_1421718E0 (possibly BSLSP facade) + sub_142170640 (alt)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x21718E0, fh, "sub_1421718E0 BSLSP facade", max_lines=300)
    decomp_full(IMG + 0x2170640, fh, "sub_142170640 BSLSP alt install", max_lines=300)
    decomp_full(IMG + 0x2170E60, fh, "sub_142170E60 BSLSP template init", max_lines=300)

    # ============================================================
    # PART L — sub_142161B10 (the setup fn called from every shader ctor)
    # — it installs default material. We want to know WHAT the default
    # material holds (does it have draw-ready defaults?)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART L — sub_142161B10 (shader material init)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x2161B10, fh, "sub_142161B10", max_lines=300)
    decomp_full(IMG + 0x21F9F00, fh, "sub_1421F9F00 (material cache lookup)", max_lines=300)

    # ============================================================
    # PART M — BSLSP ctor itself
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART M — BSLSP ctor sub_142171620")
    log(fh, "=========================================")
    decomp_full(BSLSP_CTOR_FN, fh, "sub_142171620 BSLSP ctor", max_lines=400)

    # ============================================================
    # PART N — find anywhere that writes BSLSP into BSGeometry+0x138
    # (shaderProperty slot). This is the missing "AttachGeometry"
    # equivalent if it's a helper function.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART N — xrefs to BSLightingShaderProperty::vftable")
    log(fh, "=========================================")
    xc = 0
    for xref in idautils.XrefsTo(BSLSP_VTABLE, 0):
        fn = ida_funcs.get_func(xref.frm)
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        fn_rva = rva(fn.start_ea) if fn else 0
        log(fh, f"  xref from 0x{xref.frm:X} in {fname} (fn RVA 0x{fn_rva:X})")
        xc += 1
        if xc > 40:
            break

    # ============================================================
    # PART O — Search for shader-install helpers that specifically
    # write to offset +0x138 (BSGEOM_SHADERPROP_OFF). Any fn that does
    # "mov [r+138], shader" IS our install helper.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART O — find writes to BSGeometry+0x138 (shaderProperty slot)")
    log(fh, "=========================================")
    # Scan for immediate "138h" in instructions that's likely a shaderProp write.
    # This is slower; cap to first 40 hits.
    n = 0
    max_scan = 40
    seg_start = IMG
    seg_end = IMG + 0x5000000
    ea = seg_start
    while ea < seg_end and n < max_scan:
        ea = idc.find_text(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT, 0, 0, "+138h")
        if ea == idc.BADADDR or ea >= seg_end:
            break
        if idc.print_insn_mnem(ea) == "mov":
            dis = idc.generate_disasm_line(ea, 0)
            fn = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(ea) or "?"
            fn_rva = rva(fn.start_ea) if fn else 0
            log(fh, f"  0x{ea:X} in {fname} (fn RVA 0x{fn_rva:X}): {dis}")
            n += 1
        ea = idc.next_head(ea)

    # ============================================================
    # PART P — Specifically confirm the "+0x138" writes in vanilla
    # install code by reading known candidate functions:
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART P — shader-install helper candidates")
    log(fh, "=========================================")
    # sub_1406B60C0 Moon → textured sky geom (USES BSSkyShaderProperty)
    # sub_14057B4A0 "SetShaderPropertyOnGeom"? — generic shader-to-geom
    for candidate_rva in [0x57B4A0, 0x57B5E0, 0x57B730]:
        try:
            decomp_full(IMG + candidate_rva, fh, f"sub at RVA 0x{candidate_rva:X}", max_lines=120)
        except Exception:
            pass

    log(fh, "\n==== END pass ====")
    fh.close()
    ida_pro.qexit(0)


main()
