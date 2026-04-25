"""
decomp_stradaB_bslsp_activation.py

SYSTEMATIC investigation: why doesn't our injected BSLightingShaderProperty
(with texset + bind_mat_texset + installed in cube+0x138) actually render?

Targets:
  1) Deep decompile sub_1421C6870 (bind_mat_texset) AND its callees
     that handle the 10-slot loop AND vtable[+112] (GetTextures) /
     vtable[+120] / vtable[+128] (the 3 material methods it dispatches to).
  2) BSLightingShaderProperty vtable @ 0x28F9FF8 — dump 80 slots with names.
  3) BSLightingShaderMaterialBase ctor via sub_142161B10 + sub_1421F9F00
     (the cached material resolver the ctor goes through). Trace:
       - default material global qword_143E488C8: is it init at startup?
       - the material's own layout + state flags
       - when BSLSP::ctor calls sub_142161B10 with the default material:
         does *a1[11] (material ptr) end up non-null + valid?
  4) BSBatchRenderer accumulation side — who calls shader.vt[X] to query
     "does this geometry contribute to render"?  Decompile vt[4]
     (Dispatch/SetPass) of BSBatchRenderer @ 0x221BC90 and vt[9] FlushBatch
     at 0x221C1B0. See who reads BSLSP+0x208 (the arg2 area of bind fn)
     and BSLSP material flags.
  5) Compare BSLSP vtable vs BSEffectShader vtable slot-by-slot.
  6) Find sub_142161950 (called with 22,31,32 from BSLSP::ctor) — this is
     a flag setter and might hold the "ready for render" bit.

Output: stradaB_bslsp_activation_raw.txt
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_bslsp_activation_raw.txt"


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


def dump_vtable(fh, vtable_ea, label, slots=80):
    log(fh, f"\n==== VTABLE {label} @ 0x{vtable_ea:X} RVA 0x{rva(vtable_ea):X} ====")
    for i in range(slots):
        slot_ea = vtable_ea + 8 * i
        target = ida_bytes.get_qword(slot_ea)
        if target == 0:
            log(fh, f"  [{i:3d}] @0x{slot_ea:X}  = NULL")
            continue
        fn = ida_funcs.get_func(target)
        if not fn:
            # likely end of vtable OR non-func data
            log(fh, f"  [{i:3d}] @0x{slot_ea:X}  0x{target:X}  (not a func)")
            continue
        try:
            size = fn.end_ea - fn.start_ea
        except Exception:
            size = 0
        fn_name = ida_funcs.get_func_name(target) or "?"
        log(fh, f"  [{i:3d}] @0x{slot_ea:X}  0x{target:X}  RVA 0x{rva(target):X}  size=0x{size:X}  {fn_name}")


def xrefs_to_addr(fh, ea, label, limit=40):
    log(fh, f"\n==== xrefs to {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) ====")
    results = []
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        fn_start = fn.start_ea if fn else 0
        fn_rva = rva(fn_start) if fn_start else 0
        log(fh, f"  xref from 0x{xref.frm:X} in {fname} (func @ 0x{fn_start:X} RVA 0x{fn_rva:X}) type={xref.type}")
        results.append((xref.frm, fn_start))
        if len(results) >= limit:
            break
    return results


def sym(name):
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea if ea != idc.BADADDR else 0


def dump_qword(fh, label, ea):
    try:
        q = ida_bytes.get_qword(ea)
        log(fh, f"  {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) = 0x{q:X}")
    except Exception as e:
        log(fh, f"  {label} @ 0x{ea:X} — read failed: {e}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== BSLSP-activation systematic RE (raw) ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # --------------------------------------------------------------------
    # STEP 0 — globals inspection (default material + singletons)
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 0 — global pointer inspection")
    log(fh, "=========================================")
    dump_qword(fh, "qword_143E488C8 (BSLSP default material)",       IMG + 0x3E488C8)
    dump_qword(fh, "qword_1431E5320 (material cache singleton)",     IMG + 0x31E5320)
    dump_qword(fh, "qword_1430DD7F8 (ITextureDB singleton)",         IMG + 0x30DD7F8)
    dump_qword(fh, "qword_143D709A8 (error texture default)",        IMG + 0x3D709A8)
    dump_qword(fh, "qword_143D709B0 (normal texture default)",       IMG + 0x3D709B0)
    dump_qword(fh, "qword_143D70978 (special texture default)",      IMG + 0x3D70978)
    dump_qword(fh, "byte_143E488C0 (material-ready flag)",           IMG + 0x3E488C0)
    dump_qword(fh, "qword_143E5ACF0 (BSEffect material global)",     IMG + 0x3E5ACF0)

    # --------------------------------------------------------------------
    # STEP 1 — deep decomp of sub_1421C6870 and its dispatched callees
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 1 — sub_1421C6870 (bind_mat_texset) — deep")
    log(fh, "=========================================")
    BIND_MAT_TEXSET = IMG + 0x21C6870
    decomp_full(BIND_MAT_TEXSET, fh, "sub_1421C6870 (bind_mat_texset) re-decomp", max_lines=400)

    # Disasm the key area where the vtable dispatches happen (+112,+120,+128)
    log(fh, "\n-- disasm of key dispatch region --")
    fn = ida_funcs.get_func(BIND_MAT_TEXSET)
    if fn:
        cur = fn.start_ea
        end = fn.end_ea
        count = 0
        while cur < end and count < 300:
            dis = idc.generate_disasm_line(cur, 0) or "?"
            log(fh, f"  0x{cur:X}  {dis}")
            cur = idc.next_head(cur, end)
            if cur == idc.BADADDR:
                break
            count += 1

    # --------------------------------------------------------------------
    # STEP 2 — BSLSP vtable dump (0x28F9FF8)
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 2 — BSLSP vtable @ RVA 0x28F9FF8")
    log(fh, "=========================================")
    BSLSP_VTABLE = IMG + 0x28F9FF8
    dump_vtable(fh, BSLSP_VTABLE, "BSLightingShaderProperty::vftable", slots=80)

    # We also care about the BSEffectShaderProperty vtable for comparison.
    # From raw3: &BSEffectShader::`vftable' isn't BSEffectShaderProperty —
    # need the PROPERTY one. Scan RTTI for ".?AVBSEffectShaderProperty@@".
    log(fh, "\n-- scanning for BSEffectShaderProperty RTTI/vtable --")
    for s in idautils.Strings():
        try:
            v = str(s)
        except Exception:
            continue
        if v == ".?AVBSEffectShaderProperty@@":
            log(fh, f"  RTTI @ 0x{s.ea:X} (RVA 0x{rva(s.ea):X})")
            # walk a few xrefs looking for a COL → vftable
            for xr in list(idautils.XrefsTo(s.ea, 0))[:6]:
                log(fh, f"    xref to mangled @ 0x{xr.frm:X} RVA 0x{rva(xr.frm):X}")
    # Also try by name (IDA may have resolved it)
    for nm in [
        "BSEffectShaderProperty::`vftable'",
        "BSLightingShaderProperty::`vftable'",
        "BSShaderProperty::`vftable'",
        "BSLightingShaderMaterialBase::`vftable'",
        "BSLightingShaderMaterial::`vftable'",
        "BSShaderMaterial::`vftable'",
    ]:
        ea = sym(nm)
        log(fh, f"  sym '{nm}' ea=0x{ea:X} RVA 0x{(rva(ea) if ea else 0):X}")
        if ea and "ShaderProperty" in nm:
            dump_vtable(fh, ea, nm, slots=80)
        if ea and "Material" in nm:
            dump_vtable(fh, ea, nm, slots=45)

    # --------------------------------------------------------------------
    # STEP 3 — BSLSP ctor re-decomp and all the helpers it calls
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 3 — BSLSP ctor re-decomp + helpers")
    log(fh, "=========================================")
    decomp_full(IMG + 0x2171620, fh, "BSLSP::ctor (sub_142171620)", max_lines=250)
    decomp_full(IMG + 0x2161B10, fh, "BSShaderProperty::init (sub_142161B10)", max_lines=300)
    decomp_full(IMG + 0x2161950, fh, "shader flag setter (sub_142161950) — called w/ 22,31,32", max_lines=200)
    decomp_full(IMG + 0x2160DA0, fh, "shader-ctor sanity (sub_142160DA0)", max_lines=200)
    decomp_full(IMG + 0x21F9F00, fh, "material cache resolver (sub_1421F9F00) — q_1431E5320 lookup", max_lines=300)
    decomp_full(IMG + 0x21FA3B0, fh, "material cache release (sub_1421FA3B0)", max_lines=200)

    # Who READS/INITIALIZES qword_143E488C8 (default BSLSP material)?
    log(fh, "\n-- xrefs to qword_143E488C8 (default BSLSP material global) --")
    xrefs_to_addr(fh, IMG + 0x3E488C8, "qword_143E488C8", limit=30)
    # Find WRITES specifically (type=1 is data-read in hex; 5 is write, 2 is offset ref)
    # decomp each xref'ing function
    seen = set()
    for xr in idautils.XrefsTo(IMG + 0x3E488C8, 0):
        fn = ida_funcs.get_func(xr.frm)
        if not fn:
            continue
        if fn.start_ea in seen:
            continue
        seen.add(fn.start_ea)
        decomp_full(fn.start_ea, fh, f"xref-to-defaultmat @ RVA 0x{rva(fn.start_ea):X}", max_lines=300)
        if len(seen) >= 6:
            break

    # byte_143E488C0 (the flag checked inside bind_mat_texset)
    log(fh, "\n-- xrefs to byte_143E488C0 (material-ready flag; controls 112/120 vs 128 branch) --")
    xrefs_to_addr(fh, IMG + 0x3E488C0, "byte_143E488C0", limit=30)

    # --------------------------------------------------------------------
    # STEP 4 — Material (BSLightingShaderMaterialBase) — who creates it?
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 4 — Material layout + flags")
    log(fh, "=========================================")
    # sub_1421F9F00 is the cache resolver; its callees do the ctor
    # Also look at sub_1421C59B0 (referenced from raw3 §3 for 0x138-byte sizes ???)
    # sub_1421C7770 + sub_1421C77D0 reference default material (from raw3 §F)
    decomp_full(IMG + 0x21C6690, fh, "BSLSP::LoadTextures companion (sub_1421C6690)", max_lines=300)
    decomp_full(IMG + 0x21711F0, fh, "BSLSP::LoadTexturesFromFile (sub_1421711F0)", max_lines=300)
    decomp_full(IMG + 0x21C7770, fh, "bslsp-deflt-mat xref sub_1421C7770", max_lines=300)
    decomp_full(IMG + 0x21C77D0, fh, "bslsp-deflt-mat xref sub_1421C77D0", max_lines=300)

    # --------------------------------------------------------------------
    # STEP 5 — BSBatchRenderer slots that TOUCH a BSLSP
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 5 — BSBatchRenderer render-side consumers of BSLSP")
    log(fh, "=========================================")
    # vt[4] Dispatch/SetPass — 0x221BC90
    decomp_full(IMG + 0x221BC90, fh, "BSBatchRenderer::Dispatch (vt4) (sub_1421BC90)", max_lines=700)
    # vt[9] FlushBatch — 0x221C1B0 (very big)
    decomp_full(IMG + 0x221C1B0, fh, "BSBatchRenderer::FlushBatch (vt9) (sub_1421C1B0) — first 500 lines", max_lines=500)
    # vt[5] EndPass
    decomp_full(IMG + 0x221C030, fh, "BSBatchRenderer::EndPass (vt5) (sub_1421C030)", max_lines=250)

    # The scene walker that accumulates visible shapes:
    decomp_full(IMG + 0x1F2D60, fh, "per-cell submit fn sub_1421F2D60 (typo'd RVA?)", max_lines=400)
    decomp_full(IMG + 0x21F2D60, fh, "per-cell submit fn sub_1421F2D60 (real)", max_lines=400)

    # --------------------------------------------------------------------
    # STEP 6 — find where the scene walker reads +0x138 and calls BSLSP vt
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 6 — accumulator: who calls BSLSP vtable methods")
    log(fh, "=========================================")
    # Search for a unique BSLSP vtable slot to find its callers.
    # Pick vt[~25-35] entries and xref-back to locate the "ask shader to contribute" site.
    log(fh, "\n-- sampling mid-vtable BSLSP slots and their xrefs --")
    for slot_idx in [1, 2, 7, 8, 9, 11, 12, 13, 14, 19, 20, 26, 27, 28, 29, 30, 31, 32, 33, 42, 43, 44, 45, 46, 47, 48, 49, 50]:
        slot_ea = BSLSP_VTABLE + 8 * slot_idx
        target  = ida_bytes.get_qword(slot_ea)
        if target == 0:
            continue
        fn = ida_funcs.get_func(target)
        sz = fn.end_ea - fn.start_ea if fn else 0
        nm = ida_funcs.get_func_name(target) or "?"
        log(fh, f"  slot[{slot_idx:2d}] -> 0x{target:X} RVA 0x{rva(target):X} size=0x{sz:X} {nm}")
        # Get a few callers of this slot (from the vtable slot itself = readers of the fn ptr)
        cnt = 0
        for xr in idautils.XrefsTo(slot_ea, 0):
            cf = ida_funcs.get_func(xr.frm)
            cfn = ida_funcs.get_func_name(xr.frm) or "?"
            cea = cf.start_ea if cf else 0
            log(fh, f"      read from 0x{xr.frm:X} in {cfn} (RVA 0x{rva(cea):X})")
            cnt += 1
            if cnt >= 4:
                break

    # --------------------------------------------------------------------
    # STEP 7 — scene_submit: check how +0x138 is DEREFERENCED at render time
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 7 — scene walkers that READ shape+0x138")
    log(fh, "=========================================")
    # Full scene walker sub_140C38F80 (from render_pipeline_report.txt)
    decomp_full(IMG + 0xC38F80, fh, "3D scene walker sub_140C38F80", max_lines=500)
    # Pre-setup fn sub_140C38910
    decomp_full(IMG + 0xC38910, fh, "3D scene context sub_140C38910", max_lines=500)

    # The accumulator that sub_1421F2D60 uses
    # Let's find a function that reads *(qword*)(shape+0x138) to dispatch
    # Scan .text for "mov rax, [rXX+138h]"  sequences that lead to a vtable call.
    log(fh, "\n-- scanning for shape+0x138 reads (sample 80) --")
    # This is slow, so we iterate names instead.

    # --------------------------------------------------------------------
    # STEP 8 — find the BSLSP render / setup hook
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 8 — BSLightingShader (not Property) setup fn")
    log(fh, "=========================================")
    # BSLightingShader ctor at RVA 0x22321F0 (from raw3 §H)
    # Its vt[X] has "SetupGeometry" which reads material state.
    decomp_full(IMG + 0x22321F0, fh, "BSLightingShader::ctor sub_1422321F0", max_lines=250)
    # scan its vtable — find RTTI anchor
    for s in idautils.Strings():
        try:
            v = str(s)
        except Exception:
            continue
        if v == ".?AVBSLightingShader@@":
            log(fh, f"\n  BSLightingShader RTTI @ 0x{s.ea:X} RVA 0x{rva(s.ea):X}")
            break

    # --------------------------------------------------------------------
    # STEP 9 — dump material vtable contents around 112,120,128 entries
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 9 — the material vtable used by bind_mat_texset")
    log(fh, "=========================================")
    # bind_mat_texset does: (*(material->vtable + 112))(a1, v16, v10)
    # then                  (*(material->vtable + 120))(a1, v10, v16)
    # else-branch:          (*(material->vtable + 128))(a1, v10)
    # 112/8 = slot 14, 120/8 = slot 15, 128/8 = slot 16
    # The material ptr here is `a1` = the material object (shader+0x58).
    # BUT its vtable is different from BSLSP's. It is the MaterialBase vtable.
    # Let's find it by decompiling sub_1421F9F00 (which allocates/returns a
    # BSLightingShaderMaterialBase ptr) and tracing what it assigns as vtable.

    # Also look at the 10-slot texture iteration
    decomp_full(IMG + 0x16A7040, fh, "tex-check helper sub_1416A7040 (inside bind loop)", max_lines=200)
    decomp_full(IMG + 0x60CA00, fh, "tex-handle registration sub_14060CA00", max_lines=250)

    # sub_1421626D0 — BSShaderTextureSet::LoadTextureIntoSlot (vt[43])
    decomp_full(IMG + 0x21626D0, fh, "BSShaderTextureSet::LoadTextureIntoSlot (vt[43], sub_1421626D0)", max_lines=300)

    # --------------------------------------------------------------------
    # STEP 10 — double-check: find xrefs to shader+0x58/material ptr and +0x208
    # --------------------------------------------------------------------
    log(fh, "\n=========================================")
    log(fh, "  STEP 10 — shader+0x58 and shader+0x208 semantics")
    log(fh, "=========================================")
    # shader+0x208 from M1 texture dossier = "a2" in sub_1421C6870.
    # Inside the ctor sub_142171620 we see writes to +112, +120, +128, +144, +152, +160, +168, +176.
    # 0x208 = 520. The ctor writes +168, +176 and then the sub_142161B10 call.
    # Let's just find any fn that reads shader+0x208:
    # Scan sub_1421C6870 — the `a2` (shader+520) is only forwarded; we need
    # to look INSIDE the material's vt[112] / vt[120] to see if they dereference it.
    # Dump sub_14216ED10 for the texture-set ctor:
    decomp_full(IMG + 0x216ED10, fh, "BSShaderTextureSet::ctor sub_14216ED10", max_lines=250)
    decomp_full(IMG + 0x21625A0, fh, "BSShaderTextureSet::ctor alt sub_1421625A0", max_lines=200)
    decomp_full(IMG + 0x21626B0, fh, "BSShaderTextureSet::GetTexturePath vt[41]", max_lines=150)
    decomp_full(IMG + 0x2162690, fh, "BSShaderTextureSet::GetTextureSlot vt[40]", max_lines=150)
    decomp_full(IMG + 0x21627B0, fh, "BSShaderTextureSet::SetTexturePath vt[44]", max_lines=150)

    log(fh, "\n==== END BSLSP activation raw ====")
    fh.close()
    ida_pro.qexit(0)


main()
