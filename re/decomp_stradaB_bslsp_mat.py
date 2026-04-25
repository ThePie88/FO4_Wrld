"""
decomp_stradaB_bslsp_mat.py  —  follow-up systematic scan

Follow-up: decomp the material-side functions that the bind_mat_texset
dispatches to via material.vt[+112], vt[+120], vt[+128].  Also dump
the BSLightingShaderMaterial vtable itself so we can identify those
three slots by name.

Also: trace `byte_143E488C0` — the flag that picks the 112/120 branch
vs the 128 branch inside bind_mat_texset.  Find WRITES (not just reads).
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_bslsp_mat_raw.txt"


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


def dump_vtable(fh, vtable_ea, label, slots=60):
    log(fh, f"\n==== VTABLE {label} @ 0x{vtable_ea:X} RVA 0x{rva(vtable_ea):X} ====")
    for i in range(slots):
        slot_ea = vtable_ea + 8 * i
        target = ida_bytes.get_qword(slot_ea)
        if target == 0:
            log(fh, f"  [{i:3d}] @0x{slot_ea:X}  = NULL")
            continue
        fn = ida_funcs.get_func(target)
        if not fn:
            log(fh, f"  [{i:3d}] @0x{slot_ea:X}  0x{target:X}  (not a func)")
            continue
        try:
            size = fn.end_ea - fn.start_ea
        except Exception:
            size = 0
        fn_name = ida_funcs.get_func_name(target) or "?"
        log(fh, f"  [{i:3d}] @0x{slot_ea:X}  0x{target:X}  RVA 0x{rva(target):X}  size=0x{size:X}  {fn_name}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== BSLSP material side — deep RE ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # -------------------------------------------------------------
    # sub_1421C5CE0 — local material ctor used by sub_1421C7770
    # sub_1421C5E30 — matching dtor
    # These plus sub_1421F9F00 are the material creation pipeline.
    # -------------------------------------------------------------
    log(fh, "\n== STEP 1 — material creation pipeline ==")
    decomp_full(IMG + 0x21C5CE0, fh, "BSLightingShaderMaterial::ctor sub_1421C5CE0", max_lines=350)
    decomp_full(IMG + 0x21C5E30, fh, "BSLightingShaderMaterial::dtor sub_1421C5E30", max_lines=300)
    decomp_full(IMG + 0x21C59B0, fh, "BSLightingShaderMaterialGlowmap?? sub_1421C59B0 (0x138 alloc)", max_lines=300)
    decomp_full(IMG + 0x21C20F0, fh, "sub_1421C20F0 (calls 21C59B0)", max_lines=250)
    decomp_full(IMG + 0x21C3B50, fh, "sub_1421C3B50 (calls 21C59B0)", max_lines=250)

    # -------------------------------------------------------------
    # byte_143E488C0 — who writes it? (the flag controlling bind branch)
    # -------------------------------------------------------------
    log(fh, "\n== STEP 2 — byte_143E488C0 flag writers ==")
    for xr in idautils.XrefsTo(IMG + 0x3E488C0, 0):
        fn = ida_funcs.get_func(xr.frm)
        fname = ida_funcs.get_func_name(xr.frm) if fn else "?"
        fea = fn.start_ea if fn else 0
        log(fh, f"  xref 0x{xr.frm:X} type={xr.type} in {fname} (RVA 0x{rva(fea):X})")
    seen = set()
    for xr in idautils.XrefsTo(IMG + 0x3E488C0, 0):
        fn = ida_funcs.get_func(xr.frm)
        if not fn or fn.start_ea in seen:
            continue
        seen.add(fn.start_ea)
        decomp_full(fn.start_ea, fh, f"byte_143E488C0-xref RVA 0x{rva(fn.start_ea):X}", max_lines=250)

    # -------------------------------------------------------------
    # BSLightingShaderMaterial vtable dump — find via RTTI string
    # -------------------------------------------------------------
    log(fh, "\n== STEP 3 — locate & dump BSLightingShaderMaterial vtable ==")
    target_rttis = [
        ".?AVBSLightingShaderMaterial@@",
        ".?AVBSLightingShaderMaterialBase@@",
        ".?AVBSShaderMaterial@@",
        ".?AVBSLightingShaderMaterialEnvmap@@",
        ".?AVBSLightingShaderMaterialGlowmap@@",
        ".?AVBSEffectShaderMaterial@@",
    ]
    for rtti in target_rttis:
        for s in idautils.Strings():
            try:
                v = str(s)
            except Exception:
                continue
            if v == rtti:
                log(fh, f"\n  RTTI '{rtti}' @ 0x{s.ea:X} RVA 0x{rva(s.ea):X}")
                # find COL (complete object locator) data that xrefs this:
                for xr in list(idautils.XrefsTo(s.ea, 0))[:4]:
                    log(fh, f"    xref mangled 0x{xr.frm:X}")
                    # walk the TypeDescriptor → locator → vtable
                break

    # Known: BSLightingShaderMaterial::`vftable' — IDA might know it by name.
    for nm in [
        "BSLightingShaderMaterial::`vftable'",
        "BSLightingShaderMaterialBase::`vftable'",
        "BSShaderMaterial::`vftable'",
        "BSLightingShaderMaterialEnvmap::`vftable'",
    ]:
        ea = ida_name.get_name_ea(idc.BADADDR, nm)
        if ea != idc.BADADDR:
            log(fh, f"\n  found '{nm}' @ 0x{ea:X} RVA 0x{rva(ea):X}")
            dump_vtable(fh, ea, nm, slots=45)

    # Brute-force: look for the three fn ptrs at offsets +112, +120, +128
    # the +0x70, +0x78, +0x80 slots of any material vtable. We can locate
    # the BSLightingShaderMaterial vtable by finding where sub_1421C5CE0
    # writes the vtable ptr during ctor init: `*(QWORD*)a1 = vtable`.
    # The decomp of sub_1421C5CE0 (above) will show the vtable store.

    # -------------------------------------------------------------
    # Try to locate material vtable via pattern: scan .rdata for arrays
    # of fn ptrs whose slot [0] points to a "RTTI-gated" material fn.
    # -------------------------------------------------------------
    # Simpler: dump candidate vtables by looking at xrefs to shader ctor
    # writes.  sub_1421C5CE0 likely has `mov [rbx], vtable_ea` — get the
    # immediate from the disasm.
    log(fh, "\n== STEP 4 — disasm sub_1421C5CE0 to extract vtable ptr ==")
    fn_ctor = ida_funcs.get_func(IMG + 0x21C5CE0)
    if fn_ctor:
        cur = fn_ctor.start_ea
        end = fn_ctor.end_ea
        count = 0
        while cur < end and count < 60:
            dis = idc.generate_disasm_line(cur, 0) or "?"
            log(fh, f"  0x{cur:X}  {dis}")
            cur = idc.next_head(cur, end)
            if cur == idc.BADADDR:
                break
            count += 1

    # -------------------------------------------------------------
    # BSLSP vt[42] = sub_1421718C0 (tiny 0x10 bytes) — likely property
    # attach shortcut. BSShaderProperty's "attach-to-geom" classic slot.
    # -------------------------------------------------------------
    log(fh, "\n== STEP 5 — BSLSP vt[42] + neighbours (ShaderProperty attach path) ==")
    decomp_full(IMG + 0x21718C0, fh, "BSLSP vt[42] sub_1421718C0 (tiny — attach?)", max_lines=100)
    decomp_full(IMG + 0x2172540, fh, "BSLSP vt[43] sub_142172540 (BIG — SetupGeometry?)", max_lines=600)
    decomp_full(IMG + 0x2173DE0, fh, "BSLSP vt[44] sub_142173DE0 (FinishSetupGeometry?)", max_lines=400)
    decomp_full(IMG + 0x2174150, fh, "BSLSP vt[45] sub_142174150 (unknown setup)", max_lines=300)
    decomp_full(IMG + 0x2174520, fh, "BSLSP vt[46] sub_142174520 (unknown)", max_lines=300)
    decomp_full(IMG + 0x21742F0, fh, "BSLSP vt[48] sub_1421742F0 (unknown)", max_lines=300)
    decomp_full(IMG + 0x2171C30, fh, "BSLSP vt[49] sub_142171C30 (unknown)", max_lines=250)
    decomp_full(IMG + 0x2174820, fh, "BSLSP vt[53] sub_142174820 (unknown)", max_lines=300)
    decomp_full(IMG + 0x2171B90, fh, "BSLSP vt[55] sub_142171B90 (unknown)", max_lines=250)
    decomp_full(IMG + 0x21724A0, fh, "BSLSP vt[61] sub_1421724A0 (unknown)", max_lines=250)

    # -------------------------------------------------------------
    # BSEffectShaderProperty vtable for comparison — from raw3 ctor
    # at RVA 0x216F9C0 we'd extract the vtable ptr the ctor installs.
    # -------------------------------------------------------------
    log(fh, "\n== STEP 6 — BSEffectShaderProperty vtable (for diff vs BSLSP) ==")
    fn_bseff = ida_funcs.get_func(IMG + 0x216F9C0)
    if fn_bseff:
        cur = fn_bseff.start_ea
        end = fn_bseff.end_ea
        count = 0
        bseff_vt = 0
        while cur < end and count < 60:
            dis = idc.generate_disasm_line(cur, 0) or "?"
            log(fh, f"  0x{cur:X}  {dis}")
            cur = idc.next_head(cur, end)
            if cur == idc.BADADDR:
                break
            count += 1
    # Also look for BSEffectShaderProperty vtable by RTTI name
    eff_ea = ida_name.get_name_ea(idc.BADADDR, "BSEffectShaderProperty::`vftable'")
    if eff_ea != idc.BADADDR:
        log(fh, f"  BSEffectShaderProperty vtable @ 0x{eff_ea:X} RVA 0x{rva(eff_ea):X}")
        dump_vtable(fh, eff_ea, "BSEffectShaderProperty::vftable", slots=65)

    # -------------------------------------------------------------
    # The key insight: who actually installs BSLSP via the Load flow?
    # sub_1421711F0 (BSLSP::LoadBinaryData / LoadTextures from NIF) does:
    #     sub_142161B10 re-resolve the material through the cache
    #     install texture-set on material+120
    #     call sub_1421C6870 with (material, shader+520, nullptr)  ← texset = null
    # Note the NULLPTR.  In OUR code path we pass the texset.  That means
    # we go DOWN the "v9 != a3" branch which installs `a3` into (material+120)
    # overwriting whatever was there.  If the material was the SHARED default
    # material, we have just corrupted the default.  See analysis below.
    # -------------------------------------------------------------
    log(fh, "\n== STEP 7 — path analysis confirmation ==")
    decomp_full(IMG + 0x160C10, fh, "sub_142160C10 (called by LoadTextures BSLSP)", max_lines=200)
    # sub_142170E60 (vt[26]) is "clone-from-template"
    decomp_full(IMG + 0x2170E60, fh, "BSLSP vt[26] sub_142170E60 (clone-from-template)", max_lines=300)
    # sub_1421710E0 vt[27] probably ClearProp
    decomp_full(IMG + 0x21710E0, fh, "BSLSP vt[27] sub_1421710E0", max_lines=300)

    # -------------------------------------------------------------
    # +0x208 = shader + 520 semantics: what does sub_1421711F0 pass?
    # `sub_1421C6870(..., a2 + 520, nullptr)` where a2 is the caller
    # NiStream/input context. So a2+520 is a BSStream state, NOT in the
    # shader. Yet our code passes `shader + 520` as a2. Let's verify by
    # reading caller context of sub_1421C6870.
    # -------------------------------------------------------------
    log(fh, "\n== STEP 8 — xrefs to sub_1421C6870 — check the 'a2' argument pattern ==")
    seen = set()
    for xr in idautils.XrefsTo(IMG + 0x21C6870, 0):
        fn = ida_funcs.get_func(xr.frm)
        if not fn or fn.start_ea in seen:
            continue
        seen.add(fn.start_ea)
        decomp_full(fn.start_ea, fh, f"caller of sub_1421C6870 RVA 0x{rva(fn.start_ea):X}", max_lines=300)
        if len(seen) >= 10:
            break

    log(fh, "\n==== END follow-up raw ====")
    fh.close()
    ida_pro.qexit(0)


main()
