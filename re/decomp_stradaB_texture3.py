"""
decomp_stradaB_texture3.py — final focused pass

We now know:
  - sub_14217A910(char *path, char a2, void **out_slot, char a4, char a5, char a6)
    writes a texture handle into *out_slot.
  - Callees: sub_1417A4540(path)  — preload/reference
             sub_1417A3540(path, qword_from_sub_1416C99E0, 0, a5, a6) — load with queue

  - qword_143D709A8  (default "error" texture handle)
  - qword_143D709B0  (default "normal" texture handle)
  - qword_143D70978  (another default — for a4==1 flag)

  - BSShaderTextureSet:
      alloc size 0x60
      vtable @ RVA 0x24A7030
      layout:
        +0x00 vtable
        +0x08 NiObjectNET base (inc refcount, name, etc)
        +0x10..+0x58 10 * BSFixedString (8 bytes each) for paths
        (possibly some tail data)
      vtable[44] @ offset 352 = "SetTexturePath(index, path)"
      vtable[41] @ offset 328 = "GetTexturePath(index)"

Goals:
  1) Decomp sub_1417A4540 and sub_1417A3540 fully — see if they're BSTextureDB
     entry points. Find where they look up the archive.
  2) Find callers of sub_14217A910 that INSTALL its output into a shader
     slot of a freshly-allocated BSEffectShaderProperty — that's our
     implementation template.
  3) Decomp sub_1421C6870 (the "bind TextureSet to material" fn called by
     sub_1421711F0 which was a BSLightingShaderProperty setup variant).
  4) Dump vtable[44] (RVA 0x161650 — we need to verify — stored at
     vtable_ea + 8*44) for BSShaderTextureSet = the SetTexturePath fn.
  5) Look for the "BSLightingShaderProperty setup with path" pattern —
     find a function that allocates BSLightingShaderProperty, allocates
     a BSShaderTextureSet, writes paths, and installs into geometry.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_texture_raw3.txt"


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


def dump_vtable_tail(fh, vt_ea, label, start=32, entries=32):
    log(fh, f"\n-- vtable tail {label} @ 0x{vt_ea:X} (RVA 0x{rva(vt_ea):X}) entries {start}..{start+entries-1} --")
    for i in range(start, start + entries):
        q = ida_bytes.get_qword(vt_ea + 8 * i)
        if q == 0:
            log(fh, f"  [{i:3d}] 0x{q:X}  NULL/END")
            break
        fname = ida_funcs.get_func_name(q) or "?"
        if not ida_funcs.get_func(q):
            log(fh, f"  [{i:3d}] 0x{q:X}  (not-a-func or end of vtable) {fname}")
            # might just be alignment data
            continue
        log(fh, f"  [{i:3d}] 0x{q:X}  RVA=0x{rva(q):X}  {fname}  (offset 0x{i*8:X})")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — Texture API dossier pass 3 ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # === PART A — texture loader callees ===
    log(fh, "\n=========================================")
    log(fh, "  PART A — sub_14217A910 callees")
    log(fh, "=========================================")
    FUNCS = [
        (0x1417A4540, "sub_1417A4540 (preload path)"),
        (0x1417A3540, "sub_1417A3540 (load with queue)"),
        (0x1416C99E0, "sub_1416C99E0 (returns some global int)"),
        (0x1421C6870, "sub_1421C6870 (bind TextureSet to material)"),
        (0x14167D900, "sub_14167D900 (fixedstring intern)"),
        (0x1416BAB90, "sub_1416BAB90 (NiObjectNET ctor)"),
        (0x1416DE030, "sub_1416DE030 (lookup fn)"),
        (0x1416DE200, "sub_1416DE200 (register, called with 'BSLightingShaderProperty')"),
    ]
    for ea, lbl in FUNCS:
        decomp_full(ea, fh, lbl, max_lines=300)

    # === PART B — BSShaderTextureSet vtable tail ===
    log(fh, "\n=========================================")
    log(fh, "  PART B — BSShaderTextureSet vtable tail (slots 32..63)")
    log(fh, "=========================================")
    dump_vtable_tail(fh, IMG + 0x24A7030, "BSShaderTextureSet vtable", start=32, entries=32)

    # === PART C — Decomp the SetTexturePath slot (vtable[44], offset 0x160) ===
    # Read the qword at vtable_ea + 352.
    log(fh, "\n=========================================")
    log(fh, "  PART C — SetTexturePath/GetTexturePath slots")
    log(fh, "=========================================")
    for slot in (40, 41, 42, 43, 44, 45, 46):
        q = ida_bytes.get_qword(IMG + 0x24A7030 + 8 * slot)
        log(fh, f"\n  vtable[{slot}] (offset 0x{slot*8:X}) = 0x{q:X} RVA=0x{rva(q):X}")
        if q and ida_funcs.get_func(q):
            decomp_full(q, fh, f"BSShaderTextureSet::vtable[{slot}]", max_lines=200)

    # === PART D — Texture preload fn sub_1417A4540 surroundings ===
    # Find its callers and see if there's a simpler "load" API that returns
    # the handle as a value (not via out-slot).
    log(fh, "\n=========================================")
    log(fh, "  PART D — callers of sub_1417A4540")
    log(fh, "=========================================")
    for xref in list(idautils.XrefsTo(IMG + 0x1417A4540 - IMG + IMG, 0))[:30]:
        fn = ida_funcs.get_func(xref.frm)
        fn_start = fn.start_ea if fn else 0
        fn_rva = rva(fn_start) if fn_start else 0
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        log(fh, f"  caller @ 0x{xref.frm:X} in {fname} fn=0x{fn_start:X} RVA=0x{fn_rva:X}")

    # === PART E — The ITextureDB vtable entry slots (loaders) ===
    # vtable[0] = sub_1417A6620, vtable[13] = sub_1417B3090, etc.
    # Check vtable[0]'s decomp — it could be the ctor or could be "Load".
    # Also look at sub_1417A6500 (vtable[5]) — good candidate for "Get handle from path".
    log(fh, "\n=========================================")
    log(fh, "  PART E — ITextureDB vtable slots decomp")
    log(fh, "=========================================")
    for ea, lbl in [
        (0x1417A6620, "ITextureDB::vt[0] (sub_1417A6620)"),
        (0x1417A6500, "ITextureDB::vt[5] (sub_1417A6500 — CreateTexture?)"),
        (0x1417A6F90, "ITextureDB::vt[6] (sub_1417A6F90)"),
        (0x1417A7600, "ITextureDB::vt[7] (sub_1417A7600)"),
        (0x1417A7270, "ITextureDB::vt[8] (sub_1417A7270)"),
        (0x1417A7280, "ITextureDB::vt[9] (sub_1417A7280)"),
        (0x1417A8EE0, "ITextureDB::vt[10] (sub_1417A8EE0)"),
        (0x1417A3540, "vt-callee (sub_1417A3540 — loaded queue)"),
        (0x1417A4540, "vt-callee (sub_1417A4540 — preload)"),
    ]:
        decomp_full(ea, fh, lbl, max_lines=250)

    # === PART F — singletons & globals holding defaults ===
    log(fh, "\n=========================================")
    log(fh, "  PART F — default texture globals")
    log(fh, "=========================================")
    for g, lbl in [
        (0x143D709A8, "qword_143D709A8 (default error texture)"),
        (0x143D709B0, "qword_143D709B0 (default normal texture)"),
        (0x143D70978, "qword_143D70978 (default flag-a4 texture)"),
        (0x143E5ACF0, "qword_143E5ACF0 (passed to BSEffectShader init)"),
        (0x143E488C8, "qword_143E488C8 (passed to BSLSP init)"),
        (0x1431E5320, "qword_1431E5320 (BSEffectShader texture manager singleton)"),
    ]:
        log(fh, f"\n  {lbl} @ 0x{g:X}")
        for xref in list(idautils.XrefsTo(g, 0))[:10]:
            fn = ida_funcs.get_func(xref.frm)
            fname = ida_funcs.get_func_name(xref.frm) or "?"
            fn_start = fn.start_ea if fn else 0
            log(fh, f"    xref from 0x{xref.frm:X} in {fname} (fn RVA 0x{rva(fn_start):X})")

    # === PART G — sub_1421C6870 deep decomp ===
    log(fh, "\n=========================================")
    log(fh, "  PART G — sub_1421C6870 (bind TextureSet to material)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x21C6870, fh, "sub_1421C6870", max_lines=500)

    # === PART H — BSEffectShader 2nd variant that takes a path ===
    # Let's look at sub_1421D2790 (first allocated shader in sub_1421792E0,
    # sized 0x198) — this IS the BSWaterShaderProperty ctor, probably.
    # And look for the BSEffectShaderProperty variant that takes a path.
    log(fh, "\n=========================================")
    log(fh, "  PART H — Shader ctors (possibly takes path)")
    log(fh, "=========================================")
    for ea, lbl in [
        (0x1421D2790, "sub_1421D2790 (probably BSWaterShader ctor)"),
        (0x142221150, "sub_142221150"),
        (0x14223D8F0, "sub_14223D8F0"),
        (0x142213000, "sub_142213000"),
        (0x14221D430, "sub_14221D430"),
        (0x1422321F0, "sub_1422321F0"),
        (0x142238CC0, "sub_142238CC0"),
        (0x142223450, "sub_142223450"),
        (0x1421FB8C0, "sub_1421FB8C0 (candidate effect w/ texture path?)"),
        (0x14223EA50, "sub_14223EA50"),
        (0x14220EAF0, "sub_14220EAF0"),
        (0x14221BAE0, "sub_14221BAE0"),
    ]:
        decomp_full(IMG + (ea - 0x140000000), fh, lbl, max_lines=120)

    # === PART I — Look at sub_1406BF310 (a direct user of sub_14217A910) ===
    log(fh, "\n=========================================")
    log(fh, "  PART I — direct users of sub_14217A910 with texture install")
    log(fh, "=========================================")
    for ea, lbl in [
        (0x1406BF310, "sub_1406BF310 (loads a texture into a slot)"),
        (0x1406B6730, "sub_1406B6730 (uses MoonShadow + default tex)"),
        (0x140454550, "sub_140454550 (early user)"),
        (0x140597200, "sub_140597200 (user)"),
        (0x140A77B50, "sub_140A77B50 (4× calls)"),
        (0x1421626D0, "sub_1421626D0 (small wrapper?)"),
        (0x140A39EC0, "sub_140A39EC0"),
    ]:
        decomp_full(IMG + (ea - 0x140000000), fh, lbl, max_lines=300)

    # === PART J — look for BSLightingShaderProperty installer (alloc + set TEX + install) ===
    log(fh, "\n=========================================")
    log(fh, "  PART J — BSLSP installer candidates (ctor callers)")
    log(fh, "=========================================")
    # sub_142171620 is the ctor. Find callers.
    bslsp_ctor = IMG + 0x2171620
    n = 0
    for xref in idautils.XrefsTo(bslsp_ctor, 0):
        fn = ida_funcs.get_func(xref.frm)
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        fn_start = fn.start_ea if fn else 0
        log(fh, f"  xref from 0x{xref.frm:X} in {fname} (fn RVA 0x{rva(fn_start):X})")
        if fn_start and n < 6:
            decomp_full(fn_start, fh, f"bslsp-ctor-caller {fname}", max_lines=200)
        n += 1
        if n >= 30:
            break

    log(fh, "\n==== END pass 3 ====")
    fh.close()
    ida_pro.qexit(0)


main()
