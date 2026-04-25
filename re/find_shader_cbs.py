"""Find D3D11 constant buffer infrastructure in Fallout4.exe 1.11.191.

Goal: locate the BSShader / BSGraphics Constant-Buffer pipeline.
   1. Confirm RVAs of BSShader, BSLightingShader, BSShaderAccumulator vtables
   2. Dump vtable virtuals (SetupTechnique / SetupMaterial / SetupGeometry / Restore*)
   3. Decompile each Setup* method so we can see what it writes into PerTechnique /
      PerMaterial / PerGeometry CBs (offsets & field names).
   4. Identify the CB-Map helpers (a pair at ~0x21A0680 / 0x21A05E0) and their
      companions for PerGeometry / Unmap.
   5. Identify the two TLS-indexed global pointers that hold current CB states
      (0x3E5AE58 / 0x3E5AE70).
   6. List *all* xrefs to the strings "PerTechnique", "PerMaterial", "PerGeometry"
      — these are the shader-init functions that register CB names.

Static precomputed RVAs (from offline pefile scan):
  BSShader            vt = 0x290DBB8    (dtor 0x222ACE0)
  BSLightingShader    vt = 0x290E458    (dtor 0x2236750)
  BSShaderAccumulator vt = 0x290A6B0    (dtor 0x21CFAE0)
  BSShaderProperty    vt = 0x28F7BB0    (dtor 0x2161FD0)
  BSLightingShaderProperty vt = 0x28F9FF8 (dtor 0x2174B20)
  BSEffectShaderProperty   vt = 0x28F9B20
  BSSkyShaderProperty      vt = 0x290CC80
  BSWaterShaderProperty    vt = 0x290A860
  BSGrassShaderProperty    vt = 0x2909958
  BSDistantTreeShaderProperty vt = 0x290D2A8

CB constant strings (in .rdata):
  PerTechnique   rva=0x269C6E8
  PerMaterial    rva=0x269C6F8
  PerGeometry    rva=0x269C708
  WorldViewProj  rva=0x29097C0 (BSGrass VS)
  WorldViewProj  rva=0x2913011 (BSDFLight? - second occurrence)
  EyePosition    rva=0x290EF10
  SunDirection   rva=0x29129A8
  SunColor       rva=0x2912998
  CameraData     rva=0x2913198
  FogParam/Near/Far rva=0x29097D0/0x29097E0/0x29097F0

Output: re/shader_cb_scan_report.txt
"""

import idautils
import ida_auto
import ida_funcs
import ida_hexrays
import ida_name
import ida_bytes
import ida_xref
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\shader_cb_scan_report.txt"
IMAGE_BASE = 0x140000000


def ea(rva):
    return IMAGE_BASE + rva


def log(fh, *a):
    s = " ".join(str(x) for x in a)
    print(s)
    fh.write(s + "\n")


def dump_vtable(fh, name, vt_rva, maxn=24):
    log(fh, f"\n--- vtable {name} @ va={hex(ea(vt_rva))} ---")
    for i in range(maxn):
        q = ida_bytes.get_qword(ea(vt_rva) + i * 8)
        if not (IMAGE_BASE + 0x1000 <= q < IMAGE_BASE + 0x242B1CC):
            log(fh, f"  [{i:2d}] <end>")
            break
        nm = ida_name.get_name(q) or "?"
        log(fh, f"  [{i:2d}] {hex(q - IMAGE_BASE):>10s}  {nm}")


def decompile(fh, rva, label):
    log(fh, f"\n=== DECOMPILE {label}  rva={hex(rva)} ===")
    f = ida_funcs.get_func(ea(rva))
    if not f:
        log(fh, "  no func object")
        return
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
        if cfunc:
            for line in str(cfunc).splitlines()[:250]:
                log(fh, "  " + line)
            return
    except Exception as e:
        log(fh, f"  hexrays failed: {e}")
    # disasm fallback
    ea_i = f.start_ea
    for _ in range(80):
        log(fh, "  " + idc.GetDisasm(ea_i))
        ea_i = idc.next_head(ea_i)
        if ea_i >= f.end_ea:
            break


def list_xrefs(fh, target_rva, label, limit=30):
    log(fh, f"\n--- xrefs TO {label} @ {hex(target_rva)} ---")
    target = ea(target_rva)
    refs = []
    for x in idautils.XrefsTo(target):
        refs.append(x.frm)
    for r in refs[:limit]:
        fn = ida_funcs.get_func(r)
        fn_s = ""
        if fn:
            fn_s = f"   (in {hex(fn.start_ea - IMAGE_BASE)} {ida_funcs.get_func_name(fn.start_ea)})"
        log(fh, f"  {hex(r - IMAGE_BASE):>10s}  {idc.GetDisasm(r)}{fn_s}")
    log(fh, f"  -- total {len(refs)}")


def main():
    ida_auto.auto_wait()
    with open(REPORT, "w", encoding="utf-8") as fh:
        log(fh, "=" * 70)
        log(fh, "FO4 1.11.191 Shader Constant Buffer Scan")
        log(fh, "=" * 70)

        # === 1. Vtables ===
        VTABLES = [
            ("BSShader", 0x290DBB8),
            ("BSLightingShader", 0x290E458),
            ("BSShaderAccumulator", 0x290A6B0),
            ("BSShaderProperty", 0x28F7BB0),
            ("BSLightingShaderProperty", 0x28F9FF8),
            ("BSEffectShaderProperty", 0x28F9B20),
            ("BSSkyShaderProperty", 0x290CC80),
            ("BSWaterShaderProperty", 0x290A860),
            ("BSGrassShaderProperty", 0x2909958),
            ("BSDistantTreeShaderProperty", 0x290D2A8),
        ]
        for name, vt in VTABLES:
            dump_vtable(fh, name, vt, 18)

        # === 2. Xrefs to CB name strings ===
        CB_NAMES = [
            ("PerTechnique", 0x269C6E8),
            ("PerMaterial", 0x269C6F8),
            ("PerGeometry", 0x269C708),
            ("WorldViewProj@0x29097C0", 0x29097C0),
            ("WorldViewProj@0x2913011", 0x2913011),
            ("EyePosition@0x290EF10", 0x290EF10),
            ("SunDirection@0x29129A8", 0x29129A8),
            ("SunColor@0x2912998", 0x2912998),
            ("CameraData@0x2913198", 0x2913198),
            ("PreviousWorld@0x2912318", 0x2912318),
            ("WorldView@0x2912328", 0x2912328),
            ("FogParam@0x29097D0", 0x29097D0),
            ("FogNearColor@0x29097E0", 0x29097E0),
            ("FogFarColor@0x29097F0", 0x29097F0),
        ]
        for name, r in CB_NAMES:
            list_xrefs(fh, r, name, 40)

        # === 3. Decompile the Setup* candidates for BSLightingShader ===
        #   vt[4] @ 0x2232DC0 — SetupTechnique?   (uses PerTechnique CB)
        #   vt[5] @ 0x2233720 — RestoreTechnique?
        #   vt[7] @ 0x2233730 — SetupMaterial?     (uses PerMaterial CB)
        #   vt[8] @ 0x22342C0 — SetupGeometry?     (uses PerGeometry CB)
        #   vt[9] @ 0x22344E0 — RestoreGeometry?
        for rva, lab in [
            (0x2232DC0, "BSLightingShader::SetupTechnique?"),
            (0x2232340, "BSLightingShader::vt[3]"),
            (0x22323C0, "BSLightingShader::vt[2]"),
            (0x2233720, "BSLightingShader::RestoreTechnique?"),
            (0x2233730, "BSLightingShader::SetupMaterial?"),
            (0x22342C0, "BSLightingShader::SetupGeometry?"),
            (0x22344E0, "BSLightingShader::RestoreGeometry?"),
            (0x21A0680, "CB_Map_helper_A (used by SetupTechnique)"),
            (0x21A05E0, "CB_Map_helper_B (sibling of helper A)"),
        ]:
            decompile(fh, rva, lab)

        # === 4. Xrefs to CB-map helpers — reveals who else updates CBs ===
        for rva, nm in [(0x21A0680, "CB_Map_A"), (0x21A05E0, "CB_Map_B")]:
            list_xrefs(fh, rva, nm, 60)

        # === 5. CB global pointers (found in SetupTechnique body)
        #   mov rdx, [0x3E5AE58]  — context/CB-A global
        #   mov rdx, [0x3E5AE70]  — context/CB-B global
        log(fh, "\n--- xrefs TO CB global ptr 0x3E5AE58 ---")
        list_xrefs(fh, 0x3E5AE58, "0x3E5AE58", 40)
        log(fh, "\n--- xrefs TO CB global ptr 0x3E5AE70 ---")
        list_xrefs(fh, 0x3E5AE70, "0x3E5AE70", 40)

        # === 6. Big table buffer at 0x3A0F400 (loaded by SetupTechnique) ===
        log(fh, "\n--- xrefs TO 0x3A0F400 (CB descriptor table?) ---")
        list_xrefs(fh, 0x3A0F400, "0x3A0F400", 40)

        log(fh, "\n[done]")


main()
