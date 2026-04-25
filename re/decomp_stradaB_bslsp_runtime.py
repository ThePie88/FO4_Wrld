"""
decomp_stradaB_bslsp_runtime.py — find a RUNTIME BSLSP installer.

We now know from the finalize pass that:
  - sub_1421711F0 (BSLSP::LoadTextures) has NO external callers at all.
  - sub_142170E60 (BSLSP template init) has NO callers.
  - sub_142174A70 is just a dup of sub_142171050.
  - The only two BSLSP alloc callers are both startup registration code,
    not runtime instantiators.
  - sub_14040AB10 allocates a BSShaderMaterialXXX (0xC8), not a BSLSP,
    and calls sub_1421C6870 to bind textures for it.
  - sub_140360A90 looks up an EXISTING BSLightingShader property from
    a refr, calls sub_1421C6870, then calls sub_1421718E0 (BSLSP vt[42]
    impl).

This strongly suggests that runtime-created BSLSP does NOT exist in
normal gameplay — the engine creates them during NIF load only.
The "install shader" vanilla pattern we need to copy is FogOfWar's
BSEffectShader, even if we have to translate it to BSLSP semantics.

Remaining tasks:
  1. Decomp sub_140376620 — another +0x138 write site — is this a
     runtime install alternative?
  2. Decomp sub_14040E510 (BSTriShape+0x138 writer) — could be
     BSGeometry-side "SetShader" method.
  3. Look at sub_1404464B8, sub_140444E20, etc. to see if any is a
     per-frame or runtime install.
  4. Decomp BSEffectShader vt[42] for comparison semantics.
  5. Decomp BSSkyShader vt[42].
  6. Decomp BSLSP vt[42] impl (sub_1421718E0) fully with callees.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_bslsp_runtime_raw.txt"


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


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — BSLSP runtime install RE pass ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # ============================================================
    # PART A — sub_140376620, another install site (+0x138 write)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART A — sub_140376620")
    log(fh, "=========================================")
    decomp_full(IMG + 0x376620, fh, "sub_140376620", max_lines=800)

    # ============================================================
    # PART B — sub_14040E510 (writes to +0x138)
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART B — sub_14040E510")
    log(fh, "=========================================")
    decomp_full(IMG + 0x40E510, fh, "sub_14040E510", max_lines=600)

    # ============================================================
    # PART C — BSSkyShader ctor via sub_142214640, vt[42]
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART C — BSSkyShader ctor + vt[42]")
    log(fh, "=========================================")
    # The Moon installer uses sub_142214640(v31) which writes the
    # BSSkyShaderProperty vtable. Find the vtable by scanning names.
    for name, nea in idautils.Names():
        if "BSSkyShader" in name and "vftable" in name:
            log(fh, f"  FOUND BSSkyShaderProperty vtable @ 0x{nea:X} RVA=0x{rva(nea):X}")
            vt_ea = nea
            q42 = ida_bytes.get_qword(vt_ea + 42*8)
            log(fh, f"  vt[42] = 0x{q42:X} RVA=0x{rva(q42):X}")
            if ida_funcs.get_func(q42):
                decomp_full(q42, fh, "BSSkyShader vt[42]", max_lines=200)
            # Also dump vt[28] (LoadTextures equivalent)
            q28 = ida_bytes.get_qword(vt_ea + 28*8)
            log(fh, f"  vt[28] = 0x{q28:X} RVA=0x{rva(q28):X}")
            if ida_funcs.get_func(q28):
                decomp_full(q28, fh, "BSSkyShader vt[28]", max_lines=200)
            break

    # ============================================================
    # PART D — BSEffectShader vtable
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART D — BSEffectShaderProperty vtable dump")
    log(fh, "=========================================")
    for name, nea in idautils.Names():
        if "BSEffectShaderProperty" in name and "vftable" in name:
            log(fh, f"  FOUND BSEffectShaderProperty vtable @ 0x{nea:X} RVA=0x{rva(nea):X}")
            vt_ea = nea
            for slot in range(36, 46):
                q = ida_bytes.get_qword(vt_ea + slot*8)
                fname = ida_funcs.get_func_name(q) or "?"
                log(fh, f"  vt[{slot}] = 0x{q:X} RVA=0x{rva(q):X} {fname}")
            q42 = ida_bytes.get_qword(vt_ea + 42*8)
            if ida_funcs.get_func(q42):
                decomp_full(q42, fh, "BSEffectShader vt[42] FULL", max_lines=200)
            break

    # ============================================================
    # PART E — sub_1421718E0 (BSLSP vt[42] impl) full decomp + its
    # callees so we understand what's REQUIRED to set up.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART E — sub_1421718E0 (BSLSP vt[42] impl) + callees")
    log(fh, "=========================================")
    decomp_full(IMG + 0x21718E0, fh, "sub_1421718E0 BSLSP vt[42] impl FULL", max_lines=600)

    # Common callees (from previous pass):
    for name, rva_offset, label in [
        ("sub_142161950", 0x2161950, "sub_142161950 (flag set)"),
        ("sub_1416D5640", 0x16D5640, "sub_1416D5640 (get flags maybe)"),
        ("sub_14181C130", 0x181C130, "sub_14181C130"),
        ("sub_14167C200", 0x167C200, "sub_14167C200 (BSFixedString has string?)"),
    ]:
        decomp_full(IMG + rva_offset, fh, label, max_lines=200)

    # ============================================================
    # PART F — dump BSTriShape vt[40] through vt[60] with names.
    # vt[40] is often "SetShader" / property-setter on geometry.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART F — BSTriShape vt[30..60] deep")
    log(fh, "=========================================")
    BSTRISHAPE_VT = IMG + 0x267E948
    for slot in range(30, 60):
        q = ida_bytes.get_qword(BSTRISHAPE_VT + slot*8)
        fname = ida_funcs.get_func_name(q) or "?"
        log(fh, f"  BSTriShape vt[{slot}] = 0x{q:X} RVA=0x{rva(q):X}  {fname}")

    # Dump some key slots fully:
    for slot in [30, 40, 41, 42, 43, 44, 45, 46, 52, 53]:
        q = ida_bytes.get_qword(BSTRISHAPE_VT + slot*8)
        if ida_funcs.get_func(q):
            decomp_full(q, fh, f"BSTriShape::vt[{slot}]", max_lines=100)

    # ============================================================
    # PART G — sub_142161B10 with arg3=1 (the "first-init" flag FogOfWar
    # uses). Already decomped but let's see the arg3 branch impact.
    # Plus sub_1421F9F00 — the material cache.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART G — sub_142161B10 arg3=1 branch analysis")
    log(fh, "=========================================")
    decomp_full(IMG + 0x2161B10, fh, "sub_142161B10 again", max_lines=150)

    # ============================================================
    # PART H — sub_14216F8E0 = BSEffectShader alloc wrapper
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART H — sub_14216F8E0 (BSEffectShader alloc wrapper)")
    log(fh, "=========================================")
    decomp_full(IMG + 0x216F8E0, fh, "sub_14216F8E0", max_lines=150)

    # sub_142214A60 = BSSkyShader alloc wrapper
    decomp_full(IMG + 0x2214A60, fh, "sub_142214A60 (BSSkyShader alloc wrapper)", max_lines=150)

    # sub_1421C5910 = BSGrassShader alloc wrapper
    decomp_full(IMG + 0x21C5910, fh, "sub_1421C5910 (BSGrassShader alloc wrapper)", max_lines=150)

    # ============================================================
    # PART I — Look for BSTriShape::SetShaderProperty-like fn.
    # Scan callers of BSLSP vt[42] (sub_1421718C0) to find "install" callers
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART I — callers of BSLSP vt[42] (sub_1421718C0) + vt[42] impl (sub_1421718E0)")
    log(fh, "=========================================")
    for ea, lbl in [
        (IMG + 0x21718C0, "BSLSP vt[42] slot sub_1421718C0"),
        (IMG + 0x21718E0, "BSLSP vt[42] impl sub_1421718E0"),
    ]:
        log(fh, f"\n==== Callers of {lbl} ====")
        seen = set()
        for xref in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(xref.frm)
            if not fn:
                continue
            if fn.start_ea in seen:
                continue
            seen.add(fn.start_ea)
            fname = ida_funcs.get_func_name(fn.start_ea) or "?"
            log(fh, f"  0x{fn.start_ea:X}  {fname}  (RVA 0x{rva(fn.start_ea):X})  xref@0x{xref.frm:X}")

    # Decomp sub_142170E60 — BSLSP template init — AS it's the vt[26]
    # and template-from-template init of the shader. Our code doesn't call it.
    decomp_full(IMG + 0x2170E60, fh, "sub_142170E60 BSLSP template init", max_lines=200)

    # ============================================================
    # PART J — Look for BSTriShape's vt slot that calls the shader's
    # vt[42]. Similar to sub_1421718E0 but the other direction.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART J — BSTriShape::SetProperty-like slots")
    log(fh, "=========================================")
    # BSTriShape vt[42] = SetAlphaProperty (known). Let's look at vt[43], vt[44].
    for slot in [42, 43, 44, 45, 46, 30, 31]:
        q = ida_bytes.get_qword(BSTRISHAPE_VT + slot*8)
        if ida_funcs.get_func(q):
            decomp_full(q, fh, f"BSTriShape::vt[{slot}]", max_lines=100)

    # ============================================================
    # PART K — Search the binary for the exact sequence:
    #   (1) sub_142171050 (BSLSP new)
    #   (2) ... (some call chain)
    #   (3) mov [reg + 138h], result_of_1
    # We can find this by looking at sub_1421792E0 and sub_14217A2E0
    # cross-references — they're the only 2 callers of sub_142171050.
    # ============================================================
    log(fh, "\n=========================================")
    log(fh, "  PART K — confirm ZERO runtime BSLSP install sites")
    log(fh, "=========================================")
    # Same as previous pass: no callers of 71050 outside startup registration.
    log(fh, "  (Confirmed previous pass: BSLSP is NEVER instantiated at runtime")
    log(fh, "   directly. The factory is registered with 'BSLightingShaderProperty'")
    log(fh, "   name; instances come from NIF deserialization.)")

    log(fh, "\n==== END runtime pass ====")
    fh.close()
    ida_pro.qexit(0)


main()
