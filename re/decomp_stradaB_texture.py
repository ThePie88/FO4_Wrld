"""
decomp_stradaB_texture.py

Find the Fallout 4 texture-loading API that takes a path string and
returns a usable texture handle for installing into a BSEffectShaderProperty
or BSLightingShaderProperty.

Targets:
  1) Find BSTextureDB entry/traits API. Starts with strings:
     - "BSTextureDB"
     - ".?AUDBTraits@BSTextureDB@@"
     - ".?AV?$EntryDB@UDBTraits@BSTextureDB@@@BSResource@@"
  2) Find usages of common DDS paths (e.g. "Textures\\Sky\\MoonShadow.dds")
     and trace the API that eats them -> texture handle.
  3) Decompile BSLightingShaderProperty ctor (sub_142171620 @ RVA 0x2171620)
     to find the texture set layout.
  4) Decompile BSEffectShaderProperty ctor/init (sub_14216F9C0, sub_142161B10)
     to see the texture slot layout.
  5) Trace NiSourceTexture / BSShaderTextureSet usage.
  6) Find the "LoadTexture(path)" style helper by tracing xrefs from a
     hardcoded DDS path string and examining what function consumes it.
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_segment
import ida_name
import ida_search
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_texture_raw.txt"


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


def disasm_block(ea, fh, label="", insn_count=80):
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


def find_strings_containing(substrs, fh, label=""):
    """Find all .rdata string addresses that contain any of the substrs.
    Returns list of (str_ea, s)."""
    log(fh, f"\n==== Searching .rdata for substrings: {substrs} ({label}) ====")
    found = []
    for s in idautils.Strings():
        try:
            v = str(s)
        except:
            continue
        if any(sub.lower() in v.lower() for sub in substrs):
            ea = s.ea
            found.append((ea, v))
            log(fh, f"  0x{ea:X}  RVA=0x{rva(ea):X}  '{v}'")
    return found


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
    """Resolve a name to an EA (or 0 if missing)."""
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea if ea != idc.BADADDR else 0


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — Texture API dossier (raw) ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # === STEP 1 — ctors of shader properties (already known) ===
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 1 — Shader ctors (effect + lighting)")
    log(fh, "=========================================")
    BSEFF_CTOR  = IMG + 0x216F9C0   # sub_14216F9C0 (BSEffectShader base ctor)
    BSEFF_INIT  = IMG + 0x2161B10   # sub_142161B10 (setup)
    BSLSP_CTOR  = IMG + 0x2171620   # sub_142171620 (BSLightingShaderProperty ctor)
    INSTALLER   = IMG + 0x372CC0    # sub_140372CC0 (FogOfWarOverlay installer)

    decomp_full(BSEFF_CTOR, fh, "BSEffectShaderProperty::ctor (base)", max_lines=400)
    decomp_full(BSEFF_INIT, fh, "BSEffectShaderProperty::init", max_lines=400)
    decomp_full(BSLSP_CTOR, fh, "BSLightingShaderProperty::ctor", max_lines=400)

    # Also dump part of the installer to see texture wiring
    decomp_full(INSTALLER, fh, "FogOfWarOverlay installer (sub_140372CC0)", max_lines=700)

    # === STEP 2 — Find DDS path strings and their xref-containing funcs ===
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 2 — DDS path strings + xref funcs")
    log(fh, "=========================================")

    hardcoded = find_strings_containing(
        [
            "Textures\\Sky\\MoonShadow",
            "Sky\\SunGlare",
            "MoonShadow.dds",
            "SunGlare.dds",
            "Interface\\Shared\\missing_image",
            "QuickSky_e.dds",
            "blooddecal.dds",
            "Textures\\Effects\\TestMeatcapGore",
        ],
        fh,
        label="hardcoded-dds-paths",
    )
    # Take at most 8 and see who xrefs them
    seen_funcs = set()
    for (sea, s) in hardcoded[:10]:
        log(fh, f"\n-- xref analysis for '{s}' @ 0x{sea:X} --")
        xrs = xrefs_to_addr(fh, sea, f"'{s}'", limit=8)
        for (_, fn_ea) in xrs[:3]:
            if fn_ea and fn_ea not in seen_funcs:
                seen_funcs.add(fn_ea)
                decomp_full(fn_ea, fh, f"consumer-of-'{s[:30]}'", max_lines=250)

    # === STEP 3 — Look for BSTextureDB-related symbols via IDA names ===
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 3 — BSTextureDB symbols scan")
    log(fh, "=========================================")

    # Walk all names; look for anything containing "TextureDB", "EntryDB", "ITextureDB"
    hits = []
    for (ea, n) in idautils.Names():
        ln = n.lower()
        if any(s in ln for s in ["texturedb", "entrydb", "itexturedb",
                                 "textureset", "bsshadertexture",
                                 "nisourcetexture", "bstexturestreamer"]):
            hits.append((ea, n))
    for (ea, n) in hits[:120]:
        log(fh, f"  0x{ea:X}  RVA=0x{rva(ea):X}  {n}")

    # === STEP 4 — RTTI class-anchored function finder ===
    # Search for .?AVBSShaderTextureSet@@ etc. and trace the vtable.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 4 — RTTI-based class vtable locations")
    log(fh, "=========================================")

    rtti_strings = [
        ".?AVBSShaderTextureSet@@",
        ".?AVBSTextureSet@@",
        ".?AVBSResourceNiBinaryStream@@",
        ".?AVITextureDB@@",
    ]
    for rtti in rtti_strings:
        # Find the string
        for s in idautils.Strings():
            try:
                v = str(s)
            except:
                continue
            if v == rtti:
                log(fh, f"\n  RTTI '{rtti}' @ 0x{s.ea:X} RVA 0x{rva(s.ea):X}")
                # Find xrefs (will lead to a TypeDescriptor struct then to vtable)
                td = s.ea - 0x10   # TypeDescriptor header is usually 0x10 before the mangled name on x64
                for xr in list(idautils.XrefsTo(td, 0))[:4]:
                    log(fh, f"    xref to TD @ 0x{xr.frm:X}  (func? 0x{(ida_funcs.get_func(xr.frm).start_ea if ida_funcs.get_func(xr.frm) else 0):X})")
                # Also direct xrefs to the mangled-string itself (for completeness)
                for xr in list(idautils.XrefsTo(s.ea, 0))[:4]:
                    log(fh, f"    xref to mangled @ 0x{xr.frm:X}")
                break

    # === STEP 5 — sub_140372CC0 (FogOfWar installer) deep decomp ===
    # This builds a BSTriShape with a BSEffectShader + a texture. Extract its
    # texture wiring.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 5 — FogOfWarOverlay installer full decomp")
    log(fh, "=========================================")
    decomp_full(INSTALLER, fh, "sub_140372CC0 (full)", max_lines=1200)

    # === STEP 6 — decomp the BSEffectShaderProperty texture slot writer ===
    # From M2 dossier: the installer did:
    #    v49 = sub_14216F9C0(shader);
    #    sub_142161B10(v49, *(_QWORD *)(v49 + 88), v48);
    # So the "sub-object" is at shader+0x58 and the setter takes it + some arg.
    # Decompile sub_142161B10 to see exactly what it writes.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 6 — BSEffectShader sub-object writer (sub_142161B10)")
    log(fh, "=========================================")
    decomp_full(BSEFF_INIT, fh, "sub_142161B10 (full)", max_lines=400)

    # Also, the constant q_1434391A0 (default texture handle) — find who writes it.
    # and see xrefs to BSEffectShader sub-object writer
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 6B — qword_1434391A0 default texture handle xrefs")
    log(fh, "=========================================")
    DEFAULT_TEX = IMG + 0x34391A0
    xrefs_to_addr(fh, DEFAULT_TEX, "qword_1434391A0 (default texture handle)", limit=30)

    # === STEP 7 — NiSourceTexture / BSShaderTextureSet class lookups ===
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 7 — BSShaderTextureSet lookup")
    log(fh, "=========================================")
    # Candidate: BSShaderTextureSet vtable is used to mark TextureSet objects.
    # Let's try by name.
    for n in [
        "BSShaderTextureSet::`vftable'",
        "BSTextureSet::`vftable'",
        "NiSourceTexture::`vftable'",
        "BSResourceNiBinaryStream::`vftable'",
        "ITextureDB::`vftable'",
    ]:
        ea = sym(n)
        log(fh, f"  {n}  ea=0x{ea:X}  RVA=0x{(rva(ea) if ea else 0):X}")

    # === STEP 8 — Hunt: any func that takes BSFixedString and looks up texture ===
    # Heuristic: look for the string "_d.DDS" (suffix for diffuse) or "%s.dds"
    # format strings, then find their xref funcs and decomp the one that's most
    # likely to be a loader.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 8 — Texture name-format xrefs")
    log(fh, "=========================================")
    fmts = find_strings_containing([
        "%s.dds", "%s_d.dds", "%s_n.dds", "%s_s.dds",
    ], fh, label="texture-path-format-strings")
    fmt_seen = set()
    for (sea, s) in fmts[:6]:
        xrs = xrefs_to_addr(fh, sea, f"format '{s}'", limit=6)
        for (_, fn_ea) in xrs[:2]:
            if fn_ea and fn_ea not in fmt_seen:
                fmt_seen.add(fn_ea)
                decomp_full(fn_ea, fh, f"fmt-consumer of '{s}'", max_lines=250)

    # === STEP 9 — Scan for calls into "BSResource::Location::OpenStream" style ===
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 9 — Look for BSResource names")
    log(fh, "=========================================")
    for (ea, n) in idautils.Names():
        ln = n.lower()
        if any(sub in ln for sub in ["bsresource::", "bsarchive", "ba2::", "bstextureimpl", "openstream", "loadstream"]):
            log(fh, f"  0x{ea:X}  RVA=0x{rva(ea):X}  {n}")

    log(fh, "\n==== END texture dossier ====")
    fh.close()
    ida_pro.qexit(0)


main()
