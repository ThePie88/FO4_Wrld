"""
M8P3 — AGENT B PASS 5 — final examination of remaining strong candidates.
"""

import idaapi, idc, ida_funcs, ida_hexrays, ida_bytes, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_AGENT_B5_raw.log"
IMG = 0x140000000
out = []

def log(s=""): out.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)
def rva(ea): return ea - IMG
def fn_size(ea):
    f = ida_funcs.get_func(ea)
    return f.size() if f else 0
def fn_name(ea):
    return ida_funcs.get_func_name(ea) or ""
def safe_decompile(ea, max_lines=400):
    try:
        c = ida_hexrays.decompile(ea)
        if not c: return None
        s = str(c).split("\n")
        if len(s) > max_lines:
            s = s[:max_lines] + ["    ... <truncated>"]
        return "\n".join(s)
    except Exception as e:
        return "<decomp error: %s>" % e
def callers_of(ea):
    out = set()
    x = ida_xref.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        f = ida_funcs.get_func(x)
        if f: out.add(f.start_ea)
        x = ida_xref.get_next_cref_to(ea, x)
    return list(out)

# Final candidates
TARGETS = [
    (0x140C87EA0, "sub_140C87EA0 - all 5 skin offsets read + matmul=1"),
    (0x140E3F220, "sub_140E3F220 - all 5 skin offsets + matmul=1"),
    (0x14187BC20, "sub_14187BC20 - reads 0x10,0x28,0x38,0x40 + matmul=1"),
    (0x1418A8DB0, "sub_1418A8DB0 - all 5 + matmul=2"),
    (0x1418BD4B0, "sub_1418BD4B0 - all 5 + matmul=2"),
    (0x14180B410, "sub_14180B410 - 0x28,0x38,0x40,0x48 + matmul=2"),
    # Direct callers of CB_Map_A on geometry-side: who fills the bone palette?
    (0x1421A3400, "sub_1421A3400 - CB_Map_A caller"),
    (0x1421A3180, "sub_1421A3180 - CB_Map_A caller"),
    (0x1421A2890, "sub_1421A2890 - CB_Map_B caller"),
    (0x1421A3680, "sub_1421A3680 - CB_Map_B caller"),
    # The Setup* virtuals — different from SetupGeometry which is a flag setter
    (0x142232DC0, "BSLightingShader::SetupTechnique"),
    (0x142233730, "BSLightingShader::SetupMaterial"),
    (0x1422342C0, "BSLightingShader::SetupGeometry"),
    # The BatchRenderer Dispatch (per-pass)
    (0x142221BC90, "BSBatchRenderer::Dispatch (vt[4])"),
    (0x142221C1B0, "BSBatchRenderer::FlushBatch (vt[9])"),
    # BSGeometry vt[27] = render-time virtual
    (0x1416D49F0, "BSGeometry slot 27 (size 174)"),
    # Pre-render vt[5x] — slot 50 (size 99)
    (0x1416D4EA0, "BSGeometry slot 50 (size 99)"),
    (0x1416D4E30, "BSGeometry slot 49 (size 99)"),
    (0x1416D4DC0, "BSGeometry slot 48 (size 91)"),
    (0x1416D4D60, "BSGeometry slot 47 (size 77)"),
]

log("=" * 80)
log(" AGENT B PASS 5 — FINAL TARGETED DECOMP")
log("=" * 80)

for ea, label in TARGETS:
    sz = fn_size(ea)
    log("\n" + "=" * 80)
    log(" %s @ %s (RVA %s, size %d)" %
        (label, hexs(ea), hexs(rva(ea)), sz))
    log("=" * 80)
    dec = safe_decompile(ea, 250)
    log(dec or "<no decomp>")
    cs = callers_of(ea)
    if cs:
        log("\n  callers (top 8):")
        for c in cs[:8]:
            log("    %s (RVA %s) %s" %
                (hexs(c), hexs(rva(c)), fn_name(c)))

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "lines:", len(out))
idaapi.qexit(0)
