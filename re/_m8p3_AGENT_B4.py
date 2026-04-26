"""
M8P3 — AGENT B PASS 4 — fast targeted decomp only, NO wide-scan.
"""

import idaapi, idc, ida_funcs, ida_hexrays, ida_bytes, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_AGENT_B4_raw.log"
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

# Tier-A: smallest / cleanest candidates
TIER_A = [
    (0x1403FA980, "sub_1403FA980 — name-search bone matrix builder (0x1AD)"),
    (0x1403FA7C0, "sub_1403FA7C0 — name-search inner (0x1B4)"),
    (0x1416EF1B0, "sub_1416EF1B0 — small (size 0x33F)"),
    (0x1416EF580, "sub_1416EF580 — size 0xD1"),
    (0x14186D990, "sub_14186D990 — reads 0x10,0x28"),
    (0x14187E990, "sub_14187E990 — reads all 5 +matmul"),
    (0x141794690, "sub_141794690 — reads 0x38,0x40,0x48"),
    (0x141799080, "sub_141799080 — reads 0x28,0x38,0x40"),
    (0x141799700, "sub_141799700 — reads 0x10,0x28,0x38,0x48"),
    (0x141790E20, "sub_141790E20 — reads 0x10,0x38,0x40,0x48"),
    (0x141787330, "sub_141787330 — bone-loop sig"),
    (0x1417876E0, "sub_1417876E0 — bone-loop sig"),
    (0x1403F74F0, "sub_1403F74F0 — caller of name-search"),
    (0x1403FABF0, "sub_1403FABF0 — recursive caller"),
    (0x1403FB7D0, "sub_1403FB7D0 — caller of sub_1403F7320"),
    (0x14040D770, "sub_14040D770 — caller of sub_1403F7320"),
    (0x140C883E0, "sub_140C883E0 — caller of sub_1403F7320"),
    (0x140CBCA00, "sub_140CBCA00 — caller of sub_1403F7320"),
    # Specific render-side suspect
    (0x140568D20, "sub_140568D20 — reads 0x10,0x38,0x40,0x48"),
    # CB-related: Map_A and Map_B
    (0x1421A0680, "CB_Map_A wrapper @ 0x21A0680"),
    (0x1421A05E0, "CB_Map_B wrapper @ 0x21A05E0"),
    # The 4 BSGeometry slot-32 / slot-33 / slot-46 that read +0x140
    (0x1416D5260, "BSGeometry slot 32 (size 306) — uses skin"),
    (0x1416C8210, "BSGeometry slot 46 (size 14)"),
    # The big render dispatcher
    (0x1421FDA30, "sub_1421FDA30 (size 10040) all-skin-fields hit"),
    # The BSGeometry-typed scenegraph collector caller
    (0x140407C80, "sub_140407C80 — drives sub_14040D4C0 over geom array"),
    (0x140408EB0, "sub_140408EB0 — same family"),
    (0x14040B630, "sub_14040B630 — collects skinned geometries"),
]

log("=" * 80)
log(" AGENT B PASS 4 — TARGETED DECOMP (NO WIDE-SCAN)")
log("=" * 80)

for ea, label in TIER_A:
    sz = fn_size(ea)
    log("\n" + "=" * 80)
    log(" %s @ %s (RVA %s, size %d)" %
        (label, hexs(ea), hexs(rva(ea)), sz))
    log("=" * 80)
    dec = safe_decompile(ea, 400)
    log(dec or "<no decomp>")
    cs = callers_of(ea)
    if cs:
        log("\n  callers (top 10):")
        for c in cs[:10]:
            log("    %s (RVA %s) %s" %
                (hexs(c), hexs(rva(c)), fn_name(c)))

# Now also look at the inverse: WHO IS CALLED with skin instance arg.
# Find all functions where IDA recognizes the first arg is a BSSkin::Instance*.
# Easier: scan the BSSkin::Instance vtable code refs.
log("\n" + "=" * 80)
log(" Code that REFERENCES the BSSkin::Instance vtable @ 0x14267E5C8")
log("=" * 80)
SK_VT = 0x14267E5C8
x = ida_xref.get_first_dref_to(SK_VT)
while x != idaapi.BADADDR:
    f = ida_funcs.get_func(x)
    fea = f.start_ea if f else idaapi.BADADDR
    log("   ref @ %s in fn %s %s" % (hexs(x), hexs(fea), fn_name(fea)))
    x = ida_xref.get_next_dref_to(SK_VT, x)

# === Look at BSSkin::BoneData vtable @ 0x14267E480 ===
log("\n" + "=" * 80)
log(" BSSkin::BoneData vtable @ 0x14267E480")
log("=" * 80)
BD_VT = 0x14267E480
log(" vtable slot dump:")
for i in range(48):
    se = BD_VT + 8 * i
    tg = ida_bytes.get_qword(se)
    if tg == 0 or not (0x140000000 <= tg < 0x150000000):
        break
    sz = fn_size(tg)
    log("   [%2d] %s -> %s (RVA %s, size %d) %s" %
        (i, hexs(se), hexs(tg), hexs(rva(tg)), sz, fn_name(tg)))

log("\n vtable data xrefs:")
x = ida_xref.get_first_dref_to(BD_VT)
while x != idaapi.BADADDR:
    f = ida_funcs.get_func(x)
    fea = f.start_ea if f else idaapi.BADADDR
    log("   ref @ %s in fn %s %s" % (hexs(x), hexs(fea), fn_name(fea)))
    x = ida_xref.get_next_dref_to(BD_VT, x)

# === Find fn near 0x14226B7DE (PreviousBones xref) — likely
# BSDFPrePassShaderVertexConstants::GetString
log("\n" + "=" * 80)
log(" Investigating 0x14226B7DE region (PreviousBones xref location)")
log("=" * 80)
# Let's read disasm around 0x14226B7DE
log("\n  disasm around 0x14226B7DE:")
for off in range(-60, 60, 4):
    ea = 0x14226B7DE + off
    if ea < 0x140000000 or ea > 0x150000000: continue
    try:
        log("   %s   %s" % (hexs(ea), idc.GetDisasm(ea)))
    except Exception:
        pass

# Try to identify the function at the start of this code block.
# Walk back 256 bytes looking for function entry markers.
log("\n  search backward for fn start:")
ea = 0x14226B7DE
for back in range(0, 0x800, 4):
    cea = ea - back
    f = ida_funcs.get_func(cea)
    if f and f.end_ea > 0x14226B7DE:
        log("    fn found: %s (RVA %s, size %d)" %
            (hexs(f.start_ea), hexs(rva(f.start_ea)), f.size()))
        log("    decomp:")
        dec = safe_decompile(f.start_ea, 100)
        log(dec or "<no decomp>")
        break

# === Also find the actual BSDFPrePassShaderVertexConstants::GetString.
# Its xref is at 0x14226B7EE per ida_render_pipeline.log.
log("\n" + "=" * 80)
log(" sub_142268900 / sub_14226B780 — BSDFPrePassShaderVertexConstants::GetString")
log("=" * 80)
# Try various function start guesses near 0x14226B7DE
for guess_start in [0x14226B780, 0x14226B7B0, 0x14226B500, 0x14226B400,
                    0x14226A000, 0x142269000]:
    f = ida_funcs.get_func(guess_start)
    if f:
        log(" guess %s -> fn %s size=%d" %
            (hexs(guess_start), hexs(f.start_ea), f.size()))

# === Also search for sub_141826* (PerGeometry refs) — these are
# CB-string-to-offset GetString functions.
log("\n" + "=" * 80)
log(" PerGeometry xref functions (CB string-to-offset table)")
log("=" * 80)
for ea in [0x1418263D0, 0x141826A00, 0x141826F40, 0x141827470, 0x1418279C0]:
    log("\n--- %s (RVA %s, size %d) ---" %
        (hexs(ea), hexs(rva(ea)), fn_size(ea)))
    dec = safe_decompile(ea, 80)
    log(dec or "<no decomp>")

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "lines:", len(out))
idaapi.qexit(0)
