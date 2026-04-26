"""
M8P3 — AGENT B PASS 3 — focused decomp of best candidates.

Skip the heavy wide-scan; just decomp the targeted functions and stuff that
matters for the dossier.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_AGENT_B3_raw.log"
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

# Tier-A: smallest / cleanest candidates that read 0x28+0x38+0x40+matmul
TIER_A = [
    (0x1403FA980, "sub_1403FA980 — name-search bone matrix builder"),
    (0x1403FA7C0, "sub_1403FA7C0 — name-search inner"),
    (0x1416EF1B0, "sub_1416EF1B0 — small (size 0x33F) +matmul +0x28+0x38+0x40"),
    (0x1416EF580, "sub_1416EF580 — size 0xD1 +matmul"),
    (0x14186D990, "sub_14186D990 — reads 0x10,0x28 +matmul"),
    (0x14187E990, "sub_14187E990 — reads all 5 +matmul"),
    (0x141794690, "sub_141794690 — reads 0x38,0x40,0x48"),
    (0x141799080, "sub_141799080 — reads 0x28,0x38,0x40"),
    (0x141799700, "sub_141799700 — reads 0x10,0x28,0x38,0x48"),
    (0x141790E20, "sub_141790E20 — reads 0x10,0x38,0x40,0x48"),
    (0x141787330, "sub_141787330 — bone-loop sig +0x70 reads"),
    (0x1417876E0, "sub_1417876E0 — bone-loop sig +0x70 reads"),
    # Caller chain
    (0x1403F74F0, "sub_1403F74F0 — caller of name-search"),
    (0x1403FABF0, "sub_1403FABF0 — recursive caller"),
    # Pre-render hooks
    (0x1416BD0B0, "sub_1416BD0B0 — RTTI cast helper used by sub_141779DA0"),
]

log("=" * 80)
log(" AGENT B PASS 3 — TARGETED DECOMP")
log("=" * 80)

for ea, label in TIER_A:
    sz = fn_size(ea)
    log("\n" + "=" * 80)
    log(" %s @ %s (RVA %s, size %d)" %
        (label, hexs(ea), hexs(rva(ea)), sz))
    log("=" * 80)
    dec = safe_decompile(ea, 400)
    log(dec or "<no decomp>")
    log("\n  callers (top 10):")
    for c in callers_of(ea)[:10]:
        log("    %s (RVA %s) %s" %
            (hexs(c), hexs(rva(c)), fn_name(c)))

# === Look for "scenegraph traversal" → skin update entry. We know
# sub_1416BF1C0 (UpdateDownwardPass) recurses children at slot 53 each
# frame. Some BSGeometry override of slot 52 might be the skin update.
# Already known: BSGeometry slot 52 = sub_1416D54E0 (calls UpdateWorldData).
# BUT what about slot 50 (sub_1416D4EA0, size 99)? slot 49 (sub_1416D4E30,
# size 99)? slot 48 (sub_1416D4DC0, size 91)? Decomp them.

log("\n" + "=" * 80)
log(" Decomp of BSGeometry slots 47-52 (the bound/transform group)")
log("=" * 80)
for ea, label in [
    (0x1416D4D60, "BSGeometry slot 47 (size 77)"),
    (0x1416D4DC0, "BSGeometry slot 48 (size 91)"),
    (0x1416D4E30, "BSGeometry slot 49 (size 99)"),
    (0x1416D4EA0, "BSGeometry slot 50 (size 99)"),
    (0x1416D54E0, "BSGeometry slot 52 (size 46) — already known: calls UWD"),
    (0x1416D54B0, "BSGeometry slot 54 (size 35)"),
]:
    sz = fn_size(ea)
    log("\n--- %s ---" % label)
    dec = safe_decompile(ea, 80)
    log(dec or "<no decomp>")

# === Look at BSDynamicTriShape vt[26]=sub_1416E4280 (size 459) — biggest.
# Possibly the dynamic-vertex update which drives CPU vertex skinning.
log("\n" + "=" * 80)
log(" BSDynamicTriShape vt[26] sub_1416E4280 (size 459) — DEEP")
log("=" * 80)
dec = safe_decompile(0x1416E4280, 400)
log(dec or "<no decomp>")

# === Look at frame_tick child sub_1404E87C0 — already known as scenegraph
# update driver. Its callees might include the skin update.
log("\n" + "=" * 80)
log(" sub_1404E87C0 — frame_tick child (size 0x7E2)")
log("=" * 80)
dec = safe_decompile(0x1404E87C0, 600)
log(dec or "<no decomp>")

# === Look at sub_1421B27D0 / sub_1421B3110 / sub_1421B69D0 — render inner ===
log("\n" + "=" * 80)
log(" Render-thread chain: sub_1421B27D0 / sub_1421B3110")
log("=" * 80)
for ea, label in [(0x1421B27D0, "sub_1421B27D0 size 0x2E6"),
                  (0x1421B3110, "sub_1421B3110 size 0x237")]:
    log("\n--- %s ---" % label)
    dec = safe_decompile(ea, 300)
    log(dec or "<no decomp>")

# === Did we miss any function that explicitly takes a BSSkin::Instance
# argument? Scan the whole .text segment for functions that read
# specifically (skin+0x28) AND (skin+0x40), AND iterate (count at
# +0x38). This is more selective than the wide scan.
log("\n" + "=" * 80)
log(" SELECTIVE wide-scan — fns reading both 0x28 AND 0x40 of skin AND")
log(" calling matmul AND that have a loop (rep instruction or jcc back)")
log("=" * 80)

# Build function list from named seg
seg = ida_segment.get_segm_by_name(".text")
fns = []
ea_cur = seg.start_ea
while ea_cur < seg.end_ea:
    f = ida_funcs.get_func(ea_cur)
    if f:
        fns.append(f.start_ea)
        ea_cur = f.end_ea
    else:
        ea_cur = idc.next_head(ea_cur, seg.end_ea)
fns = list(set(fns))
log(" total fns: %d" % len(fns))

MATMUL_EA = 0x1403444F0
RESOLVER_EA = 0x1403F85E0

def fn_features(fn_ea):
    func = ida_funcs.get_func(fn_ea)
    if not func: return None
    sz = func.size()
    if sz < 50 or sz > 4000: return None
    cur = func.start_ea
    cnt28 = cnt38 = cnt40 = cnt70 = 0
    has_matmul = False
    has_resolver = False
    has_jmp_back = False  # crude loop indicator
    last_ea_seen = func.start_ea
    while cur < func.end_ea:
        mnem = idc.print_insn_mnem(cur).lower()
        if mnem == "call":
            tgt = idc.get_operand_value(cur, 0)
            if tgt == MATMUL_EA:
                has_matmul = True
            if tgt == RESOLVER_EA:
                has_resolver = True
        if mnem in ("jmp", "jnz", "jne", "jge", "jle", "ja", "jb", "jl", "js"):
            tgt = idc.get_operand_value(cur, 0)
            if 0 < tgt < cur and tgt >= func.start_ea:
                has_jmp_back = True
        for op_idx in (0, 1, 2):
            try:
                op_str = idc.print_operand(cur, op_idx)
                if "+28h" in op_str:  cnt28 += 1
                if "+38h" in op_str:  cnt38 += 1
                if "+40h" in op_str:  cnt40 += 1
                if "+70h" in op_str:  cnt70 += 1
            except Exception:
                pass
        cur = idc.next_head(cur, func.end_ea)
    return (cnt28, cnt38, cnt40, cnt70, has_matmul, has_resolver, has_jmp_back, sz)

hits = []
for f in fns:
    feat = fn_features(f)
    if not feat: continue
    cnt28, cnt38, cnt40, cnt70, mm, rv, lp, sz = feat
    if cnt28 >= 1 and cnt40 >= 1 and mm and lp:
        hits.append((f, cnt28, cnt38, cnt40, cnt70, mm, rv, lp, sz))

hits.sort(key=lambda x: -(x[1]+x[2]+x[3]+x[4]))
log(" candidates with skin loop+matmul+0x28+0x40 reads: %d" % len(hits))
for h in hits[:30]:
    f, c28, c38, c40, c70, mm, rv, lp, sz = h
    log("   fn %s (RVA %s) sz=%d  +28=%d +38=%d +40=%d +70=%d  matmul=%d  resolver=%d  loop=%d  %s" %
        (hexs(f), hexs(rva(f)), sz, c28, c38, c40, c70, int(mm), int(rv), int(lp), fn_name(f)))

# Decomp top 6 (the strongest candidates if any look like a per-bone loop)
for h in hits[:6]:
    f, c28, c38, c40, c70, mm, rv, lp, sz = h
    log("\n" + "=" * 60)
    log(" SELECTIVE HIT: fn %s (RVA %s) +28=%d +40=%d +70=%d sz=%d" %
        (hexs(f), hexs(rva(f)), c28, c40, c70, sz))
    log("=" * 60)
    dec = safe_decompile(f, 500)
    log(dec or "<no decomp>")

# Save
with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out))
print("wrote", LOG_PATH, "lines:", len(out))
idaapi.qexit(0)
