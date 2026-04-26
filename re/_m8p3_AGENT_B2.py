"""
M8P3 — AGENT B PASS 2.

Decomp the most promising candidates that read multiple BSSkin::Instance
offsets, AND specifically search for the bone-loop CPU skin update pattern:

    for (i = 0; i < skin->count_pri; ++i) {
        bone = skin->bones_pri[i];
        bone_world = bone + 0x70;
        inv_bind = skin->boneData->boneArray + 80*i + 0x10;
        result = bone_world * inv_bind;
        out_buffer[i] = result;
    }

Specific candidates to dig into:
  - sub_140CA7880 (RVA 0xCA7880) reads skin offsets 0x10,0x28,0x38,0x48
  - sub_141790E20 (RVA 0x1790E20) reads 0x10,0x38,0x40,0x48
  - sub_141794690 (RVA 0x1794690) reads 0x38,0x40,0x48
  - sub_140568D20 (RVA 0x568D20) reads 0x10,0x38,0x40,0x48
  - sub_14187E990 (RVA 0x187E990) reads all 5 (0x10,0x28,0x38,0x40,0x48)
  - sub_140C87EA0 (RVA 0xC87EA0) reads all 5 + matmul=1
  - sub_140E3F220 (RVA 0xE3F220) reads all 5 + matmul=1
  - sub_141799080 (RVA 0x1799080) reads 0x28,0x38,0x40 (skin-loop signature)
  - sub_141799700 (RVA 0x1799700) reads 0x10,0x28,0x38,0x48

Also:
  - Decomp the BSGeometry slot 51 sub_1416D4F80 (size 633, biggest
    BSGeometry virtual): possibly the per-frame "render submit" virtual.
  - Decomp the BSGeometry slot 27 sub_1416D49F0 (size 174) and slot 33
    sub_1416D53A0 (size 252) — size suggests serialization but worth
    quick check.
  - Decomp sub_1416D5260 (slot 32, size 306, present in BSGeometry/Tri/
    SubIdx/Dyn). Likely a shared inherited update.
  - Decomp sub_1417E5B00 (BSSubIndexTriShape slot 26, size 278).
  - Decomp sub_1417E66F0 (BSSubIndexTriShape vt[67] = NEW SLOT, size 96).
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref, ida_ua
import struct

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_AGENT_B2_raw.log"
IMG = 0x140000000
out_lines = []

def log(s=""):
    out_lines.append(s if isinstance(s, str) else str(s))

def hexs(x):
    try: return "0x%X" % x
    except: return str(x)

def rva(ea): return ea - IMG

def fn_size(ea):
    f = ida_funcs.get_func(ea)
    return f.size() if f else 0

def fn_name(ea):
    return ida_funcs.get_func_name(ea) or ""

def safe_decompile(ea, max_lines=500):
    try:
        c = ida_hexrays.decompile(ea)
        if not c: return None
        s = str(c).split("\n")
        if len(s) > max_lines:
            s = s[:max_lines] + ["    ... <truncated>"]
        return "\n".join(s)
    except Exception as e:
        return "<decomp error: %s>" % e

def disasm_first(ea, n=80):
    out = []
    cur = ea
    for i in range(n):
        if cur == idaapi.BADADDR: break
        out.append("  %s   %s" % (hexs(cur), idc.GetDisasm(cur)))
        nxt = idc.next_head(cur)
        if nxt == idaapi.BADADDR: break
        cur = nxt
    return "\n".join(out)

def xrefs_to_code(ea):
    refs = []
    x = ida_xref.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_cref_to(ea, x)
    return refs

def callers_of(ea):
    out = set()
    for r in xrefs_to_code(ea):
        f = ida_funcs.get_func(r)
        if f:
            out.add(f.start_ea)
    return list(out)

# === Functions to deep-decomp ===
TARGETS = [
    (0x140CA7880, "sub_140CA7880 reads 0x10,0x28,0x38,0x48 + matmul=1"),
    (0x141790E20, "sub_141790E20 reads 0x10,0x38,0x40,0x48 + matmul=1"),
    (0x141794690, "sub_141794690 reads 0x38,0x40,0x48 + matmul=1"),
    (0x140568D20, "sub_140568D20 reads 0x10,0x38,0x40,0x48 + matmul=1"),
    (0x14187E990, "sub_14187E990 reads all 5 + matmul=1"),
    (0x140C87EA0, "sub_140C87EA0 reads all 5 + matmul=1"),
    (0x140E3F220, "sub_140E3F220 reads all 5 + matmul=1"),
    (0x141799080, "sub_141799080 reads 0x28,0x38,0x40"),
    (0x141799700, "sub_141799700 reads 0x10,0x28,0x38,0x48"),
    (0x1418A8DB0, "sub_1418A8DB0 reads all 5 + matmul=2"),
    (0x1418BD4B0, "sub_1418BD4B0 reads all 5 + matmul=2"),
    (0x14180B410, "sub_14180B410 reads 0x28,0x38,0x40,0x48 + matmul=2"),
    (0x1416EF580, "sub_1416EF580 reads 0x10,0x28,0x38 + matmul=1"),
    (0x14186D990, "sub_14186D990 reads 0x10,0x28 + matmul=1"),
    (0x141891BF0, "sub_141891BF0 reads 0x10 + matmul=1"),
    (0x14039BA80, "sub_14039BA80 reads 0x10,0x40 + matmul=1"),
    (0x1403FA980, "sub_1403FA980 reads 0x10,0x28,0x38,0x40"),
    (0x14040D4C0, "sub_14040D4C0 known: bone resolver caller"),
    # BSGeometry virtuals
    (0x1416D4F80, "BSGeometry slot 51 (size 633) — biggest"),
    (0x1416D53A0, "BSGeometry slot 33 (size 252)"),
    (0x1416D5260, "BSGeometry slot 32 (size 306)"),
    (0x1416D49F0, "BSGeometry slot 27 (size 174)"),
    (0x1416C8A60, "BSGeometry slot 53 (size 83) pre-render hook"),
    (0x1416C81A0, "BSGeometry slot 45 (size 105)"),
    # BSSubIndexTriShape vt-extras
    (0x1417E5B00, "BSSubIndexTriShape vt[26] (size 278)"),
    (0x1417E5C90, "BSSubIndexTriShape vt[27] (size 214)"),
    (0x1417E5D70, "BSSubIndexTriShape vt[28] (size 111)"),
    (0x1417E5E00, "BSSubIndexTriShape vt[30] (size 51)"),
    (0x1417E66F0, "BSSubIndexTriShape vt[67] (size 96)"),
    (0x1417E6750, "BSSubIndexTriShape vt[0] (size 204)"),
    # BSTriShape extras
    (0x1416DA340, "BSTriShape vt[0] (size 167)"),
    (0x1416D99E0, "BSTriShape vt[26] (size 331)"),
    (0x1416D9BD0, "BSTriShape vt[27] (size 541)"),
    (0x1416D9E20, "BSTriShape vt[30] (size 397)"),
    (0x1416DA2B0, "BSTriShape vt[67] (size 134)"),
    # Skin instance vtable methods (which we haven't seen)
    (0x1416D8CC0, "BSSkin::Instance vt[0] (dtor)"),
]

# Decomp each target
log("=" * 78)
log(" DECOMP OF TARGET FUNCTIONS")
log("=" * 78)

for ea, label in TARGETS:
    sz = fn_size(ea)
    log("\n" + "=" * 78)
    log(" %s @ %s (RVA %s, size %d)" % (label, hexs(ea), hexs(rva(ea)), sz))
    log("=" * 78)
    dec = safe_decompile(ea, 300)
    log(dec or "<no decomp>")
    log("\n  callers:")
    for c in callers_of(ea)[:10]:
        log("    %s (RVA %s) %s" % (hexs(c), hexs(rva(c)), fn_name(c)))

# === Special: DEEP decomp of BSGeometry slot 51 (size 633) — likely renders ===
log("\n" + "=" * 78)
log(" DEEP DECOMP — BSGeometry slot 51 sub_1416D4F80 (FULL)")
log("=" * 78)
dec = safe_decompile(0x1416D4F80, 600)
log(dec or "<no decomp>")

# === Search for BSSkin::BoneData vtable @ 0x14267E480 ===
# Anyone who uses it might process bone matrices.
log("\n" + "=" * 78)
log(" BSSkin::BoneData vtable @ 0x14267E480 — xrefs and slot dump")
log("=" * 78)

BD_VT = 0x14267E480
log(" vtable slots:")
for i in range(16):
    se = BD_VT + 8 * i
    tg = ida_bytes.get_qword(se)
    if tg == 0 or not (0x140000000 <= tg < 0x150000000):
        break
    sz = fn_size(tg)
    log("   [%2d] %s -> %s (RVA %s, size %d) %s" %
        (i, hexs(se), hexs(tg), hexs(rva(tg)), sz, fn_name(tg)))

# Find xrefs to vtable
log("\n vtable data xrefs (where vt is loaded as ptr):")
x = ida_xref.get_first_dref_to(BD_VT)
while x != idaapi.BADADDR:
    f = ida_funcs.get_func(x)
    fea = f.start_ea if f else idaapi.BADADDR
    log("   ref @ %s in fn %s %s" % (hexs(x), hexs(fea), fn_name(fea)))
    x = ida_xref.get_next_dref_to(BD_VT, x)

# === Search for BSSkin::Instance vtable usages other than ctor/dtor ===
log("\n" + "=" * 78)
log(" BSSkin::Instance vtable @ 0x14267E5C8 — full xrefs")
log("=" * 78)

SK_VT = 0x14267E5C8
x = ida_xref.get_first_dref_to(SK_VT)
while x != idaapi.BADADDR:
    f = ida_funcs.get_func(x)
    fea = f.start_ea if f else idaapi.BADADDR
    log("   ref @ %s in fn %s %s" % (hexs(x), hexs(fea), fn_name(fea)))
    x = ida_xref.get_next_dref_to(SK_VT, x)

# === Find every function that loads BSGeometry+0x140 (skin instance ptr)
#     into a register. Wider scan than before; iterate all functions.
log("\n" + "=" * 78)
log(" Wide scan: ALL functions that read [reg+0x140] where the reg holds")
log(" a BSGeometry-like object. Filter by also calling matmul OR using")
log(" the resolver sub_1403F85E0.")
log("=" * 78)

MATMUL_EA = 0x1403444F0
RESOLVER_EA = 0x1403F85E0

def fn_calls(fn_ea, target_ea):
    func = ida_funcs.get_func(fn_ea)
    if not func: return False
    cur = func.start_ea
    while cur < func.end_ea:
        if idc.print_insn_mnem(cur).lower() == "call":
            tgt = idc.get_operand_value(cur, 0)
            if tgt == target_ea: return True
        cur = idc.next_head(cur, func.end_ea)
    return False

def fn_reads_off(fn_ea, off, max_count=999):
    func = ida_funcs.get_func(fn_ea)
    if not func: return 0
    cur = func.start_ea
    cnt = 0
    needles = ["+%Xh" % off, "+0x%X" % off]
    while cur < func.end_ea:
        for op_idx in (0, 1, 2):
            try:
                op_str = idc.print_operand(cur, op_idx)
                for nd in needles:
                    if nd in op_str:
                        cnt += 1
                        if cnt >= max_count: return cnt
            except Exception:
                pass
        cur = idc.next_head(cur, func.end_ea)
    return cnt

# Get all functions; this is ~15-30 sec for 80k fns.
log(" Counting functions with 0x140 reads (may take 30s)...")
seg = ida_segment.get_segm_by_name(".text")
all_fns = []
fea = seg.start_ea
while fea < seg.end_ea:
    f = ida_funcs.get_func(fea)
    if f:
        all_fns.append(f.start_ea)
        fea = f.end_ea
    else:
        fea = idc.next_head(fea, seg.end_ea)

uniq_fns = list(set(all_fns))
log(" Total functions: %d" % len(uniq_fns))

hits = []
for f in uniq_fns:
    sz = fn_size(f)
    if sz < 30 or sz > 8000: continue
    cnt140 = fn_reads_off(f, 0x140)
    if cnt140 == 0: continue
    cnt28 = fn_reads_off(f, 0x28)
    cnt38 = fn_reads_off(f, 0x38)
    cnt40 = fn_reads_off(f, 0x40)
    cnt70 = fn_reads_off(f, 0x70)
    if cnt28 + cnt38 + cnt40 + cnt70 < 3: continue
    if cnt140 + cnt28 + cnt38 + cnt40 < 5: continue
    has_matmul = fn_calls(f, MATMUL_EA)
    has_resolver = fn_calls(f, RESOLVER_EA)
    hits.append((f, cnt140, cnt28, cnt38, cnt40, cnt70, has_matmul, has_resolver, sz))

hits.sort(key=lambda x: -(x[1] + x[2] + x[3] + x[4] + x[5]))
log("\n Top 30 hits sorted by total skin-read count:")
for h in hits[:30]:
    f, c140, c28, c38, c40, c70, mm, rv, sz = h
    log("   fn %s  size=%d  +140=%d +28=%d +38=%d +40=%d +70=%d  matmul=%d resolver=%d  %s" %
        (hexs(f), sz, c140, c28, c38, c40, c70, int(mm), int(rv), fn_name(f)))

# Decomp top 5 of these (the strongest candidates if any look like a per-bone loop)
for h in hits[:6]:
    f, c140, c28, c38, c40, c70, mm, rv, sz = h
    log("\n" + "=" * 60)
    log(" WIDE-SCAN HIT: fn %s (RVA %s) +140=%d +28=%d +38=%d +40=%d +70=%d size=%d" %
        (hexs(f), hexs(rva(f)), c140, c28, c38, c40, c70, sz))
    log("=" * 60)
    dec = safe_decompile(f, 500)
    log(dec or "<no decomp>")

# === Final: look at sub_141799080 / sub_141799700 / sub_14186D990 ===
# These show signatures that could be per-bone CPU skin update.
log("\n" + "=" * 78)
log(" Detailed disasm of sub_141799080 (size 1036) and sub_141799700 (size 700)")
log(" — those read skin offsets 0x28/0x38/0x40 — strong CPU-skin-update sig.")
log("=" * 78)

for ea, label in [(0x141799080, "sub_141799080"),
                  (0x141799700, "sub_141799700"),
                  (0x14186D990, "sub_14186D990"),
                  (0x14187E990, "sub_14187E990"),
                  (0x140568D20, "sub_140568D20")]:
    log("\n=== %s (RVA %s, size %d) — DISASM (first 100 ins) ===" %
        (label, hexs(rva(ea)), fn_size(ea)))
    log(disasm_first(ea, 100))
    log("\n--- DECOMP ---")
    log(safe_decompile(ea, 200) or "<no decomp>")

# === Search for D3D11 ID3D11DeviceContext::Map / UpdateSubresource imports ===
log("\n" + "=" * 78)
log(" D3D11 import/wrapper inspection — find skin CB upload site")
log("=" * 78)

# Find ID3D11DeviceContext::Map by searching for the string "Map" or by ext_seg
for s in ["UpdateSubresource", "Map", "VSSetConstantBuffers"]:
    needle = s.encode("utf-8") + b"\x00"
    matches = []
    seg2 = idaapi.get_first_seg()
    while seg2:
        ea = seg2.start_ea
        f = ida_bytes.find_bytes(needle, ea, seg2.end_ea)
        while f != idaapi.BADADDR:
            matches.append(f)
            f = ida_bytes.find_bytes(needle, f + 4, seg2.end_ea)
            if len(matches) >= 10: break
        seg2 = idaapi.get_next_seg(seg2.start_ea)
        if len(matches) >= 10: break
    log(" '%s' string addrs: %s" % (s, [hexs(a) for a in matches[:5]]))

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "lines:", len(out_lines))
idaapi.qexit(0)
