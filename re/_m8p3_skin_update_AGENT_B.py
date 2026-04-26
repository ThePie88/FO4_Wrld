"""
M8P3 — AGENT B INDEPENDENT SCRIPT.

Goal: Find the CPU skin update function — the routine that reads bone world
matrices from BSSkin::Instance, applies inverse-bind, writes a flat per-bone
matrix buffer that is uploaded as a constant buffer.

Strategy (DIFFERENT from Agent A — start from GPU/CB side):

  S1. CB writers: enumerate xrefs to "PerGeometry" string and walk the
      writer side (BSLightingShader::SetupGeometry, vt[8] @ 0x22342C0).
      Find which sub-function inside it iterates bones.

  S2. Pattern search: the 4x4 matmul helper sub_1403444F0 is already
      identified. Any function that calls it in a TIGHT LOOP with a
      stride matching bones (skin+0x28 / count skin+0x38) — that's a
      strong skin-update candidate.

  S3. BSGeometry/BSTriShape slot 53 = sub_1416C8A60 (already known to be
      the BSGeometry-specific UpdateWorldData override). Decompile it and
      see if it dispatches to skin processing.

  S4. Scan disasm for "mov rcx, [...0x140]" — load of skin instance
      pointer from BSGeometry+0x140. Functions that do this and ALSO call
      sub_1403444F0 (matmul) or read bones (...+0x28) are skin processors.

  S5. Look at xrefs to BSSkin::Instance vt 0x14267E5C8 — every function
      that uses RTTI/dynamic_cast to a skin instance. Then filter those
      that perform per-frame work.

  S6. Identify the "SkinDeformer" / similar string if any. Also look for
      "PreviousBones" / "BoneTintIndices" CB-field name strings to find
      direct CB-write sites.
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref, ida_ua
import struct, re

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_AGENT_B_raw.log"
IMG = 0x140000000
out_lines = []

# ---- Known constants from prior dossiers ----
SKIN_VT_RVA       = 0x267E5C8     # BSSkin::Instance vtable
GEOM_VT_RVA       = 0x267E0B8     # BSGeometry vtable
TRI_VT_RVA        = 0x267E948     # BSTriShape vtable
SUBIDX_VT_RVA     = 0x2697D40     # BSSubIndexTriShape vtable
DYN_VT_RVA        = 0x267F948     # BSDynamicTriShape vtable
MATMUL44_RVA      = 0x3444F0      # 4x4*4x4 multiply helper
NIAVOBJ_UWD_RVA   = 0x16C85A0     # NiAVObject::UpdateWorldData (base)
GEOM_SLOT53_RVA   = 0x16C8A60     # BSGeometry slot 53 override (pre-render hook)
SETUP_GEOM_RVA    = 0x22342C0     # BSLightingShader::SetupGeometry
CB_MAP_A_RVA      = 0x21A0680     # CB_Map_A
CB_MAP_B_RVA      = 0x21A05E0     # CB_Map_B
RESOLVER_RVA      = 0x3F85E0      # bone-name resolver

def log(s=""):
    out_lines.append(s if isinstance(s, str) else str(s))

def hexs(x):
    try: return "0x%X" % x
    except: return str(x)

def rva(ea): return ea - IMG

def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idaapi.BADADDR

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
            s = s[:max_lines] + ["    ... <truncated %d more lines>" % (len(s)-max_lines)]
        return "\n".join(s)
    except Exception as e:
        return "<decomp error: %s>" % e

def find_string_addr(s):
    needle = s.encode("utf-8") + b"\x00"
    matches = []
    seg = idaapi.get_first_seg()
    while seg:
        ea = seg.start_ea
        end = seg.end_ea
        f = ida_bytes.find_bytes(needle, ea, end)
        while f != idaapi.BADADDR:
            matches.append(f)
            ea2 = f + len(needle)
            f = ida_bytes.find_bytes(needle, ea2, end)
            if len(matches) >= 32: break
        seg = idaapi.get_next_seg(seg.start_ea)
        if len(matches) >= 32: break
    return matches

def xrefs_to_data(ea):
    refs = []
    x = ida_xref.get_first_dref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_dref_to(ea, x)
    return refs

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
        f = fn_start(r)
        if f != idaapi.BADADDR:
            out.add(f)
    return list(out)

# ============================================================================
# S0. Headline: dump BSGeometry / BSTriShape / BSSubIndexTriShape vtables
#     with full slot listing for slots 0..70 (covering the known 60+ slots).
# ============================================================================
log("=" * 78)
log(" S0 — Vtable dump: BSGeometry / BSTriShape / BSSubIndexTriShape")
log("=" * 78)

def dump_vtable(name, vt_rva, num_slots=72):
    log("")
    log(" === %s vtable @ %s ===" % (name, hexs(IMG + vt_rva)))
    for i in range(num_slots):
        slot_ea = IMG + vt_rva + 8 * i
        target = ida_bytes.get_qword(slot_ea)
        if target == 0 or target == idaapi.BADADDR:
            break
        # only continue if target looks like text segment ptr
        if not (0x140000000 <= target < 0x150000000):
            log("   [%2d] %s -> %s  (not text-seg, stop)" % (i, hexs(slot_ea), hexs(target)))
            break
        sz = fn_size(target)
        nm = fn_name(target)
        log("   [%2d] %s -> %s  (RVA %s, size %d)  %s" %
            (i, hexs(slot_ea), hexs(target), hexs(rva(target)), sz, nm))

dump_vtable("BSGeometry",         GEOM_VT_RVA,   72)
dump_vtable("BSTriShape",         TRI_VT_RVA,    72)
dump_vtable("BSSubIndexTriShape", SUBIDX_VT_RVA, 72)
dump_vtable("BSDynamicTriShape",  DYN_VT_RVA,    72)
dump_vtable("BSSkin::Instance",   SKIN_VT_RVA,   24)

# ============================================================================
# S1. CB writers: starting from "PerGeometry" string. Look at SetupGeometry @
#     0x22342C0; also find PreviousBones, BoneTintIndices, BoneIndex strings.
# ============================================================================
log("\n" + "=" * 78)
log(" S1 — CB-side string search and SetupGeometry decomp")
log("=" * 78)

cb_strings = ["PerGeometry", "PerTechnique", "PerMaterial",
              "PreviousBones", "BoneTintIndices", "Bones",
              "BoneIndex", "BoneMatrix", "BonePalette",
              "Skin", "skin", "SkinDeformer", "BSSkin"]

cb_strings_locs = {}
for s in cb_strings:
    matches = find_string_addr(s)
    cb_strings_locs[s] = matches
    log("\n '%s' addrs: %s" % (s, [hexs(a) for a in matches[:8]]))
    for m in matches[:6]:
        for r in xrefs_to_data(m):
            f = fn_start(r)
            log("   ref @ %s in fn %s %s" %
                (hexs(r), hexs(f), fn_name(f)))

# Decomp BSLightingShader::SetupGeometry (vt[8]) — this is the per-geometry
# CB writer. If skinning happens here, we'll see bones[] iteration.
log("\n" + "-" * 78)
log(" SetupGeometry @ 0x22342C0 decomp")
log("-" * 78)
dec = safe_decompile(IMG + SETUP_GEOM_RVA, 600)
log(dec or "<no decomp>")

log("\n" + "-" * 78)
log(" SetupGeometry callers (where it's invoked)")
log("-" * 78)
for c in callers_of(IMG + SETUP_GEOM_RVA)[:20]:
    log("   caller fn %s %s" % (hexs(c), fn_name(c)))

# ============================================================================
# S2. Matmul pattern: callers of sub_1403444F0 in TIGHT LOOPS.
# ============================================================================
log("\n" + "=" * 78)
log(" S2 — Matmul callers (sub_1403444F0). Tight-loop callers are skin-update")
log("     candidates.")
log("=" * 78)

matmul_ea = IMG + MATMUL44_RVA
matmul_callers = callers_of(matmul_ea)
log(" matmul has %d unique caller functions." % len(matmul_callers))
log("")

# For each caller, count how many CALL sites to matmul exist (multi-call ⇒
# loop or sequential 4x4 sequence).
multi_callers = []
for c in matmul_callers:
    func = ida_funcs.get_func(c)
    if not func: continue
    # iterate disasm in fn, count call sites whose target is matmul_ea
    cnt = 0
    ea = func.start_ea
    while ea < func.end_ea:
        if idc.print_insn_mnem(ea).lower() == "call":
            tgt = idc.get_operand_value(ea, 0)
            if tgt == matmul_ea:
                cnt += 1
        ea = idc.next_head(ea, func.end_ea)
    if cnt >= 1:
        multi_callers.append((c, cnt, func.size()))

multi_callers.sort(key=lambda x: -x[1])
log(" Top matmul-loop callers (by count):")
for c, cnt, sz in multi_callers[:30]:
    log("   fn %s (RVA %s) size=%d  matmul-calls=%d  %s" %
        (hexs(c), hexs(rva(c)), sz, cnt, fn_name(c)))

# Decomp the top 8 loop-callers — these are the leading skin-update candidates.
log("")
for c, cnt, sz in multi_callers[:8]:
    log("\n" + "=" * 60)
    log(" CANDIDATE: fn %s (RVA %s) — matmul-calls=%d, size=%d" %
        (hexs(c), hexs(rva(c)), cnt, sz))
    log("=" * 60)
    dec = safe_decompile(c, 250)
    log(dec or "<no decomp>")

# ============================================================================
# S3. BSGeometry slot 53 (sub_1416C8A60) decomp — BSGeometry-specific
#     UpdateWorldData hook, may dispatch to skin update.
# ============================================================================
log("\n" + "=" * 78)
log(" S3 — BSGeometry slot 53 = sub_1416C8A60 (pre-render hook)")
log("=" * 78)

dec = safe_decompile(IMG + GEOM_SLOT53_RVA, 350)
log(dec or "<no decomp>")

log("\n" + "-" * 78)
log(" sub_1416C8A60 callers")
log("-" * 78)
for c in callers_of(IMG + GEOM_SLOT53_RVA)[:20]:
    log("   caller fn %s %s" % (hexs(c), fn_name(c)))

# ============================================================================
# S4. Disasm scan: "mov rcx/rax/rbx, [reg+140h]" loads of skin instance ptr
#     from BSGeometry. Functions doing this AND calling matmul are key.
# ============================================================================
log("\n" + "=" * 78)
log(" S4 — Functions that load BSGeometry+0x140 (skin instance ptr) AND")
log("     call matmul. Filtered to 'process bones' callers.")
log("=" * 78)

# Scan the .text segment for "mov reg, [reg+140h]" disasm patterns.
# IDA's instruction iteration would be slow over the whole binary; instead
# narrow down: look at the multi_callers list and check if they read
# [...+140h] anywhere.
def fn_reads_offset_140(fn_ea):
    func = ida_funcs.get_func(fn_ea)
    if not func: return False
    ea = func.start_ea
    while ea < func.end_ea:
        # check operand 1 for memory access with 0x140 displacement
        for op_idx in (0, 1, 2):
            try:
                op_str = idc.print_operand(ea, op_idx)
                if "+140h" in op_str or "+0x140" in op_str:
                    return True
            except Exception:
                pass
        ea = idc.next_head(ea, func.end_ea)
    return False

log(" Filtering top matmul-callers by 'reads [reg+140h]':")
hot_candidates = []
for c, cnt, sz in multi_callers[:60]:
    try:
        if fn_reads_offset_140(c):
            hot_candidates.append((c, cnt, sz))
            log("   HIT: fn %s (RVA %s)  matmul=%d  size=%d  %s" %
                (hexs(c), hexs(rva(c)), cnt, sz, fn_name(c)))
    except Exception as e:
        log("   error scanning %s: %s" % (hexs(c), e))

log(" Total %d functions both call matmul AND read [+140h]." % len(hot_candidates))

# Decomp these (top 6) in full
for c, cnt, sz in hot_candidates[:6]:
    log("\n" + "=" * 60)
    log(" HOT CANDIDATE: fn %s (RVA %s) matmul=%d size=%d" %
        (hexs(c), hexs(rva(c)), cnt, sz))
    log("=" * 60)
    dec = safe_decompile(c, 400)
    log(dec or "<no decomp>")

# ============================================================================
# S5. Functions that READ BSSkin::Instance fields:
#     +0x10 (bones_fb head), +0x28 (bones_pri head), +0x38 (count),
#     +0x40 (boneData), +0x48 (skel_root). Then walk callers.
# ============================================================================
log("\n" + "=" * 78)
log(" S5 — Functions that read BSSkin::Instance critical offsets")
log("=" * 78)

# Limit scan to the multi_callers + hot_candidates.
def fn_reads_offsets(fn_ea, offsets):
    """Return set of offsets read by fn from any reg."""
    func = ida_funcs.get_func(fn_ea)
    if not func: return set()
    found = set()
    ea = func.start_ea
    while ea < func.end_ea:
        for op_idx in (0, 1, 2):
            try:
                op_str = idc.print_operand(ea, op_idx)
                for off in offsets:
                    needle = "+%Xh" % off if off >= 10 else "+%X" % off
                    if needle in op_str:
                        found.add(off)
            except Exception:
                pass
        ea = idc.next_head(ea, func.end_ea)
    return found

skin_offsets = [0x10, 0x28, 0x38, 0x40, 0x48]
log(" For each top matmul-caller, list which BSSkin::Instance offsets it reads:")
for c, cnt, sz in multi_callers[:40]:
    try:
        offs = fn_reads_offsets(c, skin_offsets)
        if offs:
            log("   fn %s (RVA %s)  matmul=%d  reads-skin-offs=%s" %
                (hexs(c), hexs(rva(c)), cnt,
                 ",".join("0x%X" % o for o in sorted(offs))))
    except Exception as e:
        pass

# ============================================================================
# S6. Vtable iter on BSSkin::Instance. Each slot — what does it do?
# ============================================================================
log("\n" + "=" * 78)
log(" S6 — BSSkin::Instance vtable slot decomp (each slot is a virtual method)")
log("=" * 78)

for i in range(24):
    slot_ea = IMG + SKIN_VT_RVA + 8 * i
    target = ida_bytes.get_qword(slot_ea)
    if target == 0 or not (0x140000000 <= target < 0x150000000):
        break
    sz = fn_size(target)
    log("\n=== BSSkin::Instance vt[%d] @ %s -> %s (RVA %s, size %d) ===" %
        (i, hexs(slot_ea), hexs(target), hexs(rva(target)), sz))
    if sz > 0 and sz < 4000:
        dec = safe_decompile(target, 80)
        if dec:
            for ln in dec.split("\n"):
                log("    " + ln)

# ============================================================================
# S7. Find where bones_pri[i]+0x70 (= bone.world matrix) is read in a loop.
#     The classic skin-update reads each bone's world matrix and writes
#     to a flat output array. Pattern: loop body `mov xmm, [reg+70h]` ... 4x.
# ============================================================================
log("\n" + "=" * 78)
log(" S7 — Functions reading [reg+70h] (bone.world) AND [reg+10h]/[reg+28h]")
log("     (skin->bones array) — strong skin-update signature.")
log("=" * 78)

def fn_reads_bone_world(fn_ea):
    """Detect 'mov xmm/movaps/movups, [reg+70h]' patterns near a 'bones' read."""
    func = ida_funcs.get_func(fn_ea)
    if not func: return (0, 0)
    reads_70 = 0
    reads_28_or_10 = 0
    ea = func.start_ea
    while ea < func.end_ea:
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem in ("movaps", "movups", "movdqa", "movdqu", "movss", "movsd", "mov"):
            for op_idx in (0, 1, 2):
                try:
                    op_str = idc.print_operand(ea, op_idx)
                    if "+70h" in op_str or "+0x70" in op_str:
                        reads_70 += 1
                    if "+28h" in op_str or "+10h" in op_str:
                        reads_28_or_10 += 1
                except Exception:
                    pass
        ea = idc.next_head(ea, func.end_ea)
    return (reads_70, reads_28_or_10)

# Scan top matmul-callers and report
log(" Filtering top matmul-callers for bone-loop signature:")
sig_hits = []
for c, cnt, sz in multi_callers[:80]:
    try:
        r70, r28 = fn_reads_bone_world(c)
        if r70 >= 4 and r28 >= 1:    # 4 row-reads from +0x70 + at least 1 bones-array read
            sig_hits.append((c, cnt, sz, r70, r28))
    except Exception:
        pass

sig_hits.sort(key=lambda x: -x[3])
log(" Bone-loop signature hits (matmul>=1, +0x70 reads>=4, +0x28/0x10 reads>=1):")
for c, cnt, sz, r70, r28 in sig_hits[:20]:
    log("   fn %s (RVA %s) size=%d  matmul=%d  +0x70-reads=%d  +0x28/10-reads=%d  %s" %
        (hexs(c), hexs(rva(c)), sz, cnt, r70, r28, fn_name(c)))

# Decomp top 5
log("")
for c, cnt, sz, r70, r28 in sig_hits[:5]:
    log("\n" + "=" * 60)
    log(" BONE-LOOP CAND: fn %s (RVA %s) matmul=%d  +70=%d +28/10=%d  size=%d" %
        (hexs(c), hexs(rva(c)), cnt, r70, r28, sz))
    log("=" * 60)
    dec = safe_decompile(c, 350)
    log(dec or "<no decomp>")

# ============================================================================
# S8. Search for D3D11 import xrefs to UpdateSubresource and Map. The skin
#     CB upload likely uses one of these. Sub-3712-byte-write site = bone CB.
#     3712 = 64 * 58 (max bones). Common counts: 30 bones × 64 = 1920;
#     58 bones × 64 = 3712; 64 bones × 64 = 4096.
# ============================================================================
log("\n" + "=" * 78)
log(" S8 — D3D11 Map / UpdateSubresource callers (CB upload sites)")
log("=" * 78)

# First, locate ID3D11DeviceContext::Map and ::UpdateSubresource. They are
# typically in the import table or via vtable on the d3d device context global.
# Look for "Map" string in vtable comments — easier to find via the wrappers
# CB_Map_A/B which are already known to wrap these.

cbmap_callers = callers_of(IMG + CB_MAP_A_RVA)
log(" CB_Map_A @ 0x21A0680 callers: %d" % len(cbmap_callers))
for c in cbmap_callers[:30]:
    log("   fn %s (RVA %s) %s" % (hexs(c), hexs(rva(c)), fn_name(c)))

cbmap_b_callers = callers_of(IMG + CB_MAP_B_RVA)
log("\n CB_Map_B @ 0x21A05E0 callers: %d" % len(cbmap_b_callers))
for c in cbmap_b_callers[:30]:
    log("   fn %s (RVA %s) %s" % (hexs(c), hexs(rva(c)), fn_name(c)))

# ============================================================================
# S9. Cross-check: in the FINAL CANDIDATE, look for size constants like 64, 0x40
#     (matrix size) or 0x50 (per-bone-data stride).
# ============================================================================
log("\n" + "=" * 78)
log(" S9 — In the final candidate(s), look for size constants 0x40, 0x50")
log("=" * 78)

def fn_uses_constants(fn_ea, consts):
    func = ida_funcs.get_func(fn_ea)
    if not func: return set()
    found = set()
    ea = func.start_ea
    while ea < func.end_ea:
        for op_idx in (0, 1, 2):
            try:
                v = idc.get_operand_value(ea, op_idx)
                if v in consts:
                    found.add(v)
            except Exception:
                pass
        ea = idc.next_head(ea, func.end_ea)
    return found

interesting_consts = {0x40, 0x50, 0x80, 0xC0, 64, 80}
log(" For top sig_hits, list which constants present:")
for c, cnt, sz, r70, r28 in sig_hits[:10]:
    found = fn_uses_constants(c, interesting_consts)
    log("   fn %s -- consts present: %s" %
        (hexs(c), ",".join("0x%X" % x for x in sorted(found))))

# ============================================================================
# Done.
# ============================================================================
log("\n" + "=" * 78)
log(" DONE.")
log("=" * 78)

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(out_lines))
print("wrote", LOG_PATH, "lines:", len(out_lines))
idaapi.qexit(0)
