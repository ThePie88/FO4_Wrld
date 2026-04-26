"""
M8P3 — SCENE REGISTER candidate analysis.

Goal: identify which post-Load3D function actually registers a freshly-loaded
BSFadeNode/BSGeometry into the engine's per-frame skin-update walker.

Decompiles the candidate set:
    sub_141026640  (annotated SCENE REGISTER)
    sub_141026980  (annotated SCENE BROADCAST — walks 6 slots in qword_1430DBD58)
    sub_14102D4C0  (broadcast worker invoked from sub_141026980)
    sub_140787980  (scene singleton notify)
    sub_1406EF810  (cell-graph notify)
    sub_140528410  (post-attach housekeeping)

Also dumps qword_1430DBD58+0x118..+0x140 layout (6 subsystem slots), tries to
identify each slot's vtable / class via RTTI, and looks for "skin update" /
"BSAnimationManager" / "BSGeometryDB" / "BSSkinManager" string evidence.

Output:
    re/_m8p3_scene_register_raw.log     (raw decompilations + xref tables)
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_scene_register_raw.log"
out_lines = []
BASE = 0x140000000

CANDIDATES = [
    ("sub_141026640", 0x1026640, "SCENE REGISTER (annotated)"),
    ("sub_141026980", 0x1026980, "SCENE BROADCAST — walks 6 slots in qword_1430DBD58"),
    ("sub_14102D4C0", 0x102D4C0, "broadcast worker"),
    ("sub_140787980", 0x787980,  "scene singleton notify"),
    ("sub_1406EF810", 0x6EF810,  "cell-graph notify"),
    ("sub_140528410", 0x528410,  "post-attach housekeeping"),
]

# Post-Load3D singletons we want to inspect
SCENE_SINGLETON  = 0x1430DBD58       # the 6-slot dispatcher
SLOTS_BASE_OFF   = 0x118
SLOTS_END_OFF    = 0x140
NUM_SLOTS        = (SLOTS_END_OFF - SLOTS_BASE_OFF) // 8 + 1   # 6 slots

# RTTI / string keys we want to detect inside decomp / xrefs
KEY_STRINGS = [
    "BSPortalGraph", "ShadowSceneNode", "BSAnimationManager",
    "BSGeometryDB", "BSSkinManager", "BSAnimationGraphManager",
    "ProcessLists", "SkinningManager", "ShadowSceneNode",
    "BSPortalGraphEntry", "BSPortalSharedNode", "BSCullingProcess",
    "BSLensFlareRenderData", "BSLightingShaderProperty",
    "BSWaterShaderProperty", "BSEffectShaderProperty",
    "BSShaderManager", "ProcessLists", "BSFadeNode",
    "BSDistantObjectInstanceRenderer", "BSScrapHeap",
    "BSMultiBoundNode", "BSPortalGraph",
]

# ----------------------------------------------------------------------
# helpers
def log(s=""):
    out_lines.append(s if isinstance(s, str) else str(s))

def hexs(x):
    try: return "0x%X" % x
    except: return str(x)

def rva(ea): return ea - BASE

def name_at(ea):
    try:
        n = ida_name.get_name(ea)
        if n: return n
    except: pass
    try:
        n = ida_funcs.get_func_name(ea)
        if n: return n
    except: pass
    return "?"

def fn_size(ea):
    f = ida_funcs.get_func(ea)
    if not f: return None
    return f.end_ea - f.start_ea

def safe_decomp(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        if cf: return str(cf)
    except Exception as e:
        return "<decomp err: %s>" % e
    return None

def disasm_lines(start_ea, max_lines=80):
    f = ida_funcs.get_func(start_ea)
    if not f:
        return ["<no func>"]
    out = []
    cur = f.start_ea
    n = 0
    while cur < f.end_ea and n < max_lines:
        line = idc.generate_disasm_line(cur, 0) or ""
        out.append("    %s: %s" % (hexs(cur), line))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
        n += 1
    return out

def call_targets_in_func(start_ea):
    f = ida_funcs.get_func(start_ea)
    if not f: return []
    out = []
    seen = set()
    cur = f.start_ea
    while cur < f.end_ea:
        mnem = idc.print_insn_mnem(cur)
        if mnem in ("call", "jmp"):
            target = idc.get_operand_value(cur, 0)
            if target and target != idc.BADADDR:
                tf = ida_funcs.get_func(target)
                if tf and target != f.start_ea:
                    key = (cur, target)
                    if key not in seen:
                        seen.add(key)
                        out.append((cur, target, mnem))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

# Build string cache
_STRING_CACHE = None
def build_string_cache():
    global _STRING_CACHE
    if _STRING_CACHE is not None: return
    _STRING_CACHE = {}
    try:
        for sx in idautils.Strings():
            try:
                s = str(sx)
                _STRING_CACHE.setdefault(s, []).append(sx.ea)
            except: pass
    except Exception as e:
        log("string cache err: %s" % e)

def find_strings_containing(needle):
    build_string_cache()
    res = []
    nl = needle.lower()
    for k, eas in _STRING_CACHE.items():
        if nl in k.lower():
            res.append((k, eas))
    return res

def xrefs_to_addr(ea):
    refs = []
    x = ida_xref.get_first_xref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_xref_to(ea, x)
    return refs

def data_xrefs_to(ea):
    refs = []
    x = ida_xref.get_first_dref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_dref_to(ea, x)
    return refs

def code_xrefs_to(ea):
    refs = []
    x = ida_xref.get_first_cref_to(ea)
    while x != idaapi.BADADDR:
        refs.append(x)
        x = ida_xref.get_next_cref_to(ea, x)
    return refs

# ============================================================================
log("=" * 78)
log(" M8P3 — SCENE REGISTER analysis")
log(" Fallout4.exe 1.11.191 next-gen   |   ImageBase 0x140000000")
log("=" * 78)

# ============================================================================
# Section 1 — decompile every candidate, list its callees + global writes
# ============================================================================
log("")
log("=" * 78)
log(" SECTION 1 — Decompile each candidate + extract globals/callees")
log("=" * 78)

candidate_decomps = {}

for nm, r, anno in CANDIDATES:
    abs_ea = BASE + r
    log("")
    log("-" * 78)
    log(" %s @ %s (RVA %s)  -- %s" % (nm, hexs(abs_ea), hexs(r), anno))
    sz = fn_size(abs_ea)
    log("   size=%s   ida_name=%s" % (hexs(sz) if sz else "?", name_at(abs_ea)))
    log("-" * 78)

    txt = safe_decomp(abs_ea)
    candidate_decomps[r] = txt
    if txt:
        for line in txt.splitlines():
            log("   " + line)
    else:
        log("   <decomp failed; emitting disasm>")
        for line in disasm_lines(abs_ea, 100):
            log(line)

    # Direct callees
    log("")
    log("   ---- direct callees ----")
    calls = call_targets_in_func(abs_ea)
    by_target = {}
    for (csite, target, mnem) in calls:
        by_target.setdefault(target, []).append((csite, mnem))
    for target in sorted(by_target.keys()):
        sites = by_target[target]
        tnm = name_at(target)
        tsz = fn_size(target)
        log("     %s (RVA %s)  %s   size=%s   #sites=%d" %
            (hexs(target), hexs(rva(target)), tnm,
             hexs(tsz) if tsz else "?", len(sites)))

# ============================================================================
# Section 2 — qword_1430DBD58 layout (the 6-slot scene singleton)
# ============================================================================
log("")
log("")
log("=" * 78)
log(" SECTION 2 — qword_1430DBD58 layout  (slots +0x118..+0x140)")
log("=" * 78)

# qword_1430DBD58 itself is a global pointer. Read its current value as a
# baseline (will be 0 in IDB because not initialized at static time).
glob_val = ida_bytes.get_qword(SCENE_SINGLETON)
log(" qword_1430DBD58 static value = %s  (probably 0; it is set at runtime)" %
    hexs(glob_val))

# Strategy A: scan every reference to qword_1430DBD58 and look for ones that
# subsequently load [reg+0x118..+0x140]. That gives us the per-slot consumer
# and the slot-write site.
log("")
log(" --- xrefs to qword_1430DBD58 ---")
xs = data_xrefs_to(SCENE_SINGLETON)
log(" total xrefs: %d" % len(xs))
for x in xs[:80]:
    f = ida_funcs.get_func(x)
    fn = name_at(f.start_ea) if f else "?"
    line = idc.generate_disasm_line(x, 0) or ""
    log("   %s  (in %s)  %s" % (hexs(x), fn, line))

# Strategy B: scan disasm of sub_141026980 (the SCENE BROADCAST) — it is
# explicitly described as walking 6 slots. Pull each slot offset and
# the function it dispatches to. We expect a pattern like:
#
#    mov  rax, [qword_1430DBD58]
#    mov  rcx, [rax + N]      ; per-slot field
#    mov  rax, [rcx]          ; slot vtable
#    call [rax + M]           ; dispatch
log("")
log(" --- disassembly walk of sub_141026980 (slot dispatch loop) ---")
broadcast_ea = BASE + 0x1026980
f = ida_funcs.get_func(broadcast_ea)
if f:
    cur = f.start_ea
    while cur < f.end_ea:
        mnem = idc.print_insn_mnem(cur)
        line = idc.generate_disasm_line(cur, 0) or ""
        # Look for any operand that references +0x118..+0x140
        op_text = (line.lower())
        if any(("+0x%xh" % off) in op_text or
               ("+%xh"   % off) in op_text for off in range(SLOTS_BASE_OFF, SLOTS_END_OFF + 1)):
            log("   %s  %s" % (hexs(cur), line))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt

# Strategy C: scan the .text segment for instructions that WRITE to
# qword_1430DBD58+N for N in [0x118..0x140]. Those are the registration sites.
# Pattern (Bethesda compiler emits this):
#    lea rcx, qword_1430DBD58
#    mov [rcx + N], rax
# or
#    mov  rcx, cs:qword_1430DBD58_ptr
#    mov  [rcx+N], rax
log("")
log(" --- scan for writes to qword_1430DBD58+0x118..0x140 (slot init) ---")
text_seg = ida_segment.get_segm_by_name(".text")
if text_seg:
    cur = text_seg.start_ea
    write_hits = []
    # We do a coarse scan: every cref/dref reference to SCENE_SINGLETON that
    # is followed within 4 instructions by "mov [reg+N], rXX" with N in
    # the slot range.
    for x in xs:
        # Read forward up to 8 instructions
        ea = x
        for step in range(8):
            line = idc.generate_disasm_line(ea, 0) or ""
            ll = line.lower()
            if "mov" in ll and "[" in ll:
                for off in range(SLOTS_BASE_OFF, SLOTS_END_OFF + 8, 8):
                    needle = "+%xh" % off
                    if needle in ll or ("+0x%x" % off) in ll:
                        write_hits.append((x, ea, off, line))
            nxt = idc.next_head(ea)
            if nxt <= ea: break
            ea = nxt
    seen = set()
    for (anchor, ea, off, line) in write_hits:
        key = (ea, off)
        if key in seen: continue
        seen.add(key)
        f = ida_funcs.get_func(ea)
        fn = name_at(f.start_ea) if f else "?"
        log("   anchor %s  ea %s  slot+%X   in %s   %s" %
            (hexs(anchor), hexs(ea), off, fn, line))

# ============================================================================
# Section 3 — Identify SKIN UPDATE registration evidence
# ============================================================================
log("")
log("")
log("=" * 78)
log(" SECTION 3 — SKIN UPDATE registration evidence")
log("=" * 78)

# 3A: search RTTI strings for skin/animation manager hits
log("")
log(" --- RTTI strings of interest ---")
for ks in KEY_STRINGS:
    hits = find_strings_containing(ks)
    for (s, eas) in hits[:6]:
        log("   %r  at %s" % (s, ", ".join(hexs(e) for e in eas)))

# 3B: for each candidate, count how many KEY_STRINGS it references via xref
log("")
log(" --- key-string presence inside each candidate decomp ---")
for nm, r, anno in CANDIDATES:
    txt = candidate_decomps.get(r) or ""
    found = []
    for k in KEY_STRINGS:
        if k.lower() in txt.lower():
            found.append(k)
    log("   %s : %s" % (nm, ", ".join(found) if found else "(none)"))

# 3C: data refs from each candidate -> scan for strings containing key terms
log("")
log(" --- string xrefs reachable from each candidate function ---")
for nm, r, anno in CANDIDATES:
    abs_ea = BASE + r
    f = ida_funcs.get_func(abs_ea)
    if not f: continue
    found = set()
    cur = f.start_ea
    while cur < f.end_ea:
        for xr in idautils.DataRefsFrom(cur):
            sn = idc.get_strlit_contents(xr, -1, 0)
            if sn:
                try: sn = sn.decode("utf-8", "replace")
                except: pass
                if any(k.lower() in sn.lower() for k in
                       ["skin", "anim", "scene", "shadow", "geom", "skel",
                        "render", "cull", "graph", "sshader"]):
                    found.add((xr, sn[:80]))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    log("   %s : %d hits" % (nm, len(found)))
    for (xr, sn) in list(found)[:8]:
        log("       %s : %r" % (hexs(xr), sn))

# 3D: find functions whose first-arg type LOOKS LIKE a BSGeometry / Skin instance
# by looking for direct reads of [reg+0x140] (the skin pointer slot we know
# from M8P3) and [reg+0x150] (the BSFadeNode flag we suspect) inside the
# candidate set.
log("")
log(" --- candidate body scan: reads of [+0x140] (skin slot) / +0x150 / +0x158 ---")
GEOM_OFFSETS = [0x140, 0x148, 0x150, 0x158]
for nm, r, anno in CANDIDATES:
    abs_ea = BASE + r
    f = ida_funcs.get_func(abs_ea)
    if not f: continue
    hits = []
    cur = f.start_ea
    while cur < f.end_ea:
        line = idc.generate_disasm_line(cur, 0) or ""
        ll = line.lower()
        for off in GEOM_OFFSETS:
            if ("+%xh" % off) in ll or ("+0x%x" % off) in ll:
                hits.append((cur, off, line))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    if hits:
        log("   %s : %d offset-hits" % (nm, len(hits)))
        for (ea, off, line) in hits[:10]:
            log("       %s  +0x%X   %s" % (hexs(ea), off, line))
    else:
        log("   %s : (none)" % nm)

# 3E: check sub_14102D4C0 — the broadcast worker — what does it dispatch to?
# It is called per-slot inside sub_141026980. If it loads vtable+offset and
# calls, that's our virtual dispatch — we want to know which slots have
# "skin"-flavoured methods.
log("")
log(" --- sub_14102D4C0 dispatch analysis ---")
worker_ea = BASE + 0x102D4C0
worker_decomp = candidate_decomps.get(0x102D4C0)
if worker_decomp:
    log("   (decomp captured above; below is per-instruction trace)")
log("")
for line in disasm_lines(worker_ea, 60):
    log(line)

# ============================================================================
# Section 4 — additional anchors: who calls sub_141026640 / sub_141026980?
# Important: confirms these run from PC::Load3D / Actor::Load3D and not from
# something unrelated.
# ============================================================================
log("")
log("")
log("=" * 78)
log(" SECTION 4 — Callers of each candidate (cross-validation)")
log("=" * 78)

for nm, r, anno in CANDIDATES:
    abs_ea = BASE + r
    callers = code_xrefs_to(abs_ea)
    log("")
    log("   %s : %d callers" % (nm, len(callers)))
    seen_fns = set()
    for c in callers[:40]:
        f = ida_funcs.get_func(c)
        fn_ea = f.start_ea if f else 0
        if fn_ea in seen_fns: continue
        seen_fns.add(fn_ea)
        fn = name_at(fn_ea) if fn_ea else "?"
        log("       caller %s   in %s (RVA %s)" %
            (hexs(c), fn, hexs(rva(fn_ea)) if fn_ea else "?"))

# ============================================================================
# Section 5 — broader hunt: is there a single function that takes a
# BSGeometry* / BSSkin::Instance* and does PushBack into a global array?
# Heuristic:
#   - the function reads [arg+0x140] (skin slot)
#   - and writes into a BSTArray-style buffer using sub_141659...  or similar
# We list every function in .text that does BOTH within its body.
# ============================================================================
log("")
log("")
log("=" * 78)
log(" SECTION 5 — BSTArray-push fingerprint inside skin candidates")
log("=" * 78)

# Re-examine sub_141026640 and sub_141026980 closely; also look at any
# nearby fn in 0x141026xxx range (the 'scene register' family).
NEIGHBOURS = [
    0x1026000, 0x1026100, 0x1026200, 0x1026300, 0x1026400,
    0x1026500, 0x1026600, 0x1026640, 0x1026700, 0x1026800,
    0x1026900, 0x1026980, 0x1026A00, 0x1026B00, 0x1026C00,
    0x1026D00, 0x1026E00, 0x1026F00,
    0x1027000, 0x1027100, 0x1027200, 0x1027300, 0x1027400,
]
log("")
log(" --- scan 0x141026xxx neighbourhood for BSTArray-push patterns ---")
for r in NEIGHBOURS:
    abs_ea = BASE + r
    f = ida_funcs.get_func(abs_ea)
    if not f: continue
    nm = name_at(f.start_ea)
    sz = f.end_ea - f.start_ea
    # quick decomp summary
    txt = safe_decomp(f.start_ea)
    if not txt: continue
    head = txt.splitlines()[0] if txt else ""
    has_push = "PushBack" in txt or "push_back" in txt or \
               "std::vector" in txt or "BSTArray" in txt
    has_skin = "BSSkin" in txt or "Skin::" in txt or "+ 320" in txt or "+ 328" in txt
    has_geom = "Geometry" in txt or "BSFadeNode" in txt
    has_singleton = ("qword_1430DBD58" in txt) or ("dword_1430DBD58" in txt)
    if has_push or has_skin or has_geom or has_singleton:
        log("   %s (%s) size=%s  push=%s skin=%s geom=%s sing=%s" %
            (nm, hexs(f.start_ea), hexs(sz),
             has_push, has_skin, has_geom, has_singleton))
        log("       sig: %s" % head)

# ============================================================================
# Done
# ============================================================================
log("")
log("=" * 78)
log(" END")
log("=" * 78)

with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Wrote %s (%d lines)" % (LOG, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
