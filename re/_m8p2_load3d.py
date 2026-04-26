"""
M8 Phase 2 Step 1 — TESObjectREFR::Load3D Deep Reverse Engineering

Goal: find the alternative NIF entry point that creates the player's 3P body
without going through sub_1417B3E90 (the public NIF loader we already hook).

Key facts:
  - REFR::Load3D = sub_14050AC10 (RVA 0x50AC10), size 0x1009 (4105 bytes)
  - Frida confirms: sub_1417B3E90 is NEVER called for MaleBody.nif
  - Its return is the 3P BSFadeNode root (vt RVA 0x28fa3e8)
  - There must be an alt NIF entry inside REFR::Load3D's call tree

Strategy:
  1) Decompile REFR::Load3D and emit verbatim
  2) Enumerate ALL direct callees, with name/size/role
  3) For each callee, scan its body for:
        - References to BSFadeNode vtable (RVA 0x28fa3e8)
        - References to BSTriShape vtable (RVA 0x267C888)
        - String references to .nif, malebody, skeleton, etc.
        - Calls to BSResource* functions
        - Calls to BGSBodyPart record accessor / TESModel record accessor
        - Calls to NIF parsers (sub_1417B3E90 — should NOT appear)
        - Calls to any unidentified "loader-shaped" function (takes path string)
  4) Find xrefs to bone resolver sub_1403F85E0 anywhere in the binary
  5) Find PC's AnimGraphManager offset by analyzing access sites
  6) Output dossier raw log

Output: re/_m8p2_load3d_raw.log
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_nalt, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p2_load3d_raw.log"
lines = []
BASE = 0x140000000

# Known anchors
REFR_LOAD3D_RVA   = 0x50AC10        # TESObjectREFR::Load3D
ACTOR_LOAD3D_RVA  = 0xC584F0
PC_LOAD3D_RVA     = 0xD5B250

NIF_LOADER_RVA    = 0x17B3E90       # Public NIF loader (we hook this)
PRELOAD_RVA       = 0x17A3210       # BSResource async preload
BONE_RESOLVER_RVA = 0x3F85E0        # Bone resolver
APPLY_MAT_RVA     = 0x255BA0        # apply_materials walker
ANIM_GRAPH_GETTER = 0x187FF20       # Get embedded anim graph mgr
ANIMDIRTY_RVA     = 0x1895000       # animdirty (mark all anim vars dirty)

# Vtables
BSFADENODE_VT_RVA = 0x28FA3E8
BSTRISHAPE_VT_RVA = 0x267C888

# Patterns to detect "interesting" callees
SCARY_RVAS = {
    NIF_LOADER_RVA:    "sub_1417B3E90 PUBLIC NIF LOADER (we hook this)",
    PRELOAD_RVA:       "sub_1417A3210 BSResource async preload",
    BONE_RESOLVER_RVA: "sub_1403F85E0 BONE RESOLVER",
    APPLY_MAT_RVA:     "sub_140255BA0 apply_materials walker",
    ANIM_GRAPH_GETTER: "sub_14187FF20 anim graph getter",
    ANIMDIRTY_RVA:     "sub_141895000 animdirty",
}

# ---- helpers ---------------------------------------------------------------

def log(s=""):
    lines.append(s if isinstance(s, str) else str(s))

def H(x):
    try: return "0x%X" % x
    except: return str(x)

def rva(ea): return ea - BASE

def fname(ea):
    try:
        n = ida_name.get_name(ea)
        if n: return n
    except: pass
    try:
        n = ida_funcs.get_func_name(ea)
        if n: return n
    except: pass
    return "?"

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return (f.end_ea - f.start_ea) if f else None

def decomp(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        return str(cf) if cf else None
    except Exception as e:
        return "<decomp err: %s>" % e

def callees_in(start_ea):
    """Return list of (call_site_ea, target_ea, mnem) for direct calls."""
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

def string_refs(start_ea):
    f = ida_funcs.get_func(start_ea)
    if not f: return []
    out = []
    cur = f.start_ea
    while cur < f.end_ea:
        for xr in idautils.DataRefsFrom(cur):
            sn = idc.get_strlit_contents(xr, -1, 0)
            if sn:
                try: sn = sn.decode("utf-8", "replace")
                except: sn = repr(sn)
                if 3 <= len(sn) < 200:
                    out.append((cur, xr, sn))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

def data_refs_set(start_ea):
    """Return set of all data refs (target EAs) inside this func."""
    f = ida_funcs.get_func(start_ea)
    if not f: return set()
    out = set()
    cur = f.start_ea
    while cur < f.end_ea:
        for xr in idautils.DataRefsFrom(cur):
            out.add(xr)
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

def scan_offset_accesses(start_ea):
    """Scan disasm for [reg+offset] patterns where offset > 0x100. Returns
       a counter of offsets used (rough — useful for finding +0x300, +0xB78
       etc. without manual decomp inspection)."""
    f = ida_funcs.get_func(start_ea)
    if not f: return {}
    import re
    rx = re.compile(r"\+([0-9A-Fa-f]+)h?")
    out = {}
    cur = f.start_ea
    while cur < f.end_ea:
        line = idc.generate_disasm_line(cur, 0) or ""
        for m in rx.finditer(line):
            try:
                v = int(m.group(1), 16)
                if 0x10 <= v < 0x10000:
                    out[v] = out.get(v, 0) + 1
            except: pass
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

# ---------------------------------------------------------------------------
log("=" * 80)
log(" M8 PHASE 2 STEP 1 — TESObjectREFR::Load3D deep RE")
log(" Fallout4.exe 1.11.191 next-gen | imagebase 0x140000000")
log("=" * 80)

REFR_LOAD3D_EA = BASE + REFR_LOAD3D_RVA
log("")
log("REFR::Load3D EA = %s (RVA %s)" % (H(REFR_LOAD3D_EA), H(REFR_LOAD3D_RVA)))
log("size           = %s" % H(fsize(REFR_LOAD3D_EA)))

# ---- A. DECOMP REFR::Load3D body ------------------------------------------
log("")
log("=" * 80)
log(" A. TESObjectREFR::Load3D — DECOMP BODY")
log("=" * 80)
txt = decomp(REFR_LOAD3D_EA)
if txt:
    for ln in txt.splitlines():
        log("  " + ln)
else:
    log("  <decomp failed>")

# ---- B. Direct callees (~95) ----------------------------------------------
log("")
log("=" * 80)
log(" B. REFR::Load3D — DIRECT CALLEES")
log("=" * 80)
calls = callees_in(REFR_LOAD3D_EA)
log("  total direct call sites: %d" % len(calls))
by_t = {}
for cs, t, mn in calls:
    by_t.setdefault(t, []).append((cs, mn))
log("  unique callees: %d" % len(by_t))
log("")

callee_index = []  # for downstream loop
for t in sorted(by_t.keys()):
    sites = by_t[t]
    nm = fname(t)
    sz = fsize(t)
    s_rva = rva(t)
    scary = SCARY_RVAS.get(s_rva, "")
    tag = " [SCARY: %s]" % scary if scary else ""
    log("  %s (RVA %s) %s  size=%s  call_sites=%d%s" %
        (H(t), H(s_rva), nm,
         H(sz) if sz else "?", len(sites), tag))
    callee_index.append((t, nm, sz))

# ---- C. Per-callee deep scan ----------------------------------------------
log("")
log("=" * 80)
log(" C. PER-CALLEE DEEP SCAN")
log("    For each direct callee of REFR::Load3D, scan its body for:")
log("      * BSFadeNode vtable refs (RVA 0x28FA3E8)")
log("      * BSTriShape vtable refs (RVA 0x267C888)")
log("      * .nif / actor path strings")
log("      * Calls to public NIF loader sub_1417B3E90")
log("      * Calls to BSResource preload sub_1417A3210")
log("      * Calls to bone resolver sub_1403F85E0")
log("      * Calls to apply_materials walker sub_140255BA0")
log("      * BGSBodyPart-shaped iteration (offset 0x70-0x150 chained)")
log("=" * 80)

NIF_LOADER_EA  = BASE + NIF_LOADER_RVA
PRELOAD_EA     = BASE + PRELOAD_RVA
BONE_RES_EA    = BASE + BONE_RESOLVER_RVA
APPLY_MAT_EA   = BASE + APPLY_MAT_RVA
BSFADENODE_EA  = BASE + BSFADENODE_VT_RVA
BSTRISHAPE_EA  = BASE + BSTRISHAPE_VT_RVA

interesting = []  # (target_ea, score, notes)

for (t, nm, sz) in callee_index:
    if not sz: continue
    if sz > 0x6000:  # skip massive helpers (will recurse only top candidates)
        log("")
        log("  -- %s %s size=%s (too big to scan, deferring)" % (H(t), nm, H(sz)))
        continue

    inner_calls = callees_in(t)
    inner_call_targets = set(c for _, c, _ in inner_calls)
    inner_data_refs    = data_refs_set(t)
    sr = string_refs(t)

    score = 0
    notes = []

    if NIF_LOADER_EA in inner_call_targets:
        score += 10; notes.append("CALLS sub_1417B3E90")
    if PRELOAD_EA in inner_call_targets:
        score += 5; notes.append("calls BSResource preload sub_1417A3210")
    if BONE_RES_EA in inner_call_targets:
        score += 8; notes.append("CALLS BONE RESOLVER sub_1403F85E0")
    if APPLY_MAT_EA in inner_call_targets:
        score += 4; notes.append("calls apply_materials walker")

    if BSFADENODE_EA in inner_data_refs:
        score += 8; notes.append("REFS BSFadeNode VTABLE")
    if BSTRISHAPE_EA in inner_data_refs:
        score += 6; notes.append("refs BSTriShape vtable")

    nif_strs = [s for _, _, s in sr if any(k in s.lower() for k in
                ['.nif', '.bgsm', '.btr', 'malebody', 'femalebody',
                 'skeleton', 'meshes\\', 'actors\\character'])]
    if nif_strs:
        score += 3
        notes.append("nif-related strings: " + ", ".join(repr(s)[:40] for s in nif_strs[:3]))

    if score:
        interesting.append((t, nm, sz, score, notes))

interesting.sort(key=lambda r: -r[3])
log("")
log("  ===== TOP CALLEES BY INTEREST SCORE =====")
for (t, nm, sz, sc, notes) in interesting:
    log("  %s (RVA %s) %s  size=%s  score=%d" %
        (H(t), H(rva(t)), nm, H(sz), sc))
    for n in notes:
        log("      - %s" % n)

# ---- D. Decomp top suspects -----------------------------------------------
log("")
log("=" * 80)
log(" D. DEEP DECOMP — TOP SUSPECTS")
log("=" * 80)
TOP_N = 12
for (t, nm, sz, sc, notes) in interesting[:TOP_N]:
    log("")
    log("  " + "-" * 76)
    log("  %s (RVA %s)  size=%s  score=%d" % (H(t), H(rva(t)), H(sz), sc))
    log("  notes: " + "; ".join(notes))
    log("  " + "-" * 76)
    txt = decomp(t)
    if txt:
        # truncate to first 250 lines
        all_lines = txt.splitlines()
        for ln in all_lines[:300]:
            log("    " + ln)
        if len(all_lines) > 300:
            log("    ... [truncated; %d more lines]" % (len(all_lines) - 300))
    else:
        log("    <decomp failed>")

# ---- E. xrefs to bone resolver --------------------------------------------
log("")
log("=" * 80)
log(" E. XREFS TO BONE RESOLVER sub_1403F85E0")
log("=" * 80)
bone_ea = BASE + BONE_RESOLVER_RVA
log("  bone resolver at %s" % H(bone_ea))

xref_callers = set()
for xr in idautils.XrefsTo(bone_ea):
    f = ida_funcs.get_func(xr.frm)
    if f:
        xref_callers.add(f.start_ea)
        log("    xref from %s in %s @ %s (size %s)" %
            (H(xr.frm), fname(f.start_ea), H(f.start_ea),
             H(f.end_ea - f.start_ea)))
log("  unique caller funcs: %d" % len(xref_callers))

# Decomp each caller (bone resolver is small fan-in, expect 1-5)
log("")
log("  ----- decomp bone-resolver callers -----")
for caller_ea in sorted(xref_callers):
    log("")
    log("  ## caller %s (RVA %s) %s size=%s" %
        (H(caller_ea), H(rva(caller_ea)), fname(caller_ea), H(fsize(caller_ea))))
    txt = decomp(caller_ea)
    if txt:
        all_lines = txt.splitlines()
        for ln in all_lines[:150]:
            log("    " + ln)
        if len(all_lines) > 150:
            log("    ... [%d more lines]" % (len(all_lines) - 150))
    else:
        log("    <decomp failed>")

# ---- F. AnimGraphManager pointer offset ----------------------------------
log("")
log("=" * 80)
log(" F. AnimGraphManager pointer offset on Actor")
log("    Decomp sub_14187FF20 (get_anim_graph_mgr) and analyze its")
log("    'this+offset' pattern. Also search PC::Load3D / Actor::Load3D")
log("    for accesses near 0x300.")
log("=" * 80)
log("")
agm_getter = BASE + ANIM_GRAPH_GETTER
log("  sub_14187FF20 (anim graph getter) at %s" % H(agm_getter))
agm_txt = decomp(agm_getter)
if agm_txt:
    for ln in agm_txt.splitlines():
        log("    " + ln)
log("")

# Decomp animdirty consumer
log("  sub_141895000 (animdirty) at %s" % H(BASE + ANIMDIRTY_RVA))
ad_txt = decomp(BASE + ANIMDIRTY_RVA)
if ad_txt:
    for ln in ad_txt.splitlines():
        log("    " + ln)

# scan PC::Load3D + Actor::Load3D for offset 0x2F8/0x300 accesses
log("")
log("  -- offset histogram in PC::Load3D (sub_140D5B250) --")
hist = scan_offset_accesses(BASE + PC_LOAD3D_RVA)
near_300 = sorted([(o, c) for o, c in hist.items() if 0x2C0 <= o <= 0x320],
                  key=lambda x: -x[1])
for o, c in near_300:
    log("    +%X  count=%d" % (o, c))

log("")
log("  -- offset histogram in Actor::Load3D (sub_140C584F0) --")
hist2 = scan_offset_accesses(BASE + ACTOR_LOAD3D_RVA)
near_300_2 = sorted([(o, c) for o, c in hist2.items() if 0x2C0 <= o <= 0x320],
                    key=lambda x: -x[1])
for o, c in near_300_2:
    log("    +%X  count=%d" % (o, c))

log("")
log("  -- offset histogram in REFR::Load3D (sub_14050AC10) --")
hist3 = scan_offset_accesses(REFR_LOAD3D_EA)
near_300_3 = sorted([(o, c) for o, c in hist3.items() if 0x2C0 <= o <= 0x320],
                    key=lambda x: -x[1])
for o, c in near_300_3:
    log("    +%X  count=%d" % (o, c))

# ---- G. Search for ALL functions referencing BSFadeNode vtable -----------
log("")
log("=" * 80)
log(" G. ALL FUNCTIONS REFERENCING BSFadeNode VTABLE (RVA 0x28FA3E8)")
log("    Filter to those callable from REFR::Load3D's call subtree (depth 2)")
log("=" * 80)
log("")
fade_xrefs = list(idautils.XrefsTo(BSFADENODE_EA))
log("  total xrefs to BSFadeNode vtable: %d" % len(fade_xrefs))

fade_callers = set()
for xr in fade_xrefs:
    f = ida_funcs.get_func(xr.frm)
    if f:
        fade_callers.add(f.start_ea)
log("  unique funcs referencing it: %d" % len(fade_callers))

# Build the REFR::Load3D 2-deep callgraph
def collect_subtree(start_ea, max_depth=2):
    seen = set()
    stack = [(start_ea, 0)]
    while stack:
        ea, d = stack.pop()
        if ea in seen: continue
        seen.add(ea)
        if d >= max_depth: continue
        for _, t, _ in callees_in(ea):
            if t not in seen:
                stack.append((t, d+1))
    return seen

log("")
log("  Building REFR::Load3D 2-deep callgraph...")
refr_subtree = collect_subtree(REFR_LOAD3D_EA, max_depth=2)
log("  REFR::Load3D 2-deep callgraph size: %d funcs" % len(refr_subtree))
log("")

intersection = sorted(fade_callers & refr_subtree)
log("  Funcs that BOTH ref BSFadeNode vt AND are in REFR::Load3D 2-deep tree: %d" %
    len(intersection))
for ea in intersection:
    log("    %s (RVA %s) %s  size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(fsize(ea))))

# ---- H. ALL ::Load3D-shaped functions in the binary ----------------------
log("")
log("=" * 80)
log(" H. SEARCH for OTHER 'Load3D-shaped' functions (refs BSFadeNode vt)")
log("    that ALSO ref string '*.nif' / call BSResource — likely the alt loader")
log("=" * 80)
log("")

candidate_hits = []
for ea in fade_callers:
    sz = fsize(ea)
    if not sz or sz > 0x4000: continue   # ignore mega-monsters
    sr = string_refs(ea)
    nif_strs = [s for _, _, s in sr if '.nif' in s.lower()]
    inner_calls = set(c for _, c, _ in callees_in(ea))
    in_refr_tree = ea in refr_subtree
    has_preload = (PRELOAD_EA in inner_calls)
    has_pubload = (NIF_LOADER_EA in inner_calls)
    if (nif_strs or has_preload or has_pubload):
        candidate_hits.append((ea, sz, in_refr_tree, has_preload, has_pubload, nif_strs))

candidate_hits.sort(key=lambda r: (not r[2], -r[1]))   # prefer in-tree, then size
log("  Candidate alt-loaders: %d" % len(candidate_hits))
for (ea, sz, in_tree, hp, hl, nstr) in candidate_hits[:30]:
    flags = []
    if in_tree: flags.append("IN_REFR_TREE")
    if hp: flags.append("preload")
    if hl: flags.append("pubLoader")
    log("    %s (RVA %s) %s  size=%s  flags=[%s] strings=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(sz),
         ",".join(flags) or "-",
         ", ".join(repr(s)[:40] for s in nstr[:3])))

# ---- I. Search for "BGSBodyPart" / TESModel-shaped iteration -------------
log("")
log("=" * 80)
log(" I. SEARCH for BGSBodyPart-iteration in REFR::Load3D subtree")
log("    Looking for: loop that walks an array of records of size 0x70-0xC0")
log("    where each record has a +0x10 BSFixedString path field.")
log("=" * 80)
log("")

# This is heuristic — look for any callee that has BOTH:
#   - A loop pattern (cmp+jcc backedge in body)
#   - A BSFixedString c_str call (sub_14167C070)
BSFXSTR_CSTR_EA = BASE + 0x167C070
for ea in sorted(refr_subtree):
    sz = fsize(ea)
    if not sz or sz < 0x60 or sz > 0x600: continue
    inner_calls = set(c for _, c, _ in callees_in(ea))
    if BSFXSTR_CSTR_EA not in inner_calls: continue

    # Has loop?
    f = ida_funcs.get_func(ea)
    has_back_edge = False
    cur = f.start_ea
    while cur < f.end_ea:
        mnem = idc.print_insn_mnem(cur)
        if mnem in ("jnz", "jne", "jl", "jle", "jg", "jge",
                    "jb", "jbe", "ja", "jae", "loop", "loope", "loopne"):
            target = idc.get_operand_value(cur, 0)
            if target and target < cur:
                has_back_edge = True
                break
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    if not has_back_edge: continue
    log("    %s (RVA %s) %s size=%s  has_loop+BSFixedString_cstr" %
        (H(ea), H(rva(ea)), fname(ea), H(sz)))

# ---- J. THE SAVE-GAME load hypothesis: search for 3D deserialization ----
log("")
log("=" * 80)
log(" J. SAVE-GAME 3D state hypothesis — search REFR::Load3D for")
log("    BSStream::Read / save-game flag accesses")
log("=" * 80)
log("")

# Scan REFR::Load3D body for jcc that test bit at offset 0xDFE-area
# (PC's a1+0xDFE is the "loading from save" flag per M8P1 dossier)
log("  -- scanning REFR::Load3D for save-game flag accesses --")
f = ida_funcs.get_func(REFR_LOAD3D_EA)
cur = f.start_ea
save_flag_hits = []
while cur < f.end_ea:
    line = idc.generate_disasm_line(cur, 0) or ""
    ll = line.lower()
    if any(k in ll for k in ['+0dfeh', '+0dffh', '+0e00h']):
        save_flag_hits.append((cur, line))
    nxt = idc.next_head(cur)
    if nxt <= cur: break
    cur = nxt
for cs, ln in save_flag_hits[:20]:
    log("    %s : %s" % (H(cs), ln))

# ---- DONE ----------------------------------------------------------------
log("")
log("=" * 80)
log(" END")
log("=" * 80)

with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG, len(lines)))
import ida_pro
ida_pro.qexit(0)
