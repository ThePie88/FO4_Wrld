"""
M8 Phase 2 Step 1 — PHASE 2: Drill into the alternative NIF entry point.

PHASE 1 finding:
  REFR::Load3D's alternative NIF path is the virtual call
       (*(form->vt + 752))(form, this_refr, &out_3d_root)
  on a1[14] = base form record (e.g. TESNPC). This is the "else" branch when
  FormType != 53 (MOVT_STATIC).

PHASE 2 tasks:
  1. Find TESNPC vtable
  2. Decompile slot 94 (offset 752 = 94*8) of TESNPC vtable
  3. ALSO decompile the same slot in TESForm/TESBoundObject base vtables and
     all known overrides (Character, BGSBodyPart-related, etc.) — to understand
     polymorphism
  4. Find xrefs to vtable[94] with a constant offset 752 to confirm pattern
  5. Decompile bone-resolver caller sub_14040D4C0 callers (xrefs)
  6. Decompile sub_140383980 (used in form type 53 MOVT branch — possible alt)
     and sub_1417E9CB0 (called with default position vec3)
  7. Decompile sub_1402FDDE0 (in the v30 branch — looks like another loader)
  8. Confirm AnimGraphManager offset by xref-walking sub_14187FF20 callers

Output: re/_m8p2_phase2_raw.log
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_nalt, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p2_phase2_raw.log"
lines = []
BASE = 0x140000000

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

def find_string_eas(s):
    out = []
    try:
        for sx in idautils.Strings():
            try:
                if str(sx) == s:
                    out.append(sx.ea)
            except: pass
    except: pass
    return out

def vtable_from_rtti(rtti_str):
    """Walk: '.?AVTESNPC@@' -> TypeDescriptor -> COL -> vtable."""
    eas = find_string_eas(rtti_str)
    if not eas: return []
    out = []
    for s_ea in eas:
        td_ea = s_ea - 0x10
        for xr in idautils.XrefsTo(td_ea):
            if not xr.iscode:
                col_ea = xr.frm - 0xC
                for xr2 in idautils.XrefsTo(col_ea):
                    out.append(xr2.frm + 8)
    return list(set(out))

def vt_length(vt_ea, max_count=500):
    cnt = 0
    s = ida_segment.getseg(vt_ea)
    if not s: return 0
    for i in range(max_count):
        a = vt_ea + i*8
        if a >= s.end_ea: break
        v = ida_bytes.get_qword(a)
        if v == 0: break
        tseg = ida_segment.getseg(v)
        if not tseg or ida_segment.get_segm_name(tseg) != ".text":
            break
        cnt += 1
    return cnt

# ---- start ----
log("=" * 80)
log(" M8 PHASE 2 STEP 1 — PHASE 2: drill into alt NIF entry virtual")
log("=" * 80)

# ---- A: Find TESNPC vtable + slot 94 ----
log("")
log("=" * 80)
log(" A. TESNPC vtable + slot 94 (vtable+752 = 94*8)")
log("=" * 80)

CANDIDATE_RTTI = [
    ".?AVTESNPC@@",
    ".?AVTESActorBase@@",
    ".?AVTESForm@@",
    ".?AVTESBoundObject@@",
    ".?AVTESObject@@",
    ".?AVCharacter@@",
    ".?AVTESObjectACTI@@",
    ".?AVTESObjectMOVT@@",  # form type 53 maybe?
    ".?AVTESObjectMISC@@",
    ".?AVTESObjectSTAT@@",
    ".?AVTESObjectTREE@@",
    ".?AVTESObjectFURN@@",
]

# Find vtables and dump slot 94
vt_results = {}
for rtti in CANDIDATE_RTTI:
    cands = vtable_from_rtti(rtti)
    log("")
    log("  RTTI %s -> %d vtable(s)" % (rtti, len(cands)))
    for vt in cands:
        ln = vt_length(vt)
        if ln >= 95:
            slot94 = ida_bytes.get_qword(vt + 94*8)
            log("    vt %s (RVA %s) len=%d  vt[94]=%s (RVA %s)  name=%s  size=%s" %
                (H(vt), H(rva(vt)), ln, H(slot94), H(rva(slot94)),
                 fname(slot94), H(fsize(slot94))))
            vt_results[(rtti, vt)] = slot94
        else:
            log("    vt %s (RVA %s) len=%d  -- too short for slot 94" %
                (H(vt), H(rva(vt)), ln))

# Decompile each unique slot94 target
log("")
log("=" * 80)
log(" A.1 — DECOMPILE each unique vt[94] target")
log("=" * 80)
seen_slot94 = set()
for (rtti, vt), slot94_ea in vt_results.items():
    if slot94_ea in seen_slot94: continue
    seen_slot94.add(slot94_ea)
    log("")
    log("  ## vt[94] = %s (RVA %s) %s  size=%s   from RTTI %s" %
        (H(slot94_ea), H(rva(slot94_ea)), fname(slot94_ea),
         H(fsize(slot94_ea)), rtti))
    log("  " + "-"*76)
    txt = decomp(slot94_ea)
    if txt:
        for ln in txt.splitlines():
            log("    " + ln)
    else:
        log("    <decomp failed>")

# ---- B: Form-type 53 (MOVT) alt path — sub_140383980 + sub_1417E9CB0 ----
log("")
log("=" * 80)
log(" B. Form-type 53 alt path: sub_140383980 + sub_1417E9CB0")
log("=" * 80)

for (ea, label) in [
    (0x140383980, "sub_140383980 (called when (FormType==53) AND sub_1403820A0(a1))"),
    (0x1417E9CB0, "sub_1417E9CB0 (called with [a1[15]+8] -> NIF root + default position)"),
    (0x1403820A0, "sub_1403820A0 (predicate test for MOVT path)"),
    (0x140512DE0, "sub_140512DE0 (called with default scale/orient setup)"),
    (0x1402FDDE0, "sub_1402FDDE0 (in v30 branch — possibly child loader)"),
    (0x140300820, "sub_140300820 (sibling to FDDE0)"),
    (0x1402FFCA0, "sub_1402FFCA0 (sibling — third in chain)"),
]:
    log("")
    log("  ## %s @ %s (RVA %s) size=%s" % (label, H(ea), H(rva(ea)),
                                             H(fsize(ea))))
    log("  " + "-"*76)
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:200]:
            log("    " + ln)
    else:
        log("    <decomp failed>")

# ---- C: BSFadeNode helpers ----
log("")
log("=" * 80)
log(" C. BSFadeNode allocator + initializer chain")
log("=" * 80)

for (ea, label) in [
    (0x14040CF10, "sub_14040CF10 (raw alloc 0x1C0 = 448 bytes)"),
    (0x142174DC0, "sub_142174DC0 (BSFadeNode ctor — already shown)"),
    (0x1421BB590, "sub_1421BB590 (called right after with v14, v12, 0)"),
    (0x14050D2A0, "sub_14050D2A0 (per-cell parent set)"),
]:
    log("")
    log("  ## %s @ %s (RVA %s) size=%s" % (label, H(ea), H(rva(ea)),
                                             H(fsize(ea))))
    log("  " + "-"*76)
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:120]:
            log("    " + ln)
    else:
        log("    <decomp failed>")

# ---- D: Bone resolver chain ----
log("")
log("=" * 80)
log(" D. BONE RESOLVER chain — xrefs of sub_14040D4C0 (the only caller)")
log("=" * 80)

bone_caller_ea = 0x14040D4C0
log("")
log("  sub_14040D4C0 (only direct caller of bone resolver) — looking for ITS callers")
log("  to trace where bone resolution actually fires from.")

xref_callers = set()
for xr in idautils.XrefsTo(bone_caller_ea):
    f = ida_funcs.get_func(xr.frm)
    if f:
        xref_callers.add(f.start_ea)
log("  unique callers of sub_14040D4C0: %d" % len(xref_callers))
for ea in sorted(xref_callers):
    log("    %s (RVA %s) %s  size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(fsize(ea))))

log("")
log("  -- decomp of each caller --")
for caller_ea in sorted(xref_callers):
    log("")
    log("  ## %s (RVA %s) %s size=%s" % (H(caller_ea), H(rva(caller_ea)),
                                            fname(caller_ea), H(fsize(caller_ea))))
    log("  " + "-"*76)
    txt = decomp(caller_ea)
    if txt:
        for ln in txt.splitlines()[:200]:
            log("    " + ln)

# Then ITS callers (depth 2)
log("")
log("  -- 2-deep xref tree of bone resolver --")
depth2 = set()
for c in xref_callers:
    for xr in idautils.XrefsTo(c):
        f = ida_funcs.get_func(xr.frm)
        if f and f.start_ea not in xref_callers:
            depth2.add(f.start_ea)
log("  depth-2 callers (callers of callers): %d" % len(depth2))
for ea in sorted(depth2):
    log("    %s (RVA %s) %s  size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(fsize(ea))))

# ---- E: AnimGraphManager pointer offset confirmation ----
log("")
log("=" * 80)
log(" E. AnimGraphManager pointer offset — confirm via callers of sub_14187FF20")
log("=" * 80)

# Decomp the helper at depth 2 — sub_1418838E0 (called by sub_14187FF20 with v1=this+32)
log("")
log("  ## sub_1418838E0 (called by sub_14187FF20 with this+32)")
log("  " + "-"*76)
txt = decomp(0x1418838E0)
if txt:
    for ln in txt.splitlines()[:80]:
        log("    " + ln)

# Find callers of sub_14187FF20
log("")
log("  -- callers of sub_14187FF20 (anim graph getter) --")
agm_callers = set()
for xr in idautils.XrefsTo(0x14187FF20):
    f = ida_funcs.get_func(xr.frm)
    if f:
        agm_callers.add(f.start_ea)
log("  unique callers: %d" % len(agm_callers))
for ea in sorted(agm_callers):
    log("    %s (RVA %s) %s  size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(fsize(ea))))

# Now: at PC::Load3D, the call sub_14187FF20(v39) where v39 = sub_140C5C830(this) =
# a1+0x300 area. But the getter inside reads *(a1+32). So a1 here is NOT the actor —
# it's an INDIRECT pointer that lives at actor+0x300.
# Let's decompile sub_140C5C830 to see exactly what offset it returns.
log("")
log("  ## sub_140C5C830 (PC::Load3D's getter for v39)")
txt = decomp(0x140C5C830)
if txt:
    for ln in txt.splitlines():
        log("    " + ln)

log("")
log("  ## sub_140D342A0 (referenced inside sub_140C5C830?)")
# May not be the right one; we'll discover from the decomp above
txt = decomp(0x140D342A0)
if txt:
    for ln in txt.splitlines()[:60]:
        log("    " + ln)

# ---- F: fully decomp the v18-virtual call site  ----
# Get the disasm context around the vtable+752 call to confirm the form type chain.
log("")
log("=" * 80)
log(" F. DISASM context around the vtable+752 alt-loader call site")
log("=" * 80)

# In our decomp the call shows up as line ~655 hex-rays. The asm address can be
# found by searching for "mov rax, [r14]; ... call qword ptr [rax+2F0h]"-ish.
# Simpler: enumerate all calls to [reg+2F0h] within REFR::Load3D.
log("")
log("  -- scanning REFR::Load3D for indirect calls through [reg+2F0h] --")
f = ida_funcs.get_func(0x14050AC10)
cur = f.start_ea
hits_2F0 = []
while cur < f.end_ea:
    line = idc.generate_disasm_line(cur, 0) or ""
    ll = line.lower()
    if ('+2f0h' in ll or '+0x2f0' in ll) and ('call' in ll or 'jmp' in ll):
        hits_2F0.append((cur, line))
    nxt = idc.next_head(cur)
    if nxt <= cur: break
    cur = nxt
for cs, ln in hits_2F0:
    log("    %s : %s" % (H(cs), ln))

# Also dump 30 lines of context around each hit
log("")
log("  -- 20-line context around each [+2F0h] indirect call --")
for cs, ln in hits_2F0:
    log("")
    log("  --- @ %s ---" % H(cs))
    cur = cs - 0x40  # back up ~16 instructions
    for _ in range(40):
        if cur >= cs + 0x20: break
        line = idc.generate_disasm_line(cur, 0) or ""
        log("    %s : %s" % (H(cur), line))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt

# ---- G: search for ANY function in the binary that has the prologue
#         "this is a Load3D-virtual override" pattern: takes (form, refr, out_root)
#         AND calls sub_142174DC0 (BSFadeNode ctor) AND/OR sub_1417B3E90 ----
log("")
log("=" * 80)
log(" G. ANY function that calls BSFadeNode ctor sub_142174DC0 — these")
log("    are alternative NIF root creation sites (likely vt[94] overrides).")
log("=" * 80)
log("")

ctor_xrefs = set()
for xr in idautils.XrefsTo(0x142174DC0):
    f = ida_funcs.get_func(xr.frm)
    if f:
        ctor_xrefs.add(f.start_ea)
log("  total callers of sub_142174DC0 (BSFadeNode ctor): %d" % len(ctor_xrefs))
for ea in sorted(ctor_xrefs):
    sz = fsize(ea)
    log("    %s (RVA %s) %s  size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(sz) if sz else "?"))

# Now intersect with funcs that ALSO call sub_14040CF10 (the 0x1C0 alloc)
log("")
log("  -- alloc-helper sub_14040CF10 callers --")
alloc_xrefs = set()
for xr in idautils.XrefsTo(0x14040CF10):
    f = ida_funcs.get_func(xr.frm)
    if f:
        alloc_xrefs.add(f.start_ea)
log("  total callers of sub_14040CF10 (raw 0x1C0 alloc): %d" % len(alloc_xrefs))

intersection = sorted(ctor_xrefs & alloc_xrefs)
log("")
log("  >>> Funcs that call BOTH sub_14040CF10 AND sub_142174DC0 (BSFadeNode")
log("      allocate+construct in the same body): %d" % len(intersection))
for ea in intersection:
    log("    %s (RVA %s) %s  size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(fsize(ea))))

# Decomp each at length 1 (small set hopefully)
for ea in intersection[:20]:
    log("")
    log("  ## DECOMP %s (RVA %s) %s size=%s" %
        (H(ea), H(rva(ea)), fname(ea), H(fsize(ea))))
    log("  " + "-"*76)
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:200]:
            log("    " + ln)

# ---- H: TESNPC slot 94 — find via xref to vt[94]+752 directly ----
log("")
log("=" * 80)
log(" H. ENUMERATE ALL VTABLES with slot 94, dump fn ptr — to find ALL overrides")
log("=" * 80)

# We don't have a list of all TESForm subclass vtables ready. Instead we'll
# scan the whole .rdata segment for vtables and check what's at slot 94 for any
# vtable >= 100 slots.
log("")
log("  Scanning .rdata for vtables with >= 100 slots and dumping their slot 94...")

rd_seg = None
for s in idautils.Segments():
    if ida_segment.get_segm_name(ida_segment.getseg(s)) == ".rdata":
        rd_seg = ida_segment.getseg(s)
        break

# Heuristic: a vtable starts at a qword that points to a function in .text.
# We scan only at sites that are explicit data refs; otherwise too slow.
# Better: scan COL refs.
log("  (using COL+TD heuristic for safety)")

# Collect all .?AV TypeDescriptor strings that look like Class names.
all_vtables = set()
for sx in idautils.Strings():
    try:
        s = str(sx)
    except: continue
    if not s.startswith(".?AV") or not s.endswith("@@"): continue
    td_ea = sx.ea - 0x10
    for xr in idautils.XrefsTo(td_ea):
        if xr.iscode: continue
        col_ea = xr.frm - 0xC
        for xr2 in idautils.XrefsTo(col_ea):
            vt = xr2.frm + 8
            if vt_length(vt) >= 100:
                all_vtables.add((s, vt))

log("  total vtables with >= 100 slots: %d" % len(all_vtables))

# Build a map: slot94_target -> [(rtti_str, vtable_ea), ...]
slot94_map = {}
for (rtti_s, vt) in all_vtables:
    s94 = ida_bytes.get_qword(vt + 94*8)
    if s94 == 0: continue
    slot94_map.setdefault(s94, []).append((rtti_s, vt))

# Sort by number of distinct fn ptrs (most overrides = most interesting)
log("")
log("  unique slot94 targets across all 100+ slot vtables: %d" % len(slot94_map))
log("")
log("  -- top 30 by class count --")
sorted_targets = sorted(slot94_map.items(),
                         key=lambda kv: -len(kv[1]))
for (s94_ea, classes) in sorted_targets[:30]:
    nm = fname(s94_ea)
    sz = fsize(s94_ea)
    log("    %s (RVA %s) %s size=%s used_by_%d_classes" %
        (H(s94_ea), H(rva(s94_ea)), nm, H(sz) if sz else "?", len(classes)))
    for c, vt in classes[:5]:
        log("        %s @ vt %s (RVA %s)" % (c, H(vt), H(rva(vt))))
    if len(classes) > 5:
        log("        ... +%d more" % (len(classes) - 5))

# Decomp the most-overridden non-stub slot 94s
log("")
log("  -- DECOMP top 6 slot94 functions (skipping nullsub-like stubs) --")
n_decomp = 0
for (s94_ea, classes) in sorted_targets[:30]:
    if n_decomp >= 6: break
    sz = fsize(s94_ea)
    if not sz or sz < 20: continue   # skip nullsubs
    log("")
    log("  ## %s (RVA %s) %s  size=%s  used by %d classes" %
        (H(s94_ea), H(rva(s94_ea)), fname(s94_ea), H(sz), len(classes)))
    log("  used by: " + ", ".join(c for c, _ in classes[:8]))
    log("  " + "-"*76)
    txt = decomp(s94_ea)
    if txt:
        all_ln = txt.splitlines()
        for ln in all_ln[:200]:
            log("    " + ln)
        if len(all_ln) > 200:
            log("    ... [+%d lines truncated]" % (len(all_ln) - 200))
    n_decomp += 1

log("")
log("=" * 80)
log(" END")
log("=" * 80)
with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG, len(lines)))
import ida_pro
ida_pro.qexit(0)
