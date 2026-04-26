"""
M8 Phase 2 Step 1 — PHASE 3: Drill into the inner alt-loader candidates

Phase 2 results — major findings:
  1. REFR::Load3D's alt path is the virtual call vt[94]+752 on REFR.baseForm
     - call site: 0x14050AF6B
     - dispatch:
        TESNPC      vt[94] -> sub_140658690 (size 0x1FD = 509 bytes)  *** NPC/PC path ***
        Actor/PC    vt[94] -> sub_140C7BA20 (size 0xE55 = 3669 bytes) *** when actor IS baseForm ***
        Projectile  vt[94] -> sub_1404FEA30 (size 0x763)
        STAT/MOVT   vt[94] -> sub_140471AC0 (size 0x5C, calls TESBoundObject default)
        TESActorBase default vt[94] -> sub_140458370 (size 0xD, calls vt+624)
        BGSIdleMarker vt[94] -> sub_14061DA10
        ...

  2. sub_140658690 (TESNPC) calls sub_140458390 to do real work — that's our
     #1 target to decompile here.

  3. sub_1417B3480 (size 0x4D4) is the BSStream-based NIF parser variant.
     It alloc+inits a BSFadeNode (sub_142174DC0) OR an alternate ctor sub_142174E60.
     This is what reads NIFs from disk asynchronously.

  4. sub_140C7BA20 (size 0xE55) is the Actor/PC vt[94] override — bigger than
     PC::Load3D itself! This is critical for understanding how an actor's 3D
     attaches when ANOTHER reference's REFR::Load3D fires (rare).

Phase 3 tasks:
  1. Decompile sub_140458390 (FULL — likely the real alt loader)
  2. Decompile sub_140C7BA20 (FULL — Actor vt[94], 3669 bytes)
  3. Find xrefs to sub_140458390 — confirm it's the central NIF entry
  4. Decompile sub_1417B3D10 + sub_1417B40F0 (the two stream-NIF variants we saw)
  5. Decompile sub_142174E60 (alt BSFadeNode ctor)
  6. Find ALL xrefs to sub_1417B3E90 (public NIF loader) for comparison —
     count how many sites vs sub_140458390/sub_1417B3480
  7. Search for "MaleBody" / "FemaleBody" string xrefs (where do they originate)
  8. Search BGSBodyPart record path field — where is it read from
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_nalt

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p2_phase3_raw.log"
lines = []
BASE = 0x140000000

def log(s=""): lines.append(s if isinstance(s, str) else str(s))
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

log("=" * 80)
log(" M8 PHASE 2 STEP 1 — PHASE 3: drill into inner alt-loader candidates")
log("=" * 80)

# ---- A: full decomp of inner candidates ----
log("")
log("=" * 80)
log(" A. FULL decomps")
log("=" * 80)

CANDIDATES = [
    (0x140458390, "sub_140458390 — INNER alt-loader called from TESNPC vt[94]"),
    (0x140C7BA20, "sub_140C7BA20 — Actor/PC vt[94] override (3669 bytes!)"),
    (0x1417B3480, "sub_1417B3480 — BSStream-based NIF parser variant"),
    (0x1417B3D10, "sub_1417B3D10 — alt NIF entry called by sub_1404568E0"),
    (0x1417B40F0, "sub_1417B40F0 — alt NIF entry called by sub_1404568E0"),
    (0x142174E60, "sub_142174E60 — alt BSFadeNode ctor"),
    (0x140458370, "sub_140458370 — TESActorBase default vt[94] (just calls vt+624)"),
    (0x140471AC0, "sub_140471AC0 — STAT vt[94] (small wrapper)"),
    (0x14061DA10, "sub_14061DA10 — BGSIdleMarker vt[94]"),
    # also the helpers
    (0x140454090, "sub_140454090 — calls BSFadeNode ctor + alloc directly"),
    (0x1404568E0, "sub_1404568E0 — TESObjectLIGH-shaped, calls 1417B40F0/1417B3D10"),
    (0x14048F0A0, "sub_14048F0A0 — calls BSFadeNode ctor + alloc directly"),
]

for (ea, label) in CANDIDATES:
    log("")
    log("  " + "-" * 76)
    log("  ## %s @ %s (RVA %s)  size=%s" % (label, H(ea), H(rva(ea)),
                                              H(fsize(ea))))
    log("  " + "-" * 76)
    txt = decomp(ea)
    if txt:
        all_lines = txt.splitlines()
        max_lines = 350 if fsize(ea) and fsize(ea) > 0x600 else 250
        for ln in all_lines[:max_lines]:
            log("    " + ln)
        if len(all_lines) > max_lines:
            log("    ... [+%d lines truncated]" % (len(all_lines) - max_lines))
    else:
        log("    <decomp failed>")

# ---- B: xrefs to public vs alt NIF loaders ----
log("")
log("=" * 80)
log(" B. CALL-SITE COMPARISON — public vs alt NIF loaders")
log("=" * 80)

for (ea, label) in [
    (0x1417B3E90, "PUBLIC NIF LOADER sub_1417B3E90 (we hook this)"),
    (0x1417B3480, "ALT NIF PARSER sub_1417B3480 (BSStream-based)"),
    (0x1417B3D10, "ALT sub_1417B3D10"),
    (0x1417B40F0, "ALT sub_1417B40F0"),
    (0x140458390, "INNER ALT sub_140458390"),
]:
    log("")
    log("  ## %s" % label)
    callers = set()
    for xr in idautils.XrefsTo(ea):
        f = ida_funcs.get_func(xr.frm)
        if f:
            callers.add((f.start_ea, xr.frm))
    log("  total call sites: %d   unique caller funcs: %d" %
        (len(callers), len(set(c[0] for c in callers))))
    for caller_ea, csite in sorted(callers)[:15]:
        log("    %s in %s @ %s (caller size %s)" %
            (H(csite), fname(caller_ea), H(caller_ea),
             H(fsize(caller_ea)) if fsize(caller_ea) else "?"))
    if len(callers) > 15:
        log("    ... +%d more" % (len(callers) - 15))

# ---- C: MaleBody / FemaleBody string xrefs ----
log("")
log("=" * 80)
log(" C. STRING XREFS — MaleBody, FemaleBody, .nif, BGSBodyPart")
log("=" * 80)

# Build string cache and find body-related strings
target_subs = ['malebody', 'femalebody', 'characterassets', 'bodyparts',
               'skeleton.nif', 'bodypartfile', 'bodypart', 'meshes\\actors',
               'fox01', 'fox02']

found_strings = []
try:
    for sx in idautils.Strings():
        try:
            s = str(sx)
            sl = s.lower()
            for t in target_subs:
                if t in sl:
                    found_strings.append((sx.ea, s))
                    break
        except: pass
except Exception as e:
    log("  string-cache err: %s" % e)

log("  found %d body-related strings" % len(found_strings))
for (ea, s) in found_strings[:60]:
    log("")
    log("    @ %s : %r" % (H(ea), s[:120]))
    callers = set()
    for xr in idautils.XrefsTo(ea):
        f = ida_funcs.get_func(xr.frm)
        if f:
            callers.add(f.start_ea)
    for c in sorted(callers)[:5]:
        log("      xref from %s (RVA %s) %s  size=%s" %
            (H(c), H(rva(c)), fname(c), H(fsize(c)) if fsize(c) else "?"))
    if len(callers) > 5:
        log("      ... +%d more" % (len(callers) - 5))

# ---- D: Walk sub_140C7BA20 callees to find KEY operations ----
log("")
log("=" * 80)
log(" D. ANALYSIS — callees of sub_140C7BA20 (Actor vt[94], 3669 bytes)")
log("    Look for: NIF loader / BSResource / TESModel / BGSBodyPart accesses")
log("=" * 80)

actor94_callees = callees_in(0x140C7BA20)
log("  total direct callees of sub_140C7BA20: %d" % len(set(c for _, c, _ in actor94_callees)))
unique_targets = sorted(set(c for _, c, _ in actor94_callees))
NIF_PUB    = 0x1417B3E90
NIF_ALT_1  = 0x1417B3480
NIF_ALT_2  = 0x1417B3D10
NIF_ALT_3  = 0x1417B40F0
INNER_ALT  = 0x140458390
PRELOAD    = 0x1417A3210
BONE_RES   = 0x1403F85E0
APPLY_MAT  = 0x140255BA0
BSFADE     = 0x142174DC0

flagged = {
    NIF_PUB:   "PUBLIC NIF LOADER (we hook)",
    NIF_ALT_1: "ALT BSStream parser",
    NIF_ALT_2: "ALT 1417B3D10",
    NIF_ALT_3: "ALT 1417B40F0",
    INNER_ALT: "INNER ALT 140458390",
    PRELOAD:   "BSResource preload",
    BONE_RES:  "BONE RESOLVER",
    APPLY_MAT: "apply_materials walker",
    BSFADE:    "BSFadeNode ctor",
}

for t in unique_targets:
    flag = flagged.get(t, "")
    fl_str = "  [%s]" % flag if flag else ""
    log("    %s (RVA %s) %s  size=%s%s" %
        (H(t), H(rva(t)), fname(t),
         H(fsize(t)) if fsize(t) else "?", fl_str))

# ---- E: Walk sub_140458390 callees ----
log("")
log("=" * 80)
log(" E. ANALYSIS — callees of sub_140458390 (the inner alt-loader)")
log("=" * 80)

inner_callees = callees_in(0x140458390)
log("  total direct callees: %d" % len(set(c for _, c, _ in inner_callees)))
for t in sorted(set(c for _, c, _ in inner_callees)):
    flag = flagged.get(t, "")
    fl_str = "  [%s]" % flag if flag else ""
    log("    %s (RVA %s) %s  size=%s%s" %
        (H(t), H(rva(t)), fname(t),
         H(fsize(t)) if fsize(t) else "?", fl_str))

# ---- F: Search for vtable+752 indirect calls in REFR::Load3D's call subtree ----
log("")
log("=" * 80)
log(" F. ALL CALL SITES that dispatch through [reg+2F0h]/+752 in the binary")
log("=" * 80)
log("")

# Scan all .text for "call qword ptr [reg+2F0h]" or "call qword ptr [reg+0x2F0]"
text_seg = None
for s in idautils.Segments():
    if ida_segment.get_segm_name(ida_segment.getseg(s)) == ".text":
        text_seg = ida_segment.getseg(s)
        break

if text_seg:
    cur = text_seg.start_ea
    hits_2F0_global = []
    n_scanned = 0
    while cur < text_seg.end_ea:
        line = idc.generate_disasm_line(cur, 0) or ""
        ll = line.lower()
        if ('call' in ll) and ('+2f0h' in ll or '+0x2f0' in ll):
            f = ida_funcs.get_func(cur)
            hits_2F0_global.append((cur, f.start_ea if f else 0, line))
        cur = idc.next_head(cur)
        if cur == idc.BADADDR: break
        n_scanned += 1
        if n_scanned > 5000000: break  # hard cap

    log("  total binary-wide call [+2F0h] sites: %d" % len(hits_2F0_global))
    for cs, fea, ln in hits_2F0_global[:40]:
        log("    %s in %s (RVA %s) %s : %s" %
            (H(cs), H(fea), H(rva(fea)) if fea else "?",
             fname(fea) if fea else "?", ln))
    if len(hits_2F0_global) > 40:
        log("    ... +%d more" % (len(hits_2F0_global) - 40))
else:
    log("  .text segment not found")

# ---- G: TESNPC + TESBoundObject vtable+624 (TESActorBase default delegates here) ----
log("")
log("=" * 80)
log(" G. TESActorBase vt[94] (sub_140458370) delegates to vtable+624 (= slot 78)")
log("    -- decomp slot 78 of various form vtables")
log("=" * 80)

# Look at TESActorBase / TESBoundObject vt[78]
for vt_ea in [0x1424CDC08, 0x14248E850]:  # TESActorBase, TESBoundObject
    log("")
    log("  vt %s (RVA %s) -- slot 78" % (H(vt_ea), H(rva(vt_ea))))
    s78 = ida_bytes.get_qword(vt_ea + 78*8)
    log("    vt[78] = %s (RVA %s) %s  size=%s" %
        (H(s78), H(rva(s78)), fname(s78), H(fsize(s78)) if fsize(s78) else "?"))
    if s78:
        txt = decomp(s78)
        if txt:
            for ln in txt.splitlines()[:120]:
                log("      " + ln)

log("")
log("=" * 80)
log(" END")
log("=" * 80)
with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG, len(lines)))
import ida_pro
ida_pro.qexit(0)
