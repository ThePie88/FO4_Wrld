"""
M8 Phase 2 Step 1 — PHASE 4: final missing pieces

Now I've identified:
  - Alt-loader: sub_140458740 (RVA 0x458740, size 0x114F = 4431 bytes!)
    Wrapped by sub_140458390 (TLS phase setter)
    Called from TESNPC vt[94] = sub_140658690 indirectly via sub_140458390
    Also called by sub_1404391C0 (another path)
    Recursive (calls itself for body parts!)

  - sub_142174E60 = BSFadeNode "AssignSource" alt ctor (cross-link var)
  - sub_140C7BA20 = Actor/PC vt[94] is AUDIO related (sub_14162FD40 sound builder),
    NOT the NIF loader — confirms our 1FP/3P separation

Phase 4 tasks:
  1. Decompile sub_1404391C0 (the OTHER caller of sub_140458740)
     to understand when sub_140458740 is called outside of TESNPC context.
  2. Decompile sub_140458740 IN FULL (4431 bytes; no truncation)
  3. Decompile sub_1404080E0 (the depth-2 caller of bone resolver)
  4. Find xrefs to sub_1404080E0 to trace bone resolution origin
  5. Inspect sub_140658690 callees more carefully (esp BSFadeNode handling)
  6. Verify the AnimGraphManager pointer chain offsets:
        actor + 0x300 -> +0x08 -> +0x3E0 -> +0x18 -> +0x18 = AGM
"""

import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_nalt

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p2_phase4_raw.log"
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
log(" M8 PHASE 2 STEP 1 — PHASE 4: final pieces")
log("=" * 80)

# ---- A: Decomp sub_1404391C0 (other caller) ----
log("")
log("=" * 80)
log(" A. sub_1404391C0 — second caller of sub_140458740")
log("=" * 80)

txt = decomp(0x1404391C0)
if txt:
    for ln in txt.splitlines():
        log("  " + ln)
else:
    log("  <decomp failed>")

# its callees
log("")
log("  -- callees of sub_1404391C0 --")
for cs, t, mn in callees_in(0x1404391C0):
    log("    %s %s -> %s (RVA %s) %s  size=%s" %
        (H(cs), mn, H(t), H(rva(t)), fname(t),
         H(fsize(t)) if fsize(t) else "?"))

# Find its callers
log("")
log("  -- callers of sub_1404391C0 --")
for xr in idautils.XrefsTo(0x1404391C0):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("    %s in %s (RVA %s) %s  size=%s" %
            (H(xr.frm), H(f.start_ea), H(rva(f.start_ea)),
             fname(f.start_ea), H(f.end_ea - f.start_ea)))

# ---- B: Decomp sub_140458740 in FULL ----
log("")
log("=" * 80)
log(" B. sub_140458740 — FULL DECOMP (the BIG 3D LOADER, 4431 bytes)")
log("=" * 80)

# decomp full
txt = decomp(0x140458740)
if txt:
    log("  size=%s" % H(fsize(0x140458740)))
    log("")
    for ln in txt.splitlines():
        log("  " + ln)
else:
    log("  <decomp failed — try via disasm>")

log("")
log("  -- callees of sub_140458740 (deduped) --")
unique = sorted(set(t for _, t, _ in callees_in(0x140458740)))
for t in unique:
    log("    %s (RVA %s) %s  size=%s" %
        (H(t), H(rva(t)), fname(t),
         H(fsize(t)) if fsize(t) else "?"))

# ---- C: bone resolver depth 2 callers ----
log("")
log("=" * 80)
log(" C. sub_1404080E0 — depth-2 caller of bone resolver (= caller's caller)")
log("=" * 80)

txt = decomp(0x1404080E0)
if txt:
    log("  size=%s" % H(fsize(0x1404080E0)))
    log("")
    for ln in txt.splitlines()[:200]:
        log("  " + ln)

# ITS callers
log("")
log("  -- callers of sub_1404080E0 --")
for xr in idautils.XrefsTo(0x1404080E0):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("    %s in %s (RVA %s) %s  size=%s" %
            (H(xr.frm), H(f.start_ea), H(rva(f.start_ea)),
             fname(f.start_ea), H(f.end_ea - f.start_ea)))

# ---- D: sub_140658690 internal flow ----
log("")
log("=" * 80)
log(" D. sub_140658690 (TESNPC vt[94]) — callees in detail")
log("=" * 80)

for cs, t, mn in callees_in(0x140658690):
    log("    %s %s -> %s (RVA %s) %s  size=%s" %
        (H(cs), mn, H(t), H(rva(t)), fname(t),
         H(fsize(t)) if fsize(t) else "?"))

# ---- E: AnimGraphManager pointer chain ----
log("")
log("=" * 80)
log(" E. AnimGraphManager chain — full breakdown")
log("=" * 80)
log("")
log("  Per phase2 finding:")
log("    PC::Load3D: v39 = sub_140C5C830(this);  // returns *(this+0x300) -> sub_140D342A0")
log("    sub_140C5C830:")
log("        v3 = *(__int64*)(a1 + 768);   // 768 = 0x300")
log("        if (v3) return sub_140D342A0(v3, ...);")
log("    sub_140D342A0:")
log("        result = *(a1 + 8);  // +0x08")
log("        if (result) return *(result + 992);  // +0x3E0")
log("    sub_14187FF20:")
log("        v1 = *(a1 + 32);  // +0x20")
log("        if (v1) return sub_1418838E0(v1);")
log("    sub_1418838E0:")
log("        result = *(a1 + 24);  // +0x18")
log("        if (result) return *(result + 24);  // +0x18")
log("")
log("  CHAIN: actor + 0x300 -> +0x08 -> +0x3E0 -> +0x20 -> +0x18 -> +0x18 = AGM")
log("")
log("  Also: at line 514 of PC::Load3D decomp:")
log("    'sub_141895000(v40)' is called with v40 = the result of sub_14187FF20.")
log("    v40 = the AnimGraphManager wrapper. Confirm by decomping animdirty:")

txt = decomp(0x141895000)
if txt:
    for ln in txt.splitlines()[:60]:
        log("    " + ln)

# Decomp the helper sub_1418838E0 in full
log("")
log("  -- sub_1418838E0 (depth 1 from sub_14187FF20) --")
txt = decomp(0x1418838E0)
if txt:
    for ln in txt.splitlines():
        log("    " + ln)

# Decomp sub_141880CD0 (used by animdirty per dossier)
log("")
log("  -- sub_141880CD0 (used by animdirty - produces 16-bit version stamp) --")
txt = decomp(0x141880CD0)
if txt:
    for ln in txt.splitlines()[:60]:
        log("    " + ln)

# ---- F: search ALL '+300h' constant accesses in PC/Actor/REFR Load3D
#         and resolve them with disasm context ----
log("")
log("=" * 80)
log(" F. ALL [reg+300h] accesses in PC::Load3D, Actor::Load3D, REFR::Load3D")
log("=" * 80)
log("")

for fn_ea, label in [
    (0x140D5B250, "PC::Load3D"),
    (0x140C584F0, "Actor::Load3D"),
    (0x14050AC10, "REFR::Load3D"),
]:
    log("")
    log("  -- %s @ %s --" % (label, H(fn_ea)))
    f = ida_funcs.get_func(fn_ea)
    cur = f.start_ea
    hits = []
    while cur < f.end_ea:
        line = idc.generate_disasm_line(cur, 0) or ""
        ll = line.lower()
        if ('+300h' in ll or '+0x300' in ll or '+2f8h' in ll or '+0x2f8' in ll
            or '+2f0h' in ll or '+0x2f0' in ll):
            hits.append((cur, line))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    for cs, ln in hits:
        log("    %s : %s" % (H(cs), ln))

# ---- G: Decompile sub_142174E60 (BSFadeNode AssignSource alt-ctor) ----
log("")
log("=" * 80)
log(" G. sub_142174E60 (BSFadeNode AssignSource alt-ctor)")
log("=" * 80)
txt = decomp(0x142174E60)
if txt:
    for ln in txt.splitlines():
        log("  " + ln)

# Decomp sub_142175310 + sub_142177590 (the OTHER BSFadeNode vtable writers)
for ea in [0x142175310, 0x142177590, 0x142177E60]:
    log("")
    log("  ## sub_%X (BSFadeNode-vt writer) size=%s" % (ea, H(fsize(ea))))
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:80]:
            log("    " + ln)

log("")
log("=" * 80)
log(" END")
log("=" * 80)
with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG, len(lines)))
import ida_pro
ida_pro.qexit(0)
