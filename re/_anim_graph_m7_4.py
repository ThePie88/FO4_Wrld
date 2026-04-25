"""
M7.b Pass 4 — finalize Q1-Q6 answers.

Key new facts to confirm:
  - sub_140818DA0 = SetVariableFloat engine fn (3 args: holder*, BSFixedString*, float)
  - sub_140818D60 = SetVariableBool
  - sub_140818D80 = SetVariableInt
  - Actor::IAnimationGraphManagerHolder embedded at offset +72 (0x48) inside Actor
  - sub_14131AB20 = BShkbAnimationGraph ctor (size 0x3D0)
  - SAHMH ctor candidates: sub_14081BC00 (basic ctor), sub_14081BC40 (alt)
  - sub_140CA9980 = registers BSAnimationGraphChannels (Speed/Pitch/etc)
  - BSAnimationGraphManager vtable @ 0x142626320
  - BShkbAnimationGraph vtable @ 0x142626B38
  - BGSBehaviorGraphModel vtable @ 0x1424D0048
  - BSBehaviorGraphExtraData @ 0x142697818
  - hkbBehaviorGraph vtable @ 0x1426334E0
  - "Hkbloadanimati..." truncated string — likely "HkbLoadAnimationFromBuffer" or similar

Drill:
  1. Decomp sub_140818DA0/D60/D80 — engine variable setters
  2. Decomp sub_14081BC00 (basic SAHMH ctor)
  3. Decomp 14130EAE0 (called from SAHMH vt[1] — likely the update tick)
  4. Find what calls SAHMH vt[7] (graph allocator) — vanilla flow
  5. Read 'Hkbloadanimati' / 'Hkbunloadanima' / 'aBehaviorgraph' strings + xrefs
  6. Decomp BShkbAnimationGraph::vftable[0..20]
  7. Decomp ExtraAnimGraphManager ExtraData (ctor + Add to ExtraDataList)
  8. Find caller of sub_140CA9980 — that's the Actor.RegisterDataChannels-like function
  9. Look at sub_14081C0E0 (vt[4]) and sub_14081C140 (vt[5]) — get/set graph
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_anim_graph_m7.log"
out_lines = []

def log(s):
    out_lines.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)
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
def decomp(ea, label=""):
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            log("\n========== %s @ %s ==========" % (label, hexs(ea)))
            log(str(cf))
            return cf
    except Exception as e:
        log("decomp err %s: %s" % (hexs(ea), e))
    return None
def xrefs_to(ea):
    try: return list(idautils.XrefsTo(ea))
    except: return []

log("\n" + "=" * 78)
log(" PASS 4 — final drill")
log("=" * 78)

# 1. The engine variable setters
for ea, label in [
    (0x140818DA0, "engine SetVariableFloat (anim)"),
    (0x140818D60, "engine SetVariableBool (anim)"),
    (0x140818D80, "engine SetVariableInt (anim)"),
]:
    decomp(ea, label)

# 2. SAHMH basic ctor
for ea, label in [
    (0x14081BC00, "SAHMH basic ctor"),
    (0x14081BC40, "SAHMH alt ctor (the dtor-like that resets)"),
    (0x140818DF0, "sub_140818DF0 — base ctor"),
    (0x140818E10, "sub_140818E10 — base dtor"),
]:
    decomp(ea, label)

# 3. Look at what sub_14130EAE0 does
decomp(0x14130EAE0, "sub_14130EAE0 — anim graph update entry?")

# 4. Find xrefs to sub_14081C1A0 (SAHMH allocator) — earlier said 0 callers, retry without iscode filter
log("\n--- ALL xrefs to SAHMH vt[7] sub_14081C1A0 ---")
for xr in xrefs_to(0x14081C1A0):
    log("  xref from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))

# vt[7] is in vtable so its only xref is the vtable slot itself.
# Real callers go through vtable dispatch — search for offset 56 (vt[7] = +0x38) call patterns, hard.
# Instead, find xrefs to sub_14131AB20 (the actual graph ctor it calls).
log("\n--- xrefs to BShkbAnimationGraph ctor sub_14131AB20 ---")
for xr in xrefs_to(0x14131AB20):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s @ %s" % (hexs(xr.frm), name_at(f.start_ea), hexs(f.start_ea)))

# 5. Strings related to behaviors
log("\n--- 'Hkbloadanimati' and similar strings ---")
for sx in idautils.Strings():
    s = str(sx)
    if "Hkb" in s or "hkb" in s or "behaviorgraph" in s.lower() or "aBehavior" in s:
        log("  %s @ %s" % (repr(s)[:80], hexs(sx.ea)))

# 6. BShkbAnimationGraph vtable
log("\n--- BShkbAnimationGraph vtable @ 0x142626B38 ---")
vt = 0x142626B38
for i in range(40):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# Decomp first few BShkbAnimationGraph methods
for i in range(0, 12):
    fn_ea = ida_bytes.get_qword(0x142626B38 + i*8)
    if fn_ea and ida_funcs.get_func(fn_ea):
        decomp(fn_ea, "BShkbAnimGraph vt[%d]" % i)

# 7. BSAnimationGraphManager vtable
log("\n--- BSAnimationGraphManager vtable @ 0x142626320 ---")
vt = 0x142626320
for i in range(40):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# 8. ExtraAnimGraphManager (ExtraData)
log("\n--- ExtraAnimGraphManager vtable @ 0x142469578 ---")
vt = 0x142469578
for i in range(20):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# Decomp ExtraAnimGraphManager dtor (vt[0])
ext_anim_vt0 = ida_bytes.get_qword(0x142469578)
if ext_anim_vt0:
    decomp(ext_anim_vt0, "ExtraAnimGraphManager vt[0] (dtor)")

# 9. Find xrefs to ExtraAnimGraphManager vtable (find ctor)
log("\n--- xrefs to ExtraAnimGraphManager vtable 0x142469578 (find ctor) ---")
for xr in xrefs_to(0x142469578):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))
        decomp(f.start_ea, "ExtraAnimGraphManager ctor candidate @ 0x%X" % f.start_ea)

# 10. Find caller of sub_140CA9980 (channel registration)
log("\n--- callers of sub_140CA9980 (channel registrar) ---")
for xr in xrefs_to(0x140CA9980):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 11. Find callers of the variable setters — confirm parameter list
log("\n--- callers of engine SetVariableFloat sub_140818DA0 ---")
for xr in xrefs_to(0x140818DA0):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 12. SAHMH vt[4]/vt[5] (get/set graph)
for ea, label in [
    (0x14081C0E0, "SAHMH vt[4] GetGraph"),
    (0x14081C140, "SAHMH vt[5] SetGraph"),
    (0x14081C1A0, "SAHMH vt[7] CreateGraph (already done)"),
]:
    decomp(ea, label)

# 13. Confirm — does the BShkbAnimationGraph ctor sub_14131AB20 set up a hkb skeleton?
# Already decompiled — it allocates BSIRagdollDriver + BShkbAnimationGraph fields, no skeleton.
# Skeleton attach must be in a separate fn called later.

# 14. Look at xrefs to sub_14131AB20 — get the full graph creation chain
log("\n--- ALL xrefs to BShkbAnimationGraph ctor 0x14131AB20 (incl data) ---")
for xr in xrefs_to(0x14131AB20):
    log("  xref from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))

# 15. Find behavior load fn — look for "BehaviorPath" or "Loaded behavior"
log("\n--- 'BehaviorPath' / 'LoadBehavior' strings ---")
for sx in idautils.Strings():
    s = str(sx)
    if ("BehaviorPath" in s or "LoadBehavior" in s or "loadAnim" in s.lower() or
        "loadbehavior" in s.lower()):
        log("  %s @ %s" % (repr(s)[:80], hexs(sx.ea)))

# 16. .hkx file extension references
log("\n--- '.hkx' extension references in code ---")
hkx_lits = [".hkx", "%s.hkx", "Behaviors\\%s", "Behaviors\\\\%s", "Behaviors/%s",
            "%s\\Behaviors\\%s.hkx", "Actors\\%s\\Behaviors\\%s.hkx",
            "Meshes\\Actors\\%s\\Behaviors\\%s.hkx",
            "Meshes\\AnimationData",
            "Race::BehaviorGraph"]
for s in hkx_lits:
    for sx in idautils.Strings():
        if str(sx) == s:
            log("  %r @ %s" % (s, hexs(sx.ea)))
            for xr in xrefs_to(sx.ea):
                f = ida_funcs.get_func(xr.frm)
                fn = name_at(f.start_ea) if f else "?"
                log("      xref from %s in %s" % (hexs(xr.frm), fn))

# 17. Look at race-behavior-graph TESRace ESM data structure offsets
# The TESRace record stores a "behavior graph" path per gender. RTTI: TESRace
log("\n--- Names matching TESRace + 'behavior' or 'graph' ---")
for n_ea, n in idautils.Names():
    if "TESRace" in n and ("Behavior" in n or "Graph" in n or "Animation" in n):
        log("  %s  %s" % (hexs(n_ea), n))

# 18. Find BGSBehaviorGraphModel — likely the form record's behavior graph reference
log("\n--- BGSBehaviorGraphModel vtable @ 0x1424D0048 ---")
vt = 0x1424D0048
for i in range(20):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# 19. PlayerCharacter vt[18] (sub_140D656A0) — likely Init3D / Load3D variant
# Often in Bethesda games: vt[18] is "Setup3D" type fn for actors. Decomp to check.
decomp(0x140D656A0, "PlayerCharacter vt[18]")
decomp(0x140D67C50, "PlayerCharacter vt[19]")
decomp(0x140D67DC0, "PlayerCharacter vt[20]")

# 20. The function that calls 0x140CA9980 — that's the actor anim init code
log("\n--- Search for call to 0x140CA9980 across all functions ---")
# done above already

# 21. The Actor full vtable — pick from 0x142EE4288 (most likely)
log("\n--- Possible Actor vtable @ 0x142EE4288 ---")
vt = 0x142EE4288
for i in range(40):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Appended %d lines" % len(out_lines))
import ida_pro
ida_pro.qexit(0)
