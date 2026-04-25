"""
M7.b Pass 6 — final pieces.
1. BSBehaviorGraphExtraData vtable + ctor — what NIF-side data does it hold?
2. SetAnimGraphVar console handler sub_1405D8800 decomp
3. BShkbAnimGraph SetVariable functions (sub_141326590 = SetVarFloat per-graph)
4. Find BSAnimationGraphManager (different from BShkbAnimGraph) ctor — that's the holder.vt[4] return
5. Verify how SAHMH manager (the 0x3D0 byte struct) relates to BShkbAnimationGraph
6. Player vt[18] sub_140D656A0 — likely PC Init3D
7. The Update tick fn (Actor.AnimGraph::Update)
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_anim_graph_m7.log"
out_lines = []
def log(s): out_lines.append(s if isinstance(s, str) else str(s))
def hexs(x): return "0x%X" % x
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
    except Exception as e:
        log("decomp err %s: %s" % (hexs(ea), e))

log("\n" + "=" * 78)
log(" PASS 6 — final missing pieces")
log("=" * 78)

# 1. BSBehaviorGraphExtraData vtable + ctor
log("\n--- BSBehaviorGraphExtraData vtable @ 0x142697818 ---")
vt = 0x142697818
for i in range(20):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))
    decomp(v, "BSBehaviorGraphExtraData vt[%d]" % i)

# Find ctor
log("\n--- BSBehaviorGraphExtraData ctor (xrefs to vtable) ---")
for xr in idautils.XrefsTo(0x142697818):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))
        decomp(f.start_ea, "BSBehaviorGraphExtraData ctor candidate")

# 2. SetAnimGraphVar console handler
decomp(0x1405D8800, "SetAnimGraphVar console handler")

# 3. BShkbAnimGraph per-graph SetVariableFloat sub_141326590
decomp(0x141326590, "BShkbAnimGraph::SetVariableFloat (per-graph)")
decomp(0x1413264B0, "BShkbAnimGraph::SetVariableBool (per-graph)")
decomp(0x141326670, "BShkbAnimGraph::SetVariableInt (per-graph)")

# 4. SAHMH vt[2] (was nullsub) and SAHMH vt[4] = "GetGraphMgr"
# Already done in pass 2.

# 5. Look at sub_141326590 → it should call hkbBehaviorGraph SetVariableFloat
# already done.

# 6. PC vt[18] decomp
decomp(0x140D656A0, "PlayerCharacter vt[18] (sub_140D656A0)")

# 7. Find Actor::Load3D — it's calling sub_140CA9280 (SAHMH alloc).
# Actor::Load3D = caller of sub_140CA9280?
log("\n--- Callers of sub_140CA9280 (Actor SAHMH alloc) ---")
for xr in idautils.XrefsTo(0x140CA9280):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 8. Update tick — usually Actor.vt[?] called per-frame via process scheduler.
# Look at sub_141326BB0 callers (BShkbAnimGraph vt[1])
log("\n--- Callers of BShkbAnimGraph vt[1] sub_141326BB0 (IsActive) ---")
for xr in idautils.XrefsTo(0x141326BB0):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 9. Find xrefs to sub_141326590 — is it called from an update fn?
log("\n--- Callers of BShkbAnimGraph::SetVariableFloat sub_141326590 ---")
for xr in idautils.XrefsTo(0x141326590):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 10. Look at sub_140D7CFB0 caller — possibly Player::SetupSAHMH
log("\n--- Callers of sub_140D7CFB0 (Player SAHMH alloc) ---")
for xr in idautils.XrefsTo(0x140D7CFB0):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 11. Decomp sub_14131AE70 — used in BShkbAnimGraph dtor + sub_14131A080 loader
decomp(0x14131AE70, "sub_14131AE70 (BShkbAnimGraph dtor / cleanup)")

# 12. Decomp sub_141323B50 — called between BShkbAnimGraph ctor and load fn (sub_14131A080)
decomp(0x141323B50, "sub_141323B50 (BShkbAnimGraph::Init / SetCharacterData?)")

# 13. The Init3D path — look at sub_140C5A8C0 (called from sub_1402B4BD0 = item drop SAHMH)
# Probably gets BehaviorGraph from something
decomp(0x140C5A8C0, "sub_140C5A8C0 (callsite from SAHMH ctor wrapper)")

# 14. Look at hkb-load functions — the actual havok loader
log("\n--- Names containing 'hkbLoad' or 'hkbInit' ---")
for n_ea, n in idautils.Names():
    nl = n.lower()
    if "hkbload" in nl or "hkbinit" in nl or ("loadanim" in nl and "graph" in nl):
        log("  %s  %s" % (hexs(n_ea), n))

# 15. Look at BSAnimationGraphManager vtable @ 0x142626320 — this is the per-actor graph mgr
log("\n--- BSAnimationGraphManager full vtable @ 0x142626320 ---")
vt = 0x142626320
for i in range(15):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))
    decomp(v, "BSAnimGraphMgr vt[%d]" % i)

# Find xrefs to BSAnimGraphMgr vtable -> ctor
log("\n--- BSAnimationGraphManager ctor (xrefs) ---")
for xr in idautils.XrefsTo(0x142626320):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# 16. Decomp BShkbAnimGraph ctor (sub_14131AB20) more carefully — it has a2 = something
# from caller passing actor; what does a2 do?
# (already done in pass 3 — but the ctor stored a2 at +896 — that's the "owner" pointer)
# 17. Find xrefs to "Race" or "TESRace" -> behavior graph fields (TESNPC+440)
log("\n--- Names: TESNPC + offset 440 ---")
# Hard to find statically; skip.

# Final: sub_141326580 = SetVariableFloat WITHOUT the lock; let's try +0x10 below
decomp(0x141326580, "sub_141326580 (just before SetVarFloat)")

# Append
with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Appended %d lines" % len(out_lines))
import ida_pro
ida_pro.qexit(0)
