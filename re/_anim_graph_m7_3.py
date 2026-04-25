"""
M7.b Pass 3 — drill SetAnimationVariableFloat/Bool/Int natives + engine fn

Found:
  Native impl     : sub_14115CCB0  (SetAnimationVariableFloat)
                    sub_14115CC10  (SetAnimationVariableBool)
                    sub_14115CD50  (SetAnimationVariableInt)
  These call: vt[?] on IAnimationGraphManagerHolder

Drill:
  1. Decomp those 3 natives + their underlying engine fn
  2. Decomp Actor::Load3D properly — the REAL one (the 0x140458740 was a model substitution path)
  3. Find ALL callers of SimpleAnimationGraphManagerHolder ctor or vtable -> find Actor wiring
  4. Find the actual Actor RTTI vtable and grep for "AddVariableUpdate" / fn that creates SAHMH
  5. The vt[7] fn at sub_14081C1A0 allocates 0x3D0 bytes & calls sub_14131AB20 — likely THE ANIM GRAPH MGR ALLOC
  6. sub_14131AB20 — investigate (probably hkbBehaviorGraphManager-equivalent)
  7. PlayerCharacter Load3D — the master template
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

log("\n=" * 39)
log(" PASS 3 — Native impls + engine fn")
log("=" * 78)

# ====== 1. Decomp Papyrus natives ======
for ea, label in [
    (0x14115CCB0, "Papyrus SetAnimationVariableFloat impl"),
    (0x14115CC10, "Papyrus SetAnimationVariableBool impl"),
    (0x14115CD50, "Papyrus SetAnimationVariableInt impl"),
    (0x14115C9F0, "Papyrus SetAngle impl"),  # for comparison
]:
    decomp(ea, label)

# ====== 2. Find what engine fn the natives end up calling ======
# Typical chain: Native -> obj.vt[?] -> SAHMH-method -> graph-method
# Decomp also possible inner helper.

# ====== 3. Decomp the SAHMH alloc path: vt[7] sub_14081C1A0 → sub_14131AB20 ======
log("\n--- ANIM GRAPH ALLOCATION PATH ---")
decomp(0x14081C1A0, "SAHMH vt[7] (graph allocator entry)")
decomp(0x14131AB20, "anim graph mgr ctor sub_14131AB20")
decomp(0x14081C250, "SAHMH dtor helper sub_14081C250")
decomp(0x14081BC00, "SAHMH ref helper sub_14081BC00 (writes vtable)")
decomp(0x14081BC40, "SAHMH ref helper sub_14081BC40 (writes vtable)")
decomp(0x14081C350, "SAHMH dtor sub_14081C350")

# ====== 4. Find SAHMH ctor — its xrefs to vtable 0x142518C10 from inside an unnamed fn ======
# The function that puts the vtable into a freshly allocated object IS the ctor.
log("\n--- SAHMH ctor candidates (xrefs to vt 0x142518C10) ---")
for xr in xrefs_to(0x142518C10):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s @ %s" %
            (hexs(xr.frm), name_at(f.start_ea), hexs(f.start_ea)))

# ====== 5. WeaponAnimationGraphManagerHolder vt — is there a matching path for it? ======
log("\n--- WeaponAnimationGraphManagerHolder vtable @ 0x142518DE8 ---")
vt = 0x142518DE8
for i in range(30):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# ====== 6. ExtraAnimGraphManager (ExtraData) — find vtable + ctor ======
# RTTI string at 0x142F96698; TD at 0x142F96688
log("\n--- ExtraAnimGraphManager (ExtraData) ---")
for n_ea, n in idautils.Names():
    if "ExtraAnimGraph" in n:
        log("  %s  %s" % (hexs(n_ea), n))

# ====== 7. Decomp the SetAngle impl as a comparison (we know SetAngle works) ======
# done above.

# ====== 8. Walk Player3DLoad / Player::Init3D ======
# Player singleton is qword_1432D2260 (per memory note)
# Look for fn that calls 0x14081C1A0 (SAHMH vt[7])
log("\n--- Functions calling SAHMH vt[7] sub_14081C1A0 ---")
for xr in xrefs_to(0x14081C1A0):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("  call from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# ====== 9. Find the function that REGISTERS SAHMH on an Actor — likely calls vt[7] indirectly via an interface ======
# Look at sub_14081C1A0 carefully — what does it write to? It allocates 0x3D0 bytes
# and assigns to `*a2` which is *passed in*. So this is a "Get-or-create" pattern:
# Caller: SAHMH_GetOrCreate(holder_ptr, &out_graph_ptr);
# After this, graph is at holder+8 (vt[4] returns holder[1] = graph).

# Find SimpleAnimationGraphManagerHolder.Get from the vt[7] caller chain.
# Actually the layout:
#   holder+0  vtable
#   holder+8  graph_ptr (refcounted)
#   holder+16 graph_ptr_other (refcounted)

# ====== 10. Find Actor::Load3D — the REAL one (not the model swap).
# Look for "Actor" RTTI vtable, find its Load3D slot, and decomp.
# Actor TD is well-known; the vtable's Load3D will reference NIF loader sub_1417B3E90.

# Try to find a function that calls BOTH sub_1417B3E90 AND vt[7] of SAHMH
log("\n--- Functions calling both sub_1417B3E90 (NIF loader) and 0x14081C1A0 (SAHMH allocator) ---")
nif_callers = set()
for xr in xrefs_to(0x1417B3E90):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f: nif_callers.add(f.start_ea)
sahmh_callers = set()
for xr in xrefs_to(0x14081C1A0):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f: sahmh_callers.add(f.start_ea)
common = nif_callers & sahmh_callers
log("  NIF callers: %d" % len(nif_callers))
log("  SAHMH allocator callers: %d" % len(sahmh_callers))
log("  Common: %d" % len(common))
for ea in sorted(common):
    log("    %s  %s" % (hexs(ea), name_at(ea)))

# ====== 11. Look for caller chain Actor.Load3D -> ?
#    Find function names like "Actor::"
log("\n--- Names matching Actor:: or Player:: or Load3D ---")
hits = 0
for n_ea, n in idautils.Names():
    if "Load3D" in n or n.startswith("?Load3D"):
        log("  %s  %s" % (hexs(n_ea), n))
        hits += 1
    if hits > 50: break
log("  total Load3D hits: %d" % hits)

# Also look for "Init3D"
hits = 0
for n_ea, n in idautils.Names():
    if "Init3D" in n:
        log("  Init3D: %s  %s" % (hexs(n_ea), n))
        hits += 1
    if hits > 50: break

# Player ctor / player Load3D
hits = 0
for n_ea, n in idautils.Names():
    if "PlayerCharacter" in n and "Load" in n:
        log("  PlayerCharacter+Load: %s  %s" % (hexs(n_ea), n))
        hits += 1
    if hits > 100: break

# ====== 12. Find Actor's Load3D by walking Actor vtable.
# Actor is .?AVActor@@. Find xrefs.
log("\n--- Actor vtable lookup ---")
actor_str_ea = None
for sx in idautils.Strings():
    if str(sx) == ".?AVActor@@":
        actor_str_ea = sx.ea
        break
log("  Actor RTTI string @ %s" % hexs(actor_str_ea or 0))
if actor_str_ea:
    actor_td = actor_str_ea - 0x10
    log("  Actor TD @ %s" % hexs(actor_td))
    for xr in xrefs_to(actor_td):
        if not xr.iscode:
            col_ea = xr.frm - 0xC
            log("    Actor ObjLocator @ %s" % hexs(col_ea))
            for xr2 in xrefs_to(col_ea):
                vt_ea = xr2.frm + 8
                log("      Actor vtable @ %s" % hexs(vt_ea))

# ====== 13. PlayerCharacter vtable — known from memory (RVA 0x2564838) ======
log("\n--- PlayerCharacter vtable @ 0x142564838 (per memory note) ---")
vt = 0x142564838
# Scan first 160 entries (Actor has ~120, derived may add a few)
for i in range(160):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE — likely end)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# ====== 14. Look at the function 0x140CA9980 which references both SpeedSmoothed and TurnDeltaSmoothed strings
# This is likely an Actor::SetupAnimGraph-type function.
log("\n--- sub_140CA9980 (refs SpeedSmoothed + TurnDeltaSmoothed) ---")
decomp(0x140CA9980, "sub_140CA9980 — possibly Actor::SetupAnimVarUpdate")

# ====== 15. Look at sub_141186A33 IsRunning xref ======
decomp(0x1411861C0, "sub_1411861C0 — IsRunning context")

# ====== 16. Decomp sub_1410FC980 — IsRunning's Papyrus binder enclosure ======
# already done in pass 1; skip

# ====== 17. Find ResetAnimationGraph / ResetGraphManager / "InitiateGraph" ======
log("\n--- Names matching ?Animation?Graph or Reset?Graph ---")
hits = 0
for n_ea, n in idautils.Names():
    nl = n.lower()
    if ("graphmanager" in nl or "animationgraph" in nl or "behaviorgraph" in nl or
        "loadbehavior" in nl or "loadanim" in nl or "graphload" in nl or
        "graphattach" in nl or "createanim" in nl):
        log("  %s  %s" % (hexs(n_ea), n))
        hits += 1
    if hits > 100: break

# Append
with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Appended %d lines" % len(out_lines))
import ida_pro
ida_pro.qexit(0)
