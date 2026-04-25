"""
M7.b Pass 5 — final dive into the variable setter and BShkbAnimGraph SetVar
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
log(" PASS 5 — Variable setters + ExtraData ctor + Actor::SetupAnimGraph entry")
log("=" * 78)

# Inner variable setters
for ea, label in [
    (0x14081B010, "engine SetVariableFloat inner sub_14081B010"),
    (0x14081B5A0, "engine SetVariableBool inner sub_14081B5A0"),
    (0x14081AE50, "engine SetVariableInt inner sub_14081AE50"),
]:
    decomp(ea, label)

# Decomp the function that calls sub_14131AB20 to attach behavior
# Earlier we found callers: 1402B4BD0, 140528AB0, 140CA9280, 140D7CFB0, 14131A080
for ea, label in [
    (0x1402B4BD0, "fn calling BShkbAnimGraph ctor — sub_1402B4BD0"),
    (0x140528AB0, "fn calling BShkbAnimGraph ctor — sub_140528AB0"),
    (0x140CA9280, "fn calling BShkbAnimGraph ctor — sub_140CA9280 (likely Actor)"),
    (0x140D7CFB0, "fn calling BShkbAnimGraph ctor — sub_140D7CFB0 (likely Player)"),
    (0x14131A080, "fn calling BShkbAnimGraph ctor — sub_14131A080 (loader)"),
]:
    decomp(ea, label)

# Decomp who calls Actor::SetupAnimVarUpdate sub_140CA9980
for xr in idautils.XrefsTo(0x140CA9980):
    if xr.iscode:
        f = ida_funcs.get_func(xr.frm)
        if f:
            log("Caller of sub_140CA9980: %s @ %s" % (name_at(f.start_ea), hexs(f.start_ea)))
            decomp(f.start_ea, "Caller of sub_140CA9980")

# Decomp PlayerCharacter vt[18..21] — these are likely Setup3D/Init3D variants
# vt[18] = sub_140D656A0
# vt[19] = sub_140D67C50
# vt[20] = sub_140D67DC0
# vt[21] = sub_140D682F0

# Look at xrefs to sub_140D656A0 too — it's called by something during 3D load
log("\n--- Callers of PlayerCharacter vt[18] sub_140D656A0 ---")
for xr in idautils.XrefsTo(0x140D656A0):
    log("  xref from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))

log("\n--- Callers of PlayerCharacter vt[19] sub_140D67C50 ---")
for xr in idautils.XrefsTo(0x140D67C50):
    log("  xref from %s (iscode=%d)" % (hexs(xr.frm), xr.iscode))

# Decomp the engine variable setter further to confirm signature
# sub_14081B010 takes (a1, a2, &val) — what's a1?
# a1 is "a3 + 72" from native, where a3 is the Actor; so a1 IS the IAnimationGraphManagerHolder
# at offset 72 inside Actor.

# Look for the actual graph-side SetVariableFloat
# BShkbAnimGraph likely has a SetVariableFloat method exposed from havok hkbBehaviorGraph.

# Find xrefs to BShkbAnimationGraph vtable 0x142626B38 — the ctor
log("\n--- ALL xrefs to BShkbAnimationGraph vtable 0x142626B38 (ctor) ---")
for xr in idautils.XrefsTo(0x142626B38):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))

# Decomp the graph SetVariableFloat (likely in BShkbAnimGraph or hkbBehaviorGraph vtable)
log("\n--- BShkbAnimationGraph vtable @ 0x142626B38 (more entries) ---")
vt = 0x142626B38
for i in range(60):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# Check ExtraDataList add — looking for AddExtra fn (could attach EAGM ExtraData to BSFadeNode)
log("\n--- Names: ExtraData / AddExtra / ExtraList ---")
for n_ea, n in idautils.Names():
    if "ExtraData" in n or "ExtraList" in n or "AddExtra" in n:
        log("  %s  %s" % (hexs(n_ea), n))
        # too verbose, limit
        if len(out_lines) > 600:
            break

# Decomp ExtraAnimGraphManager dtor (vt[0]) to understand layout
ext_anim_vt0 = ida_bytes.get_qword(0x142469578)
if ext_anim_vt0:
    decomp(ext_anim_vt0, "ExtraAnimGraphManager vt[0] dtor")

# Decomp the rest of the EAGM vtable
log("\n--- ExtraAnimGraphManager full vtable ---")
vt = 0x142469578
for i in range(20):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))
    decomp(v, "EAGM vt[%d]" % i)

# Find ExtraAnimGraphManager ctor (xrefs to its vtable)
log("\n--- xrefs to EAGM vtable 0x142469578 (find ctor) ---")
for xr in idautils.XrefsTo(0x142469578):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))
        decomp(f.start_ea, "EAGM ctor candidate")

# Find Actor's vt[?] that is Load3D
# Actor vtable likely at 0x142EE4288 or 0x142EED248
# Let me dump 0x142EE4288 partially
log("\n--- Possible Actor vtable @ 0x142EE4288 (first 30 entries) ---")
vt = 0x142EE4288
for i in range(40):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# Check the alt Actor vtable too
log("\n--- Possible Actor vtable @ 0x143EDEE0C (first 30 entries) ---")
vt = 0x143EDEE0C
for i in range(40):
    v = ida_bytes.get_qword(vt + i*8)
    if not v: break
    seg = idaapi.getseg(v)
    if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
        log("  vt[%d] = %s (NOT-CODE)" % (i, hexs(v)))
        break
    log("  vt[%d] = %s (%s)" % (i, hexs(v), name_at(v)))

# Compare PlayerCharacter[18] = sub_140D656A0 against TESObjectREFR[18] (which would be plain Load3D).
# Actually the compare with Player (which inherits Actor): PlayerCharacter vt[18] = 0x140D656A0
# If Actor::Load3D is at slot 18, then Actor vtable[18] would also be a "Load3D" variant.

# Final: SetAnimGraphVar console binding
log("\n--- Walk console-cmd table at 0x142EF4400..0x142EF4500 ---")
for off in range(0, 0x100, 8):
    ea = 0x142EF4400 + off
    v = ida_bytes.get_qword(ea)
    if 0x140000000 < v < 0x150000000:
        if ida_funcs.get_func(v):
            log("  +%X (%s) → fn %s (%s)" % (off, hexs(ea), hexs(v), name_at(v)))
        else:
            try:
                s = idc.get_strlit_contents(v, -1, 0)
                if s:
                    log("  +%X (%s) → str %s = %r" % (off, hexs(ea), hexs(v), s[:40]))
            except: pass

# Also search 0x142EF4470 and around
log("\n--- Console cmd table around 0x142EF4470 ---")
for off in range(-0x80, 0x100, 8):
    ea = 0x142EF4470 + off
    v = ida_bytes.get_qword(ea)
    if 0x140000000 < v < 0x150000000:
        if ida_funcs.get_func(v):
            log("  +%+04X (%s) → fn %s (%s)" % (off, hexs(ea), hexs(v), name_at(v)))
        else:
            try:
                s = idc.get_strlit_contents(v, -1, 0)
                if s:
                    log("  +%+04X (%s) → str %s = %r" % (off, hexs(ea), hexs(v), s[:40]))
            except: pass

# SetAnimGraphVar console handler
# the string xref @ 0x142EF4470 likely is one of (name, alias, help, args, fn).
# Walk forward 5x8 = 40 bytes to find the function pointer in the same record.
log("\n--- Disasm around 0x142EF4470 ---")
ea = 0x142EF4400
for off in range(0, 0x100, 8):
    addr = ea + off
    v = ida_bytes.get_qword(addr)
    if 0x140000000 <= v < 0x150000000:
        try:
            s = idc.get_strlit_contents(v, -1, 0)
            sn = repr(s.decode('latin-1', 'replace'))[:60] if s else "?"
        except: sn = "?"
        fn = name_at(v) if ida_funcs.get_func(v) else ""
        log("  +%X = %s (str=%s%s)" % (off, hexs(v), sn, " fn=" + fn if fn else ""))
    else:
        log("  +%X = %s" % (off, hexs(v)))

with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Appended %d lines" % len(out_lines))
import ida_pro
ida_pro.qexit(0)
