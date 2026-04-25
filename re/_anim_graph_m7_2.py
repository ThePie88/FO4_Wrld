"""
M7.b Pass 2 — drill into specific functions identified in pass 1.

Pass 1 results:
  - SimpleAnimationGraphManagerHolder vtable @ 0x142518C10
  - vt[0] = 0x14081C350 (likely dtor — typical MSVC layout)
  - IAnimationGraphManagerHolder vtable @ 0x142518A50 (interface dispatch)
  - SetAnimationVariableFloat string xref @ 0x141164E37 — register Papyrus native
  - Actor::Load3D-like @ 0x140458740 — analyzed
  - REFR::Load3D @ 0x14033D1E0 — analyzed
  - FirstPersonBase.hkx @ 0x142518170 — only one .hkx string

Now drill:
  1. The function at 0x141164E37 (Papyrus binder for SetAnimationVariableFloat)
  2. The native impl behind it (next instruction's lea rcx target)
  3. SimpleAnimationGraphManagerHolder vt[0..40] full dump (interface = 5 slots, then derived)
  4. ALL members called via vt[?] from inside Papyrus natives (find SetAnimationVariableFloat path)
  5. Functions that REFERENCE the SimpleAnimationGraphManagerHolder vtable 0x142518C10 (find ctor)
  6. The function around 0x142F1ED90 ('FirstPersonBase.hkx' xref in data — likely a string table for behaviors)
  7. Search for "BSAnimationGraphManager" or "BSBehavior" type strings — third-party reference
  8. xrefs to BSFadeNode-related slots at +0x140 (animation hooks?)
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment

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

def xrefs_from(ea):
    try: return list(idautils.XrefsFrom(ea))
    except: return []

def dump_vtable(vt_ea, label, n=40):
    log("\n--- vtable %s @ %s ---" % (label, hexs(vt_ea)))
    for i in range(n):
        v = ida_bytes.get_qword(vt_ea + i*8)
        if v == 0:
            break
        # If outside .text segment, stop
        seg = idaapi.getseg(v)
        if not seg or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
            log("  vt[%d] = %s (NOT-CODE — likely end of vtable)" % (i, hexs(v)))
            break
        fn = name_at(v) if ida_funcs.get_func(v) else "?"
        log("  vt[%d] = %s (%s)" % (i, hexs(v), fn))

log("")
log("=" * 78)
log(" PASS 2 — DEEP DRILL")
log("=" * 78)

# ======================================
# 1. SimpleAnimationGraphManagerHolder full vtable
# ======================================
log("\n=== SECTION P2.A — SimpleAnimationGraphManagerHolder vtable @ 0x142518C10 ===")
dump_vtable(0x142518C10, "SimpleAnimationGraphManagerHolder", 40)

log("\n=== SECTION P2.B — IAnimationGraphManagerHolder vtable @ 0x142518A50 ===")
dump_vtable(0x142518A50, "IAnimationGraphManagerHolder", 40)

# ======================================
# 2. Decomp the vtable methods that look meaningful (vt[1..15])
# ======================================
log("\n=== SECTION P2.C — Decomp SAHMH vt methods ===")
sahmh_vt = 0x142518C10
for i in range(20):
    fn_ea = ida_bytes.get_qword(sahmh_vt + i*8)
    if not fn_ea or not ida_funcs.get_func(fn_ea):
        continue
    decomp(fn_ea, "SAHMH vt[%d]" % i)

# ======================================
# 3. IAnimationGraphManagerHolder interface methods (likely include Set/GetVariable...)
# ======================================
log("\n=== SECTION P2.D — Decomp IAGMH vt methods (interface) ===")
iagmh_vt = 0x142518A50
for i in range(20):
    fn_ea = ida_bytes.get_qword(iagmh_vt + i*8)
    if not fn_ea or not ida_funcs.get_func(fn_ea):
        continue
    decomp(fn_ea, "IAGMH vt[%d]" % i)

# ======================================
# 4. Walk near 0x141164E37 — SetAnimationVariableFloat string xref. Find the native it's bound to.
# ======================================
log("\n=== SECTION P2.E — SetAnimationVariableFloat Papyrus native registration ===")
# Decomp surrounding fn
f = ida_funcs.get_func(0x141164E37)
if f:
    log("Enclosing fn: %s @ %s..%s" % (name_at(f.start_ea), hexs(f.start_ea), hexs(f.end_ea)))
    decomp(f.start_ea, "Papyrus SetAnimationVariableFloat binder")

# Walk a few instructions around the xref to find lea rcx, native_fn
log("\nDisassembly around xref 0x141164E37:")
ea = 0x141164E10
while ea < 0x141164EE0:
    mnem = idc.print_insn_mnem(ea)
    op0 = idc.print_operand(ea, 0)
    op1 = idc.print_operand(ea, 1)
    sz = idc.get_item_size(ea)
    if sz <= 0: sz = 1
    log("  %s: %s %s, %s" % (hexs(ea), mnem, op0, op1))
    ea += sz

# ======================================
# 5. Search for ALL "Papyrus *AnimationVariable*" string xrefs and decompile binders
# ======================================
log("\n=== SECTION P2.F — All AnimVar Papyrus binders ===")
for s in ["SetAnimationVariableFloat", "SetAnimationVariableBool", "SetAnimationVariableInt",
          "GetAnimationVariableFloat", "GetAnimationVariableBool", "GetAnimationVariableInt"]:
    # Find string addr
    str_eas = []
    try:
        for sx in idautils.Strings():
            if str(sx) == s:
                str_eas.append(sx.ea)
    except: pass
    log("\n--- %s ---" % s)
    for str_ea in str_eas:
        log("  string @ %s" % hexs(str_ea))
        for xr in xrefs_to(str_ea):
            f = ida_funcs.get_func(xr.frm)
            log("    xref %s in %s" % (hexs(xr.frm),
                                       name_at(f.start_ea) if f else "?"))
            # Walk forward up to 5 instructions and look for a `lea rcx, sub_xxx` (the native fn)
            cur = xr.frm
            for step in range(8):
                nxt = idc.next_head(cur)
                if nxt == idaapi.BADADDR: break
                cur = nxt
                mnem = idc.print_insn_mnem(cur)
                op0 = idc.print_operand(cur, 0)
                if mnem == "lea":
                    target = idc.get_operand_value(cur, 1)
                    if target and ida_funcs.get_func(target):
                        log("      forward lea -> %s (%s) at %s (op0 %s)" %
                            (hexs(target), name_at(target), hexs(cur), op0))
            # Walk BACKWARD up to 8 instructions
            cur = xr.frm
            for step in range(8):
                prv = idc.prev_head(cur)
                if prv == idaapi.BADADDR: break
                cur = prv
                mnem = idc.print_insn_mnem(cur)
                op0 = idc.print_operand(cur, 0)
                if mnem == "lea":
                    target = idc.get_operand_value(cur, 1)
                    if target and ida_funcs.get_func(target):
                        log("      backward lea -> %s (%s) at %s (op0 %s)" %
                            (hexs(target), name_at(target), hexs(cur), op0))

# ======================================
# 6. Find xrefs to SAHMH vtable 0x142518C10 — these include the ctor
# ======================================
log("\n=== SECTION P2.G — SAHMH vtable xrefs (find ctor) ===")
for xr in xrefs_to(0x142518C10):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s @ %s" %
            (hexs(xr.frm), name_at(f.start_ea), hexs(f.start_ea)))
        decomp(f.start_ea, "Possible SAHMH ctor/dtor caller @ 0x%X" % f.start_ea)

# Also IAGMH vtable 0x142518A50 (probably an interface; less likely a real ctor)
log("\n=== SECTION P2.H — IAGMH vtable xrefs ===")
for xr in xrefs_to(0x142518A50):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  xref from %s in %s @ %s" %
            (hexs(xr.frm), name_at(f.start_ea), hexs(f.start_ea)))

# ======================================
# 7. ExtraAnimGraphManager ExtraData class — vtable + ctor
# ======================================
log("\n=== SECTION P2.I — ExtraAnimGraphManager ExtraData class ===")
# RTTI string at 0x142F96698; TD at 0x142F96688
for n_ea, n in idautils.Names():
    if "ExtraAnimGraph" in n:
        log("  %s  %s" % (hexs(n_ea), n))

# Try to find ExtraAnimGraphManager vtable
for xr in xrefs_to(0x142F96688):  # TypeDescriptor
    if not xr.iscode:
        col_ea = xr.frm - 0xC
        log("  EAGM ObjLocator @ %s" % hexs(col_ea))
        for xr2 in xrefs_to(col_ea):
            vt_ea = xr2.frm + 8
            log("    EAGM vtable @ %s" % hexs(vt_ea))
            dump_vtable(vt_ea, "ExtraAnimGraphManager", 30)

# ======================================
# 8. Look at sub_14081BC00 and sub_14081BC40 (xrefs to SAHMH vtable from pass 1)
# ======================================
log("\n=== SECTION P2.J — Functions referencing SAHMH vtable ===")
for ea in [0x14081BC00, 0x14081BC40, 0x14081C350]:
    decomp(ea, "fn_%X" % ea)

# ======================================
# 9. Look near 0x141164E10 (where SetAnimationVariableFloat string is referenced) for the native binder.
#    The Papyrus native registration pattern in Bethesda games is typically:
#       lea rcx, "FuncName"     ; name
#       lea r8,  fn_implementation
#       call BindNative
#    or as a table entry:
#       qword "FuncName"
#       qword fn_implementation
#       qword fn_other_metadata
# ======================================
log("\n=== SECTION P2.K — Decomp the function 0x141164E10 region (Papyrus binder) ===")
# Find enclosing function
fn = ida_funcs.get_func(0x141164E37)
if fn:
    decomp(fn.start_ea, "Native binder around SetAnimationVariableFloat")

# ======================================
# 10. Search the .rdata for "Papyrus SetAnimationVariableFloat" — that's the diagnostic string
# ======================================
log("\n=== SECTION P2.L — 'Papyrus SetAnimationVariable*' diagnostic strings ===")
for s in ["Papyrus SetAnimationVariableFloat", "Papyrus SetAnimationVariableBool",
          "Papyrus GetAnimationVariableFloat", "Papyrus GetAnimationVariableBool",
          "Papyrus SetAnimGraphVar"]:
    try:
        for sx in idautils.Strings():
            if str(sx) == s:
                log("  %r @ %s" % (s, hexs(sx.ea)))
                for xr in xrefs_to(sx.ea):
                    log("    xref %s" % hexs(xr.frm))
    except Exception as e:
        log("  err: %s" % e)

# ======================================
# 11. SetAnimGraphVar console command — decomp the binding
# ======================================
log("\n=== SECTION P2.M — SetAnimGraphVar console binding @ 0x142EF4470 (data) ===")
# That xref @ 0x142EF4470 is in data — likely a console command table entry.
# Console command tables in Bethesda games:
#   { "commandName", "alias", "help", N_args, fn_pointer, ... }
# Dump 0x142EF4460..0x142EF44A0
log("Dumping console-cmd table region 0x142EF4460..0x142EF44C0:")
for off in range(0, 0x60, 8):
    ea = 0x142EF4460 + off
    v = ida_bytes.get_qword(ea)
    log("  +%02X = %s @ %s" % (off, hexs(v), hexs(ea)))
    # If it points to an ANSI string nearby (0x142...), print first 32 chars
    if 0x140000000 < v < 0x150000000:
        try:
            s = idc.get_strlit_contents(v, -1, 0)
            if s: log("    string: %r" % s[:60])
        except: pass
    # If it points to a function, print fn name
    if ida_funcs.get_func(v):
        log("    fn: %s" % name_at(v))

# Also walk a wider region to find the function pointer
log("\nWider scan 0x142EF4400..0x142EF4500:")
for off in range(0, 0x100, 8):
    ea = 0x142EF4400 + off
    v = ida_bytes.get_qword(ea)
    if 0x140000000 < v < 0x150000000 and ida_funcs.get_func(v):
        log("  +%X (%s) → fn %s (%s)" % (off, hexs(ea), hexs(v), name_at(v)))

# ======================================
# 12. Check sub_14006CCC0 (xref AimPitchCurrent) — likely the place where engine
# READS the var name in anim graph (channel registration)
# ======================================
log("\n=== SECTION P2.N — Anim var registration callsites ===")
for ea in [0x14006CCC0, 0x14006CCF0, 0x14006CD20,
           0x14006D500, 0x14006D530,
           0x14006E880, 0x14006E8B0,
           0x14006EC10, 0x14006EC40,
           0x140CA9980,  # the SpeedSmoothed/TurnDeltaSmoothed callsite
           ]:
    decomp(ea, "anim var setup fn @ 0x%X" % ea)

# ======================================
# 13. Find fn that loads behavior .hkx for the animation graph manager
# ======================================
log("\n=== SECTION P2.O — Behavior loading path ===")
# Find xrefs to 0x142F1ED90 (where FirstPersonBase.hkx is referenced from data)
log("Function near data ref 0x142F1ED90:")
log("Disassembly 0x142F1ED80..0x142F1EDA0:")
for off in range(0, 0x20, 8):
    ea = 0x142F1ED80 + off
    v = ida_bytes.get_qword(ea)
    log("  +%X (%s) = %s" % (off, hexs(ea), hexs(v)))
# Find xrefs to that data location
for xr in xrefs_to(0x142F1ED90):
    f = ida_funcs.get_func(xr.frm)
    if f:
        log("  data xref from %s in %s" % (hexs(xr.frm), name_at(f.start_ea)))
        decomp(f.start_ea, "fn referencing 'FirstPersonBase.hkx' table entry")

# Look for "BSAnimation" and "BSBehavior" classes
log("\nSearching for BSAnimation/BSBehavior class names:")
for n_ea, n in idautils.Names():
    if "BSAnimationGraph" in n or "BSBehavior" in n:
        log("  %s  %s" % (hexs(n_ea), n))

# ======================================
# 14. Find LoadAnimationGraph or AttachAnimationGraph fn
# ======================================
log("\n=== SECTION P2.P — Look for animation graph attach/load fns ===")
# Search names for keywords
for n_ea, n in idautils.Names():
    nl = n.lower()
    if ("animationgraph" in nl or "anim_graph" in nl or "behaviorgraph" in nl
        or "animgraph" in nl or "bgsanim" in nl or "loadanim" in nl):
        log("  %s  %s" % (hexs(n_ea), n))

# ======================================
# 15. AnimGraphPreload — likely loads the .hkx
# ======================================
log("\n=== SECTION P2.Q — ExtraAnimGraphPreload analysis ===")
# RTTI string at 0x142F975D8; TD at 0x142F975C8
for xr in xrefs_to(0x142F975C8):
    if not xr.iscode:
        col_ea = xr.frm - 0xC
        log("  EAGP ObjLocator @ %s" % hexs(col_ea))
        for xr2 in xrefs_to(col_ea):
            vt_ea = xr2.frm + 8
            log("    EAGP vtable @ %s" % hexs(vt_ea))
            dump_vtable(vt_ea, "ExtraAnimGraphPreload", 30)

log("\n=== END PASS 2 ===")

# Append to existing log file
with open(LOG_PATH, "a", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Appended %d lines" % len(out_lines))
import ida_pro
ida_pro.qexit(0)
