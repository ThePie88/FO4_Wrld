"""
M8P3 phase 4 — REVISED HYPOTHESIS.

Phase 3 revealed that qword_1430DBD58 is NOT a scene singleton but the
PlayerControls/PlayerInputManager singleton (its ctor creates BSTEventSinks
for OtherEventEnabledEvent, UserEventEnabledEvent, IdleInputEvent).

So sub_141026640/sub_141026980 register loaded3D for INPUT-DISPATCH, not for
rendering. The actual skin-update registration must be elsewhere.

Real candidates for skin-update / scene-graph registration:
  1. ShadowSceneNode attachment side-effect — qword_143E47A10
  2. sub_140787980(qword_1430DD9F0, a1)  — confirmed in REFR::Load3D
     qword_1430DD9F0 is a DIFFERENT scene singleton — investigate!
  3. sub_1406EF810 (cell-graph notify)
  4. sub_140528410 (post-attach housekeeping — sets flag bits)
  5. The vtable call at  vftable+0x478 (1144) — REFR::Load3D dispatches a
     virtual that we haven't decompiled yet.

This phase:
  - Identify qword_1430DD9F0 (the scene singleton in REFR::Load3D)
  - Find functions that call BSGeometry-update / BSAnimationUpdate
  - Investigate the BSAnimationGraphManager singleton — its ctor / global
    storage
  - Find the per-frame skin walker by string "BSSkinPart" / "SkinningManager"
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_scene_register4_raw.log"
out_lines = []
BASE = 0x140000000

def log(s=""): out_lines.append(s if isinstance(s, str) else str(s))
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
def disasm_lines(start_ea, max_lines=200):
    f = ida_funcs.get_func(start_ea)
    if not f: return ["<no func>"]
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

log("=" * 78)
log(" M8P3 phase 4 — REVISED HYPOTHESIS")
log(" Hypothesis: qword_1430DBD58 = PlayerControls singleton (NOT scene).")
log(" Real registration target: qword_1430DD9F0 / qword_143E47A10 / vt-call.")
log("=" * 78)

# =========================================================================
# Section A — qword_1430DD9F0 (called from REFR::Load3D site 0x140787980)
# =========================================================================
log("")
log("=" * 78)
log(" SECTION A — qword_1430DD9F0 (the OTHER scene singleton)")
log("=" * 78)
ea = 0x1430DD9F0
seg = ida_segment.getseg(ea)
log(" segment: %s   addr %s" %
    (ida_segment.get_segm_name(seg) if seg else "?", hexs(ea)))
log(" static value: %s" % hexs(ida_bytes.get_qword(ea)))
log("")
log(" --- xrefs to qword_1430DD9F0 ---")
x = ida_xref.get_first_dref_to(ea)
all_xrefs = []
while x != idaapi.BADADDR:
    all_xrefs.append(x)
    x = ida_xref.get_next_dref_to(ea, x)
log(" total: %d" % len(all_xrefs))

write_sites = []
for xea in all_xrefs:
    line = (idc.generate_disasm_line(xea, 0) or "").strip()
    comma = line.find(",")
    if comma > 0 and "qword_1430DD9F0" in line[:comma] and "lea" not in line.lower() and "mov" in line.lower():
        write_sites.append((xea, line))

log(" WRITE sites: %d" % len(write_sites))
for ea2, line in write_sites[:10]:
    f = ida_funcs.get_func(ea2)
    fn = name_at(f.start_ea) if f else "?"
    log("   %s in %s   %s" % (hexs(ea2), fn, line))

# Backtrace each write
for ea2, line in write_sites[:5]:
    log("")
    log(" --- back-trace 30 instr around WRITE site %s ---" % hexs(ea2))
    cur = ea2
    for _ in range(30):
        cur = idc.prev_head(cur)
        if cur == idc.BADADDR: break
    for _ in range(35):
        line2 = idc.generate_disasm_line(cur, 0) or ""
        log("    %s: %s" % (hexs(cur), line2))
        nxt = idc.next_head(cur)
        if nxt <= cur or nxt > ea2 + 16: break
        cur = nxt

# =========================================================================
# Section B — qword_143E47A10 (ShadowSceneNode singleton per memory)
# =========================================================================
log("")
log("=" * 78)
log(" SECTION B — qword_143E47A10 (ShadowSceneNode singleton)")
log("=" * 78)
ea = 0x143E47A10
seg = ida_segment.getseg(ea)
log(" segment: %s   addr %s" %
    (ida_segment.get_segm_name(seg) if seg else "?", hexs(ea)))
log(" static value: %s" % hexs(ida_bytes.get_qword(ea)))
log("")
log(" --- xrefs ---")
x = ida_xref.get_first_dref_to(ea)
ssn_xrefs = []
while x != idaapi.BADADDR:
    ssn_xrefs.append(x)
    x = ida_xref.get_next_dref_to(ea, x)
log(" total: %d" % len(ssn_xrefs))

write_sites = []
for xea in ssn_xrefs:
    line = (idc.generate_disasm_line(xea, 0) or "").strip()
    comma = line.find(",")
    if comma > 0 and "qword_143E47A10" in line[:comma] and "lea" not in line.lower() and "mov" in line.lower():
        write_sites.append((xea, line))
log(" WRITE sites: %d" % len(write_sites))
for ea2, line in write_sites[:10]:
    f = ida_funcs.get_func(ea2)
    fn = name_at(f.start_ea) if f else "?"
    log("   %s in %s   %s" % (hexs(ea2), fn, line))

# Sample callers reading SSN
log("")
log(" --- read sites (first 30) ---")
n = 0
for xea in ssn_xrefs:
    line = (idc.generate_disasm_line(xea, 0) or "").strip()
    if "qword_143E47A10" in line and "mov" in line.lower():
        # Filter writes
        comma = line.find(",")
        is_write = comma > 0 and "qword_143E47A10" in line[:comma]
        if not is_write:
            f = ida_funcs.get_func(xea)
            fn = name_at(f.start_ea) if f else "?"
            log("   %s in %s   %s" % (hexs(xea), fn, line))
            n += 1
            if n >= 30: break

# =========================================================================
# Section C — Find skin-update / animation walker by string anchor
# Look for any RTTI string like 'BSAnimationGraphManager', 'SkinningManager',
# 'BSSkin' etc., follow the xrefs to find the singleton, then who reads it
# every frame.
# =========================================================================
log("")
log("=" * 78)
log(" SECTION C — anim/skin manager singleton hunting")
log("=" * 78)

ANIM_STRINGS = [
    "BSAnimationGraphManager",
    "BSAnimationGraph",
    "BSAnimationManager",
    "SkinningManager",
    "BSSkinManager",
    "BSGeometryDB",
    "BShkbAnimationGraph",
    "BSAnimationGraphChannel",
    "ProcessLists",
]

# Build string cache
STRINGS = {}
try:
    for sx in idautils.Strings():
        try:
            s = str(sx)
            STRINGS.setdefault(s, []).append(sx.ea)
        except: pass
except Exception as e:
    log("string cache err: %s" % e)

for ks in ANIM_STRINGS:
    log("")
    log(" --- %r ---" % ks)
    found = []
    for k, eas in STRINGS.items():
        if ks in k:
            found.append((k, eas))
    found = found[:3]
    for k, eas in found:
        log("    %r at %s" % (k, ", ".join(hexs(e) for e in eas)))

# =========================================================================
# Section D — Investigate the virtual call at REFR::Load3D
# It dispatches via vt+0x478 (=1144) and vt+0x4C8 (=1224). Decompile the
# REFR vtable slots at those offsets.
# =========================================================================
log("")
log("=" * 78)
log(" SECTION D — REFR vtable slots near the post-attach virtuals")
log("=" * 78)
# REFR vtable per memory: 0x14249CBC8
REFR_VT = 0x14249CBC8

# Slot index = byte offset / 8.
# vt+0x478 = slot 143
# vt+0x4C8 = slot 153 (1224/8=153)
# vt+0x510 = slot 162 (1296/8=162) — also called from sub_140528410
for slot_off in (0x478, 0x4C8, 0x510):
    slot_ea = REFR_VT + slot_off
    val = ida_bytes.get_qword(slot_ea)
    log("   REFR vt+%X (slot %d) -> %s   name=%s" %
        (slot_off, slot_off // 8, hexs(val), name_at(val)))
    sz = fn_size(val)
    log("       size=%s" % (hexs(sz) if sz else "?"))
    # Decompile briefly
    txt = safe_decomp(val)
    if txt:
        for line in txt.splitlines()[:60]:
            log("       " + line)
    log("")

# =========================================================================
# Section E — sub_140528410 deep-dive: it sets +0x10000000000 flag and
# calls vt+0x478 (1144LL) which we just identified above. Confirm what
# bit-flags and what subsystem.
# Also: it calls sub_140311540(a1, 0x10000000) — what is that?
# =========================================================================
log("")
log("=" * 78)
log(" SECTION E — sub_140311540  (called from sub_140528410 with 0x10000000)")
log("=" * 78)
target = BASE + 0x311540
sz = fn_size(target)
log(" sub_140311540 RVA 0x311540  size=%s" % (hexs(sz) if sz else "?"))
txt = safe_decomp(target)
if txt:
    for line in txt.splitlines()[:60]:
        log("    " + line)

# =========================================================================
# Section F — Look at sub_140C595F0 (the BIP* sibling cleanup) just to
# confirm it's not the registration site
# =========================================================================
log("")
log("=" * 78)
log(" SECTION F — sub_140C595F0 (BIP sibling cleanup)")
log("=" * 78)
target = BASE + 0xC595F0
sz = fn_size(target)
log(" sub_140C595F0 RVA 0xC595F0  size=%s" % (hexs(sz) if sz else "?"))
txt = safe_decomp(target)
if txt:
    for line in txt.splitlines()[:80]:
        log("    " + line)

# =========================================================================
# Section G — search for "BSAnimationGraphManager" usage  (this is what
# binds anim updates — therefore SKIN updates)
# =========================================================================
log("")
log("=" * 78)
log(" SECTION G — BSAnimationGraphManager — bind / register sites")
log("=" * 78)

# Find xrefs to RTTI string ".?AVBSAnimationGraphManager@@" then find vtable
rtti = ".?AVBSAnimationGraphManager@@"
hits = STRINGS.get(rtti, [])
log(" RTTI '.?AVBSAnimationGraphManager@@' at: %s" % ", ".join(hexs(h) for h in hits))
# Type Descriptor is at strea-0x10
for s_ea in hits:
    td_ea = s_ea - 0x10
    log("    TD %s" % hexs(td_ea))
    # COL refs the TD at +0xC
    for xr in idautils.XrefsTo(td_ea):
        col_ea = xr.frm - 0xC
        for xr2 in idautils.XrefsTo(col_ea):
            vt = xr2.frm + 8
            log("       possible vtable %s" % hexs(vt))
            # First 4 vtable slots
            for i in range(8):
                vea = ida_bytes.get_qword(vt + 8*i)
                if vea:
                    log("           vt[%d] -> %s   %s" %
                        (i, hexs(vea), name_at(vea)))

log("")
log("=" * 78)
log(" END")
log("=" * 78)
with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))
print("Wrote %s (%d lines)" % (LOG, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
