"""
M8P3 Phase 2 — drill into the most important sub-functions identified by phase 1:

  sub_141020D60   (called by sub_141026640 — the SCENE REGISTER worker itself)
  sub_140BB1B80   (called by sub_14102D4C0 — handle resolver?)
  sub_1417A0A30   (called by sub_14102D4C0 — passes 'unk_1430E1910')
  sub_141027E40   (writes to slot+0x130; xref hit in phase 1)
  sub_14102C820   (writes to slot+0x130; xref hit)

Also: identify the type of `a1` parameter (struct holding the 6 slots) by
finding callers of sub_141026640. Phase 1 found ONE caller: sub_140D5B250
(PlayerCharacter::Load3D). So `a1` traces back to PC::Load3D context.

Decompile the chain:
   PC::Load3D -> sub_141026640(actor, loaded3D, ?) at site 0x140D5B476
   PC::Load3D -> sub_141026980(?, ?) at site 0x140D5B679

We need the EXACT call sites with arg types.

Also: dump unk_1430E1910 — likely a string literal or an RTTI key.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_scene_register2_raw.log"
out_lines = []
BASE = 0x140000000

DRILL = [
    ("sub_141020D60", 0x1020D60, "core SCENE REGISTER worker — called from sub_141026640"),
    ("sub_140BB1B80", 0xBB1B80,  "called by sub_14102D4C0; uses qword_1432D2260 (PC singleton)"),
    ("sub_1417A0A30", 0x17A0A30, "called by sub_14102D4C0; takes unk_1430E1910"),
    ("sub_141027E40", 0x1027E40, "writes to slot+0x130 (xref-hit)"),
    ("sub_14102C820", 0x102C820, "writes to slot+0x130 (xref-hit)"),
    # Also re-decomp the call sites in PC::Load3D (the one that matters)
    ("sub_140D5B250", 0xD5B250,  "PC::Load3D — wrapping context for sub_141026640 / sub_141026980"),
]

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
log(" M8P3 phase2 — drill into SCENE REGISTER sub-functions")
log("=" * 78)

# ============================================================================
# Section A — Decompile each drill target
# ============================================================================
for nm, r, anno in DRILL:
    abs_ea = BASE + r
    sz = fn_size(abs_ea)
    log("")
    log("-" * 78)
    log(" %s @ %s (RVA %s)  size=%s  -- %s" %
        (nm, hexs(abs_ea), hexs(r), hexs(sz) if sz else "?", anno))
    log("-" * 78)
    txt = safe_decomp(abs_ea)
    if txt:
        for line in txt.splitlines():
            log("   " + line)
    else:
        log("  <decomp failed>")

# ============================================================================
# Section B — Inspect unk_1430E1910 (used by sub_1417A0A30 in candidate)
# ============================================================================
log("")
log("=" * 78)
log(" SECTION B — what is unk_1430E1910 ?")
log("=" * 78)
ea = 0x1430E1910
seg = ida_segment.getseg(ea)
log("  segment: %s   addr %s" %
    (ida_segment.get_segm_name(seg) if seg else "?", hexs(ea)))
log("  bytes:")
for i in range(0, 0x40, 8):
    q = ida_bytes.get_qword(ea + i)
    log("    +%X  : %s   (%s)" % (i, hexs(q), name_at(q) if q else "?"))
# string content?
for off in (0, 8, 16, 24):
    s = idc.get_strlit_contents(ea + off, -1, 0)
    if s:
        try: s = s.decode("utf-8", "replace")
        except: pass
        log("    str@+%X : %r" % (off, s))

# Also look for this address in xrefs (data refs — who else uses it)
log("")
log("  --- code refs to unk_1430E1910 ---")
x = ida_xref.get_first_dref_to(ea)
while x != idaapi.BADADDR:
    f = ida_funcs.get_func(x)
    fn = name_at(f.start_ea) if f else "?"
    line = idc.generate_disasm_line(x, 0) or ""
    log("    %s  in %s   %s" % (hexs(x), fn, line))
    x = ida_xref.get_next_dref_to(ea, x)

# ============================================================================
# Section C — Slot-write hits — investigate full context of each writer
# ============================================================================
log("")
log("=" * 78)
log(" SECTION C — writers to qword_1430DBD58+slot (the registration sites)")
log("=" * 78)

# The phase1 hits we want to expand:
#   anchor 0x140D5A20B  ea 0x140D5A212  slot+140   in sub_140D5A150
#   anchor 0x140C36E0D  ea 0x140C36E1D  slot+128   in sub_140C36A10
#   anchor 0x140C3EBC0  ea 0x140C3EBD0  slot+128   in sub_140C3EAD0
#   anchor 0x140D736CA  ea 0x140D736EB  slot+140   in sub_140D73620
#   anchor 0x141027F20  ea 0x141027F35  slot+130   in sub_141027E40
#   anchor 0x14102D1EE  ea 0x14102D202  slot+130   in sub_14102C820
EXPAND_FNS = [
    ("sub_140D5A150", 0xD5A150, "reads/writes slot+140 with qword_1430DBD58 base"),
    ("sub_140C36A10", 0xC36A10, "reads/writes slot+128"),
    ("sub_140C3EAD0", 0xC3EAD0, "reads/writes slot+128"),
    ("sub_140D73620", 0xD73620, "reads/writes slot+140"),
    ("sub_14102C820", 0x102C820, "writes slot+130"),
]

for nm, r, anno in EXPAND_FNS:
    abs_ea = BASE + r
    sz = fn_size(abs_ea)
    log("")
    log("-" * 78)
    log(" %s @ %s (RVA %s)  size=%s  -- %s" %
        (nm, hexs(abs_ea), hexs(r), hexs(sz) if sz else "?", anno))
    log("-" * 78)
    txt = safe_decomp(abs_ea)
    if txt:
        # Limit: first 80 lines of decomp
        lines = txt.splitlines()
        for line in lines[:80]:
            log("   " + line)
        if len(lines) > 80:
            log("   ... truncated (%d more lines) ..." % (len(lines) - 80))
    else:
        log("  <decomp failed>")

# ============================================================================
# Section D — type of `a1` in sub_141026640 / sub_141026980
#
# In sub_141026640, a1 is dereferenced at +224 (=0xE0) and +256 (=0x100).
# In sub_141026980, a1 is the same kind of struct, but accessed at
# +0x118..+0x140. So a1 is a struct of size ~0x148. NOT qword_1430DBD58.
# Likely it's the "Cell" or the "BSPortalGraphEntry" the Actor lives in.
#
# Decompile the call site in PC::Load3D to extract the actual base.
# ============================================================================
log("")
log("=" * 78)
log(" SECTION D — call sites of sub_141026640 / sub_141026980 in PC::Load3D")
log("=" * 78)

PC_LOAD3D_EA = BASE + 0xD5B250
log("")
log(" Decomp PC::Load3D — focus on call sites 0x140D5B476 / 0x140D5B679")
txt = safe_decomp(PC_LOAD3D_EA)
if txt:
    # just dump the lines that mention sub_141026640 / sub_141026980 / sub_141020D60
    # plus +/-3 lines of context.
    lines = txt.splitlines()
    NEEDLES = ["sub_141026640", "sub_141026980", "sub_141020D60",
               "sub_140C584F0",   # Actor::Load3D
               "sub_141027E40", "sub_14102C820"]
    for i, ln in enumerate(lines):
        for n in NEEDLES:
            if n in ln:
                lo = max(0, i - 4)
                hi = min(len(lines), i + 5)
                log("")
                log("   ----- around line %d (matched %s) -----" % (i, n))
                for k in range(lo, hi):
                    marker = ">>> " if k == i else "    "
                    log("   %s%s" % (marker, lines[k]))
                break

# Same for Actor::Load3D
ACTOR_LOAD3D_EA = BASE + 0xC584F0
log("")
log(" Decomp Actor::Load3D — focus on the same calls")
txt = safe_decomp(ACTOR_LOAD3D_EA)
if txt:
    lines = txt.splitlines()
    for i, ln in enumerate(lines):
        for n in ["sub_141026640", "sub_141026980", "sub_141020D60",
                  "sub_140528410", "sub_140787980", "sub_1406EF810",
                  "sub_14050AC10"]:   # REFR::Load3D
            if n in ln:
                lo = max(0, i - 4)
                hi = min(len(lines), i + 5)
                log("")
                log("   ----- around line %d (matched %s) -----" % (i, n))
                for k in range(lo, hi):
                    marker = ">>> " if k == i else "    "
                    log("   %s%s" % (marker, lines[k]))
                break

# ============================================================================
# Section E — Decompile REFR::Load3D briefly to find its scene-attach calls
# (where sub_140787980 / sub_1406EF810 / sub_140528410 are invoked)
# ============================================================================
log("")
log("=" * 78)
log(" SECTION E — REFR::Load3D scene-attach call sites")
log("=" * 78)
REFR_LOAD3D_EA = BASE + 0x50AC10
txt = safe_decomp(REFR_LOAD3D_EA)
if txt:
    lines = txt.splitlines()
    for i, ln in enumerate(lines):
        for n in ["sub_140787980", "sub_1406EF810", "sub_140528410",
                  "qword_1430DBD58", "qword_143E47A10",   # ShadowSceneNode singleton
                  "sub_141020D60", "sub_141026640", "sub_141026980"]:
            if n in ln:
                lo = max(0, i - 5)
                hi = min(len(lines), i + 6)
                log("")
                log("   ----- around line %d (matched %s) -----" % (i, n))
                for k in range(lo, hi):
                    marker = ">>> " if k == i else "    "
                    log("   %s%s" % (marker, lines[k]))
                break

# ============================================================================
# Section F — qword_1432D2260 (the singleton arg used by sub_140BB1B80)
# This is the PlayerCharacter singleton (per memory). Confirm.
# ============================================================================
log("")
log("=" * 78)
log(" SECTION F — qword_1432D2260 (the singleton used by sub_140BB1B80)")
log("=" * 78)
ea = 0x1432D2260
seg = ida_segment.getseg(ea)
log("  segment: %s   addr %s" %
    (ida_segment.get_segm_name(seg) if seg else "?", hexs(ea)))
log("  static value: %s" % hexs(ida_bytes.get_qword(ea)))
log("  named: %s" % name_at(ea))
log("")
log("  --- xrefs (first 20) ---")
x = ida_xref.get_first_dref_to(ea); n = 0
while x != idaapi.BADADDR and n < 20:
    f = ida_funcs.get_func(x)
    fn = name_at(f.start_ea) if f else "?"
    line = idc.generate_disasm_line(x, 0) or ""
    log("    %s  in %s   %s" % (hexs(x), fn, line))
    x = ida_xref.get_next_dref_to(ea, x); n += 1

# ============================================================================
# Section G — final: caller-context of sub_141026640 in PC::Load3D —
# what is the actual `a1` argument? We trace registers backward from the
# call site 0x140D5B476.
# ============================================================================
log("")
log("=" * 78)
log(" SECTION G — call site context: PC::Load3D -> sub_141026640")
log("=" * 78)
SITE = 0x140D5B476
# print 30 instructions before the call site
log("")
log("  --- 40 instructions BEFORE call to sub_141026640 ---")
ea = SITE
for _ in range(40):
    ea = idc.prev_head(ea)
    if ea == idc.BADADDR: break
log("  starting at %s" % hexs(ea))
for _ in range(45):
    line = idc.generate_disasm_line(ea, 0) or ""
    log("    %s: %s" % (hexs(ea), line))
    ea = idc.next_head(ea)
    if ea > SITE + 16: break

# same for sub_141026980 site at 0x140D5B679
SITE2 = 0x140D5B679
log("")
log("  --- 40 instructions BEFORE call to sub_141026980 ---")
ea = SITE2
for _ in range(40):
    ea = idc.prev_head(ea)
    if ea == idc.BADADDR: break
log("  starting at %s" % hexs(ea))
for _ in range(45):
    line = idc.generate_disasm_line(ea, 0) or ""
    log("    %s: %s" % (hexs(ea), line))
    ea = idc.next_head(ea)
    if ea > SITE2 + 16: break

log("")
log("=" * 78)
log(" END")
log("=" * 78)

with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))
print("Wrote %s (%d lines)" % (LOG, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
