"""
M8P1 — second pass: decompile the key direct callees of PlayerCharacter::Load3D
to characterize what they do.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_nalt

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p1_callees_raw.log"
out_lines = []
BASE = 0x140000000

def log(s): out_lines.append(s if isinstance(s, str) else str(s))
def hexs(x): return "0x%X" % x
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

def decomp(ea, label=""):
    log("")
    log("==============================================================================")
    log(" %s @ %s (RVA %s) size=%s" % (label, hexs(ea), hexs(rva(ea)),
                                          hexs(fn_size(ea)) if fn_size(ea) else "?"))
    log("==============================================================================")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            log(str(cf))
        else:
            log("<decomp failed>")
    except Exception as e:
        log("<decomp err: %s>" % e)

def callees_in(start_ea):
    """Return set of direct call targets in the function."""
    f = ida_funcs.get_func(start_ea)
    if not f: return set()
    out = set()
    cur = f.start_ea
    while cur < f.end_ea:
        mnem = idc.print_insn_mnem(cur)
        if mnem in ("call", "jmp"):
            t = idc.get_operand_value(cur, 0)
            if t and t != idc.BADADDR:
                tf = ida_funcs.get_func(t)
                if tf and t != f.start_ea:
                    out.add(t)
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

def string_refs(start_ea):
    f = ida_funcs.get_func(start_ea)
    if not f: return []
    out = []
    cur = f.start_ea
    while cur < f.end_ea:
        for xr in idautils.DataRefsFrom(cur):
            sn = idc.get_strlit_contents(xr, -1, 0)
            if sn:
                try: sn = sn.decode("utf-8", "replace")
                except: sn = repr(sn)
                if len(sn) >= 3 and len(sn) < 200:
                    out.append((cur, xr, sn))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

# Key callees to decomp
TARGETS = [
    (0x140D623D0, "Wrapper that builds NIF path arg before NIF loader call"),
    (0x140D5BA10, "Tail attach helper (a1, ext_3d, v55, v56, v57)"),
    (0x140C9AAC0, "Likely scene-graph parent/attach (called twice in Load3D + once in Actor::Load3D)"),
    (0x14045FCA0, "Post-NIF init helper"),
    (0x140C5C830, "Get cached/alt scene tree?"),
    (0x140CE0040, "Init step after Load3D"),
    (0x140D35EE0, "Init step after Load3D 2"),
    (0x140C595F0, "Actor post-load helper"),
    (0x14050AC10, "TESObjectREFR::Load3D (base, called by Actor::Load3D)"),
    (0x140D9AF10, "AnimGraph init? (gets a1[367]=loaded3D, a1+26)"),
    (0x140D79000, "Subsystem trigger when actor==player & 3D state mismatch"),
    (0x141026640, "Possibly scene-graph register (calls qword_1430DBD58 obj)"),
    (0x141026980, "Possibly scene-graph attach"),
    (0x141895000, "Anim graph setup variant"),
    (0x14187FF20, "Anim related getter"),
    (0x140D86320, "Get parent/initial 3D"),
    (0x140BB1B80, "Find/create child by tag (called 3x with tag 18, 21, then 0)"),
    (0x140D3ADF0, "Subsystem getter (a1[96] -> ... )"),
]

log("=" * 78)
log(" M8P1 — Load3D direct callees decomp")
log("=" * 78)

for ea, desc in TARGETS:
    decomp(ea, "[%s] %s" % (hexs(ea), desc))
    # Also log string refs inside this function
    sr = string_refs(ea)
    if sr:
        log("  STRING REFS:")
        for (csite, dref, s) in sr:
            log("    %s -> %s : %r" % (hexs(csite), hexs(dref), s[:120]))
    # And direct callees
    cs = callees_in(ea)
    if cs:
        log("  DIRECT CALLEES (%d):" % len(cs))
        for c in sorted(cs):
            log("    %s (RVA %s) %s  size=%s" % (
                hexs(c), hexs(rva(c)), name_at(c),
                hexs(fn_size(c)) if fn_size(c) else "?"))

# Also: any function in Fallout4 that references the literal "skeleton.nif"?
# This will help us locate where vanilla Load3D path actually emits the skeleton load.
log("")
log("=" * 78)
log(" SKELETON.NIF / MaleBody / FemaleBody string refs (global)")
log("=" * 78)

# Build string cache
ss = idautils.Strings()
hits = {}
for s in ss:
    try:
        t = str(s)
    except: continue
    tl = t.lower()
    for kw in ["skeleton.nif", "skeleton_female", "malebody", "femalebody",
              "characterassets", "behaviorgraph", "behaviors\\", "actors\\character"]:
        if kw in tl:
            hits.setdefault(t, []).append(s.ea)

for t, eas in sorted(hits.items()):
    log("  %r:" % t[:80])
    for e in eas:
        log("    @ %s" % hexs(e))
        # Find code xrefs
        n = 0
        for xr in idautils.XrefsTo(e):
            f = ida_funcs.get_func(xr.frm)
            if f:
                log("      xref from %s in %s @ %s" %
                    (hexs(xr.frm), name_at(f.start_ea), hexs(f.start_ea)))
                n += 1
                if n >= 4: break

with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Wrote %s (%d lines)" % (LOG, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
