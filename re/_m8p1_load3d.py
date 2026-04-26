"""
M8 Phase 1 Step 1.1+1.2 — Find PlayerCharacter::Load3D and Actor::Load3D + dossier.

Strategy:
 1) Dump PlayerCharacter vtable @ RVA 0x2564838 (abs 0x142564838) — every slot
    until NULL or end-of-segment. Note function names, sizes, prologue bytes,
    and any qword that does NOT point into a function.
 2) Identify the Load3D slot by signature heuristic:
       - virtual fn taking (this, NiPoint3* origin, refresh_flags) approximately
       - body should call NIF loader (sub_1417B3E90), reference field +0xB78,
         construct BSFadeNode, attach to scene-graph parent.
 3) Walk Actor RTTI -> Actor vtable; find PlayerCharacter override (different ptr).
 4) Hex-Rays decompile the chosen Load3D body and emit it verbatim (or summarized
    if too long) plus call-graph (every direct callee with name + RVA + arg count).
 5) Flag the "scary" calls: skeleton.nif, MaleBody/FemaleBody, BSAnimationGraph,
    ShadowSceneNode/BSFadeNode parenting, bone resolver, apply_materials walker.
 6) Compute function size.

Output: re/_m8p1_load3d_raw.log (raw evidence) — final dossier produced separately.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_nalt, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p1_load3d_raw.log"
out_lines = []

BASE = 0x140000000
PC_VT_RVA  = 0x2564838            # PlayerCharacter vtable
PC_VT_ABS  = BASE + PC_VT_RVA      # 0x142564838

# Known anchors
NIF_LOADER_RVA = 0x17B3E90           # sub_1417B3E90 (NIF loader)
LOADED_3D_OFFSET = 0xB78
ALT_SCENE_PTR_OFFSET = 0xF0

# "Scary" RVAs from prior work
SCARY_RVAS = {
    0x17B3E90: "sub_1417B3E90 NIF loader (we use this in Frida)",
    0x3F85E0:  "sub_1403F85E0 bone resolver",
    0x255BA0:  "sub_140255BA0 apply_materials walker",
}

def log(s):
    out_lines.append(s if isinstance(s, str) else str(s))

def hexs(x):
    try: return "0x%X" % x
    except: return str(x)

def rva(ea):  return ea - BASE

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

def first_bytes(ea, n=16):
    try:
        b = ida_bytes.get_bytes(ea, n)
        return b.hex() if b else ""
    except:
        return ""

def first_disasm_lines(ea, n=8):
    out = []
    cur = ea
    for _ in range(n):
        if cur == idc.BADADDR: break
        line = idc.generate_disasm_line(cur, 0) or ""
        out.append("    %s: %s" % (hexs(cur), line))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return out

def decomp_text(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        if cf: return str(cf)
    except Exception as e:
        return "<decomp err: %s>" % e
    return None

def call_targets_in_func(start_ea):
    """Return list of (call_site_ea, target_ea) for direct calls inside the func."""
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
                # Filter: only direct call/jmp into another function in .text
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

def find_string_simple(s):
    """Build/use a string cache."""
    global _STRING_CACHE
    try:
        _STRING_CACHE
    except NameError:
        _STRING_CACHE = {}
        try:
            ss = idautils.Strings()
            for sx in ss:
                try:
                    _STRING_CACHE.setdefault(str(sx), []).append(sx.ea)
                except:
                    pass
        except Exception as e:
            log("string-cache err: %s" % e)
    return list(_STRING_CACHE.get(s, []))

# =============================================================
log("=" * 78)
log(" M8 PHASE 1 — Actor::Load3D / PlayerCharacter::Load3D dossier")
log(" Fallout4.exe 1.11.191 next-gen   |   ImageBase 0x140000000")
log("=" * 78)

# =============================================================
# STEP A — PlayerCharacter vtable dump
# =============================================================
log("")
log("=" * 78)
log(" A. PlayerCharacter vtable dump @ RVA 0x%X (abs %s)" % (PC_VT_RVA, hexs(PC_VT_ABS)))
log("=" * 78)

# Sanity: confirm it lives in .rdata
seg = ida_segment.getseg(PC_VT_ABS)
log("  segment: name=%s start=%s end=%s" % (
    ida_segment.get_segm_name(seg) if seg else "?",
    hexs(seg.start_ea) if seg else "?",
    hexs(seg.end_ea) if seg else "?"))

vt_slots = []
MAX_SLOTS = 320     # PlayerCharacter is huge; expect ~250 slots
for i in range(MAX_SLOTS):
    addr = PC_VT_ABS + i * 8
    if seg and addr >= seg.end_ea:
        log("  [stop] reached segment end at slot %d" % i)
        break
    v = ida_bytes.get_qword(addr)
    if v == 0:
        log("  [stop] NULL slot at index %d" % i)
        break
    # Sanity: pointer must be in .text
    tseg = ida_segment.getseg(v)
    if not tseg or ida_segment.get_segm_name(tseg) != ".text":
        log("  [stop] slot %d -> %s outside .text (seg=%s) — likely end of vtable" %
            (i, hexs(v), ida_segment.get_segm_name(tseg) if tseg else "?"))
        break
    nm = name_at(v)
    sz = fn_size(v)
    fb = first_bytes(v, 8)
    vt_slots.append((i, addr, v, nm, sz))
    log("  vt[%3d] @ %s -> %s  size=%s  name=%s  prologue=%s" %
        (i, hexs(addr), hexs(v),
         hexs(sz) if sz else "?",
         nm,
         fb))
log("  total non-null slots: %d" % len(vt_slots))

# =============================================================
# STEP B — Identify Load3D slot via heuristic
# =============================================================
log("")
log("=" * 78)
log(" B. Heuristic: identify Load3D slot")
log("=" * 78)

# Heuristic 1: function references field +0xB78 (loaded3D)
# Heuristic 2: function calls NIF loader RVA 0x17B3E90
# Heuristic 3: function calls sub_140458740 (the partial Load3D-like we found earlier)
# Heuristic 4: function references string "skeleton.nif" / "MaleBody"

NIF_ABS = BASE + NIF_LOADER_RVA
log("  NIF loader abs: %s" % hexs(NIF_ABS))

def slot_calls_into(slot_ea, target_ea):
    """Does the function at slot_ea make a direct call to target_ea?"""
    calls = call_targets_in_func(slot_ea)
    return any(t == target_ea for (_, t, _) in calls)

def slot_refs_offset(slot_ea, off):
    """Does the function at slot_ea reference [..+off]? Crude scan."""
    f = ida_funcs.get_func(slot_ea)
    if not f: return False
    cur = f.start_ea
    needle = "+%Xh" % off
    needle_low = needle.lower()
    needle_alt = "+0%Xh" % off if off >= 0xA else needle
    while cur < f.end_ea:
        line = idc.generate_disasm_line(cur, 0) or ""
        ll = line.lower()
        if needle_low in ll or ("+%xh" % off).lower() in ll:
            return True
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return False

candidates = []
for (i, slot_addr, v, nm, sz) in vt_slots:
    score = 0
    notes = []
    if slot_calls_into(v, NIF_ABS):
        score += 5; notes.append("calls NIF loader")
    if slot_calls_into(v, BASE + 0x458740):
        score += 4; notes.append("calls sub_140458740")
    if slot_refs_offset(v, LOADED_3D_OFFSET):
        score += 3; notes.append("refs +B78h")
    if score:
        candidates.append((i, slot_addr, v, nm, sz, score, notes))

log("  Heuristic candidate slots (score > 0):")
candidates.sort(key=lambda r: -r[5])
for (i, slot_addr, v, nm, sz, score, notes) in candidates[:20]:
    log("    vt[%3d] @ %s -> %s  score=%d  notes=%s  name=%s  size=%s" %
        (i, hexs(slot_addr), hexs(v), score, ", ".join(notes), nm,
         hexs(sz) if sz else "?"))

# Pick the top candidate
if candidates:
    LOAD3D_IDX = candidates[0][0]
    LOAD3D_EA  = candidates[0][2]
    log("")
    log("  >>> CHOSEN Load3D slot: vt[%d] -> %s (RVA %s)" %
        (LOAD3D_IDX, hexs(LOAD3D_EA), hexs(rva(LOAD3D_EA))))
else:
    LOAD3D_IDX = None
    LOAD3D_EA  = None
    log("  !!! No candidates met heuristic. Falling back to common slot indices.")
    # Common Load3D slot indices in Bethesda games: tied to TESObjectREFR vtable.
    # Try a few reasonable indices.
    for tryi in [105, 107, 109, 110, 111, 112, 113, 114, 115]:
        if tryi < len(vt_slots):
            log("  trying vt[%d] = %s (%s)" % (tryi, hexs(vt_slots[tryi][2]), vt_slots[tryi][3]))

# =============================================================
# STEP C — Find Actor vtable + Actor::Load3D
# =============================================================
log("")
log("=" * 78)
log(" C. Locate Actor vtable, find Actor::Load3D for comparison")
log("=" * 78)

# Find .?AVActor@@ TypeDescriptor and walk to its vtable.
actor_rtti_str = ".?AVActor@@"
eas = find_string_simple(actor_rtti_str)
log("  Actor RTTI string %r at: %s" % (actor_rtti_str, ", ".join(hexs(e) for e in eas)))

actor_vt_candidates = []
for s_ea in eas:
    td_ea = s_ea - 0x10
    log("  TD candidate %s (string %s)" % (hexs(td_ea), hexs(s_ea)))
    # COL refs the TD at +0xC. We look for any 32-bit field where TD = field_ea + base.
    # Easier: just walk xrefs to td_ea and check.
    for xr in idautils.XrefsTo(td_ea):
        if not xr.iscode:
            col_ea = xr.frm - 0xC
            # COL is referenced by vtable[-1]
            for xr2 in idautils.XrefsTo(col_ea):
                vt = xr2.frm + 8
                actor_vt_candidates.append(vt)
                log("    possible Actor vtable @ %s (COL %s)" % (hexs(vt), hexs(col_ea)))

# Dedup
actor_vt_candidates = list(set(actor_vt_candidates))
log("  Unique Actor vtable candidates: %d" % len(actor_vt_candidates))

# Pick the largest (most slots until NULL) as the "real" Actor vt
def vt_length(vt_ea, max_count=500):
    cnt = 0
    s = ida_segment.getseg(vt_ea)
    if not s: return 0
    for i in range(max_count):
        a = vt_ea + i*8
        if a >= s.end_ea: break
        v = ida_bytes.get_qword(a)
        if v == 0: break
        tseg = ida_segment.getseg(v)
        if not tseg or ida_segment.get_segm_name(tseg) != ".text":
            break
        cnt += 1
    return cnt

actor_vt_lens = [(vt, vt_length(vt)) for vt in actor_vt_candidates]
actor_vt_lens.sort(key=lambda r: -r[1])
log("  Actor vtable lengths:")
for vt, ln in actor_vt_lens[:10]:
    log("    %s len=%d" % (hexs(vt), ln))

ACTOR_VT = actor_vt_lens[0][0] if actor_vt_lens else None
if ACTOR_VT:
    log("  >>> CHOSEN Actor vtable: %s (RVA %s)" % (hexs(ACTOR_VT), hexs(rva(ACTOR_VT))))
    if LOAD3D_IDX is not None:
        actor_load3d = ida_bytes.get_qword(ACTOR_VT + LOAD3D_IDX * 8)
        log("  Actor vt[%d] (same slot as PC) -> %s (RVA %s)  name=%s" %
            (LOAD3D_IDX, hexs(actor_load3d), hexs(rva(actor_load3d)), name_at(actor_load3d)))
        if actor_load3d != LOAD3D_EA:
            log("  >>> PlayerCharacter OVERRIDES Load3D")
        else:
            log("  >>> PlayerCharacter inherits Load3D from Actor (same fn ptr)")

# =============================================================
# STEP D — Decompile Load3D
# =============================================================
log("")
log("=" * 78)
log(" D. Decompile PlayerCharacter::Load3D (or chosen candidate)")
log("=" * 78)

if LOAD3D_EA:
    f = ida_funcs.get_func(LOAD3D_EA)
    log("  Load3D func: %s..%s  size=%s" % (hexs(f.start_ea), hexs(f.end_ea),
                                              hexs(f.end_ea - f.start_ea)))
    log("")
    log("  ----- DECOMP BEGIN -----")
    txt = decomp_text(LOAD3D_EA)
    if txt:
        for line in txt.splitlines():
            log("  " + line)
    else:
        log("  <decomp failed — emitting disasm>")
        log("\n".join(first_disasm_lines(LOAD3D_EA, 200)))
    log("  ----- DECOMP END -----")

    # Also decompile the Actor version if different
    if ACTOR_VT and LOAD3D_IDX is not None:
        actor_load3d = ida_bytes.get_qword(ACTOR_VT + LOAD3D_IDX * 8)
        if actor_load3d != LOAD3D_EA:
            log("")
            log("  ----- ACTOR::LOAD3D DECOMP BEGIN -----")
            txt2 = decomp_text(actor_load3d)
            if txt2:
                for line in txt2.splitlines():
                    log("  " + line)
            log("  ----- ACTOR::LOAD3D DECOMP END -----")

# =============================================================
# STEP E — Direct callees + scary call detection
# =============================================================
log("")
log("=" * 78)
log(" E. Direct callees of Load3D (call/jmp targets inside func)")
log("=" * 78)

if LOAD3D_EA:
    calls = call_targets_in_func(LOAD3D_EA)
    log("  total direct call sites: %d" % len(calls))
    # Group by target
    by_target = {}
    for (csite, target, mnem) in calls:
        by_target.setdefault(target, []).append((csite, mnem))
    log("  unique targets: %d" % len(by_target))
    log("")
    for target in sorted(by_target.keys()):
        sites = by_target[target]
        nm = name_at(target)
        sz = fn_size(target)
        scary = SCARY_RVAS.get(rva(target))
        scary_tag = " [SCARY: %s]" % scary if scary else ""
        log("    %s (RVA %s) %s  size=%s  calls=%d%s" %
            (hexs(target), hexs(rva(target)), nm,
             hexs(sz) if sz else "?", len(sites), scary_tag))

    # Also check for scary RVAs that AREN'T direct calls (might be indirect through vtable)
    log("")
    log("  --- scan for known SCARY RVAs in disasm (direct or operand refs) ---")
    f = ida_funcs.get_func(LOAD3D_EA)
    cur = f.start_ea
    while cur < f.end_ea:
        line = idc.generate_disasm_line(cur, 0) or ""
        for r, desc in SCARY_RVAS.items():
            target = BASE + r
            if ("%X" % target) in line.upper() or ("sub_%X" % target).lower() in line.lower():
                log("    %s: %s  [%s]" % (hexs(cur), line, desc))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt

    # Also look for string refs inside Load3D (e.g. "skeleton.nif")
    log("")
    log("  --- string refs inside Load3D body ---")
    cur = f.start_ea
    while cur < f.end_ea:
        for xr in idautils.DataRefsFrom(cur):
            sn = idc.get_strlit_contents(xr, -1, 0)
            if sn:
                try: sn = sn.decode("utf-8", "replace")
                except: sn = repr(sn)
                if any(k in sn.lower() for k in
                       ["skeleton", "malebody", "femalebody", "behavior", ".nif",
                        ".hkx", "meshes\\", "actors\\"]):
                    log("    %s  ref->%s : %r" % (hexs(cur), hexs(xr), sn))
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt

# =============================================================
# STEP F — TESObjectREFR vtable for sanity (find common Load3D slot index)
# =============================================================
log("")
log("=" * 78)
log(" F. TESObjectREFR vtable — locate base Load3D slot index")
log("=" * 78)

eas2 = find_string_simple(".?AVTESObjectREFR@@")
log("  TESObjectREFR RTTI: %s" % ", ".join(hexs(e) for e in eas2))
refr_vts = []
for s_ea in eas2:
    td_ea = s_ea - 0x10
    for xr in idautils.XrefsTo(td_ea):
        if not xr.iscode:
            col_ea = xr.frm - 0xC
            for xr2 in idautils.XrefsTo(col_ea):
                refr_vts.append(xr2.frm + 8)
refr_vts = list(set(refr_vts))
refr_vt_lens = [(vt, vt_length(vt)) for vt in refr_vts]
refr_vt_lens.sort(key=lambda r: -r[1])
log("  Top REFR vtables:")
for vt, ln in refr_vt_lens[:5]:
    log("    %s len=%d" % (hexs(vt), ln))

if refr_vt_lens and LOAD3D_IDX is not None:
    refr_vt = refr_vt_lens[0][0]
    refr_load3d = ida_bytes.get_qword(refr_vt + LOAD3D_IDX * 8)
    log("  REFR vt[%d] -> %s (RVA %s)  name=%s" %
        (LOAD3D_IDX, hexs(refr_load3d), hexs(rva(refr_load3d)), name_at(refr_load3d)))
    if refr_load3d != ida_bytes.get_qword(ACTOR_VT + LOAD3D_IDX * 8) if ACTOR_VT else True:
        log("  >>> Actor overrides Load3D from REFR base")

# =============================================================
# DONE
# =============================================================
log("")
log("=" * 78)
log(" END")
log("=" * 78)

with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))

print("Wrote %s (%d lines)" % (LOG, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
