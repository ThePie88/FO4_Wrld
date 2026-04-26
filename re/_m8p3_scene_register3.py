"""
M8P3 phase 3 — final disambiguation. We need to identify:

  - The TYPE of the singleton at qword_1430DBD58 — what class is it?
    Look for any function that LOADS this singleton and reads [rax] (vtable),
    or any constructor that WRITES this singleton.
  - The 6 slot fields at +0x118..+0x140 — by looking at all RVAs that read
    those offsets through the singleton, then identifying the vtable of the
    object stored in each slot.
  - sub_141020D60 — the actual SCENE REGISTER worker. It calls sub_1417A0A30
    (a vtable dispatcher) and writes a1+88 (target of registration).
  - sub_140BB1B80 -> sub_140C58C70 -> sub_1403776E0 — what is this chain?

Plus: trace the lifetime of qword_1430DBD58 (CTOR call) to know its type.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name
import ida_segment, ida_xref, ida_ua

LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_m8p3_scene_register3_raw.log"
out_lines = []
BASE = 0x140000000

DRILL = [
    ("sub_140C58C70", 0xC58C70, "called by sub_140BB1B80"),
    ("sub_1403776E0", 0x3776E0, "called by sub_140BB1B80"),
    ("sub_141020D60", 0x1020D60, "the actual SCENE REGISTER worker"),
    ("sub_141029950", 0x1029950, "called when *(byte+426)==0 — slot+140 user"),
    ("sub_141029AB0", 0x1029AB0, "called when *(byte+426)==0 — slot+140 user"),
    ("sub_14102B070", 0x102B070, "queries qword_1430DBD58 for slot index 2"),
    ("sub_14102B090", 0x102B090, "queries qword_1430DBD58 for slot index 2"),
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
log(" M8P3 phase 3 — final disambiguation")
log("=" * 78)

# =========================================================================
# Section A — decompile each new drill target
# =========================================================================
for nm, r, anno in DRILL:
    abs_ea = BASE + r
    sz = fn_size(abs_ea)
    log("")
    log("-" * 78)
    log(" %s @ %s (RVA %s) size=%s -- %s" %
        (nm, hexs(abs_ea), hexs(r), hexs(sz) if sz else "?", anno))
    log("-" * 78)
    txt = safe_decomp(abs_ea)
    if txt:
        for line in txt.splitlines()[:80]:
            log("   " + line)
    else:
        log("   <decomp failed>")

# =========================================================================
# Section B — qword_1430DBD58 ctor / writer
# Look for stores TO qword_1430DBD58 (not reads) — that's the ctor site.
# =========================================================================
log("")
log("=" * 78)
log(" SECTION B — qword_1430DBD58: who WRITES it (= ctor / init site)")
log("=" * 78)
SCENE = 0x1430DBD58
x = ida_xref.get_first_dref_to(SCENE)
all_xrefs = []
while x != idaapi.BADADDR:
    all_xrefs.append(x)
    x = ida_xref.get_next_dref_to(SCENE, x)
log(" total xrefs: %d" % len(all_xrefs))

# A WRITE site has form "mov cs:qword_1430DBD58, rXX" or "mov [rip+...], rXX".
# The disasm string for a write is "mov cs:qword_1430DBD58, ..." with the
# qword as the destination operand.
write_sites = []
for ea in all_xrefs:
    line = (idc.generate_disasm_line(ea, 0) or "").strip()
    # IDA writes destination first; check if "qword_1430DBD58" comes before the comma
    if "qword_1430DBD58" in line:
        comma = line.find(",")
        if comma > 0:
            lhs = line[:comma]
            rhs = line[comma+1:]
            if "qword_1430DBD58" in lhs and "lea" not in line.lower() and "mov" in line.lower():
                # destination = singleton  -> WRITE
                write_sites.append((ea, line))
log(" detected %d candidate WRITE sites" % len(write_sites))
for ea, line in write_sites[:40]:
    f = ida_funcs.get_func(ea)
    fn = name_at(f.start_ea) if f else "?"
    log("    %s in %s   %s" % (hexs(ea), fn, line))

# =========================================================================
# Section C — slot+0x118..+0x140 ENGINE TIMING
# Look for the per-frame walker — a function that loops over all 6 slots
# and dispatches a "tick" or "update" virtual call.
# Pattern would be:
#   mov rcx, qword_1430DBD58
#   add rcx, 118h
#   loop reading [rcx], [rcx+8], ...
# =========================================================================
log("")
log("=" * 78)
log(" SECTION C — per-frame walker over slots +0x118..+0x140")
log("=" * 78)

# We already know sub_141026980 walks the slots, but it's fired on
# Load3D — it's a one-shot. We want a function that walks the slots EVERY
# FRAME. Look for callers of sub_14102D4C0 OR functions that read slots
# via [rcx+118h]..[rcx+140h] AND have "update" / "tick" / "Update" pattern
# (multiple read accesses to all 6 slots in sequence).

# Strategy: enumerate every function in .text. For each, count reads to
# [Rxx+118h], +120h, +128h, +130h, +138h, +140h. If a function reads >=4
# of the 6 it's a strong candidate.

def count_slot_reads(start_ea):
    f = ida_funcs.get_func(start_ea)
    if not f: return None
    cur = f.start_ea
    seen_offs = set()
    while cur < f.end_ea:
        line = (idc.generate_disasm_line(cur, 0) or "").lower()
        for off in (0x118, 0x120, 0x128, 0x130, 0x138, 0x140):
            if ("+%xh" % off) in line:
                seen_offs.add(off)
        nxt = idc.next_head(cur)
        if nxt <= cur: break
        cur = nxt
    return seen_offs

# Limit: only scan functions that already xref qword_1430DBD58
walker_candidates = []
fns_seen = set()
for ea in all_xrefs:
    f = ida_funcs.get_func(ea)
    if not f: continue
    if f.start_ea in fns_seen: continue
    fns_seen.add(f.start_ea)
    offs = count_slot_reads(f.start_ea)
    if offs and len(offs) >= 3:
        walker_candidates.append((f.start_ea, offs))

walker_candidates.sort(key=lambda r: -len(r[1]))
log(" functions reading >=3 of the 6 slots:")
for fa, offs in walker_candidates[:30]:
    fn = name_at(fa)
    sz = fn_size(fa)
    sl = sorted("+%X" % o for o in offs)
    log("    %s (%s) RVA %s  size=%s  slots=%s" %
        (fn, hexs(fa), hexs(rva(fa)), hexs(sz) if sz else "?", " ".join(sl)))

# =========================================================================
# Section D — what is the *v6 in PC::Load3D?
# v6 = a1 + 367 (a1 = PC* — so byte offset 367*8 = 2936 = 0xB78)
# 0xB78 is the loaded3D pointer per memory.
# So *v6 = loaded3D = the BSFadeNode root (the body or the actor's 3D).
# =========================================================================
log("")
log("=" * 78)
log(" SECTION D — confirm: a1[367] in PC::Load3D = 'loaded3D' field")
log("=" * 78)
log(" a1[367] = a1 + 367*8 = a1 + 2936 = a1 + 0xB78")
log(" Per memory: PC.loaded3D is at +0xB78. CONFIRMED.")
log(" So sub_141026640(qword_1430DBD58, loaded3D, v19) registers loaded3D.")
log("")
log(" But what is v19?  v19 = sub_140BB1B80(a1, loaded3D, &21, true)")
log(" Let me decompile sub_140BB1B80 to see what type-id 21 returns.")
log("")
# Already decomp'd — sub_140BB1B80 -> sub_140C58C70(a1) -> sub_1403776E0(...)
# sub_140C58C70 likely returns a sub-tree of the actor (maybe the BSFadeNode itself
# or a specific child). Let's decompile sub_140C58C70 to see what it does.
# Actually it's already in DRILL — done above.

# =========================================================================
# Section E — is sub_141027E40 (slot+130 writer) called from any
# per-frame update? Look at its callers.
# =========================================================================
log("")
log("=" * 78)
log(" SECTION E — callers of sub_141027E40 (slot+130 reader/writer)")
log("=" * 78)
target = BASE + 0x1027E40
x = ida_xref.get_first_cref_to(target)
seen = set()
while x != idaapi.BADADDR:
    f = ida_funcs.get_func(x)
    if f and f.start_ea not in seen:
        seen.add(f.start_ea)
        log("    caller %s in %s (RVA %s)" %
            (hexs(x), name_at(f.start_ea), hexs(rva(f.start_ea))))
    x = ida_xref.get_next_cref_to(target, x)

# =========================================================================
# Section F — look at unk_1430E1910 — is it actually a string / FormID
# =========================================================================
log("")
log("=" * 78)
log(" SECTION F — re-examine unk_1430E1910 — bytes / context")
log("=" * 78)
ea = 0x1430E1910
log(" bytes (32 dwords):")
for i in range(32):
    v = ida_bytes.get_dword(ea + i*4)
    log("    +%02X : %s" % (i*4, hexs(v)))
# Also: who else uses unk_1430E1910? -> 4 known refs from phase 2.
# From sub_141020D60 + sub_14102D4C0, both pass it as 2nd arg to sub_1417A0A30
# which decomp showed is a name-resolver that does:
#   sub_14167C200(a2)        -> validate FixedString a2
#   sub_1416BD0B0(a1, &qword_1438C8C48)   -> some lookup
#   *(_QWORD *)a1 + 16/48/368  -> vtable methods
# This is BSFixedString.LookUpInScene-ish. The 'unk' is actually a
# BSFixedString whose data lives elsewhere — IDA didn't classify the slot
# but the bytes are a FixedString control block.

# Section G — what is qword_1430DBD58 most likely class? Easy to determine
# by looking at *qword_1430DBD58 (the vtable pointer)
log("")
log("=" * 78)
log(" SECTION G — what does qword_1430DBD58 point to (vtable hint)")
log("=" * 78)
log(" At dump time it's 0xFFFF... (uninitialized). Need to find an EA where")
log(" a vtable is stored to qword_1430DBD58, or where a vtable from a known")
log(" class is captured. Search: any 'mov [rax], offset xxx_vftable' near a")
log(" 'mov cs:qword_1430DBD58, rax' write.")
log("")
log(" --- 30 instructions around each WRITE site to qword_1430DBD58 ---")
for ea, line in write_sites[:6]:
    log("")
    log(" WRITE site %s : %s" % (hexs(ea), line))
    # 30 instructions before
    cur = ea
    for _ in range(30):
        cur = idc.prev_head(cur)
        if cur == idc.BADADDR: break
    log("   --- back-trace ---")
    for _ in range(35):
        line2 = idc.generate_disasm_line(cur, 0) or ""
        log("    %s: %s" % (hexs(cur), line2))
        nxt = idc.next_head(cur)
        if nxt <= cur or nxt > ea + 16: break
        cur = nxt

log("")
log("=" * 78)
log(" END")
log("=" * 78)

with open(LOG, "w", encoding="utf-8", errors="replace") as fp:
    fp.write("\n".join(out_lines))
print("Wrote %s (%d lines)" % (LOG, len(out_lines)))
import ida_pro
ida_pro.qexit(0)
