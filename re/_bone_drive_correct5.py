"""
M7.c — Pass 5 — FINAL CONFIRMATION

We now know:
  - vt[52] = sub_1416C85A0 is the actual SetWorldFromLocal function.
  - It calls sub_1403444F0(parent.world, scratch, this.local) when there's a parent.
  - Without parent: this.world = this.local (copy 60 bytes).
  - With parent shortcut bit 0x200000000000: this.world = parent.world (copy 60 bytes).

We need:
  1. sub_1403444F0 — confirm it's the matrix multiply.
  2. ANY copy-pose function that takes (src skeleton, dst skeleton)? Search.
  3. The ANIM GRAPH's actual write to bone.local. Pose application path.
     This is where we determine if anim writes ONLY rotation, or also translate.

Strategy for #3: Find a function that walks the bone array of the actor's
skeleton and does memcpy from the anim graph's pose buffer to each bone's
+0x30 (local rot). If ALSO writes +0x60 (local trans), we know anim writes
translate too.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_bone_drive_correct5.log"
lines = []

def log(s=""):
    if not isinstance(s, str): s = str(s)
    lines.append(s)
def H(x):
    try: return "0x%X" % x
    except: return str(x)
def fnname(ea):
    try: return idc.get_func_name(ea) or "?"
    except: return "?"
def decomp(ea, label="", maxn=None):
    log("--- %s @ %s ---" % (label, H(ea)))
    try:
        cf = ida_hexrays.decompile(ea)
        if not cf: log("(decompile failed)"); return
        s = str(cf)
        if maxn:
            s_lines = s.splitlines()
            if len(s_lines) > maxn:
                s = "\n".join(s_lines[:maxn]) + "\n... (truncated, %d total)" % len(s_lines)
        log(s)
    except Exception as e: log("(exception: %s)" % e)
    log("--- /end ---"); log("")

def xrefs_to(ea):
    return [r.frm for r in idautils.XrefsTo(ea)]

##############################################################################
# 1. sub_1403444F0 — NiTransform multiply
##############################################################################

log("=" * 80)
log("THE NiTRANSFORM MULTIPLY FUNCTION (proves world = parent.world * local)")
log("=" * 80)
log("")

decomp(0x1403444F0, "sub_1403444F0 (NiTransform multiply)", maxn=300)

# xrefs to confirm it's used widely as a transform fn
log("[xrefs to sub_1403444F0]")
refs = xrefs_to(0x1403444F0)
log("  %d xrefs total" % len(refs))
for r in refs[:20]:
    fn = ida_funcs.get_func(r)
    if fn:
        log("  xref @ %s in fn %s @ %s" % (H(r), fnname(fn.start_ea), H(fn.start_ea)))

##############################################################################
# 2. The anim graph's pose write — find function called from BShkbAnimGraph::Generate
##############################################################################

log("")
log("=" * 80)
log("BShkbAnimGraph pose application — what bone fields are written")
log("=" * 80)
log("")

# From pass 1, BShkbAnimGraph::vt[3] (Generate, sub_141326C00) is the entry.
# Look at what it calls.
log("[Calls inside BShkbAnimGraph::vt[3] sub_141326C00]")
fn = ida_funcs.get_func(0x141326C00)
if fn:
    calls = set()
    cur = fn.start_ea
    while cur < fn.end_ea:
        mnem = idc.print_insn_mnem(cur)
        if mnem == "call":
            target = idc.get_operand_value(cur, 0)
            if target and target != idc.BADADDR:
                calls.add(target)
        cur = idc.next_head(cur)
    for c in sorted(calls):
        nm = idc.get_name(c) or "?"
        f = ida_funcs.get_func(c)
        sz = (f.end_ea - f.start_ea) if f else 0
        log("  calls %s = %s (%d bytes)" % (H(c), nm, sz))

# Decompile the most likely pose-application function:
# sub_141872090 and sub_141872190 (per pass 1 they are called inside the
# pose loop in Generate)
decomp(0x141872090, "sub_141872090 (pose write?)", maxn=100)
decomp(0x141872190, "sub_141872190 (pose write?)", maxn=100)
decomp(0x14125EB50, "sub_14125EB50 (also called in pose loop)", maxn=100)

##############################################################################
# 3. Look for the broader pose-application chain. The flow:
#    BShkbAnimGraph::Generate -> ApplyPose -> per-bone write
##############################################################################

# Search for fns that write to ALL of: bone+0x30, +0x40, +0x60.
# Or: that take (NiNode*, hkVector4* or similar).

# Actually a simpler approach: find the fn that converts a havok pose
# (hkQsTransform: rotation/translation/scale per bone) into engine
# NiTransforms.

# hkQsTransform fields: rotation (hkQuaternion = 4 floats), translation
# (hkVector4 = 4 floats with padding), scale (hkVector4 = 4 floats with
# padding). Total 48 bytes. Rotation is QUATERNION, not 3x3 matrix.

# Bethesda has a function that converts hkQuaternion -> NiMatrix3 + writes
# to bone. Let's search.

log("")
log("=" * 80)
log("Search for hkQuaternion -> NiMatrix3 conversion + bone write")
log("=" * 80)
log("")

# Strings related to the conversion
needles = ["hkQsTransform", "hkQuaternion", "NiMatrix3", "BoneArray",
           "ApplyTransforms", "PoseToLocal", "LocalFromPose"]
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    for n in needles:
        if n in txt and len(txt) < 80:
            log("  %s  %r" % (H(s.ea), txt))
            break

##############################################################################
# 4. Look at the function that REGISTERS bones with the anim graph.
#    That binding tells us which fields get written per bone.
##############################################################################

log("")
log("=" * 80)
log("Bone-registration in anim graph")
log("=" * 80)
log("")

# sub_14132BF90 (called by BShkbAnimGraph::vt[7]) — looks like pose-to-bone setup
decomp(0x14132BF90, "sub_14132BF90 (pose binding setup)", maxn=200)

# sub_141393B40 (called by BShkbAnimGraph::vt[7])
decomp(0x141393B40, "sub_141393B40", maxn=150)

# sub_14133A9C0 (called by BShkbAnimGraph::vt[7])
decomp(0x14133A9C0, "sub_14133A9C0 (memcpy of 48 bytes per bone?)", maxn=150)

##############################################################################
# 5. Find the per-bone write function. Look for fn that writes to
#    +0x30..+0x60 (local rot 48 bytes) AND +0x60..+0x6C (local trans 12 bytes).
##############################################################################

log("")
log("=" * 80)
log("Direct search: fns that copy 48 bytes to bone +0x30 (local rot)")
log("=" * 80)
log("")

# Search broader range, but smaller fns
ranges = [(0x141300000, 0x141500000)]  # anim graph hot region
hits = 0
for r0, r1 in ranges:
    for ea in idautils.Functions(r0, r1):
        if hits >= 30: break
        try:
            cf = ida_hexrays.decompile(ea)
            if not cf: continue
            s = str(cf)
            # Looking for "memcpy(bone + 48, ..., 48)" or similar patterns
            if "+ 48" in s and "memcpy" in s.lower():
                fn = ida_funcs.get_func(ea)
                sz = (fn.end_ea - fn.start_ea) if fn else 0
                if sz < 0x200:
                    hits += 1
                    log("[candidate sub_%X size=%d]" % (ea, sz))
                    decomp(ea, "candidate sub_%X" % ea, maxn=50)
        except: continue

##############################################################################
# 6. Look at hkbCharacter or havok-side setup.
#    sub_141326590 = BShkbAnimGraph::SetVarFloat (per-graph, from pass 1)
#    sub_141322xxxx range = anim graph internals.
##############################################################################

log("")
log("=" * 80)
log("Anim graph internals — pose writer hint via inner per-graph SetVar")
log("=" * 80)
log("")

# sub_141326590 = SetVarFloat (per-graph)
decomp(0x141326590, "BShkbAnimGraph::SetVarFloat (per-graph)", maxn=100)

# sub_141398EB0 — pulls hkbBehaviorGraph from BShkbAnimGraph (vt[3] uses it)
decomp(0x141398EB0, "sub_141398EB0 (Get hkbBehaviorGraph)", maxn=80)

##############################################################################
# 7. Final: search for the actual "ApplyPose" engine function.
#    Bethesda calls the result-writer "BSAnimationGraphChannel::Update" maybe.
##############################################################################

log("")
log("=" * 80)
log("Look at BShkbAnimGraph anim channel update (where pose is written to bones)")
log("=" * 80)
log("")

# sub_140CA9980 = Actor::RegisterDataChannels (per anim_graph_m7.log)
# Inside that, channels store (actor - 72) as owner. Each channel has an
# Update method that writes to specific Actor fields based on anim variables.
# But that's NOT bone writes — that's "speed variable" type writes.

# The ACTUAL bone-write happens during the engine's animation graph apply
# step. It's likely sub_141327220 = BShkbAnimGraph::vt[7] (we saw it copies
# 48 bytes per bone in pass 1).

# Re-inspect vt[7] body more thoroughly:
log("[FULL decomp of BShkbAnimGraph::vt[7] = sub_141327220 (pose application)]")
decomp(0x141327220, "BShkbAnimGraph::vt[7] full", maxn=200)

##############################################################################

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as f:
    f.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG_PATH, len(lines)))
ida_pro.qexit(0)
