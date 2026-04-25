"""
M7.c — pass 2 — DEEPER DIVE.

Focus:
  1. NiNode vt[48] = 0x1416BEAC0 — appears to be the real UpdateDownwardPass
     for NiNode (497 bytes). NiAVObject vt[48] just walks children +
     calls vt[51] which is nullsub for NiAVObject base.
  2. NiNode vt[47] = 0x1416BF500 — UpdateWorldBound.
  3. NiNode vt[49] = 0x1416BECC0 — UpdateNode (594 bytes).
  4. NiNode vt[50] = 0x1416BF080 — Update something (305 bytes).
  5. Find xrefs / instances of "_skin" bones (do NIFs ref them by name?).
  6. Decompile sub_142174DC0 (BSFadeNode ctor) and sub_142174E60 (NIF wrap).
  7. Decomp BShkbAnimGraph::Generate (vt[3] sub_141326C00) inner pose-write.
  8. Find the function that writes bone.local from anim graph output.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_bone_drive_correct2.log"
lines = []

def log(s=""):
    if not isinstance(s, str): s = str(s)
    lines.append(s)

def H(x):
    try: return "0x%X" % x
    except: return str(x)

def decomp(ea, label="", maxn=None):
    log("--- %s @ %s ---" % (label, H(ea)))
    try:
        cf = ida_hexrays.decompile(ea)
        if not cf:
            log("(decompile failed)")
            return
        s = str(cf)
        if maxn:
            s_lines = s.splitlines()
            if len(s_lines) > maxn:
                s = "\n".join(s_lines[:maxn]) + "\n... (truncated, %d total)" % len(s_lines)
        log(s)
    except Exception as e:
        log("(exception: %s)" % e)
    log("--- /end ---")
    log("")

def xrefs_to(ea):
    return [r.frm for r in idautils.XrefsTo(ea)]

def fnname(ea):
    try:
        return idc.get_func_name(ea) or "?"
    except: return "?"

##############################################################################
# 1. NiNode vt[48] real UpdateDownwardPass
##############################################################################

log("=" * 80)
log("NiNode UpdateDownwardPass family — the REAL composition")
log("=" * 80)
log("")

# vt[48] of NiNode = NiNode::UpdateDownwardPass (497 bytes)
decomp(0x1416BEAC0, "NiNode::vt[48] (UpdateDownwardPass override)", maxn=300)

# vt[47] of NiNode (314 bytes) — likely UpdateBound
decomp(0x1416BF500, "NiNode::vt[47] (UpdateBound)", maxn=200)

# vt[49] of NiNode (594 bytes)
decomp(0x1416BECC0, "NiNode::vt[49]", maxn=300)

# vt[50] of NiNode (305 bytes)
decomp(0x1416BF080, "NiNode::vt[50]", maxn=200)

# vt[46] of NiNode (112 bytes) — small, may be UpdateBound
decomp(0x1416BE990, "NiNode::vt[46]", maxn=100)

# vt[40] of NiNode (155 bytes)
decomp(0x1416BEA10, "NiNode::vt[40]", maxn=100)

# vt[41] of NiNode (124 bytes)
decomp(0x1416BE900, "NiNode::vt[41]", maxn=100)

##############################################################################
# 2. The composition — look for parent.world * local pattern in NiAVObject vt[47]
##############################################################################

log("=" * 80)
log("The COMPOSITION FUNCTION — search for matrix-multiply 'world = parent_world * local'")
log("=" * 80)
log("")

# NiAVObject vt[47] is sub_1416C8230 (206 bytes) — UpdatePropertiesUpward maybe
decomp(0x1416C8230, "NiAVObject::vt[47]", maxn=120)

# NiAVObject vt[49] is sub_1416C83A0 (237 bytes)
decomp(0x1416C83A0, "NiAVObject::vt[49]", maxn=150)

# NiAVObject vt[50] is sub_1416C84A0 (237 bytes)
decomp(0x1416C84A0, "NiAVObject::vt[50]", maxn=150)

# NiAVObject vt[53] is sub_1416C8A60 (83 bytes)
decomp(0x1416C8A60, "NiAVObject::vt[53]", maxn=80)

##############################################################################
# 3. _skin bone strings — find xrefs by enumerating each
##############################################################################

log("=" * 80)
log("_skin bone strings — xrefs to each (find the consumer)")
log("=" * 80)
log("")

skin_strs = [
    (0x1424CEE18, "_skin"),
    (0x1424CEE30, "Head_skin"),
    (0x1424CEE40, "Face_skin"),
    (0x1424CEE50, "Neck1_skin"),
    (0x1424CEE60, "Neck_skin"),
    (0x1424CEE70, "chest_skin"),
    (0x1424CEE80, "LBreast_skin"),
    (0x1424CEE90, "RBreast_skin"),
    (0x1424CEEA0, "Chest_Rear_Skin"),
    (0x1424CEEB0, "Chest_Upper_Skin"),
    (0x1424CEEC8, "Neck_Low_skin"),
    (0x1424CEED8, "Spine2_skin"),
    (0x1424CEEE8, "UpperBelly_skin"),
    (0x1424CEEF8, "Spine2_Rear_skin"),
    (0x1424CEF10, "Spine1_skin"),
    (0x1424CEF20, "Belly_skin"),
    (0x1424CEF30, "Spine1_Rear_skin"),
    (0x1424CF1C8, "Pelvis_skin"),
    (0x1424CF1D8, "RButtFat_skin"),
    (0x1424CF1E8, "LButtFat_skin"),
    (0x1424CF1F8, "Pelvis_Rear_skin"),
    (0x14247F6B0, "%s_skin"),
]

for ea, name in skin_strs:
    refs = xrefs_to(ea)
    log("'%s' @ %s -- %d xrefs" % (name, H(ea), len(refs)))
    for r in refs[:5]:
        fn = ida_funcs.get_func(r)
        if fn:
            log("  xref %s in fn %s @ %s" % (H(r), fnname(fn.start_ea) or "?", H(fn.start_ea)))
        else:
            log("  xref %s (no fn)" % H(r))

# Also look at the function that uses '%s_skin' format string —
# that's likely where bones get their _skin suffix
log("")
log("[Decomp fn that uses '%%s_skin' format]")
fmt_str_ea = 0x14247F6B0
for r in xrefs_to(fmt_str_ea)[:3]:
    fn = ida_funcs.get_func(r)
    if fn:
        decomp(fn.start_ea, "fn using %s_skin", maxn=120)

##############################################################################
# 4. NIF wrap functions sub_142174DC0 and sub_142174E60
##############################################################################

log("")
log("=" * 80)
log("BSFadeNode ctor + NIF wrapping")
log("=" * 80)
log("")

decomp(0x142174DC0, "sub_142174DC0 (BSFadeNode ctor)", maxn=200)
decomp(0x142174E60, "sub_142174E60 (NIF wrap to FadeNode)", maxn=200)

##############################################################################
# 5. PoseTransfer / PoseToBones related — find by string xref
##############################################################################

log("")
log("=" * 80)
log("Pose-related fn dispatch")
log("=" * 80)
log("")

# Find xrefs for these specific strings (from previous pass):
pose_strs = [
    (0x142714008, "StCopyPose"),
    (0x14249D540, "Behavior ragdoll save/load state mismatch..."),
    (0x14265B860, "Local pose is not available."),
    (0x1426E0C70, "animatedSkeleton"),
    (0x1426E0C88, "hkbAnimatedSkeletonGenerator"),
    (0x14270DE50, "BSLimbCycleModifier requires..."),
    (0x14270B7A0, "TthkbAnimatedSkeletonGenerator::update"),
    (0x142633C30, "hkaskeletonmapper.cpp"),
    (0x1426412C0, "hkaSkeletonLocalFrameOnBone"),
]
for ea, label in pose_strs:
    refs = xrefs_to(ea)
    log("[%s @ %s] %d xrefs" % (label, H(ea), len(refs)))
    for r in refs[:3]:
        fn = ida_funcs.get_func(r)
        if fn:
            log("  xref @ %s in fn %s @ %s" % (H(r), fnname(fn.start_ea) or "?", H(fn.start_ea)))

##############################################################################
# 6. Anim graph SetVar -> per-bone write chain
##############################################################################

log("")
log("=" * 80)
log("BShkbAnimGraph::Generate — find pose write")
log("=" * 80)
log("")

# vt[3] is the big update fn (sub_141326C00, 1287 bytes). Decomp full.
decomp(0x141326C00, "BShkbAnimGraph::vt[3] (Generate)", maxn=400)

##############################################################################
# 7. Look at the actual bone-world composition: find any fn that does
#    "this->world.rot = mat3_mul(parent->world.rot, this->local.rot)"
##############################################################################

log("")
log("=" * 80)
log("Bone composition functions — find fns that read parent.world AND local.rot")
log("=" * 80)
log("")

# In the NiAVObject ctor sub_1416C8CD0, default values are written.
decomp(0x1416C8CD0, "NiAVObject ctor", maxn=120)

# NiNode ctor sub_1416BDFE0
decomp(0x1416BDFE0, "NiNode ctor", maxn=80)

# Find the SetParent helper sub_1416C8B60
decomp(0x1416C8B60, "sub_1416C8B60 (SetParent?)", maxn=60)

# vt[55] = sub_1416C8AD0 (45 bytes) — small, possibly SetWorldXform
decomp(0x1416C8AD0, "NiAVObject vt[55]", maxn=40)
decomp(0x1416C8AC0, "NiAVObject vt[54]", maxn=40)
decomp(0x1416C8B10, "NiAVObject vt[56]", maxn=40)

##############################################################################
# 8. Find functions that write to NiAVObject + 0xA0 (world translate) directly.
##############################################################################

log("")
log("=" * 80)
log("Search for writers to bone.world.translate (+0xA0) and rot (+0x70)")
log("=" * 80)
log("")

# This is hard without symbol names. Use disasm to grep for "mov [reg+A0]"
# Actually, just look at all places that generate world transforms in the
# animation graph hot path. Specifically sub_1416BEAC0 (NiNode UDP) is
# the main world-update target. Look at what it calls.

# Trace what NiNode::vt[48] (UpdateDownwardPass) calls
log("[Trace calls inside NiNode::vt[48] sub_1416BEAC0]")
fn = ida_funcs.get_func(0x1416BEAC0)
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

##############################################################################
# 9. Look for HEAD-related strings to confirm vanilla bone names
##############################################################################

log("")
log("=" * 80)
log("Vanilla bone names (search the binary)")
log("=" * 80)
log("")

needles_bones = [
    "SPINE1", "SPINE2", "Pelvis", "Chest", "Neck1_sk", "HEAD",
    "LArm_Collarbone", "LArm_UpperArm", "LArm_ForeArm",
    "RArm_Collarbone", "RArm_UpperArm",
    "LLeg_Thigh", "LLeg_Calf", "LLeg_Foot",
    "RLeg_Thigh", "RLeg_Calf", "RLeg_Foot",
    "Bip01", "COM", "Root", "Skeleton.nif Root",
    "RootNode",
]
seen = set()
hits = []
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    for n in needles_bones:
        if n in txt and len(txt) < 64:
            if (s.ea, txt) not in seen:
                seen.add((s.ea, txt))
                hits.append((s.ea, txt))
            break
for ea, txt in hits[:80]:
    refs = xrefs_to(ea)
    log("  %s  %r  (%d xrefs)" % (H(ea), txt, len(refs)))

##############################################################################

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as f:
    f.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG_PATH, len(lines)))
ida_pro.qexit(0)
