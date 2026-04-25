"""
M7.c — DEFINITIVE bone-drive RE.

We need to know:
  Q1 — Does anim graph WRITE to bone.local.translate, or only rotation?
  Q2 — World composition formula (parent.world o local).
  Q3 — Does an engine "copy pose" function exist? Or what's the proper recipe?
  Q4 — Why ghost (MaleBody.nif standalone) bones differ from player skeleton.
  Q5 — Sample bone walk: which names exist on each side.

Strategy:
  1. Decompile BShkbAnimationGraph::Generate path + downstream writers.
  2. Decompile NiAVObject::UpdateDownwardPass / vt[51] (Update / UpdateNode).
  3. Search the binary for "CopyPose" / "RetargetSkeleton" / etc.
  4. Decompile the NIF parser block-handler for NiNode + NiSkinInstance to
     understand standalone-NIF skeleton creation vs Actor::Load3D path.
  5. Use the BSFadeNode RTTI / vtable to identify "is_node" predicates.

Output:
  re/_bone_drive_correct.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_bone_drive_correct.log"
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
    log("--- /end %s ---" % label)
    log("")

def disasm_n(ea, n=40):
    log("--- disasm %s ---" % H(ea))
    cur = ea
    for _ in range(n):
        log("  %08X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR: break
        cur = nxt
    log("")

def find_strings(needles, max_per=10):
    """Yield (str_ea, string) for each binary string containing any needle."""
    out = []
    for s in idautils.Strings():
        try:
            txt = str(s)
        except: continue
        for n in needles:
            if n.lower() in txt.lower():
                out.append((s.ea, txt))
                break
        if len(out) >= max_per * len(needles):
            break
    return out

def xrefs_to(ea):
    return [r.frm for r in idautils.XrefsTo(ea)]

def func_name(ea):
    fn = ida_funcs.get_func(ea)
    if not fn: return "(no func)"
    return idc.get_func_name(fn.start_ea), fn.start_ea

def vt_slot(vt_ea, slot):
    return ida_bytes.get_qword(vt_ea + slot*8)

##############################################################################
# Q1+Q2 — Anim graph writers + UpdateDownwardPass / vt[51] composition
##############################################################################

log("=" * 80)
log("Q1/Q2 — Anim writers + UpdateDownwardPass composition")
log("=" * 80)
log("")

# Known RVAs:
#   NiAVObject vtable @ 0x14267D0C0
#   NiNode vtable     @ 0x14267C888
#   UpdateDownwardPass wrapper (RVA 0x16C8050)
#   vt[48] of NiAVObject = sub_1416C8310 (real UpdateDownwardPass)
#   BShkbAnimationGraph ctor 0x14131AB20

NIAV_VT  = 0x14267D0C0
NINODE_VT = 0x14267C888
BSFADE_VT = 0x1428FA3E8

log("[NiAVObject vtable @ %s] dumping slots 40..68 (Update*)" % H(NIAV_VT))
for slot in range(40, 70):
    ea = vt_slot(NIAV_VT, slot)
    if ea and ea != idc.BADADDR:
        nm = idc.get_name(ea) or ""
        fn = ida_funcs.get_func(ea)
        sz = (fn.end_ea - fn.start_ea) if fn else 0
        log("  vt[%2d] = %s  %s  (%d bytes)" % (slot, H(ea), nm, sz))

log("")
log("[NiNode vtable @ %s] dumping slots 40..68" % H(NINODE_VT))
for slot in range(40, 70):
    ea = vt_slot(NINODE_VT, slot)
    if ea and ea != idc.BADADDR:
        nm = idc.get_name(ea) or ""
        fn = ida_funcs.get_func(ea)
        sz = (fn.end_ea - fn.start_ea) if fn else 0
        log("  vt[%2d] = %s  %s  (%d bytes)" % (slot, H(ea), nm, sz))

log("")
log("[BSFadeNode vtable @ %s] dumping slots 40..68" % H(BSFADE_VT))
for slot in range(40, 70):
    ea = vt_slot(BSFADE_VT, slot)
    if ea and ea != idc.BADADDR:
        nm = idc.get_name(ea) or ""
        fn = ida_funcs.get_func(ea)
        sz = (fn.end_ea - fn.start_ea) if fn else 0
        log("  vt[%2d] = %s  %s  (%d bytes)" % (slot, H(ea), nm, sz))

log("")
log("[Decomp UpdateDownwardPass wrapper sub_1416C8050]")
decomp(0x1416C8050, "sub_1416C8050 (UpdateDownwardPass wrapper)", maxn=120)

log("[Decomp NiAVObject vt[48] = UpdateDownwardPass real, sub_1416C8310]")
decomp(0x1416C8310, "sub_1416C8310 (NiAVObject::UpdateDownwardPass)", maxn=120)

# vt[51] should be UpdateNode / UpdateWorldData (composes world = parent.world * local)
log("[NiAVObject vt[51] decomp]")
vt51 = vt_slot(NIAV_VT, 51)
log("  vt[51] = %s" % H(vt51))
decomp(vt51, "NiAVObject::vt[51] (UpdateNode/UpdateWorldData)", maxn=200)

# vt[52] is UpdateBound (called by UpdateDownwardPass)
log("[NiAVObject vt[52] decomp]")
vt52 = vt_slot(NIAV_VT, 52)
log("  vt[52] = %s" % H(vt52))
decomp(vt52, "NiAVObject::vt[52] (UpdateBound)", maxn=80)

# NiNode vt[51] override (composes children too)
log("[NiNode vt[51] decomp — should walk children + compose world]")
vt51_node = vt_slot(NINODE_VT, 51)
log("  vt[51] = %s" % H(vt51_node))
decomp(vt51_node, "NiNode::vt[51]", maxn=200)

# NiNode vt[42] is the per-child recursion (called by UpdateDownwardPass)
log("[NiAVObject vt[42] — child traversal]")
vt42 = vt_slot(NIAV_VT, 42)
log("  vt[42] = %s" % H(vt42))
decomp(vt42, "NiAVObject::vt[42]", maxn=120)

vt42_node = vt_slot(NINODE_VT, 42)
log("[NiNode vt[42] — child traversal]")
log("  vt[42] = %s" % H(vt42_node))
decomp(vt42_node, "NiNode::vt[42]", maxn=120)

##############################################################################
# Anim graph: BShkbAnimationGraph::Generate / Apply pose
##############################################################################

log("")
log("=" * 80)
log("Q1 — Anim graph pose application: what fields are written?")
log("=" * 80)
log("")

# BShkbAnimationGraph vtable @ 0x142626B38 (per anim_graph_m7.log)
BSHKB_VT = 0x142626B38
log("[BShkbAnimationGraph vtable @ %s] slots 0..40" % H(BSHKB_VT))
for slot in range(0, 40):
    ea = vt_slot(BSHKB_VT, slot)
    if ea and ea != idc.BADADDR:
        nm = idc.get_name(ea) or ""
        fn = ida_funcs.get_func(ea)
        sz = (fn.end_ea - fn.start_ea) if fn else 0
        log("  vt[%2d] = %s  %s  (%d bytes)" % (slot, H(ea), nm, sz))

# Look for callers/refs to local-translate vs local-rot offsets
log("")
log("[Searching xrefs for code that writes NiAVObject local fields]")
log("  local.rot @ +0x30   local.trans @ +0x60   local.scale @ +0x6C")
log("  world.rot @ +0x70   world.trans @ +0xA0   world.scale @ +0xAC")

# Enumerate functions in anim graph hot-spot region 0x14131xxxx and 0x141326xxx
# and decompile a few that have "+0x60" or "+0x30" writes.
# Simpler: decomp BShkbAnimGraph::Update (slot ~ vt[3] or [4] usually),
# and the ApplyPose-like fn.

# Vt[3] is usually Update on subclasses inheriting from hkbCharacter etc.
# Try ALL slots that look like "regular" fns
log("")
log("[Decomp BShkbAnimationGraph vt[3..10]]")
for slot in range(3, 11):
    ea = vt_slot(BSHKB_VT, slot)
    if ea and ea != idc.BADADDR:
        decomp(ea, "BShkbAnimGraph::vt[%d]" % slot, maxn=80)

##############################################################################
# Find pose-application functions by string xref
##############################################################################

log("")
log("=" * 80)
log("Q3 — Search for engine 'copy pose / retarget skeleton' helpers")
log("=" * 80)
log("")

needles = [
    "CopyPose", "copyPose", "ApplyPose", "applyPose",
    "RetargetSkeleton", "retargetSkeleton", "RetargetPose", "retargetPose",
    "PoseToBones", "BonesToPose",
    "BlendPose", "blendPose", "MergePose",
    "AnimationPose", "PoseTransfer",
    "CopySkeleton", "SetLocalTransform", "SetWorldTransform",
    "ApplySkeletonPose", "SkeletonCopy", "SkeletonRetarget",
]
found = find_strings(needles, max_per=5)
log("[String search: %d hits]" % len(found))
for ea, txt in found:
    log("  %s  %r" % (H(ea), txt))
log("")

# Also do binary search for "Pose" anywhere
log("[More 'Pose' related strings (broader)]")
allp = []
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    if "pose" in txt.lower() and len(txt) < 80:
        allp.append((s.ea, txt))
        if len(allp) >= 60: break
for ea, txt in allp:
    log("  %s  %r" % (H(ea), txt))

##############################################################################
# Q4 — NIF parser: NiNode block handler + NiSkinInstance (BSDismember)
##############################################################################

log("")
log("=" * 80)
log("Q4 — Standalone NIF load vs Actor skeleton: structural differences")
log("=" * 80)
log("")

# Find the NIF block factory table. The NIF parser dispatches by block-type
# string ("NiNode", "BSFadeNode", "BSTriShape", "BSDismemberSkinInstance" etc.)
needles2 = ["NiNode", "BSFadeNode", "BSDismemberSkinInstance",
            "NiSkinInstance", "NiSkinData", "NiSkinPartition",
            "BSTriShape", "BSSubIndexTriShape", "BSDynamicTriShape",
            "Skeleton.nif", "MaleBody.nif", "skeleton",
            "_skin", "Pelvis_skin", "Belly_skin", "ButtFat_skin",
            "Skeleton Root", "Skeleton.nif Root"]
found2 = find_strings(needles2, max_per=8)
log("[NIF block-type and name strings]")
for ea, txt in found2:
    log("  %s  %r" % (H(ea), txt))

# Find references to "Skeleton.nif"
log("")
log("[Xrefs to 'Skeleton.nif']")
for ea, txt in found2:
    if "skeleton.nif" in txt.lower():
        for x in xrefs_to(ea):
            try:
                fn = ida_funcs.get_func(x)
                if fn:
                    log("  xref %s -> in fn %s @ %s" % (H(x), idc.get_func_name(fn) or "?", H(fn.start_ea)))
            except: pass

# Find skeleton path constant in race / TESNPC / similar
log("")
log("[Xrefs to 'Pelvis_skin' / 'Belly_skin']")
for ea, txt in found2:
    if "pelvis_skin" in txt.lower() or "belly_skin" in txt.lower() or "buttfat_skin" in txt.lower():
        log("  string %s = %r" % (H(ea), txt))
        for x in xrefs_to(ea):
            try:
                fn = ida_funcs.get_func(x)
                if fn:
                    log("    xref %s -> in fn %s @ %s" % (H(x), idc.get_func_name(fn) or "?", H(fn.start_ea)))
            except: pass

##############################################################################
# Q5 — Check the nif loader for skeleton-creation hints
##############################################################################

# Get everything sub_1417B3E90 calls.
log("")
log("[Re-decomp NIF loader sub_1417B3E90 (top entry)]")
decomp(0x1417B3E90, "sub_1417B3E90 (NIF loader entry)", maxn=200)

# The actual block parser sub_1417B3480
log("[Re-decomp NIF block parser sub_1417B3480]")
decomp(0x1417B3480, "sub_1417B3480 (NIF inner)", maxn=300)

##############################################################################
# Q3 — Does ApplyPose / similar exist? Search by signature heuristic.
##############################################################################

log("")
log("=" * 80)
log("Q3 — Search by structural heuristic: fn that takes 2 NiNode-like args + walks")
log("=" * 80)
log("")

# We look at xrefs to NiAVObject vtable assigned to function args.
# Easier: find all functions that READ +0x70 (world.rot src) AND WRITE +0x30 (local.rot dst).
# That's the pattern of "copy world to local".

# Iterate functions that reference both 0x70 and 0x30 immediates AND involve memcpy-like
# behavior. Sample only functions in 1.4MB range around bone-related ones.

log("[Searching functions that DECOMPILE to contain '+0x70' AND '+0x30' AND memcpy]")
candidates = []
# Scan a focused region: 0x14131xxxx (anim graph) + 0x141326xxx (per-graph SetVar)
# + 0x1416Cxxxx (NiAVObject region)
ranges = [(0x141000000, 0x141500000), (0x1416B0000, 0x1416E0000)]
hits = 0
for r0, r1 in ranges:
    for ea in idautils.Functions(r0, r1):
        if hits >= 200: break
        try:
            cf = ida_hexrays.decompile(ea)
            if not cf: continue
            s = str(cf)
            # Must mention both translate (+0x60 / 0xA0) and rot (+0x30 / 0x70) offsets.
            has_local_rot = ("+ 48" in s) or ("+0x30" in s)
            has_local_tx  = ("+ 96" in s) or ("+0x60" in s)
            has_world_rot = ("+ 112" in s) or ("+0x70" in s)
            has_world_tx  = ("+ 160" in s) or ("+0xA0" in s)
            if (has_world_rot and has_local_rot) or (has_world_tx and has_local_tx):
                candidates.append((ea, idc.get_func_name(ea)))
                hits += 1
        except: continue
    if hits >= 200: break

log("Found %d candidates that touch both local and world transforms:" % len(candidates))
for ea, nm in candidates[:50]:
    log("  %s  %s" % (H(ea), nm))

# Decomp the most promising ones (vt[51] already done). Filter to small fns.
log("")
log("[Decomp top candidates (size < 0x800 to avoid Update fns)]")
for ea, nm in candidates:
    fn = ida_funcs.get_func(ea)
    if not fn: continue
    sz = fn.end_ea - fn.start_ea
    if sz > 0x800: continue
    log("\n--- candidate %s (%d bytes) ---" % (nm, sz))
    decomp(ea, nm, maxn=60)

##############################################################################
# Q4 / Q5 — Find what "skin bones" actually are.
# NIF parser is data-driven by block-type string. Find block factory map.
##############################################################################

log("")
log("=" * 80)
log("Q4 — Block factory: how NiNode and BSDismemberSkinInstance get instantiated")
log("=" * 80)
log("")

# Search for "BSDismemberSkinInstance" string and trace its xref chain.
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    if txt == "BSDismemberSkinInstance":
        log("[BSDismemberSkinInstance string @ %s]" % H(s.ea))
        for x in xrefs_to(s.ea):
            log("  xref @ %s in %s" % (H(x), idc.get_name(x) or "?"))
            fn = ida_funcs.get_func(x)
            if fn:
                log("    fn = %s @ %s" % (idc.get_func_name(fn.start_ea) or "?", H(fn.start_ea)))
        break

# Look at how Actor (PlayerCharacter) sets up its skeleton tree — Actor::Load3D path
# We already know REFR::Load3D = sub_14033D1E0. Let's decomp it focused on bone tree.
log("")
log("[Re-decomp REFR::Load3D = sub_14033D1E0]")
decomp(0x14033D1E0, "sub_14033D1E0 (TESObjectREFR::Load3D)", maxn=300)

##############################################################################
# Final: NiAVObject vt[6] is name (GetClassName). Vt[37] is "GetAVObject" usually.
# Look at all vt slots we haven't covered.
##############################################################################

log("")
log("=" * 80)
log("Misc — NiAVObject vt[6, 12, 30, 42, 51, 52] full coverage")
log("=" * 80)
log("")

# Also dump small slot decompiles for orientation
for slot in [4, 5, 6, 13, 19, 30, 31, 35, 36, 37, 38, 39, 40, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56]:
    ea = vt_slot(NIAV_VT, slot)
    if ea and ea != idc.BADADDR:
        fn = ida_funcs.get_func(ea)
        sz = (fn.end_ea - fn.start_ea) if fn else 0
        if sz < 0x300:
            decomp(ea, "NiAVObject vt[%d]" % slot, maxn=40)

##############################################################################

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as f:
    f.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG_PATH, len(lines)))
ida_pro.qexit(0)
