"""
M7.c — Pass 4 — Find the ACTUAL local->world composition

Strategy:
  1. Decompile BSFadeNode vt[48] = 0x1421764B0 — different override.
  2. Look at BSFadeNode vt[49] = 0x142176360 — UpdatePropertiesUpward maybe.
  3. Look at NiNode vt[53] sub_1416BF1C0 (347 bytes).
  4. Find a function that explicitly multiplies 3x3 matrix * vec + reads
     from +0x30 (local.rot) and +0x70 (world.rot).
  5. Search byte pattern for "movups xmm,[reg+30h]" type patterns —
     too noisy. Instead use heuristic: small fn (<300 bytes) that takes
     2 args, both pointers to NiAVObject-sized structs, and does
     SIMD math.
  6. Look at  sub_141789A90, sub_141789F80 (xrefs to bound expand =
     possibly skin update or anim apply).

Final goal: find or rule out a "copy pose" engine helper. If none exists,
confirm manual recipe.

Also Q5: list bone names — sample the actor skeleton tree by reading
+0xF0->+0x08 (or +0xB78), and also get the MaleBody.nif standalone bone list.
We can't do that statically. But we can list bone names BY string reference
and see what subtree of the binary they appear in.

Q4 ANSWER (now clear):
- Standalone NIF (MaleBody.nif via 0x1417B3E90) loads ONLY the body mesh
  with its skin instance. The skin instance has NAMED bone references like
  "Pelvis_skin", "Belly_skin" — these are NAMES of bones the SKIN expects
  to exist in the parent skeleton (above the BSFadeNode).
- When loaded standalone, sub_1417B3E90 calls sub_1417B4960 which loads
  the skeleton.nif TOO and parents the body under it. We need to inspect
  this.

So: maybe the standalone path actually DOES create a real skeleton parent.
Look at sub_1417B4960 (called near end of NIF loader).
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_bone_drive_correct4.log"
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
# 1. BSFadeNode vt[48] override
##############################################################################

log("=" * 80)
log("BSFadeNode override of UpdateDownwardPass")
log("=" * 80)
log("")

decomp(0x1421764B0, "BSFadeNode vt[48]", maxn=200)
decomp(0x142176360, "BSFadeNode vt[49]", maxn=200)

# vt[53] of BSFadeNode @ 0x142176590 (134 bytes)
decomp(0x142176590, "BSFadeNode vt[53]", maxn=80)

# vt[57] of BSFadeNode @ 0x1421754C0 (1138 bytes) — big — possibly the big update
# Skip due to size. Decomp first 100 lines only.
decomp(0x1421754C0, "BSFadeNode vt[57]", maxn=300)

##############################################################################
# 2. Look for specific composition: search for fn that has "matrix3*vec+vec"
##############################################################################

log("")
log("=" * 80)
log("World composition: NiNode vt[53] sub_1416BF1C0 (347 bytes)")
log("=" * 80)
log("")

decomp(0x1416BF1C0, "NiNode vt[53]", maxn=200)

##############################################################################
# 3. NIF loader's sub_1417B4960 (called at end of sub_1417B3E90 if loaded)
##############################################################################

log("")
log("=" * 80)
log("Post-load fn sub_1417B4960 — does it load skeleton parent?")
log("=" * 80)
log("")

decomp(0x1417B4960, "sub_1417B4960 (post-load)", maxn=300)

##############################################################################
# 4. Look at xrefs to sub_1416E7E30 (bound merge) — they include skinning fns
##############################################################################

log("")
log("=" * 80)
log("Skinning / vertex-update fns that touch bone bounds")
log("=" * 80)
log("")

# These are post-skinning bound-update fns. Find their callers — that's
# the bigger picture of bone-driven mesh update.
sk_fns = [
    (0x141789A90, 192),
    (0x141789F80, 256),
    (0x1417B8840, 256),
    (0x1417E9490, 200),
    (0x14180CCA0, 200),
    (0x142177340, 100),
    (0x1421D9530, 100),
    (0x1421E4E60, 100),
    (0x1421E5250, 100),
]
for ea, ln in sk_fns:
    decomp(ea, "sub_%X" % ea, maxn=ln)

##############################################################################
# 5. Search for actual "world = parent.world * local" math —
#    A specific signature: read a1+0x70 (world rot), a1+0x30 (local rot),
#    multiply 3x3 matrices.  This is a dot product chain: 9 muls, 6 adds.
##############################################################################

log("")
log("=" * 80)
log("Direct search for world=parent*local: small fns reading +0x30 and +0x70")
log("=" * 80)
log("")

# Heuristic: function that reads +0x30 (offset 48) AND writes +0x70 (offset 112).
# These are the actual rotation copy / multiplications.
ranges = [(0x141600000, 0x142800000)]  # render + ni hot region
hits = 0
for r0, r1 in ranges:
    for ea in idautils.Functions(r0, r1):
        if hits >= 50: break
        try:
            cf = ida_hexrays.decompile(ea)
            if not cf: continue
            s = str(cf)
            if ("a1 + 48" in s) and ("a1 + 112" in s) and "*(" in s:
                fn = ida_funcs.get_func(ea)
                sz = (fn.end_ea - fn.start_ea) if fn else 0
                if 60 < sz < 0x300:
                    log("[candidate sub_%X size=%d]" % (ea, sz))
                    log("  has 'a1 + 48' AND 'a1 + 112'")
                    hits += 1
                    decomp(ea, "candidate sub_%X" % ea, maxn=80)
        except: continue

##############################################################################
# 6. Look more directly: a fn that takes 'parent' + 'this' as 2 NiAVObjects
##############################################################################

log("")
log("=" * 80)
log("Final: look for SetWorldTransform (vt-based or fn-based)")
log("=" * 80)
log("")

# Search for "SetWorld" string
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    if "SetWorld" in txt and len(txt) < 80:
        log("  %s  %r" % (H(s.ea), txt))

# Look at NiAVObject vt[55] body — earlier we saw it sets a1+5 (a1+0x28 = parent)
# and calls vt[48].
# Also vt[56] does a complex thing with offsets.

# Let me look for SetParent chain — each child's world should be propagated
# Once parent is set, child UpdateDownwardPass triggers.

# But for OUR case (we don't change parent), we need to FORCE composition.

# CRITICAL: Look at functions called BY UpdateDownwardPass that read local
# fields. Trace what NiAVObject vt[52] (UpdateBound, sub_1416C85A0) does in
# the NON-trivial branch — that branch matters when parent != null.

decomp(0x1416C85A0, "NiAVObject vt[52] FULL (UpdateBound — has world write?)", maxn=400)

##############################################################################

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as f:
    f.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG_PATH, len(lines)))
ida_pro.qexit(0)
