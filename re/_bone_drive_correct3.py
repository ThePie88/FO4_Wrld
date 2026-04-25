"""
M7.c — Pass 3 — FINAL DETAILS

Need:
  1. sub_1416E7E30 (314 bytes, called from NiNode::vt[48]) — likely the actual
     local→world composition! Decompile.
  2. sub_1403F85E0 — the bone-name-resolver that does "name" then "name_skin".
     Confirms what we suspect about ghost skin bones.
  3. sub_1403FB7D0 — the OTHER consumer of "%s_skin". May be the skin-bone
     resolver that walks ACTOR's tree (so we know which lookup to do).
  4. Look at sub_140651780 + sub_140664AD0 (xrefs to bare "_skin").
  5. Check NiAVObject vt[48] and the recursion to confirm offset semantics.
  6. Look for bone-by-name lookup helper (very common, takes BSFixedString).

Also: sub_1416E7E30 should be UPDATE_WORLD_FROM_LOCAL composition. Confirm.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_bone_drive_correct3.log"
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
# 1. THE COMPOSITION FUNCTION sub_1416E7E30 (called from vt[48] children loop)
##############################################################################

log("=" * 80)
log("THE WORLD-COMPOSITION FN (called by NiNode::UpdateDownwardPass)")
log("=" * 80)
log("")

decomp(0x1416E7E30, "sub_1416E7E30 (BoundsExpand or SetWorldXform?)", maxn=300)

# Also the xrefs to sub_1416E7E30 to confirm what calls it
refs = xrefs_to(0x1416E7E30)
log("[xrefs to sub_1416E7E30]")
for r in refs[:30]:
    fn = ida_funcs.get_func(r)
    if fn:
        log("  xref @ %s in fn %s @ %s" % (H(r), fnname(fn.start_ea), H(fn.start_ea)))

##############################################################################
# 2. The bone-resolver (gets "_skin" suffix bones from skeleton)
##############################################################################

log("")
log("=" * 80)
log("BONE NAME RESOLVER — '_skin' suffix handling")
log("=" * 80)
log("")

decomp(0x1403F85E0, "sub_1403F85E0 (bone resolver: tries name then name_skin)", maxn=80)
decomp(0x1403FB5F0, "sub_1403FB5F0 (the inner lookup fn)", maxn=80)
decomp(0x1403FB7D0, "sub_1403FB7D0 (other %s_skin user)", maxn=200)

# 3. The "_skin" suffix consumer in sub_140651780/sub_140664AD0
decomp(0x140651780, "sub_140651780 (xref to bare '_skin')", maxn=120)
decomp(0x140664AD0, "sub_140664AD0 (xref to bare '_skin')", maxn=120)

##############################################################################
# 4. The face/body skin-bone lookup table  sub_14065DD30 (consumes ALL the
#    'Head_skin', 'Face_skin', 'Neck1_skin', etc. strings)
##############################################################################

log("=" * 80)
log("THE SKIN-BONE NAME TABLE consumer (sub_14065DD30)")
log("=" * 80)
log("")

decomp(0x14065DD30, "sub_14065DD30 (consumes all *_skin bone strings)", maxn=400)

##############################################################################
# 5. Confirm bone-by-name lookup helper (common pattern: walks tree by name)
##############################################################################

log("=" * 80)
log("Find bone-by-name lookup helper")
log("=" * 80)
log("")

# Search for "GetObjectByName" or similar
needles = ["GetObjectByName", "FindNode", "LookupBone", "GetBoneByName",
           "FindObject", "GetChildByName", "FindChild", "GetExtraData"]
log("[String search for bone-lookup helpers]")
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    for n in needles:
        if n in txt and len(txt) < 80:
            log("  %s  %r" % (H(s.ea), txt))
            for r in xrefs_to(s.ea)[:2]:
                fn = ida_funcs.get_func(r)
                if fn: log("    xref in %s" % fnname(fn.start_ea))
            break

##############################################################################
# 6. Skeleton.nif resolution path
##############################################################################

log("")
log("=" * 80)
log("Skeleton.nif resolution")
log("=" * 80)
log("")

# Find xrefs of the path string "skeleton.nif" specifically (case-insensitive search)
for s in idautils.Strings():
    try: txt = str(s)
    except: continue
    tl = txt.lower()
    if ("skeleton.nif" in tl) and ("/" in tl or "\\" in tl) and len(txt) < 200:
        log("  Path %s  %r  refs: %d" % (H(s.ea), txt, len(xrefs_to(s.ea))))

# Actor's skeleton lives at Actor+0xF0->+0x08 per the user's notes.
# Find what +0xF0 is on the Actor side. We know PC vtable @ 0x142564838.
# Actor inherits from REFR. +0xF0 is in REFR / Actor base data. Let's find
# any decomp that does a1 + 240 / a1 + 0xF0 with that pattern.

# Look at PC RegisterDataChannels overrides (sub_140D7D060) to see what +0xF0 is.
log("")
log("[Actor skeleton accessor]")
decomp(0x140D7D060, "PC::RegisterDataChannels", maxn=60)

# Find PC vt[140] (Get3D — known good)
# Just to confirm the +0xB78 path
decomp(0x140D5BB30, "PC vt[140] Get3D", maxn=40)

# Try to find sub_14050D990 (template fallback) — what does it return?
decomp(0x14050D990, "sub_14050D990 (template 3D fallback)", maxn=80)

##############################################################################
# 7. Look for "anim object" attached to actor at +0xF0
##############################################################################

# Search for fn that reads (Actor + 0xF0) AND then reads (that + 0x08)
# Actor's animated-skeleton-ptr (per user notes, +0xF0 -> +0x08).

log("")
log("=" * 80)
log("Actor +0xF0 -> +0x08 pattern  (animated skeleton root accessor)")
log("=" * 80)
log("")

# sub_140CA9980 (Actor::RegisterDataChannels) reads various Actor fields.
# Per anim_graph_m7.log it stores `actor - 72` as channel owner.
# So channel.owner = actor + 72 (= IAGMH embedded). The actor's anim
# state is at this offset. The "skeleton at +0xF0" claim probably refers
# to the loaded3D field actually at +0xB78 (we already know).

# But the user's brief says "Actor+0xF0->+0x08". That's different.
# Let's check what's at +0xF0. Maybe ExtraData / "third-person" model?
# In TESObjectREFR layout, +0xF0 is a known offset. Let's find a decomp
# that touches it and see.

# sub_14033D1E0 = REFR::Load3D — should reference +0xF0 if it's a known field.
log("[Re-decomp sub_14033D1E0 REFR::Load3D for +0xF0/+0xB78 references]")
decomp(0x14033D1E0, "REFR::Load3D", maxn=400)

##############################################################################

with open(LOG_PATH, "w", encoding="utf-8", errors="replace") as f:
    f.write("\n".join(lines))

print("Wrote %s (%d lines)" % (LOG_PATH, len(lines)))
ida_pro.qexit(0)
