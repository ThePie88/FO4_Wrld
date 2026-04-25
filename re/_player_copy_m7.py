"""
M7.b Player-copy ghost animation RE.

Investigates:
  Q1 — Player loaded3D offset within Actor / TESObjectREFR.
  Q2 — Bone tree structure of player 3D + children offset.
  Q3 — Bone transform layout (local vs world rot/translate).
  Q4 — UpdateDownwardPass sufficiency.
  Q5 — Race compatibility (Male vs Female bone names).
  Q6 — Implementation recipe RVAs.

Output: re/_player_copy_m7_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment, ida_xref

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_raw.log"
out_lines = []

def log(s):
    out_lines.append(s if isinstance(s, str) else str(s))

def hexs(x):
    try:
        return "0x%X" % x
    except:
        return str(x)

def decomp(ea, label=""):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            log("\n========== %s @ %s ==========" % (label, hexs(ea)))
            log(str(cfunc))
            return cfunc
    except Exception as e:
        log("decomp err %s: %s" % (hexs(ea), e))
    return None

def find_string_addr(s):
    matches = []
    needle = s.encode("utf-8") + b"\x00"
    seg = idaapi.get_first_seg()
    while seg:
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            f = ida_bytes.find_bytes(needle, ea, end)
            if f == idaapi.BADADDR:
                break
            matches.append(f)
            ea = f + len(needle)
        seg = idaapi.get_next_seg(seg.start_ea)
        if len(matches) >= 16:
            break
    return matches

def xrefs_to(ea, max_=20):
    out = []
    for r in idautils.XrefsTo(ea):
        out.append((r.frm, r.iscode, r.type))
        if len(out) >= max_:
            break
    return out

def func_containing(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None

# =============================================================================
# Pass 1: Player singleton sub_141122670 + Actor::GetCurrent3D / Get3D
# =============================================================================
log("=" * 80)
log(" M7.b PLAYER-COPY GHOST RE")
log(" Fallout4.exe 1.11.191 next-gen")
log("=" * 80)

# ----- Q1.A: Find Get3D / GetCurrent3D / loaded3D access ----------------------
log("\n--- Q1.A: Looking up GetCurrent3D / Get3D / loaded3D vtable methods ---")

# Search for "loaded3D" related strings (TESObjectREFR has Get3D() in CommonLibF4)
for s in ["GetCurrent3D", "Get3D", "loaded3D", "GetFadeNode", "BSFadeNode",
          "Actor::Get3D", "TESObjectREFR::Get3D", "Loaded3D", "currentRefr3D"]:
    locs = find_string_addr(s)
    if locs:
        log("  string %r found at %s" % (s, [hexs(l) for l in locs]))

# ----- Q1.B: PlayerCharacter vtable @ 0x142564838 — slots that return BSFadeNode -----
log("\n--- Q1.B: PlayerCharacter vtable scan @ 0x142564838 ---")

PC_VTABLE = 0x142564838
# Read first 100 vtable slots, look for short fns that read this+OFFSET
for slot in range(0, 100):
    fn = ida_bytes.get_qword(PC_VTABLE + slot * 8)
    if fn == 0 or fn == idaapi.BADADDR:
        continue
    name = ida_name.get_ea_name(fn)
    if name:
        log("  vt[%3d] = %s  (%s)" % (slot, hexs(fn), name))

# ----- Q1.C: Find Papyrus natives that return 3D — look for "Get3D" Papyrus binder
log("\n--- Q1.C: Search for known Papyrus refr/3d native binder ---")

# Use the well-known Papyrus 'IsCurrentlyAttached' / 'IsAttached' / 'Is3DLoaded'
for s in ["IsLoaded", "Is3DLoaded", "GetCurrent3D", "GetCurrent3DLoaded"]:
    addrs = find_string_addr(s)
    for a in addrs:
        log("  %r @ %s" % (s, hexs(a)))
        for fr, _, _ in xrefs_to(a, 5):
            f = func_containing(fr)
            log("    xref from %s (in fn %s)" % (hexs(fr), hexs(f) if f else "?"))

# ----- Q1.D: Decompile candidate Actor::GetCurrent3D / similar -----
# In CommonLibF4: Actor : MagicTarget : ActorValueOwner : TESObjectREFR ...
# TESObjectREFR has loadedData (offset 0x68 in older builds, 0x70/+ in next-gen)
# CommonLibF4 says TESObjectREFR layout puts loadedData around 0x68 in SE/AE,
# loadedData->data3D is around the 0x68 region too (3-step deref).

# Heuristic — find a fn xref'd from many places that just does:
#   mov rax, [rcx+0x68]  (loadedData ptr)
#   test rax, rax
#   mov rax, [rax+0x?]   (data3D ptr)
#   ret

log("\n--- Q1.D: Heuristic for short Get3D-style functions ---")

# Strong fingerprint: small fn (8-30 bytes) that does:
#   48 8b 41 68    mov rax, [rcx+0x68]   ; loadedData
#   48 85 c0       test rax, rax         ; null check
#   74 ??          jz short
#   48 8b 40 ??    mov rax, [rax+0x?]    ; data3D from loadedData
#   c3             ret
# Sweep over all functions and find this byte pattern at start.

def scan_short_get3d():
    """Find functions matching the small Get3D-style fingerprint."""
    candidates = []
    for fn_ea in idautils.Functions():
        f = ida_funcs.get_func(fn_ea)
        if not f:
            continue
        size = f.end_ea - f.start_ea
        if size < 6 or size > 64:
            continue
        head = ida_bytes.get_bytes(fn_ea, min(size, 32))
        if not head:
            continue
        # Look for "mov rax, [rcx+disp8]" = 48 8B 41 ??
        if head[0:3] == b"\x48\x8B\x41":
            disp = head[3]
            # And then "ret" within first 16 bytes
            if b"\xC3" in head[:24]:
                candidates.append((fn_ea, size, disp, head[:24].hex()))
    candidates.sort(key=lambda c: c[1])
    return candidates[:80]

cands = scan_short_get3d()
log("\n  Short fns starting with 'mov rax, [rcx+disp8]; ret' (top 80):")
for ea, size, disp, hexbytes in cands:
    n = ida_name.get_ea_name(ea)
    log("    fn %s size=%d disp=0x%X bytes=%s name=%s" %
        (hexs(ea), size, disp, hexbytes, n))

# ----- Q2: Find apply_materials walker sub_140255BA0 to learn child traversal -----
log("\n--- Q2: Apply materials walker sub_140255BA0 (child traversal pattern) ---")
decomp(0x140255BA0, "sub_140255BA0 apply_materials_walker")

# Per-geometry apply (called per leaf)
decomp(0x140256070, "sub_140256070 per_geometry_apply")

# ----- Q2.B: NiNode::AttachChild RVA 0x16BE170 - children offset confirmed
log("\n--- Q2.B: NiNode::AttachChild sub_1416BE170 (proves children offset) ---")
decomp(0x1416BE170, "sub_1416BE170 NiNode::AttachChild")

# ----- Q3: BSFadeNode vtable -----
log("\n--- Q3: BSFadeNode vtable scan ---")
# BSFadeNode : NiNode. In CommonLibF4 BSFadeNode is at offset NiNode + 0x140 = 0x158
# Search RTTI for BSFadeNode

bsfade_typedesc = find_string_addr(".?AVBSFadeNode@@")
log("  BSFadeNode TypeDescriptor candidates: %s" % [hexs(t) for t in bsfade_typedesc])

# Find NiNode children offset proof from NiNode ctor sub_1416BDFE0
decomp(0x1416BDFE0, "sub_1416BDFE0 NiNode::ctor (children init)")

# ----- Q3.B: NiAVObject::UpdateWorldData / UpdateDownwardPass -----
log("\n--- Q3.B: UpdateDownwardPass sub_1416C8050 ---")
decomp(0x1416C8050, "sub_1416C8050 NiAVObject::UpdateDownwardPass")

# Also dump NiAVObject ctor for layout confirmation
decomp(0x1416C8CD0, "sub_1416C8CD0 NiAVObject::ctor")

# ----- Q4: REFR Load3D pipeline path -----
log("\n--- Q4: REFR::Load3D / Actor::Load3D vt slots ---")

# REFR vtable at 0x142564838 (PlayerCharacter inherits from REFR via Actor).
# Find Load3D-like vt slots — usually short fns calling NIF loader.

# Scan REFR / Actor vtables. Player vtable was 0x142564838. Look at slots 17-20
# which the dossier marked as Setup3D.

for vt, label in [(0x142564838, "PlayerCharacter"),
                  (0x142513078, "Actor (probable)")]:
    log("\n  Scanning vtable %s @ %s" % (label, hexs(vt)))
    for slot in [16, 17, 18, 19, 20, 21, 22, 23]:
        fn = ida_bytes.get_qword(vt + slot * 8)
        if fn and fn != idaapi.BADADDR:
            name = ida_name.get_ea_name(fn)
            sz = 0
            ff = ida_funcs.get_func(fn)
            if ff:
                sz = ff.end_ea - ff.start_ea
            log("    vt[%2d] = %s  size=%d  %s" % (slot, hexs(fn), sz, name or ""))

# ----- Q4.B: Decompile sub_140D656A0 (PC vt[18] from prior dossier) -----
log("\n--- Q4.B: Decompile sub_140D656A0 (suspected Setup3D) ---")
decomp(0x140D656A0, "sub_140D656A0 PC vt[18] candidate Setup3D")

# Decompile REFR::Load3D from prior dossier: sub_14033D1E0
log("\n--- Q4.C: REFR::Load3D sub_14033D1E0 ---")
decomp(0x14033D1E0, "sub_14033D1E0 REFR::Load3D")

# ----- Q5: Find skinning bone search code (resolves bone by name) -----
log("\n--- Q5: Bone-by-name search code ---")

# CommonLibF4 has a function that walks a NiNode tree finding a child by name.
# The engine uses NiNode::GetObjectByName — find by string xrefs to bone-name strings.

for s in ["SPINE2", "Chest", "Neck1_sk", "HEAD", "LArm_UpperArm",
          "RArm_UpperArm", "Pelvis", "COM"]:
    addrs = find_string_addr(s)
    for a in addrs[:2]:
        log("  bone name %r @ %s" % (s, hexs(a)))
        for fr, _, _ in xrefs_to(a, 3):
            f = func_containing(fr)
            log("    xref from %s (in fn %s)" % (hexs(fr), hexs(f) if f else "?"))

# Find generic GetObjectByName candidate — short fn comparing this+0x10 (m_name)
# Actually: NiNode::GetObjectByName probably doesn't exist as standalone — engine
# uses BSFixedString comparison + recursive walk. Let's search for "FindBoneByName"

for s in ["GetObjectByName", "FindBoneByName", "GetBoneByName", "RootNode"]:
    locs = find_string_addr(s)
    if locs:
        log("  %r @ %s" % (s, [hexs(l) for l in locs]))

# ----- Q6: Useful RVAs from prior dossiers — verify they're still in IDA -----
log("\n--- Q6: Confirm key RVAs from prior dossiers are still in IDA ---")
for name, rva in [
    ("Player singleton qword", 0x1432D2260),
    ("PlayerCharacter vtable", 0x142564838),
    ("NiNode AttachChild", 0x1416BE170),
    ("UpdateDownwardPass", 0x1416C8050),
    ("apply_materials walker", 0x140255BA0),
    ("NIF loader entry", 0x1417B3E90),
]:
    n = ida_name.get_ea_name(rva)
    f = ida_funcs.get_func(rva)
    sz = (f.end_ea - f.start_ea) if f else 0
    log("  %-30s  %s  fn_size=%d  ida_name=%s" % (name, hexs(rva), sz, n))

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))

print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
