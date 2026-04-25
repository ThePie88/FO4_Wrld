"""
M7.b Pass 3 — Pin down the Get3D / loaded3D offset.

Strategy:
  - sub_140C87EA0 calls apply_materials walker — this is Actor::Load3D
  - decompile it, find where it stores the BSFadeNode result.
  - decompile sub_140429E50, sub_140434DA0, sub_140C87EA0 (all xref to walker)
  - decompile sub_141162D02 inner ctx (Papyrus Is3DLoaded native)

Output: re/_player_copy_m7_3_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_3_raw.log"
out_lines = []

def log(s): out_lines.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)

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

log("=" * 80)
log(" M7.b PASS 3 — Pin Get3D offset via Actor::Load3D candidates")
log("=" * 80)

# Candidates xref-ing apply_materials walker
candidates = [
    (0x140247C70, "sub_140247C70"),
    (0x1402C46F0, "sub_1402C46F0"),
    (0x140359870, "sub_140359870"),
    (0x14035C950, "sub_14035C950"),
    (0x140429E50, "sub_140429E50"),
    (0x140434DA0, "sub_140434DA0"),
    (0x14050AC10, "sub_14050AC10"),
    (0x140C87EA0, "sub_140C87EA0  (Actor-range candidate)"),
]
for ea, label in candidates:
    decomp(ea, "apply_mats caller " + label)

# Also: TESForm vtable scan for Setup3D / Get3D slot.
# In FO4 1.11.191 PlayerCharacter vtable is 0x142564838.
# Look at vt slots around 110-180 — typical Get3D slot range.
log("\n--- PC vtable extended slots 100-200 ---")
PC_VT = 0x142564838
for slot in range(100, 200):
    fn = ida_bytes.get_qword(PC_VT + slot * 8)
    if not fn or fn == idaapi.BADADDR:
        continue
    f = ida_funcs.get_func(fn)
    sz = (f.end_ea - f.start_ea) if f else 0
    n = ida_name.get_ea_name(fn) or ""
    log("  vt[%3d] = %s  size=%-6d %s" % (slot, hexs(fn), sz, n))

# Find very small (<= 30 bytes) vt slots that look like Get3D — single deref
log("\n--- PC vtable small (<= 30) fns — likely accessors ---")
for slot in range(0, 250):
    fn = ida_bytes.get_qword(PC_VT + slot * 8)
    if not fn or fn == idaapi.BADADDR:
        continue
    f = ida_funcs.get_func(fn)
    if not f:
        continue
    sz = f.end_ea - f.start_ea
    if sz > 30:
        continue
    head = ida_bytes.get_bytes(fn, min(sz, 32))
    if not head:
        continue
    n = ida_name.get_ea_name(fn) or ""
    log("  vt[%3d] = %s size=%d bytes=%s %s" % (slot, hexs(fn), sz, head[:24].hex(), n))

# Find sub_141162D02 and decompile its containing fn
log("\n--- Papyrus Is3DLoaded fn 0x14115EFB0 — dump SHORT prologue 32 bytes ---")
prologue = ida_bytes.get_bytes(0x14115EFB0, 64)
if prologue:
    log("  bytes: %s" % prologue.hex())

# Find a smaller, more digestible approach: look at sub_140C87EA0 only.
# Also peek at xrefs of "BSFadeNode" string (RTTI), and find the
# BSFadeNode TypeDescriptor data — gives us BSFadeNode vtable RVA.

# BSFadeNode vtable = ?
log("\n--- BSFadeNode vtable lookup ---")
# scan for ?_7BSFadeNode names
for sn in idautils.Names():
    ea, name = sn
    if name and "BSFadeNode" in name and "vftable" in name:
        log("  %s @ %s" % (name, hexs(ea)))
    if name and "BSFadeNode" in name:
        log("  %s @ %s" % (name, hexs(ea)))

# IsCurrentlyAttached — Papyrus binder in 0x14114B280 — decomp it
log("\n--- Papyrus binder for IsLoaded sub_14114B280 ---")
decomp(0x14114B280, "sub_14114B280  Papyrus IsLoaded")

# Is3DLoaded's binder context from 0x14115EFB0+ small — but the actual
# small Get3D function is what we want. Search xrefs of NIF loader sub_1417B3E90
# AND apply_materials walker — there must be a SHARED parent.

# Also try: PlayerCharacter::Update3DPosition etc — RTTI string
for sn in ["3DLoaded", "BSGeometry", "loadedReference"]:
    pass  # placeholder

# Search for short fns under 0x140C5xxxx-0x140D9xxxx (Actor range) that
# match the pattern: load [rcx+disp]; load [rax+disp2]; ret  (the canonical
# Get3D = loadedData->data3D pattern)
log("\n--- Actor range small Get3D-pattern: mov rax,[rcx+d1]; mov rax,[rax+d2]; ret ---")
ACTOR_LO, ACTOR_HI = 0x140C50000, 0x140DA0000
def scan_get3d_chained(lo, hi):
    out = []
    for fn_ea in idautils.Functions(lo, hi):
        f = ida_funcs.get_func(fn_ea)
        if not f: continue
        sz = f.end_ea - f.start_ea
        if sz < 8 or sz > 40: continue
        head = ida_bytes.get_bytes(fn_ea, min(sz, 24))
        if not head: continue
        # Patterns:
        #  48 8B 41 dd                mov rax, [rcx+dd]            (1-step)
        #  48 8B 41 dd 48 8B 40 dd c3 mov rax, [rcx+dd]; mov rax, [rax+dd]; ret
        #  48 8B 49 dd 48 8B 41 dd c3 mov rcx, [rcx+dd]; mov rax, [rcx+dd]; ret
        if head[0:3] == b"\x48\x8B\x41" and len(head) > 7:
            # Check if 0x48 0x85 0xC0 (test rax, rax) follows OR another mov rax
            if head[3+1:3+1+3] == b"\x48\x8B\x40":
                d1 = head[3]
                d2 = head[3+4]
                out.append((fn_ea, sz, d1, d2, head[:24].hex()))
        elif head[0:3] == b"\x48\x8B\x49" and len(head) > 8:
            if head[4:7] == b"\x48\x8B\x41":
                d1 = head[3]
                d2 = head[7]
                out.append((fn_ea, sz, d1, d2, head[:24].hex()))
    return out

cands = scan_get3d_chained(ACTOR_LO, ACTOR_HI)
for ea, sz, d1, d2, hb in cands[:60]:
    n = ida_name.get_ea_name(ea) or ""
    log("  %s sz=%d d1=0x%X d2=0x%X bytes=%s %s" %
        (hexs(ea), sz, d1, d2, hb, n))

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))
print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
